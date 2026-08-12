use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use maverick_core::frame::{ErrorCode, Frame, FrameType, OpenTcpPayload};
use maverick_core::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{timeout, Duration};

use crate::socks5;
use crate::tunnel::ClientTunnel;
use crate::ClientTunnelPool;

const FLOW_ID: u64 = 1;

pub async fn handle_socks_connection(
    local: TcpStream,
    config: Arc<ClientConfig>,
    flow_permit: OwnedSemaphorePermit,
) -> Result<()> {
    crate::reject_retired_v1_h3(&config)?;
    let tunnel_pool = Arc::new(ClientTunnelPool::new(config));
    let result =
        handle_socks_connection_with_pool(local, Arc::clone(&tunnel_pool), flow_permit).await;
    tunnel_pool.shutdown();
    result
}

pub(crate) async fn handle_socks_connection_with_pool(
    mut local: TcpStream,
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_permit: OwnedSemaphorePermit,
) -> Result<()> {
    crate::reject_retired_v1_h3(tunnel_pool.config())?;
    let read_timeout = Duration::from_millis(tunnel_pool.config().advanced.connect_timeout_ms);
    let request = match timeout(read_timeout, socks5::read_request(&mut local)).await {
        Ok(Ok(req)) => req,
        Ok(Err(err)) => {
            let _ = socks5::write_failure(&mut local).await;
            return Err(err);
        }
        Err(_) => {
            let _ = socks5::write_failure(&mut local).await;
            bail!("SOCKS request timed out");
        }
    };
    if request.command == socks5::SocksCommand::UdpAssociate {
        let control_peer = local.peer_addr().ok();
        return socks5::serve_udp_associate_with_pool(
            local,
            tunnel_pool,
            flow_permit,
            control_peer,
        )
        .await;
    }

    handle_local_connect(
        local,
        tunnel_pool,
        request.target,
        request.port,
        ConnectReply::Socks5,
        Bytes::new(),
        flow_permit,
    )
    .await
}

pub(crate) enum ConnectReply {
    Socks5,
    HttpConnect,
}

pub(crate) async fn handle_local_connect(
    mut local: TcpStream,
    tunnel_pool: Arc<ClientTunnelPool>,
    target: maverick_core::frame::TargetAddr,
    port: u16,
    reply: ConnectReply,
    initial_data: Bytes,
    _flow_permit: OwnedSemaphorePermit,
) -> Result<()> {
    crate::reject_retired_v1_h3(tunnel_pool.config())?;
    let mut tunnel = match open_tcp_tunnel(&tunnel_pool, target, port).await {
        Ok(tunnel) => tunnel,
        Err(err) => {
            let _ = write_connect_failure(&mut local, &reply).await;
            return Err(err);
        }
    };

    write_connect_success(&mut local, &reply).await?;
    if !initial_data.is_empty() {
        tunnel
            .send_frame(
                Frame::new(FrameType::TcpData, 0, FLOW_ID, initial_data),
                false,
            )
            .await?;
    }

    let _ = relay_stream_and_tunnel(
        local,
        tunnel,
        Duration::from_secs(tunnel_pool.config().advanced.idle_timeout_secs),
    )
    .await?;
    Ok(())
}

pub(crate) async fn open_tcp_tunnel(
    tunnel_pool: &ClientTunnelPool,
    target: maverick_core::frame::TargetAddr,
    port: u16,
) -> Result<ClientTunnel> {
    crate::reject_retired_v1_h3(tunnel_pool.config())?;
    let mut tunnel = tunnel_pool.open().await?;
    let open = OpenTcpPayload::new(target, port);
    tunnel
        .send_frame(
            Frame::new(FrameType::OpenTcp, 0, FLOW_ID, open.encode()?),
            false,
        )
        .await?;

    match tunnel.read_next_frame().await? {
        Some(frame) if frame.frame_type == FrameType::WindowUpdate && frame.flow_id == FLOW_ID => {
            Ok(tunnel)
        }
        Some(frame) if matches!(frame.frame_type, FrameType::Error | FrameType::CloseFlow) => {
            tunnel.finish_response().await?;
            bail!("remote target connection failed")
        }
        Some(frame) if frame.frame_type == FrameType::TcpReset => {
            bail!("remote target connection failed")
        }
        _ => bail!("server closed before flow opened"),
    }
}

async fn write_connect_success(local: &mut TcpStream, reply: &ConnectReply) -> Result<()> {
    match reply {
        ConnectReply::Socks5 => socks5::write_success(local).await,
        ConnectReply::HttpConnect => {
            local
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            local.flush().await?;
            Ok(())
        }
    }
}

async fn write_connect_failure(local: &mut TcpStream, reply: &ConnectReply) -> Result<()> {
    match reply {
        ConnectReply::Socks5 => socks5::write_failure(local).await,
        ConnectReply::HttpConnect => {
            local
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                .await?;
            local.flush().await?;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayClose {
    Graceful,
    Reset,
}

pub(crate) async fn relay_stream_and_tunnel<S>(
    local: S,
    mut tunnel: ClientTunnel,
    idle_timeout: Duration,
) -> Result<RelayClose>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let mut local_buf = vec![0u8; 16 * 1024];
    let mut local_eof = false;

    loop {
        if local_eof {
            tokio::select! {
                _ = tokio::time::sleep(idle_timeout) => break,
                remote_frame = tunnel.read_next_frame() => {
                    match remote_frame? {
                        Some(frame) => {
                            let finish_response = response_frame_is_complete(frame.frame_type);
                            if let Some(close) =
                                handle_remote_frame(frame, &mut local_write, idle_timeout).await?
                            {
                                if finish_response {
                                    tunnel.finish_response().await?;
                                }
                                return Ok(close);
                            }
                        }
                        None => break,
                    }
                }
            }
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(idle_timeout) => {
                break;
            }
            local_read_result = local_read.read(&mut local_buf) => {
                let n = local_read_result?;
                if n == 0 {
                    tunnel
                        .send_frame(Frame::new(FrameType::TcpFin, 0, FLOW_ID, Bytes::new()), true)
                        .await?;
                    local_eof = true;
                } else {
                    tunnel
                        .send_frame(
                            Frame::new(
                                FrameType::TcpData,
                                0,
                                FLOW_ID,
                                Bytes::copy_from_slice(&local_buf[..n]),
                            ),
                            false,
                        )
                        .await?;
                }
            }
            remote_frame = tunnel.read_next_frame() => {
                match remote_frame? {
                    Some(frame) => {
                        let finish_response = response_frame_is_complete(frame.frame_type);
                        if let Some(close) =
                            handle_remote_frame(frame, &mut local_write, idle_timeout).await?
                        {
                            if finish_response {
                                tunnel.finish_response().await?;
                            }
                            return Ok(close);
                        }
                    }
                    None => break,
                }
            }
        }
    }
    Ok(RelayClose::Graceful)
}

fn response_frame_is_complete(frame_type: FrameType) -> bool {
    matches!(
        frame_type,
        FrameType::TcpFin | FrameType::CloseFlow | FrameType::Error
    )
}

async fn handle_remote_frame<W>(
    frame: Frame,
    local_write: &mut W,
    idle_timeout: Duration,
) -> Result<Option<RelayClose>>
where
    W: AsyncWrite + Unpin,
{
    if frame.flow_id != FLOW_ID {
        return Ok(None);
    }
    match frame.frame_type {
        FrameType::TcpData => {
            write_all_with_idle_timeout(local_write, &frame.payload, idle_timeout).await?;
            Ok(None)
        }
        FrameType::TcpFin | FrameType::CloseFlow => {
            let _ = local_write.shutdown().await;
            Ok(Some(RelayClose::Graceful))
        }
        FrameType::TcpReset | FrameType::Error => {
            let _ = local_write.shutdown().await;
            Ok(Some(RelayClose::Reset))
        }
        _ => Ok(None),
    }
}

async fn write_all_with_idle_timeout<W>(
    writer: &mut W,
    mut bytes: &[u8],
    idle_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        let written = timeout(idle_timeout, writer.write(bytes))
            .await
            .context("local relay write timed out")??;
        if written == 0 {
            bail!("local relay writer closed before the frame was complete");
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

#[allow(dead_code)]
fn _error_frame(code: ErrorCode) -> Frame {
    Frame::new(FrameType::Error, 0, FLOW_ID, code.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{Mode, SecretString};
    use tokio::net::TcpListener;

    fn retired_h3_config() -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "127.0.0.1:1".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_socks".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig {
                experimental_h3: true,
                ..ClientAdvancedConfig::default()
            },
        }
    }

    async fn connected_local_write_half() -> Result<(tokio::net::tcp::OwnedWriteHalf, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let peer = TcpStream::connect(addr).await?;
        let (local, _) = listener.accept().await?;
        let (_, local_write) = local.into_split();
        Ok((local_write, peer))
    }

    #[tokio::test]
    async fn remote_tcp_data_is_written_to_local_stream() -> Result<()> {
        let (mut local_write, mut peer) = connected_local_write_half().await?;
        let frame = Frame::new(FrameType::TcpData, 0, FLOW_ID, Bytes::from_static(b"hello"));

        let close = handle_remote_frame(frame, &mut local_write, Duration::from_secs(1)).await?;

        assert_eq!(close, None);
        let mut buf = [0u8; 5];
        peer.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn public_socks_helper_rejects_retired_h3_before_local_eof_read() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let peer = TcpStream::connect(addr).await?;
        let (local, _) = listener.accept().await?;
        drop(peer);
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await?;

        let error = handle_socks_connection(local, Arc::new(retired_h3_config()), permit)
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remote_close_frame_shuts_down_local_stream() -> Result<()> {
        for frame_type in [FrameType::TcpReset, FrameType::Error] {
            let (mut local_write, mut peer) = connected_local_write_half().await?;
            let frame = Frame::new(frame_type, 0, FLOW_ID, Bytes::new());

            let close =
                handle_remote_frame(frame, &mut local_write, Duration::from_secs(1)).await?;

            assert_eq!(close, Some(RelayClose::Reset));
            let mut buf = [0u8; 1];
            assert_eq!(peer.read(&mut buf).await?, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn remote_fin_remains_graceful() -> Result<()> {
        for frame_type in [FrameType::TcpFin, FrameType::CloseFlow] {
            let (mut local_write, mut peer) = connected_local_write_half().await?;
            let frame = Frame::new(frame_type, 0, FLOW_ID, Bytes::new());

            let close =
                handle_remote_frame(frame, &mut local_write, Duration::from_secs(1)).await?;

            assert_eq!(close, Some(RelayClose::Graceful));
            let mut buf = [0u8; 1];
            assert_eq!(peer.read(&mut buf).await?, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn unrelated_flow_frame_is_ignored() -> Result<()> {
        let (mut local_write, mut peer) = connected_local_write_half().await?;
        let frame = Frame::new(
            FrameType::TcpData,
            0,
            FLOW_ID + 1,
            Bytes::from_static(b"ignored"),
        );

        let close = handle_remote_frame(frame, &mut local_write, Duration::from_secs(1)).await?;

        assert_eq!(close, None);
        let mut buf = [0u8; 1];
        assert!(timeout(Duration::from_millis(25), peer.read(&mut buf))
            .await
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn blocked_local_sink_does_not_outlive_idle_timeout() -> Result<()> {
        let (local, _blocked_peer) = tokio::io::duplex(1);
        let (_, mut local_write) = tokio::io::split(local);
        let frame = Frame::new(
            FrameType::TcpData,
            0,
            FLOW_ID,
            Bytes::from(vec![0x33; 64 * 1024]),
        );

        let result = timeout(
            Duration::from_secs(1),
            handle_remote_frame(frame, &mut local_write, Duration::from_millis(25)),
        )
        .await
        .expect("blocked local write outlived the relay idle timeout");
        assert!(result.is_err(), "blocked local write should time out");
        Ok(())
    }

    #[tokio::test]
    async fn slow_local_sink_with_continuous_progress_does_not_time_out() -> Result<()> {
        let payload = Bytes::from_static(b"slow-progress");
        let (local, mut peer) = tokio::io::duplex(1);
        let (_, mut local_write) = tokio::io::split(local);
        let expected_len = payload.len();
        let reader = tokio::spawn(async move {
            let mut received = Vec::with_capacity(expected_len);
            for _ in 0..expected_len {
                let mut byte = [0u8; 1];
                peer.read_exact(&mut byte).await?;
                received.push(byte[0]);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Result::<Vec<u8>>::Ok(received)
        });
        let started = tokio::time::Instant::now();

        write_all_with_idle_timeout(&mut local_write, &payload, Duration::from_millis(100)).await?;

        assert!(
            started.elapsed() > Duration::from_millis(100),
            "test must take longer than one idle-timeout interval"
        );
        assert_eq!(reader.await??, payload);
        Ok(())
    }
}
