use std::sync::Arc;

use anyhow::{bail, Result};
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
        Some(frame)
            if matches!(
                frame.frame_type,
                FrameType::Error | FrameType::TcpReset | FrameType::CloseFlow
            ) =>
        {
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
                            if let Some(close) = handle_remote_frame(frame, &mut local_write).await? {
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
                        if let Some(close) = handle_remote_frame(frame, &mut local_write).await? {
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

async fn handle_remote_frame<W>(frame: Frame, local_write: &mut W) -> Result<Option<RelayClose>>
where
    W: AsyncWrite + Unpin,
{
    if frame.flow_id != FLOW_ID {
        return Ok(None);
    }
    match frame.frame_type {
        FrameType::TcpData => {
            local_write.write_all(&frame.payload).await?;
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

#[allow(dead_code)]
fn _error_frame(code: ErrorCode) -> Frame {
    Frame::new(FrameType::Error, 0, FLOW_ID, code.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

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

        let close = handle_remote_frame(frame, &mut local_write).await?;

        assert_eq!(close, None);
        let mut buf = [0u8; 5];
        peer.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello");
        Ok(())
    }

    #[tokio::test]
    async fn remote_close_frame_shuts_down_local_stream() -> Result<()> {
        for frame_type in [FrameType::TcpReset, FrameType::Error] {
            let (mut local_write, mut peer) = connected_local_write_half().await?;
            let frame = Frame::new(frame_type, 0, FLOW_ID, Bytes::new());

            let close = handle_remote_frame(frame, &mut local_write).await?;

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

            let close = handle_remote_frame(frame, &mut local_write).await?;

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

        let close = handle_remote_frame(frame, &mut local_write).await?;

        assert_eq!(close, None);
        let mut buf = [0u8; 1];
        assert!(timeout(Duration::from_millis(25), peer.read(&mut buf))
            .await
            .is_err());
        Ok(())
    }
}
