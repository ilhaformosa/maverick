//! Shared full-session checks for the local handshake experiments only.
use super::MaverickHarness;
use anyhow::{ensure, Context, Result};
use maverick_client::connector::TcpSession;
use maverick_client::connector::{Bytes, UdpCarrier, UdpSession};
use maverick_client::transport::TransportKind;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

pub const PAYLOAD_SIZE: usize = 512 * 1024;

#[derive(serde::Serialize)]
pub struct UdpObservation {
    carrier: &'static str,
    payload_limit: usize,
    upload_datagrams: usize,
    download_datagrams: usize,
    upload_bytes: usize,
    download_bytes: usize,
    cancelled: bool,
}

pub async fn udp_target() -> Result<UdpSocket> {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    // macOS's ordinary UDP send buffer cannot send the maximum H2 payload.
    // These are process-owned socket options, never host network settings.
    let options = socket2::SockRef::from(&socket);
    options.set_send_buffer_size(131_072)?;
    options.set_recv_buffer_size(131_072)?;
    Ok(socket)
}

pub async fn transfer_udp(
    mut session: UdpSession,
    target: &UdpSocket,
    carrier: UdpCarrier,
    cancel: bool,
) -> Result<UdpObservation> {
    ensure!(session.carrier() == carrier, "unexpected UDP carrier");
    let maximum = session.max_payload();
    ensure!(maximum > 0);
    match carrier {
        UdpCarrier::H2Reliable => ensure!(maximum == 65_507),
        UdpCarrier::H3Native => ensure!(maximum <= 1_200),
    }
    ensure!(
        !session.send(Bytes::from(vec![0; maximum + 1]))?,
        "oversized UDP accepted"
    );
    let mut buffer = vec![0; 65_535];
    let mut source = None;
    let mut upload_bytes = 0;
    // Receive every accepted packet before sending another; native UDP remains
    // unreliable and this test does not impose an ordering/retransmission policy.
    for (index, size) in [0, 1, maximum.min(1024), maximum].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size)
            .map(|offset| ((offset + index) % 251) as u8)
            .collect();
        ensure!(session.send(Bytes::copy_from_slice(&payload))?);
        let (count, peer) = target.recv_from(&mut buffer).await?;
        ensure!(buffer[..count] == payload, "UDP upload content mismatch");
        if let Some(source) = source {
            ensure!(peer == source, "UDP source port changed");
        }
        source = Some(peer);
        upload_bytes += count;
    }
    let source = source.context("no UDP source observed")?;
    let mut download_bytes = 0;
    // Five independent replies after four uploads: not request/response pairing.
    for (index, size) in [maximum, 0, 1, maximum.min(1024), maximum]
        .into_iter()
        .enumerate()
    {
        let payload: Vec<u8> = (0..size)
            .map(|offset| ((offset + index + 17) % 251) as u8)
            .collect();
        ensure!(target.send_to(&payload, source).await? == payload.len());
        ensure!(
            session.recv().await?.as_ref() == payload,
            "UDP download content mismatch"
        );
        download_bytes += size;
    }
    ensure!(
        timeout(Duration::from_millis(60), target.recv_from(&mut buffer))
            .await
            .is_err(),
        "unexpected UDP upload or replay"
    );
    if cancel {
        drop(session);
    } else {
        session.close().await?;
    }
    timeout(Duration::from_secs(3), async {
        loop {
            match UdpSocket::bind(source).await {
                Ok(socket) => {
                    drop(socket);
                    return Ok::<_, anyhow::Error>(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("UDP target source socket did not release")??;
    Ok(UdpObservation {
        carrier: match carrier {
            UdpCarrier::H2Reliable => "h2_reliable",
            UdpCarrier::H3Native => "h3_native",
        },
        payload_limit: maximum,
        upload_datagrams: 4,
        download_datagrams: 5,
        upload_bytes,
        download_bytes,
        cancelled: cancel,
    })
}

pub async fn metrics(harness: &MaverickHarness) -> Result<serde_json::Value> {
    let mut socket = TcpStream::connect(harness.server.metrics_addr.context("no metrics")?).await?;
    socket
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = String::new();
    socket.read_to_string(&mut response).await?;
    Ok(serde_json::from_str(
        response
            .split_once("\r\n\r\n")
            .context("invalid metrics HTTP")?
            .1,
    )?)
}

pub async fn drained(harness: &MaverickHarness) -> Result<serde_json::Value> {
    timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = metrics(harness).await?;
            if [
                "active_connections",
                "active_flows",
                "active_pre_auth",
                "active_fallbacks",
            ]
            .iter()
            .all(|key| snapshot[key] == 0)
            {
                return Ok(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("server resources did not drain")?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    socket: S,
    outgoing: &[u8],
    expected: &[u8],
) -> Result<()> {
    let (mut read, mut write) = tokio::io::split(socket);
    let send = async {
        write.write_all(outgoing).await?;
        write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let receive = async {
        let mut received = vec![0; expected.len()];
        read.read_exact(&mut received).await?;
        ensure!(received == expected, "application content mismatch");
        ensure!(
            read.read(&mut [0; 1]).await? == 0,
            "unexpected trailing data"
        );
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(send, receive)?;
    Ok(())
}

pub async fn transfer(
    session: TcpSession,
    target: &TcpListener,
    target_first: Option<bool>,
    carrier: TransportKind,
) -> Result<()> {
    ensure!(session.carrier() == carrier, "unexpected carrier");
    let (mut app, local) = tokio::io::duplex(4096);
    let (mut peer, _) = target.accept().await?;
    let upload: Vec<u8> = (0..PAYLOAD_SIZE).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = upload.iter().map(|value| value ^ 0xa5).collect();
    if let Some(target_first) = target_first {
        // Force each half-close order before allowing data in the other direction.
        let application = async {
            if !target_first {
                app.write_all(&upload).await?;
                app.shutdown().await?;
            }
            let mut received = vec![0; download.len()];
            app.read_exact(&mut received).await?;
            ensure!(received == download);
            ensure!(app.read(&mut [0; 1]).await? == 0);
            if target_first {
                app.write_all(&upload).await?;
                app.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let origin = async {
            if target_first {
                peer.write_all(&download).await?;
                peer.shutdown().await?;
            }
            let mut received = vec![0; upload.len()];
            peer.read_exact(&mut received).await?;
            ensure!(received == upload);
            ensure!(peer.read(&mut [0; 1]).await? == 0);
            if !target_first {
                peer.write_all(&download).await?;
                peer.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(session.relay(local), application, origin)?;
    } else {
        tokio::try_join!(
            session.relay(local),
            exchange(app, &upload, &download),
            exchange(peer, &download, &upload)
        )?;
    }
    Ok(())
}
