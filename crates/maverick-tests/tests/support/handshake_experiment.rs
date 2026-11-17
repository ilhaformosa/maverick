//! Shared full-session checks for the local handshake experiments only.
use super::MaverickHarness;
use anyhow::{ensure, Context, Result};
use maverick_client::connector::TcpSession;
use maverick_client::transport::TransportKind;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub const PAYLOAD_SIZE: usize = 512 * 1024;

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
