use std::sync::Arc;

use anyhow::{bail, Result};
use bytes::Bytes;
use maverick_core::frame::{Frame, FrameType};
use maverick_core::ClientConfig;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::tunnel;
use crate::ClientTunnelPool;

const DNS_FLOW_ID: u64 = 1;
const MAX_DNS_PACKET_SIZE: usize = 65_535;

pub async fn serve_dns(
    socket: UdpSocket,
    config: Arc<ClientConfig>,
    flow_limit: Arc<Semaphore>,
    shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let tunnel_pool = Arc::new(ClientTunnelPool::new(config));
    let result = serve_dns_with_pool(socket, Arc::clone(&tunnel_pool), flow_limit, shutdown).await;
    tunnel_pool.shutdown();
    result
}

pub(crate) async fn serve_dns_with_pool(
    socket: UdpSocket,
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_limit: Arc<Semaphore>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let socket = Arc::new(socket);
    let mut query_tasks = JoinSet::new();
    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            joined = query_tasks.join_next(), if !query_tasks.is_empty() => {
                if let Some(joined) = joined {
                    joined?;
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, peer) = match recv {
                    Ok(received) => received,
                    Err(err) => {
                        debug!(error = %err, "DNS relay recv failed");
                        crate::backoff_after_listener_error().await;
                        continue;
                    }
                };
                if !crate::allows_local_listener_peer(peer) {
                    warn!(%peer, "rejected non-loopback DNS peer");
                    continue;
                }
                let query = Bytes::copy_from_slice(&buf[..len]);
                let socket = Arc::clone(&socket);
                let tunnel_pool = Arc::clone(&tunnel_pool);
                let flow_limit = Arc::clone(&flow_limit);
                let flow_permit = match flow_limit.try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(%peer, "DNS relay query rejected by client flow limit");
                        continue;
                    }
                };
                query_tasks.spawn(async move {
                    let _flow_permit = flow_permit;
                    match resolve_via_pool(&tunnel_pool, query).await {
                        Ok(response) => {
                            let _ = socket.send_to(&response, peer).await;
                        }
                        Err(err) => {
                            debug!(error = %err, "DNS relay query failed");
                        }
                    }
                });
            }
        }
    }
    query_tasks.abort_all();
    while let Some(joined) = query_tasks.join_next().await {
        if let Err(err) = joined {
            if !err.is_cancelled() {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

pub async fn resolve_via_tunnel(config: &ClientConfig, query: Bytes) -> Result<Bytes> {
    resolve_with_tunnel(tunnel::open(config).await?, query).await
}

pub(crate) async fn resolve_via_pool(pool: &ClientTunnelPool, query: Bytes) -> Result<Bytes> {
    resolve_with_tunnel(pool.open().await?, query).await
}

async fn resolve_with_tunnel(mut tunnel: tunnel::ClientTunnel, query: Bytes) -> Result<Bytes> {
    tunnel
        .send_frame(Frame::new(FrameType::DnsQuery, 0, DNS_FLOW_ID, query), true)
        .await?;

    match tunnel.read_next_frame().await? {
        Some(frame)
            if frame.frame_type == FrameType::DnsResponse && frame.flow_id == DNS_FLOW_ID =>
        {
            Ok(frame.payload)
        }
        Some(frame) if frame.frame_type == FrameType::Error => bail!("DNS relay failed"),
        _ => bail!("server closed before DNS response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{Mode, SecretString};
    use tokio::time::{timeout, Duration};

    fn test_config() -> ClientConfig {
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
                credential_id: "u_dns".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }

    #[tokio::test]
    async fn dns_query_is_rejected_when_flow_limit_is_exhausted() -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let dns_addr = socket.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(serve_dns(
            socket,
            Arc::new(test_config()),
            Arc::new(Semaphore::new(0)),
            shutdown_rx,
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.send_to(b"query", dns_addr).await?;
        let mut response = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(100), client.recv_from(&mut response))
                .await
                .is_err()
        );

        let _ = shutdown_tx.send(());
        join.await??;
        Ok(())
    }
}
