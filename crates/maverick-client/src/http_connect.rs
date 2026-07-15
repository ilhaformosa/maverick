use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use maverick_core::frame::TargetAddr;
use maverick_core::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use crate::session::{handle_local_connect, ConnectReply};
use crate::ClientTunnelPool;

const MAX_CONNECT_HEADER_BYTES: usize = 8192;

pub async fn serve_http_connect(
    listener: TcpListener,
    config: Arc<ClientConfig>,
    flow_limit: Arc<Semaphore>,
    shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let tunnel_pool = Arc::new(ClientTunnelPool::new(config));
    let result =
        serve_http_connect_with_pool(listener, Arc::clone(&tunnel_pool), flow_limit, shutdown)
            .await;
    tunnel_pool.shutdown();
    result
}

pub(crate) async fn serve_http_connect_with_pool(
    listener: TcpListener,
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_limit: Arc<Semaphore>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut connection_tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            joined = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(joined) = joined {
                    joined?;
                }
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(error = %err, "HTTP CONNECT accept failed");
                        crate::backoff_after_listener_error().await;
                        continue;
                    }
                };
                if !crate::allows_local_listener_peer(peer) {
                    warn!(%peer, "rejected non-loopback HTTP CONNECT peer");
                    continue;
                }
                let Some(flow_permit) = crate::try_client_flow_permit(&flow_limit) else {
                    debug!(%peer, "HTTP CONNECT rejected by client flow limit");
                    continue;
                };
                let tunnel_pool = Arc::clone(&tunnel_pool);
                connection_tasks.spawn(async move {
                    if let Err(err) = handle_http_connect(stream, tunnel_pool, flow_permit).await {
                        debug!(%peer, error = %err, "HTTP CONNECT connection ended");
                    }
                });
            }
        }
    }
    connection_tasks.abort_all();
    while let Some(joined) = connection_tasks.join_next().await {
        if let Err(err) = joined {
            if !err.is_cancelled() {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

async fn handle_http_connect(
    mut stream: TcpStream,
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_permit: OwnedSemaphorePermit,
) -> Result<()> {
    let read_timeout = Duration::from_millis(tunnel_pool.config().advanced.connect_timeout_ms);
    let (target, port, initial_data) =
        match timeout(read_timeout, read_connect_target(&mut stream)).await {
            Ok(Ok(target)) => target,
            Ok(Err(err)) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                    .await;
                return Err(err);
            }
            Err(_) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                    .await;
                bail!("HTTP CONNECT request timed out");
            }
        };
    handle_local_connect(
        stream,
        tunnel_pool,
        target,
        port,
        ConnectReply::HttpConnect,
        initial_data,
        flow_permit,
    )
    .await
}

async fn read_connect_target(stream: &mut TcpStream) -> Result<(TargetAddr, u16, Bytes)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            bail!("client disconnected before CONNECT headers");
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if data.len() > MAX_CONNECT_HEADER_BYTES {
            bail!("CONNECT headers too large");
        }
    }
    parse_connect_request_bytes(&data)
}

fn parse_connect_request_bytes(data: &[u8]) -> Result<(TargetAddr, u16, Bytes)> {
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("CONNECT header terminator missing")?;
    let text = std::str::from_utf8(&data[..header_end]).context("CONNECT headers are not utf-8")?;
    let first_line = text.lines().next().context("missing request line")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().context("missing method")?;
    let authority = parts.next().context("missing authority")?;
    let version = parts.next().context("missing HTTP version")?;
    if method != "CONNECT" || !version.starts_with("HTTP/") {
        bail!("not an HTTP CONNECT request");
    }
    let (target, port) = parse_authority(authority)?;
    let initial_data = Bytes::copy_from_slice(&data[header_end + 4..]);
    Ok((target, port, initial_data))
}

fn parse_authority(authority: &str) -> Result<(TargetAddr, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("invalid IPv6 CONNECT authority")?;
        let addr: Ipv6Addr = host.parse().context("invalid IPv6 address")?;
        let port = port.parse().context("invalid CONNECT port")?;
        return Ok((TargetAddr::Ipv6(addr), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .context("CONNECT authority must include port")?;
    let port = port.parse().context("invalid CONNECT port")?;
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        Ok((TargetAddr::Ipv4(addr), port))
    } else if let Ok(addr) = host.parse::<Ipv6Addr>() {
        Ok((TargetAddr::Ipv6(addr), port))
    } else {
        Ok((TargetAddr::Domain(host.to_owned()), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_domain_authority() {
        let (target, port) = parse_authority("example.com:443").unwrap();
        assert_eq!(target, TargetAddr::Domain("example.com".into()));
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_ipv4_authority() {
        let (target, port) = parse_authority("127.0.0.1:8080").unwrap();
        assert_eq!(target, TargetAddr::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_connect_preserves_early_data_after_headers() {
        let (target, port, initial_data) = parse_connect_request_bytes(
            b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com\r\n\r\nearly-data",
        )
        .unwrap();
        assert_eq!(target, TargetAddr::Domain("example.com".into()));
        assert_eq!(port, 443);
        assert_eq!(initial_data, Bytes::from_static(b"early-data"));
    }
}
