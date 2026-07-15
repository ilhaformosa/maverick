//! Maverick local client.

#![forbid(unsafe_code)]

pub mod connection_manager;
pub mod dns;
pub mod h2_transport;
#[cfg(feature = "h3")]
pub mod h3_transport;
pub mod http_connect;
pub mod scheduler;
pub mod session;
pub mod socks5;
pub mod transport;
#[cfg(feature = "tun-runtime")]
mod tun_runtime;
pub mod tunnel;
pub mod udp;
pub mod ws_transport;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use maverick_core::ClientConfig;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use connection_manager::{ClientTunnelPool, H2ConnectionPoolSnapshot};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

pub struct ClientHandle {
    pub local_addr: SocketAddr,
    pub dns_addr: Option<SocketAddr>,
    pub http_connect_addr: Option<SocketAddr>,
    shutdowns: Vec<oneshot::Sender<()>>,
    joins: Vec<tokio::task::JoinHandle<Result<()>>>,
    tunnel_pool: Arc<ClientTunnelPool>,
    #[cfg(feature = "tun-runtime")]
    flow_limit: Arc<Semaphore>,
    #[cfg(feature = "tun-runtime")]
    tun_runtime: Option<maverick_tun::PacketRuntimeHandle>,
    #[cfg(feature = "tun-runtime")]
    tun_connector: Option<Arc<tun_runtime::MaverickTunConnector>>,
}

impl ClientHandle {
    pub fn h2_connection_pool_snapshot(&self) -> H2ConnectionPoolSnapshot {
        self.tunnel_pool.h2_snapshot()
    }

    #[cfg(feature = "tun-runtime")]
    pub fn tun_runtime_snapshot(&self) -> Option<maverick_tun::PacketRuntimeSnapshot> {
        self.tun_runtime.as_ref().map(|runtime| runtime.snapshot())
    }

    #[cfg(feature = "tun-runtime")]
    pub async fn start_tun_runtime(
        &mut self,
        mut runtime_config: maverick_tun::PacketRuntimeConfig,
        io: maverick_tun::PacketIo,
    ) -> Result<()> {
        anyhow::ensure!(
            self.tunnel_pool.config().advanced.experimental_tun,
            "advanced.experimental_tun must be enabled"
        );
        anyhow::ensure!(
            self.tun_runtime.is_none(),
            "TUN packet runtime is already started"
        );
        let shared_limit = self.tunnel_pool.config().advanced.max_concurrent_flows as usize;
        runtime_config.max_tcp_flows = runtime_config.max_tcp_flows.min(shared_limit);
        runtime_config.max_udp_associations = runtime_config.max_udp_associations.min(shared_limit);
        runtime_config.max_dns_queries = runtime_config.max_dns_queries.min(shared_limit);
        let max_tcp_tasks = runtime_config.max_tcp_flows;
        let connector = Arc::new(tun_runtime::MaverickTunConnector::new(
            Arc::clone(&self.tunnel_pool),
            Arc::clone(&self.flow_limit),
            runtime_config.tcp_buffer_bytes,
            runtime_config.dns_timeout,
            runtime_config.shutdown_timeout,
            max_tcp_tasks,
        ));
        let flow_connector: Arc<dyn maverick_tun::FlowConnector> = connector.clone();
        let runtime = maverick_tun::start_packet_runtime(runtime_config, io, flow_connector)
            .map_err(anyhow::Error::from)?;
        self.tun_connector = Some(connector);
        self.tun_runtime = Some(runtime);
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        for tx in self.shutdowns.drain(..) {
            let _ = tx.send(());
        }
        #[cfg(feature = "tun-runtime")]
        let tun_result = match self.tun_runtime.take() {
            Some(runtime) => runtime
                .shutdown()
                .await
                .map(|_| ())
                .map_err(anyhow::Error::from),
            None => Ok(()),
        };
        #[cfg(feature = "tun-runtime")]
        let connector_result = match self.tun_connector.take() {
            Some(connector) => connector.shutdown().await,
            None => Ok(()),
        };
        self.tunnel_pool.shutdown();
        let mut join_result = Ok(());
        for join in self.joins {
            let result = match join.await {
                Ok(result) => result,
                Err(err) => Err(anyhow::Error::from(err)),
            };
            if let Err(err) = result {
                if join_result.is_ok() {
                    join_result = Err(err);
                }
            }
        }
        #[cfg(feature = "tun-runtime")]
        tun_result?;
        #[cfg(feature = "tun-runtime")]
        connector_result?;
        join_result
    }
}

pub async fn start_client(config: ClientConfig) -> Result<ClientHandle> {
    config.validate().map_err(anyhow::Error::from)?;
    #[cfg(not(feature = "tun-runtime"))]
    anyhow::ensure!(
        !config.advanced.experimental_tun,
        "advanced.experimental_tun requires the tun-runtime build feature"
    );
    let listener = TcpListener::bind(config.local.socks5.listen).await?;
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        warn!(
            listen = %local_addr,
            "SOCKS5 listener is not loopback-only; protect this port explicitly"
        );
    }
    let flow_limit = Arc::new(Semaphore::new(
        config.advanced.max_concurrent_flows as usize,
    ));
    let config = Arc::new(config);
    let tunnel_pool = Arc::new(ClientTunnelPool::new(Arc::clone(&config)));
    let (socks_shutdown_tx, socks_shutdown_rx) = oneshot::channel();
    let socks_tunnel_pool = Arc::clone(&tunnel_pool);
    let socks_flow_limit = Arc::clone(&flow_limit);
    let socks_join = tokio::spawn(async move {
        serve_socks(
            listener,
            socks_tunnel_pool,
            socks_flow_limit,
            socks_shutdown_rx,
        )
        .await
    });

    let mut shutdowns = vec![socks_shutdown_tx];
    let mut joins = vec![socks_join];
    let mut dns_addr = None;
    let mut http_connect_addr = None;

    if let Some(dns_config) = &config.local.dns {
        if dns_config.enabled {
            if let Some(listen) = dns_config.listen {
                let socket = UdpSocket::bind(listen).await?;
                let addr = socket.local_addr()?;
                if !addr.ip().is_loopback() {
                    warn!(
                        listen = %addr,
                        "DNS listener is not loopback-only; protect this port explicitly"
                    );
                }
                let (dns_shutdown_tx, dns_shutdown_rx) = oneshot::channel();
                let dns_tunnel_pool = Arc::clone(&tunnel_pool);
                let dns_flow_limit = Arc::clone(&flow_limit);
                let dns_join = tokio::spawn(async move {
                    dns::serve_dns_with_pool(
                        socket,
                        dns_tunnel_pool,
                        dns_flow_limit,
                        dns_shutdown_rx,
                    )
                    .await
                });
                shutdowns.push(dns_shutdown_tx);
                joins.push(dns_join);
                dns_addr = Some(addr);
            }
        }
    }
    if let Some(http_config) = &config.local.http_connect {
        if http_config.enabled {
            if let Some(listen) = http_config.listen {
                let listener = TcpListener::bind(listen).await?;
                let addr = listener.local_addr()?;
                if !addr.ip().is_loopback() {
                    warn!(
                        listen = %addr,
                        "HTTP CONNECT listener is not loopback-only; protect this port explicitly"
                    );
                }
                let (http_shutdown_tx, http_shutdown_rx) = oneshot::channel();
                let http_tunnel_pool = Arc::clone(&tunnel_pool);
                let http_flow_limit = Arc::clone(&flow_limit);
                let http_join = tokio::spawn(async move {
                    http_connect::serve_http_connect_with_pool(
                        listener,
                        http_tunnel_pool,
                        http_flow_limit,
                        http_shutdown_rx,
                    )
                    .await
                });
                shutdowns.push(http_shutdown_tx);
                joins.push(http_join);
                http_connect_addr = Some(addr);
            }
        }
    }

    Ok(ClientHandle {
        local_addr,
        dns_addr,
        http_connect_addr,
        shutdowns,
        joins,
        tunnel_pool,
        #[cfg(feature = "tun-runtime")]
        flow_limit,
        #[cfg(feature = "tun-runtime")]
        tun_runtime: None,
        #[cfg(feature = "tun-runtime")]
        tun_connector: None,
    })
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let handle = start_client(config).await?;
    info!(listen = %handle.local_addr, "Maverick SOCKS5 client listening");
    if let Some(dns_addr) = handle.dns_addr {
        info!(listen = %dns_addr, "Maverick DNS relay listening");
    }
    if let Some(http_addr) = handle.http_connect_addr {
        info!(listen = %http_addr, "Maverick HTTP CONNECT client listening");
    }
    tokio::signal::ctrl_c().await?;
    handle.shutdown().await
}

async fn serve_socks(
    listener: TcpListener,
    tunnel_pool: Arc<ClientTunnelPool>,
    flow_limit: Arc<Semaphore>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut connection_tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Maverick client shutdown requested");
                break;
            }
            joined = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(joined) = joined {
                    joined?;
                }
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(error = %err, "SOCKS5 accept failed");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                if !allows_local_listener_peer(peer) {
                    warn!(%peer, "rejected non-loopback SOCKS5 peer");
                    continue;
                }
                let Some(flow_permit) = try_client_flow_permit(&flow_limit) else {
                    debug!(%peer, "SOCKS5 connection rejected by client flow limit");
                    continue;
                };
                let tunnel_pool = Arc::clone(&tunnel_pool);
                connection_tasks.spawn(async move {
                    if let Err(err) = session::handle_socks_connection_with_pool(stream, tunnel_pool, flow_permit).await {
                        tracing::debug!(%peer, error = %err, "SOCKS connection ended");
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

pub(crate) fn try_client_flow_permit(flow_limit: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    flow_limit.clone().try_acquire_owned().ok()
}

pub(crate) fn allows_local_listener_peer(peer: SocketAddr) -> bool {
    peer.ip().is_loopback()
}

pub(crate) async fn backoff_after_listener_error() {
    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
}

#[cfg(all(test, not(feature = "tun-runtime")))]
mod build_gate_tests {
    use super::*;
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{Mode, SecretString};

    #[tokio::test]
    async fn tun_runtime_config_requires_build_feature() {
        let advanced = ClientAdvancedConfig {
            experimental_tun: true,
            ..ClientAdvancedConfig::default()
        };
        let config = ClientConfig {
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
                credential_id: "u_build_gate".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced,
        };

        let err = match start_client(config).await {
            Ok(handle) => {
                handle.shutdown().await.unwrap();
                panic!("TUN config unexpectedly started without build feature");
            }
            Err(err) => err,
        };

        assert!(err.to_string().contains("tun-runtime build feature"));
    }
}
