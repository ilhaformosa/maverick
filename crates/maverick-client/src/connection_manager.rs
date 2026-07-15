use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use maverick_core::ClientConfig;
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::time::timeout;
use tracing::debug;

use crate::transport::{self, H2TunnelRequestSender, TransportKind};
use crate::tunnel::{self, ClientTunnel};

const MAX_READY_ATTEMPTS: usize = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H2ConnectionPoolSnapshot {
    pub connections_created: u64,
    pub streams_opened: u64,
    pub streams_reused: u64,
    pub reconnects: u64,
    pub readiness_failures: u64,
    pub stream_open_failures: u64,
    pub handshake_timeouts: u64,
    pub idle_retirements: u64,
    pub closed_retirements: u64,
    pub active_streams: u32,
    pub cached_connection: bool,
    pub shutdown: bool,
}

pub(crate) struct ClientTunnelPool {
    config: Arc<ClientConfig>,
    h2: H2ConnectionManager,
}

impl ClientTunnelPool {
    pub(crate) fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            h2: H2ConnectionManager::new(Arc::clone(&config)),
            config,
        }
    }

    pub(crate) fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub(crate) async fn open(&self) -> Result<ClientTunnel> {
        match transport::default_transport_kind(&self.config) {
            TransportKind::H2 => self.open_h2().await,
            TransportKind::CloudflareWs | TransportKind::H3 => tunnel::open(&self.config).await,
        }
    }

    async fn open_h2(&self) -> Result<ClientTunnel> {
        let mut last_error = None;
        for _ in 0..MAX_READY_ATTEMPTS {
            let managed = self.h2.acquire().await?;
            let generation = managed.generation;
            match timeout(
                Duration::from_millis(self.config.advanced.connect_timeout_ms),
                tunnel::open_managed_h2(&self.config, managed),
            )
            .await
            {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                Ok(Err(err)) if err.downcast_ref::<h2::Error>().is_some() => {
                    self.h2.invalidate_after_stream_open_failure(generation);
                    last_error = Some(err.context("pooled H2 stream open failed"));
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    self.h2.record_handshake_timeout();
                    bail!("pooled H2 tunnel handshake timed out");
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("pooled H2 stream open failed")))
    }

    pub(crate) fn h2_snapshot(&self) -> H2ConnectionPoolSnapshot {
        self.h2.snapshot()
    }

    pub(crate) fn shutdown(&self) {
        self.h2.shutdown();
    }
}

struct H2ConnectionManager {
    inner: Arc<H2ConnectionManagerInner>,
}

struct H2ConnectionManagerInner {
    config: Arc<ClientConfig>,
    connect_gate: AsyncMutex<()>,
    state: Mutex<H2ConnectionPoolState>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Default)]
struct H2ConnectionPoolState {
    connection: Option<CachedH2Connection>,
    next_generation: u64,
    connections_created: u64,
    streams_opened: u64,
    streams_reused: u64,
    reconnects: u64,
    readiness_failures: u64,
    stream_open_failures: u64,
    handshake_timeouts: u64,
    idle_retirements: u64,
    closed_retirements: u64,
    active_streams: u32,
    shutdown: bool,
}

struct CachedH2Connection {
    generation: u64,
    sender: h2::client::SendRequest<bytes::Bytes>,
    channel_binding: Option<maverick_core::auth::TlsChannelBinding>,
    connection_closed: watch::Receiver<bool>,
    active_streams: u32,
    idle_since: Option<Instant>,
}

struct H2Checkout {
    generation: u64,
    transport: H2TunnelRequestSender,
    lease: H2ConnectionLease,
}

pub(crate) struct ManagedH2TunnelRequestSender {
    pub(crate) transport: H2TunnelRequestSender,
    pub(crate) lease: H2ConnectionLease,
    generation: u64,
}

pub(crate) struct H2ConnectionLease {
    inner: Weak<H2ConnectionManagerInner>,
    generation: u64,
}

impl Drop for H2ConnectionLease {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut state = lock_state(&inner.state);
        state.active_streams = state.active_streams.saturating_sub(1);
        let Some(connection) = state.connection.as_mut() else {
            return;
        };
        if connection.generation != self.generation {
            return;
        }
        connection.active_streams = connection.active_streams.saturating_sub(1);
        if connection.active_streams == 0 {
            connection.idle_since = Some(Instant::now());
        }
    }
}

impl H2ConnectionManager {
    fn new(config: Arc<ClientConfig>) -> Self {
        let connect_timeout = Duration::from_millis(config.advanced.connect_timeout_ms);
        let idle_timeout = Duration::from_secs(config.advanced.idle_timeout_secs);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let inner = Arc::new(H2ConnectionManagerInner {
            config,
            connect_gate: AsyncMutex::new(()),
            state: Mutex::new(H2ConnectionPoolState::default()),
            connect_timeout,
            idle_timeout,
            shutdown_tx,
        });
        spawn_idle_maintenance(&inner, shutdown_rx);
        Self { inner }
    }

    async fn acquire(&self) -> Result<ManagedH2TunnelRequestSender> {
        let mut last_error = None;
        for _ in 0..MAX_READY_ATTEMPTS {
            let checkout = self.checkout_or_connect().await?;
            let generation = checkout.generation;
            let H2TunnelRequestSender {
                sender,
                channel_binding,
            } = checkout.transport;
            match timeout(self.inner.connect_timeout, sender.ready()).await {
                Ok(Ok(sender)) => {
                    return Ok(ManagedH2TunnelRequestSender {
                        transport: H2TunnelRequestSender {
                            sender,
                            channel_binding,
                        },
                        lease: checkout.lease,
                        generation,
                    });
                }
                Ok(Err(err)) => {
                    self.invalidate_after_readiness_failure(generation);
                    last_error =
                        Some(anyhow::Error::new(err).context("pooled H2 connection closed"));
                }
                Err(_) => bail!("pooled H2 stream acquisition timed out"),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("pooled H2 stream acquisition failed")))
    }

    async fn checkout_or_connect(&self) -> Result<H2Checkout> {
        if let Some(checkout) = self.checkout_cached()? {
            return Ok(checkout);
        }

        let _connect_guard = timeout(self.inner.connect_timeout, self.inner.connect_gate.lock())
            .await
            .context("waiting for pooled H2 connection timed out")?;
        if let Some(checkout) = self.checkout_cached()? {
            return Ok(checkout);
        }

        let connection = crate::h2_transport::connect_with_status(&self.inner.config).await?;
        self.install_and_checkout(connection)
    }

    fn checkout_cached(&self) -> Result<Option<H2Checkout>> {
        let mut state = lock_state(&self.inner.state);
        if state.shutdown {
            bail!("H2 connection pool is shut down");
        }
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| *connection.connection_closed.borrow())
        {
            state.connection.take();
            state.closed_retirements = state.closed_retirements.saturating_add(1);
        }
        let Some(connection) = state.connection.as_mut() else {
            return Ok(None);
        };
        connection.active_streams = connection.active_streams.saturating_add(1);
        connection.idle_since = None;
        let generation = connection.generation;
        let sender = connection.sender.clone();
        let channel_binding = connection.channel_binding;
        state.active_streams = state.active_streams.saturating_add(1);
        state.streams_opened = state.streams_opened.saturating_add(1);
        state.streams_reused = state.streams_reused.saturating_add(1);
        Ok(Some(H2Checkout {
            generation,
            transport: H2TunnelRequestSender {
                sender,
                channel_binding,
            },
            lease: H2ConnectionLease {
                inner: Arc::downgrade(&self.inner),
                generation,
            },
        }))
    }

    fn install_and_checkout(
        &self,
        connection: crate::h2_transport::H2Connection,
    ) -> Result<H2Checkout> {
        let transport = connection.transport;
        let mut state = lock_state(&self.inner.state);
        if state.shutdown {
            bail!("H2 connection pool is shut down");
        }
        if state.connection.is_some() {
            bail!("H2 connection pool changed while connecting");
        }
        state.next_generation = state.next_generation.saturating_add(1);
        let generation = state.next_generation;
        if state.connections_created > 0 {
            state.reconnects = state.reconnects.saturating_add(1);
        }
        state.connections_created = state.connections_created.saturating_add(1);
        state.streams_opened = state.streams_opened.saturating_add(1);
        state.active_streams = state.active_streams.saturating_add(1);
        state.connection = Some(CachedH2Connection {
            generation,
            sender: transport.sender.clone(),
            channel_binding: transport.channel_binding,
            connection_closed: connection.connection_closed,
            active_streams: 1,
            idle_since: None,
        });
        debug!(generation, "created pooled H2 connection");
        Ok(H2Checkout {
            generation,
            transport,
            lease: H2ConnectionLease {
                inner: Arc::downgrade(&self.inner),
                generation,
            },
        })
    }

    fn invalidate_after_readiness_failure(&self, generation: u64) {
        let mut state = lock_state(&self.inner.state);
        state.readiness_failures = state.readiness_failures.saturating_add(1);
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| connection.generation == generation)
        {
            state.connection.take();
        }
    }

    fn invalidate_after_stream_open_failure(&self, generation: u64) {
        let mut state = lock_state(&self.inner.state);
        state.stream_open_failures = state.stream_open_failures.saturating_add(1);
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| connection.generation == generation)
        {
            state.connection.take();
        }
    }

    fn record_handshake_timeout(&self) {
        let mut state = lock_state(&self.inner.state);
        state.handshake_timeouts = state.handshake_timeouts.saturating_add(1);
    }

    fn snapshot(&self) -> H2ConnectionPoolSnapshot {
        let state = lock_state(&self.inner.state);
        H2ConnectionPoolSnapshot {
            connections_created: state.connections_created,
            streams_opened: state.streams_opened,
            streams_reused: state.streams_reused,
            reconnects: state.reconnects,
            readiness_failures: state.readiness_failures,
            stream_open_failures: state.stream_open_failures,
            handshake_timeouts: state.handshake_timeouts,
            idle_retirements: state.idle_retirements,
            closed_retirements: state.closed_retirements,
            active_streams: state.active_streams,
            cached_connection: state.connection.is_some(),
            shutdown: state.shutdown,
        }
    }

    fn shutdown(&self) {
        let mut state = lock_state(&self.inner.state);
        state.shutdown = true;
        state.connection.take();
        drop(state);
        let _ = self.inner.shutdown_tx.send(true);
    }
}

fn spawn_idle_maintenance(
    inner: &Arc<H2ConnectionManagerInner>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let weak = Arc::downgrade(inner);
    let interval = maintenance_interval(inner.idle_timeout);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    retire_inactive_connection(&inner);
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

fn maintenance_interval(idle_timeout: Duration) -> Duration {
    (idle_timeout / 2).clamp(Duration::from_millis(10), Duration::from_secs(1))
}

fn retire_inactive_connection(inner: &H2ConnectionManagerInner) {
    let mut state = lock_state(&inner.state);
    let Some(connection) = state.connection.as_ref() else {
        return;
    };
    if *connection.connection_closed.borrow() {
        state.connection.take();
        state.closed_retirements = state.closed_retirements.saturating_add(1);
        debug!("retired closed pooled H2 connection");
        return;
    }
    let idle_elapsed = connection
        .idle_since
        .is_some_and(|idle_since| idle_since.elapsed() >= inner.idle_timeout);
    if connection.active_streams == 0 && idle_elapsed {
        state.connection.take();
        state.idle_retirements = state.idle_retirements.saturating_add(1);
        debug!("retired idle pooled H2 connection");
    }
}

fn lock_state(state: &Mutex<H2ConnectionPoolState>) -> MutexGuard<'_, H2ConnectionPoolState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        ClientAdvancedConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{Mode, SecretString};

    fn test_config() -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
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
                credential_id: "u_pool".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        })
    }

    #[tokio::test]
    async fn shutdown_closes_pool_for_new_checkouts() {
        let pool = ClientTunnelPool::new(test_config());
        pool.shutdown();

        let snapshot = pool.h2_snapshot();
        assert!(snapshot.shutdown);
        assert!(!snapshot.cached_connection);
        assert!(pool.open().await.is_err());
    }

    #[test]
    fn maintenance_interval_is_bounded() {
        assert_eq!(
            maintenance_interval(Duration::from_millis(1)),
            Duration::from_millis(10)
        );
        assert_eq!(
            maintenance_interval(Duration::from_secs(10)),
            Duration::from_secs(1)
        );
    }
}
