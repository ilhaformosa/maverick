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
pub const H2_DURATION_BUCKET_UPPER_BOUNDS_MS: [u64; 10] =
    [10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];
const H2_DURATION_BUCKET_COUNT: usize = H2_DURATION_BUCKET_UPPER_BOUNDS_MS.len() + 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H2DurationHistogramSnapshot {
    pub count: u64,
    pub sum_ms: u64,
    pub buckets: [u64; H2_DURATION_BUCKET_COUNT],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H2ConnectionPoolSnapshot {
    pub connections_created: u64,
    pub streams_opened: u64,
    pub streams_reused: u64,
    pub reconnects: u64,
    pub readiness_failures: u64,
    pub stream_open_failures: u64,
    pub handshake_timeouts: u64,
    pub timeout_retirements: u64,
    pub timeout_recoveries: u64,
    pub idle_retirements: u64,
    pub closed_retirements: u64,
    pub runtime_stream_resets: u64,
    pub runtime_send_stalls: u64,
    pub connection_setup_duration_ms: H2DurationHistogramSnapshot,
    pub tunnel_open_duration_ms: H2DurationHistogramSnapshot,
    pub active_streams: u32,
    pub cached_connection: bool,
    pub shutdown: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct H2PoolShutdownSnapshot {
    pub(crate) pool: H2ConnectionPoolSnapshot,
    pub(crate) pooled_h2_client_observed_outer_tls12_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls13_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_unknown_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_group_x25519_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_group_secp256r1_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_group_secp384r1_connections: u64,
    pub(crate) pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections: u64,
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
        let mut timeout_recovery_pending = false;
        for attempt in 0..MAX_READY_ATTEMPTS {
            let tunnel_open_started_at = Instant::now();
            let managed = self.h2.acquire().await?;
            let generation = managed.generation;
            match timeout(
                Duration::from_millis(self.config.advanced.connect_timeout_ms),
                tunnel::open_managed_h2(&self.config, managed),
            )
            .await
            {
                Ok(Ok(tunnel)) => {
                    self.h2
                        .record_tunnel_open_duration(tunnel_open_started_at.elapsed());
                    if timeout_recovery_pending {
                        self.h2.record_timeout_recovery();
                    }
                    return Ok(tunnel);
                }
                Ok(Err(err)) if err.downcast_ref::<tunnel::H2SendStalled>().is_some() => {
                    // A healthy connection at its peer-advertised concurrent
                    // stream limit can also stall here. Keep that generation
                    // cached instead of silently bypassing its capacity with
                    // another outer H2 connection.
                    let retired = self
                        .h2
                        .retire_after_handshake_timeout_if_unshared(generation);
                    let err = err.context("pooled H2 tunnel handshake timed out");
                    if retired && attempt + 1 < MAX_READY_ATTEMPTS {
                        timeout_recovery_pending = true;
                        last_error = Some(err);
                        continue;
                    }
                    return Err(err);
                }
                Ok(Err(err)) if err.downcast_ref::<h2::Error>().is_some() => {
                    self.h2.invalidate_after_stream_open_failure(generation);
                    last_error = Some(err.context("pooled H2 stream open failed"));
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    let retired = self
                        .h2
                        .retire_after_handshake_timeout_if_unshared(generation);
                    let err = anyhow::anyhow!("pooled H2 tunnel handshake timed out");
                    if retired && attempt + 1 < MAX_READY_ATTEMPTS {
                        timeout_recovery_pending = true;
                        last_error = Some(err);
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("pooled H2 stream open failed")))
    }

    pub(crate) fn h2_snapshot(&self) -> H2ConnectionPoolSnapshot {
        self.h2.snapshot()
    }

    pub(crate) fn h2_shutdown_snapshot(&self) -> H2PoolShutdownSnapshot {
        self.h2.shutdown_snapshot()
    }

    #[cfg(test)]
    pub(crate) fn test_h2_runtime_metrics_lease(&self) -> H2ConnectionLease {
        H2ConnectionLease {
            inner: Arc::downgrade(&self.h2.inner),
            generation: 0,
        }
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
    pooled_h2_client_observed_outer_tls12_connections: u64,
    pooled_h2_client_observed_outer_tls13_connections: u64,
    pooled_h2_client_observed_outer_tls_unknown_connections: u64,
    pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections: u64,
    pooled_h2_client_observed_outer_tls_group_x25519_connections: u64,
    pooled_h2_client_observed_outer_tls_group_secp256r1_connections: u64,
    pooled_h2_client_observed_outer_tls_group_secp384r1_connections: u64,
    pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections: u64,
    streams_opened: u64,
    streams_reused: u64,
    reconnects: u64,
    readiness_failures: u64,
    stream_open_failures: u64,
    handshake_timeouts: u64,
    timeout_retirements: u64,
    timeout_recoveries: u64,
    idle_retirements: u64,
    closed_retirements: u64,
    runtime_stream_resets: u64,
    runtime_send_stalls: u64,
    connection_setup_duration_ms: H2DurationHistogram,
    tunnel_open_duration_ms: H2DurationHistogram,
    active_streams: u32,
    shutdown: bool,
}

impl H2ConnectionPoolState {
    fn record_installed_connection(
        &mut self,
        observed_outer_tls_version: crate::h2_transport::ObservedOuterTlsVersion,
        observed_outer_tls_group: crate::h2_transport::ObservedOuterTlsGroup,
    ) {
        let next_connections_created = self.connections_created.saturating_add(1);
        if next_connections_created == self.connections_created {
            return;
        }
        self.connections_created = next_connections_created;
        match observed_outer_tls_version {
            crate::h2_transport::ObservedOuterTlsVersion::Tls12 => {
                self.pooled_h2_client_observed_outer_tls12_connections = self
                    .pooled_h2_client_observed_outer_tls12_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsVersion::Tls13 => {
                self.pooled_h2_client_observed_outer_tls13_connections = self
                    .pooled_h2_client_observed_outer_tls13_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsVersion::Unknown => {
                self.pooled_h2_client_observed_outer_tls_unknown_connections = self
                    .pooled_h2_client_observed_outer_tls_unknown_connections
                    .saturating_add(1);
            }
        }
        match observed_outer_tls_group {
            crate::h2_transport::ObservedOuterTlsGroup::X25519MlKem768 => {
                self.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections = self
                    .pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsGroup::X25519 => {
                self.pooled_h2_client_observed_outer_tls_group_x25519_connections = self
                    .pooled_h2_client_observed_outer_tls_group_x25519_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsGroup::Secp256r1 => {
                self.pooled_h2_client_observed_outer_tls_group_secp256r1_connections = self
                    .pooled_h2_client_observed_outer_tls_group_secp256r1_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsGroup::Secp384r1 => {
                self.pooled_h2_client_observed_outer_tls_group_secp384r1_connections = self
                    .pooled_h2_client_observed_outer_tls_group_secp384r1_connections
                    .saturating_add(1);
            }
            crate::h2_transport::ObservedOuterTlsGroup::OtherOrUnknown => {
                self.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections = self
                    .pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections
                    .saturating_add(1);
            }
        }
    }

    fn snapshot(&self) -> H2ConnectionPoolSnapshot {
        H2ConnectionPoolSnapshot {
            connections_created: self.connections_created,
            streams_opened: self.streams_opened,
            streams_reused: self.streams_reused,
            reconnects: self.reconnects,
            readiness_failures: self.readiness_failures,
            stream_open_failures: self.stream_open_failures,
            handshake_timeouts: self.handshake_timeouts,
            timeout_retirements: self.timeout_retirements,
            timeout_recoveries: self.timeout_recoveries,
            idle_retirements: self.idle_retirements,
            closed_retirements: self.closed_retirements,
            runtime_stream_resets: self.runtime_stream_resets,
            runtime_send_stalls: self.runtime_send_stalls,
            connection_setup_duration_ms: self.connection_setup_duration_ms.snapshot(),
            tunnel_open_duration_ms: self.tunnel_open_duration_ms.snapshot(),
            active_streams: self.active_streams,
            cached_connection: self.connection.is_some(),
            shutdown: self.shutdown,
        }
    }

    fn shutdown_snapshot(&self) -> H2PoolShutdownSnapshot {
        H2PoolShutdownSnapshot {
            pool: self.snapshot(),
            pooled_h2_client_observed_outer_tls12_connections: self
                .pooled_h2_client_observed_outer_tls12_connections,
            pooled_h2_client_observed_outer_tls13_connections: self
                .pooled_h2_client_observed_outer_tls13_connections,
            pooled_h2_client_observed_outer_tls_unknown_connections: self
                .pooled_h2_client_observed_outer_tls_unknown_connections,
            pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections: self
                .pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
            pooled_h2_client_observed_outer_tls_group_x25519_connections: self
                .pooled_h2_client_observed_outer_tls_group_x25519_connections,
            pooled_h2_client_observed_outer_tls_group_secp256r1_connections: self
                .pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
            pooled_h2_client_observed_outer_tls_group_secp384r1_connections: self
                .pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
            pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections: self
                .pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
        }
    }
}

#[derive(Default)]
struct H2DurationHistogram {
    count: u64,
    sum_ms: u64,
    buckets: [u64; H2_DURATION_BUCKET_COUNT],
}

impl H2DurationHistogram {
    fn record(&mut self, elapsed: Duration) {
        let elapsed_ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
        self.count = self.count.saturating_add(1);
        self.sum_ms = self.sum_ms.saturating_add(elapsed_ms);
        for (index, upper_bound_ms) in H2_DURATION_BUCKET_UPPER_BOUNDS_MS.iter().enumerate() {
            if elapsed_ms <= *upper_bound_ms {
                self.buckets[index] = self.buckets[index].saturating_add(1);
            }
        }
        let infinite_bucket = H2_DURATION_BUCKET_COUNT - 1;
        self.buckets[infinite_bucket] = self.buckets[infinite_bucket].saturating_add(1);
    }

    fn snapshot(&self) -> H2DurationHistogramSnapshot {
        H2DurationHistogramSnapshot {
            count: self.count,
            sum_ms: self.sum_ms,
            buckets: self.buckets,
        }
    }
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

impl H2ConnectionLease {
    pub(crate) fn record_runtime_stream_reset(&self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut state = lock_state(&inner.state);
        state.runtime_stream_resets = state.runtime_stream_resets.saturating_add(1);
    }

    pub(crate) fn record_runtime_send_stall(&self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut state = lock_state(&inner.state);
        state.runtime_send_stalls = state.runtime_send_stalls.saturating_add(1);
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

        let connection_setup_started_at = Instant::now();
        let connection = crate::h2_transport::connect_with_status(&self.inner.config).await?;
        self.record_connection_setup_duration(connection_setup_started_at.elapsed());
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
        let crate::h2_transport::H2Connection {
            transport,
            connection_closed,
            observed_outer_tls_version,
            observed_outer_tls_group,
        } = connection;
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
        state.record_installed_connection(observed_outer_tls_version, observed_outer_tls_group);
        state.streams_opened = state.streams_opened.saturating_add(1);
        state.active_streams = state.active_streams.saturating_add(1);
        state.connection = Some(CachedH2Connection {
            generation,
            sender: transport.sender.clone(),
            channel_binding: transport.channel_binding,
            connection_closed,
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

    fn retire_after_handshake_timeout_if_unshared(&self, generation: u64) -> bool {
        let mut state = lock_state(&self.inner.state);
        state.handshake_timeouts = state.handshake_timeouts.saturating_add(1);
        let should_retire = state.connection.as_ref().is_some_and(|connection| {
            connection.generation == generation && connection.active_streams == 0
        });
        if should_retire {
            state.connection.take();
            state.timeout_retirements = state.timeout_retirements.saturating_add(1);
            debug!(generation, "retired timed-out pooled H2 connection");
            return true;
        }
        false
    }

    fn record_timeout_recovery(&self) {
        let mut state = lock_state(&self.inner.state);
        state.timeout_recoveries = state.timeout_recoveries.saturating_add(1);
    }

    fn record_connection_setup_duration(&self, elapsed: Duration) {
        let mut state = lock_state(&self.inner.state);
        state.connection_setup_duration_ms.record(elapsed);
    }

    fn record_tunnel_open_duration(&self, elapsed: Duration) {
        let mut state = lock_state(&self.inner.state);
        state.tunnel_open_duration_ms.record(elapsed);
    }

    fn snapshot(&self) -> H2ConnectionPoolSnapshot {
        let state = lock_state(&self.inner.state);
        state.snapshot()
    }

    fn shutdown_snapshot(&self) -> H2PoolShutdownSnapshot {
        let state = lock_state(&self.inner.state);
        state.shutdown_snapshot()
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
    use tokio::io::duplex;

    async fn test_h2_connection() -> crate::h2_transport::H2Connection {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(async move {
            let Ok(mut connection) = h2::server::Builder::new()
                .handshake::<_, bytes::Bytes>(server_io)
                .await
            else {
                return;
            };
            while let Some(request) = connection.accept().await {
                let Ok((_request, mut respond)) = request else {
                    break;
                };
                let _ = respond.send_response(http::Response::new(()), true);
            }
        });

        let (sender, connection) = h2::client::handshake(client_io)
            .await
            .expect("test H2 client handshake");
        let (closed_tx, closed_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = connection.await;
            let _ = closed_tx.send(true);
        });
        crate::h2_transport::H2Connection {
            transport: H2TunnelRequestSender {
                sender,
                channel_binding: None,
            },
            connection_closed: closed_rx,
            observed_outer_tls_version: crate::h2_transport::ObservedOuterTlsVersion::Unknown,
            observed_outer_tls_group: crate::h2_transport::ObservedOuterTlsGroup::OtherOrUnknown,
        }
    }

    async fn test_h2_connection_with_observed_outer_tls(
        version: crate::h2_transport::ObservedOuterTlsVersion,
        group: crate::h2_transport::ObservedOuterTlsGroup,
    ) -> crate::h2_transport::H2Connection {
        let mut connection = test_h2_connection().await;
        connection.observed_outer_tls_version = version;
        connection.observed_outer_tls_group = group;
        connection
    }

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

    #[tokio::test]
    async fn duration_histograms_use_fixed_cumulative_buckets() {
        let manager = H2ConnectionManager::new(test_config());
        manager.record_connection_setup_duration(Duration::from_millis(10));
        manager.record_connection_setup_duration(Duration::from_millis(11));
        manager.record_connection_setup_duration(Duration::from_millis(10_001));
        manager.record_tunnel_open_duration(Duration::from_millis(25));

        let snapshot = manager.snapshot();
        assert_eq!(
            snapshot.connection_setup_duration_ms,
            H2DurationHistogramSnapshot {
                count: 3,
                sum_ms: 10_022,
                buckets: [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3],
            }
        );
        assert_eq!(
            snapshot.tunnel_open_duration_ms,
            H2DurationHistogramSnapshot {
                count: 1,
                sum_ms: 25,
                buckets: [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            }
        );
    }

    #[tokio::test]
    async fn runtime_failure_counters_are_numeric_and_saturating() {
        let manager = H2ConnectionManager::new(test_config());
        let lease = H2ConnectionLease {
            inner: Arc::downgrade(&manager.inner),
            generation: 0,
        };
        lease.record_runtime_stream_reset();
        lease.record_runtime_send_stall();
        lease.record_runtime_send_stall();

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.runtime_stream_resets, 1);
        assert_eq!(snapshot.runtime_send_stalls, 2);
    }

    #[tokio::test]
    async fn installed_physical_connections_are_counted_once_by_both_outer_tls_partitions() {
        use crate::h2_transport::ObservedOuterTlsGroup::{
            OtherOrUnknown, Secp256r1, Secp384r1, X25519MlKem768, X25519,
        };
        use crate::h2_transport::ObservedOuterTlsVersion::{Tls12, Tls13, Unknown};

        let manager = H2ConnectionManager::new(test_config());
        let first = manager
            .install_and_checkout(
                test_h2_connection_with_observed_outer_tls(Tls12, X25519MlKem768).await,
            )
            .expect("install first test connection");
        let first_generation = first.generation;
        drop(first);

        let cached_once = manager
            .checkout_cached()
            .expect("checkout first cached stream")
            .expect("first cached connection");
        drop(cached_once);
        let cached_twice = manager
            .checkout_cached()
            .expect("checkout second cached stream")
            .expect("second cached connection");
        drop(cached_twice);

        {
            let state = lock_state(&manager.inner.state);
            assert_eq!(state.connections_created, 1);
            assert_eq!(
                (
                    state.pooled_h2_client_observed_outer_tls12_connections,
                    state.pooled_h2_client_observed_outer_tls13_connections,
                    state.pooled_h2_client_observed_outer_tls_unknown_connections,
                ),
                (1, 0, 0)
            );
            assert_eq!(
                (
                    state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
                    state.pooled_h2_client_observed_outer_tls_group_x25519_connections,
                    state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
                    state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
                    state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
                ),
                (1, 0, 0, 0, 0)
            );
        }

        manager.invalidate_after_readiness_failure(first_generation);
        let replacements = [
            (Tls13, X25519),
            (Tls13, Secp256r1),
            (Tls13, Secp384r1),
            (Unknown, OtherOrUnknown),
        ];
        for (index, (version, group)) in replacements.into_iter().enumerate() {
            let replacement = manager
                .install_and_checkout(
                    test_h2_connection_with_observed_outer_tls(version, group).await,
                )
                .expect("install replacement test connection");
            let generation = replacement.generation;
            drop(replacement);
            if index + 1 < replacements.len() {
                manager.invalidate_after_readiness_failure(generation);
            }
        }

        let state = lock_state(&manager.inner.state);
        assert_eq!(state.connections_created, 5);
        assert_eq!(state.reconnects, 4);
        assert_eq!(
            (
                state.pooled_h2_client_observed_outer_tls12_connections,
                state.pooled_h2_client_observed_outer_tls13_connections,
                state.pooled_h2_client_observed_outer_tls_unknown_connections,
            ),
            (1, 3, 1)
        );
        assert_eq!(
            (
                state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
                state.pooled_h2_client_observed_outer_tls_group_x25519_connections,
                state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
                state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
                state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls12_connections as u128
                + state.pooled_h2_client_observed_outer_tls13_connections as u128
                + state.pooled_h2_client_observed_outer_tls_unknown_connections as u128,
            state.connections_created as u128
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_x25519_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections
                    as u128,
            state.connections_created as u128
        );
        drop(state);

        let shutdown_snapshot = manager.shutdown_snapshot();
        assert_eq!(shutdown_snapshot.pool.connections_created, 5);
        assert_eq!(
            (
                shutdown_snapshot.pooled_h2_client_observed_outer_tls12_connections,
                shutdown_snapshot.pooled_h2_client_observed_outer_tls13_connections,
                shutdown_snapshot.pooled_h2_client_observed_outer_tls_unknown_connections,
            ),
            (1, 3, 1)
        );
        assert_eq!(
            (
                shutdown_snapshot
                    .pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
                shutdown_snapshot.pooled_h2_client_observed_outer_tls_group_x25519_connections,
                shutdown_snapshot.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
                shutdown_snapshot.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
                shutdown_snapshot
                    .pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
            ),
            (1, 1, 1, 1, 1)
        );
    }

    #[test]
    fn observed_outer_tls_partitions_saturate_without_losing_the_invariants() {
        let mut state = H2ConnectionPoolState {
            connections_created: u64::MAX - 1,
            pooled_h2_client_observed_outer_tls12_connections: u64::MAX - 1,
            pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections: u64::MAX - 1,
            ..H2ConnectionPoolState::default()
        };

        assert_eq!(
            state.pooled_h2_client_observed_outer_tls12_connections as u128
                + state.pooled_h2_client_observed_outer_tls13_connections as u128
                + state.pooled_h2_client_observed_outer_tls_unknown_connections as u128,
            state.connections_created as u128
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_x25519_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections
                    as u128,
            state.connections_created as u128
        );

        state.record_installed_connection(
            crate::h2_transport::ObservedOuterTlsVersion::Tls12,
            crate::h2_transport::ObservedOuterTlsGroup::X25519MlKem768,
        );

        assert_eq!(state.connections_created, u64::MAX);
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls12_connections,
            u64::MAX
        );
        assert_eq!(state.pooled_h2_client_observed_outer_tls13_connections, 0);
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_unknown_connections,
            0
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
            u64::MAX
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_x25519_connections,
            0
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
            0
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
            0
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
            0
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls12_connections as u128
                + state.pooled_h2_client_observed_outer_tls13_connections as u128
                + state.pooled_h2_client_observed_outer_tls_unknown_connections as u128,
            state.connections_created as u128
        );
        assert_eq!(
            state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_x25519_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections as u128
                + state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections
                    as u128,
            state.connections_created as u128
        );

        let saturated_tls_partition = (
            state.pooled_h2_client_observed_outer_tls12_connections,
            state.pooled_h2_client_observed_outer_tls13_connections,
            state.pooled_h2_client_observed_outer_tls_unknown_connections,
        );
        let saturated_group_partition = (
            state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
            state.pooled_h2_client_observed_outer_tls_group_x25519_connections,
            state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
            state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
            state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
        );

        state.record_installed_connection(
            crate::h2_transport::ObservedOuterTlsVersion::Tls13,
            crate::h2_transport::ObservedOuterTlsGroup::X25519,
        );

        assert_eq!(state.connections_created, u64::MAX);
        assert_eq!(
            (
                state.pooled_h2_client_observed_outer_tls12_connections,
                state.pooled_h2_client_observed_outer_tls13_connections,
                state.pooled_h2_client_observed_outer_tls_unknown_connections,
            ),
            saturated_tls_partition
        );
        assert_eq!(
            (
                state.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
                state.pooled_h2_client_observed_outer_tls_group_x25519_connections,
                state.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
                state.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
                state.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
            ),
            saturated_group_partition
        );
        assert_eq!(
            saturated_tls_partition.0 as u128
                + saturated_tls_partition.1 as u128
                + saturated_tls_partition.2 as u128,
            state.connections_created as u128
        );
        assert_eq!(
            saturated_group_partition.0 as u128
                + saturated_group_partition.1 as u128
                + saturated_group_partition.2 as u128
                + saturated_group_partition.3 as u128
                + saturated_group_partition.4 as u128,
            state.connections_created as u128
        );
    }

    #[tokio::test]
    async fn completed_connection_rejected_before_install_is_not_counted() {
        let manager = H2ConnectionManager::new(test_config());
        manager.shutdown();

        let connection = test_h2_connection_with_observed_outer_tls(
            crate::h2_transport::ObservedOuterTlsVersion::Tls13,
            crate::h2_transport::ObservedOuterTlsGroup::X25519,
        )
        .await;
        assert!(manager.install_and_checkout(connection).is_err());

        let snapshot = manager.shutdown_snapshot();
        assert_eq!(snapshot.pool.connections_created, 0);
        assert_eq!(
            (
                snapshot.pooled_h2_client_observed_outer_tls12_connections,
                snapshot.pooled_h2_client_observed_outer_tls13_connections,
                snapshot.pooled_h2_client_observed_outer_tls_unknown_connections,
                snapshot.pooled_h2_client_observed_outer_tls_group_x25519_mlkem768_connections,
                snapshot.pooled_h2_client_observed_outer_tls_group_x25519_connections,
                snapshot.pooled_h2_client_observed_outer_tls_group_secp256r1_connections,
                snapshot.pooled_h2_client_observed_outer_tls_group_secp384r1_connections,
                snapshot.pooled_h2_client_observed_outer_tls_group_other_or_unknown_connections,
            ),
            (0, 0, 0, 0, 0, 0, 0, 0)
        );
    }

    #[tokio::test]
    async fn timeout_retirement_requires_unshared_exact_generation() {
        let manager = H2ConnectionManager::new(test_config());
        let first = manager
            .install_and_checkout(test_h2_connection().await)
            .expect("install first test connection");
        let first_generation = first.generation;

        assert!(
            !manager.retire_after_handshake_timeout_if_unshared(first_generation),
            "an active generation must not be retired"
        );
        let while_active = manager.snapshot();
        assert_eq!(while_active.handshake_timeouts, 1);
        assert_eq!(while_active.timeout_retirements, 0);
        assert!(while_active.cached_connection);
        assert_eq!(while_active.active_streams, 1);

        let H2Checkout {
            transport: first_transport,
            lease: first_lease,
            ..
        } = first;
        drop(first_lease);
        assert!(
            manager.retire_after_handshake_timeout_if_unshared(first_generation),
            "an unshared timed-out generation should be retired"
        );
        let after_retirement = manager.snapshot();
        assert_eq!(after_retirement.handshake_timeouts, 2);
        assert_eq!(after_retirement.timeout_retirements, 1);
        assert!(!after_retirement.cached_connection);
        assert_eq!(after_retirement.active_streams, 0);

        let second = manager
            .install_and_checkout(test_h2_connection().await)
            .expect("install replacement test connection");
        let second_generation = second.generation;
        assert_ne!(second_generation, first_generation);

        // A delayed timeout report from the retired generation must not remove
        // the newer cached generation.
        assert!(
            !manager.retire_after_handshake_timeout_if_unshared(first_generation),
            "an old timeout must not retire the replacement generation"
        );
        let after_late_timeout = manager.snapshot();
        assert_eq!(after_late_timeout.handshake_timeouts, 3);
        assert_eq!(after_late_timeout.timeout_retirements, 1);
        assert_eq!(after_late_timeout.timeout_recoveries, 0);
        assert!(after_late_timeout.cached_connection);
        assert_eq!(
            lock_state(&manager.inner.state)
                .connection
                .as_ref()
                .map(|connection| connection.generation),
            Some(second_generation)
        );

        // Removing the cache's sender clone does not terminate handles already
        // checked out on the retired generation.
        let H2TunnelRequestSender {
            sender,
            channel_binding: _,
        } = first_transport;
        timeout(Duration::from_secs(1), sender.ready())
            .await
            .expect("old checkout readiness timed out")
            .expect("old checkout was closed by cache retirement");

        drop(second);
        assert_eq!(manager.snapshot().active_streams, 0);
    }
}
