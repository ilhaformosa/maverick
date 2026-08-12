use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use bytes::Bytes;
use futures::FutureExt;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
    UdpPacket,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Instant as TokioInstant};
use tokio_util::sync::CancellationToken;

use crate::device::BoundedDevice;
use crate::{
    BoxTcpFlow, Datagram, DnsInterception, FlowConnector, FlowConnectorSnapshot, FlowErrorKind,
    PacketIo, PacketRead, PacketRuntimeConfig, PacketRuntimeError, PacketRuntimeFailure,
    PacketRuntimeSnapshot, PacketRuntimeState, ShutdownReport, ENGINE_NAME, ENGINE_VERSION,
};

#[derive(Clone)]
pub struct PacketRuntimeHandle {
    inner: Arc<HandleInner>,
}

struct HandleInner {
    cancel: CancellationToken,
    join: Mutex<Option<JoinHandle<Result<(), PacketRuntimeFailure>>>>,
    terminal: Arc<Notify>,
    counters: Arc<Counters>,
    connector: Arc<dyn FlowConnector>,
    shutdown_timeout: Duration,
    configured_buffer_capacity_bytes: usize,
    packet_queue_depth: usize,
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl PacketRuntimeHandle {
    pub fn snapshot(&self) -> PacketRuntimeSnapshot {
        self.inner.counters.snapshot(
            self.inner.configured_buffer_capacity_bytes,
            self.inner.packet_queue_depth,
            self.inner.connector.snapshot(),
        )
    }

    pub async fn shutdown(&self) -> Result<ShutdownReport, PacketRuntimeError> {
        let started = StdInstant::now();
        let before = self.snapshot();
        let already_stopped = matches!(
            before.state,
            PacketRuntimeState::Stopped | PacketRuntimeState::Failed
        );
        self.inner.cancel.cancel();

        let join = self.inner.join.lock().await.take();
        if let Some(mut join) = join {
            let wait = self
                .inner
                .shutdown_timeout
                .saturating_add(Duration::from_secs(2));
            match timeout(wait, &mut join).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(failure))) => {
                    self.inner.counters.fail(failure);
                }
                Ok(Err(_)) => {
                    self.inner.counters.fail(PacketRuntimeFailure::Task);
                }
                Err(_) => {
                    join.abort();
                    let _ = join.await;
                    self.inner.counters.forced.store(true, Ordering::Relaxed);
                    self.inner
                        .counters
                        .fail(PacketRuntimeFailure::ShutdownTimedOut);
                }
            }
        } else if !already_stopped {
            let wait = self
                .inner
                .shutdown_timeout
                .saturating_add(Duration::from_secs(2));
            if timeout(wait, self.wait_for_terminal()).await.is_err() {
                self.inner.counters.forced.store(true, Ordering::Relaxed);
                self.inner
                    .counters
                    .fail(PacketRuntimeFailure::ShutdownTimedOut);
            }
        }

        self.inner.terminal.notify_waiters();
        let final_snapshot = self.snapshot();
        if let Some(failure) = final_snapshot.last_failure {
            return Err(PacketRuntimeError::RuntimeFailed(failure));
        }
        Ok(ShutdownReport {
            already_stopped,
            forced: self.inner.counters.forced.load(Ordering::Relaxed),
            elapsed: started.elapsed(),
            final_snapshot,
        })
    }

    async fn wait_for_terminal(&self) {
        loop {
            let notified = self.inner.terminal.notified();
            if matches!(
                self.snapshot().state,
                PacketRuntimeState::Stopped | PacketRuntimeState::Failed
            ) {
                return;
            }
            notified.await;
        }
    }
}

pub fn start_packet_runtime(
    config: PacketRuntimeConfig,
    io: PacketIo,
    connector: Arc<dyn FlowConnector>,
) -> Result<PacketRuntimeHandle, PacketRuntimeError> {
    config.validate()?;
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(PacketRuntimeError::RuntimeUnavailable);
    }
    let connector_snapshot = connector.snapshot();
    validate_connector_snapshot(connector_snapshot)?;
    let configured_buffer_capacity_bytes = config
        .buffer_capacity_bytes()?
        .checked_add(connector_snapshot.buffer_capacity_bytes)
        .ok_or(PacketRuntimeError::InvalidConfig(
            "combined packet and connector buffer capacity overflowed",
        ))?;
    if configured_buffer_capacity_bytes > 256 * 1024 * 1024 {
        return Err(PacketRuntimeError::InvalidConfig(
            "combined packet and connector buffer capacity exceeds 256 MiB",
        ));
    }
    let counters = Arc::new(Counters::new());
    counters.set_state(PacketRuntimeState::Running);
    let cancel = CancellationToken::new();
    let terminal = Arc::new(Notify::new());
    let task_counters = Arc::clone(&counters);
    let task_cancel = cancel.clone();
    let task_terminal = Arc::clone(&terminal);
    let handle_connector = Arc::clone(&connector);
    let shutdown_timeout = config.shutdown_timeout;
    let packet_queue_depth = config.packet_queue_depth;
    let join = tokio::spawn(async move {
        let result = AssertUnwindSafe(async {
            let _task = TaskGuard::new(Arc::clone(&task_counters));
            run_runtime(
                config,
                io,
                connector,
                task_cancel,
                Arc::clone(&task_counters),
            )
            .await
        })
        .catch_unwind()
        .await
        .unwrap_or(Err(PacketRuntimeFailure::Task));
        match result {
            Ok(()) => task_counters.set_state(PacketRuntimeState::Stopped),
            Err(failure) => task_counters.fail(failure),
        }
        task_counters.clear_live_state();
        task_terminal.notify_waiters();
        result
    });

    Ok(PacketRuntimeHandle {
        inner: Arc::new(HandleInner {
            cancel,
            join: Mutex::new(Some(join)),
            terminal,
            counters,
            connector: handle_connector,
            shutdown_timeout,
            configured_buffer_capacity_bytes,
            packet_queue_depth,
        }),
    })
}

fn validate_connector_snapshot(snapshot: FlowConnectorSnapshot) -> Result<(), PacketRuntimeError> {
    if snapshot.active_tasks > snapshot.peak_tasks
        || snapshot.buffered_bytes > snapshot.buffer_capacity_bytes
        || snapshot.peak_buffered_bytes > snapshot.buffer_capacity_bytes
    {
        return Err(PacketRuntimeError::InvalidConfig(
            "flow connector resource snapshot is inconsistent",
        ));
    }
    if snapshot.active_tasks != 0
        || snapshot.peak_tasks != 0
        || snapshot.buffered_bytes != 0
        || snapshot.peak_buffered_bytes != 0
    {
        return Err(PacketRuntimeError::InvalidConfig(
            "flow connector must be fresh and quiescent at startup",
        ));
    }
    Ok(())
}

struct Counters {
    state: AtomicU8,
    failure: AtomicU8,
    forced: AtomicBool,
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_rejected: AtomicU64,
    malformed_packets: AtomicU64,
    unsupported_packets: AtomicU64,
    tcp_flows_opened: AtomicU64,
    tcp_flows_rejected: AtomicU64,
    tcp_flows_failed: AtomicU64,
    active_tcp_flows: AtomicUsize,
    peak_tcp_flows: AtomicUsize,
    udp_associations_opened: AtomicU64,
    udp_associations_failed: AtomicU64,
    udp_datagrams_dropped: AtomicU64,
    active_udp_associations: AtomicUsize,
    peak_udp_associations: AtomicUsize,
    dns_queries_started: AtomicU64,
    dns_queries_rejected: AtomicU64,
    dns_queries_failed: AtomicU64,
    active_dns_queries: AtomicUsize,
    peak_dns_queries: AtomicUsize,
    active_tasks: AtomicUsize,
    peak_tasks: AtomicUsize,
    ingress_queue_depth: AtomicUsize,
    egress_queue_depth: AtomicUsize,
    peak_ingress_queue_depth: AtomicUsize,
    peak_egress_queue_depth: AtomicUsize,
    tracked_buffered_bytes: AtomicUsize,
    actor_buffered_bytes: AtomicUsize,
    peak_buffered_bytes: AtomicUsize,
}

impl Counters {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(state_to_u8(PacketRuntimeState::Created)),
            failure: AtomicU8::new(0),
            forced: AtomicBool::new(false),
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_rejected: AtomicU64::new(0),
            malformed_packets: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            tcp_flows_opened: AtomicU64::new(0),
            tcp_flows_rejected: AtomicU64::new(0),
            tcp_flows_failed: AtomicU64::new(0),
            active_tcp_flows: AtomicUsize::new(0),
            peak_tcp_flows: AtomicUsize::new(0),
            udp_associations_opened: AtomicU64::new(0),
            udp_associations_failed: AtomicU64::new(0),
            udp_datagrams_dropped: AtomicU64::new(0),
            active_udp_associations: AtomicUsize::new(0),
            peak_udp_associations: AtomicUsize::new(0),
            dns_queries_started: AtomicU64::new(0),
            dns_queries_rejected: AtomicU64::new(0),
            dns_queries_failed: AtomicU64::new(0),
            active_dns_queries: AtomicUsize::new(0),
            peak_dns_queries: AtomicUsize::new(0),
            active_tasks: AtomicUsize::new(0),
            peak_tasks: AtomicUsize::new(0),
            ingress_queue_depth: AtomicUsize::new(0),
            egress_queue_depth: AtomicUsize::new(0),
            peak_ingress_queue_depth: AtomicUsize::new(0),
            peak_egress_queue_depth: AtomicUsize::new(0),
            tracked_buffered_bytes: AtomicUsize::new(0),
            actor_buffered_bytes: AtomicUsize::new(0),
            peak_buffered_bytes: AtomicUsize::new(0),
        }
    }

    fn set_state(&self, state: PacketRuntimeState) {
        self.state.store(state_to_u8(state), Ordering::Release);
    }

    fn fail(&self, failure: PacketRuntimeFailure) {
        let _ = self.failure.compare_exchange(
            0,
            failure_to_u8(failure),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.set_state(PacketRuntimeState::Failed);
    }

    fn add_tracked_bytes(&self, bytes: usize) {
        let value = self
            .tracked_buffered_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            + bytes;
        self.update_peak_buffered(value + self.actor_buffered_bytes.load(Ordering::Relaxed));
    }

    fn remove_tracked_bytes(&self, bytes: usize) {
        let _ = self.tracked_buffered_bytes.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_sub(bytes)),
        );
    }

    fn set_actor_buffered_bytes(&self, bytes: usize) {
        self.actor_buffered_bytes.store(bytes, Ordering::Relaxed);
        self.update_peak_buffered(bytes + self.tracked_buffered_bytes.load(Ordering::Relaxed));
    }

    fn update_peak_buffered(&self, value: usize) {
        update_peak(&self.peak_buffered_bytes, value);
    }

    fn clear_live_state(&self) {
        self.active_tcp_flows.store(0, Ordering::Relaxed);
        self.active_udp_associations.store(0, Ordering::Relaxed);
        self.active_dns_queries.store(0, Ordering::Relaxed);
        self.ingress_queue_depth.store(0, Ordering::Relaxed);
        self.egress_queue_depth.store(0, Ordering::Relaxed);
        self.tracked_buffered_bytes.store(0, Ordering::Relaxed);
        self.actor_buffered_bytes.store(0, Ordering::Relaxed);
    }

    fn snapshot(
        &self,
        configured_buffer_capacity_bytes: usize,
        packet_queue_depth: usize,
        connector: FlowConnectorSnapshot,
    ) -> PacketRuntimeSnapshot {
        let tracked = self.tracked_buffered_bytes.load(Ordering::Relaxed);
        let actor = self.actor_buffered_bytes.load(Ordering::Relaxed);
        let (active_tcp_flows, peak_tcp_flows) =
            current_and_peak(&self.active_tcp_flows, &self.peak_tcp_flows);
        let (active_udp_associations, peak_udp_associations) =
            current_and_peak(&self.active_udp_associations, &self.peak_udp_associations);
        let (active_dns_queries, peak_dns_queries) =
            current_and_peak(&self.active_dns_queries, &self.peak_dns_queries);
        let (active_tasks, peak_tasks) = current_and_peak(&self.active_tasks, &self.peak_tasks);
        // A receive frees one Tokio channel slot just before the actor decrements
        // its separate gauge. The channel capacity is the authoritative bound.
        let (ingress_queue_depth, peak_ingress_queue_depth) = bounded_current_and_peak(
            &self.ingress_queue_depth,
            &self.peak_ingress_queue_depth,
            packet_queue_depth,
        );
        let (egress_queue_depth, peak_egress_queue_depth) = bounded_current_and_peak(
            &self.egress_queue_depth,
            &self.peak_egress_queue_depth,
            packet_queue_depth,
        );
        let engine_buffered_bytes = tracked.saturating_add(actor);
        let engine_peak_buffered_bytes = self
            .peak_buffered_bytes
            .load(Ordering::Relaxed)
            .max(engine_buffered_bytes);
        let connector_peak_tasks = connector.peak_tasks.max(connector.active_tasks);
        let connector_peak_buffered_bytes =
            connector.peak_buffered_bytes.max(connector.buffered_bytes);
        PacketRuntimeSnapshot {
            engine_name: ENGINE_NAME,
            engine_version: ENGINE_VERSION,
            state: u8_to_state(self.state.load(Ordering::Acquire)),
            last_failure: u8_to_failure(self.failure.load(Ordering::Acquire)),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_rejected: self.packets_rejected.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            tcp_flows_opened: self.tcp_flows_opened.load(Ordering::Relaxed),
            tcp_flows_rejected: self.tcp_flows_rejected.load(Ordering::Relaxed),
            tcp_flows_failed: self.tcp_flows_failed.load(Ordering::Relaxed),
            active_tcp_flows,
            peak_tcp_flows,
            udp_associations_opened: self.udp_associations_opened.load(Ordering::Relaxed),
            udp_associations_failed: self.udp_associations_failed.load(Ordering::Relaxed),
            udp_datagrams_dropped: self.udp_datagrams_dropped.load(Ordering::Relaxed),
            active_udp_associations,
            peak_udp_associations,
            dns_queries_started: self.dns_queries_started.load(Ordering::Relaxed),
            dns_queries_rejected: self.dns_queries_rejected.load(Ordering::Relaxed),
            dns_queries_failed: self.dns_queries_failed.load(Ordering::Relaxed),
            active_dns_queries,
            peak_dns_queries,
            active_tasks: active_tasks.saturating_add(connector.active_tasks),
            peak_tasks: peak_tasks.saturating_add(connector_peak_tasks),
            ingress_queue_depth,
            egress_queue_depth,
            peak_ingress_queue_depth,
            peak_egress_queue_depth,
            buffered_bytes: engine_buffered_bytes.saturating_add(connector.buffered_bytes),
            peak_buffered_bytes: engine_peak_buffered_bytes
                .saturating_add(connector_peak_buffered_bytes),
            configured_buffer_capacity_bytes,
        }
    }
}

fn current_and_peak(current: &AtomicUsize, peak: &AtomicUsize) -> (usize, usize) {
    let current = current.load(Ordering::Relaxed);
    let peak = peak.load(Ordering::Relaxed).max(current);
    (current, peak)
}

fn bounded_current_and_peak(
    current: &AtomicUsize,
    peak: &AtomicUsize,
    hard_limit: usize,
) -> (usize, usize) {
    let (current, peak) = current_and_peak(current, peak);
    (current.min(hard_limit), peak.min(hard_limit))
}

fn state_to_u8(state: PacketRuntimeState) -> u8 {
    match state {
        PacketRuntimeState::Created => 0,
        PacketRuntimeState::Running => 1,
        PacketRuntimeState::Draining => 2,
        PacketRuntimeState::Stopped => 3,
        PacketRuntimeState::Failed => 4,
    }
}

fn u8_to_state(value: u8) -> PacketRuntimeState {
    match value {
        1 => PacketRuntimeState::Running,
        2 => PacketRuntimeState::Draining,
        3 => PacketRuntimeState::Stopped,
        4 => PacketRuntimeState::Failed,
        _ => PacketRuntimeState::Created,
    }
}

fn failure_to_u8(failure: PacketRuntimeFailure) -> u8 {
    match failure {
        PacketRuntimeFailure::PacketRead => 1,
        PacketRuntimeFailure::PacketWrite => 2,
        PacketRuntimeFailure::Engine => 3,
        PacketRuntimeFailure::Task => 4,
        PacketRuntimeFailure::ShutdownTimedOut => 5,
    }
}

fn u8_to_failure(value: u8) -> Option<PacketRuntimeFailure> {
    match value {
        1 => Some(PacketRuntimeFailure::PacketRead),
        2 => Some(PacketRuntimeFailure::PacketWrite),
        3 => Some(PacketRuntimeFailure::Engine),
        4 => Some(PacketRuntimeFailure::Task),
        5 => Some(PacketRuntimeFailure::ShutdownTimedOut),
        _ => None,
    }
}

fn update_peak(peak: &AtomicUsize, value: usize) {
    let mut current = peak.load(Ordering::Relaxed);
    while value > current {
        match peak.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

struct TaskGuard(Arc<Counters>);

impl TaskGuard {
    fn new(counters: Arc<Counters>) -> Self {
        let active = counters.active_tasks.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&counters.peak_tasks, active);
        Self(counters)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.active_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

struct ActiveGuard {
    active: Arc<Counters>,
    kind: ActiveKind,
}

enum ActiveKind {
    Dns,
}

impl ActiveGuard {
    fn dns(counters: Arc<Counters>) -> Self {
        let active = counters.active_dns_queries.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&counters.peak_dns_queries, active);
        Self {
            active: counters,
            kind: ActiveKind::Dns,
        }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        match self.kind {
            ActiveKind::Dns => {
                self.active
                    .active_dns_queries
                    .fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

struct Tracked<T: AsRef<[u8]>> {
    value: Option<T>,
    counters: Arc<Counters>,
    len: usize,
}

impl<T: AsRef<[u8]>> Tracked<T> {
    fn new(value: T, counters: Arc<Counters>) -> Self {
        let len = value.as_ref().len();
        counters.add_tracked_bytes(len);
        Self {
            value: Some(value),
            counters,
            len,
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.value.as_ref().expect("tracked value present").as_ref()
    }

    fn into_inner(mut self) -> T {
        self.value.take().expect("tracked value present")
    }

    fn into_parts(mut self) -> (T, ByteLease) {
        let value = self.value.take().expect("tracked value present");
        let lease = ByteLease {
            counters: Arc::clone(&self.counters),
            len: self.len,
        };
        self.len = 0;
        (value, lease)
    }
}

impl<T: AsRef<[u8]>> Drop for Tracked<T> {
    fn drop(&mut self) {
        self.counters.remove_tracked_bytes(self.len);
    }
}

struct ByteLease {
    counters: Arc<Counters>,
    len: usize,
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        self.counters.remove_tracked_bytes(self.len);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpFlowKey {
    app: SocketAddr,
    target: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpTargetKey(SocketAddr);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpAssociationKey {
    app: SocketAddr,
    target: SocketAddr,
}

enum PacketClass {
    Tcp { key: TcpFlowKey, new_syn: bool },
    Udp { target: SocketAddr },
    Fragment(IpAddr),
    Unsupported,
}

enum EngineEvent {
    PacketReadFailed,
    PacketWriteFailed,
    PacketEof,
    TcpOpened(TcpFlowKey),
    TcpData {
        key: TcpFlowKey,
        data: Tracked<Bytes>,
        accepted: oneshot::Sender<()>,
    },
    TcpRemoteFin(TcpFlowKey),
    TcpDone {
        key: TcpFlowKey,
        failed: bool,
    },
    UdpResponse {
        key: UdpAssociationKey,
        endpoint: SocketAddr,
        payload: Tracked<Bytes>,
        accepted: oneshot::Sender<()>,
    },
    UdpDone {
        key: UdpAssociationKey,
        failed: bool,
    },
    DnsResponse {
        target: SocketAddr,
        app: SocketAddr,
        response: Tracked<Bytes>,
        _active: ActiveGuard,
    },
}

enum TcpCommand {
    Data(Tracked<Bytes>),
    LocalFin,
}

struct UdpCommand {
    endpoint: SocketAddr,
    payload: Tracked<Bytes>,
}

struct PendingTcpData {
    data: Tracked<Bytes>,
    offset: usize,
    accepted: Option<oneshot::Sender<()>>,
}

struct EgressPacket {
    packet: Tracked<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
}

struct TcpEntry {
    handle: SocketHandle,
    commands: mpsc::Sender<TcpCommand>,
    cancel: CancellationToken,
    opened: bool,
    local_fin_sent: bool,
    worker_done: bool,
    pending_remote: Option<PendingTcpData>,
}

struct UdpTargetEntry {
    handle: SocketHandle,
    target: SocketAddr,
    last_activity: StdInstant,
}

struct PendingUdpResponse {
    app: SocketAddr,
    target: SocketAddr,
    payload: Tracked<Bytes>,
    accepted: Option<oneshot::Sender<()>>,
}

struct UdpAssociationEntry {
    commands: mpsc::Sender<UdpCommand>,
    cancel: CancellationToken,
    pending_response: Option<PendingUdpResponse>,
}

struct Runtime {
    config: PacketRuntimeConfig,
    connector: Arc<dyn FlowConnector>,
    counters: Arc<Counters>,
    cancel: CancellationToken,
    io_cancel: CancellationToken,
    udp_dns_cancel: CancellationToken,
    interface: Interface,
    device: BoundedDevice,
    sockets: SocketSet<'static>,
    started: StdInstant,
    ingress: mpsc::Receiver<Tracked<Vec<u8>>>,
    ingress_open: bool,
    reader_eof_seen: bool,
    egress: mpsc::Sender<EgressPacket>,
    egress_permits: Arc<Semaphore>,
    events_rx: mpsc::Receiver<EngineEvent>,
    events_tx: mpsc::Sender<EngineEvent>,
    tasks: JoinSet<()>,
    tcp: HashMap<TcpFlowKey, TcpEntry>,
    udp_targets: HashMap<UdpTargetKey, UdpTargetEntry>,
    udp_associations: HashMap<UdpAssociationKey, UdpAssociationEntry>,
    pending_dns_responses: VecDeque<PendingUdpResponse>,
    next_udp_reap: StdInstant,
    accepting: bool,
    draining_deadline: Option<TokioInstant>,
    fatal_failure: Option<PacketRuntimeFailure>,
}

async fn run_runtime(
    config: PacketRuntimeConfig,
    io: PacketIo,
    connector: Arc<dyn FlowConnector>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
) -> Result<(), PacketRuntimeFailure> {
    let (reader, writer) = io.into_parts();
    let (ingress_tx, ingress_rx) = mpsc::channel(config.packet_queue_depth);
    let (egress_tx, egress_rx) = mpsc::channel(config.packet_queue_depth);
    let egress_permits = Arc::new(Semaphore::new(config.packet_queue_depth));
    let (events_tx, events_rx) = mpsc::channel(config.event_queue_depth);
    let io_cancel = cancel.child_token();

    let reader_join = tokio::spawn(packet_reader_task(
        reader,
        ingress_tx,
        events_tx.clone(),
        io_cancel.clone(),
        config.mtu,
        Arc::clone(&counters),
    ));
    let writer_join = tokio::spawn(packet_writer_task(
        writer,
        egress_rx,
        events_tx.clone(),
        io_cancel.clone(),
        Arc::clone(&counters),
    ));

    let mut device = BoundedDevice::new(config.mtu, config.packet_queue_depth);
    let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
    interface_config.random_seed = rand::random();
    let mut interface = Interface::new(interface_config, &mut device, Instant::ZERO);
    interface.set_any_ip(true);

    let reader_monitor = tokio::spawn(io_task_monitor(
        reader_join,
        events_tx.clone(),
        EngineEvent::PacketReadFailed,
        io_cancel.clone(),
        Arc::clone(&counters),
    ));
    let writer_monitor = tokio::spawn(io_task_monitor(
        writer_join,
        events_tx.clone(),
        EngineEvent::PacketWriteFailed,
        io_cancel.clone(),
        Arc::clone(&counters),
    ));

    let udp_dns_cancel = cancel.child_token();
    let started = StdInstant::now();
    let next_udp_reap = started + udp_reap_interval(&config);
    let mut runtime = Runtime {
        config,
        connector,
        counters,
        cancel,
        io_cancel,
        udp_dns_cancel,
        interface,
        device,
        sockets: SocketSet::new(Vec::new()),
        started,
        ingress: ingress_rx,
        ingress_open: true,
        reader_eof_seen: false,
        egress: egress_tx,
        egress_permits,
        events_rx,
        events_tx,
        tasks: JoinSet::new(),
        tcp: HashMap::new(),
        udp_targets: HashMap::new(),
        udp_associations: HashMap::new(),
        pending_dns_responses: VecDeque::new(),
        next_udp_reap,
        accepting: true,
        draining_deadline: None,
        fatal_failure: None,
    };

    runtime.run().await;
    runtime.cleanup().await;

    runtime.io_cancel.cancel();
    let _ = tokio::join!(join_or_abort(reader_monitor), join_or_abort(writer_monitor));
    runtime
        .counters
        .ingress_queue_depth
        .store(0, Ordering::Relaxed);
    runtime
        .counters
        .egress_queue_depth
        .store(0, Ordering::Relaxed);
    runtime.counters.set_actor_buffered_bytes(0);

    match runtime.fatal_failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

async fn io_task_monitor(
    join: JoinHandle<()>,
    events: mpsc::Sender<EngineEvent>,
    panic_event: EngineEvent,
    cancel: CancellationToken,
    counters: Arc<Counters>,
) {
    let _task = TaskGuard::new(counters);
    if join.await.is_err() {
        let _ = send_io_event(&events, panic_event, &cancel).await;
    }
}

async fn send_io_event(
    events: &mpsc::Sender<EngineEvent>,
    event: EngineEvent,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = events.send(event) => result.is_ok(),
    }
}

async fn join_or_abort(mut join: JoinHandle<()>) {
    if timeout(Duration::from_secs(1), &mut join).await.is_err() {
        join.abort();
        let _ = join.await;
    }
}

async fn packet_reader_task(
    mut reader: Box<dyn crate::PacketReader>,
    ingress: mpsc::Sender<Tracked<Vec<u8>>>,
    events: mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    mtu: usize,
    counters: Arc<Counters>,
) {
    let _task = TaskGuard::new(Arc::clone(&counters));
    loop {
        let mut packet = vec![0; mtu];
        let received = tokio::select! {
            _ = cancel.cancelled() => return,
            result = reader.receive(&mut packet) => result,
        };
        let length = match received {
            Ok(PacketRead::Eof) => {
                let _ = send_io_event(&events, EngineEvent::PacketEof, &cancel).await;
                return;
            }
            Ok(PacketRead::Packet(length)) if length <= mtu => length,
            Ok(_) | Err(_) => {
                let _ = send_io_event(&events, EngineEvent::PacketReadFailed, &cancel).await;
                return;
            }
        };
        packet.truncate(length);
        let tracked = Tracked::new(packet, Arc::clone(&counters));
        let permit = tokio::select! {
            _ = cancel.cancelled() => return,
            result = ingress.reserve() => match result {
                Ok(permit) => permit,
                Err(_) => return,
            },
        };
        let depth = counters.ingress_queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&counters.peak_ingress_queue_depth, depth);
        permit.send(tracked);
    }
}

async fn packet_writer_task(
    mut writer: Box<dyn crate::PacketWriter>,
    mut egress: mpsc::Receiver<EgressPacket>,
    events: mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
) {
    let _task = TaskGuard::new(Arc::clone(&counters));
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => break,
            packet = egress.recv() => match packet {
                Some(packet) => packet,
                None => break,
            },
        };
        let result = tokio::select! {
            _ = cancel.cancelled() => {
                counters.egress_queue_depth.fetch_sub(1, Ordering::Relaxed);
                break;
            },
            result = writer.send(packet.packet.as_slice()) => result,
        };
        if result.is_err() {
            let _ = send_io_event(&events, EngineEvent::PacketWriteFailed, &cancel).await;
            counters.egress_queue_depth.fetch_sub(1, Ordering::Relaxed);
            break;
        }
        counters.egress_queue_depth.fetch_sub(1, Ordering::Relaxed);
        counters.packets_sent.fetch_add(1, Ordering::Relaxed);
    }
    while egress.try_recv().is_ok() {
        let _ = counters.egress_queue_depth.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_sub(1)),
        );
    }
}

impl Runtime {
    async fn run(&mut self) {
        let tick = tokio::time::sleep(self.config.poll_interval);
        tokio::pin!(tick);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled(), if self.draining_deadline.is_none() => {
                    self.begin_draining(false);
                }
                event = self.events_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_event(event);
                    }
                }
                packet = self.ingress.recv(), if self.ingress_open => {
                    match packet {
                        Some(packet) => self.handle_packet(packet),
                        // The reader reports EOF and failures through the event channel.
                        // Waiting for that event prevents a closed ingress queue from
                        // racing a fatal reader notification into a clean shutdown.
                        None => {
                            self.ingress_open = false;
                            if self.reader_eof_seen {
                                self.begin_draining(false);
                            }
                        }
                    }
                }
                joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if matches!(joined, Some(Err(_))) {
                        self.record_failure(PacketRuntimeFailure::Task);
                    }
                }
                _ = &mut tick => {
                    tick.as_mut().reset(TokioInstant::now() + self.config.poll_interval);
                }
            }

            self.reap_completed_tasks();
            self.poll_engine();
            self.drive_tcp();
            self.drive_udp();
            self.poll_engine();
            self.flush_device_output();
            self.reap_udp_targets();
            self.refresh_actor_buffered_bytes();

            if self.should_stop() {
                break;
            }
        }
    }

    fn reap_completed_tasks(&mut self) {
        while let Some(joined) = self.tasks.try_join_next() {
            if joined.is_err() {
                self.record_failure(PacketRuntimeFailure::Task);
            }
        }
    }

    fn record_failure(&mut self, failure: PacketRuntimeFailure) {
        if self.fatal_failure.is_none() {
            self.fatal_failure = Some(failure);
        }
        self.begin_draining(true);
    }

    fn begin_draining(&mut self, immediate: bool) {
        if self.draining_deadline.is_some() {
            if immediate {
                self.draining_deadline = Some(TokioInstant::now());
            }
            return;
        }
        self.accepting = false;
        self.counters.set_state(PacketRuntimeState::Draining);
        self.udp_dns_cancel.cancel();
        for entry in self.udp_associations.values() {
            entry.cancel.cancel();
        }
        self.draining_deadline = Some(if immediate {
            TokioInstant::now()
        } else {
            TokioInstant::now() + self.config.shutdown_timeout
        });
    }

    fn should_stop(&mut self) -> bool {
        let Some(deadline) = self.draining_deadline else {
            return false;
        };
        let connector = self.connector.snapshot();
        let quiescent = self.tcp.is_empty()
            && self.udp_associations.is_empty()
            && self.counters.active_dns_queries.load(Ordering::Relaxed) == 0
            && self.counters.ingress_queue_depth.load(Ordering::Relaxed) == 0
            && self.counters.egress_queue_depth.load(Ordering::Relaxed) == 0
            && self.events_rx.is_empty()
            && self.tasks.is_empty()
            && self.pending_dns_responses.is_empty()
            && self.device.is_empty()
            && connector.active_tasks == 0
            && connector.buffered_bytes == 0;
        if quiescent {
            return true;
        }
        if TokioInstant::now() >= deadline {
            self.counters.forced.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn handle_event(&mut self, event: EngineEvent) {
        match event {
            EngineEvent::PacketReadFailed => {
                self.record_failure(PacketRuntimeFailure::PacketRead);
            }
            EngineEvent::PacketWriteFailed => {
                self.record_failure(PacketRuntimeFailure::PacketWrite);
            }
            EngineEvent::PacketEof => {
                self.reader_eof_seen = true;
                if !self.ingress_open {
                    self.begin_draining(false);
                }
            }
            EngineEvent::TcpOpened(key) => {
                if let Some(entry) = self.tcp.get_mut(&key) {
                    entry.opened = true;
                }
            }
            EngineEvent::TcpData {
                key,
                data,
                accepted,
            } => {
                if let Some(entry) = self.tcp.get_mut(&key) {
                    if entry.pending_remote.is_none() {
                        entry.pending_remote = Some(PendingTcpData {
                            data,
                            offset: 0,
                            accepted: Some(accepted),
                        });
                    }
                }
            }
            EngineEvent::TcpRemoteFin(key) => {
                if let Some(entry) = self.tcp.get(&key) {
                    self.sockets.get_mut::<tcp::Socket>(entry.handle).close();
                }
            }
            EngineEvent::TcpDone { key, failed } => {
                if let Some(entry) = self.tcp.get_mut(&key) {
                    entry.worker_done = true;
                    if failed {
                        self.counters
                            .tcp_flows_failed
                            .fetch_add(1, Ordering::Relaxed);
                        self.sockets.get_mut::<tcp::Socket>(entry.handle).abort();
                    }
                }
            }
            EngineEvent::UdpResponse {
                key,
                endpoint,
                payload,
                accepted,
            } => {
                if endpoint != key.target {
                    self.counters
                        .udp_datagrams_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = accepted.send(());
                    return;
                }
                if let Some(entry) = self.udp_associations.get_mut(&key) {
                    if entry.pending_response.is_none() {
                        entry.pending_response = Some(PendingUdpResponse {
                            app: key.app,
                            target: key.target,
                            payload,
                            accepted: Some(accepted),
                        });
                    }
                }
            }
            EngineEvent::UdpDone { key, failed } => {
                if failed {
                    self.counters
                        .udp_associations_failed
                        .fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .udp_datagrams_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.remove_udp_association(key);
            }
            EngineEvent::DnsResponse {
                target,
                app,
                response,
                _active,
            } => {
                if self.pending_dns_responses.len() < self.config.max_dns_queries {
                    self.pending_dns_responses.push_back(PendingUdpResponse {
                        app,
                        target,
                        payload: response,
                        accepted: None,
                    });
                } else {
                    self.counters
                        .dns_queries_rejected
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn handle_packet(&mut self, packet: Tracked<Vec<u8>>) {
        self.counters
            .ingress_queue_depth
            .fetch_sub(1, Ordering::Relaxed);
        self.counters
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        let packet = packet.into_inner();
        if packet.is_empty() || packet.len() > self.config.mtu {
            self.counters
                .packets_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .malformed_packets
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let classification = match classify_packet(&packet) {
            Ok(classification) => classification,
            Err(()) => {
                self.counters
                    .packets_rejected
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .malformed_packets
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if !self.family_enabled(&classification) {
            self.counters
                .packets_rejected
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut pending_tcp = None;
        match classification {
            PacketClass::Tcp { key, new_syn } => {
                if new_syn && !self.tcp.contains_key(&key) {
                    if self.accepting && self.tcp.len() < self.config.max_tcp_flows {
                        pending_tcp = self.add_tcp_listener(key).ok().map(|handle| (key, handle));
                    } else {
                        self.counters
                            .tcp_flows_rejected
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            PacketClass::Udp { target } => {
                self.ensure_udp_target(target);
            }
            PacketClass::Fragment(_) => {}
            PacketClass::Unsupported => {
                self.counters
                    .packets_rejected
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .unsupported_packets
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        if self.device.admit(packet).is_err() {
            self.counters
                .packets_rejected
                .fetch_add(1, Ordering::Relaxed);
            if let Some((_, handle)) = pending_tcp {
                self.sockets.remove(handle);
            }
            return;
        }
        self.poll_engine();
        if let Some((key, handle)) = pending_tcp {
            let state = self.sockets.get::<tcp::Socket>(handle).state();
            if state == tcp::State::Listen {
                self.sockets.remove(handle);
                self.counters
                    .packets_rejected
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .malformed_packets
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.start_tcp_worker(key, handle);
            }
        }
    }

    fn family_enabled(&self, class: &PacketClass) -> bool {
        let address = match class {
            PacketClass::Tcp { key, .. } => key.target.ip(),
            PacketClass::Udp { target } => target.ip(),
            PacketClass::Fragment(address) => *address,
            PacketClass::Unsupported => return true,
        };
        match address {
            IpAddr::V4(_) => self.config.ipv4_enabled,
            IpAddr::V6(_) => self.config.ipv6_enabled,
        }
    }

    fn add_tcp_listener(&mut self, key: TcpFlowKey) -> Result<SocketHandle, ()> {
        let rx = tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_timeout(Some(smoltcp::time::Duration::from_millis(
            duration_millis_u64(self.config.tcp_idle_timeout),
        )));
        socket
            .listen(to_smol_endpoint(key.target))
            .map_err(|_| ())?;
        Ok(self.sockets.add(socket))
    }

    fn start_tcp_worker(&mut self, key: TcpFlowKey, handle: SocketHandle) {
        let (commands, command_rx) = mpsc::channel(self.config.tcp_channel_depth);
        let cancel = CancellationToken::new();
        let connector = Arc::clone(&self.connector);
        let events = self.events_tx.clone();
        let worker_cancel = cancel.clone();
        let counters = Arc::clone(&self.counters);
        let worker_counters = Arc::clone(&counters);
        let connect_timeout = self.config.connect_timeout;
        let idle_timeout = self.config.tcp_idle_timeout;
        self.tasks.spawn(async move {
            let _task = TaskGuard::new(Arc::clone(&counters));
            tcp_worker(TcpWorkerContext {
                key,
                connector,
                commands: command_rx,
                events,
                cancel: worker_cancel,
                connect_timeout,
                idle_timeout,
                counters: worker_counters,
            })
            .await;
        });
        self.tcp.insert(
            key,
            TcpEntry {
                handle,
                commands,
                cancel,
                opened: false,
                local_fin_sent: false,
                worker_done: false,
                pending_remote: None,
            },
        );
        let active = self
            .counters
            .active_tcp_flows
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        update_peak(&self.counters.peak_tcp_flows, active);
        self.counters
            .tcp_flows_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    fn ensure_udp_target(&mut self, target: SocketAddr) {
        let key = UdpTargetKey(target);
        if let Some(entry) = self.udp_targets.get_mut(&key) {
            entry.last_activity = StdInstant::now();
            return;
        }
        if !self.accepting || self.udp_targets.len() >= self.config.max_udp_targets {
            self.counters
                .udp_datagrams_dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_message_depth],
            vec![0; self.config.udp_buffer_bytes],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_message_depth],
            vec![0; self.config.udp_buffer_bytes],
        );
        let mut socket = udp::Socket::new(rx, tx);
        if socket.bind(to_smol_endpoint(target)).is_err() {
            self.counters
                .udp_datagrams_dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let handle = self.sockets.add(socket);
        self.udp_targets.insert(
            key,
            UdpTargetEntry {
                handle,
                target,
                last_activity: StdInstant::now(),
            },
        );
    }

    fn poll_engine(&mut self) {
        let elapsed = self.started.elapsed().as_millis().min(i64::MAX as u128) as i64;
        self.interface.poll(
            Instant::from_millis(elapsed),
            &mut self.device,
            &mut self.sockets,
        );
    }

    fn drive_tcp(&mut self) {
        let keys: Vec<_> = self.tcp.keys().copied().collect();
        let mut remove = Vec::new();
        let (tcp_entries, sockets) = (&mut self.tcp, &mut self.sockets);
        for key in keys {
            let Some(entry) = tcp_entries.get_mut(&key) else {
                continue;
            };
            let socket = sockets.get_mut::<tcp::Socket>(entry.handle);

            if let Some(pending) = entry.pending_remote.as_mut() {
                if socket.can_send() {
                    match socket.send_slice(&pending.data.as_slice()[pending.offset..]) {
                        Ok(written) => {
                            pending.offset += written;
                            if pending.offset == pending.data.as_slice().len() {
                                if let Some(accepted) = pending.accepted.take() {
                                    let _ = accepted.send(());
                                }
                                entry.pending_remote = None;
                            }
                        }
                        Err(_) => {
                            socket.abort();
                        }
                    }
                }
            }

            if entry.opened && socket.can_recv() && entry.commands.capacity() > 0 {
                let amount = socket.recv_queue().min(16 * 1024);
                let mut data = vec![0; amount];
                if let Ok(read) = socket.recv_slice(&mut data) {
                    data.truncate(read);
                    if read > 0 {
                        let command = TcpCommand::Data(Tracked::new(
                            Bytes::from(data),
                            Arc::clone(&self.counters),
                        ));
                        if entry.commands.try_send(command).is_err() {
                            socket.abort();
                        }
                    }
                }
            }

            if entry.opened
                && !entry.local_fin_sent
                && socket.state() == tcp::State::CloseWait
                && !socket.can_recv()
                && entry.commands.capacity() > 0
                && entry.commands.try_send(TcpCommand::LocalFin).is_ok()
            {
                entry.local_fin_sent = true;
            }

            if socket.state() == tcp::State::Closed
                || (entry.worker_done && entry.pending_remote.is_none() && !socket.is_active())
            {
                entry.cancel.cancel();
                remove.push((key, entry.handle));
            }
        }
        for (key, handle) in remove {
            self.tcp.remove(&key);
            self.sockets.remove(handle);
            self.counters
                .active_tcp_flows
                .fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn drive_udp(&mut self) {
        self.drain_udp_requests();
        self.send_udp_responses();
    }

    fn drain_udp_requests(&mut self) {
        let targets: Vec<_> = self.udp_targets.keys().copied().collect();
        let mut received = Vec::new();
        for target_key in targets {
            let Some(target_entry) = self.udp_targets.get_mut(&target_key) else {
                continue;
            };
            let socket = self.sockets.get_mut::<udp::Socket>(target_entry.handle);
            while socket.can_recv() {
                let Ok((payload, metadata)) = socket.recv() else {
                    break;
                };
                let app = from_smol_endpoint(metadata.endpoint);
                let target = target_entry.target;
                target_entry.last_activity = StdInstant::now();
                received.push((app, target, Bytes::copy_from_slice(payload)));
            }
        }

        for (app, target, payload) in received {
            if payload.len() > self.config.max_udp_payload_bytes {
                self.counters
                    .udp_datagrams_dropped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if self.config.dns_interception == DnsInterception::Port53 && target.port() == 53 {
                self.start_dns_query(app, target, payload);
            } else {
                self.dispatch_udp(app, target, payload);
            }
        }
    }

    fn start_dns_query(&mut self, app: SocketAddr, target: SocketAddr, query: Bytes) {
        if !self.accepting
            || query.len() > self.config.max_dns_payload_bytes
            || self.counters.active_dns_queries.load(Ordering::Relaxed)
                >= self.config.max_dns_queries
        {
            self.counters
                .dns_queries_rejected
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.counters
            .dns_queries_started
            .fetch_add(1, Ordering::Relaxed);
        let connector = Arc::clone(&self.connector);
        let events = self.events_tx.clone();
        let cancel = self.udp_dns_cancel.child_token();
        let counters = Arc::clone(&self.counters);
        let query = Tracked::new(query, Arc::clone(&counters));
        let active = ActiveGuard::dns(Arc::clone(&counters));
        let dns_timeout = self.config.dns_timeout;
        let max_dns_payload_bytes = self.config.max_dns_payload_bytes;
        self.tasks.spawn(async move {
            let _task = TaskGuard::new(Arc::clone(&counters));
            let (query, _query_lease) = query.into_parts();
            let result = tokio::select! {
                _ = cancel.cancelled() => Ok(None),
                result = timeout(dns_timeout, connector.exchange_dns(query, cancel.clone())) => {
                    match result {
                        Ok(Ok(response)) => Ok(Some(response)),
                        Ok(Err(error))
                            if error.kind == FlowErrorKind::Cancelled && cancel.is_cancelled() =>
                        {
                            Ok(None)
                        }
                        _ => Err(()),
                    }
                }
            };
            match result {
                Ok(Some(response)) if response.len() <= max_dns_payload_bytes => {
                    let response = Tracked::new(response, counters);
                    let _ = events
                        .send(EngineEvent::DnsResponse {
                            target,
                            app,
                            response,
                            _active: active,
                        })
                        .await;
                }
                Ok(Some(_)) => {
                    counters
                        .dns_queries_rejected
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(()) => {
                    counters.dns_queries_failed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {}
            }
        });
    }

    fn dispatch_udp(&mut self, app: SocketAddr, target: SocketAddr, payload: Bytes) {
        let key = UdpAssociationKey { app, target };
        if !self.udp_associations.contains_key(&key) {
            if !self.accepting || self.udp_associations.len() >= self.config.max_udp_associations {
                self.counters
                    .udp_datagrams_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.start_udp_worker(key);
        }
        let Some(entry) = self.udp_associations.get(&key) else {
            return;
        };
        if entry
            .commands
            .try_send(UdpCommand {
                endpoint: target,
                payload: Tracked::new(payload, Arc::clone(&self.counters)),
            })
            .is_err()
        {
            self.counters
                .udp_datagrams_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn start_udp_worker(&mut self, key: UdpAssociationKey) {
        let (commands, command_rx) = mpsc::channel(self.config.udp_channel_depth);
        let cancel = self.udp_dns_cancel.child_token();
        let worker_cancel = cancel.clone();
        let connector = Arc::clone(&self.connector);
        let events = self.events_tx.clone();
        let counters = Arc::clone(&self.counters);
        let worker_counters = Arc::clone(&counters);
        let connect_timeout = self.config.connect_timeout;
        let idle_timeout = self.config.udp_idle_timeout;
        let max_payload_bytes = self.config.max_udp_payload_bytes;
        self.tasks.spawn(async move {
            let _task = TaskGuard::new(Arc::clone(&counters));
            udp_worker(UdpWorkerContext {
                key,
                connector,
                commands: command_rx,
                events,
                cancel: worker_cancel,
                connect_timeout,
                idle_timeout,
                counters: worker_counters,
                max_payload_bytes,
            })
            .await;
        });
        self.udp_associations.insert(
            key,
            UdpAssociationEntry {
                commands,
                cancel,
                pending_response: None,
            },
        );
        let active = self
            .counters
            .active_udp_associations
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        update_peak(&self.counters.peak_udp_associations, active);
        self.counters
            .udp_associations_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    fn send_udp_responses(&mut self) {
        let keys: Vec<_> = self.udp_associations.keys().copied().collect();
        for key in keys {
            let Some(entry) = self.udp_associations.get_mut(&key) else {
                continue;
            };
            let Some(pending) = entry.pending_response.as_mut() else {
                continue;
            };
            if Self::try_send_udp_response(&mut self.sockets, &self.udp_targets, pending) {
                if let Some(accepted) = pending.accepted.take() {
                    let _ = accepted.send(());
                }
                entry.pending_response = None;
            }
        }

        let count = self.pending_dns_responses.len();
        for _ in 0..count {
            let Some(mut pending) = self.pending_dns_responses.pop_front() else {
                break;
            };
            if !Self::try_send_udp_response(&mut self.sockets, &self.udp_targets, &mut pending) {
                self.pending_dns_responses.push_back(pending);
                break;
            }
        }
    }

    fn try_send_udp_response(
        sockets: &mut SocketSet<'static>,
        targets: &HashMap<UdpTargetKey, UdpTargetEntry>,
        pending: &mut PendingUdpResponse,
    ) -> bool {
        let Some(target) = targets.get(&UdpTargetKey(pending.target)) else {
            return true;
        };
        let socket = sockets.get_mut::<udp::Socket>(target.handle);
        if !socket.can_send() {
            return false;
        }
        let metadata = udp::UdpMetadata {
            endpoint: to_smol_endpoint(pending.app),
            local_address: Some(IpAddress::from(pending.target.ip())),
            meta: Default::default(),
        };
        socket
            .send_slice(pending.payload.as_slice(), metadata)
            .is_ok()
    }

    fn remove_udp_association(&mut self, key: UdpAssociationKey) {
        if let Some(entry) = self.udp_associations.remove(&key) {
            entry.cancel.cancel();
            self.counters
                .active_udp_associations
                .fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn reap_udp_targets(&mut self) {
        let now = StdInstant::now();
        if now < self.next_udp_reap {
            return;
        }
        self.next_udp_reap = now + udp_reap_interval(&self.config);
        let idle = self.config.udp_idle_timeout;
        let dns_active = self.counters.active_dns_queries.load(Ordering::Relaxed) > 0;
        let association_targets: HashSet<_> = self
            .udp_associations
            .keys()
            .map(|association| association.target)
            .collect();
        let pending_dns_targets: HashSet<_> = self
            .pending_dns_responses
            .iter()
            .map(|pending| pending.target)
            .collect();
        let remove: Vec<_> = self
            .udp_targets
            .iter()
            .filter_map(|(key, entry)| {
                let association_in_use = association_targets.contains(&entry.target);
                let dns_in_use = (dns_active && entry.target.port() == 53)
                    || pending_dns_targets.contains(&entry.target);
                let in_use = association_in_use || dns_in_use;
                (!in_use && now.duration_since(entry.last_activity) >= idle).then_some(*key)
            })
            .collect();
        for key in remove {
            if let Some(entry) = self.udp_targets.remove(&key) {
                self.sockets.remove(entry.handle);
            }
        }
    }

    fn flush_device_output(&mut self) {
        while let Some(packet) = self.device.take_outgoing() {
            let tracked = Tracked::new(packet, Arc::clone(&self.counters));
            let permit = match Arc::clone(&self.egress_permits).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    self.device.put_outgoing_front(tracked.into_inner());
                    break;
                }
            };
            let depth = self
                .counters
                .egress_queue_depth
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            update_peak(&self.counters.peak_egress_queue_depth, depth);
            match self.egress.try_send(EgressPacket {
                packet: tracked,
                _permit: permit,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(packet)) => {
                    self.counters
                        .egress_queue_depth
                        .fetch_sub(1, Ordering::Relaxed);
                    self.device.put_outgoing_front(packet.packet.into_inner());
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.counters
                        .egress_queue_depth
                        .fetch_sub(1, Ordering::Relaxed);
                    self.record_failure(PacketRuntimeFailure::PacketWrite);
                    break;
                }
            }
        }
    }

    fn refresh_actor_buffered_bytes(&self) {
        let mut bytes = self.device.buffered_bytes();
        for entry in self.tcp.values() {
            let socket = self.sockets.get::<tcp::Socket>(entry.handle);
            bytes = bytes
                .saturating_add(socket.recv_queue())
                .saturating_add(socket.send_queue());
        }
        for entry in self.udp_targets.values() {
            let socket = self.sockets.get::<udp::Socket>(entry.handle);
            bytes = bytes
                .saturating_add(socket.recv_queue())
                .saturating_add(socket.send_queue());
        }
        self.counters.set_actor_buffered_bytes(bytes);
    }

    async fn cleanup(&mut self) {
        self.accepting = false;
        self.io_cancel.cancel();
        self.udp_dns_cancel.cancel();
        for entry in self.tcp.values() {
            entry.cancel.cancel();
        }
        for entry in self.udp_associations.values() {
            entry.cancel.cancel();
        }
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.tcp.clear();
        self.udp_associations.clear();
        self.pending_dns_responses.clear();
        let handles: Vec<_> = self
            .udp_targets
            .values()
            .map(|entry| entry.handle)
            .collect();
        self.udp_targets.clear();
        for handle in handles {
            self.sockets.remove(handle);
        }
        self.counters.active_tcp_flows.store(0, Ordering::Relaxed);
        self.counters
            .active_udp_associations
            .store(0, Ordering::Relaxed);
        self.counters.active_dns_queries.store(0, Ordering::Relaxed);
    }
}

fn udp_reap_interval(config: &PacketRuntimeConfig) -> Duration {
    config
        .udp_idle_timeout
        .min(Duration::from_secs(1))
        .max(config.poll_interval)
}

struct TcpWorkerContext {
    key: TcpFlowKey,
    connector: Arc<dyn FlowConnector>,
    commands: mpsc::Receiver<TcpCommand>,
    events: mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    connect_timeout: Duration,
    idle_timeout: Duration,
    counters: Arc<Counters>,
}

async fn tcp_worker(context: TcpWorkerContext) {
    let TcpWorkerContext {
        key,
        connector,
        mut commands,
        events,
        cancel,
        connect_timeout,
        idle_timeout,
        counters,
    } = context;
    let result = tokio::select! {
        _ = cancel.cancelled() => return,
        result = timeout(connect_timeout, connector.open_tcp(key.target, cancel.clone())) => result,
    };
    let opened = match result {
        Ok(Ok(flow)) => flow,
        Ok(Err(error)) if error.kind == FlowErrorKind::Cancelled && cancel.is_cancelled() => {
            return;
        }
        _ => {
            let _ = events
                .send(EngineEvent::TcpDone { key, failed: true })
                .await;
            return;
        }
    };
    if events.send(EngineEvent::TcpOpened(key)).await.is_err() {
        return;
    }
    relay_tcp_flow(
        key,
        opened,
        &mut commands,
        &events,
        cancel,
        idle_timeout,
        counters,
    )
    .await;
}

async fn relay_tcp_flow(
    key: TcpFlowKey,
    flow: BoxTcpFlow,
    commands: &mut mpsc::Receiver<TcpCommand>,
    events: &mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    idle_timeout: Duration,
    counters: Arc<Counters>,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(flow);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let local = relay_tcp_local_to_remote(
        &mut remote_write,
        commands,
        cancel.clone(),
        activity_tx.clone(),
    );
    let remote = relay_tcp_remote_to_local(
        key,
        &mut remote_read,
        events,
        cancel.clone(),
        activity_tx,
        counters,
    );
    tokio::pin!(local);
    tokio::pin!(remote);

    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut local_done = false;
    let mut remote_done = false;
    let mut failed = false;

    while !local_done || !remote_done {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = &mut local, if !local_done => {
                local_done = true;
                if result.is_err() {
                    failed = true;
                    break;
                }
                idle.as_mut().reset(TokioInstant::now() + idle_timeout);
            }
            result = &mut remote, if !remote_done => {
                remote_done = true;
                if result.is_err() {
                    failed = true;
                    break;
                }
                idle.as_mut().reset(TokioInstant::now() + idle_timeout);
            }
            activity = activity_rx.recv() => {
                if activity.is_some() {
                    idle.as_mut().reset(TokioInstant::now() + idle_timeout);
                }
            }
            _ = &mut idle => {
                failed = true;
                break;
            }
        }
    }
    let _ = events
        .send(EngineEvent::TcpDone {
            key,
            failed: failed && !cancel.is_cancelled(),
        })
        .await;
}

async fn relay_tcp_local_to_remote<W: AsyncWrite + Unpin>(
    remote_write: &mut W,
    commands: &mut mpsc::Receiver<TcpCommand>,
    cancel: CancellationToken,
    activity: mpsc::Sender<()>,
) -> Result<(), ()> {
    loop {
        let command = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            command = commands.recv() => command,
        };
        match command {
            Some(TcpCommand::Data(data)) => {
                let result = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = remote_write.write_all(data.as_slice()) => result,
                };
                result.map_err(|_| ())?;
                let _ = activity.try_send(());
            }
            Some(TcpCommand::LocalFin) | None => {
                let result = tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    result = remote_write.shutdown() => result,
                };
                result.map_err(|_| ())?;
                let _ = activity.try_send(());
                return Ok(());
            }
        }
    }
}

async fn relay_tcp_remote_to_local<R: AsyncRead + Unpin>(
    key: TcpFlowKey,
    remote_read: &mut R,
    events: &mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    activity: mpsc::Sender<()>,
    counters: Arc<Counters>,
) -> Result<(), ()> {
    let mut read_buffer = vec![0; 16 * 1024];
    loop {
        let length = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = remote_read.read(&mut read_buffer) => result.map_err(|_| ())?,
        };
        if length == 0 {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = events.send(EngineEvent::TcpRemoteFin(key)) => result.map_err(|_| ())?,
            }
            let _ = activity.try_send(());
            return Ok(());
        }

        let data = Tracked::new(
            Bytes::copy_from_slice(&read_buffer[..length]),
            Arc::clone(&counters),
        );
        let (accepted, wait) = oneshot::channel();
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = events.send(EngineEvent::TcpData { key, data, accepted }) => {
                result.map_err(|_| ())?;
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = wait => result.map_err(|_| ())?,
        }
        let _ = activity.try_send(());
    }
}

struct UdpWorkerContext {
    key: UdpAssociationKey,
    connector: Arc<dyn FlowConnector>,
    commands: mpsc::Receiver<UdpCommand>,
    events: mpsc::Sender<EngineEvent>,
    cancel: CancellationToken,
    connect_timeout: Duration,
    idle_timeout: Duration,
    counters: Arc<Counters>,
    max_payload_bytes: usize,
}

async fn udp_worker(context: UdpWorkerContext) {
    let UdpWorkerContext {
        key,
        connector,
        mut commands,
        events,
        cancel,
        connect_timeout,
        idle_timeout,
        counters,
        max_payload_bytes,
    } = context;
    let result = tokio::select! {
        _ = cancel.cancelled() => return,
        result = timeout(connect_timeout, connector.open_udp(cancel.clone())) => result,
    };
    let mut flow = match result {
        Ok(Ok(flow)) => flow,
        Ok(Err(error)) if error.kind == FlowErrorKind::Cancelled && cancel.is_cancelled() => {
            return;
        }
        _ => {
            let _ = events
                .send(EngineEvent::UdpDone { key, failed: true })
                .await;
            return;
        }
    };

    let mut failed = false;
    loop {
        let command = tokio::select! {
            _ = cancel.cancelled() => break,
            result = timeout(idle_timeout, commands.recv()) => match result {
                Ok(command) => command,
                Err(_) => break,
            }
        };
        let Some(command) = command else {
            break;
        };
        let (payload, _payload_lease) = command.payload.into_parts();
        let datagram = Datagram::new(command.endpoint, payload);
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            result = timeout(
                idle_timeout,
                flow.exchange(datagram, cancel.clone()),
            ) => result,
        };
        let datagram = match result {
            Ok(Ok(datagram)) => datagram,
            Ok(Err(error)) if error.kind == FlowErrorKind::Cancelled && cancel.is_cancelled() => {
                break;
            }
            _ => {
                failed = true;
                break;
            }
        };
        if datagram.payload.len() > max_payload_bytes {
            failed = true;
            break;
        }
        let endpoint = datagram.endpoint;
        let payload = Tracked::new(datagram.payload, Arc::clone(&counters));
        let (accepted, wait) = oneshot::channel();
        if events
            .send(EngineEvent::UdpResponse {
                key,
                endpoint,
                payload,
                accepted,
            })
            .await
            .is_err()
        {
            return;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = wait => {}
        }
    }
    let close = timeout(Duration::from_secs(1), flow.close()).await;
    if !cancel.is_cancelled() && !matches!(close, Ok(Ok(()))) {
        failed = true;
    }
    let _ = events
        .send(EngineEvent::UdpDone {
            key,
            failed: failed && !cancel.is_cancelled(),
        })
        .await;
}

fn classify_packet(packet: &[u8]) -> Result<PacketClass, ()> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => classify_ipv4(packet),
        Some(6) => classify_ipv6(packet),
        _ => Err(()),
    }
}

fn classify_ipv4(packet: &[u8]) -> Result<PacketClass, ()> {
    let packet = Ipv4Packet::new_checked(packet).map_err(|_| ())?;
    let source = IpAddr::from(IpAddress::Ipv4(packet.src_addr()));
    let destination = IpAddr::from(IpAddress::Ipv4(packet.dst_addr()));
    if packet.frag_offset() != 0 {
        return Ok(PacketClass::Fragment(destination));
    }
    classify_transport(
        source,
        destination,
        packet.next_header(),
        packet.payload(),
        packet.more_frags(),
    )
}

fn classify_ipv6(packet: &[u8]) -> Result<PacketClass, ()> {
    let packet = Ipv6Packet::new_checked(packet).map_err(|_| ())?;
    let source = IpAddr::from(IpAddress::Ipv6(packet.src_addr()));
    let destination = IpAddr::from(IpAddress::Ipv6(packet.dst_addr()));
    classify_transport(
        source,
        destination,
        packet.next_header(),
        packet.payload(),
        false,
    )
}

fn classify_transport(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpProtocol,
    payload: &[u8],
    fragmented: bool,
) -> Result<PacketClass, ()> {
    match protocol {
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).map_err(|_| ())?;
            let app = SocketAddr::new(source, packet.src_port());
            let target = SocketAddr::new(destination, packet.dst_port());
            Ok(PacketClass::Tcp {
                key: TcpFlowKey { app, target },
                new_syn: packet.syn() && !packet.ack() && !packet.rst(),
            })
        }
        IpProtocol::Udp => {
            let (source_port, destination_port) = if fragmented {
                if payload.len() < 8 {
                    return Err(());
                }
                (
                    u16::from_be_bytes([payload[0], payload[1]]),
                    u16::from_be_bytes([payload[2], payload[3]]),
                )
            } else {
                let packet = UdpPacket::new_checked(payload).map_err(|_| ())?;
                (packet.src_port(), packet.dst_port())
            };
            let _app = SocketAddr::new(source, source_port);
            Ok(PacketClass::Udp {
                target: SocketAddr::new(destination, destination_port),
            })
        }
        _ => Ok(PacketClass::Unsupported),
    }
}

fn to_smol_endpoint(endpoint: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(endpoint.ip()), endpoint.port())
}

fn from_smol_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(IpAddr::from(endpoint.addr), endpoint.port)
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BlockedExchangeState {
        exchange_entered: Notify,
        send_release: Notify,
        inbound_ready: Notify,
        inbound_injected: AtomicBool,
        exchange_calls: AtomicUsize,
        close_calls: AtomicUsize,
    }

    impl BlockedExchangeState {
        fn new() -> Self {
            Self {
                exchange_entered: Notify::new(),
                send_release: Notify::new(),
                inbound_ready: Notify::new(),
                inbound_injected: AtomicBool::new(false),
                exchange_calls: AtomicUsize::new(0),
                close_calls: AtomicUsize::new(0),
            }
        }

        fn inject_inbound(&self) {
            self.inbound_injected.store(true, Ordering::SeqCst);
            self.inbound_ready.notify_one();
        }
    }

    struct BlockedExchangeFlow {
        state: Arc<BlockedExchangeState>,
        response: Datagram,
    }

    impl crate::DatagramFlow for BlockedExchangeFlow {
        fn exchange<'a>(
            &'a mut self,
            _datagram: Datagram,
            _cancel: CancellationToken,
        ) -> crate::BoxFuture<'a, Result<Datagram, crate::FlowError>> {
            let state = Arc::clone(&self.state);
            let response = self.response.clone();
            Box::pin(async move {
                state.exchange_calls.fetch_add(1, Ordering::SeqCst);
                state.exchange_entered.notify_one();
                state.send_release.notified().await;
                state.inbound_ready.notified().await;
                if !state.inbound_injected.load(Ordering::SeqCst) {
                    return Err(crate::FlowError::new(FlowErrorKind::DatagramExchange));
                }
                Ok(response)
            })
        }

        fn close<'a>(&'a mut self) -> crate::BoxFuture<'a, Result<(), crate::FlowError>> {
            self.state.close_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    struct BlockedExchangeConnector {
        state: Arc<BlockedExchangeState>,
        response: Datagram,
    }

    impl FlowConnector for BlockedExchangeConnector {
        fn snapshot(&self) -> FlowConnectorSnapshot {
            FlowConnectorSnapshot::default()
        }

        fn open_tcp<'a>(
            &'a self,
            _target: SocketAddr,
            _cancel: CancellationToken,
        ) -> crate::BoxFuture<'a, Result<BoxTcpFlow, crate::FlowError>> {
            Box::pin(async { Err(crate::FlowError::new(FlowErrorKind::RemoteConnection)) })
        }

        fn exchange_dns<'a>(
            &'a self,
            _query: Bytes,
            _cancel: CancellationToken,
        ) -> crate::BoxFuture<'a, Result<Bytes, crate::FlowError>> {
            Box::pin(async { Err(crate::FlowError::new(FlowErrorKind::DnsExchange)) })
        }

        fn open_udp<'a>(
            &'a self,
            _cancel: CancellationToken,
        ) -> crate::BoxFuture<'a, Result<Box<dyn crate::DatagramFlow>, crate::FlowError>> {
            let flow = BlockedExchangeFlow {
                state: Arc::clone(&self.state),
                response: self.response.clone(),
            };
            Box::pin(async move { Ok(Box::new(flow) as Box<dyn crate::DatagramFlow>) })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PrivateDatagramError {
        Closed,
        Cancelled,
        Capacity,
        SendFailed,
        ReceiveFailed,
        TimedOut,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PrivateTerminalState {
        Running,
        Closed,
        Cancelled,
        SendFailed,
        ReceiveFailed,
    }

    impl PrivateTerminalState {
        fn error(self) -> PrivateDatagramError {
            match self {
                Self::Running | Self::Closed => PrivateDatagramError::Closed,
                Self::Cancelled => PrivateDatagramError::Cancelled,
                Self::SendFailed => PrivateDatagramError::SendFailed,
                Self::ReceiveFailed => PrivateDatagramError::ReceiveFailed,
            }
        }
    }

    async fn wait_for_private_terminal(
        mut terminal: tokio::sync::watch::Receiver<PrivateTerminalState>,
    ) -> PrivateDatagramError {
        loop {
            let state = *terminal.borrow();
            if state != PrivateTerminalState::Running {
                return state.error();
            }
            if terminal.changed().await.is_err() {
                return PrivateDatagramError::Closed;
            }
        }
    }

    #[derive(Clone, Copy)]
    struct PrivateAssociationLimits {
        packet_count: usize,
        byte_count: usize,
        channel_depth: usize,
    }

    impl Default for PrivateAssociationLimits {
        fn default() -> Self {
            Self {
                packet_count: 2,
                byte_count: 64,
                channel_depth: 2,
            }
        }
    }

    struct PrivateQueuedDatagram {
        datagram: Datagram,
        _packet_permit: OwnedSemaphorePermit,
        _byte_permit: OwnedSemaphorePermit,
    }

    struct PrivateSendCommand {
        datagram: Datagram,
        complete: oneshot::Sender<Result<(), PrivateDatagramError>>,
        _packet_permit: OwnedSemaphorePermit,
        _byte_permit: OwnedSemaphorePermit,
    }

    async fn acquire_private_budget(
        packet_budget: &Arc<Semaphore>,
        byte_budget: &Arc<Semaphore>,
        byte_capacity: usize,
        payload_len: usize,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), PrivateDatagramError> {
        if payload_len > byte_capacity || payload_len > u32::MAX as usize {
            return Err(PrivateDatagramError::Capacity);
        }
        let packet_permit = Arc::clone(packet_budget)
            .acquire_owned()
            .await
            .map_err(|_| PrivateDatagramError::Closed)?;
        let byte_permit = Arc::clone(byte_budget)
            .acquire_many_owned(payload_len as u32)
            .await
            .map_err(|_| PrivateDatagramError::Closed)?;
        Ok((packet_permit, byte_permit))
    }

    struct PrivateDatagramTx {
        commands: mpsc::Sender<PrivateSendCommand>,
        terminal: tokio::sync::watch::Receiver<PrivateTerminalState>,
        packet_budget: Arc<Semaphore>,
        byte_budget: Arc<Semaphore>,
        byte_capacity: usize,
        state: Arc<PrivateFakeState>,
    }

    impl PrivateDatagramTx {
        async fn send(&self, datagram: Datagram) -> Result<(), PrivateDatagramError> {
            if *self.terminal.borrow() != PrivateTerminalState::Running {
                return Err(self.terminal.borrow().error());
            }
            let (packet_permit, byte_permit) = match acquire_private_budget(
                &self.packet_budget,
                &self.byte_budget,
                self.byte_capacity,
                datagram.payload.len(),
            )
            .await
            {
                Ok(budget) => budget,
                Err(PrivateDatagramError::Capacity) => {
                    return Err(PrivateDatagramError::Capacity);
                }
                Err(PrivateDatagramError::Closed) => {
                    return Err(wait_for_private_terminal(self.terminal.clone()).await);
                }
                Err(error) => return Err(error),
            };
            self.state.outbound_admitted.fetch_add(1, Ordering::SeqCst);
            self.state.outbound_admitted_notify.notify_one();
            let (complete, wait) = oneshot::channel();
            if self
                .commands
                .send(PrivateSendCommand {
                    datagram,
                    complete,
                    _packet_permit: packet_permit,
                    _byte_permit: byte_permit,
                })
                .await
                .is_err()
            {
                return Err(wait_for_private_terminal(self.terminal.clone()).await);
            }
            match wait.await {
                Ok(result) => result,
                Err(_) => Err(wait_for_private_terminal(self.terminal.clone()).await),
            }
        }
    }

    struct PrivateDatagramRx {
        inbound: mpsc::Receiver<PrivateQueuedDatagram>,
        terminal: tokio::sync::watch::Receiver<PrivateTerminalState>,
    }

    impl PrivateDatagramRx {
        async fn recv(&mut self) -> Result<Datagram, PrivateDatagramError> {
            loop {
                tokio::select! {
                    biased;
                    changed = self.terminal.changed() => {
                        if changed.is_err()
                            || *self.terminal.borrow() != PrivateTerminalState::Running
                        {
                            return Err(self.terminal.borrow().error());
                        }
                    }
                    item = self.inbound.recv() => {
                        return match item {
                            Some(queued) => Ok(queued.datagram),
                            None => Err(wait_for_private_terminal(self.terminal.clone()).await),
                        };
                    }
                }
            }
        }
    }

    enum PrivateControlCommand {
        Close(oneshot::Sender<Result<(), PrivateDatagramError>>),
    }

    struct PrivateDatagramControl {
        commands: mpsc::Sender<PrivateControlCommand>,
        immediate_cancel: CancellationToken,
        terminal: tokio::sync::watch::Receiver<PrivateTerminalState>,
        join: Option<JoinHandle<()>>,
    }

    impl PrivateDatagramControl {
        async fn close(mut self) -> Result<(), PrivateDatagramError> {
            let (complete, wait) = oneshot::channel();
            if self
                .commands
                .send(PrivateControlCommand::Close(complete))
                .await
                .is_err()
            {
                self.join_task().await?;
                return match *self.terminal.borrow() {
                    PrivateTerminalState::Closed => Ok(()),
                    state => Err(state.error()),
                };
            }
            let result = match timeout(Duration::from_secs(1), wait).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(wait_for_private_terminal(self.terminal.clone()).await),
                Err(_) => {
                    self.immediate_cancel.cancel();
                    Err(PrivateDatagramError::TimedOut)
                }
            };
            let join = self.join_task().await;
            result.and(join)
        }

        async fn cancel(mut self) -> Result<(), PrivateDatagramError> {
            self.immediate_cancel.cancel();
            self.join_task().await
        }

        async fn join_task(&mut self) -> Result<(), PrivateDatagramError> {
            let Some(mut join) = self.join.take() else {
                return Ok(());
            };
            match timeout(Duration::from_secs(1), &mut join).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(PrivateDatagramError::Cancelled),
                Err(_) => {
                    self.immediate_cancel.cancel();
                    join.abort();
                    let _ = join.await;
                    Err(PrivateDatagramError::TimedOut)
                }
            }
        }
    }

    impl Drop for PrivateDatagramControl {
        fn drop(&mut self) {
            self.immediate_cancel.cancel();
        }
    }

    struct PrivateOwnedDatagramAssociation {
        tx: PrivateDatagramTx,
        rx: PrivateDatagramRx,
        control: PrivateDatagramControl,
    }

    struct PrivateFakeState {
        send_entered: Notify,
        send_release: Notify,
        send_accepted: Notify,
        outbound_admitted_notify: Notify,
        inbound_admission_attempted: Notify,
        inbound_received: Notify,
        inbound_forwarded: Notify,
        close_requested: Notify,
        actor_started: Notify,
        actor_released: Notify,
        fail_send: AtomicBool,
        active_actors: AtomicUsize,
        active_adapters: AtomicUsize,
        send_calls: AtomicUsize,
        send_inflight: AtomicUsize,
        send_accepts: AtomicUsize,
        outbound_admitted: AtomicUsize,
        inbound_admission_attempts: AtomicUsize,
        receive_calls: AtomicUsize,
        receive_forwarded: AtomicUsize,
        close_requests: AtomicUsize,
        close_calls: AtomicUsize,
    }

    impl PrivateFakeState {
        fn new() -> Self {
            Self {
                send_entered: Notify::new(),
                send_release: Notify::new(),
                send_accepted: Notify::new(),
                outbound_admitted_notify: Notify::new(),
                inbound_admission_attempted: Notify::new(),
                inbound_received: Notify::new(),
                inbound_forwarded: Notify::new(),
                close_requested: Notify::new(),
                actor_started: Notify::new(),
                actor_released: Notify::new(),
                fail_send: AtomicBool::new(false),
                active_actors: AtomicUsize::new(0),
                active_adapters: AtomicUsize::new(0),
                send_calls: AtomicUsize::new(0),
                send_inflight: AtomicUsize::new(0),
                send_accepts: AtomicUsize::new(0),
                outbound_admitted: AtomicUsize::new(0),
                inbound_admission_attempts: AtomicUsize::new(0),
                receive_calls: AtomicUsize::new(0),
                receive_forwarded: AtomicUsize::new(0),
                close_requests: AtomicUsize::new(0),
                close_calls: AtomicUsize::new(0),
            }
        }
    }

    struct PrivateActorGuard {
        state: Arc<PrivateFakeState>,
        terminal: tokio::sync::watch::Sender<PrivateTerminalState>,
        terminal_published: bool,
    }

    impl PrivateActorGuard {
        fn new(
            state: Arc<PrivateFakeState>,
            terminal: tokio::sync::watch::Sender<PrivateTerminalState>,
        ) -> Self {
            state.active_actors.fetch_add(1, Ordering::SeqCst);
            state.actor_started.notify_one();
            Self {
                state,
                terminal,
                terminal_published: false,
            }
        }

        fn publish_terminal(&mut self, state: PrivateTerminalState) {
            if !self.terminal_published {
                self.terminal_published = true;
                let _ = self.terminal.send(state);
            }
        }
    }

    impl Drop for PrivateActorGuard {
        fn drop(&mut self) {
            self.publish_terminal(PrivateTerminalState::Cancelled);
            self.state.active_actors.fetch_sub(1, Ordering::SeqCst);
            self.state.actor_released.notify_one();
        }
    }

    struct PrivateSendAttemptGuard {
        state: Arc<PrivateFakeState>,
    }

    impl PrivateSendAttemptGuard {
        fn new(state: Arc<PrivateFakeState>) -> Self {
            state.send_inflight.fetch_add(1, Ordering::SeqCst);
            Self { state }
        }
    }

    impl Drop for PrivateSendAttemptGuard {
        fn drop(&mut self) {
            self.state.send_inflight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct PrivateFakeSendHalf {
        state: Arc<PrivateFakeState>,
    }

    impl PrivateFakeSendHalf {
        fn begin_send(
            &mut self,
            _datagram: Datagram,
        ) -> crate::BoxFuture<'static, Result<(), PrivateDatagramError>> {
            let state = Arc::clone(&self.state);
            Box::pin(async move {
                state.send_calls.fetch_add(1, Ordering::SeqCst);
                let _inflight = PrivateSendAttemptGuard::new(Arc::clone(&state));
                state.send_entered.notify_one();
                state.send_release.notified().await;
                if state.fail_send.load(Ordering::SeqCst) {
                    return Err(PrivateDatagramError::SendFailed);
                }
                state.send_accepts.fetch_add(1, Ordering::SeqCst);
                state.send_accepted.notify_one();
                Ok(())
            })
        }
    }

    struct PrivateFakeRecvHalf {
        inbound: mpsc::Receiver<Result<PrivateQueuedDatagram, PrivateDatagramError>>,
        state: Arc<PrivateFakeState>,
    }

    struct PrivateFakeCloseOwner {
        state: Arc<PrivateFakeState>,
        closed: bool,
    }

    impl PrivateFakeCloseOwner {
        fn new(state: Arc<PrivateFakeState>) -> Self {
            state.active_adapters.fetch_add(1, Ordering::SeqCst);
            Self {
                state,
                closed: false,
            }
        }

        async fn close(&mut self) {
            if !self.closed {
                self.closed = true;
                self.state.close_calls.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl Drop for PrivateFakeCloseOwner {
        fn drop(&mut self) {
            self.state.active_adapters.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct PrivateFakeIngress {
        inbound: mpsc::Sender<Result<PrivateQueuedDatagram, PrivateDatagramError>>,
        packet_budget: Arc<Semaphore>,
        byte_budget: Arc<Semaphore>,
        byte_capacity: usize,
        state: Arc<PrivateFakeState>,
    }

    impl PrivateFakeIngress {
        async fn inject(&self, datagram: Datagram) -> Result<(), PrivateDatagramError> {
            self.state
                .inbound_admission_attempts
                .fetch_add(1, Ordering::SeqCst);
            self.state.inbound_admission_attempted.notify_one();
            let (packet_permit, byte_permit) = acquire_private_budget(
                &self.packet_budget,
                &self.byte_budget,
                self.byte_capacity,
                datagram.payload.len(),
            )
            .await?;
            self.inbound
                .send(Ok(PrivateQueuedDatagram {
                    datagram,
                    _packet_permit: packet_permit,
                    _byte_permit: byte_permit,
                }))
                .await
                .map_err(|_| PrivateDatagramError::Closed)
        }

        async fn fail_receive(&self) -> Result<(), PrivateDatagramError> {
            self.inbound
                .send(Err(PrivateDatagramError::ReceiveFailed))
                .await
                .map_err(|_| PrivateDatagramError::Closed)
        }
    }

    struct PrivateAssociationHarness {
        ingress: PrivateFakeIngress,
        state: Arc<PrivateFakeState>,
        outbound_packets: Arc<Semaphore>,
        outbound_bytes: Arc<Semaphore>,
        inbound_packets: Arc<Semaphore>,
        inbound_bytes: Arc<Semaphore>,
        limits: PrivateAssociationLimits,
    }

    impl PrivateAssociationHarness {
        fn release_send(&self) {
            self.state.send_release.notify_one();
        }

        fn fail_send(&self) {
            self.state.fail_send.store(true, Ordering::SeqCst);
        }

        fn assert_released(&self) {
            assert_eq!(self.state.active_actors.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.active_adapters.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.send_inflight.load(Ordering::SeqCst), 0);
            assert_eq!(
                self.outbound_packets.available_permits(),
                self.limits.packet_count
            );
            assert_eq!(
                self.outbound_bytes.available_permits(),
                self.limits.byte_count
            );
            assert_eq!(
                self.inbound_packets.available_permits(),
                self.limits.packet_count
            );
            assert_eq!(
                self.inbound_bytes.available_permits(),
                self.limits.byte_count
            );
            assert_eq!(self.state.close_calls.load(Ordering::SeqCst), 1);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PrivateDirectionExit {
        Graceful,
        Cancelled,
        Fatal(PrivateDatagramError),
    }

    fn fail_queued_private_sends(
        commands: &mut mpsc::Receiver<PrivateSendCommand>,
        error: PrivateDatagramError,
    ) {
        commands.close();
        while let Ok(command) = commands.try_recv() {
            let _ = command.complete.send(Err(error));
        }
    }

    async fn drive_private_send_direction(
        mut send_half: PrivateFakeSendHalf,
        mut commands: mpsc::Receiver<PrivateSendCommand>,
        graceful_stop: CancellationToken,
        immediate_cancel: CancellationToken,
        terminal: tokio::sync::watch::Receiver<PrivateTerminalState>,
    ) -> PrivateDirectionExit {
        loop {
            let command = tokio::select! {
                biased;
                _ = immediate_cancel.cancelled() => {
                    let error = match *terminal.borrow() {
                        PrivateTerminalState::Running => PrivateDatagramError::Cancelled,
                        state => state.error(),
                    };
                    fail_queued_private_sends(
                        &mut commands,
                        error,
                    );
                    return if error == PrivateDatagramError::Cancelled {
                        PrivateDirectionExit::Cancelled
                    } else {
                        PrivateDirectionExit::Fatal(error)
                    };
                }
                _ = graceful_stop.cancelled() => {
                    fail_queued_private_sends(
                        &mut commands,
                        PrivateDatagramError::Closed,
                    );
                    return PrivateDirectionExit::Graceful;
                }
                command = commands.recv() => match command {
                    Some(command) => command,
                    None => return PrivateDirectionExit::Graceful,
                }
            };
            let PrivateSendCommand {
                datagram,
                complete,
                _packet_permit,
                _byte_permit,
            } = command;
            let mut pending_send = send_half.begin_send(datagram);
            let result = tokio::select! {
                biased;
                _ = immediate_cancel.cancelled() => {
                    Err(match *terminal.borrow() {
                        PrivateTerminalState::Running => PrivateDatagramError::Cancelled,
                        state => state.error(),
                    })
                }
                result = &mut pending_send => result,
            };
            let _ = complete.send(result);
            drop(_packet_permit);
            drop(_byte_permit);
            match result {
                Ok(()) => {}
                Err(PrivateDatagramError::Cancelled) => {
                    fail_queued_private_sends(&mut commands, PrivateDatagramError::Cancelled);
                    return PrivateDirectionExit::Cancelled;
                }
                Err(error) => {
                    fail_queued_private_sends(&mut commands, error);
                    return PrivateDirectionExit::Fatal(error);
                }
            }
        }
    }

    async fn drive_private_receive_direction(
        mut recv_half: PrivateFakeRecvHalf,
        inbound: mpsc::Sender<PrivateQueuedDatagram>,
        graceful_stop: CancellationToken,
        immediate_cancel: CancellationToken,
    ) -> PrivateDirectionExit {
        loop {
            let event = tokio::select! {
                biased;
                _ = immediate_cancel.cancelled() => {
                    return PrivateDirectionExit::Cancelled;
                }
                _ = graceful_stop.cancelled() => {
                    return PrivateDirectionExit::Graceful;
                }
                event = recv_half.inbound.recv() => match event {
                    Some(event) => event,
                    None => {
                        return PrivateDirectionExit::Fatal(
                            PrivateDatagramError::ReceiveFailed,
                        );
                    }
                }
            };
            let queued = match event {
                Ok(queued) => queued,
                Err(error) => return PrivateDirectionExit::Fatal(error),
            };
            recv_half.state.receive_calls.fetch_add(1, Ordering::SeqCst);
            recv_half.state.inbound_received.notify_one();
            let deliver = inbound.send(queued);
            tokio::pin!(deliver);
            let delivered = tokio::select! {
                biased;
                _ = immediate_cancel.cancelled() => false,
                _ = graceful_stop.cancelled() => false,
                result = &mut deliver => result.is_ok(),
            };
            if !delivered {
                return if immediate_cancel.is_cancelled() {
                    PrivateDirectionExit::Cancelled
                } else {
                    PrivateDirectionExit::Graceful
                };
            }
            recv_half
                .state
                .receive_forwarded
                .fetch_add(1, Ordering::SeqCst);
            recv_half.state.inbound_forwarded.notify_one();
        }
    }

    fn terminal_state_for(error: Option<PrivateDatagramError>) -> PrivateTerminalState {
        match error {
            None | Some(PrivateDatagramError::Closed) => PrivateTerminalState::Closed,
            Some(PrivateDatagramError::Cancelled | PrivateDatagramError::TimedOut) => {
                PrivateTerminalState::Cancelled
            }
            Some(PrivateDatagramError::SendFailed) => PrivateTerminalState::SendFailed,
            Some(PrivateDatagramError::ReceiveFailed | PrivateDatagramError::Capacity) => {
                PrivateTerminalState::ReceiveFailed
            }
        }
    }

    struct PrivateActorBudgets {
        outbound_packets: Arc<Semaphore>,
        outbound_bytes: Arc<Semaphore>,
        inbound_packets: Arc<Semaphore>,
        inbound_bytes: Arc<Semaphore>,
    }

    impl PrivateActorBudgets {
        fn close(&self) {
            self.outbound_packets.close();
            self.outbound_bytes.close();
            self.inbound_packets.close();
            self.inbound_bytes.close();
        }
    }

    struct PrivateAssociationActorContext {
        send_half: PrivateFakeSendHalf,
        recv_half: PrivateFakeRecvHalf,
        close_owner: PrivateFakeCloseOwner,
        send_commands: mpsc::Receiver<PrivateSendCommand>,
        inbound: mpsc::Sender<PrivateQueuedDatagram>,
        control: mpsc::Receiver<PrivateControlCommand>,
        immediate_cancel: CancellationToken,
        terminal: tokio::sync::watch::Sender<PrivateTerminalState>,
        budgets: PrivateActorBudgets,
        state: Arc<PrivateFakeState>,
    }

    async fn run_private_association_actor(context: PrivateAssociationActorContext) {
        let PrivateAssociationActorContext {
            send_half,
            recv_half,
            mut close_owner,
            send_commands,
            inbound,
            mut control,
            immediate_cancel,
            terminal,
            budgets,
            state,
        } = context;
        let direction_terminal = terminal.subscribe();
        let mut actor = PrivateActorGuard::new(Arc::clone(&state), terminal);
        let graceful_stop = CancellationToken::new();
        let mut send_direction = Box::pin(drive_private_send_direction(
            send_half,
            send_commands,
            graceful_stop.clone(),
            immediate_cancel.clone(),
            direction_terminal,
        ));
        let mut receive_direction = Box::pin(drive_private_receive_direction(
            recv_half,
            inbound,
            graceful_stop.clone(),
            immediate_cancel.clone(),
        ));
        let mut send_exit = None;
        let mut receive_exit = None;
        let mut close_waiter = None;
        let mut terminal_error = None;

        while send_exit.is_none() || receive_exit.is_none() {
            tokio::select! {
                biased;
                _ = immediate_cancel.cancelled(), if terminal_error.is_none() => {
                    terminal_error = Some(PrivateDatagramError::Cancelled);
                    actor.publish_terminal(PrivateTerminalState::Cancelled);
                    graceful_stop.cancel();
                }
                command = control.recv(),
                    if close_waiter.is_none() && terminal_error.is_none() =>
                {
                    match command {
                        Some(PrivateControlCommand::Close(waiter)) => {
                            state.close_requests.fetch_add(1, Ordering::SeqCst);
                            state.close_requested.notify_one();
                            close_waiter = Some(waiter);
                            graceful_stop.cancel();
                        }
                        None => {
                            terminal_error = Some(PrivateDatagramError::Cancelled);
                            immediate_cancel.cancel();
                            graceful_stop.cancel();
                        }
                    }
                }
                result = &mut send_direction, if send_exit.is_none() => {
                    send_exit = Some(result);
                    if let PrivateDirectionExit::Fatal(error) = result {
                        if terminal_error.is_none() {
                            terminal_error = Some(error);
                            actor.publish_terminal(terminal_state_for(Some(error)));
                        }
                        immediate_cancel.cancel();
                        graceful_stop.cancel();
                    } else if result == PrivateDirectionExit::Cancelled
                        && terminal_error.is_none()
                    {
                        terminal_error = Some(PrivateDatagramError::Cancelled);
                        immediate_cancel.cancel();
                        graceful_stop.cancel();
                    }
                }
                result = &mut receive_direction, if receive_exit.is_none() => {
                    receive_exit = Some(result);
                    if let PrivateDirectionExit::Fatal(error) = result {
                        if terminal_error.is_none() {
                            terminal_error = Some(error);
                            actor.publish_terminal(terminal_state_for(Some(error)));
                        }
                        immediate_cancel.cancel();
                        graceful_stop.cancel();
                    } else if result == PrivateDirectionExit::Cancelled
                        && terminal_error.is_none()
                    {
                        terminal_error = Some(PrivateDatagramError::Cancelled);
                        immediate_cancel.cancel();
                        graceful_stop.cancel();
                    }
                }
            }
        }

        let final_state = terminal_state_for(terminal_error);
        actor.publish_terminal(final_state);
        budgets.close();
        close_owner.close().await;
        if let Some(waiter) = close_waiter {
            let result = terminal_error.map_or(Ok(()), Err);
            let _ = waiter.send(result);
        }
    }

    fn start_private_owned_association(
        limits: PrivateAssociationLimits,
    ) -> (PrivateOwnedDatagramAssociation, PrivateAssociationHarness) {
        assert!(limits.packet_count > 0);
        assert!(limits.byte_count > 0);
        assert!(limits.channel_depth > 0);
        let state = Arc::new(PrivateFakeState::new());
        let outbound_packets = Arc::new(Semaphore::new(limits.packet_count));
        let outbound_bytes = Arc::new(Semaphore::new(limits.byte_count));
        let inbound_packets = Arc::new(Semaphore::new(limits.packet_count));
        let inbound_bytes = Arc::new(Semaphore::new(limits.byte_count));
        let (send_commands, send_command_rx) = mpsc::channel(limits.channel_depth);
        let (adapter_inbound, adapter_inbound_rx) = mpsc::channel(limits.channel_depth);
        let (inbound, inbound_rx) = mpsc::channel(limits.channel_depth);
        let (control, control_rx) = mpsc::channel(1);
        let (terminal, terminal_rx) = tokio::sync::watch::channel(PrivateTerminalState::Running);
        let immediate_cancel = CancellationToken::new();
        let send_half = PrivateFakeSendHalf {
            state: Arc::clone(&state),
        };
        let recv_half = PrivateFakeRecvHalf {
            inbound: adapter_inbound_rx,
            state: Arc::clone(&state),
        };
        let close_owner = PrivateFakeCloseOwner::new(Arc::clone(&state));
        let budgets = PrivateActorBudgets {
            outbound_packets: Arc::clone(&outbound_packets),
            outbound_bytes: Arc::clone(&outbound_bytes),
            inbound_packets: Arc::clone(&inbound_packets),
            inbound_bytes: Arc::clone(&inbound_bytes),
        };
        let actor_cancel = immediate_cancel.clone();
        let actor_state = Arc::clone(&state);
        let join = tokio::spawn(async move {
            run_private_association_actor(PrivateAssociationActorContext {
                send_half,
                recv_half,
                close_owner,
                send_commands: send_command_rx,
                inbound,
                control: control_rx,
                immediate_cancel: actor_cancel,
                terminal,
                budgets,
                state: actor_state,
            })
            .await;
        });
        let association = PrivateOwnedDatagramAssociation {
            tx: PrivateDatagramTx {
                commands: send_commands,
                terminal: terminal_rx.clone(),
                packet_budget: Arc::clone(&outbound_packets),
                byte_budget: Arc::clone(&outbound_bytes),
                byte_capacity: limits.byte_count,
                state: Arc::clone(&state),
            },
            rx: PrivateDatagramRx {
                inbound: inbound_rx,
                terminal: terminal_rx.clone(),
            },
            control: PrivateDatagramControl {
                commands: control,
                immediate_cancel,
                terminal: terminal_rx,
                join: Some(join),
            },
        };
        let harness = PrivateAssociationHarness {
            ingress: PrivateFakeIngress {
                inbound: adapter_inbound,
                packet_budget: Arc::clone(&inbound_packets),
                byte_budget: Arc::clone(&inbound_bytes),
                byte_capacity: limits.byte_count,
                state: Arc::clone(&state),
            },
            state,
            outbound_packets,
            outbound_bytes,
            inbound_packets,
            inbound_bytes,
            limits,
        };
        (association, harness)
    }

    #[tokio::test]
    async fn old_udp_worker_blocks_inbound_until_exchange_is_released() {
        let app = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_001);
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let key = UdpAssociationKey { app, target };
        let outbound = Bytes::from_static(b"A");
        let inbound = Bytes::from_static(b"B");
        let state = Arc::new(BlockedExchangeState::new());
        let connector: Arc<dyn FlowConnector> = Arc::new(BlockedExchangeConnector {
            state: Arc::clone(&state),
            response: Datagram::new(target, inbound.clone()),
        });
        let counters = Arc::new(Counters::new());
        let cancel = CancellationToken::new();
        let (commands_tx, commands_rx) = mpsc::channel(1);
        let (events_tx, mut events_rx) = mpsc::channel(2);
        commands_tx
            .send(UdpCommand {
                endpoint: target,
                payload: Tracked::new(outbound, Arc::clone(&counters)),
            })
            .await
            .unwrap();

        let worker = tokio::spawn(udp_worker(UdpWorkerContext {
            key,
            connector,
            commands: commands_rx,
            events: events_tx,
            cancel,
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            counters,
            max_payload_bytes: 64,
        }));

        state.exchange_entered.notified().await;
        assert_eq!(state.exchange_calls.load(Ordering::SeqCst), 1);
        state.inject_inbound();
        let delivered_before_release =
            matches!(events_rx.try_recv(), Ok(EngineEvent::UdpResponse { .. }));

        state.send_release.notify_one();
        match timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("old UDP worker did not finish exchange cleanup")
            .expect("old UDP worker closed its event channel")
        {
            EngineEvent::UdpResponse {
                key: event_key,
                endpoint,
                payload,
                accepted,
            } => {
                assert_eq!(event_key, key);
                assert_eq!(endpoint, target);
                assert_eq!(payload.as_slice(), inbound.as_ref());
                let _ = accepted.send(());
            }
            _ => panic!("unexpected old UDP worker event"),
        }
        drop(commands_tx);
        match timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("old UDP worker did not finish terminal cleanup")
            .expect("old UDP worker closed before terminal event")
        {
            EngineEvent::UdpDone {
                key: event_key,
                failed,
            } => {
                assert_eq!(event_key, key);
                assert!(!failed);
            }
            _ => panic!("unexpected old UDP worker terminal event"),
        }
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("old UDP worker task leaked")
            .expect("old UDP worker task panicked");
        assert_eq!(state.exchange_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.close_calls.load(Ordering::SeqCst), 1);

        assert!(
            !delivered_before_release,
            "old UDP worker unexpectedly delivered inbound before exchange(A) completed"
        );
    }

    fn assert_private_handle_is_send_static<T: Send + 'static>() {}

    async fn wait_for_private_count(
        counter: &AtomicUsize,
        notify: &Notify,
        expected: usize,
        message: &'static str,
    ) {
        timeout(Duration::from_secs(1), async {
            while counter.load(Ordering::SeqCst) < expected {
                notify.notified().await;
            }
        })
        .await
        .expect(message);
    }

    #[tokio::test]
    async fn private_owned_actor_receives_while_send_remains_pending() {
        assert_private_handle_is_send_static::<PrivateDatagramTx>();
        assert_private_handle_is_send_static::<PrivateDatagramRx>();
        assert_private_handle_is_send_static::<PrivateDatagramControl>();

        for _ in 0..64 {
            let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
            let (association, harness) =
                start_private_owned_association(PrivateAssociationLimits::default());
            let PrivateOwnedDatagramAssociation {
                tx,
                mut rx,
                control,
            } = association;
            let send = tokio::spawn(async move {
                tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                    .await
            });

            timeout(
                Duration::from_secs(1),
                harness.state.send_entered.notified(),
            )
            .await
            .expect("private send never reached the explicit barrier");
            assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
            assert_eq!(harness.state.send_inflight.load(Ordering::SeqCst), 1);
            assert!(!send.is_finished());

            let receive = tokio::spawn(async move { rx.recv().await });
            harness
                .ingress
                .inject(Datagram::new(target, Bytes::from_static(b"B")))
                .await
                .unwrap();
            let received = timeout(Duration::from_secs(1), receive)
                .await
                .expect("private receive made no progress while send was blocked")
                .expect("private receive task panicked")
                .expect("private receive failed");
            assert_eq!(received, Datagram::new(target, Bytes::from_static(b"B")));
            assert!(!send.is_finished());
            assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
            assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
            assert_eq!(harness.state.send_inflight.load(Ordering::SeqCst), 1);

            harness.release_send();
            timeout(Duration::from_secs(1), send)
                .await
                .expect("private send did not complete after barrier release")
                .expect("private send task panicked")
                .expect("private send failed");
            assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
            assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 1);
            assert_eq!(harness.state.send_inflight.load(Ordering::SeqCst), 0);
            assert_eq!(harness.state.receive_calls.load(Ordering::SeqCst), 1);
            assert_eq!(harness.state.receive_forwarded.load(Ordering::SeqCst), 1);

            control.close().await.expect("private close failed");
            harness.assert_released();
        }
    }

    #[tokio::test]
    async fn private_owned_actor_finishes_accepted_send_after_waiter_cancel() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            mut rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");
        send.abort();
        assert!(send
            .await
            .expect_err("send waiter was not cancelled")
            .is_cancelled());

        harness
            .ingress
            .inject(Datagram::new(target, Bytes::from_static(b"B")))
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive stalled after send waiter cancellation")
            .expect("receive failed after send waiter cancellation");
        assert_eq!(received.payload, Bytes::from_static(b"B"));
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);

        harness.release_send();
        timeout(
            Duration::from_secs(1),
            harness.state.send_accepted.notified(),
        )
        .await
        .expect("accepted send was cancelled with its caller");
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 1);
        control.close().await.expect("private close failed");
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_receive_wait_can_be_cancelled_without_consuming_next_packet() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx: _tx,
            mut rx,
            control,
        } = association;
        let mut cancelled_wait = Box::pin(rx.recv());
        assert!(futures::poll!(&mut cancelled_wait).is_pending());
        drop(cancelled_wait);

        harness
            .ingress
            .inject(Datagram::new(target, Bytes::from_static(b"B")))
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("new receive wait did not make progress")
            .expect("new receive wait failed");
        assert_eq!(received.payload, Bytes::from_static(b"B"));
        control.close().await.expect("private close failed");
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_immediate_cancel_releases_blocked_send_and_all_budgets() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            rx: _rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");

        control.cancel().await.expect("private cancel failed");
        let send_result = timeout(Duration::from_secs(1), send)
            .await
            .expect("cancelled send waiter leaked")
            .expect("cancelled send waiter task panicked");
        assert_eq!(send_result, Err(PrivateDatagramError::Cancelled));
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_outbound_packet_and_byte_budgets_backpressure_third_send() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let limits = PrivateAssociationLimits {
            packet_count: 2,
            byte_count: 2,
            channel_depth: 1,
        };
        let (association, harness) = start_private_owned_association(limits);
        let PrivateOwnedDatagramAssociation {
            tx,
            rx: _rx,
            control,
        } = association;
        let sends = tokio::spawn(async move {
            tokio::join!(
                tx.send(Datagram::new(target, Bytes::from_static(b"A"))),
                tx.send(Datagram::new(target, Bytes::from_static(b"B"))),
                tx.send(Datagram::new(target, Bytes::from_static(b"C"))),
            )
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("first bounded send never entered");
        wait_for_private_count(
            &harness.state.outbound_admitted,
            &harness.state.outbound_admitted_notify,
            2,
            "two outbound budget slots were not admitted",
        )
        .await;
        assert_eq!(harness.outbound_packets.available_permits(), 0);
        assert_eq!(harness.outbound_bytes.available_permits(), 0);
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert!(!sends.is_finished());

        harness.release_send();
        wait_for_private_count(
            &harness.state.send_calls,
            &harness.state.send_entered,
            2,
            "second bounded send never entered",
        )
        .await;
        wait_for_private_count(
            &harness.state.outbound_admitted,
            &harness.state.outbound_admitted_notify,
            3,
            "third outbound send never acquired released budget",
        )
        .await;
        harness.release_send();
        wait_for_private_count(
            &harness.state.send_calls,
            &harness.state.send_entered,
            3,
            "third bounded send never entered",
        )
        .await;
        harness.release_send();

        let results = timeout(Duration::from_secs(1), sends)
            .await
            .expect("bounded sends did not finish")
            .expect("bounded send task panicked");
        assert_eq!(results, (Ok(()), Ok(()), Ok(())));
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 3);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 3);
        control.close().await.expect("private close failed");
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_full_inbound_queue_backpressures_and_preserves_packet_order() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let limits = PrivateAssociationLimits {
            packet_count: 2,
            byte_count: 2,
            channel_depth: 1,
        };
        let (association, harness) = start_private_owned_association(limits);
        let PrivateOwnedDatagramAssociation {
            tx: _tx,
            mut rx,
            control,
        } = association;
        harness
            .ingress
            .inject(Datagram::new(target, Bytes::from_static(b"A")))
            .await
            .unwrap();
        wait_for_private_count(
            &harness.state.receive_forwarded,
            &harness.state.inbound_forwarded,
            1,
            "first inbound packet was not queued",
        )
        .await;
        harness
            .ingress
            .inject(Datagram::new(target, Bytes::from_static(b"B")))
            .await
            .unwrap();
        wait_for_private_count(
            &harness.state.receive_calls,
            &harness.state.inbound_received,
            2,
            "second inbound packet did not reach bounded delivery",
        )
        .await;
        assert_eq!(harness.state.receive_forwarded.load(Ordering::SeqCst), 1);
        assert_eq!(harness.inbound_packets.available_permits(), 0);
        assert_eq!(harness.inbound_bytes.available_permits(), 0);

        let third_ingress = harness.ingress.clone();
        let third = tokio::spawn(async move {
            third_ingress
                .inject(Datagram::new(target, Bytes::from_static(b"C")))
                .await
        });
        wait_for_private_count(
            &harness.state.inbound_admission_attempts,
            &harness.state.inbound_admission_attempted,
            3,
            "third inbound admission was not attempted",
        )
        .await;
        assert!(!third.is_finished());

        let first = rx.recv().await.unwrap();
        assert_eq!(first.payload, Bytes::from_static(b"A"));
        wait_for_private_count(
            &harness.state.receive_forwarded,
            &harness.state.inbound_forwarded,
            2,
            "second inbound packet did not leave backpressure",
        )
        .await;
        timeout(Duration::from_secs(1), third)
            .await
            .expect("third inbound packet stayed blocked after budget release")
            .expect("third inbound injector panicked")
            .expect("third inbound injection failed");
        wait_for_private_count(
            &harness.state.receive_calls,
            &harness.state.inbound_received,
            3,
            "third inbound packet did not reach delivery",
        )
        .await;
        let second = rx.recv().await.unwrap();
        let third = rx.recv().await.unwrap();
        assert_eq!(second.payload, Bytes::from_static(b"B"));
        assert_eq!(third.payload, Bytes::from_static(b"C"));
        control.close().await.expect("private close failed");
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_graceful_close_waits_for_the_same_pending_send() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            rx: _rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");
        let close = tokio::spawn(control.close());
        wait_for_private_count(
            &harness.state.close_requests,
            &harness.state.close_requested,
            1,
            "graceful close did not reach the supervisor",
        )
        .await;
        assert!(!close.is_finished());
        assert!(!send.is_finished());
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_inflight.load(Ordering::SeqCst), 1);

        harness.release_send();
        timeout(Duration::from_secs(1), send)
            .await
            .expect("pending send did not finish during graceful close")
            .expect("pending send task panicked")
            .expect("pending send failed during graceful close");
        timeout(Duration::from_secs(1), close)
            .await
            .expect("graceful close did not finish after send acceptance")
            .expect("graceful close task panicked")
            .expect("graceful close failed");
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 1);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_hard_close_deadline_cancels_blocked_send_without_leak() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            rx: _rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");

        let close_result = control.close().await;
        assert_eq!(close_result, Err(PrivateDatagramError::TimedOut));
        let send_result = timeout(Duration::from_secs(1), send)
            .await
            .expect("hard-close send waiter leaked")
            .expect("hard-close send waiter task panicked");
        assert_eq!(send_result, Err(PrivateDatagramError::Cancelled));
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_fatal_send_error_reaches_receive_terminal_once() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            mut rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");
        harness.fail_send();
        harness.release_send();

        let send_result = timeout(Duration::from_secs(1), send)
            .await
            .expect("fatal send waiter leaked")
            .expect("fatal send waiter task panicked");
        assert_eq!(send_result, Err(PrivateDatagramError::SendFailed));
        let receive_result = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive side did not observe fatal send terminal");
        assert_eq!(receive_result, Err(PrivateDatagramError::SendFailed));
        assert_eq!(control.close().await, Err(PrivateDatagramError::SendFailed));
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_fatal_receive_error_makes_sender_unavailable() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            mut rx,
            control,
        } = association;
        harness.ingress.fail_receive().await.unwrap();

        let receive_result = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive side did not observe its fatal terminal");
        assert_eq!(receive_result, Err(PrivateDatagramError::ReceiveFailed));
        let send_result = timeout(
            Duration::from_secs(1),
            tx.send(Datagram::new(target, Bytes::from_static(b"A"))),
        )
        .await
        .expect("sender did not become terminal");
        assert_eq!(send_result, Err(PrivateDatagramError::ReceiveFailed));
        assert_eq!(
            control.close().await,
            Err(PrivateDatagramError::ReceiveFailed)
        );
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_receive_fatal_reaches_pending_send_with_one_category() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx,
            mut rx,
            control,
        } = association;
        let send = tokio::spawn(async move {
            tx.send(Datagram::new(target, Bytes::from_static(b"A")))
                .await
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("private send never reached the explicit barrier");
        harness.ingress.fail_receive().await.unwrap();

        let receive_result = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive side did not observe its fatal terminal");
        let send_result = timeout(Duration::from_secs(1), send)
            .await
            .expect("pending send did not observe receive fatal")
            .expect("pending send task panicked");
        assert_eq!(receive_result, Err(PrivateDatagramError::ReceiveFailed));
        assert_eq!(send_result, Err(PrivateDatagramError::ReceiveFailed));
        assert_eq!(
            control.close().await,
            Err(PrivateDatagramError::ReceiveFailed)
        );
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn private_receive_fatal_reaches_sender_waiting_for_budget() {
        let target = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
        let limits = PrivateAssociationLimits {
            packet_count: 1,
            byte_count: 1,
            channel_depth: 1,
        };
        let (association, harness) = start_private_owned_association(limits);
        let PrivateOwnedDatagramAssociation {
            tx,
            mut rx,
            control,
        } = association;
        let sends = tokio::spawn(async move {
            tokio::join!(
                tx.send(Datagram::new(target, Bytes::from_static(b"A"))),
                tx.send(Datagram::new(target, Bytes::from_static(b"B"))),
            )
        });
        timeout(
            Duration::from_secs(1),
            harness.state.send_entered.notified(),
        )
        .await
        .expect("first private send never reached the explicit barrier");
        assert_eq!(harness.outbound_packets.available_permits(), 0);
        assert_eq!(harness.outbound_bytes.available_permits(), 0);
        assert!(!sends.is_finished());

        harness.ingress.fail_receive().await.unwrap();
        let receive_result = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("receive side did not observe its fatal terminal");
        let send_results = timeout(Duration::from_secs(1), sends)
            .await
            .expect("budget-waiting senders did not observe receive fatal")
            .expect("budget-waiting send task panicked");
        assert_eq!(receive_result, Err(PrivateDatagramError::ReceiveFailed));
        assert_eq!(
            send_results,
            (
                Err(PrivateDatagramError::ReceiveFailed),
                Err(PrivateDatagramError::ReceiveFailed)
            )
        );
        assert_eq!(
            control.close().await,
            Err(PrivateDatagramError::ReceiveFailed)
        );
        assert_eq!(harness.state.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.state.send_accepts.load(Ordering::SeqCst), 0);
        harness.assert_released();
    }

    #[tokio::test]
    async fn dropping_private_control_cancels_and_releases_the_actor() {
        let (association, harness) =
            start_private_owned_association(PrivateAssociationLimits::default());
        let PrivateOwnedDatagramAssociation {
            tx: _tx,
            rx: _rx,
            control,
        } = association;
        timeout(
            Duration::from_secs(1),
            harness.state.actor_started.notified(),
        )
        .await
        .expect("private actor never started");
        let released = harness.state.actor_released.notified();
        drop(control);
        timeout(Duration::from_secs(1), released)
            .await
            .expect("dropped private control left the actor running");
        harness.assert_released();
    }

    #[test]
    fn default_configuration_is_bounded() {
        let config = PacketRuntimeConfig::default();
        config.validate().unwrap();
        assert!(config.buffer_capacity_bytes().unwrap() <= 256 * 1024 * 1024);
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        let config = PacketRuntimeConfig {
            max_tcp_flows: 0,
            ..PacketRuntimeConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(PacketRuntimeError::InvalidConfig(_))
        ));

        let config = PacketRuntimeConfig {
            mtu: 1200,
            ..PacketRuntimeConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn tcp_relay_echo_exceeding_duplex_capacity_does_not_deadlock() {
        let key = TcpFlowKey {
            app: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_000),
            target: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443),
        };
        let payload = vec![0x5a; 4096];
        let counters = Arc::new(Counters::new());
        let cancel = CancellationToken::new();
        let (flow, mut peer) = tokio::io::duplex(64);
        let (commands_tx, mut commands_rx) = mpsc::channel(2);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        commands_tx
            .send(TcpCommand::Data(Tracked::new(
                Bytes::copy_from_slice(&payload),
                Arc::clone(&counters),
            )))
            .await
            .unwrap();
        commands_tx.send(TcpCommand::LocalFin).await.unwrap();

        let relay = relay_tcp_flow(
            key,
            Box::new(flow),
            &mut commands_rx,
            &events_tx,
            cancel,
            Duration::from_secs(1),
            counters,
        );
        let peer_echo = async {
            let mut buffer = [0_u8; 32];
            loop {
                let length = peer.read(&mut buffer).await.unwrap();
                if length == 0 {
                    peer.shutdown().await.unwrap();
                    return;
                }
                peer.write_all(&buffer[..length]).await.unwrap();
            }
        };
        let collect = async {
            let mut echoed = Vec::new();
            loop {
                match events_rx.recv().await.unwrap() {
                    EngineEvent::TcpData {
                        key: event_key,
                        data,
                        accepted,
                    } => {
                        assert_eq!(event_key, key);
                        echoed.extend_from_slice(data.as_slice());
                        let _ = accepted.send(());
                    }
                    EngineEvent::TcpRemoteFin(event_key) => assert_eq!(event_key, key),
                    EngineEvent::TcpDone {
                        key: event_key,
                        failed,
                    } => {
                        assert_eq!(event_key, key);
                        return (echoed, failed);
                    }
                    _ => panic!("unexpected TCP relay event"),
                }
            }
        };

        let (_, _, (echoed, failed)) = timeout(Duration::from_secs(2), async {
            tokio::join!(relay, peer_echo, collect)
        })
        .await
        .expect("full-duplex relay deadlocked");
        assert!(!failed);
        assert_eq!(echoed, payload);
    }

    #[test]
    fn queue_snapshot_never_exceeds_the_hard_channel_capacity() {
        let counters = Counters::new();
        counters.ingress_queue_depth.store(33, Ordering::Relaxed);
        counters
            .peak_ingress_queue_depth
            .store(34, Ordering::Relaxed);
        counters.egress_queue_depth.store(35, Ordering::Relaxed);
        counters
            .peak_egress_queue_depth
            .store(36, Ordering::Relaxed);

        let snapshot = counters.snapshot(1024, 32, FlowConnectorSnapshot::default());
        assert_eq!(snapshot.ingress_queue_depth, 32);
        assert_eq!(snapshot.peak_ingress_queue_depth, 32);
        assert_eq!(snapshot.egress_queue_depth, 32);
        assert_eq!(snapshot.peak_egress_queue_depth, 32);
    }
}
