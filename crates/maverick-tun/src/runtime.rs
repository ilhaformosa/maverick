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
