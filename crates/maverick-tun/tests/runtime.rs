use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use etherparse::{
    IpFragOffset, IpNumber, Ipv4Header, PacketBuilder, SlicedPacket, TcpHeader, TransportSlice,
    UdpHeader,
};
use maverick_tun::{
    start_packet_runtime, BoxFuture, BoxTcpFlow, Datagram, DatagramFlow, FlowConnector,
    FlowConnectorSnapshot, FlowError, FlowErrorKind, PacketIo, PacketRead, PacketReader,
    PacketRuntimeConfig, PacketRuntimeError, PacketRuntimeFailure, PacketRuntimeHandle,
    PacketRuntimeState, PacketWriter,
};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;

const CLIENT_SEQUENCE: u32 = 100;

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn app(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41_000),
            Self::V6 => SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
                41_000,
            ),
        }
    }

    fn target(self, port: u16) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), port),
            Self::V6 => SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
                port,
            ),
        }
    }
}

struct ChannelReader {
    packets: mpsc::Receiver<Vec<u8>>,
}

impl PacketReader for ChannelReader {
    fn receive<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, io::Result<PacketRead>> {
        Box::pin(async move {
            let Some(packet) = self.packets.recv().await else {
                return Ok(PacketRead::Eof);
            };
            if packet.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized packet",
                ));
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(PacketRead::Packet(packet.len()))
        })
    }
}

struct ChannelWriter {
    packets: mpsc::Sender<Vec<u8>>,
}

impl PacketWriter for ChannelWriter {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.packets
                .send(packet.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "packet peer closed"))
        })
    }
}

#[derive(Clone, Copy)]
enum TcpBehavior {
    Echo,
    StallOpen,
    StallRead,
    Refuse,
    PanicOpen,
}

#[derive(Clone, Copy)]
enum DnsBehavior {
    Respond,
    DelayedRespond,
    Fail,
    Stall,
    Oversize,
}

#[derive(Clone, Copy)]
enum UdpBehavior {
    Echo,
    Stall,
    Oversize,
}

struct FakeConnector {
    tcp_behavior: TcpBehavior,
    dns_behavior: DnsBehavior,
    udp_behavior: UdpBehavior,
    tcp_opens: AtomicU64,
    dns_queries: AtomicU64,
    udp_opens: AtomicU64,
    resources: Arc<FakeConnectorResources>,
}

impl FakeConnector {
    fn with_behaviors(
        tcp_behavior: TcpBehavior,
        dns_behavior: DnsBehavior,
        udp_behavior: UdpBehavior,
    ) -> Self {
        Self {
            tcp_behavior,
            dns_behavior,
            udp_behavior,
            tcp_opens: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            udp_opens: AtomicU64::new(0),
            resources: Arc::new(FakeConnectorResources {
                active_tasks: AtomicU64::new(0),
                peak_tasks: AtomicU64::new(0),
            }),
        }
    }
}

impl FlowConnector for FakeConnector {
    fn snapshot(&self) -> FlowConnectorSnapshot {
        const TCP_BUFFER_BYTES: usize = 64 * 1024;
        const MAX_TCP_TASKS: usize = 128;
        const DUPLEX_CAPACITY_BYTES: usize = TCP_BUFFER_BYTES * 2;
        let active_tasks = self.resources.active_tasks.load(Ordering::Relaxed) as usize;
        let peak_tasks = self.resources.peak_tasks.load(Ordering::Relaxed) as usize;
        FlowConnectorSnapshot {
            active_tasks,
            peak_tasks,
            buffered_bytes: active_tasks.saturating_mul(DUPLEX_CAPACITY_BYTES),
            peak_buffered_bytes: peak_tasks.saturating_mul(DUPLEX_CAPACITY_BYTES),
            buffer_capacity_bytes: MAX_TCP_TASKS.saturating_mul(DUPLEX_CAPACITY_BYTES),
        }
    }

    fn open_tcp<'a>(
        &'a self,
        _target: SocketAddr,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<BoxTcpFlow, FlowError>> {
        Box::pin(async move {
            self.tcp_opens.fetch_add(1, Ordering::Relaxed);
            match self.tcp_behavior {
                TcpBehavior::StallOpen => {
                    cancel.cancelled().await;
                    Err(FlowError::new(FlowErrorKind::Cancelled))
                }
                TcpBehavior::Echo => {
                    let (runtime, mut peer) = duplex(64 * 1024);
                    let task_guard = FakeConnectorTaskGuard::new(Arc::clone(&self.resources));
                    tokio::spawn(async move {
                        let _task_guard = task_guard;
                        let mut buffer = [0u8; 16 * 1024];
                        loop {
                            let length = tokio::select! {
                                _ = cancel.cancelled() => return,
                                result = peer.read(&mut buffer) => match result {
                                    Ok(length) => length,
                                    Err(_) => return,
                                },
                            };
                            if length == 0 {
                                let _ = peer.shutdown().await;
                                return;
                            }
                            if peer.write_all(&buffer[..length]).await.is_err() {
                                return;
                            }
                        }
                    });
                    Ok(Box::new(runtime) as BoxTcpFlow)
                }
                TcpBehavior::StallRead => {
                    let (runtime, peer) = duplex(1);
                    let task_guard = FakeConnectorTaskGuard::new(Arc::clone(&self.resources));
                    tokio::spawn(async move {
                        let _task_guard = task_guard;
                        let _peer = peer;
                        cancel.cancelled().await;
                    });
                    Ok(Box::new(runtime) as BoxTcpFlow)
                }
                TcpBehavior::Refuse => Err(FlowError::new(FlowErrorKind::RemoteConnection)),
                TcpBehavior::PanicOpen => panic!("intentional connector panic"),
            }
        })
    }

    fn exchange_dns<'a>(
        &'a self,
        _query: Bytes,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Bytes, FlowError>> {
        Box::pin(async move {
            self.dns_queries.fetch_add(1, Ordering::Relaxed);
            match self.dns_behavior {
                DnsBehavior::Respond => tokio::select! {
                    _ = cancel.cancelled() => Err(FlowError::new(FlowErrorKind::Cancelled)),
                    _ = tokio::task::yield_now() => Ok(Bytes::from_static(b"dns-response")),
                },
                DnsBehavior::DelayedRespond => tokio::select! {
                    _ = cancel.cancelled() => Err(FlowError::new(FlowErrorKind::Cancelled)),
                    _ = tokio::time::sleep(Duration::from_millis(75)) => {
                        Ok(Bytes::from_static(b"dns-response"))
                    },
                },
                DnsBehavior::Fail => Err(FlowError::new(FlowErrorKind::DnsExchange)),
                DnsBehavior::Stall => {
                    cancel.cancelled().await;
                    Err(FlowError::new(FlowErrorKind::Cancelled))
                }
                DnsBehavior::Oversize => Ok(Bytes::from(vec![0; 513])),
            }
        })
    }

    fn open_udp<'a>(
        &'a self,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn DatagramFlow>, FlowError>> {
        Box::pin(async move {
            self.udp_opens.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(FakeDatagramFlow {
                behavior: self.udp_behavior,
            }) as Box<dyn DatagramFlow>)
        })
    }
}

struct FakeConnectorResources {
    active_tasks: AtomicU64,
    peak_tasks: AtomicU64,
}

struct FakeConnectorTaskGuard(Arc<FakeConnectorResources>);

impl FakeConnectorTaskGuard {
    fn new(resources: Arc<FakeConnectorResources>) -> Self {
        let active = resources.active_tasks.fetch_add(1, Ordering::Relaxed) + 1;
        resources.peak_tasks.fetch_max(active, Ordering::Relaxed);
        Self(resources)
    }
}

impl Drop for FakeConnectorTaskGuard {
    fn drop(&mut self) {
        self.0.active_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

struct FakeDatagramFlow {
    behavior: UdpBehavior,
}

impl DatagramFlow for FakeDatagramFlow {
    fn exchange<'a>(
        &'a mut self,
        datagram: Datagram,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Datagram, FlowError>> {
        Box::pin(async move {
            match self.behavior {
                UdpBehavior::Echo => tokio::select! {
                    _ = cancel.cancelled() => Err(FlowError::new(FlowErrorKind::Cancelled)),
                    _ = tokio::task::yield_now() => Ok(datagram),
                },
                UdpBehavior::Stall => {
                    cancel.cancelled().await;
                    Err(FlowError::new(FlowErrorKind::Cancelled))
                }
                UdpBehavior::Oversize => {
                    Ok(Datagram::new(datagram.endpoint, Bytes::from(vec![0; 1233])))
                }
            }
        })
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), FlowError>> {
        Box::pin(async { Ok(()) })
    }
}

struct Harness {
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
    runtime: PacketRuntimeHandle,
    connector: Arc<FakeConnector>,
}

impl Harness {
    fn start(tcp_behavior: TcpBehavior, config: PacketRuntimeConfig) -> Self {
        Self::start_with_behaviors(
            tcp_behavior,
            DnsBehavior::Respond,
            UdpBehavior::Echo,
            config,
        )
    }

    fn start_with_behaviors(
        tcp_behavior: TcpBehavior,
        dns_behavior: DnsBehavior,
        udp_behavior: UdpBehavior,
        mut config: PacketRuntimeConfig,
    ) -> Self {
        config.poll_interval = Duration::from_millis(1);
        let (input, packets) = mpsc::channel(config.packet_queue_depth);
        let (writer, output) = mpsc::channel(config.packet_queue_depth);
        let io = PacketIo::new(ChannelReader { packets }, ChannelWriter { packets: writer });
        let connector = Arc::new(FakeConnector::with_behaviors(
            tcp_behavior,
            dns_behavior,
            udp_behavior,
        ));
        let flow_connector: Arc<dyn FlowConnector> = connector.clone();
        let runtime = start_packet_runtime(config, io, flow_connector).unwrap();
        Self {
            input,
            output,
            runtime,
            connector,
        }
    }

    async fn send(&self, packet: Vec<u8>) {
        self.input.send(packet).await.unwrap();
    }

    async fn recv_tcp_where(
        &mut self,
        predicate: impl Fn(&TcpHeader, &[u8]) -> bool,
    ) -> (TcpHeader, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut observed = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let packet = match timeout(remaining, self.output.recv()).await {
                Ok(Some(packet)) => packet,
                other => panic!(
                    "TCP packet output stopped: {other:?}; observed={observed:?}; snapshot={:?}",
                    self.runtime.snapshot()
                ),
            };
            if let Some((header, payload)) = parsed_tcp(&packet) {
                observed.push((
                    header.syn,
                    header.ack,
                    header.rst,
                    header.fin,
                    header.sequence_number,
                    header.acknowledgment_number,
                    payload.len(),
                ));
                if predicate(&header, &payload) {
                    return (header, payload);
                }
            }
        }
    }

    async fn recv_udp(&mut self) -> (UdpHeader, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let packet = timeout(remaining, self.output.recv())
                .await
                .expect("UDP packet output timeout")
                .expect("packet output closed");
            if let Some(parsed) = parsed_udp(&packet) {
                return parsed;
            }
        }
    }
}

fn test_config() -> PacketRuntimeConfig {
    PacketRuntimeConfig {
        mtu: 1280,
        max_tcp_flows: 8,
        max_udp_targets: 8,
        max_udp_associations: 8,
        max_dns_queries: 4,
        packet_queue_depth: 16,
        event_queue_depth: 32,
        tcp_buffer_bytes: 4096,
        tcp_channel_depth: 2,
        udp_buffer_bytes: 4096,
        udp_message_depth: 8,
        udp_channel_depth: 4,
        max_udp_payload_bytes: 1232,
        max_dns_payload_bytes: 512,
        connect_timeout: Duration::from_millis(250),
        tcp_idle_timeout: Duration::from_secs(2),
        udp_idle_timeout: Duration::from_millis(100),
        dns_timeout: Duration::from_millis(250),
        shutdown_timeout: Duration::from_millis(150),
        poll_interval: Duration::from_millis(1),
        ..PacketRuntimeConfig::default()
    }
}

async fn establish_and_echo(harness: &mut Harness, family: Family, payload: &[u8]) {
    let app = family.app();
    let target = family.target(443);
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (syn_ack, _) = harness
        .recv_tcp_where(|header, payload| header.syn && header.ack && payload.is_empty())
        .await;
    let server_sequence = syn_ack.sequence_number;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1,
            Some(server_sequence + 1),
            TcpFlags::NONE,
            &[],
        ))
        .await;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1,
            Some(server_sequence + 1),
            TcpFlags::PSH,
            payload,
        ))
        .await;
    let (_, echoed) = harness
        .recv_tcp_where(|_, response| response == payload)
        .await;
    assert_eq!(echoed, payload);

    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1 + payload.len() as u32,
            Some(server_sequence + 1 + payload.len() as u32),
            TcpFlags::RST,
            &[],
        ))
        .await;
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 0
    })
    .await;
}

#[tokio::test]
async fn ipv4_tcp_round_trip_and_clean_idempotent_shutdown() {
    let mut harness = Harness::start(TcpBehavior::Echo, test_config());
    establish_and_echo(&mut harness, Family::V4, b"v4-request").await;
    assert_eq!(harness.connector.tcp_opens.load(Ordering::Relaxed), 1);

    let first = harness.runtime.shutdown().await.unwrap();
    assert!(!first.already_stopped);
    assert!(!first.forced);
    assert_eq!(first.final_snapshot.state, PacketRuntimeState::Stopped);
    assert_quiescent(&first.final_snapshot);

    let second = harness.runtime.shutdown().await.unwrap();
    assert!(second.already_stopped);
    assert_quiescent(&second.final_snapshot);
}

#[tokio::test]
async fn ipv6_tcp_round_trip() {
    let mut harness = Harness::start(TcpBehavior::Echo, test_config());
    establish_and_echo(&mut harness, Family::V6, b"v6-request").await;
    let report = harness.runtime.shutdown().await.unwrap();
    assert!(!report.forced);
    assert_eq!(report.final_snapshot.dns_queries_failed, 0);
    assert_eq!(report.final_snapshot.udp_associations_failed, 0);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn dns_and_generic_udp_round_trip_without_cross_flow_mix() {
    let mut config = test_config();
    config.udp_idle_timeout = Duration::from_millis(20);
    let mut harness = Harness::start_with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::DelayedRespond,
        UdpBehavior::Echo,
        config,
    );
    let app = Family::V4.app();
    let dns_target = Family::V4.target(53);
    harness
        .send(udp_packet(app, dns_target, b"dns-query"))
        .await;
    let (dns_header, dns_payload) = harness.recv_udp().await;
    assert_eq!(dns_header.source_port, 53);
    assert_eq!(dns_header.destination_port, app.port());
    assert_eq!(dns_payload, b"dns-response");

    let udp_target = Family::V6.target(5353);
    let udp_app = Family::V6.app();
    harness
        .send(udp_packet(udp_app, udp_target, b"udp-query"))
        .await;
    let (udp_header, udp_payload) = harness.recv_udp().await;
    assert_eq!(udp_header.source_port, udp_target.port());
    assert_eq!(udp_header.destination_port, udp_app.port());
    assert_eq!(udp_payload, b"udp-query");

    wait_for(Duration::from_secs(1), || {
        let snapshot = harness.runtime.snapshot();
        snapshot.active_dns_queries == 0 && snapshot.active_udp_associations == 0
    })
    .await;
    assert_eq!(harness.connector.dns_queries.load(Ordering::Relaxed), 1);
    assert_eq!(harness.connector.udp_opens.load(Ordering::Relaxed), 1);
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn flow_limit_and_malformed_burst_remain_bounded() {
    let mut config = test_config();
    config.max_tcp_flows = 1;
    let mut harness = Harness::start(TcpBehavior::Echo, config.clone());
    let first_app = Family::V4.app();
    let first_target = Family::V4.target(443);
    harness
        .send(tcp_packet(
            first_app,
            first_target,
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (syn_ack, _) = harness
        .recv_tcp_where(|header, _| header.syn && header.ack)
        .await;
    harness
        .send(tcp_packet(
            first_app,
            first_target,
            CLIENT_SEQUENCE + 1,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::NONE,
            &[],
        ))
        .await;

    let second_app = SocketAddr::new(first_app.ip(), first_app.port() + 1);
    let second_target = Family::V4.target(444);
    harness
        .send(tcp_packet(
            second_app,
            second_target,
            CLIENT_SEQUENCE + 10,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (reset, _) = harness.recv_tcp_where(|header, _| header.rst).await;
    assert!(reset.rst);

    for length in 0..40 {
        harness.send(vec![0; length]).await;
    }
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().malformed_packets >= 40
    })
    .await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.active_tcp_flows, 1);
    assert_eq!(snapshot.peak_tcp_flows, 1);
    assert!(snapshot.tcp_flows_rejected >= 1);
    assert!(snapshot.buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    assert!(snapshot.peak_ingress_queue_depth <= config.packet_queue_depth);
    assert!(snapshot.peak_egress_queue_depth <= config.packet_queue_depth);

    harness
        .send(tcp_packet(
            first_app,
            first_target,
            CLIENT_SEQUENCE + 1,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::RST,
            &[],
        ))
        .await;
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 0
    })
    .await;
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn disabled_ipv4_rejects_non_initial_fragments_before_engine_admission() {
    let mut config = test_config();
    config.ipv4_enabled = false;
    let harness = Harness::start(TcpBehavior::Echo, config);
    let mut header = Ipv4Header::new(8, 64, IpNumber::UDP, [10, 0, 0, 2], [192, 0, 2, 10]).unwrap();
    header.dont_fragment = false;
    header.fragment_offset = IpFragOffset::try_new(1).unwrap();
    let mut fragment = Vec::new();
    header.write(&mut fragment).unwrap();
    fragment.extend_from_slice(&[0; 8]);

    harness.send(fragment).await;
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().packets_received == 1
    })
    .await;

    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.packets_rejected, 1);
    assert_eq!(snapshot.malformed_packets, 0);
    assert_eq!(snapshot.unsupported_packets, 0);
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn shutdown_during_stalled_connect_is_forced_but_leak_free() {
    let mut config = test_config();
    config.connect_timeout = Duration::from_secs(5);
    config.shutdown_timeout = Duration::from_millis(80);
    let harness = Harness::start(TcpBehavior::StallOpen, config);
    harness
        .send(tcp_packet(
            Family::V4.app(),
            Family::V4.target(443),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 1
    })
    .await;

    let report = harness.runtime.shutdown().await.unwrap();
    assert!(report.forced);
    assert_eq!(report.final_snapshot.tcp_flows_failed, 0);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn remote_open_refusal_emits_reset_and_releases_flow() {
    let mut harness = Harness::start(TcpBehavior::Refuse, test_config());
    harness
        .send(tcp_packet(
            Family::V4.app(),
            Family::V4.target(443),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (reset, _) = harness.recv_tcp_where(|header, _| header.rst).await;
    assert!(reset.rst);
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 0
    })
    .await;
    assert_eq!(harness.runtime.snapshot().tcp_flows_failed, 1);
    assert_eq!(harness.connector.tcp_opens.load(Ordering::Relaxed), 1);
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn flow_task_panic_fails_runtime_and_cleans_up() {
    let harness = Harness::start(TcpBehavior::PanicOpen, test_config());
    harness
        .send(tcp_packet(
            Family::V4.app(),
            Family::V4.target(443),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;

    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().state == PacketRuntimeState::Failed
    })
    .await;

    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.last_failure, Some(PacketRuntimeFailure::Task));
    assert_quiescent(&snapshot);
    assert!(matches!(
        harness.runtime.shutdown().await,
        Err(PacketRuntimeError::RuntimeFailed(
            PacketRuntimeFailure::Task
        ))
    ));
}

#[tokio::test]
async fn stalled_tcp_reader_propagates_fixed_backpressure_and_cancels() {
    let config = test_config();
    let mut harness = Harness::start(TcpBehavior::StallRead, config.clone());
    let app = Family::V4.app();
    let target = Family::V4.target(443);
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (syn_ack, _) = harness
        .recv_tcp_where(|header, _| header.syn && header.ack)
        .await;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::NONE,
            &[],
        ))
        .await;

    let segment = vec![7; 512];
    for index in 0..8 {
        harness
            .send(tcp_packet(
                app,
                target,
                CLIENT_SEQUENCE + 1 + index * segment.len() as u32,
                Some(syn_ack.sequence_number + 1),
                TcpFlags::PSH,
                &segment,
            ))
            .await;
    }
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().buffered_bytes > 0
    })
    .await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.active_tcp_flows, 1);
    assert!(snapshot.buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    assert!(snapshot.peak_buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    assert!(snapshot.peak_ingress_queue_depth <= config.packet_queue_depth);
    assert!(snapshot.peak_egress_queue_depth <= config.packet_queue_depth);

    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1 + 8 * segment.len() as u32,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::RST,
            &[],
        ))
        .await;
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 0
    })
    .await;
    let report = harness.runtime.shutdown().await.unwrap();
    assert!(!report.forced);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn local_half_close_delivers_response_and_fin() {
    let mut harness = Harness::start(TcpBehavior::Echo, test_config());
    let app = Family::V4.app();
    let target = Family::V4.target(443);
    let request = b"half-close";
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await;
    let (syn_ack, _) = harness
        .recv_tcp_where(|header, _| header.syn && header.ack)
        .await;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::PSH,
            request,
        ))
        .await;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 1 + request.len() as u32,
            Some(syn_ack.sequence_number + 1),
            TcpFlags::FIN,
            &[],
        ))
        .await;
    let (data_header, response) = harness
        .recv_tcp_where(|_, payload| payload == request)
        .await;
    assert_eq!(response, request);
    let (fin, _) = harness.recv_tcp_where(|header, _| header.fin).await;
    harness
        .send(tcp_packet(
            app,
            target,
            CLIENT_SEQUENCE + 2 + request.len() as u32,
            Some(fin.sequence_number + 1),
            TcpFlags::NONE,
            &[],
        ))
        .await;
    assert!(data_header.sequence_number > syn_ack.sequence_number);
    wait_for(Duration::from_secs(1), || {
        harness.runtime.snapshot().active_tcp_flows == 0
    })
    .await;
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn dns_and_udp_admission_limits_reject_excess_without_leaks() {
    let mut config = test_config();
    config.max_dns_queries = 1;
    config.max_udp_targets = 2;
    config.max_udp_associations = 1;
    config.udp_channel_depth = 1;
    let harness = Harness::start_with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Stall,
        UdpBehavior::Stall,
        config,
    );
    let dns_target = Family::V4.target(53);
    harness
        .send(udp_packet(Family::V4.app(), dns_target, b"dns-one"))
        .await;
    harness
        .send(udp_packet(
            SocketAddr::new(Family::V4.app().ip(), Family::V4.app().port() + 1),
            dns_target,
            b"dns-two",
        ))
        .await;
    let udp_target = Family::V4.target(5353);
    for index in 0..5 {
        harness
            .send(udp_packet(Family::V4.app(), udp_target, &[index as u8; 8]))
            .await;
    }
    wait_for(Duration::from_secs(1), || {
        let snapshot = harness.runtime.snapshot();
        snapshot.active_dns_queries == 1
            && snapshot.active_udp_associations == 1
            && snapshot.dns_queries_rejected >= 1
            && snapshot.udp_datagrams_dropped >= 1
    })
    .await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.peak_dns_queries, 1);
    assert_eq!(snapshot.peak_udp_associations, 1);
    assert!(snapshot.buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    let report = harness.runtime.shutdown().await.unwrap();
    assert!(!report.forced);
    assert_eq!(report.final_snapshot.dns_queries_failed, 0);
    assert_eq!(report.final_snapshot.udp_associations_failed, 0);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn oversized_dns_and_udp_responses_are_rejected_before_queueing() {
    let config = test_config();
    let harness = Harness::start_with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Oversize,
        UdpBehavior::Oversize,
        config,
    );
    harness
        .send(udp_packet(
            Family::V4.app(),
            Family::V4.target(53),
            b"dns-query",
        ))
        .await;
    harness
        .send(udp_packet(
            Family::V4.app(),
            Family::V4.target(5353),
            b"udp-query",
        ))
        .await;

    wait_for(Duration::from_secs(1), || {
        let snapshot = harness.runtime.snapshot();
        snapshot.dns_queries_rejected >= 1
            && snapshot.udp_datagrams_dropped >= 1
            && snapshot.active_dns_queries == 0
            && snapshot.active_udp_associations == 0
    })
    .await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.dns_queries_failed, 0);
    assert_eq!(snapshot.udp_associations_failed, 1);
    assert_eq!(snapshot.udp_datagrams_dropped, 1);
    assert!(snapshot.buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    assert!(snapshot.peak_buffered_bytes <= snapshot.configured_buffer_capacity_bytes);
    let report = harness.runtime.shutdown().await.unwrap();
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn dns_connector_failure_is_counted_without_shutdown_noise() {
    let harness = Harness::start_with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Fail,
        UdpBehavior::Echo,
        test_config(),
    );
    harness
        .send(udp_packet(
            Family::V4.app(),
            Family::V4.target(53),
            b"dns-query",
        ))
        .await;

    wait_for(Duration::from_secs(1), || {
        let snapshot = harness.runtime.snapshot();
        snapshot.dns_queries_failed == 1 && snapshot.active_dns_queries == 0
    })
    .await;
    let snapshot = harness.runtime.snapshot();
    assert_eq!(snapshot.dns_queries_started, 1);
    assert_eq!(snapshot.dns_queries_rejected, 0);

    let report = harness.runtime.shutdown().await.unwrap();
    assert_eq!(report.final_snapshot.dns_queries_failed, 1);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn inconsistent_connector_resource_snapshot_rejects_startup() {
    let connector = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    connector.resources.active_tasks.store(1, Ordering::Relaxed);
    connector.resources.peak_tasks.store(0, Ordering::Relaxed);
    let flow_connector: Arc<dyn FlowConnector> = connector;
    let (_input, packets) = mpsc::channel(1);
    let (writer, _output) = mpsc::channel(1);
    let io = PacketIo::new(ChannelReader { packets }, ChannelWriter { packets: writer });

    let result = start_packet_runtime(test_config(), io, flow_connector);

    assert!(matches!(
        result,
        Err(PacketRuntimeError::InvalidConfig(
            "flow connector resource snapshot is inconsistent"
        ))
    ));

    let connector = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    connector.resources.peak_tasks.store(1, Ordering::Relaxed);
    let flow_connector: Arc<dyn FlowConnector> = connector;
    let (_input, packets) = mpsc::channel(1);
    let (writer, _output) = mpsc::channel(1);
    let io = PacketIo::new(ChannelReader { packets }, ChannelWriter { packets: writer });

    let result = start_packet_runtime(test_config(), io, flow_connector);

    assert!(matches!(
        result,
        Err(PacketRuntimeError::InvalidConfig(
            "flow connector must be fresh and quiescent at startup"
        ))
    ));
}

#[test]
fn startup_without_tokio_runtime_returns_an_error() {
    let connector: Arc<dyn FlowConnector> = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    let result = start_packet_runtime(
        test_config(),
        PacketIo::new(EofReader, SinkWriter),
        connector,
    );

    assert!(matches!(
        result,
        Err(PacketRuntimeError::RuntimeUnavailable)
    ));
}

struct ErrorReader;

impl PacketReader for ErrorReader {
    fn receive<'a>(&'a mut self, _buffer: &'a mut [u8]) -> BoxFuture<'a, io::Result<PacketRead>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::BrokenPipe, "read failed")) })
    }
}

struct PanicReader;

impl PacketReader for PanicReader {
    fn receive<'a>(&'a mut self, _buffer: &'a mut [u8]) -> BoxFuture<'a, io::Result<PacketRead>> {
        Box::pin(async { panic!("intentional packet reader panic") })
    }
}

struct EofReader;

impl PacketReader for EofReader {
    fn receive<'a>(&'a mut self, _buffer: &'a mut [u8]) -> BoxFuture<'a, io::Result<PacketRead>> {
        Box::pin(async { Ok(PacketRead::Eof) })
    }
}

struct SinkWriter;

impl PacketWriter for SinkWriter {
    fn send<'a>(&'a mut self, _packet: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct ErrorWriter;

impl PacketWriter for ErrorWriter {
    fn send<'a>(&'a mut self, _packet: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::BrokenPipe, "write failed")) })
    }
}

#[tokio::test]
async fn packet_read_error_and_reader_panic_fail_coarsely_and_clean_up() {
    for io in [
        PacketIo::new(ErrorReader, SinkWriter),
        PacketIo::new(PanicReader, SinkWriter),
    ] {
        let connector: Arc<dyn FlowConnector> = Arc::new(FakeConnector::with_behaviors(
            TcpBehavior::Echo,
            DnsBehavior::Respond,
            UdpBehavior::Echo,
        ));
        let runtime = start_packet_runtime(test_config(), io, connector).unwrap();
        wait_for(Duration::from_secs(1), || {
            runtime.snapshot().state == PacketRuntimeState::Failed
        })
        .await;
        let snapshot = runtime.snapshot();
        assert_eq!(
            snapshot.last_failure,
            Some(PacketRuntimeFailure::PacketRead)
        );
        assert_quiescent(&snapshot);
        assert!(matches!(
            runtime.shutdown().await,
            Err(PacketRuntimeError::RuntimeFailed(
                PacketRuntimeFailure::PacketRead
            ))
        ));
    }
}

#[tokio::test]
async fn packet_write_error_fails_coarsely_and_clean_up() {
    let (input, packets) = mpsc::channel(4);
    let io = PacketIo::new(ChannelReader { packets }, ErrorWriter);
    let connector: Arc<dyn FlowConnector> = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    let runtime = start_packet_runtime(test_config(), io, connector).unwrap();
    input
        .send(tcp_packet(
            Family::V4.app(),
            Family::V4.target(443),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .await
        .unwrap();
    drop(input);
    wait_for(Duration::from_secs(1), || {
        runtime.snapshot().state == PacketRuntimeState::Failed
    })
    .await;
    let snapshot = runtime.snapshot();
    assert_eq!(
        snapshot.last_failure,
        Some(PacketRuntimeFailure::PacketWrite)
    );
    assert_quiescent(&snapshot);
}

#[tokio::test]
async fn packet_eof_stops_cleanly_before_explicit_shutdown() {
    let io = PacketIo::new(EofReader, SinkWriter);
    let connector: Arc<dyn FlowConnector> = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    let runtime = start_packet_runtime(test_config(), io, connector).unwrap();
    wait_for(Duration::from_secs(1), || {
        runtime.snapshot().state == PacketRuntimeState::Stopped
    })
    .await;
    let report = runtime.shutdown().await.unwrap();
    assert!(report.already_stopped);
    assert_quiescent(&report.final_snapshot);
}

#[tokio::test]
async fn packet_eof_drains_packets_already_accepted_by_the_reader() {
    let (input, packets) = mpsc::channel(4);
    input
        .try_send(tcp_packet(
            Family::V4.app(),
            Family::V4.target(443),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ))
        .unwrap();
    input.try_send(vec![0]).unwrap();
    drop(input);
    let io = PacketIo::new(ChannelReader { packets }, SinkWriter);
    let connector: Arc<dyn FlowConnector> = Arc::new(FakeConnector::with_behaviors(
        TcpBehavior::Echo,
        DnsBehavior::Respond,
        UdpBehavior::Echo,
    ));
    let runtime = start_packet_runtime(test_config(), io, connector).unwrap();

    wait_for(Duration::from_secs(1), || {
        runtime.snapshot().state == PacketRuntimeState::Stopped
    })
    .await;

    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.packets_received, 2);
    assert_eq!(snapshot.packets_rejected, 1);
    assert_eq!(snapshot.malformed_packets, 1);
    assert_eq!(snapshot.tcp_flows_opened, 1);
    assert_quiescent(&snapshot);
}

fn assert_quiescent(snapshot: &maverick_tun::PacketRuntimeSnapshot) {
    assert_eq!(snapshot.active_tcp_flows, 0);
    assert_eq!(snapshot.active_udp_associations, 0);
    assert_eq!(snapshot.active_dns_queries, 0);
    assert_eq!(snapshot.active_tasks, 0);
    assert_eq!(snapshot.ingress_queue_depth, 0);
    assert_eq!(snapshot.egress_queue_depth, 0);
    assert_eq!(snapshot.buffered_bytes, 0);
}

async fn wait_for(timeout_duration: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout_duration;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[derive(Clone, Copy)]
struct TcpFlags {
    syn: bool,
    fin: bool,
    rst: bool,
    psh: bool,
}

impl TcpFlags {
    const NONE: Self = Self {
        syn: false,
        fin: false,
        rst: false,
        psh: false,
    };
    const SYN: Self = Self {
        syn: true,
        ..Self::NONE
    };
    const RST: Self = Self {
        rst: true,
        ..Self::NONE
    };
    const FIN: Self = Self {
        fin: true,
        ..Self::NONE
    };
    const PSH: Self = Self {
        psh: true,
        ..Self::NONE
    };
}

fn tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: Option<u32>,
    flags: TcpFlags,
    payload: &[u8],
) -> Vec<u8> {
    let source_port = source.port();
    let destination_port = destination.port();
    let mut builder = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => PacketBuilder::ipv4(
            source.octets(),
            destination.octets(),
            64,
        )
        .tcp(source_port, destination_port, sequence, 32_768),
        (IpAddr::V6(source), IpAddr::V6(destination)) => PacketBuilder::ipv6(
            source.octets(),
            destination.octets(),
            64,
        )
        .tcp(source_port, destination_port, sequence, 32_768),
        _ => panic!("mixed address families"),
    };
    if flags.syn {
        builder = builder.syn();
    }
    if flags.fin {
        builder = builder.fin();
    }
    if flags.rst {
        builder = builder.rst();
    }
    if flags.psh {
        builder = builder.psh();
    }
    if let Some(acknowledgment) = acknowledgment {
        builder = builder.ack(acknowledgment);
    }
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let builder = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            PacketBuilder::ipv4(source_ip.octets(), destination_ip.octets(), 64)
                .udp(source.port(), destination.port())
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            PacketBuilder::ipv6(source_ip.octets(), destination_ip.octets(), 64)
                .udp(source.port(), destination.port())
        }
        _ => panic!("mixed address families"),
    };
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

fn parsed_tcp(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    match sliced.transport? {
        TransportSlice::Tcp(tcp) => Some((tcp.to_header(), tcp.payload().to_vec())),
        _ => None,
    }
}

fn parsed_udp(packet: &[u8]) -> Option<(UdpHeader, Vec<u8>)> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    match sliced.transport? {
        TransportSlice::Udp(udp) => Some((udp.to_header(), udp.payload().to_vec())),
        _ => None,
    }
}
