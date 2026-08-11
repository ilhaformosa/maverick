#![cfg(feature = "tun-runtime")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use etherparse::{PacketBuilder, SlicedPacket, TcpHeader, TransportSlice, UdpHeader};
#[cfg(feature = "h3")]
use maverick_client::transport;
#[cfg(feature = "h3")]
use maverick_core::GuiTransportCarrier;
use maverick_tun::{
    BoxFuture, PacketIo, PacketRead, PacketReader, PacketRuntimeConfig, PacketRuntimeState,
    PacketWriter,
};
#[cfg(feature = "h3")]
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

#[allow(dead_code)]
mod support;

use support::{
    start_echo_server, start_fake_dns_server, start_udp_echo_server, HarnessOptions,
    MaverickHarness,
};

const APP_SEQUENCE: u32 = 700;

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

struct PacketPeer {
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
}

impl PacketPeer {
    async fn send(&self, packet: Vec<u8>) -> Result<()> {
        self.input.send(packet).await?;
        Ok(())
    }

    async fn recv_tcp_where(
        &mut self,
        predicate: impl Fn(&TcpHeader, &[u8]) -> bool,
    ) -> Result<(TcpHeader, Vec<u8>)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let packet = timeout(remaining, self.output.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("packet output closed"))?;
            if let Some((header, payload)) = parsed_tcp(&packet) {
                if predicate(&header, &payload) {
                    return Ok((header, payload));
                }
            }
        }
    }

    async fn recv_udp(&mut self) -> Result<(UdpHeader, Vec<u8>)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let packet = timeout(remaining, self.output.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("packet output closed"))?;
            if let Some(parsed) = parsed_udp(&packet) {
                return Ok(parsed);
            }
        }
    }
}

#[tokio::test]
async fn packet_runtime_reuses_real_auth_h2_tcp_dns_and_udp_paths() -> Result<()> {
    let tcp_target = start_echo_server().await?;
    let dns_upstream = start_fake_dns_server().await?;
    let udp_target = start_udp_echo_server().await?;
    let mut fixture = MaverickHarness::start_with_options(HarnessOptions {
        dns_upstream: Some(dns_upstream),
        experimental_tun: true,
        client_idle_timeout_secs: Some(2),
        ..HarnessOptions::default()
    })
    .await?;

    let config = PacketRuntimeConfig {
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
        connect_timeout: Duration::from_secs(2),
        tcp_idle_timeout: Duration::from_secs(2),
        udp_idle_timeout: Duration::from_millis(150),
        dns_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_millis(500),
        poll_interval: Duration::from_millis(1),
        ..PacketRuntimeConfig::default()
    };
    let expected_buffer_capacity =
        config.buffer_capacity_bytes()? + config.max_tcp_flows * config.tcp_buffer_bytes * 2;
    let (input, reader) = mpsc::channel(config.packet_queue_depth);
    let (writer, output) = mpsc::channel(config.packet_queue_depth);
    fixture
        .client
        .start_tun_runtime(
            config,
            PacketIo::new(
                ChannelReader { packets: reader },
                ChannelWriter { packets: writer },
            ),
        )
        .await?;
    let mut peer = PacketPeer { input, output };

    let app = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41_000);
    peer.send(tcp_packet(
        app,
        tcp_target,
        APP_SEQUENCE,
        None,
        TcpFlags::SYN,
        &[],
    ))
    .await?;
    let (syn_ack, _) = peer
        .recv_tcp_where(|header, payload| header.syn && header.ack && payload.is_empty())
        .await?;
    let request = b"authenticated-packet-flow";
    peer.send(tcp_packet(
        app,
        tcp_target,
        APP_SEQUENCE + 1,
        Some(syn_ack.sequence_number + 1),
        TcpFlags::PSH,
        request,
    ))
    .await?;
    let (_, response) = peer.recv_tcp_where(|_, payload| payload == request).await?;
    assert_eq!(response, request);
    peer.send(tcp_packet(
        app,
        tcp_target,
        APP_SEQUENCE + 1 + request.len() as u32,
        Some(syn_ack.sequence_number + 1 + request.len() as u32),
        TcpFlags::RST,
        &[],
    ))
    .await?;

    let dns_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
    peer.send(udp_packet(app, dns_target, b"question")).await?;
    let (dns_header, dns_response) = peer.recv_udp().await?;
    assert_eq!(dns_header.source_port, 53);
    assert_eq!(dns_response, b"dns-response:question");

    let udp_app = SocketAddr::new(app.ip(), app.port() + 1);
    peer.send(udp_packet(udp_app, udp_target, b"datagram"))
        .await?;
    let (udp_header, udp_response) = peer.recv_udp().await?;
    assert_eq!(udp_header.source_port, udp_target.port());
    assert_eq!(udp_response, b"datagram");

    wait_for(Duration::from_secs(3), || {
        let snapshot = fixture.client.tun_runtime_snapshot().unwrap();
        snapshot.active_tcp_flows == 0
            && snapshot.active_dns_queries == 0
            && snapshot.active_udp_associations == 0
    })
    .await?;
    let snapshot = fixture.client.tun_runtime_snapshot().unwrap();
    assert_eq!(snapshot.state, PacketRuntimeState::Running);
    assert_eq!(snapshot.tcp_flows_opened, 1);
    assert_eq!(snapshot.tcp_flows_failed, 0);
    assert_eq!(snapshot.dns_queries_started, 1);
    assert_eq!(snapshot.dns_queries_failed, 0);
    assert_eq!(snapshot.udp_associations_opened, 1);
    assert_eq!(snapshot.udp_associations_failed, 0);
    assert_eq!(
        snapshot.configured_buffer_capacity_bytes,
        expected_buffer_capacity
    );
    assert!(snapshot.buffered_bytes <= snapshot.configured_buffer_capacity_bytes);

    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 1);
    assert!(pool.streams_opened >= 3, "{pool:?}");
    assert!(pool.streams_reused >= 2, "{pool:?}");

    fixture.shutdown().await
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_packet_runtime_receives_target_push_without_new_local_packet() -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        experimental_tun: true,
        ..HarnessOptions::default()
    })
    .await?;
    let client_config = fixture.client_config();
    assert_h3_transport(&client_config);

    let runtime_config = PacketRuntimeConfig {
        connect_timeout: Duration::from_secs(2),
        udp_idle_timeout: Duration::from_secs(5),
        shutdown_timeout: Duration::from_secs(5),
        ..PacketRuntimeConfig::default()
    };
    let queue_depth = runtime_config.packet_queue_depth;
    let (input, reader) = mpsc::channel(queue_depth);
    let (writer, output) = mpsc::channel(queue_depth);
    fixture
        .client
        .start_tun_runtime(
            runtime_config,
            PacketIo::new(
                ChannelReader { packets: reader },
                ChannelWriter { packets: writer },
            ),
        )
        .await?;
    let mut peer = PacketPeer { input, output };
    let app = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41_001);

    peer.send(udp_packet(app, target_addr, b"tun-h3-seed"))
        .await?;
    let mut target_buffer = [0u8; 128];
    let (seed_len, exact_source) =
        timeout(Duration::from_secs(2), target.recv_from(&mut target_buffer)).await??;
    assert_eq!(&target_buffer[..seed_len], b"tun-h3-seed");
    target.send_to(b"tun-h3-seed-reply", exact_source).await?;
    let (seed_header, seed_reply) = peer.recv_udp().await?;
    assert_eq!(seed_header.source_port, target_addr.port());
    assert_eq!(seed_header.destination_port, app.port());
    assert_eq!(seed_reply, b"tun-h3-seed-reply");

    wait_for(Duration::from_secs(2), || {
        fixture
            .client
            .tun_runtime_snapshot()
            .is_some_and(|snapshot| snapshot.active_udp_associations == 1)
    })
    .await?;
    assert_h3_transport(&client_config);
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_eq!(pool.active_streams, 0);

    match UdpSocket::bind(exact_source).await {
        Ok(socket) => {
            drop(socket);
            anyhow::bail!("active TUN target source was released before target push");
        }
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
        Err(error) => return Err(error.into()),
    }
    target.send_to(b"tun-h3-target-push", exact_source).await?;
    let push_delivered = match timeout(Duration::from_secs(1), peer.recv_udp()).await {
        Err(_) => false,
        Ok(result) => {
            let (push_header, push) = result?;
            assert_eq!(push_header.source_port, target_addr.port());
            assert_eq!(push_header.destination_port, app.port());
            assert_eq!(push, b"tun-h3-target-push");
            true
        }
    };

    if push_delivered {
        peer.send(udp_packet(app, target_addr, b"tun-h3-after-push"))
            .await?;
        let (after_len, after_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buffer)).await??;
        assert_eq!(after_source, exact_source);
        assert_eq!(&target_buffer[..after_len], b"tun-h3-after-push");
        target
            .send_to(b"tun-h3-after-push-reply", after_source)
            .await?;
        let (after_header, after_reply) = peer.recv_udp().await?;
        assert_eq!(after_header.source_port, target_addr.port());
        assert_eq!(after_header.destination_port, app.port());
        assert_eq!(after_reply, b"tun-h3-after-push-reply");
    }

    assert_h3_transport(&client_config);
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_eq!(pool.active_streams, 0);

    drop(peer);
    wait_for(Duration::from_secs(3), || {
        fixture
            .client
            .tun_runtime_snapshot()
            .is_some_and(|snapshot| {
                snapshot.state == PacketRuntimeState::Stopped
                    && snapshot.last_failure.is_none()
                    && snapshot.active_udp_associations == 0
                    && snapshot.active_tasks == 0
                    && snapshot.ingress_queue_depth == 0
                    && snapshot.egress_queue_depth == 0
                    && snapshot.buffered_bytes == 0
            })
    })
    .await?;
    let snapshot = fixture.client.tun_runtime_snapshot().unwrap();
    assert_eq!(snapshot.udp_associations_opened, 1);
    assert_eq!(snapshot.udp_associations_failed, 0);
    assert_h3_transport(&client_config);

    let rebound = wait_for_udp_rebind(exact_source).await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    drop(rebound);
    fixture.shutdown().await?;

    if !push_delivered {
        panic!("normal TUN legacy-H3 UDP target push stayed unavailable");
    }
    Ok(())
}

#[tokio::test]
async fn packet_runtime_requires_explicit_runtime_gate() -> Result<()> {
    let mut fixture = MaverickHarness::start().await?;
    let config = PacketRuntimeConfig::default();
    let (_input, reader) = mpsc::channel(1);
    let (writer, _output) = mpsc::channel(1);

    let err = fixture
        .client
        .start_tun_runtime(
            config,
            PacketIo::new(
                ChannelReader { packets: reader },
                ChannelWriter { packets: writer },
            ),
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("advanced.experimental_tun"));
    assert!(fixture.client.tun_runtime_snapshot().is_none());
    fixture.shutdown().await
}

async fn wait_for(timeout_duration: Duration, mut predicate: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + timeout_duration;
    while !predicate() {
        if Instant::now() >= deadline {
            anyhow::bail!("condition did not become true before timeout");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

#[cfg(feature = "h3")]
fn assert_h3_transport(config: &maverick_core::config::ClientConfig) {
    let snapshot = transport::transport_debug_snapshot(config);
    assert_eq!(snapshot.active_transport, GuiTransportCarrier::H3);
    assert!(snapshot.h3_candidate_enabled);
    assert!(!snapshot.h3_in_cooldown);
}

#[cfg(feature = "h3")]
async fn wait_for_udp_rebind(address: SocketAddr) -> Result<UdpSocket> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match UdpSocket::bind(address).await {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpFlags {
    syn: bool,
    rst: bool,
    psh: bool,
}

impl TcpFlags {
    const NONE: Self = Self {
        syn: false,
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
    let mut builder = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => PacketBuilder::ipv4(
            source_ip.octets(),
            destination_ip.octets(),
            64,
        )
        .tcp(source.port(), destination.port(), sequence, 32_768),
        _ => panic!("integration fixture requires IPv4 endpoints"),
    };
    if flags.syn {
        builder = builder.syn();
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
        _ => panic!("integration fixture requires IPv4 endpoints"),
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
