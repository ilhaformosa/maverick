#![cfg(feature = "tun-runtime")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use etherparse::{PacketBuilder, SlicedPacket, TcpHeader, TransportSlice, UdpHeader};
use maverick_tun::{
    BoxFuture, PacketIo, PacketRead, PacketReader, PacketRuntimeConfig, PacketRuntimeState,
    PacketWriter,
};
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
