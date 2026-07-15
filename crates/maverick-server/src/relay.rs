use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use maverick_core::config::ServerEgressPolicyConfig;
use maverick_core::frame::{ErrorCode, Frame, FrameType, OpenTcpPayload, UdpPacketPayload};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{sleep_until, timeout, Duration, Instant};

#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_second: u64,
    next_available: Mutex<Instant>,
}

#[derive(Clone)]
pub struct TunnelRelayPolicy {
    pub idle_timeout: Duration,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub padding: RuntimePadding,
    pub cover_traffic: RuntimeCoverTraffic,
    pub shaping_metrics: Option<ShapingMetricSinks>,
}

#[derive(Clone)]
pub struct ShapingMetricSinks {
    pub padding_frames: Arc<AtomicU64>,
    pub padding_bytes: Arc<AtomicU64>,
    pub cover_traffic_padding_frames: Arc<AtomicU64>,
    pub cover_traffic_padding_bytes: Arc<AtomicU64>,
}

impl ShapingMetricSinks {
    fn record_padding(&self, emission: PaddingEmission) {
        let total_frames = emission.padding_frames + emission.cover_traffic_padding_frames;
        let total_bytes = emission.padding_bytes + emission.cover_traffic_padding_bytes;
        if total_frames > 0 {
            self.padding_frames
                .fetch_add(total_frames as u64, Ordering::Relaxed);
        }
        if total_bytes > 0 {
            self.padding_bytes
                .fetch_add(total_bytes as u64, Ordering::Relaxed);
        }
        if emission.cover_traffic_padding_frames > 0 {
            self.cover_traffic_padding_frames.fetch_add(
                emission.cover_traffic_padding_frames as u64,
                Ordering::Relaxed,
            );
        }
        if emission.cover_traffic_padding_bytes > 0 {
            self.cover_traffic_padding_bytes.fetch_add(
                emission.cover_traffic_padding_bytes as u64,
                Ordering::Relaxed,
            );
        }
    }
}

impl TunnelRelayPolicy {
    pub fn record_padding(&self, emission: PaddingEmission) {
        if let Some(metrics) = &self.shaping_metrics {
            metrics.record_padding(emission);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PaddingEmission {
    pub padding_frames: usize,
    pub padding_bytes: usize,
    pub cover_traffic_padding_frames: usize,
    pub cover_traffic_padding_bytes: usize,
}

impl RateLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            next_available: Mutex::new(Instant::now()),
        }
    }

    pub fn delay_for(&self, bytes: usize) -> Duration {
        if bytes == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(bytes as f64 / self.bytes_per_second as f64)
    }

    pub async fn throttle(&self, bytes: usize) {
        let delay = self.delay_for(bytes);
        if delay.is_zero() {
            return;
        }
        let mut next_available = self.next_available.lock().await;
        let now = Instant::now();
        let start_at = (*next_available).max(now);
        let wake_at = start_at + delay;
        *next_available = wake_at;
        drop(next_available);
        sleep_until(wake_at).await;
    }
}

pub async fn open_target(
    open: &OpenTcpPayload,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> Result<TcpStream> {
    let authority = open.target.to_authority(open.port);
    let addrs = resolve_allowed_authority(&authority, timeout_ms, egress).await?;
    timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(addrs.as_slice()),
    )
    .await
    .context("target connect timed out")?
    .with_context(|| "target connect failed")
}

pub async fn relay_target_and_tunnel(
    target: TcpStream,
    mut send_stream: h2::SendStream<Bytes>,
    mut recv_stream: h2::RecvStream,
    mut recv_buf: BytesMut,
    max_frame_size: usize,
    flow_id: u64,
    policy: TunnelRelayPolicy,
) -> Result<()> {
    let (mut target_read, mut target_write) = target.into_split();
    let mut target_buf = vec![0u8; 16 * 1024];
    let mut client_eof = false;

    loop {
        if client_eof {
            tokio::select! {
                _ = tokio::time::sleep(policy.idle_timeout) => {
                    break;
                }
                target_read_result = target_read.read(&mut target_buf) => {
                    let n = target_read_result?;
                    if n == 0 {
                        let padding_bytes = send_frame_with_padding(
                            &mut send_stream,
                            Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                            max_frame_size,
                            true,
                            &policy.padding,
                            &policy.cover_traffic,
                        )?;
                        policy.record_padding(padding_bytes);
                        break;
                    }
                    if let Some(limiter) = &policy.rate_limiter {
                        limiter.throttle(n).await;
                    }
                    let padding_bytes = send_frame_with_padding(
                        &mut send_stream,
                        Frame::new(
                            FrameType::TcpData,
                            0,
                            flow_id,
                            Bytes::copy_from_slice(&target_buf[..n]),
                        ),
                        max_frame_size,
                        false,
                        &policy.padding,
                        &policy.cover_traffic,
                    )?;
                    policy.record_padding(padding_bytes);
                }
            }
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(policy.idle_timeout) => {
                break;
            }
            target_read_result = target_read.read(&mut target_buf) => {
                let n = target_read_result?;
                if n == 0 {
                    let padding_bytes = send_frame_with_padding(
                        &mut send_stream,
                        Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                        max_frame_size,
                        true,
                        &policy.padding,
                        &policy.cover_traffic,
                    )?;
                    policy.record_padding(padding_bytes);
                    break;
                }
                if let Some(limiter) = &policy.rate_limiter {
                    limiter.throttle(n).await;
                }
                let padding_bytes = send_frame_with_padding(
                    &mut send_stream,
                    Frame::new(FrameType::TcpData, 0, flow_id, Bytes::copy_from_slice(&target_buf[..n])),
                    max_frame_size,
                    false,
                    &policy.padding,
                    &policy.cover_traffic,
                )?;
                policy.record_padding(padding_bytes);
            }
            tunnel_frame = read_next_frame(&mut recv_stream, &mut recv_buf, max_frame_size) => {
                match tunnel_frame? {
                    Some(frame) if frame.flow_id == flow_id => {
                        match frame.frame_type {
                            FrameType::TcpData => {
                                if let Some(limiter) = &policy.rate_limiter {
                                    limiter.throttle(frame.payload.len()).await;
                                }
                                target_write.write_all(&frame.payload).await?;
                            }
                            FrameType::TcpFin | FrameType::CloseFlow | FrameType::TcpReset => {
                                let _ = target_write.shutdown().await;
                                client_eof = true;
                            }
                            _ => {}
                        }
                    }
                    Some(_) => {}
                    None => {
                        let _ = target_write.shutdown().await;
                        client_eof = true;
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn send_frame(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
) -> Result<()> {
    let encoded = encode_grpc_frame(frame, max_frame_size)?;
    stream.send_data(encoded, end_stream)?;
    Ok(())
}

pub fn send_frame_with_padding(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    padding: &RuntimePadding,
    cover_traffic: &RuntimeCoverTraffic,
) -> Result<PaddingEmission> {
    let mut emission = PaddingEmission::default();
    if let Some(padding_frame) =
        padding.padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        send_frame(stream, padding_frame, max_frame_size, false)?;
    }
    for cover_frame in
        cover_traffic.padding_frames(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        send_frame(stream, cover_frame, max_frame_size, false)?;
    }
    send_frame(stream, frame, max_frame_size, end_stream)?;
    Ok(emission)
}

pub async fn read_next_frame(
    stream: &mut h2::RecvStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
) -> Result<Option<Frame>> {
    read_next_frame_impl(stream, buf, max_frame_size, None, usize::MAX).await
}

pub async fn read_next_frame_capturing(
    stream: &mut h2::RecvStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
    capture: &mut BytesMut,
    max_capture_size: usize,
) -> Result<Option<Frame>> {
    read_next_frame_impl(stream, buf, max_frame_size, Some(capture), max_capture_size).await
}

async fn read_next_frame_impl(
    stream: &mut h2::RecvStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
    mut capture: Option<&mut BytesMut>,
    max_capture_size: usize,
) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = decode_grpc_frame_from(buf, max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        match stream.data().await {
            Some(Ok(bytes)) => {
                let consumed = bytes.len();
                if let Some(capture) = capture.as_deref_mut() {
                    if consumed > max_capture_size.saturating_sub(capture.len()) {
                        bail!("captured tunnel request body exceeded size limit");
                    }
                    capture.extend_from_slice(&bytes);
                }
                stream.flow_control().release_capacity(consumed)?;
                buf.extend_from_slice(&bytes);
            }
            Some(Err(err)) => return Err(err.into()),
            None => return Ok(None),
        }
    }
}

pub fn error_frame(flow_id: u64, code: ErrorCode) -> Frame {
    Frame::new(FrameType::Error, 0, flow_id, code.encode())
}

pub async fn relay_dns_query(
    query: &[u8],
    upstream: &str,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> Result<Bytes> {
    let upstream = first_allowed_addr(upstream, timeout_ms, egress).await?;
    let socket = bind_udp_for_target(upstream).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; 65_535];
    let len = timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf))
        .await
        .context("DNS upstream timed out")??;
    buf.truncate(len);
    Ok(Bytes::from(buf))
}

pub async fn relay_udp_packet(
    packet: &UdpPacketPayload,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> Result<UdpPacketPayload> {
    let authority = packet.target.to_authority(packet.port);
    let target = first_allowed_addr(&authority, timeout_ms, egress).await?;
    let socket = bind_udp_for_target(target).await?;
    socket.connect(target).await?;
    socket.send(&packet.data).await?;
    let mut buf = vec![0u8; 65_535];
    let len = timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf))
        .await
        .context("UDP target timed out")??;
    buf.truncate(len);
    Ok(UdpPacketPayload::new(
        packet.target.clone(),
        packet.port,
        Bytes::from(buf),
    ))
}

async fn bind_udp_for_target(target: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind UDP relay socket for {target}"))
}

async fn first_allowed_addr(
    authority: &str,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> Result<SocketAddr> {
    let addrs = resolve_allowed_authority(authority, timeout_ms, egress).await?;
    addrs
        .into_iter()
        .next()
        .context("allowed address set unexpectedly empty")
}

async fn resolve_allowed_authority(
    authority: &str,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> Result<Vec<SocketAddr>> {
    let resolved = timeout(Duration::from_millis(timeout_ms), lookup_host(authority))
        .await
        .context("target resolution timed out")?
        .with_context(|| format!("resolve target {authority}"))?;
    let allowed: Vec<SocketAddr> = resolved
        .filter(|addr| egress.allows_ip(addr.ip()))
        .collect();
    if allowed.is_empty() {
        bail!("egress policy rejected target {authority}");
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::{
        relay_dns_query, relay_target_and_tunnel, relay_udp_packet, RateLimiter, TunnelRelayPolicy,
    };
    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use maverick_core::config::ServerEgressPolicyConfig;
    use maverick_core::frame::{Frame, FrameType, TargetAddr, UdpPacketPayload};
    use maverick_core::grpc::encode_grpc_frame;
    use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    #[test]
    fn rate_limiter_computes_expected_delay() {
        let limiter = RateLimiter::new(1_000);
        assert_eq!(limiter.delay_for(500), Duration::from_millis(500));
        assert_eq!(limiter.delay_for(0), Duration::ZERO);
    }

    #[test]
    fn default_egress_policy_blocks_non_public_ranges() {
        let policy = ServerEgressPolicyConfig::default();
        assert!(!policy.allows_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!policy.allows_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!policy.allows_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!policy.allows_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!policy.allows_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!policy.allows_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!policy.allows_ip(IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(!policy.allows_ip(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(policy.allows_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(policy.allows_ip(IpAddr::V6("2606:4700:4700::1111".parse().unwrap())));
    }

    #[test]
    fn egress_policy_allows_explicit_loopback() {
        let policy = ServerEgressPolicyConfig {
            allow_loopback: true,
            ..ServerEgressPolicyConfig::default()
        };
        assert!(policy.allows_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(policy.allows_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn udp_relay_roundtrip_supports_ipv6_loopback() -> Result<()> {
        let Some(echo_addr) = spawn_ipv6_udp_echo().await? else {
            return Ok(());
        };
        let policy = ServerEgressPolicyConfig {
            allow_loopback: true,
            ..ServerEgressPolicyConfig::default()
        };
        let packet = UdpPacketPayload::new(
            TargetAddr::Ipv6(Ipv6Addr::LOCALHOST),
            echo_addr.port(),
            Bytes::from_static(b"ipv6-udp"),
        );

        let response = timeout(
            Duration::from_secs(2),
            relay_udp_packet(&packet, 1_000, &policy),
        )
        .await??;

        assert_eq!(response.data, Bytes::from_static(b"ipv6-udp"));
        Ok(())
    }

    #[tokio::test]
    async fn dns_relay_roundtrip_supports_ipv6_upstream() -> Result<()> {
        let Some(echo_addr) = spawn_ipv6_udp_echo().await? else {
            return Ok(());
        };
        let policy = ServerEgressPolicyConfig {
            allow_loopback: true,
            ..ServerEgressPolicyConfig::default()
        };
        let upstream = format!("[::1]:{}", echo_addr.port());

        let response = timeout(
            Duration::from_secs(2),
            relay_dns_query(b"ipv6-dns", &upstream, 1_000, &policy),
        )
        .await??;

        assert_eq!(response, Bytes::from_static(b"ipv6-dns"));
        Ok(())
    }

    #[tokio::test]
    async fn h2_relay_exits_after_idle_timeout_when_target_silent_after_client_eof() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (_held_target, _) = target_listener.accept().await?;
        let (client_io, server_io) = duplex(16 * 1024);
        let relay_task = tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await?;
            let (request, mut respond) = h2.accept().await.expect("h2 request")?;
            let response = http::Response::builder().status(200).body(())?;
            let send_stream = respond.send_response(response, false)?;
            relay_target_and_tunnel(
                target,
                send_stream,
                request.into_body(),
                BytesMut::new(),
                65_536,
                1,
                test_relay_policy(),
            )
            .await
        });
        let (client, connection) = h2::client::handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (_response, mut body) = client.send_request(request, false)?;
        body.send_data(
            encode_grpc_frame(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()), 65_536)?,
            true,
        )?;

        let joined = timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay task should exit after idle timeout");
        joined.expect("relay task should not panic")?;
        Ok(())
    }

    fn test_relay_policy() -> TunnelRelayPolicy {
        TunnelRelayPolicy {
            idle_timeout: Duration::from_millis(50),
            rate_limiter: None,
            padding: RuntimePadding::disabled(),
            cover_traffic: RuntimeCoverTraffic::disabled(),
            shaping_metrics: None,
        }
    }

    async fn spawn_ipv6_udp_echo() -> Result<Option<SocketAddr>> {
        let socket = match UdpSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await {
            Ok(socket) => socket,
            Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let addr = socket.local_addr()?;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], peer).await;
            }
        });
        Ok(Some(addr))
    }
}
