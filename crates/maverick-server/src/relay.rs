use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::poll_fn;
use maverick_core::config::ServerEgressPolicyConfig;
use maverick_core::frame::{ErrorCode, Frame, FrameType, OpenTcpPayload, UdpPacketPayload};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    let mut pending_send: Option<PendingH2Send> = None;

    loop {
        let desired_capacity = pending_send
            .as_ref()
            .and_then(|pending| pending.frames.front())
            .map_or(0, Bytes::len);
        let closing = pending_send
            .as_ref()
            .is_some_and(|pending| pending.end_stream);

        tokio::select! {
            _ = tokio::time::sleep(policy.idle_timeout) => {
                break;
            }

            capacity = wait_h2_capacity(&mut send_stream, desired_capacity),
                if pending_send.is_some() =>
            {
                let capacity = capacity?;
                if capacity == 0 {
                    continue;
                }
                let pending = pending_send.as_mut().expect("pending H2 send");
                let is_last_frame = pending.frames.len() == 1;
                let front = pending.frames.front_mut().expect("pending H2 frame");
                let chunk = front.split_to(capacity.min(front.len()));
                let frame_finished = front.is_empty();
                let end_stream = pending.end_stream && is_last_frame && frame_finished;
                send_stream.send_data(chunk, end_stream)?;
                if frame_finished {
                    pending.frames.pop_front();
                }
                if pending.frames.is_empty() {
                    let completed = pending_send.take().expect("completed H2 send");
                    policy.record_padding(completed.emission);
                    if completed.end_stream {
                        break;
                    }
                }
            }

            target_read_result = target_read.read(&mut target_buf),
                if pending_send.is_none() =>
            {
                let n = target_read_result?;
                if n == 0 {
                    pending_send = Some(prepare_frame_with_padding(
                        Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                        max_frame_size,
                        true,
                        &policy.padding,
                        &policy.cover_traffic,
                    )?);
                    continue;
                }
                if let Some(limiter) = &policy.rate_limiter {
                    limiter.throttle(n).await;
                }
                pending_send = Some(prepare_frame_with_padding(
                    Frame::new(FrameType::TcpData, 0, flow_id, Bytes::copy_from_slice(&target_buf[..n])),
                    max_frame_size,
                    false,
                    &policy.padding,
                    &policy.cover_traffic,
                )?);
            }

            tunnel_frame = read_next_frame(&mut recv_stream, &mut recv_buf, max_frame_size),
                if !client_eof && !closing =>
            {
                if pending_send.is_some() {
                    send_stream.reserve_capacity(0);
                }
                match tunnel_frame? {
                    Some(frame) if frame.flow_id == flow_id => {
                        match frame.frame_type {
                            FrameType::TcpData => {
                                if let Some(limiter) = &policy.rate_limiter {
                                    limiter.throttle(frame.payload.len()).await;
                                }
                                write_all_with_idle_timeout(
                                    &mut target_write,
                                    &frame.payload,
                                    policy.idle_timeout,
                                    "target relay write timed out",
                                )
                                .await?;
                            }
                            FrameType::TcpFin | FrameType::CloseFlow => {
                                let _ = target_write.shutdown().await;
                                client_eof = true;
                            }
                            FrameType::TcpReset => {
                                let _ = target_write.shutdown().await;
                                break;
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

async fn write_all_with_idle_timeout<W>(
    writer: &mut W,
    mut bytes: &[u8],
    idle_timeout: Duration,
    timeout_context: &'static str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        let written = timeout(idle_timeout, writer.write(bytes))
            .await
            .context(timeout_context)??;
        if written == 0 {
            bail!("relay writer closed before the frame was complete");
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

struct PendingH2Send {
    frames: VecDeque<Bytes>,
    end_stream: bool,
    emission: PaddingEmission,
}

fn prepare_frame_with_padding(
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    padding: &RuntimePadding,
    cover_traffic: &RuntimeCoverTraffic,
) -> Result<PendingH2Send> {
    let mut frames = VecDeque::new();
    let mut emission = PaddingEmission::default();
    if let Some(padding_frame) =
        padding.padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        frames.push_back(encode_grpc_frame(padding_frame, max_frame_size)?);
    }
    for cover_frame in
        cover_traffic.padding_frames(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        frames.push_back(encode_grpc_frame(cover_frame, max_frame_size)?);
    }
    frames.push_back(encode_grpc_frame(frame, max_frame_size)?);
    Ok(PendingH2Send {
        frames,
        end_stream,
        emission,
    })
}

async fn wait_h2_capacity(stream: &mut h2::SendStream<Bytes>, desired: usize) -> Result<usize> {
    stream.reserve_capacity(desired);
    loop {
        let current = stream.capacity();
        if current > 0 {
            return Ok(current.min(desired));
        }
        let assigned = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("h2 send stream closed before capacity was available")??;
        if assigned > 0 {
            return Ok(assigned.min(desired));
        }
    }
}

pub async fn send_frame(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    stall_timeout: Duration,
) -> Result<()> {
    send_bytes_with_capacity(
        stream,
        encode_grpc_frame(frame, max_frame_size)?,
        end_stream,
        stall_timeout,
    )
    .await?;
    Ok(())
}

async fn send_bytes_with_capacity(
    stream: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
    stall_timeout: Duration,
) -> Result<()> {
    if bytes.is_empty() {
        stream.send_data(bytes, end_stream)?;
        return Ok(());
    }

    while !bytes.is_empty() {
        let capacity = match timeout(stall_timeout, wait_h2_capacity(stream, bytes.len())).await {
            Ok(result) => result?,
            Err(_) => {
                stream.reserve_capacity(0);
                bail!("h2 send stalled while waiting for receiver capacity");
            }
        };
        if capacity == 0 {
            continue;
        }
        let chunk_len = capacity.min(bytes.len());
        let chunk = bytes.split_to(chunk_len);
        stream.send_data(chunk, end_stream && bytes.is_empty())?;
    }
    Ok(())
}

pub async fn send_frame_with_padding(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    stall_timeout: Duration,
    padding: &RuntimePadding,
    cover_traffic: &RuntimeCoverTraffic,
) -> Result<PaddingEmission> {
    let mut emission = PaddingEmission::default();
    if let Some(padding_frame) =
        padding.padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        send_frame(stream, padding_frame, max_frame_size, false, stall_timeout).await?;
    }
    for cover_frame in
        cover_traffic.padding_frames(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        send_frame(stream, cover_frame, max_frame_size, false, stall_timeout).await?;
    }
    send_frame(stream, frame, max_frame_size, end_stream, stall_timeout).await?;
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
        relay_dns_query, relay_target_and_tunnel, relay_udp_packet, send_frame,
        write_all_with_idle_timeout, RateLimiter, TunnelRelayPolicy,
    };
    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use maverick_core::config::ServerEgressPolicyConfig;
    use maverick_core::frame::{Frame, FrameType, TargetAddr, UdpPacketPayload};
    use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
    use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    #[test]
    fn rate_limiter_computes_expected_delay() {
        let limiter = RateLimiter::new(1_000);
        assert_eq!(limiter.delay_for(500), Duration::from_millis(500));
        assert_eq!(limiter.delay_for(0), Duration::ZERO);
    }

    #[tokio::test]
    async fn relay_write_times_out_after_no_progress() -> Result<()> {
        let (mut writer, _held_reader) = duplex(1);
        let result = timeout(
            Duration::from_secs(1),
            write_all_with_idle_timeout(
                &mut writer,
                b"blocked",
                Duration::from_millis(25),
                "test relay write timed out",
            ),
        )
        .await
        .expect("blocked relay write should remain bounded");

        let error = result.expect_err("blocked relay write should time out");
        assert!(error.to_string().contains("test relay write timed out"));
        Ok(())
    }

    #[tokio::test]
    async fn relay_write_timeout_resets_after_each_progress() -> Result<()> {
        let payload = Bytes::from_static(b"steady-progress");
        let (mut writer, mut reader) = duplex(1);
        let expected = payload.clone();
        let reader_task = tokio::spawn(async move {
            let mut received = Vec::with_capacity(expected.len());
            for _ in 0..expected.len() {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte).await?;
                received.push(byte[0]);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Result::<Vec<u8>>::Ok(received)
        });

        let idle_timeout = Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        timeout(
            Duration::from_secs(2),
            write_all_with_idle_timeout(
                &mut writer,
                &payload,
                idle_timeout,
                "test relay write timed out",
            ),
        )
        .await
        .expect("steady write progress should remain bounded")?;
        assert!(
            started.elapsed() > idle_timeout,
            "the transfer should outlive one idle window"
        );
        assert_eq!(reader_task.await??, payload);
        Ok(())
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

    #[tokio::test]
    async fn h2_server_send_waits_for_receiver_capacity() -> Result<()> {
        let (client_io, server_io) = duplex(16 * 1024);
        let (send_started_tx, send_started_rx) = tokio::sync::oneshot::channel();
        let (send_completed_tx, mut send_completed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((_request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let payload = Bytes::from(vec![0x5a; 128 * 1024]);
                    let _ = send_started_tx.send(());
                    let result = send_frame(
                        &mut send_stream,
                        Frame::new(FrameType::TcpData, 0, 1, payload),
                        256 * 1024,
                        true,
                        Duration::from_secs(2),
                    )
                    .await;
                    let _ = send_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(1_024)
            .initial_connection_window_size(1_024);
        let (client, connection) = builder.handshake::<_, Bytes>(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, _request_body) = client.send_request(request, true)?;
        let mut response_body = response.await?.into_body();
        send_started_rx.await?;

        assert!(
            timeout(Duration::from_millis(50), &mut send_completed_rx)
                .await
                .is_err(),
            "server send completed before the receiver released H2 capacity"
        );

        let mut received = BytesMut::new();
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk?;
            received.extend_from_slice(&chunk);
            response_body.flow_control().release_capacity(chunk.len())?;
        }
        timeout(Duration::from_secs(2), send_completed_rx).await???;
        let frame = decode_grpc_frame_from(&mut received, 256 * 1024)?
            .expect("complete flow-controlled frame");
        assert_eq!(frame.frame_type, FrameType::TcpData);
        assert_eq!(frame.payload, Bytes::from(vec![0x5a; 128 * 1024]));
        assert!(received.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn h2_server_send_times_out_when_receiver_grants_no_capacity() -> Result<()> {
        let (client_io, server_io) = duplex(16 * 1024);
        let (send_completed_tx, send_completed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((_request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let result = send_frame(
                        &mut send_stream,
                        Frame::new(FrameType::TcpData, 0, 1, Bytes::from_static(b"no-capacity")),
                        65_536,
                        true,
                        Duration::from_millis(25),
                    )
                    .await;
                    let _ = send_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(0);
        let (client, connection) = builder.handshake::<_, Bytes>(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, _request_body) = client.send_request(request, true)?;
        let _response_body = response.await?.into_body();

        let result = timeout(Duration::from_secs(1), send_completed_rx)
            .await
            .expect("zero-window H2 send should remain bounded")
            .expect("server send task should report its result");
        let error = result.expect_err("zero-window H2 send should time out");
        assert!(error
            .to_string()
            .contains("h2 send stalled while waiting for receiver capacity"));
        Ok(())
    }

    #[tokio::test]
    async fn h2_backpressure_preserves_upload_direction() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (target_peer, _) = target_listener.accept().await?;
        let (mut target_peer_read, mut target_peer_write) = target_peer.into_split();

        let (client_io, server_io) = duplex(16 * 1024);
        let (relay_completed_tx, relay_completed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let result = relay_target_and_tunnel(
                        target,
                        send_stream,
                        request.into_body(),
                        BytesMut::new(),
                        256 * 1024,
                        1,
                        TunnelRelayPolicy {
                            idle_timeout: Duration::from_secs(2),
                            rate_limiter: None,
                            padding: RuntimePadding::disabled(),
                            cover_traffic: RuntimeCoverTraffic::disabled(),
                            shaping_metrics: None,
                        },
                    )
                    .await;
                    let _ = relay_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(1_024);
        let (client, connection) = builder.handshake::<_, Bytes>(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, mut request_body) = client.send_request(request, false)?;
        let mut response_body = response.await?.into_body();

        let target_payload = vec![0x42; 128 * 1024];
        let target_writer = tokio::spawn(async move {
            target_peer_write.write_all(&target_payload).await?;
            target_peer_write.shutdown().await?;
            Result::<()>::Ok(())
        });

        let first_chunk = timeout(Duration::from_secs(2), response_body.data())
            .await
            .expect("server should start the response")
            .expect("response should contain data")?;

        let marker = Bytes::from_static(b"upload-still-moves");
        request_body.send_data(
            encode_grpc_frame(
                Frame::new(FrameType::TcpData, 0, 1, marker.clone()),
                256 * 1024,
            )?,
            false,
        )?;
        let mut received_marker = vec![0u8; marker.len()];
        timeout(
            Duration::from_secs(2),
            target_peer_read.read_exact(&mut received_marker),
        )
        .await
        .expect("upload must continue while the response window is full")?;
        assert_eq!(received_marker, marker);

        request_body.send_data(
            encode_grpc_frame(
                Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()),
                256 * 1024,
            )?,
            true,
        )?;

        let mut response_bytes = BytesMut::new();
        response_bytes.extend_from_slice(&first_chunk);
        response_body
            .flow_control()
            .release_capacity(first_chunk.len())?;
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk?;
            response_bytes.extend_from_slice(&chunk);
            response_body.flow_control().release_capacity(chunk.len())?;
        }

        let mut relayed_bytes = 0usize;
        let mut saw_fin = false;
        while let Some(frame) = decode_grpc_frame_from(&mut response_bytes, 256 * 1024)? {
            match frame.frame_type {
                FrameType::TcpData => relayed_bytes += frame.payload.len(),
                FrameType::TcpFin => saw_fin = true,
                _ => {}
            }
        }
        assert_eq!(relayed_bytes, 128 * 1024);
        assert!(saw_fin);
        assert!(response_bytes.is_empty());

        target_writer.await??;
        timeout(Duration::from_secs(2), relay_completed_rx).await???;
        Ok(())
    }

    #[tokio::test]
    async fn h2_tcp_reset_releases_target_without_waiting_for_idle_timeout() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (_held_target_peer, _) = target_listener.accept().await?;
        let (client_io, server_io) = duplex(16 * 1024);
        let (relay_completed_tx, relay_completed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let result = relay_target_and_tunnel(
                        target,
                        send_stream,
                        request.into_body(),
                        BytesMut::new(),
                        65_536,
                        1,
                        TunnelRelayPolicy {
                            idle_timeout: Duration::from_secs(5),
                            rate_limiter: None,
                            padding: RuntimePadding::disabled(),
                            cover_traffic: RuntimeCoverTraffic::disabled(),
                            shaping_metrics: None,
                        },
                    )
                    .await;
                    let _ = relay_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let (client, connection) = h2::client::handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (_response, mut request_body) = client.send_request(request, false)?;
        request_body.send_data(
            encode_grpc_frame(Frame::new(FrameType::TcpReset, 0, 1, Bytes::new()), 65_536)?,
            true,
        )?;

        timeout(Duration::from_secs(1), relay_completed_rx)
            .await
            .expect("TCP reset must release the relay promptly")??;
        Ok(())
    }

    #[tokio::test]
    async fn h2_request_stream_reset_releases_target_without_idle_wait() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (_held_target_peer, _) = target_listener.accept().await?;
        let (client_io, server_io) = duplex(16 * 1024);
        let (relay_completed_tx, relay_completed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let result = relay_target_and_tunnel(
                        target,
                        send_stream,
                        request.into_body(),
                        BytesMut::new(),
                        65_536,
                        1,
                        TunnelRelayPolicy {
                            idle_timeout: Duration::from_secs(5),
                            rate_limiter: None,
                            padding: RuntimePadding::disabled(),
                            cover_traffic: RuntimeCoverTraffic::disabled(),
                            shaping_metrics: None,
                        },
                    )
                    .await;
                    let _ = relay_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let (client, connection) = h2::client::handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, mut request_body) = client.send_request(request, false)?;
        let response_body = response.await?.into_body();
        request_body.send_reset(h2::Reason::CANCEL);

        let relay_result = timeout(Duration::from_secs(1), relay_completed_rx)
            .await
            .expect("H2 request reset must release the relay promptly")
            .expect("relay task should report its result");
        assert!(
            relay_result.is_err(),
            "an H2 request reset should terminate the relay with an error"
        );
        drop(response_body);
        Ok(())
    }

    #[tokio::test]
    async fn h2_client_fin_still_receives_delayed_target_response() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (mut target_peer, _) = target_listener.accept().await?;
        let target_task = tokio::spawn(async move {
            let mut request = Vec::new();
            target_peer.read_to_end(&mut request).await?;
            target_peer.write_all(b"response-after-fin").await?;
            target_peer.shutdown().await?;
            Result::<Vec<u8>>::Ok(request)
        });

        let (client_io, server_io) = duplex(16 * 1024);
        let (relay_completed_tx, relay_completed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((request, mut respond))) = h2.accept().await {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = respond.send_response(response, false).unwrap();
                tokio::spawn(async move {
                    let result = relay_target_and_tunnel(
                        target,
                        send_stream,
                        request.into_body(),
                        BytesMut::new(),
                        65_536,
                        1,
                        TunnelRelayPolicy {
                            idle_timeout: Duration::from_secs(2),
                            rate_limiter: None,
                            padding: RuntimePadding::disabled(),
                            cover_traffic: RuntimeCoverTraffic::disabled(),
                            shaping_metrics: None,
                        },
                    )
                    .await;
                    let _ = relay_completed_tx.send(result);
                });
            }
            while h2.accept().await.is_some() {}
        });

        let (client, connection) = h2::client::handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, mut request_body) = client.send_request(request, false)?;
        request_body.send_data(
            encode_grpc_frame(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()), 65_536)?,
            true,
        )?;

        let mut response_body = response.await?.into_body();
        let mut response_bytes = BytesMut::new();
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk?;
            response_bytes.extend_from_slice(&chunk);
            response_body.flow_control().release_capacity(chunk.len())?;
        }

        let mut payload = BytesMut::new();
        let mut saw_fin = false;
        while let Some(frame) = decode_grpc_frame_from(&mut response_bytes, 65_536)? {
            match frame.frame_type {
                FrameType::TcpData => payload.extend_from_slice(&frame.payload),
                FrameType::TcpFin => saw_fin = true,
                _ => {}
            }
        }
        assert_eq!(&payload[..], b"response-after-fin");
        assert!(saw_fin);
        assert!(response_bytes.is_empty());
        assert!(target_task.await??.is_empty());
        timeout(Duration::from_secs(2), relay_completed_rx).await???;
        Ok(())
    }

    #[tokio::test]
    async fn h2_slow_bulk_stream_does_not_starve_tiny_stream() -> Result<()> {
        let (client_io, server_io) = duplex(16 * 1024);
        let (bulk_started_tx, bulk_started_rx) = tokio::sync::oneshot::channel();
        let (bulk_completed_tx, bulk_completed_rx) = tokio::sync::oneshot::channel();
        let (tiny_completed_tx, tiny_completed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut bulk_started_tx = Some(bulk_started_tx);
            let mut bulk_completed_tx = Some(bulk_completed_tx);
            let mut tiny_completed_tx = Some(tiny_completed_tx);
            let mut h2 = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((request, mut respond))) = h2.accept().await {
                let path = request.uri().path().to_owned();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send_stream = respond.send_response(response, false).unwrap();
                if path == "/bulk" {
                    let started = bulk_started_tx.take().expect("one bulk stream");
                    let completed = bulk_completed_tx.take().expect("one bulk stream");
                    tokio::spawn(async move {
                        let _ = started.send(());
                        let result = send_frame(
                            &mut send_stream,
                            Frame::new(
                                FrameType::TcpData,
                                0,
                                1,
                                Bytes::from(vec![0x7a; 128 * 1024]),
                            ),
                            256 * 1024,
                            true,
                            Duration::from_secs(2),
                        )
                        .await;
                        let _ = completed.send(result);
                    });
                } else {
                    let completed = tiny_completed_tx.take().expect("one tiny stream");
                    tokio::spawn(async move {
                        let result = send_frame(
                            &mut send_stream,
                            Frame::new(FrameType::TcpData, 0, 2, Bytes::from_static(b"tiny")),
                            256 * 1024,
                            true,
                            Duration::from_secs(2),
                        )
                        .await;
                        let _ = completed.send(result);
                    });
                }
            }
        });

        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(1_024);
        let (client, connection) = builder.handshake::<_, Bytes>(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;

        let bulk_request = http::Request::builder()
            .method("POST")
            .uri("/bulk")
            .body(())?;
        let (bulk_response, _bulk_request_body) = client.send_request(bulk_request, true)?;
        let mut bulk_body = bulk_response.await?.into_body();
        bulk_started_rx.await?;
        let first_bulk_chunk = timeout(Duration::from_secs(1), bulk_body.data())
            .await
            .expect("bulk response should start")
            .expect("bulk response should contain data")?;

        client = client.ready().await?;
        let tiny_request = http::Request::builder()
            .method("POST")
            .uri("/tiny")
            .body(())?;
        let (tiny_response, _tiny_request_body) = client.send_request(tiny_request, true)?;
        let mut tiny_body = tiny_response.await?.into_body();
        let tiny_chunk = timeout(Duration::from_secs(2), tiny_body.data())
            .await
            .expect("tiny stream must not wait for the stalled bulk stream")
            .expect("tiny response should contain data")?;
        tiny_body
            .flow_control()
            .release_capacity(tiny_chunk.len())?;
        assert!(
            tiny_body.data().await.is_none(),
            "tiny response should end promptly"
        );
        timeout(Duration::from_secs(2), tiny_completed_rx).await???;
        let mut tiny_bytes = BytesMut::from(&tiny_chunk[..]);
        let tiny_frame =
            decode_grpc_frame_from(&mut tiny_bytes, 256 * 1024)?.expect("complete tiny frame");
        assert_eq!(tiny_frame.payload, Bytes::from_static(b"tiny"));
        assert!(tiny_bytes.is_empty());

        let mut bulk_bytes = BytesMut::from(&first_bulk_chunk[..]);
        bulk_body
            .flow_control()
            .release_capacity(first_bulk_chunk.len())?;
        while let Some(chunk) = bulk_body.data().await {
            let chunk = chunk?;
            bulk_bytes.extend_from_slice(&chunk);
            bulk_body.flow_control().release_capacity(chunk.len())?;
        }
        timeout(Duration::from_secs(2), bulk_completed_rx).await???;
        let bulk_frame =
            decode_grpc_frame_from(&mut bulk_bytes, 256 * 1024)?.expect("complete bulk frame");
        assert_eq!(bulk_frame.payload.len(), 128 * 1024);
        assert!(bulk_bytes.is_empty());
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
