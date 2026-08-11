use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{future::poll_fn, stream::FuturesUnordered, StreamExt};
use http::{HeaderMap, HeaderValue};
use maverick_core::config::ServerEgressPolicyConfig;
use maverick_core::frame::{
    ErrorCode, Frame, FrameType, OpenTcpPayload, TargetAddr, UdpPacketPayload,
};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;
use std::future::{ready, Future};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::{sleep_until, timeout, timeout_at, Duration, Instant};

const TARGET_CONNECT_RACE_DELAY: Duration = Duration::from_millis(250);
pub(crate) const TARGET_OPEN_LATENCY_BUCKETS_MS: [u64; 10] =
    [10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];
const TARGET_OPEN_LATENCY_BUCKET_COUNT: usize = TARGET_OPEN_LATENCY_BUCKETS_MS.len() + 1;

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

#[derive(Clone)]
pub(crate) struct TargetOpenMetricSinks {
    pub(crate) resolution_timeouts: Arc<AtomicU64>,
    pub(crate) resolution_failures: Arc<AtomicU64>,
    pub(crate) connect_timeouts: Arc<AtomicU64>,
    pub(crate) connect_failures: Arc<AtomicU64>,
    pub(crate) resolution_latency: CumulativeLatencyMetric,
    pub(crate) connect_latency: CumulativeLatencyMetric,
}

#[derive(Clone, Debug)]
pub(crate) struct CumulativeLatencyMetric {
    count: Arc<AtomicU64>,
    sum_ms: Arc<AtomicU64>,
    cumulative_buckets: Arc<[AtomicU64; TARGET_OPEN_LATENCY_BUCKET_COUNT]>,
}

impl Default for CumulativeLatencyMetric {
    fn default() -> Self {
        Self {
            count: Arc::new(AtomicU64::new(0)),
            sum_ms: Arc::new(AtomicU64::new(0)),
            cumulative_buckets: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CumulativeLatencySnapshot {
    pub(crate) count: u64,
    pub(crate) sum_ms: u64,
    pub(crate) cumulative_buckets: [u64; TARGET_OPEN_LATENCY_BUCKET_COUNT],
}

impl CumulativeLatencyMetric {
    pub(crate) fn record(&self, elapsed: Duration) {
        let elapsed_ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(elapsed_ms, Ordering::Relaxed);
        for (index, bound_ms) in TARGET_OPEN_LATENCY_BUCKETS_MS.iter().enumerate() {
            if elapsed <= Duration::from_millis(*bound_ms) {
                self.cumulative_buckets[index].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.cumulative_buckets[TARGET_OPEN_LATENCY_BUCKET_COUNT - 1]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> CumulativeLatencySnapshot {
        CumulativeLatencySnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_ms: self.sum_ms.load(Ordering::Relaxed),
            cumulative_buckets: std::array::from_fn(|index| {
                self.cumulative_buckets[index].load(Ordering::Relaxed)
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct H2SendStall;

impl fmt::Display for H2SendStall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("h2 send stalled while waiting for receiver capacity")
    }
}

impl StdError for H2SendStall {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetOpenFailureKind {
    ResolutionTimeout,
    ResolutionFailure,
    EgressPolicyRejected,
    ConnectTimeout,
    ConnectFailure,
}

#[derive(Debug)]
struct TargetOpenFailure {
    kind: TargetOpenFailureKind,
    source: Option<io::Error>,
}

impl TargetOpenFailure {
    fn new(kind: TargetOpenFailureKind) -> Self {
        Self { kind, source: None }
    }

    fn with_source(kind: TargetOpenFailureKind, source: io::Error) -> Self {
        Self {
            kind,
            source: Some(source),
        }
    }
}

impl fmt::Display for TargetOpenFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            TargetOpenFailureKind::ResolutionTimeout => "target resolution timed out",
            TargetOpenFailureKind::ResolutionFailure => "target resolution failed",
            TargetOpenFailureKind::EgressPolicyRejected => "egress policy rejected target",
            TargetOpenFailureKind::ConnectTimeout => "target connect timed out",
            TargetOpenFailureKind::ConnectFailure => "target connect failed",
        })
    }
}

impl StdError for TargetOpenFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectV3TargetOpenFailureKind {
    ResolutionTimeout,
    ResolutionFailure,
    EgressPolicyRejected,
    ConnectTimeout,
    ConnectFailure,
}

pub(crate) struct DirectV3TargetOpenError {
    kind: DirectV3TargetOpenFailureKind,
}

impl DirectV3TargetOpenError {
    const fn new(kind: DirectV3TargetOpenFailureKind) -> Self {
        Self { kind }
    }

    #[allow(dead_code)]
    pub(crate) const fn kind(&self) -> DirectV3TargetOpenFailureKind {
        self.kind
    }

    fn recorded(kind: DirectV3TargetOpenFailureKind, metrics: &TargetOpenMetricSinks) -> Self {
        metrics.record_direct_v3(kind);
        Self::new(kind)
    }
}

impl fmt::Debug for DirectV3TargetOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("direct-v3 target-open error")
    }
}

impl fmt::Display for DirectV3TargetOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            DirectV3TargetOpenFailureKind::ResolutionTimeout => {
                "direct-v3 target resolution timed out"
            }
            DirectV3TargetOpenFailureKind::ResolutionFailure => {
                "direct-v3 target resolution failed"
            }
            DirectV3TargetOpenFailureKind::EgressPolicyRejected => {
                "direct-v3 egress policy rejected target"
            }
            DirectV3TargetOpenFailureKind::ConnectTimeout => "direct-v3 target connect timed out",
            DirectV3TargetOpenFailureKind::ConnectFailure => "direct-v3 target connect failed",
        })
    }
}

impl StdError for DirectV3TargetOpenError {}

impl TargetOpenMetricSinks {
    fn record(&self, kind: TargetOpenFailureKind) {
        let counter = match kind {
            TargetOpenFailureKind::ResolutionTimeout => Some(&self.resolution_timeouts),
            TargetOpenFailureKind::ResolutionFailure => Some(&self.resolution_failures),
            TargetOpenFailureKind::EgressPolicyRejected => None,
            TargetOpenFailureKind::ConnectTimeout => Some(&self.connect_timeouts),
            TargetOpenFailureKind::ConnectFailure => Some(&self.connect_failures),
        };
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_direct_v3(&self, kind: DirectV3TargetOpenFailureKind) {
        let counter = match kind {
            DirectV3TargetOpenFailureKind::ResolutionTimeout => Some(&self.resolution_timeouts),
            DirectV3TargetOpenFailureKind::ResolutionFailure => Some(&self.resolution_failures),
            DirectV3TargetOpenFailureKind::EgressPolicyRejected => None,
            DirectV3TargetOpenFailureKind::ConnectTimeout => Some(&self.connect_timeouts),
            DirectV3TargetOpenFailureKind::ConnectFailure => Some(&self.connect_failures),
        };
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
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
    open_target_inner(&open.target, open.port, timeout_ms, egress, None).await
}

pub(crate) async fn open_target_with_metrics(
    open: &OpenTcpPayload,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
    metrics: &TargetOpenMetricSinks,
) -> Result<TcpStream> {
    open_target_addr_with_metrics(&open.target, open.port, timeout_ms, egress, metrics).await
}

pub(crate) async fn open_target_addr_with_metrics(
    target: &TargetAddr,
    port: u16,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
    metrics: &TargetOpenMetricSinks,
) -> Result<TcpStream> {
    open_target_inner(target, port, timeout_ms, egress, Some(metrics)).await
}

#[cfg_attr(not(feature = "quiche-foundation"), allow(dead_code))]
pub(crate) async fn open_target_addr_before_deadline_with_metrics(
    target: &TargetAddr,
    port: u16,
    absolute_deadline: std::time::Instant,
    egress: &ServerEgressPolicyConfig,
    metrics: &TargetOpenMetricSinks,
) -> std::result::Result<TcpStream, DirectV3TargetOpenError> {
    let resolved = match target {
        TargetAddr::Domain(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct-v3 Domain resolution unavailable",
        )),
        TargetAddr::Ipv4(addr) => Ok(vec![SocketAddr::from((*addr, port))]),
        TargetAddr::Ipv6(addr) => Ok(vec![SocketAddr::from((*addr, port))]),
    };
    open_target_addr_before_deadline_with_metrics_using(
        absolute_deadline,
        egress,
        metrics,
        move || ready(resolved),
        |addrs| connect_target_addresses(addrs, TARGET_CONNECT_RACE_DELAY, connect_target_tcp),
    )
    .await
}

async fn open_target_addr_before_deadline_with_metrics_using<
    T,
    Resolve,
    ResolveFuture,
    Connect,
    ConnectFuture,
>(
    absolute_deadline: std::time::Instant,
    egress: &ServerEgressPolicyConfig,
    metrics: &TargetOpenMetricSinks,
    resolver: Resolve,
    connector: Connect,
) -> std::result::Result<T, DirectV3TargetOpenError>
where
    Resolve: FnOnce() -> ResolveFuture,
    ResolveFuture: Future<Output = io::Result<Vec<SocketAddr>>>,
    Connect: FnOnce(Vec<SocketAddr>) -> ConnectFuture,
    ConnectFuture: Future<Output = io::Result<T>>,
{
    let absolute_deadline = Instant::from_std(absolute_deadline);
    if Instant::now() >= absolute_deadline {
        return Err(DirectV3TargetOpenError::recorded(
            DirectV3TargetOpenFailureKind::ResolutionTimeout,
            metrics,
        ));
    }

    let resolution_started = Instant::now();
    let resolved = match timeout_at(absolute_deadline, resolver()).await {
        Err(_) => {
            return Err(DirectV3TargetOpenError::recorded(
                DirectV3TargetOpenFailureKind::ResolutionTimeout,
                metrics,
            ))
        }
        Ok(_result) if Instant::now() >= absolute_deadline => {
            return Err(DirectV3TargetOpenError::recorded(
                DirectV3TargetOpenFailureKind::ResolutionTimeout,
                metrics,
            ))
        }
        Ok(Err(_)) => {
            return Err(DirectV3TargetOpenError::recorded(
                DirectV3TargetOpenFailureKind::ResolutionFailure,
                metrics,
            ))
        }
        Ok(Ok(resolved)) if resolved.is_empty() => {
            return Err(DirectV3TargetOpenError::recorded(
                DirectV3TargetOpenFailureKind::ResolutionFailure,
                metrics,
            ))
        }
        Ok(Ok(resolved)) => resolved,
    };

    let allowed = resolved
        .into_iter()
        .filter(|addr| egress.allows_ip(addr.ip()))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return Err(DirectV3TargetOpenError::new(
            DirectV3TargetOpenFailureKind::EgressPolicyRejected,
        ));
    }
    metrics
        .resolution_latency
        .record(resolution_started.elapsed());

    if Instant::now() >= absolute_deadline {
        return Err(DirectV3TargetOpenError::recorded(
            DirectV3TargetOpenFailureKind::ConnectTimeout,
            metrics,
        ));
    }
    let connect_started = Instant::now();
    match timeout_at(absolute_deadline, connector(allowed)).await {
        Err(_) => Err(DirectV3TargetOpenError::recorded(
            DirectV3TargetOpenFailureKind::ConnectTimeout,
            metrics,
        )),
        Ok(_) if Instant::now() >= absolute_deadline => Err(DirectV3TargetOpenError::recorded(
            DirectV3TargetOpenFailureKind::ConnectTimeout,
            metrics,
        )),
        Ok(Err(_)) => Err(DirectV3TargetOpenError::recorded(
            DirectV3TargetOpenFailureKind::ConnectFailure,
            metrics,
        )),
        Ok(Ok(connected)) => {
            metrics.connect_latency.record(connect_started.elapsed());
            Ok(connected)
        }
    }
}

async fn open_target_inner(
    target: &TargetAddr,
    port: u16,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
    metrics: Option<&TargetOpenMetricSinks>,
) -> Result<TcpStream> {
    let authority = target.to_authority(port);
    let resolution_started = Instant::now();
    let addrs = match resolve_allowed_authority_classified(&authority, timeout_ms, egress).await {
        Ok(addrs) => {
            if let Some(metrics) = metrics {
                metrics
                    .resolution_latency
                    .record(resolution_started.elapsed());
            }
            addrs
        }
        Err(failure) => {
            if let Some(metrics) = metrics {
                metrics.record(failure.kind);
            }
            return Err(anyhow::Error::new(failure).context("resolve target"));
        }
    };
    let connect_started = Instant::now();
    match connect_with_timeout(
        connect_target_addresses(addrs, TARGET_CONNECT_RACE_DELAY, connect_target_tcp),
        Duration::from_millis(timeout_ms),
    )
    .await
    {
        Ok(target) => {
            if let Some(metrics) = metrics {
                metrics.connect_latency.record(connect_started.elapsed());
            }
            Ok(target)
        }
        Err(failure) => {
            if let Some(metrics) = metrics {
                metrics.record(failure.kind);
            }
            Err(anyhow::Error::new(failure))
        }
    }
}

async fn connect_target_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    let target = TcpStream::connect(addr).await?;
    target.set_nodelay(true).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("enable TCP_NODELAY on target connection: {error}"),
        )
    })?;
    Ok(target)
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
                if pending_send.is_some() {
                    return Err(H2SendStall.into());
                }
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
                let front = pending.frames.front_mut().expect("pending H2 frame");
                let chunk = front.split_to(capacity.min(front.len()));
                let frame_finished = front.is_empty();
                send_stream.send_data(chunk, false)?;
                if frame_finished {
                    pending.frames.pop_front();
                }
                if pending.frames.is_empty() {
                    let completed = pending_send.take().expect("completed H2 send");
                    policy.record_padding(completed.emission);
                    if completed.end_stream {
                        // The Maverick terminal frame is complete. Close the
                        // outer gRPC response with trailers, never DATA
                        // END_STREAM.
                        send_grpc_ok_trailers(&mut send_stream)?;
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
                        // Request EOS without a Maverick FIN/CloseFlow is an
                        // abrupt protocol end. Dropping the still-open response
                        // stream makes h2 send RST_STREAM instead of a false
                        // grpc-status: 0.
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn send_grpc_ok_trailers(stream: &mut h2::SendStream<Bytes>) -> Result<()> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    stream.send_trailers(trailers)?;
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
                return Err(H2SendStall.into());
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
    let target = ConnectedUdpTarget::open(&packet.target, packet.port, timeout_ms, egress).await?;
    relay_connected_udp_packet(&target, packet, timeout_ms).await
}

pub(super) struct UdpFlowRelay {
    active: Option<ActiveUdpTarget>,
}

struct ActiveUdpTarget {
    target: TargetAddr,
    port: u16,
    owner: ConnectedUdpTarget,
}

impl UdpFlowRelay {
    pub(super) fn new() -> Self {
        Self { active: None }
    }

    #[cfg(feature = "h3")]
    pub(super) fn has_active_target(&self) -> bool {
        self.active.is_some()
    }

    pub(super) async fn send_packet(
        &mut self,
        packet: &UdpPacketPayload,
        timeout_ms: u64,
        egress: &ServerEgressPolicyConfig,
    ) -> Result<()> {
        let reuses_active = self
            .active
            .as_ref()
            .is_some_and(|active| active.target == packet.target && active.port == packet.port);
        if !reuses_active {
            self.active.take();
            let owner =
                ConnectedUdpTarget::open(&packet.target, packet.port, timeout_ms, egress).await?;
            self.active = Some(ActiveUdpTarget {
                target: packet.target.clone(),
                port: packet.port,
                owner,
            });
        }

        let result = self
            .active
            .as_ref()
            .context("UDP flow target missing after open")?
            .owner
            .send(&packet.data)
            .await;
        if result.is_err() {
            self.active.take();
        }
        result
    }

    pub(super) async fn recv_packet(&mut self, buf: &mut [u8]) -> Result<UdpPacketPayload> {
        let result = async {
            let active = self
                .active
                .as_ref()
                .context("UDP flow target missing before receive")?;
            let len = active.owner.recv(buf).await?;
            Ok(UdpPacketPayload::new(
                active.target.clone(),
                active.port,
                Bytes::copy_from_slice(&buf[..len]),
            ))
        }
        .await;
        if result.is_err() {
            self.active.take();
        }
        result
    }

    pub(super) async fn relay_packet(
        &mut self,
        packet: &UdpPacketPayload,
        timeout_ms: u64,
        egress: &ServerEgressPolicyConfig,
    ) -> Result<UdpPacketPayload> {
        self.send_packet(packet, timeout_ms, egress).await?;
        let mut buf = vec![0u8; 65_535];
        match timeout(
            Duration::from_millis(timeout_ms),
            self.recv_packet(&mut buf),
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                // Cancelling recv_packet at its deadline cannot run its error
                // cleanup, so the serial composition clears the owner here.
                self.active.take();
                Err(err).context("UDP target timed out")
            }
        }
    }
}

async fn relay_connected_udp_packet(
    target: &ConnectedUdpTarget,
    packet: &UdpPacketPayload,
    timeout_ms: u64,
) -> Result<UdpPacketPayload> {
    target.send(&packet.data).await?;
    let mut buf = vec![0u8; 65_535];
    let len = timeout(Duration::from_millis(timeout_ms), target.recv(&mut buf))
        .await
        .context("UDP target timed out")??;
    buf.truncate(len);
    Ok(UdpPacketPayload::new(
        packet.target.clone(),
        packet.port,
        Bytes::from(buf),
    ))
}

struct ConnectedUdpTarget {
    socket: UdpSocket,
}

impl ConnectedUdpTarget {
    async fn open(
        target: &TargetAddr,
        port: u16,
        timeout_ms: u64,
        egress: &ServerEgressPolicyConfig,
    ) -> Result<Self> {
        let authority = target.to_authority(port);
        let target = first_allowed_addr(&authority, timeout_ms, egress).await?;
        let socket = bind_udp_for_target(target).await?;
        socket.connect(target).await?;
        Ok(Self { socket })
    }

    async fn send(&self, data: &[u8]) -> Result<()> {
        let sent = self.socket.send(data).await?;
        if sent != data.len() {
            bail!("UDP target send was incomplete");
        }
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.socket.recv(buf).await?)
    }
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
    resolve_allowed_authority_classified(authority, timeout_ms, egress)
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| format!("resolve target {authority}"))
}

async fn resolve_allowed_authority_classified(
    authority: &str,
    timeout_ms: u64,
    egress: &ServerEgressPolicyConfig,
) -> std::result::Result<Vec<SocketAddr>, TargetOpenFailure> {
    let resolved = async {
        lookup_host(authority)
            .await
            .map(|resolved| resolved.collect::<Vec<_>>())
    };
    resolve_allowed_addresses(resolved, Duration::from_millis(timeout_ms), egress).await
}

async fn resolve_allowed_addresses<F>(
    resolved: F,
    timeout_duration: Duration,
    egress: &ServerEgressPolicyConfig,
) -> std::result::Result<Vec<SocketAddr>, TargetOpenFailure>
where
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let resolved = match timeout(timeout_duration, resolved).await {
        Ok(Ok(resolved)) if !resolved.is_empty() => resolved,
        Ok(Ok(_)) => {
            return Err(TargetOpenFailure::new(
                TargetOpenFailureKind::ResolutionFailure,
            ))
        }
        Ok(Err(source)) => {
            return Err(TargetOpenFailure::with_source(
                TargetOpenFailureKind::ResolutionFailure,
                source,
            ))
        }
        Err(_) => {
            return Err(TargetOpenFailure::new(
                TargetOpenFailureKind::ResolutionTimeout,
            ))
        }
    };
    let allowed = resolved
        .into_iter()
        .filter(|addr| egress.allows_ip(addr.ip()))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return Err(TargetOpenFailure::new(
            TargetOpenFailureKind::EgressPolicyRejected,
        ));
    }
    Ok(allowed)
}

#[derive(Clone, Copy)]
struct ConnectCandidate {
    addr: SocketAddr,
    original_index: usize,
}

async fn connect_target_addresses<T, C, F>(
    addrs: Vec<SocketAddr>,
    race_delay: Duration,
    mut connect: C,
) -> io::Result<T>
where
    C: FnMut(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target address set is empty",
        ));
    }

    let has_ipv4 = addrs.iter().any(SocketAddr::is_ipv4);
    let has_ipv6 = addrs.iter().any(SocketAddr::is_ipv6);
    if !(has_ipv4 && has_ipv6) {
        let mut last_error = None;
        for addr in addrs {
            match connect(addr).await {
                Ok(connected) => return Ok(connected),
                Err(error) => last_error = Some(error),
            }
        }
        return Err(last_error.expect("non-empty target address set must produce an error"));
    }

    let first_is_ipv4 = addrs[0].is_ipv4();
    let mut first_family = VecDeque::new();
    let mut other_family = VecDeque::new();
    for (original_index, addr) in addrs.iter().copied().enumerate() {
        let candidate = ConnectCandidate {
            addr,
            original_index,
        };
        if addr.is_ipv4() == first_is_ipv4 {
            first_family.push_back(candidate);
        } else {
            other_family.push_back(candidate);
        }
    }

    let mut pending_candidates = VecDeque::with_capacity(addrs.len());
    while !first_family.is_empty() || !other_family.is_empty() {
        if let Some(candidate) = first_family.pop_front() {
            pending_candidates.push_back(candidate);
        }
        if let Some(candidate) = other_family.pop_front() {
            pending_candidates.push_back(candidate);
        }
    }

    let mut errors = (0..addrs.len())
        .map(|_| None)
        .collect::<Vec<Option<io::Error>>>();
    let mut make_attempt = |candidate: ConnectCandidate| {
        let connected = connect(candidate.addr);
        async move { (candidate.original_index, connected.await) }
    };
    let mut in_flight = FuturesUnordered::new();
    let first = pending_candidates
        .pop_front()
        .expect("mixed-family target address set must be non-empty");
    in_flight.push(make_attempt(first));

    loop {
        let completed = if !pending_candidates.is_empty() && in_flight.len() < 2 {
            tokio::select! {
                completed = in_flight.next() => completed,
                _ = tokio::time::sleep(race_delay) => None,
            }
        } else {
            in_flight.next().await
        };

        if let Some((original_index, result)) = completed {
            match result {
                Ok(connected) => return Ok(connected),
                Err(error) => errors[original_index] = Some(error),
            }
            if let Some(candidate) = pending_candidates.pop_front() {
                in_flight.push(make_attempt(candidate));
            }
        } else if let Some(candidate) = pending_candidates.pop_front() {
            in_flight.push(make_attempt(candidate));
        }

        if in_flight.is_empty() && pending_candidates.is_empty() {
            return Err(errors
                .into_iter()
                .last()
                .flatten()
                .expect("all target connection attempts must have an error"));
        }
    }
}

async fn connect_with_timeout<T, F>(
    connected: F,
    timeout_duration: Duration,
) -> std::result::Result<T, TargetOpenFailure>
where
    F: Future<Output = io::Result<T>>,
{
    match timeout(timeout_duration, connected).await {
        Ok(Ok(connected)) => Ok(connected),
        Ok(Err(source)) => Err(TargetOpenFailure::with_source(
            TargetOpenFailureKind::ConnectFailure,
            source,
        )),
        Err(_) => Err(TargetOpenFailure::new(
            TargetOpenFailureKind::ConnectTimeout,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        connect_target_addresses, connect_target_tcp, connect_with_timeout, open_target,
        open_target_addr_before_deadline_with_metrics,
        open_target_addr_before_deadline_with_metrics_using, open_target_addr_with_metrics,
        open_target_with_metrics, relay_dns_query, relay_target_and_tunnel, relay_udp_packet,
        resolve_allowed_addresses, send_frame, write_all_with_idle_timeout, ConnectedUdpTarget,
        CumulativeLatencyMetric, DirectV3TargetOpenError, DirectV3TargetOpenFailureKind,
        H2SendStall, RateLimiter, TargetOpenFailure, TargetOpenFailureKind, TargetOpenMetricSinks,
        TunnelRelayPolicy, UdpFlowRelay, TARGET_CONNECT_RACE_DELAY,
    };
    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use futures::poll;
    use maverick_core::config::ServerEgressPolicyConfig;
    use maverick_core::frame::{Frame, FrameType, OpenTcpPayload, TargetAddr, UdpPacketPayload};
    use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
    use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
    use std::error::Error as StdError;
    use std::future::{pending, ready};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{advance, sleep, sleep_until, timeout, Duration, Instant};

    async fn assert_grpc_ok_trailers(body: &mut h2::RecvStream) -> Result<()> {
        let trailers = body
            .trailers()
            .await?
            .expect("complete gRPC response must contain trailers");
        assert_eq!(
            trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
        Ok(())
    }

    #[test]
    fn rate_limiter_computes_expected_delay() {
        let limiter = RateLimiter::new(1_000);
        assert_eq!(limiter.delay_for(500), Duration::from_millis(500));
        assert_eq!(limiter.delay_for(0), Duration::ZERO);
    }

    fn target_metric_sinks() -> TargetOpenMetricSinks {
        TargetOpenMetricSinks {
            resolution_timeouts: Arc::new(AtomicU64::new(0)),
            resolution_failures: Arc::new(AtomicU64::new(0)),
            connect_timeouts: Arc::new(AtomicU64::new(0)),
            connect_failures: Arc::new(AtomicU64::new(0)),
            resolution_latency: CumulativeLatencyMetric::default(),
            connect_latency: CumulativeLatencyMetric::default(),
        }
    }

    fn target_metric_values(metrics: &TargetOpenMetricSinks) -> [u64; 4] {
        [
            metrics.resolution_timeouts.load(Ordering::Relaxed),
            metrics.resolution_failures.load(Ordering::Relaxed),
            metrics.connect_timeouts.load(Ordering::Relaxed),
            metrics.connect_failures.load(Ordering::Relaxed),
        ]
    }

    fn loopback_egress_policy() -> ServerEgressPolicyConfig {
        ServerEgressPolicyConfig {
            allow_loopback: true,
            ..ServerEgressPolicyConfig::default()
        }
    }

    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn target_tcp_connector_enables_nodelay() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = connect_target_tcp(listener.local_addr()?).await?;
        let (_peer, _) = listener.accept().await?;

        assert!(target.nodelay()?);
        Ok(())
    }

    #[test]
    fn target_latency_metric_uses_fixed_cumulative_buckets() {
        let metric = CumulativeLatencyMetric::default();
        metric.record(Duration::from_millis(5));
        metric.record(Duration::from_millis(250));
        metric.record(Duration::from_millis(10_001));

        let snapshot = metric.snapshot();
        assert_eq!(snapshot.count, 3);
        assert_eq!(snapshot.sum_ms, 10_256);
        assert_eq!(
            snapshot.cumulative_buckets,
            [1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3]
        );
    }

    #[tokio::test]
    async fn successful_target_open_records_resolution_and_connect_latency() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = listener.local_addr()?;
        let accepted = tokio::spawn(async move { listener.accept().await });
        let open = OpenTcpPayload::new(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target_addr.port());
        let metrics = target_metric_sinks();

        let target =
            open_target_with_metrics(&open, 1_000, &loopback_egress_policy(), &metrics).await?;
        let (_peer, _) = accepted.await??;

        assert_eq!(metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(metrics.connect_latency.snapshot().count, 1);
        assert_eq!(
            metrics.resolution_latency.snapshot().cumulative_buckets[10],
            1
        );
        assert_eq!(metrics.connect_latency.snapshot().cumulative_buckets[10], 1);
        drop(target);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_and_structured_target_open_share_ipv4_path() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let target_addr = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
        let open = OpenTcpPayload::new(target_addr.clone(), port);

        let legacy_target = open_target(&open, 1_000, &loopback_egress_policy()).await?;
        let (_legacy_peer, _) = listener.accept().await?;

        let metrics = target_metric_sinks();
        let structured_target = open_target_addr_with_metrics(
            &target_addr,
            port,
            1_000,
            &loopback_egress_policy(),
            &metrics,
        )
        .await?;
        let (_structured_peer, _) = listener.accept().await?;

        assert!(legacy_target.nodelay()?);
        assert!(structured_target.nodelay()?);
        assert_eq!(metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(metrics.connect_latency.snapshot().count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn structured_domain_target_uses_existing_resolver() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let metrics = target_metric_sinks();

        let target = open_target_addr_with_metrics(
            &TargetAddr::Domain("localhost".to_owned()),
            port,
            1_000,
            &loopback_egress_policy(),
            &metrics,
        )
        .await?;
        let (_peer, _) = listener.accept().await?;

        assert!(target.nodelay()?);
        assert_eq!(metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(metrics.connect_latency.snapshot().count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_and_structured_target_open_share_ipv6_path_when_available() -> Result<()> {
        let listener = match TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await {
            Ok(listener) => listener,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error.into()),
        };
        let port = listener.local_addr()?.port();
        let target_addr = TargetAddr::Ipv6(Ipv6Addr::LOCALHOST);
        let open = OpenTcpPayload::new(target_addr.clone(), port);

        let legacy_target = open_target(&open, 1_000, &loopback_egress_policy()).await?;
        let (_legacy_peer, _) = listener.accept().await?;

        let metrics = target_metric_sinks();
        let structured_target = open_target_addr_with_metrics(
            &target_addr,
            port,
            1_000,
            &loopback_egress_policy(),
            &metrics,
        )
        .await?;
        let (_structured_peer, _) = listener.accept().await?;

        assert!(legacy_target.nodelay()?);
        assert!(structured_target.nodelay()?);
        assert_eq!(metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(metrics.connect_latency.snapshot().count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_and_structured_egress_rejection_precedes_connect() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let target_addr = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
        let open = OpenTcpPayload::new(target_addr.clone(), port);
        let egress = ServerEgressPolicyConfig::default();
        let legacy_metrics = target_metric_sinks();
        let structured_metrics = target_metric_sinks();

        let legacy_error = open_target_with_metrics(&open, 1_000, &egress, &legacy_metrics)
            .await
            .expect_err("legacy target open must enforce egress policy");
        let structured_error =
            open_target_addr_with_metrics(&target_addr, port, 1_000, &egress, &structured_metrics)
                .await
                .expect_err("structured target open must enforce egress policy");

        let legacy_failure = legacy_error
            .downcast_ref::<TargetOpenFailure>()
            .expect("legacy error must retain its fixed target-open category");
        let structured_failure = structured_error
            .downcast_ref::<TargetOpenFailure>()
            .expect("structured error must retain its fixed target-open category");
        assert_eq!(
            legacy_failure.kind,
            TargetOpenFailureKind::EgressPolicyRejected
        );
        assert_eq!(structured_failure.kind, legacy_failure.kind);
        assert_eq!(target_metric_values(&legacy_metrics), [0, 0, 0, 0]);
        assert_eq!(
            target_metric_values(&structured_metrics),
            target_metric_values(&legacy_metrics)
        );
        assert_eq!(legacy_metrics.resolution_latency.snapshot().count, 0);
        assert_eq!(structured_metrics.resolution_latency.snapshot().count, 0);
        assert!(
            timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "egress rejection must happen before a TCP connection is attempted"
        );
        Ok(())
    }

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn target_resolution_timeout_increments_only_its_counter() {
        let failure = resolve_allowed_addresses(
            pending::<io::Result<Vec<SocketAddr>>>(),
            Duration::from_millis(1),
            &loopback_egress_policy(),
        )
        .await
        .expect_err("pending resolver must time out");
        assert_eq!(failure.kind, TargetOpenFailureKind::ResolutionTimeout);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [1, 0, 0, 0]);
    }

    #[tokio::test]
    async fn target_resolution_failure_increments_only_its_counter() {
        let failure = resolve_allowed_addresses(
            ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "synthetic resolver failure",
            ))),
            Duration::from_secs(1),
            &loopback_egress_policy(),
        )
        .await
        .expect_err("resolver error must fail");
        assert_eq!(failure.kind, TargetOpenFailureKind::ResolutionFailure);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 1, 0, 0]);
    }

    #[tokio::test]
    async fn target_connect_timeout_increments_only_its_counter() {
        let failure = connect_with_timeout(pending::<io::Result<()>>(), Duration::from_millis(1))
            .await
            .expect_err("pending connector must time out");
        assert_eq!(failure.kind, TargetOpenFailureKind::ConnectTimeout);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 0, 1, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn legacy_h2_two_stage_target_open_can_run_for_nineteen_seconds() {
        let started = Instant::now();
        let resolved = resolve_allowed_addresses(
            async {
                sleep(Duration::from_secs(9)).await;
                Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])
            },
            Duration::from_secs(10),
            &loopback_egress_policy(),
        )
        .await
        .expect("synthetic resolution must finish inside its own deadline");
        assert_eq!(started.elapsed(), Duration::from_secs(9));

        let failure = connect_with_timeout(pending::<io::Result<()>>(), Duration::from_secs(10))
            .await
            .expect_err("legacy H2 connect stage must receive a fresh timeout");

        assert!(!resolved.is_empty());
        assert_eq!(failure.kind, TargetOpenFailureKind::ConnectTimeout);
        assert_eq!(started.elapsed(), Duration::from_secs(19));
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_dns_time_leaves_only_the_shared_deadline_remainder() {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(10);
        let connector_started = Arc::new(StdMutex::new(None));
        let connector_observation = Arc::clone(&connector_started);
        let metrics = target_metric_sinks();

        let error = open_target_addr_before_deadline_with_metrics_using(
            deadline.into_std(),
            &loopback_egress_policy(),
            &metrics,
            || async {
                sleep(Duration::from_secs(9)).await;
                Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])
            },
            move |_| {
                *connector_observation.lock().unwrap() = Some(Instant::now());
                pending::<io::Result<usize>>()
            },
        )
        .await
        .expect_err("connector must receive only the remaining whole-attempt budget");

        assert_eq!(error.kind(), DirectV3TargetOpenFailureKind::ConnectTimeout);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(
            connector_started.lock().unwrap().expect("connector called") - started,
            Duration::from_secs(9)
        );
        assert_eq!(target_metric_values(&metrics), [0, 0, 1, 0]);
    }

    #[tokio::test]
    async fn direct_v3_production_domain_fails_closed_before_system_resolution_or_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind direct-v3 Domain rejection target");
        let port = listener.local_addr().expect("read loopback target").port();
        let metrics = target_metric_sinks();
        let result = open_target_addr_before_deadline_with_metrics(
            &TargetAddr::Domain("localhost".to_owned()),
            port,
            (Instant::now() + Duration::from_secs(1)).into_std(),
            &loopback_egress_policy(),
            &metrics,
        )
        .await;

        assert!(
            timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err(),
            "direct-v3 production Domain must not reach a resolved target"
        );
        let error = result.expect_err("direct-v3 production Domain must fail closed");
        assert_eq!(
            error.kind(),
            DirectV3TargetOpenFailureKind::ResolutionFailure
        );
        assert_eq!(target_metric_values(&metrics), [0, 1, 0, 0]);
        assert_eq!(metrics.resolution_latency.snapshot().count, 0);
        assert_eq!(metrics.connect_latency.snapshot().count, 0);
    }

    #[tokio::test]
    async fn direct_v3_production_ip_literals_connect_with_exact_latency_metrics() {
        let ipv4_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind direct-v3 IPv4 target");
        let ipv4_port = ipv4_listener
            .local_addr()
            .expect("read direct-v3 IPv4 target")
            .port();
        let ipv4_metrics = target_metric_sinks();
        let ipv4_target = open_target_addr_before_deadline_with_metrics(
            &TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            ipv4_port,
            (Instant::now() + Duration::from_secs(1)).into_std(),
            &loopback_egress_policy(),
            &ipv4_metrics,
        )
        .await
        .expect("direct-v3 IPv4 literal connects");
        let (ipv4_peer, _) = ipv4_listener
            .accept()
            .await
            .expect("accept direct-v3 IPv4 target");
        assert_eq!(target_metric_values(&ipv4_metrics), [0, 0, 0, 0]);
        assert_eq!(ipv4_metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(ipv4_metrics.connect_latency.snapshot().count, 1);
        drop((ipv4_target, ipv4_peer));

        let ipv6_listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return;
            }
            Err(_) => panic!("bind direct-v3 IPv6 target"),
        };
        let ipv6_port = ipv6_listener
            .local_addr()
            .expect("read direct-v3 IPv6 target")
            .port();
        let ipv6_metrics = target_metric_sinks();
        let ipv6_target = open_target_addr_before_deadline_with_metrics(
            &TargetAddr::Ipv6(Ipv6Addr::LOCALHOST),
            ipv6_port,
            (Instant::now() + Duration::from_secs(1)).into_std(),
            &loopback_egress_policy(),
            &ipv6_metrics,
        )
        .await
        .expect("direct-v3 IPv6 literal connects");
        let (ipv6_peer, _) = ipv6_listener
            .accept()
            .await
            .expect("accept direct-v3 IPv6 target");
        assert_eq!(target_metric_values(&ipv6_metrics), [0, 0, 0, 0]);
        assert_eq!(ipv6_metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(ipv6_metrics.connect_latency.snapshot().count, 1);
        drop((ipv6_target, ipv6_peer));
    }

    #[tokio::test]
    async fn direct_v3_production_expired_domain_preserves_timeout_priority() {
        let metrics = target_metric_sinks();
        let expired = Instant::now()
            .checked_sub(Duration::from_nanos(1))
            .expect("test clock permits a prior instant");
        let error = open_target_addr_before_deadline_with_metrics(
            &TargetAddr::Domain("unused.invalid".to_owned()),
            443,
            expired.into_std(),
            &loopback_egress_policy(),
            &metrics,
        )
        .await
        .expect_err("expired Domain attempt must retain timeout priority");
        assert_eq!(
            error.kind(),
            DirectV3TargetOpenFailureKind::ResolutionTimeout
        );
        assert_eq!(target_metric_values(&metrics), [1, 0, 0, 0]);
        assert_eq!(metrics.resolution_latency.snapshot().count, 0);
        assert_eq!(metrics.connect_latency.snapshot().count, 0);
    }

    #[tokio::test]
    async fn direct_v3_generic_helper_drop_cancels_injected_pending_resolution_or_connect_future() {
        let resolution_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resolution_guard = Arc::clone(&resolution_dropped);
        let resolution_metrics = target_metric_sinks();
        let resolution_policy = loopback_egress_policy();
        let mut resolution_attempt = Box::pin(open_target_addr_before_deadline_with_metrics_using(
            (Instant::now() + Duration::from_secs(10)).into_std(),
            &resolution_policy,
            &resolution_metrics,
            move || async move {
                let _guard = DropFlag(resolution_guard);
                pending::<io::Result<Vec<SocketAddr>>>().await
            },
            |_| ready(Ok::<_, io::Error>(())),
        ));
        assert!(poll!(resolution_attempt.as_mut()).is_pending());
        drop(resolution_attempt);
        assert!(resolution_dropped.load(Ordering::Acquire));
        assert_eq!(target_metric_values(&resolution_metrics), [0, 0, 0, 0]);
        assert_eq!(resolution_metrics.resolution_latency.snapshot().count, 0);
        assert_eq!(resolution_metrics.connect_latency.snapshot().count, 0);

        let connect_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connect_guard = Arc::clone(&connect_dropped);
        let connect_metrics = target_metric_sinks();
        let connect_policy = loopback_egress_policy();
        let mut connect_attempt = Box::pin(open_target_addr_before_deadline_with_metrics_using(
            (Instant::now() + Duration::from_secs(10)).into_std(),
            &connect_policy,
            &connect_metrics,
            || ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])),
            move |_| async move {
                let _guard = DropFlag(connect_guard);
                pending::<io::Result<()>>().await
            },
        ));
        assert!(poll!(connect_attempt.as_mut()).is_pending());
        drop(connect_attempt);
        assert!(connect_dropped.load(Ordering::Acquire));
        tokio::task::yield_now().await;
        assert_eq!(target_metric_values(&connect_metrics), [0, 0, 0, 0]);
        assert_eq!(connect_metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(connect_metrics.connect_latency.snapshot().count, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_resolution_at_deadline_counts_once_and_never_connects() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let connector_calls = Arc::new(AtomicUsize::new(0));
        let observed_connector_calls = Arc::clone(&connector_calls);
        let metrics = target_metric_sinks();

        let error = open_target_addr_before_deadline_with_metrics_using(
            deadline.into_std(),
            &loopback_egress_policy(),
            &metrics,
            || async {
                sleep_until(deadline).await;
                Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])
            },
            move |_| {
                observed_connector_calls.fetch_add(1, Ordering::Relaxed);
                ready(Ok::<_, io::Error>(()))
            },
        )
        .await
        .expect_err("resolution reaching the strict deadline must time out");

        assert_eq!(
            error.kind(),
            DirectV3TargetOpenFailureKind::ResolutionTimeout
        );
        assert_eq!(connector_calls.load(Ordering::Relaxed), 0);
        assert_eq!(target_metric_values(&metrics), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_connect_at_shared_deadline_counts_once() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let metrics = target_metric_sinks();

        let error = open_target_addr_before_deadline_with_metrics_using(
            deadline.into_std(),
            &loopback_egress_policy(),
            &metrics,
            || ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])),
            move |_| async move {
                sleep_until(deadline).await;
                Ok::<_, io::Error>(())
            },
        )
        .await
        .expect_err("connect reaching the same strict deadline must time out");

        assert_eq!(error.kind(), DirectV3TargetOpenFailureKind::ConnectTimeout);
        assert_eq!(target_metric_values(&metrics), [0, 0, 1, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_expired_deadline_rejects_before_resolver_or_connector() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let connector_calls = Arc::clone(&calls);
        let metrics = target_metric_sinks();
        let expired = Instant::now()
            .checked_sub(Duration::from_nanos(1))
            .expect("paused clock must permit a prior instant");

        let error = open_target_addr_before_deadline_with_metrics_using(
            expired.into_std(),
            &loopback_egress_policy(),
            &metrics,
            move || {
                resolver_calls.fetch_add(1, Ordering::Relaxed);
                ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))]))
            },
            move |_| {
                connector_calls.fetch_add(1, Ordering::Relaxed);
                ready(Ok::<_, io::Error>(()))
            },
        )
        .await
        .expect_err("an already expired attempt must fail before work starts");

        assert_eq!(
            error.kind(),
            DirectV3TargetOpenFailureKind::ResolutionTimeout
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(target_metric_values(&metrics), [1, 0, 0, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_failures_are_typed_counted_once_and_egress_precedes_connect() {
        const PRIVATE_MARKER: &str = "sensitive-synthetic-marker.invalid";
        let deadline = (Instant::now() + Duration::from_secs(10)).into_std();

        let resolution_metrics = target_metric_sinks();
        let resolution_error = open_target_addr_before_deadline_with_metrics_using(
            deadline,
            &loopback_egress_policy(),
            &resolution_metrics,
            || ready(Err(io::Error::other(PRIVATE_MARKER))),
            |_| ready(Ok::<_, io::Error>(())),
        )
        .await
        .expect_err("synthetic resolver failure must be typed");
        assert_eq!(
            resolution_error.kind(),
            DirectV3TargetOpenFailureKind::ResolutionFailure
        );
        assert_eq!(target_metric_values(&resolution_metrics), [0, 1, 0, 0]);

        let order = Arc::new(StdMutex::new(Vec::new()));
        let resolver_order = Arc::clone(&order);
        let connector_order = Arc::clone(&order);
        let egress_metrics = target_metric_sinks();
        let egress_error = open_target_addr_before_deadline_with_metrics_using(
            deadline,
            &ServerEgressPolicyConfig::default(),
            &egress_metrics,
            move || {
                resolver_order.lock().unwrap().push("resolution");
                ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))]))
            },
            move |_| {
                connector_order.lock().unwrap().push("connect");
                ready(Ok::<_, io::Error>(()))
            },
        )
        .await
        .expect_err("egress policy must reject before connect");
        assert_eq!(
            egress_error.kind(),
            DirectV3TargetOpenFailureKind::EgressPolicyRejected
        );
        assert_eq!(*order.lock().unwrap(), ["resolution"]);
        assert_eq!(target_metric_values(&egress_metrics), [0, 0, 0, 0]);

        let connect_metrics = target_metric_sinks();
        let connect_error = open_target_addr_before_deadline_with_metrics_using(
            deadline,
            &loopback_egress_policy(),
            &connect_metrics,
            || ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])),
            |_| ready(Err::<(), io::Error>(io::Error::other(PRIVATE_MARKER))),
        )
        .await
        .expect_err("synthetic connect failure must be typed");
        assert_eq!(
            connect_error.kind(),
            DirectV3TargetOpenFailureKind::ConnectFailure
        );
        assert_eq!(target_metric_values(&connect_metrics), [0, 0, 0, 1]);

        for error in [resolution_error, egress_error, connect_error] {
            assert!(!error.to_string().contains(PRIVATE_MARKER));
            assert!(!format!("{error:?}").contains(PRIVATE_MARKER));
            assert!(StdError::source(&error).is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn direct_v3_synthetic_success_returns_neutral_sentinel_before_deadline() {
        let metrics = target_metric_sinks();
        let sentinel = open_target_addr_before_deadline_with_metrics_using(
            (Instant::now() + Duration::from_secs(10)).into_std(),
            &loopback_egress_policy(),
            &metrics,
            || ready(Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))])),
            |_| ready(Ok::<_, io::Error>(7_u8)),
        )
        .await
        .expect("synthetic success before the deadline must return its sentinel");

        assert_eq!(sentinel, 7);
        assert_eq!(target_metric_values(&metrics), [0, 0, 0, 0]);
        assert_eq!(metrics.resolution_latency.snapshot().count, 1);
        assert_eq!(metrics.connect_latency.snapshot().count, 1);
    }

    #[test]
    fn direct_v3_typed_errors_have_fixed_value_free_text_and_no_source() {
        let cases = [
            (
                DirectV3TargetOpenFailureKind::ResolutionTimeout,
                "direct-v3 target resolution timed out",
            ),
            (
                DirectV3TargetOpenFailureKind::ResolutionFailure,
                "direct-v3 target resolution failed",
            ),
            (
                DirectV3TargetOpenFailureKind::EgressPolicyRejected,
                "direct-v3 egress policy rejected target",
            ),
            (
                DirectV3TargetOpenFailureKind::ConnectTimeout,
                "direct-v3 target connect timed out",
            ),
            (
                DirectV3TargetOpenFailureKind::ConnectFailure,
                "direct-v3 target connect failed",
            ),
        ];
        for (kind, display) in cases {
            let error = DirectV3TargetOpenError::new(kind);
            assert_eq!(error.to_string(), display);
            assert_eq!(format!("{error:?}"), "direct-v3 target-open error");
            assert!(StdError::source(&error).is_none());
            assert!(error.to_string().len() <= 40);
        }
    }

    #[test]
    fn direct_v3_production_source_has_one_endpoint_call_and_no_system_resolver() {
        let opener = ["open_target_addr_before_deadline", "_with_metrics"].concat();
        let endpoint = include_str!("quiche_endpoint.rs");
        let endpoint_production = endpoint
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("endpoint production source");
        assert_eq!(endpoint_production.matches(&opener).count(), 1);

        let runtime = include_str!("quiche_runtime.rs");
        let runtime_production = runtime
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("runtime production source");
        assert!(!runtime_production.contains(&opener));

        let relay = include_str!("relay.rs");
        let direct_opener = relay
            .split("pub(crate) async fn open_target_addr_before_deadline_with_metrics(")
            .nth(1)
            .expect("direct-v3 production opener source")
            .split("async fn open_target_addr_before_deadline_with_metrics_using<")
            .next()
            .expect("direct-v3 production opener body");
        for forbidden in [
            "lookup_host",
            "to_authority",
            "spawn_blocking",
            "getaddrinfo",
        ] {
            assert!(!direct_opener.contains(forbidden));
        }
        for required in [
            "TargetAddr::Domain(_)",
            "TargetAddr::Ipv4(addr)",
            "TargetAddr::Ipv6(addr)",
            "move || ready(resolved)",
        ] {
            assert!(direct_opener.contains(required));
        }
        assert!(relay.contains("lookup_host(authority)"));
    }

    #[tokio::test]
    async fn target_connect_failure_increments_only_its_counter() {
        let failure = connect_with_timeout(
            ready(Err::<(), io::Error>(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "synthetic connector failure",
            ))),
            Duration::from_secs(1),
        )
        .await
        .expect_err("connector error must fail");
        assert_eq!(failure.kind, TargetOpenFailureKind::ConnectFailure);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 0, 0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn dual_stack_connect_starts_other_family_after_race_delay() {
        let first: SocketAddr = "[::1]:41001".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let mut connected = Box::pin(connect_target_addresses(
            vec![first, second],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let attempts = Arc::clone(&recorded_attempts);
                async move {
                    attempts.lock().unwrap().push(addr);
                    if addr == first {
                        pending::<io::Result<SocketAddr>>().await
                    } else {
                        Ok(addr)
                    }
                }
            },
        ));

        assert!(poll!(connected.as_mut()).is_pending());
        assert_eq!(*attempts.lock().unwrap(), vec![first]);

        advance(TARGET_CONNECT_RACE_DELAY - Duration::from_millis(1)).await;
        assert!(poll!(connected.as_mut()).is_pending());
        assert_eq!(*attempts.lock().unwrap(), vec![first]);

        advance(Duration::from_millis(1)).await;
        assert_eq!(connected.await.unwrap(), second);
        assert_eq!(*attempts.lock().unwrap(), vec![first, second]);
    }

    #[tokio::test(start_paused = true)]
    async fn same_family_connects_remain_sequential() {
        let first: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41004".parse().unwrap();
        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let mut connected = Box::pin(connect_target_addresses(
            vec![first, second],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let attempts = Arc::clone(&recorded_attempts);
                async move {
                    attempts.lock().unwrap().push(addr);
                    if addr == first {
                        pending::<io::Result<SocketAddr>>().await
                    } else {
                        Ok(addr)
                    }
                }
            },
        ));

        assert!(poll!(connected.as_mut()).is_pending());
        advance(TARGET_CONNECT_RACE_DELAY * 4).await;
        assert!(poll!(connected.as_mut()).is_pending());
        assert_eq!(*attempts.lock().unwrap(), vec![first]);
    }

    #[tokio::test]
    async fn same_family_failures_preserve_resolver_order_and_last_error() {
        let first: SocketAddr = "127.0.0.1:41023".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41024".parse().unwrap();
        let last: SocketAddr = "127.0.0.1:41025".parse().unwrap();
        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);

        let error = connect_target_addresses(
            vec![first, second, last],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let attempts = Arc::clone(&recorded_attempts);
                async move {
                    attempts.lock().unwrap().push(addr);
                    Err::<SocketAddr, _>(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("synthetic failure for {}", addr.port()),
                    ))
                }
            },
        )
        .await
        .expect_err("all failed same-family connections must fail");

        assert_eq!(*attempts.lock().unwrap(), vec![first, second, last]);
        assert_eq!(
            error.to_string(),
            format!("synthetic failure for {}", last.port())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_preferred_family_starts_alternate_immediately() {
        let first: SocketAddr = "[::1]:41005".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41006".parse().unwrap();
        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);

        let connected = connect_target_addresses(
            vec![first, second],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let attempts = Arc::clone(&recorded_attempts);
                async move {
                    attempts.lock().unwrap().push(addr);
                    if addr == first {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "synthetic preferred-family failure",
                        ))
                    } else {
                        Ok(addr)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(connected, second);
        assert_eq!(*attempts.lock().unwrap(), vec![first, second]);
    }

    #[tokio::test(start_paused = true)]
    async fn dual_stack_connect_never_starts_more_than_two_attempts() {
        let first: SocketAddr = "[::1]:41007".parse().unwrap();
        let second_first_family: SocketAddr = "[::1]:41008".parse().unwrap();
        let first_other_family: SocketAddr = "127.0.0.1:41009".parse().unwrap();
        let second_other_family: SocketAddr = "127.0.0.1:41010".parse().unwrap();
        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let mut connected = Box::pin(connect_target_addresses(
            vec![
                first,
                second_first_family,
                first_other_family,
                second_other_family,
            ],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let attempts = Arc::clone(&recorded_attempts);
                async move {
                    attempts.lock().unwrap().push(addr);
                    pending::<io::Result<SocketAddr>>().await
                }
            },
        ));

        assert!(poll!(connected.as_mut()).is_pending());
        advance(TARGET_CONNECT_RACE_DELAY).await;
        assert!(poll!(connected.as_mut()).is_pending());
        assert_eq!(*attempts.lock().unwrap(), vec![first, first_other_family]);

        advance(TARGET_CONNECT_RACE_DELAY * 10).await;
        assert!(poll!(connected.as_mut()).is_pending());
        assert_eq!(attempts.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn dual_stack_winner_cancels_pending_attempt() {
        let first: SocketAddr = "[::1]:41011".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41012".parse().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let dropped_attempts = Arc::clone(&dropped);
        let mut connected = Box::pin(connect_target_addresses(
            vec![first, second],
            TARGET_CONNECT_RACE_DELAY,
            move |addr| {
                let dropped = Arc::clone(&dropped_attempts);
                async move {
                    if addr == first {
                        let _drop_counter = DropCounter(dropped);
                        pending::<io::Result<SocketAddr>>().await
                    } else {
                        Ok(addr)
                    }
                }
            },
        ));

        assert!(poll!(connected.as_mut()).is_pending());
        advance(TARGET_CONNECT_RACE_DELAY).await;
        assert_eq!(connected.await.unwrap(), second);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dual_stack_all_failures_return_last_resolver_error() {
        let first: SocketAddr = "[::1]:41013".parse().unwrap();
        let second_first_family: SocketAddr = "[::1]:41014".parse().unwrap();
        let last_in_resolver_order: SocketAddr = "127.0.0.1:41015".parse().unwrap();

        let error = connect_target_addresses(
            vec![first, second_first_family, last_in_resolver_order],
            TARGET_CONNECT_RACE_DELAY,
            |addr| async move {
                Err::<SocketAddr, _>(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("synthetic failure for {}", addr.port()),
                ))
            },
        )
        .await
        .expect_err("all failed target connections must fail");

        assert_eq!(
            error.to_string(),
            format!("synthetic failure for {}", last_in_resolver_order.port())
        );
    }

    #[tokio::test]
    async fn dual_stack_all_failures_record_one_request_level_failure() {
        let first: SocketAddr = "[::1]:41016".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41017".parse().unwrap();
        let failure = connect_with_timeout(
            connect_target_addresses(vec![first, second], TARGET_CONNECT_RACE_DELAY, |_| {
                ready(Err::<SocketAddr, _>(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "synthetic target connection failure",
                )))
            }),
            Duration::from_secs(1),
        )
        .await
        .expect_err("failed target connections must fail");
        assert_eq!(failure.kind, TargetOpenFailureKind::ConnectFailure);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 0, 0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn dual_stack_deadline_records_one_request_level_timeout() {
        let first: SocketAddr = "[::1]:41018".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:41019".parse().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let dropped_attempts = Arc::clone(&dropped);
        let failure = connect_with_timeout(
            connect_target_addresses(vec![first, second], TARGET_CONNECT_RACE_DELAY, move |_| {
                let dropped = Arc::clone(&dropped_attempts);
                async move {
                    let _drop_counter = DropCounter(dropped);
                    pending::<io::Result<SocketAddr>>().await
                }
            }),
            TARGET_CONNECT_RACE_DELAY + Duration::from_millis(1),
        )
        .await
        .expect_err("pending target connections must time out");
        assert_eq!(failure.kind, TargetOpenFailureKind::ConnectTimeout);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 0, 1, 0]);
    }

    #[tokio::test]
    async fn egress_filter_runs_before_dual_stack_connect_attempts() {
        let blocked: SocketAddr = "10.0.0.1:41020".parse().unwrap();
        let first_allowed: SocketAddr = "[::1]:41021".parse().unwrap();
        let second_allowed: SocketAddr = "127.0.0.1:41022".parse().unwrap();
        let allowed = resolve_allowed_addresses(
            ready(Ok(vec![blocked, first_allowed, second_allowed])),
            Duration::from_secs(1),
            &loopback_egress_policy(),
        )
        .await
        .expect("loopback targets should remain allowed");
        assert_eq!(allowed, vec![first_allowed, second_allowed]);

        let attempts = Arc::new(StdMutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let connected = connect_target_addresses(allowed, TARGET_CONNECT_RACE_DELAY, move |addr| {
            let attempts = Arc::clone(&recorded_attempts);
            async move {
                attempts.lock().unwrap().push(addr);
                if addr == first_allowed {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "synthetic first-family failure",
                    ))
                } else {
                    Ok(addr)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(connected, second_allowed);
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![first_allowed, second_allowed]
        );
    }

    #[tokio::test]
    async fn egress_policy_rejection_does_not_increment_failure_counters() {
        let loopback: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let failure = resolve_allowed_addresses(
            ready(Ok(vec![loopback])),
            Duration::from_secs(1),
            &ServerEgressPolicyConfig::default(),
        )
        .await
        .expect_err("default policy must reject loopback");
        assert_eq!(failure.kind, TargetOpenFailureKind::EgressPolicyRejected);

        let metrics = target_metric_sinks();
        metrics.record(failure.kind);
        assert_eq!(target_metric_values(&metrics), [0, 0, 0, 0]);
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
    async fn t025a1_connected_udp_owner_reuses_source_and_receives_arrival_order() -> Result<()> {
        const PACKET_A: &[u8] = b"owner-packet-a";
        const PACKET_B: &[u8] = b"owner-packet-b";
        const FORGED_REPLY: &[u8] = b"foreign-forged-reply";
        const TARGET_REPLY_B: &[u8] = b"target-reply-b";
        const TARGET_REPLY_A: &[u8] = b"target-reply-a";

        timeout(Duration::from_secs(4), async {
            let target_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let target_addr = target_socket.local_addr()?;
            let policy = ServerEgressPolicyConfig {
                allow_loopback: true,
                ..ServerEgressPolicyConfig::default()
            };
            let owner = ConnectedUdpTarget::open(
                &TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target_addr.port(),
                1_000,
                &policy,
            )
            .await?;

            owner.send(PACKET_A).await?;
            owner.send(PACKET_B).await?;

            let mut first_packet = [0u8; 64];
            let (first_len, first_source) = timeout(
                Duration::from_secs(1),
                target_socket.recv_from(&mut first_packet),
            )
            .await
            .expect("target must receive owner packet A within the bound")?;
            assert_eq!(&first_packet[..first_len], PACKET_A);

            let mut second_packet = [0u8; 64];
            let (second_len, second_source) = timeout(
                Duration::from_secs(1),
                target_socket.recv_from(&mut second_packet),
            )
            .await
            .expect("target must receive owner packet B within the bound")?;
            assert_eq!(&second_packet[..second_len], PACKET_B);
            assert_eq!(
                first_source, second_source,
                "one connected UDP target owner must reuse its source address"
            );

            let foreign_socket =
                UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            assert_eq!(
                foreign_socket.send_to(FORGED_REPLY, first_source).await?,
                FORGED_REPLY.len()
            );
            assert_eq!(
                target_socket.send_to(TARGET_REPLY_B, first_source).await?,
                TARGET_REPLY_B.len()
            );
            assert_eq!(
                target_socket.send_to(TARGET_REPLY_A, first_source).await?,
                TARGET_REPLY_A.len()
            );

            let mut first_reply = [0u8; 64];
            let first_reply_len = timeout(Duration::from_secs(1), owner.recv(&mut first_reply))
                .await
                .expect("owner must receive target reply B within the bound")?;
            assert_eq!(&first_reply[..first_reply_len], TARGET_REPLY_B);

            let mut second_reply = [0u8; 64];
            let second_reply_len = timeout(Duration::from_secs(1), owner.recv(&mut second_reply))
                .await
                .expect("owner must receive target reply A within the bound")?;
            assert_eq!(&second_reply[..second_reply_len], TARGET_REPLY_A);

            let source_bind_error = match UdpSocket::bind(first_source).await {
                Ok(socket) => {
                    drop(socket);
                    panic!("the live UDP target owner must retain its source address");
                }
                Err(error) => error,
            };
            assert_eq!(source_bind_error.kind(), io::ErrorKind::AddrInUse);

            drop(owner);
            let rebound_source = UdpSocket::bind(first_source).await?;
            assert_eq!(rebound_source.local_addr()?, first_source);
            drop(rebound_source);

            drop(target_socket);
            let rebound_target = UdpSocket::bind(target_addr).await?;
            assert_eq!(rebound_target.local_addr()?, target_addr);
            Ok::<(), anyhow::Error>(())
        })
        .await
        .expect("connected UDP owner loopback I/O must remain bounded")?;

        Ok(())
    }

    #[tokio::test]
    async fn t024a1_udp_flow_relay_switches_target_after_releasing_old_owner() -> Result<()> {
        timeout(Duration::from_secs(4), async {
            let target_a = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let target_b = match UdpSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).await {
                Ok(socket) => socket,
                Err(err) if err.kind() == io::ErrorKind::AddrNotAvailable => return Ok(()),
                Err(err) => return Err(err.into()),
            };
            let target_a_addr = target_a.local_addr()?;
            let target_b_addr = target_b.local_addr()?;
            let policy = ServerEgressPolicyConfig {
                allow_loopback: true,
                ..ServerEgressPolicyConfig::default()
            };
            let mut flow = UdpFlowRelay::new();

            let packet_a = UdpPacketPayload::new(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target_a_addr.port(),
                Bytes::from_static(b"switch-a"),
            );
            let (response_a, source_a) = {
                let relay = flow.relay_packet(&packet_a, 1_000, &policy);
                let target_roundtrip = async {
                    let mut buf = [0u8; 64];
                    let (len, source) = target_a.recv_from(&mut buf).await?;
                    assert_eq!(&buf[..len], b"switch-a");
                    target_a.send_to(b"reply-a", source).await?;
                    Result::<SocketAddr>::Ok(source)
                };
                let (response, source) = tokio::join!(relay, target_roundtrip);
                (response?, source?)
            };
            assert_eq!(response_a.data, Bytes::from_static(b"reply-a"));

            let packet_b = UdpPacketPayload::new(
                TargetAddr::Ipv6(Ipv6Addr::LOCALHOST),
                target_b_addr.port(),
                Bytes::from_static(b"switch-b"),
            );
            let (response_b, source_b) = {
                let relay = flow.relay_packet(&packet_b, 1_000, &policy);
                let target_roundtrip = async {
                    let mut buf = [0u8; 64];
                    let (len, source) = target_b.recv_from(&mut buf).await?;
                    assert_eq!(&buf[..len], b"switch-b");
                    target_b.send_to(b"reply-b", source).await?;
                    Result::<SocketAddr>::Ok(source)
                };
                let (response, source) = tokio::join!(relay, target_roundtrip);
                (response?, source?)
            };
            assert_eq!(response_b.data, Bytes::from_static(b"reply-b"));
            assert!(source_a.is_ipv4());
            assert!(source_b.is_ipv6());
            let active = flow
                .active
                .as_ref()
                .expect("switched target must remain active");
            assert_eq!(active.target, TargetAddr::Ipv6(Ipv6Addr::LOCALHOST));
            assert_eq!(active.port, target_b_addr.port());

            let rebound_a = UdpSocket::bind(source_a).await?;
            assert_eq!(rebound_a.local_addr()?, source_a);
            let source_b_error = match UdpSocket::bind(source_b).await {
                Ok(socket) => {
                    drop(socket);
                    panic!("switched UDP target owner must retain its new source address");
                }
                Err(error) => error,
            };
            assert_eq!(source_b_error.kind(), io::ErrorKind::AddrInUse);

            drop(flow);
            let rebound_b = UdpSocket::bind(source_b).await?;
            assert_eq!(rebound_b.local_addr()?, source_b);
            Ok::<(), anyhow::Error>(())
        })
        .await
        .expect("UDP target switch loopback I/O must remain bounded")?;

        Ok(())
    }

    #[tokio::test]
    async fn t024a1_udp_flow_relay_timeout_clears_owner_and_releases_source() -> Result<()> {
        timeout(Duration::from_secs(4), async {
            let target = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let target_addr = target.local_addr()?;
            let policy = ServerEgressPolicyConfig {
                allow_loopback: true,
                ..ServerEgressPolicyConfig::default()
            };
            let mut flow = UdpFlowRelay::new();
            let stale_packet = UdpPacketPayload::new(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target_addr.port(),
                Bytes::from_static(b"stale-request"),
            );

            let (stale_result, stale_source) = {
                let relay = flow.relay_packet(&stale_packet, 250, &policy);
                let target_receive = async {
                    let mut buf = [0u8; 64];
                    let (len, source) = target.recv_from(&mut buf).await?;
                    assert_eq!(&buf[..len], b"stale-request");
                    Result::<SocketAddr>::Ok(source)
                };
                let (result, source) = tokio::join!(relay, target_receive);
                (result, source?)
            };
            let stale_error = stale_result.expect_err("silent target must time out");
            assert!(stale_error.to_string().contains("UDP target timed out"));
            assert!(flow.active.is_none(), "receive timeout must clear the slot");

            let rebound_source = UdpSocket::bind(stale_source).await?;
            assert_eq!(rebound_source.local_addr()?, stale_source);
            Ok::<(), anyhow::Error>(())
        })
        .await
        .expect("UDP timeout owner clearing loopback I/O must remain bounded")?;

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
                        test_relay_policy(),
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
        let (response, mut body) = client.send_request(request, false)?;
        let mut response_body = response.await?.into_body();
        body.send_data(
            encode_grpc_frame(Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()), 65_536)?,
            true,
        )?;

        timeout(Duration::from_secs(1), relay_completed_rx)
            .await
            .expect("relay task should exit after idle timeout")??;
        let response_end = timeout(Duration::from_secs(1), response_body.data())
            .await
            .expect("timed-out relay response should reset promptly");
        assert!(
            matches!(response_end, Some(Err(_))),
            "relay timeout must reset instead of sending grpc-status: 0"
        );
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
        assert!(error.downcast_ref::<H2SendStall>().is_some());
        assert!(error
            .to_string()
            .contains("h2 send stalled while waiting for receiver capacity"));
        let metrics = crate::runtime_metrics::ServerRuntimeMetrics::default();
        metrics.record_h2_request_error(&error);
        assert!(metrics.json_snapshot().contains("\"h2_send_stalls\":1"));
        assert!(metrics.json_snapshot().contains("\"h2_stream_resets\":0"));
        Ok(())
    }

    #[tokio::test]
    async fn h2_bulk_relay_zero_window_records_one_send_stall() -> Result<()> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = TcpStream::connect(target_listener.local_addr()?).await?;
        let (mut target_peer, _) = target_listener.accept().await?;
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
                            idle_timeout: Duration::from_millis(25),
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
        builder.initial_window_size(0);
        let (client, connection) = builder.handshake::<_, Bytes>(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, _request_body) = client.send_request(request, false)?;
        let _response_body = response.await?.into_body();

        target_peer.write_all(b"blocked bulk response").await?;
        let relay_error = timeout(Duration::from_secs(1), relay_completed_rx)
            .await
            .expect("zero-window bulk relay must remain bounded")
            .expect("relay task must report its result")
            .expect_err("zero-window bulk relay must report a send stall");
        assert!(relay_error.downcast_ref::<H2SendStall>().is_some());

        let metrics = crate::runtime_metrics::ServerRuntimeMetrics::default();
        metrics.record_h2_request_error(&relay_error);
        let snapshot = metrics.json_snapshot();
        assert!(snapshot.contains("\"h2_send_stalls\":1"));
        assert!(snapshot.contains("\"h2_stream_resets\":0"));
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
        assert_grpc_ok_trailers(&mut response_body).await?;

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
        let (response, mut request_body) = client.send_request(request, false)?;
        let mut response_body = response.await?.into_body();
        request_body.send_data(
            encode_grpc_frame(Frame::new(FrameType::TcpReset, 0, 1, Bytes::new()), 65_536)?,
            true,
        )?;

        timeout(Duration::from_secs(1), relay_completed_rx)
            .await
            .expect("TCP reset must release the relay promptly")??;
        let response_end = timeout(Duration::from_secs(1), response_body.data())
            .await
            .expect("TCP reset response should end promptly");
        assert!(
            matches!(response_end, Some(Err(_))),
            "TCP reset must remain RST_STREAM instead of grpc-status: 0"
        );
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
        let relay_error =
            relay_result.expect_err("an H2 request reset should terminate the relay with an error");
        let metrics = crate::runtime_metrics::ServerRuntimeMetrics::default();
        metrics.record_h2_request_error(&relay_error);
        assert!(metrics.json_snapshot().contains("\"h2_stream_resets\":1"));
        assert!(metrics.json_snapshot().contains("\"h2_send_stalls\":0"));
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
        assert_grpc_ok_trailers(&mut response_body).await?;

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
