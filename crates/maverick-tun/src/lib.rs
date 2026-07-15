//! Experimental unprivileged packet runtime for Maverick.
//!
//! This crate accepts packet I/O that has already been opened by a caller. It
//! has no API for creating interfaces or changing routes, DNS, firewalls, or
//! host networking.

#![forbid(unsafe_code)]

mod device;
mod runtime;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub use runtime::{start_packet_runtime, PacketRuntimeHandle};

pub const ENGINE_NAME: &str = "smoltcp";
pub const ENGINE_VERSION: &str = "0.13.1";

const ENGINE_ASSEMBLER_MAX_SEGMENTS: usize = 4;
const ENGINE_FRAGMENTATION_BUFFER_BYTES: usize = 1500;
const ENGINE_REASSEMBLY_BUFFER_COUNT: usize = 1;
const ENGINE_REASSEMBLY_BUFFER_BYTES: usize = 1500;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRead {
    Packet(usize),
    Eof,
}

pub trait PacketReader: Send + 'static {
    fn receive<'a>(&'a mut self, buffer: &'a mut [u8]) -> BoxFuture<'a, io::Result<PacketRead>>;
}

pub trait PacketWriter: Send + 'static {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
}

pub struct PacketIo {
    reader: Box<dyn PacketReader>,
    writer: Box<dyn PacketWriter>,
}

impl PacketIo {
    pub fn new<R, W>(reader: R, writer: W) -> Self
    where
        R: PacketReader,
        W: PacketWriter,
    {
        Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    pub(crate) fn into_parts(self) -> (Box<dyn PacketReader>, Box<dyn PacketWriter>) {
        (self.reader, self.writer)
    }
}

pub trait AsyncDuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncDuplexStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxTcpFlow = Box<dyn AsyncDuplexStream>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowErrorKind {
    AdmissionRejected,
    RemoteConnection,
    DnsExchange,
    DatagramExchange,
    TimedOut,
    Cancelled,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("packet flow operation failed: {kind}")]
pub struct FlowError {
    pub kind: FlowErrorKind,
}

impl FlowError {
    pub const fn new(kind: FlowErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for FlowErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AdmissionRejected => "admission rejected",
            Self::RemoteConnection => "remote connection failed",
            Self::DnsExchange => "DNS exchange failed",
            Self::DatagramExchange => "datagram exchange failed",
            Self::TimedOut => "operation timed out",
            Self::Cancelled => "operation cancelled",
            Self::Closed => "flow closed",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub endpoint: SocketAddr,
    pub payload: Bytes,
}

impl Datagram {
    pub fn new(endpoint: SocketAddr, payload: Bytes) -> Self {
        Self { endpoint, payload }
    }
}

pub trait DatagramFlow: Send {
    fn exchange<'a>(
        &'a mut self,
        datagram: Datagram,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Datagram, FlowError>>;

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<(), FlowError>>;
}

pub trait FlowConnector: Send + Sync + 'static {
    fn snapshot(&self) -> FlowConnectorSnapshot;

    fn open_tcp<'a>(
        &'a self,
        target: SocketAddr,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<BoxTcpFlow, FlowError>>;

    fn exchange_dns<'a>(
        &'a self,
        query: Bytes,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Bytes, FlowError>>;

    fn open_udp<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn DatagramFlow>, FlowError>>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowConnectorSnapshot {
    pub active_tasks: usize,
    pub peak_tasks: usize,
    pub buffered_bytes: usize,
    pub peak_buffered_bytes: usize,
    pub buffer_capacity_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsInterception {
    Disabled,
    Port53,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketRuntimeConfig {
    pub mtu: usize,
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub dns_interception: DnsInterception,
    pub max_tcp_flows: usize,
    pub max_udp_targets: usize,
    pub max_udp_associations: usize,
    pub max_dns_queries: usize,
    pub packet_queue_depth: usize,
    pub event_queue_depth: usize,
    pub tcp_buffer_bytes: usize,
    pub tcp_channel_depth: usize,
    pub udp_buffer_bytes: usize,
    pub udp_message_depth: usize,
    pub udp_channel_depth: usize,
    pub max_udp_payload_bytes: usize,
    pub max_dns_payload_bytes: usize,
    pub connect_timeout: Duration,
    pub tcp_idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub dns_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for PacketRuntimeConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            ipv4_enabled: true,
            ipv6_enabled: true,
            dns_interception: DnsInterception::Port53,
            max_tcp_flows: 128,
            max_udp_targets: 64,
            max_udp_associations: 64,
            max_dns_queries: 32,
            packet_queue_depth: 64,
            event_queue_depth: 256,
            tcp_buffer_bytes: 64 * 1024,
            tcp_channel_depth: 2,
            udp_buffer_bytes: 64 * 1024,
            udp_message_depth: 32,
            udp_channel_depth: 8,
            max_udp_payload_bytes: 1452,
            max_dns_payload_bytes: 1232,
            connect_timeout: Duration::from_secs(10),
            tcp_idle_timeout: Duration::from_secs(300),
            udp_idle_timeout: Duration::from_secs(60),
            dns_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(5),
        }
    }
}

impl PacketRuntimeConfig {
    pub fn validate(&self) -> Result<(), PacketRuntimeError> {
        validate_engine_build()?;
        if !self.ipv4_enabled && !self.ipv6_enabled {
            return Err(PacketRuntimeError::InvalidConfig(
                "at least one IP family must be enabled",
            ));
        }
        let minimum_mtu = if self.ipv6_enabled { 1280 } else { 576 };
        if !(minimum_mtu..=65_535).contains(&self.mtu) {
            return Err(PacketRuntimeError::InvalidConfig(
                "MTU is outside the enabled IP-family range",
            ));
        }
        validate_limit("max_tcp_flows", self.max_tcp_flows, 4096)?;
        validate_limit("max_udp_targets", self.max_udp_targets, 4096)?;
        validate_limit("max_udp_associations", self.max_udp_associations, 4096)?;
        validate_limit("max_dns_queries", self.max_dns_queries, 4096)?;
        validate_limit("packet_queue_depth", self.packet_queue_depth, 4096)?;
        validate_limit("event_queue_depth", self.event_queue_depth, 16_384)?;
        validate_limit("tcp_channel_depth", self.tcp_channel_depth, 64)?;
        validate_limit("udp_message_depth", self.udp_message_depth, 1024)?;
        validate_limit("udp_channel_depth", self.udp_channel_depth, 1024)?;

        if !(self.mtu..=4 * 1024 * 1024).contains(&self.tcp_buffer_bytes) {
            return Err(PacketRuntimeError::InvalidConfig(
                "TCP buffer size must be at least the MTU and at most 4 MiB",
            ));
        }
        if !(self.mtu..=4 * 1024 * 1024).contains(&self.udp_buffer_bytes) {
            return Err(PacketRuntimeError::InvalidConfig(
                "UDP buffer size must be at least the MTU and at most 4 MiB",
            ));
        }
        let max_unfragmented_udp = self.mtu.saturating_sub(48);
        if self.max_udp_payload_bytes == 0
            || self.max_udp_payload_bytes > max_unfragmented_udp
            || self.max_udp_payload_bytes > self.udp_buffer_bytes
        {
            return Err(PacketRuntimeError::InvalidConfig(
                "maximum UDP payload exceeds the unfragmented packet budget",
            ));
        }
        if self.max_dns_payload_bytes == 0
            || self.max_dns_payload_bytes > self.max_udp_payload_bytes
        {
            return Err(PacketRuntimeError::InvalidConfig(
                "maximum DNS payload exceeds the UDP payload limit",
            ));
        }
        for (name, value) in [
            ("connect_timeout", self.connect_timeout),
            ("tcp_idle_timeout", self.tcp_idle_timeout),
            ("udp_idle_timeout", self.udp_idle_timeout),
            ("dns_timeout", self.dns_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
            ("poll_interval", self.poll_interval),
        ] {
            if value.is_zero() || value > Duration::from_secs(24 * 60 * 60) {
                return Err(PacketRuntimeError::InvalidConfig(match name {
                    "connect_timeout" => "connect timeout must be between zero and 24 hours",
                    "tcp_idle_timeout" => "TCP idle timeout must be between zero and 24 hours",
                    "udp_idle_timeout" => "UDP idle timeout must be between zero and 24 hours",
                    "dns_timeout" => "DNS timeout must be between zero and 24 hours",
                    "shutdown_timeout" => "shutdown timeout must be between zero and 24 hours",
                    _ => "poll interval must be between zero and 24 hours",
                }));
            }
        }
        if self.poll_interval > Duration::from_secs(1) {
            return Err(PacketRuntimeError::InvalidConfig(
                "poll interval must not exceed one second",
            ));
        }
        if self.buffer_capacity_bytes()? > 256 * 1024 * 1024 {
            return Err(PacketRuntimeError::InvalidConfig(
                "configured packet runtime buffer capacity exceeds 256 MiB",
            ));
        }
        Ok(())
    }

    pub fn buffer_capacity_bytes(&self) -> Result<usize, PacketRuntimeError> {
        const TCP_WORK_CHUNK: usize = 16 * 1024;
        let engine_fragmentation = ENGINE_REASSEMBLY_BUFFER_COUNT
            .checked_mul(ENGINE_REASSEMBLY_BUFFER_BYTES)
            .and_then(|value| value.checked_add(ENGINE_FRAGMENTATION_BUFFER_BYTES));
        let packet_queues = self
            .packet_queue_depth
            .checked_mul(4)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_mul(self.mtu));
        let tcp = self
            .max_tcp_flows
            .checked_mul(self.tcp_buffer_bytes)
            .and_then(|value| value.checked_mul(2));
        let udp = self
            .max_udp_targets
            .checked_mul(self.udp_buffer_bytes)
            .and_then(|value| value.checked_mul(2));
        let tcp_work = self
            .max_tcp_flows
            .checked_mul(self.tcp_channel_depth.saturating_add(2))
            .and_then(|value| value.checked_mul(TCP_WORK_CHUNK));
        let udp_work = self
            .max_udp_associations
            .checked_mul(self.udp_channel_depth.saturating_add(1))
            .and_then(|value| value.checked_mul(self.max_udp_payload_bytes));
        let dns_work = self
            .max_dns_queries
            .checked_mul(self.max_dns_payload_bytes)
            .and_then(|value| value.checked_mul(2));
        let event_work = self
            .event_queue_depth
            .checked_mul(TCP_WORK_CHUNK.max(self.max_udp_payload_bytes));
        engine_fragmentation
            .and_then(|fragmentation| {
                packet_queues.and_then(|value| value.checked_add(fragmentation))
            })
            .and_then(|value| tcp.and_then(|tcp| value.checked_add(tcp)))
            .and_then(|value| udp.and_then(|udp| value.checked_add(udp)))
            .and_then(|value| tcp_work.and_then(|work| value.checked_add(work)))
            .and_then(|value| udp_work.and_then(|work| value.checked_add(work)))
            .and_then(|value| dns_work.and_then(|work| value.checked_add(work)))
            .and_then(|value| event_work.and_then(|work| value.checked_add(work)))
            .ok_or(PacketRuntimeError::InvalidConfig(
                "configured packet runtime buffer capacity overflowed",
            ))
    }
}

fn validate_engine_build() -> Result<(), PacketRuntimeError> {
    if smoltcp::config::ASSEMBLER_MAX_SEGMENT_COUNT != ENGINE_ASSEMBLER_MAX_SEGMENTS
        || smoltcp::config::FRAGMENTATION_BUFFER_SIZE != ENGINE_FRAGMENTATION_BUFFER_BYTES
        || smoltcp::config::REASSEMBLY_BUFFER_COUNT != ENGINE_REASSEMBLY_BUFFER_COUNT
        || smoltcp::config::REASSEMBLY_BUFFER_SIZE != ENGINE_REASSEMBLY_BUFFER_BYTES
    {
        return Err(PacketRuntimeError::InvalidConfig(
            "smoltcp build-time buffer configuration drifted",
        ));
    }
    Ok(())
}

fn validate_limit(
    _name: &'static str,
    value: usize,
    maximum: usize,
) -> Result<(), PacketRuntimeError> {
    if value == 0 || value > maximum {
        return Err(PacketRuntimeError::InvalidConfig(
            "configured resource limit is zero or exceeds its hard maximum",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRuntimeState {
    Created,
    Running,
    Draining,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRuntimeFailure {
    PacketRead,
    PacketWrite,
    Engine,
    Task,
    ShutdownTimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketRuntimeSnapshot {
    pub engine_name: &'static str,
    pub engine_version: &'static str,
    pub state: PacketRuntimeState,
    pub last_failure: Option<PacketRuntimeFailure>,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_rejected: u64,
    pub malformed_packets: u64,
    pub unsupported_packets: u64,
    pub tcp_flows_opened: u64,
    pub tcp_flows_rejected: u64,
    pub tcp_flows_failed: u64,
    pub active_tcp_flows: usize,
    pub peak_tcp_flows: usize,
    pub udp_associations_opened: u64,
    pub udp_associations_failed: u64,
    pub udp_datagrams_dropped: u64,
    pub active_udp_associations: usize,
    pub peak_udp_associations: usize,
    pub dns_queries_started: u64,
    pub dns_queries_rejected: u64,
    pub dns_queries_failed: u64,
    pub active_dns_queries: usize,
    pub peak_dns_queries: usize,
    pub active_tasks: usize,
    pub peak_tasks: usize,
    pub ingress_queue_depth: usize,
    pub egress_queue_depth: usize,
    pub peak_ingress_queue_depth: usize,
    pub peak_egress_queue_depth: usize,
    pub buffered_bytes: usize,
    pub peak_buffered_bytes: usize,
    pub configured_buffer_capacity_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    pub already_stopped: bool,
    pub forced: bool,
    pub elapsed: Duration,
    pub final_snapshot: PacketRuntimeSnapshot,
}

#[derive(Debug, thiserror::Error)]
pub enum PacketRuntimeError {
    #[error("invalid packet runtime configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("packet runtime failed: {0:?}")]
    RuntimeFailed(PacketRuntimeFailure),
    #[error("packet runtime requires an active Tokio runtime")]
    RuntimeUnavailable,
}
