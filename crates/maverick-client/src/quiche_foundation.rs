//! Private, feature-gated direct-quiche foundation.
//!
//! `quiche` owns QUIC, TLS, and HTTP/3. This module only drives one UDP socket
//! and one connection with Tokio. It has no connection router or control queue,
//! and no quiche, BoringSSL, or TLS type leaves this private module.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::ssl::SslRef;
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Barrier, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

const MAX_UDP_PAYLOAD_BYTES: usize = 1_350;
const MAX_DATAGRAM_FRAME_BYTES: u64 = 65_536;
const SEND_CAPACITY_FACTOR: f64 = 1.0;
const CONNECTION_TASK_LIMIT: usize = 8;
const DATAGRAM_QUEUE_LIMIT: usize = 32;
const OBSERVATION_QUEUE_LIMIT: usize = 1;
const INITIAL_CONNECTION_WINDOW_BYTES: u64 = 1_048_576;
const INITIAL_BIDI_STREAM_WINDOW_BYTES: u64 = 65_536;
const INITIAL_UNI_STREAM_WINDOW_BYTES: u64 = 16_384;
const MAX_STREAM_WINDOW_BYTES: u64 = 65_536;
const MAX_BIDI_STREAMS: u64 = 8;
const MAX_UNI_STREAMS: u64 = 8;
const MAX_FIELD_SECTION_BYTES: u64 = 16_384;
const QPACK_MAX_TABLE_CAPACITY: u64 = 0;
const QPACK_BLOCKED_STREAMS: u64 = 0;
const MAX_PRIORITY_UPDATE_BYTES: u64 = 256;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const PATH_CHALLENGE_QUEUE_LIMIT: usize = 3;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_RUN_TIMEOUT: Duration = Duration::from_secs(10);

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

#[derive(Clone, Copy)]
enum EarlyDataPolicy {
    Disabled,
}

#[derive(Clone)]
struct ConnectionTaskBudget {
    permits: Arc<Semaphore>,
}

impl ConnectionTaskBudget {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(CONNECTION_TASK_LIMIT)),
        }
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, FoundationError> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| FoundationError::TaskBudgetUnavailable)
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NegotiatedGroup {
    X25519MlKem768,
    X25519,
    Secp256r1,
    Secp384r1,
    OtherOrUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerH3Settings {
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    extended_connect: bool,
    datagram: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerQuicLimits {
    max_idle_timeout_ms: u64,
    max_udp_payload_bytes: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    disable_active_migration: bool,
    active_connection_id_limit: u64,
    max_datagram_frame_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FoundationObservation {
    channel_binding: TlsChannelBinding,
    negotiated_group: NegotiatedGroup,
    alpn_h3: bool,
    early_data: bool,
    peer_quic: PeerQuicLimits,
    peer_h3: PeerH3Settings,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoundationError {
    AlpnMismatch,
    ConnectionUnavailable,
    DriverStopped,
    DriverTimeout,
    EarlyDataRejected,
    ExporterUnavailable,
    H3Unavailable,
    ObservationQueueUnavailable,
    PacketUnavailable,
    SocketUnavailable,
    TaskBudgetUnavailable,
}

impl fmt::Display for FoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlpnMismatch => "native H3 ALPN mismatch",
            Self::ConnectionUnavailable => "native H3 connection unavailable",
            Self::DriverStopped => "native H3 driver stopped",
            Self::DriverTimeout => "native H3 driver timeout",
            Self::EarlyDataRejected => "native H3 early data rejected",
            Self::ExporterUnavailable => "native H3 TLS exporter unavailable",
            Self::H3Unavailable => "native H3 connection unavailable",
            Self::ObservationQueueUnavailable => "native H3 observation queue unavailable",
            Self::PacketUnavailable => "native H3 packet unavailable",
            Self::SocketUnavailable => "native H3 socket unavailable",
            Self::TaskBudgetUnavailable => "native H3 task budget unavailable",
        })
    }
}

impl std::error::Error for FoundationError {}

struct FoundationDriver {
    socket: UdpSocket,
    local_address: SocketAddr,
    peer_address: SocketAddr,
    connection: quiche::Connection,
    h3_config: Option<quiche::h3::Config>,
    h3_connection: Option<quiche::h3::Connection>,
    tls_observation: Option<(TlsChannelBinding, NegotiatedGroup, PeerQuicLimits)>,
    observation_tx: mpsc::Sender<FoundationObservation>,
    ready_barrier: Arc<Barrier>,
    _task_permit: OwnedSemaphorePermit,
}

impl FoundationDriver {
    fn new(
        socket: UdpSocket,
        peer_address: SocketAddr,
        connection: quiche::Connection,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        task_permit: OwnedSemaphorePermit,
    ) -> Result<Self, FoundationError> {
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        if !local_address.ip().is_loopback() || !peer_address.ip().is_loopback() {
            return Err(FoundationError::SocketUnavailable);
        }

        Ok(Self {
            socket,
            local_address,
            peer_address,
            connection,
            h3_config: Some(bounded_h3_config()?),
            h3_connection: None,
            tls_observation: None,
            observation_tx,
            ready_barrier,
            _task_permit: task_permit,
        })
    }

    async fn run(mut self) -> Result<(), FoundationError> {
        match timeout(CONNECTION_RUN_TIMEOUT, self.run_inner()).await {
            Ok(result) => result,
            Err(_) => Err(FoundationError::DriverTimeout),
        }
    }

    async fn run_inner(&mut self) -> Result<(), FoundationError> {
        let handshake_started = Instant::now();
        let mut receive_buffer = [0_u8; MAX_UDP_PAYLOAD_BYTES];
        let mut send_buffer = [0_u8; MAX_UDP_PAYLOAD_BYTES];

        loop {
            self.initialize_h3()?;
            if self.process_h3()? {
                self.flush_packets(&mut send_buffer).await?;
                self.ready_barrier.wait().await;
                // Both peers have parsed SETTINGS. This immediate application
                // close proves bounded task cleanup, not a full graceful drain.
                self.connection
                    .close(true, 0, b"")
                    .map_err(|_| FoundationError::ConnectionUnavailable)?;
                self.flush_packets(&mut send_buffer).await?;
                return Ok(());
            }
            self.flush_packets(&mut send_buffer).await?;

            if self.connection.is_closed() {
                return Err(FoundationError::DriverStopped);
            }
            if !self.connection.is_established() && handshake_started.elapsed() >= HANDSHAKE_TIMEOUT
            {
                return Err(FoundationError::DriverTimeout);
            }

            let wait = self
                .connection
                .timeout()
                .unwrap_or(MAX_IDLE_TIMEOUT)
                .min(MAX_IDLE_TIMEOUT);
            match timeout(wait, self.socket.recv_from(&mut receive_buffer)).await {
                Ok(Ok((length, from))) => {
                    if from != self.peer_address {
                        return Err(FoundationError::PacketUnavailable);
                    }
                    let info = quiche::RecvInfo {
                        from,
                        to: self.local_address,
                    };
                    self.connection
                        .recv(&mut receive_buffer[..length], info)
                        .map_err(|_| FoundationError::PacketUnavailable)?;
                }
                Ok(Err(_)) => return Err(FoundationError::SocketUnavailable),
                Err(_) => self.connection.on_timeout(),
            }
        }
    }

    fn initialize_h3(&mut self) -> Result<(), FoundationError> {
        if !h3_initialization_ready(
            self.connection.is_established(),
            self.connection.is_in_early_data(),
        )? || self.h3_connection.is_some()
        {
            return Ok(());
        }

        if self.connection.application_proto() != b"h3" {
            return Err(FoundationError::AlpnMismatch);
        }

        let tls: &mut SslRef = self.connection.as_mut();
        let label = std::str::from_utf8(TLS_CHANNEL_BINDING_EXPORTER_LABEL)
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let mut output = [0_u8; 32];
        tls.export_keying_material(&mut output, label, None)
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let channel_binding = TlsChannelBinding::new(output);
        let negotiated_group = negotiated_group(tls.curve_name());
        let peer_quic = peer_quic_limits(
            self.connection
                .peer_transport_params()
                .ok_or(FoundationError::ConnectionUnavailable)?,
        );
        self.tls_observation = Some((channel_binding, negotiated_group, peer_quic));

        let h3_config = self
            .h3_config
            .take()
            .ok_or(FoundationError::H3Unavailable)?;
        self.h3_connection = Some(
            quiche::h3::Connection::with_transport(&mut self.connection, &h3_config)
                .map_err(|_| FoundationError::H3Unavailable)?,
        );
        Ok(())
    }

    fn process_h3(&mut self) -> Result<bool, FoundationError> {
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(false);
        };
        loop {
            match h3_connection.poll(&mut self.connection) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(_) => return Err(FoundationError::H3Unavailable),
            }
        }

        let Some(raw_settings) = h3_connection.peer_settings_raw() else {
            return Ok(false);
        };
        let peer_h3 = PeerH3Settings {
            max_field_section_size: peer_setting(raw_settings, SETTINGS_MAX_FIELD_SECTION_SIZE),
            qpack_max_table_capacity: peer_setting(raw_settings, SETTINGS_QPACK_MAX_TABLE_CAPACITY),
            qpack_blocked_streams: peer_setting(raw_settings, SETTINGS_QPACK_BLOCKED_STREAMS),
            extended_connect: h3_connection.extended_connect_enabled_by_peer(),
            datagram: h3_connection.dgram_enabled_by_peer(&self.connection),
        };
        if !peer_h3.extended_connect || !peer_h3.datagram {
            return Ok(false);
        }

        let (channel_binding, negotiated_group, peer_quic) = self
            .tls_observation
            .take()
            .ok_or(FoundationError::ExporterUnavailable)?;
        self.observation_tx
            .try_send(FoundationObservation {
                channel_binding,
                negotiated_group,
                alpn_h3: true,
                early_data: false,
                peer_quic,
                peer_h3,
            })
            .map_err(|_| FoundationError::ObservationQueueUnavailable)?;
        Ok(true)
    }

    async fn flush_packets(
        &mut self,
        send_buffer: &mut [u8; MAX_UDP_PAYLOAD_BYTES],
    ) -> Result<(), FoundationError> {
        loop {
            let (length, info) = match self.connection.send(send_buffer) {
                Ok(value) => value,
                Err(quiche::Error::Done) => return Ok(()),
                Err(_) => return Err(FoundationError::PacketUnavailable),
            };
            if info.from != self.local_address || info.to != self.peer_address {
                return Err(FoundationError::PacketUnavailable);
            }
            let sent = self
                .socket
                .send_to(&send_buffer[..length], info.to)
                .await
                .map_err(|_| FoundationError::SocketUnavailable)?;
            if sent != length {
                return Err(FoundationError::PacketUnavailable);
            }
        }
    }
}

fn bounded_quic_config(verify_peer: bool) -> Result<quiche::Config, FoundationError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|_| FoundationError::ConnectionUnavailable)?;
    config.verify_peer(verify_peer);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|_| FoundationError::AlpnMismatch)?;
    config.set_max_idle_timeout(MAX_IDLE_TIMEOUT.as_millis() as u64);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD_BYTES);
    config.set_initial_max_data(INITIAL_CONNECTION_WINDOW_BYTES);
    config.set_initial_max_stream_data_bidi_local(INITIAL_BIDI_STREAM_WINDOW_BYTES);
    config.set_initial_max_stream_data_bidi_remote(INITIAL_BIDI_STREAM_WINDOW_BYTES);
    config.set_initial_max_stream_data_uni(INITIAL_UNI_STREAM_WINDOW_BYTES);
    config.set_initial_max_streams_bidi(MAX_BIDI_STREAMS);
    config.set_initial_max_streams_uni(MAX_UNI_STREAMS);
    config.set_max_connection_window(INITIAL_CONNECTION_WINDOW_BYTES);
    config.set_max_stream_window(MAX_STREAM_WINDOW_BYTES);
    config.set_active_connection_id_limit(ACTIVE_CONNECTION_ID_LIMIT);
    config.set_disable_active_migration(true);
    config.set_max_amplification_factor(3);
    config.set_send_capacity_factor(SEND_CAPACITY_FACTOR);
    config.set_path_challenge_recv_max_queue_len(PATH_CHALLENGE_QUEUE_LIMIT);
    config.enable_dgram(true, DATAGRAM_QUEUE_LIMIT, DATAGRAM_QUEUE_LIMIT);
    config.enable_pacing(false);
    config.discover_pmtu(false);
    config.set_pmtud_max_probes(3);
    config.grease(true);

    apply_early_data_policy(&mut config, EarlyDataPolicy::Disabled);
    Ok(config)
}

fn apply_early_data_policy(_config: &mut quiche::Config, policy: EarlyDataPolicy) {
    match policy {
        // Early data is opt-in in quiche. The disabled branch deliberately
        // never calls Config::enable_early_data(). The live connection is
        // checked independently after the handshake.
        EarlyDataPolicy::Disabled => {}
    }
}

fn bounded_h3_config() -> Result<quiche::h3::Config, FoundationError> {
    let mut config = quiche::h3::Config::new().map_err(|_| FoundationError::H3Unavailable)?;
    // This bounds the decoded field section at 16 KiB. quiche 0.29.3 allows
    // an encoded temporary header block up to 24 KiB before ExcessiveLoad.
    config.set_max_field_section_size(MAX_FIELD_SECTION_BYTES);
    config.set_qpack_max_table_capacity(QPACK_MAX_TABLE_CAPACITY);
    config.set_qpack_blocked_streams(QPACK_BLOCKED_STREAMS);
    config.set_max_priority_update_size(MAX_PRIORITY_UPDATE_BYTES);
    config.enable_extended_connect(true);
    Ok(config)
}

fn h3_initialization_ready(
    is_established: bool,
    is_in_early_data: bool,
) -> Result<bool, FoundationError> {
    if is_in_early_data {
        return Err(FoundationError::EarlyDataRejected);
    }
    Ok(is_established)
}

fn negotiated_group(name: Option<&str>) -> NegotiatedGroup {
    match name {
        Some("X25519MLKEM768") => NegotiatedGroup::X25519MlKem768,
        Some("X25519") => NegotiatedGroup::X25519,
        Some("P-256") => NegotiatedGroup::Secp256r1,
        Some("P-384") => NegotiatedGroup::Secp384r1,
        Some(_) | None => NegotiatedGroup::OtherOrUnknown,
    }
}

fn peer_quic_limits(params: &quiche::TransportParams) -> PeerQuicLimits {
    PeerQuicLimits {
        max_idle_timeout_ms: params.max_idle_timeout,
        max_udp_payload_bytes: params.max_udp_payload_size,
        initial_max_data: params.initial_max_data,
        initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni: params.initial_max_stream_data_uni,
        initial_max_streams_bidi: params.initial_max_streams_bidi,
        initial_max_streams_uni: params.initial_max_streams_uni,
        disable_active_migration: params.disable_active_migration,
        active_connection_id_limit: params.active_conn_id_limit,
        max_datagram_frame_bytes: params.max_datagram_frame_size,
    }
}

fn peer_setting(settings: &[(u64, u64)], id: u64) -> Option<u64> {
    settings
        .iter()
        .find_map(|(setting_id, value)| (*setting_id == id).then_some(*value))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    use super::*;

    const TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(12);

    fn fixed_ok<T, E>(result: Result<T, E>, message: &'static str) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("{message}"),
        }
    }

    fn fixed_some<T>(value: Option<T>, message: &'static str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{message}"),
        }
    }

    async fn run_server(
        socket: UdpSocket,
        mut config: quiche::Config,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        task_permit: OwnedSemaphorePermit,
    ) -> Result<(), FoundationError> {
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        let mut first_packet = [0_u8; MAX_UDP_PAYLOAD_BYTES];
        let (length, peer_address) =
            timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut first_packet))
                .await
                .map_err(|_| FoundationError::DriverTimeout)?
                .map_err(|_| FoundationError::SocketUnavailable)?;
        if !peer_address.ip().is_loopback() {
            return Err(FoundationError::SocketUnavailable);
        }

        let header =
            quiche::Header::from_slice(&mut first_packet[..length], quiche::MAX_CONN_ID_LEN)
                .map_err(|_| FoundationError::PacketUnavailable)?;
        if header.ty != quiche::Type::Initial || !quiche::version_is_supported(header.version) {
            return Err(FoundationError::PacketUnavailable);
        }
        let mut connection =
            quiche::accept(&header.dcid, None, local_address, peer_address, &mut config)
                .map_err(|_| FoundationError::ConnectionUnavailable)?;
        connection
            .recv(
                &mut first_packet[..length],
                quiche::RecvInfo {
                    from: peer_address,
                    to: local_address,
                },
            )
            .map_err(|_| FoundationError::PacketUnavailable)?;

        FoundationDriver::new(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
            task_permit,
        )?
        .run()
        .await
    }

    async fn run_client(
        socket: UdpSocket,
        peer_address: SocketAddr,
        mut config: quiche::Config,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        task_permit: OwnedSemaphorePermit,
    ) -> Result<(), FoundationError> {
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        let source_connection_id = [0x51_u8; quiche::MAX_CONN_ID_LEN];
        let source_connection_id = quiche::ConnectionId::from_ref(&source_connection_id);
        let connection = quiche::connect(
            Some("localhost"),
            &source_connection_id,
            local_address,
            peer_address,
            &mut config,
        )
        .map_err(|_| FoundationError::ConnectionUnavailable)?;

        FoundationDriver::new(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
            task_permit,
        )?
        .run()
        .await
    }

    async fn finish_tasks(
        mut client_task: JoinHandle<Result<(), FoundationError>>,
        mut server_task: JoinHandle<Result<(), FoundationError>>,
    ) {
        let joined = timeout(TASK_JOIN_TIMEOUT, async {
            let client = (&mut client_task).await;
            let server = (&mut server_task).await;
            (client, server)
        })
        .await;

        match joined {
            Ok((client, server)) => {
                fixed_ok(
                    fixed_ok(client, "join loopback H3 client task"),
                    "finish loopback H3 client task",
                );
                fixed_ok(
                    fixed_ok(server, "join loopback H3 server task"),
                    "finish loopback H3 server task",
                );
            }
            Err(_) => {
                client_task.abort();
                server_task.abort();
                let _ = client_task.await;
                let _ = server_task.await;
                panic!("stop loopback H3 tasks within fixed timeout");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_h3_loopback_proves_tls_settings_bounds_and_shutdown() {
        let temp = fixed_ok(TempDir::new(), "create temporary certificate directory");
        let cert_path = temp.path().join("cert.pem");
        let key_path = temp.path().join("key.pem");
        let certified = fixed_ok(
            rcgen::generate_simple_self_signed(vec!["localhost".into()]),
            "generate temporary loopback certificate",
        );
        fixed_ok(
            std::fs::write(&cert_path, certified.cert.pem()),
            "write temporary loopback certificate",
        );
        fixed_ok(
            std::fs::write(&key_path, certified.key_pair.serialize_pem()),
            "write temporary loopback key",
        );
        let cert = fixed_some(cert_path.to_str(), "read temporary certificate path");
        let key = fixed_some(key_path.to_str(), "read temporary key path");

        let mut server_config = fixed_ok(
            bounded_quic_config(false),
            "build bounded loopback H3 server configuration",
        );
        fixed_ok(
            server_config.load_cert_chain_from_pem_file(cert),
            "load temporary loopback certificate",
        );
        fixed_ok(
            server_config.load_priv_key_from_pem_file(key),
            "load temporary loopback key",
        );
        let client_config = fixed_ok(
            bounded_quic_config(false),
            "build bounded loopback H3 client configuration",
        );

        let server_socket = fixed_ok(
            UdpSocket::bind("127.0.0.1:0").await,
            "bind loopback H3 server",
        );
        let server_address = fixed_ok(server_socket.local_addr(), "read loopback H3 address");
        let client_socket = fixed_ok(
            UdpSocket::bind("127.0.0.1:0").await,
            "bind loopback H3 client",
        );

        let task_budget = ConnectionTaskBudget::new();
        let server_permit = fixed_ok(task_budget.try_acquire(), "reserve loopback H3 server task");
        let client_permit = fixed_ok(task_budget.try_acquire(), "reserve loopback H3 client task");
        let ready_barrier = Arc::new(Barrier::new(2));
        let (server_tx, mut server_rx) = mpsc::channel(OBSERVATION_QUEUE_LIMIT);
        let (client_tx, mut client_rx) = mpsc::channel(OBSERVATION_QUEUE_LIMIT);

        let server_task = tokio::spawn(run_server(
            server_socket,
            server_config,
            server_tx,
            Arc::clone(&ready_barrier),
            server_permit,
        ));
        let client_task = tokio::spawn(run_client(
            client_socket,
            server_address,
            client_config,
            client_tx,
            ready_barrier,
            client_permit,
        ));

        let client = fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, client_rx.recv()).await,
                "wait for loopback H3 client observation",
            ),
            "receive loopback H3 client observation",
        );
        let server = fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, server_rx.recv()).await,
                "wait for loopback H3 server observation",
            ),
            "receive loopback H3 server observation",
        );
        finish_tasks(client_task, server_task).await;

        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        assert_eq!(client.channel_binding, server.channel_binding);
        assert!(client.alpn_h3 && server.alpn_h3);
        assert!(!client.early_data && !server.early_data);
        assert_ne!(client.negotiated_group, NegotiatedGroup::OtherOrUnknown);
        assert_eq!(client.negotiated_group, server.negotiated_group);
        let expected_quic = PeerQuicLimits {
            max_idle_timeout_ms: MAX_IDLE_TIMEOUT.as_millis() as u64,
            max_udp_payload_bytes: MAX_UDP_PAYLOAD_BYTES as u64,
            initial_max_data: INITIAL_CONNECTION_WINDOW_BYTES,
            initial_max_stream_data_bidi_local: INITIAL_BIDI_STREAM_WINDOW_BYTES,
            initial_max_stream_data_bidi_remote: INITIAL_BIDI_STREAM_WINDOW_BYTES,
            initial_max_stream_data_uni: INITIAL_UNI_STREAM_WINDOW_BYTES,
            initial_max_streams_bidi: MAX_BIDI_STREAMS,
            initial_max_streams_uni: MAX_UNI_STREAMS,
            disable_active_migration: true,
            active_connection_id_limit: ACTIVE_CONNECTION_ID_LIMIT,
            max_datagram_frame_bytes: Some(MAX_DATAGRAM_FRAME_BYTES),
        };
        assert_eq!(client.peer_quic, expected_quic);
        assert_eq!(server.peer_quic, expected_quic);
        let expected_settings = PeerH3Settings {
            max_field_section_size: Some(MAX_FIELD_SECTION_BYTES),
            qpack_max_table_capacity: Some(QPACK_MAX_TABLE_CAPACITY),
            qpack_blocked_streams: Some(QPACK_BLOCKED_STREAMS),
            extended_connect: true,
            datagram: true,
        };
        assert_eq!(client.peer_h3, expected_settings);
        assert_eq!(server.peer_h3, expected_settings);

        assert_eq!(MAX_UDP_PAYLOAD_BYTES, 1_350);
        assert_eq!(SEND_CAPACITY_FACTOR, 1.0);
        assert_eq!(DATAGRAM_QUEUE_LIMIT, 32);
        assert_eq!(INITIAL_CONNECTION_WINDOW_BYTES, 1_048_576);
        assert_eq!(MAX_BIDI_STREAMS, 8);
        assert_eq!(MAX_UNI_STREAMS, 8);
        assert_eq!(MAX_FIELD_SECTION_BYTES, 16_384);
        assert_eq!(QPACK_MAX_TABLE_CAPACITY, 0);
        assert_eq!(QPACK_BLOCKED_STREAMS, 0);
        assert_eq!(MAX_PRIORITY_UPDATE_BYTES, 256);
        assert_eq!(ACTIVE_CONNECTION_ID_LIMIT, 2);
        assert_eq!(PATH_CHALLENGE_QUEUE_LIMIT, 3);
    }

    #[tokio::test]
    async fn observation_channel_and_task_budget_fail_closed_at_capacity() {
        let observation = FoundationObservation {
            channel_binding: TlsChannelBinding::new([0_u8; 32]),
            negotiated_group: NegotiatedGroup::X25519,
            alpn_h3: true,
            early_data: false,
            peer_quic: PeerQuicLimits {
                max_idle_timeout_ms: MAX_IDLE_TIMEOUT.as_millis() as u64,
                max_udp_payload_bytes: MAX_UDP_PAYLOAD_BYTES as u64,
                initial_max_data: INITIAL_CONNECTION_WINDOW_BYTES,
                initial_max_stream_data_bidi_local: INITIAL_BIDI_STREAM_WINDOW_BYTES,
                initial_max_stream_data_bidi_remote: INITIAL_BIDI_STREAM_WINDOW_BYTES,
                initial_max_stream_data_uni: INITIAL_UNI_STREAM_WINDOW_BYTES,
                initial_max_streams_bidi: MAX_BIDI_STREAMS,
                initial_max_streams_uni: MAX_UNI_STREAMS,
                disable_active_migration: true,
                active_connection_id_limit: ACTIVE_CONNECTION_ID_LIMIT,
                max_datagram_frame_bytes: Some(MAX_DATAGRAM_FRAME_BYTES),
            },
            peer_h3: PeerH3Settings {
                max_field_section_size: Some(MAX_FIELD_SECTION_BYTES),
                qpack_max_table_capacity: Some(QPACK_MAX_TABLE_CAPACITY),
                qpack_blocked_streams: Some(QPACK_BLOCKED_STREAMS),
                extended_connect: true,
                datagram: true,
            },
        };
        let (tx, mut rx) = mpsc::channel(OBSERVATION_QUEUE_LIMIT);
        fixed_ok(tx.try_send(observation), "fill bounded observation queue");
        assert!(matches!(
            tx.try_send(observation),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(rx.recv().await, Some(observation));

        let task_budget = ConnectionTaskBudget::new();
        let mut permits = Vec::with_capacity(CONNECTION_TASK_LIMIT);
        for _ in 0..CONNECTION_TASK_LIMIT {
            permits.push(fixed_ok(
                task_budget.try_acquire(),
                "fill bounded connection task budget",
            ));
        }
        assert_eq!(
            task_budget.try_acquire().err(),
            Some(FoundationError::TaskBudgetUnavailable)
        );
        drop(permits);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[test]
    fn foundation_errors_use_only_fixed_privacy_safe_messages() {
        let cases = [
            (FoundationError::AlpnMismatch, "native H3 ALPN mismatch"),
            (
                FoundationError::ConnectionUnavailable,
                "native H3 connection unavailable",
            ),
            (FoundationError::DriverStopped, "native H3 driver stopped"),
            (FoundationError::DriverTimeout, "native H3 driver timeout"),
            (
                FoundationError::EarlyDataRejected,
                "native H3 early data rejected",
            ),
            (
                FoundationError::ExporterUnavailable,
                "native H3 TLS exporter unavailable",
            ),
            (
                FoundationError::H3Unavailable,
                "native H3 connection unavailable",
            ),
            (
                FoundationError::ObservationQueueUnavailable,
                "native H3 observation queue unavailable",
            ),
            (
                FoundationError::PacketUnavailable,
                "native H3 packet unavailable",
            ),
            (
                FoundationError::SocketUnavailable,
                "native H3 socket unavailable",
            ),
            (
                FoundationError::TaskBudgetUnavailable,
                "native H3 task budget unavailable",
            ),
        ];

        for (error, expected) in cases {
            let message = error.to_string();
            assert_eq!(message, expected);
            assert!(message.len() <= 48);
            assert!(!message.contains("127.0.0.1"));
            assert!(!message.contains("localhost"));
            assert!(!message.contains('/'));
        }
    }

    #[test]
    fn early_data_is_rejected_before_the_established_guard() {
        assert_eq!(
            h3_initialization_ready(false, true),
            Err(FoundationError::EarlyDataRejected)
        );
        assert_eq!(h3_initialization_ready(false, false), Ok(false));
        assert_eq!(h3_initialization_ready(true, false), Ok(true));
    }
}
