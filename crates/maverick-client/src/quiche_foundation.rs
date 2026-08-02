//! Private, feature-gated direct-quiche foundation.
//!
//! `quiche` owns QUIC, TLS, and HTTP/3. This module drives one UDP socket and
//! one connection with Tokio behind a fixed-capacity private manager command
//! queue. It has no connection router, and no quiche, BoringSSL, or TLS type
//! leaves this private module.

use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::ssl::{SslRef, SslVersion};
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use maverick_core::auth_v3::{AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Barrier, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const MAX_UDP_PAYLOAD_BYTES: usize = 1_350;
const MAX_DATAGRAM_FRAME_BYTES: u64 = 65_536;
const SEND_CAPACITY_FACTOR: f64 = 1.0;
const CONNECTION_TASK_LIMIT: usize = 8;
const COMMAND_QUEUE_LIMIT: usize = 1;
const CONNECTION_LEASE_LIMIT: usize = 1;
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
const COMMAND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const DRIVER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(2);

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

#[cfg(test)]
const T026C_AUTHORITY: &str = "auth.invalid";
#[cfg(test)]
const T026C_CONTROL_PATH: &str = "/synthetic-h3-auth-v3";
#[cfg(test)]
const T026C_NOW: u64 = 1_800_000_000;
#[cfg(test)]
const T026C_REQUEST_SPLIT: usize = 113;
#[cfg(test)]
const T026C_RESPONSE_SPLIT: usize = 127;
#[cfg(test)]
const T026C_APPLICATION_CLOSE_CODE: u64 = 0x100;

static NEXT_CONNECTION_GENERATION: AtomicU64 = AtomicU64::new(1);

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

#[derive(Clone, Copy, Eq, PartialEq)]
struct AuthV3Exporter([u8; AUTH_V3_EXPORTER_LEN]);

impl AuthV3Exporter {
    const fn new(value: [u8; AUTH_V3_EXPORTER_LEN]) -> Self {
        Self(value)
    }

    const fn as_bytes(&self) -> &[u8; AUTH_V3_EXPORTER_LEN] {
        &self.0
    }
}

impl fmt::Debug for AuthV3Exporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("redacted auth-v3 exporter")
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct LegacyExporter([u8; AUTH_V3_EXPORTER_LEN]);

#[cfg(test)]
impl LegacyExporter {
    const fn new(value: [u8; AUTH_V3_EXPORTER_LEN]) -> Self {
        Self(value)
    }

    const fn as_bytes(&self) -> &[u8; AUTH_V3_EXPORTER_LEN] {
        &self.0
    }
}

#[cfg(test)]
impl fmt::Debug for LegacyExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("redacted legacy exporter")
    }
}

struct TlsObservation {
    channel_binding: TlsChannelBinding,
    auth_v3_exporter: AuthV3Exporter,
    negotiated_group: NegotiatedGroup,
    peer_quic: PeerQuicLimits,
    #[cfg(test)]
    legacy_exporter: LegacyExporter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FoundationObservation {
    generation: ConnectionGeneration,
    channel_binding: TlsChannelBinding,
    auth_v3_exporter: AuthV3Exporter,
    #[cfg(test)]
    legacy_exporter: LegacyExporter,
    negotiated_group: NegotiatedGroup,
    actual_tls13: bool,
    alpn_h3: bool,
    early_data: bool,
    peer_quic: PeerQuicLimits,
    peer_h3: PeerH3Settings,
}

impl FoundationObservation {
    fn auth_v3_exporter_for<'observation, 'manager>(
        &'observation self,
        lease: &'observation ConnectionLease<'manager>,
    ) -> Result<&'observation AuthV3Exporter, FoundationError> {
        if self.generation != lease.generation() {
            return Err(FoundationError::GenerationMismatch);
        }
        Ok(&self.auth_v3_exporter)
    }
}

#[cfg(test)]
mod auth_runtime_reference {
    use maverick_core::auth_v3::{
        encode_auth_v3_client_control, encode_auth_v3_server_confirmation,
        verify_auth_v3_client_control, verify_auth_v3_server_confirmation, AuthV3Carrier,
        AuthV3ClientControlInput, AuthV3ClientReceipt, AuthV3PreselectedProfile,
        AuthV3ServerConfirmationInput, AuthV3TlsVersion, AUTH_V3_CLIENT_CONTROL_LEN,
        AUTH_V3_SERVER_CONFIRMATION_LEN,
    };
    use maverick_core::config::{ClientRoleConfig, DirectV3TransportStrategy, ServerRoleConfig};
    use quiche::h3::NameValue;
    use rand::{rngs::OsRng, TryRngCore};

    use super::*;

    const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const TEST_NOT_AFTER: u64 = T026C_NOW + 172_800;
    const TEST_HANDLE: &str = "VVVVVVVVVVVVVVVVVVVVVQ";
    const TEST_PRINCIPAL: &str = "EREREREREREREREREREREQ";
    const TEST_DEPLOYMENT: &str = "IiIiIiIiIiIiIiIiIiIiIg";
    const TEST_NAMESPACE: &str = "MzMzMzMzMzMzMzMzMzMzMw";
    const TEST_SERVER_ID: &str = "RERERERERERERERERERERA";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum TestAuthRole {
        Client,
        Server,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ReferenceFault {
        None,
        MalformedClientControl,
        WrongClientMac,
        WrongClientExporter,
        WrongClientProfile,
        WrongClientPolicy,
        WrongServerConfirmation,
        DuplicateControl,
        PreAuthDatagram,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) struct ReferenceOutcome {
        pub(super) role: TestAuthRole,
        pub(super) slot_claims: u8,
        pub(super) sent_body_chunks: u8,
        pub(super) received_data_events: u8,
        pub(super) request_bytes: usize,
        pub(super) response_bytes: usize,
        pub(super) datagram_checks: u16,
    }

    impl fmt::Debug for ReferenceOutcome {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test-private auth-v3 reference outcome")
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuthSlot {
        Fresh,
        Authenticating(Option<u64>),
        Authenticated,
        Consumed,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuthPhase {
        Fresh,
        ClientSendingHeaders,
        ClientSendingBody,
        ClientWaitingResponse,
        ClientReceivingResponse,
        ServerReceivingRequest,
        ServerSendingHeaders,
        ServerSendingBody,
        Authenticated,
        Consumed,
        Failed,
    }

    struct BodySendState<const LENGTH: usize> {
        bytes: [u8; LENGTH],
        stream_id: u64,
        offset: usize,
        chunk_end: usize,
        split_at: usize,
        completed_chunks: u8,
    }

    impl<const LENGTH: usize> BodySendState<LENGTH> {
        fn new(bytes: [u8; LENGTH], stream_id: u64, split_at: usize) -> Self {
            Self {
                bytes,
                stream_id,
                offset: 0,
                chunk_end: split_at,
                split_at,
                completed_chunks: 0,
            }
        }

        fn pending(&self) -> (&[u8], bool) {
            (
                &self.bytes[self.offset..self.chunk_end],
                self.chunk_end == LENGTH,
            )
        }

        fn record_progress(&mut self, written: usize) -> Result<bool, FoundationError> {
            let pending = self.chunk_end.saturating_sub(self.offset);
            if written == 0 || written > pending {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.offset += written;
            if self.offset != self.chunk_end {
                return Ok(false);
            }
            self.completed_chunks = self
                .completed_chunks
                .checked_add(1)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            if self.offset == LENGTH {
                return Ok(true);
            }
            if self.chunk_end != self.split_at {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.chunk_end = LENGTH;
            Ok(false)
        }

        fn clear(&mut self) {
            self.bytes.fill(0);
            self.stream_id = 0;
            self.offset = 0;
            self.chunk_end = 0;
            self.completed_chunks = 0;
        }
    }

    enum TestRoleConfig {
        Client(ClientRoleConfig),
        Server(ServerRoleConfig),
    }

    impl TestRoleConfig {
        fn parse(role: TestAuthRole) -> Result<Self, FoundationError> {
            let parsed = match role {
                TestAuthRole::Client => Self::Client(
                    ClientRoleConfig::from_yaml_str(&test_client_role_yaml())
                        .map_err(|_| FoundationError::PreAuthApplicationActivity)?,
                ),
                TestAuthRole::Server => Self::Server(
                    ServerRoleConfig::from_yaml_str(&test_server_role_yaml())
                        .map_err(|_| FoundationError::PreAuthApplicationActivity)?,
                ),
            };
            if parsed.transport_strategy()? != DirectV3TransportStrategy::H3
                || parsed.tunnel_path()? != T026C_CONTROL_PATH
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            let _preselected_before_io = parsed.preselected_profile()?;
            Ok(parsed)
        }

        fn transport_strategy(&self) -> Result<DirectV3TransportStrategy, FoundationError> {
            match self {
                Self::Client(config) => config
                    .direct_v3()
                    .map(|config| config.transport_strategy())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
                Self::Server(config) => config
                    .direct_v3()
                    .map(|config| config.transport_strategy())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn tunnel_path(&self) -> Result<&str, FoundationError> {
            match self {
                Self::Client(config) => config
                    .direct_v3()
                    .map(|config| config.tunnel_path())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
                Self::Server(config) => config
                    .direct_v3()
                    .map(|config| config.tunnel_path())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn preselected_profile(&self) -> Result<AuthV3PreselectedProfile<'_>, FoundationError> {
            match self {
                Self::Client(config) => config
                    .direct_v3()
                    .map(|config| config.preselected_profile())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
                Self::Server(config) => config
                    .direct_v3()
                    .map(|config| config.preselected_profile())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn client_server_name(&self) -> Option<&str> {
            match self {
                Self::Client(config) => config.direct_v3().map(|config| config.server_name()),
                Self::Server(_) => None,
            }
        }
    }

    pub(super) struct TestAuthRuntime {
        role: TestAuthRole,
        fault: ReferenceFault,
        role_config: TestRoleConfig,
        expected_authority: &'static [u8],
        slot: AuthSlot,
        phase: AuthPhase,
        facts: Option<FoundationObservation>,
        deadline: Option<Instant>,
        request_send: Option<BodySendState<AUTH_V3_CLIENT_CONTROL_LEN>>,
        response_send: Option<BodySendState<AUTH_V3_SERVER_CONFIRMATION_LEN>>,
        request_recv: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
        request_recv_len: usize,
        response_recv: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
        response_recv_len: usize,
        slot_claims: u8,
        received_data_events: u8,
        datagram_checks: u16,
    }

    impl TestAuthRuntime {
        pub(super) fn new(role: TestAuthRole) -> Result<Self, FoundationError> {
            Self::with_fault(role, ReferenceFault::None)
        }

        pub(super) fn with_fault(
            role: TestAuthRole,
            fault: ReferenceFault,
        ) -> Result<Self, FoundationError> {
            if !valid_test_authority(T026C_AUTHORITY.as_bytes())
                || !valid_test_control_path(T026C_CONTROL_PATH.as_bytes())
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            let role_config = TestRoleConfig::parse(role)?;
            if role == TestAuthRole::Client
                && role_config.client_server_name() != Some(T026C_AUTHORITY)
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Ok(Self {
                role,
                fault,
                role_config,
                expected_authority: T026C_AUTHORITY.as_bytes(),
                slot: AuthSlot::Fresh,
                phase: AuthPhase::Fresh,
                facts: None,
                deadline: None,
                request_send: None,
                response_send: None,
                request_recv: [0; AUTH_V3_CLIENT_CONTROL_LEN],
                request_recv_len: 0,
                response_recv: [0; AUTH_V3_SERVER_CONFIRMATION_LEN],
                response_recv_len: 0,
                slot_claims: 0,
                received_data_events: 0,
                datagram_checks: 0,
            })
        }

        pub(super) fn install_live_facts(
            &mut self,
            observation: FoundationObservation,
            raw_sni: Option<&str>,
        ) -> Result<(), FoundationError> {
            if self.facts.is_some()
                || !observation.actual_tls13
                || !observation.alpn_h3
                || observation.early_data
                || observation.peer_h3.max_field_section_size != Some(MAX_FIELD_SECTION_BYTES)
                || observation.peer_h3.qpack_max_table_capacity != Some(QPACK_MAX_TABLE_CAPACITY)
                || observation.peer_h3.qpack_blocked_streams != Some(QPACK_BLOCKED_STREAMS)
                || !observation.peer_h3.extended_connect
                || !observation.peer_h3.datagram
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            if self.role == TestAuthRole::Server
                && raw_sni.map(str::as_bytes) != Some(self.expected_authority)
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.facts = Some(observation);
            Ok(())
        }

        pub(super) fn check_datagram_queue(
            &mut self,
            connection: &quiche::Connection,
        ) -> Result<(), FoundationError> {
            self.datagram_checks = self
                .datagram_checks
                .checked_add(1)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            if connection.dgram_recv_front_len().is_some() {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Ok(())
        }

        pub(super) fn drive_outbound(
            &mut self,
            connection: &mut quiche::Connection,
            h3_connection: &mut quiche::h3::Connection,
            foundation_ready: bool,
        ) -> Result<(), FoundationError> {
            if let Some(deadline) = self.deadline {
                if Instant::now() >= deadline {
                    return Err(FoundationError::DriverTimeout);
                }
            }

            if self.role == TestAuthRole::Client
                && self.phase == AuthPhase::Fresh
                && foundation_ready
            {
                if self.fault == ReferenceFault::PreAuthDatagram {
                    connection
                        .dgram_send(b"test-private-datagram")
                        .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
                }
                self.prepare_client_control()?;
                self.check_datagram_queue(connection)?;
                self.claim_client_slot()?;
                self.phase = AuthPhase::ClientSendingHeaders;
            }

            match self.phase {
                AuthPhase::ClientSendingHeaders => {
                    let headers = request_headers(
                        self.expected_authority,
                        self.role_config.tunnel_path()?.as_bytes(),
                    );
                    match h3_connection.send_request(connection, &headers, false) {
                        Ok(stream_id) => {
                            if self.fault == ReferenceFault::DuplicateControl {
                                h3_connection
                                    .send_request(connection, &headers, false)
                                    .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
                            }
                            self.bind_client_stream(stream_id)?;
                            let body = self
                                .request_send
                                .take()
                                .ok_or(FoundationError::PreAuthApplicationActivity)?
                                .bytes;
                            self.request_send =
                                Some(BodySendState::new(body, stream_id, T026C_REQUEST_SPLIT));
                            self.phase = AuthPhase::ClientSendingBody;
                        }
                        Err(quiche::h3::Error::StreamBlocked) => {}
                        Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
                    }
                }
                AuthPhase::ClientSendingBody => {
                    let (stream_id, pending_len, fin) = {
                        let send = self
                            .request_send
                            .as_ref()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?;
                        let (pending, fin) = send.pending();
                        (send.stream_id, pending.len(), fin)
                    };
                    let result = {
                        let send = self
                            .request_send
                            .as_ref()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?;
                        let (pending, _) = send.pending();
                        h3_connection.send_body(connection, stream_id, pending, fin)
                    };
                    match result {
                        Ok(written) => {
                            if written > pending_len {
                                return Err(FoundationError::PreAuthApplicationActivity);
                            }
                            let complete = self
                                .request_send
                                .as_mut()
                                .ok_or(FoundationError::PreAuthApplicationActivity)?
                                .record_progress(written)?;
                            if complete {
                                self.phase = AuthPhase::ClientWaitingResponse;
                            }
                        }
                        Err(quiche::h3::Error::Done) => {}
                        Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
                    }
                }
                AuthPhase::ServerSendingHeaders => {
                    let stream_id = self.bound_stream()?;
                    let headers = response_headers();
                    match h3_connection.send_response(connection, stream_id, &headers, false) {
                        Ok(()) => self.phase = AuthPhase::ServerSendingBody,
                        Err(quiche::h3::Error::StreamBlocked) => {}
                        Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
                    }
                }
                AuthPhase::ServerSendingBody => {
                    let (stream_id, pending_len, fin) = {
                        let send = self
                            .response_send
                            .as_ref()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?;
                        let (pending, fin) = send.pending();
                        (send.stream_id, pending.len(), fin)
                    };
                    let result = {
                        let send = self
                            .response_send
                            .as_ref()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?;
                        let (pending, _) = send.pending();
                        h3_connection.send_body(connection, stream_id, pending, fin)
                    };
                    match result {
                        Ok(written) => {
                            if written > pending_len {
                                return Err(FoundationError::PreAuthApplicationActivity);
                            }
                            let complete = self
                                .response_send
                                .as_mut()
                                .ok_or(FoundationError::PreAuthApplicationActivity)?
                                .record_progress(written)?;
                            if complete {
                                self.check_datagram_queue(connection)?;
                                self.authenticate()?;
                            }
                        }
                        Err(quiche::h3::Error::Done) => {}
                        Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
                    }
                }
                AuthPhase::Fresh
                | AuthPhase::ClientWaitingResponse
                | AuthPhase::ClientReceivingResponse
                | AuthPhase::ServerReceivingRequest
                | AuthPhase::Authenticated => {}
                AuthPhase::Consumed => {
                    return Err(FoundationError::PreAuthApplicationActivity);
                }
                AuthPhase::Failed => {
                    return Err(FoundationError::PreAuthApplicationActivity);
                }
            }
            Ok(())
        }

        pub(super) fn handle_event(
            &mut self,
            connection: &mut quiche::Connection,
            h3_connection: &mut quiche::h3::Connection,
            stream_id: u64,
            event: quiche::h3::Event,
        ) -> Result<(), FoundationError> {
            match (self.role, event) {
                (TestAuthRole::Server, quiche::h3::Event::Headers { list, more_frames }) => {
                    self.claim_server_slot(stream_id)?;
                    if !more_frames
                        || !valid_request_headers_for(
                            &list,
                            self.expected_authority,
                            self.role_config.tunnel_path()?.as_bytes(),
                        )
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    self.phase = AuthPhase::ServerReceivingRequest;
                    Ok(())
                }
                (TestAuthRole::Server, quiche::h3::Event::Data) => {
                    self.admit_data_event(AuthPhase::ServerReceivingRequest, stream_id)?;
                    drain_body(
                        h3_connection,
                        connection,
                        stream_id,
                        &mut self.request_recv,
                        &mut self.request_recv_len,
                    )
                }
                (TestAuthRole::Server, quiche::h3::Event::Finished) => {
                    if self.phase != AuthPhase::ServerReceivingRequest
                        || self.bound_stream()? != stream_id
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    exact_body_finished(self.request_recv_len, AUTH_V3_CLIENT_CONTROL_LEN)?;
                    self.prepare_server_confirmation()?;
                    self.phase = AuthPhase::ServerSendingHeaders;
                    Ok(())
                }
                (TestAuthRole::Client, quiche::h3::Event::Headers { list, more_frames }) => {
                    if self.phase != AuthPhase::ClientWaitingResponse
                        || self.bound_stream()? != stream_id
                        || !more_frames
                        || !valid_response_headers(&list)
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    self.phase = AuthPhase::ClientReceivingResponse;
                    Ok(())
                }
                (TestAuthRole::Client, quiche::h3::Event::Data) => {
                    self.admit_data_event(AuthPhase::ClientReceivingResponse, stream_id)?;
                    drain_body(
                        h3_connection,
                        connection,
                        stream_id,
                        &mut self.response_recv,
                        &mut self.response_recv_len,
                    )
                }
                (TestAuthRole::Client, quiche::h3::Event::Finished) => {
                    if self.phase != AuthPhase::ClientReceivingResponse
                        || self.bound_stream()? != stream_id
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    exact_body_finished(self.response_recv_len, AUTH_V3_SERVER_CONFIRMATION_LEN)?;
                    self.verify_server_confirmation()?;
                    self.check_datagram_queue(connection)?;
                    self.authenticate()
                }
                (_, quiche::h3::Event::Reset(_))
                | (_, quiche::h3::Event::GoAway)
                | (_, quiche::h3::Event::PriorityUpdate) => {
                    Err(FoundationError::PreAuthApplicationActivity)
                }
            }
        }

        pub(super) fn take_success_outcome(&mut self) -> Option<ReferenceOutcome> {
            if self.phase != AuthPhase::Authenticated || self.slot != AuthSlot::Authenticated {
                return None;
            }
            self.facts.as_ref()?;
            let (sent_body_chunks, request_bytes, response_bytes) = match self.role {
                TestAuthRole::Client => {
                    let send = self.request_send.as_ref()?;
                    (send.completed_chunks, send.offset, self.response_recv_len)
                }
                TestAuthRole::Server => {
                    let send = self.response_send.as_ref()?;
                    (send.completed_chunks, self.request_recv_len, send.offset)
                }
            };
            let outcome = ReferenceOutcome {
                role: self.role,
                slot_claims: self.slot_claims,
                sent_body_chunks,
                received_data_events: self.received_data_events,
                request_bytes,
                response_bytes,
                datagram_checks: self.datagram_checks,
            };
            self.facts.take()?;
            self.slot = AuthSlot::Consumed;
            self.phase = AuthPhase::Consumed;
            self.clear_auth_buffers();
            Some(outcome)
        }

        pub(super) fn fail_closed(&mut self) {
            self.slot = AuthSlot::Consumed;
            self.phase = AuthPhase::Failed;
            self.clear_auth_buffers();
            self.facts = None;
        }

        fn prepare_client_control(&mut self) -> Result<(), FoundationError> {
            let facts = self
                .facts
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            let preselected = self.role_config.preselected_profile()?;
            let mut alternate_exporter = *facts.auth_v3_exporter.as_bytes();
            if self.fault == ReferenceFault::WrongClientExporter {
                alternate_exporter[0] ^= 0x80;
            }
            let exporter = if self.fault == ReferenceFault::WrongClientExporter {
                &alternate_exporter
            } else {
                facts.auth_v3_exporter.as_bytes()
            };
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                facts.early_data,
                exporter,
                true,
                Some(&[]),
                self.role_config.tunnel_path()?,
            );
            let mut client_nonce = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut client_nonce)
                .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let mut control = encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, T026C_NOW, client_nonce),
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            match self.fault {
                ReferenceFault::MalformedClientControl => control[0] ^= 0x80,
                ReferenceFault::WrongClientMac => control[255] ^= 0x80,
                ReferenceFault::WrongClientProfile => control[48] ^= 0x80,
                ReferenceFault::WrongClientPolicy => control[12] ^= 0x80,
                ReferenceFault::None
                | ReferenceFault::WrongClientExporter
                | ReferenceFault::WrongServerConfirmation
                | ReferenceFault::DuplicateControl
                | ReferenceFault::PreAuthDatagram => {}
            }
            self.request_send = Some(BodySendState::new(control, 0, T026C_REQUEST_SPLIT));
            Ok(())
        }

        fn prepare_server_confirmation(&mut self) -> Result<(), FoundationError> {
            let facts = self
                .facts
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            let preselected = self.role_config.preselected_profile()?;
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                facts.early_data,
                facts.auth_v3_exporter.as_bytes(),
                true,
                Some(&[]),
                self.role_config.tunnel_path()?,
            );
            let verified = verify_auth_v3_client_control(
                &self.request_recv,
                &preselected.trusted_profile(),
                &context,
                T026C_NOW,
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let mut server_nonce = [0_u8; 32];
            let mut session_id = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut server_nonce)
                .and_then(|()| OsRng.try_fill_bytes(&mut session_id))
                .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let mut confirmation = encode_auth_v3_server_confirmation(
                verified,
                &context,
                &AuthV3ServerConfirmationInput::new(
                    T026C_NOW,
                    T026C_NOW + 1_800,
                    T026C_NOW + 86_400,
                    server_nonce,
                    session_id,
                    65_536,
                    128,
                ),
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            if self.fault == ReferenceFault::WrongServerConfirmation {
                confirmation[319] ^= 0x80;
            }
            let stream_id = self.bound_stream()?;
            self.response_send = Some(BodySendState::new(
                confirmation,
                stream_id,
                T026C_RESPONSE_SPLIT,
            ));
            Ok(())
        }

        fn verify_server_confirmation(&self) -> Result<(), FoundationError> {
            let facts = self
                .facts
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            let request = &self
                .request_send
                .as_ref()
                .ok_or(FoundationError::PreAuthApplicationActivity)?
                .bytes;
            let preselected = self.role_config.preselected_profile()?;
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                facts.early_data,
                facts.auth_v3_exporter.as_bytes(),
                true,
                Some(&[]),
                self.role_config.tunnel_path()?,
            );
            verify_auth_v3_server_confirmation(
                &self.response_recv,
                request,
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientReceipt::new(T026C_NOW, 131_072, 256),
            )
            .map(|_| ())
            .map_err(|_| FoundationError::PreAuthApplicationActivity)
        }

        fn claim_client_slot(&mut self) -> Result<(), FoundationError> {
            if self.slot != AuthSlot::Fresh {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.slot = AuthSlot::Authenticating(None);
            self.slot_claims = self
                .slot_claims
                .checked_add(1)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            self.deadline = Some(
                Instant::now()
                    .checked_add(CONNECTION_RUN_TIMEOUT)
                    .ok_or(FoundationError::DriverTimeout)?,
            );
            Ok(())
        }

        fn claim_server_slot(&mut self, stream_id: u64) -> Result<(), FoundationError> {
            if self.slot != AuthSlot::Fresh || self.phase != AuthPhase::Fresh {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.slot = AuthSlot::Authenticating(Some(stream_id));
            self.slot_claims = self
                .slot_claims
                .checked_add(1)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            self.deadline = Some(
                Instant::now()
                    .checked_add(CONNECTION_RUN_TIMEOUT)
                    .ok_or(FoundationError::DriverTimeout)?,
            );
            if self.facts.is_none() {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Ok(())
        }

        fn bind_client_stream(&mut self, stream_id: u64) -> Result<(), FoundationError> {
            if self.slot != AuthSlot::Authenticating(None) {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.slot = AuthSlot::Authenticating(Some(stream_id));
            Ok(())
        }

        fn admit_data_event(
            &mut self,
            expected_phase: AuthPhase,
            stream_id: u64,
        ) -> Result<(), FoundationError> {
            if self.phase != expected_phase || self.bound_stream()? != stream_id {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.received_data_events = self
                .received_data_events
                .checked_add(1)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            Ok(())
        }

        fn bound_stream(&self) -> Result<u64, FoundationError> {
            match self.slot {
                AuthSlot::Authenticating(Some(stream_id)) => Ok(stream_id),
                _ => Err(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn authenticate(&mut self) -> Result<(), FoundationError> {
            if !matches!(self.slot, AuthSlot::Authenticating(Some(_))) {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.slot = AuthSlot::Authenticated;
            self.phase = AuthPhase::Authenticated;
            Ok(())
        }

        fn clear_auth_buffers(&mut self) {
            if let Some(send) = self.request_send.as_mut() {
                send.clear();
            }
            if let Some(send) = self.response_send.as_mut() {
                send.clear();
            }
            self.request_send = None;
            self.response_send = None;
            self.request_recv.fill(0);
            self.request_recv_len = 0;
            self.response_recv.fill(0);
            self.response_recv_len = 0;
            self.deadline = None;
        }
    }

    impl Drop for TestAuthRuntime {
        fn drop(&mut self) {
            self.clear_auth_buffers();
        }
    }

    fn drain_body<const LENGTH: usize>(
        h3_connection: &mut quiche::h3::Connection,
        connection: &mut quiche::Connection,
        stream_id: u64,
        output: &mut [u8; LENGTH],
        received: &mut usize,
    ) -> Result<(), FoundationError> {
        loop {
            if *received == LENGTH {
                let mut oversize = [0_u8; 1];
                match h3_connection.recv_body(connection, stream_id, &mut oversize) {
                    Ok(_) => return Err(FoundationError::PreAuthApplicationActivity),
                    Err(quiche::h3::Error::Done) => return Ok(()),
                    Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
                }
            }
            match h3_connection.recv_body(connection, stream_id, &mut output[*received..]) {
                Ok(0) => return Err(FoundationError::PreAuthApplicationActivity),
                Ok(length) => {
                    *received = bounded_body_progress(*received, length, LENGTH)?;
                }
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(_) => return Err(FoundationError::PreAuthApplicationActivity),
            }
        }
    }

    pub(super) fn bounded_body_progress(
        received: usize,
        next: usize,
        limit: usize,
    ) -> Result<usize, FoundationError> {
        let total = received
            .checked_add(next)
            .ok_or(FoundationError::PreAuthApplicationActivity)?;
        if next == 0 || total > limit {
            return Err(FoundationError::PreAuthApplicationActivity);
        }
        Ok(total)
    }

    pub(super) fn exact_body_finished(
        received: usize,
        expected: usize,
    ) -> Result<(), FoundationError> {
        if received != expected {
            return Err(FoundationError::PreAuthApplicationActivity);
        }
        Ok(())
    }

    pub(super) fn valid_request_headers<T: NameValue>(headers: &[T]) -> bool {
        valid_request_headers_for(
            headers,
            T026C_AUTHORITY.as_bytes(),
            T026C_CONTROL_PATH.as_bytes(),
        )
    }

    pub(super) fn valid_response_headers<T: NameValue>(headers: &[T]) -> bool {
        exact_headers(headers, &response_header_pairs())
    }

    fn exact_headers<T: NameValue>(headers: &[T], expected: &[(&[u8], &[u8])]) -> bool {
        headers.len() == expected.len()
            && headers
                .iter()
                .zip(expected)
                .all(|(actual, (name, value))| actual.name() == *name && actual.value() == *value)
    }

    fn valid_request_headers_for<T: NameValue>(
        headers: &[T],
        authority: &[u8],
        path: &[u8],
    ) -> bool {
        let expected = [
            (b":method".as_slice(), b"POST".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":authority".as_slice(), authority),
            (b":path".as_slice(), path),
            (
                b"content-type".as_slice(),
                b"application/maverick-auth-v3".as_slice(),
            ),
            (b"content-length".as_slice(), b"256".as_slice()),
        ];
        exact_headers(headers, &expected)
    }

    fn request_headers(authority: &[u8], path: &[u8]) -> [quiche::h3::Header; 6] {
        [
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", authority),
            quiche::h3::Header::new(b":path", path),
            quiche::h3::Header::new(b"content-type", b"application/maverick-auth-v3"),
            quiche::h3::Header::new(b"content-length", b"256"),
        ]
    }

    fn response_headers() -> [quiche::h3::Header; 3] {
        [
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"content-type", b"application/maverick-auth-v3"),
            quiche::h3::Header::new(b"content-length", b"320"),
        ]
    }

    pub(super) fn request_header_pairs() -> [(&'static [u8], &'static [u8]); 6] {
        [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", T026C_AUTHORITY.as_bytes()),
            (b":path", T026C_CONTROL_PATH.as_bytes()),
            (b"content-type", b"application/maverick-auth-v3"),
            (b"content-length", b"256"),
        ]
    }

    pub(super) fn response_header_pairs() -> [(&'static [u8], &'static [u8]); 3] {
        [
            (b":status", b"200"),
            (b"content-type", b"application/maverick-auth-v3"),
            (b"content-length", b"320"),
        ]
    }

    fn valid_test_authority(authority: &[u8]) -> bool {
        !authority.is_empty()
            && authority.is_ascii()
            && !authority.starts_with(b".")
            && !authority.ends_with(b".")
            && authority
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-'))
    }

    fn valid_test_control_path(path: &[u8]) -> bool {
        path.starts_with(b"/") && path.is_ascii() && !path.contains(&b'?')
    }

    fn test_binding_yaml() -> String {
        format!(
            r#"      provisioning_handle: "{TEST_HANDLE}"
      principal_id: "{TEST_PRINCIPAL}"
      deployment_profile_id: "{TEST_DEPLOYMENT}"
      credential_namespace_id: "{TEST_NAMESPACE}"
      server_identity_id: "{TEST_SERVER_ID}"
      credential_epoch: 7
      credential_not_after_unix: {TEST_NOT_AFTER}
      secret: "{TEST_SECRET}"
"#,
        )
    }

    fn test_client_role_yaml() -> String {
        format!(
            r#"version: 3
role: client
security:
  posture: standard
transport:
  strategy: h3
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
local:
  socks5:
    listen: "127.0.0.1:0"
server:
  address: "{T026C_AUTHORITY}:443"
  server_name: "{T026C_AUTHORITY}"
  tunnel_path: "{T026C_CONTROL_PATH}"
  ca_cert: null
  cert_pin: null
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
{}"#,
            test_binding_yaml()
        )
    }

    fn test_server_role_yaml() -> String {
        format!(
            r#"version: 3
role: server
security:
  posture: standard
transport:
  strategy: h3
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
listen: "127.0.0.1:0"
tls:
  cert_path: "certificate.pem"
  key_path: "key.pem"
maverick:
  tunnel_path: "{T026C_CONTROL_PATH}"
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
{}"#,
            test_binding_yaml()
        )
    }

    #[cfg(test)]
    mod state_tests {
        use super::*;

        fn synthetic_live_facts() -> FoundationObservation {
            FoundationObservation {
                generation: ConnectionGeneration(91),
                channel_binding: TlsChannelBinding::new([0x31; 32]),
                auth_v3_exporter: AuthV3Exporter::new([0x41; AUTH_V3_EXPORTER_LEN]),
                legacy_exporter: LegacyExporter::new([0x51; AUTH_V3_EXPORTER_LEN]),
                negotiated_group: NegotiatedGroup::X25519,
                actual_tls13: true,
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
            }
        }

        #[test]
        fn server_claims_once_before_requiring_facts_and_rejects_early_or_trailing_events() {
            let mut before_facts = TestAuthRuntime::new(TestAuthRole::Server)
                .expect("construct facts-order reference runtime");
            assert_eq!(
                before_facts.claim_server_slot(0),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert_eq!(before_facts.slot, AuthSlot::Authenticating(Some(0)));
            assert_eq!(before_facts.slot_claims, 1);
            assert!(before_facts.facts.is_none());

            let mut sequencing = TestAuthRuntime::new(TestAuthRole::Server)
                .expect("construct event-order reference runtime");
            sequencing
                .install_live_facts(synthetic_live_facts(), Some(T026C_AUTHORITY))
                .expect("install synthetic live facts");
            assert_eq!(
                sequencing.admit_data_event(AuthPhase::ServerReceivingRequest, 0),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            sequencing
                .claim_server_slot(0)
                .expect("claim first request");
            sequencing.phase = AuthPhase::ServerReceivingRequest;
            assert_eq!(
                sequencing.claim_server_slot(0),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert_eq!(
                sequencing.claim_server_slot(4),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert_eq!(sequencing.slot_claims, 1);
        }

        #[cfg(feature = "unstable-quiche-strict-push-test-support")]
        #[test]
        fn handle_event_rejects_trailers_control_events_and_wrong_stream_without_reopening_slot() {
            fn assert_rejected_without_reopening(
                session: &mut quiche::h3::testing::Session,
                role: TestAuthRole,
                phase: AuthPhase,
                stream_id: u64,
                event: quiche::h3::Event,
            ) {
                let mut runtime = TestAuthRuntime::new(role)
                    .expect("construct direct event rejection reference runtime");
                let raw_sni = (role == TestAuthRole::Server).then_some(T026C_AUTHORITY);
                runtime
                    .install_live_facts(synthetic_live_facts(), raw_sni)
                    .expect("install direct event rejection facts");
                match role {
                    TestAuthRole::Client => {
                        runtime
                            .claim_client_slot()
                            .expect("claim direct event client slot");
                        runtime
                            .bind_client_stream(0)
                            .expect("bind direct event client stream");
                    }
                    TestAuthRole::Server => runtime
                        .claim_server_slot(0)
                        .expect("claim direct event server slot"),
                }
                runtime.phase = phase;
                let claimed_slot = runtime.slot;

                let result = match role {
                    TestAuthRole::Client => runtime.handle_event(
                        &mut session.pipe.client,
                        &mut session.client,
                        stream_id,
                        event,
                    ),
                    TestAuthRole::Server => runtime.handle_event(
                        &mut session.pipe.server,
                        &mut session.server,
                        stream_id,
                        event,
                    ),
                };
                assert_eq!(result, Err(FoundationError::PreAuthApplicationActivity));
                assert_eq!(runtime.slot, claimed_slot);
                assert_eq!(runtime.slot_claims, 1);
                assert_eq!(runtime.phase, phase);
                assert!(runtime.facts.is_some());
                let second_claim = match role {
                    TestAuthRole::Client => runtime.claim_client_slot(),
                    TestAuthRole::Server => runtime.claim_server_slot(4),
                };
                assert_eq!(
                    second_claim,
                    Err(FoundationError::PreAuthApplicationActivity)
                );
                assert_eq!(runtime.slot, claimed_slot);
                assert_eq!(runtime.slot_claims, 1);
            }

            let mut transport = bounded_self_signed_loopback_quic_config()
                .expect("construct direct event rejection QUIC config");
            let h3_config =
                bounded_h3_config().expect("construct direct event rejection H3 config");
            let mut session =
                quiche::h3::testing::Session::with_configs(&mut transport, &h3_config)
                    .expect("construct direct event rejection H3 session");
            for (role, phase) in [
                (TestAuthRole::Client, AuthPhase::ClientReceivingResponse),
                (TestAuthRole::Server, AuthPhase::ServerReceivingRequest),
            ] {
                for event in [
                    quiche::h3::Event::Headers {
                        list: vec![quiche::h3::Header::new(b"x-trailer", b"1")],
                        more_frames: false,
                    },
                    quiche::h3::Event::Reset(7),
                    quiche::h3::Event::GoAway,
                    quiche::h3::Event::PriorityUpdate,
                ] {
                    assert_rejected_without_reopening(&mut session, role, phase, 0, event);
                }
                assert_rejected_without_reopening(
                    &mut session,
                    role,
                    phase,
                    4,
                    quiche::h3::Event::Data,
                );
                assert_rejected_without_reopening(
                    &mut session,
                    role,
                    phase,
                    0,
                    quiche::h3::Event::Finished,
                );
            }
        }

        #[test]
        fn success_outcome_take_is_transactional_and_one_shot() {
            let mut runtime = TestAuthRuntime::new(TestAuthRole::Client)
                .expect("construct transactional outcome reference runtime");
            runtime
                .install_live_facts(synthetic_live_facts(), None)
                .expect("install transactional outcome facts");
            runtime.slot = AuthSlot::Authenticated;
            runtime.phase = AuthPhase::Authenticated;
            runtime.slot_claims = 1;
            runtime.received_data_events = 2;
            runtime.datagram_checks = 2;

            assert!(runtime.take_success_outcome().is_none());
            assert!(runtime.facts.is_some());
            assert_eq!(runtime.slot, AuthSlot::Authenticated);
            assert_eq!(runtime.phase, AuthPhase::Authenticated);

            let mut request =
                BodySendState::new([0_u8; AUTH_V3_CLIENT_CONTROL_LEN], 0, T026C_REQUEST_SPLIT);
            request.offset = AUTH_V3_CLIENT_CONTROL_LEN;
            request.chunk_end = AUTH_V3_CLIENT_CONTROL_LEN;
            request.completed_chunks = 2;
            runtime.request_send = Some(request);
            runtime.response_recv_len = AUTH_V3_SERVER_CONFIRMATION_LEN;

            let outcome = runtime
                .take_success_outcome()
                .expect("take complete transactional outcome");
            assert_eq!(outcome.slot_claims, 1);
            assert_eq!(outcome.sent_body_chunks, 2);
            assert_eq!(outcome.received_data_events, 2);
            assert_eq!(outcome.request_bytes, AUTH_V3_CLIENT_CONTROL_LEN);
            assert_eq!(outcome.response_bytes, AUTH_V3_SERVER_CONFIRMATION_LEN);
            assert_eq!(outcome.datagram_checks, 2);
            assert!(runtime.facts.is_none());
            assert_eq!(runtime.slot, AuthSlot::Consumed);
            assert_eq!(runtime.phase, AuthPhase::Consumed);
            assert!(runtime.take_success_outcome().is_none());
        }
    }
}

#[cfg(test)]
use auth_runtime_reference::{
    bounded_body_progress, exact_body_finished, request_header_pairs, response_header_pairs,
    valid_request_headers, valid_response_headers, ReferenceFault, ReferenceOutcome, TestAuthRole,
    TestAuthRuntime,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoundationError {
    AlpnMismatch,
    CommandQueueUnavailable,
    ConnectionUnavailable,
    DriverStopped,
    DriverTimeout,
    EarlyDataRejected,
    ExporterUnavailable,
    GenerationMismatch,
    H3Unavailable,
    LeaseUnavailable,
    ManagerClosed,
    ObservationQueueUnavailable,
    PacketUnavailable,
    PreAuthApplicationActivity,
    SocketUnavailable,
    TaskBudgetUnavailable,
    TlsVersionMismatch,
}

impl fmt::Display for FoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlpnMismatch => "native H3 ALPN mismatch",
            Self::CommandQueueUnavailable => "native H3 command queue unavailable",
            Self::ConnectionUnavailable => "native H3 connection unavailable",
            Self::DriverStopped => "native H3 driver stopped",
            Self::DriverTimeout => "native H3 driver timeout",
            Self::EarlyDataRejected => "native H3 early data rejected",
            Self::ExporterUnavailable => "native H3 TLS exporter unavailable",
            Self::GenerationMismatch => "native H3 generation mismatch",
            Self::H3Unavailable => "native H3 connection unavailable",
            Self::LeaseUnavailable => "native H3 lease unavailable",
            Self::ManagerClosed => "native H3 manager closed",
            Self::ObservationQueueUnavailable => "native H3 observation queue unavailable",
            Self::PacketUnavailable => "native H3 packet unavailable",
            Self::PreAuthApplicationActivity => "native H3 pre-auth activity rejected",
            Self::SocketUnavailable => "native H3 socket unavailable",
            Self::TaskBudgetUnavailable => "native H3 task budget unavailable",
            Self::TlsVersionMismatch => "native H3 TLS version mismatch",
        })
    }
}

impl std::error::Error for FoundationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionGeneration(u64);

enum DriverCommand {
    Acquire {
        response: oneshot::Sender<ConnectionGeneration>,
    },
    Close,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct DriverExit {
    #[cfg(test)]
    reference_outcome: Option<ReferenceOutcome>,
}

struct ConnectionLease<'manager> {
    generation: ConnectionGeneration,
    _permit: OwnedSemaphorePermit,
    _manager: PhantomData<&'manager SingleIdentityQuicManager>,
}

impl ConnectionLease<'_> {
    fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    fn release(self) {}
}

struct SingleIdentityQuicManager {
    command_tx: Option<mpsc::Sender<DriverCommand>>,
    lease_permits: Arc<Semaphore>,
    driver_task: Option<JoinHandle<Result<DriverExit, FoundationError>>>,
}

impl SingleIdentityQuicManager {
    fn start(
        driver: FoundationDriver,
        task_permit: OwnedSemaphorePermit,
    ) -> Result<Self, FoundationError> {
        let generation = next_connection_generation()?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_LIMIT);
        let driver_task = tokio::spawn(async move {
            let _task_permit = task_permit;
            driver.run(command_rx, generation).await
        });
        Ok(Self {
            command_tx: Some(command_tx),
            lease_permits: Arc::new(Semaphore::new(CONNECTION_LEASE_LIMIT)),
            driver_task: Some(driver_task),
        })
    }

    async fn acquire(&self) -> Result<ConnectionLease<'_>, FoundationError> {
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(FoundationError::ManagerClosed)?;
        let permit = self
            .lease_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| FoundationError::LeaseUnavailable)?;
        let (response_tx, response_rx) = oneshot::channel();
        try_send_driver_command(
            command_tx,
            DriverCommand::Acquire {
                response: response_tx,
            },
        )?;
        let generation = timeout(COMMAND_RESPONSE_TIMEOUT, response_rx)
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::DriverStopped)?;
        Ok(ConnectionLease {
            generation,
            _permit: permit,
            _manager: PhantomData,
        })
    }

    async fn close(&mut self) -> Result<(), FoundationError> {
        if self.lease_permits.available_permits() != CONNECTION_LEASE_LIMIT {
            return Err(FoundationError::LeaseUnavailable);
        }
        let Some(command_tx) = self.command_tx.take() else {
            return Ok(());
        };
        let send_result = try_send_driver_command(&command_tx, DriverCommand::Close);
        drop(command_tx);
        let join_result = self.join_driver().await.map(|_| ());
        send_result.and(join_result)
    }

    async fn join_driver(&mut self) -> Result<DriverExit, FoundationError> {
        let Some(mut driver_task) = self.driver_task.take() else {
            return Ok(DriverExit::default());
        };
        match timeout(DRIVER_JOIN_TIMEOUT, &mut driver_task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(FoundationError::DriverStopped),
            Err(_) => {
                driver_task.abort();
                let _ = timeout(DRIVER_JOIN_TIMEOUT, driver_task).await;
                Err(FoundationError::DriverTimeout)
            }
        }
    }

    #[cfg(test)]
    async fn take_driver_exit(&mut self) -> Result<DriverExit, FoundationError> {
        let result = self.join_driver().await;
        self.command_tx.take();
        result
    }
}

impl Drop for SingleIdentityQuicManager {
    fn drop(&mut self) {
        self.command_tx.take();
        if let Some(driver_task) = self.driver_task.take() {
            driver_task.abort();
        }
    }
}

fn next_connection_generation() -> Result<ConnectionGeneration, FoundationError> {
    NEXT_CONNECTION_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
            generation.checked_add(1)
        })
        .map(ConnectionGeneration)
        .map_err(|_| FoundationError::ConnectionUnavailable)
}

fn try_send_driver_command(
    command_tx: &mpsc::Sender<DriverCommand>,
    command: DriverCommand,
) -> Result<(), FoundationError> {
    command_tx.try_send(command).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => FoundationError::CommandQueueUnavailable,
        mpsc::error::TrySendError::Closed(_) => FoundationError::DriverStopped,
    })
}

struct FoundationDriver {
    socket: UdpSocket,
    local_address: SocketAddr,
    peer_address: SocketAddr,
    connection: quiche::Connection,
    h3_config: Option<quiche::h3::Config>,
    h3_connection: Option<quiche::h3::Connection>,
    tls_observation: Option<TlsObservation>,
    observation_tx: mpsc::Sender<FoundationObservation>,
    ready_barrier: Arc<Barrier>,
    #[cfg(test)]
    pre_auth_request_trigger: Option<Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(test)]
    auth_runtime: Option<TestAuthRuntime>,
}

impl FoundationDriver {
    fn new(
        socket: UdpSocket,
        peer_address: SocketAddr,
        connection: quiche::Connection,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
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
            #[cfg(test)]
            pre_auth_request_trigger: None,
            #[cfg(test)]
            auth_runtime: None,
        })
    }

    async fn run(
        mut self,
        mut command_rx: mpsc::Receiver<DriverCommand>,
        generation: ConnectionGeneration,
    ) -> Result<DriverExit, FoundationError> {
        let result = self.run_inner(&mut command_rx, generation).await;
        #[cfg(test)]
        if result.is_err() {
            if let Some(runtime) = self.auth_runtime.as_mut() {
                runtime.fail_closed();
                if !self.connection.is_closed() {
                    let _ = self
                        .connection
                        .close(true, T026C_APPLICATION_CLOSE_CODE, b"");
                    let mut send_buffer = [0_u8; MAX_UDP_PAYLOAD_BYTES];
                    let _ = self.flush_packets(&mut send_buffer).await;
                }
            }
        }
        result
    }

    async fn run_inner(
        &mut self,
        command_rx: &mut mpsc::Receiver<DriverCommand>,
        generation: ConnectionGeneration,
    ) -> Result<DriverExit, FoundationError> {
        let handshake_started = Instant::now();
        let mut receive_buffer = [0_u8; MAX_UDP_PAYLOAD_BYTES];
        let mut send_buffer = [0_u8; MAX_UDP_PAYLOAD_BYTES];
        let mut foundation_ready = false;

        loop {
            self.initialize_h3()?;
            #[cfg(test)]
            self.send_queued_pre_auth_request()?;
            let observation_ready = self.process_h3(generation)?;
            if !foundation_ready && observation_ready {
                self.flush_packets(&mut send_buffer).await?;
                timeout(HANDSHAKE_TIMEOUT, self.ready_barrier.wait())
                    .await
                    .map_err(|_| FoundationError::DriverTimeout)?;
                foundation_ready = true;
            }
            #[cfg(test)]
            self.drive_test_auth(foundation_ready)?;
            self.flush_packets(&mut send_buffer).await?;

            #[cfg(test)]
            if let Some(outcome) = self.take_test_auth_success_outcome() {
                if !self.connection.is_closed() {
                    match self
                        .connection
                        .close(true, T026C_APPLICATION_CLOSE_CODE, b"")
                    {
                        Ok(()) | Err(quiche::Error::Done) => {}
                        Err(_) => return Err(FoundationError::ConnectionUnavailable),
                    }
                }
                self.flush_packets(&mut send_buffer).await?;
                return Ok(DriverExit {
                    reference_outcome: Some(outcome),
                });
            }

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

            if !foundation_ready {
                self.receive_packet(wait, &mut receive_buffer).await?;
                continue;
            }

            tokio::select! {
                biased;
                command = command_rx.recv() => {
                    match command {
                        Some(DriverCommand::Acquire { response }) => {
                            let _ = response.send(generation);
                        }
                        Some(DriverCommand::Close) | None => {
                            // T021b promises bounded reclamation, not a
                            // graceful QUIC drain.
                            self.connection
                                .close(true, 0, b"")
                                .map_err(|_| FoundationError::ConnectionUnavailable)?;
                            self.flush_packets(&mut send_buffer).await?;
                            return Ok(DriverExit::default());
                        }
                    }
                }
                packet = timeout(wait, self.socket.recv_from(&mut receive_buffer)) => {
                    self.process_received_packet(packet, &mut receive_buffer)?;
                }
            }
        }
    }

    async fn receive_packet(
        &mut self,
        wait: Duration,
        receive_buffer: &mut [u8; MAX_UDP_PAYLOAD_BYTES],
    ) -> Result<(), FoundationError> {
        let packet = timeout(wait, self.socket.recv_from(receive_buffer)).await;
        self.process_received_packet(packet, receive_buffer)
    }

    fn process_received_packet(
        &mut self,
        packet: Result<Result<(usize, SocketAddr), std::io::Error>, tokio::time::error::Elapsed>,
        receive_buffer: &mut [u8; MAX_UDP_PAYLOAD_BYTES],
    ) -> Result<(), FoundationError> {
        match packet {
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
        Ok(())
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
        if tls.version2() != Some(SslVersion::TLS1_3) {
            return Err(FoundationError::TlsVersionMismatch);
        }

        let legacy_label = std::str::from_utf8(TLS_CHANNEL_BINDING_EXPORTER_LABEL)
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let mut legacy_output = [0_u8; AUTH_V3_EXPORTER_LEN];
        tls.export_keying_material(&mut legacy_output, legacy_label, None)
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let channel_binding = TlsChannelBinding::new(legacy_output);

        let auth_v3_label = std::str::from_utf8(AUTH_V3_EXPORTER_LABEL)
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let mut auth_v3_output = [0_u8; AUTH_V3_EXPORTER_LEN];
        tls.export_keying_material(&mut auth_v3_output, auth_v3_label, Some(&[]))
            .map_err(|_| FoundationError::ExporterUnavailable)?;
        let auth_v3_exporter = AuthV3Exporter::new(auth_v3_output);
        let negotiated_group = negotiated_group(tls.curve_name());
        let peer_quic = peer_quic_limits(
            self.connection
                .peer_transport_params()
                .ok_or(FoundationError::ConnectionUnavailable)?,
        );
        self.tls_observation = Some(TlsObservation {
            channel_binding,
            auth_v3_exporter,
            negotiated_group,
            peer_quic,
            #[cfg(test)]
            legacy_exporter: LegacyExporter::new(legacy_output),
        });

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

    fn process_h3(&mut self, generation: ConnectionGeneration) -> Result<bool, FoundationError> {
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(false);
        };

        #[cfg(test)]
        if let Some(runtime) = self.auth_runtime.as_mut() {
            runtime.check_datagram_queue(&self.connection)?;
        }
        let event = h3_connection.poll(&mut self.connection);
        #[cfg(test)]
        if let Some(runtime) = self.auth_runtime.as_mut() {
            runtime.check_datagram_queue(&self.connection)?;
        }

        match event {
            Ok(received_event) => {
                #[cfg(test)]
                if let Some(runtime) = self.auth_runtime.as_mut() {
                    let (stream_id, event) = received_event;
                    runtime.check_datagram_queue(&self.connection)?;
                    runtime.handle_event(&mut self.connection, h3_connection, stream_id, event)?;
                    return Ok(false);
                }
                #[cfg(not(test))]
                let _ = received_event;
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Err(quiche::h3::Error::Done) => {}
            Err(_) => return Err(FoundationError::H3Unavailable),
        }

        if self.tls_observation.is_none() {
            return Ok(false);
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

        let tls_observation = self
            .tls_observation
            .take()
            .ok_or(FoundationError::ExporterUnavailable)?;
        let observation = FoundationObservation {
            generation,
            channel_binding: tls_observation.channel_binding,
            auth_v3_exporter: tls_observation.auth_v3_exporter,
            #[cfg(test)]
            legacy_exporter: tls_observation.legacy_exporter,
            negotiated_group: tls_observation.negotiated_group,
            actual_tls13: true,
            alpn_h3: true,
            early_data: false,
            peer_quic: tls_observation.peer_quic,
            peer_h3,
        };
        #[cfg(test)]
        if let Some(runtime) = self.auth_runtime.as_mut() {
            runtime.install_live_facts(observation, self.connection.server_name())?;
        }
        self.observation_tx
            .try_send(observation)
            .map_err(|_| FoundationError::ObservationQueueUnavailable)?;
        Ok(true)
    }

    #[cfg(test)]
    fn drive_test_auth(&mut self, foundation_ready: bool) -> Result<(), FoundationError> {
        let Some(runtime) = self.auth_runtime.as_mut() else {
            return Ok(());
        };
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(());
        };
        runtime.drive_outbound(&mut self.connection, h3_connection, foundation_ready)
    }

    #[cfg(test)]
    fn take_test_auth_success_outcome(&mut self) -> Option<ReferenceOutcome> {
        self.auth_runtime
            .as_mut()
            .and_then(TestAuthRuntime::take_success_outcome)
    }

    #[cfg(test)]
    fn send_queued_pre_auth_request(&mut self) -> Result<(), FoundationError> {
        let send_request = self
            .pre_auth_request_trigger
            .as_ref()
            .is_some_and(|trigger| trigger.load(Ordering::Acquire));
        if !send_request {
            return Ok(());
        }
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(());
        };
        let headers = [
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"auth.invalid"),
            quiche::h3::Header::new(b":path", b"/synthetic-h3-auth-v3"),
            quiche::h3::Header::new(b"content-type", b"application/maverick-auth-v3"),
            quiche::h3::Header::new(b"content-length", b"256"),
        ];
        match h3_connection.send_request(&mut self.connection, &headers, false) {
            Ok(stream_id) => {
                let body = [0x5a_u8; 256];
                let first = h3_connection
                    .send_body(&mut self.connection, stream_id, &body[..127], false)
                    .map_err(|_| FoundationError::H3Unavailable)?;
                let second = h3_connection
                    .send_body(&mut self.connection, stream_id, &body[first..], true)
                    .map_err(|_| FoundationError::H3Unavailable)?;
                if first != 127 || first + second != body.len() {
                    return Err(FoundationError::H3Unavailable);
                }
                self.pre_auth_request_trigger = None;
                Ok(())
            }
            Err(quiche::h3::Error::StreamBlocked) => Ok(()),
            Err(_) => Err(FoundationError::H3Unavailable),
        }
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
            let sent = timeout(
                SOCKET_IO_TIMEOUT,
                self.socket.send_to(&send_buffer[..length], info.to),
            )
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::SocketUnavailable)?;
            if sent != length {
                return Err(FoundationError::PacketUnavailable);
            }
        }
    }
}

fn bounded_quic_config() -> Result<quiche::Config, FoundationError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|_| FoundationError::ConnectionUnavailable)?;
    config.verify_peer(true);
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

#[cfg(test)]
fn bounded_self_signed_loopback_quic_config() -> Result<quiche::Config, FoundationError> {
    let mut config = bounded_quic_config()?;
    // This exception is confined to self-signed 127.0.0.1 unit tests. A
    // product trust path must keep the default peer verification above.
    config.verify_peer(false);
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
    // This is unconditional for every client and server driver created by the
    // private foundation. It must be enabled before H3 connection creation or
    // any H3 I/O; there is no configuration fallback to quiche's default.
    config.set_reject_peer_push_activity(true);
    config.set_suppress_trace_logging(true);
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
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Mutex, MutexGuard, Once};

    use maverick_core::auth_v3::{
        encode_auth_v3_client_control, encode_auth_v3_server_confirmation,
        verify_auth_v3_client_control, verify_auth_v3_server_confirmation, AuthV3Carrier,
        AuthV3ClientControlInput, AuthV3ClientReceipt, AuthV3Error, AuthV3OwnedProvisioningProfile,
        AuthV3PreselectedProfile, AuthV3ProvisioningHandle, AuthV3ServerConfirmationInput,
        AuthV3SingletonBinding, AuthV3TlsVersion, AUTH_V3_CLIENT_CONTROL_LEN,
        AUTH_V3_SERVER_CONFIRMATION_LEN,
    };
    use maverick_core::SecretString;
    use tempfile::TempDir;

    use super::*;

    const T022A_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const T022A_CONTROL_PATH: &str = "/synthetic-h3-auth-v3";
    const T022A_NOW: u64 = 1_800_000_000;
    const T022A_NOT_AFTER: u64 = T022A_NOW + 172_800;
    const TRACE_SAFE_SENTINEL: &str = "tx frm SETTINGS";
    const TRACE_REQUEST_MARKER: &str = "rq-026b2-marker";
    const TRACE_REQUEST_DEBUG_MARKER: &str =
        "[114, 113, 45, 48, 50, 54, 98, 50, 45, 109, 97, 114, 107, 101, 114]";
    const TRACE_RESPONSE_MARKER: &str = "rs-026b2-marker";
    const TRACE_RESPONSE_DEBUG_MARKER: &str =
        "[114, 115, 45, 48, 50, 54, 98, 50, 45, 109, 97, 114, 107, 101, 114]";
    const LOOPBACK_TEST_LOCK_TIMEOUT: Duration = CONNECTION_RUN_TIMEOUT;
    static LOOPBACK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static TRACE_LOGGER_INIT: Once = Once::new();
    static TRACE_CAPTURE_LOCK: Mutex<()> = Mutex::new(());
    static CAPTURE_H3_TRACE: AtomicBool = AtomicBool::new(false);
    static H3_TRACE_RECORDS: AtomicUsize = AtomicUsize::new(0);
    static QPACK_TRACE_RECORDS: AtomicUsize = AtomicUsize::new(0);
    static SAW_TRACE_SAFE_SENTINEL: AtomicBool = AtomicBool::new(false);
    static SAW_TRACE_REQUEST_MARKER: AtomicBool = AtomicBool::new(false);
    static SAW_TRACE_RESPONSE_MARKER: AtomicBool = AtomicBool::new(false);

    struct H3TraceLogger;

    impl log::Log for H3TraceLogger {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() == log::Level::Trace && metadata.target().starts_with("quiche::h3")
        }

        fn log(&self, record: &log::Record<'_>) {
            let capture = CAPTURE_H3_TRACE.load(Ordering::Acquire);
            if !capture || !self.enabled(record.metadata()) {
                return;
            }

            let message = record.args().to_string();
            H3_TRACE_RECORDS.fetch_add(1, Ordering::Relaxed);
            if record.target().contains("::qpack") {
                QPACK_TRACE_RECORDS.fetch_add(1, Ordering::Relaxed);
            }
            SAW_TRACE_SAFE_SENTINEL
                .fetch_or(message.contains(TRACE_SAFE_SENTINEL), Ordering::Relaxed);
            SAW_TRACE_REQUEST_MARKER.fetch_or(
                message.contains(TRACE_REQUEST_DEBUG_MARKER),
                Ordering::Relaxed,
            );
            SAW_TRACE_RESPONSE_MARKER.fetch_or(
                message.contains(TRACE_RESPONSE_DEBUG_MARKER),
                Ordering::Relaxed,
            );
        }

        fn flush(&self) {}
    }

    static H3_TRACE_LOGGER: H3TraceLogger = H3TraceLogger;

    struct H3TraceCaptureGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for H3TraceCaptureGuard {
        fn drop(&mut self) {
            CAPTURE_H3_TRACE.store(false, Ordering::Release);
        }
    }

    fn begin_h3_trace_capture() -> H3TraceCaptureGuard {
        let lock = TRACE_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        TRACE_LOGGER_INIT.call_once(|| {
            assert!(
                log::set_logger(&H3_TRACE_LOGGER).is_ok(),
                "install H3 trace capture logger"
            );
            log::set_max_level(log::LevelFilter::Trace);
        });
        H3_TRACE_RECORDS.store(0, Ordering::Relaxed);
        QPACK_TRACE_RECORDS.store(0, Ordering::Relaxed);
        SAW_TRACE_SAFE_SENTINEL.store(false, Ordering::Relaxed);
        SAW_TRACE_REQUEST_MARKER.store(false, Ordering::Relaxed);
        SAW_TRACE_RESPONSE_MARKER.store(false, Ordering::Relaxed);
        CAPTURE_H3_TRACE.store(true, Ordering::Release);
        H3TraceCaptureGuard { _lock: lock }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestStageError {
        DeadlineExceeded,
        SocketUnavailable,
    }

    impl fmt::Display for TestStageError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::DeadlineExceeded => "loopback test stage deadline exceeded",
                Self::SocketUnavailable => "loopback test socket unavailable",
            })
        }
    }

    impl std::error::Error for TestStageError {}

    struct LoopbackPair {
        _temp: TempDir,
        client: SingleIdentityQuicManager,
        server: SingleIdentityQuicManager,
        client_observation_rx: mpsc::Receiver<FoundationObservation>,
        server_observation_rx: mpsc::Receiver<FoundationObservation>,
        client_connections_created: Arc<AtomicUsize>,
        server_connections_created: Arc<AtomicUsize>,
        client_address: SocketAddr,
        server_address: SocketAddr,
    }

    struct ClientStartFixture<'fixture> {
        connections_created: &'fixture AtomicUsize,
        pre_auth_request_trigger: Option<Arc<AtomicBool>>,
        auth_runtime: Option<TestAuthRuntime>,
    }

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

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    fn foundation_test_session_with_h3_config(
        h3_config: &quiche::h3::Config,
    ) -> (TempDir, quiche::h3::testing::Session) {
        let temp = fixed_ok(
            TempDir::new(),
            "create strict-gate temporary certificate directory",
        );
        let cert_path = temp.path().join("cert.pem");
        let key_path = temp.path().join("key.pem");
        let certified = fixed_ok(
            rcgen::generate_simple_self_signed(vec!["localhost".into()]),
            "generate strict-gate temporary certificate",
        );
        fixed_ok(
            std::fs::write(&cert_path, certified.cert.pem()),
            "write strict-gate temporary certificate",
        );
        fixed_ok(
            std::fs::write(&key_path, certified.key_pair.serialize_pem()),
            "write strict-gate temporary key",
        );
        let mut transport = fixed_ok(
            bounded_self_signed_loopback_quic_config(),
            "build strict-gate transport configuration",
        );
        fixed_ok(
            transport.load_cert_chain_from_pem_file(fixed_some(
                cert_path.to_str(),
                "read strict-gate temporary certificate path",
            )),
            "load strict-gate temporary certificate",
        );
        fixed_ok(
            transport.load_priv_key_from_pem_file(fixed_some(
                key_path.to_str(),
                "read strict-gate temporary key path",
            )),
            "load strict-gate temporary key",
        );
        let session = fixed_ok(
            quiche::h3::testing::Session::with_configs(&mut transport, h3_config),
            "build strict-gate paired-role session",
        );
        (temp, session)
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    fn foundation_strict_test_session() -> (TempDir, quiche::h3::testing::Session) {
        let h3_config = fixed_ok(bounded_h3_config(), "build strict H3 configuration");
        foundation_test_session_with_h3_config(&h3_config)
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    fn exercise_bidirectional_synthetic_headers(session: &mut quiche::h3::testing::Session) {
        use quiche::h3::{self, Header};

        fixed_ok(session.handshake(), "handshake trace-gate session");
        let request = vec![
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"synthetic-foundation.invalid"),
            Header::new(b":path", b"/synthetic-foundation-trace"),
            Header::new(b"x-synthetic-request", TRACE_REQUEST_MARKER.as_bytes()),
        ];
        let stream_id = fixed_ok(
            session
                .client
                .send_request(&mut session.pipe.client, &request, true),
            "send synthetic request headers",
        );
        fixed_ok(session.advance(), "advance synthetic request headers");
        match fixed_ok(session.poll_server(), "poll synthetic request headers") {
            (
                received_stream_id,
                h3::Event::Headers {
                    list,
                    more_frames: false,
                },
            ) => {
                assert_eq!(received_stream_id, stream_id);
                assert_eq!(list, request);
            }
            _ => panic!("unexpected synthetic request event"),
        }

        let response = vec![
            Header::new(b":status", b"200"),
            Header::new(b"x-synthetic-response", TRACE_RESPONSE_MARKER.as_bytes()),
        ];
        fixed_ok(
            session
                .server
                .send_response(&mut session.pipe.server, stream_id, &response, true),
            "send synthetic response headers",
        );
        fixed_ok(session.advance(), "advance synthetic response headers");
        match fixed_ok(session.poll_client(), "poll synthetic response headers") {
            (
                received_stream_id,
                h3::Event::Headers {
                    list,
                    more_frames: false,
                },
            ) => {
                assert_eq!(received_stream_id, stream_id);
                assert_eq!(list, response);
            }
            _ => panic!("unexpected synthetic response event"),
        }
    }

    async fn bounded_test_lock<'lock>(
        lock: &'lock tokio::sync::Mutex<()>,
        bound: Duration,
    ) -> Result<tokio::sync::MutexGuard<'lock, ()>, TestStageError> {
        timeout(bound, lock.lock())
            .await
            .map_err(|_| TestStageError::DeadlineExceeded)
    }

    async fn bind_bounded_loopback_socket(
        address: SocketAddr,
    ) -> Result<UdpSocket, TestStageError> {
        timeout(SOCKET_IO_TIMEOUT, UdpSocket::bind(address))
            .await
            .map_err(|_| TestStageError::DeadlineExceeded)?
            .map_err(|_| TestStageError::SocketUnavailable)
    }

    fn t022a_binding() -> AuthV3SingletonBinding {
        let profile = fixed_ok(
            AuthV3OwnedProvisioningProfile::new(
                [0x11; 16],
                [0x22; 16],
                [0x33; 16],
                [0x44; 16],
                true,
                T022A_CONTROL_PATH.to_owned(),
                7,
                T022A_NOT_AFTER,
                fixed_ok(
                    SecretString::new(T022A_SECRET),
                    "construct synthetic auth-v3 secret",
                ),
            ),
            "construct synthetic auth-v3 profile",
        );
        fixed_ok(
            AuthV3SingletonBinding::new(
                fixed_ok(
                    AuthV3ProvisioningHandle::new([0x55; 16]),
                    "construct synthetic provisioning handle",
                ),
                vec![profile],
            ),
            "construct synthetic singleton auth-v3 binding",
        )
    }

    fn assert_t022a_live_facts(observation: &FoundationObservation) {
        assert!(observation.actual_tls13);
        assert!(observation.alpn_h3);
        assert!(!observation.early_data);
        assert_ne!(
            observation.negotiated_group,
            NegotiatedGroup::OtherOrUnknown
        );
        assert_eq!(
            observation.peer_quic,
            PeerQuicLimits {
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
            }
        );
        assert_eq!(
            observation.peer_h3,
            PeerH3Settings {
                max_field_section_size: Some(MAX_FIELD_SECTION_BYTES),
                qpack_max_table_capacity: Some(QPACK_MAX_TABLE_CAPACITY),
                qpack_blocked_streams: Some(QPACK_BLOCKED_STREAMS),
                extended_connect: true,
                datagram: true,
            }
        );
    }

    fn complete_t022a_auth_v3_round_trip(
        preselected: &AuthV3PreselectedProfile<'_>,
        client_observation: &FoundationObservation,
        client_exporter: &[u8; AUTH_V3_EXPORTER_LEN],
        server_observation: &FoundationObservation,
        server_exporter: &[u8; AUTH_V3_EXPORTER_LEN],
        nonce_byte: u8,
    ) -> (
        [u8; AUTH_V3_CLIENT_CONTROL_LEN],
        [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
    ) {
        assert_t022a_live_facts(client_observation);
        assert_t022a_live_facts(server_observation);

        let client_context = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            client_observation.early_data,
            client_exporter,
            true,
            Some(&[]),
            T022A_CONTROL_PATH,
        );
        let server_context = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            server_observation.early_data,
            server_exporter,
            true,
            Some(&[]),
            T022A_CONTROL_PATH,
        );
        let profile = preselected.trusted_profile();
        let control = fixed_ok(
            encode_auth_v3_client_control(
                &profile,
                &client_context,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, T022A_NOW, [nonce_byte; 32]),
            ),
            "encode same-generation H3 auth-v3 control",
        );
        assert_eq!(control.len(), AUTH_V3_CLIENT_CONTROL_LEN);
        let verified = fixed_ok(
            verify_auth_v3_client_control(
                &control,
                &preselected.trusted_profile(),
                &server_context,
                T022A_NOW,
            ),
            "verify same-generation H3 auth-v3 control",
        );
        let confirmation = fixed_ok(
            encode_auth_v3_server_confirmation(
                verified,
                &server_context,
                &AuthV3ServerConfirmationInput::new(
                    T022A_NOW,
                    T022A_NOW + 1_800,
                    T022A_NOW + 86_400,
                    [nonce_byte.wrapping_add(1); 32],
                    [nonce_byte.wrapping_add(2); 16],
                    65_536,
                    128,
                ),
            ),
            "encode same-generation H3 auth-v3 confirmation",
        );
        assert_eq!(confirmation.len(), AUTH_V3_SERVER_CONFIRMATION_LEN);
        fixed_ok(
            verify_auth_v3_server_confirmation(
                &confirmation,
                &control,
                &preselected.trusted_profile(),
                &client_context,
                &AuthV3ClientReceipt::new(T022A_NOW, 131_072, 256),
            ),
            "verify same-generation H3 auth-v3 confirmation",
        );
        (control, confirmation)
    }

    async fn start_server(
        socket: UdpSocket,
        mut config: quiche::Config,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        task_permit: OwnedSemaphorePermit,
        connections_created: &AtomicUsize,
        auth_runtime: Option<TestAuthRuntime>,
    ) -> Result<SingleIdentityQuicManager, FoundationError> {
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
        connections_created.fetch_add(1, Ordering::Relaxed);
        connection
            .recv(
                &mut first_packet[..length],
                quiche::RecvInfo {
                    from: peer_address,
                    to: local_address,
                },
            )
            .map_err(|_| FoundationError::PacketUnavailable)?;

        let mut driver = FoundationDriver::new(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
        )?;
        driver.auth_runtime = auth_runtime;
        SingleIdentityQuicManager::start(driver, task_permit)
    }

    fn start_client(
        socket: UdpSocket,
        peer_address: SocketAddr,
        mut config: quiche::Config,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        task_permit: OwnedSemaphorePermit,
        fixture: ClientStartFixture<'_>,
    ) -> Result<SingleIdentityQuicManager, FoundationError> {
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        let source_connection_id = [0x51_u8; quiche::MAX_CONN_ID_LEN];
        let source_connection_id = quiche::ConnectionId::from_ref(&source_connection_id);
        let connection = quiche::connect(
            Some(T026C_AUTHORITY),
            &source_connection_id,
            local_address,
            peer_address,
            &mut config,
        )
        .map_err(|_| FoundationError::ConnectionUnavailable)?;
        fixture.connections_created.fetch_add(1, Ordering::Relaxed);

        let mut driver = FoundationDriver::new(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
        )?;
        driver.pre_auth_request_trigger = fixture.pre_auth_request_trigger;
        driver.auth_runtime = fixture.auth_runtime;
        SingleIdentityQuicManager::start(driver, task_permit)
    }

    async fn start_loopback_pair(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
    ) -> LoopbackPair {
        start_loopback_pair_with_client_request_trigger(
            client_task_budget,
            server_task_budget,
            None,
        )
        .await
    }

    async fn start_loopback_pair_with_client_request_trigger(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
        pre_auth_request_trigger: Option<Arc<AtomicBool>>,
    ) -> LoopbackPair {
        start_loopback_pair_with_options(
            client_task_budget,
            server_task_budget,
            pre_auth_request_trigger,
            None,
            None,
        )
        .await
    }

    async fn start_t026c_loopback_pair(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
    ) -> LoopbackPair {
        start_t026c_loopback_pair_with_faults(
            client_task_budget,
            server_task_budget,
            ReferenceFault::None,
            ReferenceFault::None,
        )
        .await
    }

    async fn start_t026c_loopback_pair_with_faults(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
        client_fault: ReferenceFault,
        server_fault: ReferenceFault,
    ) -> LoopbackPair {
        start_loopback_pair_with_options(
            client_task_budget,
            server_task_budget,
            None,
            Some(fixed_ok(
                TestAuthRuntime::with_fault(TestAuthRole::Client, client_fault),
                "construct test-private H3 client auth runtime",
            )),
            Some(fixed_ok(
                TestAuthRuntime::with_fault(TestAuthRole::Server, server_fault),
                "construct test-private H3 server auth runtime",
            )),
        )
        .await
    }

    async fn start_loopback_pair_with_options(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
        pre_auth_request_trigger: Option<Arc<AtomicBool>>,
        client_auth_runtime: Option<TestAuthRuntime>,
        server_auth_runtime: Option<TestAuthRuntime>,
    ) -> LoopbackPair {
        let temp = fixed_ok(TempDir::new(), "create temporary certificate directory");
        let cert_path = temp.path().join("cert.pem");
        let key_path = temp.path().join("key.pem");
        let certified = fixed_ok(
            rcgen::generate_simple_self_signed(vec![T026C_AUTHORITY.into()]),
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
            bounded_self_signed_loopback_quic_config(),
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
            bounded_self_signed_loopback_quic_config(),
            "build bounded loopback H3 client configuration",
        );

        let server_socket = fixed_ok(
            bind_bounded_loopback_socket(SocketAddr::from(([127, 0, 0, 1], 0))).await,
            "bind bounded loopback H3 server",
        );
        let server_address = fixed_ok(server_socket.local_addr(), "read loopback H3 address");
        let client_socket = fixed_ok(
            bind_bounded_loopback_socket(SocketAddr::from(([127, 0, 0, 1], 0))).await,
            "bind bounded loopback H3 client",
        );
        let client_address = fixed_ok(client_socket.local_addr(), "read loopback client address");

        let server_permit = fixed_ok(
            server_task_budget.try_acquire(),
            "reserve loopback H3 server task",
        );
        let client_permit = fixed_ok(
            client_task_budget.try_acquire(),
            "reserve loopback H3 client task",
        );
        let ready_barrier = Arc::new(Barrier::new(2));
        let (server_tx, server_observation_rx) = mpsc::channel(OBSERVATION_QUEUE_LIMIT);
        let (client_tx, client_observation_rx) = mpsc::channel(OBSERVATION_QUEUE_LIMIT);
        let client_connections_created = Arc::new(AtomicUsize::new(0));
        let server_connections_created = Arc::new(AtomicUsize::new(0));

        let server_setup = start_server(
            server_socket,
            server_config,
            server_tx,
            Arc::clone(&ready_barrier),
            server_permit,
            &server_connections_created,
            server_auth_runtime,
        );
        let client = fixed_ok(
            start_client(
                client_socket,
                server_address,
                client_config,
                client_tx,
                ready_barrier,
                client_permit,
                ClientStartFixture {
                    connections_created: &client_connections_created,
                    pre_auth_request_trigger,
                    auth_runtime: client_auth_runtime,
                },
            ),
            "start managed loopback H3 client",
        );
        let server = fixed_ok(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, server_setup).await,
                "complete loopback H3 server setup",
            ),
            "start managed loopback H3 server",
        );

        LoopbackPair {
            _temp: temp,
            client,
            server,
            client_observation_rx,
            server_observation_rx,
            client_connections_created,
            server_connections_created,
            client_address,
            server_address,
        }
    }

    async fn receive_loopback_observations(
        pair: &mut LoopbackPair,
    ) -> (FoundationObservation, FoundationObservation) {
        let client_observation = fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, pair.client_observation_rx.recv()).await,
                "wait for loopback H3 client observation",
            ),
            "receive loopback H3 client observation",
        );
        let server_observation = fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, pair.server_observation_rx.recv()).await,
                "wait for loopback H3 server observation",
            ),
            "receive loopback H3 server observation",
        );
        (client_observation, server_observation)
    }

    async fn close_loopback_pair(pair: &mut LoopbackPair) {
        let (client_close, server_close) = tokio::join!(pair.client.close(), pair.server.close());
        fixed_ok(client_close, "close managed loopback H3 client");
        fixed_ok(server_close, "close managed loopback H3 server");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_loopback_lock_fails_within_short_local_deadline() {
        let lock = tokio::sync::Mutex::new(());
        let held_guard = fixed_ok(
            bounded_test_lock(&lock, Duration::from_millis(50)).await,
            "acquire synthetic loopback test lock",
        );
        let bounded_attempt = timeout(
            Duration::from_millis(500),
            bounded_test_lock(&lock, Duration::from_millis(20)),
        )
        .await;
        let error = match bounded_attempt {
            Ok(Err(error)) => error,
            Ok(Ok(_)) | Err(_) => panic!("bounded loopback test lock did not fail closed"),
        };
        let message_is_fixed = error.to_string() == "loopback test stage deadline exceeded";
        assert!(
            message_is_fixed,
            "bounded loopback lock error was not fixed"
        );
        assert!(std::error::Error::source(&error).is_none());
        drop(held_guard);
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    #[test]
    fn foundation_h3_builder_enables_strict_gate_for_client_and_server_roles() {
        use quiche::h3::{self, frame};

        let (_server_temp, mut server_rejects) = foundation_strict_test_session();
        fixed_ok(server_rejects.handshake(), "handshake strict server role");
        fixed_ok(
            server_rejects.send_frame_client(frame::Frame::MaxPushId { push_id: 2 }, 2, false),
            "send strict server-role peer push frame",
        );
        assert_eq!(
            server_rejects.poll_server(),
            Err(h3::Error::FrameUnexpected)
        );

        let (_client_temp, mut client_rejects) = foundation_strict_test_session();
        fixed_ok(client_rejects.handshake(), "handshake strict client role");
        fixed_ok(
            client_rejects.pipe.server.stream_send(19, &[1], false),
            "send strict client-role peer push stream",
        );
        fixed_ok(
            client_rejects.advance(),
            "advance strict client-role peer push stream",
        );
        assert_eq!(
            client_rejects.poll_client(),
            Err(h3::Error::FrameUnexpected)
        );
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    #[test]
    fn foundation_h3_builder_suppresses_all_h3_trace_for_both_roles() {
        let default_config = fixed_ok(quiche::h3::Config::new(), "build default H3 config");
        let (_default_temp, mut default_session) =
            foundation_test_session_with_h3_config(&default_config);
        let default_capture = begin_h3_trace_capture();
        exercise_bidirectional_synthetic_headers(&mut default_session);
        drop(default_capture);

        assert!(H3_TRACE_RECORDS.load(Ordering::Relaxed) > 0);
        assert!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed) > 0);
        assert!(SAW_TRACE_SAFE_SENTINEL.load(Ordering::Relaxed));
        assert!(SAW_TRACE_REQUEST_MARKER.load(Ordering::Relaxed));
        assert!(SAW_TRACE_RESPONSE_MARKER.load(Ordering::Relaxed));

        let (_foundation_temp, mut foundation_session) = foundation_strict_test_session();
        let foundation_capture = begin_h3_trace_capture();
        exercise_bidirectional_synthetic_headers(&mut foundation_session);
        drop(foundation_capture);

        assert_eq!(H3_TRACE_RECORDS.load(Ordering::Relaxed), 0);
        assert_eq!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t026c_exact_split_control_round_trip_verifies_and_closes_both_roles() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let trace_capture = begin_h3_trace_capture();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let (client_observation, server_observation) =
            receive_loopback_observations(&mut pair).await;
        assert_t022a_live_facts(&client_observation);
        assert_t022a_live_facts(&server_observation);
        assert_eq!(
            client_observation.auth_v3_exporter,
            server_observation.auth_v3_exporter
        );

        let (client_exit, server_exit) = tokio::join!(
            timeout(CONNECTION_RUN_TIMEOUT, pair.client.take_driver_exit()),
            timeout(CONNECTION_RUN_TIMEOUT, pair.server.take_driver_exit()),
        );
        let client_exit = fixed_ok(client_exit, "wait for test-private H3 client auth closure");
        let server_exit = fixed_ok(server_exit, "wait for test-private H3 server auth closure");
        assert!(
            client_exit.is_ok(),
            "client reference outcome was not successful: {client_exit:?}"
        );
        assert!(
            server_exit.is_ok(),
            "server reference outcome was not successful: {server_exit:?}"
        );
        let client_exit = fixed_ok(client_exit, "complete test-private H3 client auth closure");
        let server_exit = fixed_ok(server_exit, "complete test-private H3 server auth closure");
        let client_outcome = fixed_some(
            client_exit.reference_outcome,
            "read test-private H3 client reference outcome",
        );
        let server_outcome = fixed_some(
            server_exit.reference_outcome,
            "read test-private H3 server reference outcome",
        );
        for (outcome, role) in [
            (client_outcome, TestAuthRole::Client),
            (server_outcome, TestAuthRole::Server),
        ] {
            assert_eq!(outcome.role, role);
            assert_eq!(outcome.slot_claims, 1);
            assert_eq!(outcome.sent_body_chunks, 2);
            assert!(outcome.received_data_events >= 2);
            assert_eq!(outcome.request_bytes, AUTH_V3_CLIENT_CONTROL_LEN);
            assert_eq!(outcome.response_bytes, AUTH_V3_SERVER_CONFIRMATION_LEN);
            assert!(outcome.datagram_checks >= 2);
            assert_eq!(
                format!("{outcome:?}"),
                "test-private auth-v3 reference outcome"
            );
        }
        drop(trace_capture);
        assert_eq!(H3_TRACE_RECORDS.load(Ordering::Relaxed), 0);
        assert_eq!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed), 0);
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);

        let client_address = pair.client_address;
        let server_address = pair.server_address;
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim test-private H3 client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(server_address).await,
            "reclaim test-private H3 server socket",
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t026c_real_fail_closed_matrix_has_zero_h3_or_qpack_trace() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let trace_capture = begin_h3_trace_capture();
        let cases = [
            (ReferenceFault::MalformedClientControl, ReferenceFault::None),
            (ReferenceFault::WrongClientMac, ReferenceFault::None),
            (ReferenceFault::WrongClientExporter, ReferenceFault::None),
            (ReferenceFault::WrongClientProfile, ReferenceFault::None),
            (ReferenceFault::WrongClientPolicy, ReferenceFault::None),
            (ReferenceFault::DuplicateControl, ReferenceFault::None),
            (ReferenceFault::PreAuthDatagram, ReferenceFault::None),
            (
                ReferenceFault::None,
                ReferenceFault::WrongServerConfirmation,
            ),
        ];

        for (client_fault, server_fault) in cases {
            let task_budget = ConnectionTaskBudget::new();
            let mut pair = start_t026c_loopback_pair_with_faults(
                &task_budget,
                &task_budget,
                client_fault,
                server_fault,
            )
            .await;
            let (client_observation, server_observation) =
                receive_loopback_observations(&mut pair).await;
            assert_t022a_live_facts(&client_observation);
            assert_t022a_live_facts(&server_observation);

            let (client_exit, server_exit) = tokio::join!(
                timeout(CONNECTION_RUN_TIMEOUT, pair.client.take_driver_exit()),
                timeout(CONNECTION_RUN_TIMEOUT, pair.server.take_driver_exit()),
            );
            let client_exit = fixed_ok(client_exit, "wait for rejected H3 client generation");
            let server_exit = fixed_ok(server_exit, "wait for rejected H3 server generation");
            if server_fault == ReferenceFault::WrongServerConfirmation {
                let server_outcome = fixed_some(
                    fixed_ok(server_exit, "complete server confirmation send boundary")
                        .reference_outcome,
                    "read server confirmation send outcome",
                );
                assert_eq!(server_outcome.role, TestAuthRole::Server);
                assert_eq!(
                    server_outcome.response_bytes,
                    AUTH_V3_SERVER_CONFIRMATION_LEN
                );
                assert!(client_exit.is_err());
            } else {
                assert_eq!(
                    server_exit.err(),
                    Some(FoundationError::PreAuthApplicationActivity)
                );
                assert!(client_exit.is_err());
            }

            assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
            assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
            let client_address = pair.client_address;
            let server_address = pair.server_address;
            drop(pair);
            assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
            drop(fixed_ok(
                bind_bounded_loopback_socket(client_address).await,
                "reclaim rejected H3 client socket",
            ));
            drop(fixed_ok(
                bind_bounded_loopback_socket(server_address).await,
                "reclaim rejected H3 server socket",
            ));
        }

        drop(trace_capture);
        assert_eq!(H3_TRACE_RECORDS.load(Ordering::Relaxed), 0);
        assert_eq!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn t026c_exact_header_and_body_admission_matrix_fails_closed() {
        fn owned_headers(pairs: &[(&[u8], &[u8])]) -> Vec<quiche::h3::Header> {
            pairs
                .iter()
                .map(|(name, value)| quiche::h3::Header::new(name, value))
                .collect()
        }

        let request_pairs = request_header_pairs();
        let request = owned_headers(&request_pairs);
        assert!(valid_request_headers(&request));

        let replacements: [(usize, &[u8], &[u8]); 8] = [
            (0, b":method", b"GET"),
            (1, b":scheme", b"http"),
            (2, b":authority", b"other.invalid"),
            (2, b"host", T026C_AUTHORITY.as_bytes()),
            (3, b":path", b"/synthetic-h3-auth-v3?"),
            (4, b"content-type", b"Application/Maverick-Auth-V3"),
            (5, b"content-length", b"0256"),
            (3, b":protocol", b"connect-udp"),
        ];
        for (index, name, value) in replacements {
            let mut invalid = request.clone();
            invalid[index] = quiche::h3::Header::new(name, value);
            assert!(!valid_request_headers(&invalid));
        }

        let mut reordered = request.clone();
        reordered.swap(3, 4);
        assert!(!valid_request_headers(&reordered));
        let mut duplicated = request.clone();
        duplicated[5] = quiche::h3::Header::new(request_pairs[4].0, request_pairs[4].1);
        assert!(!valid_request_headers(&duplicated));
        let mut unknown = request.clone();
        unknown.push(quiche::h3::Header::new(b"x-unknown", b"1"));
        assert!(!valid_request_headers(&unknown));
        assert!(!valid_request_headers(&request[..5]));

        let response_pairs = response_header_pairs();
        let response = owned_headers(&response_pairs);
        assert!(valid_response_headers(&response));
        for (index, name, value) in [
            (0, b":status".as_slice(), b"204".as_slice()),
            (
                1,
                b"content-type".as_slice(),
                b"application/octet-stream".as_slice(),
            ),
            (2, b"content-length".as_slice(), b"0320".as_slice()),
        ] {
            let mut invalid = response.clone();
            invalid[index] = quiche::h3::Header::new(name, value);
            assert!(!valid_response_headers(&invalid));
        }
        let mut response_reordered = response.clone();
        response_reordered.swap(0, 1);
        assert!(!valid_response_headers(&response_reordered));
        let mut response_extra = response.clone();
        response_extra.push(quiche::h3::Header::new(b"x-unknown", b"1"));
        assert!(!valid_response_headers(&response_extra));

        assert_eq!(bounded_body_progress(0, 113, 256), Ok(113));
        assert_eq!(bounded_body_progress(113, 143, 256), Ok(256));
        assert_eq!(exact_body_finished(256, 256), Ok(()));
        assert_eq!(
            exact_body_finished(255, 256),
            Err(FoundationError::PreAuthApplicationActivity)
        );
        assert_eq!(
            bounded_body_progress(0, 257, 256),
            Err(FoundationError::PreAuthApplicationActivity)
        );
        assert_eq!(
            bounded_body_progress(256, 1, 256),
            Err(FoundationError::PreAuthApplicationActivity)
        );
        assert_eq!(
            bounded_body_progress(0, 0, 256),
            Err(FoundationError::PreAuthApplicationActivity)
        );
    }

    #[test]
    fn t026c_auth_bytes_reject_wrong_carrier_exporter_generation_and_replay() {
        let binding = t022a_binding();
        let preselected = binding.preselected_profile();
        let exporter_a = [0x71_u8; AUTH_V3_EXPORTER_LEN];
        let exporter_b = [0x72_u8; AUTH_V3_EXPORTER_LEN];
        let h3_context_a = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter_a,
            true,
            Some(&[]),
            T022A_CONTROL_PATH,
        );
        let h3_context_b = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter_b,
            true,
            Some(&[]),
            T022A_CONTROL_PATH,
        );
        let h2_context = preselected.trusted_connection_context(
            AuthV3Carrier::H2,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter_a,
            true,
            Some(&[]),
            T022A_CONTROL_PATH,
        );
        let control_a = fixed_ok(
            encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &h3_context_a,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, T022A_NOW, [0x11; 32]),
            ),
            "encode first reference control",
        );
        let control_b = fixed_ok(
            encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &h3_context_a,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, T022A_NOW, [0x12; 32]),
            ),
            "encode second reference control",
        );
        let h2_control = fixed_ok(
            encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &h2_context,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H2, T022A_NOW, [0x13; 32]),
            ),
            "encode wrong-carrier control",
        );
        assert_eq!(
            verify_auth_v3_client_control(
                &h2_control,
                &preselected.trusted_profile(),
                &h3_context_a,
                T022A_NOW,
            )
            .err(),
            Some(AuthV3Error::Context)
        );
        assert_eq!(
            verify_auth_v3_client_control(
                &control_a,
                &preselected.trusted_profile(),
                &h3_context_b,
                T022A_NOW,
            )
            .err(),
            Some(AuthV3Error::Mac)
        );

        let verified = fixed_ok(
            verify_auth_v3_client_control(
                &control_a,
                &preselected.trusted_profile(),
                &h3_context_a,
                T022A_NOW,
            ),
            "verify first reference control",
        );
        let confirmation = fixed_ok(
            encode_auth_v3_server_confirmation(
                verified,
                &h3_context_a,
                &AuthV3ServerConfirmationInput::new(
                    T022A_NOW,
                    T022A_NOW + 1_800,
                    T022A_NOW + 86_400,
                    [0x21; 32],
                    [0x22; 16],
                    65_536,
                    128,
                ),
            ),
            "encode first reference confirmation",
        );
        let receipt = AuthV3ClientReceipt::new(T022A_NOW, 131_072, 256);
        assert!(matches!(
            verify_auth_v3_server_confirmation(
                &confirmation,
                &control_b,
                &preselected.trusted_profile(),
                &h3_context_a,
                &receipt,
            ),
            Err(AuthV3Error::Commitment | AuthV3Error::Mac)
        ));
        assert_eq!(
            verify_auth_v3_server_confirmation(
                &confirmation,
                &control_a,
                &preselected.trusted_profile(),
                &h3_context_b,
                &receipt,
            )
            .err(),
            Some(AuthV3Error::Mac)
        );
        let mut wrong_confirmation = confirmation;
        wrong_confirmation[319] ^= 0x80;
        assert_eq!(
            verify_auth_v3_server_confirmation(
                &wrong_confirmation,
                &control_a,
                &preselected.trusted_profile(),
                &h3_context_a,
                &receipt,
            )
            .err(),
            Some(AuthV3Error::Mac)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_control_post_is_red_as_pre_auth_application_activity() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let client_task_budget = ConnectionTaskBudget::new();
        let server_task_budget = ConnectionTaskBudget::new();
        let request_trigger = Arc::new(AtomicBool::new(false));
        let mut pair = start_loopback_pair_with_client_request_trigger(
            &client_task_budget,
            &server_task_budget,
            Some(Arc::clone(&request_trigger)),
        )
        .await;
        let (client_observation, server_observation) =
            receive_loopback_observations(&mut pair).await;
        assert_t022a_live_facts(&client_observation);
        assert_t022a_live_facts(&server_observation);
        assert!(matches!(
            pair.server_observation_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let server_generation = server_observation.generation;
        let server_lease = fixed_ok(
            pair.server.acquire().await,
            "acquire observed pre-auth server generation",
        );
        assert_eq!(server_lease.generation(), server_generation);
        server_lease.release();
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);

        request_trigger.store(true, Ordering::Release);
        let client_lease = fixed_ok(
            pair.client.acquire().await,
            "wake client driver for post-observation request",
        );
        client_lease.release();
        let server_result = fixed_ok(
            timeout(CONNECTION_RUN_TIMEOUT, pair.server.join_driver()).await,
            "wait for pre-auth H3 activity rejection",
        );

        assert_eq!(
            server_result,
            Err(FoundationError::PreAuthApplicationActivity)
        );
        assert_eq!(pair.server_observation_rx.recv().await, None);
        assert_eq!(
            pair.server.acquire().await.err(),
            Some(FoundationError::DriverStopped)
        );
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);

        let client_address = pair.client_address;
        let server_address = pair.server_address;
        drop(pair);
        let client_permits = fixed_ok(
            timeout(
                DRIVER_JOIN_TIMEOUT,
                client_task_budget
                    .permits
                    .clone()
                    .acquire_many_owned(CONNECTION_TASK_LIMIT as u32),
            )
            .await,
            "reclaim rejected-generation client task budget",
        );
        let client_permits = fixed_ok(
            client_permits,
            "hold reclaimed rejected-generation client task budget",
        );
        drop(client_permits);
        assert_eq!(
            client_task_budget.available_permits(),
            CONNECTION_TASK_LIMIT
        );
        assert_eq!(
            server_task_budget.available_permits(),
            CONNECTION_TASK_LIMIT
        );
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim rejected-generation client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(server_address).await,
            "reclaim rejected-generation server socket",
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_h3_loopback_proves_tls_settings_bounds_and_shutdown() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_loopback_pair(&task_budget, &task_budget).await;
        let (client_observation, server_observation) =
            receive_loopback_observations(&mut pair).await;
        let first_lease = fixed_ok(
            pair.client.acquire().await,
            "acquire first single-identity H3 lease",
        );
        let generation = first_lease.generation();
        assert_eq!(client_observation.generation, generation);
        fixed_ok(
            client_observation.auth_v3_exporter_for(&first_lease),
            "bind client exporter observation to first lease",
        );
        assert_eq!(
            pair.client.acquire().await.err(),
            Some(FoundationError::LeaseUnavailable)
        );
        first_lease.release();
        let second_lease = fixed_ok(
            pair.client.acquire().await,
            "acquire reused single-identity H3 lease",
        );
        assert_eq!(second_lease.generation(), generation);
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        second_lease.release();
        let server_lease = fixed_ok(
            pair.server.acquire().await,
            "acquire single-identity H3 server lease",
        );
        assert_eq!(server_observation.generation, server_lease.generation());
        fixed_ok(
            server_observation.auth_v3_exporter_for(&server_lease),
            "bind server exporter observation to lease",
        );
        server_lease.release();

        let client_sender = fixed_some(
            pair.client.command_tx.as_ref(),
            "read managed client command sender",
        )
        .downgrade();
        let server_sender = fixed_some(
            pair.server.command_tx.as_ref(),
            "read managed server command sender",
        )
        .downgrade();
        close_loopback_pair(&mut pair).await;

        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        assert!(client_sender.upgrade().is_none());
        assert!(server_sender.upgrade().is_none());
        assert_eq!(
            pair.client.acquire().await.err(),
            Some(FoundationError::ManagerClosed)
        );
        drop(fixed_ok(
            bind_bounded_loopback_socket(pair.client_address).await,
            "reclaim managed loopback H3 client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(pair.server_address).await,
            "reclaim managed loopback H3 server socket",
        ));

        let legacy_bindings_match =
            client_observation.channel_binding == server_observation.channel_binding;
        assert!(legacy_bindings_match, "loopback legacy exporter mismatch");
        let auth_v3_exporters_match =
            client_observation.auth_v3_exporter == server_observation.auth_v3_exporter;
        assert!(
            auth_v3_exporters_match,
            "loopback auth-v3 exporter mismatch"
        );
        let legacy_exporters_match =
            client_observation.legacy_exporter == server_observation.legacy_exporter;
        assert!(
            legacy_exporters_match,
            "loopback legacy exporter provenance mismatch"
        );
        let exporter_labels_are_separated = client_observation.auth_v3_exporter.as_bytes()
            != client_observation.legacy_exporter.as_bytes();
        assert!(
            exporter_labels_are_separated,
            "loopback exporter labels were not separated"
        );
        assert!(client_observation.actual_tls13 && server_observation.actual_tls13);
        assert!(client_observation.alpn_h3 && server_observation.alpn_h3);
        assert!(!client_observation.early_data && !server_observation.early_data);
        assert_ne!(
            client_observation.negotiated_group,
            NegotiatedGroup::OtherOrUnknown
        );
        assert_eq!(
            client_observation.negotiated_group,
            server_observation.negotiated_group
        );
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
        assert_eq!(client_observation.peer_quic, expected_quic);
        assert_eq!(server_observation.peer_quic, expected_quic);
        let expected_settings = PeerH3Settings {
            max_field_section_size: Some(MAX_FIELD_SECTION_BYTES),
            qpack_max_table_capacity: Some(QPACK_MAX_TABLE_CAPACITY),
            qpack_blocked_streams: Some(QPACK_BLOCKED_STREAMS),
            extended_connect: true,
            datagram: true,
        };
        assert_eq!(client_observation.peer_h3, expected_settings);
        assert_eq!(server_observation.peer_h3, expected_settings);

        assert_eq!(MAX_UDP_PAYLOAD_BYTES, 1_350);
        assert_eq!(SEND_CAPACITY_FACTOR, 1.0);
        assert_eq!(COMMAND_QUEUE_LIMIT, 1);
        assert_eq!(CONNECTION_LEASE_LIMIT, 1);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_drop_cancels_driver_and_reclaims_owned_resources() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let client_task_budget = ConnectionTaskBudget::new();
        let server_task_budget = ConnectionTaskBudget::new();
        let mut pair = start_loopback_pair(&client_task_budget, &server_task_budget).await;
        fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, pair.client_observation_rx.recv()).await,
                "wait for managed H3 client readiness",
            ),
            "receive managed H3 client readiness",
        );
        fixed_some(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, pair.server_observation_rx.recv()).await,
                "wait for managed H3 server readiness",
            ),
            "receive managed H3 server readiness",
        );

        let mut remaining_permits = Vec::with_capacity(CONNECTION_TASK_LIMIT - 1);
        for _ in 1..CONNECTION_TASK_LIMIT {
            remaining_permits.push(fixed_ok(
                client_task_budget.try_acquire(),
                "reserve remaining client task capacity",
            ));
        }
        let client_sender = fixed_some(
            pair.client.command_tx.as_ref(),
            "read managed client command sender",
        )
        .downgrade();
        let client_address = pair.client_address;
        drop(pair.client);

        let reclaimed_permit = fixed_ok(
            timeout(
                DRIVER_JOIN_TIMEOUT,
                client_task_budget.permits.clone().acquire_owned(),
            )
            .await,
            "reclaim dropped manager task permit",
        );
        let reclaimed_permit = fixed_ok(reclaimed_permit, "hold reclaimed manager task permit");
        assert!(client_sender.upgrade().is_none());
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim dropped manager socket",
        ));

        fixed_ok(pair.server.close().await, "close drop-test H3 server");
        drop(reclaimed_permit);
        drop(remaining_permits);
        assert_eq!(
            client_task_budget.available_permits(),
            CONNECTION_TASK_LIMIT
        );
        assert_eq!(
            server_task_budget.available_permits(),
            CONNECTION_TASK_LIMIT
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t022a_live_auth_v3_round_trip_is_bound_to_manager_generation() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_loopback_pair(&task_budget, &task_budget).await;
        let (client_observation, server_observation) =
            receive_loopback_observations(&mut pair).await;
        let client_lease = fixed_ok(
            pair.client.acquire().await,
            "acquire T022a client generation lease",
        );
        let server_lease = fixed_ok(
            pair.server.acquire().await,
            "acquire T022a server generation lease",
        );
        assert_eq!(client_observation.generation, client_lease.generation());
        assert_eq!(server_observation.generation, server_lease.generation());
        assert_ne!(client_lease.generation(), server_lease.generation());
        let auth_v3_exporters_match =
            client_observation.auth_v3_exporter == server_observation.auth_v3_exporter;
        assert!(
            auth_v3_exporters_match,
            "T022a same-generation exporter mismatch"
        );
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);

        let binding = t022a_binding();
        let preselected = binding.preselected_profile();
        {
            let client_exporter = fixed_ok(
                client_observation.auth_v3_exporter_for(&client_lease),
                "bind T022a client exporter to manager generation",
            );
            let server_exporter = fixed_ok(
                server_observation.auth_v3_exporter_for(&server_lease),
                "bind T022a server exporter to manager generation",
            );
            complete_t022a_auth_v3_round_trip(
                &preselected,
                &client_observation,
                client_exporter.as_bytes(),
                &server_observation,
                server_exporter.as_bytes(),
                0x41,
            );
        }
        client_lease.release();
        server_lease.release();
        close_loopback_pair(&mut pair).await;
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t022a_replacement_generation_reauthenticates_and_rejects_old_control() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let binding = t022a_binding();
        let preselected = binding.preselected_profile();

        let mut first_pair = start_loopback_pair(&task_budget, &task_budget).await;
        let (first_client_observation, first_server_observation) =
            receive_loopback_observations(&mut first_pair).await;
        let first_client_lease = fixed_ok(
            first_pair.client.acquire().await,
            "acquire first T022a client generation",
        );
        let first_server_lease = fixed_ok(
            first_pair.server.acquire().await,
            "acquire first T022a server generation",
        );
        let first_client_generation = first_client_lease.generation();
        let first_server_generation = first_server_lease.generation();
        let (first_control, first_confirmation) = {
            let client_exporter = fixed_ok(
                first_client_observation.auth_v3_exporter_for(&first_client_lease),
                "bind first T022a client exporter",
            );
            let server_exporter = fixed_ok(
                first_server_observation.auth_v3_exporter_for(&first_server_lease),
                "bind first T022a server exporter",
            );
            complete_t022a_auth_v3_round_trip(
                &preselected,
                &first_client_observation,
                client_exporter.as_bytes(),
                &first_server_observation,
                server_exporter.as_bytes(),
                0x51,
            )
        };
        first_client_lease.release();
        first_server_lease.release();
        close_loopback_pair(&mut first_pair).await;

        let mut second_pair = start_loopback_pair(&task_budget, &task_budget).await;
        let (second_client_observation, second_server_observation) =
            receive_loopback_observations(&mut second_pair).await;
        let second_client_lease = fixed_ok(
            second_pair.client.acquire().await,
            "acquire replacement T022a client generation",
        );
        let second_server_lease = fixed_ok(
            second_pair.server.acquire().await,
            "acquire replacement T022a server generation",
        );
        assert_ne!(second_client_lease.generation(), first_client_generation);
        assert_ne!(second_server_lease.generation(), first_server_generation);
        let wrong_client_generation_rejected = matches!(
            first_client_observation.auth_v3_exporter_for(&second_client_lease),
            Err(FoundationError::GenerationMismatch)
        );
        assert!(
            wrong_client_generation_rejected,
            "replacement client generation accepted an old exporter observation"
        );
        let wrong_server_generation_rejected = matches!(
            first_server_observation.auth_v3_exporter_for(&second_server_lease),
            Err(FoundationError::GenerationMismatch)
        );
        assert!(
            wrong_server_generation_rejected,
            "replacement server generation accepted an old exporter observation"
        );

        {
            let second_client_exporter = fixed_ok(
                second_client_observation.auth_v3_exporter_for(&second_client_lease),
                "bind replacement T022a client exporter",
            );
            let second_server_exporter = fixed_ok(
                second_server_observation.auth_v3_exporter_for(&second_server_lease),
                "bind replacement T022a server exporter",
            );
            let replacement_server_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                second_server_observation.early_data,
                second_server_exporter.as_bytes(),
                true,
                Some(&[]),
                T022A_CONTROL_PATH,
            );
            assert_eq!(
                verify_auth_v3_client_control(
                    &first_control,
                    &preselected.trusted_profile(),
                    &replacement_server_context,
                    T022A_NOW,
                )
                .err(),
                Some(AuthV3Error::Mac)
            );
            let (second_control, _) = complete_t022a_auth_v3_round_trip(
                &preselected,
                &second_client_observation,
                second_client_exporter.as_bytes(),
                &second_server_observation,
                second_server_exporter.as_bytes(),
                0x61,
            );
            let replacement_client_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                second_client_observation.early_data,
                second_client_exporter.as_bytes(),
                true,
                Some(&[]),
                T022A_CONTROL_PATH,
            );
            assert!(matches!(
                verify_auth_v3_server_confirmation(
                    &first_confirmation,
                    &second_control,
                    &preselected.trusted_profile(),
                    &replacement_client_context,
                    &AuthV3ClientReceipt::new(T022A_NOW, 131_072, 256),
                ),
                Err(AuthV3Error::Commitment | AuthV3Error::Mac)
            ));
        }
        assert_eq!(
            first_pair
                .client_connections_created
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            second_pair
                .client_connections_created
                .load(Ordering::Relaxed),
            1
        );
        second_client_lease.release();
        second_server_lease.release();
        close_loopback_pair(&mut second_pair).await;
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t022a_exporter_provenance_context_and_debug_fail_closed() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_loopback_pair(&task_budget, &task_budget).await;
        let (client_observation, server_observation) =
            receive_loopback_observations(&mut pair).await;
        let client_lease = fixed_ok(
            pair.client.acquire().await,
            "acquire provenance-test T022a client generation",
        );
        let server_lease = fixed_ok(
            pair.server.acquire().await,
            "acquire provenance-test T022a server generation",
        );
        let binding = t022a_binding();
        let preselected = binding.preselected_profile();

        {
            let client_exporter = fixed_ok(
                client_observation.auth_v3_exporter_for(&client_lease),
                "bind provenance-test T022a client exporter",
            );
            let server_exporter = fixed_ok(
                server_observation.auth_v3_exporter_for(&server_lease),
                "bind provenance-test T022a server exporter",
            );
            let (control, _) = complete_t022a_auth_v3_round_trip(
                &preselected,
                &client_observation,
                client_exporter.as_bytes(),
                &server_observation,
                server_exporter.as_bytes(),
                0x71,
            );

            let exporter_labels_differ =
                TLS_CHANNEL_BINDING_EXPORTER_LABEL != AUTH_V3_EXPORTER_LABEL;
            assert!(
                exporter_labels_differ,
                "T022a exporter labels unexpectedly match"
            );
            let legacy_exporters_match =
                client_observation.legacy_exporter == server_observation.legacy_exporter;
            assert!(legacy_exporters_match, "T022a legacy exporter mismatch");
            let legacy_and_auth_v3_differ =
                server_observation.legacy_exporter.as_bytes() != server_exporter.as_bytes();
            assert!(
                legacy_and_auth_v3_differ,
                "T022a legacy and auth-v3 exporters unexpectedly match"
            );
            let legacy_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                server_observation.legacy_exporter.as_bytes(),
                true,
                Some(&[]),
                T022A_CONTROL_PATH,
            );
            assert_eq!(
                verify_auth_v3_client_control(
                    &control,
                    &preselected.trusted_profile(),
                    &legacy_context,
                    T022A_NOW,
                )
                .err(),
                Some(AuthV3Error::Mac)
            );

            let mut wrong_exporter = *server_exporter.as_bytes();
            wrong_exporter[0] ^= 0x80;
            let wrong_exporter_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                &wrong_exporter,
                true,
                Some(&[]),
                T022A_CONTROL_PATH,
            );
            assert_eq!(
                verify_auth_v3_client_control(
                    &control,
                    &preselected.trusted_profile(),
                    &wrong_exporter_context,
                    T022A_NOW,
                )
                .err(),
                Some(AuthV3Error::Mac)
            );

            let wrong_generation_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                server_exporter.as_bytes(),
                false,
                Some(&[]),
                T022A_CONTROL_PATH,
            );
            assert_eq!(
                verify_auth_v3_client_control(
                    &control,
                    &preselected.trusted_profile(),
                    &wrong_generation_context,
                    T022A_NOW,
                )
                .err(),
                Some(AuthV3Error::Context)
            );

            let absent_context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                server_exporter.as_bytes(),
                true,
                None,
                T022A_CONTROL_PATH,
            );
            assert_eq!(
                verify_auth_v3_client_control(
                    &control,
                    &preselected.trusted_profile(),
                    &absent_context,
                    T022A_NOW,
                )
                .err(),
                Some(AuthV3Error::Context)
            );
        }

        let first_auth_debug = format!("{:?}", AuthV3Exporter::new([0x81; AUTH_V3_EXPORTER_LEN]));
        let second_auth_debug = format!("{:?}", AuthV3Exporter::new([0x82; AUTH_V3_EXPORTER_LEN]));
        let auth_debug_is_fixed_and_redacted = first_auth_debug == "redacted auth-v3 exporter"
            && second_auth_debug == "redacted auth-v3 exporter"
            && first_auth_debug == second_auth_debug;
        assert!(
            auth_debug_is_fixed_and_redacted,
            "auth-v3 exporter Debug was not fixed and redacted"
        );
        let legacy_debug = format!("{:?}", LegacyExporter::new([0x83; AUTH_V3_EXPORTER_LEN]));
        assert!(
            legacy_debug == "redacted legacy exporter",
            "legacy exporter Debug was not fixed and redacted"
        );
        client_lease.release();
        server_lease.release();
        close_loopback_pair(&mut pair).await;
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test]
    async fn observation_channel_and_task_budget_fail_closed_at_capacity() {
        let observation = FoundationObservation {
            generation: ConnectionGeneration(1),
            channel_binding: TlsChannelBinding::new([0_u8; 32]),
            auth_v3_exporter: AuthV3Exporter::new([0_u8; AUTH_V3_EXPORTER_LEN]),
            legacy_exporter: LegacyExporter::new([0_u8; AUTH_V3_EXPORTER_LEN]),
            negotiated_group: NegotiatedGroup::X25519,
            actual_tls13: true,
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
        let received_observation_matches = rx.recv().await == Some(observation);
        assert!(
            received_observation_matches,
            "bounded observation contents mismatch"
        );

        let (command_tx, _command_rx) = mpsc::channel(COMMAND_QUEUE_LIMIT);
        fixed_ok(
            try_send_driver_command(&command_tx, DriverCommand::Close),
            "fill bounded manager command queue",
        );
        assert_eq!(
            try_send_driver_command(&command_tx, DriverCommand::Close).err(),
            Some(FoundationError::CommandQueueUnavailable)
        );

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
                FoundationError::CommandQueueUnavailable,
                "native H3 command queue unavailable",
            ),
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
                FoundationError::GenerationMismatch,
                "native H3 generation mismatch",
            ),
            (
                FoundationError::H3Unavailable,
                "native H3 connection unavailable",
            ),
            (
                FoundationError::LeaseUnavailable,
                "native H3 lease unavailable",
            ),
            (FoundationError::ManagerClosed, "native H3 manager closed"),
            (
                FoundationError::ObservationQueueUnavailable,
                "native H3 observation queue unavailable",
            ),
            (
                FoundationError::PacketUnavailable,
                "native H3 packet unavailable",
            ),
            (
                FoundationError::PreAuthApplicationActivity,
                "native H3 pre-auth activity rejected",
            ),
            (
                FoundationError::SocketUnavailable,
                "native H3 socket unavailable",
            ),
            (
                FoundationError::TaskBudgetUnavailable,
                "native H3 task budget unavailable",
            ),
            (
                FoundationError::TlsVersionMismatch,
                "native H3 TLS version mismatch",
            ),
        ];

        for (error, expected) in cases {
            let message = error.to_string();
            assert_eq!(message, expected);
            assert!(std::error::Error::source(&error).is_none());
            let debug = format!("{error:?}");
            for rendered in [&message, &debug] {
                assert!(rendered.len() <= 48);
                for forbidden in [
                    "127.0.0.1",
                    "localhost",
                    "example.invalid",
                    T026C_AUTHORITY,
                    T026C_CONTROL_PATH,
                    "POST",
                    "https",
                    "content-type",
                    "application/maverick-auth-v3",
                    "MVA3",
                    "mv1_",
                    "/",
                ] {
                    assert!(!rendered.contains(forbidden));
                }
            }
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
