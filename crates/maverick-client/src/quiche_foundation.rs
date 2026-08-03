//! Private, feature-gated direct-quiche foundation.
//!
//! `quiche` owns QUIC, TLS, and HTTP/3. This module drives one UDP socket and
//! one connection with Tokio behind a fixed-capacity private manager command
//! queue. It has no connection router, and no quiche, BoringSSL, or TLS type
//! leaves this private module.

use std::fmt;
#[cfg(test)]
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::ssl::{SslRef, SslVersion};
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use maverick_core::auth_v3::{AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Barrier, Notify, OwnedSemaphorePermit, Semaphore};
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
const AUTHENTICATED_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(15);
const DRIVER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(2);
const AUTH_FAILURE_CLOSE_CODE: u64 = 0x100;

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
    #[cfg(test)]
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

mod generation_auth {
    use maverick_core::auth_v3::{
        encode_auth_v3_client_control, encode_auth_v3_server_confirmation,
        verify_auth_v3_client_control, verify_auth_v3_server_confirmation, AuthV3Carrier,
        AuthV3ClientControlInput, AuthV3ClientReceipt, AuthV3PreselectedProfile,
        AuthV3ServerConfirmationInput, AuthV3TlsVersion, VerifiedAuthV3ServerConfirmation,
        AUTH_V3_CLIENT_CONTROL_LEN, AUTH_V3_SERVER_CONFIRMATION_LEN,
    };
    use maverick_core::config::{ClientRoleConfig, DirectV3TransportStrategy, ServerRoleConfig};
    use quiche::h3::NameValue;
    use rand::{rngs::OsRng, TryRngCore};

    use super::*;

    #[cfg(test)]
    const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    #[cfg(test)]
    const TEST_NOT_AFTER: u64 = T026C_NOW + 172_800;
    #[cfg(test)]
    const TEST_HANDLE: &str = "VVVVVVVVVVVVVVVVVVVVVQ";
    #[cfg(test)]
    const TEST_PRINCIPAL: &str = "EREREREREREREREREREREQ";
    #[cfg(test)]
    const TEST_DEPLOYMENT: &str = "IiIiIiIiIiIiIiIiIiIiIg";
    #[cfg(test)]
    const TEST_NAMESPACE: &str = "MzMzMzMzMzMzMzMzMzMzMw";
    #[cfg(test)]
    const TEST_SERVER_ID: &str = "RERERERERERERERERERERA";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum AuthRole {
        Client,
        Server,
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ReferenceFault {
        None,
        MalformedClientControl,
        WrongClientMac,
        WrongClientExporter,
        WrongClientProfile,
        WrongClientPolicy,
        WrongClientReceipt,
        WrongServerConfirmation,
        DuplicateControl,
        PreAuthDatagram,
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) struct ReferenceOutcome {
        pub(super) role: AuthRole,
        pub(super) slot_claims: u8,
        pub(super) sent_body_chunks: u8,
        pub(super) received_data_events: u8,
        pub(super) request_bytes: usize,
        pub(super) response_bytes: usize,
        pub(super) datagram_checks: u16,
    }

    #[cfg(test)]
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
        Failed,
    }

    pub(super) struct BodySendState<const CAPACITY: usize> {
        bytes: [u8; CAPACITY],
        length: usize,
        stream_id: u64,
        offset: usize,
        chunk_end: usize,
        split_at: usize,
        #[cfg(test)]
        completed_chunks: u8,
    }

    impl<const CAPACITY: usize> BodySendState<CAPACITY> {
        fn new(bytes: [u8; CAPACITY], stream_id: u64, split_at: usize) -> Self {
            Self {
                bytes,
                length: CAPACITY,
                stream_id,
                offset: 0,
                chunk_end: split_at,
                split_at,
                #[cfg(test)]
                completed_chunks: 0,
            }
        }

        pub(super) fn bounded(
            bytes: [u8; CAPACITY],
            length: usize,
            stream_id: u64,
            split_at: usize,
        ) -> Result<Self, FoundationError> {
            if length == 0 || length > CAPACITY || split_at == 0 || split_at > length {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            Ok(Self {
                bytes,
                length,
                stream_id,
                offset: 0,
                chunk_end: split_at,
                split_at,
                #[cfg(test)]
                completed_chunks: 0,
            })
        }

        pub(super) fn pending(&self) -> (&[u8], bool) {
            (
                &self.bytes[self.offset..self.chunk_end],
                self.chunk_end == self.length,
            )
        }

        pub(super) fn stream_id(&self) -> u64 {
            self.stream_id
        }

        pub(super) fn set_stream_id(&mut self, stream_id: u64) {
            self.stream_id = stream_id;
        }

        pub(super) fn sent_len(&self) -> usize {
            self.offset
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
            #[cfg(test)]
            {
                self.completed_chunks = self
                    .completed_chunks
                    .checked_add(1)
                    .ok_or(FoundationError::PreAuthApplicationActivity)?;
            }
            if self.offset == self.length {
                return Ok(true);
            }
            if self.chunk_end != self.split_at {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.chunk_end = self.length;
            Ok(false)
        }

        pub(super) fn clear(&mut self) {
            self.bytes.fill(0);
            self.length = 0;
            self.stream_id = 0;
            self.offset = 0;
            self.chunk_end = 0;
            #[cfg(test)]
            {
                self.completed_chunks = 0;
            }
        }
    }

    pub(super) fn record_body_send_result<const CAPACITY: usize>(
        state: &mut BodySendState<CAPACITY>,
        pending_len: usize,
        result: Result<usize, quiche::h3::Error>,
    ) -> Result<bool, FoundationError> {
        record_bounded_send_result(
            state,
            pending_len,
            result,
            FoundationError::PreAuthApplicationActivity,
        )
    }

    pub(super) fn record_bounded_send_result<const CAPACITY: usize>(
        state: &mut BodySendState<CAPACITY>,
        pending_len: usize,
        result: Result<usize, quiche::h3::Error>,
        rejection: FoundationError,
    ) -> Result<bool, FoundationError> {
        match result {
            Ok(written) if written <= pending_len => state.record_progress(written),
            Ok(_) => Err(rejection),
            Err(quiche::h3::Error::Done) => Ok(false),
            Err(_) => Err(rejection),
        }
    }

    enum FrozenDirectV3Role {
        Client(ClientRoleConfig),
        Server(ServerRoleConfig),
    }

    impl FrozenDirectV3Role {
        fn client(config: ClientRoleConfig) -> Result<Self, FoundationError> {
            let frozen = Self::Client(config);
            frozen.validate_before_io()?;
            Ok(frozen)
        }

        fn server(config: ServerRoleConfig) -> Result<Self, FoundationError> {
            let frozen = Self::Server(config);
            frozen.validate_before_io()?;
            Ok(frozen)
        }

        fn validate_before_io(&self) -> Result<(), FoundationError> {
            if self.transport_strategy()? != DirectV3TransportStrategy::H3
                || !valid_control_path(self.tunnel_path()?.as_bytes())
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            let authority = self.expected_authority()?.as_bytes();
            if authority.is_empty() || !authority.is_ascii() {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            let _preselected_before_io = self.preselected_profile()?;
            Ok(())
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

        fn role(&self) -> AuthRole {
            match self {
                Self::Client(_) => AuthRole::Client,
                Self::Server(_) => AuthRole::Server,
            }
        }

        fn expected_authority(&self) -> Result<&str, FoundationError> {
            match self {
                Self::Client(config) => config
                    .direct_v3()
                    .map(|config| config.server_name())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
                Self::Server(config) => config
                    .direct_v3()
                    .map(|config| config.expected_authority())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn client_server_name(&self) -> Result<&str, FoundationError> {
            match self {
                Self::Client(config) => config
                    .direct_v3()
                    .map(|config| config.server_name())
                    .ok_or(FoundationError::PreAuthApplicationActivity),
                Self::Server(_) => Err(FoundationError::PreAuthApplicationActivity),
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct TrustedGenerationAuthInputs {
        trusted_unix_anchor: u64,
        monotonic_anchor: Instant,
        admission_expiry: u64,
        hard_expiry: u64,
        max_frame_size: u32,
        max_concurrent_flows: u32,
        client_max_frame_size: u32,
        client_max_concurrent_flows: u32,
    }

    impl TrustedGenerationAuthInputs {
        pub(super) fn new(
            now: u64,
            admission_expiry: u64,
            hard_expiry: u64,
            max_frame_size: u32,
            max_concurrent_flows: u32,
            client_max_frame_size: u32,
            client_max_concurrent_flows: u32,
        ) -> Result<Self, FoundationError> {
            if now == 0
                || admission_expiry <= now
                || hard_expiry <= admission_expiry
                || max_frame_size == 0
                || max_concurrent_flows == 0
                || client_max_frame_size == 0
                || client_max_concurrent_flows == 0
            {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Ok(Self {
                trusted_unix_anchor: now,
                monotonic_anchor: Instant::now(),
                admission_expiry,
                hard_expiry,
                max_frame_size,
                max_concurrent_flows,
                client_max_frame_size,
                client_max_concurrent_flows,
            })
        }

        #[cfg(test)]
        fn with_test_anchor(mut self, monotonic_anchor: Instant) -> Self {
            self.monotonic_anchor = monotonic_anchor;
            self
        }

        fn deadline_for(&self, expiry_unix: u64) -> Result<Instant, FoundationError> {
            let seconds = expiry_unix
                .checked_sub(self.trusted_unix_anchor)
                .filter(|seconds| *seconds != 0)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            self.monotonic_anchor
                .checked_add(Duration::from_secs(seconds))
                .ok_or(FoundationError::PreAuthApplicationActivity)
        }
    }

    struct AuthenticatedGenerationPolicy {
        verified: VerifiedAuthV3ServerConfirmation,
        admission_deadline: Instant,
        hard_deadline: Instant,
        effective_local_flow_limit: u32,
    }

    impl AuthenticatedGenerationPolicy {
        fn new(
            verified: VerifiedAuthV3ServerConfirmation,
            inputs: &TrustedGenerationAuthInputs,
        ) -> Result<Self, FoundationError> {
            let admission_deadline = inputs.deadline_for(verified.admission_expiry_unix())?;
            let hard_deadline = inputs.deadline_for(verified.hard_expiry_unix())?;
            if admission_deadline >= hard_deadline {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            let local_flow_limit = u32::try_from(CONNECTION_LEASE_LIMIT)
                .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let effective_local_flow_limit = verified.max_concurrent_flows().min(local_flow_limit);
            if effective_local_flow_limit == 0 {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            Ok(Self {
                verified,
                admission_deadline,
                hard_deadline,
                effective_local_flow_limit,
            })
        }

        fn admission_expiry_unix(&self) -> u64 {
            self.verified.admission_expiry_unix()
        }

        fn hard_expiry_unix(&self) -> u64 {
            self.verified.hard_expiry_unix()
        }

        fn max_frame_size(&self) -> u32 {
            self.verified.max_frame_size()
        }

        fn max_concurrent_flows(&self) -> u32 {
            self.verified.max_concurrent_flows()
        }

        fn effective_local_flow_limit(&self) -> u32 {
            self.effective_local_flow_limit
        }

        fn admission_deadline(&self) -> Instant {
            self.admission_deadline
        }

        pub(super) fn hard_deadline(&self) -> Instant {
            self.hard_deadline
        }

        pub(super) fn admits_new_flow_at(&self, now: Instant) -> bool {
            now < self.admission_deadline
        }

        fn hard_active_at(&self, now: Instant) -> bool {
            now < self.hard_deadline
        }
    }

    pub(super) struct AuthenticatedGeneration {
        generation: ConnectionGeneration,
        active: Arc<AtomicBool>,
        policy: Arc<AuthenticatedGenerationPolicy>,
    }

    impl AuthenticatedGeneration {
        fn duplicate(&self) -> Self {
            Self {
                generation: self.generation,
                active: Arc::clone(&self.active),
                policy: Arc::clone(&self.policy),
            }
        }

        pub(super) fn authorizes(&self, candidate: &Self) -> bool {
            self.authorizes_at(candidate, Instant::now())
        }

        fn authorizes_at(&self, candidate: &Self, now: Instant) -> bool {
            self.generation == candidate.generation
                && Arc::ptr_eq(&self.active, &candidate.active)
                && Arc::ptr_eq(&self.policy, &candidate.policy)
                && self.is_active_at(now)
                && candidate.is_active_at(now)
        }

        pub(super) fn generation(&self) -> ConnectionGeneration {
            self.generation
        }

        pub(super) fn is_active(&self) -> bool {
            self.is_active_at(Instant::now())
        }

        fn is_active_at(&self, now: Instant) -> bool {
            self.active.load(Ordering::Acquire) && self.policy.hard_active_at(now)
        }

        pub(super) fn admits_new_flow_at(&self, now: Instant) -> bool {
            self.is_active_at(now) && self.policy.admits_new_flow_at(now)
        }

        pub(super) fn hard_deadline(&self) -> Instant {
            self.policy.hard_deadline()
        }

        #[cfg(test)]
        pub(super) fn admission_deadline(&self) -> Instant {
            self.policy.admission_deadline()
        }
    }

    pub(super) struct AuthenticatedConnectionLease {
        authenticated: AuthenticatedGeneration,
        lease_active: Arc<AtomicBool>,
        lease_dropped: Arc<Notify>,
        _permit: OwnedSemaphorePermit,
    }

    impl AuthenticatedConnectionLease {
        pub(super) fn generation(&self) -> ConnectionGeneration {
            self.authenticated.generation
        }

        pub(super) fn is_active(&self) -> bool {
            self.authenticated.is_active()
        }

        #[cfg(test)]
        pub(super) fn admission_expiry_unix(&self) -> u64 {
            self.authenticated.policy.admission_expiry_unix()
        }

        #[cfg(test)]
        pub(super) fn hard_expiry_unix(&self) -> u64 {
            self.authenticated.policy.hard_expiry_unix()
        }

        #[cfg(test)]
        pub(super) fn max_frame_size(&self) -> u32 {
            self.authenticated.policy.max_frame_size()
        }

        #[cfg(test)]
        pub(super) fn max_concurrent_flows(&self) -> u32 {
            self.authenticated.policy.max_concurrent_flows()
        }

        #[cfg(test)]
        pub(super) fn effective_local_flow_limit(&self) -> u32 {
            self.authenticated.policy.effective_local_flow_limit()
        }

        #[cfg(test)]
        pub(super) fn hard_deadline(&self) -> Instant {
            self.authenticated.hard_deadline()
        }

        pub(super) fn release(self) {}
    }

    impl Drop for AuthenticatedConnectionLease {
        fn drop(&mut self) {
            self.lease_active.store(false, Ordering::Release);
            self.lease_dropped.notify_one();
        }
    }

    pub(super) struct AuthenticatedLeaseProof {
        authenticated: AuthenticatedGeneration,
        lease_active: Arc<AtomicBool>,
        lease_dropped: Arc<Notify>,
    }

    impl AuthenticatedLeaseProof {
        pub(super) fn authorizes(&self, current: &AuthenticatedGeneration) -> bool {
            self.authorizes_at(current, Instant::now())
        }

        pub(super) fn authorizes_at(
            &self,
            current: &AuthenticatedGeneration,
            now: Instant,
        ) -> bool {
            current.authorizes_at(&self.authenticated, now)
                && self.lease_active.load(Ordering::Acquire)
        }

        pub(super) fn drop_notification(&self) -> Arc<Notify> {
            Arc::clone(&self.lease_dropped)
        }
    }

    pub(super) fn lease_command_proof(
        lease: &AuthenticatedConnectionLease,
    ) -> AuthenticatedLeaseProof {
        AuthenticatedLeaseProof {
            authenticated: lease.authenticated.duplicate(),
            lease_active: Arc::clone(&lease.lease_active),
            lease_dropped: Arc::clone(&lease.lease_dropped),
        }
    }

    pub(super) fn bind_authenticated_lease(
        authenticated: AuthenticatedGeneration,
        permit: OwnedSemaphorePermit,
    ) -> Result<AuthenticatedConnectionLease, FoundationError> {
        if !authenticated.is_active() || authenticated.policy.effective_local_flow_limit() == 0 {
            return Err(FoundationError::PostAuthFlowRejected);
        }
        Ok(AuthenticatedConnectionLease {
            authenticated,
            lease_active: Arc::new(AtomicBool::new(true)),
            lease_dropped: Arc::new(Notify::new()),
            _permit: permit,
        })
    }

    #[cfg(test)]
    pub(super) fn test_authenticated_lease(
        generation: u64,
    ) -> Result<(AuthenticatedGeneration, AuthenticatedConnectionLease), FoundationError> {
        let inputs = test_trusted_inputs()?;
        let authenticated = AuthenticatedGeneration {
            generation: ConnectionGeneration(generation),
            active: Arc::new(AtomicBool::new(true)),
            policy: Arc::new(AuthenticatedGenerationPolicy::new(
                test_verified_confirmation(),
                &inputs,
            )?),
        };
        let permit = Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .map_err(|_| FoundationError::LeaseUnavailable)?;
        let lease = bind_authenticated_lease(authenticated.duplicate(), permit)?;
        Ok((authenticated, lease))
    }

    pub(super) struct GenerationAuth {
        role: AuthRole,
        parameters: TrustedGenerationAuthInputs,
        active: Arc<AtomicBool>,
        #[cfg(test)]
        fault: ReferenceFault,
        role_config: FrozenDirectV3Role,
        slot: AuthSlot,
        phase: AuthPhase,
        facts: Option<FoundationObservation>,
        authenticated_generation: Option<ConnectionGeneration>,
        authenticated_policy: Option<Arc<AuthenticatedGenerationPolicy>>,
        deadline: Option<Instant>,
        request_send: Option<BodySendState<AUTH_V3_CLIENT_CONTROL_LEN>>,
        response_send: Option<BodySendState<AUTH_V3_SERVER_CONFIRMATION_LEN>>,
        request_recv: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
        request_recv_len: usize,
        response_recv: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
        response_recv_len: usize,
        #[cfg(test)]
        slot_claims: u8,
        #[cfg(test)]
        received_data_events: u8,
        #[cfg(test)]
        datagram_checks: u16,
        #[cfg(test)]
        reference_outcome: Option<ReferenceOutcome>,
    }

    impl GenerationAuth {
        pub(super) fn client(
            config: ClientRoleConfig,
            inputs: TrustedGenerationAuthInputs,
        ) -> Result<Self, FoundationError> {
            Self::new(FrozenDirectV3Role::client(config)?, inputs)
        }

        pub(super) fn server(
            config: ServerRoleConfig,
            inputs: TrustedGenerationAuthInputs,
        ) -> Result<Self, FoundationError> {
            Self::new(FrozenDirectV3Role::server(config)?, inputs)
        }

        fn new(
            role_config: FrozenDirectV3Role,
            parameters: TrustedGenerationAuthInputs,
        ) -> Result<Self, FoundationError> {
            role_config.validate_before_io()?;
            let role = role_config.role();
            Ok(Self {
                role,
                parameters,
                active: Arc::new(AtomicBool::new(true)),
                #[cfg(test)]
                fault: ReferenceFault::None,
                role_config,
                slot: AuthSlot::Fresh,
                phase: AuthPhase::Fresh,
                facts: None,
                authenticated_generation: None,
                authenticated_policy: None,
                deadline: None,
                request_send: None,
                response_send: None,
                request_recv: [0; AUTH_V3_CLIENT_CONTROL_LEN],
                request_recv_len: 0,
                response_recv: [0; AUTH_V3_SERVER_CONFIRMATION_LEN],
                response_recv_len: 0,
                #[cfg(test)]
                slot_claims: 0,
                #[cfg(test)]
                received_data_events: 0,
                #[cfg(test)]
                datagram_checks: 0,
                #[cfg(test)]
                reference_outcome: None,
            })
        }

        #[cfg(test)]
        pub(super) fn new_test(role: AuthRole) -> Result<Self, FoundationError> {
            Self::with_fault(role, ReferenceFault::None)
        }

        #[cfg(test)]
        pub(super) fn with_fault(
            role: AuthRole,
            fault: ReferenceFault,
        ) -> Result<Self, FoundationError> {
            let role_config = match role {
                AuthRole::Client => FrozenDirectV3Role::client(
                    ClientRoleConfig::from_yaml_str(&test_client_role_yaml())
                        .map_err(|_| FoundationError::PreAuthApplicationActivity)?,
                )?,
                AuthRole::Server => FrozenDirectV3Role::server(
                    ServerRoleConfig::from_yaml_str(&test_server_role_yaml())
                        .map_err(|_| FoundationError::PreAuthApplicationActivity)?,
                )?,
            };
            let parameters = test_trusted_inputs()?;
            let mut runtime = Self::new(role_config, parameters)?;
            runtime.fault = fault;
            Ok(runtime)
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
            if self.role == AuthRole::Server
                && raw_sni.map(str::as_bytes)
                    != Some(self.role_config.expected_authority()?.as_bytes())
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
            #[cfg(test)]
            {
                self.datagram_checks = self
                    .datagram_checks
                    .checked_add(1)
                    .ok_or(FoundationError::PreAuthApplicationActivity)?;
            }
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
            self.check_deadline()?;

            if self.role == AuthRole::Client && self.phase == AuthPhase::Fresh && foundation_ready {
                #[cfg(test)]
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
                        self.role_config.expected_authority()?.as_bytes(),
                        self.role_config.tunnel_path()?.as_bytes(),
                    );
                    let request_result = h3_connection.send_request(connection, &headers, false);
                    let Some(stream_id) = self.admit_request_send_result(request_result)? else {
                        return Ok(());
                    };
                    #[cfg(test)]
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
                    self.request_send = Some(BodySendState::new(
                        body,
                        stream_id,
                        self.request_chunk_end(),
                    ));
                    self.phase = AuthPhase::ClientSendingBody;
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
                    let complete = record_body_send_result(
                        self.request_send
                            .as_mut()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?,
                        pending_len,
                        result,
                    )?;
                    if complete {
                        self.phase = AuthPhase::ClientWaitingResponse;
                    }
                }
                AuthPhase::ServerSendingHeaders => {
                    let stream_id = self.bound_stream()?;
                    let headers = response_headers();
                    if self.admit_response_send_result(
                        h3_connection.send_response(connection, stream_id, &headers, false),
                    )? {
                        self.phase = AuthPhase::ServerSendingBody;
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
                    let complete = record_body_send_result(
                        self.response_send
                            .as_mut()
                            .ok_or(FoundationError::PreAuthApplicationActivity)?,
                        pending_len,
                        result,
                    )?;
                    if complete {
                        self.check_datagram_queue(connection)?;
                        self.authenticate()?;
                    }
                }
                AuthPhase::Fresh
                | AuthPhase::ClientWaitingResponse
                | AuthPhase::ClientReceivingResponse
                | AuthPhase::ServerReceivingRequest
                | AuthPhase::Authenticated => {}
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
            self.check_deadline()?;
            match (self.role, event) {
                (AuthRole::Server, quiche::h3::Event::Headers { list, more_frames }) => {
                    self.claim_server_slot(stream_id)?;
                    if !more_frames
                        || !valid_request_headers_for(
                            &list,
                            self.role_config.expected_authority()?.as_bytes(),
                            self.role_config.tunnel_path()?.as_bytes(),
                        )
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    self.phase = AuthPhase::ServerReceivingRequest;
                    Ok(())
                }
                (AuthRole::Server, quiche::h3::Event::Data) => {
                    self.admit_data_event(AuthPhase::ServerReceivingRequest, stream_id)?;
                    drain_body(
                        h3_connection,
                        connection,
                        stream_id,
                        &mut self.request_recv,
                        &mut self.request_recv_len,
                    )
                }
                (AuthRole::Server, quiche::h3::Event::Finished) => {
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
                (AuthRole::Client, quiche::h3::Event::Headers { list, more_frames }) => {
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
                (AuthRole::Client, quiche::h3::Event::Data) => {
                    self.admit_data_event(AuthPhase::ClientReceivingResponse, stream_id)?;
                    drain_body(
                        h3_connection,
                        connection,
                        stream_id,
                        &mut self.response_recv,
                        &mut self.response_recv_len,
                    )
                }
                (AuthRole::Client, quiche::h3::Event::Finished) => {
                    if self.phase != AuthPhase::ClientReceivingResponse
                        || self.bound_stream()? != stream_id
                    {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    }
                    exact_body_finished(self.response_recv_len, AUTH_V3_SERVER_CONFIRMATION_LEN)?;
                    self.authenticated_policy = Some(self.verify_server_confirmation()?);
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

        #[cfg(test)]
        pub(super) fn take_success_outcome(&mut self) -> Option<ReferenceOutcome> {
            self.reference_outcome.take()
        }

        #[cfg(test)]
        fn record_reference_outcome(&mut self) -> Result<(), FoundationError> {
            let (sent_body_chunks, request_bytes, response_bytes) = match self.role {
                AuthRole::Client => {
                    let send = self
                        .request_send
                        .as_ref()
                        .ok_or(FoundationError::PreAuthApplicationActivity)?;
                    (send.completed_chunks, send.offset, self.response_recv_len)
                }
                AuthRole::Server => {
                    let send = self
                        .response_send
                        .as_ref()
                        .ok_or(FoundationError::PreAuthApplicationActivity)?;
                    (send.completed_chunks, self.request_recv_len, send.offset)
                }
            };
            self.reference_outcome = Some(ReferenceOutcome {
                role: self.role,
                slot_claims: self.slot_claims,
                sent_body_chunks,
                received_data_events: self.received_data_events,
                request_bytes,
                response_bytes,
                datagram_checks: self.datagram_checks,
            });
            Ok(())
        }

        pub(super) fn fail_closed(&mut self) {
            self.slot = AuthSlot::Consumed;
            self.phase = AuthPhase::Failed;
            self.active.store(false, Ordering::Release);
            self.clear_auth_buffers();
            self.facts = None;
            self.authenticated_generation = None;
        }

        fn prepare_client_control(&mut self) -> Result<(), FoundationError> {
            let facts = self
                .facts
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            let preselected = self.role_config.preselected_profile()?;
            let mut exporter = *facts.auth_v3_exporter.as_bytes();
            #[cfg(test)]
            if self.fault == ReferenceFault::WrongClientExporter {
                exporter[0] ^= 0x80;
            }
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                facts.early_data,
                &exporter,
                true,
                Some(&[]),
                self.role_config.tunnel_path()?,
            );
            let mut client_nonce = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut client_nonce)
                .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let control_result = encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientControlInput::new(
                    AuthV3Carrier::H3,
                    self.parameters.trusted_unix_anchor,
                    client_nonce,
                ),
            );
            client_nonce.fill(0);
            exporter.fill(0);
            let control =
                control_result.map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            #[cfg(test)]
            let mut control = control;
            #[cfg(test)]
            match self.fault {
                ReferenceFault::MalformedClientControl => control[0] ^= 0x80,
                ReferenceFault::WrongClientMac => control[255] ^= 0x80,
                ReferenceFault::WrongClientProfile => control[48] ^= 0x80,
                ReferenceFault::WrongClientPolicy => control[12] ^= 0x80,
                ReferenceFault::None
                | ReferenceFault::WrongClientExporter
                | ReferenceFault::WrongClientReceipt
                | ReferenceFault::WrongServerConfirmation
                | ReferenceFault::DuplicateControl
                | ReferenceFault::PreAuthDatagram => {}
            }
            self.request_send = Some(BodySendState::new(control, 0, self.request_chunk_end()));
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
                self.parameters.trusted_unix_anchor,
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let mut server_nonce = [0_u8; 32];
            let mut session_id = [0_u8; 16];
            OsRng
                .try_fill_bytes(&mut server_nonce)
                .and_then(|()| OsRng.try_fill_bytes(&mut session_id))
                .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let confirmation_result = encode_auth_v3_server_confirmation(
                verified,
                &context,
                &AuthV3ServerConfirmationInput::new(
                    self.parameters.trusted_unix_anchor,
                    self.parameters.admission_expiry,
                    self.parameters.hard_expiry,
                    server_nonce,
                    session_id,
                    self.parameters.max_frame_size,
                    self.parameters.max_concurrent_flows,
                ),
            );
            server_nonce.fill(0);
            session_id.fill(0);
            let confirmation =
                confirmation_result.map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            let verified_confirmation = verify_auth_v3_server_confirmation(
                &confirmation,
                &self.request_recv,
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientReceipt::new(
                    self.parameters.trusted_unix_anchor,
                    self.parameters.client_max_frame_size,
                    self.parameters.client_max_concurrent_flows,
                ),
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            self.authenticated_policy = Some(Arc::new(AuthenticatedGenerationPolicy::new(
                verified_confirmation,
                &self.parameters,
            )?));
            #[cfg(test)]
            let mut confirmation = confirmation;
            #[cfg(test)]
            if self.fault == ReferenceFault::WrongServerConfirmation {
                confirmation[319] ^= 0x80;
            }
            let stream_id = self.bound_stream()?;
            self.response_send = Some(BodySendState::new(
                confirmation,
                stream_id,
                self.response_chunk_end(),
            ));
            Ok(())
        }

        fn verify_server_confirmation(
            &self,
        ) -> Result<Arc<AuthenticatedGenerationPolicy>, FoundationError> {
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
            let client_max_frame_size = self.parameters.client_max_frame_size;
            #[cfg(test)]
            let client_max_frame_size = if self.fault == ReferenceFault::WrongClientReceipt {
                1
            } else {
                client_max_frame_size
            };
            let verified = verify_auth_v3_server_confirmation(
                &self.response_recv,
                request,
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientReceipt::new(
                    self.parameters.trusted_unix_anchor,
                    client_max_frame_size,
                    self.parameters.client_max_concurrent_flows,
                ),
            )
            .map_err(|_| FoundationError::PreAuthApplicationActivity)?;
            Ok(Arc::new(AuthenticatedGenerationPolicy::new(
                verified,
                &self.parameters,
            )?))
        }

        fn claim_client_slot(&mut self) -> Result<(), FoundationError> {
            if self.slot != AuthSlot::Fresh {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.slot = AuthSlot::Authenticating(None);
            #[cfg(test)]
            {
                self.slot_claims = self
                    .slot_claims
                    .checked_add(1)
                    .ok_or(FoundationError::PreAuthApplicationActivity)?;
            }
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
            #[cfg(test)]
            {
                self.slot_claims = self
                    .slot_claims
                    .checked_add(1)
                    .ok_or(FoundationError::PreAuthApplicationActivity)?;
            }
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

        fn admit_request_send_result(
            &self,
            result: Result<u64, quiche::h3::Error>,
        ) -> Result<Option<u64>, FoundationError> {
            match result {
                Ok(stream_id) => Ok(Some(stream_id)),
                Err(quiche::h3::Error::StreamBlocked) => Ok(None),
                Err(_) => Err(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn admit_response_send_result(
            &self,
            result: Result<(), quiche::h3::Error>,
        ) -> Result<bool, FoundationError> {
            match result {
                Ok(()) => Ok(true),
                Err(quiche::h3::Error::StreamBlocked) => Ok(false),
                Err(_) => Err(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn admit_data_event(
            &mut self,
            expected_phase: AuthPhase,
            stream_id: u64,
        ) -> Result<(), FoundationError> {
            if self.phase != expected_phase || self.bound_stream()? != stream_id {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            #[cfg(test)]
            {
                self.received_data_events = self
                    .received_data_events
                    .checked_add(1)
                    .ok_or(FoundationError::PreAuthApplicationActivity)?;
            }
            Ok(())
        }

        fn bound_stream(&self) -> Result<u64, FoundationError> {
            match self.slot {
                AuthSlot::Authenticating(Some(stream_id)) => Ok(stream_id),
                _ => Err(FoundationError::PreAuthApplicationActivity),
            }
        }

        fn check_deadline(&self) -> Result<(), FoundationError> {
            if self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Err(FoundationError::DriverTimeout);
            }
            Ok(())
        }

        fn authenticate(&mut self) -> Result<(), FoundationError> {
            if !matches!(self.slot, AuthSlot::Authenticating(Some(_))) {
                return Err(FoundationError::PreAuthApplicationActivity);
            }
            self.enforce_hard_deadline_at(Instant::now())?;
            let generation = self
                .facts
                .as_ref()
                .map(|facts| facts.generation)
                .ok_or(FoundationError::PreAuthApplicationActivity)?;
            #[cfg(test)]
            self.record_reference_outcome()?;
            self.slot = AuthSlot::Authenticated;
            self.phase = AuthPhase::Authenticated;
            self.authenticated_generation = Some(generation);
            self.facts = None;
            self.clear_auth_buffers();
            Ok(())
        }

        pub(super) fn authenticated_generation(&self) -> Option<AuthenticatedGeneration> {
            if self.slot != AuthSlot::Authenticated
                || self.phase != AuthPhase::Authenticated
                || !self.active.load(Ordering::Acquire)
            {
                return None;
            }
            let authenticated = AuthenticatedGeneration {
                generation: self.authenticated_generation?,
                active: Arc::clone(&self.active),
                policy: Arc::clone(self.authenticated_policy.as_ref()?),
            };
            authenticated.is_active().then_some(authenticated)
        }

        pub(super) fn hard_deadline(&self) -> Option<Instant> {
            self.authenticated_policy
                .as_ref()
                .map(|policy| policy.hard_deadline())
        }

        pub(super) fn enforce_hard_deadline_at(&self, now: Instant) -> Result<(), FoundationError> {
            if self
                .authenticated_policy
                .as_ref()
                .is_some_and(|policy| !policy.hard_active_at(now))
            {
                self.active.store(false, Ordering::Release);
                return Err(FoundationError::PostAuthFlowRejected);
            }
            Ok(())
        }

        pub(super) fn role(&self) -> AuthRole {
            self.role
        }

        pub(super) fn client_server_name(&self) -> Result<&str, FoundationError> {
            self.role_config.client_server_name()
        }

        fn request_chunk_end(&self) -> usize {
            #[cfg(test)]
            {
                T026C_REQUEST_SPLIT
            }
            #[cfg(not(test))]
            {
                AUTH_V3_CLIENT_CONTROL_LEN
            }
        }

        fn response_chunk_end(&self) -> usize {
            #[cfg(test)]
            {
                T026C_RESPONSE_SPLIT
            }
            #[cfg(not(test))]
            {
                AUTH_V3_SERVER_CONFIRMATION_LEN
            }
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

    #[cfg(test)]
    fn test_trusted_inputs() -> Result<TrustedGenerationAuthInputs, FoundationError> {
        TrustedGenerationAuthInputs::new(
            T026C_NOW,
            T026C_NOW + 1_800,
            T026C_NOW + 86_400,
            65_536,
            128,
            131_072,
            256,
        )
    }

    #[cfg(test)]
    fn test_trusted_inputs_at(
        anchor: Instant,
    ) -> Result<TrustedGenerationAuthInputs, FoundationError> {
        TrustedGenerationAuthInputs::new(
            T026C_NOW,
            T026C_NOW + 1_800,
            T026C_NOW + 86_400,
            65_536,
            128,
            131_072,
            256,
        )
        .map(|inputs| inputs.with_test_anchor(anchor))
    }

    #[cfg(test)]
    fn test_verified_confirmation() -> VerifiedAuthV3ServerConfirmation {
        let config = ClientRoleConfig::from_yaml_str(&test_client_role_yaml())
            .expect("parse verified-policy client role");
        let direct = config
            .direct_v3()
            .expect("read verified-policy direct role");
        let preselected = direct.preselected_profile();
        let exporter = [0x41; AUTH_V3_EXPORTER_LEN];
        let context = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter,
            true,
            Some(&[]),
            T026C_CONTROL_PATH,
        );
        let control = encode_auth_v3_client_control(
            &preselected.trusted_profile(),
            &context,
            &AuthV3ClientControlInput::new(AuthV3Carrier::H3, T026C_NOW, [0x61; 32]),
        )
        .expect("encode verified-policy client control");
        let verified_control = verify_auth_v3_client_control(
            &control,
            &preselected.trusted_profile(),
            &context,
            T026C_NOW,
        )
        .expect("verify verified-policy client control");
        let confirmation = encode_auth_v3_server_confirmation(
            verified_control,
            &context,
            &AuthV3ServerConfirmationInput::new(
                T026C_NOW,
                T026C_NOW + 1_800,
                T026C_NOW + 86_400,
                [0x62; 32],
                [0x63; 16],
                65_536,
                128,
            ),
        )
        .expect("encode verified-policy server confirmation");
        verify_auth_v3_server_confirmation(
            &confirmation,
            &control,
            &preselected.trusted_profile(),
            &context,
            &AuthV3ClientReceipt::new(T026C_NOW, 131_072, 256),
        )
        .expect("verify verified-policy server confirmation")
    }

    impl Drop for GenerationAuth {
        fn drop(&mut self) {
            self.active.store(false, Ordering::Release);
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    fn valid_control_path(path: &[u8]) -> bool {
        path.starts_with(b"/") && path.is_ascii() && !path.contains(&b'?') && !path.contains(&b'#')
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
  expected_authority: "{T026C_AUTHORITY}"
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

        #[test]
        fn t023b1_verified_policy_keeps_original_anchor_expiries_and_selected_limits() {
            let client_anchor = Instant::now();
            let server_anchor = client_anchor
                .checked_add(Duration::from_millis(7))
                .expect("construct distinct server monotonic anchor");
            let client_inputs = test_trusted_inputs_at(client_anchor)
                .expect("construct anchored client policy inputs");
            let server_inputs = test_trusted_inputs_at(server_anchor)
                .expect("construct anchored server policy inputs");
            let client_policy =
                AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &client_inputs)
                    .expect("construct verified client policy");
            let server_policy =
                AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &server_inputs)
                    .expect("construct verified server policy");

            assert_eq!(
                client_policy.admission_expiry_unix(),
                server_policy.admission_expiry_unix()
            );
            assert_eq!(
                client_policy.hard_expiry_unix(),
                server_policy.hard_expiry_unix()
            );
            assert_eq!(client_policy.max_frame_size(), 65_536);
            assert_eq!(client_policy.max_concurrent_flows(), 128);
            assert_eq!(client_policy.effective_local_flow_limit(), 1);
            assert_eq!(
                client_policy.admission_deadline(),
                client_anchor + Duration::from_secs(1_800)
            );
            assert_eq!(
                server_policy.admission_deadline(),
                server_anchor + Duration::from_secs(1_800)
            );
            assert_eq!(
                client_policy.hard_deadline(),
                client_anchor + Duration::from_secs(86_400)
            );
            assert_eq!(
                server_policy.hard_deadline(),
                server_anchor + Duration::from_secs(86_400)
            );
        }

        #[test]
        fn t023b1_admission_and_hard_equality_are_strict_without_resetting_the_anchor() {
            let anchor = Instant::now();
            let inputs = test_trusted_inputs_at(anchor).expect("construct strict policy inputs");
            let simulated_auth_completion = anchor + Duration::from_secs(900);
            let policy = AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &inputs)
                .expect("construct strict verified policy");

            assert_eq!(
                policy.admission_deadline(),
                anchor + Duration::from_secs(1_800)
            );
            assert!(policy.admits_new_flow_at(simulated_auth_completion));
            assert!(
                policy.admits_new_flow_at(policy.admission_deadline() - Duration::from_nanos(1))
            );
            assert!(!policy.admits_new_flow_at(policy.admission_deadline()));
            assert!(
                !policy.admits_new_flow_at(policy.admission_deadline() + Duration::from_nanos(1))
            );
            assert!(policy.hard_active_at(policy.hard_deadline() - Duration::from_nanos(1)));
            assert!(!policy.hard_active_at(policy.hard_deadline()));
            assert!(!policy.hard_active_at(policy.hard_deadline() + Duration::from_nanos(1)));
        }

        #[test]
        fn t023b1_generation_authorization_requires_the_same_policy_arc() {
            let anchor = Instant::now();
            let inputs = test_trusted_inputs_at(anchor).expect("construct identity inputs");
            let first_policy = Arc::new(
                AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &inputs)
                    .expect("construct first identity policy"),
            );
            let second_policy = Arc::new(
                AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &inputs)
                    .expect("construct second identity policy"),
            );
            let active = Arc::new(AtomicBool::new(true));
            let current = AuthenticatedGeneration {
                generation: ConnectionGeneration(92),
                active: Arc::clone(&active),
                policy: Arc::clone(&first_policy),
            };
            let same_policy = current.duplicate();
            let different_policy = AuthenticatedGeneration {
                generation: current.generation,
                active,
                policy: second_policy,
            };
            let before_hard = first_policy.hard_deadline() - Duration::from_nanos(1);

            assert!(current.authorizes_at(&same_policy, before_hard));
            assert!(!current.authorizes_at(&different_policy, before_hard));
            assert!(!current.authorizes_at(&same_policy, first_policy.hard_deadline()));
        }

        #[test]
        fn t023b1_deadline_derivation_fails_closed_on_an_invalid_anchor_relation() {
            let trusted_unix_anchor = T026C_NOW + 90_000;
            let inputs = TrustedGenerationAuthInputs::new(
                trusted_unix_anchor,
                trusted_unix_anchor + 1,
                trusted_unix_anchor + 2,
                65_536,
                128,
                131_072,
                256,
            )
            .map(|inputs| inputs.with_test_anchor(Instant::now()))
            .expect("construct mismatched deadline inputs");
            assert!(matches!(
                AuthenticatedGenerationPolicy::new(test_verified_confirmation(), &inputs),
                Err(FoundationError::PreAuthApplicationActivity)
            ));
        }

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

        #[cfg(feature = "unstable-quiche-strict-push-test-support")]
        fn flow_control_session(
            mut transport: quiche::Config,
            h3: &quiche::h3::Config,
        ) -> (tempfile::TempDir, quiche::h3::testing::Session) {
            let temp = tempfile::TempDir::new().expect("create flow-control certificate directory");
            let cert_path = temp.path().join("cert.pem");
            let key_path = temp.path().join("key.pem");
            let certified = rcgen::generate_simple_self_signed(vec![T026C_AUTHORITY.into()])
                .expect("generate flow-control certificate");
            std::fs::write(&cert_path, certified.cert.pem())
                .expect("write flow-control certificate");
            std::fs::write(&key_path, certified.key_pair.serialize_pem())
                .expect("write flow-control key");
            transport
                .load_cert_chain_from_pem_file(
                    cert_path
                        .to_str()
                        .expect("read flow-control certificate path"),
                )
                .expect("load flow-control certificate");
            transport
                .load_priv_key_from_pem_file(key_path.to_str().expect("read flow-control key path"))
                .expect("load flow-control key");
            let session = quiche::h3::testing::Session::with_configs(&mut transport, h3)
                .expect("construct flow-control session");
            (temp, session)
        }

        #[test]
        fn server_claims_once_before_requiring_facts_and_rejects_early_or_trailing_events() {
            let mut before_facts = GenerationAuth::new_test(AuthRole::Server)
                .expect("construct facts-order reference runtime");
            assert_eq!(
                before_facts.claim_server_slot(0),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert_eq!(before_facts.slot, AuthSlot::Authenticating(Some(0)));
            assert_eq!(before_facts.slot_claims, 1);
            assert!(before_facts.facts.is_none());

            let mut sequencing = GenerationAuth::new_test(AuthRole::Server)
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

        #[test]
        fn frozen_roles_and_trusted_inputs_fail_before_any_network_seam() {
            let bad_authority = test_client_role_yaml().replace(
                &format!("server_name: \"{T026C_AUTHORITY}\""),
                "server_name: \"invalid:443\"",
            );
            assert!(ClientRoleConfig::from_yaml_str(&bad_authority).is_err());

            let bad_path = test_client_role_yaml().replace(
                &format!("tunnel_path: \"{T026C_CONTROL_PATH}\""),
                "tunnel_path: \"/synthetic-h3-auth-v3?query\"",
            );
            let parsed_bad_path = ClientRoleConfig::from_yaml_str(&bad_path)
                .expect("parse path for private pre-I/O gate");
            assert_eq!(
                GenerationAuth::client(
                    parsed_bad_path,
                    test_trusted_inputs().expect("construct trusted test inputs"),
                )
                .err(),
                Some(FoundationError::PreAuthApplicationActivity)
            );

            assert_eq!(
                TrustedGenerationAuthInputs::new(0, 1, 2, 1, 1, 1, 1).err(),
                Some(FoundationError::PreAuthApplicationActivity)
            );

            let server_config = ServerRoleConfig::from_yaml_str(&test_server_role_yaml())
                .expect("parse frozen server role");
            let mut server = GenerationAuth::server(
                server_config,
                test_trusted_inputs().expect("construct trusted server inputs"),
            )
            .expect("freeze server role before I/O");
            assert_eq!(
                server.install_live_facts(synthetic_live_facts(), Some("other.invalid")),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert!(server.facts.is_none());
            assert_eq!(server.slot, AuthSlot::Fresh);

            let missing_sni_config = ServerRoleConfig::from_yaml_str(&test_server_role_yaml())
                .expect("parse missing-SNI server role");
            let mut missing_sni = GenerationAuth::server(
                missing_sni_config,
                test_trusted_inputs().expect("construct missing-SNI inputs"),
            )
            .expect("freeze missing-SNI server role before I/O");
            assert_eq!(
                missing_sni.install_live_facts(synthetic_live_facts(), None),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert!(missing_sni.facts.is_none());
        }

        #[test]
        fn occupied_auth_deadline_fails_without_reopening_the_generation_slot() {
            let mut runtime = GenerationAuth::new_test(AuthRole::Client)
                .expect("construct deadline reference runtime");
            runtime
                .install_live_facts(synthetic_live_facts(), None)
                .expect("install deadline live facts");
            runtime
                .claim_client_slot()
                .expect("occupy deadline auth slot");
            runtime.deadline = Some(Instant::now());
            assert_eq!(
                runtime.check_deadline(),
                Err(FoundationError::DriverTimeout)
            );
            assert_eq!(
                runtime.claim_client_slot(),
                Err(FoundationError::PreAuthApplicationActivity)
            );
            assert_eq!(runtime.slot_claims, 1);
            runtime.fail_closed();
            assert!(!runtime.active.load(Ordering::Acquire));
        }

        #[cfg(feature = "unstable-quiche-strict-push-test-support")]
        #[test]
        fn real_quiche_blocked_partial_and_done_retries_preserve_the_same_attempt_suffix() {
            let mut blocked_transport = bounded_self_signed_loopback_quic_config()
                .expect("construct blocked-request transport");
            blocked_transport.set_initial_max_data(150);
            blocked_transport.set_initial_max_stream_data_bidi_local(150);
            blocked_transport.set_initial_max_stream_data_bidi_remote(150);
            blocked_transport.set_initial_max_streams_bidi(100);
            let blocked_h3 = bounded_h3_config().expect("construct blocked-request H3 config");
            let (_blocked_temp, mut blocked) = flow_control_session(blocked_transport, &blocked_h3);
            blocked
                .handshake()
                .expect("handshake blocked-request session");

            let mut client = GenerationAuth::new_test(AuthRole::Client)
                .expect("construct blocked-request auth runtime");
            client
                .install_live_facts(synthetic_live_facts(), None)
                .expect("install blocked-request facts");
            client
                .prepare_client_control()
                .expect("prepare blocked-request control");
            client
                .claim_client_slot()
                .expect("claim blocked-request slot");
            client.phase = AuthPhase::ClientSendingHeaders;
            let headers = request_headers(
                client
                    .role_config
                    .expected_authority()
                    .expect("read blocked-request authority")
                    .as_bytes(),
                client
                    .role_config
                    .tunnel_path()
                    .expect("read blocked-request path")
                    .as_bytes(),
            );
            let fill_headers = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"flow.invalid"),
                quiche::h3::Header::new(b":path", b"/fill"),
            ];
            assert_eq!(
                blocked
                    .client
                    .send_request(&mut blocked.pipe.client, &fill_headers, true),
                Ok(0)
            );
            let blocked_result =
                blocked
                    .client
                    .send_request(&mut blocked.pipe.client, &headers, false);
            assert_eq!(blocked_result, Err(quiche::h3::Error::StreamBlocked));
            assert_eq!(
                client
                    .admit_request_send_result(blocked_result)
                    .expect("admit real blocked request result"),
                None
            );
            assert_eq!(client.slot, AuthSlot::Authenticating(None));
            assert_eq!(client.phase, AuthPhase::ClientSendingHeaders);
            assert_eq!(client.slot_claims, 1);

            let mut response_blocked_transport = bounded_self_signed_loopback_quic_config()
                .expect("construct blocked-response transport");
            response_blocked_transport.set_initial_max_data(10_000);
            response_blocked_transport.set_initial_max_stream_data_bidi_local(1);
            response_blocked_transport.set_initial_max_stream_data_bidi_remote(1_024);
            let response_blocked_h3 =
                bounded_h3_config().expect("construct blocked-response H3 config");
            let (_response_blocked_temp, mut response_blocked) =
                flow_control_session(response_blocked_transport, &response_blocked_h3);
            response_blocked
                .handshake()
                .expect("handshake blocked-response session");
            let response_stream = response_blocked
                .client
                .send_request(&mut response_blocked.pipe.client, &headers, true)
                .expect("send blocked-response request");
            response_blocked
                .advance()
                .expect("advance blocked-response request");
            assert!(matches!(
                response_blocked.poll_server(),
                Ok((id, quiche::h3::Event::Headers { .. })) if id == response_stream
            ));
            assert_eq!(
                response_blocked.poll_server(),
                Ok((response_stream, quiche::h3::Event::Finished))
            );
            let response_result = response_blocked.server.send_response(
                &mut response_blocked.pipe.server,
                response_stream,
                &response_headers(),
                false,
            );
            assert_eq!(response_result, Err(quiche::h3::Error::StreamBlocked));
            let mut server = GenerationAuth::new_test(AuthRole::Server)
                .expect("construct blocked-response auth runtime");
            server
                .install_live_facts(synthetic_live_facts(), Some(T026C_AUTHORITY))
                .expect("install blocked-response facts");
            server
                .claim_server_slot(response_stream)
                .expect("claim blocked-response slot");
            server.phase = AuthPhase::ServerSendingHeaders;
            assert!(!server
                .admit_response_send_result(response_result)
                .expect("admit real blocked response result"));
            assert_eq!(server.slot, AuthSlot::Authenticating(Some(response_stream)));
            assert_eq!(server.phase, AuthPhase::ServerSendingHeaders);
            assert_eq!(server.slot_claims, 1);

            let mut body_transport = bounded_self_signed_loopback_quic_config()
                .expect("construct body-flow-control transport");
            body_transport.set_initial_max_data(10_000);
            body_transport.set_initial_max_stream_data_bidi_local(100);
            body_transport.set_initial_max_stream_data_bidi_remote(1_024);
            let body_h3 = bounded_h3_config().expect("construct body-flow-control H3 config");
            let (_body_temp, mut body) = flow_control_session(body_transport, &body_h3);
            body.handshake()
                .expect("handshake body-flow-control session");
            let stream_id = body
                .client
                .send_request(&mut body.pipe.client, &headers, true)
                .expect("send body-flow-control request");
            body.advance().expect("advance body-flow-control request");
            assert!(matches!(
                body.poll_server(),
                Ok((id, quiche::h3::Event::Headers { .. })) if id == stream_id
            ));
            assert_eq!(
                body.poll_server(),
                Ok((stream_id, quiche::h3::Event::Finished))
            );
            body.server
                .send_response(&mut body.pipe.server, stream_id, &response_headers(), false)
                .expect("send body-flow-control response headers");

            let original: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN] =
                std::array::from_fn(|index| ((index * 31 + 7) % 251) as u8);
            let mut send = BodySendState::new(original, stream_id, AUTH_V3_SERVER_CONFIRMATION_LEN);
            assert_eq!(send.stream_id, stream_id);
            let (first_pending, first_fin) = send.pending();
            let first_pending_len = first_pending.len();
            let first_result =
                body.server
                    .send_body(&mut body.pipe.server, stream_id, first_pending, first_fin);
            let first_written = first_result.expect("observe real partial body write");
            assert!(first_written > 0 && first_written < first_pending_len);
            assert!(
                !record_body_send_result(&mut send, first_pending_len, Ok(first_written),)
                    .expect("record real partial body write")
            );
            let (same_suffix, same_fin) = send.pending();
            assert_eq!(same_suffix, &original[first_written..]);
            assert!(same_fin);
            assert_eq!(send.stream_id, stream_id);
            let done_result =
                body.server
                    .send_body(&mut body.pipe.server, stream_id, same_suffix, same_fin);
            assert_eq!(done_result, Err(quiche::h3::Error::Done));
            let same_suffix_len = same_suffix.len();
            assert!(
                !record_body_send_result(&mut send, same_suffix_len, done_result,)
                    .expect("record real Done without progress")
            );
            let (retry_suffix, retry_fin) = send.pending();
            assert_eq!(retry_suffix, &original[first_written..]);
            assert!(retry_fin);
            assert_eq!(send.stream_id, stream_id);
        }

        #[cfg(feature = "unstable-quiche-strict-push-test-support")]
        #[test]
        fn expired_generation_rejects_an_admissible_event_before_any_state_or_byte_change() {
            let mut transport = bounded_self_signed_loopback_quic_config()
                .expect("construct expired-event QUIC config");
            let h3_config = bounded_h3_config().expect("construct expired-event H3 config");
            let mut session =
                quiche::h3::testing::Session::with_configs(&mut transport, &h3_config)
                    .expect("construct expired-event H3 session");
            let mut runtime = GenerationAuth::new_test(AuthRole::Client)
                .expect("construct expired-event auth runtime");
            runtime
                .install_live_facts(synthetic_live_facts(), None)
                .expect("install expired-event facts");
            runtime
                .claim_client_slot()
                .expect("claim expired-event client slot");
            runtime
                .bind_client_stream(0)
                .expect("bind expired-event client stream");
            runtime.phase = AuthPhase::ClientWaitingResponse;
            runtime.deadline = Some(Instant::now());

            let slot_before = runtime.slot;
            let phase_before = runtime.phase;
            let request_before = runtime.request_recv;
            let response_before = runtime.response_recv;
            let request_len_before = runtime.request_recv_len;
            let response_len_before = runtime.response_recv_len;
            let result = runtime.handle_event(
                &mut session.pipe.client,
                &mut session.client,
                0,
                quiche::h3::Event::Headers {
                    list: response_headers().to_vec(),
                    more_frames: true,
                },
            );

            assert_eq!(result, Err(FoundationError::DriverTimeout));
            assert_eq!(runtime.slot, slot_before);
            assert_eq!(runtime.phase, phase_before);
            assert_eq!(runtime.request_recv, request_before);
            assert_eq!(runtime.response_recv, response_before);
            assert_eq!(runtime.request_recv_len, request_len_before);
            assert_eq!(runtime.response_recv_len, response_len_before);
            assert!(runtime.authenticated_generation().is_none());
        }

        #[cfg(feature = "unstable-quiche-strict-push-test-support")]
        #[test]
        fn handle_event_rejects_trailers_control_events_and_wrong_stream_without_reopening_slot() {
            fn assert_rejected_without_reopening(
                session: &mut quiche::h3::testing::Session,
                role: AuthRole,
                phase: AuthPhase,
                stream_id: u64,
                event: quiche::h3::Event,
            ) {
                let mut runtime = GenerationAuth::new_test(role)
                    .expect("construct direct event rejection reference runtime");
                let raw_sni = (role == AuthRole::Server).then_some(T026C_AUTHORITY);
                runtime
                    .install_live_facts(synthetic_live_facts(), raw_sni)
                    .expect("install direct event rejection facts");
                match role {
                    AuthRole::Client => {
                        runtime
                            .claim_client_slot()
                            .expect("claim direct event client slot");
                        runtime
                            .bind_client_stream(0)
                            .expect("bind direct event client stream");
                    }
                    AuthRole::Server => runtime
                        .claim_server_slot(0)
                        .expect("claim direct event server slot"),
                }
                runtime.phase = phase;
                let claimed_slot = runtime.slot;

                let result = match role {
                    AuthRole::Client => runtime.handle_event(
                        &mut session.pipe.client,
                        &mut session.client,
                        stream_id,
                        event,
                    ),
                    AuthRole::Server => runtime.handle_event(
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
                    AuthRole::Client => runtime.claim_client_slot(),
                    AuthRole::Server => runtime.claim_server_slot(4),
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
                (AuthRole::Client, AuthPhase::ClientReceivingResponse),
                (AuthRole::Server, AuthPhase::ServerReceivingRequest),
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
            let mut runtime = GenerationAuth::new_test(AuthRole::Client)
                .expect("construct transactional outcome reference runtime");
            runtime
                .install_live_facts(synthetic_live_facts(), None)
                .expect("install transactional outcome facts");
            runtime.slot = AuthSlot::Authenticating(Some(0));
            runtime.phase = AuthPhase::ClientReceivingResponse;
            runtime.slot_claims = 1;
            runtime.received_data_events = 2;
            runtime.datagram_checks = 2;

            assert!(runtime.take_success_outcome().is_none());
            assert!(runtime.facts.is_some());
            assert_eq!(runtime.slot, AuthSlot::Authenticating(Some(0)));

            let mut request =
                BodySendState::new([0_u8; AUTH_V3_CLIENT_CONTROL_LEN], 0, T026C_REQUEST_SPLIT);
            request.offset = AUTH_V3_CLIENT_CONTROL_LEN;
            request.chunk_end = AUTH_V3_CLIENT_CONTROL_LEN;
            request.completed_chunks = 2;
            runtime.request_send = Some(request);
            runtime.response_recv_len = AUTH_V3_SERVER_CONFIRMATION_LEN;
            runtime.authenticated_policy = Some(Arc::new(
                AuthenticatedGenerationPolicy::new(
                    test_verified_confirmation(),
                    &runtime.parameters,
                )
                .expect("construct transactional authenticated policy"),
            ));
            runtime
                .authenticate()
                .expect("authenticate complete transactional runtime");

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
            assert_eq!(runtime.slot, AuthSlot::Authenticated);
            assert_eq!(runtime.phase, AuthPhase::Authenticated);
            assert!(runtime.authenticated_generation().is_some());
            assert!(runtime.take_success_outcome().is_none());
        }
    }
}

mod classic_connect {
    use quiche::h3::NameValue;

    use super::generation_auth::{
        record_bounded_send_result, AuthRole, AuthenticatedGeneration, AuthenticatedLeaseProof,
        BodySendState,
    };
    use super::*;

    pub(super) const FLOW_BUFFER_LIMIT: usize = 16_384;
    const REFERENCE_AUTHORITY: &[u8] = b"reference.invalid:443";
    const FLOW_RESET_CODE: u64 = 0x101;

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum ReferenceFault {
        None,
        MissingRequestField,
        DuplicateRequestField,
        UnknownRequestField,
        WrongRequestOrder,
        WrongMethod,
        InvalidAuthority,
        SecondRequest,
        NonSuccessResponse,
        ExtraResponseField,
        DuplicateResponseField,
        ResponseTrailer,
        ResetAfterResponse,
        StallAfterArm,
    }

    #[cfg(test)]
    #[derive(Clone)]
    pub(super) struct ReferenceSpy {
        header_send_attempts: Arc<std::sync::atomic::AtomicUsize>,
        body_send_calls: Arc<std::sync::atomic::AtomicUsize>,
        request_streams_opened: Arc<std::sync::atomic::AtomicUsize>,
        arm_attempts: Arc<std::sync::atomic::AtomicUsize>,
        buffered_bytes: Arc<std::sync::atomic::AtomicUsize>,
        lease_drop_wakeups: Arc<std::sync::atomic::AtomicUsize>,
        lease_wait_armed: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(test)]
    impl ReferenceSpy {
        fn new() -> Self {
            Self {
                header_send_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                body_send_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                request_streams_opened: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                arm_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                buffered_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                lease_drop_wakeups: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                lease_wait_armed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        pub(super) fn header_send_attempts(&self) -> usize {
            self.header_send_attempts.load(Ordering::Acquire)
        }

        pub(super) fn body_send_calls(&self) -> usize {
            self.body_send_calls.load(Ordering::Acquire)
        }

        pub(super) fn request_streams_opened(&self) -> usize {
            self.request_streams_opened.load(Ordering::Acquire)
        }

        pub(super) fn arm_attempts(&self) -> usize {
            self.arm_attempts.load(Ordering::Acquire)
        }

        pub(super) fn buffered_bytes(&self) -> usize {
            self.buffered_bytes.load(Ordering::Acquire)
        }

        pub(super) fn lease_drop_wakeups(&self) -> usize {
            self.lease_drop_wakeups.load(Ordering::Acquire)
        }

        pub(super) fn lease_wait_armed(&self) -> usize {
            self.lease_wait_armed.load(Ordering::Acquire)
        }

        pub(super) fn record_lease_drop_wakeup(&self) {
            self.lease_drop_wakeups.fetch_add(1, Ordering::AcqRel);
        }

        pub(super) fn record_lease_wait_armed(&self) {
            self.lease_wait_armed.store(1, Ordering::Release);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FlowPhase {
        Dormant,
        ClientSendingHeaders,
        ClientWaitingResponse,
        ClientSendingData,
        ClientReceivingData,
        ServerWaitingRequest,
        ServerSendingResponse,
        ServerReceivingData,
        ServerSendingData,
        Complete,
        Failed,
    }

    pub(super) struct FlowBuffer {
        bytes: [u8; FLOW_BUFFER_LIMIT],
        length: usize,
    }

    impl FlowBuffer {
        pub(super) fn from_slice(bytes: &[u8]) -> Result<Self, FoundationError> {
            if bytes.is_empty() || bytes.len() > FLOW_BUFFER_LIMIT {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            let mut bounded = [0_u8; FLOW_BUFFER_LIMIT];
            bounded[..bytes.len()].copy_from_slice(bytes);
            Ok(Self {
                bytes: bounded,
                length: bytes.len(),
            })
        }

        fn empty() -> Self {
            Self {
                bytes: [0; FLOW_BUFFER_LIMIT],
                length: 0,
            }
        }

        pub(super) fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.length]
        }

        fn clear(&mut self) {
            self.bytes.fill(0);
            self.length = 0;
        }
    }

    impl fmt::Debug for FlowBuffer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("redacted classic CONNECT data")
        }
    }

    pub(super) struct ClassicConnectOutcome {
        received: FlowBuffer,
        #[cfg(test)]
        stream_id: u64,
        #[cfg(test)]
        header_send_attempts: usize,
        #[cfg(test)]
        body_send_calls: usize,
    }

    impl ClassicConnectOutcome {
        pub(super) fn received(&self) -> &[u8] {
            self.received.as_slice()
        }

        #[cfg(test)]
        pub(super) fn stream_id(&self) -> u64 {
            self.stream_id
        }

        #[cfg(test)]
        pub(super) fn header_send_attempts(&self) -> usize {
            self.header_send_attempts
        }

        #[cfg(test)]
        pub(super) fn body_send_calls(&self) -> usize {
            self.body_send_calls
        }
    }

    impl fmt::Debug for ClassicConnectOutcome {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private classic CONNECT reference outcome")
        }
    }

    pub(super) struct ClassicConnectReference {
        role: Option<AuthRole>,
        phase: FlowPhase,
        proof: Option<AuthenticatedLeaseProof>,
        stream_id: Option<u64>,
        outbound: Option<BodySendState<FLOW_BUFFER_LIMIT>>,
        inbound: FlowBuffer,
        response: Option<oneshot::Sender<Result<ClassicConnectOutcome, FoundationError>>>,
        #[cfg(test)]
        fault: ReferenceFault,
        #[cfg(test)]
        spy: ReferenceSpy,
    }

    impl ClassicConnectReference {
        pub(super) fn new(role: Option<AuthRole>) -> Self {
            Self {
                role,
                phase: FlowPhase::Dormant,
                proof: None,
                stream_id: None,
                outbound: None,
                inbound: FlowBuffer::empty(),
                response: None,
                #[cfg(test)]
                fault: ReferenceFault::None,
                #[cfg(test)]
                spy: ReferenceSpy::new(),
            }
        }

        pub(super) fn arm(
            &mut self,
            current: &AuthenticatedGeneration,
            proof: AuthenticatedLeaseProof,
            outbound: FlowBuffer,
            response: oneshot::Sender<Result<ClassicConnectOutcome, FoundationError>>,
            #[cfg(test)] fault: ReferenceFault,
        ) -> Result<(), FoundationError> {
            self.arm_at(
                current,
                proof,
                outbound,
                response,
                Instant::now(),
                #[cfg(test)]
                fault,
            )
        }

        pub(super) fn arm_at(
            &mut self,
            current: &AuthenticatedGeneration,
            proof: AuthenticatedLeaseProof,
            outbound: FlowBuffer,
            response: oneshot::Sender<Result<ClassicConnectOutcome, FoundationError>>,
            now: Instant,
            #[cfg(test)] fault: ReferenceFault,
        ) -> Result<(), FoundationError> {
            if self.phase != FlowPhase::Dormant
                || !proof.authorizes_at(current, now)
                || !current.admits_new_flow_at(now)
                || self.role.is_none()
                || response.is_closed()
            {
                let _ = response.send(Err(FoundationError::PostAuthFlowRejected));
                return Err(FoundationError::PostAuthFlowRejected);
            }
            let length = outbound.length;
            let send = match BodySendState::bounded(outbound.bytes, length, 0, length) {
                Ok(send) => send,
                Err(error) => {
                    let _ = response.send(Err(error));
                    return Err(error);
                }
            };
            self.outbound = Some(send);
            self.proof = Some(proof);
            self.response = Some(response);
            #[cfg(test)]
            {
                self.fault = fault;
                self.spy.arm_attempts.fetch_add(1, Ordering::AcqRel);
                self.spy.buffered_bytes.store(length, Ordering::Release);
            }
            self.phase = match self.role {
                Some(AuthRole::Client) => FlowPhase::ClientSendingHeaders,
                Some(AuthRole::Server) => FlowPhase::ServerWaitingRequest,
                None => return Err(FoundationError::PostAuthFlowRejected),
            };
            Ok(())
        }

        pub(super) fn has_attempt(&self) -> bool {
            !matches!(
                self.phase,
                FlowPhase::Dormant | FlowPhase::Complete | FlowPhase::Failed
            )
        }

        #[cfg(test)]
        pub(super) fn test_spy(&self) -> ReferenceSpy {
            self.spy.clone()
        }

        #[cfg(test)]
        pub(super) fn test_bound_stream(&self) -> Option<u64> {
            self.stream_id
        }

        pub(super) fn route_is_open_for(&self, current: &AuthenticatedGeneration) -> bool {
            self.route_is_open_for_at(current, Instant::now())
        }

        pub(super) fn route_is_open_for_at(
            &self,
            current: &AuthenticatedGeneration,
            now: Instant,
        ) -> bool {
            !matches!(
                self.phase,
                FlowPhase::Dormant | FlowPhase::Complete | FlowPhase::Failed
            ) && self
                .proof
                .as_ref()
                .is_some_and(|proof| proof.authorizes_at(current, now))
        }

        pub(super) fn active_lease_notification(&self) -> Option<Arc<Notify>> {
            self.has_attempt()
                .then(|| {
                    self.proof
                        .as_ref()
                        .map(AuthenticatedLeaseProof::drop_notification)
                })
                .flatten()
        }

        pub(super) fn drive_outbound(
            &mut self,
            current: &AuthenticatedGeneration,
            connection: &mut quiche::Connection,
            h3_connection: &mut quiche::h3::Connection,
        ) -> Result<(), FoundationError> {
            self.drive_outbound_at(current, connection, h3_connection, Instant::now())
        }

        pub(super) fn drive_outbound_at(
            &mut self,
            current: &AuthenticatedGeneration,
            connection: &mut quiche::Connection,
            h3_connection: &mut quiche::h3::Connection,
            now: Instant,
        ) -> Result<(), FoundationError> {
            if !self.route_is_open_for_at(current, now) {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            if self
                .response
                .as_ref()
                .is_none_or(oneshot::Sender::is_closed)
            {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            #[cfg(test)]
            if self.fault == ReferenceFault::StallAfterArm {
                return Ok(());
            }
            match self.phase {
                FlowPhase::ClientSendingHeaders => {
                    #[cfg(test)]
                    {
                        self.spy.header_send_attempts.fetch_add(1, Ordering::AcqRel);
                    }
                    let headers = self.request_headers();
                    match h3_connection.send_request(connection, &headers, false) {
                        Ok(stream_id) => {
                            #[cfg(test)]
                            self.spy
                                .request_streams_opened
                                .fetch_add(1, Ordering::AcqRel);
                            self.stream_id = Some(stream_id);
                            self.outbound
                                .as_mut()
                                .ok_or(FoundationError::PostAuthFlowRejected)?
                                .set_stream_id(stream_id);
                            #[cfg(test)]
                            if self.fault == ReferenceFault::SecondRequest {
                                let _second_stream = h3_connection
                                    .send_request(connection, &request_headers(), false)
                                    .map_err(|_| FoundationError::PostAuthFlowRejected)?;
                                self.spy
                                    .request_streams_opened
                                    .fetch_add(1, Ordering::AcqRel);
                            }
                            self.phase = FlowPhase::ClientWaitingResponse;
                        }
                        Err(quiche::h3::Error::StreamBlocked) => {}
                        Err(_) => return Err(FoundationError::PostAuthFlowRejected),
                    }
                }
                FlowPhase::ServerSendingResponse => {
                    #[cfg(test)]
                    {
                        self.spy.header_send_attempts.fetch_add(1, Ordering::AcqRel);
                    }
                    let stream_id = self.bound_stream()?;
                    let headers = self.response_headers();
                    match h3_connection.send_response(connection, stream_id, &headers, false) {
                        Ok(()) => {
                            #[cfg(test)]
                            match self.fault {
                                ReferenceFault::ResponseTrailer => {
                                    h3_connection
                                        .send_additional_headers(
                                            connection,
                                            stream_id,
                                            &[quiche::h3::Header::new(b"x-trailer", b"1")],
                                            true,
                                            true,
                                        )
                                        .map_err(|_| FoundationError::PostAuthFlowRejected)?;
                                }
                                ReferenceFault::ResetAfterResponse => {
                                    connection
                                        .stream_shutdown(
                                            stream_id,
                                            quiche::Shutdown::Write,
                                            FLOW_RESET_CODE,
                                        )
                                        .map_err(|_| FoundationError::PostAuthFlowRejected)?;
                                }
                                _ => {}
                            }
                            self.phase = FlowPhase::ServerReceivingData;
                        }
                        Err(quiche::h3::Error::StreamBlocked) => {}
                        Err(_) => return Err(FoundationError::PostAuthFlowRejected),
                    }
                }
                FlowPhase::ClientSendingData | FlowPhase::ServerSendingData => {
                    #[cfg(test)]
                    {
                        self.spy.body_send_calls.fetch_add(1, Ordering::AcqRel);
                    }
                    let (stream_id, pending_len, fin) = {
                        let send = self
                            .outbound
                            .as_ref()
                            .ok_or(FoundationError::PostAuthFlowRejected)?;
                        let (pending, fin) = send.pending();
                        (send.stream_id(), pending.len(), fin)
                    };
                    let result = {
                        let send = self
                            .outbound
                            .as_ref()
                            .ok_or(FoundationError::PostAuthFlowRejected)?;
                        let (pending, _) = send.pending();
                        h3_connection.send_body(connection, stream_id, pending, fin)
                    };
                    let complete = record_bounded_send_result(
                        self.outbound
                            .as_mut()
                            .ok_or(FoundationError::PostAuthFlowRejected)?,
                        pending_len,
                        result,
                        FoundationError::PostAuthFlowRejected,
                    )?;
                    if complete {
                        if self.phase == FlowPhase::ClientSendingData {
                            self.phase = FlowPhase::ClientReceivingData;
                        } else {
                            self.complete()?;
                        }
                    }
                }
                FlowPhase::Dormant
                | FlowPhase::ClientWaitingResponse
                | FlowPhase::ClientReceivingData
                | FlowPhase::ServerWaitingRequest
                | FlowPhase::ServerReceivingData
                | FlowPhase::Complete => {}
                FlowPhase::Failed => return Err(FoundationError::PostAuthFlowRejected),
            }
            Ok(())
        }

        pub(super) fn handle_event(
            &mut self,
            current: &AuthenticatedGeneration,
            connection: &mut quiche::Connection,
            h3_connection: &mut quiche::h3::Connection,
            stream_id: u64,
            event: quiche::h3::Event,
        ) -> Result<(), FoundationError> {
            if !self.route_is_open_for(current) {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            if self
                .response
                .as_ref()
                .is_none_or(oneshot::Sender::is_closed)
            {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            match (self.role, event) {
                (Some(AuthRole::Server), quiche::h3::Event::Headers { list, more_frames })
                    if self.phase == FlowPhase::ServerWaitingRequest =>
                {
                    if !more_frames || !valid_request_headers(&list) {
                        return Err(FoundationError::PostAuthFlowRejected);
                    }
                    self.stream_id = Some(stream_id);
                    self.outbound
                        .as_mut()
                        .ok_or(FoundationError::PostAuthFlowRejected)?
                        .set_stream_id(stream_id);
                    self.phase = FlowPhase::ServerSendingResponse;
                    Ok(())
                }
                (Some(AuthRole::Client), quiche::h3::Event::Headers { list, more_frames })
                    if self.phase == FlowPhase::ClientWaitingResponse =>
                {
                    if self.bound_stream()? != stream_id
                        || !more_frames
                        || !valid_response_headers(&list)
                    {
                        return Err(FoundationError::PostAuthFlowRejected);
                    }
                    self.phase = FlowPhase::ClientSendingData;
                    Ok(())
                }
                (Some(AuthRole::Server), quiche::h3::Event::Data)
                    if self.phase == FlowPhase::ServerReceivingData =>
                {
                    self.require_stream(stream_id)?;
                    drain_flow_body(h3_connection, connection, stream_id, &mut self.inbound)
                }
                (Some(AuthRole::Client), quiche::h3::Event::Data)
                    if self.phase == FlowPhase::ClientReceivingData =>
                {
                    self.require_stream(stream_id)?;
                    drain_flow_body(h3_connection, connection, stream_id, &mut self.inbound)
                }
                (Some(AuthRole::Server), quiche::h3::Event::Finished)
                    if self.phase == FlowPhase::ServerReceivingData =>
                {
                    self.require_stream(stream_id)?;
                    if self.inbound.length == 0 {
                        return Err(FoundationError::PostAuthFlowRejected);
                    }
                    self.phase = FlowPhase::ServerSendingData;
                    Ok(())
                }
                (Some(AuthRole::Client), quiche::h3::Event::Finished)
                    if self.phase == FlowPhase::ClientReceivingData =>
                {
                    self.require_stream(stream_id)?;
                    if self.inbound.length == 0 {
                        return Err(FoundationError::PostAuthFlowRejected);
                    }
                    self.complete()
                }
                (_, quiche::h3::Event::Reset(_))
                | (_, quiche::h3::Event::GoAway)
                | (_, quiche::h3::Event::PriorityUpdate)
                | (_, quiche::h3::Event::Headers { .. })
                | (_, quiche::h3::Event::Data)
                | (_, quiche::h3::Event::Finished) => Err(FoundationError::PostAuthFlowRejected),
            }
        }

        pub(super) fn fail_closed(&mut self) {
            self.phase = FlowPhase::Failed;
            self.proof = None;
            self.stream_id = None;
            if let Some(send) = self.outbound.as_mut() {
                send.clear();
            }
            self.outbound = None;
            self.inbound.clear();
            #[cfg(test)]
            self.spy.buffered_bytes.store(0, Ordering::Release);
            if let Some(response) = self.response.take() {
                let _ = response.send(Err(FoundationError::PostAuthFlowRejected));
            }
        }

        fn complete(&mut self) -> Result<(), FoundationError> {
            let response = self
                .response
                .take()
                .ok_or(FoundationError::PostAuthFlowRejected)?;
            let received = std::mem::replace(&mut self.inbound, FlowBuffer::empty());
            let outcome = ClassicConnectOutcome {
                received,
                #[cfg(test)]
                stream_id: self.bound_stream()?,
                #[cfg(test)]
                header_send_attempts: self.spy.header_send_attempts(),
                #[cfg(test)]
                body_send_calls: self.spy.body_send_calls(),
            };
            if let Some(send) = self.outbound.as_mut() {
                send.clear();
            }
            self.outbound = None;
            #[cfg(test)]
            self.spy.buffered_bytes.store(0, Ordering::Release);
            self.phase = FlowPhase::Complete;
            response
                .send(Ok(outcome))
                .map_err(|_| FoundationError::DriverStopped)
        }

        fn request_headers(&self) -> Vec<quiche::h3::Header> {
            #[cfg(test)]
            {
                let mut headers = request_headers().to_vec();
                match self.fault {
                    ReferenceFault::MissingRequestField => {
                        headers.pop();
                    }
                    ReferenceFault::DuplicateRequestField => {
                        headers[1] = quiche::h3::Header::new(b":method", b"CONNECT");
                    }
                    ReferenceFault::UnknownRequestField => {
                        headers.push(quiche::h3::Header::new(b"x-extra", b"1"));
                    }
                    ReferenceFault::WrongRequestOrder => headers.swap(0, 1),
                    ReferenceFault::WrongMethod => {
                        headers[0] = quiche::h3::Header::new(b":method", b"GET");
                    }
                    ReferenceFault::InvalidAuthority => {
                        headers[1] = quiche::h3::Header::new(b":authority", b"invalid");
                    }
                    _ => {}
                }
                headers
            }
            #[cfg(not(test))]
            request_headers().to_vec()
        }

        fn response_headers(&self) -> Vec<quiche::h3::Header> {
            #[cfg(test)]
            {
                let mut headers = response_headers().to_vec();
                match self.fault {
                    ReferenceFault::NonSuccessResponse => {
                        headers[0] = quiche::h3::Header::new(b":status", b"403");
                    }
                    ReferenceFault::ExtraResponseField => {
                        headers.push(quiche::h3::Header::new(b"x-extra", b"1"));
                    }
                    ReferenceFault::DuplicateResponseField => {
                        headers.push(quiche::h3::Header::new(b":status", b"200"));
                    }
                    _ => {}
                }
                headers
            }
            #[cfg(not(test))]
            response_headers().to_vec()
        }

        fn bound_stream(&self) -> Result<u64, FoundationError> {
            self.stream_id.ok_or(FoundationError::PostAuthFlowRejected)
        }

        fn require_stream(&self, stream_id: u64) -> Result<(), FoundationError> {
            if self.bound_stream()? != stream_id {
                return Err(FoundationError::PostAuthFlowRejected);
            }
            Ok(())
        }
    }

    impl Drop for ClassicConnectReference {
        fn drop(&mut self) {
            self.fail_closed();
        }
    }

    fn drain_flow_body(
        h3_connection: &mut quiche::h3::Connection,
        connection: &mut quiche::Connection,
        stream_id: u64,
        output: &mut FlowBuffer,
    ) -> Result<(), FoundationError> {
        loop {
            if output.length == FLOW_BUFFER_LIMIT {
                let mut oversize = [0_u8; 1];
                return match h3_connection.recv_body(connection, stream_id, &mut oversize) {
                    Ok(_) => Err(FoundationError::PostAuthFlowRejected),
                    Err(quiche::h3::Error::Done) => Ok(()),
                    Err(_) => Err(FoundationError::PostAuthFlowRejected),
                };
            }
            match h3_connection.recv_body(connection, stream_id, &mut output.bytes[output.length..])
            {
                Ok(0) => return Err(FoundationError::PostAuthFlowRejected),
                Ok(length) => {
                    output.length = output
                        .length
                        .checked_add(length)
                        .ok_or(FoundationError::PostAuthFlowRejected)?;
                }
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(_) => return Err(FoundationError::PostAuthFlowRejected),
            }
        }
    }

    pub(super) fn valid_request_headers<T: NameValue>(headers: &[T]) -> bool {
        exact_headers(headers, &request_header_pairs()) && valid_authority(headers[1].value())
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

    fn valid_authority(authority: &[u8]) -> bool {
        if authority != REFERENCE_AUTHORITY || !authority.is_ascii() {
            return false;
        }
        let Some(separator) = authority.iter().rposition(|byte| *byte == b':') else {
            return false;
        };
        let host = &authority[..separator];
        let port = &authority[separator + 1..];
        !host.is_empty()
            && host.split(|byte| *byte == b'.').all(|label| {
                !label.is_empty()
                    && !label.starts_with(b"-")
                    && !label.ends_with(b"-")
                    && label
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            })
            && !port.is_empty()
            && port.iter().all(u8::is_ascii_digit)
            && port != b"0"
    }

    fn request_headers() -> [quiche::h3::Header; 2] {
        [
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":authority", REFERENCE_AUTHORITY),
        ]
    }

    fn response_headers() -> [quiche::h3::Header; 1] {
        [quiche::h3::Header::new(b":status", b"200")]
    }

    pub(super) fn request_header_pairs() -> [(&'static [u8], &'static [u8]); 2] {
        [
            (b":method", b"CONNECT"),
            (b":authority", REFERENCE_AUTHORITY),
        ]
    }

    pub(super) fn response_header_pairs() -> [(&'static [u8], &'static [u8]); 1] {
        [(b":status", b"200")]
    }
}

use generation_auth::{
    bind_authenticated_lease, lease_command_proof, AuthenticatedConnectionLease,
    AuthenticatedGeneration, AuthenticatedLeaseProof, GenerationAuth,
};

use classic_connect::{ClassicConnectOutcome, ClassicConnectReference, FlowBuffer};

#[cfg(test)]
use classic_connect::{ReferenceFault as ClassicConnectFault, ReferenceSpy as ClassicConnectSpy};

#[cfg(test)]
use generation_auth::{
    bounded_body_progress, exact_body_finished, request_header_pairs, response_header_pairs,
    valid_request_headers, valid_response_headers, AuthRole, ReferenceFault, ReferenceOutcome,
};

#[cfg(all(test, feature = "unstable-quiche-strict-push-test-support"))]
use generation_auth::{record_bounded_send_result, test_authenticated_lease, BodySendState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoundationError {
    AlpnMismatch,
    PostAuthFlowRejected,
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
            Self::PostAuthFlowRejected => "native H3 post-auth flow rejected",
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
    AcquireAuthenticated {
        response: oneshot::Sender<AuthenticatedGeneration>,
    },
    OpenClassicConnect {
        proof: AuthenticatedLeaseProof,
        outbound: Box<FlowBuffer>,
        response: oneshot::Sender<Result<ClassicConnectOutcome, FoundationError>>,
        #[cfg(test)]
        fault: ClassicConnectFault,
    },
    #[cfg(test)]
    Acquire {
        response: oneshot::Sender<ConnectionGeneration>,
    },
    #[cfg(test)]
    ObserveDriverTick {
        response: oneshot::Sender<()>,
    },
    #[cfg(test)]
    ExpireAuthenticatedAt {
        now: Instant,
        response: oneshot::Sender<()>,
    },
    Close,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct DriverExit {
    #[cfg(test)]
    reference_outcome: Option<ReferenceOutcome>,
}

#[cfg(test)]
struct ConnectionLease<'manager> {
    generation: ConnectionGeneration,
    _permit: OwnedSemaphorePermit,
    _manager: PhantomData<&'manager SingleIdentityQuicManager>,
}

#[cfg(test)]
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
    #[cfg(test)]
    classic_connect_spy: ClassicConnectSpy,
}

impl SingleIdentityQuicManager {
    fn start(
        driver: FoundationDriver,
        task_permit: OwnedSemaphorePermit,
    ) -> Result<Self, FoundationError> {
        let generation = next_connection_generation()?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_LIMIT);
        #[cfg(test)]
        let classic_connect_spy = driver.classic_connect.test_spy();
        let driver_task = tokio::spawn(async move {
            let _task_permit = task_permit;
            driver.run(command_rx, generation).await
        });
        Ok(Self {
            command_tx: Some(command_tx),
            lease_permits: Arc::new(Semaphore::new(CONNECTION_LEASE_LIMIT)),
            driver_task: Some(driver_task),
            #[cfg(test)]
            classic_connect_spy,
        })
    }

    async fn acquire_authenticated(&self) -> Result<AuthenticatedConnectionLease, FoundationError> {
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
            DriverCommand::AcquireAuthenticated {
                response: response_tx,
            },
        )?;
        let authenticated = timeout(AUTHENTICATED_ACQUIRE_TIMEOUT, response_rx)
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::DriverStopped)?;
        bind_authenticated_lease(authenticated, permit)
    }

    async fn open_classic_connect_reference(
        &self,
        lease: &AuthenticatedConnectionLease,
        outbound: &[u8],
    ) -> Result<ClassicConnectOutcome, FoundationError> {
        #[cfg(test)]
        {
            return self
                .open_classic_connect_reference_with_fault(
                    lease,
                    outbound,
                    ClassicConnectFault::None,
                )
                .await;
        }
        #[cfg(not(test))]
        {
            self.open_classic_connect_reference_inner(lease, outbound)
                .await
        }
    }

    #[cfg(test)]
    async fn open_classic_connect_reference_with_fault(
        &self,
        lease: &AuthenticatedConnectionLease,
        outbound: &[u8],
        fault: ClassicConnectFault,
    ) -> Result<ClassicConnectOutcome, FoundationError> {
        self.open_classic_connect_reference_inner(lease, outbound, fault)
            .await
    }

    async fn open_classic_connect_reference_inner(
        &self,
        lease: &AuthenticatedConnectionLease,
        outbound: &[u8],
        #[cfg(test)] fault: ClassicConnectFault,
    ) -> Result<ClassicConnectOutcome, FoundationError> {
        let response_rx = self.enqueue_classic_connect_reference(
            lease,
            outbound,
            #[cfg(test)]
            fault,
        )?;
        timeout(AUTHENTICATED_ACQUIRE_TIMEOUT, response_rx)
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::DriverStopped)?
    }

    fn enqueue_classic_connect_reference(
        &self,
        lease: &AuthenticatedConnectionLease,
        outbound: &[u8],
        #[cfg(test)] fault: ClassicConnectFault,
    ) -> Result<oneshot::Receiver<Result<ClassicConnectOutcome, FoundationError>>, FoundationError>
    {
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(FoundationError::ManagerClosed)?;
        if !lease.is_active() {
            return Err(FoundationError::PostAuthFlowRejected);
        }
        let outbound = Box::new(FlowBuffer::from_slice(outbound)?);
        let proof = lease_command_proof(lease);
        let (response_tx, response_rx) = oneshot::channel();
        try_send_driver_command(
            command_tx,
            DriverCommand::OpenClassicConnect {
                proof,
                outbound,
                response: response_tx,
                #[cfg(test)]
                fault,
            },
        )?;
        Ok(response_rx)
    }

    #[cfg(test)]
    fn start_stalled_classic_connect(
        &self,
        lease: &AuthenticatedConnectionLease,
        outbound: &[u8],
    ) -> Result<oneshot::Receiver<Result<ClassicConnectOutcome, FoundationError>>, FoundationError>
    {
        self.enqueue_classic_connect_reference(lease, outbound, ClassicConnectFault::StallAfterArm)
    }

    #[cfg(test)]
    async fn expire_authenticated_at(&self, now: Instant) -> Result<(), FoundationError> {
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(FoundationError::ManagerClosed)?;
        let (response_tx, response_rx) = oneshot::channel();
        try_send_driver_command(
            command_tx,
            DriverCommand::ExpireAuthenticatedAt {
                now,
                response: response_tx,
            },
        )?;
        timeout(COMMAND_RESPONSE_TIMEOUT, response_rx)
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::DriverStopped)
    }

    #[cfg(test)]
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

    #[cfg(test)]
    async fn observe_driver_tick(&self) -> Result<(), FoundationError> {
        let command_tx = self
            .command_tx
            .as_ref()
            .ok_or(FoundationError::ManagerClosed)?;
        let (response_tx, response_rx) = oneshot::channel();
        try_send_driver_command(
            command_tx,
            DriverCommand::ObserveDriverTick {
                response: response_tx,
            },
        )?;
        timeout(COMMAND_RESPONSE_TIMEOUT, response_rx)
            .await
            .map_err(|_| FoundationError::DriverTimeout)?
            .map_err(|_| FoundationError::DriverStopped)
    }

    async fn close(&mut self) -> Result<(), FoundationError> {
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

    #[cfg(test)]
    async fn close_and_take_driver_exit(&mut self) -> Result<DriverExit, FoundationError> {
        let Some(command_tx) = self.command_tx.take() else {
            return self.join_driver().await;
        };
        try_send_driver_command(&command_tx, DriverCommand::Close)?;
        drop(command_tx);
        self.join_driver().await
    }

    #[cfg(test)]
    fn driver_is_finished(&self) -> bool {
        self.driver_task
            .as_ref()
            .is_none_or(JoinHandle::is_finished)
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
    pre_auth_request_trigger: Option<Arc<AtomicBool>>,
    auth_runtime: DriverAuthRuntime,
    classic_connect: ClassicConnectReference,
}

enum DriverAuthRuntime {
    Authenticated(Box<GenerationAuth>),
    #[cfg(test)]
    FoundationOnly,
}

impl DriverAuthRuntime {
    fn generation(&self) -> Option<&GenerationAuth> {
        match self {
            Self::Authenticated(runtime) => Some(runtime),
            #[cfg(test)]
            Self::FoundationOnly => None,
        }
    }

    fn generation_mut(&mut self) -> Option<&mut GenerationAuth> {
        match self {
            Self::Authenticated(runtime) => Some(runtime),
            #[cfg(test)]
            Self::FoundationOnly => None,
        }
    }
}

impl FoundationDriver {
    fn new(
        socket: UdpSocket,
        peer_address: SocketAddr,
        connection: quiche::Connection,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        auth_runtime: GenerationAuth,
    ) -> Result<Self, FoundationError> {
        Self::new_inner(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
            DriverAuthRuntime::Authenticated(Box::new(auth_runtime)),
        )
    }

    #[cfg(test)]
    fn new_test_foundation(
        socket: UdpSocket,
        peer_address: SocketAddr,
        connection: quiche::Connection,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
    ) -> Result<Self, FoundationError> {
        Self::new_inner(
            socket,
            peer_address,
            connection,
            observation_tx,
            ready_barrier,
            DriverAuthRuntime::FoundationOnly,
        )
    }

    fn new_inner(
        socket: UdpSocket,
        peer_address: SocketAddr,
        connection: quiche::Connection,
        observation_tx: mpsc::Sender<FoundationObservation>,
        ready_barrier: Arc<Barrier>,
        auth_runtime: DriverAuthRuntime,
    ) -> Result<Self, FoundationError> {
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        if !local_address.ip().is_loopback() || !peer_address.ip().is_loopback() {
            return Err(FoundationError::SocketUnavailable);
        }

        let classic_connect =
            ClassicConnectReference::new(auth_runtime.generation().map(GenerationAuth::role));
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
            auth_runtime,
            classic_connect,
        })
    }

    fn authenticated_hard_deadline(&self) -> Option<Instant> {
        self.auth_runtime
            .generation()
            .and_then(GenerationAuth::hard_deadline)
    }

    fn enforce_authenticated_hard_deadline(&self) -> Result<(), FoundationError> {
        if let Some(runtime) = self.auth_runtime.generation() {
            runtime.enforce_hard_deadline_at(Instant::now())?;
        }
        Ok(())
    }

    fn enforce_active_flow_lease(&self) -> Result<(), FoundationError> {
        if !self.classic_connect.has_attempt() {
            return Ok(());
        }
        let authenticated = self
            .authenticated_generation()
            .ok_or(FoundationError::PostAuthFlowRejected)?;
        if !self.classic_connect.route_is_open_for(&authenticated) {
            return Err(FoundationError::PostAuthFlowRejected);
        }
        Ok(())
    }

    fn revoke_authenticated_state(&mut self) {
        self.classic_connect.fail_closed();
        if let Some(runtime) = self.auth_runtime.generation_mut() {
            runtime.fail_closed();
        }
    }

    async fn run(
        mut self,
        mut command_rx: mpsc::Receiver<DriverCommand>,
        generation: ConnectionGeneration,
    ) -> Result<DriverExit, FoundationError> {
        let result = self.run_inner(&mut command_rx, generation).await;
        if result.is_err() {
            self.classic_connect.fail_closed();
            if let Some(runtime) = self.auth_runtime.generation_mut() {
                runtime.fail_closed();
                if !self.connection.is_closed() {
                    let _ = self.connection.close(true, AUTH_FAILURE_CLOSE_CODE, b"");
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
        let mut pending_authenticated_acquire: Option<oneshot::Sender<AuthenticatedGeneration>> =
            None;

        loop {
            self.enforce_authenticated_hard_deadline()?;
            self.enforce_active_flow_lease()?;
            self.initialize_h3()?;
            #[cfg(test)]
            self.send_queued_pre_auth_request()?;
            let observation_ready = self.process_h3(generation)?;
            self.enforce_authenticated_hard_deadline()?;
            self.enforce_active_flow_lease()?;
            if !foundation_ready && observation_ready {
                self.flush_packets(&mut send_buffer).await?;
                timeout(HANDSHAKE_TIMEOUT, self.ready_barrier.wait())
                    .await
                    .map_err(|_| FoundationError::DriverTimeout)?;
                foundation_ready = true;
            }
            self.drive_generation_auth(foundation_ready)?;
            self.flush_packets(&mut send_buffer).await?;
            self.enforce_authenticated_hard_deadline()?;
            self.enforce_active_flow_lease()?;

            if let Some(response) = pending_authenticated_acquire.take() {
                self.enforce_authenticated_hard_deadline()?;
                if let Some(authenticated) = self.authenticated_generation() {
                    let _ = response.send(authenticated);
                } else {
                    pending_authenticated_acquire = Some(response);
                }
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

            let hard_deadline = self.authenticated_hard_deadline();
            let active_lease_notification = self.classic_connect.active_lease_notification();
            #[cfg(test)]
            if active_lease_notification.is_some() {
                self.classic_connect.test_spy().record_lease_wait_armed();
            }
            let hard_deadline_wait = async move {
                match hard_deadline {
                    Some(deadline) => {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            let active_lease_wait = async move {
                match active_lease_notification {
                    Some(notification) => notification.notified().await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                biased;
                _ = hard_deadline_wait => {
                    self.revoke_authenticated_state();
                    return Err(FoundationError::PostAuthFlowRejected);
                }
                _ = active_lease_wait => {
                    let active_lease_result = self.enforce_active_flow_lease();
                    #[cfg(test)]
                    if active_lease_result.is_err() {
                        self.classic_connect
                            .test_spy()
                            .record_lease_drop_wakeup();
                    }
                    active_lease_result?;
                }
                command = command_rx.recv() => {
                    match command {
                        Some(DriverCommand::AcquireAuthenticated { response }) => {
                            if let Some(authenticated) = self.authenticated_generation() {
                                let _ = response.send(authenticated);
                            } else if pending_authenticated_acquire.is_none() {
                                pending_authenticated_acquire = Some(response);
                            } else {
                                return Err(FoundationError::CommandQueueUnavailable);
                            }
                        }
                        Some(DriverCommand::OpenClassicConnect {
                            proof,
                            outbound,
                            response,
                            #[cfg(test)]
                            fault,
                        }) => {
                            let Some(authenticated) = self.authenticated_generation() else {
                                let _ = response.send(Err(FoundationError::PostAuthFlowRejected));
                                return Err(FoundationError::PostAuthFlowRejected);
                            };
                            if !authenticated.admits_new_flow_at(Instant::now()) {
                                let _ = response.send(Err(FoundationError::PostAuthFlowRejected));
                                return Err(FoundationError::PostAuthFlowRejected);
                            }
                            self.classic_connect.arm(
                                &authenticated,
                                proof,
                                *outbound,
                                response,
                                #[cfg(test)]
                                fault,
                            )?;
                        }
                        #[cfg(test)]
                        Some(DriverCommand::Acquire { response }) => {
                            let _ = response.send(generation);
                        }
                        #[cfg(test)]
                        Some(DriverCommand::ObserveDriverTick { response }) => {
                            let _ = response.send(());
                        }
                        #[cfg(test)]
                        Some(DriverCommand::ExpireAuthenticatedAt { now, response }) => {
                            let expired = self
                                .auth_runtime
                                .generation()
                                .ok_or(FoundationError::PostAuthFlowRejected)?
                                .enforce_hard_deadline_at(now)
                                .is_err();
                            let _ = response.send(());
                            if expired {
                                self.revoke_authenticated_state();
                                return Err(FoundationError::PostAuthFlowRejected);
                            }
                        }
                        Some(DriverCommand::Close) | None => {
                            // T021b promises bounded reclamation, not a
                            // graceful QUIC drain.
                            self.connection
                                .close(true, 0, b"")
                                .map_err(|_| FoundationError::ConnectionUnavailable)?;
                            self.flush_packets(&mut send_buffer).await?;
                            return Ok(self.driver_exit());
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
        if let Some(runtime) = self.auth_runtime.generation() {
            runtime.enforce_hard_deadline_at(Instant::now())?;
        }
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(false);
        };

        loop {
            if let Some(runtime) = self.auth_runtime.generation_mut() {
                runtime.check_datagram_queue(&self.connection)?;
            }
            let event = h3_connection.poll(&mut self.connection);
            if let Some(runtime) = self.auth_runtime.generation_mut() {
                runtime.check_datagram_queue(&self.connection)?;
            }

            match event {
                Ok((stream_id, event)) => {
                    let Some(runtime) = self.auth_runtime.generation_mut() else {
                        return Err(FoundationError::PreAuthApplicationActivity);
                    };
                    runtime.enforce_hard_deadline_at(Instant::now())?;
                    runtime.check_datagram_queue(&self.connection)?;
                    if let Some(authenticated) = runtime.authenticated_generation() {
                        if !self.classic_connect.route_is_open_for(&authenticated) {
                            return Err(FoundationError::PostAuthFlowRejected);
                        }
                        self.classic_connect.handle_event(
                            &authenticated,
                            &mut self.connection,
                            h3_connection,
                            stream_id,
                            event,
                        )?;
                    } else {
                        runtime.handle_event(
                            &mut self.connection,
                            h3_connection,
                            stream_id,
                            event,
                        )?;
                    }
                    continue;
                }
                Err(quiche::h3::Error::Done) => break,
                Err(_) => return Err(FoundationError::H3Unavailable),
            }
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
        if let Some(runtime) = self.auth_runtime.generation_mut() {
            runtime.install_live_facts(observation, self.connection.server_name())?;
        }
        self.observation_tx
            .try_send(observation)
            .map_err(|_| FoundationError::ObservationQueueUnavailable)?;
        Ok(true)
    }

    fn drive_generation_auth(&mut self, foundation_ready: bool) -> Result<(), FoundationError> {
        let Some(runtime) = self.auth_runtime.generation_mut() else {
            return Ok(());
        };
        runtime.enforce_hard_deadline_at(Instant::now())?;
        let Some(h3_connection) = self.h3_connection.as_mut() else {
            return Ok(());
        };
        runtime.drive_outbound(&mut self.connection, h3_connection, foundation_ready)?;
        if self.classic_connect.has_attempt() {
            let authenticated = runtime
                .authenticated_generation()
                .ok_or(FoundationError::PostAuthFlowRejected)?;
            self.classic_connect.drive_outbound(
                &authenticated,
                &mut self.connection,
                h3_connection,
            )?;
        }
        Ok(())
    }

    fn authenticated_generation(&self) -> Option<AuthenticatedGeneration> {
        self.auth_runtime
            .generation()
            .and_then(GenerationAuth::authenticated_generation)
    }

    fn driver_exit(&mut self) -> DriverExit {
        DriverExit {
            #[cfg(test)]
            reference_outcome: self
                .auth_runtime
                .generation_mut()
                .and_then(GenerationAuth::take_success_outcome),
        }
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
        auth_runtime: Option<GenerationAuth>,
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
        let transport = fixed_ok(
            bounded_self_signed_loopback_quic_config(),
            "build strict-gate transport configuration",
        );
        foundation_test_session_with_configs(transport, h3_config)
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    fn foundation_test_session_with_configs(
        mut transport: quiche::Config,
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
        auth_runtime: Option<GenerationAuth>,
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

        let driver = match auth_runtime {
            Some(auth_runtime) => FoundationDriver::new(
                socket,
                peer_address,
                connection,
                observation_tx,
                ready_barrier,
                auth_runtime,
            )?,
            None => FoundationDriver::new_test_foundation(
                socket,
                peer_address,
                connection,
                observation_tx,
                ready_barrier,
            )?,
        };
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
        let ClientStartFixture {
            connections_created,
            pre_auth_request_trigger,
            auth_runtime,
        } = fixture;
        let local_address = socket
            .local_addr()
            .map_err(|_| FoundationError::SocketUnavailable)?;
        let source_connection_id = [0x51_u8; quiche::MAX_CONN_ID_LEN];
        let source_connection_id = quiche::ConnectionId::from_ref(&source_connection_id);
        let server_name = match auth_runtime.as_ref() {
            Some(runtime) => runtime.client_server_name()?,
            None => T026C_AUTHORITY,
        };
        let connection = quiche::connect(
            Some(server_name),
            &source_connection_id,
            local_address,
            peer_address,
            &mut config,
        )
        .map_err(|_| FoundationError::ConnectionUnavailable)?;
        connections_created.fetch_add(1, Ordering::Relaxed);

        let mut driver = match auth_runtime {
            Some(auth_runtime) => FoundationDriver::new(
                socket,
                peer_address,
                connection,
                observation_tx,
                ready_barrier,
                auth_runtime,
            )?,
            None => FoundationDriver::new_test_foundation(
                socket,
                peer_address,
                connection,
                observation_tx,
                ready_barrier,
            )?,
        };
        driver.pre_auth_request_trigger = pre_auth_request_trigger;
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
                GenerationAuth::with_fault(AuthRole::Client, client_fault),
                "construct test-private H3 client auth runtime",
            )),
            Some(fixed_ok(
                GenerationAuth::with_fault(AuthRole::Server, server_fault),
                "construct test-private H3 server auth runtime",
            )),
        )
        .await
    }

    async fn start_loopback_pair_with_options(
        client_task_budget: &ConnectionTaskBudget,
        server_task_budget: &ConnectionTaskBudget,
        pre_auth_request_trigger: Option<Arc<AtomicBool>>,
        client_auth_runtime: Option<GenerationAuth>,
        server_auth_runtime: Option<GenerationAuth>,
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

    async fn wait_for_stalled_flow_arms(pair: &LoopbackPair) {
        fixed_ok(
            timeout(COMMAND_RESPONSE_TIMEOUT, async {
                loop {
                    if pair.client.classic_connect_spy.arm_attempts() == 1
                        && pair.server.classic_connect_spy.arm_attempts() == 1
                        && pair.client.classic_connect_spy.lease_wait_armed() == 1
                        && pair.server.classic_connect_spy.lease_wait_armed() == 1
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await,
            "wait for stalled classic CONNECT arms",
        );
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
    async fn t026d_authenticated_generation_handoff_stays_open_until_explicit_close() {
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

        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire authenticated H3 client generation");
        let server_lease = fixed_ok(server_lease, "acquire authenticated H3 server generation");
        assert!(
            !pair.client.driver_is_finished(),
            "client driver stopped after handoff"
        );
        assert!(
            !pair.server.driver_is_finished(),
            "server driver stopped after handoff"
        );
        assert_eq!(client_lease.generation(), client_observation.generation);
        assert_eq!(server_lease.generation(), server_observation.generation);
        assert_eq!(
            client_lease.admission_expiry_unix(),
            server_lease.admission_expiry_unix()
        );
        assert_eq!(
            client_lease.hard_expiry_unix(),
            server_lease.hard_expiry_unix()
        );
        assert_eq!(client_lease.max_frame_size(), 65_536);
        assert_eq!(server_lease.max_frame_size(), 65_536);
        assert_eq!(client_lease.max_concurrent_flows(), 128);
        assert_eq!(server_lease.max_concurrent_flows(), 128);
        assert_eq!(client_lease.effective_local_flow_limit(), 1);
        assert_eq!(server_lease.effective_local_flow_limit(), 1);
        assert!(client_lease.is_active());
        assert!(server_lease.is_active());
        assert!(!pair.client.driver_is_finished());
        assert!(!pair.server.driver_is_finished());
        assert_eq!(
            pair.client.acquire_authenticated().await.err(),
            Some(FoundationError::LeaseUnavailable)
        );

        let (client_exit, server_exit) = tokio::join!(
            pair.client.close_and_take_driver_exit(),
            pair.server.close_and_take_driver_exit(),
        );
        let client_exit = fixed_ok(client_exit, "explicitly close authenticated H3 client");
        let server_exit = fixed_ok(server_exit, "explicitly close authenticated H3 server");
        assert!(!client_lease.is_active());
        assert!(!server_lease.is_active());
        let client_outcome = fixed_some(
            client_exit.reference_outcome,
            "read test-private H3 client reference outcome",
        );
        let server_outcome = fixed_some(
            server_exit.reference_outcome,
            "read test-private H3 server reference outcome",
        );
        for (outcome, role) in [
            (client_outcome, AuthRole::Client),
            (server_outcome, AuthRole::Server),
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
        client_lease.release();
        server_lease.release();
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
    async fn t023b1_idle_lease_drop_returns_only_its_permit_and_allows_reacquire() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (first_client, first_server) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let first_client = fixed_ok(first_client, "acquire idle client lease");
        let first_server = fixed_ok(first_server, "acquire idle server lease");
        let client_generation = first_client.generation();
        let server_generation = first_server.generation();
        drop(first_client);
        drop(first_server);
        assert_eq!(pair.client.lease_permits.available_permits(), 1);
        assert_eq!(pair.server.lease_permits.available_permits(), 1);
        fixed_ok(
            pair.client.observe_driver_tick().await,
            "observe client after idle lease drop",
        );
        fixed_ok(
            pair.server.observe_driver_tick().await,
            "observe server after idle lease drop",
        );
        assert_eq!(pair.client.classic_connect_spy.lease_drop_wakeups(), 0);
        assert_eq!(pair.server.classic_connect_spy.lease_drop_wakeups(), 0);

        let (second_client, second_server) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let second_client = fixed_ok(second_client, "reacquire idle client generation");
        let second_server = fixed_ok(second_server, "reacquire idle server generation");
        assert_eq!(second_client.generation(), client_generation);
        assert_eq!(second_server.generation(), server_generation);
        assert!(second_client.is_active());
        assert!(second_server.is_active());
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);

        let (client_exit, server_exit) = tokio::join!(
            pair.client.close_and_take_driver_exit(),
            pair.server.close_and_take_driver_exit(),
        );
        fixed_ok(client_exit, "close reacquired idle client");
        fixed_ok(server_exit, "close reacquired idle server");
        assert!(!second_client.is_active());
        assert!(!second_server.is_active());
        second_client.release();
        second_server.release();
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t023b1_hard_equality_closes_an_idle_authenticated_generation() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire hard-idle client lease");
        let server_lease = fixed_ok(server_lease, "acquire hard-idle server lease");
        let (client_expired, server_expired) = tokio::join!(
            pair.client
                .expire_authenticated_at(client_lease.hard_deadline()),
            pair.server
                .expire_authenticated_at(server_lease.hard_deadline()),
        );
        fixed_ok(client_expired, "expire idle client at hard equality");
        fixed_ok(server_expired, "expire idle server at hard equality");
        let (client_exit, server_exit) = tokio::join!(
            pair.client.take_driver_exit(),
            pair.server.take_driver_exit(),
        );
        assert_eq!(
            client_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            server_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert!(!client_lease.is_active());
        assert!(!server_lease.is_active());
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
        let client_address = pair.client_address;
        let server_address = pair.server_address;
        client_lease.release();
        server_lease.release();
        assert_eq!(pair.client.lease_permits.available_permits(), 1);
        assert_eq!(pair.server.lease_permits.available_permits(), 1);
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim hard-idle client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(server_address).await,
            "reclaim hard-idle server socket",
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t023b1_active_flow_lease_drop_notifies_and_closes_without_retry() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire notify client lease");
        let server_lease = fixed_ok(server_lease, "acquire notify server lease");
        let client_response = fixed_ok(
            pair.client
                .start_stalled_classic_connect(&client_lease, b"notify-client-pattern"),
            "start stalled notify client flow",
        );
        let server_response = fixed_ok(
            pair.server
                .start_stalled_classic_connect(&server_lease, b"notify-server-pattern"),
            "start stalled notify server flow",
        );
        wait_for_stalled_flow_arms(&pair).await;
        assert_eq!(pair.client.classic_connect_spy.header_send_attempts(), 0);
        assert_eq!(pair.server.classic_connect_spy.header_send_attempts(), 0);
        assert!(pair.client.classic_connect_spy.buffered_bytes() > 0);
        assert!(pair.server.classic_connect_spy.buffered_bytes() > 0);

        drop(client_lease);
        assert_eq!(pair.client.lease_permits.available_permits(), 1);
        let client_result = fixed_ok(
            fixed_ok(
                timeout(CONNECTION_RUN_TIMEOUT, client_response).await,
                "wait for notified client flow response",
            ),
            "receive notified client flow response",
        );
        assert_eq!(
            client_result.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        let client_exit = fixed_ok(
            timeout(CONNECTION_RUN_TIMEOUT, pair.client.take_driver_exit()).await,
            "reclaim notified client driver",
        );
        assert_eq!(
            client_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(pair.client.classic_connect_spy.lease_drop_wakeups(), 1);
        assert_eq!(pair.client.classic_connect_spy.buffered_bytes(), 0);
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);

        let server_result = fixed_ok(
            timeout(CONNECTION_RUN_TIMEOUT, server_response).await,
            "wait for peer-closed server flow response",
        );
        assert!(server_result.is_ok_and(|result| result.is_err()));
        let server_exit = fixed_ok(
            timeout(CONNECTION_RUN_TIMEOUT, pair.server.take_driver_exit()).await,
            "reclaim peer-closed server driver",
        );
        assert!(server_exit.is_err());
        assert!(!server_lease.is_active());
        assert_eq!(pair.server.classic_connect_spy.buffered_bytes(), 0);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
        let client_address = pair.client_address;
        let server_address = pair.server_address;
        server_lease.release();
        assert_eq!(pair.server.lease_permits.available_permits(), 1);
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim notified client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(server_address).await,
            "reclaim notified server socket",
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t023b1_hard_equality_closes_a_stalled_active_flow_and_reclaims_it() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire hard-flow client lease");
        let server_lease = fixed_ok(server_lease, "acquire hard-flow server lease");
        let client_response = fixed_ok(
            pair.client
                .start_stalled_classic_connect(&client_lease, b"hard-client-pattern"),
            "start hard-expiry client flow",
        );
        let server_response = fixed_ok(
            pair.server
                .start_stalled_classic_connect(&server_lease, b"hard-server-pattern"),
            "start hard-expiry server flow",
        );
        wait_for_stalled_flow_arms(&pair).await;
        let (client_expired, server_expired) = tokio::join!(
            pair.client
                .expire_authenticated_at(client_lease.hard_deadline()),
            pair.server
                .expire_authenticated_at(server_lease.hard_deadline()),
        );
        fixed_ok(client_expired, "expire active client at hard equality");
        fixed_ok(server_expired, "expire active server at hard equality");
        let (client_response, server_response) = tokio::join!(client_response, server_response);
        assert!(fixed_ok(client_response, "receive hard client response").is_err());
        assert!(fixed_ok(server_response, "receive hard server response").is_err());
        let (client_exit, server_exit) = tokio::join!(
            pair.client.take_driver_exit(),
            pair.server.take_driver_exit(),
        );
        assert_eq!(
            client_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            server_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert!(!client_lease.is_active());
        assert!(!server_lease.is_active());
        assert_eq!(pair.client.classic_connect_spy.buffered_bytes(), 0);
        assert_eq!(pair.server.classic_connect_spy.buffered_bytes(), 0);
        assert_eq!(pair.client.classic_connect_spy.request_streams_opened(), 0);
        assert_eq!(pair.server.classic_connect_spy.request_streams_opened(), 0);
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
        let client_address = pair.client_address;
        let server_address = pair.server_address;
        client_lease.release();
        server_lease.release();
        assert_eq!(pair.client.lease_permits.available_permits(), 1);
        assert_eq!(pair.server.lease_permits.available_permits(), 1);
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
        drop(fixed_ok(
            bind_bounded_loopback_socket(client_address).await,
            "reclaim hard-flow client socket",
        ));
        drop(fixed_ok(
            bind_bounded_loopback_socket(server_address).await,
            "reclaim hard-flow server socket",
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t027a1_authenticated_single_stream_carries_raw_bidirectional_data_and_half_closes() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire authenticated client generation");
        let server_lease = fixed_ok(server_lease, "acquire authenticated server generation");

        let (client_flow, server_flow) = tokio::join!(
            pair.client
                .open_classic_connect_reference(&client_lease, b"client-to-server-pattern-027a1",),
            pair.server
                .open_classic_connect_reference(&server_lease, b"server-to-client-pattern-027a1",),
        );
        let client_flow = fixed_ok(client_flow, "complete client classic CONNECT reference");
        let server_flow = fixed_ok(server_flow, "complete server classic CONNECT reference");
        assert_eq!(client_flow.received(), b"server-to-client-pattern-027a1");
        assert_eq!(server_flow.received(), b"client-to-server-pattern-027a1");
        assert_eq!(client_flow.stream_id(), server_flow.stream_id());
        assert_eq!(client_flow.header_send_attempts(), 1);
        assert_eq!(server_flow.header_send_attempts(), 1);
        assert!(client_flow.body_send_calls() >= 1);
        assert!(server_flow.body_send_calls() >= 1);
        assert_eq!(pair.client.classic_connect_spy.request_streams_opened(), 1);
        assert_eq!(pair.server.classic_connect_spy.request_streams_opened(), 0);

        fixed_ok(
            pair.client.observe_driver_tick().await,
            "observe client driver after completed CONNECT",
        );
        fixed_ok(
            pair.server.observe_driver_tick().await,
            "observe server driver after completed CONNECT",
        );
        assert!(!pair.client.driver_is_finished());
        assert!(!pair.server.driver_is_finished());
        assert!(client_lease.is_active());
        assert!(server_lease.is_active());
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);

        let (client_exit, server_exit) = tokio::join!(
            pair.client.close_and_take_driver_exit(),
            pair.server.close_and_take_driver_exit(),
        );
        fixed_ok(client_exit, "close successful classic CONNECT client");
        fixed_ok(server_exit, "close successful classic CONNECT server");
        assert!(!client_lease.is_active());
        assert!(!server_lease.is_active());
        client_lease.release();
        server_lease.release();
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t027a1_second_flow_is_consumed_without_opening_another_stream() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pair).await;
        let (client_lease, server_lease) = tokio::join!(
            pair.client.acquire_authenticated(),
            pair.server.acquire_authenticated(),
        );
        let client_lease = fixed_ok(client_lease, "acquire single-flow client lease");
        let server_lease = fixed_ok(server_lease, "acquire single-flow server lease");
        let first = tokio::join!(
            pair.client
                .open_classic_connect_reference(&client_lease, b"first-client-pattern"),
            pair.server
                .open_classic_connect_reference(&server_lease, b"first-server-pattern"),
        );
        fixed_ok(first.0, "complete first client flow");
        fixed_ok(first.1, "complete first server flow");

        let second = tokio::join!(
            pair.client
                .open_classic_connect_reference(&client_lease, b"second-client-pattern"),
            pair.server
                .open_classic_connect_reference(&server_lease, b"second-server-pattern"),
        );
        assert_eq!(second.0.err(), Some(FoundationError::PostAuthFlowRejected));
        assert_eq!(second.1.err(), Some(FoundationError::PostAuthFlowRejected));
        assert_eq!(pair.client.classic_connect_spy.request_streams_opened(), 1);
        assert_eq!(pair.server.classic_connect_spy.request_streams_opened(), 0);
        assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
        let (client_exit, server_exit) = tokio::join!(
            pair.client.take_driver_exit(),
            pair.server.take_driver_exit(),
        );
        assert_eq!(
            client_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            server_exit.err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert!(!client_lease.is_active());
        assert!(!server_lease.is_active());
        client_lease.release();
        server_lease.release();
        drop(pair);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t027a1_pre_auth_closed_wrong_and_replacement_generation_send_zero_headers() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();
        let mut source = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut source).await;
        let (source_client_lease, source_server_lease) = tokio::join!(
            source.client.acquire_authenticated(),
            source.server.acquire_authenticated(),
        );
        let source_client_lease = fixed_ok(source_client_lease, "acquire source client lease");
        let source_server_lease = fixed_ok(source_server_lease, "acquire source server lease");

        let mut pre_auth = start_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut pre_auth).await;
        assert!(
            pre_auth
                .client
                .open_classic_connect_reference(
                    &source_client_lease,
                    b"pre-auth-must-not-send-pattern",
                )
                .await
                .is_err()
        );
        assert_eq!(
            pre_auth.client.classic_connect_spy.header_send_attempts(),
            0
        );
        assert_eq!(
            pre_auth.client.classic_connect_spy.request_streams_opened(),
            0
        );
        let (pre_auth_client_exit, pre_auth_server_exit) = tokio::join!(
            timeout(CONNECTION_RUN_TIMEOUT, pre_auth.client.take_driver_exit()),
            timeout(CONNECTION_RUN_TIMEOUT, pre_auth.server.take_driver_exit()),
        );
        assert!(fixed_ok(pre_auth_client_exit, "reclaim pre-auth client").is_err());
        assert!(fixed_ok(pre_auth_server_exit, "reclaim pre-auth server").is_err());
        drop(pre_auth);

        let mut wrong_generation = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut wrong_generation).await;
        assert_eq!(
            wrong_generation
                .client
                .open_classic_connect_reference(
                    &source_client_lease,
                    b"wrong-generation-must-not-send-pattern",
                )
                .await
                .err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            wrong_generation
                .client
                .classic_connect_spy
                .header_send_attempts(),
            0
        );
        assert_eq!(
            wrong_generation
                .client
                .classic_connect_spy
                .request_streams_opened(),
            0
        );
        let (wrong_client_exit, wrong_server_exit) = tokio::join!(
            timeout(
                CONNECTION_RUN_TIMEOUT,
                wrong_generation.client.take_driver_exit(),
            ),
            timeout(
                CONNECTION_RUN_TIMEOUT,
                wrong_generation.server.take_driver_exit(),
            ),
        );
        assert!(fixed_ok(wrong_client_exit, "reclaim wrong-generation client").is_err());
        assert!(fixed_ok(wrong_server_exit, "reclaim wrong-generation server").is_err());
        drop(wrong_generation);

        let (source_client_exit, source_server_exit) = tokio::join!(
            source.client.close_and_take_driver_exit(),
            source.server.close_and_take_driver_exit(),
        );
        fixed_ok(source_client_exit, "close source client generation");
        fixed_ok(source_server_exit, "close source server generation");
        assert!(!source_client_lease.is_active());
        assert!(!source_server_lease.is_active());
        assert_eq!(
            source
                .client
                .open_classic_connect_reference(
                    &source_client_lease,
                    b"closed-manager-must-not-send-pattern",
                )
                .await
                .err(),
            Some(FoundationError::ManagerClosed)
        );

        let mut replacement = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut replacement).await;
        assert_eq!(
            replacement
                .client
                .open_classic_connect_reference(
                    &source_client_lease,
                    b"old-lease-must-not-send-pattern",
                )
                .await
                .err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            replacement
                .client
                .classic_connect_spy
                .header_send_attempts(),
            0
        );
        assert_eq!(
            replacement
                .client
                .classic_connect_spy
                .request_streams_opened(),
            0
        );
        fixed_ok(
            replacement.client.observe_driver_tick().await,
            "replacement remains active after old-lease rejection",
        );
        let (replacement_client_lease, replacement_server_lease) = tokio::join!(
            replacement.client.acquire_authenticated(),
            replacement.server.acquire_authenticated(),
        );
        let replacement_client_lease =
            fixed_ok(replacement_client_lease, "acquire replacement client lease");
        let replacement_server_lease =
            fixed_ok(replacement_server_lease, "acquire replacement server lease");
        let replacement_flow = tokio::join!(
            replacement.client.open_classic_connect_reference(
                &replacement_client_lease,
                b"replacement-client-pattern",
            ),
            replacement.server.open_classic_connect_reference(
                &replacement_server_lease,
                b"replacement-server-pattern",
            ),
        );
        assert!(replacement_flow.0.is_ok());
        assert!(replacement_flow.1.is_ok());
        assert_eq!(
            replacement
                .client
                .classic_connect_spy
                .request_streams_opened(),
            1
        );
        let (replacement_client_exit, replacement_server_exit) = tokio::join!(
            replacement.client.close_and_take_driver_exit(),
            replacement.server.close_and_take_driver_exit(),
        );
        fixed_ok(replacement_client_exit, "close replacement client");
        fixed_ok(replacement_server_exit, "close replacement server");
        source_client_lease.release();
        source_server_lease.release();
        replacement_client_lease.release();
        replacement_server_lease.release();
        drop(source);
        drop(replacement);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t027a1_real_field_reset_trailer_and_second_stream_fail_closed_without_retry() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let cases = [
            (
                ClassicConnectFault::MissingRequestField,
                ClassicConnectFault::None,
            ),
            (
                ClassicConnectFault::DuplicateRequestField,
                ClassicConnectFault::None,
            ),
            (
                ClassicConnectFault::UnknownRequestField,
                ClassicConnectFault::None,
            ),
            (
                ClassicConnectFault::WrongRequestOrder,
                ClassicConnectFault::None,
            ),
            (ClassicConnectFault::WrongMethod, ClassicConnectFault::None),
            (
                ClassicConnectFault::InvalidAuthority,
                ClassicConnectFault::None,
            ),
            (
                ClassicConnectFault::SecondRequest,
                ClassicConnectFault::None,
            ),
            (
                ClassicConnectFault::None,
                ClassicConnectFault::NonSuccessResponse,
            ),
            (
                ClassicConnectFault::None,
                ClassicConnectFault::ExtraResponseField,
            ),
            (
                ClassicConnectFault::None,
                ClassicConnectFault::DuplicateResponseField,
            ),
            (
                ClassicConnectFault::None,
                ClassicConnectFault::ResponseTrailer,
            ),
            (
                ClassicConnectFault::None,
                ClassicConnectFault::ResetAfterResponse,
            ),
        ];

        for (client_fault, server_fault) in cases {
            let task_budget = ConnectionTaskBudget::new();
            let mut pair = start_t026c_loopback_pair(&task_budget, &task_budget).await;
            let _ = receive_loopback_observations(&mut pair).await;
            let (client_lease, server_lease) = tokio::join!(
                pair.client.acquire_authenticated(),
                pair.server.acquire_authenticated(),
            );
            let client_lease = fixed_ok(client_lease, "acquire rejected-flow client lease");
            let server_lease = fixed_ok(server_lease, "acquire rejected-flow server lease");
            let (client_flow, server_flow) = tokio::join!(
                pair.client.open_classic_connect_reference_with_fault(
                    &client_lease,
                    b"rejected-client-pattern",
                    client_fault,
                ),
                pair.server.open_classic_connect_reference_with_fault(
                    &server_lease,
                    b"rejected-server-pattern",
                    server_fault,
                ),
            );
            assert!(client_flow.is_err());
            assert!(server_flow.is_err());
            let (client_exit, server_exit) = tokio::join!(
                timeout(CONNECTION_RUN_TIMEOUT, pair.client.take_driver_exit()),
                timeout(CONNECTION_RUN_TIMEOUT, pair.server.take_driver_exit()),
            );
            assert!(fixed_ok(client_exit, "reclaim rejected-flow client").is_err());
            assert!(fixed_ok(server_exit, "reclaim rejected-flow server").is_err());
            assert_eq!(pair.client_connections_created.load(Ordering::Relaxed), 1);
            assert_eq!(pair.server_connections_created.load(Ordering::Relaxed), 1);
            assert_eq!(pair.server.classic_connect_spy.request_streams_opened(), 0);
            if server_fault == ClassicConnectFault::ResetAfterResponse {
                assert_eq!(pair.client.classic_connect_spy.request_streams_opened(), 1);
            }
            if client_fault == ClassicConnectFault::SecondRequest {
                assert_eq!(pair.client.classic_connect_spy.request_streams_opened(), 2);
            }
            let client_address = pair.client_address;
            let server_address = pair.server_address;
            client_lease.release();
            server_lease.release();
            drop(pair);
            assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
            drop(fixed_ok(
                bind_bounded_loopback_socket(client_address).await,
                "reclaim rejected-flow client socket",
            ));
            drop(fixed_ok(
                bind_bounded_loopback_socket(server_address).await,
                "reclaim rejected-flow server socket",
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t026d_replacement_generation_reauthenticates_without_inheriting_capability() {
        let _test_guard = fixed_ok(
            bounded_test_lock(&LOOPBACK_TEST_LOCK, LOOPBACK_TEST_LOCK_TIMEOUT).await,
            "acquire bounded loopback test lock",
        );
        let task_budget = ConnectionTaskBudget::new();

        let mut first = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut first).await;
        let (first_client, first_server) = tokio::join!(
            first.client.acquire_authenticated(),
            first.server.acquire_authenticated(),
        );
        let first_client = fixed_ok(first_client, "authenticate first client generation");
        let first_server = fixed_ok(first_server, "authenticate first server generation");
        let first_client_generation = first_client.generation();
        let first_server_generation = first_server.generation();
        let (first_client_exit, first_server_exit) = tokio::join!(
            first.client.close_and_take_driver_exit(),
            first.server.close_and_take_driver_exit(),
        );
        assert!(fixed_ok(first_client_exit, "close first client generation")
            .reference_outcome
            .is_some());
        assert!(fixed_ok(first_server_exit, "close first server generation")
            .reference_outcome
            .is_some());
        assert!(!first_client.is_active());
        assert!(!first_server.is_active());

        let mut second = start_t026c_loopback_pair(&task_budget, &task_budget).await;
        let _ = receive_loopback_observations(&mut second).await;
        let (second_client, second_server) = tokio::join!(
            second.client.acquire_authenticated(),
            second.server.acquire_authenticated(),
        );
        let second_client = fixed_ok(second_client, "authenticate replacement client generation");
        let second_server = fixed_ok(second_server, "authenticate replacement server generation");
        assert_ne!(second_client.generation(), first_client_generation);
        assert_ne!(second_server.generation(), first_server_generation);
        assert!(second_client.is_active());
        assert!(second_server.is_active());
        assert_eq!(first.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(first.server_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(second.client_connections_created.load(Ordering::Relaxed), 1);
        assert_eq!(second.server_connections_created.load(Ordering::Relaxed), 1);

        let (second_client_exit, second_server_exit) = tokio::join!(
            second.client.close_and_take_driver_exit(),
            second.server.close_and_take_driver_exit(),
        );
        assert!(
            fixed_ok(second_client_exit, "close replacement client generation")
                .reference_outcome
                .is_some()
        );
        assert!(
            fixed_ok(second_server_exit, "close replacement server generation")
                .reference_outcome
                .is_some()
        );
        assert!(!second_client.is_active());
        assert!(!second_server.is_active());
        first_client.release();
        first_server.release();
        second_client.release();
        second_server.release();
        drop(first);
        drop(second);
        assert_eq!(task_budget.available_permits(), CONNECTION_TASK_LIMIT);
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
            (ReferenceFault::WrongClientReceipt, ReferenceFault::None),
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

            let (client_result, server_result) = tokio::join!(
                pair.client.acquire_authenticated(),
                pair.server.acquire_authenticated(),
            );
            if client_fault == ReferenceFault::WrongClientReceipt
                || server_fault == ReferenceFault::WrongServerConfirmation
            {
                let server_lease = fixed_ok(
                    server_result,
                    "server reaches local confirmation queue boundary",
                );
                assert_eq!(server_lease.admission_expiry_unix(), T026C_NOW + 1_800);
                assert_eq!(server_lease.hard_expiry_unix(), T026C_NOW + 86_400);
                assert_eq!(server_lease.max_frame_size(), 65_536);
                assert_eq!(server_lease.max_concurrent_flows(), 128);
                assert_eq!(server_lease.effective_local_flow_limit(), 1);
                assert!(server_lease.is_active() || pair.server.driver_is_finished());
                assert!(client_result.is_err());
                server_lease.release();
            } else {
                assert!(server_result.is_err());
                assert!(client_result.is_err());
            }

            let (client_exit, server_exit) = tokio::join!(
                timeout(CONNECTION_RUN_TIMEOUT, pair.client.take_driver_exit()),
                timeout(CONNECTION_RUN_TIMEOUT, pair.server.take_driver_exit()),
            );
            assert!(fixed_ok(client_exit, "reclaim rejected H3 client").is_err());
            assert!(fixed_ok(server_exit, "reclaim rejected H3 server").is_err());

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
    fn t023b1_new_flow_admission_is_strict_but_an_armed_flow_keeps_running() {
        let (equal_current, equal_lease) = fixed_ok(
            generation_auth::test_authenticated_lease(401),
            "construct admission-equality lease",
        );
        let mut equal = ClassicConnectReference::new(Some(AuthRole::Client));
        let equal_spy = equal.test_spy();
        let (equal_tx, mut equal_rx) = oneshot::channel();
        assert_eq!(
            equal.arm_at(
                &equal_current,
                lease_command_proof(&equal_lease),
                fixed_ok(
                    FlowBuffer::from_slice(b"admission-equality-pattern"),
                    "construct admission-equality payload",
                ),
                equal_tx,
                equal_current.admission_deadline(),
                ClassicConnectFault::None,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            fixed_ok(equal_rx.try_recv(), "read admission-equality response").err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(equal_spy.header_send_attempts(), 0);
        assert_eq!(equal_spy.request_streams_opened(), 0);
        assert_eq!(equal_spy.buffered_bytes(), 0);
        equal_lease.release();

        let (armed_current, armed_lease) = fixed_ok(
            generation_auth::test_authenticated_lease(402),
            "construct pre-admission lease",
        );
        let mut armed = ClassicConnectReference::new(Some(AuthRole::Client));
        let (armed_tx, _armed_rx) = oneshot::channel();
        fixed_ok(
            armed.arm_at(
                &armed_current,
                lease_command_proof(&armed_lease),
                fixed_ok(
                    FlowBuffer::from_slice(b"pre-admission-pattern"),
                    "construct pre-admission payload",
                ),
                armed_tx,
                armed_current.admission_deadline() - Duration::from_nanos(1),
                ClassicConnectFault::None,
            ),
            "arm flow before admission expiry",
        );
        assert!(armed.route_is_open_for_at(&armed_current, armed_current.admission_deadline()));
        assert!(armed.route_is_open_for_at(
            &armed_current,
            armed_current.admission_deadline() + Duration::from_secs(1)
        ));
        assert!(!armed.route_is_open_for_at(&armed_current, armed_current.hard_deadline()));
        armed.fail_closed();
        armed_lease.release();
    }

    #[test]
    fn t027a1_classic_connect_field_sections_are_exact_and_extended_connect_is_absent() {
        fn owned_headers(pairs: &[(&[u8], &[u8])]) -> Vec<quiche::h3::Header> {
            pairs
                .iter()
                .map(|(name, value)| quiche::h3::Header::new(name, value))
                .collect()
        }

        let request_pairs = classic_connect::request_header_pairs();
        let request = owned_headers(&request_pairs);
        assert!(classic_connect::valid_request_headers(&request));
        assert_eq!(request.len(), 2);
        for forbidden in [b":scheme".as_slice(), b":path", b":protocol"] {
            assert!(request.iter().all(|header| {
                use quiche::h3::NameValue;
                header.name() != forbidden
            }));
        }

        for invalid in [
            request[..1].to_vec(),
            vec![request[0].clone(), request[0].clone()],
            vec![
                request[0].clone(),
                request[1].clone(),
                quiche::h3::Header::new(b"x-extra", b"1"),
            ],
            vec![request[1].clone(), request[0].clone()],
            vec![
                quiche::h3::Header::new(b":method", b"GET"),
                request[1].clone(),
            ],
            vec![
                request[0].clone(),
                quiche::h3::Header::new(b":authority", b"reference.invalid"),
            ],
            vec![
                request[0].clone(),
                quiche::h3::Header::new(b":authority", b"user@reference.invalid:443"),
            ],
            vec![
                request[0].clone(),
                quiche::h3::Header::new(b":authority", b"reference.invalid:0"),
            ],
            vec![
                request[0].clone(),
                quiche::h3::Header::new(b":protocol", b"connect-udp"),
            ],
        ] {
            assert!(!classic_connect::valid_request_headers(&invalid));
        }

        let response_pairs = classic_connect::response_header_pairs();
        let response = owned_headers(&response_pairs);
        assert!(classic_connect::valid_response_headers(&response));
        assert_eq!(response.len(), 1);
        for invalid in [
            Vec::new(),
            vec![quiche::h3::Header::new(b":status", b"403")],
            vec![response[0].clone(), response[0].clone()],
            vec![
                response[0].clone(),
                quiche::h3::Header::new(b"x-extra", b"1"),
            ],
        ] {
            assert!(!classic_connect::valid_response_headers(&invalid));
        }
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    #[test]
    fn t027a1_router_requires_live_lease_and_canceled_command_sends_zero_headers() {
        fn armed_client(
            current: &AuthenticatedGeneration,
            lease: &AuthenticatedConnectionLease,
        ) -> (
            ClassicConnectReference,
            oneshot::Receiver<Result<ClassicConnectOutcome, FoundationError>>,
            ClassicConnectSpy,
        ) {
            let mut reference = ClassicConnectReference::new(Some(AuthRole::Client));
            let spy = reference.test_spy();
            let (response_tx, response_rx) = oneshot::channel();
            fixed_ok(
                reference.arm(
                    current,
                    lease_command_proof(lease),
                    fixed_ok(
                        FlowBuffer::from_slice(b"lease-bound-pattern"),
                        "bound lease payload",
                    ),
                    response_tx,
                    ClassicConnectFault::None,
                ),
                "arm lease-bound classic CONNECT",
            );
            (reference, response_rx, spy)
        }

        let (_temp, mut session) = foundation_strict_test_session();
        fixed_ok(session.handshake(), "handshake lease-bound session");

        let (hard_current, hard_lease) = fixed_ok(
            test_authenticated_lease(500),
            "construct hard-equality test lease",
        );
        let (mut hard, _hard_rx, hard_spy) = armed_client(&hard_current, &hard_lease);
        assert_eq!(
            hard.drive_outbound_at(
                &hard_current,
                &mut session.pipe.client,
                &mut session.client,
                hard_current.hard_deadline(),
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(hard_spy.header_send_attempts(), 0);
        assert_eq!(hard_spy.request_streams_opened(), 0);
        hard.fail_closed();
        hard_lease.release();

        let (released_current, released_lease) = fixed_ok(
            test_authenticated_lease(501),
            "construct released test lease",
        );
        let (mut released, _released_rx, released_spy) =
            armed_client(&released_current, &released_lease);
        released_lease.release();
        assert!(!released.route_is_open_for(&released_current));
        assert_eq!(
            released.drive_outbound(
                &released_current,
                &mut session.pipe.client,
                &mut session.client,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(released_spy.header_send_attempts(), 0);
        assert_eq!(released_spy.request_streams_opened(), 0);

        let (dropped_current, dropped_lease) = fixed_ok(
            test_authenticated_lease(502),
            "construct dropped test lease",
        );
        let (mut dropped, _dropped_rx, dropped_spy) =
            armed_client(&dropped_current, &dropped_lease);
        drop(dropped_lease);
        assert_eq!(
            dropped.drive_outbound(
                &dropped_current,
                &mut session.pipe.client,
                &mut session.client,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(dropped_spy.header_send_attempts(), 0);
        assert_eq!(dropped_spy.request_streams_opened(), 0);

        let (canceled_current, canceled_lease) = fixed_ok(
            test_authenticated_lease(503),
            "construct canceled test lease",
        );
        let (mut canceled, canceled_rx, canceled_spy) =
            armed_client(&canceled_current, &canceled_lease);
        drop(canceled_rx);
        assert_eq!(
            canceled.drive_outbound(
                &canceled_current,
                &mut session.pipe.client,
                &mut session.client,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(canceled_spy.header_send_attempts(), 0);
        assert_eq!(canceled_spy.request_streams_opened(), 0);
        canceled_lease.release();

        let (first_current, first_lease) = fixed_ok(
            test_authenticated_lease(504),
            "construct wrong-generation lease",
        );
        let (replacement_current, replacement_lease) = fixed_ok(
            test_authenticated_lease(505),
            "construct replacement generation",
        );
        let mut wrong_generation = ClassicConnectReference::new(Some(AuthRole::Client));
        let wrong_spy = wrong_generation.test_spy();
        let (wrong_tx, mut wrong_rx) = oneshot::channel();
        assert_eq!(
            wrong_generation.arm(
                &replacement_current,
                lease_command_proof(&first_lease),
                fixed_ok(
                    FlowBuffer::from_slice(b"wrong-generation-pattern"),
                    "wrong generation payload",
                ),
                wrong_tx,
                ClassicConnectFault::None,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            fixed_ok(wrong_rx.try_recv(), "read wrong-generation response").err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(wrong_spy.header_send_attempts(), 0);
        assert_eq!(wrong_spy.request_streams_opened(), 0);
        assert!(first_current.is_active());
        first_lease.release();
        replacement_lease.release();

        let (route_current, route_lease) = fixed_ok(
            test_authenticated_lease(506),
            "construct wrong-stream route lease",
        );
        let (mut route, _route_rx, route_spy) = armed_client(&route_current, &route_lease);
        fixed_ok(
            route.drive_outbound(
                &route_current,
                &mut session.pipe.client,
                &mut session.client,
            ),
            "bind wrong-stream response route",
        );
        let bound_stream = fixed_some(route.test_bound_stream(), "read bound response stream");
        let response_headers: Vec<_> = classic_connect::response_header_pairs()
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name, value))
            .collect();
        assert!(classic_connect::valid_response_headers(&response_headers));
        assert_eq!(
            route.handle_event(
                &route_current,
                &mut session.pipe.client,
                &mut session.client,
                bound_stream + 4,
                quiche::h3::Event::Headers {
                    list: response_headers,
                    more_frames: true,
                },
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        route.fail_closed();
        assert!(!route.route_is_open_for(&route_current));
        let (retry_tx, mut retry_rx) = oneshot::channel();
        assert_eq!(
            route.arm(
                &route_current,
                lease_command_proof(&route_lease),
                fixed_ok(
                    FlowBuffer::from_slice(b"wrong-stream-retry-pattern"),
                    "construct wrong-stream retry payload",
                ),
                retry_tx,
                ClassicConnectFault::None,
            ),
            Err(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(
            fixed_ok(retry_rx.try_recv(), "read wrong-stream retry response").err(),
            Some(FoundationError::PostAuthFlowRejected)
        );
        assert_eq!(route_spy.header_send_attempts(), 1);
        assert_eq!(route_spy.request_streams_opened(), 1);
        route_lease.release();
    }

    #[cfg(feature = "unstable-quiche-strict-push-test-support")]
    #[test]
    fn t027a1_real_streamblocked_partial_and_done_keep_one_stream_and_exact_suffix() {
        let h3_config = fixed_ok(bounded_h3_config(), "build blocked CONNECT H3 config");
        let mut blocked_transport = fixed_ok(
            bounded_self_signed_loopback_quic_config(),
            "build blocked CONNECT transport",
        );
        blocked_transport.set_initial_max_data(125);
        blocked_transport.set_initial_max_stream_data_bidi_local(125);
        blocked_transport.set_initial_max_stream_data_bidi_remote(125);
        blocked_transport.set_initial_max_streams_bidi(100);
        let (_blocked_temp, mut blocked) =
            foundation_test_session_with_configs(blocked_transport, &h3_config);
        fixed_ok(blocked.handshake(), "handshake blocked CONNECT session");
        let fill_headers = [
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"flow.invalid"),
            quiche::h3::Header::new(b":path", b"/fill"),
        ];
        assert_eq!(
            blocked
                .client
                .send_request(&mut blocked.pipe.client, &fill_headers, true),
            Ok(0)
        );
        let blocked_headers: Vec<_> = classic_connect::request_header_pairs()
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name, value))
            .collect();
        assert_eq!(
            blocked
                .client
                .send_request(&mut blocked.pipe.client, &blocked_headers, false,),
            Err(quiche::h3::Error::StreamBlocked)
        );
        let (blocked_current, blocked_lease) = fixed_ok(
            test_authenticated_lease(601),
            "construct blocked CONNECT lease",
        );
        let mut blocked_reference = ClassicConnectReference::new(Some(AuthRole::Client));
        let blocked_spy = blocked_reference.test_spy();
        let (blocked_tx, _blocked_rx) = oneshot::channel();
        fixed_ok(
            blocked_reference.arm(
                &blocked_current,
                lease_command_proof(&blocked_lease),
                fixed_ok(
                    FlowBuffer::from_slice(b"blocked-connect-pattern"),
                    "construct blocked CONNECT payload",
                ),
                blocked_tx,
                ClassicConnectFault::None,
            ),
            "arm blocked CONNECT reference",
        );
        fixed_ok(
            blocked_reference.drive_outbound(
                &blocked_current,
                &mut blocked.pipe.client,
                &mut blocked.client,
            ),
            "observe real CONNECT StreamBlocked",
        );
        assert_eq!(blocked_spy.header_send_attempts(), 1);
        assert_eq!(blocked_spy.request_streams_opened(), 0);
        assert!(blocked_reference.route_is_open_for(&blocked_current));
        blocked_lease.release();

        let mut body_transport = fixed_ok(
            bounded_self_signed_loopback_quic_config(),
            "build partial CONNECT transport",
        );
        body_transport.set_initial_max_data(10_000);
        body_transport.set_initial_max_stream_data_bidi_local(100);
        body_transport.set_initial_max_stream_data_bidi_remote(1_024);
        let (_body_temp, mut body) =
            foundation_test_session_with_configs(body_transport, &h3_config);
        fixed_ok(body.handshake(), "handshake partial CONNECT session");
        let request_headers: Vec<_> = classic_connect::request_header_pairs()
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name, value))
            .collect();
        let stream_id = fixed_ok(
            body.client
                .send_request(&mut body.pipe.client, &request_headers, false),
            "send partial CONNECT request",
        );
        fixed_ok(body.advance(), "advance partial CONNECT request");
        assert!(matches!(
            body.poll_server(),
            Ok((received, quiche::h3::Event::Headers { .. })) if received == stream_id
        ));
        let response_headers: Vec<_> = classic_connect::response_header_pairs()
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name, value))
            .collect();
        fixed_ok(
            body.server
                .send_response(&mut body.pipe.server, stream_id, &response_headers, false),
            "send partial CONNECT response headers",
        );

        let length = 1_024;
        let mut original = [0_u8; classic_connect::FLOW_BUFFER_LIMIT];
        for (index, byte) in original[..length].iter_mut().enumerate() {
            *byte = ((index * 29 + 17) % 251) as u8;
        }
        let mut send = fixed_ok(
            BodySendState::bounded(original, length, stream_id, length),
            "construct bounded CONNECT send state",
        );
        let (first_pending, first_fin) = send.pending();
        let first_pending_len = first_pending.len();
        let first_result =
            body.server
                .send_body(&mut body.pipe.server, stream_id, first_pending, first_fin);
        let first_written = fixed_ok(first_result, "observe real partial CONNECT write");
        assert!(first_written > 0 && first_written < first_pending_len);
        assert!(!fixed_ok(
            record_bounded_send_result(
                &mut send,
                first_pending_len,
                Ok(first_written),
                FoundationError::PostAuthFlowRejected,
            ),
            "record real partial CONNECT write",
        ));
        let (first_suffix, first_suffix_fin) = send.pending();
        assert_eq!(first_suffix, &original[first_written..length]);
        assert!(first_suffix_fin);
        assert_eq!(send.stream_id(), stream_id);

        let done_result = body.server.send_body(
            &mut body.pipe.server,
            stream_id,
            first_suffix,
            first_suffix_fin,
        );
        assert_eq!(done_result, Err(quiche::h3::Error::Done));
        let first_suffix_len = first_suffix.len();
        assert!(!fixed_ok(
            record_bounded_send_result(
                &mut send,
                first_suffix_len,
                done_result,
                FoundationError::PostAuthFlowRejected,
            ),
            "record real CONNECT Done",
        ));
        assert_eq!(send.pending().0, &original[first_written..length]);
        assert_eq!(send.stream_id(), stream_id);

        let mut received = [0_u8; classic_connect::FLOW_BUFFER_LIMIT];
        let mut received_len = 0;
        let mut send_complete = false;
        let mut response_finished = false;
        let mut send_calls = 2;
        for _ in 0..64 {
            fixed_ok(body.advance(), "advance partial CONNECT data");
            loop {
                match body.poll_client() {
                    Ok((received_stream, quiche::h3::Event::Headers { list, .. })) => {
                        assert_eq!(received_stream, stream_id);
                        assert!(classic_connect::valid_response_headers(&list));
                    }
                    Ok((received_stream, quiche::h3::Event::Data)) => {
                        assert_eq!(received_stream, stream_id);
                        loop {
                            match body.client.recv_body(
                                &mut body.pipe.client,
                                stream_id,
                                &mut received[received_len..length],
                            ) {
                                Ok(0) => panic!("partial CONNECT receive made zero progress"),
                                Ok(read) => received_len += read,
                                Err(quiche::h3::Error::Done) => break,
                                Err(_) => panic!("partial CONNECT receive failed"),
                            }
                        }
                    }
                    Ok((received_stream, quiche::h3::Event::Finished)) => {
                        assert_eq!(received_stream, stream_id);
                        response_finished = true;
                    }
                    Ok(_) => panic!("unexpected partial CONNECT event"),
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => panic!("partial CONNECT poll failed"),
                }
            }
            if send_complete && response_finished {
                break;
            }
            fixed_ok(body.advance(), "return partial CONNECT flow control");
            if !send_complete {
                let (pending, fin) = send.pending();
                let pending_len = pending.len();
                let result = body
                    .server
                    .send_body(&mut body.pipe.server, stream_id, pending, fin);
                send_calls += 1;
                send_complete = fixed_ok(
                    record_bounded_send_result(
                        &mut send,
                        pending_len,
                        result,
                        FoundationError::PostAuthFlowRejected,
                    ),
                    "record resumed CONNECT send",
                );
            }
        }
        assert!(send_complete);
        assert!(response_finished);
        assert!(send_calls > 2);
        assert_eq!(send.stream_id(), stream_id);
        assert_eq!(send.sent_len(), length);
        assert_eq!(received_len, length);
        assert_eq!(&received[..received_len], &original[..length]);
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
        let invalid_userinfo_marker = ["user", "@", "reference.invalid:443"].concat();
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
                FoundationError::PostAuthFlowRejected,
                "native H3 post-auth flow rejected",
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
                    "reference.invalid",
                    ":authority",
                    invalid_userinfo_marker.as_str(),
                    T026C_AUTHORITY,
                    T026C_CONTROL_PATH,
                    "POST",
                    "CONNECT",
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
