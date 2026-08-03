//! Private, connection-local native-quiche server ownership seam.
//!
//! This module performs no DNS lookup or target connect and owns no listener,
//! connection registry, task, or channel. A pending Classic CONNECT slot may
//! own one already-connected target socket handed back by its outer driver.
//! That driver can synchronously feed one bounded packet at a time, drain one
//! bounded packet at a time, and schedule the returned timer.

#![forbid(unsafe_code)]

use crate::h3_connect::parse_classic_connect_request;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::ssl::{SslRef, SslVersion};
use maverick_core::auth_v3::{
    encode_auth_v3_server_confirmation, verify_auth_v3_client_control, AuthV3Carrier,
    AuthV3ServerConfirmationInput, AuthV3TlsVersion, AUTH_V3_CLIENT_CONTROL_LEN,
    AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN, AUTH_V3_SERVER_CONFIRMATION_LEN,
};
use maverick_core::config::{
    DirectV3ServerRoleConfig, DirectV3TransportStrategy, ServerEgressPolicyConfig, ServerRoleConfig,
};
use maverick_core::frame::TargetAddr;
use quiche::h3::NameValue;
use rand::{rngs::OsRng, TryRngCore};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;

pub(super) const MAX_PACKET_BYTES: usize = 1_350;
const INITIAL_CONNECTION_WINDOW_BYTES: u64 = 1_048_576;
const INITIAL_BIDI_STREAM_WINDOW_BYTES: u64 = 65_536;
const INITIAL_UNI_STREAM_WINDOW_BYTES: u64 = 16_384;
const MAX_STREAM_WINDOW_BYTES: u64 = 65_536;
const MAX_BIDI_STREAMS: u64 = 8;
const MAX_PENDING_CLASSIC_CONNECTS: usize = MAX_BIDI_STREAMS as usize;
pub(super) const MAX_TARGET_DISPATCH_FUTURES: usize = MAX_PENDING_CLASSIC_CONNECTS;
const TARGET_TO_CLIENT_BUFFER_BYTES: usize = 16 * 1024;
const CLIENT_TO_TARGET_BUFFER_BYTES: usize = 16 * 1024;
const TARGET_IO_DIRECTIONS: usize = 2;
const TARGET_IO_CURSOR_LENGTH: usize = MAX_PENDING_CLASSIC_CONNECTS * TARGET_IO_DIRECTIONS;
const MAX_TARGET_IO_OPERATIONS_PER_ROUND: usize = 4;
const TARGET_IO_MAX_OPERATION_BYTES: usize = 16 * 1024;
#[cfg(test)]
const MAX_TARGET_TO_CLIENT_IO_OPERATIONS_PER_ROUND: usize = MAX_TARGET_IO_OPERATIONS_PER_ROUND;
const _: () = assert!(TARGET_TO_CLIENT_BUFFER_BYTES * MAX_PENDING_CLASSIC_CONNECTS <= 128 * 1024);
const _: () = assert!(CLIENT_TO_TARGET_BUFFER_BYTES * MAX_PENDING_CLASSIC_CONNECTS <= 128 * 1024);
const _: () = assert!(
    (TARGET_TO_CLIENT_BUFFER_BYTES + CLIENT_TO_TARGET_BUFFER_BYTES) * MAX_PENDING_CLASSIC_CONNECTS
        <= 256 * 1024
);
const _: () =
    assert!(TARGET_IO_MAX_OPERATION_BYTES * MAX_TARGET_IO_OPERATIONS_PER_ROUND <= 64 * 1024);
const MAX_UNI_STREAMS: u64 = 8;
const MAX_FIELD_SECTION_BYTES: u64 = 16_384;
const QPACK_MAX_TABLE_CAPACITY: u64 = 0;
const QPACK_BLOCKED_STREAMS: u64 = 0;
const MAX_PRIORITY_UPDATE_BYTES: u64 = 256;
const DATAGRAM_QUEUE_LIMIT: usize = 32;
const MAX_DATAGRAM_FRAME_BYTES: u64 = 65_536;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const PATH_CHALLENGE_QUEUE_LIMIT: usize = 3;
const MAX_IDLE_TIMEOUT_MILLIS: u64 = 5_000;
const PRE_AUTH_CLOSE_CODE: u64 = 0x105;
pub(super) const AUTH_WALL_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_CONTENT_TYPE: &[u8] = b"application/maverick-auth-v3";
const AUTH_ADMISSION_LIFETIME_SECONDS: u64 = 1_800;
const AUTH_HARD_LIFETIME_SECONDS: u64 = 86_400;
const AUTH_MAX_FRAME_SIZE: u32 = 65_536;
const AUTH_MAX_CONCURRENT_FLOWS: u32 = 128;
const MAX_H3_EVENTS_PER_DRIVE: usize = 8;
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

#[derive(Clone, Copy)]
pub(super) struct PacketMeta {
    pub(super) from: SocketAddr,
    pub(super) to: SocketAddr,
}

#[derive(Clone)]
pub(super) struct FrozenDirectV3ServerRole {
    owner: Arc<ServerRoleConfig>,
}

impl FrozenDirectV3ServerRole {
    pub(super) fn new(owner: Arc<ServerRoleConfig>) -> Result<Self, RuntimeError> {
        let Some(direct) = owner.direct_v3() else {
            return Err(RuntimeError::RoleUnavailable);
        };
        if owner.version() != 3 || direct.transport_strategy() != DirectV3TransportStrategy::H3 {
            return Err(RuntimeError::RoleUnavailable);
        }
        let _preselected_before_io = direct.preselected_profile();
        Ok(Self { owner })
    }

    fn direct_v3(&self) -> &DirectV3ServerRoleConfig {
        self.owner
            .direct_v3()
            .expect("frozen direct-v3 server role remains validated")
    }

    fn expected_authority(&self) -> &[u8] {
        self.direct_v3().expected_authority().as_bytes()
    }

    fn tunnel_path(&self) -> &[u8] {
        self.direct_v3().tunnel_path().as_bytes()
    }

    pub(super) fn listen(&self) -> SocketAddr {
        self.direct_v3().listen()
    }

    #[cfg(test)]
    pub(super) fn has_owner(&self, expected: &Arc<ServerRoleConfig>) -> bool {
        Arc::ptr_eq(&self.owner, expected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerAuthState {
    Fresh,
    Authenticating,
    SendingConfirmation,
    Authenticated,
    Failed,
}

struct AuthenticatedGenerationCapability {
    generation: ServerSourceConnectionId,
    session_id: [u8; 16],
    credential_epoch: u64,
    admission_expiry_unix: u64,
    hard_expiry_unix: u64,
    admission_deadline: Instant,
    hard_deadline: Instant,
    active: bool,
    revoked: bool,
    carrier: AuthV3Carrier,
    max_frame_size: u32,
    max_concurrent_flows: u32,
}

impl AuthenticatedGenerationCapability {
    fn activate_at(mut self, now: Instant) -> Result<Self, RuntimeError> {
        if self.active
            || self.revoked
            || now >= self.admission_deadline
            || now >= self.hard_deadline
        {
            return Err(RuntimeError::AuthenticationExpired);
        }
        self.active = true;
        Ok(self)
    }

    fn is_active_at(&self, now: Instant) -> bool {
        self.active && !self.revoked && now < self.hard_deadline
    }

    fn permits_admission_at(&self, generation: &ServerSourceConnectionId, now: Instant) -> bool {
        self.active
            && !self.revoked
            && self.generation.as_bytes() == generation.as_bytes()
            && now < self.admission_deadline
            && now < self.hard_deadline
    }

    fn revoke(&mut self) {
        self.active = false;
        self.revoked = true;
    }

    fn pending_deadline(&self) -> Instant {
        self.admission_deadline.min(self.hard_deadline)
    }

    fn pending_is_valid_at(&self, now: Instant) -> bool {
        !self.active && !self.revoked && now < self.admission_deadline && now < self.hard_deadline
    }

    fn permits_completion_at(&self, generation: &ServerSourceConnectionId, now: Instant) -> bool {
        self.active
            && !self.revoked
            && self.generation.as_bytes() == generation.as_bytes()
            && now < self.hard_deadline
    }

    fn permits_response_at(&self, generation: &ServerSourceConnectionId, now: Instant) -> bool {
        self.active
            && !self.revoked
            && self.generation.as_bytes() == generation.as_bytes()
            && now < self.hard_deadline
    }
}

impl fmt::Debug for AuthenticatedGenerationCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authenticated server generation capability")
    }
}

struct PendingClassicConnect {
    generation: ServerSourceConnectionId,
    stream_id: u64,
    target: Option<TargetAddr>,
    port: u16,
    peer_write_half_closed: bool,
    max_frame_size: u32,
    dispatch_state: TargetDispatchState,
    opened_target: Option<TcpStream>,
    target_payload: Box<[u8; TARGET_TO_CLIENT_BUFFER_BYTES]>,
    upload_state: UploadDispatchState,
    upload_payload: Box<[u8; CLIENT_TO_TARGET_BUFFER_BYTES]>,
    #[cfg(test)]
    target_read_failure_requested: bool,
    #[cfg(test)]
    target_write_failure_requested: bool,
    #[cfg(test)]
    target_shutdown_failure_requested: bool,
}

impl fmt::Debug for PendingClassicConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("pending Classic CONNECT metadata")
    }
}

impl PendingClassicConnect {
    fn clear_payloads(&mut self) {
        self.target_payload.fill(0);
        self.upload_payload.fill(0);
    }
}

impl Drop for PendingClassicConnect {
    fn drop(&mut self) {
        self.clear_payloads();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetDispatchState {
    Admitted,
    InFlight,
    ResponsePending,
    ResponseAccepted,
    BodyPending { offset: usize, length: usize },
    TargetEofFinPending,
    ResponseFinAccepted,
}

impl TargetDispatchState {
    fn owns_opened_target(self) -> bool {
        matches!(
            self,
            Self::ResponsePending
                | Self::ResponseAccepted
                | Self::BodyPending { .. }
                | Self::TargetEofFinPending
                | Self::ResponseFinAccepted
        )
    }

    fn response_was_accepted(self) -> bool {
        matches!(
            self,
            Self::ResponseAccepted
                | Self::BodyPending { .. }
                | Self::TargetEofFinPending
                | Self::ResponseFinAccepted
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UploadDispatchState {
    Idle,
    RecvPending,
    WritePending { offset: usize, length: usize },
    ShutdownPending,
    WriteHalfClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TargetIoDirection {
    TargetToClient,
    ClientToTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TargetIoSignal {
    slot_index: usize,
    direction: TargetIoDirection,
}

impl TargetIoSignal {
    fn position(self) -> usize {
        self.slot_index * TARGET_IO_DIRECTIONS
            + match self.direction {
                TargetIoDirection::TargetToClient => 0,
                TargetIoDirection::ClientToTarget => 1,
            }
    }

    fn from_position(position: usize) -> Self {
        Self {
            slot_index: position / TARGET_IO_DIRECTIONS,
            direction: if position.is_multiple_of(TARGET_IO_DIRECTIONS) {
                TargetIoDirection::TargetToClient
            } else {
                TargetIoDirection::ClientToTarget
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TargetIoRound {
    operations: usize,
    #[cfg(test)]
    progress_operations: usize,
    operation_progress_bytes: usize,
    #[cfg(test)]
    upload_recv_progress_mask: usize,
    #[cfg(test)]
    target_write_progress_mask: usize,
    #[cfg(test)]
    target_write_blocked_mask: usize,
    #[cfg(test)]
    target_shutdown_progress_mask: usize,
}

impl TargetIoRound {
    pub(super) const fn operations(self) -> usize {
        self.operations
    }

    #[cfg(test)]
    pub(super) const fn progress_operations(self) -> usize {
        self.progress_operations
    }

    #[cfg(test)]
    const fn operation_progress_bytes(self) -> usize {
        self.operation_progress_bytes
    }

    #[cfg(test)]
    pub(super) const fn upload_recv_progress_mask(self) -> usize {
        self.upload_recv_progress_mask
    }

    #[cfg(test)]
    pub(super) const fn target_write_progress_mask(self) -> usize {
        self.target_write_progress_mask
    }

    #[cfg(test)]
    pub(super) const fn target_write_blocked_mask(self) -> usize {
        self.target_write_blocked_mask
    }

    #[cfg(test)]
    pub(super) const fn target_shutdown_progress_mask(self) -> usize {
        self.target_shutdown_progress_mask
    }

    #[cfg(test)]
    fn observe_operation(
        &mut self,
        signal: TargetIoSignal,
        upload_before: Option<UploadDispatchState>,
        outcome: TargetIoOutcome,
    ) {
        if signal.direction != TargetIoDirection::ClientToTarget {
            return;
        }
        let bit = 1_usize << signal.slot_index;
        match (upload_before, outcome) {
            (Some(UploadDispatchState::RecvPending), TargetIoOutcome::Progress { .. }) => {
                self.upload_recv_progress_mask |= bit;
            }
            (Some(UploadDispatchState::WritePending { .. }), TargetIoOutcome::Progress { .. }) => {
                self.target_write_progress_mask |= bit;
            }
            (Some(UploadDispatchState::WritePending { .. }), TargetIoOutcome::Blocked) => {
                self.target_write_blocked_mask |= bit;
            }
            (Some(UploadDispatchState::ShutdownPending), TargetIoOutcome::StateTransition) => {
                self.target_shutdown_progress_mask |= bit;
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetIoOutcome {
    Progress { bytes: usize },
    StateTransition,
    Blocked,
    Quiescent,
}

pub(super) struct TargetOpenDispatchToken {
    generation: ServerSourceConnectionId,
    stream_id: u64,
    target: TargetAddr,
    port: u16,
    max_frame_size: u32,
    egress_policy: ServerEgressPolicyConfig,
    attempt_deadline: Instant,
}

impl TargetOpenDispatchToken {
    pub(super) const fn attempt_deadline(&self) -> Instant {
        self.attempt_deadline
    }

    pub(super) fn is_structurally_valid(&self) -> bool {
        let target_is_present = match &self.target {
            TargetAddr::Domain(domain) => !domain.is_empty(),
            TargetAddr::Ipv4(_) | TargetAddr::Ipv6(_) => true,
        };
        let _read_only_policy = self.egress_policy;
        target_is_present && self.port != 0 && self.max_frame_size != 0
    }

    #[cfg(test)]
    fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub(super) fn target(&self) -> &TargetAddr {
        &self.target
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn egress_policy(&self) -> ServerEgressPolicyConfig {
        self.egress_policy
    }
}

impl fmt::Debug for TargetOpenDispatchToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private target-open dispatch token")
    }
}

struct PendingClassicConnectSlots {
    slots: [Option<PendingClassicConnect>; MAX_PENDING_CLASSIC_CONNECTS],
}

impl PendingClassicConnectSlots {
    fn empty() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
        }
    }

    fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    fn quota_for(capability: &AuthenticatedGenerationCapability) -> usize {
        usize::try_from(capability.max_concurrent_flows)
            .unwrap_or(0)
            .min(MAX_PENDING_CLASSIC_CONNECTS)
    }

    fn has_quota_for(&self, capability: &AuthenticatedGenerationCapability) -> bool {
        self.len() < Self::quota_for(capability)
    }

    fn contains_stream(&self, stream_id: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|pending| pending.stream_id == stream_id)
    }

    fn insert(
        &mut self,
        pending: PendingClassicConnect,
        capability: &AuthenticatedGenerationCapability,
    ) -> Result<(), RuntimeError> {
        if !self.has_quota_for(capability)
            || self.contains_stream(pending.stream_id)
            || pending.generation.as_bytes() != capability.generation.as_bytes()
            || pending.max_frame_size != capability.max_frame_size
            || pending.target.is_none()
            || pending.dispatch_state != TargetDispatchState::Admitted
            || pending.opened_target.is_some()
        {
            return Err(RuntimeError::ClassicConnectAdmissionRejected);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(RuntimeError::ClassicConnectAdmissionRejected)?;
        *slot = Some(pending);
        Ok(())
    }

    fn mark_peer_write_half_closed(&mut self, stream_id: u64) -> Result<(), RuntimeError> {
        let pending = self
            .slots
            .iter_mut()
            .flatten()
            .find(|pending| pending.stream_id == stream_id)
            .ok_or(RuntimeError::ClassicConnectAdmissionRejected)?;
        if pending.peer_write_half_closed {
            return Err(RuntimeError::ClassicConnectAdmissionRejected);
        }
        if pending.dispatch_state.response_was_accepted() {
            match pending.upload_state {
                UploadDispatchState::Idle => {
                    pending.upload_state = UploadDispatchState::ShutdownPending;
                }
                UploadDispatchState::RecvPending | UploadDispatchState::WritePending { .. } => {}
                UploadDispatchState::ShutdownPending | UploadDispatchState::WriteHalfClosed => {
                    return Err(RuntimeError::ClassicConnectAdmissionRejected);
                }
            }
        } else if pending.upload_state != UploadDispatchState::Idle {
            return Err(RuntimeError::ClassicConnectAdmissionRejected);
        }
        pending.peer_write_half_closed = true;
        Ok(())
    }

    fn stream_ids_requiring_send(&self) -> [Option<u64>; MAX_PENDING_CLASSIC_CONNECTS] {
        std::array::from_fn(|index| {
            self.slots[index].as_ref().and_then(|pending| {
                (pending.dispatch_state != TargetDispatchState::ResponseFinAccepted)
                    .then_some(pending.stream_id)
            })
        })
    }

    fn next_admitted_index(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|pending| pending.dispatch_state == TargetDispatchState::Admitted)
        })
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            if let Some(pending) = slot.as_mut() {
                pending.clear_payloads();
            }
            *slot = None;
        }
    }
}

impl Drop for PendingClassicConnectSlots {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for PendingClassicConnectSlots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded pending Classic CONNECT slots")
    }
}

struct ServerAuthMachine {
    state: ServerAuthState,
    wall_deadline: Option<Instant>,
    stream_id: Option<u64>,
    control: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
    control_len: usize,
    exporter: [u8; AUTH_V3_EXPORTER_LEN],
    confirmation: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
    confirmation_headers_sent: bool,
    confirmation_offset: usize,
    pending: Option<AuthenticatedGenerationCapability>,
    capability: Option<AuthenticatedGenerationCapability>,
}

impl ServerAuthMachine {
    fn fresh() -> Self {
        Self {
            state: ServerAuthState::Fresh,
            wall_deadline: None,
            stream_id: None,
            control: [0; AUTH_V3_CLIENT_CONTROL_LEN],
            control_len: 0,
            exporter: [0; AUTH_V3_EXPORTER_LEN],
            confirmation: [0; AUTH_V3_SERVER_CONFIRMATION_LEN],
            confirmation_headers_sent: false,
            confirmation_offset: 0,
            pending: None,
            capability: None,
        }
    }

    fn transition(&mut self, next: ServerAuthState) -> Result<(), RuntimeError> {
        let legal = matches!(
            (self.state, next),
            (ServerAuthState::Fresh, ServerAuthState::Authenticating)
                | (
                    ServerAuthState::Authenticating,
                    ServerAuthState::SendingConfirmation
                )
                | (
                    ServerAuthState::SendingConfirmation,
                    ServerAuthState::Authenticated
                )
        );
        if !legal {
            return Err(RuntimeError::AuthenticationRejected);
        }
        self.state = next;
        Ok(())
    }

    fn start(
        &mut self,
        stream_id: u64,
        exporter: [u8; AUTH_V3_EXPORTER_LEN],
    ) -> Result<(), RuntimeError> {
        self.transition(ServerAuthState::Authenticating)?;
        self.stream_id = Some(stream_id);
        self.exporter = exporter;
        Ok(())
    }

    fn enter_gate(&mut self, now: Instant) -> Result<(), RuntimeError> {
        if self.state != ServerAuthState::Fresh {
            return Ok(());
        }
        if self.wall_deadline.is_none() {
            self.wall_deadline = now.checked_add(AUTH_WALL_TIMEOUT);
        }
        self.wall_deadline
            .is_some()
            .then_some(())
            .ok_or(RuntimeError::AuthenticationUnavailable)
    }

    fn install_confirmation(
        &mut self,
        confirmation: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
        pending: AuthenticatedGenerationCapability,
    ) -> Result<(), RuntimeError> {
        self.transition(ServerAuthState::SendingConfirmation)?;
        self.control.fill(0);
        self.control_len = 0;
        self.exporter.fill(0);
        self.confirmation = confirmation;
        self.confirmation_headers_sent = false;
        self.confirmation_offset = 0;
        self.pending = Some(pending);
        Ok(())
    }

    fn authenticate(&mut self, now: Instant) -> Result<(), RuntimeError> {
        if !self.confirmation_headers_sent
            || self.confirmation_offset != AUTH_V3_SERVER_CONFIRMATION_LEN
        {
            return Err(RuntimeError::AuthenticationRejected);
        }
        if self.wall_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(RuntimeError::AuthenticationExpired);
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(RuntimeError::AuthenticationRejected)?;
        if !pending.pending_is_valid_at(now) {
            return Err(RuntimeError::AuthenticationExpired);
        }
        let pending = self
            .pending
            .take()
            .ok_or(RuntimeError::AuthenticationRejected)?;
        let capability = pending.activate_at(now)?;
        self.transition(ServerAuthState::Authenticated)?;
        self.confirmation.fill(0);
        self.wall_deadline = None;
        self.capability = Some(capability);
        Ok(())
    }

    fn mark_confirmation_headers_sent(&mut self) -> Result<(), RuntimeError> {
        if self.state != ServerAuthState::SendingConfirmation || self.confirmation_headers_sent {
            return Err(RuntimeError::AuthenticationRejected);
        }
        self.confirmation_headers_sent = true;
        Ok(())
    }

    fn record_confirmation_write(
        &mut self,
        written: usize,
        requested: usize,
    ) -> Result<bool, RuntimeError> {
        let remaining = AUTH_V3_SERVER_CONFIRMATION_LEN
            .checked_sub(self.confirmation_offset)
            .ok_or(RuntimeError::AuthenticationRejected)?;
        if self.state != ServerAuthState::SendingConfirmation
            || !self.confirmation_headers_sent
            || written == 0
            || written > requested
            || requested != remaining
        {
            return Err(RuntimeError::AuthenticationRejected);
        }
        self.confirmation_offset += written;
        Ok(written == requested)
    }

    fn fail(&mut self) {
        self.clear_buffers();
        if let Some(pending) = self.pending.as_mut() {
            pending.revoke();
        }
        if let Some(capability) = self.capability.as_mut() {
            capability.revoke();
        }
        self.pending = None;
        self.capability = None;
        self.wall_deadline = None;
        self.stream_id = None;
        self.state = ServerAuthState::Failed;
    }

    fn revoke(&mut self) {
        if let Some(pending) = self.pending.as_mut() {
            pending.revoke();
        }
        if let Some(capability) = self.capability.as_mut() {
            capability.revoke();
        }
    }

    fn clear_buffers(&mut self) {
        self.control.fill(0);
        self.control_len = 0;
        self.exporter.fill(0);
        self.confirmation.fill(0);
        self.confirmation_headers_sent = false;
        self.confirmation_offset = 0;
    }

    fn bound_stream(&self) -> Result<u64, RuntimeError> {
        self.stream_id.ok_or(RuntimeError::AuthenticationRejected)
    }

    fn is_authenticated(&self) -> bool {
        self.state == ServerAuthState::Authenticated
            && self
                .capability
                .as_ref()
                .is_some_and(|capability| capability.is_active_at(Instant::now()))
    }

    fn capability_deadline(&self) -> Option<Instant> {
        let pending = self
            .pending
            .as_ref()
            .filter(|capability| !capability.active && !capability.revoked)
            .map(AuthenticatedGenerationCapability::pending_deadline);
        let active = self
            .capability
            .as_ref()
            .filter(|capability| capability.active && !capability.revoked)
            .map(|capability| capability.hard_deadline);
        match (pending, active) {
            (Some(pending), Some(active)) => Some(pending.min(active)),
            (Some(pending), None) => Some(pending),
            (None, Some(active)) => Some(active),
            (None, None) => None,
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        match (self.wall_deadline, self.capability_deadline()) {
            (Some(wall), Some(capability)) => Some(wall.min(capability)),
            (Some(wall), None) => Some(wall),
            (None, Some(capability)) => Some(capability),
            (None, None) => None,
        }
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        self.wall_deadline.is_some_and(|deadline| now >= deadline)
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| !pending.pending_is_valid_at(now))
            || self
                .capability
                .as_ref()
                .is_some_and(|capability| !capability.is_active_at(now))
    }
}

impl Drop for ServerAuthMachine {
    fn drop(&mut self) {
        self.revoke();
        self.clear_buffers();
    }
}

impl fmt::Debug for ServerAuthMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.state {
            ServerAuthState::Fresh => "fresh server authentication state",
            ServerAuthState::Authenticating => "authenticating server state",
            ServerAuthState::SendingConfirmation => "sending server confirmation state",
            ServerAuthState::Authenticated => "authenticated server state",
            ServerAuthState::Failed => "failed server authentication state",
        })
    }
}

impl fmt::Debug for FrozenDirectV3ServerRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("frozen direct-v3 server role")
    }
}

#[derive(Clone, Copy)]
pub(super) struct ServerSourceConnectionId([u8; quiche::MAX_CONN_ID_LEN]);

impl ServerSourceConnectionId {
    pub(super) fn new(bytes: [u8; quiche::MAX_CONN_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_quiche(&self) -> quiche::ConnectionId<'_> {
        quiche::ConnectionId::from_ref(&self.0)
    }
}

pub(super) struct ServerConnectionConfig {
    transport: quiche::Config,
    role: FrozenDirectV3ServerRole,
}

impl ServerConnectionConfig {
    pub(super) fn new(role: FrozenDirectV3ServerRole) -> Result<Self, RuntimeError> {
        let mut transport = bounded_transport_config()?;
        let direct = role.direct_v3();
        transport
            .load_cert_chain_from_pem_file(private_path(direct.cert_path())?)
            .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
        transport
            .load_priv_key_from_pem_file(private_path(direct.key_path())?)
            .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
        Ok(Self { transport, role })
    }

    #[cfg(test)]
    pub(super) fn has_role_owner(&self, expected: &Arc<ServerRoleConfig>) -> bool {
        self.role.has_owner(expected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreAuthFoundationState {
    AwaitingHandshake,
    AwaitingPeerSettings,
    Ready,
}

impl PreAuthFoundationState {
    fn h3_initialized(&mut self) {
        if *self == Self::AwaitingHandshake {
            *self = Self::AwaitingPeerSettings;
        }
    }

    fn peer_settings_verified(&mut self) {
        if *self == Self::AwaitingPeerSettings {
            *self = Self::Ready;
        }
    }

    const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

pub(super) struct ServerConnection {
    transport: quiche::Connection,
    h3_config: Option<quiche::h3::Config>,
    h3: Option<quiche::h3::Connection>,
    role: FrozenDirectV3ServerRole,
    generation: ServerSourceConnectionId,
    auth: ServerAuthMachine,
    pending_connects: PendingClassicConnectSlots,
    target_io_cursor: usize,
    #[cfg(test)]
    auth_body_read_calls: usize,
    #[cfg(test)]
    target_read_calls: usize,
    #[cfg(test)]
    target_send_body_calls: usize,
    #[cfg(test)]
    upload_recv_body_calls: usize,
    #[cfg(test)]
    upload_data_events: usize,
    #[cfg(test)]
    target_write_calls: usize,
    #[cfg(test)]
    target_shutdown_calls: usize,
    pre_auth_foundation: PreAuthFoundationState,
    local_address: SocketAddr,
    peer_address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectionLifecycle {
    Active,
    ClosingPendingSend,
    Draining,
    Closed,
}

impl ServerConnection {
    pub(super) fn accept_initial(
        config: &mut ServerConnectionConfig,
        source_connection_id: ServerSourceConnectionId,
        packet: &mut [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<Self, RuntimeError> {
        let packet = bounded_packet(packet, length)?;
        let header = quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN)
            .map_err(|_| RuntimeError::InitialPacketRejected)?;
        if header.ty != quiche::Type::Initial || !quiche::version_is_supported(header.version) {
            return Err(RuntimeError::InitialPacketRejected);
        }
        if header.dcid.as_ref() == source_connection_id.as_bytes() {
            return Err(RuntimeError::InitialPacketRejected);
        }

        let quiche_source_connection_id = source_connection_id.as_quiche();
        let mut transport = quiche::accept(
            &quiche_source_connection_id,
            None,
            meta.to,
            meta.from,
            &mut config.transport,
        )
        .map_err(|_| RuntimeError::ConnectionUnavailable)?;
        transport
            .recv(
                packet,
                quiche::RecvInfo {
                    from: meta.from,
                    to: meta.to,
                },
            )
            .map_err(|_| RuntimeError::PacketRejected)?;

        let mut connection = Self {
            transport,
            h3_config: Some(bounded_h3_config()?),
            h3: None,
            role: config.role.clone(),
            generation: source_connection_id,
            auth: ServerAuthMachine::fresh(),
            pending_connects: PendingClassicConnectSlots::empty(),
            target_io_cursor: 0,
            #[cfg(test)]
            auth_body_read_calls: 0,
            #[cfg(test)]
            target_read_calls: 0,
            #[cfg(test)]
            target_send_body_calls: 0,
            #[cfg(test)]
            upload_recv_body_calls: 0,
            #[cfg(test)]
            upload_data_events: 0,
            #[cfg(test)]
            target_write_calls: 0,
            #[cfg(test)]
            target_shutdown_calls: 0,
            pre_auth_foundation: PreAuthFoundationState::AwaitingHandshake,
            local_address: meta.to,
            peer_address: meta.from,
        };
        if !connection.has_stable_source_connection_id(&source_connection_id) {
            connection.fail_closed(PRE_AUTH_CLOSE_CODE);
            return Err(RuntimeError::ConnectionUnavailable);
        }
        connection.drive_h3()?;
        Ok(connection)
    }

    pub(super) fn receive_packet(
        &mut self,
        packet: &mut [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<(), RuntimeError> {
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        if self.lifecycle() == ConnectionLifecycle::Closed {
            return Err(RuntimeError::PacketRejected);
        }
        if meta.from != self.peer_address || meta.to != self.local_address {
            return Err(RuntimeError::PacketRejected);
        }
        match self.transport.recv(
            bounded_packet(packet, length)?,
            quiche::RecvInfo {
                from: meta.from,
                to: meta.to,
            },
        ) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(_) => {
                if self.lifecycle() != ConnectionLifecycle::Active {
                    self.clear_generation_state();
                }
                return Err(RuntimeError::PacketRejected);
            }
        }
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        self.drive_h3()
    }

    pub(super) fn next_packet(
        &mut self,
        packet: &mut [u8; MAX_PACKET_BYTES],
    ) -> Result<Option<(usize, PacketMeta)>, RuntimeError> {
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        self.drive_h3()?;
        let result = match self.transport.send(packet) {
            Ok((length, info)) => {
                if length > MAX_PACKET_BYTES
                    || info.from != self.local_address
                    || info.to != self.peer_address
                {
                    return Err(RuntimeError::PacketUnavailable);
                }
                Ok(Some((
                    length,
                    PacketMeta {
                        from: info.from,
                        to: info.to,
                    },
                )))
            }
            Err(quiche::Error::Done) => Ok(None),
            Err(_) => Err(RuntimeError::PacketUnavailable),
        };
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        result
    }

    pub(super) fn next_timeout(&self) -> Option<Duration> {
        let transport = self.transport.timeout();
        let auth = self
            .auth
            .next_deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()));
        match (transport, auth) {
            (Some(transport), Some(auth)) => Some(transport.min(auth)),
            (Some(transport), None) => Some(transport),
            (None, Some(auth)) => Some(auth),
            (None, None) => None,
        }
    }

    pub(super) fn on_timeout(&mut self) -> Result<(), RuntimeError> {
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        self.transport.on_timeout();
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        self.drive_h3()
    }

    pub(super) fn is_established(&self) -> bool {
        self.transport.is_established()
    }

    pub(super) fn pre_auth_foundation_ready(&self) -> bool {
        self.pre_auth_foundation.is_ready()
    }

    pub(super) fn is_authenticated(&self) -> bool {
        self.lifecycle() == ConnectionLifecycle::Active && self.auth.is_authenticated()
    }

    pub(super) fn lifecycle(&self) -> ConnectionLifecycle {
        if self.transport.is_closed() {
            ConnectionLifecycle::Closed
        } else if self.transport.is_draining() {
            ConnectionLifecycle::Draining
        } else if self.transport.local_error().is_some() {
            ConnectionLifecycle::ClosingPendingSend
        } else {
            ConnectionLifecycle::Active
        }
    }

    pub(super) fn close(&mut self) -> Result<(), RuntimeError> {
        self.clear_generation_state();
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        self.transport
            .close(true, 0, b"")
            .map_err(|_| RuntimeError::CloseUnavailable)?;
        Ok(())
    }

    pub(super) fn reject_pre_auth(&mut self) -> Result<(), RuntimeError> {
        self.reject_generation()
    }

    pub(super) fn reject_generation(&mut self) -> Result<(), RuntimeError> {
        self.clear_generation_state();
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        self.transport
            .close(true, PRE_AUTH_CLOSE_CODE, b"")
            .map_err(|_| RuntimeError::CloseUnavailable)?;
        Ok(())
    }

    fn drive_h3(&mut self) -> Result<(), RuntimeError> {
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        if self.transport.is_in_early_data() {
            return self.reject_with(RuntimeError::EarlyDataRejected);
        }

        if self.transport.is_established() && self.h3.is_none() {
            self.validate_live_tls_facts()?;
            let h3_config = self.h3_config.take().ok_or(RuntimeError::H3Unavailable)?;
            self.h3 = Some(
                quiche::h3::Connection::with_transport(&mut self.transport, &h3_config)
                    .map_err(|_| RuntimeError::H3Unavailable)?,
            );
            self.pre_auth_foundation.h3_initialized();
        }

        let Some(mut h3) = self.h3.take() else {
            return Ok(());
        };
        let result = self.drive_h3_events(&mut h3);
        self.h3 = Some(h3);
        if let Err(error) = result {
            if error != RuntimeError::H3Unavailable
                && self.lifecycle() == ConnectionLifecycle::Active
            {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
            }
        }
        result
    }

    fn drive_h3_events(&mut self, h3: &mut quiche::h3::Connection) -> Result<(), RuntimeError> {
        let mut events = 0_usize;
        loop {
            self.enforce_authenticated_lifecycle_at(Instant::now())?;
            if self.transport.dgram_recv_front_len().is_some() {
                return self.reject_with(RuntimeError::PreAuthApplicationActivity);
            }
            self.reject_if_pending_stream_stopped()?;

            let event = h3.poll(&mut self.transport);
            if self.transport.dgram_recv_front_len().is_some() {
                return self.reject_with(RuntimeError::PreAuthApplicationActivity);
            }

            match event {
                Ok((stream_id, event)) => {
                    if let Err(error) = observe_h3_application_event(&mut events) {
                        return self.reject_with(error);
                    }
                    self.refresh_peer_settings(h3)?;
                    if !self.pre_auth_foundation.is_ready() {
                        return self.reject_with(RuntimeError::PeerSettingsRejected);
                    }
                    self.handle_h3_event(h3, stream_id, event)?;
                    self.drive_confirmation(h3)?;
                }
                Err(quiche::h3::Error::Done) => {
                    self.refresh_peer_settings(h3)?;
                    self.drive_confirmation(h3)?;
                    self.drive_classic_connect_responses(h3)?;
                    return Ok(());
                }
                Err(_) => {
                    // quiche can already have selected its own H3 wire error for a
                    // malformed frame. Do not replace that fact with a 0x105 claim.
                    self.clear_generation_state();
                    return Err(RuntimeError::H3Unavailable);
                }
            }
        }
    }

    fn refresh_peer_settings(&mut self, h3: &quiche::h3::Connection) -> Result<(), RuntimeError> {
        if self.pre_auth_foundation.is_ready() {
            return self.auth.enter_gate(Instant::now());
        }
        let Some(raw_settings) = h3.peer_settings_raw() else {
            return Ok(());
        };
        if !peer_settings_match(h3, &self.transport, raw_settings) {
            return self.reject_with(RuntimeError::PeerSettingsRejected);
        }
        self.pre_auth_foundation.peer_settings_verified();
        self.auth.enter_gate(Instant::now())
    }

    fn handle_h3_event(
        &mut self,
        h3: &mut quiche::h3::Connection,
        stream_id: u64,
        event: quiche::h3::Event,
    ) -> Result<(), RuntimeError> {
        match event {
            quiche::h3::Event::Headers { list, more_frames } => {
                if self.auth.state == ServerAuthState::Authenticated {
                    if let Err(error) = self.admit_classic_connect(stream_id, &list, more_frames) {
                        return self.reject_with(error);
                    }
                    return Ok(());
                }
                if self.auth.state != ServerAuthState::Fresh {
                    return self.reject_with(RuntimeError::AuthenticationRejected);
                }
                let exact = exact_auth_request_headers(
                    &list,
                    self.role.expected_authority(),
                    self.role.tunnel_path(),
                );
                if !exact {
                    return self.reject_with(RuntimeError::PreAuthApplicationActivity);
                }
                if !more_frames {
                    return self.reject_with(RuntimeError::AuthenticationRejected);
                }
                let exporter = self.observe_live_auth_exporter()?;
                if let Err(error) = self.auth.start(stream_id, exporter) {
                    return self.reject_with(error);
                }
                Ok(())
            }
            quiche::h3::Event::Data => {
                if self.auth.state == ServerAuthState::Authenticated {
                    #[cfg(test)]
                    {
                        self.upload_data_events += 1;
                    }
                    if let Err(error) = self.begin_client_to_target_data(stream_id) {
                        return self.reject_with(error);
                    }
                    return Ok(());
                }
                self.receive_auth_body(h3, stream_id)
            }
            quiche::h3::Event::Finished => {
                if self.auth.state == ServerAuthState::Authenticated {
                    if let Err(error) = self.pending_connects.mark_peer_write_half_closed(stream_id)
                    {
                        return self.reject_with(error);
                    }
                    return Ok(());
                }
                if self.auth.state != ServerAuthState::Authenticating
                    || self.auth.bound_stream()? != stream_id
                    || self.auth.control_len != AUTH_V3_CLIENT_CONTROL_LEN
                {
                    return self.reject_with(RuntimeError::AuthenticationRejected);
                }
                self.finish_authentication_request()
            }
            quiche::h3::Event::Reset(_)
            | quiche::h3::Event::PriorityUpdate
            | quiche::h3::Event::GoAway => {
                self.reject_with(RuntimeError::PreAuthApplicationActivity)
            }
        }
    }

    fn begin_client_to_target_data(&mut self, stream_id: u64) -> Result<(), RuntimeError> {
        let mut matches = self
            .pending_connects
            .slots
            .iter_mut()
            .flatten()
            .filter(|pending| pending.stream_id == stream_id);
        let pending = matches
            .next()
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        if matches.next().is_some()
            || !pending.dispatch_state.response_was_accepted()
            || pending.opened_target.is_none()
            || pending.peer_write_half_closed
            || pending.upload_state != UploadDispatchState::Idle
        {
            return Err(RuntimeError::ClassicConnectDataRejected);
        }
        pending.upload_payload.fill(0);
        pending.upload_state = UploadDispatchState::RecvPending;
        Ok(())
    }

    fn receive_auth_body(
        &mut self,
        h3: &mut quiche::h3::Connection,
        stream_id: u64,
    ) -> Result<(), RuntimeError> {
        if self.auth.state != ServerAuthState::Authenticating
            || self.auth.bound_stream()? != stream_id
        {
            return self.reject_with(RuntimeError::AuthenticationRejected);
        }
        loop {
            #[cfg(test)]
            {
                self.auth_body_read_calls += 1;
            }
            let read = if self.auth.control_len < AUTH_V3_CLIENT_CONTROL_LEN {
                h3.recv_body(
                    &mut self.transport,
                    stream_id,
                    &mut self.auth.control[self.auth.control_len..],
                )
            } else {
                let mut overflow = [0_u8; 1];
                h3.recv_body(&mut self.transport, stream_id, &mut overflow)
            };
            match read {
                Ok(0) => return self.reject_with(RuntimeError::AuthenticationRejected),
                Ok(length) if self.auth.control_len < AUTH_V3_CLIENT_CONTROL_LEN => {
                    self.auth.control_len = self
                        .auth
                        .control_len
                        .checked_add(length)
                        .filter(|length| *length <= AUTH_V3_CLIENT_CONTROL_LEN)
                        .ok_or(RuntimeError::AuthenticationRejected)?;
                }
                Ok(_) => return self.reject_with(RuntimeError::AuthenticationRejected),
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(_) => return self.reject_with(RuntimeError::AuthenticationRejected),
            }
        }
    }

    fn admit_classic_connect(
        &mut self,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        more_frames: bool,
    ) -> Result<(), RuntimeError> {
        let pending = self.prepare_classic_connect(stream_id, headers, more_frames)?;
        self.commit_classic_connect(pending)
    }

    fn prepare_classic_connect(
        &self,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        more_frames: bool,
    ) -> Result<PendingClassicConnect, RuntimeError> {
        let capability = self
            .auth
            .capability
            .as_ref()
            .filter(|capability| capability.permits_admission_at(&self.generation, Instant::now()))
            .ok_or(RuntimeError::ClassicConnectAdmissionRejected)?;
        if !self.pending_connects.has_quota_for(capability) {
            return Err(RuntimeError::ClassicConnectAdmissionRejected);
        }
        if !more_frames
            || self.auth.stream_id == Some(stream_id)
            || self.pending_connects.contains_stream(stream_id)
        {
            return Err(RuntimeError::ClassicConnectAdmissionRejected);
        }
        let borrowed = match headers {
            [first, second] => [
                (first.name(), first.value()),
                (second.name(), second.value()),
            ],
            _ => return Err(RuntimeError::ClassicConnectAdmissionRejected),
        };
        let (target, port) = parse_classic_connect_request(&borrowed)
            .map_err(|_| RuntimeError::ClassicConnectAdmissionRejected)?;
        Ok(PendingClassicConnect {
            generation: self.generation,
            stream_id,
            target: Some(target),
            port,
            peer_write_half_closed: false,
            max_frame_size: capability.max_frame_size,
            dispatch_state: TargetDispatchState::Admitted,
            opened_target: None,
            target_payload: Box::new([0; TARGET_TO_CLIENT_BUFFER_BYTES]),
            upload_state: UploadDispatchState::Idle,
            upload_payload: Box::new([0; CLIENT_TO_TARGET_BUFFER_BYTES]),
            #[cfg(test)]
            target_read_failure_requested: false,
            #[cfg(test)]
            target_write_failure_requested: false,
            #[cfg(test)]
            target_shutdown_failure_requested: false,
        })
    }

    fn commit_classic_connect(
        &mut self,
        pending: PendingClassicConnect,
    ) -> Result<(), RuntimeError> {
        let capability = self
            .auth
            .capability
            .as_ref()
            .filter(|capability| capability.permits_admission_at(&self.generation, Instant::now()))
            .ok_or(RuntimeError::ClassicConnectAdmissionRejected)?;
        self.pending_connects.insert(pending, capability)
    }

    pub(super) fn take_target_open_dispatch(
        &mut self,
        now: Instant,
    ) -> Result<Option<TargetOpenDispatchToken>, RuntimeError> {
        let Some(slot_index) = self.pending_connects.next_admitted_index() else {
            return Ok(None);
        };
        let capability = self
            .auth
            .capability
            .as_ref()
            .filter(|capability| capability.permits_admission_at(&self.generation, now))
            .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
        let hard_deadline = capability.hard_deadline;
        let max_frame_size = capability.max_frame_size;
        let timeout = Duration::from_millis(self.role.direct_v3().target_open_timeout_ms());
        let attempt_deadline = checked_attempt_deadline(now, timeout, hard_deadline)?;
        let egress_policy = *self.role.direct_v3().target_open_egress_policy();
        let pending = self.pending_connects.slots[slot_index]
            .as_mut()
            .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
        if pending.dispatch_state != TargetDispatchState::Admitted
            || pending.generation.as_bytes() != self.generation.as_bytes()
            || pending.max_frame_size != max_frame_size
            || pending.opened_target.is_some()
        {
            return Err(RuntimeError::TargetOpenDispatchRejected);
        }
        let target = pending
            .target
            .take()
            .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
        pending.dispatch_state = TargetDispatchState::InFlight;
        Ok(Some(TargetOpenDispatchToken {
            generation: pending.generation,
            stream_id: pending.stream_id,
            target,
            port: pending.port,
            max_frame_size: pending.max_frame_size,
            egress_policy,
            attempt_deadline,
        }))
    }

    pub(super) fn complete_target_open_dispatch(
        &mut self,
        token: TargetOpenDispatchToken,
        opened_target: TcpStream,
        now: Instant,
    ) -> Result<(), RuntimeError> {
        let capability = self
            .auth
            .capability
            .as_ref()
            .filter(|capability| capability.permits_completion_at(&token.generation, now))
            .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
        if now >= token.attempt_deadline || token.max_frame_size != capability.max_frame_size {
            return Err(RuntimeError::TargetOpenDispatchRejected);
        }
        let pending = self
            .pending_connects
            .slots
            .iter_mut()
            .flatten()
            .find(|pending| pending.stream_id == token.stream_id)
            .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
        if pending.generation.as_bytes() != token.generation.as_bytes()
            || pending.dispatch_state != TargetDispatchState::InFlight
            || pending.target.is_some()
            || pending.port != token.port
            || pending.max_frame_size != token.max_frame_size
            || pending.opened_target.is_some()
        {
            return Err(RuntimeError::TargetOpenDispatchRejected);
        }
        pending.opened_target = Some(opened_target);
        pending.dispatch_state = TargetDispatchState::ResponsePending;
        Ok(())
    }

    fn drive_classic_connect_responses(
        &mut self,
        h3: &mut quiche::h3::Connection,
    ) -> Result<(), RuntimeError> {
        for slot_index in 0..MAX_PENDING_CLASSIC_CONNECTS {
            let Some(pending) = self.pending_connects.slots[slot_index].as_ref() else {
                continue;
            };
            if pending.dispatch_state != TargetDispatchState::ResponsePending {
                continue;
            }

            let now = Instant::now();
            let capability = self
                .auth
                .capability
                .as_ref()
                .filter(|capability| capability.permits_response_at(&self.generation, now))
                .ok_or(RuntimeError::ClassicConnectResponseRejected)?;
            let stream_id = pending.stream_id;
            if pending.generation.as_bytes() != self.generation.as_bytes()
                || pending.max_frame_size != capability.max_frame_size
                || pending.target.is_some()
                || pending.opened_target.is_none()
                || self
                    .pending_connects
                    .slots
                    .iter()
                    .flatten()
                    .filter(|candidate| candidate.stream_id == stream_id)
                    .count()
                    != 1
                || self.transport.stream_capacity(stream_id).is_err()
            {
                return self.reject_with(RuntimeError::ClassicConnectResponseRejected);
            }

            let headers = [quiche::h3::Header::new(b":status", b"200")];
            match h3.send_response(&mut self.transport, stream_id, &headers, false) {
                Ok(()) => {
                    let pending = self.pending_connects.slots[slot_index]
                        .as_mut()
                        .ok_or(RuntimeError::ClassicConnectResponseRejected)?;
                    if pending.dispatch_state != TargetDispatchState::ResponsePending
                        || pending.generation.as_bytes() != self.generation.as_bytes()
                        || pending.stream_id != stream_id
                        || pending.target.is_some()
                        || pending.opened_target.is_none()
                    {
                        return self.reject_with(RuntimeError::ClassicConnectResponseRejected);
                    }
                    pending.clear_payloads();
                    pending.upload_state = if pending.peer_write_half_closed {
                        UploadDispatchState::ShutdownPending
                    } else {
                        UploadDispatchState::Idle
                    };
                    pending.dispatch_state = TargetDispatchState::ResponseAccepted;
                }
                Err(quiche::h3::Error::StreamBlocked) => continue,
                Err(_) => return self.reject_with(RuntimeError::ClassicConnectResponseRejected),
            }
        }
        Ok(())
    }

    pub(super) fn has_target_io_waiter(&self) -> bool {
        self.pending_connects.slots.iter().flatten().any(|pending| {
            pending.dispatch_state == TargetDispatchState::ResponseAccepted
                || matches!(
                    pending.upload_state,
                    UploadDispatchState::WritePending { .. }
                )
        })
    }

    pub(super) fn has_immediate_target_io_work(&self) -> bool {
        self.pending_connects.slots.iter().flatten().any(|pending| {
            matches!(
                pending.upload_state,
                UploadDispatchState::RecvPending | UploadDispatchState::ShutdownPending
            )
        })
    }

    pub(super) fn wait_target_io_ready(
        &self,
    ) -> impl std::future::Future<Output = Result<TargetIoSignal, RuntimeError>> + '_ {
        let start = self.target_io_cursor;
        std::future::poll_fn(move |context| {
            for offset in 0..TARGET_IO_CURSOR_LENGTH {
                let position = (start + offset) % TARGET_IO_CURSOR_LENGTH;
                let signal = TargetIoSignal::from_position(position);
                let Some(pending) = self.pending_connects.slots[signal.slot_index].as_ref() else {
                    continue;
                };
                let eligible = match signal.direction {
                    TargetIoDirection::TargetToClient => {
                        pending.dispatch_state == TargetDispatchState::ResponseAccepted
                    }
                    TargetIoDirection::ClientToTarget => matches!(
                        pending.upload_state,
                        UploadDispatchState::WritePending { .. }
                    ),
                };
                if !eligible {
                    continue;
                }
                let Some(target) = pending.opened_target.as_ref() else {
                    return Poll::Ready(Err(RuntimeError::ClassicConnectDataRejected));
                };
                let readiness = match signal.direction {
                    TargetIoDirection::TargetToClient => target.poll_read_ready(context),
                    TargetIoDirection::ClientToTarget => target.poll_write_ready(context),
                };
                match readiness {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(signal)),
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(RuntimeError::ClassicConnectDataRejected));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
    }

    #[cfg(test)]
    fn has_target_read_waiter(&self) -> bool {
        self.pending_connects
            .slots
            .iter()
            .flatten()
            .any(|pending| pending.dispatch_state == TargetDispatchState::ResponseAccepted)
    }

    #[cfg(test)]
    fn wait_target_readable(
        &self,
    ) -> impl std::future::Future<Output = Result<usize, RuntimeError>> + '_ {
        futures::FutureExt::map(self.wait_target_io_ready(), |result| {
            let signal = result?;
            if signal.direction != TargetIoDirection::TargetToClient {
                return Err(RuntimeError::ClassicConnectDataRejected);
            }
            Ok(signal.slot_index)
        })
    }

    pub(super) fn drive_target_io_round(
        &mut self,
        ready_signal: Option<TargetIoSignal>,
    ) -> Result<TargetIoRound, RuntimeError> {
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(TargetIoRound::default());
        }
        if ready_signal.is_some_and(|signal| signal.position() >= TARGET_IO_CURSOR_LENGTH) {
            return self.reject_with(RuntimeError::ClassicConnectDataRejected);
        }
        if !self
            .pending_connects
            .slots
            .iter()
            .flatten()
            .any(|pending| pending.dispatch_state.owns_opened_target())
        {
            return Ok(TargetIoRound::default());
        }

        let Some(mut h3) = self.h3.take() else {
            return self.reject_with(RuntimeError::ClassicConnectDataRejected);
        };
        let result = self.drive_target_io_round_inner(&mut h3, ready_signal);
        self.h3 = Some(h3);
        if let Err(error) = result {
            if self.lifecycle() == ConnectionLifecycle::Active {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
            }
            return Err(error);
        }
        result
    }

    #[cfg(test)]
    fn drive_target_to_client_round(
        &mut self,
        readable_slot: Option<usize>,
    ) -> Result<usize, RuntimeError> {
        let signal = readable_slot.map(|slot_index| TargetIoSignal {
            slot_index,
            direction: TargetIoDirection::TargetToClient,
        });
        self.drive_target_io_round(signal)
            .map(TargetIoRound::operations)
    }

    fn drive_target_io_round_inner(
        &mut self,
        h3: &mut quiche::h3::Connection,
        ready_signal: Option<TargetIoSignal>,
    ) -> Result<TargetIoRound, RuntimeError> {
        let now = Instant::now();
        for slot_index in 0..MAX_PENDING_CLASSIC_CONNECTS {
            let Some(pending) = self.pending_connects.slots[slot_index].as_ref() else {
                continue;
            };
            if pending.dispatch_state.owns_opened_target() {
                self.validate_target_io_slot(slot_index, now)?;
            }
        }
        if let Some(signal) = ready_signal {
            let pending = self.pending_connects.slots[signal.slot_index]
                .as_ref()
                .ok_or(RuntimeError::ClassicConnectDataRejected)?;
            let valid = match signal.direction {
                TargetIoDirection::TargetToClient => {
                    pending.dispatch_state == TargetDispatchState::ResponseAccepted
                }
                TargetIoDirection::ClientToTarget => matches!(
                    pending.upload_state,
                    UploadDispatchState::WritePending { .. }
                ),
            };
            if !valid {
                return Err(RuntimeError::ClassicConnectDataRejected);
            }
        }

        let mut round = TargetIoRound::default();
        let mut scanned_without_operation = 0_usize;
        let mut stopped_positions = 0_u16;
        if let Some(signal) = ready_signal {
            self.target_io_cursor = (signal.position() + 1) % TARGET_IO_CURSOR_LENGTH;
            #[cfg(test)]
            let upload_before = self.pending_connects.slots[signal.slot_index]
                .as_ref()
                .map(|pending| pending.upload_state);
            let outcome = self.perform_target_io_operation(h3, signal)?;
            Self::record_target_io_outcome(&mut round, outcome)?;
            #[cfg(test)]
            round.observe_operation(signal, upload_before, outcome);
            if matches!(
                outcome,
                TargetIoOutcome::Blocked | TargetIoOutcome::Quiescent
            ) {
                stopped_positions |= 1_u16 << signal.position();
            }
        } else if !self.has_immediate_target_io_work() {
            let probe = (0..TARGET_IO_CURSOR_LENGTH)
                .map(|offset| {
                    TargetIoSignal::from_position(
                        (self.target_io_cursor + offset) % TARGET_IO_CURSOR_LENGTH,
                    )
                })
                .find(|signal| self.target_io_operation_eligibility(*signal) == (true, true));
            if let Some(signal) = probe {
                self.target_io_cursor = (signal.position() + 1) % TARGET_IO_CURSOR_LENGTH;
                #[cfg(test)]
                let upload_before = self.pending_connects.slots[signal.slot_index]
                    .as_ref()
                    .map(|pending| pending.upload_state);
                let outcome = self.perform_target_io_operation(h3, signal)?;
                Self::record_target_io_outcome(&mut round, outcome)?;
                #[cfg(test)]
                round.observe_operation(signal, upload_before, outcome);
                if matches!(
                    outcome,
                    TargetIoOutcome::Blocked | TargetIoOutcome::Quiescent
                ) {
                    stopped_positions |= 1_u16 << signal.position();
                }
            }
            // A no-signal round with no immediate work probes only the one
            // direction that was already socket-ready-eligible when the round
            // began. Immediate H3 receive or target-shutdown state uses the
            // same rotating shared budget without spending an operation on an
            // unrelated speculative socket probe.
        }
        while round.operations < MAX_TARGET_IO_OPERATIONS_PER_ROUND
            && scanned_without_operation < TARGET_IO_CURSOR_LENGTH
        {
            let position = self.target_io_cursor;
            self.target_io_cursor = (self.target_io_cursor + 1) % TARGET_IO_CURSOR_LENGTH;
            if stopped_positions & (1_u16 << position) != 0 {
                scanned_without_operation += 1;
                continue;
            }
            let signal = TargetIoSignal::from_position(position);
            let (eligible, socket_probe) = self.target_io_operation_eligibility(signal);
            let eligible = eligible && !socket_probe;
            if !eligible {
                scanned_without_operation += 1;
                continue;
            }

            scanned_without_operation = 0;
            #[cfg(test)]
            let upload_before = self.pending_connects.slots[signal.slot_index]
                .as_ref()
                .map(|pending| pending.upload_state);
            let outcome = self.perform_target_io_operation(h3, signal)?;
            Self::record_target_io_outcome(&mut round, outcome)?;
            #[cfg(test)]
            round.observe_operation(signal, upload_before, outcome);
            if matches!(
                outcome,
                TargetIoOutcome::Blocked | TargetIoOutcome::Quiescent
            ) {
                stopped_positions |= 1_u16 << position;
            }
        }
        if round.operations > MAX_TARGET_IO_OPERATIONS_PER_ROUND
            || round.operation_progress_bytes > 64 * 1024
        {
            return Err(RuntimeError::ClassicConnectDataRejected);
        }
        Ok(round)
    }

    fn target_io_operation_eligibility(&self, signal: TargetIoSignal) -> (bool, bool) {
        let Some(pending) = self.pending_connects.slots[signal.slot_index].as_ref() else {
            return (false, false);
        };
        match signal.direction {
            TargetIoDirection::TargetToClient => match pending.dispatch_state {
                TargetDispatchState::ResponseAccepted => (true, true),
                TargetDispatchState::BodyPending { .. }
                | TargetDispatchState::TargetEofFinPending => (true, false),
                TargetDispatchState::Admitted
                | TargetDispatchState::InFlight
                | TargetDispatchState::ResponsePending
                | TargetDispatchState::ResponseFinAccepted => (false, false),
            },
            TargetIoDirection::ClientToTarget => match pending.upload_state {
                UploadDispatchState::RecvPending | UploadDispatchState::ShutdownPending => {
                    (true, false)
                }
                UploadDispatchState::WritePending { .. } => (true, true),
                UploadDispatchState::Idle | UploadDispatchState::WriteHalfClosed => (false, false),
            },
        }
    }

    fn record_target_io_outcome(
        round: &mut TargetIoRound,
        outcome: TargetIoOutcome,
    ) -> Result<(), RuntimeError> {
        round.operations = round
            .operations
            .checked_add(1)
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        if matches!(
            outcome,
            TargetIoOutcome::Progress { .. } | TargetIoOutcome::StateTransition
        ) {
            #[cfg(test)]
            {
                round.progress_operations = round
                    .progress_operations
                    .checked_add(1)
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
            }
        }
        if let TargetIoOutcome::Progress { bytes } = outcome {
            if bytes > TARGET_IO_MAX_OPERATION_BYTES {
                return Err(RuntimeError::ClassicConnectDataRejected);
            }
            round.operation_progress_bytes = round
                .operation_progress_bytes
                .checked_add(bytes)
                .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        }
        Ok(())
    }

    fn validate_target_io_slot(
        &mut self,
        slot_index: usize,
        now: Instant,
    ) -> Result<(), RuntimeError> {
        let capability = self
            .auth
            .capability
            .as_ref()
            .filter(|capability| capability.permits_response_at(&self.generation, now))
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        let pending = self.pending_connects.slots[slot_index]
            .as_ref()
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        let payload_state_is_valid = match pending.dispatch_state {
            TargetDispatchState::BodyPending { offset, length } => {
                offset < length && length <= TARGET_TO_CLIENT_BUFFER_BYTES
            }
            TargetDispatchState::ResponsePending
            | TargetDispatchState::ResponseAccepted
            | TargetDispatchState::TargetEofFinPending
            | TargetDispatchState::ResponseFinAccepted => true,
            TargetDispatchState::Admitted | TargetDispatchState::InFlight => false,
        };
        let upload_state_is_valid = match pending.upload_state {
            UploadDispatchState::Idle
            | UploadDispatchState::RecvPending
            | UploadDispatchState::ShutdownPending
            | UploadDispatchState::WriteHalfClosed => true,
            UploadDispatchState::WritePending { offset, length } => {
                offset < length && length <= CLIENT_TO_TARGET_BUFFER_BYTES
            }
        };
        if pending.generation.as_bytes() != self.generation.as_bytes()
            || pending.max_frame_size != capability.max_frame_size
            || pending.target.is_some()
            || pending.opened_target.is_none()
            || !payload_state_is_valid
            || !upload_state_is_valid
            || (pending.upload_state != UploadDispatchState::Idle
                && !pending.dispatch_state.response_was_accepted())
            || (matches!(
                pending.upload_state,
                UploadDispatchState::ShutdownPending | UploadDispatchState::WriteHalfClosed
            ) && !pending.peer_write_half_closed)
            || (pending.dispatch_state.response_was_accepted()
                && pending.peer_write_half_closed
                && pending.upload_state == UploadDispatchState::Idle)
            || self
                .pending_connects
                .slots
                .iter()
                .flatten()
                .filter(|candidate| candidate.stream_id == pending.stream_id)
                .count()
                != 1
            || (pending.dispatch_state != TargetDispatchState::ResponseFinAccepted
                && self.transport.stream_capacity(pending.stream_id).is_err())
        {
            return Err(RuntimeError::ClassicConnectDataRejected);
        }
        Ok(())
    }

    fn perform_target_io_operation(
        &mut self,
        h3: &mut quiche::h3::Connection,
        signal: TargetIoSignal,
    ) -> Result<TargetIoOutcome, RuntimeError> {
        match signal.direction {
            TargetIoDirection::TargetToClient => {
                self.perform_target_to_client_operation(h3, signal.slot_index)
            }
            TargetIoDirection::ClientToTarget => {
                self.perform_client_to_target_operation(h3, signal.slot_index)
            }
        }
    }

    fn perform_target_to_client_operation(
        &mut self,
        h3: &mut quiche::h3::Connection,
        slot_index: usize,
    ) -> Result<TargetIoOutcome, RuntimeError> {
        let state = self.pending_connects.slots[slot_index]
            .as_ref()
            .map(|pending| pending.dispatch_state)
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        match state {
            TargetDispatchState::ResponseAccepted => {
                #[cfg(test)]
                {
                    self.target_read_calls += 1;
                    if self.pending_connects.slots[slot_index]
                        .as_ref()
                        .is_some_and(|pending| pending.target_read_failure_requested)
                    {
                        return Err(RuntimeError::ClassicConnectDataRejected);
                    }
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let target = pending
                    .opened_target
                    .as_ref()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                match target.try_read(&mut pending.target_payload[..]) {
                    Ok(0) => {
                        pending.target_payload.fill(0);
                        pending.dispatch_state = TargetDispatchState::TargetEofFinPending;
                        Ok(TargetIoOutcome::Progress { bytes: 0 })
                    }
                    Ok(length) if length <= TARGET_TO_CLIENT_BUFFER_BYTES => {
                        pending.dispatch_state =
                            TargetDispatchState::BodyPending { offset: 0, length };
                        Ok(TargetIoOutcome::Progress { bytes: length })
                    }
                    Ok(_) => Err(RuntimeError::ClassicConnectDataRejected),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        Ok(TargetIoOutcome::Blocked)
                    }
                    Err(_) => Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
            TargetDispatchState::BodyPending { offset, length } => {
                #[cfg(test)]
                {
                    self.target_send_body_calls += 1;
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let remaining = length
                    .checked_sub(offset)
                    .filter(|remaining| *remaining != 0)
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let send = h3.send_body(
                    &mut self.transport,
                    pending.stream_id,
                    &pending.target_payload[offset..length],
                    false,
                );
                match send {
                    Ok(written) if written != 0 && written <= remaining => {
                        let next_offset = offset
                            .checked_add(written)
                            .filter(|next_offset| *next_offset <= length)
                            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                        if next_offset == length {
                            pending.target_payload[..length].fill(0);
                            pending.dispatch_state = TargetDispatchState::ResponseAccepted;
                        } else {
                            pending.dispatch_state = TargetDispatchState::BodyPending {
                                offset: next_offset,
                                length,
                            };
                        }
                        Ok(TargetIoOutcome::Progress { bytes: written })
                    }
                    Ok(_) => Err(RuntimeError::ClassicConnectDataRejected),
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                        Ok(TargetIoOutcome::Blocked)
                    }
                    Err(_) => Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
            TargetDispatchState::TargetEofFinPending => {
                #[cfg(test)]
                {
                    self.target_send_body_calls += 1;
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                match h3.send_body(&mut self.transport, pending.stream_id, &[], true) {
                    Ok(0) => {
                        pending.target_payload.fill(0);
                        pending.dispatch_state = TargetDispatchState::ResponseFinAccepted;
                        Ok(TargetIoOutcome::Progress { bytes: 0 })
                    }
                    Ok(_) => Err(RuntimeError::ClassicConnectDataRejected),
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                        Ok(TargetIoOutcome::Blocked)
                    }
                    Err(_) => Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
            TargetDispatchState::Admitted
            | TargetDispatchState::InFlight
            | TargetDispatchState::ResponsePending
            | TargetDispatchState::ResponseFinAccepted => {
                Err(RuntimeError::ClassicConnectDataRejected)
            }
        }
    }

    fn perform_client_to_target_operation(
        &mut self,
        h3: &mut quiche::h3::Connection,
        slot_index: usize,
    ) -> Result<TargetIoOutcome, RuntimeError> {
        let state = self.pending_connects.slots[slot_index]
            .as_ref()
            .map(|pending| pending.upload_state)
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        match state {
            UploadDispatchState::RecvPending => {
                #[cfg(test)]
                {
                    self.upload_recv_body_calls += 1;
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                if pending.upload_payload.iter().any(|byte| *byte != 0) {
                    return Err(RuntimeError::ClassicConnectDataRejected);
                }
                match h3.recv_body(
                    &mut self.transport,
                    pending.stream_id,
                    &mut pending.upload_payload[..],
                ) {
                    Ok(0) => Err(RuntimeError::ClassicConnectDataRejected),
                    Ok(length) if length <= CLIENT_TO_TARGET_BUFFER_BYTES => {
                        pending.upload_state =
                            UploadDispatchState::WritePending { offset: 0, length };
                        Ok(TargetIoOutcome::Progress { bytes: length })
                    }
                    Ok(_) => Err(RuntimeError::ClassicConnectDataRejected),
                    Err(quiche::h3::Error::Done) => {
                        pending.upload_payload.fill(0);
                        pending.upload_state = if pending.peer_write_half_closed {
                            UploadDispatchState::ShutdownPending
                        } else {
                            UploadDispatchState::Idle
                        };
                        Ok(TargetIoOutcome::Quiescent)
                    }
                    Err(_) => Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
            UploadDispatchState::WritePending { offset, length } => {
                #[cfg(test)]
                {
                    self.target_write_calls += 1;
                    if self.pending_connects.slots[slot_index]
                        .as_ref()
                        .is_some_and(|pending| pending.target_write_failure_requested)
                    {
                        return Err(RuntimeError::ClassicConnectDataRejected);
                    }
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let remaining = length
                    .checked_sub(offset)
                    .filter(|remaining| *remaining != 0)
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let target = pending
                    .opened_target
                    .as_ref()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                match target.try_write(&pending.upload_payload[offset..length]) {
                    Ok(written) if written != 0 && written <= remaining => {
                        let next_offset = offset
                            .checked_add(written)
                            .filter(|next_offset| *next_offset <= length)
                            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                        if next_offset == length {
                            pending.upload_payload[..length].fill(0);
                            pending.upload_state = UploadDispatchState::RecvPending;
                        } else {
                            pending.upload_state = UploadDispatchState::WritePending {
                                offset: next_offset,
                                length,
                            };
                        }
                        Ok(TargetIoOutcome::Progress { bytes: written })
                    }
                    Ok(_) => Err(RuntimeError::ClassicConnectDataRejected),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        Ok(TargetIoOutcome::Blocked)
                    }
                    Err(_) => Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
            UploadDispatchState::ShutdownPending => {
                #[cfg(test)]
                {
                    self.target_shutdown_calls += 1;
                    if self.pending_connects.slots[slot_index]
                        .as_ref()
                        .is_some_and(|pending| pending.target_shutdown_failure_requested)
                    {
                        return Err(RuntimeError::ClassicConnectDataRejected);
                    }
                }
                let pending = self.pending_connects.slots[slot_index]
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                if !pending.peer_write_half_closed
                    || pending.upload_payload.iter().any(|byte| *byte != 0)
                {
                    return Err(RuntimeError::ClassicConnectDataRejected);
                }
                let target = pending
                    .opened_target
                    .as_mut()
                    .ok_or(RuntimeError::ClassicConnectDataRejected)?;
                let mut context = Context::from_waker(futures::task::noop_waker_ref());
                match Pin::new(target).poll_shutdown(&mut context) {
                    Poll::Ready(Ok(())) => {
                        pending.upload_state = UploadDispatchState::WriteHalfClosed;
                        Ok(TargetIoOutcome::StateTransition)
                    }
                    Poll::Ready(Err(_)) | Poll::Pending => {
                        Err(RuntimeError::ClassicConnectDataRejected)
                    }
                }
            }
            UploadDispatchState::Idle | UploadDispatchState::WriteHalfClosed => {
                Err(RuntimeError::ClassicConnectDataRejected)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn waiting_target_dispatch_count_for_test(&self) -> usize {
        self.pending_connects
            .slots
            .iter()
            .flatten()
            .filter(|pending| pending.dispatch_state.owns_opened_target())
            .count()
    }

    #[cfg(test)]
    pub(super) fn waiting_opened_target_count_for_test(&self) -> usize {
        self.pending_connects
            .slots
            .iter()
            .flatten()
            .filter(|pending| {
                pending.dispatch_state.owns_opened_target()
                    && pending.target.is_none()
                    && pending.opened_target.is_some()
            })
            .count()
    }

    #[cfg(test)]
    pub(super) fn saturate_pending_upload_target_for_test(&self) -> Result<(), RuntimeError> {
        let mut matches = self
            .pending_connects
            .slots
            .iter()
            .flatten()
            .filter(|pending| {
                matches!(
                    pending.upload_state,
                    UploadDispatchState::WritePending { .. }
                )
            });
        let pending = matches
            .next()
            .filter(|pending| pending.dispatch_state.response_was_accepted())
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        if matches.next().is_some() {
            return Err(RuntimeError::ClassicConnectDataRejected);
        }
        let target = pending
            .opened_target
            .as_ref()
            .ok_or(RuntimeError::ClassicConnectDataRejected)?;
        let filler = [0xa7_u8; CLIENT_TO_TARGET_BUFFER_BYTES];
        for _ in 0..1_024 {
            match target.try_write(&filler) {
                Ok(0) => return Err(RuntimeError::ClassicConnectDataRejected),
                Ok(length) if length <= filler.len() => {}
                Ok(_) => return Err(RuntimeError::ClassicConnectDataRejected),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(());
                }
                Err(_) => return Err(RuntimeError::ClassicConnectDataRejected),
            }
        }
        Err(RuntimeError::ClassicConnectDataRejected)
    }

    #[cfg(test)]
    fn response_pending_count_for_test(&self) -> usize {
        self.pending_connects
            .slots
            .iter()
            .flatten()
            .filter(|pending| pending.dispatch_state == TargetDispatchState::ResponsePending)
            .count()
    }

    #[cfg(test)]
    fn response_accepted_count_for_test(&self) -> usize {
        self.pending_connects
            .slots
            .iter()
            .flatten()
            .filter(|pending| pending.dispatch_state == TargetDispatchState::ResponseAccepted)
            .count()
    }

    fn reject_if_pending_stream_stopped(&mut self) -> Result<(), RuntimeError> {
        for stream_id in self
            .pending_connects
            .stream_ids_requiring_send()
            .into_iter()
            .flatten()
        {
            if self.transport.stream_capacity(stream_id).is_err() {
                return self.reject_with(RuntimeError::ClassicConnectAdmissionRejected);
            }
        }
        Ok(())
    }

    fn finish_authentication_request(&mut self) -> Result<(), RuntimeError> {
        self.validate_live_tls_facts()?;
        let now_unix = trusted_now_unix()?;
        let monotonic_now = Instant::now();
        let exporter = self.auth.exporter;
        let preselected = self.role.direct_v3().preselected_profile();
        let context = preselected.trusted_connection_context(
            AuthV3Carrier::H3,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter,
            true,
            Some(&[]),
            self.role.direct_v3().tunnel_path(),
        );
        let verified = verify_auth_v3_client_control(
            &self.auth.control,
            &preselected.trusted_profile(),
            &context,
            now_unix,
        )
        .map_err(|_| RuntimeError::AuthenticationRejected)?;
        let credential_epoch = verified.credential_epoch();
        let (admission_expiry_unix, hard_expiry_unix) =
            selected_expiries(now_unix, verified.credential_not_after_unix())?;
        let admission_deadline = monotonic_now
            .checked_add(Duration::from_secs(admission_expiry_unix - now_unix))
            .ok_or(RuntimeError::AuthenticationUnavailable)?;
        let hard_deadline = monotonic_now
            .checked_add(Duration::from_secs(hard_expiry_unix - now_unix))
            .ok_or(RuntimeError::AuthenticationUnavailable)?;
        let server_nonce = random_nonzero::<32>()?;
        let session_id = random_nonzero::<16>()?;
        let confirmation = encode_auth_v3_server_confirmation(
            verified,
            &context,
            &AuthV3ServerConfirmationInput::new(
                now_unix,
                admission_expiry_unix,
                hard_expiry_unix,
                server_nonce,
                session_id,
                AUTH_MAX_FRAME_SIZE,
                AUTH_MAX_CONCURRENT_FLOWS,
            ),
        )
        .map_err(|_| RuntimeError::AuthenticationRejected)?;
        let pending = AuthenticatedGenerationCapability {
            generation: self.generation,
            session_id,
            credential_epoch,
            admission_expiry_unix,
            hard_expiry_unix,
            admission_deadline,
            hard_deadline,
            active: false,
            revoked: false,
            carrier: AuthV3Carrier::H3,
            max_frame_size: AUTH_MAX_FRAME_SIZE,
            max_concurrent_flows: AUTH_MAX_CONCURRENT_FLOWS,
        };
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        self.auth.install_confirmation(confirmation, pending)
    }

    fn drive_confirmation(&mut self, h3: &mut quiche::h3::Connection) -> Result<(), RuntimeError> {
        if self.auth.state != ServerAuthState::SendingConfirmation {
            return Ok(());
        }
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        let stream_id = self.auth.bound_stream()?;
        if !self.auth.confirmation_headers_sent {
            match h3.send_response(
                &mut self.transport,
                stream_id,
                &auth_confirmation_headers(),
                false,
            ) {
                Ok(()) => self.auth.mark_confirmation_headers_sent()?,
                Err(quiche::h3::Error::StreamBlocked) => {
                    self.enforce_authenticated_lifecycle_at(Instant::now())?;
                    return Ok(());
                }
                Err(_) => return self.reject_with(RuntimeError::AuthenticationRejected),
            }
        }
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        let offset = self.auth.confirmation_offset;
        let requested = AUTH_V3_SERVER_CONFIRMATION_LEN
            .checked_sub(offset)
            .ok_or(RuntimeError::AuthenticationRejected)?;
        if requested == 0 {
            return self.reject_with(RuntimeError::AuthenticationRejected);
        }
        let send = h3.send_body(
            &mut self.transport,
            stream_id,
            &self.auth.confirmation[offset..],
            true,
        );
        self.enforce_authenticated_lifecycle_at(Instant::now())?;
        match send {
            Ok(0) => self.reject_with(RuntimeError::AuthenticationRejected),
            Ok(written) if written <= requested => {
                if self.auth.record_confirmation_write(written, requested)? {
                    self.auth.authenticate(Instant::now())?;
                }
                Ok(())
            }
            Ok(_) => self.reject_with(RuntimeError::AuthenticationRejected),
            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => Ok(()),
            Err(_) => self.reject_with(RuntimeError::AuthenticationRejected),
        }
    }

    fn validate_live_tls_facts(&mut self) -> Result<(), RuntimeError> {
        if self.transport.application_proto() != b"h3" {
            return self.reject_with(RuntimeError::AlpnRejected);
        }
        let tls: &mut SslRef = self.transport.as_mut();
        if tls.version2() != Some(SslVersion::TLS1_3) {
            return self.reject_with(RuntimeError::TlsVersionRejected);
        }
        if self.transport.server_name().map(str::as_bytes) != Some(self.role.expected_authority()) {
            return self.reject_with(RuntimeError::ServerNameRejected);
        }
        Ok(())
    }

    fn observe_live_auth_exporter(&mut self) -> Result<[u8; AUTH_V3_EXPORTER_LEN], RuntimeError> {
        self.validate_live_tls_facts()?;
        let label = std::str::from_utf8(AUTH_V3_EXPORTER_LABEL)
            .map_err(|_| RuntimeError::AuthenticationUnavailable)?;
        let mut exporter = [0_u8; AUTH_V3_EXPORTER_LEN];
        let tls: &mut SslRef = self.transport.as_mut();
        tls.export_keying_material(&mut exporter, label, Some(&[]))
            .map_err(|_| RuntimeError::AuthenticationUnavailable)?;
        Ok(exporter)
    }

    fn enforce_authenticated_lifecycle_at(&mut self, now: Instant) -> Result<(), RuntimeError> {
        if self.lifecycle() != ConnectionLifecycle::Active {
            self.clear_generation_state();
            return Ok(());
        }
        if self.auth.is_expired_at(now) {
            return self.reject_with(RuntimeError::AuthenticationExpired);
        }
        Ok(())
    }

    fn reject_with<T>(&mut self, error: RuntimeError) -> Result<T, RuntimeError> {
        self.fail_closed(PRE_AUTH_CLOSE_CODE);
        Err(error)
    }

    fn fail_closed(&mut self, code: u64) {
        self.clear_generation_state();
        if self.lifecycle() == ConnectionLifecycle::Active {
            let _ = self.transport.close(true, code, b"");
        }
    }

    fn clear_generation_state(&mut self) {
        self.pending_connects.clear();
        self.auth.fail();
    }

    pub(super) fn revoke_authenticated_generation(&mut self) -> Result<(), RuntimeError> {
        self.auth.revoke();
        self.reject_generation()
    }

    pub(super) fn has_stable_source_connection_id(
        &self,
        expected: &ServerSourceConnectionId,
    ) -> bool {
        let mut source_ids = self.transport.source_ids();
        matches!(
            (source_ids.next(), source_ids.next()),
            (Some(source_id), None) if source_id.as_ref() == expected.as_bytes()
        )
    }

    #[cfg(test)]
    pub(super) fn h3_initialized(&self) -> bool {
        self.h3.is_some()
    }

    #[cfg(test)]
    pub(super) fn has_role_owner(&self, expected: &Arc<ServerRoleConfig>) -> bool {
        self.role.has_owner(expected)
    }

    #[cfg(test)]
    pub(super) fn expire_authenticated_generation_for_test(&mut self) -> Result<(), RuntimeError> {
        let capability = self
            .auth
            .capability
            .as_mut()
            .ok_or(RuntimeError::AuthenticationUnavailable)?;
        capability.hard_deadline = Instant::now();
        Ok(())
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        self.pending_connects.clear();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RuntimeError {
    RoleUnavailable,
    ConfigurationUnavailable,
    InitialPacketRejected,
    ConnectionUnavailable,
    PacketRejected,
    PacketUnavailable,
    EarlyDataRejected,
    AlpnRejected,
    TlsVersionRejected,
    ServerNameRejected,
    H3Unavailable,
    H3EventBudgetExhausted,
    PeerSettingsRejected,
    PreAuthApplicationActivity,
    AuthenticationRejected,
    AuthenticationUnavailable,
    AuthenticationExpired,
    ClassicConnectAdmissionRejected,
    ClassicConnectResponseRejected,
    ClassicConnectDataRejected,
    TargetOpenDispatchRejected,
    CloseUnavailable,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RoleUnavailable => "server direct-v3 role unavailable",
            Self::ConfigurationUnavailable => "server connection configuration unavailable",
            Self::InitialPacketRejected => "initial server packet rejected",
            Self::ConnectionUnavailable => "server connection unavailable",
            Self::PacketRejected => "server packet rejected",
            Self::PacketUnavailable => "server packet unavailable",
            Self::EarlyDataRejected => "server early data rejected",
            Self::AlpnRejected => "server application protocol rejected",
            Self::TlsVersionRejected => "server TLS version rejected",
            Self::ServerNameRejected => "server TLS name rejected",
            Self::H3Unavailable => "server H3 state unavailable",
            Self::H3EventBudgetExhausted => "server H3 event budget exhausted",
            Self::PeerSettingsRejected => "server peer settings rejected",
            Self::PreAuthApplicationActivity => "pre-authentication application activity rejected",
            Self::AuthenticationRejected => "server authentication rejected",
            Self::AuthenticationUnavailable => "server authentication unavailable",
            Self::AuthenticationExpired => "server authentication expired",
            Self::ClassicConnectAdmissionRejected => "Classic CONNECT admission rejected",
            Self::ClassicConnectResponseRejected => "Classic CONNECT response rejected",
            Self::ClassicConnectDataRejected => "Classic CONNECT data rejected",
            Self::TargetOpenDispatchRejected => "target-open dispatch rejected",
            Self::CloseUnavailable => "server connection close unavailable",
        };
        formatter.write_str(message)
    }
}

fn peer_settings_match(
    h3: &quiche::h3::Connection,
    transport: &quiche::Connection,
    settings: &[(u64, u64)],
) -> bool {
    PeerFoundationSettings {
        max_field_section_size: peer_setting(settings, SETTINGS_MAX_FIELD_SECTION_SIZE),
        qpack_max_table_capacity: peer_setting(settings, SETTINGS_QPACK_MAX_TABLE_CAPACITY),
        qpack_blocked_streams: peer_setting(settings, SETTINGS_QPACK_BLOCKED_STREAMS),
        extended_connect: h3.extended_connect_enabled_by_peer(),
        h3_datagram: h3.dgram_enabled_by_peer(transport),
        quic_datagram_frame_bytes: transport
            .peer_transport_params()
            .and_then(|params| params.max_datagram_frame_size),
    }
    .matches_required()
}

fn observe_h3_application_event(events: &mut usize) -> Result<(), RuntimeError> {
    *events = events
        .checked_add(1)
        .ok_or(RuntimeError::H3EventBudgetExhausted)?;
    if *events > MAX_H3_EVENTS_PER_DRIVE {
        return Err(RuntimeError::H3EventBudgetExhausted);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerFoundationSettings {
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    extended_connect: bool,
    h3_datagram: bool,
    quic_datagram_frame_bytes: Option<u64>,
}

impl PeerFoundationSettings {
    fn matches_required(self) -> bool {
        self.max_field_section_size == Some(MAX_FIELD_SECTION_BYTES)
            && self.qpack_max_table_capacity == Some(QPACK_MAX_TABLE_CAPACITY)
            && self.qpack_blocked_streams == Some(QPACK_BLOCKED_STREAMS)
            && self.extended_connect
            && self.h3_datagram
            && self.quic_datagram_frame_bytes == Some(MAX_DATAGRAM_FRAME_BYTES)
    }
}

fn peer_setting(settings: &[(u64, u64)], id: u64) -> Option<u64> {
    settings
        .iter()
        .find_map(|(setting_id, value)| (*setting_id == id).then_some(*value))
}

impl fmt::Debug for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private server connection error")
    }
}

impl std::error::Error for RuntimeError {}

fn exact_auth_request_headers(
    headers: &[quiche::h3::Header],
    expected_authority: &[u8],
    expected_path: &[u8],
) -> bool {
    let expected: [(&[u8], &[u8]); 6] = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", expected_authority),
        (b":path", expected_path),
        (b"content-type", AUTH_CONTENT_TYPE),
        (b"content-length", b"256"),
    ];
    headers.len() == expected.len()
        && headers
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.name() == expected.0 && actual.value() == expected.1)
}

fn auth_confirmation_headers() -> [quiche::h3::Header; 3] {
    [
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"content-type", AUTH_CONTENT_TYPE),
        quiche::h3::Header::new(b"content-length", b"320"),
    ]
}

fn trusted_now_unix() -> Result<u64, RuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RuntimeError::AuthenticationUnavailable)
}

fn selected_expiries(
    now_unix: u64,
    credential_not_after_unix: u64,
) -> Result<(u64, u64), RuntimeError> {
    let hard_expiry_unix = now_unix
        .checked_add(AUTH_HARD_LIFETIME_SECONDS)
        .map_or(credential_not_after_unix, |limit| {
            limit.min(credential_not_after_unix)
        });
    if hard_expiry_unix.saturating_sub(now_unix) < 2 {
        return Err(RuntimeError::AuthenticationRejected);
    }
    let admission_limit = now_unix
        .checked_add(AUTH_ADMISSION_LIFETIME_SECONDS)
        .ok_or(RuntimeError::AuthenticationUnavailable)?;
    let admission_expiry_unix = admission_limit.min(hard_expiry_unix - 1);
    if admission_expiry_unix <= now_unix {
        return Err(RuntimeError::AuthenticationRejected);
    }
    Ok((admission_expiry_unix, hard_expiry_unix))
}

fn checked_attempt_deadline(
    now: Instant,
    timeout: Duration,
    hard_deadline: Instant,
) -> Result<Instant, RuntimeError> {
    if timeout.is_zero() || now >= hard_deadline {
        return Err(RuntimeError::TargetOpenDispatchRejected);
    }
    let timeout_deadline = now
        .checked_add(timeout)
        .ok_or(RuntimeError::TargetOpenDispatchRejected)?;
    Ok(timeout_deadline.min(hard_deadline))
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], RuntimeError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RuntimeError::AuthenticationUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(RuntimeError::AuthenticationUnavailable)
}

fn private_path(path: &Path) -> Result<&str, RuntimeError> {
    path.to_str().ok_or(RuntimeError::ConfigurationUnavailable)
}

fn bounded_packet(
    packet: &mut [u8; MAX_PACKET_BYTES],
    length: usize,
) -> Result<&mut [u8], RuntimeError> {
    if length == 0 || length > MAX_PACKET_BYTES {
        return Err(RuntimeError::PacketRejected);
    }
    Ok(&mut packet[..length])
}

pub(super) fn bounded_transport_config() -> Result<quiche::Config, RuntimeError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
    config.set_max_idle_timeout(MAX_IDLE_TIMEOUT_MILLIS);
    config.set_max_recv_udp_payload_size(MAX_PACKET_BYTES);
    config.set_max_send_udp_payload_size(MAX_PACKET_BYTES);
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
    config.set_path_challenge_recv_max_queue_len(PATH_CHALLENGE_QUEUE_LIMIT);
    config.enable_dgram(true, DATAGRAM_QUEUE_LIMIT, DATAGRAM_QUEUE_LIMIT);
    config.enable_pacing(false);
    config.discover_pmtu(false);
    // 0-RTT is opt-in in quiche. This module deliberately never calls
    // Config::enable_early_data(), and also rejects a live early-data state.
    Ok(config)
}

pub(super) fn bounded_h3_config() -> Result<quiche::h3::Config, RuntimeError> {
    let mut config =
        quiche::h3::Config::new().map_err(|_| RuntimeError::ConfigurationUnavailable)?;
    config.set_reject_peer_push_activity(true);
    config.set_suppress_trace_logging(true);
    config.set_max_field_section_size(MAX_FIELD_SECTION_BYTES);
    config.set_qpack_max_table_capacity(QPACK_MAX_TABLE_CAPACITY);
    config.set_qpack_blocked_streams(QPACK_BLOCKED_STREAMS);
    config.set_max_priority_update_size(MAX_PRIORITY_UPDATE_BYTES);
    config.enable_extended_connect(true);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use maverick_core::auth_v3::{encode_auth_v3_client_control, AuthV3ClientControlInput};

    use super::*;

    const CLIENT_ADDRESS: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 41_001);
    const SERVER_ADDRESS: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 41_002);
    const SERVER_SOURCE_CONNECTION_ID: [u8; quiche::MAX_CONN_ID_LEN] =
        [0xa5; quiche::MAX_CONN_ID_LEN];
    const MAX_SHUTTLE_STEPS: usize = 64;

    #[derive(Clone, Copy)]
    enum PeerSettingsFault {
        None,
        MaxFieldWrong,
        QpackTableMissing,
        QpackTableWrong,
        QpackBlockedMissing,
        QpackBlockedWrong,
        ExtendedConnectMissing,
        DatagramMissing,
    }

    type ReceivePacketFn = fn(
        &mut ServerConnection,
        &mut [u8; MAX_PACKET_BYTES],
        usize,
        PacketMeta,
    ) -> Result<(), RuntimeError>;
    type NextPacketFn = fn(
        &mut ServerConnection,
        &mut [u8; MAX_PACKET_BYTES],
    ) -> Result<Option<(usize, PacketMeta)>, RuntimeError>;
    type NextTimeoutFn = fn(&ServerConnection) -> Option<Duration>;
    type OnTimeoutFn = fn(&mut ServerConnection) -> Result<(), RuntimeError>;

    struct TestPair {
        client: quiche::Connection,
        client_h3: Option<quiche::h3::Connection>,
        client_h3_config: Option<quiche::h3::Config>,
        server: ServerConnection,
    }

    async fn connected_target_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback target listener");
        let address = listener.local_addr().expect("read loopback target address");
        let (opened, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (
            opened.expect("connect loopback target"),
            accepted.expect("accept loopback target").0,
        )
    }

    async fn connected_target_pair_with_small_send_buffer() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind small-send-buffer target listener");
        let address = listener
            .local_addr()
            .expect("read small-send-buffer target address");
        let socket = tokio::net::TcpSocket::new_v4().expect("create target TcpSocket");
        socket
            .set_send_buffer_size(1_024)
            .expect("set target test send buffer");
        let (opened, accepted) = tokio::join!(socket.connect(address), listener.accept());
        (
            opened.expect("connect small-send-buffer target"),
            accepted.expect("accept small-send-buffer target").0,
        )
    }

    fn fill_real_target_send_buffer(target: &TcpStream) -> usize {
        let filler = [0xa7_u8; CLIENT_TO_TARGET_BUFFER_BYTES];
        let mut filled = 0_usize;
        let mut blocked = false;
        for _ in 0..1_024 {
            match target.try_write(&filler) {
                Ok(0) => panic!("real target prefill made invalid zero progress"),
                Ok(written) => {
                    filled = filled
                        .checked_add(written)
                        .expect("bounded target prefill length");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(_) => panic!("real target prefill failed"),
            }
        }
        assert!(
            blocked,
            "small real target send buffer must reach WouldBlock"
        );
        assert_ne!(filled, 0);
        filled
    }

    async fn drain_real_target_filler(peer: &mut TcpStream, mut remaining: usize) {
        use tokio::io::AsyncReadExt;

        let mut buffer = [0_u8; 8 * 1024];
        while remaining != 0 {
            let requested = remaining.min(buffer.len());
            let read =
                tokio::time::timeout(Duration::from_secs(1), peer.read(&mut buffer[..requested]))
                    .await
                    .expect("drain real target filler within bound")
                    .expect("read real target filler");
            assert_ne!(read, 0);
            assert!(buffer[..read].iter().all(|byte| *byte == 0xa7));
            remaining -= read;
        }
    }

    async fn assert_target_peer_eof(mut peer: TcpStream) {
        use tokio::io::AsyncReadExt;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
                .await
                .expect("target peer closes within bound")
                .expect_err("closed target peer reports EOF")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    async fn assert_target_peer_closed(mut peer: TcpStream) {
        use tokio::io::AsyncReadExt;

        let kind = tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .expect("target peer closes within bound")
            .expect_err("closed target peer returns no target-bound byte")
            .kind();
        assert!(matches!(
            kind,
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        ));
    }

    async fn response_pending_pair(authority: &[u8]) -> (TestPair, u64, TcpStream) {
        let mut pair = TestPair::new().expect("construct response-pending pair");
        pair.authenticate_generation()
            .expect("authenticate response-pending pair");
        let headers = test_classic_connect_headers(authority, false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue response-pending CONNECT");
        pair.client_to_server()
            .expect("admit response-pending CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take response-pending dispatch")
            .expect("response-pending dispatch exists");
        let (opened_target, peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff target into response-pending slot");
        (pair, stream_id, peer)
    }

    async fn response_accepted_pair(authority: &[u8]) -> (TestPair, u64, TcpStream) {
        let (mut pair, stream_id, peer) = response_pending_pair(authority).await;
        pair.server
            .drive_h3()
            .expect("accept response into local queue");
        assert_eq!(pair.server.response_pending_count_for_test(), 0);
        assert_eq!(pair.server.response_accepted_count_for_test(), 1);
        (pair, stream_id, peer)
    }

    async fn response_accepted_pair_with_blocked_target(
        authority: &[u8],
    ) -> (TestPair, u64, TcpStream, usize) {
        let mut pair = TestPair::new().expect("construct blocked-upload pair");
        pair.authenticate_generation()
            .expect("authenticate blocked-upload pair");
        let headers = test_classic_connect_headers(authority, false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue blocked-upload CONNECT");
        pair.client_to_server()
            .expect("admit blocked-upload CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take blocked-upload dispatch")
            .expect("blocked-upload dispatch exists");
        let (opened_target, peer) = connected_target_pair_with_small_send_buffer().await;
        let filler_length = fill_real_target_send_buffer(&opened_target);
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff prefilled target");
        pair.server
            .drive_h3()
            .expect("accept blocked-upload response");
        (pair, stream_id, peer, filler_length)
    }

    async fn body_pending_pair_with_small_window(authority: &[u8]) -> (TestPair, u64, TcpStream) {
        use tokio::io::AsyncWriteExt;

        let mut pair = TestPair::with_response_window(512).expect("construct small-window pair");
        pair.authenticate_generation()
            .expect("authenticate small-window pair");
        let headers = test_classic_connect_headers(authority, false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue small-window CONNECT");
        pair.client_to_server().expect("admit small-window CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take small-window dispatch")
            .expect("small-window dispatch exists");
        let (opened_target, mut peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff small-window target");
        pair.server
            .drive_h3()
            .expect("accept small-window response");
        pair.server_to_client()
            .expect("deliver small-window response");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll small-window response"));
        let payload = [0x6d_u8; TARGET_TO_CLIENT_BUFFER_BYTES * 2];
        peer.write_all(&payload)
            .await
            .expect("write small-window target payload");
        let slot_index =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                .await
                .expect("small-window target becomes readable")
                .expect("small-window target readiness is usable");
        pair.server
            .drive_target_to_client_round(Some(slot_index))
            .expect("read and partially queue small-window payload");
        assert!(matches!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("small-window slot remains occupied")
                .dispatch_state,
            TargetDispatchState::BodyPending { .. }
        ));
        (pair, stream_id, peer)
    }

    async fn both_payload_buffers_pending_pair(authority: &[u8]) -> (TestPair, u64, TcpStream) {
        const UPLOAD_MARKER: &[u8] = b"buffered-upload-marker";

        let (mut pair, stream_id, peer) = body_pending_pair_with_small_window(authority).await;
        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("double-buffer H3 client exists")
                .send_body(&mut pair.client, stream_id, UPLOAD_MARKER, false),
            Ok(UPLOAD_MARKER.len())
        );
        pair.client_to_server()
            .expect("deliver double-buffer upload DATA event");
        pair.server
            .drive_target_io_round(None)
            .expect("receive upload while download suffix remains buffered");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("double-buffer slot remains occupied");
        assert!(matches!(
            pending.dispatch_state,
            TargetDispatchState::BodyPending { .. }
        ));
        assert_eq!(
            pending.upload_state,
            UploadDispatchState::WritePending {
                offset: 0,
                length: UPLOAD_MARKER.len(),
            }
        );
        assert!(pending.target_payload.iter().any(|byte| *byte != 0));
        assert_eq!(
            &pending.upload_payload[..UPLOAD_MARKER.len()],
            UPLOAD_MARKER
        );
        (pair, stream_id, peer)
    }

    async fn eight_shutdown_pending_pair(authority: &[u8]) -> (TestPair, Vec<u64>, Vec<TcpStream>) {
        let mut pair = TestPair::new().expect("construct eight-shutdown pair");
        pair.authenticate_generation()
            .expect("authenticate eight-shutdown pair");
        let headers = test_classic_connect_headers(authority, false);
        let mut stream_ids = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        let mut target_peers = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        for _ in 0..MAX_PENDING_CLASSIC_CONNECTS {
            let stream_id = pair
                .send_classic_connect(&headers, false)
                .expect("queue one eight-shutdown CONNECT");
            pair.client_to_server()
                .expect("admit one eight-shutdown CONNECT");
            let token = pair
                .server
                .take_target_open_dispatch(Instant::now())
                .expect("take one eight-shutdown dispatch")
                .expect("one eight-shutdown dispatch exists");
            let (opened_target, target_peer) = connected_target_pair().await;
            pair.server
                .complete_target_open_dispatch(token, opened_target, Instant::now())
                .expect("handoff one eight-shutdown target");
            pair.server
                .drive_h3()
                .expect("accept one eight-shutdown response");
            pair.server_to_client()
                .expect("deliver one eight-shutdown response");
            assert!(pair
                .poll_exact_classic_connect_success(stream_id)
                .expect("observe one eight-shutdown response"));
            stream_ids.push(stream_id);
            target_peers.push(target_peer);
        }
        for stream_id in &stream_ids {
            assert_eq!(pair.client.stream_send(*stream_id, b"", true), Ok(0));
        }
        assert!(pair
            .client_transport_to_server_without_h3_drive()
            .expect("deliver all eight empty request FINs"));
        pair.server
            .drive_h3()
            .expect("record exactly eight request Finished events");
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| pending.upload_state == UploadDispatchState::ShutdownPending));
        (pair, stream_ids, target_peers)
    }

    struct ConfirmationProgress {
        body: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
        offset: usize,
        headers_seen: bool,
        finished: bool,
    }

    impl ConfirmationProgress {
        fn empty() -> Self {
            Self {
                body: [0; AUTH_V3_SERVER_CONFIRMATION_LEN],
                offset: 0,
                headers_seen: false,
                finished: false,
            }
        }
    }

    impl TestPair {
        fn new() -> Result<Self, RuntimeError> {
            Self::with_server_name("localhost", Some("localhost"))
        }

        fn with_server_name(
            expected_authority: &str,
            offered_server_name: Option<&str>,
        ) -> Result<Self, RuntimeError> {
            Self::with_peer_settings(
                expected_authority,
                offered_server_name,
                PeerSettingsFault::None,
            )
        }

        fn with_peer_settings(
            expected_authority: &str,
            offered_server_name: Option<&str>,
            fault: PeerSettingsFault,
        ) -> Result<Self, RuntimeError> {
            Self::with_options(
                expected_authority,
                offered_server_name,
                fault,
                INITIAL_BIDI_STREAM_WINDOW_BYTES,
                INITIAL_CONNECTION_WINDOW_BYTES,
                quiche::h3::APPLICATION_PROTOCOL,
                MAX_IDLE_TIMEOUT_MILLIS,
            )
        }

        fn with_response_window(response_window: u64) -> Result<Self, RuntimeError> {
            Self::with_options(
                "localhost",
                Some("localhost"),
                PeerSettingsFault::None,
                response_window,
                INITIAL_CONNECTION_WINDOW_BYTES,
                quiche::h3::APPLICATION_PROTOCOL,
                MAX_IDLE_TIMEOUT_MILLIS,
            )
        }

        fn with_connection_window(connection_window: u64) -> Result<Self, RuntimeError> {
            Self::with_options(
                "localhost",
                Some("localhost"),
                PeerSettingsFault::None,
                INITIAL_BIDI_STREAM_WINDOW_BYTES,
                connection_window,
                quiche::h3::APPLICATION_PROTOCOL,
                MAX_IDLE_TIMEOUT_MILLIS,
            )
        }

        fn with_negotiated_alpn(alpn: &[&[u8]]) -> Result<Self, RuntimeError> {
            Self::with_options(
                "localhost",
                Some("localhost"),
                PeerSettingsFault::None,
                INITIAL_BIDI_STREAM_WINDOW_BYTES,
                INITIAL_CONNECTION_WINDOW_BYTES,
                alpn,
                MAX_IDLE_TIMEOUT_MILLIS,
            )
        }

        fn with_idle_timeout(idle_timeout_millis: u64) -> Result<Self, RuntimeError> {
            Self::with_options(
                "localhost",
                Some("localhost"),
                PeerSettingsFault::None,
                INITIAL_BIDI_STREAM_WINDOW_BYTES,
                INITIAL_CONNECTION_WINDOW_BYTES,
                quiche::h3::APPLICATION_PROTOCOL,
                idle_timeout_millis,
            )
        }

        fn with_options(
            expected_authority: &str,
            offered_server_name: Option<&str>,
            fault: PeerSettingsFault,
            response_window: u64,
            connection_window: u64,
            alpn: &[&[u8]],
            idle_timeout_millis: u64,
        ) -> Result<Self, RuntimeError> {
            let directory =
                tempfile::tempdir().map_err(|_| RuntimeError::ConfigurationUnavailable)?;
            let certificate_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
            std::fs::write(&certificate_path, certified.cert.pem())
                .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
            std::fs::write(&key_path, certified.key_pair.serialize_pem())
                .map_err(|_| RuntimeError::ConfigurationUnavailable)?;

            let owner = test_server_role(
                &certificate_path,
                &key_path,
                expected_authority,
                "h3",
                7,
                "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            )?;
            let role = FrozenDirectV3ServerRole::new(owner)?;
            let mut server_config = ServerConnectionConfig::new(role)?;
            server_config
                .transport
                .set_max_idle_timeout(idle_timeout_millis);
            server_config
                .transport
                .set_application_protos(alpn)
                .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
            let mut client_config = bounded_transport_config()?;
            client_config.verify_peer(false);
            client_config.set_max_idle_timeout(idle_timeout_millis);
            client_config.set_initial_max_data(connection_window);
            client_config.set_max_connection_window(connection_window);
            client_config.set_initial_max_stream_data_bidi_local(response_window);
            client_config
                .set_application_protos(alpn)
                .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
            if matches!(fault, PeerSettingsFault::DatagramMissing) {
                client_config.enable_dgram(false, 0, 0);
            }
            let client_h3_config = test_peer_h3_config(fault)?;
            let source_connection_id = [0x51_u8; quiche::MAX_CONN_ID_LEN];
            let source_connection_id = quiche::ConnectionId::from_ref(&source_connection_id);
            let mut client = quiche::connect(
                offered_server_name,
                &source_connection_id,
                CLIENT_ADDRESS,
                SERVER_ADDRESS,
                &mut client_config,
            )
            .map_err(|_| RuntimeError::ConnectionUnavailable)?;

            let mut first_packet = [0_u8; MAX_PACKET_BYTES];
            let (length, info) = client
                .send(&mut first_packet)
                .map_err(|_| RuntimeError::PacketUnavailable)?;
            let initial_header =
                quiche::Header::from_slice(&mut first_packet[..length], quiche::MAX_CONN_ID_LEN)
                    .map_err(|_| RuntimeError::InitialPacketRejected)?;
            let server_source_connection_id =
                ServerSourceConnectionId::new(SERVER_SOURCE_CONNECTION_ID);
            assert_ne!(
                initial_header.dcid.as_ref(),
                server_source_connection_id.as_bytes(),
                "server-owned SCID must not come from the client Initial"
            );
            let server = ServerConnection::accept_initial(
                &mut server_config,
                server_source_connection_id,
                &mut first_packet,
                length,
                PacketMeta {
                    from: info.from,
                    to: info.to,
                },
            )?;
            assert_eq!(
                server.transport.source_id().as_ref(),
                SERVER_SOURCE_CONNECTION_ID.as_ref(),
                "live server connection must use the server-owned SCID"
            );
            Ok(Self {
                client,
                client_h3: None,
                client_h3_config: Some(client_h3_config),
                server,
            })
        }

        fn drive_until_h3_initialized_before_peer_settings(&mut self) -> Result<(), RuntimeError> {
            for _ in 0..MAX_SHUTTLE_STEPS {
                self.server_to_client()?;
                self.client_to_server()?;
                if self.client.is_in_early_data() {
                    return Err(RuntimeError::EarlyDataRejected);
                }
                if self.client.is_established() && self.client_h3.is_none() {
                    let h3_config = self
                        .client_h3_config
                        .take()
                        .ok_or(RuntimeError::H3Unavailable)?;
                    self.client_h3 = Some(
                        quiche::h3::Connection::with_transport(&mut self.client, &h3_config)
                            .map_err(|_| RuntimeError::H3Unavailable)?,
                    );
                }
                if self.client_h3.is_some()
                    && self.server.is_established()
                    && self.server.h3_initialized()
                {
                    return Ok(());
                }
            }
            Err(RuntimeError::ConnectionUnavailable)
        }

        fn drive_until_h3(&mut self) -> Result<(), RuntimeError> {
            self.drive_until_h3_initialized_before_peer_settings()?;
            for _ in 0..MAX_SHUTTLE_STEPS {
                self.server_to_client()?;
                self.client_to_server()?;
                if self.client.is_in_early_data() {
                    return Err(RuntimeError::EarlyDataRejected);
                }
                if self.client.is_established() && self.client_h3.is_none() {
                    let h3_config = self
                        .client_h3_config
                        .take()
                        .ok_or(RuntimeError::H3Unavailable)?;
                    self.client_h3 = Some(
                        quiche::h3::Connection::with_transport(&mut self.client, &h3_config)
                            .map_err(|_| RuntimeError::H3Unavailable)?,
                    );
                }
                if self.client_h3.is_some()
                    && self.server.is_established()
                    && self.server.pre_auth_foundation_ready()
                {
                    return Ok(());
                }
            }
            Err(RuntimeError::ConnectionUnavailable)
        }

        fn client_to_server(&mut self) -> Result<bool, RuntimeError> {
            let mut moved = false;
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            loop {
                match self.client.send(&mut packet) {
                    Ok((length, info)) => {
                        moved = true;
                        self.server.receive_packet(
                            &mut packet,
                            length,
                            PacketMeta {
                                from: info.from,
                                to: info.to,
                            },
                        )?;
                    }
                    Err(quiche::Error::Done) => return Ok(moved),
                    Err(_) => return Err(RuntimeError::PacketUnavailable),
                }
            }
        }

        fn client_transport_to_server_without_h3_drive(&mut self) -> Result<bool, RuntimeError> {
            let mut moved = false;
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            loop {
                match self.client.send(&mut packet) {
                    Ok((length, info)) => {
                        moved = true;
                        self.server
                            .transport
                            .recv(
                                &mut packet[..length],
                                quiche::RecvInfo {
                                    from: info.from,
                                    to: info.to,
                                },
                            )
                            .map_err(|_| RuntimeError::PacketRejected)?;
                    }
                    Err(quiche::Error::Done) => return Ok(moved),
                    Err(_) => return Err(RuntimeError::PacketUnavailable),
                }
            }
        }

        fn server_transport_to_client_without_h3_drive(&mut self) -> Result<bool, RuntimeError> {
            let mut moved = false;
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            loop {
                match self.server.transport.send(&mut packet) {
                    Ok((length, info)) => {
                        moved = true;
                        self.client
                            .recv(
                                &mut packet[..length],
                                quiche::RecvInfo {
                                    from: info.from,
                                    to: info.to,
                                },
                            )
                            .map_err(|_| RuntimeError::PacketRejected)?;
                    }
                    Err(quiche::Error::Done) => return Ok(moved),
                    Err(_) => return Err(RuntimeError::PacketUnavailable),
                }
            }
        }

        fn server_to_client(&mut self) -> Result<bool, RuntimeError> {
            let mut moved = false;
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            while let Some((length, meta)) = self.server.next_packet(&mut packet)? {
                moved = true;
                self.client
                    .recv(
                        &mut packet[..length],
                        quiche::RecvInfo {
                            from: meta.from,
                            to: meta.to,
                        },
                    )
                    .map_err(|_| RuntimeError::PacketRejected)?;
            }
            Ok(moved)
        }

        fn send_pre_auth_headers(
            &mut self,
            headers: &[quiche::h3::Header],
        ) -> Result<RuntimeError, RuntimeError> {
            self.client_h3
                .as_mut()
                .ok_or(RuntimeError::H3Unavailable)?
                .send_request(&mut self.client, headers, true)
                .map_err(|_| RuntimeError::H3Unavailable)?;

            let mut packet = [0_u8; MAX_PACKET_BYTES];
            loop {
                match self.client.send(&mut packet) {
                    Ok((length, info)) => match self.server.receive_packet(
                        &mut packet,
                        length,
                        PacketMeta {
                            from: info.from,
                            to: info.to,
                        },
                    ) {
                        Ok(()) => {}
                        Err(error) => return Ok(error),
                    },
                    Err(quiche::Error::Done) => {
                        return Err(RuntimeError::PreAuthApplicationActivity)
                    }
                    Err(_) => return Err(RuntimeError::PacketUnavailable),
                }
            }
        }

        fn send_pre_auth_request(&mut self) -> Result<RuntimeError, RuntimeError> {
            let headers = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/"),
            ];
            self.send_pre_auth_headers(&headers)
        }

        fn live_client_control(
            &mut self,
        ) -> Result<[u8; AUTH_V3_CLIENT_CONTROL_LEN], RuntimeError> {
            let label = std::str::from_utf8(AUTH_V3_EXPORTER_LABEL)
                .map_err(|_| RuntimeError::AuthenticationUnavailable)?;
            let mut exporter = [0_u8; AUTH_V3_EXPORTER_LEN];
            if self.client.application_proto() != b"h3" {
                return Err(RuntimeError::AuthenticationUnavailable);
            }
            let tls: &mut SslRef = self.client.as_mut();
            if tls.version2() != Some(SslVersion::TLS1_3) {
                return Err(RuntimeError::AuthenticationUnavailable);
            }
            tls.export_keying_material(&mut exporter, label, Some(&[]))
                .map_err(|_| RuntimeError::AuthenticationUnavailable)?;
            self.client_control_with_exporter(&exporter)
        }

        fn client_control_with_exporter(
            &self,
            exporter: &[u8; AUTH_V3_EXPORTER_LEN],
        ) -> Result<[u8; AUTH_V3_CLIENT_CONTROL_LEN], RuntimeError> {
            let preselected = self.server.role.direct_v3().preselected_profile();
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                exporter,
                true,
                Some(&[]),
                self.server.role.direct_v3().tunnel_path(),
            );
            encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, trusted_now_unix()?, [0x6b; 32]),
            )
            .map_err(|_| RuntimeError::AuthenticationUnavailable)
        }

        fn send_auth_control(&mut self, control: &[u8], fin: bool) -> Result<u64, RuntimeError> {
            self.send_auth_fragments(&[control], fin)
        }

        fn send_auth_fragments(
            &mut self,
            fragments: &[&[u8]],
            final_fin: bool,
        ) -> Result<u64, RuntimeError> {
            let headers = test_auth_request_headers();
            let h3 = self.client_h3.as_mut().ok_or(RuntimeError::H3Unavailable)?;
            let stream_id = h3
                .send_request(&mut self.client, &headers, false)
                .map_err(|_| RuntimeError::H3Unavailable)?;
            for (index, fragment) in fragments.iter().enumerate() {
                let fin = final_fin && index + 1 == fragments.len();
                let written = h3
                    .send_body(&mut self.client, stream_id, fragment, fin)
                    .map_err(|_| RuntimeError::H3Unavailable)?;
                if written != fragment.len() {
                    return Err(RuntimeError::PacketUnavailable);
                }
            }
            Ok(stream_id)
        }

        fn send_auth_headers_only(&mut self) -> Result<u64, RuntimeError> {
            let headers = test_auth_request_headers();
            self.client_h3
                .as_mut()
                .ok_or(RuntimeError::H3Unavailable)?
                .send_request(&mut self.client, &headers, false)
                .map_err(|_| RuntimeError::H3Unavailable)
        }

        fn authenticate_generation(&mut self) -> Result<u64, RuntimeError> {
            self.drive_until_h3()?;
            let control = self.live_client_control()?;
            let stream_id = self.send_auth_control(&control, true)?;
            self.client_to_server()?;
            self.collect_confirmation(stream_id)?;
            for _ in 0..2 {
                self.client_to_server()?;
                self.server_to_client()?;
            }
            if !self.server.is_authenticated() {
                return Err(RuntimeError::AuthenticationRejected);
            }
            Ok(stream_id)
        }

        fn send_classic_connect(
            &mut self,
            headers: &[quiche::h3::Header],
            fin: bool,
        ) -> Result<u64, RuntimeError> {
            self.client_h3
                .as_mut()
                .ok_or(RuntimeError::H3Unavailable)?
                .send_request(&mut self.client, headers, fin)
                .map_err(|_| RuntimeError::ClassicConnectAdmissionRejected)
        }

        fn poll_exact_classic_connect_success(
            &mut self,
            expected_stream: u64,
        ) -> Result<bool, RuntimeError> {
            let h3 = self.client_h3.as_mut().ok_or(RuntimeError::H3Unavailable)?;
            let mut seen = false;
            loop {
                match h3.poll(&mut self.client) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, more_frames }))
                        if stream_id == expected_stream
                            && !seen
                            && more_frames
                            && list.len() == 1
                            && list[0].name() == b":status"
                            && list[0].value() == b"200" =>
                    {
                        seen = true;
                    }
                    Ok(_) | Err(quiche::h3::Error::StreamBlocked) => {
                        return Err(RuntimeError::ClassicConnectResponseRejected);
                    }
                    Err(quiche::h3::Error::Done) => return Ok(seen),
                    Err(_) => return Err(RuntimeError::ClassicConnectResponseRejected),
                }
            }
        }

        fn poll_classic_connect_body(
            &mut self,
            expected_stream: u64,
            output: &mut Vec<u8>,
        ) -> Result<bool, RuntimeError> {
            let h3 = self.client_h3.as_mut().ok_or(RuntimeError::H3Unavailable)?;
            loop {
                match h3.poll(&mut self.client) {
                    Ok((stream_id, quiche::h3::Event::Data)) if stream_id == expected_stream => {
                        let mut body = [0_u8; TARGET_TO_CLIENT_BUFFER_BYTES];
                        loop {
                            match h3.recv_body(&mut self.client, stream_id, &mut body) {
                                Ok(0) => return Err(RuntimeError::ClassicConnectDataRejected),
                                Ok(length) => output.extend_from_slice(&body[..length]),
                                Err(quiche::h3::Error::Done) => break,
                                Err(_) => return Err(RuntimeError::ClassicConnectDataRejected),
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished))
                        if stream_id == expected_stream =>
                    {
                        return Ok(true);
                    }
                    Ok(_) | Err(quiche::h3::Error::StreamBlocked) => {
                        return Err(RuntimeError::ClassicConnectDataRejected);
                    }
                    Err(quiche::h3::Error::Done) => return Ok(false),
                    Err(_) => return Err(RuntimeError::ClassicConnectDataRejected),
                }
            }
        }

        fn collect_confirmation(
            &mut self,
            expected_stream: u64,
        ) -> Result<[u8; AUTH_V3_SERVER_CONFIRMATION_LEN], RuntimeError> {
            let mut progress = ConfirmationProgress::empty();
            for _ in 0..MAX_SHUTTLE_STEPS {
                self.server_to_client()?;
                self.poll_confirmation(expected_stream, &mut progress)?;
                if progress.finished {
                    return Ok(progress.body);
                }
                self.client_to_server()?;
            }
            Err(RuntimeError::AuthenticationUnavailable)
        }

        fn poll_confirmation(
            &mut self,
            expected_stream: u64,
            progress: &mut ConfirmationProgress,
        ) -> Result<(), RuntimeError> {
            let h3 = self.client_h3.as_mut().ok_or(RuntimeError::H3Unavailable)?;
            loop {
                match h3.poll(&mut self.client) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                        if stream_id != expected_stream
                            || progress.headers_seen
                            || !more_frames
                            || list.len() != 3
                            || list[0].name() != b":status"
                            || list[0].value() != b"200"
                            || list[1].name() != b"content-type"
                            || list[1].value() != AUTH_CONTENT_TYPE
                            || list[2].name() != b"content-length"
                            || list[2].value() != b"320"
                        {
                            return Err(RuntimeError::AuthenticationRejected);
                        }
                        progress.headers_seen = true;
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if stream_id != expected_stream || progress.offset >= progress.body.len() {
                            return Err(RuntimeError::AuthenticationRejected);
                        }
                        loop {
                            match h3.recv_body(
                                &mut self.client,
                                stream_id,
                                &mut progress.body[progress.offset..],
                            ) {
                                Ok(length) if length > 0 => progress.offset += length,
                                Ok(_) => return Err(RuntimeError::AuthenticationRejected),
                                Err(quiche::h3::Error::Done) => break,
                                Err(_) => return Err(RuntimeError::AuthenticationRejected),
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if stream_id != expected_stream
                            || !progress.headers_seen
                            || progress.offset != progress.body.len()
                            || progress.finished
                        {
                            return Err(RuntimeError::AuthenticationRejected);
                        }
                        progress.finished = true;
                    }
                    Ok(_) => return Err(RuntimeError::AuthenticationRejected),
                    Err(quiche::h3::Error::Done) => return Ok(()),
                    Err(_) => return Err(RuntimeError::H3Unavailable),
                }
            }
        }

        fn deliver_close_to_client(&mut self) {
            self.server_to_client()
                .expect("deliver fixed pre-authentication close in memory");
            let peer_error = self
                .client
                .peer_error()
                .expect("real peer receives pre-authentication close");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, PRE_AUTH_CLOSE_CODE);
            assert!(peer_error.reason.is_empty());
        }
    }

    fn test_peer_h3_config(fault: PeerSettingsFault) -> Result<quiche::h3::Config, RuntimeError> {
        let mut config =
            quiche::h3::Config::new().map_err(|_| RuntimeError::ConfigurationUnavailable)?;
        config.set_reject_peer_push_activity(true);
        config.set_suppress_trace_logging(true);
        config.set_max_field_section_size(if matches!(fault, PeerSettingsFault::MaxFieldWrong) {
            MAX_FIELD_SECTION_BYTES + 1
        } else {
            MAX_FIELD_SECTION_BYTES
        });
        if !matches!(fault, PeerSettingsFault::QpackTableMissing) {
            config.set_qpack_max_table_capacity(
                if matches!(fault, PeerSettingsFault::QpackTableWrong) {
                    1
                } else {
                    QPACK_MAX_TABLE_CAPACITY
                },
            );
        }
        if !matches!(fault, PeerSettingsFault::QpackBlockedMissing) {
            config.set_qpack_blocked_streams(
                if matches!(fault, PeerSettingsFault::QpackBlockedWrong) {
                    1
                } else {
                    QPACK_BLOCKED_STREAMS
                },
            );
        }
        config.set_max_priority_update_size(MAX_PRIORITY_UPDATE_BYTES);
        config.enable_extended_connect(!matches!(fault, PeerSettingsFault::ExtendedConnectMissing));
        Ok(config)
    }

    fn test_auth_request_headers() -> [quiche::h3::Header; 6] {
        [
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/direct-v3"),
            quiche::h3::Header::new(b"content-type", AUTH_CONTENT_TYPE),
            quiche::h3::Header::new(b"content-length", b"256"),
        ]
    }

    fn test_classic_connect_headers(
        authority: &[u8],
        authority_first: bool,
    ) -> [quiche::h3::Header; 2] {
        if authority_first {
            [
                quiche::h3::Header::new(b":authority", authority),
                quiche::h3::Header::new(b":method", b"CONNECT"),
            ]
        } else {
            [
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", authority),
            ]
        }
    }

    fn test_server_role(
        certificate_path: &Path,
        key_path: &Path,
        expected_authority: &str,
        transport_strategy: &str,
        credential_epoch: u64,
        secret: &str,
    ) -> Result<Arc<ServerRoleConfig>, RuntimeError> {
        let yaml = format!(
            r#"version: 3
role: server
security: {{ posture: standard }}
transport: {{ strategy: {transport_strategy} }}
trust: {{ route: direct_to_maverick }}
name_privacy: {{ minimum: plain_sni }}
traffic_shaping: {{ policy: disabled }}
listen: "127.0.0.1:0"
tls:
  cert_path: "{}"
  key_path: "{}"
maverick:
  tunnel_path: "/direct-v3"
  expected_authority: "{expected_authority}"
target_open:
  timeout_ms: 10000
  egress:
    allow_loopback: false
    allow_private: false
    allow_link_local: false
    allow_multicast: false
    allow_unspecified: false
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
      provisioning_handle: "EREREREREREREREREREREQ"
      principal_id: "IiIiIiIiIiIiIiIiIiIiIg"
      deployment_profile_id: "MzMzMzMzMzMzMzMzMzMzMw"
      credential_namespace_id: "RERERERERERERERERERERA"
      server_identity_id: "VVVVVVVVVVVVVVVVVVVVVQ"
      credential_epoch: {credential_epoch}
      credential_not_after_unix: 1800172800
      secret: "{secret}"
"#,
            certificate_path.display(),
            key_path.display(),
        );
        ServerRoleConfig::from_yaml_str(&yaml)
            .map(Arc::new)
            .map_err(|_| RuntimeError::RoleUnavailable)
    }

    #[test]
    fn t027b2b2_1_server_advertises_required_h3_capabilities() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair through peer SETTINGS");
        pair.server_to_client()
            .expect("deliver server SETTINGS in memory");
        let client_h3 = pair.client_h3.as_mut().expect("client H3 exists");
        match client_h3.poll(&mut pair.client) {
            Err(quiche::h3::Error::Done) => {}
            Ok((_stream_id, _event)) => panic!("SETTINGS must remain internal H3 work"),
            Err(_) => panic!("server SETTINGS must be processable"),
        }
        let raw_settings = client_h3
            .peer_settings_raw()
            .expect("client processed actual server SETTINGS");
        assert_eq!(
            peer_setting(raw_settings, SETTINGS_MAX_FIELD_SECTION_SIZE),
            Some(MAX_FIELD_SECTION_BYTES)
        );
        assert_eq!(
            peer_setting(raw_settings, SETTINGS_QPACK_MAX_TABLE_CAPACITY),
            Some(QPACK_MAX_TABLE_CAPACITY)
        );
        assert_eq!(
            peer_setting(raw_settings, SETTINGS_QPACK_BLOCKED_STREAMS),
            Some(QPACK_BLOCKED_STREAMS)
        );
        assert!(
            client_h3.extended_connect_enabled_by_peer(),
            "T027b-2b2-1 requires server Extended CONNECT"
        );
        assert!(
            client_h3.dgram_enabled_by_peer(&pair.client),
            "T027b-2b2-1 requires H3 plus QUIC DATAGRAM"
        );
        assert_eq!(
            pair.client
                .peer_transport_params()
                .and_then(|params| params.max_datagram_frame_size),
            Some(MAX_DATAGRAM_FRAME_BYTES)
        );
        assert_eq!(DATAGRAM_QUEUE_LIMIT, 32);
    }

    #[test]
    fn t027b2b2_1_readiness_waits_for_actual_peer_settings_processing() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3_initialized_before_peer_settings()
            .expect("initialize both H3 objects without delivering client SETTINGS");

        assert!(pair.server.is_established());
        assert!(pair.server.h3_initialized());
        assert!(
            pair.server
                .h3
                .as_ref()
                .expect("server H3 exists")
                .peer_settings_raw()
                .is_none(),
            "client SETTINGS have not reached server H3 poll"
        );
        assert!(!pair.server.pre_auth_foundation_ready());

        pair.drive_until_h3()
            .expect("deliver and process actual client SETTINGS");
        assert!(pair.server.pre_auth_foundation_ready());
    }

    #[test]
    fn t027b2b2_1_peer_settings_contract_rejects_each_missing_or_wrong_requirement() {
        let required = PeerFoundationSettings {
            max_field_section_size: Some(MAX_FIELD_SECTION_BYTES),
            qpack_max_table_capacity: Some(QPACK_MAX_TABLE_CAPACITY),
            qpack_blocked_streams: Some(QPACK_BLOCKED_STREAMS),
            extended_connect: true,
            h3_datagram: true,
            quic_datagram_frame_bytes: Some(MAX_DATAGRAM_FRAME_BYTES),
        };
        assert!(required.matches_required());

        let mut rejected = Vec::new();
        for settings in [
            PeerFoundationSettings {
                max_field_section_size: None,
                ..required
            },
            PeerFoundationSettings {
                max_field_section_size: Some(MAX_FIELD_SECTION_BYTES + 1),
                ..required
            },
            PeerFoundationSettings {
                qpack_max_table_capacity: None,
                ..required
            },
            PeerFoundationSettings {
                qpack_max_table_capacity: Some(1),
                ..required
            },
            PeerFoundationSettings {
                qpack_blocked_streams: None,
                ..required
            },
            PeerFoundationSettings {
                qpack_blocked_streams: Some(1),
                ..required
            },
            PeerFoundationSettings {
                extended_connect: false,
                ..required
            },
            PeerFoundationSettings {
                h3_datagram: false,
                ..required
            },
            PeerFoundationSettings {
                quic_datagram_frame_bytes: None,
                ..required
            },
            PeerFoundationSettings {
                quic_datagram_frame_bytes: Some(MAX_DATAGRAM_FRAME_BYTES - 1),
                ..required
            },
        ] {
            rejected.push(!settings.matches_required());
        }
        assert_eq!(rejected, vec![true; 10]);
    }

    #[test]
    fn t027b2b2_1_readiness_state_only_advances_and_has_value_free_debug() {
        let mut state = PreAuthFoundationState::AwaitingHandshake;
        state.peer_settings_verified();
        assert_eq!(state, PreAuthFoundationState::AwaitingHandshake);
        state.h3_initialized();
        assert_eq!(state, PreAuthFoundationState::AwaitingPeerSettings);
        state.peer_settings_verified();
        assert_eq!(state, PreAuthFoundationState::Ready);
        state.h3_initialized();
        state.peer_settings_verified();
        assert_eq!(state, PreAuthFoundationState::Ready);
        assert_eq!(format!("{state:?}"), "Ready");
    }

    #[test]
    fn t027b2b2_1_live_peer_settings_faults_close_with_fixed_code() {
        for fault in [
            PeerSettingsFault::MaxFieldWrong,
            PeerSettingsFault::QpackTableMissing,
            PeerSettingsFault::QpackTableWrong,
            PeerSettingsFault::QpackBlockedMissing,
            PeerSettingsFault::QpackBlockedWrong,
            PeerSettingsFault::ExtendedConnectMissing,
            PeerSettingsFault::DatagramMissing,
        ] {
            let mut pair = TestPair::with_peer_settings("localhost", Some("localhost"), fault)
                .expect("construct bounded in-memory pair");
            let error = pair
                .drive_until_h3()
                .expect_err("mismatched live peer SETTINGS must fail closed");
            assert_eq!(error, RuntimeError::PeerSettingsRejected);
            assert!(!pair.server.pre_auth_foundation_ready());
            pair.deliver_close_to_client();
        }
    }

    #[test]
    fn t027b2b2_1_live_sni_is_required_and_byte_exact() {
        for offered in [None, Some("origin.invalid"), Some("other.invalid")] {
            let mut pair = TestPair::with_server_name("Origin.Invalid", offered)
                .expect("construct bounded in-memory pair");
            let error = pair
                .drive_until_h3()
                .expect_err("missing or mismatched live SNI must fail closed");
            assert_eq!(error, RuntimeError::ServerNameRejected);
            pair.deliver_close_to_client();
        }

        let mut exact = TestPair::with_server_name("Origin.Invalid", Some("Origin.Invalid"))
            .expect("construct exact-SNI pair");
        exact
            .drive_until_h3()
            .expect("byte-exact case-sensitive SNI reaches foundation readiness");
        assert!(exact.server.pre_auth_foundation_ready());
    }

    #[test]
    fn t027b2b2_2_live_negotiated_alpn_cannot_be_replaced_by_expected_config() {
        let mut pair = TestPair::with_negotiated_alpn(&[b"h2"])
            .expect("construct non-H3 negotiated test pair");
        let error = pair
            .drive_until_h3()
            .expect_err("live non-H3 ALPN must fail before auth");
        assert_eq!(error, RuntimeError::AlpnRejected);
        assert!(!pair.server.pre_auth_foundation_ready());
        assert!(!pair.server.is_authenticated());
        pair.deliver_close_to_client();
    }

    #[test]
    fn t027b2b2_1_mandatory_settings_and_qpack_work_remain_internal() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("mandatory H3 streams and SETTINGS process internally");
        assert!(pair.server.pre_auth_foundation_ready());
        assert!(pair.server.h3.as_ref().is_some());
    }

    #[test]
    fn t027b2b2_1_pre_auth_datagram_is_never_read_and_closes_generation() {
        for after_settings in [false, true] {
            let mut pair = TestPair::new().expect("construct bounded in-memory pair");
            if after_settings {
                pair.drive_until_h3()
                    .expect("drive bounded in-memory pair through peer SETTINGS");
            } else {
                pair.drive_until_h3_initialized_before_peer_settings()
                    .expect("initialize H3 before delivering peer SETTINGS");
            }
            pair.client
                .dgram_send(b"test-private-datagram-marker")
                .expect("queue one bounded test Datagram");
            let error = pair
                .client_to_server()
                .expect_err("pre-auth Datagram must fail closed");
            assert_eq!(error, RuntimeError::PreAuthApplicationActivity);
            pair.deliver_close_to_client();
            assert!(!error.to_string().contains("marker"));
            assert_eq!(format!("{error:?}"), "private server connection error");
        }

        let source = include_str!("quiche_runtime.rs");
        assert!(!source.contains(&[".dgram_", "recv("].concat()));
    }

    #[test]
    fn t027b2b2_2_auth_headers_with_immediate_fin_fail_closed() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair through peer SETTINGS");
        let headers = test_auth_request_headers();
        let error = pair
            .send_pre_auth_headers(&headers)
            .expect("receive fixed auth-shaped request rejection");
        assert_eq!(error, RuntimeError::AuthenticationRejected);
        pair.deliver_close_to_client();
    }

    #[test]
    fn server_owns_established_h3_until_explicit_close_and_drop() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair to H3");

        assert!(pair.server.is_established());
        assert!(pair.server.pre_auth_foundation_ready());
        assert!(pair.server.next_timeout().is_some());
        pair.server
            .close()
            .expect("explicitly close server-owned connection");
        let local_error = pair
            .server
            .transport
            .local_error()
            .expect("local close records a pending application error");
        assert!(local_error.is_app);
        assert_eq!(local_error.error_code, 0);
        assert!(!pair.server.transport.is_draining());
        assert!(!pair.server.transport.is_closed());
        assert_eq!(
            pair.server.lifecycle(),
            ConnectionLifecycle::ClosingPendingSend
        );
        pair.server_to_client()
            .expect("deliver explicit server close in memory");
        let peer_error = pair
            .client
            .peer_error()
            .expect("real peer receives the server CONNECTION_CLOSE");
        assert!(peer_error.is_app);
        assert_eq!(peer_error.error_code, 0);
        assert!(peer_error.reason.is_empty());
        assert!(pair.server.transport.is_draining());
        assert!(!pair.server.transport.is_closed());
        assert_eq!(pair.server.lifecycle(), ConnectionLifecycle::Draining);
        assert!(pair.client.is_draining() || pair.client.is_closed());
        drop(pair.server);
    }

    #[test]
    fn server_rejects_pre_authentication_application_activity() {
        for after_settings in [false, true] {
            let mut pair = TestPair::new().expect("construct bounded in-memory pair");
            if after_settings {
                pair.drive_until_h3()
                    .expect("drive bounded in-memory pair through peer SETTINGS");
            } else {
                pair.drive_until_h3_initialized_before_peer_settings()
                    .expect("initialize H3 before delivering peer SETTINGS");
            }

            let error = pair
                .send_pre_auth_request()
                .expect("receive fixed pre-authentication rejection");
            assert_eq!(error, RuntimeError::PreAuthApplicationActivity);
            assert_eq!(
                error.to_string(),
                "pre-authentication application activity rejected"
            );
            assert_eq!(format!("{error:?}"), "private server connection error");
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(
                pair.server.lifecycle(),
                ConnectionLifecycle::ClosingPendingSend
            );
            pair.deliver_close_to_client();
            assert!(pair.client.is_draining() || pair.client.is_closed());
        }
    }

    #[test]
    fn packet_and_timer_api_remain_synchronous_and_bounded() {
        let receive_packet: ReceivePacketFn = ServerConnection::receive_packet;
        let next_packet: NextPacketFn = ServerConnection::next_packet;
        let next_timeout: NextTimeoutFn = ServerConnection::next_timeout;
        let on_timeout: OnTimeoutFn = ServerConnection::on_timeout;
        let _ = (receive_packet, next_packet, next_timeout, on_timeout);
        assert_eq!(MAX_PACKET_BYTES, 1_350);
    }

    #[test]
    fn t027b2b2_2_auth_state_contract_is_explicit_and_value_free() {
        let phases = [
            ServerAuthState::Fresh,
            ServerAuthState::Authenticating,
            ServerAuthState::SendingConfirmation,
            ServerAuthState::Authenticated,
            ServerAuthState::Failed,
        ];
        assert_eq!(
            phases.map(|phase| format!("{phase:?}")),
            [
                "Fresh",
                "Authenticating",
                "SendingConfirmation",
                "Authenticated",
                "Failed",
            ]
        );
        assert_eq!(
            format!("{:?}", ServerAuthMachine::fresh()),
            "fresh server authentication state"
        );
    }

    #[test]
    fn t027b2b2_2_exact_live_auth_happy_path_installs_capability_after_final_fin() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive same live generation through required SETTINGS");
        let generation = pair.server.generation;
        let control = pair
            .live_client_control()
            .expect("encode exact control from the live client exporter");
        let stream_id = pair
            .send_auth_control(&control, true)
            .expect("queue exact auth stream");
        assert!(!pair.server.is_authenticated());
        pair.client_to_server()
            .expect("deliver exact control on the same live generation");
        assert!(pair.server.is_authenticated());
        let capability = pair
            .server
            .auth
            .capability
            .as_ref()
            .expect("final H3 body plus FIN installs capability");
        assert_eq!(capability.generation.as_bytes(), generation.as_bytes());
        assert!(capability.session_id.iter().any(|byte| *byte != 0));
        assert_eq!(capability.credential_epoch, 7);
        assert!(capability.active);
        assert!(!capability.revoked);
        assert_eq!(capability.carrier, AuthV3Carrier::H3);
        assert_eq!(capability.max_frame_size, 65_536);
        assert_eq!(capability.max_concurrent_flows, 128);
        assert_eq!(
            format!("{capability:?}"),
            "authenticated server generation capability"
        );
        assert!(capability.admission_expiry_unix < capability.hard_expiry_unix);
        assert!(capability.admission_deadline < capability.hard_deadline);
        let confirmation = pair
            .collect_confirmation(stream_id)
            .expect("receive exact 320-byte confirmation with final FIN");
        assert_eq!(confirmation.len(), AUTH_V3_SERVER_CONFIRMATION_LEN);
        assert_eq!(pair.server.auth.state, ServerAuthState::Authenticated);
        assert!(pair.server.auth.control.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.exporter.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.confirmation.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn t027b2b2_2_same_batch_settings_are_installed_before_first_headers() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.drive_until_h3_initialized_before_peer_settings()
            .expect("initialize H3 before server processes peer SETTINGS");
        assert!(!pair.server.pre_auth_foundation_ready());
        let control = pair.live_client_control().expect("encode live control");
        pair.send_auth_control(&control, true)
            .expect("queue SETTINGS followed by first auth request");
        pair.client_to_server()
            .expect("same drive validates SETTINGS before accepting Headers");
        assert!(pair.server.pre_auth_foundation_ready());
        assert!(pair.server.is_authenticated());
        assert_eq!(pair.server.auth.state, ServerAuthState::Authenticated);
    }

    #[test]
    fn t027b2b2_2_confirmation_progress_never_authenticates_early() {
        let now = Instant::now();
        let mut auth = ServerAuthMachine::fresh();
        auth.enter_gate(now).expect("start absolute auth wall");
        auth.start(0, [0x91; AUTH_V3_EXPORTER_LEN])
            .expect("occupy one auth stream");
        let pending = AuthenticatedGenerationCapability {
            generation: ServerSourceConnectionId::new(SERVER_SOURCE_CONNECTION_ID),
            session_id: [0x82; 16],
            credential_epoch: 7,
            admission_expiry_unix: 10_100,
            hard_expiry_unix: 10_200,
            admission_deadline: now + Duration::from_secs(5),
            hard_deadline: now + Duration::from_secs(6),
            active: false,
            revoked: false,
            carrier: AuthV3Carrier::H3,
            max_frame_size: AUTH_MAX_FRAME_SIZE,
            max_concurrent_flows: AUTH_MAX_CONCURRENT_FLOWS,
        };
        auth.install_confirmation([0x73; AUTH_V3_SERVER_CONFIRMATION_LEN], pending)
            .expect("install one fixed confirmation");

        assert_eq!(auth.state, ServerAuthState::SendingConfirmation);
        assert_eq!(
            auth.next_deadline(),
            Some(now + Duration::from_secs(5)),
            "pending admission must be scheduled before the fixed auth wall"
        );
        assert!(
            auth.authenticate(now).is_err(),
            "blocked headers cannot authenticate"
        );
        auth.mark_confirmation_headers_sent()
            .expect("one atomic response header section accepted");
        assert!(!auth
            .record_confirmation_write(73, AUTH_V3_SERVER_CONFIRMATION_LEN)
            .expect("record exact first suffix"));
        assert_eq!(auth.confirmation_offset, 73);
        assert_eq!(auth.state, ServerAuthState::SendingConfirmation);
        assert!(
            auth.authenticate(now).is_err(),
            "partial body cannot authenticate"
        );
        assert!(auth
            .record_confirmation_write(247, 247)
            .expect("record exact remaining suffix with final FIN"));
        assert_eq!(auth.confirmation_offset, AUTH_V3_SERVER_CONFIRMATION_LEN);
        auth.wall_deadline = Some(now);
        assert_eq!(
            auth.authenticate(now),
            Err(RuntimeError::AuthenticationExpired),
            "activation must recheck trusted monotonic time after the final write"
        );
        auth.wall_deadline = Some(now + AUTH_WALL_TIMEOUT);
        auth.authenticate(now + Duration::from_secs(1))
            .expect("only complete final suffix permits capability");
        assert_eq!(auth.state, ServerAuthState::Authenticated);
    }

    #[test]
    fn t027b2b2_2_live_blocked_and_partial_confirmation_remain_pending() {
        let mut blocked = TestPair::with_response_window(0).expect("construct blocked pair");
        blocked.drive_until_h3().expect("reach auth gate");
        let control = blocked.live_client_control().expect("encode valid control");
        blocked
            .send_auth_control(&control, true)
            .expect("queue valid control");
        blocked
            .client_to_server()
            .expect("blocked response remains retryable");
        assert_eq!(
            blocked.server.auth.state,
            ServerAuthState::SendingConfirmation
        );
        assert!(!blocked.server.auth.confirmation_headers_sent);
        assert_eq!(blocked.server.auth.confirmation_offset, 0);
        assert!(!blocked.server.is_authenticated());

        let mut partial = TestPair::with_response_window(256).expect("construct partial pair");
        partial.drive_until_h3().expect("reach auth gate");
        let control = partial.live_client_control().expect("encode valid control");
        partial
            .send_auth_control(&control, true)
            .expect("queue valid control");
        partial
            .client_to_server()
            .expect("partial response remains retryable");
        assert_eq!(
            partial.server.auth.state,
            ServerAuthState::SendingConfirmation
        );
        assert!(partial.server.auth.confirmation_headers_sent);
        assert!(partial.server.auth.confirmation_offset < AUTH_V3_SERVER_CONFIRMATION_LEN);
        assert!(!partial.server.is_authenticated());
    }

    #[test]
    fn t027b2b2_2_live_partial_confirmation_retries_exact_suffix_to_fin() {
        let mut pair = TestPair::with_response_window(256).expect("construct partial pair");
        pair.drive_until_h3().expect("reach auth gate");
        let control = pair.live_client_control().expect("encode valid control");
        let stream_id = pair
            .send_auth_control(&control, true)
            .expect("queue valid control");
        pair.client_to_server()
            .expect("accept only the first bounded confirmation prefix");
        let accepted_prefix = pair.server.auth.confirmation_offset;
        let expected = pair.server.auth.confirmation;
        assert!(accepted_prefix > 0 && accepted_prefix < expected.len());

        let mut progress = ConfirmationProgress::empty();
        pair.server_to_client()
            .expect("deliver the accepted prefix to free peer flow control");
        pair.poll_confirmation(stream_id, &mut progress)
            .expect("consume the exact first prefix");
        assert_eq!(progress.offset, accepted_prefix);
        assert_eq!(
            progress.body[..accepted_prefix],
            expected[..accepted_prefix]
        );
        assert!(!progress.finished);

        for _ in 0..MAX_SHUTTLE_STEPS {
            pair.client_to_server()
                .expect("deliver flow-control credit and retry only the suffix");
            pair.server_to_client()
                .expect("deliver one bounded retry round");
            pair.poll_confirmation(stream_id, &mut progress)
                .expect("consume the retried suffix without duplication");
            if progress.finished {
                break;
            }
        }
        assert!(progress.finished);
        assert_eq!(progress.offset, AUTH_V3_SERVER_CONFIRMATION_LEN);
        assert_eq!(progress.body, expected);
        assert!(pair.server.is_authenticated());
    }

    #[test]
    fn t027b2b2_2_pending_and_wall_expiry_win_live_unblock_races() {
        for deadline_kind in 0..3 {
            let mut pair = TestPair::with_response_window(256).expect("construct partial pair");
            pair.drive_until_h3().expect("reach auth gate");
            let control = pair.live_client_control().expect("encode valid control");
            let stream_id = pair
                .send_auth_control(&control, true)
                .expect("queue valid control");
            pair.client_to_server()
                .expect("leave one confirmation suffix flow-control blocked");
            let accepted_prefix = pair.server.auth.confirmation_offset;
            assert!(accepted_prefix > 0 && accepted_prefix < AUTH_V3_SERVER_CONFIRMATION_LEN);

            let mut progress = ConfirmationProgress::empty();
            pair.server_to_client()
                .expect("deliver and consume the accepted prefix");
            pair.poll_confirmation(stream_id, &mut progress)
                .expect("consuming the prefix queues fresh peer credit");
            assert_eq!(progress.offset, accepted_prefix);

            let expires = Instant::now() + Duration::from_millis(3);
            match deadline_kind {
                0 => pair.server.auth.wall_deadline = Some(expires),
                1 => {
                    pair.server
                        .auth
                        .pending
                        .as_mut()
                        .expect("confirmation owns one pending capability")
                        .admission_deadline = expires;
                }
                2 => {
                    pair.server
                        .auth
                        .pending
                        .as_mut()
                        .expect("confirmation owns one pending capability")
                        .hard_deadline = expires;
                }
                _ => unreachable!(),
            }
            assert!(pair
                .server
                .next_timeout()
                .is_some_and(|timeout| !timeout.is_zero()));
            std::thread::sleep(Duration::from_millis(6));
            assert!(pair
                .server
                .next_timeout()
                .is_some_and(|timeout| timeout.is_zero()));

            assert_eq!(
                pair.client_to_server()
                    .expect_err("expired deadline must beat the live unblock retry"),
                RuntimeError::AuthenticationExpired
            );
            assert_eq!(pair.server.auth.state, ServerAuthState::Failed);
            assert!(!pair.server.is_authenticated());
            assert!(pair.server.auth.pending.is_none());
            assert!(pair.server.auth.capability.is_none());
            assert!(pair.server.auth.control.iter().all(|byte| *byte == 0));
            assert!(pair.server.auth.exporter.iter().all(|byte| *byte == 0));
            assert!(pair.server.auth.confirmation.iter().all(|byte| *byte == 0));
            pair.deliver_close_to_client();
            assert_eq!(progress.offset, accepted_prefix);
            assert!(!progress.finished);
        }
    }

    #[test]
    fn t027b2b2_2_expiry_selection_is_frozen_bounded_and_fail_closed() {
        assert_eq!(selected_expiries(1_000, 90_000), Ok((2_800, 87_400)));
        assert_eq!(selected_expiries(1_000, 2_000), Ok((1_999, 2_000)));
        assert_eq!(
            selected_expiries(1_000, 1_001),
            Err(RuntimeError::AuthenticationRejected)
        );
        assert_eq!(
            selected_expiries(1_000, 1_000),
            Err(RuntimeError::AuthenticationRejected)
        );
        for error in [
            RuntimeError::H3EventBudgetExhausted,
            RuntimeError::PreAuthApplicationActivity,
            RuntimeError::AuthenticationRejected,
            RuntimeError::AuthenticationUnavailable,
            RuntimeError::AuthenticationExpired,
        ] {
            assert!(error.to_string().len() <= 64);
            assert_eq!(format!("{error:?}"), "private server connection error");
        }
    }

    #[test]
    fn t027b2b2_2_headers_are_exact_ordered_and_bounded() {
        let exact = test_auth_request_headers();
        assert!(exact_auth_request_headers(
            &exact,
            b"localhost",
            b"/direct-v3"
        ));
        for mutation in [
            (0, b"GET".as_slice()),
            (1, b"http".as_slice()),
            (2, b"other.invalid".as_slice()),
            (3, b"/wrong".as_slice()),
            (4, b"application/octet-stream".as_slice()),
            (5, b"255".as_slice()),
        ] {
            let mut headers = exact.clone();
            headers[mutation.0] = quiche::h3::Header::new(headers[mutation.0].name(), mutation.1);
            assert!(!exact_auth_request_headers(
                &headers,
                b"localhost",
                b"/direct-v3"
            ));
        }
        assert!(!exact_auth_request_headers(
            &exact[..5],
            b"localhost",
            b"/direct-v3"
        ));
        assert_eq!(MAX_H3_EVENTS_PER_DRIVE, 8);
        let production = include_str!("quiche_runtime.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production source prefix exists");
        for forbidden in ["connect_target", "resolve_dns", "open_relay"] {
            assert!(!production.contains(forbidden));
        }
    }

    #[test]
    fn t027b2b2_2_live_control_rejects_wrong_wire_commitments_and_bounds() {
        for offset in [0_usize, 12, 32, 40, 48, 80, 112, 176, 192, 224] {
            let mut pair = TestPair::new().expect("construct bounded in-memory pair");
            pair.drive_until_h3()
                .expect("reach the live authentication gate");
            let mut control = pair.live_client_control().expect("encode valid control");
            control[offset] ^= 0x80;
            pair.send_auth_control(&control, true)
                .expect("queue bounded invalid control");
            let error = pair
                .client_to_server()
                .expect_err("wrong auth-v3 field must fail closed");
            assert_eq!(error, RuntimeError::AuthenticationRejected);
            assert_eq!(pair.server.auth.state, ServerAuthState::Failed);
            assert!(!pair.server.is_authenticated());
            pair.deliver_close_to_client();
        }

        for length in [
            AUTH_V3_CLIENT_CONTROL_LEN - 1,
            AUTH_V3_CLIENT_CONTROL_LEN + 1,
        ] {
            let mut pair = TestPair::new().expect("construct bounded in-memory pair");
            pair.drive_until_h3().expect("reach auth gate");
            let control = pair.live_client_control().expect("encode valid control");
            let mut body = [0_u8; AUTH_V3_CLIENT_CONTROL_LEN + 1];
            body[..AUTH_V3_CLIENT_CONTROL_LEN].copy_from_slice(&control);
            pair.send_auth_control(&body[..length], true)
                .expect("queue bounded wrong-length body");
            let error = pair
                .client_to_server()
                .expect_err("short or long body must fail closed");
            assert_eq!(error, RuntimeError::AuthenticationRejected);
            pair.deliver_close_to_client();
        }
    }

    #[test]
    fn t027b2b2_2_wrong_live_exporter_or_preselected_profile_fails_closed() {
        let mut wrong_exporter = TestPair::new().expect("construct exporter pair");
        wrong_exporter.drive_until_h3().expect("reach auth gate");
        let control = wrong_exporter
            .client_control_with_exporter(&[0x5a; AUTH_V3_EXPORTER_LEN])
            .expect("encode against a different exporter");
        wrong_exporter
            .send_auth_control(&control, true)
            .expect("queue wrong-exporter control");
        assert_eq!(
            wrong_exporter
                .client_to_server()
                .expect_err("live exporter mismatch must reject"),
            RuntimeError::AuthenticationRejected
        );
        wrong_exporter.deliver_close_to_client();

        let mut wrong_profile = TestPair::new().expect("construct profile pair");
        wrong_profile.drive_until_h3().expect("reach auth gate");
        let control = wrong_profile
            .live_client_control()
            .expect("encode against original preselected profile");
        let original = wrong_profile.server.role.direct_v3();
        let alternate = test_server_role(
            original.cert_path(),
            original.key_path(),
            "localhost",
            "h3",
            7,
            "mv1_AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        )
        .expect("parse alternate local profile");
        wrong_profile.server.role =
            FrozenDirectV3ServerRole::new(alternate).expect("preselect one alternate profile");
        wrong_profile
            .send_auth_control(&control, true)
            .expect("queue original-profile control");
        assert_eq!(
            wrong_profile
                .client_to_server()
                .expect_err("preselected profile mismatch must reject"),
            RuntimeError::AuthenticationRejected
        );
        wrong_profile.deliver_close_to_client();
    }

    #[test]
    fn t027b2b2_2_fragmented_control_is_one_stream_and_one_generation() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3().expect("reach auth gate");
        let generation = pair.server.generation;
        let control = pair.live_client_control().expect("encode valid control");
        let stream = pair
            .send_auth_fragments(
                &[
                    &control[..1],
                    &control[1..127],
                    &control[127..255],
                    &control[255..],
                ],
                true,
            )
            .expect("queue four bounded fragments");
        pair.client_to_server()
            .expect("deliver fragments on one physical generation");
        assert!(pair.server.is_authenticated());
        assert_eq!(pair.server.auth.bound_stream(), Ok(stream));
        assert_eq!(
            pair.server
                .auth
                .capability
                .as_ref()
                .expect("capability exists")
                .generation
                .as_bytes(),
            generation.as_bytes()
        );
    }

    #[test]
    fn t027b2b2_2_duplicate_stream_and_reset_fail_closed() {
        let mut duplicate = TestPair::new().expect("construct duplicate pair");
        duplicate.drive_until_h3().expect("reach auth gate");
        duplicate
            .send_auth_headers_only()
            .expect("queue first auth headers");
        duplicate
            .send_auth_headers_only()
            .expect("queue second auth headers");
        let error = duplicate
            .client_to_server()
            .expect_err("second stream must fail the generation");
        assert_eq!(error, RuntimeError::AuthenticationRejected);
        duplicate.deliver_close_to_client();

        let mut reset = TestPair::new().expect("construct reset pair");
        reset.drive_until_h3().expect("reach auth gate");
        let stream = reset
            .send_auth_headers_only()
            .expect("queue first auth headers");
        reset
            .client
            .stream_shutdown(stream, quiche::Shutdown::Write, 0x44)
            .expect("reset the request stream");
        let error = reset
            .client_to_server()
            .expect_err("request reset must fail closed");
        assert!(matches!(
            error,
            RuntimeError::PreAuthApplicationActivity | RuntimeError::H3Unavailable
        ));
        assert!(!reset.server.is_authenticated());

        let mut stopped = TestPair::new().expect("construct stop pair");
        stopped.drive_until_h3().expect("reach auth gate");
        let control = stopped.live_client_control().expect("encode valid control");
        let stream = stopped
            .send_auth_control(&control, true)
            .expect("queue valid request");
        stopped
            .client
            .stream_shutdown(stream, quiche::Shutdown::Read, 0x45)
            .expect("stop the response direction");
        let error = stopped
            .client_to_server()
            .expect_err("STOP_SENDING must fail the generation");
        assert_eq!(error, RuntimeError::AuthenticationRejected);
        assert!(!stopped.server.is_authenticated());
        stopped.deliver_close_to_client();
    }

    #[test]
    fn t027b2b2_2_goaway_and_priority_update_fail_closed_independently() {
        let mut goaway = TestPair::new().expect("construct GOAWAY pair");
        goaway.drive_until_h3().expect("reach auth gate");
        goaway
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_goaway(&mut goaway.client, 0)
            .expect("queue client GOAWAY");
        assert_eq!(
            goaway
                .client_to_server()
                .expect_err("pre-auth GOAWAY must close"),
            RuntimeError::PreAuthApplicationActivity
        );
        goaway.deliver_close_to_client();

        let mut priority = TestPair::new().expect("construct priority pair");
        priority.drive_until_h3().expect("reach auth gate");
        priority
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_priority_update_for_request(
                &mut priority.client,
                0,
                &quiche::h3::Priority::default(),
            )
            .expect("queue client priority update");
        assert_eq!(
            priority
                .client_to_server()
                .expect_err("pre-auth priority update must close"),
            RuntimeError::PreAuthApplicationActivity
        );
        priority.deliver_close_to_client();
    }

    #[test]
    fn t027b2d2_eight_h3_events_fit_and_ninth_exhausts_production_budget() {
        let mut pair = TestPair::new().expect("construct bounded event-budget pair");
        pair.drive_until_h3().expect("reach auth gate");
        let mut events = 0;
        for expected in 1..=MAX_H3_EVENTS_PER_DRIVE {
            observe_h3_application_event(&mut events)
                .expect("all eight fixed-slot application events fit");
            assert_eq!(events, expected);
        }
        assert_eq!(
            observe_h3_application_event(&mut events)
                .expect_err("the ninth application event must exhaust production budget"),
            RuntimeError::H3EventBudgetExhausted
        );
        assert_eq!(
            pair.server
                .reject_with::<()>(RuntimeError::H3EventBudgetExhausted)
                .expect_err("production budget failure closes the live generation"),
            RuntimeError::H3EventBudgetExhausted
        );
        pair.deliver_close_to_client();
    }

    #[test]
    fn t027b2b2_2_peer_close_immediately_clears_authenticated_generation() {
        let mut pair = TestPair::new().expect("construct peer-close pair");
        pair.drive_until_h3().expect("reach auth gate");
        let control = pair.live_client_control().expect("encode valid control");
        pair.send_auth_control(&control, true)
            .expect("queue valid control");
        pair.client_to_server().expect("authenticate generation");
        assert!(pair.server.is_authenticated());

        pair.client
            .close(true, 0x44, b"")
            .expect("peer initiates a real QUIC application close");
        pair.client_to_server()
            .expect("deliver peer close on the authenticated generation");
        assert_ne!(pair.server.lifecycle(), ConnectionLifecycle::Active);
        assert!(!pair.server.is_authenticated());
        assert_eq!(pair.server.auth.state, ServerAuthState::Failed);
        assert!(pair.server.auth.pending.is_none());
        assert!(pair.server.auth.capability.is_none());
        assert!(pair.server.auth.control.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.exporter.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.confirmation.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn t027b2b2_2_idle_timeout_immediately_clears_authenticated_generation() {
        let mut pair = TestPair::with_idle_timeout(25).expect("construct short-idle pair");
        pair.drive_until_h3().expect("reach auth gate");
        let control = pair.live_client_control().expect("encode valid control");
        let stream_id = pair
            .send_auth_control(&control, true)
            .expect("queue valid control");
        pair.client_to_server().expect("authenticate generation");
        pair.collect_confirmation(stream_id)
            .expect("finish the real authenticated exchange");
        assert!(pair.server.is_authenticated());

        let idle = pair
            .server
            .next_timeout()
            .expect("real QUIC idle timer exists");
        std::thread::sleep(idle + Duration::from_millis(10));
        pair.server
            .on_timeout()
            .expect("apply the real QUIC idle timeout");
        assert_ne!(pair.server.lifecycle(), ConnectionLifecycle::Active);
        assert!(!pair.server.is_authenticated());
        assert_eq!(pair.server.auth.state, ServerAuthState::Failed);
        assert!(pair.server.auth.pending.is_none());
        assert!(pair.server.auth.capability.is_none());
        assert!(pair.server.auth.control.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.exporter.iter().all(|byte| *byte == 0));
        assert!(pair.server.auth.confirmation.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn t027b2b2_2_absolute_wall_and_hard_expiry_cannot_be_renewed() {
        let now = Instant::now();
        let mut auth = ServerAuthMachine::fresh();
        auth.enter_gate(now).expect("enter gate once");
        let fixed = auth.wall_deadline.expect("wall deadline installed");
        auth.enter_gate(now + Duration::from_secs(9))
            .expect("activity does not fail before deadline");
        assert_eq!(auth.wall_deadline, Some(fixed));
        assert_eq!(fixed, now + AUTH_WALL_TIMEOUT);

        let mut wall = TestPair::new().expect("construct wall deadline pair");
        wall.drive_until_h3().expect("reach auth gate");
        wall.server.auth.wall_deadline = Some(Instant::now());
        let mut packet = [0_u8; MAX_PACKET_BYTES];
        assert!(matches!(
            wall.server.next_packet(&mut packet),
            Err(RuntimeError::AuthenticationExpired)
        ));
        wall.deliver_close_to_client();

        let mut hard = TestPair::new().expect("construct hard expiry pair");
        hard.drive_until_h3().expect("reach auth gate");
        let control = hard.live_client_control().expect("encode valid control");
        hard.send_auth_control(&control, true)
            .expect("queue valid auth control");
        hard.client_to_server().expect("authenticate generation");
        let capability = hard
            .server
            .auth
            .capability
            .as_mut()
            .expect("capability exists");
        capability.hard_deadline = Instant::now();
        assert!(Instant::now() >= capability.hard_deadline);
        assert!(matches!(
            hard.server.next_packet(&mut packet),
            Err(RuntimeError::AuthenticationExpired)
        ));
        assert!(!hard.server.is_authenticated());
        hard.deliver_close_to_client();
    }

    #[test]
    fn t027b2b2_2_revocation_wins_before_any_future_admission() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.drive_until_h3().expect("reach auth gate");
        let control = pair.live_client_control().expect("encode valid control");
        pair.send_auth_control(&control, true)
            .expect("queue valid auth control");
        pair.client_to_server().expect("authenticate generation");
        let capability = pair
            .server
            .auth
            .capability
            .as_mut()
            .expect("capability exists");
        capability.revoke();
        assert!(!capability.is_active_at(Instant::now()));
        assert!(!pair.server.is_authenticated());
        let mut packet = [0_u8; MAX_PACKET_BYTES];
        assert!(matches!(
            pair.server.next_packet(&mut packet),
            Err(RuntimeError::AuthenticationExpired)
        ));
        pair.deliver_close_to_client();
    }

    #[test]
    fn t027b2b3_authenticated_generation_admits_one_strict_classic_connect() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate and finish confirmation");
        assert!(pair.server.is_authenticated());

        let headers = test_classic_connect_headers(b"example.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue one strict Classic CONNECT");
        pair.client_to_server()
            .expect("authenticated strict Classic CONNECT must be admitted");
        assert_eq!(pair.server.lifecycle(), ConnectionLifecycle::Active);
        assert_eq!(pair.server.pending_connects.len(), 1);
        let pending = pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .next()
            .expect("one pending metadata slot exists");
        assert_eq!(
            pending.generation.as_bytes(),
            pair.server.generation.as_bytes()
        );
        assert_eq!(pending.stream_id, stream_id);
        assert_eq!(
            pending.target,
            Some(TargetAddr::Domain("example.invalid".to_owned()))
        );
        assert_eq!(pending.port, 443);
        assert!(!pending.peer_write_half_closed);
        assert_eq!(pending.max_frame_size, AUTH_MAX_FRAME_SIZE);

        pair.server_to_client()
            .expect("only transport bookkeeping may be emitted");
        assert!(matches!(
            pair.client_h3
                .as_mut()
                .expect("client H3 exists")
                .poll(&mut pair.client),
            Err(quiche::h3::Error::Done)
        ));
    }

    #[test]
    fn t027b2b3_confirmation_fin_precedes_every_flow_admission() {
        let mut pair = TestPair::with_response_window(0).expect("construct blocked pair");
        pair.drive_until_h3().expect("reach auth gate");
        let control = pair.live_client_control().expect("encode valid control");
        pair.send_auth_control(&control, true)
            .expect("queue valid auth control");
        pair.client_to_server()
            .expect("leave confirmation headers flow-control blocked");
        assert_eq!(pair.server.auth.state, ServerAuthState::SendingConfirmation);
        assert!(!pair.server.is_authenticated());

        let headers = test_classic_connect_headers(b"example.invalid:443", false);
        pair.send_classic_connect(&headers, false)
            .expect("queue a premature CONNECT");
        assert!(pair.client_to_server().is_err());
        assert_eq!(pair.server.pending_connects.len(), 0);
        assert!(pair.server.auth.capability.is_none());
    }

    #[test]
    fn t027b2b3_real_h3_headers_admit_domain_ipv4_ipv6_in_both_orders() {
        for (authority, expected, authority_first) in [
            (
                b"example.invalid:443".as_slice(),
                TargetAddr::Domain("example.invalid".to_owned()),
                false,
            ),
            (
                b"example.invalid:443".as_slice(),
                TargetAddr::Domain("example.invalid".to_owned()),
                true,
            ),
            (
                b"192.0.2.1:8443".as_slice(),
                TargetAddr::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                false,
            ),
            (
                b"192.0.2.1:8443".as_slice(),
                TargetAddr::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                true,
            ),
            (
                b"[2001:db8::1]:65535".as_slice(),
                TargetAddr::Ipv6("2001:db8::1".parse().expect("RFC IPv6 literal")),
                false,
            ),
            (
                b"[2001:db8::1]:65535".as_slice(),
                TargetAddr::Ipv6("2001:db8::1".parse().expect("RFC IPv6 literal")),
                true,
            ),
        ] {
            let mut pair = TestPair::new().expect("construct bounded pair");
            pair.authenticate_generation()
                .expect("authenticate generation");
            let headers = test_classic_connect_headers(authority, authority_first);
            pair.send_classic_connect(&headers, false)
                .expect("queue strict Classic CONNECT");
            pair.client_to_server().expect("admit strict metadata");
            let pending = pair
                .server
                .pending_connects
                .slots
                .iter()
                .flatten()
                .next()
                .expect("one pending slot");
            assert_eq!(pending.target, Some(expected));
            assert_eq!(pair.server.pending_connects.len(), 1);
        }
    }

    #[test]
    fn t027b2b3_capability_predicate_is_generation_bound_and_deadline_strict() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let capability = pair
            .server
            .auth
            .capability
            .as_ref()
            .expect("active capability");
        let other_generation = ServerSourceConnectionId::new([0x5c; quiche::MAX_CONN_ID_LEN]);
        assert!(capability.permits_admission_at(
            &pair.server.generation,
            capability.admission_deadline - Duration::from_nanos(1)
        ));
        assert!(!capability
            .permits_admission_at(&pair.server.generation, capability.admission_deadline));
        assert!(!capability.permits_admission_at(
            &pair.server.generation,
            capability.admission_deadline + Duration::from_nanos(1)
        ));
        assert!(!capability.permits_admission_at(&pair.server.generation, capability.hard_deadline));
        assert!(!capability.permits_admission_at(&other_generation, Instant::now()));
    }

    #[test]
    fn t027b2b3_prepare_and_commit_repeat_the_same_capability_predicate() {
        for revoke_between_checks in [false, true] {
            let mut pair = TestPair::new().expect("construct bounded pair");
            pair.authenticate_generation()
                .expect("authenticate generation");
            let headers = test_classic_connect_headers(b"example.invalid:443", false);
            let pending = pair
                .server
                .prepare_classic_connect(4, &headers, true)
                .expect("first predicate and strict parser pass");
            assert_eq!(
                pending.target,
                Some(TargetAddr::Domain("example.invalid".to_owned()))
            );
            let capability = pair
                .server
                .auth
                .capability
                .as_mut()
                .expect("active capability");
            if revoke_between_checks {
                capability.revoke();
            } else {
                capability.admission_deadline = Instant::now();
            }
            assert_eq!(
                pair.server.commit_classic_connect(pending),
                Err(RuntimeError::ClassicConnectAdmissionRejected)
            );
            assert_eq!(pair.server.pending_connects.len(), 0);
        }
    }

    #[test]
    fn t027b2b3_pre_auth_and_invalid_headers_never_create_a_slot() {
        let mut pre_auth = TestPair::new().expect("construct pre-auth pair");
        pre_auth.drive_until_h3().expect("reach auth gate");
        let exact = test_classic_connect_headers(b"example.invalid:443", false);
        pre_auth
            .send_classic_connect(&exact, false)
            .expect("queue pre-auth CONNECT");
        assert!(pre_auth.client_to_server().is_err());
        assert_eq!(pre_auth.server.pending_connects.len(), 0);

        let mut reused_auth = TestPair::new().expect("construct auth-stream reuse pair");
        let auth_stream = reused_auth
            .authenticate_generation()
            .expect("authenticate generation");
        assert!(matches!(
            reused_auth
                .server
                .prepare_classic_connect(auth_stream, &exact, true),
            Err(RuntimeError::ClassicConnectAdmissionRejected)
        ));
        assert_eq!(reused_auth.server.pending_connects.len(), 0);

        let cases = vec![
            vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":authority", b"example.invalid:443"),
            ],
            vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":method", b"CONNECT"),
            ],
            vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":unknown", b"x"),
            ],
            vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", b"example.invalid:443"),
                quiche::h3::Header::new(b"x-extra", b"1"),
            ],
        ];
        for headers in cases {
            let mut pair = TestPair::new().expect("construct invalid-header pair");
            pair.authenticate_generation()
                .expect("authenticate generation");
            pair.send_classic_connect(&headers, false)
                .expect("queue invalid request metadata");
            assert!(pair.client_to_server().is_err());
            assert_eq!(pair.server.pending_connects.len(), 0);
        }

        let mut no_more_frames = TestPair::new().expect("construct FIN pair");
        no_more_frames
            .authenticate_generation()
            .expect("authenticate generation");
        no_more_frames
            .send_classic_connect(&exact, true)
            .expect("queue initial Headers with immediate FIN");
        assert!(no_more_frames.client_to_server().is_err());
        assert_eq!(no_more_frames.server.pending_connects.len(), 0);
    }

    #[test]
    fn t027b2b3_fixed_quota_is_transport_eight_not_advertised_128() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"quota.invalid:443", false);
        for expected in 1..=MAX_PENDING_CLASSIC_CONNECTS {
            pair.send_classic_connect(&headers, false)
                .unwrap_or_else(|_| panic!("transport permits bounded request stream {expected}"));
            pair.client_to_server().expect("admit bounded metadata");
            pair.server_to_client()
                .expect("deliver bounded transport credit");
            assert_eq!(pair.server.pending_connects.len(), expected);
        }
        let capability = pair
            .server
            .auth
            .capability
            .as_ref()
            .expect("active capability");
        assert_eq!(capability.max_concurrent_flows, 128);
        assert_eq!(MAX_BIDI_STREAMS, 8);
        assert_eq!(PendingClassicConnectSlots::quota_for(capability), 8);
        assert!(pair.send_classic_connect(&headers, false).is_err());
        assert!(matches!(
            pair.server.prepare_classic_connect(10_000, &headers, true),
            Err(RuntimeError::ClassicConnectAdmissionRejected)
        ));
        assert_eq!(pair.server.pending_connects.len(), 8);
    }

    #[test]
    fn t027b2b3_admission_expiry_keeps_existing_metadata_but_rejects_new_flow() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"existing.invalid:443", false);
        pair.send_classic_connect(&headers, false)
            .expect("queue first CONNECT");
        pair.client_to_server().expect("admit first metadata");
        pair.server
            .auth
            .capability
            .as_mut()
            .expect("active capability")
            .admission_deadline = Instant::now();

        let mut packet = [0_u8; MAX_PACKET_BYTES];
        pair.server
            .next_packet(&mut packet)
            .expect("admission expiry alone does not close the generation");
        assert!(pair.server.is_authenticated());
        assert_eq!(pair.server.pending_connects.len(), 1);

        let second = test_classic_connect_headers(b"new.invalid:8443", false);
        pair.send_classic_connect(&second, false)
            .expect("transport can carry the rejected new flow");
        assert_eq!(
            pair.client_to_server()
                .expect_err("expired admission must reject the new flow"),
            RuntimeError::ClassicConnectAdmissionRejected
        );
        assert_eq!(pair.server.pending_connects.len(), 0);
        assert!(!pair.server.is_authenticated());
    }

    #[test]
    fn t027b2b3_pre_200_data_is_rejected_without_recv_body_or_payload_retention() {
        let marker = b"test-private-payload-marker";
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"data.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        pair.client_to_server().expect("admit CONNECT metadata");
        let reads_before = pair.server.auth_body_read_calls;
        let upload_reads_before = pair.server.upload_recv_body_calls;
        let written = pair
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_body(&mut pair.client, stream_id, marker, false)
            .expect("queue forbidden DATA");
        assert_eq!(written, marker.len());
        let error = pair
            .client_to_server()
            .expect_err("first DATA event closes the generation");
        assert_eq!(error, RuntimeError::ClassicConnectDataRejected);
        assert_eq!(pair.server.auth_body_read_calls, reads_before);
        assert_eq!(pair.server.upload_recv_body_calls, upload_reads_before);
        assert_eq!(pair.server.pending_connects.len(), 0);
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains("payload-marker"));
            assert!(rendered.len() <= 64);
        }
    }

    #[test]
    fn t027b2b3_finished_only_marks_half_close_and_duplicate_closes() {
        let mut pair = TestPair::new().expect("construct bounded pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"finished.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        pair.client_to_server().expect("admit CONNECT metadata");
        assert_eq!(
            pair.client.stream_send(stream_id, b"", true),
            Ok(0),
            "raw QUIC FIN produces Finished without a DATA frame"
        );
        pair.client_to_server()
            .expect("first Finished only marks peer write half-close");
        let pending = pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .next()
            .expect("slot remains occupied");
        assert!(pending.peer_write_half_closed);
        assert_eq!(pair.server.pending_connects.len(), 1);
        assert_eq!(pair.server.lifecycle(), ConnectionLifecycle::Active);
        pair.server_to_client()
            .expect("only transport bookkeeping may be emitted");
        assert!(matches!(
            pair.client_h3
                .as_mut()
                .expect("client H3 exists")
                .poll(&mut pair.client),
            Err(quiche::h3::Error::Done)
        ));

        let mut h3 = pair.server.h3.take().expect("server H3 exists");
        let error = pair
            .server
            .handle_h3_event(&mut h3, stream_id, quiche::h3::Event::Finished)
            .expect_err("duplicate Finished closes the generation");
        pair.server.h3 = Some(h3);
        assert_eq!(error, RuntimeError::ClassicConnectAdmissionRejected);
        assert_eq!(pair.server.pending_connects.len(), 0);
        assert_eq!(
            pair.server
                .transport
                .local_error()
                .expect("fixed application close")
                .error_code,
            PRE_AUTH_CLOSE_CODE
        );
    }

    #[test]
    fn t027b2b3_trailers_and_unknown_stream_events_close_generation() {
        let mut trailers = TestPair::new().expect("construct trailers pair");
        trailers
            .authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"trailers.invalid:443", false);
        let stream_id = trailers
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        trailers.client_to_server().expect("admit CONNECT metadata");
        trailers
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_additional_headers(
                &mut trailers.client,
                stream_id,
                &[quiche::h3::Header::new(b"x-trailer", b"1")],
                true,
                false,
            )
            .expect("queue forbidden trailer section");
        assert_eq!(
            trailers
                .client_to_server()
                .expect_err("trailers close generation"),
            RuntimeError::ClassicConnectAdmissionRejected
        );
        assert_eq!(trailers.server.pending_connects.len(), 0);

        let mut unknown = TestPair::new().expect("construct unknown-event pair");
        unknown
            .authenticate_generation()
            .expect("authenticate generation");
        let mut h3 = unknown.server.h3.take().expect("server H3 exists");
        let error = unknown
            .server
            .handle_h3_event(&mut h3, 40, quiche::h3::Event::Finished)
            .expect_err("unknown stream Finished closes generation");
        unknown.server.h3 = Some(h3);
        assert_eq!(error, RuntimeError::ClassicConnectAdmissionRejected);
        assert_eq!(unknown.server.pending_connects.len(), 0);
    }

    #[test]
    fn t027b2b3_reset_and_stop_sending_each_close_the_generation() {
        let mut reset = TestPair::new().expect("construct reset pair");
        reset
            .authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"reset.invalid:443", false);
        let stream_id = reset
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        reset.client_to_server().expect("admit CONNECT metadata");
        reset
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x44)
            .expect("queue request reset");
        assert!(reset.client_to_server().is_err());
        assert_eq!(reset.server.pending_connects.len(), 0);
        assert!(!reset.server.is_authenticated());

        let mut stopped = TestPair::new().expect("construct STOP_SENDING pair");
        stopped
            .authenticate_generation()
            .expect("authenticate generation");
        let stream_id = stopped
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        stopped.client_to_server().expect("admit CONNECT metadata");
        stopped
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x45)
            .expect("queue STOP_SENDING");
        assert_eq!(
            stopped
                .client_to_server()
                .expect_err("STOP_SENDING closes generation"),
            RuntimeError::ClassicConnectAdmissionRejected
        );
        assert_eq!(stopped.server.pending_connects.len(), 0);
        assert!(!stopped.server.is_authenticated());
    }

    #[test]
    fn t027b2b3_datagram_goaway_and_priority_update_close_after_authentication() {
        let mut datagram = TestPair::new().expect("construct Datagram pair");
        datagram
            .authenticate_generation()
            .expect("authenticate generation");
        datagram
            .client
            .dgram_send(b"test-private-datagram-marker")
            .expect("queue bounded Datagram");
        assert_eq!(
            datagram
                .client_to_server()
                .expect_err("Datagram closes generation"),
            RuntimeError::PreAuthApplicationActivity
        );
        assert!(!datagram.server.is_authenticated());

        let mut goaway = TestPair::new().expect("construct GOAWAY pair");
        goaway
            .authenticate_generation()
            .expect("authenticate generation");
        goaway
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_goaway(&mut goaway.client, 0)
            .expect("queue GOAWAY");
        assert_eq!(
            goaway
                .client_to_server()
                .expect_err("GOAWAY closes generation"),
            RuntimeError::PreAuthApplicationActivity
        );
        assert!(!goaway.server.is_authenticated());

        let mut priority = TestPair::new().expect("construct priority pair");
        priority
            .authenticate_generation()
            .expect("authenticate generation");
        let headers = test_classic_connect_headers(b"priority.invalid:443", false);
        let stream_id = priority
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        priority.client_to_server().expect("admit CONNECT metadata");
        priority
            .client_h3
            .as_mut()
            .expect("client H3 exists")
            .send_priority_update_for_request(
                &mut priority.client,
                stream_id,
                &quiche::h3::Priority::default(),
            )
            .expect("queue priority update");
        assert_eq!(
            priority
                .client_to_server()
                .expect_err("priority update closes generation"),
            RuntimeError::PreAuthApplicationActivity
        );
        assert_eq!(priority.server.pending_connects.len(), 0);
    }

    #[test]
    fn t027b2b3_hard_expiry_revocation_and_transport_close_clear_all_targets() {
        let headers = test_classic_connect_headers(b"cleanup.invalid:443", false);

        let mut hard = TestPair::new().expect("construct hard-expiry pair");
        hard.authenticate_generation()
            .expect("authenticate generation");
        hard.send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        hard.client_to_server().expect("admit CONNECT metadata");
        hard.server
            .auth
            .capability
            .as_mut()
            .expect("active capability")
            .hard_deadline = Instant::now();
        let mut packet = [0_u8; MAX_PACKET_BYTES];
        let error = match hard.server.next_packet(&mut packet) {
            Err(error) => error,
            Ok(_) => panic!("hard expiry must close generation"),
        };
        assert_eq!(error, RuntimeError::AuthenticationExpired);
        assert_eq!(hard.server.pending_connects.len(), 0);
        let local_error = hard
            .server
            .transport
            .local_error()
            .expect("hard expiry installs fixed close");
        assert!(local_error.is_app);
        assert_eq!(local_error.error_code, PRE_AUTH_CLOSE_CODE);
        assert!(local_error.reason.is_empty());
        hard.deliver_close_to_client();
        assert_eq!(hard.server.lifecycle(), ConnectionLifecycle::Draining);

        let mut revoked = TestPair::new().expect("construct revocation pair");
        revoked
            .authenticate_generation()
            .expect("authenticate generation");
        revoked
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        revoked.client_to_server().expect("admit CONNECT metadata");
        revoked
            .server
            .revoke_authenticated_generation()
            .expect("revocation closes generation");
        assert_eq!(revoked.server.pending_connects.len(), 0);
        let local_error = revoked
            .server
            .transport
            .local_error()
            .expect("revocation installs fixed close");
        assert!(local_error.is_app);
        assert_eq!(local_error.error_code, PRE_AUTH_CLOSE_CODE);
        assert!(local_error.reason.is_empty());
        revoked.deliver_close_to_client();
        assert_eq!(revoked.server.lifecycle(), ConnectionLifecycle::Draining);

        let mut closed = TestPair::new().expect("construct peer-close pair");
        closed
            .authenticate_generation()
            .expect("authenticate generation");
        closed
            .send_classic_connect(&headers, false)
            .expect("queue CONNECT metadata");
        closed.client_to_server().expect("admit CONNECT metadata");
        closed
            .client
            .close(true, 0x44, b"")
            .expect("peer closes transport");
        closed
            .client_to_server()
            .expect("process peer transport close");
        assert_eq!(closed.server.pending_connects.len(), 0);
        assert!(!closed.server.is_authenticated());
        assert_ne!(closed.server.lifecycle(), ConnectionLifecycle::Active);
    }

    #[test]
    fn t027b2b3_replacement_generation_is_empty_and_must_reauthenticate() {
        let headers = test_classic_connect_headers(b"replacement.invalid:443", false);
        let mut original = TestPair::new().expect("construct original generation");
        original
            .authenticate_generation()
            .expect("authenticate original generation");
        original
            .send_classic_connect(&headers, false)
            .expect("queue original CONNECT metadata");
        original
            .client_to_server()
            .expect("admit original metadata");
        assert_eq!(original.server.pending_connects.len(), 1);
        original
            .server
            .revoke_authenticated_generation()
            .expect("close original generation");
        assert_eq!(original.server.pending_connects.len(), 0);
        drop(original);

        let mut unauthenticated = TestPair::new().expect("construct replacement generation");
        assert_eq!(unauthenticated.server.pending_connects.len(), 0);
        assert!(!unauthenticated.server.is_authenticated());
        unauthenticated
            .drive_until_h3()
            .expect("replacement reaches only foundation readiness");
        unauthenticated
            .send_classic_connect(&headers, false)
            .expect("queue forbidden pre-auth CONNECT");
        assert!(unauthenticated.client_to_server().is_err());
        assert_eq!(unauthenticated.server.pending_connects.len(), 0);

        let mut reauthenticated = TestPair::new().expect("construct fresh replacement");
        reauthenticated
            .authenticate_generation()
            .expect("replacement authenticates from the beginning");
        assert_eq!(reauthenticated.server.pending_connects.len(), 0);
        reauthenticated
            .send_classic_connect(&headers, false)
            .expect("queue replacement CONNECT metadata");
        reauthenticated
            .client_to_server()
            .expect("admit only after replacement authentication");
        assert_eq!(reauthenticated.server.pending_connects.len(), 1);
    }

    #[test]
    fn t027b2b3_slot_capability_and_error_formatting_are_value_free() {
        let marker = "format-marker.invalid";
        let mut pair = TestPair::new().expect("construct formatting pair");
        pair.authenticate_generation()
            .expect("authenticate generation");
        let authority = format!("{marker}:65432");
        let headers = test_classic_connect_headers(authority.as_bytes(), false);
        let pending = pair
            .server
            .prepare_classic_connect(4, &headers, true)
            .expect("prepare structured metadata");
        assert_eq!(format!("{pending:?}"), "pending Classic CONNECT metadata");
        pair.server
            .commit_classic_connect(pending)
            .expect("commit structured metadata");

        let capability = pair
            .server
            .auth
            .capability
            .as_ref()
            .expect("active capability");
        let rendered = [
            format!("{capability:?}"),
            format!("{:?}", pair.server.pending_connects),
            RuntimeError::ClassicConnectAdmissionRejected.to_string(),
            format!("{:?}", RuntimeError::ClassicConnectAdmissionRejected),
        ];
        assert_eq!(rendered[0], "authenticated server generation capability");
        assert_eq!(rendered[1], "bounded pending Classic CONNECT slots");
        for value in rendered {
            assert!(value.len() <= 64);
            for forbidden in [marker, "65432", "replacement.invalid", "2001:db8"] {
                assert!(!value.contains(forbidden));
            }
        }

        let production = include_str!("quiche_runtime.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production source prefix exists");
        for forbidden in [
            "tokio::spawn",
            "HashMap<",
            "Vec<PendingClassicConnect",
            "connect_target",
            "resolve_dns",
            "open_relay",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("target_payload: Box<[u8; TARGET_TO_CLIENT_BUFFER_BYTES]>"));
        assert_eq!(
            production
                .matches("target_payload: Box<[u8; TARGET_TO_CLIENT_BUFFER_BYTES]>")
                .count(),
            1
        );
        assert!(production.contains("upload_payload: Box<[u8; CLIENT_TO_TARGET_BUFFER_BYTES]>"));
        assert_eq!(
            production
                .matches("upload_payload: Box<[u8; CLIENT_TO_TARGET_BUFFER_BYTES]>")
                .count(),
            1
        );
        assert!(production.contains("const MAX_TARGET_IO_OPERATIONS_PER_ROUND: usize = 4;"));
        let target_data_path = production
            .split("    pub(super) fn has_target_io_waiter")
            .nth(1)
            .expect("bounded target-data path exists")
            .split("    #[cfg(test)]\n    pub(super) fn waiting_target_dispatch_count_for_test")
            .next()
            .expect("bounded target-data path ends before test helpers");
        assert!(target_data_path.contains("poll_read_ready"));
        assert!(target_data_path.contains("poll_write_ready"));
        assert!(target_data_path.contains("target.try_read"));
        assert!(target_data_path.contains("target.try_write"));
        assert!(target_data_path.contains("h3.send_body"));
        assert!(target_data_path.contains("h3.recv_body"));
        assert!(target_data_path.contains("Pin::new(target).poll_shutdown"));
        assert_eq!(target_data_path.matches("target.try_write").count(), 1);
        assert_eq!(target_data_path.matches("poll_shutdown").count(), 1);
        for forbidden in [
            "into_split",
            "try_shutdown",
            "as_raw_fd",
            "from_raw_fd",
            "unsafe {",
            "transport.stream_recv",
            "tokio::spawn",
            "JoinSet",
            "FuturesUnordered",
            "mpsc::channel",
            "watch::channel",
            "Vec<",
        ] {
            assert!(!target_data_path.contains(forbidden));
        }
    }

    #[test]
    fn t027b2c1_admitted_slot_has_one_shot_dispatch_and_keeps_its_quota() {
        let mut pair = TestPair::new().expect("construct dispatch pair");
        pair.authenticate_generation()
            .expect("authenticate dispatch generation");
        let headers = test_classic_connect_headers(b"dispatch-marker.invalid:443", false);
        pair.send_classic_connect(&headers, false)
            .expect("queue admitted CONNECT");
        pair.client_to_server().expect("admit CONNECT metadata");

        let now = Instant::now();
        let token = pair
            .server
            .take_target_open_dispatch(now)
            .expect("create dispatch token")
            .expect("one admitted slot is dispatchable");
        assert_eq!(pair.server.pending_connects.len(), 1);
        assert!(pair
            .server
            .take_target_open_dispatch(now)
            .expect("duplicate take is a fixed no-op")
            .is_none());
        assert_eq!(format!("{token:?}"), "private target-open dispatch token");
    }

    #[test]
    fn t027b2c1_eight_in_flight_tokens_are_the_original_eight_slots() {
        let mut pair = TestPair::new().expect("construct eight-slot pair");
        pair.authenticate_generation()
            .expect("authenticate eight-slot generation");
        let headers = test_classic_connect_headers(b"bounded.invalid:443", false);
        for _ in 0..MAX_TARGET_DISPATCH_FUTURES {
            pair.send_classic_connect(&headers, false)
                .expect("queue bounded CONNECT");
            pair.client_to_server().expect("admit bounded CONNECT");
            pair.server_to_client()
                .expect("return bounded request-stream credit");
        }
        for expected_futures in 1..=MAX_TARGET_DISPATCH_FUTURES {
            let token = pair
                .server
                .take_target_open_dispatch(Instant::now())
                .expect("take admitted token")
                .expect("one original slot remains admitted");
            assert_eq!(token.port(), 443);
            assert_eq!(
                pair.server.pending_connects.len(),
                MAX_TARGET_DISPATCH_FUTURES
            );
            assert_eq!(
                pair.server
                    .pending_connects
                    .slots
                    .iter()
                    .flatten()
                    .filter(|pending| pending.dispatch_state == TargetDispatchState::InFlight)
                    .count(),
                expected_futures
            );
        }
        assert!(pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("all original slots are already in flight")
            .is_none());
        assert!(pair.send_classic_connect(&headers, false).is_err());
        assert_eq!(pair.server.pending_connects.len(), 8);
    }

    #[tokio::test]
    async fn t027b2c1_attempt_deadline_is_one_strict_minimum() {
        let headers = test_classic_connect_headers(b"deadline.invalid:8443", false);

        let mut timeout_first = TestPair::new().expect("construct timeout-first pair");
        timeout_first
            .authenticate_generation()
            .expect("authenticate timeout-first generation");
        timeout_first
            .send_classic_connect(&headers, false)
            .expect("queue timeout-first CONNECT");
        timeout_first
            .client_to_server()
            .expect("admit timeout-first CONNECT");
        let now = Instant::now();
        timeout_first
            .server
            .auth
            .capability
            .as_mut()
            .expect("active timeout-first capability")
            .hard_deadline = now + Duration::from_secs(30);
        let timeout_token = timeout_first
            .server
            .take_target_open_dispatch(now)
            .expect("compute timeout-first deadline")
            .expect("take timeout-first token");
        assert_eq!(
            timeout_token.attempt_deadline(),
            now + Duration::from_secs(10)
        );

        let mut hard_first = TestPair::new().expect("construct hard-first pair");
        hard_first
            .authenticate_generation()
            .expect("authenticate hard-first generation");
        hard_first
            .send_classic_connect(&headers, false)
            .expect("queue hard-first CONNECT");
        hard_first
            .client_to_server()
            .expect("admit hard-first CONNECT");
        let now = Instant::now();
        let hard_deadline = now + Duration::from_secs(3);
        hard_first
            .server
            .auth
            .capability
            .as_mut()
            .expect("active hard-first capability")
            .hard_deadline = hard_deadline;
        let hard_token = hard_first
            .server
            .take_target_open_dispatch(now)
            .expect("compute hard-first deadline")
            .expect("take hard-first token");
        assert_eq!(hard_token.attempt_deadline(), hard_deadline);
        assert_eq!(hard_token.port(), 8443);
        assert_eq!(
            hard_token.target(),
            &TargetAddr::Domain("deadline.invalid".to_owned())
        );
        assert_eq!(
            hard_token.egress_policy(),
            ServerEgressPolicyConfig::default()
        );
        let (opened, peer) = connected_target_pair().await;
        assert_eq!(
            hard_first
                .server
                .complete_target_open_dispatch(hard_token, opened, hard_deadline),
            Err(RuntimeError::TargetOpenDispatchRejected),
            "the absolute deadline boundary is strict"
        );
        assert_target_peer_eof(peer).await;
    }

    #[tokio::test]
    async fn t027b2c1_completion_rechecks_generation_revocation_and_hard_expiry() {
        let headers = test_classic_connect_headers(b"stale.invalid:443", false);

        let mut mismatch = TestPair::new().expect("construct generation-mismatch pair");
        mismatch
            .authenticate_generation()
            .expect("authenticate generation-mismatch pair");
        mismatch
            .send_classic_connect(&headers, false)
            .expect("queue generation-mismatch CONNECT");
        mismatch
            .client_to_server()
            .expect("admit generation-mismatch CONNECT");
        let mut token = mismatch
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take generation-mismatch token")
            .expect("generation-mismatch token exists");
        token.generation = ServerSourceConnectionId::new([0x77; quiche::MAX_CONN_ID_LEN]);
        let (opened, peer) = connected_target_pair().await;
        assert_eq!(
            mismatch
                .server
                .complete_target_open_dispatch(token, opened, Instant::now()),
            Err(RuntimeError::TargetOpenDispatchRejected)
        );
        assert_target_peer_eof(peer).await;

        let mut revoked = TestPair::new().expect("construct revoke-race pair");
        revoked
            .authenticate_generation()
            .expect("authenticate revoke-race generation");
        revoked
            .send_classic_connect(&headers, false)
            .expect("queue revoke-race CONNECT");
        revoked
            .client_to_server()
            .expect("admit revoke-race CONNECT");
        let token = revoked
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take revoke-race token")
            .expect("revoke-race token exists");
        revoked
            .server
            .revoke_authenticated_generation()
            .expect("revoke generation before completion");
        let (opened, peer) = connected_target_pair().await;
        assert_eq!(
            revoked
                .server
                .complete_target_open_dispatch(token, opened, Instant::now()),
            Err(RuntimeError::TargetOpenDispatchRejected)
        );
        assert_target_peer_eof(peer).await;

        let mut hard = TestPair::new().expect("construct hard-race pair");
        hard.authenticate_generation()
            .expect("authenticate hard-race generation");
        hard.send_classic_connect(&headers, false)
            .expect("queue hard-race CONNECT");
        hard.client_to_server().expect("admit hard-race CONNECT");
        let token = hard
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take hard-race token")
            .expect("hard-race token exists");
        hard.server
            .auth
            .capability
            .as_mut()
            .expect("active hard-race capability")
            .hard_deadline = Instant::now();
        let (opened, peer) = connected_target_pair().await;
        assert_eq!(
            hard.server
                .complete_target_open_dispatch(token, opened, Instant::now()),
            Err(RuntimeError::TargetOpenDispatchRejected)
        );
        assert_target_peer_eof(peer).await;
    }

    #[tokio::test]
    async fn t027b2c1_admission_expiry_blocks_untaken_work_but_not_in_flight_completion() {
        let headers = test_classic_connect_headers(b"admission-boundary.invalid:443", false);

        let mut untaken = TestPair::new().expect("construct untaken-expiry pair");
        untaken
            .authenticate_generation()
            .expect("authenticate untaken-expiry generation");
        untaken
            .send_classic_connect(&headers, false)
            .expect("queue untaken-expiry CONNECT");
        untaken
            .client_to_server()
            .expect("admit untaken-expiry CONNECT");
        untaken
            .server
            .auth
            .capability
            .as_mut()
            .expect("active untaken-expiry capability")
            .admission_deadline = Instant::now();
        assert!(matches!(
            untaken.server.take_target_open_dispatch(Instant::now()),
            Err(RuntimeError::TargetOpenDispatchRejected)
        ));

        let mut in_flight = TestPair::new().expect("construct in-flight-expiry pair");
        in_flight
            .authenticate_generation()
            .expect("authenticate in-flight-expiry generation");
        in_flight
            .send_classic_connect(&headers, false)
            .expect("queue in-flight-expiry CONNECT");
        in_flight
            .client_to_server()
            .expect("admit in-flight-expiry CONNECT");
        let token = in_flight
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take before admission expiry")
            .expect("in-flight-expiry token exists");
        in_flight
            .server
            .auth
            .capability
            .as_mut()
            .expect("active in-flight-expiry capability")
            .admission_deadline = Instant::now();
        in_flight
            .server
            .complete_target_open_dispatch(token, connected_target_pair().await.0, Instant::now())
            .expect("admission expiry does not invalidate in-flight work");
        assert_eq!(in_flight.server.pending_connects.len(), 1);
        assert!(matches!(
            in_flight.server.pending_connects.slots[0]
                .as_ref()
                .expect("waiting slot remains occupied")
                .dispatch_state,
            TargetDispatchState::ResponsePending
        ));
    }

    #[tokio::test]
    async fn t027b2c1_peer_fin_during_dispatch_updates_slot_without_staling_token() {
        let mut pair = TestPair::new().expect("construct in-flight FIN pair");
        pair.authenticate_generation()
            .expect("authenticate in-flight FIN generation");
        let headers = test_classic_connect_headers(b"fin-race.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue in-flight FIN CONNECT");
        pair.client_to_server()
            .expect("admit in-flight FIN CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take in-flight FIN token")
            .expect("in-flight FIN token exists");
        assert_eq!(pair.client.stream_send(stream_id, b"", true), Ok(0));
        pair.client_to_server()
            .expect("peer FIN updates the occupied in-flight slot");
        pair.server
            .complete_target_open_dispatch(token, connected_target_pair().await.0, Instant::now())
            .expect("legal peer FIN does not stale the dispatch token");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("waiting slot remains occupied after peer FIN");
        assert!(pending.peer_write_half_closed);
        assert!(matches!(
            pending.dispatch_state,
            TargetDispatchState::ResponsePending
        ));
    }

    #[test]
    fn t027b2c1_dispatch_token_and_errors_are_value_free() {
        let marker = "dispatch-secret-marker.invalid";
        let mut pair = TestPair::new().expect("construct private-format pair");
        pair.authenticate_generation()
            .expect("authenticate private-format generation");
        let headers = test_classic_connect_headers(format!("{marker}:54321").as_bytes(), false);
        pair.send_classic_connect(&headers, false)
            .expect("queue private-format CONNECT");
        pair.client_to_server()
            .expect("admit private-format CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take private-format token")
            .expect("private-format token exists");
        for rendered in [
            format!("{token:?}"),
            RuntimeError::TargetOpenDispatchRejected.to_string(),
            format!("{:?}", RuntimeError::TargetOpenDispatchRejected),
        ] {
            assert!(rendered.len() <= 64);
            assert!(!rendered.contains(marker));
            assert!(!rendered.contains("54321"));
        }
    }

    #[tokio::test]
    async fn t027b2c4_completion_places_connected_target_in_original_slot_until_connection_drop() {
        use tokio::io::AsyncReadExt;
        use tokio::time::timeout;

        let mut pair = TestPair::new().expect("construct socket-owner pair");
        pair.authenticate_generation()
            .expect("authenticate socket-owner generation");
        let headers = test_classic_connect_headers(b"socket-owner.invalid:443", false);
        pair.send_classic_connect(&headers, false)
            .expect("queue socket-owner CONNECT");
        pair.client_to_server().expect("admit socket-owner CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take socket-owner token")
            .expect("socket-owner token exists");

        let (opened_target, mut peer) = connected_target_pair().await;

        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff connected target into original slot");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("original slot remains occupied");
        assert!(pending.opened_target.is_some());
        assert!(matches!(
            pending.dispatch_state,
            TargetDispatchState::ResponsePending
        ));
        assert!(timeout(Duration::from_millis(25), peer.read_u8())
            .await
            .is_err());

        drop(pair.server);
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read_u8())
                .await
                .expect("slot-owned target closes within bound")
                .expect_err("closed target peer reports EOF")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn t027b2d0_handoff_is_the_only_transition_to_pending_and_local_queue_acceptance() {
        let mut pair = TestPair::new().expect("construct response-state pair");
        pair.authenticate_generation()
            .expect("authenticate response-state pair");
        let headers = test_classic_connect_headers(b"response-state.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue response-state CONNECT");
        pair.client_to_server()
            .expect("admit response-state CONNECT");
        assert_eq!(pair.server.response_pending_count_for_test(), 0);
        assert_eq!(pair.server.response_accepted_count_for_test(), 0);
        pair.server
            .drive_h3()
            .expect("drive before target dispatch");
        assert!(!pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll before target dispatch"));

        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take response-state dispatch")
            .expect("response-state dispatch exists");
        pair.server.drive_h3().expect("drive before target handoff");
        assert_eq!(pair.server.response_pending_count_for_test(), 0);
        assert_eq!(pair.server.response_accepted_count_for_test(), 0);
        assert!(!pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll before target handoff"));

        let (opened_target, peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff target to original response slot");
        assert_eq!(pair.server.response_pending_count_for_test(), 1);
        assert_eq!(pair.server.response_accepted_count_for_test(), 0);
        pair.server
            .auth
            .capability
            .as_mut()
            .expect("active response capability")
            .admission_deadline = Instant::now();
        pair.server
            .drive_h3()
            .expect("queue response after handoff and admission expiry");
        assert_eq!(pair.server.response_pending_count_for_test(), 0);
        assert_eq!(pair.server.response_accepted_count_for_test(), 1);
        assert!(!pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("local queue acceptance is not client receipt"));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.readable())
                .await
                .is_err()
        );

        pair.server_to_client()
            .expect("deliver locally queued success response");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll exact success response"));
        pair.server.drive_h3().expect("repeat response drive");
        pair.server_to_client().expect("repeat response flush");
        assert!(!pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("accepted response is never sent twice"));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.readable())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn t027b2d0_real_stream_blocked_is_atomic_and_retries_same_response_once() {
        let mut pair =
            TestPair::with_connection_window(512).expect("construct connection-flow-blocked pair");
        pair.authenticate_generation()
            .expect("authenticate connection-flow-blocked pair");
        let headers = test_classic_connect_headers(b"blocked-response.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue blocked-response CONNECT");
        pair.client_to_server()
            .expect("admit blocked-response CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take blocked-response dispatch")
            .expect("blocked-response dispatch exists");

        assert_eq!(pair.server.transport.stream_send(1, b"", false), Ok(0));
        let filler_capacity = pair
            .server
            .transport
            .stream_capacity(1)
            .expect("read real server send capacity");
        assert!(filler_capacity > 0 && filler_capacity <= 512);
        let filler = vec![0x5a; filler_capacity];
        assert_eq!(
            pair.server.transport.stream_send(1, &filler, false),
            Ok(filler_capacity)
        );

        let (opened_target, peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff target before real StreamBlocked");
        pair.server
            .drive_h3()
            .expect("real StreamBlocked keeps generation active");
        assert_eq!(pair.server.response_pending_count_for_test(), 1);
        assert_eq!(pair.server.response_accepted_count_for_test(), 0);
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("blocked response retains original slot");
        assert_eq!(pending.stream_id, stream_id);
        assert!(pending.target.is_none());
        assert!(pending.opened_target.is_some());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.readable())
                .await
                .is_err()
        );

        pair.server_to_client()
            .expect("deliver only the connection-window filler");
        let mut response_probe = [0_u8; 32];
        assert_eq!(
            pair.client.stream_recv(stream_id, &mut response_probe),
            Err(quiche::Error::Done),
            "blocked atomic HEADERS must contribute zero response-stream bytes"
        );
        let mut received = 0_usize;
        let mut filler_probe = [0_u8; 512];
        loop {
            match pair.client.stream_recv(1, &mut filler_probe) {
                Ok((length, false)) => received += length,
                Ok((_, true)) => panic!("test filler stream unexpectedly finished"),
                Err(quiche::Error::Done) => break,
                Err(_) => panic!("read real flow-control filler"),
            }
        }
        assert_eq!(received, filler_capacity);

        for _ in 0..MAX_SHUTTLE_STEPS {
            pair.client_to_server()
                .expect("deliver real peer flow-control credit");
            if pair.server.response_accepted_count_for_test() == 1 {
                break;
            }
            pair.server.drive_h3().expect("retry blocked response");
        }
        assert_eq!(pair.server.response_pending_count_for_test(), 0);
        assert_eq!(pair.server.response_accepted_count_for_test(), 1);
        pair.server_to_client()
            .expect("deliver safely retried success response");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll one safely retried success response"));
        pair.server
            .drive_h3()
            .expect("repeat accepted response drive");
        pair.server_to_client()
            .expect("repeat accepted response flush");
        assert!(!pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("retry produces no duplicate response"));
    }

    #[tokio::test]
    async fn t027b2d0_peer_request_fin_still_allows_exact_success_without_data_plane() {
        let mut pair = TestPair::new().expect("construct peer-FIN response pair");
        pair.authenticate_generation()
            .expect("authenticate peer-FIN response pair");
        let headers = test_classic_connect_headers(b"peer-fin.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue peer-FIN CONNECT");
        pair.client_to_server().expect("admit peer-FIN CONNECT");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take peer-FIN dispatch")
            .expect("peer-FIN dispatch exists");
        assert_eq!(pair.client.stream_send(stream_id, b"", true), Ok(0));
        pair.client_to_server()
            .expect("record peer request write-half FIN");
        let (opened_target, peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("handoff target after peer request FIN");
        pair.server
            .drive_h3()
            .expect("queue response after peer FIN");
        pair.server_to_client()
            .expect("deliver response after peer FIN");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll exact response after peer FIN"));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.readable())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn t027b2d0_response_prechecks_fail_closed_and_release_slot_socket() {
        let (mut revoked, _, revoked_peer) =
            response_pending_pair(b"response-revoked.invalid:443").await;
        revoked
            .server
            .revoke_authenticated_generation()
            .expect("revoke response-pending generation");
        assert_eq!(revoked.server.pending_connects.len(), 0);
        assert_target_peer_eof(revoked_peer).await;

        let (mut expired, _, expired_peer) =
            response_pending_pair(b"response-expired.invalid:443").await;
        expired
            .server
            .auth
            .capability
            .as_mut()
            .expect("active response-expiry capability")
            .hard_deadline = Instant::now();
        assert_eq!(
            expired.server.drive_h3(),
            Err(RuntimeError::AuthenticationExpired)
        );
        assert_eq!(expired.server.pending_connects.len(), 0);
        assert_target_peer_eof(expired_peer).await;

        let (mut generation, _, generation_peer) =
            response_pending_pair(b"response-generation.invalid:443").await;
        generation.server.pending_connects.slots[0]
            .as_mut()
            .expect("generation-mismatch response slot")
            .generation = ServerSourceConnectionId::new([0x77; quiche::MAX_CONN_ID_LEN]);
        assert_eq!(
            generation.server.drive_h3(),
            Err(RuntimeError::ClassicConnectResponseRejected)
        );
        assert_eq!(generation.server.pending_connects.len(), 0);
        assert_target_peer_eof(generation_peer).await;

        let (mut stream, _, stream_peer) =
            response_pending_pair(b"response-stream.invalid:443").await;
        stream.server.pending_connects.slots[0]
            .as_mut()
            .expect("stream-mismatch response slot")
            .stream_id = u64::MAX;
        assert!(stream.server.drive_h3().is_err());
        assert_eq!(stream.server.pending_connects.len(), 0);
        assert_target_peer_eof(stream_peer).await;

        let (mut frame, _, frame_peer) = response_pending_pair(b"response-frame.invalid:443").await;
        frame.server.pending_connects.slots[0]
            .as_mut()
            .expect("frame-mismatch response slot")
            .max_frame_size += 1;
        assert_eq!(
            frame.server.drive_h3(),
            Err(RuntimeError::ClassicConnectResponseRejected)
        );
        assert_eq!(frame.server.pending_connects.len(), 0);
        assert_target_peer_eof(frame_peer).await;
    }

    #[tokio::test]
    async fn t027b2d0_reset_stop_and_pre_200_data_fail_closed_without_relay() {
        let (mut reset, reset_stream, reset_peer) =
            response_pending_pair(b"response-reset.invalid:443").await;
        reset
            .client
            .stream_shutdown(reset_stream, quiche::Shutdown::Write, 0x41)
            .expect("reset response-pending request stream");
        assert!(reset.client_to_server().is_err());
        assert_eq!(reset.server.pending_connects.len(), 0);
        assert_target_peer_eof(reset_peer).await;

        let (mut stopped, stopped_stream, stopped_peer) =
            response_pending_pair(b"response-stop.invalid:443").await;
        stopped
            .client
            .stream_shutdown(stopped_stream, quiche::Shutdown::Read, 0x42)
            .expect("stop response-pending response stream");
        assert!(stopped.client_to_server().is_err());
        assert_eq!(stopped.server.pending_connects.len(), 0);
        assert_target_peer_eof(stopped_peer).await;

        let (mut data, data_stream, data_peer) =
            response_pending_pair(b"response-data.invalid:443").await;
        assert_eq!(
            data.client_h3
                .as_mut()
                .expect("client H3 exists for premature DATA")
                .send_body(&mut data.client, data_stream, b"not-a-tunnel", false),
            Ok(12)
        );
        assert!(data.client_to_server().is_err());
        assert_eq!(data.server.pending_connects.len(), 0);
        assert_target_peer_eof(data_peer).await;
    }

    #[tokio::test]
    async fn t027b2d1_would_block_preserves_slot_and_later_readiness_delivers_exact_data() {
        use tokio::io::AsyncWriteExt;

        let (mut pair, stream_id, mut peer) =
            response_accepted_pair(b"target-would-block.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before target readiness");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll response before target readiness"));

        assert_eq!(pair.server.drive_target_to_client_round(Some(0)), Ok(1));
        assert_eq!(pair.server.target_read_calls, 1);
        assert_eq!(pair.server.target_send_body_calls, 0);
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("WouldBlock retains target slot");
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseAccepted
        );
        assert!(pending.opened_target.is_some());
        assert!(tokio::time::timeout(
            Duration::from_millis(25),
            pair.server.wait_target_readable()
        )
        .await
        .is_err());

        let expected = b"later-target-readiness";
        peer.write_all(expected)
            .await
            .expect("write after initial WouldBlock");
        let slot_index =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                .await
                .expect("later target write wakes readiness")
                .expect("later target readiness is usable");
        let operations = pair
            .server
            .drive_target_to_client_round(Some(slot_index))
            .expect("read and queue later target data");
        assert!(operations <= MAX_TARGET_TO_CLIENT_IO_OPERATIONS_PER_ROUND);
        pair.server_to_client().expect("deliver later target data");
        let mut received = Vec::new();
        assert!(!pair
            .poll_classic_connect_body(stream_id, &mut received)
            .expect("poll later target data without EOF"));
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn t027b2d2_post_200_client_data_reaches_original_target_and_reply_returns_same_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"post-200-client-data";
        let reply = b"same-stream-target-reply";
        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"bidirectional.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before client DATA");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe exact response before client DATA"));

        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("bidirectional H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, false),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("accepted response permits client DATA");
        pair.server
            .drive_target_io_round(None)
            .expect("receive bounded client DATA");
        let ready_signal =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("original target becomes writable")
                .expect("target write readiness is usable");
        assert_eq!(ready_signal.direction, TargetIoDirection::ClientToTarget);
        pair.server
            .drive_target_io_round(Some(ready_signal))
            .expect("write client DATA to original target");

        let mut received_at_target = [0_u8; 20];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received_at_target),
        )
        .await
        .expect("client DATA reaches target within bound")
        .expect("read client DATA from original target");
        assert_eq!(&received_at_target, marker);

        target_peer
            .write_all(reply)
            .await
            .expect("write same-stream target reply");
        let slot_index =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                .await
                .expect("target reply becomes readable")
                .expect("target reply readiness is usable");
        pair.server
            .drive_target_to_client_round(Some(slot_index))
            .expect("queue same-stream target reply");
        pair.server_to_client()
            .expect("deliver same-stream target reply");
        let mut received_at_client = Vec::new();
        assert!(!pair
            .poll_classic_connect_body(stream_id, &mut received_at_client)
            .expect("poll same-stream target reply"));
        assert_eq!(received_at_client, reply);
    }

    #[tokio::test]
    async fn t027b2d2_real_target_would_block_preserves_suffix_and_resumes_on_writable() {
        use tokio::io::AsyncReadExt;

        let marker = b"exact-upload-suffix-after-real-would-block";
        let (mut pair, stream_id, mut target_peer, filler_length) =
            response_accepted_pair_with_blocked_target(b"blocked-upload.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before blocked upload");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe response before blocked upload"));
        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("blocked-upload H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, false),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("admit blocked-upload DATA event");

        let receive_round = pair
            .server
            .drive_target_io_round(None)
            .expect("receive one blocked-upload chunk");
        assert!(receive_round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
        assert!(receive_round.progress_operations() >= 1);
        let (offset, length) = match pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("blocked-upload slot remains occupied")
            .upload_state
        {
            UploadDispatchState::WritePending { offset, length } => (offset, length),
            _ => panic!("blocked upload retains one exact write-pending suffix"),
        };
        assert_eq!((offset, length), (0, marker.len()));
        let receives_before_block = pair.server.upload_recv_body_calls;
        let blocked_round = pair
            .server
            .drive_target_io_round(None)
            .expect("real target WouldBlock is bounded zero progress");
        assert_eq!(blocked_round.operations(), 1);
        assert_eq!(blocked_round.progress_operations(), 0);
        assert_eq!(blocked_round.operation_progress_bytes(), 0);
        assert_eq!(pair.server.upload_recv_body_calls, receives_before_block);
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("WouldBlock retains original slot")
                .upload_state,
            UploadDispatchState::WritePending { offset, length }
        );

        drain_real_target_filler(&mut target_peer, filler_length).await;
        let ready_signal =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("drained target becomes writable")
                .expect("writable signal is usable");
        assert_eq!(ready_signal.direction, TargetIoDirection::ClientToTarget);
        let resumed = pair
            .server
            .drive_target_io_round(Some(ready_signal))
            .expect("writable target resumes exact suffix");
        assert!(resumed.progress_operations() >= 1);
        assert!(resumed.operation_progress_bytes() >= marker.len());
        let mut received = [0_u8; 42];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("resumed suffix reaches target within bound")
        .expect("read resumed exact suffix");
        assert_eq!(&received, marker);
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("resumed upload keeps original slot")
                .upload_state,
            UploadDispatchState::Idle
        );
    }

    #[tokio::test]
    async fn t027b2d2_retained_and_t027b2d3_real_blocked_fin_and_reply() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"final-data-before-deferred-target-shutdown";
        let (mut pair, stream_id, mut target_peer, filler_length) =
            response_accepted_pair_with_blocked_target(b"finished-upload.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before final upload DATA");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe response before final upload DATA"));
        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("final-upload H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, true),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("deliver final DATA event before Finished rearm");
        pair.server
            .drive_target_io_round(None)
            .expect("buffer final DATA before blocked target write");
        pair.server
            .drive_h3()
            .expect("record request Finished after final DATA was buffered");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("final upload retains original slot");
        assert!(pending.peer_write_half_closed);
        assert_eq!(
            pending.upload_state,
            UploadDispatchState::WritePending {
                offset: 0,
                length: marker.len(),
            }
        );
        let blocked = pair
            .server
            .drive_target_io_round(None)
            .expect("final DATA target WouldBlock is zero progress");
        assert_eq!(blocked.progress_operations(), 0);

        drain_real_target_filler(&mut target_peer, filler_length).await;
        let ready_signal =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("final DATA target becomes writable")
                .expect("final DATA writable signal is usable");
        assert_eq!(ready_signal.direction, TargetIoDirection::ClientToTarget);
        pair.server
            .drive_target_io_round(Some(ready_signal))
            .expect("write all final DATA after target resumes");
        let mut received = [0_u8; 42];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("final DATA reaches target within bound")
        .expect("read complete final DATA");
        assert_eq!(&received, marker);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), target_peer.read_u8())
                .await
                .is_err()
        );
        let shutdown_round = pair
            .server
            .drive_target_io_round(None)
            .expect("shutdown target write half only after complete final DATA");
        assert_eq!(shutdown_round.operations(), 1);
        assert_eq!(shutdown_round.operation_progress_bytes(), 0);
        assert_eq!(shutdown_round.target_shutdown_progress_mask(), 1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target_peer.read_u8())
                .await
                .expect("target sees EOF after complete final marker")
                .expect_err("target EOF is not payload")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        let reply = b"delayed-reply-after-blocked-final-data";
        target_peer
            .write_all(reply)
            .await
            .expect("target read half remains usable for delayed reply");
        target_peer
            .shutdown()
            .await
            .expect("target closes its own write half after delayed reply");
        let readable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("delayed reply becomes readable")
                .expect("delayed reply readiness is usable");
        assert_eq!(readable.direction, TargetIoDirection::TargetToClient);
        let response_round = pair
            .server
            .drive_target_io_round(Some(readable))
            .expect("start queueing delayed reply");
        assert!(response_round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
        for _ in 0..4 {
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| {
                    pending.dispatch_state == TargetDispatchState::ResponseFinAccepted
                })
            {
                break;
            }
            let ready_signal = if pair.server.has_target_io_waiter() {
                Some(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        pair.server.wait_target_io_ready(),
                    )
                    .await
                    .expect("delayed reply continuation becomes ready")
                    .expect("delayed reply continuation signal is usable"),
                )
            } else {
                None
            };
            pair.server
                .drive_target_io_round(ready_signal)
                .expect("finish queueing delayed reply and target EOF");
        }
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("delayed-reply slot remains occupied")
                .dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        pair.server_to_client()
            .expect("deliver delayed reply and response FIN");
        let mut received_reply = Vec::new();
        assert!(pair
            .poll_classic_connect_body(stream_id, &mut received_reply)
            .expect("poll delayed reply through response FIN"));
        assert_eq!(received_reply, reply);

        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("request Finished still retains slot");
        assert!(pending.peer_write_half_closed);
        assert_eq!(pending.upload_state, UploadDispatchState::WriteHalfClosed);
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        assert!(pending.opened_target.is_some());
    }

    #[tokio::test]
    async fn t027b2d3_final_data_reaches_target_before_write_half_shutdown() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"final-upload-before-target-eof";
        let reply = b"delayed-reply-after-target-eof";
        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"request-fin-half-close.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before final upload");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe exact response before final upload"));

        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("request-FIN H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, true),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("deliver final DATA before request Finished");
        pair.server
            .drive_target_io_round(None)
            .expect("buffer final DATA before target write");
        pair.server
            .drive_h3()
            .expect("record request Finished after body consumption");

        let writable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("target becomes writable for final DATA")
                .expect("final DATA writable signal is usable");
        assert_eq!(writable.direction, TargetIoDirection::ClientToTarget);
        pair.server
            .drive_target_io_round(Some(writable))
            .expect("write the complete final DATA marker");
        pair.server
            .drive_target_io_round(None)
            .expect("drain final DATA event through recv_body Done");
        pair.server
            .drive_target_io_round(None)
            .expect("shut down only the target write half");

        let mut received = vec![0_u8; marker.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("complete final DATA reaches target before EOF")
        .expect("read complete final DATA before EOF");
        assert_eq!(received, marker);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), target_peer.read_u8())
                .await
                .expect("target observes request EOF after complete final DATA")
                .expect_err("target read after request EOF is not payload")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        target_peer
            .write_all(reply)
            .await
            .expect("target read half remains usable for delayed reply");
        target_peer
            .shutdown()
            .await
            .expect("target closes its own write half after delayed reply");
        let readable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("delayed target reply becomes readable")
                .expect("delayed reply readiness is usable");
        assert_eq!(readable.direction, TargetIoDirection::TargetToClient);
        pair.server
            .drive_target_io_round(Some(readable))
            .expect("queue delayed target reply");
        pair.server
            .drive_target_io_round(None)
            .expect("queue response FIN after delayed reply");
        pair.server_to_client()
            .expect("deliver delayed reply and response FIN");
        let mut received_reply = Vec::new();
        assert!(pair
            .poll_classic_connect_body(stream_id, &mut received_reply)
            .expect("poll delayed reply through response FIN"));
        assert_eq!(received_reply, reply);
    }

    #[tokio::test]
    async fn t027b2d3_empty_body_fin_closes_only_target_write_half() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let reply = b"reply-after-empty-request-body";
        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"empty-request-fin.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before empty request FIN");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe exact response before empty request FIN"));
        assert_eq!(pair.client.stream_send(stream_id, b"", true), Ok(0));
        pair.client_to_server().expect("deliver empty request FIN");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("empty-FIN slot remains occupied");
        assert_eq!(pending.upload_state, UploadDispatchState::ShutdownPending);
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseAccepted
        );

        let round = pair
            .server
            .drive_target_io_round(None)
            .expect("empty FIN shuts down target write half");
        assert_eq!(round.operations(), 1);
        assert_eq!(round.operation_progress_bytes(), 0);
        assert_eq!(round.target_shutdown_progress_mask(), 1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), target_peer.read_u8())
                .await
                .expect("empty request body produces target EOF")
                .expect_err("empty request EOF is not payload")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        target_peer
            .write_all(reply)
            .await
            .expect("target can reply after observing empty-body EOF");
        target_peer
            .shutdown()
            .await
            .expect("target closes reply write half");
        let readable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("empty-body delayed reply becomes readable")
                .expect("empty-body reply readiness is usable");
        pair.server
            .drive_target_io_round(Some(readable))
            .expect("start queueing empty-body delayed reply");
        for _ in 0..4 {
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| {
                    pending.dispatch_state == TargetDispatchState::ResponseFinAccepted
                })
            {
                break;
            }
            let ready_signal = if pair.server.has_target_io_waiter() {
                Some(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        pair.server.wait_target_io_ready(),
                    )
                    .await
                    .expect("empty-body reply continuation becomes ready")
                    .expect("empty-body reply continuation signal is usable"),
                )
            } else {
                None
            };
            pair.server
                .drive_target_io_round(ready_signal)
                .expect("finish queueing empty-body delayed reply and FIN");
        }
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("empty-body reply slot remains occupied")
                .dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        pair.server_to_client()
            .expect("deliver empty-body delayed reply and FIN");
        let mut received_reply = Vec::new();
        assert!(pair
            .poll_classic_connect_body(stream_id, &mut received_reply)
            .expect("poll empty-body delayed reply"));
        assert_eq!(received_reply, reply);
    }

    #[tokio::test]
    async fn t027b2d3_target_eof_and_request_fin_remain_orthogonal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"upload-after-response-fin";
        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"orthogonal-half-closes.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before target EOF");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe response before target EOF"));
        target_peer
            .shutdown()
            .await
            .expect("target closes only its write half first");
        let readable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("target EOF becomes readable")
                .expect("target EOF readiness is usable");
        pair.server
            .drive_target_io_round(Some(readable))
            .expect("queue response FIN from target EOF");
        pair.server_to_client()
            .expect("deliver response FIN before request FIN");
        let mut empty_response = Vec::new();
        assert!(pair
            .poll_classic_connect_body(stream_id, &mut empty_response)
            .expect("poll target EOF as response FIN"));
        assert!(empty_response.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), target_peer.read_u8())
                .await
                .is_err()
        );

        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("post-response-FIN H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, true),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("legal final upload follows response FIN");
        pair.server
            .drive_target_io_round(None)
            .expect("receive final upload after response FIN");
        pair.server
            .drive_h3()
            .expect("record request Finished after response FIN");
        let writable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("half-open target remains writable")
                .expect("half-open target writable signal is usable");
        pair.server
            .drive_target_io_round(Some(writable))
            .expect("write final upload after response FIN");
        pair.server
            .drive_target_io_round(None)
            .expect("shutdown target write half after response FIN");
        let mut received = vec![0_u8; marker.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("final upload reaches target after response FIN")
        .expect("read final upload after response FIN");
        assert_eq!(received, marker);
        assert_eq!(
            target_peer
                .read_u8()
                .await
                .expect_err("request FIN follows complete post-response-FIN upload")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("orthogonal slot remains occupied");
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        assert_eq!(pending.upload_state, UploadDispatchState::WriteHalfClosed);
    }

    #[tokio::test]
    async fn t027b2d3_fin_before_200_defers_shutdown_until_response_acceptance() {
        use tokio::io::AsyncReadExt;

        let mut pair = TestPair::new().expect("construct pre-200 FIN pair");
        pair.authenticate_generation()
            .expect("authenticate pre-200 FIN pair");
        let headers = test_classic_connect_headers(b"fin-before-200.invalid:443", false);
        let stream_id = pair
            .send_classic_connect(&headers, false)
            .expect("queue headers before request FIN");
        pair.client_to_server()
            .expect("admit request before pre-200 FIN");
        let token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take pre-200 FIN dispatch")
            .expect("pre-200 FIN dispatch exists");
        assert_eq!(pair.client.stream_send(stream_id, b"", true), Ok(0));
        pair.client_to_server()
            .expect("record request FIN before target readiness");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("pre-200 FIN slot remains occupied");
        assert!(pending.peer_write_half_closed);
        assert_eq!(pending.upload_state, UploadDispatchState::Idle);
        assert_eq!(pending.dispatch_state, TargetDispatchState::InFlight);

        let (opened_target, mut target_peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(token, opened_target, Instant::now())
            .expect("complete original pre-200 FIN target");
        pair.server
            .drive_h3()
            .expect("accept 200 after pre-200 FIN");
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("post-200 FIN slot remains occupied");
        assert_eq!(pending.stream_id, stream_id);
        assert_eq!(pending.upload_state, UploadDispatchState::ShutdownPending);
        pair.server
            .drive_target_io_round(None)
            .expect("shutdown target only after local 200 acceptance");
        assert_eq!(
            target_peer
                .read_u8()
                .await
                .expect_err("pre-200 FIN reaches target only after accepted response")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn t027b2d3_eight_shutdowns_use_two_shared_zero_byte_rounds() {
        use tokio::io::AsyncReadExt;

        let (mut pair, _, mut target_peers) =
            eight_shutdown_pending_pair(b"eight-shutdowns.invalid:443").await;

        let first = pair
            .server
            .drive_target_io_round(None)
            .expect("first shared shutdown round");
        let second = pair
            .server
            .drive_target_io_round(None)
            .expect("second shared shutdown round");
        assert_eq!(first.operations(), MAX_TARGET_IO_OPERATIONS_PER_ROUND);
        assert_eq!(second.operations(), MAX_TARGET_IO_OPERATIONS_PER_ROUND);
        assert_eq!(first.operation_progress_bytes(), 0);
        assert_eq!(second.operation_progress_bytes(), 0);
        assert_eq!(
            first.target_shutdown_progress_mask() | second.target_shutdown_progress_mask(),
            (1_usize << MAX_PENDING_CLASSIC_CONNECTS) - 1
        );
        assert_eq!(
            first.target_shutdown_progress_mask() & second.target_shutdown_progress_mask(),
            0
        );
        assert_eq!(
            pair.server.target_shutdown_calls,
            MAX_PENDING_CLASSIC_CONNECTS
        );
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| pending.upload_state == UploadDispatchState::WriteHalfClosed));
        for target_peer in &mut target_peers {
            assert_eq!(
                target_peer
                    .read_u8()
                    .await
                    .expect_err("every original target observes request EOF")
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn t027b2d3_exact_download_readiness_precedes_eight_shutdowns_without_starvation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"download-amid-eight-request-fins";
        let (mut pair, stream_ids, mut target_peers) =
            eight_shutdown_pending_pair(b"mixed-eight-shutdowns.invalid:443").await;
        target_peers[0]
            .write_all(marker)
            .await
            .expect("make original slot zero genuinely readable");
        let ready_signal =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("real mixed downlink readiness arrives")
                .expect("real mixed readiness signal is usable");
        assert_eq!(ready_signal.slot_index, 0);
        assert_eq!(ready_signal.direction, TargetIoDirection::TargetToClient);

        let reads_before = pair.server.target_read_calls;
        let shutdowns_before = pair.server.target_shutdown_calls;
        let first = pair
            .server
            .drive_target_io_round(Some(ready_signal))
            .expect("exact downlink readiness leads the mixed shared round");
        assert_eq!(first.operations(), MAX_TARGET_IO_OPERATIONS_PER_ROUND);
        assert_eq!(first.operation_progress_bytes(), marker.len());
        assert_eq!(pair.server.target_read_calls, reads_before + 1);
        assert_eq!(pair.server.target_shutdown_calls, shutdowns_before + 3);
        assert_eq!(first.target_shutdown_progress_mask().count_ones(), 3);
        assert!(matches!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("mixed slot zero remains occupied")
                .dispatch_state,
            TargetDispatchState::BodyPending { .. }
        ));

        let mut shutdown_mask = first.target_shutdown_progress_mask();
        let mut rounds = 1_usize;
        for _ in 0..3 {
            if pair
                .server
                .pending_connects
                .slots
                .iter()
                .flatten()
                .all(|pending| {
                    pending.upload_state == UploadDispatchState::WriteHalfClosed
                        && pending.dispatch_state == TargetDispatchState::ResponseAccepted
                })
            {
                break;
            }
            let round = pair
                .server
                .drive_target_io_round(None)
                .expect("bounded mixed continuation advances downlink and shutdowns");
            assert!(round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
            assert!(round.operation_progress_bytes() <= 64 * 1024);
            shutdown_mask |= round.target_shutdown_progress_mask();
            rounds += 1;
        }
        assert!(rounds <= 3);
        assert_eq!(shutdown_mask, (1_usize << MAX_PENDING_CLASSIC_CONNECTS) - 1);
        assert_eq!(
            pair.server.target_shutdown_calls,
            MAX_PENDING_CLASSIC_CONNECTS
        );
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| {
                pending.upload_state == UploadDispatchState::WriteHalfClosed
                    && pending.dispatch_state == TargetDispatchState::ResponseAccepted
            }));

        pair.server_to_client()
            .expect("deliver mixed downlink marker after bounded continuation");
        let mut received = Vec::new();
        assert!(!pair
            .poll_classic_connect_body(stream_ids[0], &mut received)
            .expect("poll mixed downlink marker without response FIN"));
        assert_eq!(received, marker);
        for target_peer in &mut target_peers {
            assert_eq!(
                target_peer
                    .read_u8()
                    .await
                    .expect_err("each mixed target sees exactly one request EOF")
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn t027b2d3_shutdown_failure_and_post_fin_data_fail_generation_closed() {
        {
            let (mut failure, failure_stream, failure_peer) =
                body_pending_pair_with_small_window(b"shutdown-failure.invalid:443").await;
            assert_eq!(failure.client.stream_send(failure_stream, b"", true), Ok(0));
            failure
                .client_to_server()
                .expect("record FIN for injected shutdown failure");
            let pending = failure.server.pending_connects.slots[0]
                .as_mut()
                .expect("shutdown-failure slot remains occupied");
            assert!(pending.target_payload.iter().any(|byte| *byte != 0));
            assert_eq!(pending.upload_state, UploadDispatchState::ShutdownPending);
            pending.target_shutdown_failure_requested = true;
            let error = failure
                .server
                .drive_target_io_round(None)
                .expect_err("injected shutdown failure closes generation");
            assert_eq!(error, RuntimeError::ClassicConnectDataRejected);
            assert_eq!(failure.server.pending_connects.len(), 0);
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("shutdown-failure"));
                assert!(!rendered.contains("invalid:443"));
            }
            assert_target_peer_closed(failure_peer).await;
        }

        {
            let (mut post_fin, stream_id, post_fin_peer) =
                response_accepted_pair(b"post-fin-data.invalid:443").await;
            let mut h3 = post_fin
                .server
                .h3
                .take()
                .expect("post-FIN server H3 exists");
            post_fin
                .server
                .handle_h3_event(&mut h3, stream_id, quiche::h3::Event::Finished)
                .expect("first Finished records request FIN");
            let error = post_fin
                .server
                .handle_h3_event(&mut h3, stream_id, quiche::h3::Event::Data)
                .expect_err("DATA after request FIN closes generation");
            post_fin.server.h3 = Some(h3);
            assert_eq!(error, RuntimeError::ClassicConnectDataRejected);
            assert_eq!(post_fin.server.pending_connects.len(), 0);
            assert_target_peer_closed(post_fin_peer).await;
        }
    }

    #[tokio::test]
    async fn t027b2d2_one_data_event_crosses_16k_buffer_and_drains_to_done_byte_exact() {
        use tokio::io::AsyncReadExt;

        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"multi-upload.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before multi-chunk upload");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe response before multi-chunk upload"));
        let expected: Vec<u8> = (0..(CLIENT_TO_TARGET_BUFFER_BYTES * 2 + 977))
            .map(|index| (index % 251) as u8)
            .collect();
        let data_events_before = pair.server.upload_data_events;
        let mut sent_frames = 0_usize;
        let mut transport_moves = 0_usize;
        for chunk in expected.chunks(9_137) {
            let mut offset = 0_usize;
            while offset < chunk.len() {
                let send = pair
                    .client_h3
                    .as_mut()
                    .expect("multi-chunk H3 client exists")
                    .send_body(&mut pair.client, stream_id, &chunk[offset..], false);
                match send {
                    Ok(written) => {
                        assert_ne!(written, 0);
                        offset += written;
                        let moved = pair
                            .client_transport_to_server_without_h3_drive()
                            .expect("move queued body bytes without polling server H3");
                        let acknowledged = pair
                            .server_transport_to_client_without_h3_drive()
                            .expect("return transport credit without polling server H3");
                        assert!(moved || acknowledged);
                        transport_moves += usize::from(moved);
                    }
                    Err(quiche::h3::Error::Done) => {
                        let moved = pair
                            .client_transport_to_server_without_h3_drive()
                            .expect("free client transport capacity without polling server H3");
                        let acknowledged = pair
                            .server_transport_to_client_without_h3_drive()
                            .expect("return transport credit without polling server H3");
                        assert!(moved || acknowledged);
                        transport_moves += usize::from(moved);
                        assert!(transport_moves <= MAX_SHUTTLE_STEPS);
                    }
                    Err(_) => panic!("queue one partial real H3 upload frame"),
                }
            }
            sent_frames += 1;
        }
        assert!(sent_frames >= 4);
        let final_move = pair
            .client_transport_to_server_without_h3_drive()
            .expect("move every upload frame into the server transport without polling H3");
        assert!(transport_moves != 0 || final_move);
        assert_eq!(pair.server.upload_data_events, data_events_before);
        pair.server
            .drive_h3()
            .expect("one H3 drive creates one edge-triggered DATA event");
        assert_eq!(pair.server.upload_data_events, data_events_before + 1);
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("one-event upload slot remains occupied")
                .upload_state,
            UploadDispatchState::RecvPending
        );

        let receives_before = pair.server.upload_recv_body_calls;
        let mut full_buffer_receives = 0_usize;
        for _ in 0..MAX_SHUTTLE_STEPS {
            let round = pair
                .server
                .drive_target_io_round(None)
                .expect("advance one bounded receive/write round for the same DATA event");
            assert!(round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
            assert!(round.operation_progress_bytes() <= 64 * 1024);
            assert_eq!(pair.server.upload_data_events, data_events_before + 1);
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| {
                    pending.upload_state
                        == (UploadDispatchState::WritePending {
                            offset: 0,
                            length: CLIENT_TO_TARGET_BUFFER_BYTES,
                        })
                })
            {
                full_buffer_receives += 1;
            }
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| pending.upload_state == UploadDispatchState::Idle)
            {
                break;
            }
        }
        assert!(full_buffer_receives >= 2);
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("same DATA event drains to idle")
                .upload_state,
            UploadDispatchState::Idle
        );
        assert!(pair.server.upload_recv_body_calls >= receives_before + 4);
        assert_eq!(pair.server.upload_data_events, data_events_before + 1);
        let mut received = vec![0_u8; expected.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("multi-chunk upload reaches target within bound")
        .expect("read exact multi-chunk upload");
        assert_eq!(received, expected);
        pair.server
            .drive_h3()
            .expect("drained event does not reveal a second DATA event");
        assert_eq!(pair.server.upload_data_events, data_events_before + 1);
    }

    #[tokio::test]
    async fn t027b2d2_blocked_download_window_does_not_block_same_slot_upload() {
        use tokio::io::AsyncReadExt;

        let marker = b"upload-progress-while-download-window-blocked";
        let (mut pair, stream_id, mut target_peer) =
            body_pending_pair_with_small_window(b"cross-direction.invalid:443").await;
        assert!(matches!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("cross-direction slot exists")
                .dispatch_state,
            TargetDispatchState::BodyPending { .. }
        ));
        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("cross-direction H3 client exists")
                .send_body(&mut pair.client, stream_id, marker, false),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("deliver cross-direction upload DATA");
        for _ in 0..4 {
            let round = pair
                .server
                .drive_target_io_round(None)
                .expect("advance upload while download stays blocked");
            assert!(round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| pending.upload_state == UploadDispatchState::Idle)
            {
                break;
            }
        }
        assert!(matches!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("blocked download retains slot")
                .dispatch_state,
            TargetDispatchState::BodyPending { .. }
        ));
        let mut received = [0_u8; 45];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("upload progresses despite blocked QUIC response window")
        .expect("read upload during blocked download");
        assert_eq!(&received, marker);
    }

    #[tokio::test]
    async fn t027b2d2_recv_pending_continues_after_response_fin_without_socket_waiter() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let marker = b"request-data-after-response-fin";
        let (mut pair, stream_id, mut target_peer) =
            response_accepted_pair(b"response-fin-upload.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before target EOF");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("observe response before target EOF"));

        target_peer
            .shutdown()
            .await
            .expect("close only the target-to-server write half");
        let eof_signal =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("target EOF becomes readable")
                .expect("target EOF readiness is usable");
        assert_eq!(eof_signal.direction, TargetIoDirection::TargetToClient);
        pair.server
            .drive_target_io_round(Some(eof_signal))
            .expect("queue response FIN after target EOF");
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("response-FIN slot remains fixed")
                .dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        assert!(!pair.server.has_target_io_waiter());
        assert!(!pair.server.has_immediate_target_io_work());
        pair.server_to_client()
            .expect("deliver target EOF as response FIN");
        let h3 = pair
            .client_h3
            .as_mut()
            .expect("response-FIN client H3 exists");
        assert_eq!(
            h3.poll(&mut pair.client),
            Ok((stream_id, quiche::h3::Event::Data))
        );
        let mut empty = [0_u8; 1];
        assert_eq!(
            h3.recv_body(&mut pair.client, stream_id, &mut empty),
            Err(quiche::h3::Error::Done)
        );
        assert_eq!(
            h3.poll(&mut pair.client),
            Ok((stream_id, quiche::h3::Event::Finished))
        );

        assert_eq!(
            pair.client_h3
                .as_mut()
                .expect("response-FIN client H3 exists")
                .send_body(&mut pair.client, stream_id, marker, false),
            Ok(marker.len())
        );
        pair.client_to_server()
            .expect("response FIN does not reject legal request DATA");
        assert!(!pair.server.has_target_io_waiter());
        assert!(pair.server.has_immediate_target_io_work());
        let recv_round = pair
            .server
            .drive_target_io_round(None)
            .expect("RecvPending progresses without any socket waiter");
        assert_eq!(recv_round.operations(), 1);
        assert_eq!(recv_round.upload_recv_progress_mask(), 1);
        assert!(pair.server.has_target_io_waiter());
        assert!(!pair.server.has_immediate_target_io_work());

        let writable =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_io_ready())
                .await
                .expect("half-open target remains writable")
                .expect("half-open target writable signal is usable");
        assert_eq!(writable.direction, TargetIoDirection::ClientToTarget);
        pair.server
            .drive_target_io_round(Some(writable))
            .expect("write request DATA after response FIN");
        let mut received = vec![0_u8; marker.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            target_peer.read_exact(&mut received),
        )
        .await
        .expect("request DATA reaches half-open target")
        .expect("read request DATA after response FIN");
        assert_eq!(received, marker);
    }

    #[tokio::test]
    async fn t027b2d2_single_drive_eight_data_events_feed_bidirectional_rotating_rounds() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut pair = TestPair::new().expect("construct eight-slot bidirectional pair");
        pair.authenticate_generation()
            .expect("authenticate eight-slot bidirectional pair");
        let headers = test_classic_connect_headers(b"eight-bidirectional.invalid:443", false);
        let mut stream_ids = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        let mut target_peers = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        for _ in 0..MAX_PENDING_CLASSIC_CONNECTS {
            let stream_id = pair
                .send_classic_connect(&headers, false)
                .expect("queue one eight-slot CONNECT");
            pair.client_to_server()
                .expect("admit one eight-slot CONNECT");
            let token = pair
                .server
                .take_target_open_dispatch(Instant::now())
                .expect("take one eight-slot dispatch")
                .expect("one eight-slot dispatch exists");
            let (opened_target, target_peer) = connected_target_pair().await;
            pair.server
                .complete_target_open_dispatch(token, opened_target, Instant::now())
                .expect("handoff one eight-slot target");
            pair.server
                .drive_h3()
                .expect("accept one eight-slot response");
            pair.server_to_client()
                .expect("deliver one eight-slot response");
            assert!(pair
                .poll_exact_classic_connect_success(stream_id)
                .expect("observe one exact eight-slot response"));
            stream_ids.push(stream_id);
            target_peers.push(target_peer);
        }
        assert_eq!(stream_ids.len(), MAX_PENDING_CLASSIC_CONNECTS);

        for (index, target_peer) in target_peers.iter_mut().enumerate() {
            target_peer
                .write_all(&[0x80 | index as u8])
                .await
                .expect("make every target download direction readable");
        }
        for (index, stream_id) in stream_ids.iter().copied().enumerate() {
            assert_eq!(
                pair.client_h3
                    .as_mut()
                    .expect("eight-slot H3 client exists")
                    .send_body(&mut pair.client, stream_id, &[index as u8], false),
                Ok(1)
            );
        }
        assert!(pair
            .client_transport_to_server_without_h3_drive()
            .expect("queue all eight DATA frames in server transport"));
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| { pending.upload_state == UploadDispatchState::Idle }));
        pair.server
            .drive_h3()
            .expect("one H3 drive accepts exactly eight legal DATA events");
        assert_eq!(pair.server.lifecycle(), ConnectionLifecycle::Active);
        assert_eq!(pair.server.upload_data_events, MAX_PENDING_CLASSIC_CONNECTS);
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| { pending.upload_state == UploadDispatchState::RecvPending }));

        let mut round_count = 0_usize;
        for _ in 0..(MAX_PENDING_CLASSIC_CONNECTS * 8) {
            let ready_signal = if pair.server.has_immediate_target_io_work() {
                None
            } else {
                Some(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        pair.server.wait_target_io_ready(),
                    )
                    .await
                    .expect("one eight-slot socket direction becomes ready")
                    .expect("eight-slot readiness signal is usable"),
                )
            };
            let round = pair
                .server
                .drive_target_io_round(ready_signal)
                .expect("advance one shared eight-slot I/O round");
            assert!(round.operations() <= MAX_TARGET_IO_OPERATIONS_PER_ROUND);
            assert!(round.operation_progress_bytes() <= 64 * 1024);
            round_count += 1;
            if pair.server.target_read_calls >= MAX_PENDING_CLASSIC_CONNECTS
                && pair.server.target_send_body_calls >= MAX_PENDING_CLASSIC_CONNECTS
                && pair.server.target_write_calls >= MAX_PENDING_CLASSIC_CONNECTS
                && pair
                    .server
                    .pending_connects
                    .slots
                    .iter()
                    .flatten()
                    .all(|pending| {
                        pending.dispatch_state == TargetDispatchState::ResponseAccepted
                            && pending.upload_state == UploadDispatchState::Idle
                    })
            {
                break;
            }
        }
        assert!(round_count > 1);
        assert!(pair.server.target_io_cursor < TARGET_IO_CURSOR_LENGTH);
        assert!(pair.server.target_read_calls >= MAX_PENDING_CLASSIC_CONNECTS);
        assert!(pair.server.target_send_body_calls >= MAX_PENDING_CLASSIC_CONNECTS);
        assert!(pair.server.upload_recv_body_calls >= MAX_PENDING_CLASSIC_CONNECTS * 2);
        assert!(pair.server.target_write_calls >= MAX_PENDING_CLASSIC_CONNECTS);
        assert!(pair
            .server
            .pending_connects
            .slots
            .iter()
            .flatten()
            .all(|pending| {
                pending.dispatch_state == TargetDispatchState::ResponseAccepted
                    && pending.upload_state == UploadDispatchState::Idle
            }));

        for (index, target_peer) in target_peers.iter_mut().enumerate() {
            let mut received = [0_u8; 1];
            tokio::time::timeout(
                Duration::from_secs(1),
                target_peer.read_exact(&mut received),
            )
            .await
            .expect("each upload direction reaches its original target")
            .expect("read each original-slot upload byte");
            assert_eq!(received, [index as u8]);
        }

        pair.server_to_client()
            .expect("deliver all eight target-to-client bytes");
        let mut download_seen = [false; MAX_PENDING_CLASSIC_CONNECTS];
        loop {
            let h3 = pair
                .client_h3
                .as_mut()
                .expect("eight-slot response H3 exists");
            match h3.poll(&mut pair.client) {
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    let index = stream_ids
                        .iter()
                        .position(|candidate| *candidate == stream_id)
                        .expect("DATA belongs to an original fixed slot");
                    let mut body = [0_u8; 2];
                    assert_eq!(h3.recv_body(&mut pair.client, stream_id, &mut body), Ok(1));
                    assert_eq!(body[0], 0x80 | index as u8);
                    assert_eq!(
                        h3.recv_body(&mut pair.client, stream_id, &mut body),
                        Err(quiche::h3::Error::Done)
                    );
                    assert!(!download_seen[index]);
                    download_seen[index] = true;
                }
                Err(quiche::h3::Error::Done) => break,
                other => panic!("unexpected eight-slot response event: {other:?}"),
            }
        }
        assert!(download_seen.into_iter().all(|seen| seen));
    }

    #[tokio::test]
    async fn t027b2d1_real_small_window_retries_exact_suffix_before_another_target_read() {
        let (mut pair, stream_id, _peer) =
            body_pending_pair_with_small_window(b"partial-target.invalid:443").await;
        assert_eq!(pair.server.target_read_calls, 1);
        let (first_offset, first_length) = match pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("partial target slot remains occupied")
            .dispatch_state
        {
            TargetDispatchState::BodyPending { offset, length } => (offset, length),
            _ => panic!("small window must retain one exact unsent suffix"),
        };
        assert!(first_offset > 0 && first_offset < first_length);
        assert_eq!(first_length, TARGET_TO_CLIENT_BUFFER_BYTES);

        assert_eq!(pair.server.drive_target_to_client_round(None), Ok(1));
        assert_eq!(pair.server.target_read_calls, 1);
        assert_eq!(
            pair.server.pending_connects.slots[0]
                .as_ref()
                .expect("Done retains partial target slot")
                .dispatch_state,
            TargetDispatchState::BodyPending {
                offset: first_offset,
                length: first_length,
            }
        );

        let mut received = Vec::new();
        for _ in 0..MAX_SHUTTLE_STEPS {
            pair.server_to_client()
                .expect("deliver partial target response packets");
            assert!(!pair
                .poll_classic_connect_body(stream_id, &mut received)
                .expect("poll partial target response body"));
            pair.client_to_server()
                .expect("return partial target flow credit");
            pair.server
                .drive_target_to_client_round(None)
                .expect("retry exact partial suffix");
            if pair.server.pending_connects.slots[0]
                .as_ref()
                .is_some_and(|pending| {
                    pending.dispatch_state == TargetDispatchState::ResponseAccepted
                })
            {
                break;
            }
        }
        pair.server_to_client()
            .expect("deliver final exact partial suffix");
        assert!(!pair
            .poll_classic_connect_body(stream_id, &mut received)
            .expect("poll final exact partial suffix"));
        assert_eq!(received, vec![0x6d; TARGET_TO_CLIENT_BUFFER_BYTES]);
        assert_eq!(pair.server.target_read_calls, 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                .await
                .expect("second target chunk remains readable")
                .is_ok()
        );
    }

    #[tokio::test]
    async fn t027b2d1_eight_readable_slots_rotate_with_four_operation_ceiling() {
        use tokio::io::AsyncWriteExt;

        let mut pair = TestPair::new().expect("construct eight-readable pair");
        pair.authenticate_generation()
            .expect("authenticate eight-readable pair");
        let headers = test_classic_connect_headers(b"eight-readable.invalid:443", false);
        let mut tokens = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        for _ in 0..MAX_PENDING_CLASSIC_CONNECTS {
            pair.send_classic_connect(&headers, false)
                .expect("queue eight-readable CONNECT");
            pair.client_to_server()
                .expect("admit eight-readable CONNECT");
            pair.server_to_client()
                .expect("return eight-readable stream credit");
            tokens.push(
                pair.server
                    .take_target_open_dispatch(Instant::now())
                    .expect("take eight-readable dispatch")
                    .expect("eight-readable dispatch exists"),
            );
        }
        let mut peers = Vec::with_capacity(MAX_PENDING_CLASSIC_CONNECTS);
        for token in tokens {
            let (opened_target, peer) = connected_target_pair().await;
            pair.server
                .complete_target_open_dispatch(token, opened_target, Instant::now())
                .expect("handoff eight-readable target");
            peers.push(peer);
        }
        pair.server.drive_h3().expect("accept all eight responses");
        assert_eq!(
            pair.server.response_accepted_count_for_test(),
            MAX_PENDING_CLASSIC_CONNECTS
        );
        for (index, peer) in peers.iter_mut().enumerate() {
            peer.write_all(&[index as u8])
                .await
                .expect("write one byte to readable target");
        }

        let mut advanced = [false; MAX_PENDING_CLASSIC_CONNECTS];
        let mut progress_count = 0_usize;
        for _ in 0..(MAX_PENDING_CLASSIC_CONNECTS * 3) {
            let slot_index =
                tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                    .await
                    .expect("one of eight targets remains readable")
                    .expect("eight-target readiness is usable");
            let sends_before = pair.server.target_send_body_calls;
            let operations = pair
                .server
                .drive_target_to_client_round(Some(slot_index))
                .expect("advance one rotated readable target");
            assert!(operations <= MAX_TARGET_TO_CLIENT_IO_OPERATIONS_PER_ROUND);
            if pair.server.target_send_body_calls > sends_before {
                assert_eq!(slot_index, progress_count);
                assert!(!advanced[slot_index]);
                advanced[slot_index] = true;
                progress_count += 1;
                if progress_count == MAX_PENDING_CLASSIC_CONNECTS {
                    break;
                }
            }
        }
        assert!(advanced.into_iter().all(|slot| slot));
        assert!(pair.server.target_read_calls >= MAX_PENDING_CLASSIC_CONNECTS);
        assert!(pair.server.target_io_cursor < TARGET_IO_CURSOR_LENGTH);
    }

    #[tokio::test]
    async fn t027b2d1_large_target_payload_is_chunked_exactly_before_response_fin() {
        use tokio::io::AsyncWriteExt;

        let (mut pair, stream_id, mut peer) =
            response_accepted_pair(b"large-target.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before large target payload");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll response before large target payload"));

        let expected: Vec<u8> = (0..(TARGET_TO_CLIENT_BUFFER_BYTES * 2 + 913))
            .map(|index| (index % 251) as u8)
            .collect();
        peer.write_all(&expected)
            .await
            .expect("write multi-buffer target payload");
        peer.shutdown()
            .await
            .expect("close target write half after payload");

        let mut received = Vec::with_capacity(expected.len());
        let mut finished = false;
        for _ in 0..MAX_SHUTTLE_STEPS {
            let operations = if pair.server.has_target_read_waiter() {
                let slot_index = tokio::time::timeout(
                    Duration::from_secs(1),
                    pair.server.wait_target_readable(),
                )
                .await
                .expect("large target payload remains readable")
                .expect("large target readiness is usable");
                pair.server
                    .drive_target_to_client_round(Some(slot_index))
                    .expect("advance large target payload")
            } else {
                pair.server
                    .drive_target_to_client_round(None)
                    .expect("retry large target send after flow credit")
            };
            assert!(operations <= MAX_TARGET_TO_CLIENT_IO_OPERATIONS_PER_ROUND);
            pair.server_to_client()
                .expect("deliver large target response packets");
            finished = pair
                .poll_classic_connect_body(stream_id, &mut received)
                .expect("poll large target response body");
            pair.client_to_server()
                .expect("return large target flow credit");
            if finished {
                break;
            }
        }
        assert!(finished);
        assert_eq!(received, expected);
        assert!(pair.server.target_read_calls >= 4);
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("FIN-accepted target remains in original slot");
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        assert!(pending.opened_target.is_some());
    }

    #[tokio::test]
    async fn t027b2d1_zero_byte_target_eof_queues_fin_and_retains_original_socket() {
        use tokio::io::AsyncWriteExt;

        let (mut pair, stream_id, mut peer) =
            response_accepted_pair(b"empty-target.invalid:443").await;
        pair.server_to_client()
            .expect("deliver response before empty target EOF");
        assert!(pair
            .poll_exact_classic_connect_success(stream_id)
            .expect("poll response before empty target EOF"));
        peer.shutdown()
            .await
            .expect("close empty target write half");
        let slot_index =
            tokio::time::timeout(Duration::from_secs(1), pair.server.wait_target_readable())
                .await
                .expect("empty target EOF wakes readiness")
                .expect("empty target EOF readiness is usable");
        assert_eq!(
            pair.server.drive_target_to_client_round(Some(slot_index)),
            Ok(2)
        );
        pair.server_to_client()
            .expect("deliver empty target response FIN");
        let mut received = Vec::new();
        assert!(pair
            .poll_classic_connect_body(stream_id, &mut received)
            .expect("poll empty target response FIN"));
        assert!(received.is_empty());
        let pending = pair.server.pending_connects.slots[0]
            .as_ref()
            .expect("empty-FIN target remains in original slot");
        assert_eq!(
            pending.dispatch_state,
            TargetDispatchState::ResponseFinAccepted
        );
        assert!(pending.opened_target.is_some());
    }

    #[tokio::test]
    async fn t027b2d1_buffered_reset_stop_expiry_revoke_and_client_data_fail_closed() {
        {
            let (mut read_error, _, read_error_peer) =
                response_accepted_pair(b"target-read-error.invalid:443").await;
            read_error.server.pending_connects.slots[0]
                .as_mut()
                .expect("target-read-error slot exists")
                .target_read_failure_requested = true;
            assert_eq!(
                read_error.server.drive_target_to_client_round(Some(0)),
                Err(RuntimeError::ClassicConnectDataRejected)
            );
            assert_eq!(read_error.server.pending_connects.len(), 0);
            assert_target_peer_eof(read_error_peer).await;
        }

        {
            let (mut reset, reset_stream, reset_peer) =
                body_pending_pair_with_small_window(b"buffered-reset.invalid:443").await;
            reset
                .client
                .stream_shutdown(reset_stream, quiche::Shutdown::Write, 0x51)
                .expect("reset buffered request stream");
            assert!(reset.client_to_server().is_err());
            assert_eq!(reset.server.pending_connects.len(), 0);
            assert_target_peer_closed(reset_peer).await;
        }

        {
            let (mut stopped, stopped_stream, stopped_peer) =
                body_pending_pair_with_small_window(b"buffered-stop.invalid:443").await;
            stopped
                .client
                .stream_shutdown(stopped_stream, quiche::Shutdown::Read, 0x52)
                .expect("stop buffered response stream");
            assert!(stopped.client_to_server().is_err());
            assert_eq!(stopped.server.pending_connects.len(), 0);
            assert_target_peer_closed(stopped_peer).await;
        }

        {
            let (mut expired, _, expired_peer) =
                body_pending_pair_with_small_window(b"buffered-expiry.invalid:443").await;
            expired
                .server
                .auth
                .capability
                .as_mut()
                .expect("buffered expiry capability")
                .hard_deadline = Instant::now();
            assert_eq!(
                expired.server.drive_target_to_client_round(None),
                Err(RuntimeError::AuthenticationExpired)
            );
            assert_eq!(expired.server.pending_connects.len(), 0);
            assert_target_peer_closed(expired_peer).await;
        }

        {
            let (mut revoked, _, revoked_peer) =
                body_pending_pair_with_small_window(b"buffered-revoke.invalid:443").await;
            revoked
                .server
                .revoke_authenticated_generation()
                .expect("revoke buffered generation");
            assert_eq!(revoked.server.pending_connects.len(), 0);
            assert_target_peer_closed(revoked_peer).await;
        }

        for rendered in [
            RuntimeError::ClassicConnectDataRejected.to_string(),
            format!("{:?}", RuntimeError::ClassicConnectDataRejected),
        ] {
            assert!(rendered.len() <= 64);
            assert!(!rendered.contains("marker"));
            assert!(!rendered.contains("target"));
        }
    }

    #[tokio::test]
    async fn t027b2d1_buffered_actor_cancellation_clears_payload_and_closes_target() {
        let (mut cancelled, _, cancelled_peer) =
            body_pending_pair_with_small_window(b"buffered-cancel.invalid:443").await;
        cancelled
            .server
            .close()
            .expect("actor cancellation closes buffered generation");
        assert_eq!(cancelled.server.pending_connects.len(), 0);
        assert_target_peer_closed(cancelled_peer).await;
    }

    #[tokio::test]
    async fn t027b2d2_write_error_reset_expiry_and_revoke_clear_both_payload_buffers() {
        {
            let (mut write_error, _, write_error_peer) =
                both_payload_buffers_pending_pair(b"double-buffer-write-error.invalid:443").await;
            write_error.server.pending_connects.slots[0]
                .as_mut()
                .expect("double-buffer write-error slot exists")
                .target_write_failure_requested = true;
            assert_eq!(
                write_error
                    .server
                    .drive_target_io_round(Some(TargetIoSignal {
                        slot_index: 0,
                        direction: TargetIoDirection::ClientToTarget,
                    })),
                Err(RuntimeError::ClassicConnectDataRejected)
            );
            assert_eq!(write_error.server.pending_connects.len(), 0);
            assert_target_peer_closed(write_error_peer).await;
        }

        {
            let (mut reset, reset_stream, reset_peer) =
                both_payload_buffers_pending_pair(b"double-buffer-reset.invalid:443").await;
            reset
                .client
                .stream_shutdown(reset_stream, quiche::Shutdown::Write, 0x61)
                .expect("reset double-buffer request stream");
            assert!(reset.client_to_server().is_err());
            assert_eq!(reset.server.pending_connects.len(), 0);
            assert_target_peer_closed(reset_peer).await;
        }

        {
            let (mut expired, _, expired_peer) =
                both_payload_buffers_pending_pair(b"double-buffer-expiry.invalid:443").await;
            expired
                .server
                .auth
                .capability
                .as_mut()
                .expect("double-buffer expiry capability")
                .hard_deadline = Instant::now();
            assert_eq!(
                expired.server.drive_target_io_round(None),
                Err(RuntimeError::AuthenticationExpired)
            );
            assert_eq!(expired.server.pending_connects.len(), 0);
            assert_target_peer_closed(expired_peer).await;
        }

        {
            let (mut revoked, _, revoked_peer) =
                both_payload_buffers_pending_pair(b"double-buffer-revoke.invalid:443").await;
            revoked
                .server
                .revoke_authenticated_generation()
                .expect("revoke double-buffer generation");
            assert_eq!(revoked.server.pending_connects.len(), 0);
            assert_target_peer_closed(revoked_peer).await;
        }
    }

    #[tokio::test]
    async fn t027b2d2_cancel_clears_both_payload_buffers_without_upload_marker_leak() {
        let (mut cancelled, _, cancelled_peer) =
            both_payload_buffers_pending_pair(b"double-buffer-cancel.invalid:443").await;
        cancelled
            .server
            .close()
            .expect("cancel double-buffer generation");
        assert_eq!(cancelled.server.pending_connects.len(), 0);
        assert_target_peer_closed(cancelled_peer).await;
    }

    #[tokio::test]
    async fn t027b2c4_occupied_owner_rejects_duplicate_without_overwrite() {
        let mut pair = TestPair::new().expect("construct duplicate-owner pair");
        pair.authenticate_generation()
            .expect("authenticate duplicate-owner generation");
        let headers = test_classic_connect_headers(b"duplicate-owner.invalid:443", false);
        for _ in 0..2 {
            pair.send_classic_connect(&headers, false)
                .expect("queue duplicate-owner CONNECT");
            pair.client_to_server()
                .expect("admit duplicate-owner CONNECT");
            pair.server_to_client()
                .expect("return duplicate-owner request credit");
        }

        let first_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take first duplicate-owner token")
            .expect("first duplicate-owner token exists");
        let first_stream_id = first_token.stream_id;
        let (first_opened, first_peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(first_token, first_opened, Instant::now())
            .expect("install first target owner");

        let mut duplicate_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take second duplicate-owner token")
            .expect("second duplicate-owner token exists");
        duplicate_token.stream_id = first_stream_id;
        let (duplicate_opened, duplicate_peer) = connected_target_pair().await;
        assert_eq!(
            pair.server.complete_target_open_dispatch(
                duplicate_token,
                duplicate_opened,
                Instant::now(),
            ),
            Err(RuntimeError::TargetOpenDispatchRejected)
        );
        assert_target_peer_eof(duplicate_peer).await;
        assert_eq!(pair.server.waiting_opened_target_count_for_test(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), first_peer.readable())
                .await
                .is_err()
        );

        drop(pair.server);
        assert_target_peer_eof(first_peer).await;
    }

    #[tokio::test]
    async fn t027b2c4_target_peer_write_half_close_preserves_slot_socket_bijection() {
        use tokio::io::AsyncWriteExt;

        let mut pair = TestPair::new().expect("construct target-half-close pair");
        pair.authenticate_generation()
            .expect("authenticate target-half-close generation");
        let headers = test_classic_connect_headers(b"target-half-close.invalid:443", false);
        for _ in 0..2 {
            pair.send_classic_connect(&headers, false)
                .expect("queue target-half-close CONNECT");
            pair.client_to_server()
                .expect("admit target-half-close CONNECT");
            pair.server_to_client()
                .expect("return target-half-close request credit");
        }

        let first_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take in-flight half-close token")
            .expect("in-flight half-close token exists");
        let (first_opened, mut first_peer) = connected_target_pair().await;
        first_peer
            .shutdown()
            .await
            .expect("half-close target peer before handoff");
        pair.server
            .complete_target_open_dispatch(first_token, first_opened, Instant::now())
            .expect("in-flight target half-close preserves handoff");

        let second_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take waiting-stage half-close token")
            .expect("waiting-stage half-close token exists");
        let (second_opened, mut second_peer) = connected_target_pair().await;
        pair.server
            .complete_target_open_dispatch(second_token, second_opened, Instant::now())
            .expect("install second target owner");
        second_peer
            .shutdown()
            .await
            .expect("half-close target peer after handoff");

        assert_eq!(pair.server.pending_connects.len(), 2);
        assert_eq!(pair.server.waiting_target_dispatch_count_for_test(), 2);
        assert_eq!(pair.server.waiting_opened_target_count_for_test(), 2);
    }

    #[tokio::test]
    async fn t027b2c4_stream_port_and_frame_mismatch_drop_socket_without_advancing_slot() {
        let mut pair = TestPair::new().expect("construct metadata-mismatch pair");
        pair.authenticate_generation()
            .expect("authenticate metadata-mismatch generation");
        let headers = test_classic_connect_headers(b"metadata-mismatch.invalid:443", false);
        for _ in 0..3 {
            pair.send_classic_connect(&headers, false)
                .expect("queue metadata-mismatch CONNECT");
            pair.client_to_server()
                .expect("admit metadata-mismatch CONNECT");
            pair.server_to_client()
                .expect("return metadata-mismatch request credit");
        }

        let mut stream_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take stream-mismatch token")
            .expect("stream-mismatch token exists");
        stream_token.stream_id = u64::MAX;
        let mut port_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take port-mismatch token")
            .expect("port-mismatch token exists");
        port_token.port = 444;
        let mut frame_token = pair
            .server
            .take_target_open_dispatch(Instant::now())
            .expect("take frame-mismatch token")
            .expect("frame-mismatch token exists");
        frame_token.max_frame_size += 1;

        for token in [stream_token, port_token, frame_token] {
            let (opened, peer) = connected_target_pair().await;
            assert_eq!(
                pair.server
                    .complete_target_open_dispatch(token, opened, Instant::now()),
                Err(RuntimeError::TargetOpenDispatchRejected)
            );
            assert_target_peer_eof(peer).await;
        }
        assert_eq!(pair.server.pending_connects.len(), 3);
        assert_eq!(pair.server.waiting_target_dispatch_count_for_test(), 0);
        assert_eq!(pair.server.waiting_opened_target_count_for_test(), 0);
        assert_eq!(
            pair.server
                .pending_connects
                .slots
                .iter()
                .flatten()
                .filter(|pending| pending.dispatch_state == TargetDispatchState::InFlight)
                .count(),
            3
        );
    }
}
