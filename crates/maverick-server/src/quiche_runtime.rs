//! Private, connection-local native-quiche server ownership seam.
//!
//! This module owns no socket, listener, connection registry, task, or channel.
//! A future outer driver can synchronously feed one bounded packet at a time,
//! drain one bounded packet at a time, and schedule the returned timer.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use boring::ssl::{SslRef, SslVersion};
use maverick_core::config::{
    DirectV3ServerRoleConfig, DirectV3TransportStrategy, ServerRoleConfig,
};

pub(super) const MAX_PACKET_BYTES: usize = 1_350;
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
const DATAGRAM_QUEUE_LIMIT: usize = 32;
const MAX_DATAGRAM_FRAME_BYTES: u64 = 65_536;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const PATH_CHALLENGE_QUEUE_LIMIT: usize = 3;
const MAX_IDLE_TIMEOUT_MILLIS: u64 = 5_000;
const PRE_AUTH_CLOSE_CODE: u64 = 0x105;
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

    pub(super) fn listen(&self) -> SocketAddr {
        self.direct_v3().listen()
    }

    #[cfg(test)]
    pub(super) fn has_owner(&self, expected: &Arc<ServerRoleConfig>) -> bool {
        Arc::ptr_eq(&self.owner, expected)
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
            Err(_) => return Err(RuntimeError::PacketRejected),
        }
        self.drive_h3()
    }

    pub(super) fn next_packet(
        &mut self,
        packet: &mut [u8; MAX_PACKET_BYTES],
    ) -> Result<Option<(usize, PacketMeta)>, RuntimeError> {
        match self.transport.send(packet) {
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
        }
    }

    pub(super) fn next_timeout(&self) -> Option<Duration> {
        self.transport.timeout()
    }

    pub(super) fn on_timeout(&mut self) -> Result<(), RuntimeError> {
        self.transport.on_timeout();
        self.drive_h3()
    }

    pub(super) fn is_established(&self) -> bool {
        self.transport.is_established()
    }

    pub(super) fn pre_auth_foundation_ready(&self) -> bool {
        self.pre_auth_foundation.is_ready()
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
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        self.transport
            .close(true, 0, b"")
            .map_err(|_| RuntimeError::CloseUnavailable)?;
        Ok(())
    }

    pub(super) fn reject_pre_auth(&mut self) -> Result<(), RuntimeError> {
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        self.transport
            .close(true, PRE_AUTH_CLOSE_CODE, b"")
            .map_err(|_| RuntimeError::CloseUnavailable)?;
        Ok(())
    }

    fn drive_h3(&mut self) -> Result<(), RuntimeError> {
        if self.lifecycle() != ConnectionLifecycle::Active {
            return Ok(());
        }
        if self.transport.is_in_early_data() {
            self.fail_closed(PRE_AUTH_CLOSE_CODE);
            return Err(RuntimeError::EarlyDataRejected);
        }

        if self.transport.is_established() && self.h3.is_none() {
            if self.transport.application_proto() != b"h3" {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::AlpnRejected);
            }
            let tls: &mut SslRef = self.transport.as_mut();
            if tls.version2() != Some(SslVersion::TLS1_3) {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::TlsVersionRejected);
            }
            if self.transport.server_name().map(str::as_bytes)
                != Some(self.role.expected_authority())
            {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::ServerNameRejected);
            }
            let h3_config = self.h3_config.take().ok_or(RuntimeError::H3Unavailable)?;
            self.h3 = Some(
                quiche::h3::Connection::with_transport(&mut self.transport, &h3_config)
                    .map_err(|_| RuntimeError::H3Unavailable)?,
            );
            self.pre_auth_foundation.h3_initialized();
        }

        let Some(h3) = self.h3.as_mut() else {
            return Ok(());
        };

        if self.transport.dgram_recv_front_len().is_some() {
            self.fail_closed(PRE_AUTH_CLOSE_CODE);
            return Err(RuntimeError::PreAuthApplicationActivity);
        }
        let event = h3.poll(&mut self.transport);
        if self.transport.dgram_recv_front_len().is_some() {
            self.fail_closed(PRE_AUTH_CLOSE_CODE);
            return Err(RuntimeError::PreAuthApplicationActivity);
        }
        match event {
            Ok((_stream_id, _event)) => {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::PreAuthApplicationActivity);
            }
            Err(quiche::h3::Error::Done) => {}
            Err(_) => {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::H3Unavailable);
            }
        }

        if !self.pre_auth_foundation.is_ready() {
            let Some(raw_settings) = h3.peer_settings_raw() else {
                return Ok(());
            };
            if !peer_settings_match(h3, &self.transport, raw_settings) {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                return Err(RuntimeError::PeerSettingsRejected);
            }
            self.pre_auth_foundation.peer_settings_verified();
        }
        Ok(())
    }

    fn fail_closed(&mut self, code: u64) {
        if self.lifecycle() == ConnectionLifecycle::Active {
            let _ = self.transport.close(true, code, b"");
        }
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
    PeerSettingsRejected,
    PreAuthApplicationActivity,
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
            Self::PeerSettingsRejected => "server peer settings rejected",
            Self::PreAuthApplicationActivity => "pre-authentication application activity rejected",
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

            let owner = test_server_role(&certificate_path, &key_path, expected_authority, "h3")?;
            let role = FrozenDirectV3ServerRole::new(owner)?;
            let mut server_config = ServerConnectionConfig::new(role)?;
            let mut client_config = bounded_transport_config()?;
            client_config.verify_peer(false);
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

    fn test_server_role(
        certificate_path: &Path,
        key_path: &Path,
        expected_authority: &str,
        transport_strategy: &str,
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
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
      provisioning_handle: "EREREREREREREREREREREQ"
      principal_id: "IiIiIiIiIiIiIiIiIiIiIg"
      deployment_profile_id: "MzMzMzMzMzMzMzMzMzMzMw"
      credential_namespace_id: "RERERERERERERERERERERA"
      server_identity_id: "VVVVVVVVVVVVVVVVVVVVVQ"
      credential_epoch: 7
      credential_not_after_unix: 1800172800
      secret: "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
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
    fn t027b2b2_1_auth_shaped_post_is_still_rejected_before_auth_exists() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair through peer SETTINGS");
        let headers = [
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/direct-v3"),
            quiche::h3::Header::new(b"content-type", b"application/maverick-auth-v3"),
            quiche::h3::Header::new(b"content-length", b"256"),
        ];
        let error = pair
            .send_pre_auth_headers(&headers)
            .expect("receive fixed auth-shaped request rejection");
        assert_eq!(error, RuntimeError::PreAuthApplicationActivity);
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
}
