//! Private, connection-local native-quiche server ownership seam.
//!
//! This module owns no socket, listener, connection registry, task, or channel.
//! A future outer driver can synchronously feed one bounded packet at a time,
//! drain one bounded packet at a time, and schedule the returned timer.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use boring::ssl::{SslRef, SslVersion};

pub(super) const MAX_PACKET_BYTES: usize = 1_350;
const INITIAL_CONNECTION_WINDOW_BYTES: u64 = 1_048_576;
const INITIAL_BIDI_STREAM_WINDOW_BYTES: u64 = 65_536;
const INITIAL_UNI_STREAM_WINDOW_BYTES: u64 = 16_384;
const MAX_STREAM_WINDOW_BYTES: u64 = 65_536;
const MAX_BIDI_STREAMS: u64 = 8;
const MAX_UNI_STREAMS: u64 = 8;
const MAX_FIELD_SECTION_BYTES: u64 = 16_384;
const MAX_PRIORITY_UPDATE_BYTES: u64 = 256;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const PATH_CHALLENGE_QUEUE_LIMIT: usize = 3;
const MAX_IDLE_TIMEOUT_MILLIS: u64 = 5_000;
const PRE_AUTH_CLOSE_CODE: u64 = 0x105;

#[derive(Clone, Copy)]
pub(super) struct PacketMeta {
    pub(super) from: SocketAddr,
    pub(super) to: SocketAddr,
}

#[derive(Clone, Copy)]
pub(super) struct ServerCredentials<'a> {
    pub(super) certificate_chain: &'a Path,
    pub(super) private_key: &'a Path,
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
}

impl ServerConnectionConfig {
    pub(super) fn new(credentials: ServerCredentials<'_>) -> Result<Self, RuntimeError> {
        let mut transport = bounded_transport_config()?;
        transport
            .load_cert_chain_from_pem_file(private_path(credentials.certificate_chain)?)
            .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
        transport
            .load_priv_key_from_pem_file(private_path(credentials.private_key)?)
            .map_err(|_| RuntimeError::ConfigurationUnavailable)?;
        Ok(Self { transport })
    }
}

pub(super) struct ServerConnection {
    transport: quiche::Connection,
    h3_config: Option<quiche::h3::Config>,
    h3: Option<quiche::h3::Connection>,
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

    pub(super) fn h3_is_ready(&self) -> bool {
        self.h3.is_some()
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
            let h3_config = self.h3_config.take().ok_or(RuntimeError::H3Unavailable)?;
            self.h3 = Some(
                quiche::h3::Connection::with_transport(&mut self.transport, &h3_config)
                    .map_err(|_| RuntimeError::H3Unavailable)?,
            );
        }

        let Some(h3) = self.h3.as_mut() else {
            return Ok(());
        };
        match h3.poll(&mut self.transport) {
            Ok((_stream_id, _event)) => {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                Err(RuntimeError::PreAuthApplicationActivity)
            }
            Err(quiche::h3::Error::Done) => Ok(()),
            Err(_) => {
                self.fail_closed(PRE_AUTH_CLOSE_CODE);
                Err(RuntimeError::H3Unavailable)
            }
        }
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
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RuntimeError {
    ConfigurationUnavailable,
    InitialPacketRejected,
    ConnectionUnavailable,
    PacketRejected,
    PacketUnavailable,
    EarlyDataRejected,
    AlpnRejected,
    TlsVersionRejected,
    H3Unavailable,
    PreAuthApplicationActivity,
    CloseUnavailable,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConfigurationUnavailable => "server connection configuration unavailable",
            Self::InitialPacketRejected => "initial server packet rejected",
            Self::ConnectionUnavailable => "server connection unavailable",
            Self::PacketRejected => "server packet rejected",
            Self::PacketUnavailable => "server packet unavailable",
            Self::EarlyDataRejected => "server early data rejected",
            Self::AlpnRejected => "server application protocol rejected",
            Self::TlsVersionRejected => "server TLS version rejected",
            Self::H3Unavailable => "server H3 state unavailable",
            Self::PreAuthApplicationActivity => "pre-authentication application activity rejected",
            Self::CloseUnavailable => "server connection close unavailable",
        };
        formatter.write_str(message)
    }
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
    config.enable_dgram(false, 0, 0);
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
    config.set_qpack_max_table_capacity(0);
    config.set_qpack_blocked_streams(0);
    config.set_max_priority_update_size(MAX_PRIORITY_UPDATE_BYTES);
    config.enable_extended_connect(false);
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
        server: ServerConnection,
    }

    impl TestPair {
        fn new() -> Result<Self, RuntimeError> {
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

            let mut server_config = ServerConnectionConfig::new(ServerCredentials {
                certificate_chain: &certificate_path,
                private_key: &key_path,
            })?;
            let mut client_config = bounded_transport_config()?;
            client_config.verify_peer(false);
            let source_connection_id = [0x51_u8; quiche::MAX_CONN_ID_LEN];
            let source_connection_id = quiche::ConnectionId::from_ref(&source_connection_id);
            let mut client = quiche::connect(
                Some("localhost"),
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
                server,
            })
        }

        fn drive_until_h3(&mut self) -> Result<(), RuntimeError> {
            for _ in 0..MAX_SHUTTLE_STEPS {
                self.server_to_client()?;
                self.client_to_server()?;
                if self.client.is_in_early_data() {
                    return Err(RuntimeError::EarlyDataRejected);
                }
                if self.client.is_established() && self.client_h3.is_none() {
                    let h3_config = bounded_h3_config()?;
                    self.client_h3 = Some(
                        quiche::h3::Connection::with_transport(&mut self.client, &h3_config)
                            .map_err(|_| RuntimeError::H3Unavailable)?,
                    );
                }
                if self.client_h3.is_some()
                    && self.server.is_established()
                    && self.server.h3_is_ready()
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

        fn send_pre_auth_request(&mut self) -> Result<RuntimeError, RuntimeError> {
            let headers = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/"),
            ];
            self.client_h3
                .as_mut()
                .ok_or(RuntimeError::H3Unavailable)?
                .send_request(&mut self.client, &headers, true)
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
    }

    #[test]
    fn server_owns_established_h3_until_explicit_close_and_drop() {
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair to H3");

        assert!(pair.server.is_established());
        assert!(pair.server.h3_is_ready());
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
        let mut pair = TestPair::new().expect("construct bounded in-memory pair");
        pair.drive_until_h3()
            .expect("drive bounded in-memory pair to H3");

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
        pair.server_to_client()
            .expect("deliver pre-authentication close in memory");
        let peer_error = pair
            .client
            .peer_error()
            .expect("real peer receives pre-authentication CONNECTION_CLOSE");
        assert!(peer_error.is_app);
        assert_eq!(peer_error.error_code, PRE_AUTH_CLOSE_CODE);
        assert!(peer_error.reason.is_empty());
        assert!(pair.client.is_draining() || pair.client.is_closed());
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
