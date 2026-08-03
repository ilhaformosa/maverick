//! Private bounded local UDP endpoint for native-quiche server actors.
//!
//! The endpoint owns the only receive loop, CID registry, and actor `JoinSet`.
//! Each actor receives one `ServerConnection` by value and never shares it.
//! This module has no authentication, CONNECT parser, target, DNS, opener,
//! relay, public API, or non-loopback binding seam.

#![forbid(unsafe_code)]

use std::fmt;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::{Id, JoinError, JoinSet};
use tokio::time::{timeout_at, Instant};

use crate::quiche_registry::{
    ActorInboundDisposition, ActorPacket, ConnectionRegistry, RegistryError,
};
#[cfg(test)]
use crate::quiche_runtime::ServerCredentials;
use crate::quiche_runtime::{PacketMeta, ServerConnection, MAX_PACKET_BYTES};

const ACTOR_INBOX_CAPACITY: usize = 4;
const SOCKET_RECV_BYTES: usize = MAX_PACKET_BYTES + 1;
const MAX_OUTBOUND_PACKETS_PER_ROUND: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_JOIN_BUDGET: Duration = Duration::from_secs(2);

struct Endpoint {
    socket: Arc<UdpSocket>,
    local_address: SocketAddr,
    registry: ConnectionRegistry,
    actors: JoinSet<Result<(), ActorError>>,
    unregistered_actor: Option<Id>,
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
    #[cfg(test)]
    fail_next_activation: bool,
    #[cfg(test)]
    next_actor_fault: ActorFault,
}

impl Endpoint {
    #[cfg(test)]
    async fn bind_test(
        credentials: ServerCredentials<'_>,
    ) -> Result<(Self, watch::Sender<bool>), EndpointError> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(|_| EndpointError::Bind)?;
        let local_address = socket.local_addr().map_err(|_| EndpointError::Bind)?;
        if local_address.ip() != Ipv4Addr::LOCALHOST || local_address.port() == 0 {
            return Err(EndpointError::Bind);
        }
        let registry = ConnectionRegistry::new(credentials).map_err(|_| EndpointError::Registry)?;
        let (cancel_tx, cancel_rx) = watch::channel(false);
        Ok((
            Self {
                socket: Arc::new(socket),
                local_address,
                registry,
                actors: JoinSet::new(),
                unregistered_actor: None,
                cancel_tx: cancel_tx.clone(),
                cancel_rx,
                fail_next_activation: false,
                next_actor_fault: ActorFault::None,
            },
            cancel_tx,
        ))
    }

    async fn run(&mut self) -> Result<(), EndpointError> {
        let mut receive_buffer = [0_u8; SOCKET_RECV_BYTES];
        let result = loop {
            if *self.cancel_rx.borrow() {
                break Ok(());
            }
            let actors_active = !self.actors.is_empty();
            tokio::select! {
                biased;
                changed = self.cancel_rx.changed() => {
                    let _ = changed;
                    break Ok(());
                }
                completion = self.actors.join_next_with_id(), if actors_active => {
                    let Some(completion) = completion else {
                        break Err(EndpointError::ActorLifecycle);
                    };
                    if self.reclaim_joined(completion).is_err() {
                        break Err(EndpointError::ActorLifecycle);
                    }
                }
                received = self.socket.recv_from(&mut receive_buffer) => {
                    let (length, source) = match received {
                        Ok(received) => received,
                        Err(_) => break Err(EndpointError::Receive),
                    };
                    let Some(packet) = bounded_received_datagram(&receive_buffer, length) else {
                        continue;
                    };
                    if let Err(error) = self.route_datagram(
                        packet,
                        length,
                        PacketMeta {
                            from: source,
                            to: self.local_address,
                        },
                    ) {
                        break Err(error);
                    }
                }
            }
        };

        let shutdown = self.shutdown().await;
        result.and(shutdown)
    }

    fn route_datagram(
        &mut self,
        packet: [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<(), EndpointError> {
        match self.registry.receive_actor_packet(packet, length, meta) {
            Ok(ActorInboundDisposition::Dropped)
            | Ok(ActorInboundDisposition::Routed)
            | Ok(ActorInboundDisposition::QueueFull) => Ok(()),
            Ok(ActorInboundDisposition::Created(admission)) => {
                let (pending, connection, expected_server_source_id) = (*admission).into_parts();
                let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
                let actor_socket = Arc::clone(&self.socket);
                let actor_cancel = self.cancel_rx.clone();
                #[cfg(not(test))]
                let abort = self.actors.spawn(run_connection_actor(
                    connection,
                    expected_server_source_id,
                    receiver,
                    actor_socket,
                    actor_cancel,
                ));
                #[cfg(test)]
                let abort = match std::mem::replace(&mut self.next_actor_fault, ActorFault::None) {
                    ActorFault::None => self.actors.spawn(run_connection_actor(
                        connection,
                        expected_server_source_id,
                        receiver,
                        actor_socket,
                        actor_cancel,
                    )),
                    ActorFault::Panic => self.actors.spawn(async move {
                        let _owned = (connection, receiver, actor_socket, actor_cancel);
                        panic!("injected endpoint actor panic");
                    }),
                    ActorFault::Stall => self.actors.spawn(async move {
                        let _owned = (connection, receiver, actor_socket, actor_cancel);
                        std::future::pending::<Result<(), ActorError>>().await
                    }),
                };
                let task_id = abort.id();
                #[cfg(test)]
                if self.fail_next_activation {
                    self.fail_next_activation = false;
                    self.unregistered_actor = Some(task_id);
                    abort.abort();
                    return Err(EndpointError::ActorLifecycle);
                }
                if self
                    .registry
                    .activate_actor(pending, sender, task_id)
                    .is_err()
                {
                    self.unregistered_actor = Some(task_id);
                    abort.abort();
                    return Err(EndpointError::ActorLifecycle);
                }
                Ok(())
            }
            Err(
                RegistryError::CapacityUnavailable
                | RegistryError::ConnectionIdUnavailable
                | RegistryError::ConnectionUnavailable
                | RegistryError::ActorUnavailable
                | RegistryError::PacketRejected
                | RegistryError::PacketUnavailable
                | RegistryError::StableConnectionIdUnavailable
                | RegistryError::CloseUnavailable,
            ) => Ok(()),
            Err(RegistryError::ConfigurationUnavailable) => Err(EndpointError::Registry),
        }
    }

    fn reclaim_joined(
        &mut self,
        completion: Result<(Id, Result<(), ActorError>), JoinError>,
    ) -> Result<(), EndpointError> {
        let task_id = match completion {
            Ok((task_id, _)) => task_id,
            Err(error) => error.id(),
        };
        if self.registry.reclaim_joined_actor(task_id).is_some() {
            return Ok(());
        }
        if self.unregistered_actor == Some(task_id) {
            self.unregistered_actor = None;
            return Ok(());
        }
        Err(EndpointError::ActorLifecycle)
    }

    async fn shutdown(&mut self) -> Result<(), EndpointError> {
        let _ = self.cancel_tx.send(true);
        let deadline = Instant::now() + SHUTDOWN_JOIN_BUDGET;
        let mut lifecycle_failed = false;
        let mut exceeded_budget = false;
        while !self.actors.is_empty() {
            match timeout_at(deadline, self.actors.join_next_with_id()).await {
                Ok(Some(completion)) => {
                    lifecycle_failed |= self.reclaim_joined(completion).is_err();
                }
                Ok(None) => {
                    lifecycle_failed = true;
                    break;
                }
                Err(_) => {
                    exceeded_budget = true;
                    break;
                }
            }
        }

        if exceeded_budget || !self.actors.is_empty() {
            self.actors.abort_all();
            while let Some(completion) = self.actors.join_next_with_id().await {
                lifecycle_failed |= self.reclaim_joined(completion).is_err();
            }
        }

        if self.actors.is_empty() {
            self.registry.reclaim_all_joined_actors();
            self.unregistered_actor = None;
        }

        if self.registry.actor_count() != 0
            || !self.actors.is_empty()
            || self.unregistered_actor.is_some()
        {
            return Err(EndpointError::Shutdown);
        }
        if exceeded_budget {
            Err(EndpointError::Shutdown)
        } else if lifecycle_failed {
            Err(EndpointError::ActorLifecycle)
        } else {
            Ok(())
        }
    }
}

fn bounded_received_datagram(
    receive_buffer: &[u8; SOCKET_RECV_BYTES],
    length: usize,
) -> Option<[u8; MAX_PACKET_BYTES]> {
    if length == 0 || length > MAX_PACKET_BYTES {
        return None;
    }
    let mut packet = [0_u8; MAX_PACKET_BYTES];
    packet[..length].copy_from_slice(&receive_buffer[..length]);
    Some(packet)
}

async fn run_connection_actor(
    mut connection: ServerConnection,
    expected_server_source_id: crate::quiche_runtime::ServerSourceConnectionId,
    mut inbox: mpsc::Receiver<ActorPacket>,
    socket: Arc<UdpSocket>,
    mut cancel: watch::Receiver<bool>,
) -> Result<(), ActorError> {
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        verify_stable_source_id(&connection, &expected_server_source_id)?;
        if *cancel.borrow() {
            let _ = connection.close();
            return Err(ActorError::Cancelled);
        }

        let handshake_complete = connection.is_established() && connection.h3_is_ready();
        if !handshake_complete && Instant::now() >= handshake_deadline {
            let _ = connection.close();
            return Err(ActorError::HandshakeTimeout);
        }
        if connection
            .next_timeout()
            .is_some_and(|timeout| timeout.is_zero())
        {
            connection
                .on_timeout()
                .map_err(|_| ActorError::ConnectionUnavailable)?;
            verify_stable_source_id(&connection, &expected_server_source_id)?;
        }

        #[cfg(not(test))]
        let flush = flush_outbound_round(
            &mut connection,
            &expected_server_source_id,
            &socket,
            &mut cancel,
            (!handshake_complete).then_some(handshake_deadline),
        );
        #[cfg(test)]
        let flush = flush_outbound_round(
            &mut connection,
            &expected_server_source_id,
            &socket,
            &mut cancel,
            (!handshake_complete).then_some(handshake_deadline),
            None,
        );
        match flush.await? {
            FlushOutcome::BudgetExhausted => {
                tokio::task::yield_now().await;
                continue;
            }
            FlushOutcome::Drained => {}
            FlushOutcome::HandshakeDeadline => {
                let _ = connection.close();
                return Err(ActorError::HandshakeTimeout);
            }
            FlushOutcome::IdleDeadline => {
                verify_stable_source_id(&connection, &expected_server_source_id)?;
                connection
                    .on_timeout()
                    .map_err(|_| ActorError::ConnectionUnavailable)?;
                verify_stable_source_id(&connection, &expected_server_source_id)?;
                continue;
            }
            FlushOutcome::SendDeadline => return Err(ActorError::SocketSendUnavailable),
        }
        if connection.is_terminating() {
            return Ok(());
        }

        let idle_wait = connection
            .next_timeout()
            .unwrap_or(MAX_IDLE_TIMEOUT)
            .min(MAX_IDLE_TIMEOUT);
        let idle_deadline = Instant::now() + idle_wait;
        let handshake_complete = connection.is_established() && connection.h3_is_ready();
        tokio::select! {
            biased;
            changed = cancel.changed() => {
                let _ = changed;
                let _ = connection.close();
                return Err(ActorError::Cancelled);
            }
            _ = tokio::time::sleep_until(handshake_deadline), if !handshake_complete => {
                let _ = connection.close();
                return Err(ActorError::HandshakeTimeout);
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                verify_stable_source_id(&connection, &expected_server_source_id)?;
                connection
                    .on_timeout()
                    .map_err(|_| ActorError::ConnectionUnavailable)?;
                verify_stable_source_id(&connection, &expected_server_source_id)?;
            }
            inbound = inbox.recv() => {
                let Some(mut inbound) = inbound else {
                    return Err(ActorError::InboxUnavailable);
                };
                verify_stable_source_id(&connection, &expected_server_source_id)?;
                connection
                    .receive_packet(&mut inbound.bytes, inbound.length, inbound.meta)
                    .map_err(|_| ActorError::ConnectionUnavailable)?;
                verify_stable_source_id(&connection, &expected_server_source_id)?;
            }
        }
    }
}

enum FlushOutcome {
    Drained,
    BudgetExhausted,
    HandshakeDeadline,
    IdleDeadline,
    SendDeadline,
}

async fn flush_outbound_round(
    connection: &mut ServerConnection,
    expected_server_source_id: &crate::quiche_runtime::ServerSourceConnectionId,
    socket: &UdpSocket,
    cancel: &mut watch::Receiver<bool>,
    handshake_deadline: Option<Instant>,
    #[cfg(test)] mut test_packets: Option<&mut FlushTestPackets>,
) -> Result<FlushOutcome, ActorError> {
    let mut packet = [0_u8; MAX_PACKET_BYTES];
    let round_send_deadline = Instant::now() + SOCKET_SEND_TIMEOUT;
    for _ in 0..MAX_OUTBOUND_PACKETS_PER_ROUND {
        if *cancel.borrow() {
            return Err(ActorError::Cancelled);
        }
        verify_stable_source_id(connection, expected_server_source_id)?;
        #[cfg(not(test))]
        let output = connection.next_packet(&mut packet);
        #[cfg(test)]
        let output = match test_packets.as_deref_mut() {
            Some(test_packets) => Ok(test_packets.next_packet(&mut packet)),
            None => connection.next_packet(&mut packet),
        };
        let output = output.map_err(|_| ActorError::ConnectionUnavailable)?;
        verify_stable_source_id(connection, expected_server_source_id)?;
        let Some((length, meta)) = output else {
            return Ok(FlushOutcome::Drained);
        };
        let idle_deadline = Instant::now()
            + connection
                .next_timeout()
                .unwrap_or(MAX_IDLE_TIMEOUT)
                .min(MAX_IDLE_TIMEOUT);
        let (effective_deadline, deadline_kind) =
            earliest_flush_deadline(round_send_deadline, handshake_deadline, idle_deadline);
        let send = timeout_at(
            effective_deadline,
            socket.send_to(&packet[..length], meta.to),
        );
        tokio::select! {
            biased;
            changed = cancel.changed() => {
                let _ = changed;
                return Err(ActorError::Cancelled);
            }
            result = send => {
                match result {
                    Ok(Ok(sent)) if sent == length => {}
                    Ok(_) => return Err(ActorError::SocketSendUnavailable),
                    Err(_) => {
                        return Ok(match deadline_kind {
                            FlushDeadlineKind::RoundSend => FlushOutcome::SendDeadline,
                            FlushDeadlineKind::Handshake => FlushOutcome::HandshakeDeadline,
                            FlushDeadlineKind::Idle => FlushOutcome::IdleDeadline,
                        });
                    }
                }
                verify_stable_source_id(connection, expected_server_source_id)?;
            }
        }
    }
    Ok(FlushOutcome::BudgetExhausted)
}

#[cfg(test)]
struct FlushTestPackets {
    remaining: usize,
    emitted: usize,
    meta: PacketMeta,
}

#[cfg(test)]
impl FlushTestPackets {
    fn next_packet(&mut self, packet: &mut [u8; MAX_PACKET_BYTES]) -> Option<(usize, PacketMeta)> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.emitted += 1;
        packet[0] = self.emitted as u8;
        Some((1, self.meta))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FlushDeadlineKind {
    RoundSend,
    Handshake,
    Idle,
}

fn earliest_flush_deadline(
    round_send_deadline: Instant,
    handshake_deadline: Option<Instant>,
    idle_deadline: Instant,
) -> (Instant, FlushDeadlineKind) {
    if let Some(handshake_deadline) = handshake_deadline {
        if handshake_deadline <= idle_deadline && handshake_deadline <= round_send_deadline {
            return (handshake_deadline, FlushDeadlineKind::Handshake);
        }
    }
    if idle_deadline <= round_send_deadline {
        (idle_deadline, FlushDeadlineKind::Idle)
    } else {
        (round_send_deadline, FlushDeadlineKind::RoundSend)
    }
}

fn verify_stable_source_id(
    connection: &ServerConnection,
    expected: &crate::quiche_runtime::ServerSourceConnectionId,
) -> Result<(), ActorError> {
    if connection.has_stable_source_connection_id(expected) {
        Ok(())
    } else {
        Err(ActorError::ConnectionUnavailable)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EndpointError {
    Bind,
    Receive,
    Registry,
    ActorLifecycle,
    Shutdown,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Bind => "server endpoint bind unavailable",
            Self::Receive => "server endpoint receive unavailable",
            Self::Registry => "server endpoint registry unavailable",
            Self::ActorLifecycle => "server endpoint actor unavailable",
            Self::Shutdown => "server endpoint shutdown unavailable",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private server endpoint error")
    }
}

impl std::error::Error for EndpointError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActorError {
    Cancelled,
    HandshakeTimeout,
    InboxUnavailable,
    ConnectionUnavailable,
    SocketSendUnavailable,
}

impl fmt::Display for ActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Cancelled => "server actor cancelled",
            Self::HandshakeTimeout => "server actor handshake timeout",
            Self::InboxUnavailable => "server actor inbox unavailable",
            Self::ConnectionUnavailable => "server actor connection unavailable",
            Self::SocketSendUnavailable => "server actor send unavailable",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for ActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private server actor error")
    }
}

impl std::error::Error for ActorError {}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ActorFault {
    None,
    Panic,
    Stall,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use crate::quiche_registry::{
        ActorAdmission, ActorInboundDisposition, ConnectionRegistry, RegistryError,
    };
    use crate::quiche_runtime::{
        bounded_h3_config, bounded_transport_config, PacketMeta, ServerCredentials,
        MAX_PACKET_BYTES,
    };

    use tokio::task::AbortHandle;
    use tokio::time::timeout;

    use super::*;

    type ActorReceiveFn = fn(
        &mut ConnectionRegistry,
        [u8; MAX_PACKET_BYTES],
        usize,
        PacketMeta,
    ) -> Result<ActorInboundDisposition, RegistryError>;

    struct TestCredentials {
        _directory: tempfile::TempDir,
        certificate_path: PathBuf,
        key_path: PathBuf,
    }

    impl TestCredentials {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create temporary credential directory");
            let certificate_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate local test credential");
            std::fs::write(&certificate_path, certified.cert.pem())
                .expect("write local test certificate");
            std::fs::write(&key_path, certified.key_pair.serialize_pem())
                .expect("write local test key");
            Self {
                _directory: directory,
                certificate_path,
                key_path,
            }
        }

        fn as_server_credentials(&self) -> ServerCredentials<'_> {
            ServerCredentials {
                certificate_chain: &self.certificate_path,
                private_key: &self.key_path,
            }
        }
    }

    #[derive(Clone)]
    struct TestPacket {
        bytes: [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    }

    fn initial_packet(source: SocketAddr, server: SocketAddr, marker: u8) -> TestPacket {
        let mut config = bounded_transport_config().expect("construct bounded client config");
        config.verify_peer(false);
        let source_id = [marker; quiche::MAX_CONN_ID_LEN];
        let source_id = quiche::ConnectionId::from_ref(&source_id);
        let mut client =
            quiche::connect(Some("localhost"), &source_id, source, server, &mut config)
                .expect("construct synthetic client");
        let mut bytes = [0_u8; MAX_PACKET_BYTES];
        let (length, info) = client.send(&mut bytes).expect("create client Initial");
        TestPacket {
            bytes,
            length,
            meta: PacketMeta {
                from: info.from,
                to: info.to,
            },
        }
    }

    fn actor_admission(registry: &mut ConnectionRegistry, packet: TestPacket) -> ActorAdmission {
        match registry
            .receive_actor_packet(packet.bytes, packet.length, packet.meta)
            .expect("admit actor Initial")
        {
            ActorInboundDisposition::Created(admission) => *admission,
            _ => panic!("Initial must create one actor admission"),
        }
    }

    fn activate_paused_actor(
        registry: &mut ConnectionRegistry,
        actors: &mut JoinSet<Result<(), ActorError>>,
        admission: ActorAdmission,
    ) -> (AbortHandle, mpsc::Receiver<ActorPacket>) {
        let (pending_route, connection, expected_source_id) = admission.into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let abort = actors.spawn(async move {
            let _owned = (connection, expected_source_id);
            std::future::pending::<Result<(), ActorError>>().await
        });
        registry
            .activate_actor(pending_route, sender, abort.id())
            .expect("activate paused actor route");
        (abort, receiver)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ObservedConnectionId {
        bytes: [u8; quiche::MAX_CONN_ID_LEN],
        length: usize,
    }

    struct UdpQuicheClient {
        socket: UdpSocket,
        local_address: SocketAddr,
        server_address: SocketAddr,
        connection: quiche::Connection,
        h3: Option<quiche::h3::Connection>,
        server_source_id: Option<ObservedConnectionId>,
    }

    impl UdpQuicheClient {
        async fn new(source_ip: Ipv4Addr, server_address: SocketAddr, marker: u8) -> Self {
            let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(source_ip), 0))
                .await
                .expect("bind local UDP client");
            let local_address = socket.local_addr().expect("read local UDP client address");
            let mut config = bounded_transport_config().expect("construct bounded client config");
            config.verify_peer(false);
            let source_id = [marker; quiche::MAX_CONN_ID_LEN];
            let source_id = quiche::ConnectionId::from_ref(&source_id);
            let connection = quiche::connect(
                Some("localhost"),
                &source_id,
                local_address,
                server_address,
                &mut config,
            )
            .expect("construct UDP quiche client");
            Self {
                socket,
                local_address,
                server_address,
                connection,
                h3: None,
                server_source_id: None,
            }
        }

        async fn send_pending(&mut self) {
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            for _ in 0..64 {
                match self.connection.send(&mut packet) {
                    Ok((length, info)) => {
                        assert_eq!(info.from, self.local_address);
                        assert_eq!(info.to, self.server_address);
                        let sent = self
                            .socket
                            .send_to(&packet[..length], info.to)
                            .await
                            .expect("send local QUIC packet");
                        assert_eq!(sent, length);
                    }
                    Err(quiche::Error::Done) => return,
                    Err(_) => panic!("local QUIC packet unavailable"),
                }
            }
            panic!("client outbound work exceeded test bound");
        }

        async fn receive_available(&mut self) {
            let mut packet = [0_u8; SOCKET_RECV_BYTES];
            let first = timeout(
                Duration::from_millis(25),
                self.socket.recv_from(&mut packet),
            )
            .await;
            let Ok(Ok((length, source))) = first else {
                return;
            };
            self.receive_one(&mut packet, length, source);
            for _ in 0..64 {
                match self.socket.try_recv_from(&mut packet) {
                    Ok((length, source)) => self.receive_one(&mut packet, length, source),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                    Err(_) => panic!("receive local QUIC packet"),
                }
            }
            panic!("client inbound work exceeded test bound");
        }

        fn receive_one(
            &mut self,
            packet: &mut [u8; SOCKET_RECV_BYTES],
            length: usize,
            source: SocketAddr,
        ) {
            assert_eq!(source, self.server_address);
            if self.server_source_id.is_none() {
                let header =
                    quiche::Header::from_slice(&mut packet[..length], quiche::MAX_CONN_ID_LEN)
                        .expect("parse server QUIC header");
                let mut bytes = [0_u8; quiche::MAX_CONN_ID_LEN];
                bytes[..header.scid.len()].copy_from_slice(header.scid.as_ref());
                self.server_source_id = Some(ObservedConnectionId {
                    bytes,
                    length: header.scid.len(),
                });
            }
            self.connection
                .recv(
                    &mut packet[..length],
                    quiche::RecvInfo {
                        from: source,
                        to: self.local_address,
                    },
                )
                .expect("receive server QUIC packet");
        }

        fn prepare_h3(&mut self) {
            if self.connection.is_established() && self.h3.is_none() {
                let config = bounded_h3_config().expect("construct bounded H3 client config");
                self.h3 = Some(
                    quiche::h3::Connection::with_transport(&mut self.connection, &config)
                        .expect("construct H3 client"),
                );
            }
        }
    }

    async fn drive_two_clients_to_h3(first: &mut UdpQuicheClient, second: &mut UdpQuicheClient) {
        timeout(Duration::from_secs(5), async {
            let mut ready_rounds = 0_usize;
            for _ in 0..128 {
                first.send_pending().await;
                second.send_pending().await;
                first.receive_available().await;
                second.receive_available().await;
                first.prepare_h3();
                second.prepare_h3();
                if first.h3.is_some() && second.h3.is_some() {
                    ready_rounds += 1;
                    if ready_rounds == 2 {
                        return;
                    }
                }
            }
            panic!("two UDP clients did not reach H3 within step bound");
        })
        .await
        .expect("drive two UDP clients within wall bound");
    }

    #[test]
    fn endpoint_actor_contract_has_exact_bounds() {
        assert_eq!(ACTOR_INBOX_CAPACITY, 4);
        assert_eq!(SOCKET_RECV_BYTES, 1_351);
        assert_eq!(MAX_OUTBOUND_PACKETS_PER_ROUND, 16);
        assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 5);
        assert_eq!(MAX_IDLE_TIMEOUT.as_secs(), 5);
        assert_eq!(SOCKET_SEND_TIMEOUT.as_secs(), 2);
        assert_eq!(SHUTDOWN_JOIN_BUDGET.as_secs(), 2);
    }

    #[test]
    fn registry_has_one_shot_actor_ownership_handoff() {
        let receive_actor_packet: ActorReceiveFn = ConnectionRegistry::receive_actor_packet;
        let _ = receive_actor_packet;
    }

    #[test]
    fn receive_buffer_rejects_oversize_and_accepts_exact_boundary() {
        let mut receive_buffer = [0_u8; SOCKET_RECV_BYTES];
        receive_buffer[..MAX_PACKET_BYTES].fill(0x5a);
        let packet = bounded_received_datagram(&receive_buffer, MAX_PACKET_BYTES)
            .expect("accept exact packet boundary");
        assert!(packet.iter().all(|byte| *byte == 0x5a));
        assert!(bounded_received_datagram(&receive_buffer, SOCKET_RECV_BYTES).is_none());
        assert!(bounded_received_datagram(&receive_buffer, 0).is_none());
    }

    #[test]
    fn admitted_quiche_idle_timer_is_present_and_capped_at_five_seconds() {
        let credentials = TestCredentials::new();
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_101);
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_102);
        let (_pending, connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0x21)).into_parts();
        assert!(connection.has_stable_source_connection_id(&expected));
        assert!(connection
            .next_timeout()
            .is_some_and(|timeout| timeout <= MAX_IDLE_TIMEOUT));
    }

    #[tokio::test]
    async fn real_loopback_udp_routes_two_clients_to_distinct_h3_connections_after_oversize() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.as_server_credentials())
            .await
            .expect("bind local endpoint");
        let server_address = endpoint.local_address;
        let mut first = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0x31).await;
        let mut second = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0x32).await;

        let client_work = async move {
            let oversize = [0x44_u8; SOCKET_RECV_BYTES];
            let boundary = [0x45_u8; MAX_PACKET_BYTES];
            assert_eq!(
                first
                    .socket
                    .send_to(&oversize, server_address)
                    .await
                    .expect("send oversize local datagram"),
                SOCKET_RECV_BYTES
            );
            assert_eq!(
                first
                    .socket
                    .send_to(&boundary, server_address)
                    .await
                    .expect("send boundary local datagram"),
                MAX_PACKET_BYTES
            );
            drive_two_clients_to_h3(&mut first, &mut second).await;
            let first_server_source_id = first
                .server_source_id
                .expect("observe first server source ID");
            let second_server_source_id = second
                .server_source_id
                .expect("observe second server source ID");
            assert_eq!(first_server_source_id.length, quiche::MAX_CONN_ID_LEN);
            assert_eq!(second_server_source_id.length, quiche::MAX_CONN_ID_LEN);
            assert_ne!(first_server_source_id, second_server_source_id);
            cancel.send(true).expect("cancel local endpoint");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("run and stop local endpoint");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
    }

    #[tokio::test]
    async fn actor_dispatch_requires_exact_address_and_fifth_packet_is_queue_full() {
        let credentials = TestCredentials::new();
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_001);
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_002);
        let initial = initial_packet(source, server, 0x41);
        let admission = actor_admission(&mut registry, initial.clone());
        let mut actors = JoinSet::new();
        let (abort, mut receiver) = activate_paused_actor(&mut registry, &mut actors, admission);

        let mut wrong_address = initial.clone();
        wrong_address.meta.from.set_port(source.port() + 1);
        assert!(matches!(
            registry
                .receive_actor_packet(
                    wrong_address.bytes,
                    wrong_address.length,
                    wrong_address.meta,
                )
                .expect("drop wrong-address packet"),
            ActorInboundDisposition::Dropped
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        for _ in 0..ACTOR_INBOX_CAPACITY {
            assert!(matches!(
                registry
                    .receive_actor_packet(initial.bytes, initial.length, initial.meta)
                    .expect("route packet into bounded actor inbox"),
                ActorInboundDisposition::Routed
            ));
        }
        assert!(matches!(
            registry
                .receive_actor_packet(initial.bytes, initial.length, initial.meta)
                .expect("drop fifth packet without waiting"),
            ActorInboundDisposition::QueueFull
        ));
        assert_eq!(registry.actor_count(), 1);

        abort.abort();
        assert_eq!(registry.actor_count(), 1, "abort is not a join");
        let completion = actors
            .join_next_with_id()
            .await
            .expect("join aborted actor");
        let task_id = completion.expect_err("actor was aborted").id();
        assert_eq!(
            registry.actor_count(),
            1,
            "join alone does not reclaim route"
        );
        assert!(registry.reclaim_joined_actor(task_id).is_some());
        assert_eq!(registry.actor_count(), 0);
    }

    #[tokio::test]
    async fn ended_actor_holds_source_capacity_until_join_then_slot_is_reusable() {
        let credentials = TestCredentials::new();
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44_002);
        let source_one = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44_011);
        let source_two = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44_012);
        let source_three = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44_013);
        let first = initial_packet(source_one, server, 0x51);
        let second = initial_packet(source_two, server, 0x52);
        let third = initial_packet(source_three, server, 0x53);
        let mut actors = JoinSet::new();

        let (pending, connection, expected) = actor_admission(&mut registry, first).into_parts();
        let (sender, _receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let finished = actors.spawn(async move {
            let _owned = (connection, expected);
            Ok(())
        });
        registry
            .activate_actor(pending, sender, finished.id())
            .expect("activate normally exiting actor");
        let second_admission = actor_admission(&mut registry, second);
        let (second_abort, _second_receiver) =
            activate_paused_actor(&mut registry, &mut actors, second_admission);
        tokio::task::yield_now().await;
        assert_eq!(registry.actor_count(), 2);
        assert!(matches!(
            registry.receive_actor_packet(third.bytes, third.length, third.meta),
            Err(RegistryError::CapacityUnavailable)
        ));

        let completion = actors
            .join_next_with_id()
            .await
            .expect("join normally exited actor")
            .expect("actor did not panic");
        assert_eq!(completion.0, finished.id());
        assert_eq!(registry.actor_count(), 2);
        assert!(registry.reclaim_joined_actor(completion.0).is_some());
        assert_eq!(registry.actor_count(), 1);
        assert!(matches!(
            registry
                .receive_actor_packet(third.bytes, third.length, third.meta)
                .expect("reuse source capacity after joined reclaim"),
            ActorInboundDisposition::Created(_)
        ));

        second_abort.abort();
        let completion = actors.join_next_with_id().await.expect("join second actor");
        let task_id = completion.expect_err("second actor was aborted").id();
        assert!(registry.reclaim_joined_actor(task_id).is_some());
        assert_eq!(registry.actor_count(), 0);
    }

    #[tokio::test]
    async fn run_activation_error_finishes_cleanup() {
        let credentials = TestCredentials::new();
        let (mut activation_endpoint, _cancel) =
            Endpoint::bind_test(credentials.as_server_credentials())
                .await
                .expect("bind activation-error endpoint");
        activation_endpoint.fail_next_activation = true;
        let server_address = activation_endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0x61).await;
        let send_initial = async move { client.send_pending().await };
        let (result, ()) = tokio::join!(activation_endpoint.run(), send_initial);
        assert_eq!(result, Err(EndpointError::ActorLifecycle));
        assert_eq!(activation_endpoint.registry.actor_count(), 0);
        assert!(activation_endpoint.actors.is_empty());
        assert!(activation_endpoint.unregistered_actor.is_none());
    }

    #[tokio::test]
    async fn run_joins_actor_panic_before_shutdown_finishes() {
        let credentials = TestCredentials::new();
        let (mut panic_endpoint, panic_cancel) =
            Endpoint::bind_test(credentials.as_server_credentials())
                .await
                .expect("bind panic endpoint");
        panic_endpoint.next_actor_fault = ActorFault::Panic;
        let panic_address = panic_endpoint.local_address;
        let mut panic_client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, panic_address, 0x62).await;
        let panic_work = async move {
            panic_client.send_pending().await;
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            panic_cancel.send(true).expect("cancel panic endpoint");
        };
        let (result, ()) = tokio::join!(panic_endpoint.run(), panic_work);
        result.expect("panic is joined and cleaned before endpoint shutdown");
        assert_eq!(panic_endpoint.registry.actor_count(), 0);
        assert!(panic_endpoint.actors.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_deadline_aborts_stuck_actor_then_drains_and_reclaims() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.as_server_credentials())
            .await
            .expect("bind stuck-actor endpoint");
        endpoint.next_actor_fault = ActorFault::Stall;
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_001);
        let packet = initial_packet(source, endpoint.local_address, 0x71);
        endpoint
            .route_datagram(packet.bytes, packet.length, packet.meta)
            .expect("activate stuck actor through endpoint route");
        assert_eq!(endpoint.registry.actor_count(), 1);
        cancel.send(true).expect("cancel stuck-actor endpoint");

        let started = Instant::now();
        assert_eq!(endpoint.run().await, Err(EndpointError::Shutdown));
        assert!(Instant::now().duration_since(started) >= SHUTDOWN_JOIN_BUDGET);
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert!(endpoint.unregistered_actor.is_none());
    }

    #[tokio::test]
    async fn global_actor_cap_is_eight_and_joined_cleanup_restores_all_slots() {
        let credentials = TestCredentials::new();
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 46_002);
        let mut actors = JoinSet::new();
        let mut aborts = Vec::with_capacity(crate::quiche_registry::MAX_ACTIVE_CONNECTIONS);
        for index in 0..crate::quiche_registry::MAX_ACTIVE_CONNECTIONS {
            let source_ip = Ipv4Addr::new(127, 0, 0, 1 + (index / 2) as u8);
            let source = SocketAddr::new(IpAddr::V4(source_ip), 46_100 + index as u16);
            let packet = initial_packet(source, server, 0x80 + index as u8);
            let admission = actor_admission(&mut registry, packet);
            let (abort, _receiver) = activate_paused_actor(&mut registry, &mut actors, admission);
            aborts.push(abort);
        }
        assert_eq!(
            registry.actor_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS
        );
        let ninth = initial_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 46_200),
            server,
            0x90,
        );
        assert!(matches!(
            registry.receive_actor_packet(ninth.bytes, ninth.length, ninth.meta),
            Err(RegistryError::CapacityUnavailable)
        ));

        for abort in aborts {
            abort.abort();
        }
        assert_eq!(
            registry.actor_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS
        );
        while let Some(completion) = actors.join_next_with_id().await {
            let task_id = completion.expect_err("paused actor was aborted").id();
            assert!(registry.reclaim_joined_actor(task_id).is_some());
        }
        assert_eq!(registry.actor_count(), 0);
    }

    #[tokio::test]
    async fn panicked_actor_keeps_route_until_join_error_id_is_reclaimed() {
        let credentials = TestCredentials::new();
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47_001);
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47_002);
        let (pending, connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0x91)).into_parts();
        let (sender, _receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let mut actors = JoinSet::new();
        let abort = actors.spawn(async move {
            let _owned = (connection, expected);
            panic!("injected registry actor panic");
        });
        registry
            .activate_actor(pending, sender, abort.id())
            .expect("activate panic actor");
        tokio::task::yield_now().await;
        assert_eq!(registry.actor_count(), 1);
        let error = actors
            .join_next_with_id()
            .await
            .expect("join panic actor")
            .expect_err("actor panicked");
        assert_eq!(registry.actor_count(), 1, "panic is not a joined reclaim");
        assert!(registry.reclaim_joined_actor(error.id()).is_some());
        assert_eq!(registry.actor_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_wall_deadline_is_live_at_4999ms_and_fires_at_5s() {
        let credentials = TestCredentials::new();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind actor server socket"),
        );
        let client_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind actor client socket");
        let server = server_socket
            .local_addr()
            .expect("read actor server address");
        let source = client_socket
            .local_addr()
            .expect("read actor client address");
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let (_pending, connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0xa1)).into_parts();
        let (_sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            server_socket,
            cancel_rx,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(4_999)).await;
        tokio::task::yield_now().await;
        assert!(!actor.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        let error = actor
            .await
            .expect("join handshake-timeout actor")
            .expect_err("handshake must hit wall deadline");
        assert_eq!(error, ActorError::HandshakeTimeout);
        drop(client_socket);
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_is_checked_before_handshake_queue_and_timer_work() {
        let credentials = TestCredentials::new();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind actor server socket"),
        );
        let client_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind actor client socket");
        let server = server_socket
            .local_addr()
            .expect("read actor server address");
        let source = client_socket
            .local_addr()
            .expect("read actor client address");
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let (_pending, connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0xa2)).into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        for index in 0..ACTOR_INBOX_CAPACITY {
            sender
                .try_send(ActorPacket {
                    bytes: [index as u8; MAX_PACKET_BYTES],
                    length: MAX_PACKET_BYTES,
                    meta: PacketMeta {
                        from: source,
                        to: server,
                    },
                })
                .expect("fill actor queue");
        }
        cancel_tx.send(true).expect("cancel actor before it runs");
        let started = Instant::now();
        let error = run_connection_actor(connection, expected, receiver, server_socket, cancel_rx)
            .await
            .expect_err("cancelled actor exits");
        assert_eq!(error, ActorError::Cancelled);
        assert_eq!(Instant::now(), started);
        drop(client_socket);
    }

    #[tokio::test]
    async fn seventeen_outbound_packets_stop_at_sixteen_then_cancel_prevents_last_send() {
        let credentials = TestCredentials::new();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind flush server socket"),
        );
        let client_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind flush client socket");
        let server = server_socket
            .local_addr()
            .expect("read flush server address");
        let source = client_socket
            .local_addr()
            .expect("read flush client address");
        let mut registry = ConnectionRegistry::new(credentials.as_server_credentials())
            .expect("construct actor registry");
        let (_pending, mut connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0xa3)).into_parts();
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let mut packets = FlushTestPackets {
            remaining: 17,
            emitted: 0,
            meta: PacketMeta {
                from: server,
                to: source,
            },
        };

        let outcome = flush_outbound_round(
            &mut connection,
            &expected,
            &server_socket,
            &mut cancel_rx,
            None,
            Some(&mut packets),
        )
        .await
        .expect("flush first bounded round");
        assert!(matches!(outcome, FlushOutcome::BudgetExhausted));
        assert_eq!(packets.emitted, MAX_OUTBOUND_PACKETS_PER_ROUND);
        assert_eq!(packets.remaining, 1);

        let mut received = 0_usize;
        let mut byte = [0_u8; 1];
        timeout(Duration::from_secs(1), async {
            while received < MAX_OUTBOUND_PACKETS_PER_ROUND {
                let (length, peer) = client_socket
                    .recv_from(&mut byte)
                    .await
                    .expect("receive bounded flush packet");
                assert_eq!(length, 1);
                assert_eq!(peer, server);
                received += 1;
            }
        })
        .await
        .expect("receive sixteen packets within bound");

        cancel_tx
            .send(true)
            .expect("cancel before next flush round");
        let result = flush_outbound_round(
            &mut connection,
            &expected,
            &server_socket,
            &mut cancel_rx,
            None,
            Some(&mut packets),
        )
        .await;
        assert!(matches!(result, Err(ActorError::Cancelled)));
        assert_eq!(packets.remaining, 1);
        assert_eq!(packets.emitted, MAX_OUTBOUND_PACKETS_PER_ROUND);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_flush_uses_earliest_protocol_or_round_deadline() {
        let started = Instant::now();
        let handshake = started + Duration::from_millis(100);
        let idle = started + MAX_IDLE_TIMEOUT;
        let round = started + SOCKET_SEND_TIMEOUT;
        let (deadline, kind) = earliest_flush_deadline(round, Some(handshake), idle);
        assert!(matches!(kind, FlushDeadlineKind::Handshake));
        assert!(timeout_at(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert_eq!(
            Instant::now().duration_since(started),
            Duration::from_millis(100)
        );

        let started = Instant::now();
        let idle = started + Duration::from_millis(75);
        let round = started + SOCKET_SEND_TIMEOUT;
        let (deadline, kind) = earliest_flush_deadline(round, None, idle);
        assert!(matches!(kind, FlushDeadlineKind::Idle));
        assert!(timeout_at(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert_eq!(
            Instant::now().duration_since(started),
            Duration::from_millis(75)
        );

        let started = Instant::now();
        let round = started + SOCKET_SEND_TIMEOUT;
        let (deadline, kind) = earliest_flush_deadline(round, None, started + MAX_IDLE_TIMEOUT);
        assert!(matches!(kind, FlushDeadlineKind::RoundSend));
        assert!(timeout_at(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert_eq!(Instant::now().duration_since(started), SOCKET_SEND_TIMEOUT);
    }

    #[test]
    fn endpoint_and_actor_errors_are_fixed_private_and_source_free() {
        let endpoint_errors = [
            EndpointError::Bind,
            EndpointError::Receive,
            EndpointError::Registry,
            EndpointError::ActorLifecycle,
            EndpointError::Shutdown,
        ];
        for error in endpoint_errors {
            assert_eq!(format!("{error:?}"), "private server endpoint error");
            assert!(std::error::Error::source(&error).is_none());
            assert!(!error.to_string().contains("127."));
            assert!(!error.to_string().contains(':'));
        }
        let actor_errors = [
            ActorError::Cancelled,
            ActorError::HandshakeTimeout,
            ActorError::InboxUnavailable,
            ActorError::ConnectionUnavailable,
            ActorError::SocketSendUnavailable,
        ];
        for error in actor_errors {
            assert_eq!(format!("{error:?}"), "private server actor error");
            assert!(std::error::Error::source(&error).is_none());
            assert!(!error.to_string().contains("127."));
            assert!(!error.to_string().contains(':'));
        }
    }

    #[test]
    fn ownership_and_bounded_source_shape_has_no_shared_connection_or_unbounded_queue() {
        fn assert_send<T: Send>() {}
        assert_send::<ServerConnection>();
        assert_send::<ActorPacket>();

        let endpoint_source = include_str!("quiche_endpoint.rs");
        let production_endpoint = endpoint_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production endpoint source");
        let registry_source = include_str!("quiche_registry.rs");
        for forbidden in [
            ["Arc<", "Mutex<ServerConnection"].concat(),
            ["Arc<", "Mutex<HashMap"].concat(),
            ["mpsc::", "unbounded"].concat(),
            ["tokio::", "spawn("].concat(),
        ] {
            assert!(!production_endpoint.contains(&forbidden));
            assert!(!registry_source.contains(&forbidden));
        }
        assert!(production_endpoint.contains("mpsc::channel(ACTOR_INBOX_CAPACITY)"));
        assert!(production_endpoint.contains("JoinSet<Result<(), ActorError>>"));
        assert!(production_endpoint.contains("for _ in 0..MAX_OUTBOUND_PACKETS_PER_ROUND"));
        assert!(production_endpoint.contains("tokio::task::yield_now().await"));
        assert!(registry_source.contains("sender.try_send(ActorPacket"));
    }
}
