//! Private bounded local UDP endpoint for native-quiche server actors.
//!
//! The endpoint owns the only receive loop, CID registry, and actor `JoinSet`.
//! Each actor receives one `ServerConnection` by value and never shares it.
//! This module has no authentication, CONNECT parser, target, DNS, opener,
//! relay, public API, or non-loopback binding seam.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use maverick_core::config::ServerRoleConfig;
use tokio::net::UdpSocket;
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::{mpsc, watch};
use tokio::task::{Id, JoinError, JoinSet};
use tokio::time::{timeout_at, Instant};

use crate::quiche_registry::{
    ActorInboundDisposition, ActorPacket, ConnectionRegistry, RegistryError,
};
#[cfg(test)]
use crate::quiche_runtime::AUTH_WALL_TIMEOUT;
use crate::quiche_runtime::{
    ConnectionLifecycle, FrozenDirectV3ServerRole, PacketMeta, ServerConnection, MAX_PACKET_BYTES,
};

const ACTOR_INBOX_CAPACITY: usize = 4;
const SOCKET_RECV_BYTES: usize = MAX_PACKET_BYTES + 1;
const MAX_OUTBOUND_PACKETS_PER_ROUND: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const ACTOR_TERMINATION_BUDGET: Duration = Duration::from_millis(1_500);
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
    #[cfg(test)]
    next_actor_test_gate: Option<Arc<ActorTestGate>>,
}

impl Endpoint {
    async fn bind(owner: Arc<ServerRoleConfig>) -> Result<Self, EndpointError> {
        let role = FrozenDirectV3ServerRole::new(owner).map_err(|_| EndpointError::Role)?;
        let listen = role.listen();
        if !listen.ip().is_loopback() {
            return Err(EndpointError::Bind);
        }
        let registry = ConnectionRegistry::new(role).map_err(|_| EndpointError::Registry)?;
        let socket = UdpSocket::bind(listen)
            .await
            .map_err(|_| EndpointError::Bind)?;
        let local_address = socket.local_addr().map_err(|_| EndpointError::Bind)?;
        if !local_address.ip().is_loopback() || local_address.port() == 0 {
            return Err(EndpointError::Bind);
        }
        let (cancel_tx, cancel_rx) = watch::channel(false);
        Ok(Self {
            socket: Arc::new(socket),
            local_address,
            registry,
            actors: JoinSet::new(),
            unregistered_actor: None,
            cancel_tx,
            cancel_rx,
            #[cfg(test)]
            fail_next_activation: false,
            #[cfg(test)]
            next_actor_fault: ActorFault::None,
            #[cfg(test)]
            next_actor_test_gate: None,
        })
    }

    #[cfg(test)]
    async fn bind_test(
        owner: Arc<ServerRoleConfig>,
    ) -> Result<(Self, watch::Sender<bool>), EndpointError> {
        let endpoint = Self::bind(owner).await?;
        let cancel = endpoint.cancel_tx.clone();
        Ok((endpoint, cancel))
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
                    if let Err(error) = self.reclaim_joined(completion) {
                        break Err(error);
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
                        self.next_actor_test_gate.take(),
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
        let (task_id, termination_timed_out) = match completion {
            Ok((task_id, Err(ActorError::TerminationTimeout))) => (task_id, true),
            Ok((task_id, _)) => (task_id, false),
            Err(error) => (error.id(), false),
        };
        if self.registry.reclaim_joined_actor(task_id).is_some() {
            return if termination_timed_out {
                Err(EndpointError::Shutdown)
            } else {
                Ok(())
            };
        }
        if self.unregistered_actor == Some(task_id) {
            self.unregistered_actor = None;
            return if termination_timed_out {
                Err(EndpointError::Shutdown)
            } else {
                Ok(())
            };
        }
        Err(EndpointError::ActorLifecycle)
    }

    async fn shutdown(&mut self) -> Result<(), EndpointError> {
        let _ = self.cancel_tx.send(true);
        let deadline = Instant::now() + SHUTDOWN_JOIN_BUDGET;
        let mut lifecycle_failed = false;
        let mut exceeded_budget = false;
        let mut forced_reclaim = false;
        while !self.actors.is_empty() {
            match timeout_at(deadline, self.actors.join_next_with_id()).await {
                Ok(Some(completion)) => match self.reclaim_joined(completion) {
                    Ok(()) => {}
                    Err(EndpointError::Shutdown) => forced_reclaim = true,
                    Err(_) => lifecycle_failed = true,
                },
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
                match self.reclaim_joined(completion) {
                    Ok(()) => {}
                    Err(EndpointError::Shutdown) => forced_reclaim = true,
                    Err(_) => lifecycle_failed = true,
                }
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
        if exceeded_budget || forced_reclaim {
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
    #[cfg(test)] test_gate: Option<Arc<ActorTestGate>>,
) -> Result<(), ActorError> {
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut terminal_error = None;
    let mut termination_deadline = None;
    loop {
        verify_stable_source_id(&connection, &expected_server_source_id)?;
        #[cfg(test)]
        if let Some(test_gate) = test_gate.as_deref() {
            test_gate.observe_pre_auth_foundation(
                connection.is_established(),
                connection.pre_auth_foundation_ready(),
            );
        }
        if connection.lifecycle() == ConnectionLifecycle::Closed {
            return terminal_error.map_or(Ok(()), Err);
        }
        if termination_deadline.is_none() && *cancel.borrow() {
            begin_actor_termination(
                &mut connection,
                &mut terminal_error,
                &mut termination_deadline,
                Some(ActorError::Cancelled),
            );
        }

        let handshake_complete =
            connection.is_established() && connection.pre_auth_foundation_ready();
        if termination_deadline.is_none()
            && !handshake_complete
            && Instant::now() >= handshake_deadline
        {
            begin_actor_termination(
                &mut connection,
                &mut terminal_error,
                &mut termination_deadline,
                Some(ActorError::HandshakeTimeout),
            );
        }
        let lifecycle_before_flush = connection.lifecycle();
        let immediate_timeout = timeout_may_precede_flush(lifecycle_before_flush)
            && connection
                .next_timeout()
                .is_some_and(|timeout| timeout.is_zero());
        if immediate_timeout {
            if connection.on_timeout().is_err() {
                begin_actor_termination(
                    &mut connection,
                    &mut terminal_error,
                    &mut termination_deadline,
                    Some(ActorError::ConnectionUnavailable),
                );
            }
            verify_stable_source_id(&connection, &expected_server_source_id)?;
        }

        if connection.lifecycle() == ConnectionLifecycle::Closed {
            continue;
        }
        if connection.lifecycle() == ConnectionLifecycle::Draining && termination_deadline.is_none()
        {
            begin_actor_termination(
                &mut connection,
                &mut terminal_error,
                &mut termination_deadline,
                None,
            );
        }

        let should_flush = connection.lifecycle() != ConnectionLifecycle::Draining;
        if should_flush {
            let handshake_flush_deadline = (termination_deadline.is_none() && !handshake_complete)
                .then_some(handshake_deadline);
            let flush_control = FlushControl {
                honor_cancel: termination_deadline.is_none(),
                handshake_deadline: handshake_flush_deadline,
                termination_deadline,
            };
            #[cfg(not(test))]
            let flush = flush_outbound_round(
                &mut connection,
                &expected_server_source_id,
                &socket,
                &mut cancel,
                flush_control,
            );
            #[cfg(test)]
            let flush = flush_outbound_round(
                &mut connection,
                &expected_server_source_id,
                &socket,
                &mut cancel,
                flush_control,
                FlushTestHooks {
                    packets: None,
                    actor_gate: test_gate.as_deref(),
                },
            );
            match flush.await {
                Ok(FlushOutcome::BudgetExhausted) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(FlushOutcome::Drained) => {}
                Ok(FlushOutcome::HandshakeDeadline) => {
                    begin_actor_termination(
                        &mut connection,
                        &mut terminal_error,
                        &mut termination_deadline,
                        Some(ActorError::HandshakeTimeout),
                    );
                    continue;
                }
                Ok(FlushOutcome::IdleDeadline) => {
                    verify_stable_source_id(&connection, &expected_server_source_id)?;
                    if connection.on_timeout().is_err() {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::ConnectionUnavailable),
                        );
                    }
                    verify_stable_source_id(&connection, &expected_server_source_id)?;
                    continue;
                }
                Ok(FlushOutcome::TerminationDeadline) => {
                    return Err(ActorError::TerminationTimeout);
                }
                Ok(FlushOutcome::SendDeadline) => {
                    begin_actor_termination(
                        &mut connection,
                        &mut terminal_error,
                        &mut termination_deadline,
                        Some(ActorError::SocketSendUnavailable),
                    );
                    continue;
                }
                Err(error) => {
                    begin_actor_termination(
                        &mut connection,
                        &mut terminal_error,
                        &mut termination_deadline,
                        Some(error),
                    );
                    continue;
                }
            }
        }

        if connection.lifecycle() != ConnectionLifecycle::Active && termination_deadline.is_none() {
            begin_actor_termination(
                &mut connection,
                &mut terminal_error,
                &mut termination_deadline,
                None,
            );
        }
        if connection.lifecycle() == ConnectionLifecycle::Closed {
            continue;
        }

        let protocol_wait = connection
            .next_timeout()
            .unwrap_or(MAX_IDLE_TIMEOUT)
            .min(MAX_IDLE_TIMEOUT);
        let protocol_deadline = Instant::now() + protocol_wait;
        let handshake_complete =
            connection.is_established() && connection.pre_auth_foundation_ready();
        let (actor_deadline, actor_deadline_kind) = earliest_actor_deadline(
            protocol_deadline,
            (termination_deadline.is_none() && !handshake_complete).then_some(handshake_deadline),
            termination_deadline,
        );
        #[cfg(test)]
        if connection.lifecycle() == ConnectionLifecycle::ClosingPendingSend {
            if let Some(test_gate) = test_gate.as_deref() {
                test_gate.observe_pending_close_wait();
            }
        }
        #[cfg(test)]
        if connection.lifecycle() == ConnectionLifecycle::Draining {
            if let Some(test_gate) = test_gate.as_deref() {
                test_gate.pause_draining_wait_once_if_armed().await;
            }
        }
        tokio::select! {
            biased;
            changed = cancel.changed(), if termination_deadline.is_none() => {
                let _ = changed;
                begin_actor_termination(
                    &mut connection,
                    &mut terminal_error,
                    &mut termination_deadline,
                    Some(ActorError::Cancelled),
                );
            }
            _ = tokio::time::sleep_until(actor_deadline) => {
                match actor_deadline_kind {
                    ActorDeadlineKind::Termination => {
                        return Err(ActorError::TerminationTimeout);
                    }
                    ActorDeadlineKind::Handshake => {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::HandshakeTimeout),
                        );
                    }
                    ActorDeadlineKind::Protocol => {
                        verify_stable_source_id(&connection, &expected_server_source_id)?;
                        if connection.on_timeout().is_err() {
                            begin_actor_termination(
                                &mut connection,
                                &mut terminal_error,
                                &mut termination_deadline,
                                Some(ActorError::ConnectionUnavailable),
                            );
                        }
                        verify_stable_source_id(&connection, &expected_server_source_id)?;
                    }
                }
            }
            inbound = inbox.recv() => {
                match inbound {
                    Some(mut inbound) => {
                        verify_stable_source_id(&connection, &expected_server_source_id)?;
                        if connection
                            .receive_packet(&mut inbound.bytes, inbound.length, inbound.meta)
                            .is_err()
                        {
                            begin_actor_termination(
                                &mut connection,
                                &mut terminal_error,
                                &mut termination_deadline,
                                Some(ActorError::ConnectionUnavailable),
                            );
                        }
                        verify_stable_source_id(&connection, &expected_server_source_id)?;
                    }
                    None => {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::InboxUnavailable),
                        );
                    }
                }
            }
        }
    }
}

fn timeout_may_precede_flush(lifecycle: ConnectionLifecycle) -> bool {
    matches!(
        lifecycle,
        ConnectionLifecycle::Active | ConnectionLifecycle::Draining
    )
}

fn begin_actor_termination(
    connection: &mut ServerConnection,
    terminal_error: &mut Option<ActorError>,
    termination_deadline: &mut Option<Instant>,
    error: Option<ActorError>,
) {
    let handshake_timed_out = error == Some(ActorError::HandshakeTimeout);
    if let Some(error) = error {
        terminal_error.get_or_insert(error);
    }
    if termination_deadline.is_none() {
        *termination_deadline = Some(Instant::now() + ACTOR_TERMINATION_BUDGET);
    }
    if connection.lifecycle() == ConnectionLifecycle::Active {
        let close = if handshake_timed_out {
            connection.reject_pre_auth()
        } else {
            connection.close()
        };
        if close.is_err() {
            terminal_error.get_or_insert(ActorError::ConnectionUnavailable);
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ActorDeadlineKind {
    Protocol,
    Handshake,
    Termination,
}

fn earliest_actor_deadline(
    protocol_deadline: Instant,
    handshake_deadline: Option<Instant>,
    termination_deadline: Option<Instant>,
) -> (Instant, ActorDeadlineKind) {
    if let Some(termination_deadline) = termination_deadline {
        if termination_deadline <= protocol_deadline {
            return (termination_deadline, ActorDeadlineKind::Termination);
        }
    }
    if let Some(handshake_deadline) = handshake_deadline {
        if handshake_deadline <= protocol_deadline {
            return (handshake_deadline, ActorDeadlineKind::Handshake);
        }
    }
    (protocol_deadline, ActorDeadlineKind::Protocol)
}

enum FlushOutcome {
    Drained,
    BudgetExhausted,
    HandshakeDeadline,
    IdleDeadline,
    TerminationDeadline,
    SendDeadline,
}

#[derive(Clone, Copy)]
struct FlushControl {
    honor_cancel: bool,
    handshake_deadline: Option<Instant>,
    termination_deadline: Option<Instant>,
}

async fn flush_outbound_round(
    connection: &mut ServerConnection,
    expected_server_source_id: &crate::quiche_runtime::ServerSourceConnectionId,
    socket: &UdpSocket,
    cancel: &mut watch::Receiver<bool>,
    control: FlushControl,
    #[cfg(test)] mut test_hooks: FlushTestHooks<'_>,
) -> Result<FlushOutcome, ActorError> {
    let mut packet = [0_u8; MAX_PACKET_BYTES];
    let round_send_deadline = Instant::now() + SOCKET_SEND_TIMEOUT;
    for _ in 0..MAX_OUTBOUND_PACKETS_PER_ROUND {
        if control.honor_cancel && *cancel.borrow() {
            return Err(ActorError::Cancelled);
        }
        verify_stable_source_id(connection, expected_server_source_id)?;
        #[cfg(not(test))]
        let output = connection.next_packet(&mut packet);
        #[cfg(test)]
        let output = match test_hooks.packets.as_deref_mut() {
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
        let (effective_deadline, deadline_kind) = earliest_flush_deadline(
            round_send_deadline,
            control.handshake_deadline,
            idle_deadline,
            control.termination_deadline,
        );
        let send = timeout_at(
            effective_deadline,
            socket.send_to(&packet[..length], meta.to),
        );
        #[cfg(test)]
        if let Some(actor_gate) = test_hooks.actor_gate {
            actor_gate.pause_once_if_armed().await;
        }
        tokio::select! {
            biased;
            changed = cancel.changed(), if control.honor_cancel => {
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
                            FlushDeadlineKind::Termination => FlushOutcome::TerminationDeadline,
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
struct FlushTestHooks<'a> {
    packets: Option<&'a mut FlushTestPackets>,
    actor_gate: Option<&'a ActorTestGate>,
}

#[cfg(test)]
struct FlushTestPackets {
    remaining: usize,
    emitted: usize,
    meta: PacketMeta,
}

#[cfg(test)]
#[derive(Default)]
struct ActorTestGate {
    send_armed: AtomicBool,
    send_started: Notify,
    release_send: Notify,
    pending_close_wait: Notify,
    draining_wait_armed: AtomicBool,
    draining_wait_started: Notify,
    release_draining_wait: Notify,
    established_without_foundation: AtomicBool,
}

#[cfg(test)]
impl ActorTestGate {
    fn arm_send(&self) {
        assert!(!self.send_armed.swap(true, Ordering::SeqCst));
    }

    async fn pause_once_if_armed(&self) {
        if self.send_armed.swap(false, Ordering::SeqCst) {
            self.send_started.notify_one();
            self.release_send.notified().await;
        }
    }

    fn release(&self) {
        self.release_send.notify_one();
    }

    fn observe_pending_close_wait(&self) {
        self.pending_close_wait.notify_one();
    }

    fn arm_draining_wait(&self) {
        assert!(!self.draining_wait_armed.swap(true, Ordering::SeqCst));
    }

    async fn pause_draining_wait_once_if_armed(&self) {
        if self.draining_wait_armed.swap(false, Ordering::SeqCst) {
            self.draining_wait_started.notify_one();
            self.release_draining_wait.notified().await;
        }
    }

    fn release_draining_wait(&self) {
        self.release_draining_wait.notify_one();
    }

    fn observe_pre_auth_foundation(&self, established: bool, foundation_ready: bool) {
        if established && !foundation_ready {
            self.established_without_foundation
                .store(true, Ordering::Release);
        }
    }

    fn saw_established_without_foundation(&self) -> bool {
        self.established_without_foundation.load(Ordering::Acquire)
    }
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
    Termination,
}

fn earliest_flush_deadline(
    round_send_deadline: Instant,
    handshake_deadline: Option<Instant>,
    idle_deadline: Instant,
    termination_deadline: Option<Instant>,
) -> (Instant, FlushDeadlineKind) {
    if let Some(termination_deadline) = termination_deadline {
        if termination_deadline <= idle_deadline && termination_deadline <= round_send_deadline {
            return (termination_deadline, FlushDeadlineKind::Termination);
        }
    }
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
    Role,
    Bind,
    Receive,
    Registry,
    ActorLifecycle,
    Shutdown,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Role => "server endpoint role unavailable",
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
    TerminationTimeout,
    InboxUnavailable,
    ConnectionUnavailable,
    SocketSendUnavailable,
}

impl fmt::Display for ActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Cancelled => "server actor cancelled",
            Self::HandshakeTimeout => "server actor handshake timeout",
            Self::TerminationTimeout => "server actor termination timeout",
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
        bounded_h3_config, bounded_transport_config, FrozenDirectV3ServerRole, PacketMeta,
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

        fn server_role(&self) -> Arc<ServerRoleConfig> {
            self.server_role_with("h3", "localhost", &self.certificate_path, &self.key_path)
        }

        fn server_role_with(
            &self,
            transport_strategy: &str,
            expected_authority: &str,
            certificate_path: &std::path::Path,
            key_path: &std::path::Path,
        ) -> Arc<ServerRoleConfig> {
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
      credential_epoch: 7
      credential_not_after_unix: 1800172800
      secret: "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
"#,
                certificate_path.display(),
                key_path.display(),
            );
            Arc::new(ServerRoleConfig::from_yaml_str(&yaml).expect("parse synthetic server role"))
        }

        fn frozen_role(&self) -> FrozenDirectV3ServerRole {
            FrozenDirectV3ServerRole::new(self.server_role()).expect("freeze synthetic server role")
        }

        fn legacy_server_role(
            &self,
            certificate_path: &std::path::Path,
            key_path: &std::path::Path,
        ) -> Arc<ServerRoleConfig> {
            let yaml = format!(
                r#"version: 1
listen: "127.0.0.1:0"
tls:
  cert_path: "{}"
  key_path: "{}"
maverick:
  tunnel_path: "/legacy"
users:
  - id: "legacy-user"
    secret: "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
fallback:
  type: static
  static_dir: "./public"
"#,
                certificate_path.display(),
                key_path.display(),
            );
            Arc::new(ServerRoleConfig::from_yaml_str(&yaml).expect("parse synthetic legacy role"))
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

    async fn drive_client_to_h3(client: &mut UdpQuicheClient) {
        timeout(Duration::from_secs(5), async {
            let mut ready_rounds = 0_usize;
            for _ in 0..128 {
                client.send_pending().await;
                client.receive_available().await;
                client.prepare_h3();
                if client.h3.is_some() {
                    ready_rounds += 1;
                    if ready_rounds == 2 {
                        return;
                    }
                }
            }
            panic!("UDP client did not reach H3 within step bound");
        })
        .await
        .expect("drive UDP client within wall bound");
    }

    async fn drive_endpoint_client_to_h3(endpoint: &mut Endpoint, client: &mut UdpQuicheClient) {
        timeout(Duration::from_secs(5), async {
            let mut ready_rounds = 0_usize;
            for _ in 0..128 {
                client.send_pending().await;
                route_available_client_datagrams(endpoint).await;
                client.receive_available().await;
                client.prepare_h3();
                if client.h3.is_some() {
                    ready_rounds += 1;
                    if ready_rounds == 2 {
                        return;
                    }
                }
            }
            panic!("manually driven endpoint client did not reach H3");
        })
        .await
        .expect("drive manual endpoint client within wall bound");
    }

    async fn route_available_client_datagrams(endpoint: &mut Endpoint) {
        let mut receive_buffer = [0_u8; SOCKET_RECV_BYTES];
        let first = timeout(
            Duration::from_millis(25),
            endpoint.socket.recv_from(&mut receive_buffer),
        )
        .await;
        let Ok(Ok((length, source))) = first else {
            return;
        };
        route_one_client_datagram(endpoint, &receive_buffer, length, source);
        for _ in 0..64 {
            match endpoint.socket.try_recv_from(&mut receive_buffer) {
                Ok((length, source)) => {
                    route_one_client_datagram(endpoint, &receive_buffer, length, source);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(_) => panic!("receive manual endpoint datagram"),
            }
        }
        panic!("manual endpoint inbound work exceeded test bound");
    }

    fn route_one_client_datagram(
        endpoint: &mut Endpoint,
        receive_buffer: &[u8; SOCKET_RECV_BYTES],
        length: usize,
        source: SocketAddr,
    ) {
        let packet = bounded_received_datagram(receive_buffer, length)
            .expect("manual endpoint receives bounded datagram");
        endpoint
            .route_datagram(
                packet,
                length,
                PacketMeta {
                    from: source,
                    to: endpoint.local_address,
                },
            )
            .expect("route manual endpoint datagram");
    }

    #[test]
    fn endpoint_actor_contract_has_exact_bounds() {
        assert_eq!(ACTOR_INBOX_CAPACITY, 4);
        assert_eq!(SOCKET_RECV_BYTES, 1_351);
        assert_eq!(MAX_OUTBOUND_PACKETS_PER_ROUND, 16);
        assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 5);
        assert_eq!(AUTH_WALL_TIMEOUT.as_secs(), 10);
        assert_eq!(MAX_IDLE_TIMEOUT.as_secs(), 5);
        assert_eq!(SOCKET_SEND_TIMEOUT.as_secs(), 2);
        assert_eq!(ACTOR_TERMINATION_BUDGET.as_millis(), 1_500);
        assert!(ACTOR_TERMINATION_BUDGET < SHUTDOWN_JOIN_BUDGET);
        assert_eq!(SHUTDOWN_JOIN_BUDGET.as_secs(), 2);
    }

    #[tokio::test]
    async fn t027b2b2_1_role_gate_precedes_certificate_read_and_udp_bind() {
        let credentials = TestCredentials::new();
        let missing_certificate = credentials._directory.path().join("missing-cert.pem");
        let missing_key = credentials._directory.path().join("missing-key.pem");
        let legacy = credentials.legacy_server_role(&missing_certificate, &missing_key);
        let direct_h2 =
            credentials.server_role_with("h2", "localhost", &missing_certificate, &missing_key);

        for owner in [legacy, direct_h2] {
            let error = match Endpoint::bind(owner).await {
                Ok(_) => panic!("non-H3 server role must be rejected before I/O"),
                Err(error) => error,
            };
            assert_eq!(error, EndpointError::Role);
            assert_eq!(error.to_string(), "server endpoint role unavailable");
        }

        let valid_h3 = credentials.server_role();
        let endpoint = Endpoint::bind(valid_h3)
            .await
            .expect("validated config-v3 H3 role enters local foundation");
        assert!(endpoint.local_address.ip().is_loopback());
        assert_ne!(endpoint.local_address.port(), 0);
    }

    #[tokio::test]
    async fn t027b2b2_1_same_arc_owner_reaches_registry_and_admitted_connection() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let mut endpoint = Endpoint::bind(Arc::clone(&owner))
            .await
            .expect("bind local endpoint from frozen role");
        assert!(endpoint.registry.test_has_role_owner(&owner));

        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_201);
        let packet = initial_packet(source, endpoint.local_address, 0x2a);
        let (_pending, connection, _expected) =
            actor_admission(&mut endpoint.registry, packet).into_parts();
        assert!(connection.has_role_owner(&owner));
        assert!(endpoint.registry.test_has_role_owner(&owner));
    }

    #[test]
    fn pending_local_close_is_flushed_before_any_immediate_transport_timeout() {
        assert!(!timeout_may_precede_flush(
            ConnectionLifecycle::ClosingPendingSend
        ));
        assert!(timeout_may_precede_flush(ConnectionLifecycle::Active));
        assert!(timeout_may_precede_flush(ConnectionLifecycle::Draining));
        assert!(!timeout_may_precede_flush(ConnectionLifecycle::Closed));
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
        let (mut activation_endpoint, _cancel) = Endpoint::bind_test(credentials.server_role())
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
        let (mut panic_endpoint, panic_cancel) = Endpoint::bind_test(credentials.server_role())
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
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
            None,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(4_999)).await;
        tokio::task::yield_now().await;
        assert!(!actor.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !actor.is_finished(),
            "handshake failure first enters bounded closing"
        );
        tokio::time::advance(ACTOR_TERMINATION_BUDGET).await;
        let error = actor
            .await
            .expect("join bounded-closing actor")
            .expect_err("paused transport clock reaches the hard termination boundary");
        assert_eq!(error, ActorError::TerminationTimeout);
        drop(client_socket);
    }

    #[tokio::test]
    async fn t027b2b2_1_established_quic_without_peer_settings_hits_five_second_deadline() {
        let credentials = TestCredentials::new();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind actor server socket"),
        );
        let server_address = server_socket
            .local_addr()
            .expect("read actor server address");
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xa9).await;

        let mut initial_bytes = [0_u8; MAX_PACKET_BYTES];
        let (initial_length, initial_info) = client
            .connection
            .send(&mut initial_bytes)
            .expect("create live client Initial");
        let initial = TestPacket {
            bytes: initial_bytes,
            length: initial_length,
            meta: PacketMeta {
                from: initial_info.from,
                to: initial_info.to,
            },
        };
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
        let (_pending, connection, expected) = actor_admission(&mut registry, initial).into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let test_gate = Arc::new(ActorTestGate::default());
        let started = Instant::now();
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            Arc::clone(&server_socket),
            cancel_rx,
            Some(Arc::clone(&test_gate)),
        ));

        let mut close_observed_at = None;
        let mut client_established = false;
        let actor_result = timeout(Duration::from_secs(8), async {
            loop {
                let mut routed = 0_usize;
                loop {
                    let mut bytes = [0_u8; MAX_PACKET_BYTES];
                    match client.connection.send(&mut bytes) {
                        Ok((length, info)) => {
                            sender
                                .send(ActorPacket {
                                    bytes,
                                    length,
                                    meta: PacketMeta {
                                        from: info.from,
                                        to: info.to,
                                    },
                                })
                                .await
                                .expect("route live client packet into bounded actor inbox");
                            routed += 1;
                            assert!(routed <= 64, "client send work remains bounded");
                        }
                        Err(quiche::Error::Done) => break,
                        Err(_) => panic!("live client packet unavailable"),
                    }
                }
                client.receive_available().await;
                if close_observed_at.is_none() && client.connection.peer_error().is_some() {
                    close_observed_at = Some(Instant::now().duration_since(started));
                }
                client_established |= client.connection.is_established();
                assert!(
                    client.h3.is_none(),
                    "client deliberately sends no HTTP/3 SETTINGS"
                );
                if actor.is_finished() {
                    break actor.await.expect("join settings-wait actor");
                }
                if client_established
                    && test_gate.saw_established_without_foundation()
                    && client.connection.peer_error().is_none()
                {
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("keep established QUIC live without H3 SETTINGS");
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("settings-wait actor remains bounded");
        assert!(client_established, "live client QUIC reached established");
        assert!(
            test_gate.saw_established_without_foundation(),
            "live server QUIC established while peer SETTINGS stayed absent"
        );
        assert!(matches!(
            actor_result,
            Ok(()) | Err(ActorError::HandshakeTimeout) | Err(ActorError::TerminationTimeout)
        ));
        let close_observed_at = close_observed_at.expect("deadline close reaches real peer");
        assert!(close_observed_at >= HANDSHAKE_TIMEOUT);
        assert!(close_observed_at < HANDSHAKE_TIMEOUT + ACTOR_TERMINATION_BUDGET);
        assert!(Instant::now().duration_since(started) < Duration::from_secs(8));
        let peer_error = client
            .connection
            .peer_error()
            .expect("deadline close reaches real peer");
        assert!(peer_error.is_app);
        assert_eq!(peer_error.error_code, 0x105);
        assert!(peer_error.reason.is_empty());
    }

    #[tokio::test]
    async fn cancel_flushes_close_to_established_real_peer_before_actor_reclaim() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
            .await
            .expect("bind cancel endpoint");
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xa2).await;

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            cancel.send(true).expect("cancel established endpoint");
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    if client.connection.peer_error().is_some() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancel close reaches real peer within one second");
            let peer_error = client
                .connection
                .peer_error()
                .expect("cancel close carries a real CONNECTION_CLOSE");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, 0);
            assert!(peer_error.reason.is_empty());
            assert!(
                client.connection.is_draining() || client.connection.is_closed(),
                "real peer enters QUIC termination"
            );
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("cancel endpoint joins every connection actor");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert!(endpoint.unregistered_actor.is_none());
    }

    #[tokio::test]
    async fn t027b2b2_2_auth_wall_flushes_105_and_reclaims_real_actor() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
            .await
            .expect("bind auth-wall endpoint");
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xb2).await;

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            let started = Instant::now();
            timeout(AUTH_WALL_TIMEOUT + Duration::from_secs(3), async {
                loop {
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("pre-auth activity remains bounded");
                    client.send_pending().await;
                    client.receive_available().await;
                    if client.connection.peer_error().is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("absolute auth wall closes despite continuing activity");
            let elapsed = Instant::now().duration_since(started);
            assert!(elapsed >= AUTH_WALL_TIMEOUT - Duration::from_secs(1));
            assert!(elapsed < AUTH_WALL_TIMEOUT + ACTOR_TERMINATION_BUDGET);
            let peer_error = client
                .connection
                .peer_error()
                .expect("real peer receives auth-wall close");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, 0x105);
            assert!(peer_error.reason.is_empty());
            cancel.send(true).expect("stop endpoint after actor close");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("auth-wall endpoint reclaims its actor");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert!(endpoint.unregistered_actor.is_none());
    }

    #[tokio::test]
    async fn cancel_during_in_flight_flush_restarts_close_flush_before_waiting() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
            .await
            .expect("bind in-flight cancel endpoint");
        let send_gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&send_gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xa6).await;

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            send_gate.arm_send();
            client
                .connection
                .send_ack_eliciting()
                .expect("schedule real ack-eliciting client packet");
            client.send_pending().await;
            timeout(Duration::from_secs(1), send_gate.send_started.notified())
                .await
                .expect("actor reaches controlled in-flight send");

            cancel
                .send(true)
                .expect("cancel while real actor send is in flight");
            send_gate.release();

            let close_reaches_peer = timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    if client.connection.peer_error().is_some() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            });
            tokio::select! {
                biased;
                _ = send_gate.pending_close_wait.notified() => {
                    panic!("actor waited with a pending local close before flushing it");
                }
                result = close_reaches_peer => {
                    result.expect("in-flight cancellation close reaches real peer");
                }
            }

            let peer_error = client
                .connection
                .peer_error()
                .expect("in-flight cancellation carries a real CONNECTION_CLOSE");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, 0);
            assert!(peer_error.reason.is_empty());
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("in-flight cancellation joins every connection actor");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert!(endpoint.unregistered_actor.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pre_key_cancel_uses_hard_closing_deadline_without_hanging() {
        let credentials = TestCredentials::new();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind pre-key server socket"),
        );
        let client_socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind pre-key client socket");
        let server = server_socket
            .local_addr()
            .expect("read pre-key server address");
        let source = client_socket
            .local_addr()
            .expect("read pre-key client address");
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct pre-key registry");
        let (_pending, connection, expected) =
            actor_admission(&mut registry, initial_packet(source, server, 0xa4)).into_parts();
        let (_sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        cancel_tx.send(true).expect("cancel pre-key actor");
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            server_socket,
            cancel_rx,
            None,
        ));

        tokio::task::yield_now().await;
        assert!(!actor.is_finished(), "pre-key cancel enters closing");
        tokio::time::advance(ACTOR_TERMINATION_BUDGET - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !actor.is_finished(),
            "pre-key closing remains live before its hard deadline"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let error = actor
            .await
            .expect("join pre-key cancelled actor")
            .expect_err("pre-key cancel reaches its hard closing boundary");
        assert_eq!(error, ActorError::TerminationTimeout);
    }

    #[tokio::test(start_paused = true)]
    async fn endpoint_reports_pre_key_forced_reclaim_after_draining_joinset() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) = Endpoint::bind_test(credentials.server_role())
            .await
            .expect("bind pre-key endpoint");
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 48_001);
        let initial = initial_packet(source, endpoint.local_address, 0xa5);
        endpoint
            .route_datagram(initial.bytes, initial.length, initial.meta)
            .expect("activate pre-key endpoint actor");
        assert_eq!(endpoint.registry.actor_count(), 1);
        cancel.send(true).expect("cancel pre-key endpoint");

        let started = Instant::now();
        assert_eq!(endpoint.run().await, Err(EndpointError::Shutdown));
        assert_eq!(
            Instant::now().duration_since(started),
            ACTOR_TERMINATION_BUDGET
        );
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert!(endpoint.unregistered_actor.is_none());
    }

    #[tokio::test]
    async fn peer_draining_holds_actor_routes_and_source_capacity_until_closed_join() {
        let credentials = TestCredentials::new();
        let (mut endpoint, _cancel) = Endpoint::bind_test(credentials.server_role())
            .await
            .expect("bind peer-draining endpoint");
        let test_gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&test_gate));
        let server_address = endpoint.local_address;
        let mut closing_client =
            UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xb1).await;
        drive_endpoint_client_to_h3(&mut endpoint, &mut closing_client).await;
        assert_eq!(endpoint.registry.actor_count(), 1);

        let second_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 48_011);
        let third_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 48_012);
        let second = initial_packet(second_source, server_address, 0xb2);
        endpoint
            .route_datagram(second.bytes, second.length, second.meta)
            .expect("activate second same-source-IP actor");
        assert_eq!(endpoint.registry.actor_count(), 2);

        closing_client
            .connection
            .close(true, 0x44, b"")
            .expect("peer requests application close");
        test_gate.arm_draining_wait();
        closing_client.send_pending().await;
        let mut close_datagram = [0_u8; SOCKET_RECV_BYTES];
        let (close_length, close_source) = timeout(
            Duration::from_secs(1),
            endpoint.socket.recv_from(&mut close_datagram),
        )
        .await
        .expect("peer close reaches endpoint socket")
        .expect("receive peer close datagram");
        let close_packet = bounded_received_datagram(&close_datagram, close_length)
            .expect("peer close datagram is bounded");
        assert!(matches!(
            endpoint.registry.receive_actor_packet(
                close_packet,
                close_length,
                PacketMeta {
                    from: close_source,
                    to: endpoint.local_address,
                },
            ),
            Ok(ActorInboundDisposition::Routed)
        ));
        timeout(
            Duration::from_secs(1),
            test_gate.draining_wait_started.notified(),
        )
        .await
        .expect("actor observes draining before its real timer wait");
        assert_eq!(endpoint.registry.actor_count(), 2);
        assert_eq!(endpoint.registry.test_route_count(), 4);
        assert_eq!(endpoint.registry.test_source_count(close_source), 2);

        let third = initial_packet(third_source, server_address, 0xb3);
        assert!(matches!(
            endpoint
                .registry
                .receive_actor_packet(third.bytes, third.length, third.meta,),
            Err(RegistryError::CapacityUnavailable)
        ));

        for index in 0..(crate::quiche_registry::MAX_ACTIVE_CONNECTIONS - 2) {
            let source = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2 + index as u8)),
                48_100 + index as u16,
            );
            let filler = initial_packet(source, server_address, 0xc0 + index as u8);
            endpoint
                .route_datagram(filler.bytes, filler.length, filler.meta)
                .expect("fill remaining global actor capacity");
        }
        assert_eq!(
            endpoint.registry.actor_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS
        );
        assert_eq!(
            endpoint.registry.test_route_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS * 2
        );
        let overflow_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 250)), 48_250);
        let overflow = initial_packet(overflow_source, server_address, 0xcf);
        assert!(matches!(
            endpoint
                .registry
                .receive_actor_packet(overflow.bytes, overflow.length, overflow.meta,),
            Err(RegistryError::CapacityUnavailable)
        ));

        test_gate.release_draining_wait();
        let completion = timeout(SHUTDOWN_JOIN_BUDGET, endpoint.actors.join_next_with_id())
            .await
            .expect("peer draining reaches its real protocol timer")
            .expect("peer-draining actor joins")
            .expect("peer-draining actor does not panic");
        completion
            .1
            .expect("peer-draining actor reaches transport closed naturally");
        assert_eq!(
            endpoint.registry.actor_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS,
            "join is not reclaim"
        );
        assert_eq!(
            endpoint.registry.test_route_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS * 2
        );
        assert!(matches!(
            endpoint
                .registry
                .receive_actor_packet(overflow.bytes, overflow.length, overflow.meta,),
            Err(RegistryError::CapacityUnavailable)
        ));
        assert!(endpoint
            .registry
            .reclaim_joined_actor(completion.0)
            .is_some());
        assert_eq!(
            endpoint.registry.actor_count(),
            crate::quiche_registry::MAX_ACTIVE_CONNECTIONS - 1
        );
        assert_eq!(
            endpoint.registry.test_route_count(),
            (crate::quiche_registry::MAX_ACTIVE_CONNECTIONS - 1) * 2
        );
        assert_eq!(endpoint.registry.test_source_count(close_source), 1);
        assert!(matches!(
            endpoint
                .registry
                .receive_actor_packet(overflow.bytes, overflow.length, overflow.meta,),
            Ok(ActorInboundDisposition::Created(_))
        ));
        assert!(matches!(
            endpoint
                .registry
                .receive_actor_packet(third.bytes, third.length, third.meta,),
            Ok(ActorInboundDisposition::Created(_))
        ));

        assert_eq!(endpoint.shutdown().await, Err(EndpointError::Shutdown));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
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
        let mut registry =
            ConnectionRegistry::new(credentials.frozen_role()).expect("construct actor registry");
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
            FlushControl {
                honor_cancel: true,
                handshake_deadline: None,
                termination_deadline: None,
            },
            FlushTestHooks {
                packets: Some(&mut packets),
                actor_gate: None,
            },
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
            FlushControl {
                honor_cancel: true,
                handshake_deadline: None,
                termination_deadline: None,
            },
            FlushTestHooks {
                packets: Some(&mut packets),
                actor_gate: None,
            },
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
        let (deadline, kind) = earliest_flush_deadline(round, Some(handshake), idle, None);
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
        let (deadline, kind) = earliest_flush_deadline(round, None, idle, None);
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
        let (deadline, kind) =
            earliest_flush_deadline(round, None, started + MAX_IDLE_TIMEOUT, None);
        assert!(matches!(kind, FlushDeadlineKind::RoundSend));
        assert!(timeout_at(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert_eq!(Instant::now().duration_since(started), SOCKET_SEND_TIMEOUT);

        let started = Instant::now();
        let termination = started + Duration::from_millis(50);
        let (deadline, kind) =
            earliest_actor_deadline(started + MAX_IDLE_TIMEOUT, None, Some(termination));
        assert!(matches!(kind, ActorDeadlineKind::Termination));
        assert!(timeout_at(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert_eq!(
            Instant::now().duration_since(started),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn endpoint_and_actor_errors_are_fixed_private_and_source_free() {
        let endpoint_errors = [
            EndpointError::Role,
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
            ActorError::TerminationTimeout,
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
