//! Private bounded local UDP endpoint for native-quiche server actors.
//!
//! The endpoint owns the only receive loop, CID registry, and actor `JoinSet`.
//! Each actor receives one `ServerConnection` by value and never shares it.
//! Production dispatch may open one policy-approved IP-literal target before
//! the token's whole-attempt deadline. Domain targets remain representable but
//! fail closed before system resolution. After synchronous handoff into the
//! originating `ServerConnection` slot, the actor can borrow that slot's
//! independent target read or write readiness while the connection moves
//! bounded DATA in both directions. The actor creates no second socket owner,
//! relay task, channel, or target collection.
//! This module exposes no public API or non-loopback binding seam.

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use maverick_core::config::ServerRoleConfig;
#[cfg(test)]
use tokio::net::{TcpListener, TcpSocket};
use tokio::net::{TcpStream, UdpSocket};
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
    ConnectionLifecycle, FrozenDirectV3ServerRole, PacketMeta, ServerConnection,
    TargetOpenDispatchToken, MAX_PACKET_BYTES, MAX_TARGET_DISPATCH_FUTURES,
};
use crate::relay::{self, TargetOpenMetricSinks};
use crate::runtime_metrics::ServerRuntimeMetrics;

const ACTOR_INBOX_CAPACITY: usize = 4;
const SOCKET_RECV_BYTES: usize = MAX_PACKET_BYTES + 1;
const MAX_OUTBOUND_PACKETS_PER_ROUND: usize = 16;
const MAX_READY_TARGET_COMPLETIONS_PER_ROUND: usize = 4;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const ACTOR_TERMINATION_BUDGET: Duration = Duration::from_millis(1_500);
const SHUTDOWN_JOIN_BUDGET: Duration = Duration::from_secs(2);

struct Endpoint {
    socket: Arc<UdpSocket>,
    local_address: SocketAddr,
    metrics_owner: Arc<ServerRuntimeMetrics>,
    target_open_sinks: TargetOpenMetricSinks,
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
    #[cfg(test)]
    tracked_actor_test_gate: Option<(Id, Arc<ActorTestGate>)>,
}

impl Endpoint {
    async fn bind(
        role_owner: Arc<ServerRoleConfig>,
        metrics_owner: Arc<ServerRuntimeMetrics>,
    ) -> Result<Self, EndpointError> {
        let role = FrozenDirectV3ServerRole::new(role_owner).map_err(|_| EndpointError::Role)?;
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
        let target_open_sinks = metrics_owner.target_open_sinks();
        Ok(Self {
            socket: Arc::new(socket),
            local_address,
            metrics_owner,
            target_open_sinks,
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
            #[cfg(test)]
            tracked_actor_test_gate: None,
        })
    }

    #[cfg(test)]
    async fn bind_test(
        role_owner: Arc<ServerRoleConfig>,
        metrics_owner: Arc<ServerRuntimeMetrics>,
    ) -> Result<(Self, watch::Sender<bool>), EndpointError> {
        let endpoint = Self::bind(role_owner, metrics_owner).await?;
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
                let actor_target_open_sinks = self.target_open_sinks.clone();
                #[cfg(not(test))]
                let abort = self.actors.spawn(run_connection_actor(
                    connection,
                    expected_server_source_id,
                    receiver,
                    actor_socket,
                    actor_cancel,
                    actor_target_open_sinks,
                ));
                #[cfg(test)]
                let actor_test_gate = self.next_actor_test_gate.take();
                #[cfg(test)]
                let tracked_actor_test_gate = actor_test_gate.clone();
                #[cfg(test)]
                let abort = match std::mem::replace(&mut self.next_actor_fault, ActorFault::None) {
                    ActorFault::None => self.actors.spawn(run_connection_actor(
                        connection,
                        expected_server_source_id,
                        receiver,
                        actor_socket,
                        actor_cancel,
                        actor_target_open_sinks,
                        actor_test_gate,
                    )),
                    ActorFault::Panic => self.actors.spawn(async move {
                        let _owned = (
                            connection,
                            receiver,
                            actor_socket,
                            actor_cancel,
                            actor_target_open_sinks,
                        );
                        panic!("injected endpoint actor panic");
                    }),
                    ActorFault::Stall => self.actors.spawn(async move {
                        let _owned = (
                            connection,
                            receiver,
                            actor_socket,
                            actor_cancel,
                            actor_target_open_sinks,
                        );
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
                #[cfg(test)]
                if let Some(test_gate) = tracked_actor_test_gate {
                    self.tracked_actor_test_gate = Some((task_id, test_gate));
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
        #[cfg(test)]
        self.observe_actor_join_before_reclaim(task_id);
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

    #[cfg(test)]
    fn observe_actor_join_before_reclaim(&mut self, task_id: Id) {
        if self
            .tracked_actor_test_gate
            .as_ref()
            .is_some_and(|(tracked, _)| *tracked == task_id)
        {
            let (_, test_gate) = self
                .tracked_actor_test_gate
                .take()
                .expect("tracked actor gate is present");
            test_gate.observe_parent_join_before_reclaim();
        }
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
    target_open_sinks: TargetOpenMetricSinks,
    #[cfg(test)] test_gate: Option<Arc<ActorTestGate>>,
) -> Result<(), ActorError> {
    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut terminal_error = None;
    let mut termination_deadline = None;
    let mut target_futures = TargetDispatchFutures::new(target_open_sinks);
    let mut target_io_signal = None;
    let result = async {
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
            #[cfg(test)]
            if termination_deadline.is_none() {
                if let Some(test_gate) = test_gate.as_deref() {
                    if test_gate.revoke_requested.swap(false, Ordering::AcqRel) {
                        let _ = connection.revoke_authenticated_generation();
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::TargetDispatchUnavailable),
                        );
                    } else if test_gate
                        .hard_expiry_requested
                        .swap(false, Ordering::AcqRel)
                    {
                        let _ = connection.expire_authenticated_generation_for_test();
                    } else if test_gate
                        .local_close_requested
                        .swap(false, Ordering::AcqRel)
                    {
                        let _ = connection.close();
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            None,
                        );
                    }
                }
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
            if termination_deadline.is_some() {
                target_futures.clear();
            }

            if termination_deadline.is_none() && connection.is_authenticated() {
                for _ in 0..MAX_TARGET_DISPATCH_FUTURES {
                    let token =
                        match connection.take_target_open_dispatch(std::time::Instant::now()) {
                            Ok(Some(token)) => token,
                            Ok(None) => break,
                            Err(_) => {
                                begin_actor_termination(
                                    &mut connection,
                                    &mut terminal_error,
                                    &mut termination_deadline,
                                    Some(ActorError::TargetDispatchUnavailable),
                                );
                                target_futures.clear();
                                break;
                            }
                        };
                    if target_futures
                        .push(
                            token,
                            #[cfg(test)]
                            test_gate.clone(),
                        )
                        .is_err()
                    {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::TargetDispatchUnavailable),
                        );
                        target_futures.clear();
                        break;
                    }
                }
            }

            let mut ready_completions = 0;
            for _ in 0..MAX_READY_TARGET_COMPLETIONS_PER_ROUND {
                let Some(completion) = target_futures.try_next_ready() else {
                    break;
                };
                ready_completions += 1;
                if termination_deadline.is_none()
                    && handle_target_dispatch_completion(
                        &mut connection,
                        completion,
                        #[cfg(test)]
                        test_gate.as_deref(),
                    )
                    .is_err()
                {
                    begin_actor_termination(
                        &mut connection,
                        &mut terminal_error,
                        &mut termination_deadline,
                        Some(ActorError::TargetDispatchUnavailable),
                    );
                    target_futures.clear();
                    break;
                }
            }
            #[cfg(test)]
            if let Some(test_gate) = test_gate.as_deref() {
                test_gate.observe_ready_completion_round(ready_completions);
                if ready_completions != 0 {
                    test_gate.observe_target_future_queue(target_futures.is_empty());
                }
                assert!(
                    !test_gate.take_parent_panic_request(),
                    "injected fixed connection actor panic"
                );
                if test_gate.take_parent_stall_request() {
                    test_gate.observe_parent_stall_started();
                    std::future::pending::<()>().await;
                }
            }
            if termination_deadline.is_none() && connection.is_authenticated() {
                #[cfg(test)]
                if let Some(test_gate) = test_gate.as_deref() {
                    if test_gate.take_target_write_saturation_request() {
                        connection
                            .saturate_pending_upload_target_for_test()
                            .expect("saturate the original target socket to real WouldBlock");
                        test_gate.observe_target_write_saturation();
                    }
                }
                let ready_signal = target_io_signal.take();
                let target_data_round = connection.drive_target_io_round(ready_signal);
                #[cfg(test)]
                if let (Ok(round), Some(test_gate)) = (&target_data_round, test_gate.as_deref()) {
                    test_gate.observe_target_data_round(
                        round.operations(),
                        round.progress_operations(),
                        round.upload_recv_progress_mask(),
                        round.target_write_progress_mask(),
                        round.target_write_blocked_mask(),
                        round.target_shutdown_progress_mask(),
                    );
                }
                if target_data_round.is_err() {
                    begin_actor_termination(
                        &mut connection,
                        &mut terminal_error,
                        &mut termination_deadline,
                        Some(ActorError::TargetDataUnavailable),
                    );
                    target_futures.clear();
                }
                #[cfg(test)]
                if let Some(test_gate) = test_gate.as_deref() {
                    test_gate.pause_target_data_round_once_if_armed().await;
                }
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
            if connection.lifecycle() == ConnectionLifecycle::Draining
                && termination_deadline.is_none()
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
                let handshake_flush_deadline = (termination_deadline.is_none()
                    && !handshake_complete)
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

            if connection.lifecycle() != ConnectionLifecycle::Active
                && termination_deadline.is_none()
            {
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
                (termination_deadline.is_none() && !handshake_complete)
                    .then_some(handshake_deadline),
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
                            #[cfg(test)]
                            if let Some(test_gate) = test_gate.as_deref() {
                                test_gate.observe_actor_timer();
                            }
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
                            #[cfg(test)]
                            if let Some(test_gate) = test_gate.as_deref() {
                                test_gate.observe_actor_inbound();
                            }
                            verify_stable_source_id(&connection, &expected_server_source_id)?;
                            let received = connection.receive_packet(
                                &mut inbound.bytes,
                                inbound.length,
                                inbound.meta,
                            );
                            if received.is_err() {
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
                _ = tokio::task::yield_now(),
                    if ready_completions == MAX_READY_TARGET_COMPLETIONS_PER_ROUND => {}
                completion = target_futures.next_ready(),
                    if !target_futures.is_empty()
                        && ready_completions < MAX_READY_TARGET_COMPLETIONS_PER_ROUND => {
                    let Some(completion) = completion else {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::TargetDispatchUnavailable),
                        );
                        continue;
                    };
                    #[cfg(test)]
                    if let Some(test_gate) = test_gate.as_deref() {
                        test_gate.observe_ready_completion_round(ready_completions + 1);
                    }
                    if termination_deadline.is_none()
                        && handle_target_dispatch_completion(
                            &mut connection,
                            completion,
                            #[cfg(test)]
                            test_gate.as_deref(),
                        )
                        .is_err()
                    {
                        begin_actor_termination(
                            &mut connection,
                            &mut terminal_error,
                            &mut termination_deadline,
                            Some(ActorError::TargetDispatchUnavailable),
                        );
                        target_futures.clear();
                    }
                }
                ready = connection.wait_target_io_ready(),
                    if termination_deadline.is_none()
                        && connection.has_target_io_waiter() => {
                    match ready {
                        Ok(signal) => target_io_signal = Some(signal),
                        Err(_) => {
                            begin_actor_termination(
                                &mut connection,
                                &mut terminal_error,
                                &mut termination_deadline,
                                Some(ActorError::TargetDataUnavailable),
                            );
                            target_futures.clear();
                        }
                    }
                }
                _ = tokio::task::yield_now(),
                    if termination_deadline.is_none()
                        && connection.has_immediate_target_io_work() => {
                    #[cfg(test)]
                    if let Some(test_gate) = test_gate.as_deref() {
                        test_gate.observe_immediate_target_io_yield();
                    }
                }
            }
        }
    }
    .await;
    target_futures.clear();
    result
}

type TargetDispatchFuture = Pin<
    Box<
        dyn Future<Output = Result<TargetDispatchCompletion, TargetDispatchError>> + Send + 'static,
    >,
>;

struct TargetDispatchCompletion {
    token: TargetOpenDispatchToken,
    opened_target: TcpStream,
}

impl fmt::Debug for TargetDispatchCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private target dispatch completion")
    }
}

struct TargetDispatchFutures {
    futures: FuturesUnordered<TargetDispatchFuture>,
    target_open_sinks: TargetOpenMetricSinks,
}

impl TargetDispatchFutures {
    fn new(target_open_sinks: TargetOpenMetricSinks) -> Self {
        Self {
            futures: FuturesUnordered::new(),
            target_open_sinks,
        }
    }

    fn is_empty(&self) -> bool {
        self.futures.is_empty()
    }

    fn push(
        &mut self,
        token: TargetOpenDispatchToken,
        #[cfg(test)] test_gate: Option<Arc<ActorTestGate>>,
    ) -> Result<(), TargetDispatchError> {
        if self.futures.len() >= MAX_TARGET_DISPATCH_FUTURES {
            return Err(TargetDispatchError::Unavailable);
        }
        let dispatch = run_target_dispatch_future(
            token,
            self.target_open_sinks.clone(),
            #[cfg(test)]
            test_gate,
        );
        self.futures.push(Box::pin(async move {
            match AssertUnwindSafe(dispatch).catch_unwind().await {
                Ok(result) => result,
                Err(_) => Err(TargetDispatchError::Panic),
            }
        }));
        Ok(())
    }

    fn try_next_ready(&mut self) -> Option<Result<TargetDispatchCompletion, TargetDispatchError>> {
        self.futures.next().now_or_never().flatten()
    }

    async fn next_ready(
        &mut self,
    ) -> Option<Result<TargetDispatchCompletion, TargetDispatchError>> {
        self.futures.next().await
    }

    fn clear(&mut self) {
        self.futures.clear();
    }
}

async fn run_target_dispatch_future(
    token: TargetOpenDispatchToken,
    target_open_sinks: TargetOpenMetricSinks,
    #[cfg(test)] test_gate: Option<Arc<ActorTestGate>>,
) -> Result<TargetDispatchCompletion, TargetDispatchError> {
    if !token.is_structurally_valid() {
        return Err(TargetDispatchError::Unavailable);
    }

    #[cfg(test)]
    if test_gate
        .as_deref()
        .is_some_and(ActorTestGate::uses_synthetic_target_dispatch)
    {
        let deadline = Instant::from_std(token.attempt_deadline());
        let result = timeout_at(deadline, synthetic_target_dispatch(test_gate)).await;
        drop(target_open_sinks);
        return match result {
            Ok(Ok(opened_target)) => Ok(TargetDispatchCompletion {
                token,
                opened_target,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(TargetDispatchError::Timeout),
        };
    }

    #[cfg(test)]
    if test_gate
        .as_deref()
        .is_some_and(ActorTestGate::waits_until_production_dispatch_deadline)
    {
        tokio::time::sleep_until(Instant::from_std(token.attempt_deadline())).await;
    }

    let egress_policy = token.egress_policy();
    let opened_target = relay::open_target_addr_before_deadline_with_metrics(
        token.target(),
        token.port(),
        token.attempt_deadline(),
        &egress_policy,
        &target_open_sinks,
    )
    .await
    .map_err(|_| TargetDispatchError::Unavailable)?;
    Ok(TargetDispatchCompletion {
        token,
        opened_target,
    })
}

#[cfg(test)]
async fn synthetic_target_dispatch(
    test_gate: Option<Arc<ActorTestGate>>,
) -> Result<TcpStream, TargetDispatchError> {
    match test_gate {
        Some(test_gate) => test_gate.run_synthetic_target_dispatch().await,
        None => Err(TargetDispatchError::Unavailable),
    }
}

fn handle_target_dispatch_completion(
    connection: &mut ServerConnection,
    completion: Result<TargetDispatchCompletion, TargetDispatchError>,
    #[cfg(test)] test_gate: Option<&ActorTestGate>,
) -> Result<(), ActorError> {
    let completion = completion.map_err(|_| ActorError::TargetDispatchUnavailable)?;
    connection
        .complete_target_open_dispatch(
            completion.token,
            completion.opened_target,
            std::time::Instant::now(),
        )
        .map_err(|_| ActorError::TargetDispatchUnavailable)?;
    #[cfg(test)]
    if let Some(test_gate) = test_gate {
        test_gate.observe_target_dispatch_completion(
            connection.waiting_target_dispatch_count_for_test(),
            connection.waiting_opened_target_count_for_test(),
            connection.lifecycle() == ConnectionLifecycle::Active && connection.is_authenticated(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetDispatchError {
    Unavailable,
    Timeout,
    Panic,
}

impl fmt::Debug for TargetDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private target dispatch error")
    }
}

impl fmt::Display for TargetDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "target dispatch unavailable",
            Self::Timeout => "target dispatch timeout",
            Self::Panic => "target dispatch failed",
        })
    }
}

impl std::error::Error for TargetDispatchError {}

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
    let generation_failed = matches!(
        error,
        Some(ActorError::TargetDispatchUnavailable | ActorError::TargetDataUnavailable)
    );
    if let Some(error) = error {
        terminal_error.get_or_insert(error);
    }
    if termination_deadline.is_none() {
        *termination_deadline = Some(Instant::now() + ACTOR_TERMINATION_BUDGET);
    }
    if connection.lifecycle() == ConnectionLifecycle::Active {
        let close = if handshake_timed_out {
            connection.reject_pre_auth()
        } else if generation_failed {
            connection.reject_generation()
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
                #[cfg(test)]
                if let Some(actor_gate) = test_hooks.actor_gate {
                    actor_gate.observe_actor_flush();
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
    send_after_target_completion: AtomicBool,
    send_started: Notify,
    release_send: Notify,
    pending_close_wait: Notify,
    draining_wait_armed: AtomicBool,
    draining_wait_started: Notify,
    release_draining_wait: Notify,
    established_without_foundation: AtomicBool,
    dispatch_behavior: AtomicU8,
    dispatch_started: AtomicUsize,
    dispatch_active: AtomicUsize,
    dispatch_peak: AtomicUsize,
    dispatch_ended: AtomicUsize,
    dispatch_started_notify: Notify,
    dispatch_ended_notify: Notify,
    dispatch_release_permits: AtomicUsize,
    release_dispatch: Notify,
    dispatch_target: std::sync::Mutex<Option<SocketAddr>>,
    wait_until_production_dispatch_deadline: AtomicBool,
    inbound_observed: AtomicUsize,
    inbound_while_dispatch_blocked: AtomicBool,
    flush_while_dispatch_blocked: AtomicBool,
    timer_while_dispatch_blocked: AtomicBool,
    completion_accepted: AtomicUsize,
    completion_waiting_peak: AtomicUsize,
    completion_actor_active: AtomicBool,
    completion_round_peak: AtomicUsize,
    completion_queue_drained: AtomicBool,
    completion_accepted_notify: Notify,
    target_data_zero_progress_operations: AtomicUsize,
    target_data_progress_operations: AtomicUsize,
    target_data_progress_inbound: AtomicUsize,
    target_upload_recv_progress_mask: AtomicUsize,
    target_upload_recv_progress_inbound: AtomicUsize,
    target_write_progress_mask: AtomicUsize,
    target_write_blocked_mask: AtomicUsize,
    target_shutdown_progress_mask: AtomicUsize,
    target_write_blocked_inbound: AtomicUsize,
    target_write_progress_inbound: AtomicUsize,
    immediate_target_io_yields: AtomicUsize,
    target_data_round_pause_armed: AtomicBool,
    target_data_round_paused: Notify,
    release_target_data_round: Notify,
    target_write_saturation_requested: AtomicBool,
    target_write_saturation_count: AtomicUsize,
    fail_first_dispatch: Notify,
    revoke_requested: AtomicBool,
    hard_expiry_requested: AtomicBool,
    local_close_requested: AtomicBool,
    parent_panic_requested: AtomicBool,
    parent_stall_requested: AtomicBool,
    parent_stall_started: Notify,
    parent_join_observed: AtomicBool,
    parent_join_after_dispatch_drop: AtomicBool,
    target_peer_eof_observed: AtomicBool,
    parent_join_after_target_peer_eof: AtomicBool,
}

#[cfg(test)]
impl ActorTestGate {
    const DISPATCH_BLOCK: u8 = 1;
    const DISPATCH_ERROR_FIRST: u8 = 2;
    const DISPATCH_PANIC_FIRST: u8 = 3;
    const DISPATCH_PREFILLED: u8 = 4;

    fn uses_synthetic_target_dispatch(&self) -> bool {
        self.dispatch_behavior.load(Ordering::Acquire) != 0
    }

    fn wait_until_production_dispatch_deadline(&self) {
        self.wait_until_production_dispatch_deadline
            .store(true, Ordering::Release);
    }

    fn waits_until_production_dispatch_deadline(&self) -> bool {
        self.wait_until_production_dispatch_deadline
            .load(Ordering::Acquire)
    }

    fn arm_send(&self) {
        assert!(!self.send_armed.swap(true, Ordering::SeqCst));
    }

    fn arm_send_after_target_completion(&self) {
        self.send_after_target_completion
            .store(true, Ordering::SeqCst);
        self.arm_send();
    }

    async fn pause_once_if_armed(&self) {
        if self.send_after_target_completion.load(Ordering::SeqCst)
            && self.completion_accepted.load(Ordering::Acquire) == 0
        {
            return;
        }
        if self.send_armed.swap(false, Ordering::SeqCst) {
            self.send_after_target_completion
                .store(false, Ordering::SeqCst);
            self.send_started.notify_one();
            self.release_send.notified().await;
        }
    }

    fn release(&self) {
        self.release_send.notify_one();
    }

    fn arm_target_data_round_pause(&self) {
        assert!(!self
            .target_data_round_pause_armed
            .swap(true, Ordering::SeqCst));
    }

    async fn pause_target_data_round_once_if_armed(&self) {
        if self
            .target_data_round_pause_armed
            .swap(false, Ordering::SeqCst)
        {
            self.target_data_round_paused.notify_one();
            self.release_target_data_round.notified().await;
        }
    }

    fn release_target_data_round(&self) {
        self.release_target_data_round.notify_one();
    }

    fn request_target_write_saturation(&self) {
        assert!(!self
            .target_write_saturation_requested
            .swap(true, Ordering::SeqCst));
    }

    fn take_target_write_saturation_request(&self) -> bool {
        self.target_write_saturation_requested
            .swap(false, Ordering::SeqCst)
    }

    fn observe_target_write_saturation(&self) {
        self.target_write_saturation_count
            .fetch_add(1, Ordering::AcqRel);
    }

    fn target_write_saturation_count(&self) -> usize {
        self.target_write_saturation_count.load(Ordering::Acquire)
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

    fn block_target_dispatches(&self) {
        self.dispatch_behavior
            .store(Self::DISPATCH_BLOCK, Ordering::Release);
    }

    fn prefill_target_dispatches(&self) {
        self.dispatch_behavior
            .store(Self::DISPATCH_PREFILLED, Ordering::Release);
    }

    fn set_target_dispatch_listener(&self, listener: &TcpListener) {
        let address = listener
            .local_addr()
            .expect("read loopback target listener address");
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        *self
            .dispatch_target
            .lock()
            .expect("lock synthetic target address") = Some(address);
    }

    fn error_first_target_dispatch(&self) {
        self.dispatch_behavior
            .store(Self::DISPATCH_ERROR_FIRST, Ordering::Release);
    }

    fn panic_first_target_dispatch(&self) {
        self.dispatch_behavior
            .store(Self::DISPATCH_PANIC_FIRST, Ordering::Release);
    }

    async fn wait_for_dispatch_started(&self, expected: usize) {
        while self.dispatch_started.load(Ordering::Acquire) < expected {
            self.dispatch_started_notify.notified().await;
        }
    }

    async fn wait_for_dispatch_ended(&self, expected: usize) {
        while self.dispatch_ended.load(Ordering::Acquire) < expected {
            self.dispatch_ended_notify.notified().await;
        }
    }

    fn release_target_dispatches(&self, count: usize) {
        assert!(count <= MAX_TARGET_DISPATCH_FUTURES);
        assert!(self
            .dispatch_release_permits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(count)
                    .filter(|updated| *updated <= MAX_TARGET_DISPATCH_FUTURES)
            })
            .is_ok());
        for _ in 0..count {
            self.release_dispatch.notify_one();
        }
    }

    async fn wait_for_dispatch_release(&self) {
        loop {
            let notified = self.release_dispatch.notified();
            let mut available = self.dispatch_release_permits.load(Ordering::Acquire);
            while available != 0 {
                match self.dispatch_release_permits.compare_exchange_weak(
                    available,
                    available - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return,
                    Err(current) => available = current,
                }
            }
            notified.await;
        }
    }

    fn trigger_first_dispatch_failure(&self) {
        self.fail_first_dispatch.notify_one();
    }

    fn request_revocation(&self) {
        self.revoke_requested.store(true, Ordering::Release);
    }

    fn request_hard_expiry(&self) {
        self.hard_expiry_requested.store(true, Ordering::Release);
    }

    fn request_local_close(&self) {
        self.local_close_requested.store(true, Ordering::Release);
    }

    fn dispatch_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.dispatch_started.load(Ordering::Acquire),
            self.dispatch_active.load(Ordering::Acquire),
            self.dispatch_peak.load(Ordering::Acquire),
            self.dispatch_ended.load(Ordering::Acquire),
        )
    }

    async fn wait_for_target_completions(&self, expected: usize) {
        while self.completion_accepted.load(Ordering::Acquire) < expected {
            self.completion_accepted_notify.notified().await;
        }
    }

    fn completion_snapshot(&self) -> (usize, usize, bool, usize) {
        (
            self.completion_accepted.load(Ordering::Acquire),
            self.completion_waiting_peak.load(Ordering::Acquire),
            self.completion_actor_active.load(Ordering::Acquire),
            self.completion_round_peak.load(Ordering::Acquire),
        )
    }

    fn observe_target_dispatch_completion(
        &self,
        waiting: usize,
        opened: usize,
        actor_active: bool,
    ) {
        assert_eq!(opened, waiting);
        self.completion_accepted.fetch_add(1, Ordering::AcqRel);
        self.completion_waiting_peak
            .fetch_max(waiting, Ordering::AcqRel);
        self.completion_actor_active
            .store(actor_active, Ordering::Release);
        self.completion_accepted_notify.notify_one();
    }

    fn observe_ready_completion_round(&self, processed: usize) {
        self.completion_round_peak
            .fetch_max(processed, Ordering::AcqRel);
    }

    fn observe_target_future_queue(&self, empty: bool) {
        if empty {
            self.completion_queue_drained.store(true, Ordering::Release);
        }
    }

    fn target_future_queue_drained(&self) -> bool {
        self.completion_queue_drained.load(Ordering::Acquire)
    }

    fn observe_target_data_round(
        &self,
        operations: usize,
        progress_operations: usize,
        upload_recv_progress_mask: usize,
        target_write_progress_mask: usize,
        target_write_blocked_mask: usize,
        target_shutdown_progress_mask: usize,
    ) {
        assert!(operations <= 4);
        assert!(progress_operations <= operations);
        let previous_recv_progress = self
            .target_upload_recv_progress_mask
            .fetch_or(upload_recv_progress_mask, Ordering::AcqRel);
        if upload_recv_progress_mask != 0 && previous_recv_progress == 0 {
            self.target_upload_recv_progress_inbound.store(
                self.inbound_observed.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        let previous_write_progress = self
            .target_write_progress_mask
            .fetch_or(target_write_progress_mask, Ordering::AcqRel);
        if target_write_progress_mask != 0 && previous_write_progress == 0 {
            self.target_write_progress_inbound.store(
                self.inbound_observed.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        let previous_write_blocked = self
            .target_write_blocked_mask
            .fetch_or(target_write_blocked_mask, Ordering::AcqRel);
        if target_write_blocked_mask != 0 && previous_write_blocked == 0 {
            self.target_write_blocked_inbound.store(
                self.inbound_observed.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        self.target_shutdown_progress_mask
            .fetch_or(target_shutdown_progress_mask, Ordering::AcqRel);
        if progress_operations == 0 {
            if operations != 0 {
                self.target_data_zero_progress_operations
                    .compare_exchange(0, operations, Ordering::AcqRel, Ordering::Acquire)
                    .ok();
            }
            return;
        }
        if self
            .target_data_progress_operations
            .compare_exchange(0, operations, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.target_data_progress_inbound.store(
                self.inbound_observed.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
    }

    fn target_data_progress_snapshot(&self) -> Option<(usize, usize)> {
        let operations = self.target_data_progress_operations.load(Ordering::Acquire);
        (operations != 0).then(|| {
            (
                operations,
                self.target_data_progress_inbound.load(Ordering::Acquire),
            )
        })
    }

    fn observe_immediate_target_io_yield(&self) {
        self.immediate_target_io_yields
            .fetch_add(1, Ordering::AcqRel);
    }

    fn target_upload_progress_snapshot(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.target_upload_recv_progress_mask
                .load(Ordering::Acquire),
            self.target_write_progress_mask.load(Ordering::Acquire),
            self.target_write_blocked_mask.load(Ordering::Acquire),
            self.immediate_target_io_yields.load(Ordering::Acquire),
            self.target_write_progress_inbound.load(Ordering::Acquire),
        )
    }

    fn reset_target_upload_phase(&self) {
        self.target_upload_recv_progress_mask
            .store(0, Ordering::Release);
        self.target_upload_recv_progress_inbound
            .store(0, Ordering::Release);
        self.target_write_progress_mask.store(0, Ordering::Release);
        self.target_write_progress_inbound
            .store(0, Ordering::Release);
        self.target_write_blocked_mask.store(0, Ordering::Release);
        self.target_write_blocked_inbound
            .store(0, Ordering::Release);
        self.target_shutdown_progress_mask
            .store(0, Ordering::Release);
    }

    fn target_shutdown_progress_mask(&self) -> usize {
        self.target_shutdown_progress_mask.load(Ordering::Acquire)
    }

    fn target_upload_phase_snapshot(&self) -> (usize, usize, usize, usize, usize, usize) {
        (
            self.target_upload_recv_progress_mask
                .load(Ordering::Acquire),
            self.target_upload_recv_progress_inbound
                .load(Ordering::Acquire),
            self.target_write_progress_mask.load(Ordering::Acquire),
            self.target_write_progress_inbound.load(Ordering::Acquire),
            self.target_write_blocked_mask.load(Ordering::Acquire),
            self.target_write_blocked_inbound.load(Ordering::Acquire),
        )
    }

    fn request_parent_stall(&self) {
        self.parent_stall_requested.store(true, Ordering::Release);
    }

    fn request_parent_panic(&self) {
        self.parent_panic_requested.store(true, Ordering::Release);
    }

    fn take_parent_panic_request(&self) -> bool {
        self.parent_panic_requested.swap(false, Ordering::AcqRel)
    }

    fn take_parent_stall_request(&self) -> bool {
        self.parent_stall_requested.swap(false, Ordering::AcqRel)
    }

    fn observe_parent_stall_started(&self) {
        self.parent_stall_started.notify_one();
    }

    fn observe_parent_join_before_reclaim(&self) {
        let (started, active, _, ended) = self.dispatch_counts();
        self.parent_join_after_dispatch_drop.store(
            started != 0 && active == 0 && ended == started,
            Ordering::Release,
        );
        self.parent_join_after_target_peer_eof.store(
            self.target_peer_eof_observed.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.parent_join_observed.store(true, Ordering::Release);
    }

    fn observe_target_peer_eof(&self) {
        self.target_peer_eof_observed.store(true, Ordering::Release);
    }

    fn parent_join_snapshot(&self) -> (bool, bool) {
        (
            self.parent_join_observed.load(Ordering::Acquire),
            self.parent_join_after_dispatch_drop.load(Ordering::Acquire),
        )
    }

    fn target_peer_eof_join_snapshot(&self) -> (bool, bool) {
        (
            self.target_peer_eof_observed.load(Ordering::Acquire),
            self.parent_join_after_target_peer_eof
                .load(Ordering::Acquire),
        )
    }

    fn observe_actor_inbound(&self) {
        self.inbound_observed.fetch_add(1, Ordering::AcqRel);
        if self.dispatch_active.load(Ordering::Acquire) == MAX_TARGET_DISPATCH_FUTURES {
            self.inbound_while_dispatch_blocked
                .store(true, Ordering::Release);
        }
    }

    fn observe_actor_flush(&self) {
        if self.dispatch_active.load(Ordering::Acquire) == MAX_TARGET_DISPATCH_FUTURES {
            self.flush_while_dispatch_blocked
                .store(true, Ordering::Release);
        }
    }

    fn observe_actor_timer(&self) {
        if self.dispatch_active.load(Ordering::Acquire) == MAX_TARGET_DISPATCH_FUTURES {
            self.timer_while_dispatch_blocked
                .store(true, Ordering::Release);
        }
    }

    async fn run_synthetic_target_dispatch(
        self: Arc<Self>,
    ) -> Result<TcpStream, TargetDispatchError> {
        let index = self.dispatch_started.fetch_add(1, Ordering::AcqRel);
        self.dispatch_started_notify.notify_one();
        let active = self.dispatch_active.fetch_add(1, Ordering::AcqRel) + 1;
        self.dispatch_peak.fetch_max(active, Ordering::AcqRel);
        let mut guard = SyntheticDispatchGuard {
            gate: Arc::clone(&self),
            finished: false,
        };
        let address = self
            .dispatch_target
            .lock()
            .map_err(|_| TargetDispatchError::Unavailable)?
            .ok_or(TargetDispatchError::Unavailable)?;
        let behavior = self.dispatch_behavior.load(Ordering::Acquire);
        let opened_target = if behavior == Self::DISPATCH_PREFILLED {
            let socket = TcpSocket::new_v4().map_err(|_| TargetDispatchError::Unavailable)?;
            socket
                .set_send_buffer_size(1_024)
                .map_err(|_| TargetDispatchError::Unavailable)?;
            socket
                .connect(address)
                .await
                .map_err(|_| TargetDispatchError::Unavailable)?
        } else {
            TcpStream::connect(address)
                .await
                .map_err(|_| TargetDispatchError::Unavailable)?
        };
        if behavior == Self::DISPATCH_PREFILLED {
            let filler = [0xa7_u8; 16 * 1024];
            let mut filled = 0_usize;
            let mut consecutive_blocked_turns = 0_usize;
            for _ in 0..1_024 {
                match opened_target.try_write(&filler) {
                    Ok(0) => return Err(TargetDispatchError::Unavailable),
                    Ok(written) if written <= filler.len() => {
                        filled += written;
                        consecutive_blocked_turns = 0;
                    }
                    Ok(_) => return Err(TargetDispatchError::Unavailable),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        consecutive_blocked_turns += 1;
                        if consecutive_blocked_turns == 8 {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(_) => return Err(TargetDispatchError::Unavailable),
                }
            }
            if filled == 0 || consecutive_blocked_turns != 8 {
                return Err(TargetDispatchError::Unavailable);
            }
            guard.finish();
            return Ok(opened_target);
        }
        match behavior {
            Self::DISPATCH_BLOCK => {
                self.wait_for_dispatch_release().await;
                guard.finish();
                Ok(opened_target)
            }
            Self::DISPATCH_ERROR_FIRST if index == 0 => {
                self.fail_first_dispatch.notified().await;
                Err(TargetDispatchError::Unavailable)
            }
            Self::DISPATCH_PANIC_FIRST if index == 0 => {
                self.fail_first_dispatch.notified().await;
                panic!("injected fixed synthetic target dispatch panic")
            }
            Self::DISPATCH_ERROR_FIRST | Self::DISPATCH_PANIC_FIRST => {
                self.wait_for_dispatch_release().await;
                guard.finish();
                Ok(opened_target)
            }
            _ => Err(TargetDispatchError::Unavailable),
        }
    }
}

#[cfg(test)]
struct SyntheticDispatchGuard {
    gate: Arc<ActorTestGate>,
    finished: bool,
}

#[cfg(test)]
impl SyntheticDispatchGuard {
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.gate.dispatch_active.fetch_sub(1, Ordering::AcqRel);
        self.gate.dispatch_ended.fetch_add(1, Ordering::AcqRel);
        self.gate.dispatch_ended_notify.notify_one();
    }
}

#[cfg(test)]
impl Drop for SyntheticDispatchGuard {
    fn drop(&mut self) {
        self.finish();
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
    TargetDispatchUnavailable,
    TargetDataUnavailable,
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
            Self::TargetDispatchUnavailable => "server actor target dispatch unavailable",
            Self::TargetDataUnavailable => "server actor target data unavailable",
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use boring::ssl::{SslRef, SslVersion};
    use maverick_core::auth_v3::{
        encode_auth_v3_client_control, AuthV3Carrier, AuthV3ClientControlInput, AuthV3TlsVersion,
        AUTH_V3_CLIENT_CONTROL_LEN, AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN,
    };
    use quiche::h3::NameValue;

    use crate::quiche_registry::{
        ActorAdmission, ActorInboundDisposition, ConnectionRegistry, RegistryError,
    };
    use crate::quiche_runtime::{
        bounded_h3_config, bounded_transport_config, FrozenDirectV3ServerRole, PacketMeta,
        MAX_PACKET_BYTES,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::AbortHandle;
    use tokio::time::timeout;

    use super::*;

    type ActorReceiveFn = fn(
        &mut ConnectionRegistry,
        [u8; MAX_PACKET_BYTES],
        usize,
        PacketMeta,
    ) -> Result<ActorInboundDisposition, RegistryError>;

    fn test_metrics_owner() -> Arc<ServerRuntimeMetrics> {
        Arc::new(ServerRuntimeMetrics::default())
    }

    fn target_sink_clone_count(metrics_owner: &ServerRuntimeMetrics) -> usize {
        let probe = metrics_owner.target_open_sinks();
        Arc::strong_count(&probe.resolution_timeouts) - 1
    }

    fn assert_zero_target_open_metrics(metrics_owner: &ServerRuntimeMetrics) {
        let sinks = metrics_owner.target_open_sinks();
        assert_eq!(sinks.resolution_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_failures.load(Ordering::Relaxed), 0);
        for latency in [
            sinks.resolution_latency.snapshot(),
            sinks.connect_latency.snapshot(),
        ] {
            assert_eq!(latency.count, 0);
            assert_eq!(latency.sum_ms, 0);
            assert!(latency
                .cumulative_buckets
                .iter()
                .all(|observation| *observation == 0));
        }
    }

    async fn loopback_target_listener(gate: &ActorTestGate) -> TcpListener {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback target listener");
        gate.set_target_dispatch_listener(&listener);
        listener
    }

    async fn loopback_small_receive_target_listener(gate: &ActorTestGate) -> TcpListener {
        let socket = TcpSocket::new_v4().expect("create small-receive loopback listener socket");
        socket
            .set_recv_buffer_size(1_024)
            .expect("set small target receive buffer");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind small-receive loopback target listener");
        let listener = socket
            .listen(1_024)
            .expect("listen for bounded target peers");
        gate.set_target_dispatch_listener(&listener);
        listener
    }

    async fn drain_available_target_filler(target_peer: &TcpStream) -> usize {
        timeout(Duration::from_secs(1), target_peer.readable())
            .await
            .expect("saturated target becomes readable")
            .expect("saturated target readiness remains usable");
        let mut drained = 0_usize;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match target_peer.try_read(&mut buffer) {
                Ok(0) => panic!("saturated target must remain connected"),
                Ok(length) => {
                    assert!(buffer[..length].iter().all(|byte| *byte == 0xa7));
                    drained += length;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => panic!("saturated target filler read remains available"),
            }
        }
        assert_ne!(drained, 0);
        drained
    }

    async fn accept_target_peers(listener: &TcpListener, count: usize) -> Vec<TcpStream> {
        let mut peers = Vec::with_capacity(count);
        for _ in 0..count {
            peers.push(
                timeout(Duration::from_secs(1), listener.accept())
                    .await
                    .expect("target connect reaches loopback listener")
                    .expect("accept loopback target connection")
                    .0,
            );
        }
        peers
    }

    async fn assert_target_peers_stay_open(peers: &mut [TcpStream]) {
        for peer in peers {
            assert!(timeout(Duration::from_millis(25), peer.read_u8())
                .await
                .is_err());
        }
    }

    async fn assert_target_peers_eof(peers: Vec<TcpStream>) {
        for mut peer in peers {
            assert_eq!(
                timeout(Duration::from_secs(4), peer.read_u8())
                    .await
                    .expect("target peer closes within bound")
                    .expect_err("closed target peer reports EOF")
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
    }

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
            self.server_role_with_timeout(
                transport_strategy,
                expected_authority,
                certificate_path,
                key_path,
                10_000,
            )
        }

        fn server_role_with_target_timeout(&self, timeout_ms: u64) -> Arc<ServerRoleConfig> {
            self.server_role_with_timeout(
                "h3",
                "localhost",
                &self.certificate_path,
                &self.key_path,
                timeout_ms,
            )
        }

        fn server_role_with_loopback_target(&self, timeout_ms: u64) -> Arc<ServerRoleConfig> {
            self.server_role_with_policy(
                "h3",
                "localhost",
                &self.certificate_path,
                &self.key_path,
                timeout_ms,
                true,
            )
        }

        fn server_role_with_timeout(
            &self,
            transport_strategy: &str,
            expected_authority: &str,
            certificate_path: &std::path::Path,
            key_path: &std::path::Path,
            timeout_ms: u64,
        ) -> Arc<ServerRoleConfig> {
            self.server_role_with_policy(
                transport_strategy,
                expected_authority,
                certificate_path,
                key_path,
                timeout_ms,
                false,
            )
        }

        fn server_role_with_policy(
            &self,
            transport_strategy: &str,
            expected_authority: &str,
            certificate_path: &std::path::Path,
            key_path: &std::path::Path,
            timeout_ms: u64,
            allow_loopback: bool,
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
  timeout_ms: {timeout_ms}
  egress:
    allow_loopback: {allow_loopback}
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

        async fn send_pending(&mut self) -> usize {
            let mut packet = [0_u8; MAX_PACKET_BYTES];
            let mut sent_packets = 0_usize;
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
                        sent_packets += 1;
                    }
                    Err(quiche::Error::Done) => return sent_packets,
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

        async fn authenticate_direct_v3(&mut self, owner: &ServerRoleConfig) {
            let direct = owner.direct_v3().expect("synthetic direct-v3 role");
            let label = std::str::from_utf8(AUTH_V3_EXPORTER_LABEL)
                .expect("auth-v3 exporter label is ASCII");
            let mut exporter = [0_u8; AUTH_V3_EXPORTER_LEN];
            assert_eq!(self.connection.application_proto(), b"h3");
            let tls: &mut SslRef = self.connection.as_mut();
            assert_eq!(tls.version2(), Some(SslVersion::TLS1_3));
            tls.export_keying_material(&mut exporter, label, Some(&[]))
                .expect("derive synthetic client exporter");
            let preselected = direct.preselected_profile();
            let context = preselected.trusted_connection_context(
                AuthV3Carrier::H3,
                AuthV3TlsVersion::Tls13,
                true,
                false,
                &exporter,
                true,
                Some(&[]),
                direct.tunnel_path(),
            );
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("synthetic wall clock is available")
                .as_secs();
            let control = encode_auth_v3_client_control(
                &preselected.trusted_profile(),
                &context,
                &AuthV3ClientControlInput::new(AuthV3Carrier::H3, now_unix, [0x7c; 32]),
            )
            .expect("encode synthetic auth control");
            assert_eq!(control.len(), AUTH_V3_CLIENT_CONTROL_LEN);
            let headers = [
                quiche::h3::Header::new(b":method", b"POST"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/direct-v3"),
                quiche::h3::Header::new(b"content-type", b"application/maverick-auth-v3"),
                quiche::h3::Header::new(b"content-length", b"256"),
            ];
            let h3 = self.h3.as_mut().expect("synthetic H3 client exists");
            let stream_id = h3
                .send_request(&mut self.connection, &headers, false)
                .expect("send synthetic auth headers");
            assert_eq!(
                h3.send_body(&mut self.connection, stream_id, &control, true),
                Ok(control.len())
            );
            timeout(Duration::from_secs(3), async {
                loop {
                    self.send_pending().await;
                    self.receive_available().await;
                    if self.poll_auth_confirmation(stream_id) {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("synthetic auth confirmation completes");
        }

        fn poll_auth_confirmation(&mut self, expected_stream: u64) -> bool {
            let h3 = self.h3.as_mut().expect("synthetic H3 client exists");
            loop {
                match h3.poll(&mut self.connection) {
                    Ok((stream_id, quiche::h3::Event::Headers { .. })) => {
                        assert_eq!(stream_id, expected_stream);
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        assert_eq!(stream_id, expected_stream);
                        let mut body = [0_u8; 320];
                        loop {
                            match h3.recv_body(&mut self.connection, stream_id, &mut body) {
                                Ok(length) => assert!(length > 0),
                                Err(quiche::h3::Error::Done) => break,
                                Err(_) => panic!("synthetic confirmation body unavailable"),
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        assert_eq!(stream_id, expected_stream);
                        return true;
                    }
                    Ok(_) => panic!("unexpected synthetic confirmation event"),
                    Err(quiche::h3::Error::Done) => return false,
                    Err(_) => panic!("synthetic confirmation poll unavailable"),
                }
            }
        }

        fn send_classic_connect(&mut self) -> Result<u64, quiche::h3::Error> {
            self.send_classic_connect_to("synthetic.invalid:443")
        }

        fn send_classic_connect_to(&mut self, authority: &str) -> Result<u64, quiche::h3::Error> {
            let headers = [
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", authority.as_bytes()),
            ];
            self.h3
                .as_mut()
                .expect("synthetic H3 client exists")
                .send_request(&mut self.connection, &headers, false)
        }

        fn assert_no_classic_connect_response(&mut self) {
            let h3 = self.h3.as_mut().expect("synthetic H3 client exists");
            match h3.poll(&mut self.connection) {
                Err(quiche::h3::Error::Done) => {}
                Err(_) if self.connection.peer_error().is_some() => {}
                other => panic!("failed target open must not emit an H3 response: {other:?}"),
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

    #[tokio::test]
    async fn t027b2d0_production_opener_queues_exact_success_response_after_slot_handoff() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(1_000);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind production-opener endpoint");
        let gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind production-opener loopback target");
        let authority = listener
            .local_addr()
            .expect("read production-opener target address")
            .to_string();
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xc5).await;
        let client_gate = Arc::clone(&gate);
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            let stream_id = client
                .send_classic_connect_to(&authority)
                .expect("queue production-opener CONNECT");
            client.send_pending().await;
            let (mut target_peer, _) = timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("production opener reaches loopback target")
                .expect("accept production-opener target connection");
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_target_completions(1),
            )
            .await
            .expect("production opener returns socket to original slot");
            assert_eq!(client_gate.completion_snapshot(), (1, 1, true, 1));
            client.receive_available().await;
            let h3 = client
                .h3
                .as_mut()
                .expect("production-opener H3 client exists");
            match h3.poll(&mut client.connection) {
                Ok((response_stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                    assert_eq!(response_stream_id, stream_id);
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].name(), b":status");
                    assert_eq!(list[0].value(), b"200");
                    assert!(more_frames);
                }
                other => panic!("expected exact Classic CONNECT success response, got {other:?}"),
            }
            assert!(matches!(
                h3.poll(&mut client.connection),
                Err(quiche::h3::Error::Done)
            ));
            assert!(timeout(Duration::from_millis(25), target_peer.read_u8())
                .await
                .is_err());
            client_cancel
                .send(true)
                .expect("cancel endpoint after production opener completion");
            assert_eq!(
                timeout(Duration::from_secs(4), target_peer.read_u8())
                    .await
                    .expect("slot-owned production target closes within bound")
                    .expect_err("cancel closes slot-owned production target")
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("production-opener endpoint joins its actor");
        let sinks = metrics_owner.target_open_sinks();
        assert_eq!(sinks.resolution_latency.snapshot().count, 1);
        assert_eq!(sinks.connect_latency.snapshot().count, 1);
        assert_eq!(sinks.resolution_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_failures.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn t027b2d1_real_actor_delivers_target_bytes_written_before_and_after_response() {
        const BEFORE_RESPONSE: &[u8] = b"target-before-response";
        const AFTER_RESPONSE: &[u8] = b"-target-after-response";

        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(1_000);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind target-data endpoint");
        let gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target-data loopback target");
        let authority = listener
            .local_addr()
            .expect("read target-data target address")
            .to_string();
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd1).await;
        let client_gate = Arc::clone(&gate);
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            let stream_id = client
                .send_classic_connect_to(&authority)
                .expect("queue target-data CONNECT");
            client.send_pending().await;
            let (mut target_peer, _) = timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("target-data opener reaches loopback target")
                .expect("accept target-data target connection");
            target_peer
                .write_all(BEFORE_RESPONSE)
                .await
                .expect("write target bytes before response");
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_target_completions(1),
            )
            .await
            .expect("target-data socket returns to original slot");

            client.receive_available().await;
            let h3 = client.h3.as_mut().expect("target-data H3 client exists");
            match h3.poll(&mut client.connection) {
                Ok((response_stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                    assert_eq!(response_stream_id, stream_id);
                    assert_eq!(list.len(), 1);
                    assert_eq!(list[0].name(), b":status");
                    assert_eq!(list[0].value(), b"200");
                    assert!(more_frames);
                }
                other => panic!("target DATA must follow the exact response: {other:?}"),
            }
            target_peer
                .write_all(AFTER_RESPONSE)
                .await
                .expect("write target bytes after response");

            let mut received = [0_u8; BEFORE_RESPONSE.len() + AFTER_RESPONSE.len()];
            let mut received_len = 0_usize;
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    let h3 = client.h3.as_mut().expect("target-data H3 client exists");
                    loop {
                        match h3.poll(&mut client.connection) {
                            Ok((data_stream_id, quiche::h3::Event::Data)) => {
                                assert_eq!(data_stream_id, stream_id);
                                loop {
                                    match h3.recv_body(
                                        &mut client.connection,
                                        stream_id,
                                        &mut received[received_len..],
                                    ) {
                                        Ok(length) => received_len += length,
                                        Err(quiche::h3::Error::Done) => break,
                                        Err(_) => panic!("target DATA unavailable"),
                                    }
                                }
                            }
                            Err(quiche::h3::Error::Done) => break,
                            other => panic!("unexpected target-data event: {other:?}"),
                        }
                    }
                    if received_len == received.len() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("receive target bytes written around response");
            assert_eq!(&received[..BEFORE_RESPONSE.len()], BEFORE_RESPONSE);
            assert_eq!(&received[BEFORE_RESPONSE.len()..], AFTER_RESPONSE);

            client_cancel
                .send(true)
                .expect("cancel endpoint after target DATA");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("target-data endpoint joins its actor");
    }

    #[tokio::test]
    async fn t027b2d1_real_actor_inbound_flood_cannot_starve_target_data_or_cancel() {
        const TARGET_PAYLOAD: &[u8] = b"bounded-actor-fairness";

        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(1_000);
        let metrics_owner = test_metrics_owner();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind fairness server socket"),
        );
        let server_address = server_socket
            .local_addr()
            .expect("read fairness server address");
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd2).await;
        let mut initial_bytes = [0_u8; MAX_PACKET_BYTES];
        let (initial_length, initial_info) = client
            .connection
            .send(&mut initial_bytes)
            .expect("create fairness Initial");
        let frozen_role =
            FrozenDirectV3ServerRole::new(Arc::clone(&owner)).expect("freeze fairness server role");
        let mut registry =
            ConnectionRegistry::new(frozen_role).expect("construct fairness registry");
        let (_pending, connection, expected) = actor_admission(
            &mut registry,
            TestPacket {
                bytes: initial_bytes,
                length: initial_length,
                meta: PacketMeta {
                    from: initial_info.from,
                    to: initial_info.to,
                },
            },
        )
        .into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let router_sender = sender.clone();
        let router_socket = Arc::clone(&server_socket);
        let router = tokio::spawn(async move {
            let mut packet = [0_u8; SOCKET_RECV_BYTES];
            loop {
                let Ok((length, source)) = router_socket.recv_from(&mut packet).await else {
                    return;
                };
                let Some(bytes) = bounded_received_datagram(&packet, length) else {
                    continue;
                };
                if router_sender
                    .send(ActorPacket {
                        bytes,
                        length,
                        meta: PacketMeta {
                            from: source,
                            to: server_address,
                        },
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let gate = Arc::new(ActorTestGate::default());
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            Arc::clone(&server_socket),
            cancel_rx,
            metrics_owner.target_open_sinks(),
            Some(Arc::clone(&gate)),
        ));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fairness target listener");
        let authority = listener
            .local_addr()
            .expect("read fairness target address")
            .to_string();

        drive_client_to_h3(&mut client).await;
        client.authenticate_direct_v3(&owner).await;
        gate.arm_send_after_target_completion();
        let stream_id = client
            .send_classic_connect_to(&authority)
            .expect("queue fairness CONNECT");
        client.send_pending().await;
        let (mut target_peer, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("fairness opener reaches target")
            .expect("accept fairness target connection");
        target_peer
            .write_all(TARGET_PAYLOAD)
            .await
            .expect("write fairness target payload");
        timeout(Duration::from_secs(1), gate.send_started.notified())
            .await
            .expect("pause actor response flush before fairness flood");

        let inbound_before_flood = gate.inbound_observed.load(Ordering::Acquire);
        timeout(Duration::from_secs(1), async {
            while sender.capacity() != 0 {
                client
                    .connection
                    .send_ack_eliciting()
                    .expect("queue fairness inbound PING");
                client.send_pending().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fill actor inbox with real QUIC inbound");
        assert_eq!(sender.capacity(), 0);
        assert_eq!(
            gate.inbound_observed.load(Ordering::Acquire),
            inbound_before_flood,
            "paused actor has not consumed the queued inbound flood"
        );
        gate.release();

        let mut headers_seen = false;
        let mut received = Vec::new();
        timeout(Duration::from_secs(1), async {
            loop {
                client.receive_available().await;
                let h3 = client.h3.as_mut().expect("fairness H3 client exists");
                loop {
                    match h3.poll(&mut client.connection) {
                        Ok((response_stream, quiche::h3::Event::Headers { list, more_frames })) => {
                            assert_eq!(response_stream, stream_id);
                            assert!(!headers_seen);
                            assert!(more_frames);
                            assert_eq!(list.len(), 1);
                            assert_eq!(list[0].name(), b":status");
                            assert_eq!(list[0].value(), b"200");
                            headers_seen = true;
                        }
                        Ok((data_stream, quiche::h3::Event::Data)) => {
                            assert_eq!(data_stream, stream_id);
                            assert!(headers_seen);
                            let mut body = [0_u8; 64];
                            loop {
                                match h3.recv_body(&mut client.connection, stream_id, &mut body) {
                                    Ok(length) => received.extend_from_slice(&body[..length]),
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(_) => panic!("fairness target DATA unavailable"),
                                }
                            }
                        }
                        Err(quiche::h3::Error::Done) => break,
                        other => panic!("unexpected fairness response event: {other:?}"),
                    }
                }
                if received == TARGET_PAYLOAD {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("target DATA advances before the real inbound flood drains");
        let (operations, inbound_at_target_progress) = gate
            .target_data_progress_snapshot()
            .expect("actor records one bounded target-data round");
        assert!((2..=4).contains(&operations));
        assert_eq!(
            inbound_at_target_progress,
            inbound_before_flood + 1,
            "one inbound turn must be followed by the bounded target probe"
        );

        gate.arm_send();
        target_peer
            .shutdown()
            .await
            .expect("close fairness target write half");
        client
            .connection
            .send_ack_eliciting()
            .expect("queue cancel-priority PING");
        client.send_pending().await;
        timeout(Duration::from_secs(1), gate.send_started.notified())
            .await
            .expect("pause actor flush before cancel-priority check");
        timeout(Duration::from_secs(1), async {
            while sender.capacity() != 0 {
                client
                    .connection
                    .send_ack_eliciting()
                    .expect("queue cancel-priority inbound PING");
                client.send_pending().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("refill actor inbox before cancellation");
        cancel_tx
            .send(true)
            .expect("cancel actor while inbound remains ready");
        gate.release();
        router.abort();
        assert!(router
            .await
            .expect_err("fairness router is intentionally stopped")
            .is_cancelled());
        drop(sender);
        let actor_result = timeout(Duration::from_secs(3), actor)
            .await
            .expect("cancelled fairness actor terminates")
            .expect("join cancelled fairness actor");
        assert_eq!(actor_result, Err(ActorError::Cancelled));
        assert_eq!(
            timeout(Duration::from_secs(1), target_peer.read_u8())
                .await
                .expect("cancel closes fairness target")
                .expect_err("cancelled target peer reports EOF")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn t027b2d2_retained_and_t027b2d3_real_actor_upload_then_fin() {
        const UPLOAD_MARKER: &[u8] = b"actor-upload-marker";

        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind upload actor server socket"),
        );
        let server_address = server_socket
            .local_addr()
            .expect("read upload actor server address");
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd3).await;
        let mut initial_bytes = [0_u8; MAX_PACKET_BYTES];
        let (initial_length, initial_info) = client
            .connection
            .send(&mut initial_bytes)
            .expect("create upload actor Initial");
        let frozen_role =
            FrozenDirectV3ServerRole::new(Arc::clone(&owner)).expect("freeze upload actor role");
        let mut registry =
            ConnectionRegistry::new(frozen_role).expect("construct upload actor registry");
        let (_pending, connection, expected) = actor_admission(
            &mut registry,
            TestPacket {
                bytes: initial_bytes,
                length: initial_length,
                meta: PacketMeta {
                    from: initial_info.from,
                    to: initial_info.to,
                },
            },
        )
        .into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let router_sender = sender.clone();
        let router_socket = Arc::clone(&server_socket);
        let router = tokio::spawn(async move {
            let mut packet = [0_u8; SOCKET_RECV_BYTES];
            loop {
                let Ok((length, source)) = router_socket.recv_from(&mut packet).await else {
                    return;
                };
                let Some(bytes) = bounded_received_datagram(&packet, length) else {
                    continue;
                };
                if router_sender
                    .send(ActorPacket {
                        bytes,
                        length,
                        meta: PacketMeta {
                            from: source,
                            to: server_address,
                        },
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let gate = Arc::new(ActorTestGate::default());
        gate.prefill_target_dispatches();
        let listener = loopback_small_receive_target_listener(&gate).await;
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            Arc::clone(&server_socket),
            cancel_rx,
            metrics_owner.target_open_sinks(),
            Some(Arc::clone(&gate)),
        ));

        drive_client_to_h3(&mut client).await;
        client.authenticate_direct_v3(&owner).await;
        let stream_id = client
            .send_classic_connect()
            .expect("queue upload actor CONNECT");
        client.send_pending().await;
        let (mut target_peer, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("upload actor target connect reaches listener")
            .expect("accept upload actor target");
        timeout(Duration::from_secs(1), gate.wait_for_target_completions(1))
            .await
            .expect("prefilled target socket reaches original slot");
        timeout(Duration::from_secs(1), async {
            loop {
                client.receive_available().await;
                let h3 = client.h3.as_mut().expect("upload actor H3 exists");
                match h3.poll(&mut client.connection) {
                    Ok((response_stream, quiche::h3::Event::Headers { list, more_frames })) => {
                        assert_eq!(response_stream, stream_id);
                        assert_eq!(list.len(), 1);
                        assert_eq!(list[0].name(), b":status");
                        assert_eq!(list[0].value(), b"200");
                        assert!(more_frames);
                        return;
                    }
                    Err(quiche::h3::Error::Done) => {}
                    other => panic!("unexpected upload actor response: {other:?}"),
                }
                client.send_pending().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("observe exact upload actor response");

        gate.arm_send();
        client
            .connection
            .send_ack_eliciting()
            .expect("queue upload actor pause PING");
        client.send_pending().await;
        timeout(Duration::from_secs(1), gate.send_started.notified())
            .await
            .expect("pause actor flush before upload fairness phase");
        gate.reset_target_upload_phase();
        let inbound_baseline = gate.inbound_observed.load(Ordering::Acquire);
        assert_eq!(
            client
                .h3
                .as_mut()
                .expect("upload actor H3 exists")
                .send_body(&mut client.connection, stream_id, UPLOAD_MARKER, false),
            Ok(UPLOAD_MARKER.len())
        );
        client.send_pending().await;
        timeout(Duration::from_secs(1), async {
            while sender.capacity() != 0 {
                client
                    .connection
                    .send_ack_eliciting()
                    .expect("queue upload actor fairness PING");
                client.send_pending().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fill bounded actor inbox behind real upload DATA");
        assert_eq!(sender.capacity(), 0);
        gate.arm_target_data_round_pause();
        gate.release();

        timeout(
            Duration::from_secs(1),
            gate.target_data_round_paused.notified(),
        )
        .await
        .expect("pause actor after the recv-progress target-data round");
        let (recv_mask, recv_inbound, write_mask, _, blocked_mask, _) =
            gate.target_upload_phase_snapshot();
        assert_eq!(recv_mask, 1);
        assert_eq!(recv_inbound, inbound_baseline + 1);
        assert_eq!(write_mask, 0);
        assert_eq!(blocked_mask, 0);

        let mut blocked_snapshot = None;
        let saturation_count_before = gate.target_write_saturation_count();
        for _ in 0..2 {
            gate.request_target_write_saturation();
            gate.arm_target_data_round_pause();
            gate.release_target_data_round();
            timeout(
                Duration::from_secs(1),
                gate.target_data_round_paused.notified(),
            )
            .await
            .expect("pause actor after one just-in-time saturated target-data round");
            let snapshot = gate.target_upload_phase_snapshot();
            assert_eq!(snapshot.2, 0);
            if snapshot.4 == 1 {
                blocked_snapshot = Some(snapshot);
                break;
            }
        }
        let (_, _, write_mask, _, blocked_mask, blocked_inbound) =
            blocked_snapshot.expect("two bounded inbound turns observe real target WouldBlock");
        assert_eq!(write_mask, 0);
        assert_eq!(blocked_mask, 1);
        assert!(gate.target_write_saturation_count() > saturation_count_before);
        assert!(blocked_inbound > recv_inbound);
        assert!(
            blocked_inbound <= recv_inbound + 2,
            "the shared direction cursor reaches the real write probe within two bounded inbox turns"
        );

        let _ = drain_available_target_filler(&target_peer).await;
        gate.reset_target_upload_phase();
        let mut write_progress_snapshot = None;
        for _ in 0..4 {
            gate.arm_target_data_round_pause();
            gate.release_target_data_round();
            timeout(
                Duration::from_secs(1),
                gate.target_data_round_paused.notified(),
            )
            .await
            .expect("pause actor after one recovery target-data round");
            let snapshot = gate.target_upload_phase_snapshot();
            if snapshot.2 == 1 {
                write_progress_snapshot = Some(snapshot);
                break;
            }
            if snapshot.4 == 1 {
                let _ = drain_available_target_filler(&target_peer).await;
            }
        }
        let (_, _, write_mask, _, _, _) =
            write_progress_snapshot.expect("peer drain produces real target write progress");
        assert_eq!(write_mask, 1);
        gate.release_target_data_round();
        let mut received = Vec::with_capacity(UPLOAD_MARKER.len());
        timeout(Duration::from_secs(2), async {
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let length = target_peer
                    .read(&mut buffer)
                    .await
                    .expect("drain prefilled upload target");
                assert_ne!(length, 0);
                for byte in &buffer[..length] {
                    if *byte == 0xa7 {
                        assert!(received.is_empty());
                    } else {
                        received.push(*byte);
                    }
                }
                if received.len() == UPLOAD_MARKER.len() {
                    return;
                }
                assert!(received.len() < UPLOAD_MARKER.len());
            }
        })
        .await
        .expect("writable target resumes the exact buffered upload marker");
        assert_eq!(received, UPLOAD_MARKER);
        let (_, _, write_mask, _, _, _) = gate.target_upload_phase_snapshot();
        assert_eq!(write_mask, 1);

        gate.reset_target_upload_phase();
        assert_eq!(client.connection.stream_send(stream_id, b"", true), Ok(0));
        client.send_pending().await;
        assert_eq!(
            timeout(Duration::from_secs(2), target_peer.read_u8())
                .await
                .expect("actor continuation shuts down target without another test packet")
                .expect_err("actor request FIN produces target EOF")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(gate.target_shutdown_progress_mask(), 1);

        client.receive_available().await;
        gate.arm_send();
        client
            .connection
            .send_ack_eliciting()
            .expect("queue upload cancel-priority PING");
        client.send_pending().await;
        timeout(Duration::from_secs(1), gate.send_started.notified())
            .await
            .expect("pause upload actor before cancel-priority check");
        timeout(Duration::from_secs(1), async {
            while sender.capacity() != 0 {
                client
                    .connection
                    .send_ack_eliciting()
                    .expect("queue cancel-priority upload PING");
                client.send_pending().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("refill bounded actor inbox before upload cancellation");
        cancel_tx
            .send(true)
            .expect("cancel upload actor while inbox remains ready");
        gate.release();
        router.abort();
        assert!(router
            .await
            .expect_err("upload actor router is intentionally stopped")
            .is_cancelled());
        drop(sender);
        let actor_result = timeout(Duration::from_secs(3), actor)
            .await
            .expect("cancelled upload actor terminates")
            .expect("join cancelled upload actor");
        assert_eq!(actor_result, Err(ActorError::Cancelled));
        assert_eq!(
            timeout(Duration::from_secs(1), target_peer.read_u8())
                .await
                .expect("cancel closes upload actor target")
                .expect_err("cancelled upload target reports EOF")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn t027b2c5_real_opener_egress_rejects_before_connect_without_failure_metrics() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind production-egress endpoint");
        let gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind rejected loopback target");
        let authority = listener
            .local_addr()
            .expect("read rejected target address")
            .to_string();
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xc6).await;
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect_to(&authority)
                .expect("queue policy-rejected CONNECT");
            client.send_pending().await;
            assert!(timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err());
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    client.assert_no_classic_connect_response();
                    if client.connection.peer_error().is_some() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("policy rejection closes the generation");
            let peer_error = client
                .connection
                .peer_error()
                .expect("policy rejection reaches peer");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, 0x105);
            assert!(peer_error.reason.is_empty());
            client_cancel
                .send(true)
                .expect("stop endpoint after policy rejection");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("production-egress endpoint joins its actor");
        assert_eq!(gate.completion_snapshot(), (0, 0, false, 1));
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn t027b2d0_real_target_connect_failure_never_queues_success_response() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(1_000);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind connect-failure endpoint");
        let gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let refusing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind target address before refusing connections");
        let authority = refusing_listener
            .local_addr()
            .expect("read refusing target address")
            .to_string();
        drop(refusing_listener);
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xc9).await;
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect_to(&authority)
                .expect("queue connect-failure CONNECT");
            client.send_pending().await;
            timeout(Duration::from_secs(2), async {
                loop {
                    client.receive_available().await;
                    client.assert_no_classic_connect_response();
                    if client.connection.peer_error().is_some() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("target connect failure closes the generation");
            client_cancel
                .send(true)
                .expect("stop endpoint after target connect failure");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("connect-failure endpoint joins its actor");
        assert_eq!(gate.completion_snapshot(), (0, 0, false, 1));
        let sinks = metrics_owner.target_open_sinks();
        assert_eq!(sinks.resolution_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_failures.load(Ordering::Relaxed), 1);
        assert_eq!(sinks.resolution_latency.snapshot().count, 1);
        assert_eq!(sinks.connect_latency.snapshot().count, 0);
    }

    #[tokio::test]
    async fn t027b2c5_domain_dispatch_fails_before_connect_slot_handoff_or_late_metrics() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(1_000);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind production-Domain endpoint");
        let gate = Arc::new(ActorTestGate::default());
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind production-Domain rejection target");
        let authority = format!(
            "localhost:{}",
            listener
                .local_addr()
                .expect("read production-Domain target")
                .port()
        );
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xc8).await;
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect_to(&authority)
                .expect("queue production-Domain CONNECT");
            client.send_pending().await;
            assert!(timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err());
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    client.assert_no_classic_connect_response();
                    if client.connection.peer_error().is_some() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("production-Domain rejection closes the generation");
            client_cancel
                .send(true)
                .expect("stop endpoint after production-Domain rejection");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("production-Domain endpoint joins its actor");
        assert_eq!(gate.completion_snapshot(), (0, 0, false, 1));
        let sinks = metrics_owner.target_open_sinks();
        assert_eq!(sinks.resolution_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 1);
        assert_eq!(sinks.connect_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_latency.snapshot().count, 0);
        assert_eq!(sinks.connect_latency.snapshot().count, 0);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 1);
        assert_eq!(sinks.connect_latency.snapshot().count, 0);
    }

    #[tokio::test]
    async fn t027b2c5_expired_token_deadline_is_classified_only_by_whole_attempt_opener() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_loopback_target(75);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind deadline-boundary endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.wait_until_production_dispatch_deadline();
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind deadline-boundary loopback target");
        let authority = listener
            .local_addr()
            .expect("read deadline-boundary target address")
            .to_string();
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xc7).await;
        let client_cancel = cancel.clone();

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect_to(&authority)
                .expect("queue deadline-boundary CONNECT");
            client.send_pending().await;
            assert!(timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_err());
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    client.assert_no_classic_connect_response();
                    if client.connection.peer_error().is_some() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("whole-attempt timeout closes the generation");
            client_cancel
                .send(true)
                .expect("stop endpoint after whole-attempt timeout");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("deadline-boundary endpoint joins its actor");
        let sinks = metrics_owner.target_open_sinks();
        assert_eq!(sinks.resolution_timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(sinks.resolution_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_timeouts.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.connect_failures.load(Ordering::Relaxed), 0);
        assert_eq!(sinks.resolution_latency.snapshot().count, 0);
        assert_eq!(sinks.connect_latency.snapshot().count, 0);
        assert_eq!(gate.completion_snapshot(), (0, 0, false, 1));
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

    #[derive(Clone, Copy)]
    enum BlockedFutureTermination {
        EndpointCancel,
        HardExpiry,
        Revocation,
        PeerClose,
        LocalClose,
    }

    #[derive(Clone, Copy)]
    enum CompletedActorTermination {
        Panic,
        ForcedAbort,
    }

    async fn assert_blocked_future_termination(case: BlockedFutureTermination) {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind termination-case endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe1).await;
        let client_gate = Arc::clone(&gate);
        let client_cancel = cancel.clone();
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect()
                .expect("queue termination-case CONNECT");
            client.send_pending().await;
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_dispatch_started(1),
            )
            .await
            .expect("termination-case dispatch future starts");
            let target_peers = accept_target_peers(&target_listener, 1).await;
            assert_eq!(target_sink_clone_count(&client_metrics), 4);
            assert_zero_target_open_metrics(&client_metrics);

            match case {
                BlockedFutureTermination::EndpointCancel => {
                    client_cancel
                        .send(true)
                        .expect("cancel endpoint with active dispatch future");
                }
                BlockedFutureTermination::HardExpiry => {
                    client_gate.request_hard_expiry();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake actor for hard expiry");
                    client.send_pending().await;
                }
                BlockedFutureTermination::Revocation => {
                    client_gate.request_revocation();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake actor for revocation");
                    client.send_pending().await;
                }
                BlockedFutureTermination::PeerClose => {
                    client
                        .connection
                        .close(true, 0x66, b"")
                        .expect("peer closes active generation");
                    client.send_pending().await;
                }
                BlockedFutureTermination::LocalClose => {
                    client_gate.request_local_close();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake actor for local close");
                    client.send_pending().await;
                }
            }

            timeout(
                Duration::from_secs(3),
                client_gate.wait_for_dispatch_ended(1),
            )
            .await
            .expect("termination drops the active dispatch future");
            assert_target_peers_eof(target_peers).await;
            assert_eq!(client_gate.dispatch_counts(), (1, 0, 1, 1));
            if !matches!(case, BlockedFutureTermination::EndpointCancel) {
                client_cancel
                    .send(true)
                    .expect("stop endpoint after actor termination");
            }
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("termination-case endpoint joins its actor");
        assert_eq!(gate.dispatch_counts(), (1, 0, 1, 1));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    async fn assert_slot_owned_target_termination(case: BlockedFutureTermination) {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind slot-owner termination endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe4).await;
        let client_gate = Arc::clone(&gate);
        let client_cancel = cancel.clone();
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect()
                .expect("queue slot-owner termination CONNECT");
            client.send_pending().await;
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_dispatch_started(1),
            )
            .await
            .expect("slot-owner dispatch future starts");
            let mut target_peers = accept_target_peers(&target_listener, 1).await;
            client_gate.release_target_dispatches(1);
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_target_completions(1),
            )
            .await
            .expect("connected target reaches original slot");
            assert_eq!(client_gate.dispatch_counts(), (1, 0, 1, 1));
            assert_target_peers_stay_open(&mut target_peers).await;
            assert_zero_target_open_metrics(&client_metrics);

            match case {
                BlockedFutureTermination::EndpointCancel => {
                    client_cancel
                        .send(true)
                        .expect("cancel endpoint with slot-owned target");
                }
                BlockedFutureTermination::HardExpiry => {
                    client_gate.request_hard_expiry();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake slot owner for hard expiry");
                    client.send_pending().await;
                }
                BlockedFutureTermination::Revocation => {
                    client_gate.request_revocation();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake slot owner for revocation");
                    client.send_pending().await;
                }
                BlockedFutureTermination::PeerClose => {
                    client
                        .connection
                        .close(true, 0x67, b"")
                        .expect("peer closes slot-owned generation");
                    client.send_pending().await;
                }
                BlockedFutureTermination::LocalClose => {
                    client_gate.request_local_close();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake slot owner for local close");
                    client.send_pending().await;
                }
            }

            assert_target_peers_eof(target_peers).await;
            client_gate.observe_target_peer_eof();
            if !matches!(case, BlockedFutureTermination::EndpointCancel) {
                client_cancel
                    .send(true)
                    .expect("stop slot-owner endpoint after termination");
            }
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("slot-owner endpoint joins its actor");
        assert_eq!(gate.target_peer_eof_join_snapshot(), (true, true));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    async fn assert_completed_actor_termination(case: CompletedActorTermination) {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind completed-actor termination endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe6).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect()
                .expect("queue completed-actor CONNECT");
            client.send_pending().await;
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_dispatch_started(1),
            )
            .await
            .expect("completed-actor dispatch starts");
            let mut target_peers = accept_target_peers(&target_listener, 1).await;
            client_gate.release_target_dispatches(1);
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_target_completions(1),
            )
            .await
            .expect("completed-actor target reaches slot");
            assert_target_peers_stay_open(&mut target_peers).await;
            assert_zero_target_open_metrics(&client_metrics);

            match case {
                CompletedActorTermination::Panic => {
                    client_gate.request_parent_panic();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake actor for injected panic");
                    client.send_pending().await;
                }
                CompletedActorTermination::ForcedAbort => {
                    client_gate.request_parent_stall();
                    client
                        .connection
                        .send_ack_eliciting()
                        .expect("wake actor for forced parent abort");
                    client.send_pending().await;
                    timeout(
                        Duration::from_secs(1),
                        client_gate.parent_stall_started.notified(),
                    )
                    .await
                    .expect("completed actor reaches forced stall");
                    cancel
                        .send(true)
                        .expect("cancel endpoint around completed stalled actor");
                }
            }

            assert_target_peers_eof(target_peers).await;
            if matches!(case, CompletedActorTermination::Panic) {
                cancel.send(true).expect("stop endpoint after actor panic");
            }
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        match case {
            CompletedActorTermination::Panic => {
                endpoint_result.expect("panicked actor is joined and reclaimed")
            }
            CompletedActorTermination::ForcedAbort => {
                assert_eq!(endpoint_result, Err(EndpointError::Shutdown));
            }
        }
        assert_eq!(gate.parent_join_snapshot(), (true, true));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    async fn assert_dispatch_failure_drops_sibling(panic_first: bool) {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind dispatch-failure endpoint");
        let gate = Arc::new(ActorTestGate::default());
        if panic_first {
            gate.panic_first_target_dispatch();
        } else {
            gate.error_first_target_dispatch();
        }
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe2).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            for expected in 1..=2 {
                client
                    .send_classic_connect()
                    .expect("queue dispatch-failure CONNECT");
                client.send_pending().await;
                timeout(
                    Duration::from_secs(1),
                    client_gate.wait_for_dispatch_started(expected),
                )
                .await
                .expect("start failing future and sibling");
                client.receive_available().await;
            }
            let target_peers = accept_target_peers(&target_listener, 2).await;
            assert_eq!(client_gate.dispatch_counts(), (2, 2, 2, 0));
            assert_eq!(target_sink_clone_count(&client_metrics), 5);
            assert_zero_target_open_metrics(&client_metrics);
            client_gate.trigger_first_dispatch_failure();
            timeout(
                Duration::from_secs(2),
                client_gate.wait_for_dispatch_ended(2),
            )
            .await
            .expect("dispatch failure drops its sibling future");
            assert_target_peers_eof(target_peers).await;
            assert_eq!(client_gate.dispatch_counts(), (2, 0, 2, 2));
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    if client.connection.peer_error().is_some() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("dispatch failure closes the generation");
            let peer_error = client
                .connection
                .peer_error()
                .expect("generation failure reaches peer");
            assert!(peer_error.is_app);
            assert_eq!(peer_error.error_code, 0x105);
            assert!(peer_error.reason.is_empty());
            cancel.send(true).expect("stop dispatch-failure endpoint");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("dispatch-failure endpoint joins its actor");
        assert_eq!(gate.dispatch_counts(), (2, 0, 2, 2));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    async fn assert_inbox_close_releases_target(complete_before_close: bool) {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let server_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind inbox-close server socket"),
        );
        let server_address = server_socket
            .local_addr()
            .expect("read inbox-close server address");
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe3).await;
        let mut initial_bytes = [0_u8; MAX_PACKET_BYTES];
        let (initial_length, initial_info) = client
            .connection
            .send(&mut initial_bytes)
            .expect("create inbox-close Initial");
        let mut registry = ConnectionRegistry::new(credentials.frozen_role())
            .expect("construct inbox-close registry");
        let (_pending, connection, expected) = actor_admission(
            &mut registry,
            TestPacket {
                bytes: initial_bytes,
                length: initial_length,
                meta: PacketMeta {
                    from: initial_info.from,
                    to: initial_info.to,
                },
            },
        )
        .into_parts();
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let router_sender = sender.clone();
        let router_socket = Arc::clone(&server_socket);
        let router = tokio::spawn(async move {
            let mut packet = [0_u8; SOCKET_RECV_BYTES];
            loop {
                let (length, source) = router_socket
                    .recv_from(&mut packet)
                    .await
                    .expect("receive inbox-close client packet");
                let bytes = bounded_received_datagram(&packet, length)
                    .expect("inbox-close packet is bounded");
                router_sender
                    .send(ActorPacket {
                        bytes,
                        length,
                        meta: PacketMeta {
                            from: source,
                            to: server_address,
                        },
                    })
                    .await
                    .expect("route inbox-close client packet");
            }
        });
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        let actor = tokio::spawn(run_connection_actor(
            connection,
            expected,
            receiver,
            Arc::clone(&server_socket),
            cancel_rx,
            metrics_owner.target_open_sinks(),
            Some(Arc::clone(&gate)),
        ));

        drive_client_to_h3(&mut client).await;
        client.authenticate_direct_v3(&owner).await;
        client
            .send_classic_connect()
            .expect("queue inbox-close CONNECT");
        client.send_pending().await;
        timeout(Duration::from_secs(1), gate.wait_for_dispatch_started(1))
            .await
            .expect("inbox-close dispatch future starts");
        let mut target_peers = accept_target_peers(&target_listener, 1).await;
        if complete_before_close {
            gate.release_target_dispatches(1);
            timeout(Duration::from_secs(1), gate.wait_for_target_completions(1))
                .await
                .expect("inbox-close target reaches original slot");
            assert_target_peers_stay_open(&mut target_peers).await;
            assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        } else {
            assert_eq!(target_sink_clone_count(&metrics_owner), 3);
        }
        assert_zero_target_open_metrics(&metrics_owner);

        router.abort();
        assert!(router
            .await
            .expect_err("router is intentionally stopped")
            .is_cancelled());
        drop(sender);
        timeout(Duration::from_secs(2), gate.wait_for_dispatch_ended(1))
            .await
            .expect("inbox close releases dispatch state");
        assert_target_peers_eof(target_peers).await;
        let actor_result = timeout(Duration::from_secs(3), actor)
            .await
            .expect("inbox-close actor terminates within bound")
            .expect("join inbox-close actor");
        assert!(matches!(
            actor_result,
            Err(ActorError::InboxUnavailable) | Err(ActorError::TerminationTimeout)
        ));
        assert_eq!(gate.dispatch_counts(), (1, 0, 1, 1));
        assert_eq!(target_sink_clone_count(&metrics_owner), 1);
        assert_zero_target_open_metrics(&metrics_owner);
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
        assert_eq!(MAX_READY_TARGET_COMPLETIONS_PER_ROUND, 4);
        assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 5);
        assert_eq!(AUTH_WALL_TIMEOUT.as_secs(), 10);
        assert_eq!(MAX_IDLE_TIMEOUT.as_secs(), 5);
        assert_eq!(SOCKET_SEND_TIMEOUT.as_secs(), 2);
        assert_eq!(ACTOR_TERMINATION_BUDGET.as_millis(), 1_500);
        assert!(ACTOR_TERMINATION_BUDGET < SHUTDOWN_JOIN_BUDGET);
        assert_eq!(SHUTDOWN_JOIN_BUDGET.as_secs(), 2);
    }

    #[tokio::test]
    async fn t027b2c3_endpoint_requires_caller_metrics_owner() {
        let credentials = TestCredentials::new();
        let metrics_owner = test_metrics_owner();
        let endpoint = Endpoint::bind(credentials.server_role(), Arc::clone(&metrics_owner))
            .await
            .expect("bind endpoint with caller metrics owner");

        assert!(Arc::ptr_eq(&endpoint.metrics_owner, &metrics_owner));
        assert_eq!(Arc::strong_count(&metrics_owner), 2);

        let owner_sinks = metrics_owner.target_open_sinks();
        for (endpoint_counter, owner_counter) in [
            (
                &endpoint.target_open_sinks.resolution_timeouts,
                &owner_sinks.resolution_timeouts,
            ),
            (
                &endpoint.target_open_sinks.resolution_failures,
                &owner_sinks.resolution_failures,
            ),
            (
                &endpoint.target_open_sinks.connect_timeouts,
                &owner_sinks.connect_timeouts,
            ),
            (
                &endpoint.target_open_sinks.connect_failures,
                &owner_sinks.connect_failures,
            ),
        ] {
            assert!(Arc::ptr_eq(endpoint_counter, owner_counter));
            assert_eq!(Arc::strong_count(endpoint_counter), 3);
        }

        endpoint
            .target_open_sinks
            .resolution_timeouts
            .store(1, Ordering::Relaxed);
        endpoint
            .target_open_sinks
            .resolution_failures
            .store(2, Ordering::Relaxed);
        endpoint
            .target_open_sinks
            .connect_timeouts
            .store(3, Ordering::Relaxed);
        endpoint
            .target_open_sinks
            .connect_failures
            .store(4, Ordering::Relaxed);
        assert_eq!(owner_sinks.resolution_timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(owner_sinks.resolution_failures.load(Ordering::Relaxed), 2);
        assert_eq!(owner_sinks.connect_timeouts.load(Ordering::Relaxed), 3);
        assert_eq!(owner_sinks.connect_failures.load(Ordering::Relaxed), 4);

        endpoint
            .target_open_sinks
            .resolution_latency
            .record(Duration::from_millis(10));
        endpoint
            .target_open_sinks
            .connect_latency
            .record(Duration::from_millis(25));
        assert_eq!(owner_sinks.resolution_latency.snapshot().count, 1);
        assert_eq!(owner_sinks.resolution_latency.snapshot().sum_ms, 10);
        assert_eq!(owner_sinks.connect_latency.snapshot().count, 1);
        assert_eq!(owner_sinks.connect_latency.snapshot().sum_ms, 25);

        drop(owner_sinks);
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
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
            let error = match Endpoint::bind(owner, test_metrics_owner()).await {
                Ok(_) => panic!("non-H3 server role must be rejected before I/O"),
                Err(error) => error,
            };
            assert_eq!(error, EndpointError::Role);
            assert_eq!(error.to_string(), "server endpoint role unavailable");
        }

        let valid_h3 = credentials.server_role();
        let endpoint = Endpoint::bind(valid_h3, test_metrics_owner())
            .await
            .expect("validated config-v3 H3 role enters local foundation");
        assert!(endpoint.local_address.ip().is_loopback());
        assert_ne!(endpoint.local_address.port(), 0);
    }

    #[tokio::test]
    async fn t027b2b2_1_same_arc_owner_reaches_registry_and_admitted_connection() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let mut endpoint = Endpoint::bind(Arc::clone(&owner), test_metrics_owner())
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
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
        let metrics_owner = test_metrics_owner();
        let (mut activation_endpoint, _cancel) =
            Endpoint::bind_test(credentials.server_role(), Arc::clone(&metrics_owner))
                .await
                .expect("bind activation-error endpoint");
        activation_endpoint.fail_next_activation = true;
        let server_address = activation_endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0x61).await;
        let send_initial = async move {
            client.send_pending().await;
        };
        let (result, ()) = tokio::join!(activation_endpoint.run(), send_initial);
        assert_eq!(result, Err(EndpointError::ActorLifecycle));
        assert_eq!(activation_endpoint.registry.actor_count(), 0);
        assert!(activation_endpoint.actors.is_empty());
        assert!(activation_endpoint.unregistered_actor.is_none());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn run_joins_actor_panic_before_shutdown_finishes() {
        let credentials = TestCredentials::new();
        let metrics_owner = test_metrics_owner();
        let (mut panic_endpoint, panic_cancel) =
            Endpoint::bind_test(credentials.server_role(), Arc::clone(&metrics_owner))
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
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_deadline_aborts_stuck_actor_then_drains_and_reclaims() {
        let credentials = TestCredentials::new();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), Arc::clone(&metrics_owner))
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
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
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
        let metrics_owner = test_metrics_owner();
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
            metrics_owner.target_open_sinks(),
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
        let metrics_owner = test_metrics_owner();
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
            metrics_owner.target_open_sinks(),
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
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
    async fn t027b2c1_eight_blocked_futures_preserve_udp_timer_flush_and_drop_before_reclaim() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind bounded-dispatch endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd1).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            for expected in 1..=MAX_TARGET_DISPATCH_FUTURES {
                client
                    .send_classic_connect()
                    .expect("queue bounded synthetic CONNECT");
                client.send_pending().await;
                timeout(
                    Duration::from_secs(1),
                    client_gate.wait_for_dispatch_started(expected),
                )
                .await
                .expect("actor starts each bounded dispatch future");
                client.receive_available().await;
            }
            let target_peers =
                accept_target_peers(&target_listener, MAX_TARGET_DISPATCH_FUTURES).await;
            assert!(client.send_classic_connect().is_err());
            assert_eq!(client_gate.dispatch_counts(), (8, 8, 8, 0));
            assert_eq!(target_sink_clone_count(&client_metrics), 11);
            assert_zero_target_open_metrics(&client_metrics);

            client
                .connection
                .send_ack_eliciting()
                .expect("queue next actor UDP packet");
            client.send_pending().await;
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    if client_gate
                        .inbound_while_dispatch_blocked
                        .load(Ordering::Acquire)
                        && client_gate
                            .flush_while_dispatch_blocked
                            .load(Ordering::Acquire)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("blocked futures do not stall UDP or bounded flush");

            timeout(
                Duration::from_secs(7),
                client_gate.wait_for_dispatch_ended(8),
            )
            .await
            .expect("real QUIC timer drops all blocked dispatch futures");
            assert_target_peers_eof(target_peers).await;
            assert!(client_gate
                .timer_while_dispatch_blocked
                .load(Ordering::Acquire));
            assert_eq!(client_gate.dispatch_counts(), (8, 0, 8, 8));
            assert_zero_target_open_metrics(&client_metrics);
            cancel.send(true).expect("stop bounded-dispatch endpoint");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("bounded-dispatch endpoint exits cleanly");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(gate.dispatch_counts(), (8, 0, 8, 8));
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn t027b2c1_actor_accepts_synthetic_completions_in_bounded_rounds() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind completion endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd2).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            for expected in 1..=MAX_TARGET_DISPATCH_FUTURES {
                client
                    .send_classic_connect()
                    .expect("queue completion-case CONNECT");
                client.send_pending().await;
                timeout(
                    Duration::from_secs(1),
                    client_gate.wait_for_dispatch_started(expected),
                )
                .await
                .expect("actor starts each completion-case future");
                client.receive_available().await;
            }
            let mut target_peers =
                accept_target_peers(&target_listener, MAX_TARGET_DISPATCH_FUTURES).await;
            assert_eq!(target_sink_clone_count(&client_metrics), 11);
            assert_zero_target_open_metrics(&client_metrics);

            client_gate.release_target_dispatches(MAX_TARGET_DISPATCH_FUTURES);
            timeout(
                Duration::from_secs(2),
                client_gate.wait_for_target_completions(MAX_TARGET_DISPATCH_FUTURES),
            )
            .await
            .expect("actor accepts every synthetic completion");
            assert_eq!(client_gate.dispatch_counts(), (8, 0, 8, 8));
            assert_eq!(target_sink_clone_count(&client_metrics), 3);
            assert_zero_target_open_metrics(&client_metrics);
            assert_eq!(
                client_gate.completion_snapshot(),
                (8, 8, true, MAX_READY_TARGET_COMPLETIONS_PER_ROUND),
                "the actor advances all slots while limiting each ready pre-drain round"
            );
            assert!(client_gate.target_future_queue_drained());
            assert!(
                client.send_classic_connect().is_err(),
                "eight response-stage owners retain the original fixed quota"
            );
            assert_target_peers_stay_open(&mut target_peers).await;

            let inbound_before = client_gate.inbound_observed.load(Ordering::Acquire);
            client
                .connection
                .send_ack_eliciting()
                .expect("queue post-completion actor packet");
            client.send_pending().await;
            timeout(Duration::from_secs(1), async {
                loop {
                    client.receive_available().await;
                    if client_gate.inbound_observed.load(Ordering::Acquire) > inbound_before {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("actor remains active after synthetic completions");
            cancel.send(true).expect("stop completion endpoint");
            assert_target_peers_eof(target_peers).await;
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("completion endpoint reclaims its actor");
        assert_eq!(gate.parent_join_snapshot(), (true, true));
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn t027b2c1_forced_parent_abort_drops_active_futures_before_reclaim() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role();
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind forced-parent endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xd3).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            for expected in 1..=MAX_TARGET_DISPATCH_FUTURES {
                client
                    .send_classic_connect()
                    .expect("queue forced-parent CONNECT");
                client.send_pending().await;
                timeout(
                    Duration::from_secs(1),
                    client_gate.wait_for_dispatch_started(expected),
                )
                .await
                .expect("forced-parent future starts");
                client.receive_available().await;
            }
            let target_peers =
                accept_target_peers(&target_listener, MAX_TARGET_DISPATCH_FUTURES).await;
            assert_eq!(client_gate.dispatch_counts(), (8, 8, 8, 0));
            assert_eq!(target_sink_clone_count(&client_metrics), 11);
            assert_zero_target_open_metrics(&client_metrics);

            client_gate.request_parent_stall();
            client
                .connection
                .send_ack_eliciting()
                .expect("wake actor into forced-parent stall");
            client.send_pending().await;
            timeout(
                Duration::from_secs(1),
                client_gate.parent_stall_started.notified(),
            )
            .await
            .expect("actual connection actor stalls with an active dispatch future");
            cancel
                .send(true)
                .expect("cancel endpoint around stalled connection actor");
            assert_target_peers_eof(target_peers).await;
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        assert_eq!(endpoint_result, Err(EndpointError::Shutdown));
        assert_eq!(gate.dispatch_counts(), (8, 0, 8, 8));
        assert_eq!(
            gate.parent_join_snapshot(),
            (true, true),
            "dispatch Drop guards finish before the parent join is observed and registry is reclaimed"
        );
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_eq!(target_sink_clone_count(&metrics_owner), 2);
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn t027b2c1_every_actor_termination_path_drops_blocked_future() {
        for case in [
            BlockedFutureTermination::EndpointCancel,
            BlockedFutureTermination::HardExpiry,
            BlockedFutureTermination::Revocation,
            BlockedFutureTermination::PeerClose,
            BlockedFutureTermination::LocalClose,
        ] {
            assert_blocked_future_termination(case).await;
        }
    }

    #[tokio::test]
    async fn t027b2c4_every_normal_termination_path_closes_slot_owned_target() {
        for case in [
            BlockedFutureTermination::EndpointCancel,
            BlockedFutureTermination::HardExpiry,
            BlockedFutureTermination::Revocation,
            BlockedFutureTermination::PeerClose,
            BlockedFutureTermination::LocalClose,
        ] {
            assert_slot_owned_target_termination(case).await;
        }
    }

    #[tokio::test]
    async fn t027b2c4_dispatch_timeout_drops_connected_socket_before_handoff() {
        let credentials = TestCredentials::new();
        let owner = credentials.server_role_with_target_timeout(25);
        let metrics_owner = test_metrics_owner();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(Arc::clone(&owner), Arc::clone(&metrics_owner))
                .await
                .expect("bind dispatch-timeout endpoint");
        let gate = Arc::new(ActorTestGate::default());
        gate.block_target_dispatches();
        let target_listener = loopback_target_listener(&gate).await;
        endpoint.next_actor_test_gate = Some(Arc::clone(&gate));
        let server_address = endpoint.local_address;
        let mut client = UdpQuicheClient::new(Ipv4Addr::LOCALHOST, server_address, 0xe5).await;
        let client_gate = Arc::clone(&gate);
        let client_metrics = Arc::clone(&metrics_owner);

        let client_work = async move {
            drive_client_to_h3(&mut client).await;
            client.authenticate_direct_v3(&owner).await;
            client
                .send_classic_connect()
                .expect("queue dispatch-timeout CONNECT");
            client.send_pending().await;
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_dispatch_started(1),
            )
            .await
            .expect("dispatch-timeout future starts");
            let target_peers = accept_target_peers(&target_listener, 1).await;
            timeout(
                Duration::from_secs(1),
                client_gate.wait_for_dispatch_ended(1),
            )
            .await
            .expect("absolute dispatch deadline drops future");
            assert_target_peers_eof(target_peers).await;
            assert_eq!(client_gate.completion_snapshot().0, 0);
            assert_zero_target_open_metrics(&client_metrics);
            cancel.send(true).expect("stop dispatch-timeout endpoint");
        };

        let (endpoint_result, ()) = tokio::join!(endpoint.run(), client_work);
        endpoint_result.expect("dispatch-timeout endpoint joins its actor");
        assert_eq!(endpoint.registry.actor_count(), 0);
        assert!(endpoint.actors.is_empty());
        assert_zero_target_open_metrics(&metrics_owner);
    }

    #[tokio::test]
    async fn t027b2c4_actor_panic_and_forced_abort_close_slot_owned_target_before_reclaim() {
        assert_completed_actor_termination(CompletedActorTermination::Panic).await;
        assert_completed_actor_termination(CompletedActorTermination::ForcedAbort).await;
    }

    #[tokio::test]
    async fn t027b2c1_future_error_and_panic_fail_generation_and_drop_sibling() {
        assert_dispatch_failure_drops_sibling(false).await;
        assert_dispatch_failure_drops_sibling(true).await;
    }

    #[tokio::test]
    async fn t027b2c1_inbox_close_drops_future_before_actor_return() {
        assert_inbox_close_releases_target(false).await;
    }

    #[tokio::test]
    async fn t027b2c4_inbox_close_drops_slot_owned_target_before_actor_return() {
        assert_inbox_close_releases_target(true).await;
    }

    #[tokio::test]
    async fn cancel_during_in_flight_flush_restarts_close_flush_before_waiting() {
        let credentials = TestCredentials::new();
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
        let metrics_owner = test_metrics_owner();
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
            metrics_owner.target_open_sinks(),
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
        let (mut endpoint, cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
        let (mut endpoint, _cancel) =
            Endpoint::bind_test(credentials.server_role(), test_metrics_owner())
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
            ActorError::TargetDispatchUnavailable,
            ActorError::TargetDataUnavailable,
        ];
        for error in actor_errors {
            assert_eq!(format!("{error:?}"), "private server actor error");
            assert!(std::error::Error::source(&error).is_none());
            assert!(!error.to_string().contains("127."));
            assert!(!error.to_string().contains(':'));
        }
        for error in [
            TargetDispatchError::Unavailable,
            TargetDispatchError::Timeout,
            TargetDispatchError::Panic,
        ] {
            assert_eq!(format!("{error:?}"), "private target dispatch error");
            assert!(std::error::Error::source(&error).is_none());
            assert!(error.to_string().len() <= 32);
            assert!(!error.to_string().contains("synthetic.invalid"));
            assert!(!error.to_string().contains("443"));
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
        let production_registry = registry_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production registry source");
        let runtime_source = include_str!("quiche_runtime.rs");
        let production_runtime = runtime_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production runtime source");
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
        assert_eq!(production_endpoint.matches("JoinSet<").count(), 1);
        assert!(production_endpoint.contains("FuturesUnordered<TargetDispatchFuture>"));
        assert!(production_endpoint.contains("connection.wait_target_io_ready()"));
        assert!(production_endpoint.contains("target_io_signal = Some(signal)"));
        let production_actor = production_endpoint
            .split("async fn run_connection_actor(")
            .nth(1)
            .expect("production connection actor source")
            .split("type TargetDispatchFuture")
            .next()
            .expect("production connection actor source ends before target future type");
        assert_eq!(
            production_actor.matches("drive_target_io_round(").count(),
            1
        );
        let actor_wait = production_actor
            .rfind("tokio::select! {")
            .map(|start| &production_actor[start..])
            .expect("production actor has one final biased wait");
        let cancel_position = actor_wait
            .find("changed = cancel.changed()")
            .expect("actor cancel branch exists");
        let timer_position = actor_wait
            .find("tokio::time::sleep_until(actor_deadline)")
            .expect("actor timer branch exists");
        let inbox_position = actor_wait
            .find("inbound = inbox.recv()")
            .expect("actor inbox branch exists");
        let readiness_position = actor_wait
            .find("ready = connection.wait_target_io_ready()")
            .expect("actor target readiness branch exists");
        let immediate_position = actor_wait
            .find("connection.has_immediate_target_io_work()")
            .expect("actor RecvPending continuation branch exists");
        assert!(cancel_position < timer_position);
        assert!(timer_position < inbox_position);
        assert!(inbox_position < readiness_position);
        assert!(readiness_position < immediate_position);
        let immediate_guard = production_runtime
            .split("pub(super) fn has_immediate_target_io_work")
            .nth(1)
            .expect("runtime immediate-work predicate exists")
            .split("pub(super) fn wait_target_io_ready")
            .next()
            .expect("runtime immediate-work predicate remains narrow");
        assert!(immediate_guard.contains("UploadDispatchState::RecvPending"));
        assert!(immediate_guard.contains("UploadDispatchState::ShutdownPending"));
        assert!(!immediate_guard.contains("TargetDispatchState::BodyPending"));
        assert!(!immediate_guard.contains("TargetEofFinPending"));
        assert!(production_endpoint.contains("struct TargetDispatchCompletion"));
        assert!(production_endpoint.contains("opened_target: TcpStream"));
        assert!(production_endpoint.contains("private target dispatch completion"));
        assert!(production_runtime.contains("opened_target: Option<TcpStream>"));
        assert_eq!(
            production_runtime
                .matches("opened_target: Option<TcpStream>")
                .count(),
            1
        );
        assert!(production_endpoint.contains("metrics_owner: Arc<ServerRuntimeMetrics>"));
        assert!(production_endpoint.contains("target_open_sinks: TargetOpenMetricSinks"));
        assert_eq!(
            production_endpoint
                .matches("metrics_owner.target_open_sinks()")
                .count(),
            1
        );
        for forbidden in [
            "ServerRuntimeMetrics::default()",
            "Arc::new(ServerRuntimeMetrics",
            "TargetOpenMetricSinks {",
        ] {
            assert!(!production_endpoint.contains(forbidden));
        }
        for metrics_free_source in [production_registry, production_runtime] {
            assert!(!metrics_free_source.contains("ServerRuntimeMetrics"));
            assert!(!metrics_free_source.contains("TargetOpenMetricSinks"));
        }
        assert!(!production_endpoint.contains("TargetDispatchChildren"));
        assert!(!production_endpoint.contains("run_target_dispatch_child"));
        assert!(!production_endpoint.contains(".spawn(run_target_dispatch_future"));
        assert!(production_endpoint.contains("MAX_TARGET_DISPATCH_FUTURES"));
        assert!(production_endpoint.contains("#[cfg(test)]\nasync fn synthetic_target_dispatch("));
        assert!(production_endpoint.contains("Err(TargetDispatchError::Unavailable)"));
        assert!(production_endpoint.contains("for _ in 0..MAX_OUTBOUND_PACKETS_PER_ROUND"));
        assert!(production_endpoint.contains("tokio::task::yield_now().await"));
        let production_actor_surface = production_endpoint
            .split("#[cfg(test)]\n#[derive(Default)]\nstruct ActorTestGate")
            .next()
            .expect("production endpoint ends before test-only actor gate");
        for forbidden in [
            ["lookup_", "host"].concat(),
            ["send_", "response"].concat(),
            ["recv_", "body"].concat(),
            ["relay_", "tcp"].concat(),
            ["target_", "listener"].concat(),
            "into_split".to_string(),
            "try_write".to_string(),
        ] {
            assert!(!production_actor_surface.contains(&forbidden));
        }
        let test_gate_source = production_endpoint
            .split("#[cfg(test)]\nimpl ActorTestGate")
            .nth(1)
            .expect("test-only actor gate source");
        assert_eq!(production_endpoint.matches("TcpStream::connect").count(), 1);
        assert!(test_gate_source.contains("TcpStream::connect"));
        assert!(!production_runtime.contains("TcpStream::connect"));
        assert!(!production_runtime.contains("TcpListener"));
        for socket_collection in [
            "Vec<TcpStream",
            "VecDeque<TcpStream",
            "[Option<TcpStream>",
            "HashMap<SocketAddr, TcpStream",
        ] {
            assert!(!production_endpoint.contains(socket_collection));
            assert!(!production_runtime.contains(socket_collection));
        }
        let opener = ["open_target_addr_before_deadline", "_with_metrics"].concat();
        assert_eq!(production_endpoint.matches(&opener).count(), 1);
        assert!(!production_runtime.contains(&opener));
        assert!(!production_registry.contains(&opener));
        let production_dispatch = production_endpoint
            .split("let egress_policy = token.egress_policy();")
            .nth(1)
            .expect("production target dispatch begins with frozen egress policy")
            .split("#[cfg(test)]\nasync fn synthetic_target_dispatch(")
            .next()
            .expect("production target dispatch source");
        assert!(production_dispatch.contains(&opener));
        for forbidden in [
            "timeout_at(",
            "sleep_until(",
            "tokio::spawn",
            "JoinSet",
            "send_response",
            "Headers",
            "DATA",
            "relay_target_and_tunnel",
            "ResponsePending",
            "ResponseAccepted",
        ] {
            assert!(!production_dispatch.contains(forbidden));
        }
        assert!(registry_source.contains("sender.try_send(ActorPacket"));
    }
}
