//! Private bounded CID registry for the native-quiche server foundation.
//!
//! This module provides synchronous packet routing and contains no socket, task
//! spawn, or await point. An active actor entry holds only its bounded sender and
//! task ID, never its `ServerConnection`. The retained synchronous foundation
//! path owns its connection in a mutually exclusive enum branch, so the two
//! ownership forms cannot coexist in one slot. The registry owns no Retry token,
//! address-validation claim, target connection, or data plane. The fixed
//! connection caps only bound damage from unauthenticated Initial packets;
//! without Retry they do not prove peer-address ownership or provide
//! spoofing-DoS resistance. CID rotation, retirement, migration, and multipath
//! remain deferred. Existing routes require the exact original `SocketAddr`;
//! NAT rebinding is deliberately unsupported in this slice.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use rand::{rngs::OsRng, TryRngCore};
use tokio::sync::mpsc;
use tokio::task::Id;

use crate::quiche_runtime::{
    ConnectionLifecycle, FrozenDirectV3ServerRole, PacketMeta, ServerConnection,
    ServerConnectionConfig, ServerSourceConnectionId, MAX_PACKET_BYTES,
};

pub(super) const MAX_ACTIVE_CONNECTIONS: usize = 8;
pub(super) const MAX_CONNECTIONS_PER_SOURCE: usize = 2;
const MAX_ALIASES_PER_CONNECTION: usize = 2;
const MAX_ROUTE_KEYS: usize = MAX_ACTIVE_CONNECTIONS * MAX_ALIASES_PER_CONNECTION;
const MAX_SCID_ATTEMPTS: usize = 4;
const MAX_TIMEOUT_SWEEP: usize = MAX_ACTIVE_CONNECTIONS;
const MIN_INITIAL_DCID_LEN: usize = 8;

pub(super) trait ConnectionIdGenerator {
    fn try_fill(&mut self, output: &mut [u8; quiche::MAX_CONN_ID_LEN]) -> Result<(), ()>;
}

pub(super) struct OsConnectionIdGenerator;

impl ConnectionIdGenerator for OsConnectionIdGenerator {
    fn try_fill(&mut self, output: &mut [u8; quiche::MAX_CONN_ID_LEN]) -> Result<(), ()> {
        OsRng.try_fill_bytes(output).map_err(|_| ())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RouteConnectionId {
    bytes: [u8; quiche::MAX_CONN_ID_LEN],
    length: u8,
}

impl RouteConnectionId {
    fn from_slice(value: &[u8]) -> Option<Self> {
        if value.is_empty() || value.len() > quiche::MAX_CONN_ID_LEN {
            return None;
        }
        let mut bytes = [0_u8; quiche::MAX_CONN_ID_LEN];
        bytes[..value.len()].copy_from_slice(value);
        Some(Self {
            bytes,
            length: value.len() as u8,
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

struct ParsedPacket {
    destination: RouteConnectionId,
    can_create_connection: bool,
}

enum ConnectionOwner {
    Synchronous {
        connection: Box<ServerConnection>,
        server_source_id: ServerSourceConnectionId,
    },
    Actor {
        sender: mpsc::Sender<ActorPacket>,
        task_id: Id,
    },
}

struct ConnectionEntry {
    aliases: [RouteConnectionId; MAX_ALIASES_PER_CONNECTION],
    source: SocketAddr,
    owner: ConnectionOwner,
}

pub(super) struct ConnectionRegistry<G = OsConnectionIdGenerator> {
    config: ServerConnectionConfig,
    generator: G,
    entries: [Option<ConnectionEntry>; MAX_ACTIVE_CONNECTIONS],
    next_outbound_index: usize,
}

impl ConnectionRegistry<OsConnectionIdGenerator> {
    pub(super) fn new(role: FrozenDirectV3ServerRole) -> Result<Self, RegistryError> {
        Self::with_generator(role, OsConnectionIdGenerator)
    }
}

impl<G: ConnectionIdGenerator> ConnectionRegistry<G> {
    fn with_generator(role: FrozenDirectV3ServerRole, generator: G) -> Result<Self, RegistryError> {
        let config = ServerConnectionConfig::new(role)
            .map_err(|_| RegistryError::ConfigurationUnavailable)?;
        Ok(Self {
            config,
            generator,
            entries: std::array::from_fn(|_| None),
            next_outbound_index: 0,
        })
    }

    fn receive_packet(
        &mut self,
        packet: &mut [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<InboundDisposition, RegistryError> {
        let Some(parsed) = parse_packet(packet, length) else {
            return Ok(InboundDisposition::Dropped);
        };

        if let Some(index) = self.find_route(&parsed.destination) {
            return self.route_existing(index, packet, length, meta);
        }
        if !parsed.can_create_connection {
            return Ok(InboundDisposition::Dropped);
        }

        self.create_connection(parsed.destination, packet, length, meta)
    }

    fn next_packet(
        &mut self,
        packet: &mut [u8; MAX_PACKET_BYTES],
    ) -> Result<Option<(usize, PacketMeta)>, RegistryError> {
        let start = self.next_outbound_index;
        for offset in 0..MAX_ACTIVE_CONNECTIONS {
            let index = (start + offset) % MAX_ACTIVE_CONNECTIONS;
            let Some(entry) = self.entries[index].as_mut() else {
                continue;
            };
            let ConnectionOwner::Synchronous {
                connection,
                server_source_id,
            } = &mut entry.owner
            else {
                return Err(RegistryError::ConnectionUnavailable);
            };
            if !connection.has_stable_source_connection_id(server_source_id) {
                self.entries[index] = None;
                return Err(RegistryError::StableConnectionIdUnavailable);
            }
            if connection.lifecycle() == ConnectionLifecycle::Closed {
                self.entries[index] = None;
                continue;
            }

            let result = connection.next_packet(packet);
            let stable = connection.has_stable_source_connection_id(server_source_id);
            let closed = connection.lifecycle() == ConnectionLifecycle::Closed;

            if !stable {
                self.entries[index] = None;
                return Err(RegistryError::StableConnectionIdUnavailable);
            }
            match result {
                Ok(Some(output)) => {
                    self.next_outbound_index = (index + 1) % MAX_ACTIVE_CONNECTIONS;
                    if closed {
                        self.entries[index] = None;
                    }
                    return Ok(Some(output));
                }
                Ok(None) => {
                    if closed {
                        self.entries[index] = None;
                    }
                }
                Err(_) => {
                    if closed {
                        self.entries[index] = None;
                    }
                    return Err(RegistryError::PacketUnavailable);
                }
            }
        }
        Ok(None)
    }

    fn next_timeout(&mut self) -> Result<Option<Duration>, RegistryError> {
        let mut next = None;
        for index in 0..MAX_TIMEOUT_SWEEP {
            let Some(entry) = self.entries[index].as_ref() else {
                continue;
            };
            let ConnectionOwner::Synchronous {
                connection,
                server_source_id,
            } = &entry.owner
            else {
                return Err(RegistryError::ConnectionUnavailable);
            };
            if !connection.has_stable_source_connection_id(server_source_id) {
                self.entries[index] = None;
                return Err(RegistryError::StableConnectionIdUnavailable);
            }
            if connection.lifecycle() == ConnectionLifecycle::Closed {
                self.entries[index] = None;
                continue;
            }
            if let Some(timeout) = connection.next_timeout() {
                next = Some(next.map_or(timeout, |current: Duration| current.min(timeout)));
            }
        }
        Ok(next)
    }

    fn on_timeout(&mut self) -> Result<(), RegistryError> {
        let mut failure = None;
        for index in 0..MAX_TIMEOUT_SWEEP {
            let Some(entry) = self.entries[index].as_mut() else {
                continue;
            };
            let ConnectionOwner::Synchronous {
                connection,
                server_source_id,
            } = &mut entry.owner
            else {
                failure.get_or_insert(RegistryError::ConnectionUnavailable);
                continue;
            };
            if !connection.has_stable_source_connection_id(server_source_id) {
                self.entries[index] = None;
                failure.get_or_insert(RegistryError::StableConnectionIdUnavailable);
                continue;
            }
            if connection.lifecycle() == ConnectionLifecycle::Closed {
                self.entries[index] = None;
                continue;
            }

            let result = connection.on_timeout();
            let stable = connection.has_stable_source_connection_id(server_source_id);
            let closed = connection.lifecycle() == ConnectionLifecycle::Closed;
            if !stable || closed {
                self.entries[index] = None;
            }
            if !stable {
                failure.get_or_insert(RegistryError::StableConnectionIdUnavailable);
            } else if result.is_err() {
                failure.get_or_insert(RegistryError::ConnectionUnavailable);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn close_connection(
        &mut self,
        route: &[u8],
        source: SocketAddr,
    ) -> Result<bool, RegistryError> {
        let Some(route) = RouteConnectionId::from_slice(route) else {
            return Ok(false);
        };
        let Some(index) = self.find_route(&route) else {
            return Ok(false);
        };
        if self.entries[index].as_ref().map(|entry| entry.source) != Some(source) {
            return Err(RegistryError::PacketRejected);
        }
        let stable = {
            let entry = self.entries[index]
                .as_ref()
                .expect("route index must contain a connection");
            let ConnectionOwner::Synchronous {
                connection,
                server_source_id,
            } = &entry.owner
            else {
                return Err(RegistryError::ConnectionUnavailable);
            };
            connection.has_stable_source_connection_id(server_source_id)
        };
        if !stable {
            self.entries[index] = None;
            return Err(RegistryError::StableConnectionIdUnavailable);
        }
        let entry = self.entries[index]
            .as_mut()
            .expect("route index must contain a connection");
        let ConnectionOwner::Synchronous { connection, .. } = &mut entry.owner else {
            return Err(RegistryError::ConnectionUnavailable);
        };
        let result = connection.close();
        result
            .map(|()| true)
            .map_err(|_| RegistryError::CloseUnavailable)
    }

    fn route_existing(
        &mut self,
        index: usize,
        packet: &mut [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<InboundDisposition, RegistryError> {
        let entry = self.entries[index]
            .as_mut()
            .expect("route index must contain a connection");
        let ConnectionOwner::Synchronous {
            connection,
            server_source_id,
        } = &mut entry.owner
        else {
            return Err(RegistryError::ConnectionUnavailable);
        };
        if !connection.has_stable_source_connection_id(server_source_id) {
            self.entries[index] = None;
            return Err(RegistryError::StableConnectionIdUnavailable);
        }
        if connection.lifecycle() == ConnectionLifecycle::Closed {
            self.entries[index] = None;
            return Ok(InboundDisposition::Dropped);
        }
        if entry.source != meta.from {
            return Ok(InboundDisposition::Dropped);
        }

        let result = connection.receive_packet(packet, length, meta);
        let stable = connection.has_stable_source_connection_id(server_source_id);
        let closed = connection.lifecycle() == ConnectionLifecycle::Closed;
        if !stable || closed {
            self.entries[index] = None;
        }
        if !stable {
            return Err(RegistryError::StableConnectionIdUnavailable);
        }
        result
            .map(|()| InboundDisposition::Routed)
            .map_err(|_| RegistryError::PacketRejected)
    }

    fn create_connection(
        &mut self,
        client_initial_dcid: RouteConnectionId,
        packet: &mut [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<InboundDisposition, RegistryError> {
        if self.connection_count() >= MAX_ACTIVE_CONNECTIONS
            || self.source_count(meta.from) >= MAX_CONNECTIONS_PER_SOURCE
        {
            return Err(RegistryError::CapacityUnavailable);
        }
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(RegistryError::CapacityUnavailable)?;
        let server_source_id = self.generate_source_connection_id(&client_initial_dcid)?;
        let server_route = RouteConnectionId::from_slice(server_source_id.as_bytes())
            .ok_or(RegistryError::ConnectionIdUnavailable)?;

        let connection = ServerConnection::accept_initial(
            &mut self.config,
            server_source_id,
            packet,
            length,
            meta,
        )
        .map_err(|_| RegistryError::ConnectionUnavailable)?;
        if !connection.has_stable_source_connection_id(&server_source_id)
            || connection.lifecycle() != ConnectionLifecycle::Active
        {
            return Err(RegistryError::StableConnectionIdUnavailable);
        }

        self.entries[slot] = Some(ConnectionEntry {
            aliases: [client_initial_dcid, server_route],
            source: meta.from,
            owner: ConnectionOwner::Synchronous {
                connection: Box::new(connection),
                server_source_id,
            },
        });
        Ok(InboundDisposition::Created)
    }

    fn generate_source_connection_id(
        &mut self,
        client_initial_dcid: &RouteConnectionId,
    ) -> Result<ServerSourceConnectionId, RegistryError> {
        for _ in 0..MAX_SCID_ATTEMPTS {
            let mut bytes = [0_u8; quiche::MAX_CONN_ID_LEN];
            self.generator
                .try_fill(&mut bytes)
                .map_err(|_| RegistryError::ConnectionIdUnavailable)?;
            let candidate = RouteConnectionId::from_slice(&bytes)
                .ok_or(RegistryError::ConnectionIdUnavailable)?;
            if candidate == *client_initial_dcid || self.find_route(&candidate).is_some() {
                continue;
            }
            return Ok(ServerSourceConnectionId::new(bytes));
        }
        Err(RegistryError::ConnectionIdUnavailable)
    }

    fn find_route(&self, route: &RouteConnectionId) -> Option<usize> {
        self.entries.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|entry| entry.aliases.iter().any(|alias| alias == route))
        })
    }

    fn connection_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    fn route_count(&self) -> usize {
        self.connection_count() * MAX_ALIASES_PER_CONNECTION
    }

    fn source_count(&self, source: SocketAddr) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.source.ip() == source.ip())
            })
            .count()
    }

    #[cfg(test)]
    pub(super) fn test_route_count(&self) -> usize {
        self.route_count()
    }

    #[cfg(test)]
    pub(super) fn test_source_count(&self, source: SocketAddr) -> usize {
        self.source_count(source)
    }

    pub(super) fn receive_actor_packet(
        &mut self,
        mut packet: [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    ) -> Result<ActorInboundDisposition, RegistryError> {
        let Some(parsed) = parse_packet(&mut packet, length) else {
            return Ok(ActorInboundDisposition::Dropped);
        };

        if let Some(index) = self.find_route(&parsed.destination) {
            let entry = self.entries[index]
                .as_ref()
                .expect("route index must contain a connection");
            if entry.source != meta.from {
                return Ok(ActorInboundDisposition::Dropped);
            }
            let ConnectionOwner::Actor { sender, .. } = &entry.owner else {
                return Err(RegistryError::ActorUnavailable);
            };
            return match sender.try_send(ActorPacket {
                bytes: packet,
                length,
                meta,
            }) {
                Ok(()) => Ok(ActorInboundDisposition::Routed),
                Err(mpsc::error::TrySendError::Full(_)) => Ok(ActorInboundDisposition::QueueFull),
                Err(mpsc::error::TrySendError::Closed(_)) => Err(RegistryError::ActorUnavailable),
            };
        }
        if !parsed.can_create_connection {
            return Ok(ActorInboundDisposition::Dropped);
        }
        if self.connection_count() >= MAX_ACTIVE_CONNECTIONS
            || self.source_count(meta.from) >= MAX_CONNECTIONS_PER_SOURCE
        {
            return Err(RegistryError::CapacityUnavailable);
        }

        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(RegistryError::CapacityUnavailable)?;
        let server_source_id = self.generate_source_connection_id(&parsed.destination)?;
        let server_route = RouteConnectionId::from_slice(server_source_id.as_bytes())
            .ok_or(RegistryError::ConnectionIdUnavailable)?;
        let connection = ServerConnection::accept_initial(
            &mut self.config,
            server_source_id,
            &mut packet,
            length,
            meta,
        )
        .map_err(|_| RegistryError::ConnectionUnavailable)?;
        if !connection.has_stable_source_connection_id(&server_source_id)
            || connection.lifecycle() != ConnectionLifecycle::Active
        {
            return Err(RegistryError::StableConnectionIdUnavailable);
        }

        Ok(ActorInboundDisposition::Created(Box::new(ActorAdmission {
            slot: ConnectionSlot(slot),
            aliases: [parsed.destination, server_route],
            source: meta.from,
            server_source_id,
            connection,
        })))
    }

    pub(super) fn activate_actor(
        &mut self,
        pending: PendingActorRoute,
        sender: mpsc::Sender<ActorPacket>,
        task_id: Id,
    ) -> Result<(), RegistryError> {
        let index = pending.slot.0;
        if index >= MAX_ACTIVE_CONNECTIONS || self.entries[index].is_some() {
            return Err(RegistryError::ActorUnavailable);
        }
        self.entries[index] = Some(ConnectionEntry {
            aliases: pending.aliases,
            source: pending.source,
            owner: ConnectionOwner::Actor { sender, task_id },
        });
        Ok(())
    }

    pub(super) fn reclaim_joined_actor(&mut self, task_id: Id) -> Option<ConnectionSlot> {
        let index = self.entries.iter().position(|entry| {
            matches!(
                entry.as_ref().map(|entry| &entry.owner),
                Some(ConnectionOwner::Actor {
                    task_id: entry_task_id,
                    ..
                }) if *entry_task_id == task_id
            )
        })?;
        self.entries[index] = None;
        Some(ConnectionSlot(index))
    }

    pub(super) fn actor_count(&self) -> usize {
        self.connection_count()
    }

    #[cfg(test)]
    pub(super) fn test_has_role_owner(
        &self,
        expected: &std::sync::Arc<maverick_core::config::ServerRoleConfig>,
    ) -> bool {
        self.config.has_role_owner(expected)
    }

    pub(super) fn reclaim_all_joined_actors(&mut self) {
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|entry| matches!(&entry.owner, ConnectionOwner::Actor { .. }))
            {
                *entry = None;
            }
        }
    }

    #[cfg(test)]
    fn server_source_id_for_route(&self, route: &[u8]) -> Option<[u8; quiche::MAX_CONN_ID_LEN]> {
        let route = RouteConnectionId::from_slice(route)?;
        let entry = self.entries[self.find_route(&route)?].as_ref()?;
        let ConnectionOwner::Synchronous {
            connection,
            server_source_id,
        } = &entry.owner
        else {
            return None;
        };
        if !connection.has_stable_source_connection_id(server_source_id) {
            return None;
        }
        server_source_id.as_bytes().try_into().ok()
    }

    #[cfg(test)]
    fn is_established_h3_for_route(&self, route: &[u8]) -> bool {
        let Some(route) = RouteConnectionId::from_slice(route) else {
            return false;
        };
        self.find_route(&route)
            .and_then(|index| self.entries[index].as_ref())
            .is_some_and(|entry| {
                matches!(
                    &entry.owner,
                    ConnectionOwner::Synchronous {
                        connection,
                        server_source_id,
                    } if connection.has_stable_source_connection_id(server_source_id)
                            && connection.is_established()
                            && connection.pre_auth_foundation_ready()
                )
            })
    }
}

fn parse_packet(packet: &mut [u8; MAX_PACKET_BYTES], length: usize) -> Option<ParsedPacket> {
    if length == 0 || length > MAX_PACKET_BYTES {
        return None;
    }
    let header = quiche::Header::from_slice(&mut packet[..length], quiche::MAX_CONN_ID_LEN).ok()?;
    let destination = RouteConnectionId::from_slice(header.dcid.as_ref())?;
    let can_create_connection = match header.ty {
        quiche::Type::Initial => {
            quiche::version_is_supported(header.version)
                && (MIN_INITIAL_DCID_LEN..=quiche::MAX_CONN_ID_LEN).contains(&header.dcid.len())
                && header.token.as_deref() == Some(&[])
        }
        quiche::Type::Handshake | quiche::Type::ZeroRTT => {
            if !quiche::version_is_supported(header.version) {
                return None;
            }
            false
        }
        quiche::Type::Short => false,
        quiche::Type::Retry | quiche::Type::VersionNegotiation => return None,
    };
    if header.ty == quiche::Type::Initial && !can_create_connection {
        return None;
    }
    Some(ParsedPacket {
        destination,
        can_create_connection,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundDisposition {
    Dropped,
    Routed,
    Created,
}

pub(super) struct ActorPacket {
    pub(super) bytes: [u8; MAX_PACKET_BYTES],
    pub(super) length: usize,
    pub(super) meta: PacketMeta,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ConnectionSlot(usize);

impl ConnectionSlot {
    pub(super) fn index(self) -> usize {
        self.0
    }
}

pub(super) struct ActorAdmission {
    slot: ConnectionSlot,
    aliases: [RouteConnectionId; MAX_ALIASES_PER_CONNECTION],
    source: SocketAddr,
    server_source_id: ServerSourceConnectionId,
    connection: ServerConnection,
}

impl ActorAdmission {
    pub(super) fn into_parts(
        self,
    ) -> (
        PendingActorRoute,
        ServerConnection,
        ServerSourceConnectionId,
    ) {
        (
            PendingActorRoute {
                slot: self.slot,
                aliases: self.aliases,
                source: self.source,
            },
            self.connection,
            self.server_source_id,
        )
    }
}

pub(super) struct PendingActorRoute {
    slot: ConnectionSlot,
    aliases: [RouteConnectionId; MAX_ALIASES_PER_CONNECTION],
    source: SocketAddr,
}

impl PendingActorRoute {
    pub(super) fn slot(&self) -> ConnectionSlot {
        self.slot
    }
}

pub(super) enum ActorInboundDisposition {
    Dropped,
    Routed,
    QueueFull,
    Created(Box<ActorAdmission>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RegistryError {
    ConfigurationUnavailable,
    CapacityUnavailable,
    ConnectionIdUnavailable,
    ConnectionUnavailable,
    ActorUnavailable,
    PacketRejected,
    PacketUnavailable,
    StableConnectionIdUnavailable,
    CloseUnavailable,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConfigurationUnavailable => "server registry configuration unavailable",
            Self::CapacityUnavailable => "server registry capacity unavailable",
            Self::ConnectionIdUnavailable => "server connection identifier unavailable",
            Self::ConnectionUnavailable => "server registry connection unavailable",
            Self::ActorUnavailable => "server registry actor unavailable",
            Self::PacketRejected => "server registry packet rejected",
            Self::PacketUnavailable => "server registry packet unavailable",
            Self::StableConnectionIdUnavailable => {
                "stable server connection identifier unavailable"
            }
            Self::CloseUnavailable => "server registry close unavailable",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private server registry error")
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::quiche_runtime::{
        bounded_h3_config, bounded_transport_config, FrozenDirectV3ServerRole, PacketMeta,
        MAX_PACKET_BYTES,
    };

    use super::*;

    const CLIENT_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_001);
    const SECOND_CLIENT_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_011);
    const SERVER_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_002);
    const MAX_TEST_GENERATOR_VALUES: usize = 32;
    const MAX_TEST_DRIVE_STEPS: usize = 128;

    struct ScriptedConnectionIdGenerator {
        values: [[u8; quiche::MAX_CONN_ID_LEN]; MAX_TEST_GENERATOR_VALUES],
        value_count: usize,
        calls: usize,
        fail_at: Option<usize>,
    }

    impl ScriptedConnectionIdGenerator {
        fn from_values(values: &[[u8; quiche::MAX_CONN_ID_LEN]]) -> Self {
            assert!(values.len() <= MAX_TEST_GENERATOR_VALUES);
            let mut stored = [[0_u8; quiche::MAX_CONN_ID_LEN]; MAX_TEST_GENERATOR_VALUES];
            stored[..values.len()].copy_from_slice(values);
            Self {
                values: stored,
                value_count: values.len(),
                calls: 0,
                fail_at: None,
            }
        }

        fn incrementing() -> Self {
            let mut values = [[0_u8; quiche::MAX_CONN_ID_LEN]; MAX_TEST_GENERATOR_VALUES];
            for (index, value) in values.iter_mut().enumerate() {
                value.fill(0x80_u8.wrapping_add(index as u8));
            }
            Self {
                values,
                value_count: MAX_TEST_GENERATOR_VALUES,
                calls: 0,
                fail_at: None,
            }
        }

        fn failing_first() -> Self {
            let mut generator = Self::incrementing();
            generator.fail_at = Some(0);
            generator
        }
    }

    impl ConnectionIdGenerator for ScriptedConnectionIdGenerator {
        fn try_fill(&mut self, output: &mut [u8; quiche::MAX_CONN_ID_LEN]) -> Result<(), ()> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at == Some(call) || call >= self.value_count {
                return Err(());
            }
            output.copy_from_slice(&self.values[call]);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct TestPacket {
        bytes: [u8; MAX_PACKET_BYTES],
        length: usize,
        meta: PacketMeta,
    }

    struct SyntheticClient {
        transport: quiche::Connection,
        h3: Option<quiche::h3::Connection>,
        address: SocketAddr,
    }

    impl SyntheticClient {
        fn new(address: SocketAddr, source_id_byte: u8) -> Self {
            let mut config = bounded_transport_config().expect("create bounded client config");
            config.verify_peer(false);
            let source_id = [source_id_byte; quiche::MAX_CONN_ID_LEN];
            let source_id = quiche::ConnectionId::from_ref(&source_id);
            let transport = quiche::connect(
                Some("localhost"),
                &source_id,
                address,
                SERVER_ADDRESS,
                &mut config,
            )
            .expect("construct synthetic client");
            Self {
                transport,
                h3: None,
                address,
            }
        }

        fn next_packet(&mut self) -> Option<TestPacket> {
            let mut bytes = [0_u8; MAX_PACKET_BYTES];
            match self.transport.send(&mut bytes) {
                Ok((length, info)) => Some(TestPacket {
                    bytes,
                    length,
                    meta: PacketMeta {
                        from: info.from,
                        to: info.to,
                    },
                }),
                Err(quiche::Error::Done) => None,
                Err(_) => panic!("synthetic client packet unavailable"),
            }
        }

        fn receive(&mut self, mut packet: TestPacket) {
            self.transport
                .recv(
                    &mut packet.bytes[..packet.length],
                    quiche::RecvInfo {
                        from: packet.meta.from,
                        to: packet.meta.to,
                    },
                )
                .expect("synthetic client receives routed packet");
        }

        fn ensure_h3(&mut self) {
            if self.transport.is_established() && self.h3.is_none() {
                let config = bounded_h3_config().expect("create bounded client H3 config");
                self.h3 = Some(
                    quiche::h3::Connection::with_transport(&mut self.transport, &config)
                        .expect("construct synthetic client H3 state"),
                );
            }
        }
    }

    fn test_registry(
        generator: ScriptedConnectionIdGenerator,
    ) -> ConnectionRegistry<ScriptedConnectionIdGenerator> {
        let directory = tempfile::tempdir().expect("create private test directory");
        let certificate_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("create synthetic test certificate");
        std::fs::write(&certificate_path, certified.cert.pem())
            .expect("write synthetic test certificate");
        std::fs::write(&key_path, certified.key_pair.serialize_pem())
            .expect("write synthetic test key");
        let yaml = format!(
            r#"version: 3
role: server
security: {{ posture: standard }}
transport: {{ strategy: h3 }}
trust: {{ route: direct_to_maverick }}
name_privacy: {{ minimum: plain_sni }}
traffic_shaping: {{ policy: disabled }}
listen: "127.0.0.1:0"
tls:
  cert_path: "{}"
  key_path: "{}"
maverick:
  tunnel_path: "/direct-v3"
  expected_authority: "localhost"
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
        let owner = std::sync::Arc::new(
            maverick_core::config::ServerRoleConfig::from_yaml_str(&yaml)
                .expect("parse synthetic server role"),
        );
        let role = FrozenDirectV3ServerRole::new(owner).expect("freeze synthetic server role");
        ConnectionRegistry::with_generator(role, generator).expect("construct bounded registry")
    }

    fn first_packet(client: &mut SyntheticClient) -> TestPacket {
        client.next_packet().expect("synthetic client Initial")
    }

    fn destination_id(packet: &mut TestPacket) -> RouteConnectionId {
        let header =
            quiche::Header::from_slice(&mut packet.bytes[..packet.length], quiche::MAX_CONN_ID_LEN)
                .expect("parse synthetic packet header");
        RouteConnectionId::from_slice(header.dcid.as_ref())
            .expect("copy synthetic destination connection ID")
    }

    fn receive(
        registry: &mut ConnectionRegistry<ScriptedConnectionIdGenerator>,
        packet: &mut TestPacket,
    ) -> Result<InboundDisposition, RegistryError> {
        registry.receive_packet(&mut packet.bytes, packet.length, packet.meta)
    }

    fn drive_two_clients_to_h3(
        registry: &mut ConnectionRegistry<ScriptedConnectionIdGenerator>,
        first: &mut SyntheticClient,
        first_route: &[u8],
        second: &mut SyntheticClient,
        second_route: &[u8],
    ) {
        for _ in 0..MAX_TEST_DRIVE_STEPS {
            if let Some(mut packet) = first.next_packet() {
                assert_ne!(
                    receive(registry, &mut packet).expect("route first client packet"),
                    InboundDisposition::Dropped
                );
            }
            if let Some(mut packet) = second.next_packet() {
                assert_ne!(
                    receive(registry, &mut packet).expect("route second client packet"),
                    InboundDisposition::Dropped
                );
            }

            for _ in 0..MAX_ROUTE_KEYS {
                let mut bytes = [0_u8; MAX_PACKET_BYTES];
                let Some((length, meta)) = registry
                    .next_packet(&mut bytes)
                    .expect("produce one bounded server packet")
                else {
                    break;
                };
                let packet = TestPacket {
                    bytes,
                    length,
                    meta,
                };
                if meta.to == first.address {
                    first.receive(packet);
                } else if meta.to == second.address {
                    second.receive(packet);
                } else {
                    panic!("server packet crossed synthetic client routes");
                }
            }

            first.ensure_h3();
            second.ensure_h3();
            if first.h3.is_some()
                && second.h3.is_some()
                && registry.is_established_h3_for_route(first_route)
                && registry.is_established_h3_for_route(second_route)
            {
                return;
            }
        }
        panic!("bounded registry clients did not reach H3");
    }

    fn header_only_initial(dcid_length: usize, token: Option<u8>) -> TestPacket {
        let mut packet = TestPacket {
            bytes: [0_u8; MAX_PACKET_BYTES],
            length: 0,
            meta: PacketMeta {
                from: CLIENT_ADDRESS,
                to: SERVER_ADDRESS,
            },
        };
        packet.bytes[0] = 0xc0;
        packet.bytes[1..5].copy_from_slice(&quiche::PROTOCOL_VERSION.to_be_bytes());
        packet.bytes[5] = dcid_length as u8;
        packet.bytes[6..6 + dcid_length].fill(0x31);
        let mut cursor = 6 + dcid_length;
        packet.bytes[cursor] = 0;
        cursor += 1;
        packet.bytes[cursor] = usize::from(token.is_some()) as u8;
        cursor += 1;
        if let Some(token) = token {
            packet.bytes[cursor] = token;
            cursor += 1;
        }
        packet.length = cursor;
        packet
    }

    fn add_nonempty_token(mut packet: TestPacket) -> TestPacket {
        let (dcid_length, scid_length) = {
            let header = quiche::Header::from_slice(
                &mut packet.bytes[..packet.length],
                quiche::MAX_CONN_ID_LEN,
            )
            .expect("parse tokenless Initial");
            (header.dcid.len(), header.scid.len())
        };
        let token_length_offset = 1 + 4 + 1 + dcid_length + 1 + scid_length;
        assert_eq!(packet.bytes[token_length_offset], 0);
        packet.bytes.copy_within(
            token_length_offset + 1..packet.length,
            token_length_offset + 2,
        );
        packet.bytes[token_length_offset] = 1;
        packet.bytes[token_length_offset + 1] = 0x5a;
        packet.length += 1;
        packet
    }

    #[test]
    fn unknown_and_invalid_packets_are_silent_and_never_create_output() {
        let mut registry = test_registry(ScriptedConnectionIdGenerator::incrementing());
        let mut packet = [0_u8; MAX_PACKET_BYTES];
        packet[0] = 0x40;
        packet[1..=quiche::MAX_CONN_ID_LEN].fill(0x33);
        assert_eq!(
            registry
                .receive_packet(
                    &mut packet,
                    quiche::MAX_CONN_ID_LEN + 1,
                    PacketMeta {
                        from: CLIENT_ADDRESS,
                        to: SERVER_ADDRESS,
                    },
                )
                .expect("unknown non-Initial must be silently dropped"),
            InboundDisposition::Dropped
        );

        let mut empty = [0_u8; MAX_PACKET_BYTES];
        assert_eq!(
            registry
                .receive_packet(
                    &mut empty,
                    0,
                    PacketMeta {
                        from: CLIENT_ADDRESS,
                        to: SERVER_ADDRESS,
                    },
                )
                .expect("malformed packet must be silently dropped"),
            InboundDisposition::Dropped
        );

        let mut client = SyntheticClient::new(CLIENT_ADDRESS, 0x41);
        let initial = first_packet(&mut client);
        let mut unsupported = initial;
        unsupported.bytes[1..5].copy_from_slice(&0x0a0a_0a0a_u32.to_be_bytes());
        assert!(!quiche::version_is_supported(0x0a0a_0a0a));
        assert_eq!(
            receive(&mut registry, &mut unsupported)
                .expect("unsupported Initial must be silently dropped"),
            InboundDisposition::Dropped
        );

        let mut tokened = add_nonempty_token(initial);
        assert_eq!(
            receive(&mut registry, &mut tokened)
                .expect("non-empty Initial token must be silently dropped"),
            InboundDisposition::Dropped
        );
        assert_eq!(registry.connection_count(), 0);
        assert_eq!(registry.route_count(), 0);
        assert_eq!(registry.generator.calls, 0);
        let mut output = [0_u8; MAX_PACKET_BYTES];
        assert!(registry
            .next_packet(&mut output)
            .expect("dropped packets create no response")
            .is_none());
    }

    #[test]
    fn initial_envelope_requires_supported_version_dcid_bounds_and_empty_token() {
        for length in [MIN_INITIAL_DCID_LEN, quiche::MAX_CONN_ID_LEN] {
            let mut packet = header_only_initial(length, None);
            let parsed = parse_packet(&mut packet.bytes, packet.length)
                .expect("bounded tokenless supported Initial envelope");
            assert!(parsed.can_create_connection);
            assert_eq!(parsed.destination.as_slice().len(), length);
        }
        for length in [MIN_INITIAL_DCID_LEN - 1, quiche::MAX_CONN_ID_LEN + 1] {
            let mut packet = header_only_initial(length, None);
            assert!(parse_packet(&mut packet.bytes, packet.length).is_none());
        }
        let mut tokened = header_only_initial(MIN_INITIAL_DCID_LEN, Some(0x01));
        assert!(parse_packet(&mut tokened.bytes, tokened.length).is_none());
    }

    #[test]
    fn two_clients_have_distinct_live_scids_and_never_cross_routes() {
        let first_server_id = [0xa1; quiche::MAX_CONN_ID_LEN];
        let second_server_id = [0xb2; quiche::MAX_CONN_ID_LEN];
        let mut registry = test_registry(ScriptedConnectionIdGenerator::from_values(&[
            first_server_id,
            second_server_id,
        ]));
        let mut first = SyntheticClient::new(CLIENT_ADDRESS, 0x51);
        let mut second = SyntheticClient::new(SECOND_CLIENT_ADDRESS, 0x61);
        let mut first_initial = first_packet(&mut first);
        let mut second_initial = first_packet(&mut second);
        let first_initial_dcid = destination_id(&mut first_initial);
        let second_initial_dcid = destination_id(&mut second_initial);

        assert_ne!(first_initial_dcid.as_slice(), first_server_id.as_ref());
        assert_ne!(second_initial_dcid.as_slice(), second_server_id.as_ref());
        assert!(first_initial_dcid != second_initial_dcid);
        assert_eq!(
            receive(&mut registry, &mut first_initial).expect("accept first Initial"),
            InboundDisposition::Created
        );
        assert_eq!(
            receive(&mut registry, &mut second_initial).expect("accept second Initial"),
            InboundDisposition::Created
        );
        assert_eq!(
            registry.server_source_id_for_route(first_initial_dcid.as_slice()),
            Some(first_server_id)
        );
        assert_eq!(
            registry.server_source_id_for_route(second_initial_dcid.as_slice()),
            Some(second_server_id)
        );
        assert_ne!(first_server_id, second_server_id);

        drive_two_clients_to_h3(
            &mut registry,
            &mut first,
            first_initial_dcid.as_slice(),
            &mut second,
            second_initial_dcid.as_slice(),
        );
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.route_count(), 4);
        assert_eq!(registry.source_count(CLIENT_ADDRESS), 2);
        assert_eq!(registry.source_count(SECOND_CLIENT_ADDRESS), 2);
        assert_eq!(
            registry.server_source_id_for_route(&first_server_id),
            Some(first_server_id)
        );
        assert_eq!(
            registry.server_source_id_for_route(&second_server_id),
            Some(second_server_id)
        );
    }

    #[test]
    fn initial_retransmit_reuses_one_connection_and_server_scid_routes_followup() {
        let server_id = [0xa7; quiche::MAX_CONN_ID_LEN];
        let mut registry = test_registry(ScriptedConnectionIdGenerator::from_values(&[server_id]));
        let mut client = SyntheticClient::new(CLIENT_ADDRESS, 0x52);
        let mut initial = first_packet(&mut client);
        let mut retransmit = initial;
        let initial_dcid = destination_id(&mut initial);

        assert_eq!(
            receive(&mut registry, &mut initial).expect("accept Initial"),
            InboundDisposition::Created
        );
        assert_eq!(
            receive(&mut registry, &mut retransmit).expect("route retransmitted Initial"),
            InboundDisposition::Routed
        );
        assert_eq!(registry.connection_count(), 1);
        assert_eq!(registry.route_count(), 2);
        assert_eq!(registry.generator.calls, 1);

        let mut output = [0_u8; MAX_PACKET_BYTES];
        let (length, meta) = registry
            .next_packet(&mut output)
            .expect("produce server handshake packet")
            .expect("server handshake packet exists");
        client.receive(TestPacket {
            bytes: output,
            length,
            meta,
        });
        let mut followup = first_packet(&mut client);
        assert_eq!(destination_id(&mut followup).as_slice(), server_id.as_ref());
        assert_eq!(
            receive(&mut registry, &mut followup).expect("route server-SCID packet"),
            InboundDisposition::Routed
        );
        assert_eq!(registry.connection_count(), 1);
        assert_eq!(
            registry.server_source_id_for_route(initial_dcid.as_slice()),
            Some(server_id)
        );
        assert_eq!(
            registry.server_source_id_for_route(&server_id),
            Some(server_id)
        );
    }

    #[test]
    fn per_source_cap_uses_ip_but_known_routes_require_full_socket_address() {
        let mut registry = test_registry(ScriptedConnectionIdGenerator::incrementing());
        let first_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_001);
        let second_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_002);
        let third_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_003);
        let mut first = SyntheticClient::new(first_address, 0x53);
        let mut second = SyntheticClient::new(second_address, 0x54);
        let mut third = SyntheticClient::new(third_address, 0x55);
        let mut first_initial = first_packet(&mut first);
        let mut wrong_address_replay = first_initial;
        let mut exact_replay = first_initial;
        let mut second_initial = first_packet(&mut second);
        let mut third_initial = first_packet(&mut third);

        assert_eq!(
            receive(&mut registry, &mut first_initial).expect("accept first source-IP Initial"),
            InboundDisposition::Created
        );
        wrong_address_replay.meta.from = second_address;
        assert_eq!(
            receive(&mut registry, &mut wrong_address_replay)
                .expect("wrong full address is silently dropped"),
            InboundDisposition::Dropped
        );
        assert_eq!(registry.connection_count(), 1);
        assert_eq!(
            receive(&mut registry, &mut exact_replay).expect("exact address remains routable"),
            InboundDisposition::Routed
        );
        assert_eq!(
            receive(&mut registry, &mut second_initial).expect("accept second same-IP Initial"),
            InboundDisposition::Created
        );
        assert_eq!(registry.source_count(first_address), 2);
        assert_eq!(
            receive(&mut registry, &mut third_initial)
                .expect_err("same IP with another port reaches the source cap"),
            RegistryError::CapacityUnavailable
        );
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.route_count(), 4);
        assert_eq!(registry.generator.calls, 2);
    }

    #[test]
    fn global_cap_is_checked_before_rng_or_connection_creation() {
        let mut registry = test_registry(ScriptedConnectionIdGenerator::incrementing());
        for index in 0..MAX_ACTIVE_CONNECTIONS {
            let address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1 + index as u8)),
                44_000 + index as u16,
            );
            let mut client = SyntheticClient::new(address, 0x60 + index as u8);
            let mut initial = first_packet(&mut client);
            assert_eq!(
                receive(&mut registry, &mut initial).expect("fill bounded global registry"),
                InboundDisposition::Created
            );
        }
        assert_eq!(registry.connection_count(), MAX_ACTIVE_CONNECTIONS);
        assert_eq!(registry.route_count(), MAX_ROUTE_KEYS);
        assert_eq!(registry.generator.calls, MAX_ACTIVE_CONNECTIONS);

        let overflow_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 1)), 44_100);
        let mut overflow_client = SyntheticClient::new(overflow_address, 0x70);
        let mut overflow_initial = first_packet(&mut overflow_client);
        assert_eq!(
            receive(&mut registry, &mut overflow_initial)
                .expect_err("ninth connection reaches global cap"),
            RegistryError::CapacityUnavailable
        );
        assert_eq!(registry.generator.calls, MAX_ACTIVE_CONNECTIONS);
        assert_eq!(registry.connection_count(), MAX_ACTIVE_CONNECTIONS);
        assert_eq!(registry.route_count(), MAX_ROUTE_KEYS);
    }

    #[test]
    fn rng_failure_and_four_collisions_leave_no_partial_connection() {
        let mut failing_registry = test_registry(ScriptedConnectionIdGenerator::failing_first());
        let mut client = SyntheticClient::new(CLIENT_ADDRESS, 0x71);
        let mut initial = first_packet(&mut client);
        assert_eq!(
            receive(&mut failing_registry, &mut initial).expect_err("RNG failure must fail closed"),
            RegistryError::ConnectionIdUnavailable
        );
        assert_eq!(failing_registry.connection_count(), 0);
        assert_eq!(failing_registry.route_count(), 0);

        let collision_id = [0xc1; quiche::MAX_CONN_ID_LEN];
        let collisions = [collision_id; MAX_SCID_ATTEMPTS + 1];
        let mut collision_registry =
            test_registry(ScriptedConnectionIdGenerator::from_values(&collisions));
        let mut first_collision_client = SyntheticClient::new(CLIENT_ADDRESS, 0x72);
        let mut first_collision_initial = first_packet(&mut first_collision_client);
        assert_eq!(
            receive(&mut collision_registry, &mut first_collision_initial)
                .expect("install first server SCID"),
            InboundDisposition::Created
        );
        let mut collision_client = SyntheticClient::new(SECOND_CLIENT_ADDRESS, 0x73);
        let mut collision_initial = first_packet(&mut collision_client);
        assert_eq!(
            receive(&mut collision_registry, &mut collision_initial)
                .expect_err("four existing server-SCID collisions must fail closed"),
            RegistryError::ConnectionIdUnavailable
        );
        assert_eq!(collision_registry.generator.calls, MAX_SCID_ATTEMPTS + 1);
        assert_eq!(collision_registry.connection_count(), 1);
        assert_eq!(collision_registry.route_count(), 2);

        let unique_server_id = [0xd1; quiche::MAX_CONN_ID_LEN];
        let mut corrupt_registry = test_registry(ScriptedConnectionIdGenerator::from_values(&[
            unique_server_id,
        ]));
        let mut corrupt_client = SyntheticClient::new(CLIENT_ADDRESS, 0x74);
        let mut corrupt_initial = first_packet(&mut corrupt_client);
        assert!(corrupt_initial.length > 64);
        corrupt_initial.length = 64;
        assert_eq!(
            receive(&mut corrupt_registry, &mut corrupt_initial)
                .expect_err("invalid encrypted Initial must not insert"),
            RegistryError::ConnectionUnavailable
        );
        assert_eq!(corrupt_registry.connection_count(), 0);
        assert_eq!(corrupt_registry.route_count(), 0);
    }

    #[test]
    fn local_close_retains_aliases_source_and_capacity_until_transport_is_closed() {
        let mut registry = test_registry(ScriptedConnectionIdGenerator::incrementing());
        let first_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_001);
        let second_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_002);
        let replacement_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_003);
        let mut first = SyntheticClient::new(first_address, 0x74);
        let mut second = SyntheticClient::new(second_address, 0x75);
        let mut replacement = SyntheticClient::new(replacement_address, 0x76);
        let mut first_initial = first_packet(&mut first);
        let mut second_initial = first_packet(&mut second);
        let mut replacement_initial = first_packet(&mut replacement);
        let first_initial_dcid = destination_id(&mut first_initial);

        assert_eq!(
            receive(&mut registry, &mut first_initial).unwrap(),
            InboundDisposition::Created
        );
        assert_eq!(
            receive(&mut registry, &mut second_initial).unwrap(),
            InboundDisposition::Created
        );
        drive_two_clients_to_h3(
            &mut registry,
            &mut first,
            first_initial_dcid.as_slice(),
            &mut second,
            destination_id(&mut second_initial).as_slice(),
        );
        let first_server_id = registry
            .server_source_id_for_route(first_initial_dcid.as_slice())
            .expect("first live server source ID");
        assert!(registry
            .close_connection(&first_server_id, first_address)
            .expect("request first connection close"));
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.route_count(), 4);
        assert_eq!(registry.source_count(first_address), 2);
        assert_eq!(
            registry.server_source_id_for_route(first_initial_dcid.as_slice()),
            Some(first_server_id)
        );
        assert_eq!(
            registry.server_source_id_for_route(&first_server_id),
            Some(first_server_id)
        );
        assert_eq!(
            receive(&mut registry, &mut replacement_initial)
                .expect_err("closing connection still holds same-IP capacity"),
            RegistryError::CapacityUnavailable
        );

        for _ in 0..MAX_ROUTE_KEYS {
            let mut bytes = [0_u8; MAX_PACKET_BYTES];
            let Some((length, meta)) = registry
                .next_packet(&mut bytes)
                .expect("produce pending close packet")
            else {
                break;
            };
            let packet = TestPacket {
                bytes,
                length,
                meta,
            };
            if meta.to == first.address {
                first.receive(packet);
            } else if meta.to == second.address {
                second.receive(packet);
            } else {
                panic!("server close packet crossed synthetic client routes");
            }
            if first.transport.peer_error().is_some() {
                break;
            }
        }
        let peer_error = first
            .transport
            .peer_error()
            .expect("real peer receives the server CONNECTION_CLOSE");
        assert!(peer_error.is_app);
        assert_eq!(peer_error.error_code, 0);
        assert!(peer_error.reason.is_empty());
        assert_eq!(registry.connection_count(), 2);
        assert_eq!(registry.route_count(), 4);

        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if registry.find_route(&first_initial_dcid).is_none() {
                    break;
                }
                let wait = registry
                    .next_timeout()
                    .expect("read retained draining timeout")
                    .expect("draining connection keeps a timer");
                assert!(
                    std::time::Instant::now() + wait <= deadline,
                    "draining timeout stays inside the test deadline"
                );
                std::thread::park_timeout(wait);
                registry
                    .on_timeout()
                    .expect("drive retained draining timeout");
            }

            assert_eq!(registry.connection_count(), 1);
            assert_eq!(registry.route_count(), 2);
            assert_eq!(registry.source_count(first_address), 1);
            assert!(registry
                .server_source_id_for_route(first_initial_dcid.as_slice())
                .is_none());
            assert!(registry
                .server_source_id_for_route(&first_server_id)
                .is_none());

            assert_eq!(
                receive(&mut registry, &mut replacement_initial)
                    .expect("reclaimed same-IP capacity accepts replacement"),
                InboundDisposition::Created
            );
            assert_eq!(registry.connection_count(), 2);
            assert_eq!(registry.route_count(), 4);
            assert_eq!(registry.source_count(replacement_address), 2);
            finished_tx.send(()).expect("report timer-drive completion");
        });
        finished_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("draining connection closes within the bounded worker deadline");
        worker.join().expect("join bounded timer-drive worker");
    }

    #[test]
    fn timeout_sweep_retains_pending_close_before_protocol_deadline() {
        let mut registry = test_registry(ScriptedConnectionIdGenerator::incrementing());
        let mut client = SyntheticClient::new(CLIENT_ADDRESS, 0x77);
        let mut initial = first_packet(&mut client);
        let route = destination_id(&mut initial);
        assert_eq!(
            receive(&mut registry, &mut initial).unwrap(),
            InboundDisposition::Created
        );
        let index = registry
            .find_route(&route)
            .expect("route exists before close");
        let entry = registry.entries[index]
            .as_mut()
            .expect("connection entry exists");
        let ConnectionOwner::Synchronous { connection, .. } = &mut entry.owner else {
            panic!("test entry must use synchronous ownership");
        };
        connection.close().expect("request connection close");
        assert_eq!(
            connection.lifecycle(),
            ConnectionLifecycle::ClosingPendingSend
        );
        registry.on_timeout().expect("bounded timeout sweep");
        assert_eq!(registry.connection_count(), 1);
        assert_eq!(registry.route_count(), 2);
        assert_eq!(registry.source_count(CLIENT_ADDRESS), 1);
    }

    #[test]
    fn registry_api_is_synchronous_bounded_and_privacy_safe() {
        type Registry = ConnectionRegistry<ScriptedConnectionIdGenerator>;
        type ReceiveFn = fn(
            &mut Registry,
            &mut [u8; MAX_PACKET_BYTES],
            usize,
            PacketMeta,
        ) -> Result<InboundDisposition, RegistryError>;
        type NextPacketFn = fn(
            &mut Registry,
            &mut [u8; MAX_PACKET_BYTES],
        ) -> Result<Option<(usize, PacketMeta)>, RegistryError>;
        type NextTimeoutFn = fn(&mut Registry) -> Result<Option<Duration>, RegistryError>;
        type OnTimeoutFn = fn(&mut Registry) -> Result<(), RegistryError>;
        let receive_packet: ReceiveFn = Registry::receive_packet;
        let next_packet: NextPacketFn = Registry::next_packet;
        let next_timeout: NextTimeoutFn = Registry::next_timeout;
        let on_timeout: OnTimeoutFn = Registry::on_timeout;
        let _ = (receive_packet, next_packet, next_timeout, on_timeout);

        assert_eq!(MAX_PACKET_BYTES, 1_350);
        assert_eq!(MAX_ACTIVE_CONNECTIONS, 8);
        assert_eq!(MAX_CONNECTIONS_PER_SOURCE, 2);
        assert_eq!(MAX_ALIASES_PER_CONNECTION, 2);
        assert_eq!(MAX_ROUTE_KEYS, 16);
        assert_eq!(MAX_SCID_ATTEMPTS, 4);
        assert_eq!(MAX_TIMEOUT_SWEEP, 8);

        let errors = [
            RegistryError::ConfigurationUnavailable,
            RegistryError::CapacityUnavailable,
            RegistryError::ConnectionIdUnavailable,
            RegistryError::ConnectionUnavailable,
            RegistryError::ActorUnavailable,
            RegistryError::PacketRejected,
            RegistryError::PacketUnavailable,
            RegistryError::StableConnectionIdUnavailable,
            RegistryError::CloseUnavailable,
        ];
        for error in errors {
            let display = error.to_string();
            assert!(display.len() < 64);
            assert!(!display.contains("127."));
            assert!(!display.contains(':'));
            assert_eq!(format!("{error:?}"), "private server registry error");
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn source_scan_keeps_registry_network_free_and_runtime_slot_owned_only() {
        let registry_source = include_str!("quiche_registry.rs");
        let runtime_source = include_str!("quiche_runtime.rs");
        let registry_production = registry_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production registry source");
        let runtime_production = runtime_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production runtime source");

        for forbidden in [
            "quiche::retry(",
            "accept_with_retry",
            ".new_scid(",
            "UdpSocket",
            "TcpStream",
            "TcpListener",
            "async fn",
            ".await",
            "tokio::spawn",
            "JoinSet<",
            "FuturesUnordered",
            "mpsc::channel(",
            "opened_target",
            "TargetOpenDispatchToken",
        ] {
            assert!(!registry_production.contains(forbidden));
        }

        assert!(runtime_production.contains("use tokio::net::TcpStream;"));
        assert_eq!(
            runtime_production
                .matches("opened_target: Option<TcpStream>")
                .count(),
            1
        );
        assert!(runtime_production.contains("pending.opened_target = Some(opened_target);"));
        assert!(!runtime_production.contains("type ConnectedTarget"));

        for forbidden in [
            "quiche::retry(",
            "accept_with_retry",
            ".new_scid(",
            "UdpSocket",
            "TcpListener",
            "TcpStream::connect",
            "lookup_host",
            "open_target_addr_before_deadline_with_metrics",
            "async fn",
            ".await",
            "tokio::spawn",
            "mpsc::channel(",
            "Vec<TcpStream",
            "VecDeque<TcpStream",
            "[Option<TcpStream>",
            "HashMap<SocketAddr, TcpStream",
        ] {
            assert!(!runtime_production.contains(forbidden));
        }
    }
}
