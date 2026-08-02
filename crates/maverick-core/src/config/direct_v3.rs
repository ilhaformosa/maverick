//! Strict pre-runtime parser and projection for direct-v3 role configuration.
//!
//! Config schema 3 is independent from auth wire v3 and stored-profile schema
//! version 1. Parsing constructs only locally owned singleton provisioning,
//! one byte-exact trusted expected authority, and a preselected capability. It
//! does not construct trusted connection observations, read wire bytes, access
//! a secret store, or enable runtime.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::auth_v3::{
    AuthV3Carrier, AuthV3OwnedProvisioningProfile, AuthV3PreselectedProfile,
    AuthV3ProvisioningHandle, AuthV3SingletonBinding,
};
use crate::error::{Error, Result};

use super::{validate_cert_pin, SecretString};

const INVALID_CLIENT_ROLE: &str = "invalid config v3 client role";
const INVALID_SERVER_ROLE: &str = "invalid config v3 server role";
const MAX_DNS_HOSTNAME_LEN: usize = 253;

/// Explicit pre-runtime carrier choice in config schema 3.
///
/// This value chooses only which frozen direct auth-v3 policy bytes a future
/// runtime would use. It does not prove carrier availability or observation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectV3TransportStrategy {
    /// Direct H2 over TLS.
    H2,
    /// Direct H3 over QUIC/TLS.
    H3,
}

impl DirectV3TransportStrategy {
    /// Return the matching frozen auth-v3 carrier primitive.
    pub const fn auth_v3_carrier(self) -> AuthV3Carrier {
        match self {
            Self::H2 => AuthV3Carrier::H2,
            Self::H3 => AuthV3Carrier::H3,
        }
    }
}

/// Validated pre-runtime direct-v3 client role.
///
/// The type owns one byte-exact authority and a secret-bearing singleton
/// binding from the same validated config, but exposes no secret, opaque ID,
/// provisioning handle, or raw YAML. It deliberately implements neither
/// `Clone`, `Default`, Serialize, nor generic Deserialize.
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ClientRoleConfig;
/// fn require_clone<T: Clone>() {}
/// require_clone::<DirectV3ClientRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ClientRoleConfig;
/// fn require_default<T: Default>() {}
/// require_default::<DirectV3ClientRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ClientRoleConfig;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<DirectV3ClientRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ClientRoleConfig;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<DirectV3ClientRoleConfig>();
/// ```
#[non_exhaustive]
pub struct DirectV3ClientRoleConfig {
    transport_strategy: DirectV3TransportStrategy,
    local_socks5_listen: SocketAddr,
    server_address: String,
    server_name: String,
    tunnel_path: String,
    ca_cert: Option<PathBuf>,
    cert_pin: Option<String>,
    binding: AuthV3SingletonBinding,
}

impl DirectV3ClientRoleConfig {
    /// Return the explicit pre-runtime direct carrier choice.
    pub const fn transport_strategy(&self) -> DirectV3TransportStrategy {
        self.transport_strategy
    }

    /// Return the reused local SOCKS5 listener setting.
    pub const fn local_socks5_listen(&self) -> SocketAddr {
        self.local_socks5_listen
    }

    /// Return the reused server address setting.
    pub fn server_address(&self) -> &str {
        &self.server_address
    }

    /// Return the byte-exact trusted expected authority selected before I/O.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Return the exact path bound into the owned DeploymentProfile mapping.
    pub fn tunnel_path(&self) -> &str {
        &self.tunnel_path
    }

    /// Return the optional reused CA certificate path.
    pub fn ca_cert(&self) -> Option<&Path> {
        self.ca_cert.as_deref()
    }

    /// Return the optional reused certificate pin.
    pub fn cert_pin(&self) -> Option<&str> {
        self.cert_pin.as_deref()
    }

    /// Borrow the capability selected locally before any auth-v3 wire byte.
    pub fn preselected_profile(&self) -> AuthV3PreselectedProfile<'_> {
        self.binding.preselected_profile()
    }
}

impl fmt::Debug for DirectV3ClientRoleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("validated direct-v3 client role configuration")
    }
}

/// Validated pre-runtime direct-v3 server role.
///
/// The type owns one byte-exact authority and a secret-bearing singleton
/// binding from the same validated config, but exposes no secret, opaque ID,
/// provisioning handle, or raw YAML. It deliberately implements neither
/// `Clone`, `Default`, Serialize, nor generic Deserialize.
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ServerRoleConfig;
/// fn require_clone<T: Clone>() {}
/// require_clone::<DirectV3ServerRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ServerRoleConfig;
/// fn require_default<T: Default>() {}
/// require_default::<DirectV3ServerRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ServerRoleConfig;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<DirectV3ServerRoleConfig>();
/// ```
///
/// ```compile_fail
/// use maverick_core::config::DirectV3ServerRoleConfig;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<DirectV3ServerRoleConfig>();
/// ```
#[non_exhaustive]
pub struct DirectV3ServerRoleConfig {
    transport_strategy: DirectV3TransportStrategy,
    listen: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
    tunnel_path: String,
    expected_authority: String,
    binding: AuthV3SingletonBinding,
}

impl DirectV3ServerRoleConfig {
    /// Return the explicit pre-runtime direct carrier choice.
    pub const fn transport_strategy(&self) -> DirectV3TransportStrategy {
        self.transport_strategy
    }

    /// Return the reused server listener setting.
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Return the reused TLS certificate path.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Return the reused TLS private-key path.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Return the exact path bound into the owned DeploymentProfile mapping.
    pub fn tunnel_path(&self) -> &str {
        &self.tunnel_path
    }

    /// Return the byte-exact trusted authority selected before any I/O.
    pub fn expected_authority(&self) -> &str {
        &self.expected_authority
    }

    /// Borrow the capability selected locally before any auth-v3 wire byte.
    pub fn preselected_profile(&self) -> AuthV3PreselectedProfile<'_> {
        self.binding.preselected_profile()
    }
}

impl fmt::Debug for DirectV3ServerRoleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("validated direct-v3 server role configuration")
    }
}

pub(super) fn parse_client_role_config(input: &str) -> Result<DirectV3ClientRoleConfig> {
    let wire = ClientRoleWire::deserialize(serde_yaml_ng::Deserializer::from_str(input))
        .map_err(|_| invalid_client_role())?;
    if wire.version != 3 || wire.role != RoleWire::Client {
        return Err(invalid_client_role());
    }
    validate_policy(
        &wire.security,
        &wire.transport,
        &wire.trust,
        &wire.name_privacy,
        &wire.traffic_shaping,
    )
    .map_err(|_| invalid_client_role())?;
    if !wire.local.socks5.listen.ip().is_loopback()
        || !valid_text(&wire.server.address)
        || !valid_expected_authority(&wire.server.server_name.0)
        || !valid_tunnel_path(&wire.server.tunnel_path)
        || wire
            .server
            .ca_cert
            .as_deref()
            .is_some_and(|path| !valid_path(path))
        || wire
            .server
            .cert_pin
            .as_deref()
            .is_some_and(|pin| validate_cert_pin(pin).is_err())
    {
        return Err(invalid_client_role());
    }
    let transport_strategy = transport_strategy(wire.transport.strategy);
    let binding =
        build_binding(wire.auth, &wire.server.tunnel_path).map_err(|_| invalid_client_role())?;
    Ok(DirectV3ClientRoleConfig {
        transport_strategy,
        local_socks5_listen: wire.local.socks5.listen,
        server_address: wire.server.address,
        server_name: wire.server.server_name.0,
        tunnel_path: wire.server.tunnel_path,
        ca_cert: wire.server.ca_cert,
        cert_pin: wire.server.cert_pin,
        binding,
    })
}

pub(super) fn parse_server_role_config(input: &str) -> Result<DirectV3ServerRoleConfig> {
    let wire = ServerRoleWire::deserialize(serde_yaml_ng::Deserializer::from_str(input))
        .map_err(|_| invalid_server_role())?;
    if wire.version != 3 || wire.role != RoleWire::Server {
        return Err(invalid_server_role());
    }
    validate_policy(
        &wire.security,
        &wire.transport,
        &wire.trust,
        &wire.name_privacy,
        &wire.traffic_shaping,
    )
    .map_err(|_| invalid_server_role())?;
    if !valid_path(&wire.tls.cert_path)
        || !valid_path(&wire.tls.key_path)
        || !valid_tunnel_path(&wire.maverick.tunnel_path)
        || !valid_expected_authority(&wire.maverick.expected_authority.0)
    {
        return Err(invalid_server_role());
    }
    let transport_strategy = transport_strategy(wire.transport.strategy);
    let binding =
        build_binding(wire.auth, &wire.maverick.tunnel_path).map_err(|_| invalid_server_role())?;
    Ok(DirectV3ServerRoleConfig {
        transport_strategy,
        listen: wire.listen,
        cert_path: wire.tls.cert_path,
        key_path: wire.tls.key_path,
        tunnel_path: wire.maverick.tunnel_path,
        expected_authority: wire.maverick.expected_authority.0,
        binding,
    })
}

fn invalid_client_role() -> Error {
    Error::Config(INVALID_CLIENT_ROLE.into())
}

fn invalid_server_role() -> Error {
    Error::Config(INVALID_SERVER_ROLE.into())
}

fn build_binding(auth: AuthWire, tunnel_path: &str) -> Result<AuthV3SingletonBinding> {
    if auth.minimum != AuthMinimumWire::DirectV3Only {
        return Err(Error::Config(INVALID_CLIENT_ROLE.into()));
    }
    let binding = auth.direct_v3.binding;
    let handle = AuthV3ProvisioningHandle::new(decode_opaque_16(&binding.provisioning_handle)?)
        .map_err(|_| Error::Config(INVALID_CLIENT_ROLE.into()))?;
    let profile = AuthV3OwnedProvisioningProfile::new(
        decode_opaque_16(&binding.principal_id)?,
        decode_opaque_16(&binding.deployment_profile_id)?,
        decode_opaque_16(&binding.credential_namespace_id)?,
        decode_opaque_16(&binding.server_identity_id)?,
        true,
        tunnel_path.to_owned(),
        binding.credential_epoch,
        binding.credential_not_after_unix,
        binding.secret,
    )
    .map_err(|_| Error::Config(INVALID_CLIENT_ROLE.into()))?;
    AuthV3SingletonBinding::new(handle, vec![profile])
        .map_err(|_| Error::Config(INVALID_CLIENT_ROLE.into()))
}

fn decode_opaque_16(value: &str) -> Result<[u8; 16]> {
    if value.len() != 22
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Config(INVALID_CLIENT_ROLE.into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| Error::Config(INVALID_CLIENT_ROLE.into()))?;
    let decoded: [u8; 16] = decoded
        .try_into()
        .map_err(|_| Error::Config(INVALID_CLIENT_ROLE.into()))?;
    if decoded.iter().all(|byte| *byte == 0) || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(Error::Config(INVALID_CLIENT_ROLE.into()));
    }
    Ok(decoded)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn valid_expected_authority(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_DNS_HOSTNAME_LEN
        || !value.is_ascii()
        || value.parse::<IpAddr>().is_ok()
    {
        return false;
    }

    value.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_tunnel_path(value: &str) -> bool {
    value.starts_with('/') && valid_text(value)
}

fn valid_path(value: &Path) -> bool {
    value.to_str().is_some_and(valid_text)
}

fn transport_strategy(value: TransportStrategyWire) -> DirectV3TransportStrategy {
    match value {
        TransportStrategyWire::H2 => DirectV3TransportStrategy::H2,
        TransportStrategyWire::H3 => DirectV3TransportStrategy::H3,
    }
}

fn validate_policy(
    security: &SecurityWire,
    transport: &TransportWire,
    trust: &TrustWire,
    name_privacy: &NamePrivacyWire,
    traffic_shaping: &TrafficShapingWire,
) -> std::result::Result<(), ()> {
    if security.posture != SecurityPostureWire::Standard
        || !matches!(
            transport.strategy,
            TransportStrategyWire::H2 | TransportStrategyWire::H3
        )
        || trust.route != TrustRouteWire::DirectToMaverick
        || name_privacy.minimum != NamePrivacyMinimumWire::PlainSni
        || traffic_shaping.policy != TrafficShapingPolicyWire::Disabled
    {
        return Err(());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientRoleWire {
    version: u16,
    role: RoleWire,
    security: SecurityWire,
    transport: TransportWire,
    trust: TrustWire,
    name_privacy: NamePrivacyWire,
    traffic_shaping: TrafficShapingWire,
    local: ClientLocalWire,
    server: ClientServerWire,
    auth: AuthWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRoleWire {
    version: u16,
    role: RoleWire,
    security: SecurityWire,
    transport: TransportWire,
    trust: TrustWire,
    name_privacy: NamePrivacyWire,
    traffic_shaping: TrafficShapingWire,
    listen: SocketAddr,
    tls: ServerTlsWire,
    maverick: ServerMaverickWire,
    auth: AuthWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RoleWire {
    Client,
    Server,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityWire {
    posture: SecurityPostureWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SecurityPostureWire {
    Standard,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportWire {
    strategy: TransportStrategyWire,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportStrategyWire {
    H2,
    H3,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustWire {
    route: TrustRouteWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TrustRouteWire {
    DirectToMaverick,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamePrivacyWire {
    minimum: NamePrivacyMinimumWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NamePrivacyMinimumWire {
    PlainSni,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficShapingWire {
    policy: TrafficShapingPolicyWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TrafficShapingPolicyWire {
    Disabled,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientLocalWire {
    socks5: ClientSocks5Wire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientSocks5Wire {
    listen: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientServerWire {
    address: String,
    server_name: ExpectedAuthorityWire,
    tunnel_path: String,
    #[serde(default)]
    ca_cert: Option<PathBuf>,
    #[serde(default)]
    cert_pin: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerTlsWire {
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerMaverickWire {
    tunnel_path: String,
    expected_authority: ExpectedAuthorityWire,
}

struct ExpectedAuthorityWire(String);

impl<'de> Deserialize<'de> for ExpectedAuthorityWire {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match serde_yaml_ng::Value::deserialize(deserializer)? {
            serde_yaml_ng::Value::String(value) => Ok(Self(value)),
            _ => Err(serde::de::Error::custom("invalid expected authority")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthWire {
    minimum: AuthMinimumWire,
    direct_v3: DirectV3AuthWire,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AuthMinimumWire {
    DirectV3Only,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectV3AuthWire {
    binding: BindingWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    provisioning_handle: String,
    principal_id: String,
    deployment_profile_id: String,
    credential_namespace_id: String,
    server_identity_id: String,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    secret: SecretString,
}
