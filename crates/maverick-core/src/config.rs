use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize, Serializer};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::auth::AUTH_V2_MAX_CREDENTIAL_HINT_LEN;
use crate::crypto::CryptoPolicyConfig;
use crate::error::{Error, Result};

/// User-facing product mode. This is a policy label, not a transport selector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Auto,
    Stable,
    Private,
}

pub(crate) const fn browser_tls_profile_supported() -> bool {
    cfg!(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))
}

impl Mode {
    pub fn wire_id(self) -> u8 {
        match self {
            Self::Auto => 0,
            Self::Stable => 1,
            Self::Private => 2,
        }
    }

    pub fn from_wire_id(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Auto),
            1 => Ok(Self::Stable),
            2 => Ok(Self::Private),
            _ => Err(Error::MalformedFrame("unknown mode")),
        }
    }
}

/// A high-entropy credential secret whose Debug output is always redacted.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub const PREFIX: &'static str = "mv1_";
    const MIN_SECRET_BYTES: usize = 32;

    pub fn new(value: impl Into<String>) -> Result<Self> {
        let secret = Self(value.into());
        secret.validate()?;
        Ok(secret)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::MIN_SECRET_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS random generator failed");
        Self(format!("{}{}", Self::PREFIX, URL_SAFE_NO_PAD.encode(bytes)))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        let encoded = self
            .0
            .strip_prefix(Self::PREFIX)
            .ok_or(Error::InvalidSecret)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidSecret)?;
        if decoded.len() < Self::MIN_SECRET_BYTES {
            return Err(Error::InvalidSecret);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SecretString {}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub version: u16,
    #[serde(default)]
    pub mode: Mode,
    pub local: LocalConfig,
    pub server: ClientServerConfig,
    #[serde(default)]
    pub auth: ClientAuthConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub advanced: ClientAdvancedConfig,
}

impl ClientConfig {
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        let cfg: Self = serde_yaml_ng::from_str(input)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Config("only config version 1 is supported".into()));
        }
        self.log.validate()?;
        self.server.secret.validate()?;
        if self.server.tunnel_path.is_empty() || !self.server.tunnel_path.starts_with('/') {
            return Err(Error::Config(
                "server.tunnel_path must start with '/'".into(),
            ));
        }
        validate_auth_v1_string_len("server.tunnel_path", &self.server.tunnel_path)?;
        if self.server.credential_id.is_empty() {
            return Err(Error::Config(
                "server.credential_id must not be empty".into(),
            ));
        }
        validate_auth_v1_string_len("server.credential_id", &self.server.credential_id)?;
        self.auth.validate(&self.server.credential_id)?;
        if self.server.cert_pin.is_some() {
            validate_cert_pin(self.server.cert_pin.as_deref().unwrap())?;
        }
        if !self.advanced.allow_non_loopback_listeners {
            validate_loopback_listener("local.socks5.listen", self.local.socks5.listen)?;
        }
        if self.advanced.connect_timeout_ms == 0 {
            return Err(Error::Config(
                "advanced.connect_timeout_ms must be greater than zero".into(),
            ));
        }
        if self.advanced.idle_timeout_secs == 0 {
            return Err(Error::Config(
                "advanced.idle_timeout_secs must be greater than zero".into(),
            ));
        }
        if self.advanced.max_concurrent_flows == 0 {
            return Err(Error::Config(
                "advanced.max_concurrent_flows must be greater than zero".into(),
            ));
        }
        if self.advanced.udp_idle_timeout_ms == 0 {
            return Err(Error::Config(
                "advanced.udp_idle_timeout_ms must be greater than zero".into(),
            ));
        }
        self.advanced.shaping.validate()?;
        self.advanced.validate(self.mode)?;
        self.auth.channel_binding.validate_transport_support(
            self.advanced.cloudflare_ws_enabled(),
            self.advanced.experimental_h3,
        )?;
        if let Some(dns) = &self.local.dns {
            if dns.enabled {
                let listen = dns.listen.ok_or_else(|| {
                    Error::Config(
                        "local.dns.listen is required when local.dns.enabled is true".into(),
                    )
                })?;
                if !self.advanced.allow_non_loopback_listeners {
                    validate_loopback_listener("local.dns.listen", listen)?;
                }
            }
        }
        if let Some(http_connect) = &self.local.http_connect {
            if http_connect.enabled {
                let listen = http_connect.listen.ok_or_else(|| {
                    Error::Config(
                        "local.http_connect.listen is required when local.http_connect.enabled is true"
                            .into(),
                    )
                })?;
                if !self.advanced.allow_non_loopback_listeners {
                    validate_loopback_listener("local.http_connect.listen", listen)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalConfig {
    pub socks5: Socks5Config,
    #[serde(default)]
    pub dns: Option<ClientDnsConfig>,
    #[serde(default)]
    pub http_connect: Option<HttpConnectConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socks5Config {
    pub listen: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientDnsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen: Option<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpConnectConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen: Option<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientServerConfig {
    pub address: String,
    pub server_name: String,
    pub tunnel_path: String,
    pub credential_id: String,
    pub secret: SecretString,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub cert_pin: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    #[serde(default)]
    pub channel_binding: AuthChannelBindingConfig,
    #[serde(default)]
    pub v2: AuthV2Config,
    #[serde(default)]
    pub rotation: ClientCredentialRotationConfig,
}

impl ClientAuthConfig {
    fn validate(&self, active_credential_id: &str) -> Result<()> {
        self.channel_binding.validate()?;
        self.rotation.validate(active_credential_id)?;
        self.v2
            .validate_client(active_credential_id, &self.rotation)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerAuthConfig {
    #[serde(default)]
    pub channel_binding: AuthChannelBindingConfig,
    #[serde(default)]
    pub v2: AuthV2Config,
}

impl ServerAuthConfig {
    fn validate(&self) -> Result<()> {
        self.channel_binding.validate()?;
        self.v2.validate_server()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AuthChannelBindingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub require: bool,
}

impl Default for AuthChannelBindingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require: false,
        }
    }
}

impl AuthChannelBindingConfig {
    fn validate(&self) -> Result<()> {
        if self.require && !self.enabled {
            return Err(Error::Config(
                "auth.channel_binding.require requires auth.channel_binding.enabled to be true"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_transport_support(
        &self,
        cloudflare_ws_enabled: bool,
        experimental_h3: bool,
    ) -> Result<()> {
        if self.require && cloudflare_ws_enabled {
            return Err(Error::Config(
                "auth.channel_binding.require is not supported with CDN-fronted WebSocket".into(),
            ));
        }
        if self.require && experimental_h3 {
            return Err(Error::Config(
                "auth.channel_binding.require is not supported with experimental H3".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthV2Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub require: bool,
    #[serde(default)]
    pub accepted_epochs: Vec<u64>,
}

impl AuthV2Config {
    fn validate_client(
        &self,
        active_credential_id: &str,
        rotation: &ClientCredentialRotationConfig,
    ) -> Result<()> {
        if self.require && !self.enabled {
            return Err(Error::Config(
                "auth.v2.require requires auth.v2.enabled to be true".into(),
            ));
        }
        if self.enabled {
            validate_auth_v2_credential_hint_len("server.credential_id", active_credential_id)?;
            if let Some(next_credential_id) = &rotation.next_credential_id {
                validate_auth_v2_credential_hint_len(
                    "auth.rotation.next_credential_id",
                    next_credential_id,
                )?;
            }
            if let Some(next) = &rotation.next {
                validate_auth_v2_credential_hint_len("auth.rotation.next.id", &next.id)?;
            }
            let active_epoch = rotation.active_epoch.as_deref().ok_or_else(|| {
                Error::Config(
                    "auth.rotation.active_epoch is required when auth.v2.enabled is true".into(),
                )
            })?;
            parse_auth_epoch(active_epoch)?;
        }
        Ok(())
    }

    fn validate_server(&self) -> Result<()> {
        if self.require && !self.enabled {
            return Err(Error::Config(
                "auth.v2.require requires auth.v2.enabled to be true".into(),
            ));
        }
        if !self.enabled {
            return Ok(());
        }
        if self.accepted_epochs.is_empty() {
            return Err(Error::Config(
                "auth.v2.accepted_epochs must not be empty when auth.v2.enabled is true".into(),
            ));
        }
        if !self.require {
            return Err(Error::Config(
                "auth.v2.require must be true when server auth.v2.enabled is true".into(),
            ));
        }
        if self.accepted_epochs.len() > 8 {
            return Err(Error::Config(
                "auth.v2.accepted_epochs must contain at most 8 epochs".into(),
            ));
        }
        let mut seen = Vec::new();
        for epoch in &self.accepted_epochs {
            if seen.contains(epoch) {
                return Err(Error::Config(
                    "auth.v2.accepted_epochs must not contain duplicates".into(),
                ));
            }
            seen.push(*epoch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientCredentialRotationConfig {
    #[serde(default)]
    pub active_epoch: Option<String>,
    #[serde(default)]
    pub next_credential_id: Option<String>,
    #[serde(default)]
    pub auto_switch: bool,
    #[serde(default)]
    pub next: Option<ClientNextCredentialConfig>,
}

impl ClientCredentialRotationConfig {
    fn validate(&self, active_credential_id: &str) -> Result<()> {
        if self.active_epoch.as_deref() == Some("") {
            return Err(Error::Config(
                "auth.rotation.active_epoch must not be empty".into(),
            ));
        }
        if self.next_credential_id.as_deref() == Some("") {
            return Err(Error::Config(
                "auth.rotation.next_credential_id must not be empty".into(),
            ));
        }
        if let Some(next_credential_id) = &self.next_credential_id {
            validate_auth_v1_string_len("auth.rotation.next_credential_id", next_credential_id)?;
        }
        if let Some(next) = &self.next {
            next.validate()?;
            if next.id == active_credential_id {
                return Err(Error::Config(
                    "auth.rotation.next.id must differ from server.credential_id".into(),
                ));
            }
            if let Some(next_credential_id) = &self.next_credential_id {
                if next_credential_id != &next.id {
                    return Err(Error::Config(
                        "auth.rotation.next_credential_id must match auth.rotation.next.id".into(),
                    ));
                }
            }
        }
        if self.auto_switch && self.next.is_none() {
            return Err(Error::Config(
                "auth.rotation.next is required when auth.rotation.auto_switch is true".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientNextCredentialConfig {
    pub id: String,
    pub secret: SecretString,
    pub not_before: String,
}

impl ClientNextCredentialConfig {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Config(
                "auth.rotation.next.id must not be empty".into(),
            ));
        }
        validate_auth_v1_string_len("auth.rotation.next.id", &self.id)?;
        self.secret.validate()?;
        parse_rfc3339("auth.rotation.next.not_before", &self.not_before)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCredentialSelection {
    Active,
    Next,
}

#[derive(Clone, Copy, Debug)]
pub struct SelectedClientCredential<'a> {
    pub id: &'a str,
    pub secret: &'a SecretString,
    pub selection: ClientCredentialSelection,
}

pub fn select_client_credential<'a>(
    server: &'a ClientServerConfig,
    rotation: &'a ClientCredentialRotationConfig,
    now: OffsetDateTime,
) -> Result<SelectedClientCredential<'a>> {
    select_client_credential_at_unix(server, rotation, now.unix_timestamp())
}

pub fn select_client_credential_at_unix<'a>(
    server: &'a ClientServerConfig,
    rotation: &'a ClientCredentialRotationConfig,
    now_unix: i64,
) -> Result<SelectedClientCredential<'a>> {
    if rotation.auto_switch {
        if let Some(next) = &rotation.next {
            let not_before = parse_rfc3339("auth.rotation.next.not_before", &next.not_before)?;
            if now_unix >= not_before.unix_timestamp() {
                return Ok(SelectedClientCredential {
                    id: &next.id,
                    secret: &next.secret,
                    selection: ClientCredentialSelection::Next,
                });
            }
        }
    }

    Ok(SelectedClientCredential {
        id: &server.credential_id,
        secret: &server.secret,
        selection: ClientCredentialSelection::Active,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub version: u16,
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    pub maverick: MaverickServerConfig,
    pub users: Vec<UserConfig>,
    pub fallback: FallbackConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default)]
    pub dns: Option<ServerDnsConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub advanced: ServerAdvancedConfig,
}

impl ServerConfig {
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        let cfg: Self = serde_yaml_ng::from_str(input)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Config("only config version 1 is supported".into()));
        }
        self.log.validate()?;
        if self.maverick.tunnel_path.is_empty() || !self.maverick.tunnel_path.starts_with('/') {
            return Err(Error::Config(
                "maverick.tunnel_path must start with '/'".into(),
            ));
        }
        validate_auth_v1_string_len("maverick.tunnel_path", &self.maverick.tunnel_path)?;
        if self.maverick.replay_window_secs <= 0 {
            return Err(Error::Config(
                "maverick.replay_window_secs must be greater than zero".into(),
            ));
        }
        if self.maverick.replay_window_secs > MAX_REPLAY_WINDOW_SECS {
            return Err(Error::Config(format!(
                "maverick.replay_window_secs must be at most {MAX_REPLAY_WINDOW_SECS}"
            )));
        }
        if self.maverick.replay_cache_entries_per_credential == 0 {
            return Err(Error::Config(
                "maverick.replay_cache_entries_per_credential must be greater than zero".into(),
            ));
        }
        if self.maverick.replay_cache_max_credentials_per_shard == 0 {
            return Err(Error::Config(
                "maverick.replay_cache_max_credentials_per_shard must be greater than zero".into(),
            ));
        }
        if self.maverick.max_concurrent_flows_per_user == 0 {
            return Err(Error::Config(
                "maverick.max_concurrent_flows_per_user must be greater than zero".into(),
            ));
        }
        if self.users.is_empty() {
            return Err(Error::Config("at least one user is required".into()));
        }
        self.auth.validate()?;
        for user in &self.users {
            if user.id.is_empty() {
                return Err(Error::Config("user id must not be empty".into()));
            }
            validate_auth_v1_string_len("user.id", &user.id)?;
            if self.auth.v2.enabled {
                validate_auth_v2_credential_hint_len("user.id", &user.id)?;
            }
            user.secret.validate()?;
            if let Some(rate_limit) = &user.rate_limit {
                if rate_limit.bytes_per_second == 0 {
                    return Err(Error::Config(
                        "user.rate_limit.bytes_per_second must be greater than zero".into(),
                    ));
                }
            }
            if user.max_concurrent_flows == Some(0) {
                return Err(Error::Config(
                    "user.max_concurrent_flows must be greater than zero".into(),
                ));
            }
            if let Some(rotation) = &user.rotation {
                rotation.validate_for_user(&user.id)?;
                if self.auth.v2.enabled {
                    for previous in &rotation.previous {
                        validate_auth_v2_credential_hint_len(
                            "user.rotation.previous.id",
                            &previous.id,
                        )?;
                    }
                    if let Some(next) = &rotation.next {
                        validate_auth_v2_credential_hint_len("user.rotation.next.id", &next.id)?;
                    }
                }
            }
        }
        if let Some(dns) = &self.dns {
            if dns.timeout_ms == 0 {
                return Err(Error::Config(
                    "dns.timeout_ms must be greater than zero".into(),
                ));
            }
        }
        if let Some(metrics) = &self.metrics {
            if metrics.enabled && !metrics.listen.ip().is_loopback() {
                return Err(Error::Config(
                    "metrics.listen must be loopback when metrics are enabled".into(),
                ));
            }
        }
        if self.advanced.idle_timeout_secs == 0 {
            return Err(Error::Config(
                "advanced.idle_timeout_secs must be greater than zero".into(),
            ));
        }
        if self.advanced.tcp_connect_timeout_ms == 0 {
            return Err(Error::Config(
                "advanced.tcp_connect_timeout_ms must be greater than zero".into(),
            ));
        }
        if self.advanced.handshake_timeout_ms == 0 {
            return Err(Error::Config(
                "advanced.handshake_timeout_ms must be greater than zero".into(),
            ));
        }
        if self.advanced.max_frame_size < FRAME_HEADER_MIN_MAX_SIZE {
            return Err(Error::Config(format!(
                "advanced.max_frame_size must be at least {FRAME_HEADER_MIN_MAX_SIZE}"
            )));
        }
        if self.advanced.udp_idle_timeout_ms == 0 {
            return Err(Error::Config(
                "advanced.udp_idle_timeout_ms must be greater than zero".into(),
            ));
        }
        self.advanced.shaping.validate()?;
        self.advanced.validate(self.maverick.mode_default)?;
        self.auth.channel_binding.validate_transport_support(
            self.advanced.cloudflare_ws_enabled(),
            self.advanced.experimental_h3,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaverickServerConfig {
    pub tunnel_path: String,
    #[serde(default)]
    pub mode_default: Mode,
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: i64,
    #[serde(default = "default_replay_cache_entries_per_credential")]
    pub replay_cache_entries_per_credential: usize,
    #[serde(default = "default_replay_cache_max_credentials_per_shard")]
    pub replay_cache_max_credentials_per_shard: usize,
    #[serde(default = "default_max_concurrent_flows")]
    pub max_concurrent_flows_per_user: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub secret: SecretString,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub max_concurrent_flows: Option<u32>,
    #[serde(default)]
    pub rotation: Option<UserCredentialRotationConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserCredentialRotationConfig {
    #[serde(default)]
    pub previous: Vec<PreviousCredentialConfig>,
    #[serde(default)]
    pub next: Option<NextCredentialConfig>,
}

impl UserCredentialRotationConfig {
    fn validate_for_user(&self, active_id: &str) -> Result<()> {
        if self.previous.len() > 4 {
            return Err(Error::Config(
                "user.rotation.previous must contain at most 4 credentials".into(),
            ));
        }
        let mut seen = vec![active_id.to_owned()];
        for previous in &self.previous {
            previous.validate()?;
            if seen.iter().any(|id| id == &previous.id) {
                return Err(Error::Config(
                    "user.rotation credential ids must be unique".into(),
                ));
            }
            seen.push(previous.id.clone());
        }
        if let Some(next) = &self.next {
            next.validate()?;
            if seen.iter().any(|id| id == &next.id) {
                return Err(Error::Config(
                    "user.rotation credential ids must be unique".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviousCredentialConfig {
    pub id: String,
    pub secret: SecretString,
    pub not_before: String,
    pub not_after: String,
}

impl PreviousCredentialConfig {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Config(
                "user.rotation.previous.id must not be empty".into(),
            ));
        }
        validate_auth_v1_string_len("user.rotation.previous.id", &self.id)?;
        self.secret.validate()?;
        let not_before = parse_rfc3339("user.rotation.previous.not_before", &self.not_before)?;
        let not_after = parse_rfc3339("user.rotation.previous.not_after", &self.not_after)?;
        if not_after <= not_before {
            return Err(Error::Config(
                "user.rotation.previous.not_after must be after not_before".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NextCredentialConfig {
    pub id: String,
    pub not_before: String,
}

impl NextCredentialConfig {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Config(
                "user.rotation.next.id must not be empty".into(),
            ));
        }
        validate_auth_v1_string_len("user.rotation.next.id", &self.id)?;
        parse_rfc3339("user.rotation.next.not_before", &self.not_before)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub bytes_per_second: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FallbackConfig {
    Static {
        static_dir: PathBuf,
        #[serde(default = "default_index")]
        index: String,
    },
    ReverseProxy {
        upstream: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerDnsConfig {
    pub upstream: String,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_true")]
    pub redact: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            redact: true,
        }
    }
}

impl LogConfig {
    fn validate(&self) -> Result<()> {
        if self.level.trim().is_empty() {
            return Err(Error::Config("log.level must not be empty".into()));
        }
        if !self.redact {
            return Err(Error::Config(
                "log.redact=false is not supported in this prototype".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAdvancedConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_flows")]
    pub max_concurrent_flows: u32,
    #[serde(default = "default_padding")]
    pub padding: String,
    #[serde(default = "default_udp_idle_timeout_ms")]
    pub udp_idle_timeout_ms: u64,
    #[serde(default)]
    pub shaping: ShapingConfig,
    #[serde(default)]
    pub stealth: StealthConfig,
    #[serde(default)]
    pub allow_non_loopback_listeners: bool,
    #[serde(default)]
    pub experimental_h3: bool,
    #[serde(default)]
    pub experimental_cloudflare_ws: bool,
    #[serde(default)]
    pub experimental_ech: bool,
    #[serde(default)]
    pub experimental_tun: bool,
    #[serde(default)]
    pub ech_fallback_policy: EchFallbackPolicy,
    #[serde(default)]
    pub crypto: CryptoPolicyConfig,
}

impl Default for ClientAdvancedConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_concurrent_flows: default_max_concurrent_flows(),
            padding: default_padding(),
            udp_idle_timeout_ms: default_udp_idle_timeout_ms(),
            shaping: ShapingConfig::default(),
            stealth: StealthConfig::default(),
            allow_non_loopback_listeners: false,
            experimental_h3: false,
            experimental_cloudflare_ws: false,
            experimental_ech: false,
            experimental_tun: false,
            ech_fallback_policy: EchFallbackPolicy::default(),
            crypto: CryptoPolicyConfig::default(),
        }
    }
}

impl ClientAdvancedConfig {
    pub fn cloudflare_ws_enabled(&self) -> bool {
        self.experimental_cloudflare_ws || self.stealth.cdn_fronting.enabled
    }

    fn validate(&self, mode: Mode) -> Result<()> {
        if mode == Mode::Private && self.ech_fallback_policy == EchFallbackPolicy::AllowPlainSni {
            return Err(Error::Config(
                "advanced.ech_fallback_policy=allow_plain_sni is not allowed in private mode"
                    .into(),
            ));
        }
        let cloudflare_ws_enabled = self.cloudflare_ws_enabled();
        if mode == Mode::Stable && cloudflare_ws_enabled {
            return Err(Error::Config(
                "CDN-fronted WebSocket is not allowed in stable mode".into(),
            ));
        }
        if mode == Mode::Stable && self.experimental_tun {
            return Err(Error::Config(
                "advanced.experimental_tun is not allowed in stable mode".into(),
            ));
        }
        if cloudflare_ws_enabled && self.experimental_h3 {
            return Err(Error::Config(
                "CDN-fronted WebSocket and advanced.experimental_h3 cannot both be enabled".into(),
            ));
        }
        if self.stealth.tls_fingerprint == TlsFingerprintMode::BrowserMimic && cloudflare_ws_enabled
        {
            return Err(Error::Config(
                "advanced.stealth.tls_fingerprint=browser_mimic currently supports the H2 carrier only"
                    .into(),
            ));
        }
        validate_experimental_ech(self.experimental_ech)?;
        self.stealth.validate(
            "advanced.stealth",
            mode,
            cloudflare_ws_enabled,
            browser_tls_profile_supported(),
        )?;
        if mode == Mode::Private
            && self.stealth.tls_fingerprint == TlsFingerprintMode::RustlsDefault
        {
            return Err(Error::Config(
                "advanced.stealth.tls_fingerprint=rustls_default is not allowed in private mode"
                    .into(),
            ));
        }
        self.crypto.validate(mode)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerAdvancedConfig {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub tcp_connect_timeout_ms: u64,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: u32,
    #[serde(default = "default_max_concurrent_connections_per_source")]
    pub max_concurrent_connections_per_source: u32,
    #[serde(default = "default_pre_auth_max_concurrent")]
    pub pre_auth_max_concurrent: u32,
    #[serde(default = "default_fallback_max_concurrent")]
    pub fallback_max_concurrent: u32,
    #[serde(default = "default_h2_max_concurrent_streams")]
    pub h2_max_concurrent_streams: u32,
    #[serde(default = "default_h2_max_concurrent_reset_streams")]
    pub h2_max_concurrent_reset_streams: u32,
    #[serde(default = "default_h2_max_pending_accept_reset_streams")]
    pub h2_max_pending_accept_reset_streams: u32,
    #[serde(default = "default_h2_max_local_error_reset_streams")]
    pub h2_max_local_error_reset_streams: u32,
    #[serde(default = "default_auth_failure_window_secs")]
    pub auth_failure_window_secs: u64,
    #[serde(default = "default_max_auth_failures_per_window")]
    pub max_auth_failures_per_window: u32,
    #[serde(default = "default_auth_failure_cache_max_entries")]
    pub auth_failure_cache_max_entries: u32,
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: u32,
    #[serde(default = "default_udp_idle_timeout_ms")]
    pub udp_idle_timeout_ms: u64,
    #[serde(default)]
    pub shaping: ShapingConfig,
    #[serde(default)]
    pub stealth: StealthConfig,
    #[serde(default)]
    pub egress: ServerEgressPolicyConfig,
    #[serde(default)]
    pub experimental_h3: bool,
    #[serde(default)]
    pub experimental_cloudflare_ws: bool,
    #[serde(default)]
    pub experimental_ech: bool,
    #[serde(default)]
    pub crypto: CryptoPolicyConfig,
}

impl Default for ServerAdvancedConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout_secs(),
            tcp_connect_timeout_ms: default_connect_timeout_ms(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            max_concurrent_connections: default_max_concurrent_connections(),
            max_concurrent_connections_per_source: default_max_concurrent_connections_per_source(),
            pre_auth_max_concurrent: default_pre_auth_max_concurrent(),
            fallback_max_concurrent: default_fallback_max_concurrent(),
            h2_max_concurrent_streams: default_h2_max_concurrent_streams(),
            h2_max_concurrent_reset_streams: default_h2_max_concurrent_reset_streams(),
            h2_max_pending_accept_reset_streams: default_h2_max_pending_accept_reset_streams(),
            h2_max_local_error_reset_streams: default_h2_max_local_error_reset_streams(),
            auth_failure_window_secs: default_auth_failure_window_secs(),
            max_auth_failures_per_window: default_max_auth_failures_per_window(),
            auth_failure_cache_max_entries: default_auth_failure_cache_max_entries(),
            max_frame_size: default_max_frame_size(),
            udp_idle_timeout_ms: default_udp_idle_timeout_ms(),
            shaping: ShapingConfig::default(),
            stealth: StealthConfig::default(),
            egress: ServerEgressPolicyConfig::default(),
            experimental_h3: false,
            experimental_cloudflare_ws: false,
            experimental_ech: false,
            crypto: CryptoPolicyConfig::default(),
        }
    }
}

impl ServerAdvancedConfig {
    pub fn cloudflare_ws_enabled(&self) -> bool {
        self.experimental_cloudflare_ws || self.stealth.cdn_fronting.enabled
    }

    fn validate(&self, mode: Mode) -> Result<()> {
        if self.max_concurrent_connections == 0 {
            return Err(Error::Config(
                "advanced.max_concurrent_connections must be greater than zero".into(),
            ));
        }
        if self.max_concurrent_connections_per_source == 0 {
            return Err(Error::Config(
                "advanced.max_concurrent_connections_per_source must be greater than zero".into(),
            ));
        }
        if self.pre_auth_max_concurrent == 0 {
            return Err(Error::Config(
                "advanced.pre_auth_max_concurrent must be greater than zero".into(),
            ));
        }
        if self.fallback_max_concurrent == 0 {
            return Err(Error::Config(
                "advanced.fallback_max_concurrent must be greater than zero".into(),
            ));
        }
        if self.h2_max_concurrent_streams == 0 {
            return Err(Error::Config(
                "advanced.h2_max_concurrent_streams must be greater than zero".into(),
            ));
        }
        if self.h2_max_concurrent_reset_streams == 0 {
            return Err(Error::Config(
                "advanced.h2_max_concurrent_reset_streams must be greater than zero".into(),
            ));
        }
        if self.h2_max_pending_accept_reset_streams == 0 {
            return Err(Error::Config(
                "advanced.h2_max_pending_accept_reset_streams must be greater than zero".into(),
            ));
        }
        if self.h2_max_local_error_reset_streams == 0 {
            return Err(Error::Config(
                "advanced.h2_max_local_error_reset_streams must be greater than zero".into(),
            ));
        }
        if self.auth_failure_window_secs == 0 {
            return Err(Error::Config(
                "advanced.auth_failure_window_secs must be greater than zero".into(),
            ));
        }
        if self.max_auth_failures_per_window == 0 {
            return Err(Error::Config(
                "advanced.max_auth_failures_per_window must be greater than zero".into(),
            ));
        }
        if self.auth_failure_cache_max_entries == 0 {
            return Err(Error::Config(
                "advanced.auth_failure_cache_max_entries must be greater than zero".into(),
            ));
        }
        let cloudflare_ws_enabled = self.cloudflare_ws_enabled();
        if mode == Mode::Stable && cloudflare_ws_enabled {
            return Err(Error::Config(
                "CDN-fronted WebSocket is not allowed in stable mode".into(),
            ));
        }
        if mode == Mode::Stable && self.experimental_h3 {
            return Err(Error::Config(
                "advanced.experimental_h3 is not allowed in stable mode".into(),
            ));
        }
        validate_experimental_ech(self.experimental_ech)?;
        self.stealth
            .validate("advanced.stealth", mode, cloudflare_ws_enabled, false)?;
        self.crypto.validate(mode)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprintMode {
    #[default]
    RustlsDefault,
    BrowserMimic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthConfig {
    #[serde(default)]
    pub tls_fingerprint: TlsFingerprintMode,
    #[serde(default = "default_true")]
    pub active_probe_resistance: bool,
    #[serde(default)]
    pub cdn_fronting: CdnFrontingConfig,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            tls_fingerprint: TlsFingerprintMode::RustlsDefault,
            active_probe_resistance: true,
            cdn_fronting: CdnFrontingConfig::default(),
        }
    }
}

impl StealthConfig {
    fn validate(
        &self,
        field: &str,
        mode: Mode,
        cloudflare_ws_enabled: bool,
        browser_mimic_supported: bool,
    ) -> Result<()> {
        if self.tls_fingerprint == TlsFingerprintMode::BrowserMimic && !browser_mimic_supported {
            return Err(Error::Config(format!(
                "{field}.tls_fingerprint=browser_mimic requires a browser TLS backend"
            )));
        }
        if mode == Mode::Private && !self.active_probe_resistance {
            return Err(Error::Config(format!(
                "{field}.active_probe_resistance=false is not allowed in private mode"
            )));
        }
        if cloudflare_ws_enabled && !self.active_probe_resistance {
            return Err(Error::Config(format!(
                "{field}.active_probe_resistance=false is not allowed with CDN-fronted WebSocket"
            )));
        }
        self.cdn_fronting
            .validate(&format!("{field}.cdn_fronting"), cloudflare_ws_enabled)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnFrontingProvider {
    #[default]
    Cloudflare,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdnFrontingCarrier {
    #[default]
    WebSocket,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CdnFrontingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: CdnFrontingProvider,
    #[serde(default)]
    pub carrier: CdnFrontingCarrier,
    #[serde(default)]
    pub trusted_tls_terminating_provider: bool,
}

impl CdnFrontingConfig {
    fn validate(&self, field: &str, cloudflare_ws_enabled: bool) -> Result<()> {
        if cloudflare_ws_enabled && !self.enabled {
            return Err(Error::Config(format!(
                "{field}.enabled must be true when CDN-fronted WebSocket is selected"
            )));
        }
        if self.enabled && !self.trusted_tls_terminating_provider {
            return Err(Error::Config(format!(
                "{field}.trusted_tls_terminating_provider must be true because CDN-fronted mode terminates client TLS at the provider edge"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerEgressPolicyConfig {
    #[serde(default)]
    pub allow_loopback: bool,
    #[serde(default)]
    pub allow_private: bool,
    #[serde(default)]
    pub allow_link_local: bool,
    #[serde(default)]
    pub allow_multicast: bool,
    #[serde(default)]
    pub allow_unspecified: bool,
}

impl ServerEgressPolicyConfig {
    pub fn allows_ip(self, ip: IpAddr) -> bool {
        let ip = canonicalize_egress_ip(ip);
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        if ip.is_unspecified() {
            return self.allow_unspecified;
        }
        if ip.is_multicast() {
            return self.allow_multicast;
        }
        if is_link_local_ip(ip) {
            return self.allow_link_local;
        }
        if is_private_ip(ip) {
            return self.allow_private;
        }
        if is_reserved_or_special_ip(ip) {
            return false;
        }
        true
    }
}

fn canonicalize_egress_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => embedded_ipv4_for_egress(ip)
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
    }
}

fn embedded_ipv4_for_egress(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if octets[..12] == [0; 12] {
        let embedded = [octets[12], octets[13], octets[14], octets[15]];
        if embedded != [0, 0, 0, 0] && embedded != [0, 0, 0, 1] {
            return Some(Ipv4Addr::from(embedded));
        }
    }
    if octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if octets[0] == 0x20 && octets[1] == 0x02 {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }
    if octets[..4] == [0x20, 0x01, 0x00, 0x00] {
        return Some(Ipv4Addr::new(
            !octets[12],
            !octets[13],
            !octets[14],
            !octets[15],
        ));
    }
    None
}

fn is_link_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || is_shared_ipv4(ip),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00 || is_local_use_nat64_ip(ip),
    }
}

fn is_reserved_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_reserved_or_special_ipv4(ip),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn is_reserved_or_special_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = ip.octets();
    first == 0
        || first >= 240
        || ip == Ipv4Addr::new(255, 255, 255, 255)
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
        || (first == 192 && second == 88 && third == 99)
}

fn is_shared_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first == 100 && (second & 0b1100_0000) == 64
}

fn is_local_use_nat64_ip(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EchFallbackPolicy {
    #[default]
    FailClosed,
    AllowPlainSni,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShapingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_shaping_max_padding_bytes_per_frame")]
    pub max_padding_bytes_per_frame: u16,
    #[serde(default = "default_shaping_max_overhead_ratio")]
    pub max_overhead_ratio: f64,
    #[serde(default = "default_shaping_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default = "default_shaping_max_batch_bytes")]
    pub max_batch_bytes: u32,
    #[serde(default)]
    pub cover_traffic: bool,
    #[serde(default)]
    pub cover_traffic_operator_approved: bool,
    #[serde(default = "default_cover_traffic_window_ms")]
    pub cover_traffic_window_ms: u64,
}

impl ShapingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_padding_bytes_per_frame == 0 {
            return Err(Error::Config(
                "advanced.shaping.max_padding_bytes_per_frame must be greater than zero".into(),
            ));
        }
        if !self.max_overhead_ratio.is_finite()
            || self.max_overhead_ratio < 0.0
            || self.max_overhead_ratio > 1.0
        {
            return Err(Error::Config(
                "advanced.shaping.max_overhead_ratio must be between 0.0 and 1.0".into(),
            ));
        }
        if self.max_delay_ms > 1_000 {
            return Err(Error::Config(
                "advanced.shaping.max_delay_ms must be no greater than 1000".into(),
            ));
        }
        if self.max_batch_bytes == 0 || self.max_batch_bytes > 1_048_576 {
            return Err(Error::Config(
                "advanced.shaping.max_batch_bytes must be between 1 and 1048576".into(),
            ));
        }
        if self.cover_traffic && !self.enabled {
            return Err(Error::Config(
                "advanced.shaping.enabled must be true when cover_traffic is true".into(),
            ));
        }
        if self.cover_traffic && !self.cover_traffic_operator_approved {
            return Err(Error::Config(
                "advanced.shaping.cover_traffic_operator_approved must be true when cover_traffic is true".into(),
            ));
        }
        if self.cover_traffic_window_ms == 0 || self.cover_traffic_window_ms > 60_000 {
            return Err(Error::Config(
                "advanced.shaping.cover_traffic_window_ms must be between 1 and 60000".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_padding_bytes_per_frame: default_shaping_max_padding_bytes_per_frame(),
            max_overhead_ratio: default_shaping_max_overhead_ratio(),
            max_delay_ms: default_shaping_max_delay_ms(),
            max_batch_bytes: default_shaping_max_batch_bytes(),
            cover_traffic: false,
            cover_traffic_operator_approved: false,
            cover_traffic_window_ms: default_cover_traffic_window_ms(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_index() -> String {
    "index.html".into()
}

fn default_log_level() -> String {
    "info".into()
}

fn default_padding() -> String {
    "auto".into()
}

fn default_connect_timeout_ms() -> u64 {
    10_000
}

fn default_handshake_timeout_ms() -> u64 {
    10_000
}

fn default_max_concurrent_connections() -> u32 {
    2048
}

fn default_max_concurrent_connections_per_source() -> u32 {
    256
}

fn default_pre_auth_max_concurrent() -> u32 {
    512
}

fn default_fallback_max_concurrent() -> u32 {
    512
}

fn default_h2_max_concurrent_streams() -> u32 {
    256
}

fn default_h2_max_concurrent_reset_streams() -> u32 {
    50
}

fn default_h2_max_pending_accept_reset_streams() -> u32 {
    20
}

fn default_h2_max_local_error_reset_streams() -> u32 {
    1_024
}

fn default_auth_failure_window_secs() -> u64 {
    60
}

fn default_max_auth_failures_per_window() -> u32 {
    24
}

fn default_auth_failure_cache_max_entries() -> u32 {
    4096
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_max_concurrent_flows() -> u32 {
    256
}

fn default_max_frame_size() -> u32 {
    65_536
}

fn default_replay_window_secs() -> i64 {
    120
}

fn default_replay_cache_entries_per_credential() -> usize {
    16_384
}

fn default_replay_cache_max_credentials_per_shard() -> usize {
    1_024
}

fn default_dns_timeout_ms() -> u64 {
    5_000
}

fn default_udp_idle_timeout_ms() -> u64 {
    30_000
}

fn default_shaping_max_padding_bytes_per_frame() -> u16 {
    256
}

fn default_shaping_max_overhead_ratio() -> f64 {
    0.25
}

fn default_shaping_max_delay_ms() -> u64 {
    20
}

fn default_shaping_max_batch_bytes() -> u32 {
    65_536
}

fn default_cover_traffic_window_ms() -> u64 {
    1_000
}

const FRAME_HEADER_MIN_MAX_SIZE: u32 = 14;
const AUTH_V1_MAX_STRING_LEN: usize = u16::MAX as usize;
pub const MAX_REPLAY_WINDOW_SECS: i64 = 86_400;

fn validate_auth_v1_string_len(field: &str, value: &str) -> Result<()> {
    if value.len() > AUTH_V1_MAX_STRING_LEN {
        return Err(Error::Config(format!(
            "{field} must be at most {AUTH_V1_MAX_STRING_LEN} bytes for Auth v1 wire encoding"
        )));
    }
    Ok(())
}

fn validate_auth_v2_credential_hint_len(field: &str, value: &str) -> Result<()> {
    if value.len() > AUTH_V2_MAX_CREDENTIAL_HINT_LEN {
        return Err(Error::Config(format!(
            "{field} must be at most {AUTH_V2_MAX_CREDENTIAL_HINT_LEN} bytes when auth.v2.enabled is true"
        )));
    }
    Ok(())
}

fn validate_cert_pin(pin: &str) -> Result<()> {
    let encoded = pin
        .strip_prefix("sha256/")
        .ok_or_else(|| Error::Config("cert_pin must use sha256/<base64url-no-pad>".into()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| Error::Config("cert_pin is not valid base64url".into()))?;
    if decoded.len() != 32 {
        return Err(Error::Config(
            "cert_pin SHA-256 value must be 32 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_loopback_listener(field: &str, listen: SocketAddr) -> Result<()> {
    if listen.ip().is_loopback() {
        return Ok(());
    }
    Err(Error::Config(format!(
        "{field} must be loopback unless advanced.allow_non_loopback_listeners is true"
    )))
}

fn parse_rfc3339(field: &str, value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| Error::Config(format!("{field} must be RFC3339 timestamp")))
}

pub fn parse_auth_epoch(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| Error::Config("auth.rotation.active_epoch must be an unsigned integer".into()))
}

fn validate_experimental_ech(enabled: bool) -> Result<()> {
    if enabled {
        return Err(Error::Config(
            "advanced.experimental_ech is reserved until TLS stack ECH support is implemented"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_server_config(credential_id: &str, secret: SecretString) -> ClientServerConfig {
        ClientServerConfig {
            address: "example.com:443".into(),
            server_name: "example.com".into(),
            tunnel_path: "/assets/upload".into(),
            credential_id: credential_id.into(),
            secret,
            ca_cert: None,
            cert_pin: None,
        }
    }

    fn client_config_with_server(server: ClientServerConfig) -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                dns: None,
                http_connect: None,
            },
            server,
            auth: ClientAuthConfig::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }

    fn server_config_with_user(user_id: &str, tunnel_path: &str) -> ServerConfig {
        ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: TlsConfig {
                cert_path: "./cert.pem".into(),
                key_path: "./key.pem".into(),
            },
            maverick: MaverickServerConfig {
                tunnel_path: tunnel_path.into(),
                mode_default: Mode::Auto,
                replay_window_secs: default_replay_window_secs(),
                replay_cache_entries_per_credential: default_replay_cache_entries_per_credential(),
                replay_cache_max_credentials_per_shard:
                    default_replay_cache_max_credentials_per_shard(),
                max_concurrent_flows_per_user: default_max_concurrent_flows(),
            },
            users: vec![UserConfig {
                id: user_id.into(),
                name: None,
                secret: SecretString::generate(),
                enabled: true,
                rate_limit: None,
                max_concurrent_flows: None,
                rotation: None,
            }],
            fallback: FallbackConfig::Static {
                static_dir: "./public".into(),
                index: default_index(),
            },
            auth: ServerAuthConfig::default(),
            dns: None,
            metrics: None,
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig::default(),
        }
    }

    #[test]
    fn secret_debug_redacts() {
        let secret = SecretString::generate();
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn secret_serialize_redacts_by_default() {
        let secret = SecretString::generate();
        let cfg = client_config_with_server(client_server_config("u_abc123", secret.clone()));

        let rendered = serde_yaml_ng::to_string(&cfg).unwrap();

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(secret.expose_secret()));
    }

    #[test]
    fn rejects_short_secret() {
        assert!(SecretString::new("mv1_short").is_err());
    }

    #[test]
    fn parses_valid_client_config() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
"#,
            secret.expose_secret()
        );
        ClientConfig::from_yaml_str(&input).unwrap();
    }

    #[test]
    fn rejects_client_log_redaction_disablement() {
        let secret = SecretString::generate();
        let mut cfg = client_config_with_server(client_server_config("u_abc123", secret));
        cfg.log.redact = false;

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("log.redact=false"));
    }

    #[test]
    fn client_tun_runtime_is_default_off_and_stable_mode_rejects_it() {
        let secret = SecretString::generate();
        let mut cfg = client_config_with_server(client_server_config("u_abc123", secret));
        assert!(!cfg.advanced.experimental_tun);
        cfg.mode = Mode::Stable;
        cfg.advanced.experimental_tun = true;

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("experimental_tun"));
    }

    #[test]
    fn rejects_empty_client_log_level() {
        let secret = SecretString::generate();
        let mut cfg = client_config_with_server(client_server_config("u_abc123", secret));
        cfg.log.level = "  ".into();

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("log.level"));
    }

    #[test]
    fn rejects_auth_v1_fields_that_exceed_wire_length() {
        let secret = SecretString::generate();
        let oversized = "u".repeat(AUTH_V1_MAX_STRING_LEN + 1);
        let cfg = client_config_with_server(client_server_config(&oversized, secret.clone()));
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("server.credential_id"));

        let mut cfg = client_config_with_server(client_server_config("u_abc123", secret));
        cfg.server.tunnel_path = format!("/{}", "a".repeat(AUTH_V1_MAX_STRING_LEN));
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("server.tunnel_path"));

        let cfg = server_config_with_user(&oversized, "/assets/upload");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("user.id"));

        let cfg = server_config_with_user(
            "u_abc123",
            &format!("/{}", "a".repeat(AUTH_V1_MAX_STRING_LEN)),
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("maverick.tunnel_path"));
    }

    #[test]
    fn rejects_auth_v2_credential_hints_that_exceed_wire_length() {
        let secret = SecretString::generate();
        let oversized = "u".repeat(AUTH_V2_MAX_CREDENTIAL_HINT_LEN + 1);
        let mut cfg = client_config_with_server(client_server_config(&oversized, secret));
        cfg.auth.v2.enabled = true;
        cfg.auth.rotation.active_epoch = Some("202607".into());

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("server.credential_id"));
        assert!(err.to_string().contains("auth.v2.enabled"));

        let mut cfg = server_config_with_user(&oversized, "/assets/upload");
        cfg.auth.v2.enabled = true;
        cfg.auth.v2.require = true;
        cfg.auth.v2.accepted_epochs = vec![202607];
        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("user.id"));
        assert!(err.to_string().contains("auth.v2.enabled"));
    }

    #[test]
    fn validates_cert_pin_format() {
        let pin = format!("sha256/{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
        assert!(validate_cert_pin(&pin).is_ok());
        assert!(validate_cert_pin("sha256/not-valid").is_err());
    }

    #[test]
    fn parses_valid_client_config_with_cert_pin() {
        let secret = SecretString::generate();
        let pin = format!("sha256/{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
  cert_pin: "{}"
"#,
            secret.expose_secret(),
            pin
        );
        assert!(ClientConfig::from_yaml_str(&input).is_ok());
    }

    #[test]
    fn parses_client_auth_rotation_metadata() {
        let secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  v2:
    enabled: false
  rotation:
    active_epoch: "2026-07"
    next_credential_id: "u_next"
    auto_switch: true
    next:
      id: "u_next"
      secret: "{}"
      not_before: "2026-07-15T00:00:00Z"
"#,
            secret.expose_secret(),
            next_secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert_eq!(cfg.auth.rotation.active_epoch.as_deref(), Some("2026-07"));
        assert_eq!(
            cfg.auth.rotation.next_credential_id.as_deref(),
            Some("u_next")
        );
        assert!(cfg.auth.rotation.auto_switch);
        let next = cfg.auth.rotation.next.as_ref().unwrap();
        assert_eq!(next.id, "u_next");
        assert_eq!(next.secret, next_secret);
        assert_eq!(next.not_before, "2026-07-15T00:00:00Z");
    }

    #[test]
    fn rejects_client_auto_switch_without_next_credential() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  rotation:
    auto_switch: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("auth.rotation.next is required"));
    }

    #[test]
    fn rejects_client_next_credential_id_mismatch() {
        let secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  rotation:
    next_credential_id: "u_next_a"
    next:
      id: "u_next_b"
      secret: "{}"
      not_before: "2026-07-15T00:00:00Z"
"#,
            secret.expose_secret(),
            next_secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("next_credential_id"));
    }

    #[test]
    fn client_credential_selector_switches_after_not_before() {
        let active_secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let server = client_server_config("u_active", active_secret);
        let rotation = ClientCredentialRotationConfig {
            next_credential_id: Some("u_next".into()),
            auto_switch: true,
            next: Some(ClientNextCredentialConfig {
                id: "u_next".into(),
                secret: next_secret.clone(),
                not_before: "2026-07-15T00:00:00Z".into(),
            }),
            ..ClientCredentialRotationConfig::default()
        };
        let now = parse_rfc3339("test.now", "2026-07-15T00:00:01Z")
            .unwrap()
            .unix_timestamp();

        let selected = select_client_credential_at_unix(&server, &rotation, now).unwrap();

        assert_eq!(selected.id, "u_next");
        assert_eq!(selected.secret, &next_secret);
        assert_eq!(selected.selection, ClientCredentialSelection::Next);
    }

    #[test]
    fn client_credential_selector_keeps_active_before_not_before() {
        let active_secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let server = client_server_config("u_active", active_secret.clone());
        let rotation = ClientCredentialRotationConfig {
            next_credential_id: Some("u_next".into()),
            auto_switch: true,
            next: Some(ClientNextCredentialConfig {
                id: "u_next".into(),
                secret: next_secret,
                not_before: "2026-07-15T00:00:00Z".into(),
            }),
            ..ClientCredentialRotationConfig::default()
        };
        let now = parse_rfc3339("test.now", "2026-07-14T23:59:59Z")
            .unwrap()
            .unix_timestamp();

        let selected = select_client_credential_at_unix(&server, &rotation, now).unwrap();

        assert_eq!(selected.id, "u_active");
        assert_eq!(selected.secret, &active_secret);
        assert_eq!(selected.selection, ClientCredentialSelection::Active);
    }

    #[test]
    fn parses_client_auth_v2_with_numeric_epoch() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  v2:
    enabled: true
  rotation:
    active_epoch: "202607"
"#,
            secret.expose_secret()
        );
        ClientConfig::from_yaml_str(&input).unwrap();
    }

    #[test]
    fn rejects_client_auth_v2_without_numeric_epoch() {
        let secret = SecretString::generate();
        let missing = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  v2:
    enabled: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&missing).unwrap_err();
        assert!(err.to_string().contains("active_epoch"));

        let invalid = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  v2:
    enabled: true
  rotation:
    active_epoch: "2026-07"
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&invalid).unwrap_err();
        assert!(err.to_string().contains("active_epoch"));
    }

    #[test]
    fn rejects_zero_client_advanced_timeouts() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  connect_timeout_ms: 0
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("connect_timeout_ms"));
    }

    #[test]
    fn parses_client_shaping_budget_config() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  shaping:
    enabled: true
    max_padding_bytes_per_frame: 128
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 32768
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert!(cfg.advanced.shaping.enabled);
        assert_eq!(cfg.advanced.shaping.max_padding_bytes_per_frame, 128);
    }

    #[test]
    fn rejects_unbounded_shaping_config() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  shaping:
    max_overhead_ratio: 2.0
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("max_overhead_ratio"));
    }

    #[test]
    fn rejects_cover_traffic_without_operator_approval() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  shaping:
    enabled: true
    cover_traffic: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("cover_traffic_operator_approved"));
    }

    #[test]
    fn parses_operator_approved_cover_traffic_config() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  shaping:
    enabled: true
    max_padding_bytes_per_frame: 64
    max_overhead_ratio: 0.25
    max_delay_ms: 5
    max_batch_bytes: 1024
    cover_traffic: true
    cover_traffic_operator_approved: true
    cover_traffic_window_ms: 1000
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert!(cfg.advanced.shaping.cover_traffic);
        assert!(cfg.advanced.shaping.cover_traffic_operator_approved);
        assert_eq!(cfg.advanced.shaping.cover_traffic_window_ms, 1000);
    }

    #[test]
    fn rejects_experimental_ech_until_implemented() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  experimental_ech: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("experimental_ech"));
    }

    #[test]
    fn stable_mode_rejects_experimental_cloudflare_ws() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: stable
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  experimental_cloudflare_ws: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("CDN-fronted WebSocket"));
    }

    #[cfg(not(feature = "browser-tls"))]
    #[test]
    fn rejects_browser_mimic_tls_fingerprint_until_implemented() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  stealth:
    tls_fingerprint: browser_mimic
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("browser_mimic"));
    }

    #[cfg(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn parses_browser_mimic_tls_fingerprint_when_feature_enabled() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  stealth:
    tls_fingerprint: browser_mimic
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert_eq!(
            cfg.advanced.stealth.tls_fingerprint,
            TlsFingerprintMode::BrowserMimic
        );
    }

    #[cfg(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn private_mode_accepts_only_explicit_browser_tls_profile() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: private
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  stealth:
    tls_fingerprint: browser_mimic
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert_eq!(cfg.mode, Mode::Private);
        assert_eq!(
            cfg.advanced.stealth.tls_fingerprint,
            TlsFingerprintMode::BrowserMimic
        );
    }

    #[test]
    fn private_mode_rejects_disabled_active_probe_resistance() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: private
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  stealth:
    active_probe_resistance: false
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("active_probe_resistance"));
    }

    #[test]
    fn private_mode_rejects_default_tls_fingerprint() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: private
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("tls_fingerprint"));
    }

    #[test]
    fn cloudflare_ws_requires_explicit_cdn_fronting_ack() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  experimental_cloudflare_ws: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("cdn_fronting.enabled"));

        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  experimental_cloudflare_ws: true
  stealth:
    cdn_fronting:
      enabled: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("trusted_tls_terminating_provider"));
    }

    #[test]
    fn parses_cloudflare_ws_with_explicit_cdn_fronting_ack() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  experimental_cloudflare_ws: true
  stealth:
    active_probe_resistance: true
    cdn_fronting:
      enabled: true
      trusted_tls_terminating_provider: true
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert!(cfg.advanced.experimental_cloudflare_ws);
        assert!(cfg.advanced.stealth.active_probe_resistance);
        assert!(cfg.advanced.stealth.cdn_fronting.enabled);
        assert!(
            cfg.advanced
                .stealth
                .cdn_fronting
                .trusted_tls_terminating_provider
        );
    }

    #[test]
    fn parses_cdn_fronting_as_first_class_websocket_carrier() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  stealth:
    active_probe_resistance: true
    cdn_fronting:
      enabled: true
      provider: cloudflare
      carrier: web_socket
      trusted_tls_terminating_provider: true
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert!(!cfg.advanced.experimental_cloudflare_ws);
        assert!(cfg.advanced.cloudflare_ws_enabled());
        assert!(cfg.advanced.stealth.cdn_fronting.enabled);
    }

    #[test]
    fn parses_default_crypto_policy() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  crypto:
    offered_suites:
      - "tls13"
"#,
            secret.expose_secret()
        );
        let cfg = ClientConfig::from_yaml_str(&input).unwrap();
        assert_eq!(
            cfg.advanced.crypto.offered_suites,
            vec![crate::crypto::CryptoSuiteId::Tls13]
        );
    }

    #[test]
    fn rejects_disabled_crypto_suites() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  crypto:
    offered_suites:
      - "tls13"
      - "hpke_config_v1"
    allow_experimental: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("disabled suite"));
    }

    #[test]
    fn stable_mode_rejects_experimental_crypto_policy() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: stable
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  crypto:
    offered_suites:
      - "tls13"
    allow_experimental: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("stable mode"));
    }

    #[test]
    fn server_default_mode_rejects_experimental_crypto_policy() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
  mode_default: stable
  replay_window_secs: 120
  max_concurrent_flows_per_user: 128
users:
  - id: "u_abc123"
    name: "alice"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  crypto:
    offered_suites:
      - "tls13"
    allow_experimental: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("stable mode"));
    }

    #[test]
    fn server_stable_mode_rejects_experimental_cloudflare_ws() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
  mode_default: stable
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  experimental_cloudflare_ws: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("CDN-fronted WebSocket"));
    }

    #[test]
    fn server_rejects_browser_mimic_tls_fingerprint_until_implemented() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  stealth:
    tls_fingerprint: browser_mimic
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("browser_mimic"));
    }

    #[test]
    fn server_cloudflare_ws_requires_explicit_cdn_fronting_ack() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  experimental_cloudflare_ws: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("cdn_fronting.enabled"));

        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  experimental_cloudflare_ws: true
  stealth:
    active_probe_resistance: true
    cdn_fronting:
      enabled: true
      trusted_tls_terminating_provider: true
"#,
            secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        assert!(cfg.advanced.experimental_cloudflare_ws);
        assert!(cfg.advanced.stealth.cdn_fronting.enabled);
    }

    #[test]
    fn server_parses_cdn_fronting_as_first_class_websocket_carrier() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  stealth:
    active_probe_resistance: true
    cdn_fronting:
      enabled: true
      provider: cloudflare
      carrier: web_socket
      trusted_tls_terminating_provider: true
"#,
            secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        assert!(!cfg.advanced.experimental_cloudflare_ws);
        assert!(cfg.advanced.cloudflare_ws_enabled());
        assert!(cfg.advanced.stealth.cdn_fronting.enabled);
    }

    #[test]
    fn server_stable_mode_rejects_experimental_h3() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
  mode_default: stable
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
advanced:
  experimental_h3: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("experimental_h3"));
    }

    #[test]
    fn private_mode_rejects_plain_sni_ech_fallback_policy() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: private
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  ech_fallback_policy: "allow_plain_sni"
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("allow_plain_sni"));
    }

    #[test]
    fn rejects_non_loopback_client_listener_by_default() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "0.0.0.0:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("local.socks5.listen"));
    }

    #[test]
    fn allows_non_loopback_client_listener_when_explicit() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "0.0.0.0:1080"
  dns:
    enabled: true
    listen: "0.0.0.0:5353"
  http_connect:
    enabled: true
    listen: "0.0.0.0:18080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
advanced:
  allow_non_loopback_listeners: true
"#,
            secret.expose_secret()
        );
        assert!(ClientConfig::from_yaml_str(&input).is_ok());
    }

    #[test]
    fn parses_valid_server_config_with_rate_limit() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
    rate_limit:
      bytes_per_second: 1024
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret()
        );
        ServerConfig::from_yaml_str(&input).unwrap();
    }

    #[test]
    fn default_egress_policy_classifies_embedded_ipv4_forms() {
        let policy = ServerEgressPolicyConfig::default();
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:169.254.169.254",
            "::ffff:224.0.0.1",
            "::10.0.0.1",
            "::169.254.169.254",
            "64:ff9b::127.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::5db8:d822",
            "2002:7f00:0001::",
            "2002:0a00:0001::",
            "2002:6440:0001::",
            "2002:a9fe:a9fe::",
            "2002:e000:0001::",
            "2001:0::ffff:f5ff:fffe",
        ] {
            assert!(!policy.allows_ip(address.parse::<IpAddr>().unwrap()));
        }
        for address in [
            "::ffff:93.184.216.34",
            "::93.184.216.34",
            "64:ff9b::93.184.216.34",
            "2002:5db8:d822::",
            "2001:0::ffff:a247:27dd",
        ] {
            assert!(policy.allows_ip(address.parse::<IpAddr>().unwrap()));
        }
    }

    #[test]
    fn default_egress_policy_rejects_reserved_ipv4_ranges() {
        let policy = ServerEgressPolicyConfig::default();
        for address in [
            "0.1.2.3",
            "192.0.0.8",
            "192.0.2.10",
            "198.18.0.1",
            "198.51.100.10",
            "203.0.113.10",
            "192.88.99.1",
            "192.88.99.254",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!policy.allows_ip(address.parse::<IpAddr>().unwrap()));
        }
    }

    #[test]
    fn rejects_excessive_replay_window() {
        let mut cfg = server_config_with_user("u_abc123", "/assets/upload");
        cfg.maverick.replay_window_secs = MAX_REPLAY_WINDOW_SECS + 1;

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("replay_window_secs"));
    }

    #[test]
    fn parses_valid_server_rotation_config() {
        let secret = SecretString::generate();
        let previous_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_abc123_2026_06"
          secret: "{}"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
      next:
        id: "u_abc123_2026_08"
        not_before: "2026-07-15T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret(),
            previous_secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        let rotation = cfg.users[0].rotation.as_ref().unwrap();
        assert_eq!(rotation.previous.len(), 1);
        assert_eq!(rotation.next.as_ref().unwrap().id, "u_abc123_2026_08");
    }

    #[test]
    fn parses_server_auth_v2_with_required_accepted_epochs() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
auth:
  v2:
    enabled: true
    require: true
    accepted_epochs: [202607, 202608]
"#,
            secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        assert_eq!(cfg.auth.v2.accepted_epochs, vec![202607, 202608]);
        assert!(cfg.auth.v2.require);
    }

    #[test]
    fn rejects_server_auth_v2_without_require_mode() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
auth:
  v2:
    enabled: true
    accepted_epochs: [202607]
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("auth.v2.require"));
    }

    #[test]
    fn parses_server_auth_v2_require_mode() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
auth:
  v2:
    enabled: true
    require: true
    accepted_epochs: [202607]
"#,
            secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        assert!(cfg.auth.v2.require);
    }

    #[test]
    fn rejects_auth_v2_require_without_enablement() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
auth:
  v2:
    require: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("auth.v2.require"));
    }

    #[test]
    fn rejects_server_auth_v2_without_accepted_epochs() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
auth:
  v2:
    enabled: true
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("accepted_epochs"));
    }

    #[test]
    fn rejects_duplicate_rotation_ids() {
        let secret = SecretString::generate();
        let previous_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_abc123"
          secret: "{}"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret(),
            previous_secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("credential ids must be unique"));
    }

    #[test]
    fn rejects_invalid_rotation_window() {
        let secret = SecretString::generate();
        let previous_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_abc123_2026_06"
          secret: "{}"
          not_before: "2026-07-15T00:00:00Z"
          not_after: "2026-06-01T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret(),
            previous_secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("not_after"));
    }

    #[test]
    fn rejects_short_rotated_secret() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_abc123_2026_06"
          secret: "mv1_short"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret()
        );
        assert!(ServerConfig::from_yaml_str(&input).is_err());
    }

    #[test]
    fn rejects_zero_server_advanced_timeouts() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
advanced:
  tcp_connect_timeout_ms: 0
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("tcp_connect_timeout_ms"));
    }

    #[test]
    fn rejects_zero_server_handshake_timeout() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
advanced:
  handshake_timeout_ms: 0
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("handshake_timeout_ms"));
    }

    #[test]
    fn rejects_zero_server_auth_limit_fields() {
        for field in [
            "max_concurrent_connections",
            "max_concurrent_connections_per_source",
            "pre_auth_max_concurrent",
            "fallback_max_concurrent",
            "h2_max_concurrent_streams",
            "h2_max_concurrent_reset_streams",
            "h2_max_pending_accept_reset_streams",
            "h2_max_local_error_reset_streams",
            "auth_failure_window_secs",
            "max_auth_failures_per_window",
            "auth_failure_cache_max_entries",
        ] {
            let secret = SecretString::generate();
            let input = format!(
                r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
advanced:
  {field}: 0
"#,
                secret.expose_secret()
            );
            let err = ServerConfig::from_yaml_str(&input).unwrap_err();
            assert!(
                err.to_string().contains(field),
                "expected {field} validation error, got {err}"
            );
        }
    }

    #[test]
    fn rejects_server_log_redaction_disablement() {
        let mut cfg = server_config_with_user("u_abc123", "/assets/upload");
        cfg.log.redact = false;

        let err = cfg.validate().unwrap_err();

        assert!(err.to_string().contains("log.redact=false"));
    }

    #[test]
    fn rejects_zero_replay_cache_entries_per_credential() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
  replay_cache_entries_per_credential: 0
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err
            .to_string()
            .contains("replay_cache_entries_per_credential"));
    }

    #[test]
    fn rejects_zero_replay_cache_max_credentials_per_shard() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
  replay_cache_max_credentials_per_shard: 0
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret()
        );
        let err = ServerConfig::from_yaml_str(&input).unwrap_err();
        assert!(err
            .to_string()
            .contains("replay_cache_max_credentials_per_shard"));
    }

    #[test]
    fn channel_binding_require_rejects_unsupported_transports() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
auth:
  channel_binding:
    require: true
advanced:
  experimental_h3: true
"#,
            secret.expose_secret()
        );
        let err = ClientConfig::from_yaml_str(&input).unwrap_err();
        assert!(err.to_string().contains("channel_binding.require"));
    }
}
