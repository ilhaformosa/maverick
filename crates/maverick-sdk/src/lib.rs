//! Embedded Maverick runtime API.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain};
#[cfg(target_os = "macos")]
use keyring_core::Entry;
pub use maverick_core::config::{
    AuthV2Config, ClientAdvancedConfig, ClientAuthConfig, ClientConfig,
    ClientCredentialRotationConfig, ClientNextCredentialConfig, ClientServerConfig, FallbackConfig,
    LocalConfig, LogConfig, MaverickServerConfig, MetricsConfig, Mode, SecretString,
    ServerAdvancedConfig, ServerConfig, Socks5Config, TlsConfig, UserConfig,
};
pub use maverick_core::{
    GuiConnectionState, GuiDiagnosticsSnapshot, GuiErrorClass, GuiRuntimeReadinessSnapshot,
    GuiTransportStatus, GuiTunControlState, GuiTunSafetySnapshot, TunRuntimeReadinessSnapshot,
};
#[cfg(feature = "tun-runtime")]
pub use maverick_tun::{
    PacketIo, PacketRead, PacketReader, PacketRuntimeConfig, PacketRuntimeSnapshot,
    PacketRuntimeState, PacketWriter, ShutdownReport as TunShutdownReport,
};
use serde::{Deserialize, Serialize};

mod platform_helper_ipc;
pub use platform_helper_ipc::{
    PlatformHelperErrorClass, PlatformHelperOperation, PlatformHelperOutcome,
    PlatformHelperRequest, PlatformHelperResponse, PLATFORM_HELPER_IPC_VERSION,
    PLATFORM_HELPER_JOURNAL_FILE, PLATFORM_HELPER_MAX_MESSAGE_BYTES,
};
mod reference_client;
pub use reference_client::{
    PacketRuntimeControl, PlatformHelperTransport, ReferenceClientController,
    ReferenceClientErrorClass, ReferenceClientFuture, ReferenceClientSnapshot,
    ReferenceClientState,
};

pub struct MaverickClient {
    handle: Option<maverick_client::ClientHandle>,
}

impl MaverickClient {
    pub async fn start(config: ClientConfig) -> Result<Self> {
        Ok(Self {
            handle: Some(maverick_client::start_client(config).await?),
        })
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.handle.as_ref().map(|handle| handle.local_addr)
    }

    #[cfg(feature = "tun-runtime")]
    pub async fn start_tun_runtime(
        &mut self,
        config: PacketRuntimeConfig,
        io: PacketIo,
    ) -> Result<()> {
        self.handle
            .as_mut()
            .ok_or_else(already_shutdown)?
            .start_tun_runtime(config, io)
            .await
    }

    #[cfg(feature = "tun-runtime")]
    pub fn tun_runtime_snapshot(&self) -> Option<PacketRuntimeSnapshot> {
        self.handle
            .as_ref()
            .and_then(maverick_client::ClientHandle::tun_runtime_snapshot)
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let handle = self.handle.take().ok_or_else(already_shutdown)?;
        handle.shutdown().await
    }
}

pub struct MaverickServer {
    handle: Option<maverick_server::ServerHandle>,
}

impl MaverickServer {
    pub async fn start(config: ServerConfig) -> Result<Self> {
        Ok(Self {
            handle: Some(maverick_server::start_server(config).await?),
        })
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.handle.as_ref().map(|handle| handle.local_addr)
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let handle = self.handle.take().ok_or_else(already_shutdown)?;
        handle.shutdown().await
    }
}

pub struct GuiClientRuntime {
    profile_name: String,
    config: ClientConfig,
    client: Option<MaverickClient>,
    last_error_class: Option<GuiErrorClass>,
}

impl GuiClientRuntime {
    pub fn new(profile_name: impl Into<String>, config: ClientConfig) -> Result<Self> {
        config.validate().map_err(anyhow::Error::from)?;
        Ok(Self {
            profile_name: profile_name.into(),
            config,
            client: None,
            last_error_class: None,
        })
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.client.as_ref().and_then(MaverickClient::local_addr)
    }

    pub fn diagnostics(&self) -> GuiDiagnosticsSnapshot {
        let connection_state = if self.client.is_some() {
            GuiConnectionState::Connected
        } else if self.last_error_class.is_some() {
            GuiConnectionState::Error
        } else {
            GuiConnectionState::Disconnected
        };
        let mut snapshot = GuiDiagnosticsSnapshot::from_client_config(
            &self.profile_name,
            &self.config,
            connection_state,
            self.last_error_class,
        );
        if let Some(local_addr) = self.local_addr() {
            snapshot.local_socks5 = local_addr;
        }
        snapshot
    }

    pub async fn connect(&mut self) -> Result<()> {
        if self.client.is_some() {
            return Ok(());
        }
        match MaverickClient::start(self.config.clone()).await {
            Ok(client) => {
                self.client = Some(client);
                self.last_error_class = None;
                Ok(())
            }
            Err(err) => {
                self.last_error_class = Some(GuiErrorClass::Network);
                Err(err)
            }
        }
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        client.shutdown().await?;
        self.last_error_class = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRecoveryStatus {
    Clean,
    CleanupRequired,
    Recovering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformRecoveryReason {
    RetainedHelperJournal,
    RollbackFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformRecoverySnapshot {
    pub status: PlatformRecoveryStatus,
    pub reason: Option<PlatformRecoveryReason>,
    pub helper_journal_present: bool,
}

impl PlatformRecoverySnapshot {
    pub fn from_helper_state(
        helper_journal_present: bool,
        recovery_in_progress: bool,
        rollback_failed: bool,
    ) -> Result<Self> {
        if recovery_in_progress && rollback_failed {
            anyhow::bail!("platform recovery cannot be running and failed at the same time");
        }
        if !helper_journal_present && (recovery_in_progress || rollback_failed) {
            anyhow::bail!("platform recovery state requires a retained helper journal");
        }

        let (status, reason) = if !helper_journal_present {
            (PlatformRecoveryStatus::Clean, None)
        } else if recovery_in_progress {
            (
                PlatformRecoveryStatus::Recovering,
                Some(PlatformRecoveryReason::RetainedHelperJournal),
            )
        } else if rollback_failed {
            (
                PlatformRecoveryStatus::CleanupRequired,
                Some(PlatformRecoveryReason::RollbackFailed),
            )
        } else {
            (
                PlatformRecoveryStatus::CleanupRequired,
                Some(PlatformRecoveryReason::RetainedHelperJournal),
            )
        };

        let snapshot = Self {
            status,
            reason,
            helper_journal_present,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(self) -> Result<()> {
        let valid = match self.status {
            PlatformRecoveryStatus::Clean => !self.helper_journal_present && self.reason.is_none(),
            PlatformRecoveryStatus::CleanupRequired => {
                self.helper_journal_present && self.reason.is_some()
            }
            PlatformRecoveryStatus::Recovering => {
                self.helper_journal_present
                    && self.reason == Some(PlatformRecoveryReason::RetainedHelperJournal)
            }
        };
        if !valid {
            anyhow::bail!("inconsistent platform recovery snapshot");
        }
        Ok(())
    }

    pub fn connect_allowed(self) -> bool {
        self.status == PlatformRecoveryStatus::Clean
    }

    pub fn operator_action_required(self) -> bool {
        self.status == PlatformRecoveryStatus::CleanupRequired
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ProfileSecretRef {
    pub service: String,
    pub account: String,
}

impl ProfileSecretRef {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Result<Self> {
        let reference = Self {
            service: service.into(),
            account: account.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn client_profile(profile_name: &str, slot: &str) -> Result<Self> {
        Self::new(
            "maverick.client-profile",
            format!("profile:{profile_name}:{slot}"),
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.service.trim().is_empty() {
            anyhow::bail!("profile secret reference service must not be empty");
        }
        if self.account.trim().is_empty() {
            anyhow::bail!("profile secret reference account must not be empty");
        }
        Ok(())
    }
}

pub trait ProfileSecretStore {
    fn put_secret(&mut self, reference: &ProfileSecretRef, secret: &SecretString) -> Result<()>;
    fn get_secret(&self, reference: &ProfileSecretRef) -> Result<SecretString>;
    fn delete_secret(&mut self, reference: &ProfileSecretRef) -> Result<()>;
}

#[derive(Default, Debug)]
pub struct InMemoryProfileSecretStore {
    secrets: BTreeMap<ProfileSecretRef, SecretString>,
}

impl InMemoryProfileSecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProfileSecretStore for InMemoryProfileSecretStore {
    fn put_secret(&mut self, reference: &ProfileSecretRef, secret: &SecretString) -> Result<()> {
        reference.validate()?;
        self.secrets.insert(reference.clone(), secret.clone());
        Ok(())
    }

    fn get_secret(&self, reference: &ProfileSecretRef) -> Result<SecretString> {
        self.secrets
            .get(reference)
            .cloned()
            .with_context(|| format!("missing profile secret for {}", reference.account))
    }

    fn delete_secret(&mut self, reference: &ProfileSecretRef) -> Result<()> {
        self.secrets.remove(reference);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeProfileSecretStore;

impl NativeProfileSecretStore {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "macos")]
    fn entry(reference: &ProfileSecretRef) -> Result<Entry> {
        reference.validate()?;
        Cred::build(
            MacKeychainDomain::User,
            &reference.service,
            &reference.account,
        )
        .with_context(|| {
            format!(
                "open native profile secret store entry for service {} account {}",
                reference.service, reference.account
            )
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn unsupported(reference: &ProfileSecretRef) -> Result<()> {
        reference.validate()?;
        anyhow::bail!("native profile secret store is currently macOS-only")
    }
}

impl ProfileSecretStore for NativeProfileSecretStore {
    fn put_secret(&mut self, reference: &ProfileSecretRef, secret: &SecretString) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            Self::entry(reference)?
                .set_password(secret.expose_secret())
                .with_context(|| {
                    format!(
                        "write native profile secret for service {} account {}",
                        reference.service, reference.account
                    )
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = secret;
            Self::unsupported(reference)
        }
    }

    fn get_secret(&self, reference: &ProfileSecretRef) -> Result<SecretString> {
        #[cfg(target_os = "macos")]
        {
            let secret = Self::entry(reference)?.get_password().with_context(|| {
                format!(
                    "read native profile secret for service {} account {}",
                    reference.service, reference.account
                )
            })?;
            SecretString::new(secret).map_err(anyhow::Error::from)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::unsupported(reference)?;
            unreachable!("unsupported native store returns before reading secret")
        }
    }

    fn delete_secret(&mut self, reference: &ProfileSecretRef) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            Self::entry(reference)?
                .delete_credential()
                .with_context(|| {
                    format!(
                        "delete native profile secret for service {} account {}",
                        reference.service, reference.account
                    )
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::unsupported(reference)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientProfile {
    pub profile_name: String,
    pub version: u16,
    pub mode: Mode,
    pub local: LocalConfig,
    pub server: StoredClientServerProfile,
    pub auth: StoredClientAuthProfile,
    pub log: LogConfig,
    pub advanced: ClientAdvancedConfig,
}

impl StoredClientProfile {
    pub fn store_from_config(
        profile_name: impl Into<String>,
        config: &ClientConfig,
        store: &mut impl ProfileSecretStore,
    ) -> Result<Self> {
        config.validate().map_err(anyhow::Error::from)?;
        let profile_name = profile_name.into();
        let active_secret_ref = ProfileSecretRef::client_profile(&profile_name, "active")?;
        store.put_secret(&active_secret_ref, &config.server.secret)?;

        let rotation = StoredClientCredentialRotationProfile::store_from_config(
            &profile_name,
            &config.auth.rotation,
            store,
        )?;

        Ok(Self {
            profile_name,
            version: config.version,
            mode: config.mode,
            local: config.local.clone(),
            server: StoredClientServerProfile {
                address: config.server.address.clone(),
                server_name: config.server.server_name.clone(),
                tunnel_path: config.server.tunnel_path.clone(),
                credential_id: config.server.credential_id.clone(),
                secret_ref: active_secret_ref,
                ca_cert: config.server.ca_cert.clone(),
                cert_pin: config.server.cert_pin.clone(),
            },
            auth: StoredClientAuthProfile {
                v2: config.auth.v2.clone(),
                rotation,
            },
            log: config.log.clone(),
            advanced: config.advanced.clone(),
        })
    }

    pub fn to_client_config(&self, store: &impl ProfileSecretStore) -> Result<ClientConfig> {
        let secret = store.get_secret(&self.server.secret_ref)?;
        let rotation = self.auth.rotation.to_config(store)?;
        let config = ClientConfig {
            version: self.version,
            mode: self.mode,
            local: self.local.clone(),
            server: ClientServerConfig {
                address: self.server.address.clone(),
                server_name: self.server.server_name.clone(),
                tunnel_path: self.server.tunnel_path.clone(),
                credential_id: self.server.credential_id.clone(),
                secret,
                ca_cert: self.server.ca_cert.clone(),
                cert_pin: self.server.cert_pin.clone(),
            },
            auth: ClientAuthConfig {
                channel_binding: Default::default(),
                v2: self.auth.v2.clone(),
                rotation,
            },
            log: self.log.clone(),
            advanced: self.advanced.clone(),
        };
        config.validate().map_err(anyhow::Error::from)?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientServerProfile {
    pub address: String,
    pub server_name: String,
    pub tunnel_path: String,
    pub credential_id: String,
    pub secret_ref: ProfileSecretRef,
    pub ca_cert: Option<PathBuf>,
    pub cert_pin: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientAuthProfile {
    pub v2: AuthV2Config,
    pub rotation: StoredClientCredentialRotationProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientCredentialRotationProfile {
    pub active_epoch: Option<String>,
    pub next_credential_id: Option<String>,
    pub auto_switch: bool,
    pub next: Option<StoredClientNextCredentialProfile>,
}

impl StoredClientCredentialRotationProfile {
    fn store_from_config(
        profile_name: &str,
        rotation: &ClientCredentialRotationConfig,
        store: &mut impl ProfileSecretStore,
    ) -> Result<Self> {
        let next = if let Some(next) = &rotation.next {
            let secret_ref = ProfileSecretRef::client_profile(profile_name, "next")?;
            store.put_secret(&secret_ref, &next.secret)?;
            Some(StoredClientNextCredentialProfile {
                id: next.id.clone(),
                secret_ref,
                not_before: next.not_before.clone(),
            })
        } else {
            None
        };

        Ok(Self {
            active_epoch: rotation.active_epoch.clone(),
            next_credential_id: rotation.next_credential_id.clone(),
            auto_switch: rotation.auto_switch,
            next,
        })
    }

    fn to_config(&self, store: &impl ProfileSecretStore) -> Result<ClientCredentialRotationConfig> {
        let next = self
            .next
            .as_ref()
            .map(|next| -> Result<ClientNextCredentialConfig> {
                Ok(ClientNextCredentialConfig {
                    id: next.id.clone(),
                    secret: store.get_secret(&next.secret_ref)?,
                    not_before: next.not_before.clone(),
                })
            })
            .transpose()?;

        Ok(ClientCredentialRotationConfig {
            active_epoch: self.active_epoch.clone(),
            next_credential_id: self.next_credential_id.clone(),
            auto_switch: self.auto_switch,
            next,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientNextCredentialProfile {
    pub id: String,
    pub secret_ref: ProfileSecretRef,
    pub not_before: String,
}

pub fn client_config_from_yaml(input: &str) -> maverick_core::Result<ClientConfig> {
    ClientConfig::from_yaml_str(input)
}

pub fn server_config_from_yaml(input: &str) -> maverick_core::Result<ServerConfig> {
    ServerConfig::from_yaml_str(input)
}

#[derive(Clone, Debug)]
pub struct ClientConfigBuilder {
    mode: Mode,
    socks5_listen: SocketAddr,
    server_address: Option<String>,
    server_name: Option<String>,
    tunnel_path: String,
    credential_id: Option<String>,
    secret: Option<SecretString>,
    cert_pin: Option<String>,
    experimental_h3: bool,
    experimental_tun: bool,
}

impl Default for ClientConfigBuilder {
    fn default() -> Self {
        Self {
            mode: Mode::Auto,
            socks5_listen: "127.0.0.1:1080".parse().expect("valid loopback default"),
            server_address: None,
            server_name: None,
            tunnel_path: "/assets/upload".into(),
            credential_id: None,
            secret: None,
            cert_pin: None,
            experimental_h3: false,
            experimental_tun: false,
        }
    }
}

impl ClientConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn local_socks5(mut self, listen: SocketAddr) -> Self {
        self.socks5_listen = listen;
        self
    }

    pub fn server_address(mut self, address: impl Into<String>) -> Self {
        self.server_address = Some(address.into());
        self
    }

    pub fn server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Some(server_name.into());
        self
    }

    pub fn tunnel_path(mut self, tunnel_path: impl Into<String>) -> Self {
        self.tunnel_path = tunnel_path.into();
        self
    }

    pub fn credential(mut self, credential_id: impl Into<String>, secret: SecretString) -> Self {
        self.credential_id = Some(credential_id.into());
        self.secret = Some(secret);
        self
    }

    pub fn cert_pin(mut self, cert_pin: impl Into<String>) -> Self {
        self.cert_pin = Some(cert_pin.into());
        self
    }

    pub fn experimental_h3(mut self, enabled: bool) -> Self {
        self.experimental_h3 = enabled;
        self
    }

    pub fn experimental_tun(mut self, enabled: bool) -> Self {
        self.experimental_tun = enabled;
        self
    }

    pub fn build(self) -> Result<ClientConfig> {
        let advanced = ClientAdvancedConfig {
            experimental_h3: self.experimental_h3,
            experimental_tun: self.experimental_tun,
            ..ClientAdvancedConfig::default()
        };
        let config = ClientConfig {
            version: 1,
            mode: self.mode,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: self.socks5_listen,
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: self.server_address.context("server address is required")?,
                server_name: self.server_name.context("server name is required")?,
                tunnel_path: self.tunnel_path,
                credential_id: self
                    .credential_id
                    .context("server credential id is required")?,
                secret: self
                    .secret
                    .context("server credential secret is required")?,
                ca_cert: None,
                cert_pin: self.cert_pin,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced,
        };
        config.validate().map_err(anyhow::Error::from)?;
        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfigBuilder {
    listen: SocketAddr,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    tunnel_path: String,
    mode_default: Mode,
    user_id: Option<String>,
    user_name: Option<String>,
    secret: Option<SecretString>,
    static_dir: Option<PathBuf>,
}

impl Default for ServerConfigBuilder {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:0".parse().expect("valid loopback default"),
            cert_path: None,
            key_path: None,
            tunnel_path: "/assets/upload".into(),
            mode_default: Mode::Auto,
            user_id: None,
            user_name: None,
            secret: None,
            static_dir: None,
        }
    }
}

impl ServerConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn listen(mut self, listen: SocketAddr) -> Self {
        self.listen = listen;
        self
    }

    pub fn tls_paths(
        mut self,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        self.cert_path = Some(cert_path.into());
        self.key_path = Some(key_path.into());
        self
    }

    pub fn tunnel_path(mut self, tunnel_path: impl Into<String>) -> Self {
        self.tunnel_path = tunnel_path.into();
        self
    }

    pub fn mode_default(mut self, mode: Mode) -> Self {
        self.mode_default = mode;
        self
    }

    pub fn user(mut self, user_id: impl Into<String>, secret: SecretString) -> Self {
        self.user_id = Some(user_id.into());
        self.secret = Some(secret);
        self
    }

    pub fn user_name(mut self, name: impl Into<String>) -> Self {
        self.user_name = Some(name.into());
        self
    }

    pub fn static_fallback_dir(mut self, static_dir: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(static_dir.into());
        self
    }

    pub fn build(self) -> Result<ServerConfig> {
        let config = ServerConfig {
            version: 1,
            listen: self.listen,
            tls: TlsConfig {
                cert_path: self.cert_path.context("tls cert path is required")?,
                key_path: self.key_path.context("tls key path is required")?,
            },
            maverick: MaverickServerConfig {
                tunnel_path: self.tunnel_path,
                mode_default: self.mode_default,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 16_384,
                replay_cache_max_credentials_per_shard: 1_024,
                max_concurrent_flows_per_user: 128,
            },
            users: vec![UserConfig {
                id: self.user_id.context("user id is required")?,
                name: self.user_name,
                secret: self.secret.context("user secret is required")?,
                enabled: true,
                rate_limit: None,
                max_concurrent_flows: None,
                rotation: None,
            }],
            fallback: FallbackConfig::Static {
                static_dir: self
                    .static_dir
                    .context("static fallback directory is required")?,
                index: "index.html".into(),
            },
            auth: Default::default(),
            dns: None,
            metrics: None,
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig::default(),
        };
        config.validate().map_err(anyhow::Error::from)?;
        Ok(config)
    }
}

pub fn client_config_builder() -> ClientConfigBuilder {
    ClientConfigBuilder::new()
}

pub fn server_config_builder() -> ServerConfigBuilder {
    ServerConfigBuilder::new()
}

fn already_shutdown() -> anyhow::Error {
    anyhow::anyhow!("runtime already shut down")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn client_runtime_starts_and_stops_loopback_listener() -> Result<()> {
        let runtime = MaverickClient::start(ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse()?,
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "127.0.0.1:443".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_sdk".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        })
        .await?;
        assert!(runtime.local_addr().unwrap().ip().is_loopback());
        runtime.shutdown().await
    }

    #[tokio::test]
    async fn client_runtime_rejects_non_loopback_listener_before_bind() -> Result<()> {
        let err = match MaverickClient::start(ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "0.0.0.0:0".parse()?,
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "127.0.0.1:443".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_sdk".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        })
        .await
        {
            Ok(runtime) => {
                runtime.shutdown().await?;
                panic!("client runtime accepted non-loopback listener");
            }
            Err(err) => err,
        };
        assert!(err.to_string().contains("local.socks5.listen"));
        Ok(())
    }

    #[tokio::test]
    async fn server_runtime_starts_and_stops_loopback_listener() -> Result<()> {
        let tmp = TempDir::new()?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        tokio::fs::write(&cert_path, certified.cert.pem()).await?;
        tokio::fs::write(&key_path, certified.key_pair.serialize_pem()).await?;
        tokio::fs::write(tmp.path().join("index.html"), "<!doctype html>").await?;

        let runtime = MaverickServer::start(ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse()?,
            tls: TlsConfig {
                cert_path,
                key_path,
            },
            maverick: MaverickServerConfig {
                tunnel_path: "/assets/upload".into(),
                mode_default: Mode::Auto,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 16_384,
                replay_cache_max_credentials_per_shard: 1_024,
                max_concurrent_flows_per_user: 128,
            },
            users: vec![UserConfig {
                id: "u_sdk".into(),
                name: None,
                secret: SecretString::generate(),
                enabled: true,
                rate_limit: None,
                max_concurrent_flows: None,
                rotation: None,
            }],
            fallback: FallbackConfig::Static {
                static_dir: tmp.path().to_path_buf(),
                index: "index.html".into(),
            },
            auth: Default::default(),
            dns: None,
            metrics: None,
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig::default(),
        })
        .await?;
        assert!(runtime.local_addr().unwrap().ip().is_loopback());
        runtime.shutdown().await
    }

    #[tokio::test]
    async fn server_runtime_rejects_non_loopback_metrics_before_bind() -> Result<()> {
        let tmp = TempDir::new()?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        tokio::fs::write(&cert_path, certified.cert.pem()).await?;
        tokio::fs::write(&key_path, certified.key_pair.serialize_pem()).await?;
        tokio::fs::write(tmp.path().join("index.html"), "<!doctype html>").await?;

        let err = match MaverickServer::start(ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse()?,
            tls: TlsConfig {
                cert_path,
                key_path,
            },
            maverick: MaverickServerConfig {
                tunnel_path: "/assets/upload".into(),
                mode_default: Mode::Auto,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 16_384,
                replay_cache_max_credentials_per_shard: 1_024,
                max_concurrent_flows_per_user: 128,
            },
            users: vec![UserConfig {
                id: "u_sdk".into(),
                name: None,
                secret: SecretString::generate(),
                enabled: true,
                rate_limit: None,
                max_concurrent_flows: None,
                rotation: None,
            }],
            fallback: FallbackConfig::Static {
                static_dir: tmp.path().to_path_buf(),
                index: "index.html".into(),
            },
            auth: Default::default(),
            dns: None,
            metrics: Some(MetricsConfig {
                enabled: true,
                listen: "0.0.0.0:0".parse()?,
            }),
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig::default(),
        })
        .await
        {
            Ok(runtime) => {
                runtime.shutdown().await?;
                panic!("server runtime accepted non-loopback metrics listener");
            }
            Err(err) => err,
        };
        assert!(err.to_string().contains("metrics.listen"));
        Ok(())
    }

    #[test]
    fn sdk_config_parsing_matches_core_validation() {
        let err = client_config_from_yaml("version: 2").unwrap_err();
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn client_builder_creates_valid_loopback_config() -> Result<()> {
        let secret = SecretString::generate();
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_sdk", secret)
            .experimental_h3(true)
            .experimental_tun(true)
            .build()?;
        assert_eq!(config.server.credential_id, "u_sdk");
        assert_eq!(config.local.socks5.listen.to_string(), "127.0.0.1:0");
        assert!(config.advanced.experimental_h3);
        assert!(config.advanced.experimental_tun);
        Ok(())
    }

    #[test]
    fn client_builder_requires_credentials_without_leaking_secret() {
        let err = client_config_builder()
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("credential id"));
        assert!(!err.to_string().contains("mv1_"));
    }

    #[tokio::test]
    async fn server_builder_starts_loopback_runtime() -> Result<()> {
        let tmp = TempDir::new()?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        tokio::fs::write(&cert_path, certified.cert.pem()).await?;
        tokio::fs::write(&key_path, certified.key_pair.serialize_pem()).await?;
        tokio::fs::write(tmp.path().join("index.html"), "<!doctype html>").await?;

        let config = server_config_builder()
            .tls_paths(&cert_path, &key_path)
            .static_fallback_dir(tmp.path())
            .user("u_sdk", SecretString::generate())
            .user_name("sdk-test")
            .build()?;
        let runtime = MaverickServer::start(config).await?;
        assert!(runtime.local_addr().unwrap().ip().is_loopback());
        runtime.shutdown().await
    }

    #[tokio::test]
    async fn gui_client_runtime_lifecycle_updates_redacted_diagnostics() -> Result<()> {
        let secret = SecretString::generate();
        let secret_rendered = secret.expose_secret().to_string();
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_gui_runtime_secret_2026", secret)
            .build()?;
        let mut runtime = GuiClientRuntime::new("primary", config)?;

        let disconnected = runtime.diagnostics();
        assert_eq!(
            disconnected.connection_state,
            GuiConnectionState::Disconnected
        );
        assert_eq!(disconnected.transport_status, GuiTransportStatus::Ready);
        assert!(!disconnected.tun_controls_enabled);

        runtime.connect().await?;
        let connected = runtime.diagnostics();
        assert_eq!(connected.connection_state, GuiConnectionState::Connected);
        assert!(connected.local_socks5.ip().is_loopback());
        assert_ne!(connected.local_socks5.port(), 0);
        assert!(runtime.is_connected());
        let bound_addr = connected.local_socks5;

        let rendered = format!("{connected:?} {}", serde_json::to_string(&connected)?);
        assert!(!rendered.contains("u_gui_runtime_secret_2026"));
        assert!(!rendered.contains(&secret_rendered));
        assert!(!rendered.contains("127.0.0.1:443"));

        runtime.disconnect().await?;
        assert!(!runtime.is_connected());
        assert_eq!(
            runtime.diagnostics().connection_state,
            GuiConnectionState::Disconnected
        );
        let listener = std::net::TcpListener::bind(bound_addr)?;
        drop(listener);
        Ok(())
    }

    #[tokio::test]
    async fn gui_client_runtime_disconnect_is_idempotent() -> Result<()> {
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_gui", SecretString::generate())
            .build()?;
        let mut runtime = GuiClientRuntime::new("primary", config)?;
        runtime.disconnect().await?;
        runtime.connect().await?;
        runtime.disconnect().await?;
        runtime.disconnect().await?;
        assert_eq!(
            runtime.diagnostics().connection_state,
            GuiConnectionState::Disconnected
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_keeps_active_and_next_secrets_out_of_metadata() -> Result<()> {
        let active_secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let active_rendered = active_secret.expose_secret().to_string();
        let next_rendered = next_secret.expose_secret().to_string();
        let mut config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", active_secret)
            .build()?;
        config.auth.rotation = ClientCredentialRotationConfig {
            active_epoch: Some("2026062901".into()),
            next_credential_id: Some("u_next".into()),
            auto_switch: false,
            next: Some(ClientNextCredentialConfig {
                id: "u_next".into(),
                secret: next_secret,
                not_before: "2026-07-01T00:00:00Z".into(),
            }),
        };
        config.validate().map_err(anyhow::Error::from)?;

        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let serialized = serde_json::to_string(&profile)?;
        let rendered = format!("{profile:?} {serialized} {store:?}");
        assert!(!rendered.contains(&active_rendered));
        assert!(!rendered.contains(&next_rendered));
        assert!(serialized.contains("secret_ref"));
        assert!(!serialized.contains("\"secret\""));

        let materialized = profile.to_client_config(&store)?;
        assert_eq!(
            materialized.server.secret.expose_secret(),
            active_rendered.as_str()
        );
        assert_eq!(
            materialized
                .auth
                .rotation
                .next
                .as_ref()
                .unwrap()
                .secret
                .expose_secret(),
            next_rendered.as_str()
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_requires_secret_store_to_materialize() -> Result<()> {
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", SecretString::generate())
            .build()?;
        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;

        store.delete_secret(&profile.server.secret_ref)?;
        let err = profile.to_client_config(&store).unwrap_err();
        assert!(err.to_string().contains("missing profile secret"));
        assert!(!err.to_string().contains("mv1_"));
        Ok(())
    }

    #[test]
    fn native_profile_secret_store_constructs_without_touching_system_store() {
        let store = NativeProfileSecretStore::new();
        let rendered = format!("{store:?}");
        assert_eq!(rendered, "NativeProfileSecretStore");
        assert!(!rendered.contains("mv1_"));
    }

    #[test]
    fn profile_secret_reference_rejects_empty_fields() {
        assert!(ProfileSecretRef::new("", "account").is_err());
        assert!(ProfileSecretRef::new("service", " ").is_err());
    }

    #[test]
    fn platform_recovery_clean_state_allows_connect() -> Result<()> {
        let snapshot = PlatformRecoverySnapshot::from_helper_state(false, false, false)?;
        assert_eq!(snapshot.status, PlatformRecoveryStatus::Clean);
        assert_eq!(snapshot.reason, None);
        assert!(snapshot.connect_allowed());
        assert!(!snapshot.operator_action_required());
        Ok(())
    }

    #[test]
    fn retained_helper_journal_blocks_connect_without_exposing_a_path() -> Result<()> {
        let snapshot = PlatformRecoverySnapshot::from_helper_state(true, false, false)?;
        assert_eq!(snapshot.status, PlatformRecoveryStatus::CleanupRequired);
        assert_eq!(
            snapshot.reason,
            Some(PlatformRecoveryReason::RetainedHelperJournal)
        );
        assert!(!snapshot.connect_allowed());
        assert!(snapshot.operator_action_required());

        let rendered = serde_json::to_string(&snapshot)?;
        assert!(!rendered.contains('/'));
        assert!(!rendered.contains("mv1_"));
        Ok(())
    }

    #[test]
    fn platform_recovery_distinguishes_running_and_failed_rollback() -> Result<()> {
        let recovering = PlatformRecoverySnapshot::from_helper_state(true, true, false)?;
        assert_eq!(recovering.status, PlatformRecoveryStatus::Recovering);
        assert!(!recovering.operator_action_required());

        let failed = PlatformRecoverySnapshot::from_helper_state(true, false, true)?;
        assert_eq!(failed.status, PlatformRecoveryStatus::CleanupRequired);
        assert_eq!(failed.reason, Some(PlatformRecoveryReason::RollbackFailed));
        assert!(failed.operator_action_required());
        Ok(())
    }

    #[test]
    fn platform_recovery_rejects_inconsistent_helper_state() {
        assert!(PlatformRecoverySnapshot::from_helper_state(false, true, false).is_err());
        assert!(PlatformRecoverySnapshot::from_helper_state(false, false, true).is_err());
        assert!(PlatformRecoverySnapshot::from_helper_state(true, true, true).is_err());
    }

    #[test]
    fn shutdown_error_is_redacted_and_non_secret() {
        let err = already_shutdown();
        assert!(!err.to_string().contains("mv1_"));
    }
}
