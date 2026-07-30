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
    AuthChannelBindingConfig, AuthV2Config, ClientAdvancedConfig, ClientAuthConfig, ClientConfig,
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
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

pub const STORED_CLIENT_PROFILE_SCHEMA_VERSION: u16 = 1;
const INVALID_STORED_CLIENT_PROFILE_METADATA: &str = "invalid stored client profile metadata";

/// Compatibility state for stored client-profile metadata.
///
/// Checking this state never reads from or writes to a [`ProfileSecretStore`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredClientProfileCompatibility {
    /// The current stored schema's migration-required security fields are present
    /// and internally compatible.
    Current,
    /// A legacy flat profile needs a caller-selected channel-binding policy.
    LegacyNeedsExplicitChannelBindingMigration,
    /// A nonzero stored schema using the currently understood payload shape is
    /// not supported by this SDK.
    ///
    /// A future payload containing fields this SDK does not understand may be
    /// rejected during deserialization before this status can be reported.
    UnsupportedSchema { schema_version: u16 },
    /// The profile shape and its declared stored schema are inconsistent.
    Malformed,
}

/// Typed, privacy-safe reasons why an explicit legacy migration was rejected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredClientProfileMigrationError {
    /// The profile is already current and must not be migrated again.
    AlreadyCurrent,
    /// The profile schema is not supported for legacy migration.
    UnsupportedSchema { schema_version: u16 },
    /// The profile is not a valid legacy or current stored-profile shape.
    MalformedProfile,
    /// `require = true` cannot be combined with `enabled = false`.
    InvalidChannelBinding,
    /// Required channel binding is incompatible with the stored transport metadata.
    RequiredChannelBindingUnsupportedByStoredTransport,
}

impl std::fmt::Display for StoredClientProfileMigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyCurrent => formatter.write_str("stored client profile is already current"),
            Self::UnsupportedSchema { schema_version } => write!(
                formatter,
                "stored client profile schema {schema_version} is unsupported for migration"
            ),
            Self::MalformedProfile => {
                formatter.write_str("stored client profile metadata is malformed")
            }
            Self::InvalidChannelBinding => formatter
                .write_str("channel binding cannot be required when channel binding is disabled"),
            Self::RequiredChannelBindingUnsupportedByStoredTransport => formatter.write_str(
                "required channel binding is unsupported by the stored transport metadata",
            ),
        }
    }
}

impl std::error::Error for StoredClientProfileMigrationError {}

#[derive(Clone, Debug)]
pub struct StoredClientProfile {
    pub stored_profile_schema_version: u16,
    pub profile_name: String,
    pub version: u16,
    pub mode: Mode,
    pub local: LocalConfig,
    pub server: StoredClientServerProfile,
    pub auth: StoredClientAuthProfile,
    pub log: LogConfig,
    pub advanced: ClientAdvancedConfig,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClientProfileEnvelope {
    stored_profile_schema_version: u16,
    #[serde(deserialize_with = "deserialize_strict_stored_client_profile_payload")]
    profile: StoredClientProfilePayload,
}

#[derive(Serialize)]
struct StoredClientProfilePayload {
    profile_name: String,
    version: u16,
    mode: Mode,
    local: LocalConfig,
    server: StoredClientServerProfile,
    auth: StoredClientAuthProfile,
    log: LogConfig,
    advanced: ClientAdvancedConfig,
}

#[derive(Deserialize)]
struct StoredClientProfilePayloadWire {
    profile_name: String,
    version: u16,
    mode: Mode,
    local: LocalConfig,
    server: StoredClientServerProfile,
    auth: StoredClientAuthProfile,
    log: LogConfig,
    advanced: ClientAdvancedConfig,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredClientProfileRepresentation {
    Envelope(StoredClientProfileEnvelope),
    Legacy(
        #[serde(deserialize_with = "deserialize_strict_stored_client_profile_payload")]
        StoredClientProfilePayload,
    ),
}

impl Serialize for StoredClientProfile {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.stored_profile_schema_version != STORED_CLIENT_PROFILE_SCHEMA_VERSION {
            return Err(serde::ser::Error::custom(
                "only the current stored client profile schema can be serialized",
            ));
        }
        if self.auth.channel_binding.is_none() {
            return Err(serde::ser::Error::custom(
                "current stored client profile schema requires auth.channel_binding data",
            ));
        }
        if self.compatibility_status() != StoredClientProfileCompatibility::Current {
            return Err(serde::ser::Error::custom(
                INVALID_STORED_CLIENT_PROFILE_METADATA,
            ));
        }

        StoredClientProfileEnvelope {
            stored_profile_schema_version: self.stored_profile_schema_version,
            profile: StoredClientProfilePayload::from(self),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StoredClientProfile {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let representation =
            StoredClientProfileRepresentation::deserialize(deserializer).map_err(|_| {
                <D::Error as serde::de::Error>::custom(INVALID_STORED_CLIENT_PROFILE_METADATA)
            })?;
        let (stored_profile_schema_version, profile) = match representation {
            StoredClientProfileRepresentation::Envelope(envelope) => {
                if envelope.stored_profile_schema_version == 0 {
                    return Err(serde::de::Error::custom(
                        "stored client profile envelope cannot use legacy schema version 0",
                    ));
                }
                (envelope.stored_profile_schema_version, envelope.profile)
            }
            StoredClientProfileRepresentation::Legacy(profile) => (0, profile),
        };
        Ok(profile.into_stored_profile(stored_profile_schema_version))
    }
}

fn deserialize_strict_stored_client_profile_payload<'de, D>(
    deserializer: D,
) -> std::result::Result<StoredClientProfilePayload, D::Error>
where
    D: Deserializer<'de>,
{
    let mut found_unknown_key = false;
    let payload: StoredClientProfilePayloadWire = serde_ignored::deserialize(deserializer, |_| {
        found_unknown_key = true
    })
    .map_err(|_| <D::Error as serde::de::Error>::custom(INVALID_STORED_CLIENT_PROFILE_METADATA))?;
    if found_unknown_key {
        return Err(<D::Error as serde::de::Error>::custom(
            INVALID_STORED_CLIENT_PROFILE_METADATA,
        ));
    }
    Ok(payload.into())
}

impl From<StoredClientProfilePayloadWire> for StoredClientProfilePayload {
    fn from(payload: StoredClientProfilePayloadWire) -> Self {
        Self {
            profile_name: payload.profile_name,
            version: payload.version,
            mode: payload.mode,
            local: payload.local,
            server: payload.server,
            auth: payload.auth,
            log: payload.log,
            advanced: payload.advanced,
        }
    }
}

impl From<&StoredClientProfile> for StoredClientProfilePayload {
    fn from(profile: &StoredClientProfile) -> Self {
        Self {
            profile_name: profile.profile_name.clone(),
            version: profile.version,
            mode: profile.mode,
            local: profile.local.clone(),
            server: profile.server.clone(),
            auth: profile.auth.clone(),
            log: profile.log.clone(),
            advanced: profile.advanced.clone(),
        }
    }
}

impl StoredClientProfilePayload {
    fn into_stored_profile(self, stored_profile_schema_version: u16) -> StoredClientProfile {
        StoredClientProfile {
            stored_profile_schema_version,
            profile_name: self.profile_name,
            version: self.version,
            mode: self.mode,
            local: self.local,
            server: self.server,
            auth: self.auth,
            log: self.log,
            advanced: self.advanced,
        }
    }
}

impl StoredClientProfile {
    /// Reports this profile's stored-schema and migration compatibility.
    ///
    /// This method examines stored metadata only. It never accesses a secret
    /// store and never changes the profile. A [`StoredClientProfileCompatibility::Current`]
    /// result does not prove that the complete client configuration or referenced
    /// secrets are valid, or that a runtime connection will succeed. An
    /// [`StoredClientProfileCompatibility::UnsupportedSchema`] result is available
    /// only when the stored payload otherwise uses the fields understood by this
    /// SDK; future-only fields can be rejected during deserialization first.
    #[must_use]
    pub fn compatibility_status(&self) -> StoredClientProfileCompatibility {
        match self.stored_profile_schema_version {
            0 if self.auth.channel_binding.is_none() => {
                StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
            }
            0 => StoredClientProfileCompatibility::Malformed,
            STORED_CLIENT_PROFILE_SCHEMA_VERSION => match self.auth.channel_binding {
                Some(binding)
                    if (!binding.require || binding.enabled)
                        && !self
                            .required_channel_binding_unsupported_by_stored_transport(binding) =>
                {
                    StoredClientProfileCompatibility::Current
                }
                _ => StoredClientProfileCompatibility::Malformed,
            },
            schema_version => {
                StoredClientProfileCompatibility::UnsupportedSchema { schema_version }
            }
        }
    }

    /// Explicitly migrates a legacy flat profile represented by the published
    /// Beta.1 stored-profile schema to the current stored schema.
    ///
    /// The legacy channel-binding value cannot be inferred. Callers must:
    ///
    /// 1. Deserialize the stored profile.
    /// 2. Call [`Self::compatibility_status`].
    /// 3. Ask the user or caller to choose the complete channel-binding policy.
    /// 4. Pass that policy to this method.
    /// 5. Serialize the returned profile, which uses the versioned envelope.
    ///
    /// This method is transactional: it returns a migrated clone on success and
    /// leaves the input profile unchanged on failure. It never accesses a
    /// [`ProfileSecretStore`] and never supplies default security values. Every
    /// field represented by the current [`StoredClientProfile`] schema is
    /// preserved unchanged except for the caller-supplied channel binding and
    /// the stored schema version.
    pub fn migrate_legacy_with_channel_binding(
        &self,
        channel_binding: AuthChannelBindingConfig,
    ) -> std::result::Result<Self, StoredClientProfileMigrationError> {
        match self.compatibility_status() {
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration => {}
            StoredClientProfileCompatibility::Current => {
                return Err(StoredClientProfileMigrationError::AlreadyCurrent);
            }
            StoredClientProfileCompatibility::UnsupportedSchema { schema_version } => {
                return Err(StoredClientProfileMigrationError::UnsupportedSchema {
                    schema_version,
                });
            }
            StoredClientProfileCompatibility::Malformed => {
                return Err(StoredClientProfileMigrationError::MalformedProfile);
            }
        }

        if channel_binding.require && !channel_binding.enabled {
            return Err(StoredClientProfileMigrationError::InvalidChannelBinding);
        }
        if self.required_channel_binding_unsupported_by_stored_transport(channel_binding) {
            return Err(
                StoredClientProfileMigrationError::RequiredChannelBindingUnsupportedByStoredTransport,
            );
        }

        let mut migrated = self.clone();
        migrated.auth.channel_binding = Some(channel_binding);
        migrated.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION;
        Ok(migrated)
    }

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
            stored_profile_schema_version: STORED_CLIENT_PROFILE_SCHEMA_VERSION,
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
                channel_binding: Some(config.auth.channel_binding),
                v2: config.auth.v2.clone(),
                rotation,
            },
            log: config.log.clone(),
            advanced: config.advanced.clone(),
        })
    }

    pub fn to_client_config(&self, store: &impl ProfileSecretStore) -> Result<ClientConfig> {
        let channel_binding = match self.compatibility_status() {
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration => {
                anyhow::bail!(
                    "stored client profile uses the legacy schema and requires explicit \
                 channel-binding migration before materialization"
                )
            }
            StoredClientProfileCompatibility::Current => self
                .auth
                .channel_binding
                .expect("current compatibility requires channel-binding metadata"),
            StoredClientProfileCompatibility::UnsupportedSchema { schema_version } => {
                anyhow::bail!(
                "unsupported stored client profile schema version {schema_version}; supported version is \
                 {STORED_CLIENT_PROFILE_SCHEMA_VERSION}"
                )
            }
            StoredClientProfileCompatibility::Malformed => match self.auth.channel_binding {
                None if self.stored_profile_schema_version
                    == STORED_CLIENT_PROFILE_SCHEMA_VERSION =>
                {
                    anyhow::bail!(
                    "stored client profile schema {} is missing required auth.channel_binding data",
                    STORED_CLIENT_PROFILE_SCHEMA_VERSION
                    )
                }
                Some(binding) if binding.require && !binding.enabled => anyhow::bail!(
                    "stored client profile contains invalid auth.channel_binding data: \
                     channel binding cannot be required when channel binding is disabled"
                ),
                Some(binding)
                    if self.required_channel_binding_unsupported_by_stored_transport(binding) =>
                {
                    anyhow::bail!(
                        "stored client profile contains required channel binding that is \
                         unsupported by the stored transport metadata"
                    )
                }
                _ => anyhow::bail!("stored client profile metadata is malformed"),
            },
        };

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
                channel_binding,
                v2: self.auth.v2.clone(),
                rotation,
            },
            log: self.log.clone(),
            advanced: self.advanced.clone(),
        };
        config.validate().map_err(anyhow::Error::from)?;
        Ok(config)
    }

    fn required_channel_binding_unsupported_by_stored_transport(
        &self,
        channel_binding: AuthChannelBindingConfig,
    ) -> bool {
        channel_binding.require
            && (self.advanced.tls_terminating_fronting_enabled() || self.advanced.experimental_h3)
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
    #[serde(
        default,
        deserialize_with = "deserialize_optional_stored_channel_binding"
    )]
    pub channel_binding: Option<AuthChannelBindingConfig>,
    pub v2: AuthV2Config,
    pub rotation: StoredClientCredentialRotationProfile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictStoredChannelBindingConfig {
    enabled: bool,
    require: bool,
}

fn deserialize_optional_stored_channel_binding<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<AuthChannelBindingConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StrictStoredChannelBindingConfig>::deserialize(deserializer).map(|binding| {
        binding.map(|binding| AuthChannelBindingConfig {
            enabled: binding.enabled,
            require: binding.require,
        })
    })
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

    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Beta1StoredClientProfileReaderFixture {
        profile_name: String,
        version: u16,
        mode: Mode,
        local: LocalConfig,
        server: StoredClientServerProfile,
        auth: Beta1StoredClientAuthProfileReaderFixture,
        log: LogConfig,
        advanced: ClientAdvancedConfig,
    }

    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct Beta1StoredClientAuthProfileReaderFixture {
        v2: AuthV2Config,
        rotation: StoredClientCredentialRotationProfile,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct T003StoredClientProfileEnvelopeReaderFixture {
        stored_profile_schema_version: u16,
        profile: T003StoredClientProfilePayloadReaderFixture,
    }

    #[derive(Deserialize)]
    struct T003StoredClientProfilePayloadReaderFixture {
        profile_name: String,
        version: u16,
        mode: Mode,
        local: LocalConfig,
        server: StoredClientServerProfile,
        auth: StoredClientAuthProfile,
        log: LogConfig,
        advanced: ClientAdvancedConfig,
    }

    impl T003StoredClientProfilePayloadReaderFixture {
        fn into_stored_profile(self, stored_profile_schema_version: u16) -> StoredClientProfile {
            StoredClientProfile {
                stored_profile_schema_version,
                profile_name: self.profile_name,
                version: self.version,
                mode: self.mode,
                local: self.local,
                server: self.server,
                auth: self.auth,
                log: self.log,
                advanced: self.advanced,
            }
        }
    }

    struct PanicOnSecretReadStore;

    impl ProfileSecretStore for PanicOnSecretReadStore {
        fn put_secret(
            &mut self,
            _reference: &ProfileSecretRef,
            _secret: &SecretString,
        ) -> Result<()> {
            panic!("test secret store must not be written")
        }

        fn get_secret(&self, _reference: &ProfileSecretRef) -> Result<SecretString> {
            panic!("profile secret must not be read before stored schema validation")
        }

        fn delete_secret(&mut self, _reference: &ProfileSecretRef) -> Result<()> {
            panic!("test secret store must not be changed")
        }
    }

    #[derive(Default)]
    struct CountingWriter {
        calls: usize,
        bytes: usize,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            self.bytes += buffer.len();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.calls += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailingWriter {
        calls: usize,
    }

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            Err(std::io::Error::other("synthetic downstream writer failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const BETA1_STORED_CLIENT_PROFILE_FLAT_JSON: &str = r#"
{
  "profile_name": "example-profile",
  "version": 1,
  "mode": "auto",
  "local": {
    "socks5": {
      "listen": "127.0.0.1:1080"
    },
    "dns": {
      "enabled": false,
      "listen": "127.0.0.1:15353"
    },
    "http_connect": {
      "enabled": false,
      "listen": "127.0.0.1:18080"
    }
  },
  "server": {
    "address": "example.invalid:443",
    "server_name": "example.invalid",
    "tunnel_path": "/assets/upload",
    "credential_id": "u_example",
    "secret_ref": {
      "service": "maverick.client-profile",
      "account": "profile:example-profile:active"
    },
    "ca_cert": null,
    "cert_pin": null
  },
  "auth": {
    "v2": {
      "enabled": false,
      "require": false,
      "accepted_epochs": [2026073001]
    },
    "rotation": {
      "active_epoch": "2026073001",
      "next_credential_id": "u_example_next",
      "auto_switch": true,
      "next": {
        "id": "u_example_next",
        "secret_ref": {
          "service": "maverick.client-profile",
          "account": "profile:example-profile:next"
        },
        "not_before": "2026-08-01T00:00:00Z"
      }
    }
  },
  "log": {
    "level": "info",
    "redact": true
  },
  "advanced": {
    "connect_timeout_ms": 10000,
    "idle_timeout_secs": 300,
    "max_concurrent_flows": 256,
    "padding": "auto",
    "udp_idle_timeout_ms": 30000,
    "shaping": {
      "enabled": false,
      "max_padding_bytes_per_frame": 256,
      "max_overhead_ratio": 0.25,
      "max_delay_ms": 20,
      "max_batch_bytes": 65536,
      "cover_traffic": false,
      "cover_traffic_operator_approved": false,
      "cover_traffic_window_ms": 1000
    },
    "stealth": {
      "tls_fingerprint": "rustls_default",
      "active_probe_resistance": true,
      "cdn_fronting": {
        "enabled": false,
        "provider": "cloudflare",
        "carrier": "h2",
        "trusted_tls_terminating_provider": false
      }
    },
    "allow_non_loopback_listeners": false,
    "experimental_h3": false,
    "experimental_cloudflare_ws": false,
    "experimental_ech": false,
    "experimental_tun": false,
    "ech_fallback_policy": "fail_closed",
    "crypto": {
      "offered_suites": ["tls13"],
      "allow_experimental": false,
      "require_experimental": false
    }
  }
}
"#;

    fn legacy_stored_client_profile_flat_value() -> Result<serde_json::Value> {
        Ok(serde_json::from_str(BETA1_STORED_CLIENT_PROFILE_FLAT_JSON)?)
    }

    fn current_stored_client_profile_envelope_value() -> Result<serde_json::Value> {
        Ok(serde_json::from_str(
            &current_stored_client_profile_envelope_json(),
        )?)
    }

    fn current_stored_client_profile_envelope_json() -> String {
        let profile = BETA1_STORED_CLIENT_PROFILE_FLAT_JSON.replacen(
            "\"auth\": {",
            "\"auth\": {\n    \"channel_binding\": {\n      \"enabled\": true,\n      \"require\": false\n    },",
            1,
        );
        format!("{{\"stored_profile_schema_version\":1,\"profile\":{profile}}}")
    }

    fn current_stored_client_profile() -> Result<StoredClientProfile> {
        Ok(serde_json::from_str(
            &current_stored_client_profile_envelope_json(),
        )?)
    }

    fn required_channel_binding_profile() -> Result<StoredClientProfile> {
        let mut profile = current_stored_client_profile()?;
        profile.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: true,
            require: true,
        });
        Ok(profile)
    }

    fn assert_fixed_stored_profile_serialization_error(error: &serde_json::Error) {
        let rendered = error.to_string();
        assert_eq!(rendered, INVALID_STORED_CLIENT_PROFILE_METADATA);
        assert!(std::error::Error::source(error).is_none());
        assert!(rendered.chars().all(|character| !character.is_control()));
        assert!(rendered.len() <= 128);
    }

    fn assert_contradictory_stored_profile_serialization_rejected(
        case_name: &str,
        profile: &StoredClientProfile,
    ) {
        assert_eq!(
            profile.compatibility_status(),
            StoredClientProfileCompatibility::Malformed,
            "{case_name} fixture must exercise malformed stored metadata"
        );

        let string_result = serde_json::to_string(profile);
        let value_result = serde_json::to_value(profile);
        let mut writer = CountingWriter::default();
        assert_eq!(writer.calls, 0);
        assert_eq!(writer.bytes, 0);
        let writer_result = serde_json::to_writer(&mut writer, profile);

        assert!(
            string_result.is_err() && value_result.is_err() && writer_result.is_err(),
            "{case_name} serialized before the T005 gate: to_string_ok={}, \
             to_value_ok={}, to_writer_ok={}, writer_calls={}, writer_bytes={}",
            string_result.is_ok(),
            value_result.is_ok(),
            writer_result.is_ok(),
            writer.calls,
            writer.bytes
        );
        assert_eq!(
            writer.calls, 0,
            "{case_name} called the writer before rejecting malformed metadata"
        );
        assert_eq!(
            writer.bytes, 0,
            "{case_name} wrote bytes before rejecting malformed metadata"
        );
        assert_fixed_stored_profile_serialization_error(&string_result.unwrap_err());
        assert_fixed_stored_profile_serialization_error(&value_result.unwrap_err());
        assert_fixed_stored_profile_serialization_error(&writer_result.unwrap_err());
    }

    fn secret_store_for_stored_profile(
        profile: &StoredClientProfile,
    ) -> Result<InMemoryProfileSecretStore> {
        let mut store = InMemoryProfileSecretStore::new();
        store.put_secret(&profile.server.secret_ref, &SecretString::generate())?;
        if let Some(next) = &profile.auth.rotation.next {
            store.put_secret(&next.secret_ref, &SecretString::generate())?;
        }
        Ok(store)
    }

    fn assert_fixed_stored_profile_metadata_error(error: serde_json::Error) {
        let rendered = error.to_string();
        let suffix = rendered
            .strip_prefix(INVALID_STORED_CLIENT_PROFILE_METADATA)
            .unwrap_or_else(|| panic!("unexpected stored-profile error: {rendered}"));
        if !suffix.is_empty() {
            let location = suffix
                .strip_prefix(" at line ")
                .unwrap_or_else(|| panic!("unexpected stored-profile error suffix: {suffix}"));
            let (line, column) = location
                .split_once(" column ")
                .unwrap_or_else(|| panic!("unexpected stored-profile error location: {location}"));
            assert!(line.parse::<usize>().is_ok());
            assert!(column.parse::<usize>().is_ok());
        }
        assert!(rendered.chars().all(|character| !character.is_control()));
        assert!(rendered.len() <= 128);
    }

    fn assert_stored_profile_value_rejected(value: serde_json::Value) -> Result<()> {
        let json = serde_json::to_string(&value)?;
        let error = serde_json::from_str::<StoredClientProfile>(&json).unwrap_err();
        assert_fixed_stored_profile_metadata_error(error);
        Ok(())
    }

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
        config.auth.channel_binding = AuthChannelBindingConfig {
            enabled: true,
            require: true,
        };
        config.validate().map_err(anyhow::Error::from)?;

        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let serialized = serde_json::to_string(&profile)?;
        let rendered = format!("{profile:?} {serialized} {store:?}");
        assert!(!rendered.contains(&active_rendered));
        assert!(!rendered.contains(&next_rendered));
        assert!(serialized.contains("\"stored_profile_schema_version\":1"));
        assert!(serialized.contains("\"profile\":{\"profile_name\":\"primary\""));
        assert!(serialized.contains("\"channel_binding\":{\"enabled\":true,\"require\":true}"));
        assert!(serialized.contains("secret_ref"));
        assert!(!serialized.contains("\"secret\""));
        assert!(
            serde_json::from_str::<Beta1StoredClientProfileReaderFixture>(&serialized).is_err(),
            "the Beta.1 flat-profile reader must reject the versioned envelope"
        );

        let decoded: StoredClientProfile = serde_json::from_str(&serialized)?;
        let materialized = decoded.to_client_config(&store)?;
        assert!(materialized.auth.channel_binding.enabled);
        assert!(materialized.auth.channel_binding.require);
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
    fn stored_client_profile_preserves_disabled_channel_binding() -> Result<()> {
        let mut config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", SecretString::generate())
            .build()?;
        config.auth.channel_binding = AuthChannelBindingConfig {
            enabled: false,
            require: false,
        };
        config.validate().map_err(anyhow::Error::from)?;

        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let serialized = serde_json::to_string(&profile)?;
        let decoded: StoredClientProfile = serde_json::from_str(&serialized)?;
        let materialized = decoded.to_client_config(&store)?;

        assert!(!materialized.auth.channel_binding.enabled);
        assert!(!materialized.auth.channel_binding.require);
        Ok(())
    }

    #[test]
    fn legacy_stored_client_profile_requires_explicit_channel_binding_migration() -> Result<()> {
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", SecretString::generate())
            .build()?;
        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let envelope = serde_json::to_value(profile)?;
        let mut legacy = envelope["profile"].clone();
        legacy["auth"]
            .as_object_mut()
            .unwrap()
            .remove("channel_binding");

        let legacy: StoredClientProfile = serde_json::from_value(legacy)?;
        assert_eq!(legacy.stored_profile_schema_version, 0);
        assert!(legacy.auth.channel_binding.is_none());

        let err = legacy
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err.to_string().contains("legacy schema"));
        assert!(err.to_string().contains("explicit"));
        assert!(!err.to_string().contains("missing profile secret"));
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_schema_zero_envelope_but_migrates_flat_legacy() -> Result<()> {
        let legacy_flat = legacy_stored_client_profile_flat_value()?;
        let schema_zero_envelope = serde_json::json!({
            "stored_profile_schema_version": 0,
            "profile": legacy_flat.clone(),
        });

        let err = serde_json::from_value::<StoredClientProfile>(schema_zero_envelope).unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot use legacy schema version 0"));

        let legacy: StoredClientProfile = serde_json::from_value(legacy_flat)?;
        assert_eq!(
            legacy.compatibility_status(),
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
        );
        let migrated = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: true,
            require: true,
        })?;
        assert_eq!(
            migrated.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_malformed_current_channel_binding_json_strictly() -> Result<()>
    {
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", SecretString::generate())
            .build()?;
        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let envelope = serde_json::to_value(profile)?;
        let malformed_bindings = [
            ("missing enabled", serde_json::json!({"require": false})),
            ("missing require", serde_json::json!({"enabled": true})),
            (
                "misspelled require",
                serde_json::json!({"enabled": true, "requre": false}),
            ),
            (
                "unknown field",
                serde_json::json!({"enabled": true, "require": false, "extra": false}),
            ),
            ("empty object", serde_json::json!({})),
        ];

        for (case_name, malformed_binding) in malformed_bindings {
            let mut candidate = envelope.clone();
            candidate["profile"]["auth"]["channel_binding"] = malformed_binding;
            let json = serde_json::to_string(&candidate)?;
            assert!(
                serde_json::from_str::<StoredClientProfile>(&json).is_err(),
                "{case_name} unexpectedly passed strict stored-schema deserialization"
            );
        }
        Ok(())
    }

    #[test]
    fn current_stored_profile_rejects_unknown_auth_v2_typo() -> Result<()> {
        let mut current = current_stored_client_profile_envelope_value()?;
        current["profile"]["auth"]["v2"]
            .as_object_mut()
            .unwrap()
            .remove("enabled");
        current["profile"]["auth"]["v2"]["enabeld"] = serde_json::json!(true);
        let parent: T003StoredClientProfileEnvelopeReaderFixture =
            serde_json::from_value(current.clone())?;
        let parent_profile = parent
            .profile
            .into_stored_profile(parent.stored_profile_schema_version);
        assert_eq!(
            parent_profile.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        assert!(!parent_profile.auth.v2.enabled);
        let parent_config =
            parent_profile.to_client_config(&secret_store_for_stored_profile(&parent_profile)?)?;
        assert!(!parent_config.auth.v2.enabled);

        let json = serde_json::to_string(&current)?;

        match serde_json::from_str::<StoredClientProfile>(&json) {
            Err(error) => assert_fixed_stored_profile_metadata_error(error),
            Ok(profile) => {
                let _ = profile.to_client_config(&PanicOnSecretReadStore);
                panic!("current stored profile silently accepted auth.v2.enabeld");
            }
        }
        Ok(())
    }

    #[test]
    fn legacy_stored_profile_rejects_unknown_server_cert_pin_typo() -> Result<()> {
        let mut legacy = legacy_stored_client_profile_flat_value()?;
        legacy["server"].as_object_mut().unwrap().remove("cert_pin");
        legacy["server"]["cert_pni"] = serde_json::json!("sha256:synthetic");
        let parent: T003StoredClientProfilePayloadReaderFixture =
            serde_json::from_value(legacy.clone())?;
        let parent_profile = parent.into_stored_profile(0);
        assert!(parent_profile.server.cert_pin.is_none());
        let migrated =
            parent_profile.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
                enabled: false,
                require: false,
            })?;
        let parent_config =
            migrated.to_client_config(&secret_store_for_stored_profile(&migrated)?)?;
        assert!(parent_config.server.cert_pin.is_none());

        assert_stored_profile_value_rejected(legacy)?;
        Ok(())
    }

    #[test]
    fn stored_profiles_reject_unknown_keys_at_every_payload_mapping_node() -> Result<()> {
        let payload_mapping_nodes = [
            ("payload root", ""),
            ("local", "/local"),
            ("socks5", "/local/socks5"),
            ("dns", "/local/dns"),
            ("http connect", "/local/http_connect"),
            ("server", "/server"),
            ("secret ref", "/server/secret_ref"),
            ("auth", "/auth"),
            ("auth v2", "/auth/v2"),
            ("rotation", "/auth/rotation"),
            ("rotation next", "/auth/rotation/next"),
            ("rotation next secret ref", "/auth/rotation/next/secret_ref"),
            ("log", "/log"),
            ("advanced", "/advanced"),
            ("shaping", "/advanced/shaping"),
            ("stealth", "/advanced/stealth"),
            ("CDN fronting", "/advanced/stealth/cdn_fronting"),
            ("crypto", "/advanced/crypto"),
        ];
        let representations = [
            (
                "legacy",
                legacy_stored_client_profile_flat_value()?,
                String::new(),
            ),
            (
                "current",
                current_stored_client_profile_envelope_value()?,
                "/profile".to_owned(),
            ),
        ];

        for (representation, base, prefix) in representations {
            for (node_name, relative_pointer) in payload_mapping_nodes {
                let mut candidate = base.clone();
                let pointer = format!("{prefix}{relative_pointer}");
                candidate
                    .pointer_mut(&pointer)
                    .unwrap_or_else(|| {
                        panic!(
                            "{representation} fixture is missing mapping node {node_name} at {pointer}"
                        )
                    })
                    .as_object_mut()
                    .unwrap_or_else(|| {
                        panic!(
                            "{representation} fixture node {node_name} at {pointer} is not a mapping"
                        )
                    })
                    .insert("unknown_field".into(), serde_json::json!(true));
                assert_stored_profile_value_rejected(candidate)?;
            }
        }
        Ok(())
    }

    #[test]
    fn current_envelope_rejects_unknown_root_and_channel_binding_keys() -> Result<()> {
        let current = current_stored_client_profile_envelope_value()?;
        for pointer in ["", "/profile/auth/channel_binding"] {
            let mut candidate = current.clone();
            candidate
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown_field".into(), serde_json::json!(true));
            assert_stored_profile_value_rejected(candidate)?;
        }
        Ok(())
    }

    #[test]
    fn stored_profile_unknown_key_errors_are_fixed_bounded_and_private() -> Result<()> {
        let private_marker = "SYNTHETIC_PRIVATE_MARKER_DO_NOT_ECHO";
        let private_value = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_ECHO";
        let long_suffix = "L".repeat(4_096);
        let malicious_key = format!("{private_marker}\n\u{1b}[31m{long_suffix}");
        let representations = [
            (legacy_stored_client_profile_flat_value()?, "/auth/v2"),
            (
                current_stored_client_profile_envelope_value()?,
                "/profile/auth/v2",
            ),
        ];

        for (mut candidate, pointer) in representations {
            let mapping = candidate
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap();
            mapping.insert(
                malicious_key.clone(),
                serde_json::Value::String(private_value.into()),
            );
            for index in 0..512 {
                mapping.insert(
                    format!("SYNTHETIC_UNKNOWN_{index}"),
                    serde_json::json!(true),
                );
            }
            let json = serde_json::to_string(&candidate)?;
            let rendered = serde_json::from_str::<StoredClientProfile>(&json)
                .unwrap_err()
                .to_string();

            assert!(rendered.starts_with(INVALID_STORED_CLIENT_PROFILE_METADATA));
            assert!(!rendered.contains(private_marker));
            assert!(!rendered.contains(private_value));
            assert!(!rendered.contains(&long_suffix));
            assert!(!rendered.contains("SYNTHETIC_UNKNOWN"));
            assert!(rendered.chars().all(|character| !character.is_control()));
            assert!(rendered.len() <= 128);
        }
        Ok(())
    }

    #[test]
    fn stored_profile_parse_failures_use_fixed_private_error() -> Result<()> {
        let private_marker = "SYNTHETIC_INVALID_VALUE_DO_NOT_ECHO";
        let malicious_value = format!("{private_marker}\n\u{1b}[31m");
        let mut legacy = legacy_stored_client_profile_flat_value()?;
        legacy["mode"] = serde_json::Value::String(malicious_value.clone());
        let mut current = current_stored_client_profile_envelope_value()?;
        current["profile"]["mode"] = serde_json::Value::String(malicious_value.clone());

        for candidate in [legacy, current, serde_json::Value::String(malicious_value)] {
            let json = serde_json::to_string(&candidate)?;
            let rendered = serde_json::from_str::<StoredClientProfile>(&json)
                .unwrap_err()
                .to_string();
            assert!(rendered.starts_with(INVALID_STORED_CLIENT_PROFILE_METADATA));
            assert!(!rendered.contains(private_marker));
            assert!(rendered.chars().all(|character| !character.is_control()));
            assert!(rendered.len() <= 128);
        }
        Ok(())
    }

    #[test]
    fn stored_profiles_keep_known_duplicate_key_rejection() -> Result<()> {
        let legacy_root_duplicate = BETA1_STORED_CLIENT_PROFILE_FLAT_JSON.replacen(
            "\"profile_name\": \"example-profile\",",
            "\"profile_name\": \"example-profile\",\n  \"profile_name\": \"example-profile\",",
            1,
        );
        let current = current_stored_client_profile_envelope_json();
        let current_root_duplicate = current.replacen(
            "\"stored_profile_schema_version\":1",
            "\"stored_profile_schema_version\":1,\"stored_profile_schema_version\":1",
            1,
        );
        let legacy_deep_duplicate = BETA1_STORED_CLIENT_PROFILE_FLAT_JSON.replacen(
            "\"v2\": {\n      \"enabled\": false,",
            "\"v2\": {\n      \"enabled\": false,\n      \"enabled\": true,",
            1,
        );
        let current_deep_duplicate = current.replacen(
            "\"v2\": {\n      \"enabled\": false,",
            "\"v2\": {\n      \"enabled\": false,\n      \"enabled\": true,",
            1,
        );

        assert_ne!(legacy_root_duplicate, BETA1_STORED_CLIENT_PROFILE_FLAT_JSON);
        assert_ne!(current_root_duplicate, current);
        assert_ne!(legacy_deep_duplicate, BETA1_STORED_CLIENT_PROFILE_FLAT_JSON);
        assert_ne!(current_deep_duplicate, current);

        for candidate in [
            legacy_root_duplicate,
            current_root_duplicate,
            legacy_deep_duplicate,
            current_deep_duplicate,
        ] {
            assert_fixed_stored_profile_metadata_error(
                serde_json::from_str::<StoredClientProfile>(&candidate).unwrap_err(),
            );
        }
        Ok(())
    }

    #[test]
    fn direct_public_nested_stored_profile_serde_remains_permissive() -> Result<()> {
        let auth: StoredClientAuthProfile = serde_json::from_value(serde_json::json!({
            "channel_binding": {
                "enabled": true,
                "require": false
            },
            "v2": {
                "enabled": false,
                "require": false,
                "accepted_epochs": [],
                "enabeld": true
            },
            "rotation": {
                "active_epoch": null,
                "next_credential_id": null,
                "auto_switch": false,
                "next": null
            }
        }))?;
        assert!(!auth.v2.enabled);

        let server: StoredClientServerProfile = serde_json::from_value(serde_json::json!({
            "address": "example.invalid:443",
            "server_name": "example.invalid",
            "tunnel_path": "/assets/upload",
            "credential_id": "u_example",
            "secret_ref": {
                "service": "maverick.client-profile",
                "account": "profile:example-profile:active"
            },
            "ca_cert": null,
            "cert_pin": null,
            "cert_pni": "sha256:synthetic"
        }))?;
        assert!(server.cert_pin.is_none());
        Ok(())
    }

    #[test]
    fn current_stored_client_profile_rejects_missing_channel_binding() -> Result<()> {
        let config = client_config_builder()
            .local_socks5("127.0.0.1:0".parse()?)
            .server_address("127.0.0.1:443")
            .server_name("localhost")
            .credential("u_active", SecretString::generate())
            .build()?;
        let mut store = InMemoryProfileSecretStore::new();
        let profile = StoredClientProfile::store_from_config("primary", &config, &mut store)?;
        let mut current = serde_json::to_value(profile)?;
        current["profile"]["auth"]
            .as_object_mut()
            .unwrap()
            .remove("channel_binding");
        let current: StoredClientProfile = serde_json::from_value(current)?;
        assert_eq!(
            current.stored_profile_schema_version,
            STORED_CLIENT_PROFILE_SCHEMA_VERSION
        );
        assert!(current.auth.channel_binding.is_none());

        let err = current
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required auth.channel_binding data"));
        assert!(!err.to_string().contains("missing profile secret"));
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_unknown_schema() -> Result<()> {
        let mut unknown = current_stored_client_profile_envelope_value()?;
        unknown["stored_profile_schema_version"] =
            serde_json::json!(STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1);
        let unknown: StoredClientProfile = serde_json::from_value(unknown)?;
        assert_eq!(
            unknown.compatibility_status(),
            StoredClientProfileCompatibility::UnsupportedSchema {
                schema_version: STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1
            }
        );

        let err = unknown
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported stored client profile schema version"));
        assert!(!err.to_string().contains("missing profile secret"));
        Ok(())
    }

    #[test]
    fn stored_client_profile_reports_typed_compatibility_without_secret_store() -> Result<()> {
        let legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        assert_eq!(
            legacy.compatibility_status(),
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
        );

        let current = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: false,
            require: false,
        })?;
        assert_eq!(
            current.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );

        let mut unsupported = current.clone();
        unsupported.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1;
        assert_eq!(
            unsupported.compatibility_status(),
            StoredClientProfileCompatibility::UnsupportedSchema {
                schema_version: STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1
            }
        );

        let mut malformed = current;
        malformed.auth.channel_binding = None;
        assert_eq!(
            malformed.compatibility_status(),
            StoredClientProfileCompatibility::Malformed
        );

        let mut malformed_binding = unsupported;
        malformed_binding.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION;
        malformed_binding.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });
        assert_eq!(
            malformed_binding.compatibility_status(),
            StoredClientProfileCompatibility::Malformed
        );
        Ok(())
    }

    #[test]
    fn current_stored_profile_rejects_invalid_binding_before_secret_read() -> Result<()> {
        let legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        let mut current = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: false,
            require: false,
        })?;
        current.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });

        assert_eq!(
            current.compatibility_status(),
            StoredClientProfileCompatibility::Malformed
        );
        let err = current
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("channel binding cannot be required when channel binding is disabled"));
        assert!(!err.to_string().contains("missing profile secret"));
        Ok(())
    }

    #[test]
    fn contradictory_stored_profile_serialization_rejects_invalid_binding() -> Result<()> {
        let mut profile = current_stored_client_profile()?;
        profile.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });

        assert_contradictory_stored_profile_serialization_rejected(
            "disabled required channel binding",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn contradictory_stored_profile_serialization_rejects_required_binding_with_h3() -> Result<()> {
        let mut profile = required_channel_binding_profile()?;
        profile.advanced.experimental_h3 = true;

        assert_contradictory_stored_profile_serialization_rejected(
            "required channel binding with H3",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn contradictory_stored_profile_serialization_rejects_required_binding_with_legacy_cdn_flag(
    ) -> Result<()> {
        let mut profile = required_channel_binding_profile()?;
        profile.advanced.experimental_cloudflare_ws = true;

        assert_contradictory_stored_profile_serialization_rejected(
            "required channel binding with the legacy CDN flag",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn contradictory_stored_profile_serialization_rejects_required_binding_with_cdn_fronting(
    ) -> Result<()> {
        let mut profile = required_channel_binding_profile()?;
        profile.advanced.stealth.cdn_fronting.enabled = true;
        profile
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;

        assert_contradictory_stored_profile_serialization_rejected(
            "required channel binding with first-class CDN fronting",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn malformed_current_json_cannot_be_reserialized_as_a_current_envelope() -> Result<()> {
        let mut json = current_stored_client_profile_envelope_value()?;
        json["profile"]["auth"]["channel_binding"] = serde_json::json!({
            "enabled": false,
            "require": true,
        });
        let profile: StoredClientProfile = serde_json::from_value(json)?;

        assert_contradictory_stored_profile_serialization_rejected(
            "structurally complete malformed current JSON",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn contradictory_stored_profile_serialization_error_is_fixed_private_and_bounded() -> Result<()>
    {
        let private_marker = "SYNTHETIC_PRIVATE_SERIALIZATION_MARKER_DO_NOT_ECHO";
        let private_value = format!("{private_marker}\n\u{1b}[31m{}", "L".repeat(4_096));
        let mut profile = current_stored_client_profile()?;
        profile.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });
        profile.profile_name = private_value.clone();
        profile.server.address = format!("{private_value}:443");
        profile.server.server_name = private_value.clone();
        profile.server.secret_ref.service = private_value.clone();
        profile.server.secret_ref.account = private_value;

        let error = serde_json::to_string(&profile).unwrap_err();
        let rendered = error.to_string();
        assert_fixed_stored_profile_serialization_error(&error);
        assert!(!rendered.contains(private_marker));
        assert_contradictory_stored_profile_serialization_rejected(
            "malformed metadata containing private strings",
            &profile,
        );
        Ok(())
    }

    #[test]
    fn stored_profile_serialization_preserves_error_priority_and_text() -> Result<()> {
        let legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        let mut schema_two_missing = current_stored_client_profile()?;
        schema_two_missing.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1;
        schema_two_missing.auth.channel_binding = None;
        let mut schema_two_contradictory = schema_two_missing.clone();
        schema_two_contradictory.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });
        let mut current_missing = current_stored_client_profile()?;
        current_missing.auth.channel_binding = None;
        let mut current_contradictory = current_stored_client_profile()?;
        current_contradictory.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: false,
            require: true,
        });

        let cases = [
            (
                "legacy",
                legacy,
                "only the current stored client profile schema can be serialized",
            ),
            (
                "unsupported schema with missing binding",
                schema_two_missing,
                "only the current stored client profile schema can be serialized",
            ),
            (
                "unsupported schema with contradictory binding",
                schema_two_contradictory,
                "only the current stored client profile schema can be serialized",
            ),
            (
                "current schema with missing binding",
                current_missing,
                "current stored client profile schema requires auth.channel_binding data",
            ),
            (
                "current schema with contradictory binding",
                current_contradictory,
                INVALID_STORED_CLIENT_PROFILE_METADATA,
            ),
        ];

        for (case_name, profile, expected) in cases {
            assert_eq!(
                serde_json::to_string(&profile).unwrap_err().to_string(),
                expected,
                "{case_name} changed stored-profile serialization error priority"
            );
        }
        Ok(())
    }

    #[test]
    fn current_stored_profile_serialization_preserves_fixture_shape_and_order() -> Result<()> {
        let expected = current_stored_client_profile_envelope_value()?;
        let profile: StoredClientProfile = serde_json::from_value(expected.clone())?;
        assert_eq!(
            profile.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );

        let rendered = serde_json::to_string(&profile)?;
        assert!(
            rendered
                .starts_with("{\"stored_profile_schema_version\":1,\"profile\":{\"profile_name\":"),
            "stored-profile envelope and payload field order changed"
        );
        let actual: serde_json::Value = serde_json::from_str(&rendered)?;
        assert_eq!(actual, expected);
        let round_trip: StoredClientProfile = serde_json::from_value(actual)?;
        assert_eq!(
            round_trip.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        Ok(())
    }

    #[test]
    fn current_stored_profile_preserves_downstream_writer_errors() -> Result<()> {
        let profile = current_stored_client_profile()?;
        assert_eq!(
            profile.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        let mut writer = FailingWriter::default();
        let error = serde_json::to_writer(&mut writer, &profile).unwrap_err();

        assert_eq!(writer.calls, 1);
        assert!(error.is_io());
        assert_eq!(error.to_string(), "synthetic downstream writer failure");
        assert_ne!(error.to_string(), INVALID_STORED_CLIENT_PROFILE_METADATA);
        Ok(())
    }

    #[test]
    fn optional_binding_allows_h3_and_cdn_metadata_serialization() -> Result<()> {
        let mut profile = current_stored_client_profile()?;
        profile.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: true,
            require: false,
        });
        profile.advanced.experimental_h3 = true;
        profile.advanced.experimental_cloudflare_ws = true;
        profile.advanced.stealth.cdn_fronting.enabled = true;
        profile
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;

        assert_eq!(
            profile.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        let envelope = serde_json::to_value(&profile)?;
        assert_eq!(
            envelope["profile"]["auth"]["channel_binding"]["require"],
            serde_json::json!(false)
        );
        assert_eq!(
            envelope["profile"]["advanced"]["experimental_h3"],
            serde_json::json!(true)
        );
        assert_eq!(
            envelope["profile"]["advanced"]["experimental_cloudflare_ws"],
            serde_json::json!(true)
        );
        assert_eq!(
            envelope["profile"]["advanced"]["stealth"]["cdn_fronting"]["enabled"],
            serde_json::json!(true)
        );
        let round_trip: StoredClientProfile = serde_json::from_value(envelope)?;
        assert_eq!(
            round_trip.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_migrates_all_bindings_and_preserves_represented_fields() -> Result<()>
    {
        let legacy_flat = legacy_stored_client_profile_flat_value()?;
        let bindings = [
            AuthChannelBindingConfig {
                enabled: true,
                require: true,
            },
            AuthChannelBindingConfig {
                enabled: true,
                require: false,
            },
            AuthChannelBindingConfig {
                enabled: false,
                require: false,
            },
        ];

        for binding in bindings {
            let legacy: StoredClientProfile = serde_json::from_value(legacy_flat.clone())?;
            let migrated = legacy.migrate_legacy_with_channel_binding(binding)?;
            let envelope = serde_json::to_value(&migrated)?;

            let mut expected_payload = legacy_flat.clone();
            expected_payload["auth"]["channel_binding"] = serde_json::json!({
                "enabled": binding.enabled,
                "require": binding.require,
            });
            assert_eq!(
                envelope["stored_profile_schema_version"],
                serde_json::json!(STORED_CLIENT_PROFILE_SCHEMA_VERSION)
            );
            assert_eq!(envelope["profile"], expected_payload);

            let round_trip: StoredClientProfile = serde_json::from_value(envelope)?;
            assert_eq!(
                round_trip.compatibility_status(),
                StoredClientProfileCompatibility::Current
            );
            let round_trip_binding = round_trip.auth.channel_binding.unwrap();
            assert_eq!(round_trip_binding.enabled, binding.enabled);
            assert_eq!(round_trip_binding.require, binding.require);

            assert_eq!(
                legacy.compatibility_status(),
                StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
            );
            assert!(legacy.auth.channel_binding.is_none());
            assert_eq!(legacy.stored_profile_schema_version, 0);
        }
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_nonlegacy_migration_with_typed_errors() -> Result<()> {
        let legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        let binding = AuthChannelBindingConfig {
            enabled: true,
            require: true,
        };
        let current = legacy.migrate_legacy_with_channel_binding(binding)?;
        assert_eq!(
            current
                .migrate_legacy_with_channel_binding(binding)
                .unwrap_err(),
            StoredClientProfileMigrationError::AlreadyCurrent
        );

        let mut unsupported = current.clone();
        unsupported.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1;
        assert_eq!(
            unsupported
                .migrate_legacy_with_channel_binding(binding)
                .unwrap_err(),
            StoredClientProfileMigrationError::UnsupportedSchema {
                schema_version: STORED_CLIENT_PROFILE_SCHEMA_VERSION + 1
            }
        );

        let mut malformed = current;
        malformed.auth.channel_binding = None;
        assert_eq!(
            malformed
                .migrate_legacy_with_channel_binding(binding)
                .unwrap_err(),
            StoredClientProfileMigrationError::MalformedProfile
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_invalid_migration_without_partial_change() -> Result<()> {
        let legacy_flat = legacy_stored_client_profile_flat_value()?;
        let legacy: StoredClientProfile = serde_json::from_value(legacy_flat.clone())?;

        assert_eq!(
            legacy
                .migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
                    enabled: false,
                    require: true,
                })
                .unwrap_err(),
            StoredClientProfileMigrationError::InvalidChannelBinding
        );
        assert_eq!(
            legacy.compatibility_status(),
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
        );
        assert_eq!(legacy.stored_profile_schema_version, 0);
        assert!(legacy.auth.channel_binding.is_none());

        let mut unchanged = serde_json::to_value(StoredClientProfilePayload::from(&legacy))?;
        unchanged["auth"]
            .as_object_mut()
            .unwrap()
            .remove("channel_binding");
        assert_eq!(unchanged, legacy_flat);
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_required_binding_with_cdn_fronting() -> Result<()> {
        let mut legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        legacy.advanced.stealth.cdn_fronting.enabled = true;
        legacy
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        let before = serde_json::to_value(StoredClientProfilePayload::from(&legacy))?;

        assert_eq!(
            legacy
                .migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
                    enabled: true,
                    require: true,
                })
                .unwrap_err(),
            StoredClientProfileMigrationError::RequiredChannelBindingUnsupportedByStoredTransport
        );
        assert_eq!(
            legacy.compatibility_status(),
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
        );
        assert_eq!(
            serde_json::to_value(StoredClientProfilePayload::from(&legacy))?,
            before
        );

        let mut incompatible_current = legacy.clone();
        incompatible_current.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION;
        incompatible_current.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: true,
            require: true,
        });
        assert_eq!(
            incompatible_current.compatibility_status(),
            StoredClientProfileCompatibility::Malformed
        );
        let err = incompatible_current
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported by the stored transport metadata"));
        assert!(!err.to_string().contains("missing profile secret"));

        let migrated = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: false,
            require: false,
        })?;
        assert_eq!(
            migrated.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_rejects_required_binding_with_experimental_h3() -> Result<()> {
        let mut legacy: StoredClientProfile =
            serde_json::from_value(legacy_stored_client_profile_flat_value()?)?;
        legacy.advanced.experimental_h3 = true;
        let before = serde_json::to_value(StoredClientProfilePayload::from(&legacy))?;

        assert_eq!(
            legacy
                .migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
                    enabled: true,
                    require: true,
                })
                .unwrap_err(),
            StoredClientProfileMigrationError::RequiredChannelBindingUnsupportedByStoredTransport
        );
        assert_eq!(
            legacy.compatibility_status(),
            StoredClientProfileCompatibility::LegacyNeedsExplicitChannelBindingMigration
        );
        assert_eq!(
            serde_json::to_value(StoredClientProfilePayload::from(&legacy))?,
            before
        );

        let mut incompatible_current = legacy.clone();
        incompatible_current.stored_profile_schema_version = STORED_CLIENT_PROFILE_SCHEMA_VERSION;
        incompatible_current.auth.channel_binding = Some(AuthChannelBindingConfig {
            enabled: true,
            require: true,
        });
        assert_eq!(
            incompatible_current.compatibility_status(),
            StoredClientProfileCompatibility::Malformed
        );
        let err = incompatible_current
            .to_client_config(&PanicOnSecretReadStore)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported by the stored transport metadata"));
        assert!(!err.to_string().contains("missing profile secret"));

        let migrated = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: false,
            require: false,
        })?;
        assert_eq!(
            migrated.compatibility_status(),
            StoredClientProfileCompatibility::Current
        );
        Ok(())
    }

    #[test]
    fn stored_client_profile_beta1_fixture_accepts_legacy_and_rejects_envelope() -> Result<()> {
        let legacy_flat = legacy_stored_client_profile_flat_value()?;
        assert!(
            serde_json::from_value::<Beta1StoredClientProfileReaderFixture>(legacy_flat.clone())
                .is_ok(),
            "the Beta.1 fixture must accept a real legacy flat profile"
        );

        let legacy: StoredClientProfile = serde_json::from_value(legacy_flat)?;
        let migrated = legacy.migrate_legacy_with_channel_binding(AuthChannelBindingConfig {
            enabled: true,
            require: true,
        })?;
        let envelope = serde_json::to_value(migrated)?;
        assert!(
            serde_json::from_value::<Beta1StoredClientProfileReaderFixture>(envelope).is_err(),
            "the Beta.1 fixture must reject the current versioned envelope"
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
