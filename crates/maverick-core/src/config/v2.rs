//! Strict parser for the config-v2 five-axis policy schema.
//!
//! This module validates policy and can perform the narrow, policy-only
//! projection documented below. It does not define or migrate a complete,
//! runnable client or server config, serialize a projection to YAML, consume it
//! at runtime, expose secrets, inspect runtime state, or claim peer
//! confirmation.

use serde::de::IgnoredAny;
use serde::Deserialize;

use super::{config_version, ClientConfig, ConfigVersion, Mode};
use crate::{Error, Result};

const INVALID_DOCUMENT_MESSAGE: &str = "invalid config v2 policy document";
const UNSUPPORTED_VERSION_MESSAGE: &str = "unsupported config v2 policy version";
const INVALID_POLICY_MESSAGE: &str = "invalid config v2 policy";
const MISSING_POLICY_MESSAGE: &str = "missing required config v2 policy";
const POLICY_CONFLICT_MESSAGE: &str = "conflicting config v2 policy";
const UNAVAILABLE_CAPABILITY_MESSAGE: &str = "unavailable config v2 policy capability";

/// A validated config-v2 five-axis policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    security_posture: SecurityPosture,
    transport_strategy: TransportStrategy,
    trust_route: TrustRoute,
    name_privacy_minimum: NamePrivacyMinimum,
    traffic_shaping_policy: TrafficShapingPolicy,
}

impl Policy {
    /// Parses and validates one strict config-v2 policy YAML document.
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        match config_version(input).map_err(|_| rejection(PolicyRejection::InvalidDocument))? {
            ConfigVersion::V2 => {}
            ConfigVersion::V1 | ConfigVersion::Unsupported => {
                return Err(rejection(PolicyRejection::UnsupportedVersion));
            }
        }

        let wire = PolicyWire::deserialize(serde_yaml_ng::Deserializer::from_str(input))
            .map_err(|_| rejection(PolicyRejection::InvalidPolicy))?;
        validate_wire(wire).map_err(rejection)
    }

    /// Returns the policy-schema version validated by this type.
    pub const fn version(&self) -> u16 {
        2
    }

    /// Returns the requested security posture.
    pub const fn security_posture(&self) -> SecurityPosture {
        self.security_posture
    }

    /// Returns the requested transport strategy.
    pub const fn transport_strategy(&self) -> TransportStrategy {
        self.transport_strategy
    }

    /// Returns the requested trust route.
    pub const fn trust_route(&self) -> TrustRoute {
        self.trust_route
    }

    /// Returns the minimum requested name-privacy capability.
    pub const fn name_privacy_minimum(&self) -> NamePrivacyMinimum {
        self.name_privacy_minimum
    }

    /// Returns the requested traffic-shaping policy.
    pub const fn traffic_shaping_policy(&self) -> TrafficShapingPolicy {
        self.traffic_shaping_policy
    }
}

/// A validated policy-only projection of the first supported config-v1 client subset.
///
/// This value is not a complete or runnable config-v2 client. It does not
/// migrate endpoints, credentials, authentication selection, rotation, TUN or
/// listener settings, timeouts, TLS fingerprints, crypto settings, legacy
/// padding, shaping budgets, or any other runtime configuration. It also does
/// not prove that a server confirmed or selected the projected policy.
///
/// The legacy Mode remains separate compatibility metadata and never becomes a
/// sixth config-v2 policy axis.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V1ClientPolicyProjection {
    policy: Policy,
    legacy: LegacyModeCompatibility,
}

impl V1ClientPolicyProjection {
    /// Returns the projected five-axis config-v2 policy.
    pub const fn policy(&self) -> Policy {
        self.policy
    }

    /// Returns the source config-v1 Mode retained only for legacy compatibility.
    pub const fn legacy_mode(&self) -> Mode {
        self.legacy.mode
    }

    /// Reports whether a peer confirmed the retained legacy Mode.
    ///
    /// The first policy-only projection never claims peer confirmation.
    pub const fn legacy_mode_peer_confirmed(&self) -> bool {
        self.legacy.peer_confirmed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyModeCompatibility {
    mode: Mode,
    peer_confirmed: bool,
}

/// A privacy-safe reason why a config-v1 client cannot use the first projection.
///
/// Variants never contain configuration values or underlying validation
/// errors. Callers must not infer support for complete config migration from
/// the absence of a blocker.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V1ClientPolicyProjectionBlocker {
    /// The source did not pass the canonical config-v1 client validation rules.
    InvalidSourceConfig,
    /// Stable Mode is outside the first policy-only projection.
    StableMode,
    /// Private Mode is outside the first policy-only projection.
    PrivateMode,
    /// Compatibility-only legacy classification retained for downstream API
    /// shape. Canonical v1 validation now retires H3 first, so current callers
    /// receive [`Self::InvalidSourceConfig`] instead.
    H3Configured,
    /// A WebSocket carrier is outside the first policy-only projection.
    WebSocketConfigured,
    /// A TLS-terminating front is outside the first policy-only projection.
    TlsTerminatingFrontConfigured,
    /// Enabled traffic shaping is outside the first policy-only projection.
    EnabledTrafficShaping,
}

/// Projects the first supported config-v1 Auto/H2 client subset into v2 policy.
///
/// The function always validates `config` first. After successful validation,
/// blockers are checked in this fixed order: source Mode, configured
/// WebSocket, any TLS-terminating front, then enabled traffic shaping. Invalid
/// public-constructed configs, including retired v1 H3 intent, fail closed
/// before any narrower classification. The unreachable H3 branch is retained
/// only for public enum/source compatibility until the later removal slice.
///
/// Success requires local `Mode::Auto`, direct H2-only transport, plain SNI,
/// and disabled shaping. The returned transport strategy is explicit H2 rather
/// than Auto so later Auto expansion cannot change the preserved behavior.
/// Browser-mimic ECH GREASE is still plain SNI. Valid direct-H2 channel-binding
/// choices and valid fields outside the five policy axes do not block this
/// policy-only projection, but none of those fields are migrated.
pub fn project_v1_client_policy(
    config: &ClientConfig,
) -> std::result::Result<V1ClientPolicyProjection, V1ClientPolicyProjectionBlocker> {
    if config.validate().is_err() {
        return Err(V1ClientPolicyProjectionBlocker::InvalidSourceConfig);
    }

    match config.mode {
        Mode::Auto => {}
        Mode::Stable => return Err(V1ClientPolicyProjectionBlocker::StableMode),
        Mode::Private => return Err(V1ClientPolicyProjectionBlocker::PrivateMode),
    }
    if config.advanced.experimental_h3 {
        return Err(V1ClientPolicyProjectionBlocker::H3Configured);
    }
    if config.advanced.cloudflare_ws_enabled() {
        return Err(V1ClientPolicyProjectionBlocker::WebSocketConfigured);
    }
    if config.advanced.tls_terminating_fronting_enabled() {
        return Err(V1ClientPolicyProjectionBlocker::TlsTerminatingFrontConfigured);
    }
    if config.advanced.shaping.enabled {
        return Err(V1ClientPolicyProjectionBlocker::EnabledTrafficShaping);
    }

    Ok(V1ClientPolicyProjection {
        policy: Policy {
            security_posture: SecurityPosture::Standard,
            transport_strategy: TransportStrategy::H2,
            trust_route: TrustRoute::DirectToMaverick,
            name_privacy_minimum: NamePrivacyMinimum::PlainSni,
            traffic_shaping_policy: TrafficShapingPolicy::Disabled,
        },
        legacy: LegacyModeCompatibility {
            mode: Mode::Auto,
            peer_confirmed: false,
        },
    })
}

/// The local security floor requested by a v2 policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityPosture {
    Standard,
}

/// The outer-carrier selection strategy requested by a v2 policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportStrategy {
    Auto,
    H2,
}

/// Where client-facing TLS is requested to terminate.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustRoute {
    DirectToMaverick,
    TlsTerminatingFront(FrontDetails),
}

/// Validated details for a TLS-terminating front.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontDetails {
    provider: FrontProvider,
    trusted_tls_terminating_provider: bool,
}

impl FrontDetails {
    /// Returns the explicitly selected front provider.
    pub const fn provider(&self) -> FrontProvider {
        self.provider
    }

    /// Confirms that the persisted policy explicitly acknowledged front TLS termination.
    pub const fn trusted_tls_terminating_provider(&self) -> bool {
        self.trusted_tls_terminating_provider
    }
}

/// The explicitly selected TLS-terminating front provider.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontProvider {
    Cloudflare,
}

/// The minimum name-privacy capability requested by a v2 policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamePrivacyMinimum {
    PlainSni,
}

/// The traffic-shaping policy requested by a v2 policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficShapingPolicy {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRejection {
    InvalidDocument,
    UnsupportedVersion,
    InvalidPolicy,
    MissingRequiredPolicy,
    PolicyConflict,
    UnavailableCapability,
}

fn rejection(kind: PolicyRejection) -> Error {
    let message = match kind {
        PolicyRejection::InvalidDocument => INVALID_DOCUMENT_MESSAGE,
        PolicyRejection::UnsupportedVersion => UNSUPPORTED_VERSION_MESSAGE,
        PolicyRejection::InvalidPolicy => INVALID_POLICY_MESSAGE,
        PolicyRejection::MissingRequiredPolicy => MISSING_POLICY_MESSAGE,
        PolicyRejection::PolicyConflict => POLICY_CONFLICT_MESSAGE,
        PolicyRejection::UnavailableCapability => UNAVAILABLE_CAPABILITY_MESSAGE,
    };
    Error::Config(message.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    version: u16,
    #[serde(default, deserialize_with = "deserialize_presence")]
    mode: Presence,
    security: Option<SecurityWire>,
    transport: Option<TransportWire>,
    trust: Option<TrustWire>,
    name_privacy: Option<NamePrivacyWire>,
    traffic_shaping: Option<TrafficShapingWire>,
}

#[derive(Default)]
struct Presence(bool);

fn deserialize_presence<'de, D>(deserializer: D) -> std::result::Result<Presence, D::Error>
where
    D: serde::Deserializer<'de>,
{
    IgnoredAny::deserialize(deserializer)?;
    Ok(Presence(true))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityWire {
    posture: Option<SecurityPostureWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecurityPostureWire {
    Standard,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportWire {
    strategy: Option<TransportStrategyWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportStrategyWire {
    Auto,
    H2,
    H3,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustWire {
    route: Option<TrustRouteWire>,
    #[serde(default, deserialize_with = "deserialize_front")]
    front: FrontWireField,
}

#[derive(Default)]
enum FrontWireField {
    #[default]
    Absent,
    Present(FrontWire),
}

fn deserialize_front<'de, D>(deserializer: D) -> std::result::Result<FrontWireField, D::Error>
where
    D: serde::Deserializer<'de>,
{
    FrontWire::deserialize(deserializer).map(FrontWireField::Present)
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustRouteWire {
    DirectToMaverick,
    TlsTerminatingFront,
    FrontWithInnerE2e,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontWire {
    provider: Option<FrontProviderWire>,
    trusted_tls_terminating_provider: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FrontProviderWire {
    Cloudflare,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamePrivacyWire {
    minimum: Option<NamePrivacyMinimumWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamePrivacyMinimumWire {
    PlainSni,
    NativeEch,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficShapingWire {
    policy: Option<TrafficShapingPolicyWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrafficShapingPolicyWire {
    Disabled,
    #[serde(other)]
    Unknown,
}

fn validate_wire(wire: PolicyWire) -> std::result::Result<Policy, PolicyRejection> {
    debug_assert_eq!(wire.version, 2);
    if wire.mode.0 {
        return Err(PolicyRejection::PolicyConflict);
    }

    let security = wire
        .security
        .ok_or(PolicyRejection::MissingRequiredPolicy)?;
    let transport = wire
        .transport
        .ok_or(PolicyRejection::MissingRequiredPolicy)?;
    let trust = wire.trust.ok_or(PolicyRejection::MissingRequiredPolicy)?;
    let name_privacy = wire
        .name_privacy
        .ok_or(PolicyRejection::MissingRequiredPolicy)?;
    let traffic_shaping = wire
        .traffic_shaping
        .ok_or(PolicyRejection::MissingRequiredPolicy)?;

    let security_posture = match security
        .posture
        .ok_or(PolicyRejection::MissingRequiredPolicy)?
    {
        SecurityPostureWire::Standard => SecurityPosture::Standard,
        SecurityPostureWire::Unknown => return Err(PolicyRejection::InvalidPolicy),
    };
    let transport_strategy = match transport
        .strategy
        .ok_or(PolicyRejection::MissingRequiredPolicy)?
    {
        TransportStrategyWire::Auto => TransportStrategy::Auto,
        TransportStrategyWire::H2 => TransportStrategy::H2,
        TransportStrategyWire::H3 => return Err(PolicyRejection::UnavailableCapability),
        TransportStrategyWire::Unknown => return Err(PolicyRejection::InvalidPolicy),
    };
    let route = trust.route.ok_or(PolicyRejection::MissingRequiredPolicy)?;
    let name_privacy_minimum = match name_privacy
        .minimum
        .ok_or(PolicyRejection::MissingRequiredPolicy)?
    {
        NamePrivacyMinimumWire::PlainSni => NamePrivacyMinimum::PlainSni,
        NamePrivacyMinimumWire::NativeEch => {
            return Err(PolicyRejection::UnavailableCapability);
        }
        NamePrivacyMinimumWire::Unknown => return Err(PolicyRejection::InvalidPolicy),
    };
    let traffic_shaping_policy = match traffic_shaping
        .policy
        .ok_or(PolicyRejection::MissingRequiredPolicy)?
    {
        TrafficShapingPolicyWire::Disabled => TrafficShapingPolicy::Disabled,
        TrafficShapingPolicyWire::Unknown => return Err(PolicyRejection::InvalidPolicy),
    };

    let trust_route = match route {
        TrustRouteWire::DirectToMaverick => match trust.front {
            FrontWireField::Absent => TrustRoute::DirectToMaverick,
            FrontWireField::Present(_) => return Err(PolicyRejection::PolicyConflict),
        },
        TrustRouteWire::TlsTerminatingFront => {
            let FrontWireField::Present(front) = trust.front else {
                return Err(PolicyRejection::PolicyConflict);
            };
            let provider = match front.provider {
                Some(FrontProviderWire::Cloudflare) => FrontProvider::Cloudflare,
                Some(FrontProviderWire::Unknown) => {
                    return Err(PolicyRejection::InvalidPolicy);
                }
                None => return Err(PolicyRejection::PolicyConflict),
            };
            if front.trusted_tls_terminating_provider != Some(true) {
                return Err(PolicyRejection::PolicyConflict);
            }
            TrustRoute::TlsTerminatingFront(FrontDetails {
                provider,
                trusted_tls_terminating_provider: true,
            })
        }
        TrustRouteWire::FrontWithInnerE2e => {
            return Err(PolicyRejection::UnavailableCapability);
        }
        TrustRouteWire::Unknown => return Err(PolicyRejection::InvalidPolicy),
    };

    Ok(Policy {
        security_posture,
        transport_strategy,
        trust_route,
        name_privacy_minimum,
        traffic_shaping_policy,
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use super::*;
    use crate::config::{
        AuthChannelBindingConfig, CdnFrontingCarrier, SecretString, TlsFingerprintMode,
    };
    use crate::{ClientConfig, Error, Mode, ServerConfig};

    const INVALID_DOCUMENT: &str = "invalid config v2 policy document";
    const UNSUPPORTED_VERSION: &str = "unsupported config v2 policy version";
    const INVALID_POLICY: &str = "invalid config v2 policy";
    const MISSING_POLICY: &str = "missing required config v2 policy";
    const POLICY_CONFLICT: &str = "conflicting config v2 policy";
    const UNAVAILABLE_CAPABILITY: &str = "unavailable config v2 policy capability";
    const V1_SECRET: &str = "mv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PRIVATE_MARKER: &str = "SYNTHETIC_PRIVATE_MARKER_T010B";

    fn v1_client(mode: Option<&str>) -> ClientConfig {
        let mode = mode
            .map(|mode| format!("mode: {mode}\n"))
            .unwrap_or_default();
        ClientConfig::from_yaml_str(&format!(
            r#"version: 1
{mode}local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.invalid:443"
  server_name: "example.invalid"
  tunnel_path: "/tunnel"
  credential_id: "u_test"
  secret: "{V1_SECRET}"
"#
        ))
        .unwrap()
    }

    fn assert_auto_h2_projection(projection: &V1ClientPolicyProjection) {
        let policy = projection.policy();
        assert_eq!(policy.version(), 2);
        assert_eq!(policy.security_posture(), SecurityPosture::Standard);
        assert_eq!(policy.transport_strategy(), TransportStrategy::H2);
        assert_eq!(policy.trust_route(), TrustRoute::DirectToMaverick);
        assert_eq!(policy.name_privacy_minimum(), NamePrivacyMinimum::PlainSni);
        assert_eq!(
            policy.traffic_shaping_policy(),
            TrafficShapingPolicy::Disabled
        );
        assert_eq!(projection.legacy_mode(), Mode::Auto);
        assert_eq!(projection.legacy_mode().wire_id(), 0);
        assert!(!projection.legacy_mode_peer_confirmed());
    }

    fn direct_policy(strategy: &str) -> String {
        format!(
            r#"version: 2
security:
  posture: standard
transport:
  strategy: {strategy}
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
"#
        )
    }

    fn front_policy(strategy: &str) -> String {
        format!(
            r#"version: 2
security:
  posture: standard
transport:
  strategy: {strategy}
trust:
  route: tls_terminating_front
  front:
    provider: cloudflare
    trusted_tls_terminating_provider: true
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
"#
        )
    }

    fn assert_rejection(input: &str, expected: &str) {
        let error = Policy::from_yaml_str(input).unwrap_err();
        let rendered = error.to_string();
        let debug = format!("{error:?}");
        assert!(error.source().is_none());
        assert!(rendered.len() <= 128);
        assert!(debug.len() <= 160);
        assert!(rendered
            .chars()
            .chain(debug.chars())
            .all(|character| !character.is_control()));
        match error {
            Error::Config(message) => assert_eq!(message, expected),
            other => panic!("policy parser returned non-config error: {other:?}"),
        }
    }

    #[test]
    fn accepts_direct_and_front_with_auto_and_h2() {
        for strategy in ["auto", "h2"] {
            let direct = Policy::from_yaml_str(&direct_policy(strategy)).unwrap();
            assert_eq!(direct.version(), 2);
            assert_eq!(direct.security_posture(), SecurityPosture::Standard);
            assert_eq!(
                direct.transport_strategy(),
                if strategy == "auto" {
                    TransportStrategy::Auto
                } else {
                    TransportStrategy::H2
                }
            );
            assert_eq!(direct.trust_route(), TrustRoute::DirectToMaverick);
            assert_eq!(direct.name_privacy_minimum(), NamePrivacyMinimum::PlainSni);
            assert_eq!(
                direct.traffic_shaping_policy(),
                TrafficShapingPolicy::Disabled
            );

            let front = Policy::from_yaml_str(&front_policy(strategy)).unwrap();
            assert_eq!(front.version(), 2);
            assert_eq!(front.security_posture(), SecurityPosture::Standard);
            assert_eq!(
                front.transport_strategy(),
                if strategy == "auto" {
                    TransportStrategy::Auto
                } else {
                    TransportStrategy::H2
                }
            );
            match front.trust_route() {
                TrustRoute::TlsTerminatingFront(details) => {
                    assert_eq!(details.provider(), FrontProvider::Cloudflare);
                    assert!(details.trusted_tls_terminating_provider());
                }
                other => panic!("unexpected front route: {other:?}"),
            }
            assert_eq!(front.name_privacy_minimum(), NamePrivacyMinimum::PlainSni);
            assert_eq!(
                front.traffic_shaping_policy(),
                TrafficShapingPolicy::Disabled
            );
        }
    }

    #[test]
    fn rejects_each_missing_axis_and_nested_leaf() {
        let base = direct_policy("auto");
        let missing_axes = [
            base.replace("security:\n  posture: standard\n", ""),
            base.replace("transport:\n  strategy: auto\n", ""),
            base.replace("trust:\n  route: direct_to_maverick\n", ""),
            base.replace("name_privacy:\n  minimum: plain_sni\n", ""),
            base.replace("traffic_shaping:\n  policy: disabled\n", ""),
        ];
        for input in missing_axes {
            assert_rejection(&input, MISSING_POLICY);
        }

        let missing_leaves = [
            base.replace("  posture: standard\n", ""),
            base.replace("  strategy: auto\n", ""),
            base.replace("  route: direct_to_maverick\n", ""),
            base.replace("  minimum: plain_sni\n", ""),
            base.replace("  policy: disabled\n", ""),
        ];
        for input in missing_leaves {
            assert_rejection(&input, MISSING_POLICY);
        }
    }

    #[test]
    fn rejects_null_axes_and_nested_leaves() {
        let base = direct_policy("auto");
        let null_axes = [
            base.replace("security:\n  posture: standard", "security: null"),
            base.replace("transport:\n  strategy: auto", "transport: null"),
            base.replace("trust:\n  route: direct_to_maverick", "trust: null"),
            base.replace("name_privacy:\n  minimum: plain_sni", "name_privacy: null"),
            base.replace(
                "traffic_shaping:\n  policy: disabled",
                "traffic_shaping: null",
            ),
        ];
        for input in null_axes {
            assert_rejection(&input, MISSING_POLICY);
        }

        let null_leaves = [
            base.replace("posture: standard", "posture: null"),
            base.replace("strategy: auto", "strategy: null"),
            base.replace("route: direct_to_maverick", "route: null"),
            base.replace("minimum: plain_sni", "minimum: null"),
            base.replace("policy: disabled", "policy: null"),
        ];
        for input in null_leaves {
            assert_rejection(&input, MISSING_POLICY);
        }
    }

    #[test]
    fn rejects_unknown_keys_at_every_mapping_node() {
        let direct = direct_policy("auto");
        let front = front_policy("auto");
        let cases = [
            direct.replace("version: 2", "version: 2\nunknown_root: true"),
            direct.replace(
                "  posture: standard",
                "  posture: standard\n  unknown: true",
            ),
            direct.replace("  strategy: auto", "  strategy: auto\n  unknown: true"),
            direct.replace(
                "  route: direct_to_maverick",
                "  route: direct_to_maverick\n  unknown: true",
            ),
            front.replace(
                "    trusted_tls_terminating_provider: true",
                "    trusted_tls_terminating_provider: true\n    unknown: true",
            ),
            direct.replace(
                "  minimum: plain_sni",
                "  minimum: plain_sni\n  unknown: true",
            ),
            direct.replace("  policy: disabled", "  policy: disabled\n  unknown: true"),
        ];
        for input in cases {
            assert_rejection(&input, INVALID_POLICY);
        }
    }

    #[test]
    fn rejects_root_and_nested_duplicate_fields_from_raw_yaml() {
        let direct = direct_policy("auto");
        let front = front_policy("auto");
        let invalid_document = [direct.replace("version: 2", "version: 2\nversion: 2")];
        for input in invalid_document {
            assert_rejection(&input, INVALID_DOCUMENT);
        }

        let invalid_policy = [
            direct.replace(
                "security:\n  posture: standard",
                "security:\n  posture: standard\nsecurity:\n  posture: standard",
            ),
            direct.replace(
                "  posture: standard",
                "  posture: standard\n  posture: standard",
            ),
            direct.replace("  strategy: auto", "  strategy: auto\n  strategy: h2"),
            direct.replace(
                "  route: direct_to_maverick",
                "  route: direct_to_maverick\n  route: direct_to_maverick",
            ),
            front.replace(
                "    provider: cloudflare",
                "    provider: cloudflare\n    provider: cloudflare",
            ),
            front.replace(
                "    trusted_tls_terminating_provider: true",
                "    trusted_tls_terminating_provider: true\n    trusted_tls_terminating_provider: true",
            ),
            direct.replace(
                "version: 2",
                "version: 2\nmode: null\nmode: auto",
            ),
            direct.replace(
                "  minimum: plain_sni",
                "  minimum: plain_sni\n  minimum: plain_sni",
            ),
            direct.replace(
                "  policy: disabled",
                "  policy: disabled\n  policy: disabled",
            ),
        ];
        for input in invalid_policy {
            assert_rejection(&input, INVALID_POLICY);
        }
    }

    #[test]
    fn rejects_invalid_version_documents_and_unsupported_integer_versions() {
        let base = direct_policy("auto");
        let invalid = [
            base.replacen("version: 2\n", "", 1),
            base.replace("version: 2", "version: null"),
            base.replace("version: 2", "version: \"2\""),
            base.replace("version: 2", "version: 2.0"),
            format!("{base}---\n{base}"),
            "- version\n- 2\n".to_owned(),
        ];
        for input in invalid {
            assert_rejection(&input, INVALID_DOCUMENT);
        }

        for version in ["-1", "0", "1", "3", "65536"] {
            assert_rejection(
                &base.replace("version: 2", &format!("version: {version}")),
                UNSUPPORTED_VERSION,
            );
        }
    }

    #[test]
    fn rejects_legacy_mode_even_when_null() {
        let base = direct_policy("auto");
        for mode in ["auto", "stable", "private", "null"] {
            let input = base.replace("version: 2", &format!("version: 2\nmode: {mode}"));
            assert_rejection(&input, POLICY_CONFLICT);
        }
    }

    #[test]
    fn enforces_front_details_and_trust_acknowledgment() {
        let direct_with_front = direct_policy("auto").replace(
            "  route: direct_to_maverick",
            "  route: direct_to_maverick\n  front:\n    provider: cloudflare\n    trusted_tls_terminating_provider: true",
        );
        assert_rejection(&direct_with_front, POLICY_CONFLICT);

        let front = front_policy("auto");
        assert_rejection(
            &front.replace(
                "  front:\n    provider: cloudflare\n    trusted_tls_terminating_provider: true\n",
                "",
            ),
            POLICY_CONFLICT,
        );
        assert_rejection(
            &front.replace(
                "  front:\n    provider: cloudflare\n    trusted_tls_terminating_provider: true",
                "  front: null",
            ),
            INVALID_POLICY,
        );
        assert_rejection(
            &front.replace("    provider: cloudflare\n", ""),
            POLICY_CONFLICT,
        );
        assert_rejection(
            &front.replace("provider: cloudflare", "provider: null"),
            POLICY_CONFLICT,
        );
        assert_rejection(
            &front.replace("    trusted_tls_terminating_provider: true\n", ""),
            POLICY_CONFLICT,
        );
        assert_rejection(
            &front.replace(
                "trusted_tls_terminating_provider: true",
                "trusted_tls_terminating_provider: null",
            ),
            POLICY_CONFLICT,
        );
        assert_rejection(
            &front.replace(
                "trusted_tls_terminating_provider: true",
                "trusted_tls_terminating_provider: false",
            ),
            POLICY_CONFLICT,
        );
    }

    #[test]
    fn rejects_reserved_and_unknown_values_without_exposing_them() {
        let base = direct_policy("auto");
        let reserved = [
            base.replace("strategy: auto", "strategy: h3"),
            base.replace("minimum: plain_sni", "minimum: native_ech"),
            base.replace("route: direct_to_maverick", "route: front_with_inner_e2e"),
        ];
        for input in reserved {
            assert_rejection(&input, UNAVAILABLE_CAPABILITY);
        }

        let unknown = [
            base.replace("posture: standard", "posture: future_posture"),
            base.replace("strategy: auto", "strategy: web_socket"),
            base.replace("route: direct_to_maverick", "route: future_route"),
            base.replace("minimum: plain_sni", "minimum: future_privacy"),
            base.replace("policy: disabled", "policy: enabled"),
            front_policy("auto").replace("provider: cloudflare", "provider: future_provider"),
        ];
        for input in unknown {
            assert_rejection(&input, INVALID_POLICY);
        }
    }

    #[test]
    fn disabled_shaping_rejects_every_extra_field_as_unknown() {
        let base = direct_policy("auto");
        for field in ["budget: 1", "enabled: false", "max_delay_ms: 0"] {
            assert_rejection(
                &base.replace(
                    "  policy: disabled",
                    &format!("  policy: disabled\n  {field}"),
                ),
                INVALID_POLICY,
            );
        }
    }

    #[test]
    fn errors_are_fixed_bounded_private_and_source_free() {
        let private_marker = ["SYNTHETIC_", "PRIVATE_MARKER_", "DO_NOT_ECHO"].concat();
        let private_value = ["SYNTHETIC_", "PRIVATE_VALUE_", "DO_NOT_ECHO"].concat();
        let long_suffix = "L".repeat(4_096);
        let malformed_key = format!("{private_marker}\\n\\u001b[31m{long_suffix}");
        let malformed_input = direct_policy("auto").replace(
            "  posture: standard",
            &format!("  posture: standard\n  \"{malformed_key}\": \"{private_value}\""),
        );
        let strict_input = direct_policy("auto").replace(
            "  posture: standard",
            &format!("  posture: standard\n  \"{private_marker}\": \"{private_value}\""),
        );

        for (input, expected) in [
            (malformed_input, INVALID_DOCUMENT),
            (strict_input, INVALID_POLICY),
        ] {
            let error = Policy::from_yaml_str(&input).unwrap_err();
            let rendered = error.to_string();
            let debug = format!("{error:?}");
            assert!(error.source().is_none());
            for forbidden in [
                private_marker.as_str(),
                private_value.as_str(),
                long_suffix.as_str(),
            ] {
                assert!(!rendered.contains(forbidden));
                assert!(!debug.contains(forbidden));
            }
            assert!(rendered.len() <= 128);
            assert!(debug.len() <= 160);
            assert!(rendered
                .chars()
                .chain(debug.chars())
                .all(|character| !character.is_control()));
            match error {
                Error::Config(message) => assert_eq!(message, expected),
                other => panic!("policy parser returned non-config error: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_full_config_fields_at_policy_root() {
        let base = direct_policy("auto");
        for field in ["local", "server", "auth", "secret", "runtime"] {
            let input = format!("{base}{field}:\n  private_marker: true\n");
            assert_rejection(&input, INVALID_POLICY);
        }
    }

    #[test]
    fn canonical_v1_readers_continue_to_reject_v2_policy() {
        let input = direct_policy("auto");
        assert_eq!(
            ClientConfig::from_yaml_str(&input).unwrap_err().to_string(),
            "configuration error: unsupported configuration version"
        );
        assert_eq!(
            ServerConfig::from_yaml_str(&input).unwrap_err().to_string(),
            "configuration error: unsupported configuration version"
        );
    }

    #[test]
    fn projects_omitted_and_explicit_auto_as_h2_policy() {
        let omitted = project_v1_client_policy(&v1_client(None)).unwrap();
        let explicit = project_v1_client_policy(&v1_client(Some("auto"))).unwrap();
        assert_auto_h2_projection(&omitted);
        assert_auto_h2_projection(&explicit);
        assert_eq!(omitted, explicit);
    }

    #[test]
    fn projects_all_direct_h2_channel_binding_modes() {
        for channel_binding in [
            AuthChannelBindingConfig {
                enabled: false,
                require: false,
            },
            AuthChannelBindingConfig {
                enabled: true,
                require: false,
            },
            AuthChannelBindingConfig {
                enabled: true,
                require: true,
            },
        ] {
            let mut config = v1_client(Some("auto"));
            config.auth.channel_binding = channel_binding;
            config.validate().unwrap();
            assert_auto_h2_projection(&project_v1_client_policy(&config).unwrap());
        }
    }

    #[test]
    fn projects_disabled_shaping_with_nondefault_budgets() {
        let mut config = v1_client(Some("auto"));
        config.advanced.shaping.max_padding_bytes_per_frame = 7;
        config.advanced.shaping.max_overhead_ratio = 0.5;
        config.advanced.shaping.max_delay_ms = 999;
        config.advanced.shaping.max_batch_bytes = 17;
        config.advanced.shaping.cover_traffic_window_ms = 42;
        config.advanced.padding = "legacy-policy-value".into();
        config.validate().unwrap();
        assert_auto_h2_projection(&project_v1_client_policy(&config).unwrap());
    }

    #[test]
    fn rejects_retired_h3_as_invalid_source_before_projection_blockers() {
        let mut stable = v1_client(Some("stable"));
        stable.advanced.experimental_h3 = true;
        assert_eq!(
            stable.validate().unwrap_err().to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
        assert_eq!(
            project_v1_client_policy(&stable),
            Err(V1ClientPolicyProjectionBlocker::InvalidSourceConfig)
        );

        let mut h3 = v1_client(Some("auto"));
        h3.advanced.experimental_h3 = true;
        h3.advanced.shaping.enabled = true;
        assert_eq!(
            h3.validate().unwrap_err().to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
        assert_eq!(
            project_v1_client_policy(&h3),
            Err(V1ClientPolicyProjectionBlocker::InvalidSourceConfig)
        );
    }

    #[test]
    fn rejects_modes_and_transport_or_shaping_blockers_in_fixed_order() {
        let mut websocket = v1_client(Some("auto"));
        websocket.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        websocket.advanced.stealth.cdn_fronting.enabled = true;
        websocket.advanced.stealth.cdn_fronting.carrier = CdnFrontingCarrier::WebSocket;
        websocket
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        websocket.advanced.shaping.enabled = true;
        websocket.validate().unwrap();
        assert_eq!(
            project_v1_client_policy(&websocket),
            Err(V1ClientPolicyProjectionBlocker::WebSocketConfigured)
        );

        let mut fronted_h2 = v1_client(Some("auto"));
        fronted_h2.advanced.stealth.cdn_fronting.enabled = true;
        fronted_h2.advanced.stealth.cdn_fronting.carrier = CdnFrontingCarrier::H2;
        fronted_h2
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        fronted_h2.advanced.shaping.enabled = true;
        fronted_h2.validate().unwrap();
        assert_eq!(
            project_v1_client_policy(&fronted_h2),
            Err(V1ClientPolicyProjectionBlocker::TlsTerminatingFrontConfigured)
        );

        let mut shaping = v1_client(Some("auto"));
        shaping.advanced.shaping.enabled = true;
        shaping.validate().unwrap();
        assert_eq!(
            project_v1_client_policy(&shaping),
            Err(V1ClientPolicyProjectionBlocker::EnabledTrafficShaping)
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
    fn rejects_valid_private_mode() {
        let mut private = v1_client(Some("auto"));
        private.mode = Mode::Private;
        private.validate().unwrap();
        assert_eq!(
            project_v1_client_policy(&private),
            Err(V1ClientPolicyProjectionBlocker::PrivateMode)
        );
    }

    #[cfg(not(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    )))]
    #[test]
    fn invalid_private_mode_fails_before_mode_classification() {
        let mut private = v1_client(Some("auto"));
        private.mode = Mode::Private;
        assert!(private.validate().is_err());
        assert_eq!(
            project_v1_client_policy(&private),
            Err(V1ClientPolicyProjectionBlocker::InvalidSourceConfig)
        );
    }

    #[test]
    fn invalid_source_and_success_debug_never_copy_private_values() {
        let encoded_secret =
            URL_SAFE_NO_PAD.encode(format!("{PRIVATE_MARKER}{PRIVATE_MARKER}").as_bytes());
        let mut config = v1_client(Some("auto"));
        config.server.address = format!("{PRIVATE_MARKER}:443");
        config.server.server_name = PRIVATE_MARKER.into();
        config.server.tunnel_path = format!("/{PRIVATE_MARKER}");
        config.server.credential_id = PRIVATE_MARKER.into();
        config.server.secret =
            SecretString::new(format!("{}{}", SecretString::PREFIX, encoded_secret)).unwrap();
        config.validate().unwrap();

        let projection = project_v1_client_policy(&config).unwrap();
        assert_auto_h2_projection(&projection);
        assert!(!format!("{projection:?}").contains(PRIVATE_MARKER));

        config.version = 2;
        let blocker = project_v1_client_policy(&config).unwrap_err();
        assert_eq!(
            blocker,
            V1ClientPolicyProjectionBlocker::InvalidSourceConfig
        );
        assert!(!format!("{blocker:?}").contains(PRIVATE_MARKER));
    }
}
