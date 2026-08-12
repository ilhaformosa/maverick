//! Executable oracle for behavior derivable from an already validated v1 config.
//!
//! Parsing has already collapsed omitted fields and explicit defaults, so this
//! module cannot recover source syntax or field presence. It deliberately does
//! not read the network, secrets, the clock, cooldown state, or the environment,
//! and it is not a runtime diagnostics surface. Config-v1 H3 is retired, so
//! `experimental_h3=true` cannot satisfy this evaluator's validated-input
//! precondition, and no retired Quinn build or fallback shape remains here.

use maverick_core::config::{CdnFrontingCarrier, CdnFrontingProvider};
use maverick_core::frame::FRAME_HEADER_LEN;
use maverick_core::{ClientConfig, Mode, ServerConfig, TlsFingerprintMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingBlocker {
    UnsupportedV2Carrier,
    MixedTrustRoutesNotRepresentable,
    EnabledShapingPolicyUnfrozen,
    LegacyModeCompatibilityUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLegacyMode {
    pub client_hello_mode: Mode,
    pub wire_id: u8,
    pub peer_confirmed_session_mode: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerLegacyMode {
    pub local_mode_default: Mode,
    pub wire_id: u8,
    pub client_mode_compared_or_stored: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCarrier {
    H2Only,
    FrontedH2,
    FrontedWebSocket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCarrierPolicy {
    pub candidate_selection_policy: ClientCarrier,
    pub h3_configured: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerCarrierPolicy {
    pub h2_entry_enabled: bool,
    pub websocket_entry_enabled: bool,
    pub h3_configured: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustRoute {
    DirectToMaverick,
    TlsTerminatingFront {
        provider: CdnFrontingProvider,
        carrier: CdnFrontingCarrier,
        trusted_tls_terminating_provider: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalTrustRoute {
    pub configured_assumption: TrustRoute,
    pub network_topology_proven: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Carrier {
    H2,
    WebSocket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsBackend {
    Rustls,
    BrowserMimic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamePrivacy {
    ClientPlainSni { ech_grease: bool },
    ServerNotDerivable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelBindingCandidate {
    DisabledByPolicy,
    UnavailableForCarrierOrFrontConfiguration,
    TlsExporterCandidate,
    TlsExporterRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSecurity {
    pub carrier: Carrier,
    pub trust_route: LocalTrustRoute,
    pub tls_backend: TlsBackend,
    pub name_privacy: NamePrivacy,
    pub channel_binding: ChannelBindingCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfiguredChannelBinding {
    Disabled,
    Opportunistic,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthProtocol {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCredentialSelection {
    ConfiguredActiveWithoutClock,
    ClockDependentAndNotSelected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAuthBehavior {
    pub sends: ClientAuthProtocol,
    pub channel_binding: ConfiguredChannelBinding,
    pub credential_selection: ClientCredentialSelection,
    pub mode_wire_byte_authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerAuthProtocol {
    AcceptV1,
    RequireV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerAuthBehavior {
    pub accepts: ServerAuthProtocol,
    pub channel_binding: ConfiguredChannelBinding,
    pub rotated_credential_acceptance_needs_clock: bool,
    pub client_mode_wire_byte_authenticated: bool,
    pub client_mode_compared_or_stored: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShapingBounds {
    pub max_padding_bytes_per_frame: u16,
    pub max_overhead_ratio: f64,
    pub max_delay_ms: u64,
    pub max_batch_bytes: u32,
    pub cover_traffic_window_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegularPadding {
    Disabled,
    AutoWithAdditional64ByteCap,
    PrivateWithConfiguredBounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPaddingField {
    RuntimeInert,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverTraffic {
    pub configured: bool,
    pub operator_approved: bool,
    pub allowed_by_mode_config_and_approval: bool,
    pub budget_eligibility: CoverBudgetEligibility,
    pub payload_coupled: bool,
    pub max_frames_per_eligible_send: u8,
    pub window_participates_when_plan_exists: bool,
    pub cross_call_window_throttling_enforced: bool,
    pub overhead_budget_independent_from_regular_padding: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverBudgetEligibility {
    DisabledByModeOrConfigOrApproval,
    BudgetAlwaysUnavailable,
    ConditionalOnEligiblePayloadAndPositiveRoundedBudget,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShapingFacts {
    pub configured_enabled: bool,
    pub effective_enabled: bool,
    pub bounds: ShapingBounds,
    pub regular_padding: RegularPadding,
    pub cover: CoverTraffic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameSizeBound {
    ClientNegotiatedAtRuntime,
    ServerConfigured(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientBatching {
    Disabled,
    NoEligibleFrame {
        max_batch_bytes: u32,
        frame_header_bytes: usize,
    },
    EligibleFramesUseSingleSendCallDelayThenFlush {
        max_delay_ms: u64,
        max_batch_bytes: u32,
        cross_call_batching: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClientShapingBehavior {
    pub facts: ShapingFacts,
    pub batching: ClientBatching,
    pub frame_size_bound: FrameSizeBound,
    pub legacy_advanced_padding: LegacyPaddingField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerBatching {
    pub batcher_present: bool,
    pub configured_max_delay_runtime_inert: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServerShapingBehavior {
    pub facts: ShapingFacts,
    pub batching: ServerBatching,
    pub frame_size_bound: FrameSizeBound,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientV1Behavior {
    pub mode: ClientLegacyMode,
    pub carrier: ClientCarrierPolicy,
    pub carrier_security: Vec<CarrierSecurity>,
    pub auth: ClientAuthBehavior,
    pub shaping: ClientShapingBehavior,
    pub blockers: Vec<MappingBlocker>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerV1Behavior {
    pub mode: ServerLegacyMode,
    pub carrier: ServerCarrierPolicy,
    pub carrier_security: Vec<CarrierSecurity>,
    pub auth: ServerAuthBehavior,
    pub shaping: ServerShapingBehavior,
    pub blockers: Vec<MappingBlocker>,
}

/// Evaluates a `ClientConfig` that has already passed `ClientConfig::validate`.
pub fn evaluate_client(config: &ClientConfig) -> ClientV1Behavior {
    let fronted = config.advanced.tls_terminating_fronting_enabled();
    let h3_configured = config.advanced.experimental_h3;
    let carrier = if config.advanced.cloudflare_ws_enabled() {
        ClientCarrier::FrontedWebSocket
    } else if config.advanced.cdn_fronted_h2_enabled() {
        ClientCarrier::FrontedH2
    } else {
        ClientCarrier::H2Only
    };
    let channel_binding = configured_channel_binding(
        config.auth.channel_binding.enabled,
        config.auth.channel_binding.require,
    );
    let configured_trust_route = trust_route(
        fronted,
        config.advanced.stealth.cdn_fronting.provider,
        config.advanced.stealth.cdn_fronting.carrier,
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider,
    );
    let carrier_security = match carrier {
        ClientCarrier::H2Only | ClientCarrier::FrontedH2 => vec![client_carrier_security(
            Carrier::H2,
            configured_trust_route,
            config.advanced.stealth.tls_fingerprint,
            channel_binding,
        )],
        ClientCarrier::FrontedWebSocket => vec![client_carrier_security(
            Carrier::WebSocket,
            configured_trust_route,
            TlsFingerprintMode::RustlsDefault,
            channel_binding,
        )],
    };
    let shaping = client_shaping(config);
    let mut blockers = Vec::new();
    if h3_configured || config.advanced.cloudflare_ws_enabled() {
        blockers.push(MappingBlocker::UnsupportedV2Carrier);
    }
    if shaping.facts.effective_enabled {
        blockers.push(MappingBlocker::EnabledShapingPolicyUnfrozen);
    }
    if config.mode != Mode::Auto {
        blockers.push(MappingBlocker::LegacyModeCompatibilityUnresolved);
    }

    ClientV1Behavior {
        mode: ClientLegacyMode {
            client_hello_mode: config.mode,
            wire_id: config.mode.wire_id(),
            peer_confirmed_session_mode: false,
        },
        carrier: ClientCarrierPolicy {
            candidate_selection_policy: carrier,
            h3_configured,
        },
        carrier_security,
        auth: ClientAuthBehavior {
            sends: if config.auth.v2.enabled {
                ClientAuthProtocol::V2
            } else {
                ClientAuthProtocol::V1
            },
            channel_binding,
            credential_selection: if config.auth.rotation.auto_switch {
                ClientCredentialSelection::ClockDependentAndNotSelected
            } else {
                ClientCredentialSelection::ConfiguredActiveWithoutClock
            },
            mode_wire_byte_authenticated: true,
        },
        shaping,
        blockers,
    }
}

/// Evaluates a `ServerConfig` that has already passed `ServerConfig::validate`.
pub fn evaluate_server(config: &ServerConfig) -> ServerV1Behavior {
    let front_configuration_disables_binding = config.advanced.tls_terminating_fronting_enabled();
    let websocket_entry_enabled = config.advanced.cloudflare_ws_enabled();
    let h3_configured = config.advanced.experimental_h3;
    let channel_binding = configured_channel_binding(
        config.auth.channel_binding.enabled,
        config.auth.channel_binding.require,
    );
    let direct_trust_route = trust_route(
        false,
        config.advanced.stealth.cdn_fronting.provider,
        config.advanced.stealth.cdn_fronting.carrier,
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider,
    );
    let front_trust_route = trust_route(
        true,
        config.advanced.stealth.cdn_fronting.provider,
        config.advanced.stealth.cdn_fronting.carrier,
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider,
    );
    let h2_trust_route = if config.advanced.cdn_fronted_h2_enabled() {
        front_trust_route
    } else {
        direct_trust_route
    };
    let mut carrier_security = vec![server_carrier_security(
        Carrier::H2,
        h2_trust_route,
        front_configuration_disables_binding,
        channel_binding,
    )];
    if websocket_entry_enabled {
        carrier_security.push(server_carrier_security(
            Carrier::WebSocket,
            front_trust_route,
            front_configuration_disables_binding,
            channel_binding,
        ));
    }
    let shaping = server_shaping(config);
    let mut blockers = Vec::new();
    if h3_configured || websocket_entry_enabled {
        blockers.push(MappingBlocker::UnsupportedV2Carrier);
    }
    let has_direct_route = carrier_security
        .iter()
        .any(|security| security.trust_route.configured_assumption == TrustRoute::DirectToMaverick);
    let has_front_route = carrier_security.iter().any(|security| {
        matches!(
            security.trust_route.configured_assumption,
            TrustRoute::TlsTerminatingFront { .. }
        )
    });
    if has_direct_route && has_front_route {
        blockers.push(MappingBlocker::MixedTrustRoutesNotRepresentable);
    }
    if shaping.facts.effective_enabled {
        blockers.push(MappingBlocker::EnabledShapingPolicyUnfrozen);
    }
    blockers.push(MappingBlocker::LegacyModeCompatibilityUnresolved);

    ServerV1Behavior {
        mode: ServerLegacyMode {
            local_mode_default: config.maverick.mode_default,
            wire_id: config.maverick.mode_default.wire_id(),
            client_mode_compared_or_stored: false,
        },
        carrier: ServerCarrierPolicy {
            h2_entry_enabled: true,
            websocket_entry_enabled,
            h3_configured,
        },
        carrier_security,
        auth: ServerAuthBehavior {
            accepts: if config.auth.v2.enabled {
                ServerAuthProtocol::RequireV2
            } else {
                ServerAuthProtocol::AcceptV1
            },
            channel_binding,
            rotated_credential_acceptance_needs_clock: config.users.iter().any(|user| {
                user.rotation.as_ref().is_some_and(|rotation| {
                    !rotation.previous.is_empty() || rotation.next.is_some()
                })
            }),
            client_mode_wire_byte_authenticated: true,
            client_mode_compared_or_stored: false,
        },
        shaping,
        blockers,
    }
}

fn configured_channel_binding(enabled: bool, required: bool) -> ConfiguredChannelBinding {
    if !enabled {
        ConfiguredChannelBinding::Disabled
    } else if required {
        ConfiguredChannelBinding::Required
    } else {
        ConfiguredChannelBinding::Opportunistic
    }
}

fn trust_route(
    fronted: bool,
    provider: CdnFrontingProvider,
    carrier: CdnFrontingCarrier,
    trusted_tls_terminating_provider: bool,
) -> LocalTrustRoute {
    LocalTrustRoute {
        configured_assumption: if fronted {
            TrustRoute::TlsTerminatingFront {
                provider,
                carrier,
                trusted_tls_terminating_provider,
            }
        } else {
            TrustRoute::DirectToMaverick
        },
        network_topology_proven: false,
    }
}

fn client_carrier_security(
    carrier: Carrier,
    trust_route: LocalTrustRoute,
    configured_fingerprint: TlsFingerprintMode,
    channel_binding: ConfiguredChannelBinding,
) -> CarrierSecurity {
    let tls_backend = match carrier {
        Carrier::H2 if configured_fingerprint == TlsFingerprintMode::BrowserMimic => {
            TlsBackend::BrowserMimic
        }
        Carrier::H2 | Carrier::WebSocket => TlsBackend::Rustls,
    };
    CarrierSecurity {
        carrier,
        trust_route,
        tls_backend,
        name_privacy: NamePrivacy::ClientPlainSni {
            ech_grease: carrier == Carrier::H2 && tls_backend == TlsBackend::BrowserMimic,
        },
        channel_binding: channel_binding_candidate(
            carrier,
            matches!(
                trust_route.configured_assumption,
                TrustRoute::TlsTerminatingFront { .. }
            ),
            channel_binding,
        ),
    }
}

fn server_carrier_security(
    carrier: Carrier,
    trust_route: LocalTrustRoute,
    front_configuration_disables_binding: bool,
    channel_binding: ConfiguredChannelBinding,
) -> CarrierSecurity {
    CarrierSecurity {
        carrier,
        trust_route,
        tls_backend: TlsBackend::Rustls,
        name_privacy: NamePrivacy::ServerNotDerivable,
        channel_binding: channel_binding_candidate(
            carrier,
            front_configuration_disables_binding,
            channel_binding,
        ),
    }
}

fn channel_binding_candidate(
    carrier: Carrier,
    front_configuration_disables_binding: bool,
    configured: ConfiguredChannelBinding,
) -> ChannelBindingCandidate {
    if configured == ConfiguredChannelBinding::Disabled {
        ChannelBindingCandidate::DisabledByPolicy
    } else if front_configuration_disables_binding || carrier != Carrier::H2 {
        ChannelBindingCandidate::UnavailableForCarrierOrFrontConfiguration
    } else if configured == ConfiguredChannelBinding::Required {
        ChannelBindingCandidate::TlsExporterRequired
    } else {
        ChannelBindingCandidate::TlsExporterCandidate
    }
}

fn shaping_facts(mode: Mode, config: &maverick_core::config::ShapingConfig) -> ShapingFacts {
    let effective_enabled = config.enabled && mode != Mode::Stable;
    let cover_allowed =
        effective_enabled && config.cover_traffic && config.cover_traffic_operator_approved;
    ShapingFacts {
        configured_enabled: config.enabled,
        effective_enabled,
        bounds: ShapingBounds {
            max_padding_bytes_per_frame: config.max_padding_bytes_per_frame,
            max_overhead_ratio: config.max_overhead_ratio,
            max_delay_ms: config.max_delay_ms,
            max_batch_bytes: config.max_batch_bytes,
            cover_traffic_window_ms: config.cover_traffic_window_ms,
        },
        regular_padding: if !effective_enabled {
            RegularPadding::Disabled
        } else if mode == Mode::Auto {
            RegularPadding::AutoWithAdditional64ByteCap
        } else {
            RegularPadding::PrivateWithConfiguredBounds
        },
        cover: CoverTraffic {
            configured: config.cover_traffic,
            operator_approved: config.cover_traffic_operator_approved,
            allowed_by_mode_config_and_approval: cover_allowed,
            budget_eligibility: if !cover_allowed {
                CoverBudgetEligibility::DisabledByModeOrConfigOrApproval
            } else if config.max_overhead_ratio == 0.0 {
                CoverBudgetEligibility::BudgetAlwaysUnavailable
            } else {
                CoverBudgetEligibility::ConditionalOnEligiblePayloadAndPositiveRoundedBudget
            },
            payload_coupled: true,
            max_frames_per_eligible_send: 1,
            window_participates_when_plan_exists: true,
            cross_call_window_throttling_enforced: false,
            overhead_budget_independent_from_regular_padding: true,
        },
    }
}

fn client_shaping(config: &ClientConfig) -> ClientShapingBehavior {
    let facts = shaping_facts(config.mode, &config.advanced.shaping);
    ClientShapingBehavior {
        batching: if !facts.effective_enabled || facts.bounds.max_delay_ms == 0 {
            ClientBatching::Disabled
        } else if facts.bounds.max_batch_bytes as usize <= FRAME_HEADER_LEN {
            ClientBatching::NoEligibleFrame {
                max_batch_bytes: facts.bounds.max_batch_bytes,
                frame_header_bytes: FRAME_HEADER_LEN,
            }
        } else {
            ClientBatching::EligibleFramesUseSingleSendCallDelayThenFlush {
                max_delay_ms: facts.bounds.max_delay_ms,
                max_batch_bytes: facts.bounds.max_batch_bytes,
                cross_call_batching: false,
            }
        },
        facts,
        frame_size_bound: FrameSizeBound::ClientNegotiatedAtRuntime,
        legacy_advanced_padding: LegacyPaddingField::RuntimeInert,
    }
}

fn server_shaping(config: &ServerConfig) -> ServerShapingBehavior {
    ServerShapingBehavior {
        facts: shaping_facts(config.maverick.mode_default, &config.advanced.shaping),
        batching: ServerBatching {
            batcher_present: false,
            configured_max_delay_runtime_inert: true,
        },
        frame_size_bound: FrameSizeBound::ServerConfigured(config.advanced.max_frame_size),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use maverick_core::config::v2::{
        project_v1_client_policy, NamePrivacyMinimum as V2NamePrivacyMinimum,
        TrafficShapingPolicy as V2TrafficShapingPolicy, TransportStrategy as V2TransportStrategy,
        TrustRoute as V2TrustRoute, V1ClientPolicyProjectionBlocker,
    };
    use maverick_core::config::{
        ClientNextCredentialConfig, NextCredentialConfig, SecretString, TlsFingerprintMode,
        UserCredentialRotationConfig,
    };
    use maverick_core::padding::{cover_traffic_plan, RuntimeBatcher};
    use maverick_core::{Frame, FrameType};

    const SECRET: &str = "mv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PRIVATE_MARKER: &str = "SYNTHETIC_PRIVATE_MARKER_7F4A";

    fn mode_name(mode: Mode) -> &'static str {
        match mode {
            Mode::Auto => "auto",
            Mode::Stable => "stable",
            Mode::Private => "private",
        }
    }

    fn client(mode: Mode) -> ClientConfig {
        ClientConfig::from_yaml_str(&format!(
            r#"
version: 1
mode: {}
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.invalid:443"
  server_name: "example.invalid"
  tunnel_path: "/tunnel"
  credential_id: "u_test"
  secret: "{SECRET}"
"#,
            mode_name(mode)
        ))
        .unwrap()
    }

    fn server(mode: Mode) -> ServerConfig {
        ServerConfig::from_yaml_str(&format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/tunnel"
  mode_default: {}
users:
  - id: "u_test"
    secret: "{SECRET}"
fallback:
  type: "static"
  static_dir: "./public"
"#,
            mode_name(mode)
        ))
        .unwrap()
    }

    fn enable_front(config: &mut ClientConfig, carrier: CdnFrontingCarrier) {
        config.advanced.stealth.cdn_fronting.enabled = true;
        config.advanced.stealth.cdn_fronting.carrier = carrier;
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        if carrier == CdnFrontingCarrier::WebSocket {
            config.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        }
        config.validate().unwrap();
    }

    fn enable_server_front(config: &mut ServerConfig, carrier: CdnFrontingCarrier) {
        config.advanced.stealth.cdn_fronting.enabled = true;
        config.advanced.stealth.cdn_fronting.carrier = carrier;
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        config.validate().unwrap();
    }

    #[test]
    fn mode_wire_ids_remain_local_and_peer_unconfirmed() {
        for (mode, wire_id) in [(Mode::Auto, 0), (Mode::Stable, 1)] {
            let client = evaluate_client(&client(mode));
            assert_eq!(client.mode.client_hello_mode, mode);
            assert_eq!(client.mode.wire_id, wire_id);
            assert!(!client.mode.peer_confirmed_session_mode);
        }
        for (mode, wire_id) in [(Mode::Auto, 0), (Mode::Stable, 1), (Mode::Private, 2)] {
            let server = evaluate_server(&server(mode));
            assert_eq!(server.mode.local_mode_default, mode);
            assert_eq!(server.mode.wire_id, wire_id);
            assert!(!server.mode.client_mode_compared_or_stored);
        }
    }

    #[test]
    fn auto_h2_policy_projection_matches_the_independent_oracle() {
        for config in [client(Mode::Auto), {
            let mut explicit = client(Mode::Auto);
            explicit.advanced.shaping.max_padding_bytes_per_frame = 7;
            explicit.advanced.shaping.max_overhead_ratio = 0.5;
            explicit.advanced.shaping.max_delay_ms = 999;
            explicit.advanced.shaping.max_batch_bytes = 17;
            explicit.advanced.shaping.cover_traffic_window_ms = 42;
            explicit
        }] {
            config.validate().unwrap();
            let behavior = evaluate_client(&config);
            assert!(behavior.blockers.is_empty());
            let projection = project_v1_client_policy(&config).unwrap();
            let policy = projection.policy();
            assert_eq!(behavior.carrier_security.len(), 1);
            let carrier_security = &behavior.carrier_security[0];
            assert!(matches!(
                (
                    behavior.carrier.candidate_selection_policy,
                    carrier_security.carrier,
                    policy.transport_strategy()
                ),
                (ClientCarrier::H2Only, Carrier::H2, V2TransportStrategy::H2)
            ));
            assert!(matches!(
                (
                    carrier_security.trust_route.configured_assumption,
                    policy.trust_route()
                ),
                (TrustRoute::DirectToMaverick, V2TrustRoute::DirectToMaverick)
            ));
            assert!(matches!(
                (carrier_security.name_privacy, policy.name_privacy_minimum()),
                (
                    NamePrivacy::ClientPlainSni { .. },
                    V2NamePrivacyMinimum::PlainSni
                )
            ));
            assert!(matches!(
                (
                    behavior.shaping.facts.effective_enabled,
                    policy.traffic_shaping_policy()
                ),
                (false, V2TrafficShapingPolicy::Disabled)
            ));
            assert_eq!(projection.legacy_mode(), Mode::Auto);
            assert_eq!(projection.legacy_mode().wire_id(), 0);
            assert!(!projection.legacy_mode_peer_confirmed());
        }
    }

    #[test]
    fn retired_h3_and_fronted_h2_projection_boundaries_are_distinct() {
        let mut h3 = client(Mode::Auto);
        h3.advanced.experimental_h3 = true;
        assert_eq!(
            h3.validate().unwrap_err().to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
        assert_eq!(
            project_v1_client_policy(&h3),
            Err(V1ClientPolicyProjectionBlocker::InvalidSourceConfig)
        );

        let mut fronted_h2 = client(Mode::Auto);
        enable_front(&mut fronted_h2, CdnFrontingCarrier::H2);
        assert!(evaluate_client(&fronted_h2).blockers.is_empty());
        assert_eq!(
            project_v1_client_policy(&fronted_h2),
            Err(V1ClientPolicyProjectionBlocker::TlsTerminatingFrontConfigured)
        );
    }

    #[test]
    fn stable_and_server_legacy_mode_blockers_remain() {
        assert_eq!(
            evaluate_client(&client(Mode::Stable)).blockers,
            vec![MappingBlocker::LegacyModeCompatibilityUnresolved]
        );
        assert_eq!(
            evaluate_server(&server(Mode::Auto)).blockers,
            vec![MappingBlocker::LegacyModeCompatibilityUnresolved]
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
    fn private_client_legacy_mode_blocker_remains() {
        assert_eq!(
            evaluate_client(&client(Mode::Private)).blockers,
            vec![MappingBlocker::LegacyModeCompatibilityUnresolved]
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
    fn private_client_keeps_wire_id_two_without_peer_confirmation() {
        let behavior = evaluate_client(&client(Mode::Private));
        assert_eq!(behavior.mode.client_hello_mode, Mode::Private);
        assert_eq!(behavior.mode.wire_id, 2);
        assert!(!behavior.mode.peer_confirmed_session_mode);
    }

    #[test]
    fn omitted_and_explicit_defaults_have_identical_output() {
        let implicit = client(Mode::Auto);
        let tls_fingerprint = match implicit.advanced.stealth.tls_fingerprint {
            TlsFingerprintMode::RustlsDefault => "rustls_default",
            TlsFingerprintMode::BrowserMimic => "browser_mimic",
        };
        let explicit = ClientConfig::from_yaml_str(&format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.invalid:443"
  server_name: "example.invalid"
  tunnel_path: "/tunnel"
  credential_id: "u_test"
  secret: "{SECRET}"
auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
    require: false
    accepted_epochs: []
  rotation:
    active_epoch: null
    next_credential_id: null
    auto_switch: false
    next: null
advanced:
  padding: "auto"
  experimental_h3: false
  experimental_cloudflare_ws: false
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  stealth:
    tls_fingerprint: "{tls_fingerprint}"
    active_probe_resistance: true
    cdn_fronting:
      enabled: false
      provider: "cloudflare"
      carrier: "web_socket"
      trusted_tls_terminating_provider: false
"#
        ))
        .unwrap();
        assert_eq!(evaluate_client(&implicit), evaluate_client(&explicit));

        let implicit = server(Mode::Auto);
        let explicit = ServerConfig::from_yaml_str(&format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/tunnel"
  mode_default: auto
users:
  - id: "u_test"
    secret: "{SECRET}"
fallback:
  type: "static"
  static_dir: "./public"
auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
    require: false
    accepted_epochs: []
advanced:
  experimental_h3: false
  experimental_cloudflare_ws: false
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  stealth:
    tls_fingerprint: "rustls_default"
    active_probe_resistance: true
    cdn_fronting:
      enabled: false
      provider: "cloudflare"
      carrier: "web_socket"
      trusted_tls_terminating_provider: false
"#
        ))
        .unwrap();
        assert_eq!(evaluate_server(&implicit), evaluate_server(&explicit));
    }

    #[test]
    fn client_oracle_records_h2_without_a_retired_h3_candidate() {
        let config = client(Mode::Auto);
        config.validate().unwrap();
        let behavior = evaluate_client(&config);
        assert_eq!(
            behavior.carrier.candidate_selection_policy,
            ClientCarrier::H2Only
        );
        assert!(!behavior.carrier.h3_configured);
        assert_eq!(behavior.carrier_security.len(), 1);
        assert_eq!(behavior.carrier_security[0].carrier, Carrier::H2);
        assert!(behavior.blockers.is_empty());
    }

    #[test]
    fn fronted_client_carriers_keep_route_tls_name_and_binding_facts() {
        let mut h2 = client(Mode::Auto);
        enable_front(&mut h2, CdnFrontingCarrier::H2);
        let h2 = evaluate_client(&h2);
        assert_eq!(
            h2.carrier.candidate_selection_policy,
            ClientCarrier::FrontedH2
        );
        assert_eq!(
            h2.carrier_security[0].name_privacy,
            NamePrivacy::ClientPlainSni {
                ech_grease: matches!(h2.carrier_security[0].tls_backend, TlsBackend::BrowserMimic)
            }
        );
        assert_eq!(
            h2.carrier_security[0].channel_binding,
            ChannelBindingCandidate::UnavailableForCarrierOrFrontConfiguration
        );
        assert!(matches!(
            h2.carrier_security[0].trust_route.configured_assumption,
            TrustRoute::TlsTerminatingFront { .. }
        ));

        let mut ws = client(Mode::Auto);
        enable_front(&mut ws, CdnFrontingCarrier::WebSocket);
        let ws = evaluate_client(&ws);
        assert_eq!(
            ws.carrier.candidate_selection_policy,
            ClientCarrier::FrontedWebSocket
        );
        assert_eq!(ws.carrier_security[0].carrier, Carrier::WebSocket);
        assert_eq!(ws.carrier_security[0].tls_backend, TlsBackend::Rustls);
    }

    #[test]
    fn server_oracle_records_h2_without_a_retired_h3_entry() {
        let config = server(Mode::Auto);
        config.validate().unwrap();
        let behavior = evaluate_server(&config);
        assert!(behavior.carrier.h2_entry_enabled);
        assert!(!behavior.carrier.h3_configured);
        assert_eq!(behavior.carrier_security.len(), 1);
        assert_eq!(behavior.carrier_security[0].carrier, Carrier::H2);
        assert_eq!(
            behavior.blockers,
            vec![MappingBlocker::LegacyModeCompatibilityUnresolved]
        );
    }

    #[test]
    fn server_front_entries_keep_fixed_route_and_security_facts() {
        let mut h2 = server(Mode::Auto);
        enable_server_front(&mut h2, CdnFrontingCarrier::H2);
        let h2 = evaluate_server(&h2);
        assert_eq!(
            h2.carrier_security[0].trust_route.configured_assumption,
            TrustRoute::TlsTerminatingFront {
                provider: CdnFrontingProvider::Cloudflare,
                carrier: CdnFrontingCarrier::H2,
                trusted_tls_terminating_provider: true,
            }
        );
        assert!(!h2.carrier_security[0].trust_route.network_topology_proven);
        assert!(h2.carrier.h2_entry_enabled);
        assert!(!h2.carrier.websocket_entry_enabled);
        assert_eq!(
            h2.carrier_security[0].channel_binding,
            ChannelBindingCandidate::UnavailableForCarrierOrFrontConfiguration
        );
        assert_eq!(
            h2.carrier_security[0].name_privacy,
            NamePrivacy::ServerNotDerivable
        );
        assert_eq!(
            h2.blockers,
            vec![MappingBlocker::LegacyModeCompatibilityUnresolved]
        );

        let mut ws_config = server(Mode::Auto);
        enable_server_front(&mut ws_config, CdnFrontingCarrier::WebSocket);
        let ws = evaluate_server(&ws_config);
        assert!(ws.carrier.websocket_entry_enabled);
        assert_eq!(ws.carrier_security[0].carrier, Carrier::H2);
        assert_eq!(
            ws.carrier_security[0].trust_route.configured_assumption,
            TrustRoute::DirectToMaverick
        );
        assert_eq!(ws.carrier_security[1].carrier, Carrier::WebSocket);
        assert!(matches!(
            ws.carrier_security[1].trust_route.configured_assumption,
            TrustRoute::TlsTerminatingFront {
                carrier: CdnFrontingCarrier::WebSocket,
                trusted_tls_terminating_provider: true,
                ..
            }
        ));
        assert!(ws
            .carrier_security
            .iter()
            .all(|security| !security.trust_route.network_topology_proven));
        assert_eq!(
            ws.blockers,
            vec![
                MappingBlocker::UnsupportedV2Carrier,
                MappingBlocker::MixedTrustRoutesNotRepresentable,
                MappingBlocker::LegacyModeCompatibilityUnresolved,
            ]
        );

        ws_config.advanced.experimental_cloudflare_ws = true;
        ws_config.validate().unwrap();
        assert_eq!(evaluate_server(&ws_config), ws);
    }

    #[test]
    fn server_fronting_cannot_bypass_retired_h3_validation() {
        for front_carrier in [CdnFrontingCarrier::H2, CdnFrontingCarrier::WebSocket] {
            let mut config = server(Mode::Auto);
            enable_server_front(&mut config, front_carrier);
            config.advanced.experimental_h3 = true;
            config.advanced.shaping.enabled = true;
            assert_eq!(
                config.validate().unwrap_err().to_string(),
                "configuration error: advanced.experimental_h3=true is retired for config version 1"
            );
        }
    }

    #[test]
    fn auth_and_channel_binding_are_role_and_carrier_specific() {
        let mut client = client(Mode::Auto);
        client.auth.v2.enabled = true;
        client.auth.rotation.active_epoch = Some("7".into());
        client.validate().unwrap();
        let client = evaluate_client(&client);
        assert_eq!(client.auth.sends, ClientAuthProtocol::V2);
        assert_eq!(
            client.auth.credential_selection,
            ClientCredentialSelection::ConfiguredActiveWithoutClock
        );
        assert_eq!(
            client.carrier_security[0].channel_binding,
            ChannelBindingCandidate::TlsExporterCandidate
        );

        let mut server = server(Mode::Auto);
        server.auth.v2.enabled = true;
        server.auth.v2.require = true;
        server.auth.v2.accepted_epochs = vec![7];
        server.validate().unwrap();
        let server = evaluate_server(&server);
        assert_eq!(server.auth.accepts, ServerAuthProtocol::RequireV2);
        assert!(!server.auth.client_mode_compared_or_stored);
    }

    #[test]
    fn credential_rotation_is_reported_without_reading_the_clock() {
        let mut client = client(Mode::Auto);
        client.auth.rotation.auto_switch = true;
        client.auth.rotation.next = Some(ClientNextCredentialConfig {
            id: "u_next".into(),
            secret: SecretString::new(SECRET).unwrap(),
            not_before: "2030-01-01T00:00:00Z".into(),
        });
        client.validate().unwrap();
        assert_eq!(
            evaluate_client(&client).auth.credential_selection,
            ClientCredentialSelection::ClockDependentAndNotSelected
        );

        let mut server = server(Mode::Auto);
        server.users[0].rotation = Some(UserCredentialRotationConfig {
            previous: Vec::new(),
            next: Some(NextCredentialConfig {
                id: "u_next".into(),
                not_before: "2030-01-01T00:00:00Z".into(),
            }),
        });
        server.validate().unwrap();
        assert!(
            evaluate_server(&server)
                .auth
                .rotated_credential_acceptance_needs_clock
        );
    }

    #[test]
    fn required_and_disabled_binding_candidates_survive_h3_retirement() {
        let mut required = client(Mode::Auto);
        required.auth.channel_binding.require = true;
        required.validate().unwrap();
        assert_eq!(
            evaluate_client(&required).carrier_security[0].channel_binding,
            ChannelBindingCandidate::TlsExporterRequired
        );

        let mut disabled = client(Mode::Auto);
        disabled.auth.channel_binding.enabled = false;
        disabled.validate().unwrap();
        assert_eq!(
            evaluate_client(&disabled).carrier_security[0].channel_binding,
            ChannelBindingCandidate::DisabledByPolicy
        );

        let mut h3 = client(Mode::Auto);
        h3.advanced.experimental_h3 = true;
        assert_eq!(
            h3.validate().unwrap_err().to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
    }

    #[test]
    fn shaping_mode_gates_match_runtime_padding_and_batcher_helpers() {
        assert!(
            !evaluate_client(&client(Mode::Auto))
                .shaping
                .facts
                .effective_enabled
        );
        assert!(
            !evaluate_server(&server(Mode::Auto))
                .shaping
                .facts
                .effective_enabled
        );
        for mode in [Mode::Auto, Mode::Stable, Mode::Private] {
            let mut config = server(mode);
            config.advanced.shaping.enabled = true;
            config.validate().unwrap();
            let behavior = evaluate_server(&config);
            assert_eq!(
                behavior.shaping.facts.effective_enabled,
                mode != Mode::Stable
            );
            assert_eq!(
                behavior.shaping.facts.regular_padding,
                match mode {
                    Mode::Auto => RegularPadding::AutoWithAdditional64ByteCap,
                    Mode::Stable => RegularPadding::Disabled,
                    Mode::Private => RegularPadding::PrivateWithConfiguredBounds,
                }
            );
        }

        let mut config = client(Mode::Auto);
        config.advanced.shaping.enabled = true;
        config.validate().unwrap();
        let batcher = RuntimeBatcher::from_config(config.mode, &config.advanced.shaping);
        assert!(batcher.is_enabled());
        assert!(matches!(
            evaluate_client(&config).shaping.batching,
            ClientBatching::EligibleFramesUseSingleSendCallDelayThenFlush {
                cross_call_batching: false,
                ..
            }
        ));

        let mut stable = client(Mode::Stable);
        stable.advanced.shaping.enabled = true;
        stable.validate().unwrap();
        let stable = evaluate_client(&stable);
        assert!(!stable.shaping.facts.effective_enabled);
        assert_eq!(stable.shaping.batching, ClientBatching::Disabled);
    }

    #[cfg(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn private_client_uses_full_padding_bounds_and_single_send_delay() {
        let mut config = client(Mode::Private);
        config.advanced.shaping.enabled = true;
        config.validate().unwrap();
        let shaping = evaluate_client(&config).shaping;
        assert!(shaping.facts.effective_enabled);
        assert_eq!(
            shaping.facts.regular_padding,
            RegularPadding::PrivateWithConfiguredBounds
        );
        assert!(matches!(
            shaping.batching,
            ClientBatching::EligibleFramesUseSingleSendCallDelayThenFlush {
                cross_call_batching: false,
                ..
            }
        ));
    }

    #[test]
    fn client_batching_requires_room_beyond_the_wire_header() {
        for cap in [(FRAME_HEADER_LEN - 1) as u32, FRAME_HEADER_LEN as u32] {
            let mut config = client(Mode::Auto);
            config.advanced.shaping.enabled = true;
            config.advanced.shaping.max_batch_bytes = cap;
            config.validate().unwrap();

            assert_eq!(
                evaluate_client(&config).shaping.batching,
                ClientBatching::NoEligibleFrame {
                    max_batch_bytes: cap,
                    frame_header_bytes: FRAME_HEADER_LEN,
                }
            );
            let mut runtime = RuntimeBatcher::from_config(config.mode, &config.advanced.shaping);
            let ready = runtime.push(Frame::new(FrameType::TcpData, 1, 0, Vec::new()));
            assert_eq!(ready.len(), 1);
            assert!(runtime.is_empty());
        }

        let mut config = client(Mode::Auto);
        config.advanced.shaping.enabled = true;
        config.advanced.shaping.max_batch_bytes = (FRAME_HEADER_LEN + 1) as u32;
        config.validate().unwrap();
        assert!(matches!(
            evaluate_client(&config).shaping.batching,
            ClientBatching::EligibleFramesUseSingleSendCallDelayThenFlush { .. }
        ));
        let mut runtime = RuntimeBatcher::from_config(config.mode, &config.advanced.shaping);
        assert!(runtime
            .push(Frame::new(FrameType::TcpData, 1, 0, Vec::new()))
            .is_empty());
        assert!(runtime.flush_delay().is_some());
    }

    #[test]
    fn cover_budget_reports_zero_ratio_and_small_payload_conditionally() {
        let mut config = client(Mode::Auto);
        config.advanced.shaping.enabled = true;
        config.advanced.shaping.cover_traffic = true;
        config.advanced.shaping.cover_traffic_operator_approved = true;
        config.advanced.shaping.max_overhead_ratio = 0.0;
        config.validate().unwrap();
        let behavior = evaluate_client(&config);
        assert!(
            behavior
                .shaping
                .facts
                .cover
                .allowed_by_mode_config_and_approval
        );
        assert_eq!(
            behavior.shaping.facts.cover.budget_eligibility,
            CoverBudgetEligibility::BudgetAlwaysUnavailable
        );
        assert!(cover_traffic_plan(
            config.mode,
            &config.advanced.shaping,
            4096,
            Duration::from_millis(config.advanced.shaping.cover_traffic_window_ms),
        )
        .is_none());

        config.advanced.shaping.max_overhead_ratio = 0.25;
        config.validate().unwrap();
        assert_eq!(
            evaluate_client(&config)
                .shaping
                .facts
                .cover
                .budget_eligibility,
            CoverBudgetEligibility::ConditionalOnEligiblePayloadAndPositiveRoundedBudget
        );
        let window = Duration::from_millis(config.advanced.shaping.cover_traffic_window_ms);
        assert!(cover_traffic_plan(config.mode, &config.advanced.shaping, 3, window).is_none());
        assert!(cover_traffic_plan(config.mode, &config.advanced.shaping, 4, window).is_some());
    }

    #[test]
    fn cover_and_server_delay_report_only_current_consumption() {
        let mut client_config = client(Mode::Auto);
        client_config.advanced.shaping.enabled = true;
        client_config.advanced.shaping.cover_traffic = true;
        client_config
            .advanced
            .shaping
            .cover_traffic_operator_approved = true;
        client_config.validate().unwrap();
        let cover = evaluate_client(&client_config).shaping.facts.cover;
        assert!(cover.allowed_by_mode_config_and_approval);
        assert_eq!(
            cover.budget_eligibility,
            CoverBudgetEligibility::ConditionalOnEligiblePayloadAndPositiveRoundedBudget
        );
        assert!(cover.payload_coupled);
        assert_eq!(cover.max_frames_per_eligible_send, 1);
        assert!(cover.window_participates_when_plan_exists);
        assert!(!cover.cross_call_window_throttling_enforced);
        assert!(cover.overhead_budget_independent_from_regular_padding);

        let mut server = server(Mode::Auto);
        server.advanced.shaping.enabled = true;
        server.validate().unwrap();
        let server = evaluate_server(&server);
        assert!(!server.shaping.batching.batcher_present);
        assert!(server.shaping.batching.configured_max_delay_runtime_inert);
        assert_eq!(
            evaluate_client(&client(Mode::Auto))
                .shaping
                .legacy_advanced_padding,
            LegacyPaddingField::RuntimeInert
        );
    }

    #[test]
    fn blockers_are_conditional_unique_and_stably_ordered() {
        let mut config = client(Mode::Auto);
        config.advanced.experimental_cloudflare_ws = true;
        config.advanced.stealth.cdn_fronting.enabled = true;
        config
            .advanced
            .stealth
            .cdn_fronting
            .trusted_tls_terminating_provider = true;
        config.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        config.advanced.shaping.enabled = true;
        config.validate().unwrap();
        assert_eq!(
            evaluate_client(&config).blockers,
            vec![
                MappingBlocker::UnsupportedV2Carrier,
                MappingBlocker::EnabledShapingPolicyUnfrozen,
            ]
        );
    }

    #[test]
    fn output_never_copies_private_input_strings() {
        let mut config = client(Mode::Auto);
        config.server.address = format!("{PRIVATE_MARKER}:443");
        config.server.server_name = PRIVATE_MARKER.into();
        config.server.tunnel_path = format!("/{PRIVATE_MARKER}");
        config.server.credential_id = PRIVATE_MARKER.into();
        config.advanced.padding = PRIVATE_MARKER.into();
        config.validate().unwrap();

        let rendered = format!("{:?}", evaluate_client(&config));
        assert!(!rendered.contains(PRIVATE_MARKER));
    }
}
