use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::config::{
    browser_tls_profile_supported, ClientConfig, EchFallbackPolicy, Mode, TlsFingerprintMode,
};
use crate::ech::EchReadinessSnapshot;
use crate::tun::TunRuntimeReadinessSnapshot;
use crate::util::redact_id;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiErrorClass {
    Auth,
    Config,
    Network,
    Timeout,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EchDiagnosticStatus {
    Disabled,
    Unsupported,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EchDiagnosticsSnapshot {
    pub requested: bool,
    pub implementation_supported: bool,
    pub fallback_policy: EchFallbackPolicy,
    pub status: EchDiagnosticStatus,
    pub private_mode_plain_sni_blocked: bool,
    pub readiness: EchReadinessSnapshot,
}

impl EchDiagnosticsSnapshot {
    pub fn from_client_config(config: &ClientConfig) -> Self {
        Self::new(
            config.mode,
            config.advanced.experimental_ech,
            config.advanced.ech_fallback_policy,
        )
    }

    pub fn new(mode: Mode, requested: bool, fallback_policy: EchFallbackPolicy) -> Self {
        let readiness = EchReadinessSnapshot::current();
        let implementation_supported = readiness.runtime_ready;
        Self {
            requested,
            implementation_supported,
            fallback_policy,
            status: if !requested {
                EchDiagnosticStatus::Disabled
            } else if implementation_supported {
                EchDiagnosticStatus::Ready
            } else {
                EchDiagnosticStatus::Unsupported
            },
            private_mode_plain_sni_blocked: mode == Mode::Private
                && fallback_policy == EchFallbackPolicy::AllowPlainSni,
            readiness,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StealthDiagnosticStatus {
    BaselineRustls,
    BrowserMimic,
    CdnFronted,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthDiagnosticsSnapshot {
    pub tls_fingerprint: TlsFingerprintMode,
    pub browser_mimicry_supported: bool,
    pub active_probe_resistance_required: bool,
    pub cdn_fronting_enabled: bool,
    pub cdn_tls_terminating_provider_trusted: bool,
    pub status: StealthDiagnosticStatus,
}

impl StealthDiagnosticsSnapshot {
    pub fn from_client_config(config: &ClientConfig) -> Self {
        let stealth = &config.advanced.stealth;
        let cdn_fronting = &stealth.cdn_fronting;
        let browser_mimicry_supported = browser_tls_profile_supported();
        let status = if stealth.tls_fingerprint == TlsFingerprintMode::BrowserMimic {
            if browser_mimicry_supported {
                StealthDiagnosticStatus::BrowserMimic
            } else {
                StealthDiagnosticStatus::Unsupported
            }
        } else if cdn_fronting.enabled {
            StealthDiagnosticStatus::CdnFronted
        } else {
            StealthDiagnosticStatus::BaselineRustls
        };
        Self {
            tls_fingerprint: stealth.tls_fingerprint,
            browser_mimicry_supported,
            active_probe_resistance_required: stealth.active_probe_resistance,
            cdn_fronting_enabled: cdn_fronting.enabled,
            cdn_tls_terminating_provider_trusted: cdn_fronting.trusted_tls_terminating_provider,
            status,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiTransportStatus {
    Ready,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiTransportCarrier {
    H2,
    H3,
    CloudflareWs,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuiTransportDebugSnapshot {
    pub active_transport: GuiTransportCarrier,
    pub fallback_transport: GuiTransportCarrier,
    pub h3_candidate_enabled: bool,
    pub h3_in_cooldown: bool,
}

impl GuiTransportDebugSnapshot {
    pub fn new(
        active_transport: GuiTransportCarrier,
        h3_candidate_enabled: bool,
        h3_in_cooldown: bool,
    ) -> Self {
        Self {
            active_transport,
            fallback_transport: GuiTransportCarrier::H2,
            h3_candidate_enabled,
            h3_in_cooldown,
        }
    }

    pub fn public_status(&self) -> GuiTransportStatus {
        if self.h3_candidate_enabled && self.h3_in_cooldown {
            GuiTransportStatus::Degraded
        } else {
            GuiTransportStatus::Ready
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuiDiagnosticsSnapshot {
    pub connection_state: GuiConnectionState,
    pub policy_mode: Mode,
    pub profile_name: String,
    pub local_socks5: SocketAddr,
    pub dns_listener: Option<SocketAddr>,
    pub http_connect_listener: Option<SocketAddr>,
    pub credential_display: String,
    pub last_error_class: Option<GuiErrorClass>,
    pub tun_controls_enabled: bool,
    pub tun_safety: GuiTunSafetySnapshot,
    pub transport_status: GuiTransportStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_debug: Option<GuiTransportDebugSnapshot>,
}

impl GuiDiagnosticsSnapshot {
    pub fn from_client_config(
        profile_name: impl Into<String>,
        config: &ClientConfig,
        connection_state: GuiConnectionState,
        last_error_class: Option<GuiErrorClass>,
    ) -> Self {
        let dns_listener = config
            .local
            .dns
            .as_ref()
            .and_then(|dns| dns.enabled.then_some(dns.listen).flatten());
        let http_connect_listener = config
            .local
            .http_connect
            .as_ref()
            .and_then(|http| http.enabled.then_some(http.listen).flatten());
        let tun_safety = GuiTunSafetySnapshot::default_disabled();
        Self {
            connection_state,
            policy_mode: config.mode,
            profile_name: profile_name.into(),
            local_socks5: config.local.socks5.listen,
            dns_listener,
            http_connect_listener,
            credential_display: redact_id(&config.server.credential_id),
            last_error_class,
            tun_controls_enabled: tun_safety.controls_enabled,
            tun_safety,
            transport_status: GuiTransportStatus::Ready,
            transport_debug: None,
        }
    }

    pub fn with_transport_debug(mut self, debug: GuiTransportDebugSnapshot) -> Self {
        self.transport_status = debug.public_status();
        self.transport_debug = Some(debug);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiTunControlState {
    DisabledRuntimeNotReady,
    DisabledGuiProductGateMissing,
    ReadOnlyStatusAvailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuiTunSafetySnapshot {
    pub runtime_ready: bool,
    pub gui_product_gate_ready: bool,
    pub controls_enabled: bool,
    pub apply_allowed_from_gui: bool,
    pub local_machine_network_mutation_allowed: bool,
    pub control_state: GuiTunControlState,
    pub readiness: TunRuntimeReadinessSnapshot,
}

impl GuiTunSafetySnapshot {
    pub fn default_disabled() -> Self {
        Self::from_readiness(TunRuntimeReadinessSnapshot::current(), false)
    }

    pub fn from_readiness(
        readiness: TunRuntimeReadinessSnapshot,
        gui_product_gate_ready: bool,
    ) -> Self {
        let control_state = if !readiness.runtime_ready {
            GuiTunControlState::DisabledRuntimeNotReady
        } else if !gui_product_gate_ready {
            GuiTunControlState::DisabledGuiProductGateMissing
        } else {
            GuiTunControlState::ReadOnlyStatusAvailable
        };
        Self {
            runtime_ready: readiness.runtime_ready,
            gui_product_gate_ready,
            controls_enabled: false,
            apply_allowed_from_gui: false,
            local_machine_network_mutation_allowed: false,
            control_state,
            readiness,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiRuntimeReadinessBlocker {
    CoreDiagnosticsMissing,
    SdkRuntimeBaselineMissing,
    DebugRedactionTestsMissing,
    UiScopeDecisionMissing,
    PlatformTargetDecisionMissing,
    SecureProfileStorageMissing,
    ServiceLifecycleIntegrationMissing,
    SigningNotarizationMissing,
    TunSafetyIntegrationMissing,
    UiSmokeTestsMissing,
    ReleasePackagingMissing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuiRuntimeReadinessSnapshot {
    pub core_diagnostics_ready: bool,
    pub sdk_runtime_baseline_ready: bool,
    pub debug_redaction_tests_ready: bool,
    pub ui_scope_decided: bool,
    pub platform_targets_decided: bool,
    pub secure_profile_storage_ready: bool,
    pub service_lifecycle_integration_ready: bool,
    pub signing_notarization_ready: bool,
    pub tun_safety_integration_ready: bool,
    pub ui_smoke_tests_ready: bool,
    pub release_packaging_ready: bool,
    pub runtime_ready: bool,
    pub blockers: Vec<GuiRuntimeReadinessBlocker>,
}

impl GuiRuntimeReadinessSnapshot {
    pub fn current() -> Self {
        Self::from_inputs(GuiRuntimeReadinessInputs::current())
    }

    fn from_inputs(inputs: GuiRuntimeReadinessInputs) -> Self {
        let mut blockers = Vec::new();
        if !inputs.core_diagnostics_ready {
            blockers.push(GuiRuntimeReadinessBlocker::CoreDiagnosticsMissing);
        }
        if !inputs.sdk_runtime_baseline_ready {
            blockers.push(GuiRuntimeReadinessBlocker::SdkRuntimeBaselineMissing);
        }
        if !inputs.debug_redaction_tests_ready {
            blockers.push(GuiRuntimeReadinessBlocker::DebugRedactionTestsMissing);
        }
        if !inputs.ui_scope_decided {
            blockers.push(GuiRuntimeReadinessBlocker::UiScopeDecisionMissing);
        }
        if !inputs.platform_targets_decided {
            blockers.push(GuiRuntimeReadinessBlocker::PlatformTargetDecisionMissing);
        }
        if !inputs.secure_profile_storage_ready {
            blockers.push(GuiRuntimeReadinessBlocker::SecureProfileStorageMissing);
        }
        if !inputs.service_lifecycle_integration_ready {
            blockers.push(GuiRuntimeReadinessBlocker::ServiceLifecycleIntegrationMissing);
        }
        if !inputs.signing_notarization_ready {
            blockers.push(GuiRuntimeReadinessBlocker::SigningNotarizationMissing);
        }
        if !inputs.tun_safety_integration_ready {
            blockers.push(GuiRuntimeReadinessBlocker::TunSafetyIntegrationMissing);
        }
        if !inputs.ui_smoke_tests_ready {
            blockers.push(GuiRuntimeReadinessBlocker::UiSmokeTestsMissing);
        }
        if !inputs.release_packaging_ready {
            blockers.push(GuiRuntimeReadinessBlocker::ReleasePackagingMissing);
        }

        Self {
            core_diagnostics_ready: inputs.core_diagnostics_ready,
            sdk_runtime_baseline_ready: inputs.sdk_runtime_baseline_ready,
            debug_redaction_tests_ready: inputs.debug_redaction_tests_ready,
            ui_scope_decided: inputs.ui_scope_decided,
            platform_targets_decided: inputs.platform_targets_decided,
            secure_profile_storage_ready: inputs.secure_profile_storage_ready,
            service_lifecycle_integration_ready: inputs.service_lifecycle_integration_ready,
            signing_notarization_ready: inputs.signing_notarization_ready,
            tun_safety_integration_ready: inputs.tun_safety_integration_ready,
            ui_smoke_tests_ready: inputs.ui_smoke_tests_ready,
            release_packaging_ready: inputs.release_packaging_ready,
            runtime_ready: blockers.is_empty(),
            blockers,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuiRuntimeReadinessInputs {
    core_diagnostics_ready: bool,
    sdk_runtime_baseline_ready: bool,
    debug_redaction_tests_ready: bool,
    ui_scope_decided: bool,
    platform_targets_decided: bool,
    secure_profile_storage_ready: bool,
    service_lifecycle_integration_ready: bool,
    signing_notarization_ready: bool,
    tun_safety_integration_ready: bool,
    ui_smoke_tests_ready: bool,
    release_packaging_ready: bool,
}

impl GuiRuntimeReadinessInputs {
    fn current() -> Self {
        Self {
            core_diagnostics_ready: true,
            sdk_runtime_baseline_ready: true,
            debug_redaction_tests_ready: true,
            ui_scope_decided: true,
            platform_targets_decided: true,
            secure_profile_storage_ready: true,
            service_lifecycle_integration_ready: true,
            signing_notarization_ready: false,
            tun_safety_integration_ready: true,
            ui_smoke_tests_ready: true,
            release_packaging_ready: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::config::{
        CdnFrontingCarrier, CdnFrontingConfig, ClientAdvancedConfig, ClientServerConfig,
        EchFallbackPolicy, HttpConnectConfig, LocalConfig, LogConfig, Mode, SecretString,
        Socks5Config, TlsFingerprintMode,
    };

    #[test]
    fn gui_diagnostics_redacts_sensitive_fields() {
        let secret = SecretString::generate();
        let full_id = "u_sensitive_credential_id_2026";
        let config = client_config(full_id, secret.clone());
        let snapshot = GuiDiagnosticsSnapshot::from_client_config(
            "primary",
            &config,
            GuiConnectionState::Connected,
            Some(GuiErrorClass::Network),
        );
        assert_eq!(snapshot.credential_display, "u_se...26");
        assert_eq!(snapshot.policy_mode, Mode::Auto);
        assert_eq!(snapshot.transport_status, GuiTransportStatus::Ready);
        assert_eq!(snapshot.transport_debug, None);
        assert_eq!(snapshot.local_socks5.to_string(), "127.0.0.1:1080");
        assert_eq!(
            snapshot.http_connect_listener,
            Some("127.0.0.1:18080".parse::<SocketAddr>().unwrap())
        );
        assert!(!snapshot.tun_controls_enabled);
        assert!(!snapshot.tun_safety.runtime_ready);
        assert!(!snapshot.tun_safety.gui_product_gate_ready);
        assert!(!snapshot.tun_safety.controls_enabled);
        assert!(!snapshot.tun_safety.apply_allowed_from_gui);
        assert!(!snapshot.tun_safety.local_machine_network_mutation_allowed);
        assert_eq!(
            snapshot.tun_safety.control_state,
            GuiTunControlState::DisabledRuntimeNotReady
        );

        let rendered = format!("{snapshot:?}");
        assert!(!rendered.contains(full_id));
        assert!(!rendered.contains(secret.expose_secret()));
        assert!(!rendered.contains("example.com:443"));
    }

    #[test]
    fn gui_diagnostics_omits_disabled_optional_listeners() {
        let mut config = client_config("u123", SecretString::generate());
        config.local.http_connect = Some(HttpConnectConfig {
            enabled: false,
            listen: Some("127.0.0.1:18080".parse().unwrap()),
        });
        let snapshot = GuiDiagnosticsSnapshot::from_client_config(
            "primary",
            &config,
            GuiConnectionState::Disconnected,
            None,
        );
        assert_eq!(snapshot.credential_display, "***");
        assert_eq!(snapshot.http_connect_listener, None);
        assert_eq!(snapshot.last_error_class, None);
    }

    #[test]
    fn gui_diagnostics_keeps_transport_details_debug_only() {
        let mut config = client_config("u123", SecretString::generate());
        config.mode = Mode::Private;
        config.advanced.experimental_h3 = true;
        let snapshot = GuiDiagnosticsSnapshot::from_client_config(
            "primary",
            &config,
            GuiConnectionState::Connected,
            None,
        );
        assert_eq!(snapshot.policy_mode, Mode::Private);
        assert_eq!(snapshot.transport_status, GuiTransportStatus::Ready);
        assert_eq!(snapshot.transport_debug, None);

        let ordinary_json = serde_json::to_string(&snapshot).unwrap();
        let ordinary_rendered = format!("{snapshot:?} {ordinary_json}").to_ascii_lowercase();
        assert!(!ordinary_rendered.contains("h2"));
        assert!(!ordinary_rendered.contains("h3"));
        assert!(!ordinary_rendered.contains("cooldown"));
        assert!(!ordinary_rendered.contains("experimental"));

        let debug = GuiTransportDebugSnapshot::new(GuiTransportCarrier::H2, true, true);
        let debug_snapshot = snapshot.with_transport_debug(debug);
        assert_eq!(
            debug_snapshot.transport_status,
            GuiTransportStatus::Degraded
        );
        assert_eq!(
            debug_snapshot
                .transport_debug
                .as_ref()
                .unwrap()
                .active_transport,
            GuiTransportCarrier::H2
        );

        let debug_json = serde_json::to_string(&debug_snapshot).unwrap();
        assert!(debug_json.contains("h2"));
        assert!(debug_json.contains("h3_in_cooldown"));
    }

    #[test]
    fn gui_tun_safety_snapshot_requires_runtime_and_product_gates() {
        let runtime_ready = TunRuntimeReadinessSnapshot::current();
        assert!(!runtime_ready.runtime_ready);

        let product_blocked = GuiTunSafetySnapshot::from_readiness(runtime_ready.clone(), false);
        assert!(!product_blocked.runtime_ready);
        assert!(!product_blocked.gui_product_gate_ready);
        assert!(!product_blocked.controls_enabled);
        assert!(!product_blocked.apply_allowed_from_gui);
        assert_eq!(
            product_blocked.control_state,
            GuiTunControlState::DisabledRuntimeNotReady
        );

        let enabled = GuiTunSafetySnapshot::from_readiness(runtime_ready, true);
        assert!(!enabled.controls_enabled);
        assert!(!enabled.apply_allowed_from_gui);
        assert!(!enabled.local_machine_network_mutation_allowed);
        assert_eq!(
            enabled.control_state,
            GuiTunControlState::DisabledRuntimeNotReady
        );
    }

    #[test]
    fn current_gui_runtime_readiness_tracks_deferred_product_work() {
        let snapshot = GuiRuntimeReadinessSnapshot::current();
        assert!(snapshot.core_diagnostics_ready);
        assert!(snapshot.sdk_runtime_baseline_ready);
        assert!(snapshot.debug_redaction_tests_ready);
        assert!(snapshot.ui_scope_decided);
        assert!(snapshot.platform_targets_decided);
        assert!(snapshot.secure_profile_storage_ready);
        assert!(snapshot.service_lifecycle_integration_ready);
        assert!(snapshot.tun_safety_integration_ready);
        assert!(snapshot.ui_smoke_tests_ready);
        assert!(!snapshot.runtime_ready);
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::UiScopeDecisionMissing));
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::PlatformTargetDecisionMissing));
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::SecureProfileStorageMissing));
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::ServiceLifecycleIntegrationMissing));
        assert!(snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::SigningNotarizationMissing));
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::TunSafetyIntegrationMissing));
        assert!(!snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::UiSmokeTestsMissing));
        assert!(snapshot
            .blockers
            .contains(&GuiRuntimeReadinessBlocker::ReleasePackagingMissing));
    }

    #[test]
    fn all_gui_runtime_readiness_inputs_are_required() {
        let ready_inputs = ready_gui_runtime_inputs();
        let ready = GuiRuntimeReadinessSnapshot::from_inputs(ready_inputs);
        assert!(ready.runtime_ready);
        assert!(ready.blockers.is_empty());

        let cases = [
            (
                GuiRuntimeReadinessInputs {
                    core_diagnostics_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::CoreDiagnosticsMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    sdk_runtime_baseline_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::SdkRuntimeBaselineMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    debug_redaction_tests_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::DebugRedactionTestsMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    ui_scope_decided: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::UiScopeDecisionMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    platform_targets_decided: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::PlatformTargetDecisionMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    secure_profile_storage_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::SecureProfileStorageMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    service_lifecycle_integration_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::ServiceLifecycleIntegrationMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    signing_notarization_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::SigningNotarizationMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    tun_safety_integration_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::TunSafetyIntegrationMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    ui_smoke_tests_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::UiSmokeTestsMissing,
            ),
            (
                GuiRuntimeReadinessInputs {
                    release_packaging_ready: false,
                    ..ready_inputs
                },
                GuiRuntimeReadinessBlocker::ReleasePackagingMissing,
            ),
        ];

        for (inputs, blocker) in cases {
            let snapshot = GuiRuntimeReadinessSnapshot::from_inputs(inputs);
            assert!(!snapshot.runtime_ready);
            assert_eq!(snapshot.blockers, vec![blocker]);
        }
    }

    #[test]
    fn ech_diagnostics_reports_disabled_and_unsupported_states() {
        let mut config = client_config("u123", SecretString::generate());
        let disabled = EchDiagnosticsSnapshot::from_client_config(&config);
        assert!(!disabled.requested);
        assert!(!disabled.implementation_supported);
        assert_eq!(disabled.status, EchDiagnosticStatus::Disabled);
        assert!(!disabled.private_mode_plain_sni_blocked);
        assert!(!disabled.readiness.runtime_ready);

        config.advanced.experimental_ech = true;
        let unsupported = EchDiagnosticsSnapshot::from_client_config(&config);
        assert!(unsupported.requested);
        assert!(!unsupported.implementation_supported);
        assert_eq!(unsupported.status, EchDiagnosticStatus::Unsupported);
        assert!(unsupported
            .readiness
            .blockers
            .contains(&crate::ech::EchReadinessBlocker::ServerTlsBackendMissing));
        assert!(unsupported
            .readiness
            .blockers
            .contains(&crate::ech::EchReadinessBlocker::RuntimeConfigRejected));
    }

    #[test]
    fn ech_diagnostics_flags_private_plain_sni_without_advice() {
        let snapshot =
            EchDiagnosticsSnapshot::new(Mode::Private, true, EchFallbackPolicy::AllowPlainSni);
        assert!(snapshot.private_mode_plain_sni_blocked);
        assert_eq!(snapshot.status, EchDiagnosticStatus::Unsupported);

        let rendered = serde_json::to_string(&snapshot).unwrap();
        assert!(rendered.contains("plain_sni"));
        assert!(!rendered.contains("downgrade"));
        assert!(!rendered.contains("weaken"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("Mosaic"));
    }

    #[test]
    fn stealth_diagnostics_report_baseline_and_cdn_fronted_states() {
        let mut config = client_config("u123", SecretString::generate());
        config.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        let baseline = StealthDiagnosticsSnapshot::from_client_config(&config);
        assert_eq!(baseline.tls_fingerprint, TlsFingerprintMode::RustlsDefault);
        assert_eq!(baseline.status, StealthDiagnosticStatus::BaselineRustls);
        assert_eq!(
            baseline.browser_mimicry_supported,
            browser_tls_profile_supported()
        );
        assert!(baseline.active_probe_resistance_required);
        assert!(!baseline.cdn_fronting_enabled);

        config.advanced.experimental_cloudflare_ws = true;
        config.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::WebSocket,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };
        let cdn = StealthDiagnosticsSnapshot::from_client_config(&config);
        assert_eq!(cdn.status, StealthDiagnosticStatus::CdnFronted);
        assert!(cdn.cdn_fronting_enabled);
        assert!(cdn.cdn_tls_terminating_provider_trusted);

        let rendered = serde_json::to_string(&cdn).unwrap();
        assert!(rendered.contains("cdn_fronted"));
        assert!(!rendered.contains("secret"));
    }

    fn client_config(credential_id: &str, secret: SecretString) -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:1080".parse().unwrap(),
                },
                dns: None,
                http_connect: Some(HttpConnectConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:18080".parse().unwrap()),
                }),
            },
            server: ClientServerConfig {
                address: "example.com:443".into(),
                server_name: "example.com".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: credential_id.into(),
                secret,
                ca_cert: None,
                cert_pin: None,
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }

    fn ready_gui_runtime_inputs() -> GuiRuntimeReadinessInputs {
        GuiRuntimeReadinessInputs {
            core_diagnostics_ready: true,
            sdk_runtime_baseline_ready: true,
            debug_redaction_tests_ready: true,
            ui_scope_decided: true,
            platform_targets_decided: true,
            secure_profile_storage_ready: true,
            service_lifecycle_integration_ready: true,
            signing_notarization_ready: true,
            tun_safety_integration_ready: true,
            ui_smoke_tests_ready: true,
            release_packaging_ready: true,
        }
    }
}
