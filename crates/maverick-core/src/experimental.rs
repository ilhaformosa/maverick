use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExperimentalTrackId {
    H3QuicCarrier,
    CloudflareFrontedWsCarrier,
    WebTransportCarrier,
    Ech,
    HpkeConfigEnvelope,
    NoiseNativeMode,
    MlKemHybrid,
    BlindedCredentialLookup,
    NativeNoDomainMode,
    MultiHopResearch,
    PluginSystem,
    ProductTunRuntime,
}

impl ExperimentalTrackId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H3QuicCarrier => "h3_quic_carrier",
            Self::CloudflareFrontedWsCarrier => "cloudflare_fronted_ws_carrier",
            Self::WebTransportCarrier => "webtransport_carrier",
            Self::Ech => "ech",
            Self::HpkeConfigEnvelope => "hpke_config_envelope",
            Self::NoiseNativeMode => "noise_native_mode",
            Self::MlKemHybrid => "ml_kem_hybrid",
            Self::BlindedCredentialLookup => "blinded_credential_lookup",
            Self::NativeNoDomainMode => "native_no_domain_mode",
            Self::MultiHopResearch => "multi_hop_research",
            Self::PluginSystem => "plugin_system",
            Self::ProductTunRuntime => "product_tun_runtime",
        }
    }
}

impl fmt::Display for ExperimentalTrackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalTrackStatus {
    RuntimeExperimental,
    ConfigGateOnly,
    DisabledRegistryEntry,
    ResearchOnly,
}

impl ExperimentalTrackStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeExperimental => "runtime_experimental",
            Self::ConfigGateOnly => "config_gate_only",
            Self::DisabledRegistryEntry => "disabled_registry_entry",
            Self::ResearchOnly => "research_only",
        }
    }
}

impl fmt::Display for ExperimentalTrackStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalTrackDescriptor {
    pub track: ExperimentalTrackId,
    pub title: &'static str,
    pub status: ExperimentalTrackStatus,
    pub build_gate: Option<&'static str>,
    pub runtime_gate: Option<&'static str>,
    pub default_enabled: bool,
    pub requires_external_test_host: bool,
    pub no_default_security_claim: bool,
}

pub const EXPERIMENTAL_TRACK_REGISTRY: &[ExperimentalTrackDescriptor] = &[
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::H3QuicCarrier,
        title: "H3/QUIC carrier",
        status: ExperimentalTrackStatus::RuntimeExperimental,
        build_gate: Some("h3"),
        runtime_gate: Some("advanced.experimental_h3"),
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::CloudflareFrontedWsCarrier,
        title: "Cloudflare-fronted WebSocket carrier",
        status: ExperimentalTrackStatus::RuntimeExperimental,
        build_gate: None,
        runtime_gate: Some("advanced.stealth.cdn_fronting.enabled"),
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::WebTransportCarrier,
        title: "WebTransport-like carrier",
        status: ExperimentalTrackStatus::ResearchOnly,
        build_gate: Some("webtransport-experimental"),
        runtime_gate: None,
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::Ech,
        title: "Encrypted ClientHello",
        status: ExperimentalTrackStatus::ConfigGateOnly,
        build_gate: Some("ech"),
        runtime_gate: Some("advanced.experimental_ech"),
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::HpkeConfigEnvelope,
        title: "HPKE config envelope",
        status: ExperimentalTrackStatus::DisabledRegistryEntry,
        build_gate: Some("hpke-experimental"),
        runtime_gate: Some("advanced.crypto.allow_experimental"),
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::NoiseNativeMode,
        title: "Noise native mode",
        status: ExperimentalTrackStatus::DisabledRegistryEntry,
        build_gate: Some("noise-experimental"),
        runtime_gate: Some("advanced.crypto.allow_experimental"),
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::MlKemHybrid,
        title: "ML-KEM hybrid",
        status: ExperimentalTrackStatus::DisabledRegistryEntry,
        build_gate: Some("ml-kem-hybrid"),
        runtime_gate: Some("advanced.crypto.allow_experimental"),
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::BlindedCredentialLookup,
        title: "Blinded credential lookup",
        status: ExperimentalTrackStatus::ResearchOnly,
        build_gate: Some("blinded-lookup-experimental"),
        runtime_gate: None,
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::NativeNoDomainMode,
        title: "Native no-domain mode",
        status: ExperimentalTrackStatus::ResearchOnly,
        build_gate: Some("no-domain-experimental"),
        runtime_gate: None,
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::MultiHopResearch,
        title: "Multi-hop research",
        status: ExperimentalTrackStatus::ResearchOnly,
        build_gate: None,
        runtime_gate: None,
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::PluginSystem,
        title: "Plugin system outside core protocol",
        status: ExperimentalTrackStatus::ResearchOnly,
        build_gate: None,
        runtime_gate: None,
        default_enabled: false,
        requires_external_test_host: false,
        no_default_security_claim: true,
    },
    ExperimentalTrackDescriptor {
        track: ExperimentalTrackId::ProductTunRuntime,
        title: "Product TUN packet runtime",
        status: ExperimentalTrackStatus::RuntimeExperimental,
        build_gate: Some("tun-runtime"),
        runtime_gate: Some("advanced.experimental_tun"),
        default_enabled: false,
        requires_external_test_host: true,
        no_default_security_claim: true,
    },
];

pub fn experimental_track_registry() -> &'static [ExperimentalTrackDescriptor] {
    EXPERIMENTAL_TRACK_REGISTRY
}

pub fn experimental_track_descriptor(
    track: ExperimentalTrackId,
) -> &'static ExperimentalTrackDescriptor {
    EXPERIMENTAL_TRACK_REGISTRY
        .iter()
        .find(|descriptor| descriptor.track == track)
        .expect("all ExperimentalTrackId variants must be registered")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_track_ids_are_unique() {
        let mut ids = BTreeSet::new();
        for descriptor in experimental_track_registry() {
            assert!(ids.insert(descriptor.track));
        }
    }

    #[test]
    fn all_tracks_are_default_off_and_excluded_from_default_claims() {
        for descriptor in experimental_track_registry() {
            assert!(!descriptor.default_enabled, "{:?}", descriptor.track);
            assert!(
                descriptor.no_default_security_claim,
                "{:?}",
                descriptor.track
            );
        }
    }

    #[test]
    fn runtime_or_config_gated_tracks_have_explicit_gates() {
        for descriptor in experimental_track_registry() {
            match descriptor.status {
                ExperimentalTrackStatus::RuntimeExperimental => {
                    assert!(descriptor.runtime_gate.is_some(), "{:?}", descriptor.track);
                }
                ExperimentalTrackStatus::ConfigGateOnly
                | ExperimentalTrackStatus::DisabledRegistryEntry => {
                    assert!(descriptor.build_gate.is_some(), "{:?}", descriptor.track);
                    assert!(descriptor.runtime_gate.is_some(), "{:?}", descriptor.track);
                }
                ExperimentalTrackStatus::ResearchOnly => {}
            }
        }
    }

    #[test]
    fn host_sensitive_tracks_are_marked_for_external_test_hosts() {
        for track in [
            ExperimentalTrackId::Ech,
            ExperimentalTrackId::CloudflareFrontedWsCarrier,
            ExperimentalTrackId::NativeNoDomainMode,
            ExperimentalTrackId::MultiHopResearch,
            ExperimentalTrackId::WebTransportCarrier,
            ExperimentalTrackId::ProductTunRuntime,
        ] {
            assert!(experimental_track_descriptor(track).requires_external_test_host);
        }
    }

    #[test]
    fn local_only_runtime_tracks_are_explicitly_bounded() {
        let runtime_tracks: Vec<_> = experimental_track_registry()
            .iter()
            .filter(|descriptor| {
                descriptor.status == ExperimentalTrackStatus::RuntimeExperimental
                    && !descriptor.requires_external_test_host
            })
            .map(|descriptor| descriptor.track)
            .collect();
        assert_eq!(runtime_tracks, vec![ExperimentalTrackId::H3QuicCarrier]);
    }

    #[test]
    fn blinded_lookup_remains_research_only_without_runtime_gate() {
        let descriptor =
            experimental_track_descriptor(ExperimentalTrackId::BlindedCredentialLookup);
        assert_eq!(descriptor.status, ExperimentalTrackStatus::ResearchOnly);
        assert_eq!(descriptor.build_gate, Some("blinded-lookup-experimental"));
        assert_eq!(descriptor.runtime_gate, None);
        assert!(!descriptor.default_enabled);
    }
}
