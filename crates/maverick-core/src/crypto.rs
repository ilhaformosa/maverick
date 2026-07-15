use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::Mode;
use crate::error::{Error, Result};

/// Cryptographic suite identifiers tracked by the v5 agility registry.
///
/// Only `tls13` is accepted by runtime configuration today. Other entries are
/// reserved for future reviewed experiments and are rejected by validation.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSuiteId {
    #[default]
    Tls13,
    #[serde(rename = "hpke_config_v1")]
    HpkeConfigV1,
    #[serde(rename = "noise_xx25519_chacha_poly_v1")]
    NoiseXx25519ChaChaPolyV1,
    #[serde(rename = "ml_kem_768_hybrid_v1")]
    MlKem768HybridV1,
}

impl CryptoSuiteId {
    pub const fn wire_id(self) -> u16 {
        match self {
            Self::Tls13 => 0x0001,
            Self::HpkeConfigV1 => 0x0101,
            Self::NoiseXx25519ChaChaPolyV1 => 0x0201,
            Self::MlKem768HybridV1 => 0x0301,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls13 => "tls13",
            Self::HpkeConfigV1 => "hpke_config_v1",
            Self::NoiseXx25519ChaChaPolyV1 => "noise_xx25519_chacha_poly_v1",
            Self::MlKem768HybridV1 => "ml_kem_768_hybrid_v1",
        }
    }
}

impl fmt::Display for CryptoSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSuiteStatus {
    Stable,
    Experimental,
    Deprecated,
    Removed,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoSuiteDescriptor {
    pub suite: CryptoSuiteId,
    pub status: CryptoSuiteStatus,
    pub feature_gate: Option<&'static str>,
    pub runtime_flag: Option<&'static str>,
    pub transcript_label: &'static str,
    pub test_vector_file: Option<&'static str>,
}

pub const CRYPTO_SUITE_REGISTRY: &[CryptoSuiteDescriptor] = &[
    CryptoSuiteDescriptor {
        suite: CryptoSuiteId::Tls13,
        status: CryptoSuiteStatus::Stable,
        feature_gate: None,
        runtime_flag: None,
        transcript_label: "Maverick TLS 1.3 transport v1",
        test_vector_file: None,
    },
    CryptoSuiteDescriptor {
        suite: CryptoSuiteId::HpkeConfigV1,
        status: CryptoSuiteStatus::Disabled,
        feature_gate: Some("hpke-experimental"),
        runtime_flag: Some("advanced.crypto.allow_experimental"),
        transcript_label: "Maverick HPKE config envelope v1",
        test_vector_file: Some("test-vectors/hpke-config-v1.json"),
    },
    CryptoSuiteDescriptor {
        suite: CryptoSuiteId::NoiseXx25519ChaChaPolyV1,
        status: CryptoSuiteStatus::Disabled,
        feature_gate: Some("noise-experimental"),
        runtime_flag: Some("advanced.crypto.allow_experimental"),
        transcript_label: "Maverick Noise XX25519 ChaChaPoly SHA256 v1",
        test_vector_file: Some("test-vectors/noise-xx25519-chachapoly-v1.json"),
    },
    CryptoSuiteDescriptor {
        suite: CryptoSuiteId::MlKem768HybridV1,
        status: CryptoSuiteStatus::Disabled,
        feature_gate: Some("ml-kem-hybrid"),
        runtime_flag: Some("advanced.crypto.allow_experimental"),
        transcript_label: "Maverick ML-KEM-768 hybrid v1",
        test_vector_file: Some("test-vectors/ml-kem-768-hybrid-v1.json"),
    },
];

pub fn crypto_suite_registry() -> &'static [CryptoSuiteDescriptor] {
    CRYPTO_SUITE_REGISTRY
}

pub fn crypto_suite_descriptor(suite: CryptoSuiteId) -> &'static CryptoSuiteDescriptor {
    CRYPTO_SUITE_REGISTRY
        .iter()
        .find(|descriptor| descriptor.suite == suite)
        .expect("all CryptoSuiteId variants must be registered")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseTransportContext {
    H2,
    H3,
    CloudflareWs,
    NativeNoDomainResearch,
}

impl NoiseTransportContext {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::CloudflareWs => "cloudflare_ws",
            Self::NativeNoDomainResearch => "native_no_domain_research",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NoisePrologueContext {
    pub suite: CryptoSuiteId,
    pub noise_name: &'static str,
    pub maverick_protocol: &'static str,
    pub maverick_protocol_version: u16,
    pub initiator_role: &'static str,
    pub responder_role: &'static str,
    pub transport_context: NoiseTransportContext,
    pub purpose: &'static str,
}

impl NoisePrologueContext {
    pub fn xx25519_chachapoly_v1(transport_context: NoiseTransportContext) -> Self {
        Self {
            suite: CryptoSuiteId::NoiseXx25519ChaChaPolyV1,
            noise_name: "Noise_XX_25519_ChaChaPoly_SHA256",
            maverick_protocol: "maverick-proxy",
            maverick_protocol_version: 1,
            initiator_role: "maverick-client",
            responder_role: "maverick-server",
            transport_context,
            purpose: "experimental-research-runtime",
        }
    }

    pub fn canonical_prologue(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MaverickNoisePrologue");
        encode_prologue_field(&mut out, "encoding", "length-prefixed-fields-v1");
        encode_prologue_field(&mut out, "suite", self.suite.as_str());
        encode_prologue_field(&mut out, "noise_name", self.noise_name);
        encode_prologue_field(&mut out, "maverick_protocol", self.maverick_protocol);
        encode_prologue_field(
            &mut out,
            "maverick_protocol_version",
            &self.maverick_protocol_version.to_string(),
        );
        encode_prologue_field(&mut out, "initiator_role", self.initiator_role);
        encode_prologue_field(&mut out, "responder_role", self.responder_role);
        encode_prologue_field(
            &mut out,
            "transport_context",
            self.transport_context.as_str(),
        );
        encode_prologue_field(&mut out, "purpose", self.purpose);
        out
    }
}

fn encode_prologue_field(out: &mut Vec<u8>, name: &str, value: &str) {
    let name_len = u16::try_from(name.len()).expect("Noise prologue field name fits u16");
    let value_len = u16::try_from(value.len()).expect("Noise prologue field value fits u16");
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CryptoSuiteDiagnostic {
    pub suite: CryptoSuiteId,
    pub status: CryptoSuiteStatus,
    pub offered: bool,
    pub default_enabled: bool,
    pub feature_gate: Option<String>,
    pub runtime_gate: Option<String>,
    pub test_vector_file: Option<String>,
    pub excluded_from_default_security_claims: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CryptoPolicyDiagnostics {
    pub mode: Mode,
    pub default_foundation_present: bool,
    pub stable_mode_experimental_blocked: bool,
    pub require_experimental_without_enabled_suite: bool,
    pub suites: Vec<CryptoSuiteDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseReadinessBlocker {
    BuildFeatureDisabled,
    CandidateImplementationMissing,
    ImplementationVectorsMissing,
    TranscriptTestsMissing,
    DowngradeTestsMissing,
    RuntimeSessionHarnessMissing,
    RuntimeConfigRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NoiseReadinessSnapshot {
    pub build_feature_enabled: bool,
    pub candidate_implementation_selected: bool,
    pub implementation_vectors_present: bool,
    pub transcript_tests_ready: bool,
    pub downgrade_tests_ready: bool,
    pub runtime_session_harness_ready: bool,
    pub runtime_config_accepted: bool,
    pub runtime_ready: bool,
    pub blockers: Vec<NoiseReadinessBlocker>,
}

impl NoiseReadinessSnapshot {
    pub fn current() -> Self {
        Self::from_inputs(NoiseReadinessInputs::current())
    }

    fn from_inputs(inputs: NoiseReadinessInputs) -> Self {
        let mut blockers = Vec::new();
        if !inputs.build_feature_enabled {
            blockers.push(NoiseReadinessBlocker::BuildFeatureDisabled);
        }
        if !inputs.candidate_implementation_selected {
            blockers.push(NoiseReadinessBlocker::CandidateImplementationMissing);
        }
        if !inputs.implementation_vectors_present {
            blockers.push(NoiseReadinessBlocker::ImplementationVectorsMissing);
        }
        if !inputs.transcript_tests_ready {
            blockers.push(NoiseReadinessBlocker::TranscriptTestsMissing);
        }
        if !inputs.downgrade_tests_ready {
            blockers.push(NoiseReadinessBlocker::DowngradeTestsMissing);
        }
        if !inputs.runtime_session_harness_ready {
            blockers.push(NoiseReadinessBlocker::RuntimeSessionHarnessMissing);
        }
        if !inputs.runtime_config_accepted {
            blockers.push(NoiseReadinessBlocker::RuntimeConfigRejected);
        }

        let runtime_ready = blockers.is_empty();
        Self {
            build_feature_enabled: inputs.build_feature_enabled,
            candidate_implementation_selected: inputs.candidate_implementation_selected,
            implementation_vectors_present: inputs.implementation_vectors_present,
            transcript_tests_ready: inputs.transcript_tests_ready,
            downgrade_tests_ready: inputs.downgrade_tests_ready,
            runtime_session_harness_ready: inputs.runtime_session_harness_ready,
            runtime_config_accepted: inputs.runtime_config_accepted,
            runtime_ready,
            blockers,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NoiseReadinessInputs {
    build_feature_enabled: bool,
    candidate_implementation_selected: bool,
    implementation_vectors_present: bool,
    transcript_tests_ready: bool,
    downgrade_tests_ready: bool,
    runtime_session_harness_ready: bool,
    runtime_config_accepted: bool,
}

impl NoiseReadinessInputs {
    fn current() -> Self {
        Self {
            build_feature_enabled: cfg!(feature = "noise-experimental"),
            candidate_implementation_selected: true,
            implementation_vectors_present: true,
            transcript_tests_ready: true,
            downgrade_tests_ready: true,
            runtime_session_harness_ready: cfg!(feature = "noise-experimental"),
            runtime_config_accepted: false,
        }
    }
}

pub fn crypto_policy_diagnostics(
    mode: Mode,
    policy: &CryptoPolicyConfig,
) -> CryptoPolicyDiagnostics {
    let offered: BTreeSet<CryptoSuiteId> = policy.offered_suites.iter().copied().collect();
    let suites = crypto_suite_registry()
        .iter()
        .map(|descriptor| CryptoSuiteDiagnostic {
            suite: descriptor.suite,
            status: descriptor.status,
            offered: offered.contains(&descriptor.suite),
            default_enabled: descriptor.suite == CryptoSuiteId::Tls13
                && descriptor.status == CryptoSuiteStatus::Stable,
            feature_gate: descriptor.feature_gate.map(str::to_owned),
            runtime_gate: descriptor.runtime_flag.map(str::to_owned),
            test_vector_file: descriptor.test_vector_file.map(str::to_owned),
            excluded_from_default_security_claims: descriptor.status != CryptoSuiteStatus::Stable,
        })
        .collect();
    let has_enabled_experimental = policy.offered_suites.iter().any(|suite| {
        let descriptor = crypto_suite_descriptor(*suite);
        descriptor.status == CryptoSuiteStatus::Experimental
    });

    CryptoPolicyDiagnostics {
        mode,
        default_foundation_present: offered.contains(&CryptoSuiteId::Tls13),
        stable_mode_experimental_blocked: mode == Mode::Stable
            && (policy.allow_experimental || policy.require_experimental),
        require_experimental_without_enabled_suite: policy.require_experimental
            && !has_enabled_experimental,
        suites,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CryptoPolicyConfig {
    #[serde(default = "default_crypto_suites")]
    pub offered_suites: Vec<CryptoSuiteId>,
    #[serde(default)]
    pub allow_experimental: bool,
    #[serde(default)]
    pub require_experimental: bool,
}

impl Default for CryptoPolicyConfig {
    fn default() -> Self {
        Self {
            offered_suites: default_crypto_suites(),
            allow_experimental: false,
            require_experimental: false,
        }
    }
}

impl CryptoPolicyConfig {
    pub fn validate(&self, mode: Mode) -> Result<()> {
        if self.offered_suites.is_empty() {
            return Err(Error::Config(
                "advanced.crypto.offered_suites must not be empty".into(),
            ));
        }
        if mode == Mode::Stable && (self.allow_experimental || self.require_experimental) {
            return Err(Error::Config(
                "stable mode refuses advanced.crypto experimental settings".into(),
            ));
        }
        if self.require_experimental && !self.allow_experimental {
            return Err(Error::Config(
                "advanced.crypto.require_experimental requires allow_experimental=true".into(),
            ));
        }

        let mut seen = BTreeSet::new();
        for suite in &self.offered_suites {
            if !seen.insert(*suite) {
                return Err(Error::Config(format!(
                    "advanced.crypto.offered_suites contains duplicate suite {suite}"
                )));
            }
        }
        if !seen.contains(&CryptoSuiteId::Tls13) {
            return Err(Error::Config(
                "advanced.crypto.offered_suites must include tls13".into(),
            ));
        }

        let mut has_experimental = false;
        for suite in &self.offered_suites {
            let descriptor = crypto_suite_descriptor(*suite);
            match descriptor.status {
                CryptoSuiteStatus::Stable => {}
                CryptoSuiteStatus::Experimental => {
                    if !self.allow_experimental {
                        return Err(Error::Config(format!(
                            "advanced.crypto.allow_experimental must be true to offer {suite}"
                        )));
                    }
                    has_experimental = true;
                }
                CryptoSuiteStatus::Deprecated => {
                    return Err(Error::Config(format!(
                        "advanced.crypto.offered_suites contains deprecated suite {suite}"
                    )));
                }
                CryptoSuiteStatus::Removed => {
                    return Err(Error::Config(format!(
                        "advanced.crypto.offered_suites contains removed suite {suite}"
                    )));
                }
                CryptoSuiteStatus::Disabled => {
                    return Err(Error::Config(format!(
                        "advanced.crypto.offered_suites contains disabled suite {suite}"
                    )));
                }
            }
        }
        if self.require_experimental && !has_experimental {
            return Err(Error::Config(
                "advanced.crypto.require_experimental needs at least one enabled experimental suite"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn default_crypto_suites() -> Vec<CryptoSuiteId> {
    vec![CryptoSuiteId::Tls13]
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    use snow::types::{Cipher, Dh, Hash, Random};
    use std::path::Path;

    #[test]
    fn registry_wire_ids_are_unique() {
        let mut ids = BTreeSet::new();
        for descriptor in crypto_suite_registry() {
            assert!(ids.insert(descriptor.suite.wire_id()));
        }
    }

    #[test]
    fn experimental_suites_declare_gates_labels_and_vector_paths() {
        for descriptor in crypto_suite_registry() {
            if descriptor.suite == CryptoSuiteId::Tls13 {
                continue;
            }
            assert_eq!(descriptor.status, CryptoSuiteStatus::Disabled);
            assert!(descriptor.feature_gate.is_some(), "{:?}", descriptor.suite);
            assert!(descriptor.runtime_flag.is_some(), "{:?}", descriptor.suite);
            assert!(
                descriptor.transcript_label.starts_with("Maverick "),
                "{:?}",
                descriptor.suite
            );
            assert!(
                descriptor.transcript_label.ends_with(" v1"),
                "{:?}",
                descriptor.suite
            );
            let vector_file = descriptor
                .test_vector_file
                .expect("experimental suites must declare future KAT files");
            assert!(vector_file.starts_with("test-vectors/"));
            assert!(vector_file.ends_with(".json"));
        }
    }

    #[test]
    fn noise_descriptor_binds_prologue_context() {
        let descriptor = crypto_suite_descriptor(CryptoSuiteId::NoiseXx25519ChaChaPolyV1);
        assert_eq!(descriptor.status, CryptoSuiteStatus::Disabled);
        assert!(descriptor.transcript_label.contains("Maverick Noise"));
        assert!(descriptor.transcript_label.contains("XX25519"));
        assert!(descriptor.transcript_label.contains("ChaChaPoly"));
        assert!(descriptor.transcript_label.contains("SHA256"));
        assert!(descriptor.transcript_label.ends_with(" v1"));
    }

    #[test]
    fn noise_prologue_context_binds_common_roles_transport_and_suite() {
        let h2 = NoisePrologueContext::xx25519_chachapoly_v1(NoiseTransportContext::H2);
        let h3 = NoisePrologueContext::xx25519_chachapoly_v1(NoiseTransportContext::H3);
        assert_eq!(h2.suite, CryptoSuiteId::NoiseXx25519ChaChaPolyV1);
        assert_eq!(h2.noise_name, "Noise_XX_25519_ChaChaPoly_SHA256");
        assert_eq!(h2.initiator_role, "maverick-client");
        assert_eq!(h2.responder_role, "maverick-server");
        assert_ne!(h2.canonical_prologue(), h3.canonical_prologue());

        let prologue = h2.canonical_prologue();
        assert!(contains_bytes(&prologue, b"MaverickNoisePrologue"));
        assert!(contains_bytes(&prologue, b"noise_xx25519_chacha_poly_v1"));
        assert!(contains_bytes(
            &prologue,
            b"Noise_XX_25519_ChaChaPoly_SHA256"
        ));
        assert!(contains_bytes(&prologue, b"maverick-client"));
        assert!(contains_bytes(&prologue, b"maverick-server"));
        assert!(contains_bytes(&prologue, b"h2"));
        assert!(!contains_bytes(&prologue, b"Mosaic"));
    }

    #[test]
    fn current_noise_readiness_is_not_runtime_ready() {
        let snapshot = NoiseReadinessSnapshot::current();
        assert!(!snapshot.runtime_ready);
        assert!(snapshot.candidate_implementation_selected);
        assert!(snapshot.implementation_vectors_present);
        assert!(snapshot.transcript_tests_ready);
        assert!(snapshot.downgrade_tests_ready);
        assert!(!snapshot
            .blockers
            .contains(&NoiseReadinessBlocker::CandidateImplementationMissing));
        assert!(!snapshot
            .blockers
            .contains(&NoiseReadinessBlocker::ImplementationVectorsMissing));
        assert!(!snapshot
            .blockers
            .contains(&NoiseReadinessBlocker::TranscriptTestsMissing));
        assert!(!snapshot
            .blockers
            .contains(&NoiseReadinessBlocker::DowngradeTestsMissing));
        #[cfg(feature = "noise-experimental")]
        {
            assert!(snapshot.runtime_session_harness_ready);
            assert!(!snapshot
                .blockers
                .contains(&NoiseReadinessBlocker::RuntimeSessionHarnessMissing));
        }
        #[cfg(not(feature = "noise-experimental"))]
        {
            assert!(!snapshot.runtime_session_harness_ready);
            assert!(snapshot
                .blockers
                .contains(&NoiseReadinessBlocker::RuntimeSessionHarnessMissing));
        }
        assert!(snapshot
            .blockers
            .contains(&NoiseReadinessBlocker::RuntimeConfigRejected));

        #[cfg(feature = "noise-experimental")]
        {
            assert!(snapshot.build_feature_enabled);
            assert!(!snapshot
                .blockers
                .contains(&NoiseReadinessBlocker::BuildFeatureDisabled));
        }

        #[cfg(not(feature = "noise-experimental"))]
        {
            assert!(!snapshot.build_feature_enabled);
            assert!(snapshot
                .blockers
                .contains(&NoiseReadinessBlocker::BuildFeatureDisabled));
        }
    }

    #[test]
    fn all_noise_readiness_inputs_are_required() {
        let ready = NoiseReadinessSnapshot::from_inputs(NoiseReadinessInputs {
            build_feature_enabled: true,
            candidate_implementation_selected: true,
            implementation_vectors_present: true,
            transcript_tests_ready: true,
            downgrade_tests_ready: true,
            runtime_session_harness_ready: true,
            runtime_config_accepted: true,
        });
        assert!(ready.runtime_ready);
        assert!(ready.blockers.is_empty());

        let missing_vectors = NoiseReadinessSnapshot::from_inputs(NoiseReadinessInputs {
            build_feature_enabled: true,
            candidate_implementation_selected: true,
            implementation_vectors_present: false,
            transcript_tests_ready: true,
            downgrade_tests_ready: true,
            runtime_session_harness_ready: true,
            runtime_config_accepted: true,
        });
        assert!(!missing_vectors.runtime_ready);
        assert_eq!(
            missing_vectors.blockers,
            vec![NoiseReadinessBlocker::ImplementationVectorsMissing]
        );
    }

    #[test]
    fn experimental_vector_files_exist_and_are_source_tracked() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for descriptor in crypto_suite_registry() {
            let Some(vector_file) = descriptor.test_vector_file else {
                continue;
            };
            let path = repo_root.join(vector_file);
            let input = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            let json: serde_json::Value = serde_json::from_str(&input)
                .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
            assert_eq!(json["suite"].as_str(), Some(descriptor.suite.as_str()));
            let status = json["status"].as_str().expect("vector status");
            assert!(
                status.ends_with("_no_runtime") || status.starts_with("metadata_only"),
                "{status}"
            );
            assert!(
                json.get("source").is_some() || json.get("sources").is_some(),
                "{} must record official or upstream source metadata",
                vector_file
            );
            let cases = json["cases"].as_array().expect("vector cases");
            if descriptor.suite != CryptoSuiteId::NoiseXx25519ChaChaPolyV1 {
                assert!(
                    !cases.is_empty(),
                    "{vector_file} must include KAT subset cases"
                );
            }
        }
    }

    #[test]
    fn noise_metadata_vector_matches_canonical_prologue_context() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = repo_root.join("test-vectors/noise-xx25519-chachapoly-v1.json");
        let input = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let json: serde_json::Value = serde_json::from_str(&input)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        let context = &json["prologue_context"];
        assert_eq!(
            context["encoding"].as_str(),
            Some("length-prefixed-fields-v1")
        );
        assert_eq!(
            context["noise_name"].as_str(),
            Some("Noise_XX_25519_ChaChaPoly_SHA256")
        );
        assert_eq!(context["initiator_role"].as_str(), Some("maverick-client"));
        assert_eq!(context["responder_role"].as_str(), Some("maverick-server"));
        assert_eq!(context["transport_context"].as_str(), Some("h2"));
        let expected = hex_encode(
            &NoisePrologueContext::xx25519_chachapoly_v1(NoiseTransportContext::H2)
                .canonical_prologue(),
        );
        assert_eq!(
            context["canonical_prologue_hex"].as_str(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn noise_snow_vector_matches_checked_in_transcript() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = repo_root.join("test-vectors/noise-xx25519-chachapoly-v1.json");
        let input = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let json: serde_json::Value = serde_json::from_str(&input)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        let actual = snow_noise_xx_h2_case_json();
        let cases = json["cases"].as_array().expect("vector cases");
        assert!(!cases.is_empty(), "Noise vector cases must not be empty");
        let expected = cases
            .iter()
            .find(|case| case["id"] == actual["id"])
            .expect("checked-in Snow Noise XX vector case");
        assert_eq!(expected, &actual);
    }

    #[test]
    fn noise_runtime_config_stays_rejected_despite_vector_evidence() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![
                CryptoSuiteId::Tls13,
                CryptoSuiteId::NoiseXx25519ChaChaPolyV1,
            ],
            allow_experimental: true,
            require_experimental: true,
        };

        let err = policy.validate(Mode::Private).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("disabled suite"));
        assert!(rendered.contains("noise_xx25519_chacha_poly_v1"));
    }

    #[test]
    fn default_policy_allows_tls13_only() {
        let policy = CryptoPolicyConfig::default();
        assert_eq!(policy.offered_suites, vec![CryptoSuiteId::Tls13]);
        policy.validate(Mode::Auto).unwrap();
        policy.validate(Mode::Stable).unwrap();
        policy.validate(Mode::Private).unwrap();
    }

    #[test]
    fn crypto_policy_diagnostics_reports_default_foundation() {
        let policy = CryptoPolicyConfig::default();
        let report = crypto_policy_diagnostics(Mode::Auto, &policy);

        assert!(report.default_foundation_present);
        assert!(!report.stable_mode_experimental_blocked);
        assert!(!report.require_experimental_without_enabled_suite);
        let tls = report
            .suites
            .iter()
            .find(|suite| suite.suite == CryptoSuiteId::Tls13)
            .unwrap();
        assert!(tls.offered);
        assert!(tls.default_enabled);
        assert!(!tls.excluded_from_default_security_claims);
        assert_eq!(tls.feature_gate, None);
        assert_eq!(tls.runtime_gate, None);
    }

    #[test]
    fn crypto_policy_diagnostics_marks_disabled_experiments_as_excluded() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![CryptoSuiteId::Tls13, CryptoSuiteId::MlKem768HybridV1],
            allow_experimental: true,
            require_experimental: true,
        };
        let report = crypto_policy_diagnostics(Mode::Private, &policy);
        assert!(report.require_experimental_without_enabled_suite);

        let ml_kem = report
            .suites
            .iter()
            .find(|suite| suite.suite == CryptoSuiteId::MlKem768HybridV1)
            .unwrap();
        assert!(ml_kem.offered);
        assert_eq!(ml_kem.status, CryptoSuiteStatus::Disabled);
        assert_eq!(ml_kem.feature_gate.as_deref(), Some("ml-kem-hybrid"));
        assert_eq!(
            ml_kem.runtime_gate.as_deref(),
            Some("advanced.crypto.allow_experimental")
        );
        assert!(ml_kem.excluded_from_default_security_claims);
        assert!(!ml_kem.default_enabled);
    }

    #[test]
    fn crypto_policy_diagnostics_flags_stable_experimental_policy_without_advice() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![CryptoSuiteId::Tls13],
            allow_experimental: true,
            require_experimental: false,
        };
        let report = crypto_policy_diagnostics(Mode::Stable, &policy);
        assert!(report.stable_mode_experimental_blocked);

        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains("downgrade"));
        assert!(!rendered.contains("disable_tls"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains("Mosaic"));
    }

    #[test]
    fn policy_requires_tls13_foundation() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![CryptoSuiteId::HpkeConfigV1],
            allow_experimental: true,
            require_experimental: false,
        };
        let err = policy.validate(Mode::Auto).unwrap_err();
        assert!(err.to_string().contains("include tls13"));
    }

    #[test]
    fn stable_mode_rejects_experimental_policy() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![CryptoSuiteId::Tls13],
            allow_experimental: true,
            require_experimental: false,
        };
        let err = policy.validate(Mode::Stable).unwrap_err();
        assert!(err.to_string().contains("stable mode"));
    }

    #[test]
    fn duplicate_suites_are_rejected() {
        let policy = CryptoPolicyConfig {
            offered_suites: vec![CryptoSuiteId::Tls13, CryptoSuiteId::Tls13],
            allow_experimental: false,
            require_experimental: false,
        };
        let err = policy.validate(Mode::Auto).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    fn snow_noise_xx_h2_case_json() -> serde_json::Value {
        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .expect("Noise params");
        let prologue = NoisePrologueContext::xx25519_chachapoly_v1(NoiseTransportContext::H2)
            .canonical_prologue();
        let initiator_static_private = sequential_key(0x00);
        let responder_static_private = sequential_key(0x20);
        let initiator_rng_seed = 7;
        let responder_rng_seed = 70;
        let mut initiator = snow::Builder::with_resolver(
            params.clone(),
            Box::new(DeterministicNoiseResolver::new(initiator_rng_seed)),
        )
        .prologue(&prologue)
        .unwrap()
        .local_private_key(&initiator_static_private)
        .unwrap()
        .build_initiator()
        .unwrap();
        let mut responder = snow::Builder::with_resolver(
            params,
            Box::new(DeterministicNoiseResolver::new(responder_rng_seed)),
        )
        .prologue(&prologue)
        .unwrap()
        .local_private_key(&responder_static_private)
        .unwrap()
        .build_responder()
        .unwrap();

        let mut read_buf = [0u8; 1024];
        let mut message_1 = [0u8; 1024];
        let mut message_2 = [0u8; 1024];
        let mut message_3 = [0u8; 1024];

        let message_1_len = initiator.write_message(&[], &mut message_1).unwrap();
        let responder_payload_1_len = responder
            .read_message(&message_1[..message_1_len], &mut read_buf)
            .unwrap();
        assert_eq!(responder_payload_1_len, 0);

        let message_2_len = responder.write_message(&[], &mut message_2).unwrap();
        let initiator_payload_2_len = initiator
            .read_message(&message_2[..message_2_len], &mut read_buf)
            .unwrap();
        assert_eq!(initiator_payload_2_len, 0);
        let initiator_view_remote_static = initiator.get_remote_static().unwrap().to_vec();

        let message_3_len = initiator.write_message(&[], &mut message_3).unwrap();
        let responder_payload_3_len = responder
            .read_message(&message_3[..message_3_len], &mut read_buf)
            .unwrap();
        assert_eq!(responder_payload_3_len, 0);
        let responder_view_remote_static = responder.get_remote_static().unwrap().to_vec();

        let mut initiator_transport = initiator.into_transport_mode().unwrap();
        let mut responder_transport = responder.into_transport_mode().unwrap();
        let plaintext = b"maverick-noise-transport-smoke";
        let mut transport_ciphertext = [0u8; 1024];
        let mut transport_plaintext = [0u8; 1024];
        let transport_ciphertext_len = initiator_transport
            .write_message(plaintext, &mut transport_ciphertext)
            .unwrap();
        let transport_plaintext_len = responder_transport
            .read_message(
                &transport_ciphertext[..transport_ciphertext_len],
                &mut transport_plaintext,
            )
            .unwrap();
        assert_eq!(&transport_plaintext[..transport_plaintext_len], plaintext);

        serde_json::json!({
            "id": "snow_xx25519_chachapoly_sha256_h2_empty_payloads_v1",
            "implementation": {
                "name": "snow",
                "version": "0.10.0",
                "crate": "https://crates.io/crates/snow/0.10.0",
                "docs": "https://docs.rs/snow/",
                "repository": "https://github.com/mcginty/snow",
                "license": "Apache-2.0 OR MIT",
                "formal_human_review": "not_performed"
            },
            "noise_name": "Noise_XX_25519_ChaChaPoly_SHA256",
            "transport_context": "h2",
            "deterministic_rng": {
                "resolver": "maverick_test_counting_rng_v1",
                "initiator_seed": initiator_rng_seed,
                "responder_seed": responder_rng_seed
            },
            "static_private_keys": {
                "initiator_hex": hex_encode(&initiator_static_private),
                "responder_hex": hex_encode(&responder_static_private)
            },
            "remote_static_public_keys": {
                "initiator_view_hex": hex_encode(&initiator_view_remote_static),
                "responder_view_hex": hex_encode(&responder_view_remote_static)
            },
            "handshake_messages": [
                {
                    "direction": "initiator_to_responder",
                    "tokens": "e",
                    "payload_hex": "",
                    "message_hex": hex_encode(&message_1[..message_1_len])
                },
                {
                    "direction": "responder_to_initiator",
                    "tokens": "e_ee_s_es",
                    "payload_hex": "",
                    "message_hex": hex_encode(&message_2[..message_2_len])
                },
                {
                    "direction": "initiator_to_responder",
                    "tokens": "s_se",
                    "payload_hex": "",
                    "message_hex": hex_encode(&message_3[..message_3_len])
                }
            ],
            "transport_smoke": {
                "initiator_to_responder_plaintext_hex": hex_encode(plaintext),
                "initiator_to_responder_ciphertext_hex": hex_encode(
                    &transport_ciphertext[..transport_ciphertext_len]
                ),
                "responder_decrypted_hex": hex_encode(
                    &transport_plaintext[..transport_plaintext_len]
                )
            }
        })
    }

    struct CountingNoiseRng(u64);

    impl Random for CountingNoiseRng {
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), snow::Error> {
            let mut offset = 0;
            while offset < dest.len() {
                self.0 += 1;
                let bytes = self.0.to_le_bytes();
                let take = (dest.len() - offset).min(bytes.len());
                dest[offset..offset + take].copy_from_slice(&bytes[..take]);
                offset += take;
            }
            Ok(())
        }
    }

    struct DeterministicNoiseResolver {
        rng_seed: u64,
        parent: DefaultResolver,
    }

    impl DeterministicNoiseResolver {
        fn new(rng_seed: u64) -> Self {
            Self {
                rng_seed,
                parent: DefaultResolver,
            }
        }
    }

    impl CryptoResolver for DeterministicNoiseResolver {
        fn resolve_rng(&self) -> Option<Box<dyn Random>> {
            Some(Box::new(CountingNoiseRng(self.rng_seed)))
        }

        fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
            self.parent.resolve_dh(choice)
        }

        fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
            self.parent.resolve_hash(choice)
        }

        fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
            self.parent.resolve_cipher(choice)
        }
    }

    fn sequential_key(start: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (offset, byte) in key.iter_mut().enumerate() {
            *byte = start + u8::try_from(offset).unwrap();
        }
        key
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
