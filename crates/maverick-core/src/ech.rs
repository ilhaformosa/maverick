use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EchReadinessBlocker {
    BuildFeatureDisabled,
    ClientTlsBackendMissing,
    ServerTlsBackendMissing,
    EchConfigSourceMissing,
    ControlledIntegrationMissing,
    RuntimeConfigRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EchReadinessSnapshot {
    pub build_feature_enabled: bool,
    pub rustls_client_api_tracked: bool,
    pub cloudflare_fronted_runtime_smoke_ready: bool,
    pub server_tls_backend_ready: bool,
    pub ech_config_source_ready: bool,
    pub controlled_integration_ready: bool,
    pub runtime_config_accepted: bool,
    pub runtime_ready: bool,
    pub blockers: Vec<EchReadinessBlocker>,
}

impl EchReadinessSnapshot {
    pub fn current() -> Self {
        Self::from_inputs(EchReadinessInputs::current())
    }

    fn from_inputs(inputs: EchReadinessInputs) -> Self {
        let mut blockers = Vec::new();
        if !inputs.build_feature_enabled {
            blockers.push(EchReadinessBlocker::BuildFeatureDisabled);
        }
        if !inputs.rustls_client_api_tracked {
            blockers.push(EchReadinessBlocker::ClientTlsBackendMissing);
        }
        if !inputs.server_tls_backend_ready {
            blockers.push(EchReadinessBlocker::ServerTlsBackendMissing);
        }
        if !inputs.ech_config_source_ready {
            blockers.push(EchReadinessBlocker::EchConfigSourceMissing);
        }
        if !inputs.controlled_integration_ready {
            blockers.push(EchReadinessBlocker::ControlledIntegrationMissing);
        }
        if !inputs.runtime_config_accepted {
            blockers.push(EchReadinessBlocker::RuntimeConfigRejected);
        }

        let runtime_ready = blockers.is_empty();
        Self {
            build_feature_enabled: inputs.build_feature_enabled,
            rustls_client_api_tracked: inputs.rustls_client_api_tracked,
            cloudflare_fronted_runtime_smoke_ready: inputs.cloudflare_fronted_runtime_smoke_ready,
            server_tls_backend_ready: inputs.server_tls_backend_ready,
            ech_config_source_ready: inputs.ech_config_source_ready,
            controlled_integration_ready: inputs.controlled_integration_ready,
            runtime_config_accepted: inputs.runtime_config_accepted,
            runtime_ready,
            blockers,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EchReadinessInputs {
    build_feature_enabled: bool,
    rustls_client_api_tracked: bool,
    cloudflare_fronted_runtime_smoke_ready: bool,
    server_tls_backend_ready: bool,
    ech_config_source_ready: bool,
    controlled_integration_ready: bool,
    runtime_config_accepted: bool,
}

impl EchReadinessInputs {
    fn current() -> Self {
        Self {
            build_feature_enabled: cfg!(feature = "ech"),
            rustls_client_api_tracked: cfg!(feature = "ech"),
            cloudflare_fronted_runtime_smoke_ready: true,
            server_tls_backend_ready: false,
            ech_config_source_ready: false,
            controlled_integration_ready: false,
            runtime_config_accepted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_readiness_is_not_runtime_ready() {
        let snapshot = EchReadinessSnapshot::current();
        assert!(!snapshot.runtime_ready);
        assert!(snapshot.cloudflare_fronted_runtime_smoke_ready);
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::ServerTlsBackendMissing));
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::EchConfigSourceMissing));
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::ControlledIntegrationMissing));
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::RuntimeConfigRejected));

        #[cfg(feature = "ech")]
        {
            assert!(snapshot.build_feature_enabled);
            assert!(snapshot.rustls_client_api_tracked);
            assert!(!snapshot
                .blockers
                .contains(&EchReadinessBlocker::BuildFeatureDisabled));
        }

        #[cfg(not(feature = "ech"))]
        {
            assert!(!snapshot.build_feature_enabled);
            assert!(!snapshot.rustls_client_api_tracked);
            assert!(snapshot
                .blockers
                .contains(&EchReadinessBlocker::BuildFeatureDisabled));
            assert!(snapshot
                .blockers
                .contains(&EchReadinessBlocker::ClientTlsBackendMissing));
        }
    }

    #[test]
    fn all_readiness_inputs_are_required() {
        let ready = EchReadinessSnapshot::from_inputs(EchReadinessInputs {
            build_feature_enabled: true,
            rustls_client_api_tracked: true,
            cloudflare_fronted_runtime_smoke_ready: true,
            server_tls_backend_ready: true,
            ech_config_source_ready: true,
            controlled_integration_ready: true,
            runtime_config_accepted: true,
        });
        assert!(ready.runtime_ready);
        assert!(ready.blockers.is_empty());

        let missing_client_api = EchReadinessSnapshot::from_inputs(EchReadinessInputs {
            rustls_client_api_tracked: false,
            ..EchReadinessInputs {
                build_feature_enabled: true,
                rustls_client_api_tracked: true,
                cloudflare_fronted_runtime_smoke_ready: true,
                server_tls_backend_ready: true,
                ech_config_source_ready: true,
                controlled_integration_ready: true,
                runtime_config_accepted: true,
            }
        });
        assert!(!missing_client_api.runtime_ready);
        assert_eq!(
            missing_client_api.blockers,
            vec![EchReadinessBlocker::ClientTlsBackendMissing]
        );
    }

    #[test]
    fn cloudflare_fronted_smoke_does_not_make_native_runtime_ready() {
        let snapshot = EchReadinessSnapshot::from_inputs(EchReadinessInputs {
            build_feature_enabled: true,
            rustls_client_api_tracked: true,
            cloudflare_fronted_runtime_smoke_ready: true,
            server_tls_backend_ready: false,
            ech_config_source_ready: false,
            controlled_integration_ready: true,
            runtime_config_accepted: false,
        });

        assert!(snapshot.cloudflare_fronted_runtime_smoke_ready);
        assert!(!snapshot.runtime_ready);
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::ServerTlsBackendMissing));
        assert!(snapshot
            .blockers
            .contains(&EchReadinessBlocker::RuntimeConfigRejected));
    }
}
