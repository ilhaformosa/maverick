use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use bytes::Bytes;
use maverick_core::auth::TlsChannelBinding;
use maverick_core::config::v2::{project_v1_client_policy, TransportStrategy};
use maverick_core::{ClientConfig, GuiTransportCarrier, GuiTransportDebugSnapshot};

use crate::h2_transport;

pub struct H2TunnelRequestSender {
    pub sender: h2::client::SendRequest<Bytes>,
    pub channel_binding: Option<TlsChannelBinding>,
}

pub struct CloudflareWsTunnel {
    pub stream: crate::ws_transport::WsClientStream,
    pub channel_binding: Option<TlsChannelBinding>,
}

pub enum TunnelRequestSender {
    H2(H2TunnelRequestSender),
    CloudflareWs(Box<CloudflareWsTunnel>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    H2,
    CloudflareWs,
    /// Compatibility shape only; no current implementation is installed.
    H3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefaultTransportProvenance {
    ProjectedV2Policy,
    LegacyV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DefaultTransportDecision {
    kind: TransportKind,
    provenance: DefaultTransportProvenance,
}

impl DefaultTransportDecision {
    fn kind(self) -> TransportKind {
        match self.provenance {
            DefaultTransportProvenance::ProjectedV2Policy
            | DefaultTransportProvenance::LegacyV1 => self.kind,
        }
    }
}

pub trait TunnelTransport: Send + Sync {
    fn kind(&self) -> TransportKind;

    fn connect<'a>(
        &'a self,
        config: &'a ClientConfig,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelRequestSender>> + Send + 'a>>;
}

#[derive(Debug, Default)]
pub struct H2Transport;

impl TunnelTransport for H2Transport {
    fn kind(&self) -> TransportKind {
        TransportKind::H2
    }

    fn connect<'a>(
        &'a self,
        config: &'a ClientConfig,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelRequestSender>> + Send + 'a>> {
        Box::pin(async move {
            Ok(TunnelRequestSender::H2(
                h2_transport::connect(config).await?,
            ))
        })
    }
}

pub fn default_transport_kind(config: &ClientConfig) -> TransportKind {
    default_transport_decision(config).kind()
}

fn default_transport_decision(config: &ClientConfig) -> DefaultTransportDecision {
    if project_v1_client_policy(config).is_ok_and(|projection| {
        matches!(
            projection.policy().transport_strategy(),
            TransportStrategy::H2
        )
    }) {
        return DefaultTransportDecision {
            kind: TransportKind::H2,
            provenance: DefaultTransportProvenance::ProjectedV2Policy,
        };
    }

    DefaultTransportDecision {
        kind: legacy_default_transport_kind(config),
        provenance: DefaultTransportProvenance::LegacyV1,
    }
}

fn legacy_default_transport_kind(config: &ClientConfig) -> TransportKind {
    if config.advanced.cloudflare_ws_enabled() {
        return TransportKind::CloudflareWs;
    }
    TransportKind::H2
}

pub fn transport_debug_snapshot(config: &ClientConfig) -> GuiTransportDebugSnapshot {
    if config.version == 1 && config.advanced.experimental_h3 {
        return GuiTransportDebugSnapshot::new(GuiTransportCarrier::H2, false, false);
    }
    GuiTransportDebugSnapshot::new(
        gui_transport_carrier(default_transport_kind(config)),
        false,
        false,
    )
}

pub async fn connect(config: &ClientConfig) -> Result<TunnelRequestSender> {
    crate::reject_retired_v1_h3(config)?;
    match default_transport_kind(config) {
        TransportKind::H2 => H2Transport.connect(config).await,
        TransportKind::CloudflareWs => Ok(TunnelRequestSender::CloudflareWs(Box::new(
            crate::ws_transport::connect(config).await?,
        ))),
        TransportKind::H3 => anyhow::bail!("H3 transport implementation is unavailable"),
    }
}

fn gui_transport_carrier(kind: TransportKind) -> GuiTransportCarrier {
    match kind {
        TransportKind::H2 => GuiTransportCarrier::H2,
        TransportKind::CloudflareWs => GuiTransportCarrier::CloudflareWs,
        TransportKind::H3 => GuiTransportCarrier::H3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        AuthChannelBindingConfig, CdnFrontingCarrier, CdnFrontingConfig, ClientAdvancedConfig,
        ClientAuthConfig, ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
        TlsFingerprintMode,
    };
    use maverick_core::{ClientConfig, GuiTransportCarrier, Mode, SecretString};

    const SECRET: &str = "mv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PRIVATE_MARKER: &str = "SYNTHETIC_PRIVATE_MARKER_T012B1";

    #[test]
    fn default_transport_is_h2() {
        let transport = H2Transport;
        assert_eq!(transport.kind(), TransportKind::H2);
    }

    #[test]
    fn omitted_and_explicit_auto_use_projected_v2_h2() {
        for config in [yaml_client(None), yaml_client(Some("auto"))] {
            assert_eq!(
                default_transport_decision(&config),
                DefaultTransportDecision {
                    kind: TransportKind::H2,
                    provenance: DefaultTransportProvenance::ProjectedV2Policy,
                }
            );
            assert_eq!(default_transport_kind(&config), TransportKind::H2);
            assert_eq!(
                transport_debug_snapshot(&config).active_transport,
                GuiTransportCarrier::H2
            );
        }
    }

    #[test]
    fn supported_non_policy_fields_keep_projected_v2_h2() {
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
            let mut config = client_config();
            config.auth.channel_binding = channel_binding;
            config.validate().unwrap();
            assert_projected_h2(&config);
        }

        let mut config = client_config();
        config.advanced.shaping.max_padding_bytes_per_frame = 7;
        config.advanced.shaping.max_overhead_ratio = 0.5;
        config.advanced.shaping.max_delay_ms = 999;
        config.advanced.shaping.max_batch_bytes = 17;
        config.advanced.shaping.cover_traffic_window_ms = 42;
        config.advanced.padding = "legacy-policy-value".into();
        config.validate().unwrap();
        assert_projected_h2(&config);
    }

    #[test]
    fn stable_websocket_fronting_and_shaping_keep_legacy_selection() {
        let mut stable = client_config();
        stable.mode = Mode::Stable;
        stable.validate().unwrap();
        assert_legacy_selection(&stable);

        let mut websocket = client_config();
        websocket.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        websocket.advanced.experimental_cloudflare_ws = true;
        websocket.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::WebSocket,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };
        websocket.validate().unwrap();
        assert_legacy_selection(&websocket);

        let mut fronted_websocket = client_config();
        fronted_websocket.advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
        fronted_websocket.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::WebSocket,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };
        fronted_websocket.validate().unwrap();
        assert_legacy_selection(&fronted_websocket);

        let mut fronted_h2 = client_config();
        fronted_h2.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::H2,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };
        fronted_h2.validate().unwrap();
        assert_legacy_selection(&fronted_h2);

        let mut shaping = client_config();
        shaping.advanced.shaping.enabled = true;
        shaping.validate().unwrap();
        assert_legacy_selection(&shaping);
    }

    #[cfg(all(
        feature = "browser-tls",
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn valid_private_mode_keeps_legacy_selection() {
        let mut config = client_config();
        config.mode = Mode::Private;
        config.validate().unwrap();
        assert_legacy_selection(&config);
    }

    #[test]
    fn invalid_public_config_falls_back_without_copying_values() {
        let mut config = client_config();
        config.version = 2;
        config.server.address = format!("{PRIVATE_MARKER}:443");
        config.server.server_name = PRIVATE_MARKER.into();

        let decision = default_transport_decision(&config);
        assert_eq!(decision.kind, legacy_default_transport_kind(&config));
        assert_eq!(decision.provenance, DefaultTransportProvenance::LegacyV1);
        assert!(!format!("{decision:?}").contains(PRIVATE_MARKER));
    }

    #[test]
    fn cloudflare_ws_transport_is_explicit_only() {
        let mut config = client_config();
        assert_eq!(default_transport_kind(&config), TransportKind::H2);

        config.advanced.experimental_cloudflare_ws = true;
        assert_eq!(default_transport_kind(&config), TransportKind::CloudflareWs);
        assert_eq!(
            transport_debug_snapshot(&config).active_transport,
            GuiTransportCarrier::CloudflareWs
        );
    }

    #[test]
    fn cdn_fronting_selects_cloudflare_ws_transport() {
        let mut config = client_config();
        config.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::WebSocket,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };

        assert_eq!(default_transport_kind(&config), TransportKind::CloudflareWs);
        assert_eq!(
            transport_debug_snapshot(&config).active_transport,
            GuiTransportCarrier::CloudflareWs
        );
    }

    #[test]
    fn cdn_fronted_h2_keeps_h2_transport() {
        let mut config = client_config();
        config.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            carrier: CdnFrontingCarrier::H2,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };

        assert_eq!(default_transport_kind(&config), TransportKind::H2);
        assert_eq!(
            transport_debug_snapshot(&config).active_transport,
            GuiTransportCarrier::H2
        );
    }

    #[test]
    fn transport_debug_snapshot_forces_retired_h3_to_h2_even_with_websocket() {
        let mut config = client_config();
        config.mode = Mode::Auto;
        config.advanced.experimental_h3 = true;
        config.advanced.experimental_cloudflare_ws = true;
        let snapshot = transport_debug_snapshot(&config);

        assert_eq!(snapshot.active_transport, GuiTransportCarrier::H2);
        assert!(!snapshot.h3_in_cooldown);
        assert!(!snapshot.h3_candidate_enabled);
    }

    #[tokio::test]
    async fn retired_v1_h3_is_rejected_before_transport_io() {
        let mut config = client_config();
        config.server.address = "127.0.0.1:1".into();
        config.server.server_name = "localhost".into();
        config.advanced.connect_timeout_ms = 1;
        config.advanced.experimental_h3 = true;

        let error = match connect(&config).await {
            Ok(_) => panic!("retired H3 config unexpectedly connected"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "configuration error: advanced.experimental_h3=true is retired for config version 1"
        );
    }

    fn assert_projected_h2(config: &ClientConfig) {
        assert_eq!(
            default_transport_decision(config),
            DefaultTransportDecision {
                kind: TransportKind::H2,
                provenance: DefaultTransportProvenance::ProjectedV2Policy,
            }
        );
    }

    fn assert_legacy_selection(config: &ClientConfig) {
        let legacy_kind = legacy_default_transport_kind(config);
        assert_eq!(
            default_transport_decision(config),
            DefaultTransportDecision {
                kind: legacy_kind,
                provenance: DefaultTransportProvenance::LegacyV1,
            }
        );
        assert_eq!(default_transport_kind(config), legacy_kind);
    }

    fn yaml_client(mode: Option<&str>) -> ClientConfig {
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
  secret: "{SECRET}"
"#
        ))
        .unwrap()
    }

    fn client_config() -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:1080".parse().unwrap(),
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "example.com:443".into(),
                server_name: "example.com".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u123".into(),
                secret: SecretString::generate(),
                ca_cert: None,
                cert_pin: None,
            },
            auth: ClientAuthConfig::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }
}
