use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use maverick_core::auth::TlsChannelBinding;
use maverick_core::{ClientConfig, GuiTransportCarrier, GuiTransportDebugSnapshot};

use crate::h2_transport;
use crate::scheduler::{SchedulerPolicy, SchedulerState};

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
    #[cfg(feature = "h3")]
    H3(crate::h3_transport::H3RequestSender),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    H2,
    CloudflareWs,
    H3,
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
    if config.advanced.cloudflare_ws_enabled() {
        return TransportKind::CloudflareWs;
    }
    let policy = runtime_policy(config);
    policy.select_transport(&runtime_state(config))
}

pub fn transport_debug_snapshot(config: &ClientConfig) -> GuiTransportDebugSnapshot {
    GuiTransportDebugSnapshot::new(
        gui_transport_carrier(default_transport_kind(config)),
        h3_runtime_enabled(config),
        h3_in_cooldown(config),
    )
}

pub async fn connect(config: &ClientConfig) -> Result<TunnelRequestSender> {
    match default_transport_kind(config) {
        TransportKind::H2 => H2Transport.connect(config).await,
        TransportKind::CloudflareWs => Ok(TunnelRequestSender::CloudflareWs(Box::new(
            crate::ws_transport::connect(config).await?,
        ))),
        TransportKind::H3 => match h3_connect(config).await {
            Ok(sender) => Ok(sender),
            Err(err) => {
                let policy = runtime_policy(config);
                mark_h3_failed(config, policy.h3_cooldown);
                tracing::debug!(error = %err, "H3 transport failed; falling back to H2");
                H2Transport.connect(config).await
            }
        },
    }
}

async fn h3_connect(config: &ClientConfig) -> Result<TunnelRequestSender> {
    #[cfg(feature = "h3")]
    {
        Ok(TunnelRequestSender::H3(
            crate::h3_transport::connect(config).await?,
        ))
    }
    #[cfg(not(feature = "h3"))]
    {
        let _ = config;
        anyhow::bail!("H3 transport feature is not enabled")
    }
}

fn h3_runtime_enabled(config: &ClientConfig) -> bool {
    #[cfg(feature = "h3")]
    {
        config.advanced.experimental_h3
    }
    #[cfg(not(feature = "h3"))]
    {
        let _ = config;
        false
    }
}

fn runtime_policy(config: &ClientConfig) -> SchedulerPolicy {
    let mut policy = SchedulerPolicy::for_mode(config.mode);
    policy.h3_enabled = h3_runtime_enabled(config);
    policy
}

fn runtime_state(config: &ClientConfig) -> SchedulerState {
    let mut state = SchedulerState::default();
    if h3_in_cooldown(config) {
        state.mark_failed(TransportKind::H3);
    }
    state
}

fn h3_cooldowns() -> &'static Mutex<HashMap<String, Instant>> {
    static COOLDOWNS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    COOLDOWNS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn h3_cooldown_key(config: &ClientConfig) -> String {
    format!("{}|{}", config.server.address, config.server.server_name)
}

fn h3_in_cooldown(config: &ClientConfig) -> bool {
    let now = Instant::now();
    let Ok(mut cooldowns) = h3_cooldowns().lock() else {
        return false;
    };
    cooldowns.retain(|_, until| *until > now);
    cooldowns
        .get(&h3_cooldown_key(config))
        .is_some_and(|until| *until > now)
}

fn mark_h3_failed(config: &ClientConfig, cooldown: std::time::Duration) {
    let until = Instant::now() + cooldown;
    if let Ok(mut cooldowns) = h3_cooldowns().lock() {
        cooldowns.insert(h3_cooldown_key(config), until);
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
        CdnFrontingCarrier, CdnFrontingConfig, ClientAdvancedConfig, ClientAuthConfig,
        ClientServerConfig, LocalConfig, LogConfig, Socks5Config,
    };
    use maverick_core::{ClientConfig, GuiTransportCarrier, Mode, SecretString};

    #[test]
    fn default_transport_is_h2() {
        let transport = H2Transport;
        assert_eq!(transport.kind(), TransportKind::H2);
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
    fn transport_debug_snapshot_reports_compiled_runtime_gate() {
        let mut config = client_config();
        config.mode = Mode::Auto;
        config.advanced.experimental_h3 = true;
        let snapshot = transport_debug_snapshot(&config);

        #[cfg(feature = "h3")]
        assert_eq!(snapshot.active_transport, GuiTransportCarrier::H3);
        #[cfg(not(feature = "h3"))]
        assert_eq!(snapshot.active_transport, GuiTransportCarrier::H2);

        assert!(!snapshot.h3_in_cooldown);

        #[cfg(feature = "h3")]
        assert!(snapshot.h3_candidate_enabled);
        #[cfg(not(feature = "h3"))]
        assert!(!snapshot.h3_candidate_enabled);
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
