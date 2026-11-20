use anyhow::{anyhow, ensure, Result};
use maverick_client::transport::{default_transport_kind, TransportKind};
use maverick_core::config::UdpPolicy;
use maverick_core::{ClientConfig, ServerConfig};
use std::{fs, path::Path};

const BUILD_TRANSPORTS: &str = if cfg!(feature = "experimental-h3") {
    "H2 and H3"
} else {
    "H2 only"
};

/// Only fixed descriptions leave this command. File and YAML errors can contain
/// private paths or excerpts, so detailed diagnostics stay in plain check-config.
pub(super) fn run(path: &Path, kind: &str) -> Result<()> {
    if super::config_permission_warning(path)
        .map_err(|_| anyhow!("cannot inspect configuration file permissions"))?
        .is_some()
    {
        eprintln!("warning: configuration is accessible by group/other users; consider chmod 600");
    }
    let yaml = fs::read_to_string(path).map_err(|_| anyhow!("cannot read configuration file"))?;
    let rejected = |_| {
        anyhow!("configuration rejected (compiled direct transports: {BUILD_TRANSPORTS}). Run check-config without --explain locally for details")
    };
    let (route, udp) = match kind {
        "client" => client_policy(&ClientConfig::from_yaml_str(&yaml).map_err(rejected)?)?,
        "server" => server_policy(&ServerConfig::from_yaml_str(&yaml).map_err(rejected)?)?,
        _ => unreachable!("clap validates the configuration kind"),
    };
    println!("configured route: {route}");
    println!("UDP: {udp}");
    println!("compiled direct transports: {BUILD_TRANSPORTS}");
    println!("remote connection: unverified (offline)");
    Ok(())
}

fn require_compiled_h3(required: bool) -> Result<()> {
    ensure!(
        !required || cfg!(feature = "experimental-h3"),
        "configured route requires H3 (compiled direct transports: {BUILD_TRANSPORTS})"
    );
    Ok(())
}

fn h2_route(protected: bool, fronted: bool) -> &'static str {
    if protected {
        "origin-protected H2 intermediary (pinned inner TLS)"
    } else if fronted {
        "legacy H2 intermediary (provider can read tunnel contents)"
    } else {
        "direct H2"
    }
}

fn client_policy(config: &ClientConfig) -> Result<(&'static str, &'static str)> {
    let advanced = &config.advanced;
    let carrier = default_transport_kind(config);
    require_compiled_h3(carrier == TransportKind::H3)?;
    let route = match carrier {
        TransportKind::H3 if advanced.auto_h3 => "direct automatic (new TCP connections prefer H3; H2 only after a pre-response network failure)",
        TransportKind::H3 => "direct H3",
        TransportKind::H2 => h2_route(advanced.end_to_end.is_some(), advanced.cdn_fronted_h2_enabled()),
        TransportKind::CloudflareWs => "legacy WebSocket intermediary (provider can read tunnel contents)",
    };
    let udp = match (advanced.udp_policy, carrier) {
        (_, TransportKind::CloudflareWs) => "policy omitted; UDP unsupported over WebSocket",
        (None, TransportKind::H2) => "policy omitted; legacy H2 request/reply",
        (None, TransportKind::H3) => "policy omitted; native H3 only",
        (Some(UdpPolicy::NativeRequired), _) => "native_required; native H3 only",
        (Some(UdpPolicy::AllowReliable), _) if advanced.auto_h3 =>
            "allow_reliable; prefer native H3; allow reliable H2 before sending data if H3 is unreachable before a reply or the authenticated peer lacks native UDP",
        (Some(UdpPolicy::AllowReliable), TransportKind::H3) => "allow_reliable; fixed H3 uses native datagrams only",
        (Some(UdpPolicy::AllowReliable), TransportKind::H2) => "allow_reliable; reliable H2 session",
    };
    Ok((route, udp))
}

fn server_policy(config: &ServerConfig) -> Result<(&'static str, &'static str)> {
    let advanced = &config.advanced;
    require_compiled_h3(advanced.dual_h2_h3 || advanced.quiche_h3)?;
    Ok(if advanced.dual_h2_h3 {
        (
            "direct dual H2/H3",
            "reliable over H2 or native over H3; client selects",
        )
    } else if advanced.quiche_h3 {
        ("direct H3", "native over H3")
    } else if advanced.cloudflare_ws_enabled() {
        (
            "H2 with legacy WebSocket intermediary support (provider can read tunnel contents)",
            "UDP unsupported over WebSocket; legacy request/reply over H2",
        )
    } else if advanced.cdn_fronted_h2_enabled() && !advanced.end_to_end {
        (
            h2_route(false, true),
            "legacy request/reply over H2 with an unprotected intermediary",
        )
    } else {
        (
            h2_route(advanced.end_to_end, advanced.cdn_fronted_h2_enabled()),
            "reliable over H2 (including legacy request/reply)",
        )
    })
}
