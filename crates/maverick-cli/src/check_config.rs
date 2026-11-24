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
pub(super) fn report(path: &Path, kind: &str, explain: bool, check_tls: bool) -> Result<()> {
    ensure!(
        !check_tls || kind == "server",
        "--check-tls requires --kind server"
    );
    let yaml = read_private_yaml(path)?;
    let rejected = |_| {
        anyhow!("configuration rejected (compiled direct transports: {BUILD_TRANSPORTS}). Run plain check-config locally for details")
    };
    let (route, udp) = match kind {
        "client" => client_policy(&ClientConfig::from_yaml_str(&yaml).map_err(rejected)?)?,
        "server" => {
            let config = ServerConfig::from_yaml_str(&yaml).map_err(rejected)?;
            let policy = server_policy(&config)?;
            if check_tls {
                maverick_server::check_tls_material(&config)?;
            }
            policy
        }
        _ => unreachable!("clap validates the configuration kind"),
    };
    if explain {
        println!("configured route: {route}");
        println!("UDP: {udp}");
        println!("compiled direct transports: {BUILD_TRANSPORTS}");
        println!("remote connection: unverified (offline)");
    }
    if check_tls {
        println!("server TLS certificate chain and private key: OK (offline)");
    }
    Ok(())
}

fn read_private_yaml(path: &Path) -> Result<String> {
    if super::config_permission_warning(path)
        .map_err(|_| anyhow!("cannot inspect configuration file permissions"))?
        .is_some()
    {
        eprintln!("warning: configuration is accessible by group/other users; consider chmod 600");
    }
    fs::read_to_string(path).map_err(|_| anyhow!("cannot read configuration file"))
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

/// Compare static policy only. Use the same instant and credential lookup as a new handshake.
pub(super) fn pair(client_path: &Path, server_path: &Path) -> Result<()> {
    use maverick_core::config::{parse_auth_epoch, select_client_credential_at_unix};
    use maverick_server::users::UserStore;

    let client_yaml =
        read_private_yaml(client_path).map_err(|_| anyhow!("cannot read client configuration"))?;
    let client = ClientConfig::from_yaml_str(&client_yaml).map_err(|_| {
        anyhow!("client configuration rejected (compiled direct transports: {BUILD_TRANSPORTS})")
    })?;
    let server_yaml =
        read_private_yaml(server_path).map_err(|_| anyhow!("cannot read server configuration"))?;
    let server = ServerConfig::from_yaml_str(&server_yaml).map_err(|_| {
        anyhow!("server configuration rejected (compiled direct transports: {BUILD_TRANSPORTS})")
    })?;
    let kind = default_transport_kind(&client);
    let server_h3 = server.advanced.quiche_h3 || server.advanced.dual_h2_h3;
    require_compiled_h3(kind == TransportKind::H3 || server_h3)?;
    let h2 = (kind == TransportKind::H2 || client.advanced.auto_h3) && !server.advanced.quiche_h3;
    let h3 = kind == TransportKind::H3 && server_h3;
    let ws = kind == TransportKind::CloudflareWs
        && server.advanced.cloudflare_ws_enabled()
        && !server.advanced.quiche_h3;
    let tcp = if ws { "WebSocket" } else { shared_http(h2, h3) };
    let udp_h2 = h2
        && (kind == TransportKind::H2
            || client.advanced.udp_policy == Some(UdpPolicy::AllowReliable));
    let udp = shared_http(udp_h2, h3);

    let protected = client.advanced.end_to_end.is_some();
    let protection_ok = protected == server.advanced.end_to_end;
    let path_ok = client.server.tunnel_path == server.maverick.tunnel_path;
    let epoch_ok = !client.auth.v2.enabled
        || client
            .auth
            .rotation
            .active_epoch
            .as_deref()
            .and_then(|epoch| parse_auth_epoch(epoch).ok())
            .is_some_and(|epoch| server.auth.v2.accepted_epochs.contains(&epoch));
    let auth_ok = client.auth.v2.enabled == server.auth.v2.enabled && epoch_ok;
    let client_binding = client.auth.channel_binding.enabled
        && (protected || !client.advanced.tls_terminating_fronting_enabled());
    let server_binding = server.auth.channel_binding.enabled
        && (server.advanced.end_to_end || !server.advanced.tls_terminating_fronting_enabled());
    let binding_ok = (!client_binding || server_binding)
        && (!(server.auth.channel_binding.require || server.advanced.end_to_end) || client_binding);

    let now = maverick_core::auth::current_unix();
    let selected = select_client_credential_at_unix(&client.server, &client.auth.rotation, now)
        .map_err(|_| anyhow!("client credential selection failed"))?;
    let users = UserStore::new(&server.users)
        .map_err(|_| anyhow!("server credential configuration rejected"))?;
    let (credential_ok, credential) = match users.lookup_secret(selected.id, now) {
        Some(found) if found.secret == selected.secret => (true, "match"),
        Some(_) => (false, "secret mismatch"),
        None if users.get(selected.id).is_some_and(|user| !user.enabled) => {
            (false, "disabled user")
        }
        None => (false, "no enabled credential in its acceptance window"),
    };

    let verdict = |ok| if ok { "match" } else { "mismatch" };
    println!("shared TCP carriers: {tcp}");
    println!("shared UDP carriers: {udp}");
    println!("origin protection: {}", verdict(protection_ok));
    println!("tunnel path: {}", verdict(path_ok));
    println!("authentication version/epoch: {}", verdict(auth_ok));
    println!("TLS channel binding policy: {}", verdict(binding_ok));
    println!("selected credential: {credential}");
    println!("remote connection: unverified (offline)");
    ensure!(
        (udp_h2 || h3 || ws) && protection_ok && path_ok && auth_ok && binding_ok && credential_ok,
        "configuration pair mismatch"
    );
    Ok(())
}

fn shared_http(h2: bool, h3: bool) -> &'static str {
    match (h2, h3) {
        (true, true) => "H2, H3",
        (true, false) => "H2",
        (false, true) => "H3",
        (false, false) => "none",
    }
}
