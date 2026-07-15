#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use maverick_client::{run_client, start_client};
use maverick_core::config::ShapingConfig;
use maverick_core::config::{
    ClientAdvancedConfig, ClientServerConfig, FallbackConfig, LocalConfig, LogConfig,
    MaverickServerConfig, ServerAdvancedConfig, Socks5Config, TlsConfig, UserConfig,
};
use maverick_core::util::redact_id;
use maverick_core::{
    build_tun_runtime_plan, evaluate_tun_apply_safety, experimental_track_registry, ClientConfig,
    Mode, SecretString, ServerConfig, TunApplySafetyContext, TunApplySafetyDecision, TunRoute,
    TunRoutePlan, TunRuntimeAction, TunRuntimePlan, TunRuntimeRollbackAction,
};
use maverick_server::{run_server, start_server};
use qrcode::render::unicode;
use qrcode::QrCode;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "maverick", version, about = "Maverick privacy proxy prototype")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the local SOCKS5 client.
    Client {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        allow_loose_permissions: bool,
    },
    /// Start the TLS/H2 server.
    Server {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        allow_loose_permissions: bool,
    },
    /// Generate a high-entropy user credential.
    GenUser {
        #[arg(long, default_value = "user")]
        name: String,
    },
    /// Compute a client cert_pin value from the first PEM certificate in a file.
    PinCert {
        #[arg(long)]
        cert: PathBuf,
    },
    /// Write example client/server config files to the current directory.
    GenConfig,
    /// Validate a client or server config file.
    CheckConfig {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, value_parser = ["client", "server"])]
        kind: String,
    },
    /// Dry-run config migration report. Does not rewrite files.
    MigrateConfig {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, value_parser = ["client", "server"])]
        kind: String,
    },
    /// Print a redacted inventory of configured key and credential material.
    KeyInventory {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long, value_parser = ["client", "server"])]
        kind: String,
    },
    /// Dry-run credential rotation checks for a server config.
    RotateCredential {
        #[arg(long)]
        server: PathBuf,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Print a local-only TUN dry-run plan. Does not apply system network changes.
    TunPlan {
        #[arg(long, default_value = "maverick0")]
        device: String,
        #[arg(long = "include-route", required = true)]
        include_routes: Vec<String>,
        #[arg(long = "exclude-route")]
        exclude_routes: Vec<String>,
        #[arg(long = "dns-server")]
        dns_servers: Vec<IpAddr>,
        #[arg(long)]
        abstract_runtime_plan: bool,
    },
    /// Run an approved-host-only Linux TUN helper Phase A smoke.
    TunHelperSmoke {
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value = "mavtun0")]
        device: String,
        #[arg(long = "include-route", default_value = TUN_HELPER_DEFAULT_ROUTE)]
        include_route: String,
        #[arg(long, default_value = TUN_HELPER_DEFAULT_ADDR)]
        tun_addr: String,
        #[arg(long)]
        approved_host_label: Option<String>,
        #[arg(long)]
        proxy_vpn_conflict_checked: bool,
        #[arg(long)]
        rollback_journal: Option<PathBuf>,
    },
    /// Run a read-only TUN helper preflight. Does not apply system changes.
    TunHelperPreflight {
        #[arg(long, default_value = "mavtun0")]
        device: String,
        #[arg(long = "include-route", default_value = TUN_HELPER_DEFAULT_ROUTE)]
        include_route: String,
        #[arg(long, default_value = TUN_HELPER_DEFAULT_ADDR)]
        tun_addr: String,
        #[arg(long)]
        approved_host_label: Option<String>,
        #[arg(long)]
        rollback_journal: Option<PathBuf>,
    },
    /// Recover a retained TUN helper rollback journal on an approved Linux host.
    TunHelperRollback {
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        rollback_journal: PathBuf,
        #[arg(long)]
        approved_host_label: Option<String>,
        #[arg(long)]
        proxy_vpn_conflict_checked: bool,
    },
    /// Export or dry-run import Maverick profile URIs.
    ConfigUri {
        #[command(subcommand)]
        command: ConfigUriCommand,
    },
    /// Inspect disabled-by-default experimental track status.
    Experimental {
        #[command(subcommand)]
        command: ExperimentalCommand,
    },
    /// Print version information.
    Version,
    /// Run a loopback-only direct TCP vs Maverick SOCKS relay micro-benchmark.
    BenchLocal {
        #[arg(long, default_value_t = 1024 * 1024)]
        bytes: usize,
        #[arg(long, default_value_t = 1)]
        concurrency: usize,
        #[arg(long, value_parser = ["auto", "stable", "private"], default_value = "auto")]
        mode: String,
        #[arg(long)]
        client_shaping: bool,
        #[arg(long)]
        server_shaping: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigUriCommand {
    /// Export a client profile URI. Secrets are omitted unless explicitly requested.
    Export {
        #[arg(long)]
        client: PathBuf,
        #[arg(long)]
        include_secret: bool,
        #[arg(long)]
        qr: bool,
    },
    /// Parse, validate, or explicitly materialize a profile URI.
    Import {
        #[arg(
            long,
            required_unless_present = "clipboard",
            conflicts_with = "clipboard"
        )]
        uri: Option<String>,
        #[arg(long)]
        clipboard: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ExperimentalCommand {
    /// List experiment status, gates, and local-test constraints.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Client {
            config,
            allow_loose_permissions,
        } => {
            let cfg = read_client_config_for_start(&config, allow_loose_permissions)?;
            init_tracing(&cfg.log.level);
            run_client(cfg).await
        }
        Commands::Server {
            config,
            allow_loose_permissions,
        } => {
            let cfg = read_server_config_for_start(&config, allow_loose_permissions)?;
            init_tracing(&cfg.log.level);
            run_server(cfg).await
        }
        Commands::GenUser { name } => {
            let secret = SecretString::generate();
            let id = format!("u_{}", random_id());
            println!("id: {id}");
            println!("name: {name}");
            println!("secret: {}", secret.expose_secret());
            Ok(())
        }
        Commands::PinCert { cert } => {
            let input = fs::read(&cert).with_context(|| format!("read {}", cert.display()))?;
            println!("{}", cert_pin_from_pem(&input)?);
            Ok(())
        }
        Commands::GenConfig => {
            let secret = SecretString::generate();
            write_secret_config_file(
                GENERATED_CLIENT_CONFIG,
                example_client_config(secret.expose_secret()),
            )
            .with_context(|| format!("write {GENERATED_CLIENT_CONFIG}"))?;
            write_secret_config_file(
                GENERATED_SERVER_CONFIG,
                example_server_config(secret.expose_secret()),
            )
            .with_context(|| format!("write {GENERATED_SERVER_CONFIG}"))?;
            println!("wrote {GENERATED_CLIENT_CONFIG} and {GENERATED_SERVER_CONFIG}");
            Ok(())
        }
        Commands::CheckConfig { config, kind } => {
            match kind.as_str() {
                "client" => {
                    read_client_config(&config)?;
                    println!("client config OK");
                }
                "server" => {
                    read_server_config(&config)?;
                    println!("server config OK");
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        Commands::MigrateConfig { config, kind } => migrate_config(&config, &kind),
        Commands::KeyInventory { config, kind } => key_inventory(&config, &kind),
        Commands::RotateCredential {
            server,
            user,
            dry_run,
        } => rotate_credential(&server, user.as_deref(), dry_run),
        Commands::TunPlan {
            device,
            include_routes,
            exclude_routes,
            dns_servers,
            abstract_runtime_plan,
        } => tun_plan(
            &device,
            &include_routes,
            &exclude_routes,
            &dns_servers,
            abstract_runtime_plan,
        ),
        Commands::TunHelperSmoke {
            apply,
            device,
            include_route,
            tun_addr,
            approved_host_label,
            proxy_vpn_conflict_checked,
            rollback_journal,
        } => tun_helper_smoke(TunHelperSmokeOptions {
            apply,
            device,
            include_route,
            tun_addr,
            approved_host_label,
            proxy_vpn_conflict_checked,
            rollback_journal,
        }),
        Commands::TunHelperPreflight {
            device,
            include_route,
            tun_addr,
            approved_host_label,
            rollback_journal,
        } => tun_helper_preflight(TunHelperPreflightOptions {
            device,
            include_route,
            tun_addr,
            approved_host_label,
            rollback_journal,
        }),
        Commands::TunHelperRollback {
            apply,
            rollback_journal,
            approved_host_label,
            proxy_vpn_conflict_checked,
        } => tun_helper_rollback(TunHelperRollbackOptions {
            apply,
            rollback_journal,
            approved_host_label,
            proxy_vpn_conflict_checked,
        }),
        Commands::ConfigUri { command } => match command {
            ConfigUriCommand::Export {
                client,
                include_secret,
                qr,
            } => export_config_uri(&client, include_secret, qr),
            ConfigUriCommand::Import {
                uri,
                clipboard,
                dry_run,
                output,
            } => import_config_uri_from_args(uri.as_deref(), clipboard, dry_run, output.as_deref()),
        },
        Commands::Experimental { command } => match command {
            ExperimentalCommand::List => {
                print_experimental_track_list();
                Ok(())
            }
        },
        Commands::Version => {
            println!("maverick {}", env!("CARGO_PKG_VERSION"));
            println!("protocol_version: {}", maverick_core::PROTOCOL_VERSION);
            println!(
                "features: tls13,h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,tun-plan,tun-helper-smoke,tun-helper-preflight,tun-helper-rollback"
            );
            Ok(())
        }
        Commands::BenchLocal {
            bytes,
            concurrency,
            mode,
            client_shaping,
            server_shaping,
        } => {
            bench_local(
                bytes,
                concurrency,
                parse_mode(&mode)?,
                client_shaping,
                server_shaping,
            )
            .await
        }
    }
}

fn migrate_config(path: &Path, kind: &str) -> Result<()> {
    warn_if_config_permissions_loose(path)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let report = migration_report(kind, &input)?;
    println!("migrate-config dry-run");
    println!("kind: {kind}");
    println!("config: {}", path.display());
    if report.is_empty() {
        println!("status: no changes required");
    } else {
        println!("status: defaults would be materialized");
        for item in report {
            println!("would_add: {item}");
        }
    }
    Ok(())
}

fn key_inventory(path: &Path, kind: &str) -> Result<()> {
    warn_if_config_permissions_loose(path)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let report = key_inventory_report(kind, &input)?;
    println!("key-inventory");
    println!("kind: {kind}");
    println!("config: {}", path.display());
    for item in report {
        println!("{item}");
    }
    Ok(())
}

fn key_inventory_report(kind: &str, input: &str) -> Result<Vec<String>> {
    match kind {
        "client" => {
            let cfg = ClientConfig::from_yaml_str(input)?;
            Ok(vec![
                format!("credential_id: {}", redact_id(&cfg.server.credential_id)),
                "credential_secret: [REDACTED]".into(),
                format!(
                    "cert_pin: {}",
                    if cfg.server.cert_pin.is_some() {
                        "configured"
                    } else {
                        "absent"
                    }
                ),
                format!(
                    "auth_v2: {}",
                    if cfg.auth.v2.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
                format!(
                    "rotation_active_epoch: {}",
                    cfg.auth
                        .rotation
                        .active_epoch
                        .as_deref()
                        .unwrap_or("absent")
                ),
                format!(
                    "rotation_next_credential_id: {}",
                    cfg.auth
                        .rotation
                        .next_credential_id
                        .as_deref()
                        .map(redact_id)
                        .unwrap_or_else(|| "absent".into())
                ),
                format!("rotation_auto_switch: {}", cfg.auth.rotation.auto_switch),
                format!(
                    "rotation_next_secret: {}",
                    if cfg.auth.rotation.next.is_some() {
                        "[REDACTED]"
                    } else {
                        "absent"
                    }
                ),
            ])
        }
        "server" => {
            let cfg = ServerConfig::from_yaml_str(input)?;
            let mut report = vec![
                "tls_certificate: configured".into(),
                "tls_private_key: configured".into(),
                format!("user_count: {}", cfg.users.len()),
                format!(
                    "auth_v2: {}",
                    if cfg.auth.v2.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
            ];
            for user in cfg.users {
                let previous_count = user
                    .rotation
                    .as_ref()
                    .map(|rotation| rotation.previous.len())
                    .unwrap_or(0);
                let next = user
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.next.as_ref())
                    .map(|next| redact_id(&next.id))
                    .unwrap_or_else(|| "absent".into());
                report.push(format!(
                    "user: {} enabled={} active_secret=[REDACTED] previous_credentials={} next_credential_id={}",
                    redact_id(&user.id),
                    user.enabled,
                    previous_count,
                    next
                ));
                if let Some(rotation) = user.rotation {
                    for previous in rotation.previous {
                        report.push(format!(
                            "previous_credential: {} window={}..{} secret=[REDACTED]",
                            redact_id(&previous.id),
                            previous.not_before,
                            previous.not_after
                        ));
                    }
                }
            }
            Ok(report)
        }
        _ => anyhow::bail!("kind must be client or server"),
    }
}

fn rotate_credential(path: &Path, user: Option<&str>, dry_run: bool) -> Result<()> {
    anyhow::ensure!(
        dry_run,
        "rotate-credential currently supports --dry-run only"
    );
    warn_if_config_permissions_loose(path)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg = ServerConfig::from_yaml_str(&input)?;
    let report = rotation_lint_report(&cfg, user, OffsetDateTime::now_utc())?;
    println!("rotate-credential dry-run");
    println!("server: {}", path.display());
    if let Some(user_id) = user {
        println!("user: {}", redact_id(user_id));
    }
    for item in report {
        println!("{item}");
    }
    Ok(())
}

fn tun_plan(
    device: &str,
    include_routes: &[String],
    exclude_routes: &[String],
    dns_servers: &[IpAddr],
    abstract_runtime_plan: bool,
) -> Result<()> {
    for line in tun_plan_report(
        device,
        include_routes,
        exclude_routes,
        dns_servers,
        abstract_runtime_plan,
    )? {
        println!("{line}");
    }
    Ok(())
}

fn tun_plan_report(
    device: &str,
    include_routes: &[String],
    exclude_routes: &[String],
    dns_servers: &[IpAddr],
    abstract_runtime_plan: bool,
) -> Result<Vec<String>> {
    let plan = TunRoutePlan {
        enabled: true,
        device_name: device.to_owned(),
        include_routes: parse_tun_routes(include_routes)?,
        exclude_routes: parse_tun_routes(exclude_routes)?,
        dns_servers: dns_servers.to_vec(),
    };
    let dry_run_steps = plan.dry_run_steps()?;
    let safety = evaluate_tun_apply_safety(
        &plan,
        TunApplySafetyContext {
            dry_run_completed: true,
            ..TunApplySafetyContext::default()
        },
    )?;

    let mut report = vec![
        "tun-plan".to_owned(),
        "system_apply: false".to_owned(),
        format!("device: {}", plan.device_name),
        format!("include_routes: {}", plan.include_routes.len()),
        format!("exclude_routes: {}", plan.exclude_routes.len()),
        format!("dns_servers: {}", plan.dns_servers.len()),
    ];
    for step in dry_run_steps {
        report.push(format!("dry_run_step: {step}"));
    }
    report.push(format!("apply_allowed: {}", safety.is_allowed()));
    for blocker in safety.blockers {
        report.push(format!("apply_blocker: {blocker:?}"));
    }

    if !abstract_runtime_plan {
        report.push("abstract_runtime_plan: not_requested".to_owned());
        return Ok(report);
    }

    let runtime_plan = build_tun_runtime_plan(&plan, abstract_tun_apply_context())?;
    report.push("abstract_runtime_plan: available".to_owned());
    report.push("abstract_runtime_plan_system_apply: false".to_owned());
    report.push("abstract_runtime_plan_context: planning_only_all_gates_assumed".to_owned());
    for action in &runtime_plan.apply_actions {
        report.push(format!(
            "abstract_apply_action: {}",
            describe_tun_runtime_action(action)
        ));
    }
    for action in &runtime_plan.rollback_actions {
        report.push(format!(
            "abstract_rollback_action: {}",
            describe_tun_runtime_rollback_action(action)
        ));
    }
    Ok(report)
}

const TUN_HELPER_APPROVAL_ENV: &str = "MAVERICK_TUN_HELPER_APPROVED";
const TUN_HELPER_DEFAULT_ROUTE: &str = "192.0.2.0/24";
const TUN_HELPER_DEFAULT_ADDR: &str = "10.255.0.1/30";
const TUN_HELPER_ROUTE_METRIC: &str = "4271";
const APPROVED_TUN_HELPER_HOST_LABEL: &str = "approved-linux-vm";
const GENERATED_CLIENT_CONFIG: &str = "client.generated.yaml";
const GENERATED_SERVER_CONFIG: &str = "server.generated.yaml";

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperSmokeOptions {
    apply: bool,
    device: String,
    include_route: String,
    tun_addr: String,
    approved_host_label: Option<String>,
    proxy_vpn_conflict_checked: bool,
    rollback_journal: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TunHelperSmokeEnvironment {
    operator_approved: bool,
    platform_supported: bool,
    privileges_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperSmokeReport {
    lines: Vec<String>,
    decision: TunApplySafetyDecision,
    runtime_plan: Option<TunRuntimePlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperPreflightOptions {
    device: String,
    include_route: String,
    tun_addr: String,
    approved_host_label: Option<String>,
    rollback_journal: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunHelperPreflightBlocker {
    ApprovedHostRequired,
    UnsupportedPlatform,
    IpCommandUnavailable,
    PrivilegesRequired,
    ExistingDevice,
    ExistingRoute,
    RollbackJournalUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperPreflightReport {
    lines: Vec<String>,
    blockers: Vec<TunHelperPreflightBlocker>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperRollbackOptions {
    apply: bool,
    rollback_journal: PathBuf,
    approved_host_label: Option<String>,
    proxy_vpn_conflict_checked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperRollbackJournal {
    device: String,
    device_identity: String,
    include_route: String,
    tun_addr: String,
    route_probe: String,
    approved_host_label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperRollbackReport {
    lines: Vec<String>,
    decision: TunApplySafetyDecision,
    journal: TunHelperRollbackJournal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunHelperGlobalBaseline {
    default_route_digest: String,
    resolv_conf_digest: String,
}

fn tun_helper_smoke(options: TunHelperSmokeOptions) -> Result<()> {
    let environment = detect_tun_helper_smoke_environment(&options);
    let report = tun_helper_smoke_report(&options, environment)?;
    for line in &report.lines {
        println!("{line}");
    }

    if !options.apply {
        return Ok(());
    }
    if !report.decision.is_allowed() {
        anyhow::bail!("tun helper smoke blocked by safety gate");
    }
    let runtime_plan = report
        .runtime_plan
        .as_ref()
        .context("tun helper smoke runtime plan missing after safety gate")?;
    for line in run_linux_tun_helper_smoke(&options, runtime_plan)? {
        println!("{line}");
    }
    Ok(())
}

fn tun_helper_preflight(options: TunHelperPreflightOptions) -> Result<()> {
    for line in tun_helper_preflight_report(&options)?.lines {
        println!("{line}");
    }
    Ok(())
}

fn tun_helper_rollback(options: TunHelperRollbackOptions) -> Result<()> {
    let environment = detect_tun_helper_rollback_environment(&options);
    let report = tun_helper_rollback_report(&options, environment)?;
    for line in &report.lines {
        println!("{line}");
    }

    if !options.apply {
        return Ok(());
    }
    if !report.decision.is_allowed() {
        anyhow::bail!("tun helper rollback blocked by safety gate");
    }
    for line in run_linux_tun_helper_rollback(&options.rollback_journal, &report.journal)? {
        println!("{line}");
    }
    Ok(())
}

fn detect_tun_helper_smoke_environment(
    options: &TunHelperSmokeOptions,
) -> TunHelperSmokeEnvironment {
    let operator_approved = env::var(TUN_HELPER_APPROVAL_ENV).is_ok_and(|value| value == "1");
    let platform_supported = cfg!(target_os = "linux");
    let privileges_confirmed = options.apply
        && operator_approved
        && platform_supported
        && command_success("sudo", &["-n", "true"]);

    TunHelperSmokeEnvironment {
        operator_approved,
        platform_supported,
        privileges_confirmed,
    }
}

fn detect_tun_helper_rollback_environment(
    options: &TunHelperRollbackOptions,
) -> TunHelperSmokeEnvironment {
    let operator_approved = env::var(TUN_HELPER_APPROVAL_ENV).is_ok_and(|value| value == "1");
    let platform_supported = cfg!(target_os = "linux");
    let privileges_confirmed = options.apply
        && operator_approved
        && platform_supported
        && command_success("sudo", &["-n", "true"]);

    TunHelperSmokeEnvironment {
        operator_approved,
        platform_supported,
        privileges_confirmed,
    }
}

fn tun_helper_smoke_report(
    options: &TunHelperSmokeOptions,
    environment: TunHelperSmokeEnvironment,
) -> Result<TunHelperSmokeReport> {
    validate_linux_phase_a_device(&options.device)?;
    let route = parse_tun_route(&options.include_route)?;
    validate_phase_a_documentation_route(&route)?;
    validate_phase_a_tun_addr(&options.tun_addr)?;
    let rollback_journal_path = tun_helper_rollback_journal_path(options);
    let approved_host = options
        .approved_host_label
        .as_deref()
        .is_some_and(is_approved_host_label);
    let rollback_plan_writable =
        !options.apply || rollback_journal_path_available(&rollback_journal_path);

    let plan = TunRoutePlan {
        enabled: true,
        device_name: options.device.clone(),
        include_routes: vec![route],
        exclude_routes: Vec::new(),
        dns_servers: Vec::new(),
    };
    let context = TunApplySafetyContext {
        dry_run_completed: true,
        operator_approved: options.apply && environment.operator_approved,
        approved_host,
        platform_supported: environment.platform_supported,
        privileges_confirmed: environment.privileges_confirmed,
        proxy_vpn_conflict_checked: options.proxy_vpn_conflict_checked,
        rollback_plan_writable,
    };
    let decision = evaluate_tun_apply_safety(&plan, context)?;
    let runtime_plan = if decision.is_allowed() {
        Some(build_tun_runtime_plan(&plan, context)?)
    } else {
        None
    };

    let mut lines = vec![
        "tun-helper-smoke".to_owned(),
        format!("system_apply: {}", options.apply),
        "scope: phase_a_temporary_tun_documentation_route".to_owned(),
        format!("approval_env: {TUN_HELPER_APPROVAL_ENV}"),
        format!(
            "approved_host_label: {}",
            options.approved_host_label.as_deref().unwrap_or("absent")
        ),
        format!("device: {}", options.device),
        format!("include_route: {}", options.include_route),
        format!("tun_addr: {}", options.tun_addr),
        format!("rollback_journal: {}", rollback_journal_path.display()),
        format!(
            "proxy_vpn_conflict_checked: {}",
            options.proxy_vpn_conflict_checked
        ),
        "default_route: not_touched".to_owned(),
        "global_dns: not_touched".to_owned(),
        "firewall: not_touched".to_owned(),
        "rollback: required".to_owned(),
        format!("apply_allowed: {}", decision.is_allowed()),
    ];
    for blocker in &decision.blockers {
        lines.push(format!("apply_blocker: {blocker:?}"));
    }
    if runtime_plan.is_some() {
        lines.push("runtime_plan: available".to_owned());
        lines.push("runtime_plan_scope: helper_phase_a_only".to_owned());
    } else {
        lines.push("runtime_plan: blocked".to_owned());
    }

    Ok(TunHelperSmokeReport {
        lines,
        decision,
        runtime_plan,
    })
}

fn tun_helper_preflight_report(
    options: &TunHelperPreflightOptions,
) -> Result<TunHelperPreflightReport> {
    validate_linux_phase_a_device(&options.device)?;
    let route = parse_tun_route(&options.include_route)?;
    validate_phase_a_documentation_route(&route)?;
    validate_phase_a_tun_addr(&options.tun_addr)?;
    let approved_host = options
        .approved_host_label
        .as_deref()
        .is_some_and(is_approved_host_label);
    let rollback_journal_path = tun_helper_preflight_rollback_journal_path(options);
    let rollback_journal_available = rollback_journal_path_available(&rollback_journal_path);
    let platform_linux = cfg!(target_os = "linux");

    let mut blockers = Vec::new();
    if !approved_host {
        blockers.push(TunHelperPreflightBlocker::ApprovedHostRequired);
    }
    if !platform_linux {
        blockers.push(TunHelperPreflightBlocker::UnsupportedPlatform);
    }
    let mut ip_command_available = false;
    let mut sudo_noninteractive_available = false;
    let mut existing_device = "skipped_non_linux".to_owned();
    let mut existing_route = "skipped_non_linux".to_owned();
    if platform_linux {
        ip_command_available = command_success("ip", &["-V"]);
        if !ip_command_available {
            blockers.push(TunHelperPreflightBlocker::IpCommandUnavailable);
        }
        sudo_noninteractive_available = command_success("sudo", &["-n", "true"]);
        if !sudo_noninteractive_available {
            blockers.push(TunHelperPreflightBlocker::PrivilegesRequired);
        }
        if ip_command_available {
            let device_present = command_success("ip", &["link", "show", "dev", &options.device]);
            existing_device = if device_present { "present" } else { "absent" }.to_owned();
            if device_present {
                blockers.push(TunHelperPreflightBlocker::ExistingDevice);
            }
            let route_output = command_stdout("ip", &["route", "show", &options.include_route])
                .unwrap_or_default();
            let route_present = route_output.contains(&options.device) || !route_output.is_empty();
            existing_route = if route_present { "present" } else { "absent" }.to_owned();
            if route_present {
                blockers.push(TunHelperPreflightBlocker::ExistingRoute);
            }
        }
    }
    if !rollback_journal_available {
        blockers.push(TunHelperPreflightBlocker::RollbackJournalUnavailable);
    }

    let mut lines = vec![
        "tun-helper-preflight".to_owned(),
        "system_apply: false".to_owned(),
        "scope: phase_a_temporary_tun_documentation_route".to_owned(),
        format!(
            "approved_host_label: {}",
            options.approved_host_label.as_deref().unwrap_or("absent")
        ),
        format!("device: {}", options.device),
        format!("include_route: {}", options.include_route),
        format!("tun_addr: {}", options.tun_addr),
        format!("rollback_journal: {}", rollback_journal_path.display()),
        format!("platform_linux: {platform_linux}"),
        format!("ip_command_available: {ip_command_available}"),
        format!("privileges_confirmed: {sudo_noninteractive_available}"),
        format!("existing_device: {existing_device}"),
        format!("existing_route: {existing_route}"),
        "default_route: not_touched".to_owned(),
        "global_dns: not_touched".to_owned(),
        "firewall: not_touched".to_owned(),
        format!("preflight_ready: {}", blockers.is_empty()),
    ];
    for blocker in &blockers {
        lines.push(format!("preflight_blocker: {blocker:?}"));
    }

    Ok(TunHelperPreflightReport { lines, blockers })
}

fn tun_helper_rollback_report(
    options: &TunHelperRollbackOptions,
    environment: TunHelperSmokeEnvironment,
) -> Result<TunHelperRollbackReport> {
    let journal = read_tun_helper_rollback_journal(&options.rollback_journal)?;
    let route = parse_tun_route(&journal.include_route)?;
    validate_phase_a_documentation_route(&route)?;
    validate_phase_a_tun_addr(&journal.tun_addr)?;
    validate_linux_phase_a_device(&journal.device)?;
    anyhow::ensure!(
        is_approved_host_label(&journal.approved_host_label)
            && options.approved_host_label.as_deref() == Some(journal.approved_host_label.as_str()),
        "TUN helper rollback journal approved_host_label does not match the approved request"
    );
    anyhow::ensure!(
        phase_a_route_probe(&journal.include_route)? == journal.route_probe,
        "TUN helper rollback journal route_probe does not match include_route"
    );
    let approved_host = options
        .approved_host_label
        .as_deref()
        .is_some_and(is_approved_host_label);
    let plan = TunRoutePlan {
        enabled: true,
        device_name: journal.device.clone(),
        include_routes: vec![route],
        exclude_routes: Vec::new(),
        dns_servers: Vec::new(),
    };
    let context = TunApplySafetyContext {
        dry_run_completed: true,
        operator_approved: options.apply && environment.operator_approved,
        approved_host,
        platform_supported: environment.platform_supported,
        privileges_confirmed: environment.privileges_confirmed,
        proxy_vpn_conflict_checked: options.proxy_vpn_conflict_checked,
        rollback_plan_writable: options.rollback_journal.is_file(),
    };
    let decision = evaluate_tun_apply_safety(&plan, context)?;
    let mut lines = vec![
        "tun-helper-rollback".to_owned(),
        format!("system_apply: {}", options.apply),
        "scope: phase_a_temporary_tun_documentation_route".to_owned(),
        format!("approval_env: {TUN_HELPER_APPROVAL_ENV}"),
        format!(
            "approved_host_label: {}",
            options.approved_host_label.as_deref().unwrap_or("absent")
        ),
        format!("rollback_journal: {}", options.rollback_journal.display()),
        format!("device: {}", journal.device),
        format!("include_route: {}", journal.include_route),
        format!("tun_addr: {}", journal.tun_addr),
        format!("route_probe: {}", journal.route_probe),
        format!(
            "proxy_vpn_conflict_checked: {}",
            options.proxy_vpn_conflict_checked
        ),
        "default_route: not_touched".to_owned(),
        "global_dns: not_touched".to_owned(),
        "firewall: not_touched".to_owned(),
        "rollback: idempotent_cleanup".to_owned(),
        format!("apply_allowed: {}", decision.is_allowed()),
    ];
    for blocker in &decision.blockers {
        lines.push(format!("apply_blocker: {blocker:?}"));
    }
    Ok(TunHelperRollbackReport {
        lines,
        decision,
        journal,
    })
}

fn validate_linux_phase_a_device(device: &str) -> Result<()> {
    let plan = TunRoutePlan {
        enabled: true,
        device_name: device.to_owned(),
        include_routes: vec![TunRoute::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)],
        exclude_routes: Vec::new(),
        dns_servers: Vec::new(),
    };
    plan.validate()?;
    anyhow::ensure!(
        device.len() <= 15,
        "Linux TUN helper smoke device name must be at most 15 characters"
    );
    Ok(())
}

fn validate_phase_a_documentation_route(route: &TunRoute) -> Result<()> {
    let allowed = matches!(
        (route.network, route.prefix_len),
        (IpAddr::V4(addr), 24)
            if addr == Ipv4Addr::new(192, 0, 2, 0)
                || addr == Ipv4Addr::new(198, 51, 100, 0)
                || addr == Ipv4Addr::new(203, 0, 113, 0)
    );
    anyhow::ensure!(
        allowed,
        "TUN helper smoke is limited to RFC 5737 documentation /24 routes"
    );
    Ok(())
}

fn validate_phase_a_tun_addr(raw: &str) -> Result<()> {
    anyhow::ensure!(
        raw == TUN_HELPER_DEFAULT_ADDR,
        "TUN helper smoke currently allows only {TUN_HELPER_DEFAULT_ADDR}"
    );
    let (addr, prefix) = raw
        .split_once('/')
        .context("TUN helper smoke address must be CIDR formatted")?;
    let parsed: IpAddr = addr
        .parse()
        .with_context(|| format!("parse TUN helper smoke address: {raw}"))?;
    let prefix_len: u8 = prefix
        .parse()
        .with_context(|| format!("parse TUN helper smoke address prefix: {raw}"))?;
    anyhow::ensure!(
        matches!(parsed, IpAddr::V4(_)) && prefix_len == 30,
        "TUN helper smoke address must be IPv4 /30"
    );
    Ok(())
}

fn is_approved_host_label(value: &str) -> bool {
    value == APPROVED_TUN_HELPER_HOST_LABEL
}

fn tun_helper_rollback_journal_path(options: &TunHelperSmokeOptions) -> PathBuf {
    options.rollback_journal.clone().unwrap_or_else(|| {
        env::temp_dir().join(format!(
            "maverick-tun-helper-{}-rollback.json",
            options.device
        ))
    })
}

fn tun_helper_preflight_rollback_journal_path(options: &TunHelperPreflightOptions) -> PathBuf {
    options.rollback_journal.clone().unwrap_or_else(|| {
        env::temp_dir().join(format!(
            "maverick-tun-helper-{}-rollback.json",
            options.device
        ))
    })
}

fn rollback_journal_path_available(path: &Path) -> bool {
    path.parent().is_some_and(Path::is_dir) && !path.exists()
}

fn write_tun_helper_rollback_journal(
    options: &TunHelperSmokeOptions,
    runtime_plan: &TunRuntimePlan,
    path: &Path,
    route_probe: &str,
    device_identity: &str,
) -> Result<()> {
    let parent = path
        .parent()
        .context("TUN helper rollback journal path must have a parent directory")?;
    anyhow::ensure!(
        parent.is_dir(),
        "TUN helper rollback journal parent directory does not exist: {}",
        parent.display()
    );
    let journal = serde_json::json!({
        "version": 2,
        "scope": "phase_a_temporary_tun_documentation_route",
        "status": "pending_rollback",
        "device": &options.device,
        "device_identity": device_identity,
        "include_route": &options.include_route,
        "tun_addr": &options.tun_addr,
        "route_probe": route_probe,
        "route_metric": TUN_HELPER_ROUTE_METRIC,
        "approved_host_label": options.approved_host_label.as_deref().unwrap_or("absent"),
        "default_route": "not_touched",
        "global_dns": "not_touched",
        "firewall": "not_touched",
        "runtime_plan": runtime_plan,
        "cleanup_policy": "remove_on_success_retain_on_failed_cleanup"
    });
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, &journal)
        .with_context(|| format!("serialize {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("finish {}", path.display()))?;
    Ok(())
}

fn read_tun_helper_rollback_journal(path: &Path) -> Result<TunHelperRollbackJournal> {
    validate_tun_helper_rollback_journal_metadata(path)?;
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    require_json_u64(&value, "version", path, 2)?;
    require_json_string(
        &value,
        "scope",
        path,
        Some("phase_a_temporary_tun_documentation_route"),
    )?;
    require_json_string(&value, "status", path, Some("pending_rollback"))?;
    require_json_string(&value, "route_metric", path, Some(TUN_HELPER_ROUTE_METRIC))?;
    require_json_string(&value, "default_route", path, Some("not_touched"))?;
    require_json_string(&value, "global_dns", path, Some("not_touched"))?;
    require_json_string(&value, "firewall", path, Some("not_touched"))?;

    Ok(TunHelperRollbackJournal {
        device: require_json_string(&value, "device", path, None)?,
        device_identity: require_json_string(&value, "device_identity", path, None)?,
        include_route: require_json_string(&value, "include_route", path, None)?,
        tun_addr: require_json_string(&value, "tun_addr", path, None)?,
        route_probe: require_json_string(&value, "route_probe", path, None)?,
        approved_host_label: require_json_string(&value, "approved_host_label", path, None)?,
    })
}

fn validate_tun_helper_rollback_journal_metadata(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect TUN helper rollback journal {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "TUN helper rollback journal must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mode = metadata.permissions().mode() & 0o777;
        anyhow::ensure!(
            mode & 0o077 == 0,
            "TUN helper rollback journal must not be accessible by group or other users"
        );
        let current_uid: u32 = command_stdout("id", &["-u"])
            .context("read current user id")?
            .trim()
            .parse()
            .context("parse current user id")?;
        anyhow::ensure!(
            metadata.uid() == current_uid,
            "TUN helper rollback journal must be owned by the current user"
        );
    }
    Ok(())
}

fn require_json_u64(
    value: &serde_json::Value,
    field: &str,
    path: &Path,
    expected: u64,
) -> Result<()> {
    let actual = value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .with_context(|| format!("{} missing numeric {field}", path.display()))?;
    anyhow::ensure!(
        actual == expected,
        "{} field {field} must be {expected}, got {actual}",
        path.display()
    );
    Ok(())
}

fn require_json_string(
    value: &serde_json::Value,
    field: &str,
    path: &Path,
    expected: Option<&str>,
) -> Result<String> {
    let actual = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("{} missing string {field}", path.display()))?;
    if let Some(expected) = expected {
        anyhow::ensure!(
            actual == expected,
            "{} field {field} must be {expected:?}, got {actual:?}",
            path.display()
        );
    }
    Ok(actual.to_owned())
}

fn capture_linux_tun_helper_global_baseline() -> Result<TunHelperGlobalBaseline> {
    let default_route = command_stdout("ip", &["route", "show", "default"])
        .context("capture default route baseline")?;
    let resolv_conf = fs::read("/etc/resolv.conf").context("capture DNS resolver baseline")?;
    Ok(TunHelperGlobalBaseline {
        default_route_digest: digest_bytes(default_route.as_bytes()),
        resolv_conf_digest: digest_bytes(&resolv_conf),
    })
}

fn verify_linux_tun_helper_global_baseline(before: &TunHelperGlobalBaseline) -> Result<()> {
    let after = capture_linux_tun_helper_global_baseline()?;
    anyhow::ensure!(
        before.default_route_digest == after.default_route_digest,
        "TUN helper changed the default route baseline"
    );
    anyhow::ensure!(
        before.resolv_conf_digest == after.resolv_conf_digest,
        "TUN helper changed the global DNS resolver baseline"
    );
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn run_linux_tun_helper_smoke(
    options: &TunHelperSmokeOptions,
    runtime_plan: &TunRuntimePlan,
) -> Result<Vec<String>> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "TUN helper smoke apply requires Linux"
    );
    let route_probe = phase_a_route_probe(&options.include_route)?;
    let user = command_stdout("id", &["-un"]).context("read current user")?;
    let device_identity = format!("maverick-tun-helper:{}", random_id());
    let rollback_journal_path = tun_helper_rollback_journal_path(options);
    let global_baseline = capture_linux_tun_helper_global_baseline()?;

    if command_success("ip", &["link", "show", "dev", &options.device]) {
        anyhow::bail!(
            "TUN helper smoke refusing to touch existing device {}",
            options.device
        );
    }
    let existing_route = command_stdout("ip", &["route", "show", &options.include_route])
        .context("check existing documentation route")?;
    anyhow::ensure!(
        existing_route.trim().is_empty(),
        "TUN helper smoke refusing to touch existing route {}",
        options.include_route
    );
    write_tun_helper_rollback_journal(
        options,
        runtime_plan,
        &rollback_journal_path,
        &route_probe,
        &device_identity,
    )
    .with_context(|| {
        format!(
            "write TUN helper rollback journal {}",
            rollback_journal_path.display()
        )
    })?;

    let mut created_device = false;
    let mut added_route = false;
    let result = (|| -> Result<Vec<String>> {
        let mut lines = vec![format!(
            "rollback_journal: wrote {}",
            rollback_journal_path.display()
        )];
        lines.push("global_baseline: captured".to_owned());
        run_checked(
            "sudo",
            &[
                "-n",
                "ip",
                "tuntap",
                "add",
                "dev",
                &options.device,
                "mode",
                "tun",
                "user",
                &user,
            ],
        )
        .context("create temporary TUN device")?;
        created_device = true;
        lines.push(format!("apply: created_tun_device {}", options.device));

        run_checked(
            "sudo",
            &[
                "-n",
                "ip",
                "link",
                "set",
                "dev",
                &options.device,
                "alias",
                &device_identity,
            ],
        )
        .context("bind temporary TUN device identity")?;
        verify_linux_tun_device_identity(&options.device, &device_identity)?;
        lines.push("apply: bound_tun_device_identity".to_owned());

        run_checked(
            "sudo",
            &[
                "-n",
                "ip",
                "addr",
                "add",
                &options.tun_addr,
                "dev",
                &options.device,
            ],
        )
        .context("assign temporary TUN address")?;
        lines.push(format!("apply: assigned_tun_addr {}", options.tun_addr));

        run_checked("sudo", &["-n", "ip", "link", "set", &options.device, "up"])
            .context("bring temporary TUN device up")?;
        lines.push(format!("apply: brought_tun_device_up {}", options.device));

        run_checked(
            "sudo",
            &[
                "-n",
                "ip",
                "route",
                "add",
                &options.include_route,
                "dev",
                &options.device,
                "metric",
                TUN_HELPER_ROUTE_METRIC,
            ],
        )
        .context("add documentation-prefix route")?;
        added_route = true;
        lines.push(format!(
            "apply: added_documentation_route {}",
            options.include_route
        ));

        let probe = command_stdout("ip", &["route", "get", &route_probe])
            .context("probe documentation-prefix route")?;
        anyhow::ensure!(
            probe.contains(&format!("dev {}", options.device)),
            "documentation route probe did not use {}: {}",
            options.device,
            probe.trim()
        );
        lines.push(format!(
            "verify: route_probe {} via {}",
            route_probe, options.device
        ));

        Ok(lines)
    })();

    let mut lines = match result {
        Ok(lines) => lines,
        Err(err) => {
            let cleanup_errors = cleanup_linux_tun_helper_smoke(
                &options.device,
                &options.include_route,
                added_route,
                created_device,
                &device_identity,
            );
            if cleanup_errors.is_empty() {
                let _ = fs::remove_file(&rollback_journal_path);
                return Err(err);
            }
            anyhow::bail!(
                "{err}; cleanup also reported: {}; rollback journal retained at {}",
                cleanup_errors.join("; "),
                rollback_journal_path.display()
            );
        }
    };

    let rollback_errors = cleanup_linux_tun_helper_smoke(
        &options.device,
        &options.include_route,
        added_route,
        created_device,
        &device_identity,
    );
    if !rollback_errors.is_empty() {
        anyhow::bail!(
            "TUN helper smoke rollback failed: {}; rollback journal retained at {}",
            rollback_errors.join("; "),
            rollback_journal_path.display()
        );
    }
    if added_route {
        lines.push(format!(
            "rollback: deleted_documentation_route {}",
            options.include_route
        ));
    }
    if created_device {
        lines.push(format!("rollback: deleted_tun_device {}", options.device));
    }
    fs::remove_file(&rollback_journal_path).with_context(|| {
        format!(
            "remove TUN helper rollback journal {}",
            rollback_journal_path.display()
        )
    })?;
    lines.push(format!(
        "rollback_journal: removed {}",
        rollback_journal_path.display()
    ));
    verify_linux_tun_helper_residue(&options.device, &options.include_route)?;
    verify_linux_tun_helper_global_baseline(&global_baseline)?;
    lines.push("residue_check: ok".to_owned());
    lines.push("default_route_unchanged: true".to_owned());
    lines.push("global_dns_unchanged: true".to_owned());
    lines.push("tun_helper_smoke=ok".to_owned());
    Ok(lines)
}

fn cleanup_linux_tun_helper_smoke(
    device: &str,
    route: &str,
    added_route: bool,
    created_device: bool,
    device_identity: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    let identity_verified = if created_device {
        match verify_linux_tun_device_identity(device, device_identity) {
            Ok(()) => true,
            Err(err) => {
                errors.push(format!("verify temporary TUN device identity: {err}"));
                false
            }
        }
    } else {
        false
    };
    if added_route && identity_verified {
        if let Err(err) = run_checked("sudo", &["-n", "ip", "route", "del", route, "dev", device]) {
            errors.push(format!("delete documentation route: {err}"));
        }
    }
    if created_device && identity_verified {
        if let Err(err) = run_checked("sudo", &["-n", "ip", "link", "del", device]) {
            errors.push(format!("delete TUN device: {err}"));
        }
    }
    errors
}

fn run_linux_tun_helper_rollback(
    journal_path: &Path,
    journal: &TunHelperRollbackJournal,
) -> Result<Vec<String>> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "TUN helper rollback apply requires Linux"
    );
    let global_baseline = capture_linux_tun_helper_global_baseline()?;
    let mut lines = vec!["global_baseline: captured".to_owned()];
    let device_present = command_success("ip", &["link", "show", "dev", &journal.device]);
    if device_present {
        verify_linux_tun_device_identity(&journal.device, &journal.device_identity)?;
        lines.push("rollback: verified_tun_device_identity".to_owned());
    }
    let route_output = command_stdout("ip", &["route", "show", &journal.include_route])
        .context("check retained documentation route")?;
    if route_output.contains(&journal.device) {
        anyhow::ensure!(
            device_present,
            "rollback route references a TUN device whose identity cannot be verified"
        );
        run_checked(
            "sudo",
            &[
                "-n",
                "ip",
                "route",
                "del",
                &journal.include_route,
                "dev",
                &journal.device,
            ],
        )
        .context("rollback retained documentation route")?;
        lines.push(format!(
            "rollback: deleted_documentation_route {}",
            journal.include_route
        ));
    } else {
        lines.push(format!(
            "rollback: documentation_route_absent {}",
            journal.include_route
        ));
    }

    if device_present {
        run_checked("sudo", &["-n", "ip", "link", "del", &journal.device])
            .context("rollback retained TUN device")?;
        lines.push(format!("rollback: deleted_tun_device {}", journal.device));
    } else {
        lines.push(format!("rollback: tun_device_absent {}", journal.device));
    }

    verify_linux_tun_helper_residue(&journal.device, &journal.include_route)?;
    verify_linux_tun_helper_global_baseline(&global_baseline)?;
    fs::remove_file(journal_path).with_context(|| {
        format!(
            "remove TUN helper rollback journal {}",
            journal_path.display()
        )
    })?;
    lines.push(format!(
        "rollback_journal: removed {}",
        journal_path.display()
    ));
    lines.push("residue_check: ok".to_owned());
    lines.push("default_route_unchanged: true".to_owned());
    lines.push("global_dns_unchanged: true".to_owned());
    lines.push("tun_helper_rollback=ok".to_owned());
    Ok(lines)
}

fn verify_linux_tun_device_identity(device: &str, expected_identity: &str) -> Result<()> {
    validate_linux_phase_a_device(device)?;
    anyhow::ensure!(
        expected_identity.starts_with("maverick-tun-helper:")
            && expected_identity.len() > "maverick-tun-helper:".len(),
        "TUN helper device identity is invalid"
    );
    let sysfs = Path::new("/sys/class/net").join(device);
    let alias = fs::read_to_string(sysfs.join("ifalias"))
        .with_context(|| format!("read TUN device identity for {device}"))?;
    anyhow::ensure!(
        alias.trim() == expected_identity,
        "TUN device identity does not match rollback journal"
    );
    let flags = fs::read_to_string(sysfs.join("tun_flags"))
        .with_context(|| format!("verify {device} is a TUN device"))?;
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
        .with_context(|| format!("parse TUN flags for {device}"))?;
    anyhow::ensure!(
        flags & 0x0001 != 0 && flags & 0x0002 == 0,
        "rollback target is not a TUN device"
    );
    Ok(())
}

fn verify_linux_tun_helper_residue(device: &str, route: &str) -> Result<()> {
    anyhow::ensure!(
        !command_success("ip", &["link", "show", "dev", device]),
        "TUN helper smoke residue remains for device {device}"
    );
    let route_output =
        command_stdout("ip", &["route", "show", route]).context("check route residue")?;
    anyhow::ensure!(
        !route_output.contains(device),
        "TUN helper smoke route residue remains for {route}"
    );
    Ok(())
}

fn phase_a_route_probe(route: &str) -> Result<String> {
    match route {
        "192.0.2.0/24" => Ok("192.0.2.1".to_owned()),
        "198.51.100.0/24" => Ok("198.51.100.1".to_owned()),
        "203.0.113.0/24" => Ok("203.0.113.1".to_owned()),
        _ => anyhow::bail!("TUN helper smoke route probe requires documentation /24 route"),
    }
}

fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn command_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    command_stdout(program, args).map(|_| ())
}

fn parse_tun_routes(raw_routes: &[String]) -> Result<Vec<TunRoute>> {
    raw_routes.iter().map(|raw| parse_tun_route(raw)).collect()
}

fn parse_tun_route(raw: &str) -> Result<TunRoute> {
    let (addr, prefix) = raw
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("tun route must be CIDR formatted: {raw}"))?;
    let network: IpAddr = addr
        .parse()
        .with_context(|| format!("parse TUN route address: {raw}"))?;
    let prefix_len: u8 = prefix
        .parse()
        .with_context(|| format!("parse TUN route prefix length: {raw}"))?;
    Ok(TunRoute::new(network, prefix_len))
}

fn abstract_tun_apply_context() -> TunApplySafetyContext {
    TunApplySafetyContext {
        dry_run_completed: true,
        operator_approved: true,
        approved_host: true,
        platform_supported: true,
        privileges_confirmed: true,
        proxy_vpn_conflict_checked: true,
        rollback_plan_writable: true,
    }
}

fn describe_tun_runtime_action(action: &TunRuntimeAction) -> String {
    match action {
        TunRuntimeAction::RecordRollbackPlan {
            rollback_action_count,
        } => format!("record rollback plan with {rollback_action_count} actions"),
        TunRuntimeAction::CreateTunDevice { device_name } => {
            format!("create tun device {device_name}")
        }
        TunRuntimeAction::BringDeviceUp { device_name } => {
            format!("bring tun device up {device_name}")
        }
        TunRuntimeAction::PreserveRoute { cidr } => format!("preserve route {cidr}"),
        TunRuntimeAction::AddRoute { cidr, device_name } => {
            format!("add route {cidr} via {device_name}")
        }
        TunRuntimeAction::SetDnsServers { servers } => {
            format!("set dns servers {}", servers.join(","))
        }
    }
}

fn describe_tun_runtime_rollback_action(action: &TunRuntimeRollbackAction) -> String {
    match action {
        TunRuntimeRollbackAction::RestoreDnsServers => "restore dns servers".to_owned(),
        TunRuntimeRollbackAction::RestoreRoute { cidr } => format!("restore route {cidr}"),
        TunRuntimeRollbackAction::DeleteRoute { cidr, device_name } => {
            format!("delete route {cidr} via {device_name}")
        }
        TunRuntimeRollbackAction::DeleteTunDevice { device_name } => {
            format!("delete tun device {device_name}")
        }
    }
}

fn print_experimental_track_list() {
    for line in experimental_track_report() {
        println!("{line}");
    }
}

fn experimental_track_report() -> Vec<String> {
    let mut report = vec!["experimental-tracks".to_owned()];
    for descriptor in experimental_track_registry() {
        report.push(format!("track: {}", descriptor.track));
        report.push(format!("title: {}", descriptor.title));
        report.push(format!("status: {}", descriptor.status));
        report.push(format!(
            "build_gate: {}",
            descriptor.build_gate.unwrap_or("none")
        ));
        report.push(format!(
            "runtime_gate: {}",
            descriptor.runtime_gate.unwrap_or("none")
        ));
        report.push(format!(
            "default: {}",
            if descriptor.default_enabled {
                "on"
            } else {
                "off"
            }
        ));
        report.push(format!(
            "requires_external_test_host: {}",
            descriptor.requires_external_test_host
        ));
        report.push(format!(
            "default_security_claim: {}",
            if descriptor.no_default_security_claim {
                "excluded"
            } else {
                "included"
            }
        ));
    }
    report
}

fn rotation_lint_report(
    cfg: &ServerConfig,
    requested_user: Option<&str>,
    now: OffsetDateTime,
) -> Result<Vec<String>> {
    let users = if let Some(user_id) = requested_user {
        let matched: Vec<_> = cfg.users.iter().filter(|user| user.id == user_id).collect();
        anyhow::ensure!(
            !matched.is_empty(),
            "user not found: {}",
            redact_id(user_id)
        );
        matched
    } else {
        cfg.users.iter().collect()
    };

    let mut warnings = 0usize;
    let mut report = Vec::new();
    for user in users {
        let Some(rotation) = &user.rotation else {
            report.push(format!(
                "user: {} enabled={} rotation=absent",
                redact_id(&user.id),
                user.enabled
            ));
            continue;
        };

        let next_id = rotation
            .next
            .as_ref()
            .map(|next| redact_id(&next.id))
            .unwrap_or_else(|| "absent".into());
        report.push(format!(
            "user: {} enabled={} previous_credentials={} next_credential_id={}",
            redact_id(&user.id),
            user.enabled,
            rotation.previous.len(),
            next_id
        ));
        if !user.enabled {
            warnings += 1;
            report.push(format!(
                "warning: disabled_user_has_rotation_state user={}",
                redact_id(&user.id)
            ));
        }

        for previous in &rotation.previous {
            let not_before = parse_rotation_timestamp(&previous.not_before)?;
            let not_after = parse_rotation_timestamp(&previous.not_after)?;
            let state = if now < not_before {
                "pending"
            } else if now >= not_after {
                warnings += 1;
                "expired"
            } else {
                "active_overlap"
            };
            report.push(format!(
                "previous_credential: {} state={} window={}..{} secret=[REDACTED]",
                redact_id(&previous.id),
                state,
                previous.not_before,
                previous.not_after
            ));
            if state == "expired" {
                report.push(format!(
                    "warning: previous_credential_expired user={} credential={} not_after={}",
                    redact_id(&user.id),
                    redact_id(&previous.id),
                    previous.not_after
                ));
            }
        }

        if let Some(next) = &rotation.next {
            let not_before = parse_rotation_timestamp(&next.not_before)?;
            let state = if now >= not_before {
                warnings += 1;
                "ready_for_promotion"
            } else {
                "scheduled"
            };
            report.push(format!(
                "next_credential: {} state={} not_before={} secret_material=operator_supplied",
                redact_id(&next.id),
                state,
                next.not_before
            ));
            if state == "ready_for_promotion" {
                report.push(format!(
                    "warning: next_credential_ready_for_promotion user={} credential={} not_before={}",
                    redact_id(&user.id),
                    redact_id(&next.id),
                    next.not_before
                ));
            }
        } else {
            report.push("next_credential: absent".into());
        }
    }
    report.insert(0, format!("warnings: {warnings}"));
    Ok(report)
}

fn parse_rotation_timestamp(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).context("parse RFC3339 rotation timestamp")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileUri {
    server: String,
    server_name: String,
    tunnel_path: String,
    mode: Mode,
    credential_id: Option<String>,
    secret: Option<SecretString>,
    cert_pin: Option<String>,
    experimental_h3: bool,
    experimental_ech: bool,
    experimental_tun: bool,
}

fn export_config_uri(path: &Path, include_secret: bool, qr: bool) -> Result<()> {
    validate_qr_export(include_secret, qr)?;
    let cfg = read_client_config(&path.to_path_buf())?;
    let profile = ProfileUri {
        server: cfg.server.address,
        server_name: cfg.server.server_name,
        tunnel_path: cfg.server.tunnel_path,
        mode: cfg.mode,
        credential_id: Some(cfg.server.credential_id),
        secret: include_secret.then_some(cfg.server.secret),
        cert_pin: cfg.server.cert_pin,
        experimental_h3: cfg.advanced.experimental_h3,
        experimental_ech: cfg.advanced.experimental_ech,
        experimental_tun: cfg.advanced.experimental_tun,
    };
    let uri = profile.to_uri();
    if qr {
        println!("{}", render_profile_qr(&uri)?);
    } else {
        println!("{uri}");
    }
    Ok(())
}

fn validate_qr_export(include_secret: bool, qr: bool) -> Result<()> {
    if include_secret && qr {
        anyhow::bail!(
            "refusing to render a secret-bearing profile URI as QR; omit --include-secret for QR export"
        );
    }
    Ok(())
}

fn render_profile_qr(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes()).context("encode profile URI as QR")?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .module_dimensions(1, 1)
        .build())
}

trait ClipboardReader {
    fn read_profile_uri(&self) -> Result<String>;

    fn clear_profile_uri(&self) -> Result<()> {
        Ok(())
    }
}

struct OsClipboardReader;

impl ClipboardReader for OsClipboardReader {
    fn read_profile_uri(&self) -> Result<String> {
        read_os_clipboard()
    }

    fn clear_profile_uri(&self) -> Result<()> {
        clear_os_clipboard()
    }
}

fn import_config_uri_from_args(
    uri: Option<&str>,
    clipboard: bool,
    dry_run: bool,
    output: Option<&Path>,
) -> Result<()> {
    if clipboard {
        return import_config_uri_from_clipboard(&OsClipboardReader, dry_run, output);
    }
    let uri = uri.context("--uri is required unless --clipboard is set")?;
    let uri = if uri == "-" {
        read_profile_uri_from_stdin()?
    } else {
        if profile_uri_contains_secret(uri) {
            eprintln!(
                "warning: secret-bearing profile URI was passed via argv; prefer --uri - or --clipboard"
            );
        }
        uri.to_owned()
    };
    import_config_uri(&uri, dry_run, output)
}

fn import_config_uri_from_clipboard(
    reader: &impl ClipboardReader,
    dry_run: bool,
    output: Option<&Path>,
) -> Result<()> {
    let payload = reader.read_profile_uri()?;
    anyhow::ensure!(
        !payload.trim().is_empty(),
        "clipboard does not contain a Maverick profile URI"
    );
    let result = import_config_uri(&payload, dry_run, output);
    if result.is_ok() {
        if let Err(err) = reader.clear_profile_uri() {
            eprintln!("warning: failed to clear OS clipboard after import: {err}");
        }
    }
    result
}

fn read_profile_uri_from_stdin() -> Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read profile URI from stdin")?;
    Ok(input)
}

fn profile_uri_contains_secret(uri: &str) -> bool {
    uri.contains("secret=") || uri.contains("secret%3D")
}

#[cfg(target_os = "macos")]
fn read_os_clipboard() -> Result<String> {
    read_clipboard_command("pbpaste", &[])
}

#[cfg(target_os = "macos")]
fn clear_os_clipboard() -> Result<()> {
    write_clipboard_command("pbcopy", &[], b"")
}

#[cfg(target_os = "windows")]
fn read_os_clipboard() -> Result<String> {
    read_clipboard_command(
        "powershell",
        &["-NoProfile", "-Command", "Get-Clipboard -Raw"],
    )
}

#[cfg(target_os = "windows")]
fn clear_os_clipboard() -> Result<()> {
    run_clipboard_command(
        "powershell",
        &["-NoProfile", "-Command", "Set-Clipboard -Value ''"],
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn read_os_clipboard() -> Result<String> {
    if let Ok(text) = read_clipboard_command("wl-paste", &["--no-newline"]) {
        return Ok(text);
    }
    if let Ok(text) = read_clipboard_command("xclip", &["-selection", "clipboard", "-o"]) {
        return Ok(text);
    }
    anyhow::bail!("no supported OS clipboard command found; pass --uri instead")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn clear_os_clipboard() -> Result<()> {
    if run_clipboard_command("wl-copy", &["--clear"]).is_ok() {
        return Ok(());
    }
    write_clipboard_command("xclip", &["-selection", "clipboard"], b"")
}

#[cfg(not(any(unix, target_os = "windows")))]
fn read_os_clipboard() -> Result<String> {
    anyhow::bail!("OS clipboard import is not supported on this platform; pass --uri instead")
}

#[cfg(not(any(unix, target_os = "windows")))]
fn clear_os_clipboard() -> Result<()> {
    anyhow::bail!("OS clipboard clear is not supported on this platform")
}

#[cfg(any(unix, target_os = "windows"))]
fn read_clipboard_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run OS clipboard command {program}"))?;
    anyhow::ensure!(
        output.status.success(),
        "OS clipboard command {program} failed"
    );
    String::from_utf8(output.stdout).context("OS clipboard payload is not valid UTF-8")
}

#[cfg(any(all(unix, not(target_os = "macos")), target_os = "windows"))]
fn run_clipboard_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run OS clipboard command {program}"))?;
    anyhow::ensure!(status.success(), "OS clipboard command {program} failed");
    Ok(())
}

#[cfg(unix)]
fn write_clipboard_command(program: &str, args: &[&str], input: &[u8]) -> Result<()> {
    use std::process::Stdio;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("run OS clipboard command {program}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input)
            .with_context(|| format!("write OS clipboard command {program}"))?;
    }
    let status = child
        .wait()
        .with_context(|| format!("wait for OS clipboard command {program}"))?;
    anyhow::ensure!(status.success(), "OS clipboard command {program} failed");
    Ok(())
}

fn import_config_uri(uri: &str, dry_run: bool, output: Option<&Path>) -> Result<()> {
    let profile = ProfileUri::parse(uri)?;
    if dry_run || output.is_none() {
        print_config_uri_import_summary(&profile, output);
        return Ok(());
    }

    let output = output.expect("checked output is_some");
    if output.exists() {
        anyhow::bail!(
            "refusing to overwrite existing config: {}",
            output.display()
        );
    }
    let cfg = profile.to_client_config()?;
    let yaml = client_config_secret_yaml(&cfg);
    write_secret_config_file(output, yaml)?;
    println!("config-uri import wrote client config");
    println!("output: {}", output.display());
    println!("secret: [REDACTED]");
    Ok(())
}

fn write_secret_config_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("write {}", path.display()))?;
        file.write_all(contents.as_ref())
            .with_context(|| format!("write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("write {}", path.display()))?;
        file.write_all(contents.as_ref())
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn print_config_uri_import_summary(profile: &ProfileUri, output: Option<&Path>) {
    println!("config-uri import dry-run");
    println!("status: parsed");
    if let Some(output) = output {
        println!("output: {}", output.display());
        println!("would_write: true");
    }
    println!("server: {}", profile.server);
    println!("server_name: {}", profile.server_name);
    println!("tunnel_path: {}", profile.tunnel_path);
    println!("mode: {}", mode_name(profile.mode));
    println!(
        "credential_id: {}",
        profile.credential_id.as_deref().unwrap_or("[MISSING]")
    );
    println!(
        "secret: {}",
        if profile.secret.is_some() {
            "[REDACTED]"
        } else {
            "[MISSING]"
        }
    );
    println!(
        "cert_pin: {}",
        profile.cert_pin.as_deref().unwrap_or("[MISSING]")
    );
    println!("experimental_h3: {}", profile.experimental_h3);
    println!("experimental_ech: {}", profile.experimental_ech);
    println!("experimental_tun: {}", profile.experimental_tun);
}

fn client_config_secret_yaml(cfg: &ClientConfig) -> String {
    let cert_pin = cfg
        .server
        .cert_pin
        .as_deref()
        .map(yaml_double_quoted)
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"version: 1
mode: {}

local:
  socks5:
    listen: "127.0.0.1:1080"
  dns: null
  http_connect: null

server:
  address: {}
  server_name: {}
  tunnel_path: {}
  credential_id: {}
  secret: {}
  ca_cert: null
  cert_pin: {cert_pin}

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
    require: false
  rotation:
    active_epoch: null
    next_credential_id: null
    auto_switch: false
    next: null

log:
  level: "info"
  redact: true

advanced:
  connect_timeout_ms: 10000
  idle_timeout_secs: 300
  max_concurrent_flows: 256
  padding: "auto"
  udp_idle_timeout_ms: 30000
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
  allow_non_loopback_listeners: false
  experimental_h3: {}
  experimental_cloudflare_ws: false
  experimental_ech: {}
  experimental_tun: {}
  ech_fallback_policy: "fail_closed"
  crypto:
    offered_suites:
      - "tls13"
    allow_experimental: false
    require_experimental: false
"#,
        mode_name(cfg.mode),
        yaml_double_quoted(&cfg.server.address),
        yaml_double_quoted(&cfg.server.server_name),
        yaml_double_quoted(&cfg.server.tunnel_path),
        yaml_double_quoted(&cfg.server.credential_id),
        yaml_double_quoted(cfg.server.secret.expose_secret()),
        cfg.advanced.experimental_h3,
        cfg.advanced.experimental_ech,
        cfg.advanced.experimental_tun,
    )
}

fn yaml_double_quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

impl ProfileUri {
    fn parse(input: &str) -> Result<Self> {
        let input = normalize_profile_uri_payload(input)?;
        let url = Url::parse(input).context("parse profile URI")?;
        anyhow::ensure!(url.scheme() == "maverick", "URI scheme must be maverick");
        anyhow::ensure!(
            url.host_str() == Some("profile") && url.path() == "/v1",
            "unsupported Maverick profile URI version"
        );
        let server = required_profile_query(&url, "server")?;
        let server_name = required_profile_query(&url, "name")?;
        let tunnel_path = required_profile_query(&url, "path")?;
        anyhow::ensure!(
            tunnel_path.starts_with('/'),
            "profile path must start with '/'"
        );
        let mode = parse_mode(&required_profile_query(&url, "mode")?)?;
        let credential_id = optional_profile_query(&url, "credential_id")?;
        if credential_id.as_deref() == Some("") {
            anyhow::bail!("credential_id must not be empty");
        }
        let secret = optional_profile_query(&url, "secret")?
            .map(SecretString::new)
            .transpose()?;
        let cert_pin = optional_profile_query(&url, "cert_pin")?;
        if let Some(pin) = &cert_pin {
            validate_profile_cert_pin(pin)?;
        }
        let experimental_h3 = parse_bool_query(&url, "experimental_h3")?.unwrap_or(false);
        let experimental_ech = parse_bool_query(&url, "experimental_ech")?.unwrap_or(false);
        let experimental_tun = parse_bool_query(&url, "experimental_tun")?.unwrap_or(false);
        anyhow::ensure!(
            !experimental_ech,
            "experimental_ech is not supported by this binary"
        );
        Ok(Self {
            server,
            server_name,
            tunnel_path,
            mode,
            credential_id,
            secret,
            cert_pin,
            experimental_h3,
            experimental_ech,
            experimental_tun,
        })
    }

    fn to_uri(&self) -> String {
        let mut url = Url::parse("maverick://profile/v1").expect("static URI is valid");
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("server", &self.server);
            pairs.append_pair("name", &self.server_name);
            pairs.append_pair("path", &self.tunnel_path);
            pairs.append_pair("mode", mode_name(self.mode));
            if let Some(credential_id) = &self.credential_id {
                pairs.append_pair("credential_id", credential_id);
            }
            if let Some(secret) = &self.secret {
                pairs.append_pair("secret", secret.expose_secret());
            }
            if let Some(cert_pin) = &self.cert_pin {
                pairs.append_pair("cert_pin", cert_pin);
            }
            if self.experimental_h3 {
                pairs.append_pair("experimental_h3", "true");
            }
            if self.experimental_ech {
                pairs.append_pair("experimental_ech", "true");
            }
            if self.experimental_tun {
                pairs.append_pair("experimental_tun", "true");
            }
        }
        url.to_string()
    }

    fn to_client_config(&self) -> Result<ClientConfig> {
        let credential_id = self
            .credential_id
            .clone()
            .context("profile URI must include credential_id to write config")?;
        let secret = self
            .secret
            .clone()
            .context("profile URI must include secret to write config")?;
        let cfg = ClientConfig {
            version: 1,
            mode: self.mode,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:1080".parse()?,
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: self.server.clone(),
                server_name: self.server_name.clone(),
                tunnel_path: self.tunnel_path.clone(),
                credential_id,
                secret,
                ca_cert: None,
                cert_pin: self.cert_pin.clone(),
            },
            auth: Default::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig {
                experimental_h3: self.experimental_h3,
                experimental_ech: self.experimental_ech,
                experimental_tun: self.experimental_tun,
                ..ClientAdvancedConfig::default()
            },
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

fn normalize_profile_uri_payload(input: &str) -> Result<&str> {
    let mut lines = input.lines().map(str::trim).filter(|line| !line.is_empty());
    let uri = lines
        .next()
        .context("profile URI payload must contain one URI")?;
    anyhow::ensure!(
        lines.next().is_none(),
        "profile URI payload must contain exactly one non-empty URI"
    );
    Ok(uri)
}

fn required_query(url: &Url, key: &str) -> Result<String> {
    optional_query(url, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required query field: {key}"))
}

fn required_profile_query(url: &Url, key: &str) -> Result<String> {
    let value = required_query(url, key)?;
    validate_profile_query_value(key, &value)?;
    Ok(value)
}

fn optional_query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(field, _)| field == key)
        .map(|(_, value)| value.into_owned())
}

fn optional_profile_query(url: &Url, key: &str) -> Result<Option<String>> {
    let Some(value) = optional_query(url, key) else {
        return Ok(None);
    };
    validate_profile_query_value(key, &value)?;
    Ok(Some(value))
}

fn validate_profile_query_value(key: &str, value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "profile URI field {key} must not contain control characters"
    );
    Ok(())
}

fn parse_bool_query(url: &Url, key: &str) -> Result<Option<bool>> {
    optional_query(url, key)
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => anyhow::bail!("{key} must be true or false"),
        })
        .transpose()
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value {
        "auto" => Ok(Mode::Auto),
        "stable" => Ok(Mode::Stable),
        "private" => Ok(Mode::Private),
        _ => anyhow::bail!("mode must be auto, stable, or private"),
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Auto => "auto",
        Mode::Stable => "stable",
        Mode::Private => "private",
    }
}

fn validate_profile_cert_pin(pin: &str) -> Result<()> {
    let encoded = pin
        .strip_prefix("sha256/")
        .ok_or_else(|| anyhow::anyhow!("cert_pin must use sha256/<base64url-no-pad>"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .context("cert_pin is not valid base64url")?;
    anyhow::ensure!(
        decoded.len() == 32,
        "cert_pin SHA-256 value must be 32 bytes"
    );
    Ok(())
}

fn migration_report(kind: &str, input: &str) -> Result<Vec<String>> {
    match kind {
        "client" => {
            ClientConfig::from_yaml_str(input)?;
            migration_defaults(
                input,
                &[
                    "advanced.experimental_h3",
                    "advanced.udp_idle_timeout_ms",
                    "advanced.shaping.enabled",
                    "advanced.experimental_ech",
                    "advanced.experimental_tun",
                    "advanced.ech_fallback_policy",
                    "advanced.crypto.offered_suites",
                    "auth.v2.enabled",
                    "auth.rotation.auto_switch",
                    "auth.rotation.next",
                ],
            )
        }
        "server" => {
            ServerConfig::from_yaml_str(input)?;
            migration_defaults(
                input,
                &[
                    "advanced.experimental_h3",
                    "advanced.udp_idle_timeout_ms",
                    "advanced.pre_auth_max_concurrent",
                    "advanced.auth_failure_window_secs",
                    "advanced.max_auth_failures_per_window",
                    "advanced.auth_failure_cache_max_entries",
                    "advanced.shaping.enabled",
                    "advanced.experimental_ech",
                    "advanced.crypto.offered_suites",
                    "auth.v2.enabled",
                ],
            )
        }
        _ => anyhow::bail!("kind must be client or server"),
    }
}

fn migration_defaults(input: &str, fields: &[&str]) -> Result<Vec<String>> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(input)?;
    Ok(fields
        .iter()
        .filter(|field| !yaml_has_path(&value, field))
        .map(|field| match *field {
            "advanced.experimental_h3" => "advanced.experimental_h3=false".to_owned(),
            "advanced.udp_idle_timeout_ms" => "advanced.udp_idle_timeout_ms=30000".to_owned(),
            "advanced.pre_auth_max_concurrent" => "advanced.pre_auth_max_concurrent=512".to_owned(),
            "advanced.auth_failure_window_secs" => {
                "advanced.auth_failure_window_secs=60".to_owned()
            }
            "advanced.max_auth_failures_per_window" => {
                "advanced.max_auth_failures_per_window=24".to_owned()
            }
            "advanced.auth_failure_cache_max_entries" => {
                "advanced.auth_failure_cache_max_entries=4096".to_owned()
            }
            "advanced.shaping.enabled" => "advanced.shaping.enabled=false".to_owned(),
            "advanced.experimental_ech" => "advanced.experimental_ech=false".to_owned(),
            "advanced.experimental_tun" => "advanced.experimental_tun=false".to_owned(),
            "advanced.ech_fallback_policy" => "advanced.ech_fallback_policy=fail_closed".to_owned(),
            "advanced.crypto.offered_suites" => "advanced.crypto.offered_suites=[tls13]".to_owned(),
            "auth.v2.enabled" => "auth.v2.enabled=false".to_owned(),
            "auth.rotation.auto_switch" => "auth.rotation.auto_switch=false".to_owned(),
            "auth.rotation.next" => "auth.rotation.next=null".to_owned(),
            other => other.to_owned(),
        })
        .collect())
}

fn yaml_has_path(value: &serde_yaml_ng::Value, path: &str) -> bool {
    let mut current = value;
    for segment in path.split('.') {
        let Some(next) = current.get(segment) else {
            return false;
        };
        current = next;
    }
    true
}

fn read_client_config(path: &PathBuf) -> Result<ClientConfig> {
    warn_if_config_permissions_loose(path)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ClientConfig::from_yaml_str(&input).map_err(Into::into)
}

fn read_server_config(path: &PathBuf) -> Result<ServerConfig> {
    warn_if_config_permissions_loose(path)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ServerConfig::from_yaml_str(&input).map_err(Into::into)
}

fn read_client_config_for_start(
    path: &PathBuf,
    allow_loose_permissions: bool,
) -> Result<ClientConfig> {
    enforce_config_permissions(path, allow_loose_permissions)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ClientConfig::from_yaml_str(&input).map_err(Into::into)
}

fn read_server_config_for_start(
    path: &PathBuf,
    allow_loose_permissions: bool,
) -> Result<ServerConfig> {
    enforce_config_permissions(path, allow_loose_permissions)?;
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ServerConfig::from_yaml_str(&input).map_err(Into::into)
}

fn warn_if_config_permissions_loose(path: &Path) -> Result<()> {
    if let Some(warning) = config_permission_warning(path)? {
        eprintln!("{warning}");
    }
    Ok(())
}

fn enforce_config_permissions(path: &Path, allow_loose_permissions: bool) -> Result<()> {
    if let Some(warning) = config_permission_warning(path)? {
        if allow_loose_permissions {
            eprintln!("{warning}");
            return Ok(());
        }
        anyhow::bail!(
            "{}; refusing to start without --allow-loose-permissions",
            warning
        );
    }
    Ok(())
}

fn config_permission_warning(path: &Path) -> Result<Option<String>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path)
            .with_context(|| format!("inspect permissions {}", path.display()))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Ok(Some(format!(
                "warning: {} is accessible by group/other users; consider chmod 600",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(None)
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn random_id() -> String {
    use rand::TryRngCore;

    let mut bytes = [0u8; 9];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS random generator failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn example_client_config(secret: &str) -> String {
    format!(
        r#"version: 1
mode: auto

local:
  socks5:
    listen: "127.0.0.1:1080"
  dns:
    enabled: true
    listen: "127.0.0.1:5353"
  http_connect:
    enabled: false
    listen: "127.0.0.1:18080"

server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_example"
  secret: "{secret}"
  ca_cert: null
  cert_pin: null

auth:
  v2:
    enabled: false
    require: false
  rotation:
    active_epoch: null
    next_credential_id: null
    auto_switch: false
    next: null

log:
  level: "info"
  redact: true

advanced:
  connect_timeout_ms: 10000
  idle_timeout_secs: 300
  max_concurrent_flows: 256
  padding: "auto"
  udp_idle_timeout_ms: 30000
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
  allow_non_loopback_listeners: false
  experimental_h3: false
  experimental_cloudflare_ws: false
  experimental_ech: false
  experimental_tun: false
  ech_fallback_policy: "fail_closed"
  crypto:
    offered_suites:
      - "tls13"
    allow_experimental: false
    require_experimental: false
"#
    )
}

fn example_server_config(secret: &str) -> String {
    format!(
        r#"version: 1
listen: "0.0.0.0:443"

tls:
  cert_path: "./certs/fullchain.pem"
  key_path: "./certs/privkey.pem"

maverick:
  tunnel_path: "/assets/upload"
  mode_default: "auto"
  replay_window_secs: 120
  replay_cache_entries_per_credential: 16384
  replay_cache_max_credentials_per_shard: 1024
  max_concurrent_flows_per_user: 128

users:
  - id: "u_example"
    name: "alice"
    secret: "{secret}"
    enabled: true
    rate_limit: null
    max_concurrent_flows: null
    rotation: null

fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"

# Alternative:
# fallback:
#   type: "reverse_proxy"
#   upstream: "http://127.0.0.1:8080"

dns:
  upstream: "1.1.1.1:53"
  timeout_ms: 5000

metrics:
  enabled: false
  listen: "127.0.0.1:19090"

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
    require: false

log:
  level: "info"
  redact: true

advanced:
  idle_timeout_secs: 300
  tcp_connect_timeout_ms: 10000
  handshake_timeout_ms: 10000
  max_concurrent_connections: 2048
  max_concurrent_connections_per_source: 256
  pre_auth_max_concurrent: 512
  fallback_max_concurrent: 512
  h2_max_concurrent_streams: 256
  h2_max_concurrent_reset_streams: 50
  h2_max_pending_accept_reset_streams: 20
  h2_max_local_error_reset_streams: 1024
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
  max_frame_size: 65536
  udp_idle_timeout_ms: 30000
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
  egress:
    allow_loopback: false
    allow_private: false
    allow_link_local: false
    allow_multicast: false
    allow_unspecified: false
  experimental_h3: false
  experimental_cloudflare_ws: false
  experimental_ech: false
  crypto:
    offered_suites:
      - "tls13"
    allow_experimental: false
    require_experimental: false
"#
    )
}

async fn bench_local(
    bytes: usize,
    concurrency: usize,
    mode: Mode,
    client_shaping: bool,
    server_shaping: bool,
) -> Result<()> {
    anyhow::ensure!(
        (1..=128).contains(&concurrency),
        "concurrency must be between 1 and 128"
    );
    init_tracing("warn");
    let echo_addr = start_echo_server().await?;
    let direct = time_echo_roundtrip(echo_addr, bytes).await?;

    let tmp = tempfile::tempdir()?;
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    fs::write(&cert_path, certified.cert.pem())?;
    fs::write(&key_path, certified.key_pair.serialize_pem())?;
    fs::write(
        tmp.path().join("index.html"),
        "<html><body>Maverick</body></html>",
    )?;

    let secret = SecretString::generate();
    let mut server_advanced = ServerAdvancedConfig::default();
    server_advanced.egress.allow_loopback = true;
    if server_shaping {
        server_advanced.shaping = ShapingConfig {
            enabled: true,
            ..ShapingConfig::default()
        };
    }
    let server = start_server(ServerConfig {
        version: 1,
        listen: "127.0.0.1:0".parse()?,
        tls: TlsConfig {
            cert_path: cert_path.clone(),
            key_path,
        },
        maverick: MaverickServerConfig {
            tunnel_path: "/assets/upload".into(),
            mode_default: mode,
            replay_window_secs: 120,
            replay_cache_entries_per_credential: 16_384,
            replay_cache_max_credentials_per_shard: 1_024,
            max_concurrent_flows_per_user: 128,
        },
        users: vec![UserConfig {
            id: "u_bench".into(),
            name: Some("bench".into()),
            secret: secret.clone(),
            enabled: true,
            rate_limit: None,
            max_concurrent_flows: None,
            rotation: None,
        }],
        fallback: FallbackConfig::Static {
            static_dir: tmp.path().to_path_buf(),
            index: "index.html".into(),
        },
        auth: Default::default(),
        dns: None,
        metrics: None,
        log: LogConfig::default(),
        advanced: server_advanced,
    })
    .await?;
    let mut client_advanced = ClientAdvancedConfig::default();
    if client_shaping {
        client_advanced.shaping = ShapingConfig {
            enabled: true,
            ..ShapingConfig::default()
        };
    }
    let client = start_client(ClientConfig {
        version: 1,
        mode,
        local: LocalConfig {
            socks5: Socks5Config {
                listen: "127.0.0.1:0".parse()?,
            },
            dns: None,
            http_connect: None,
        },
        server: ClientServerConfig {
            address: server.local_addr.to_string(),
            server_name: "localhost".into(),
            tunnel_path: "/assets/upload".into(),
            credential_id: "u_bench".into(),
            secret,
            ca_cert: Some(cert_path),
            cert_pin: None,
        },
        auth: Default::default(),
        log: LogConfig::default(),
        advanced: client_advanced,
    })
    .await?;

    let proxied =
        time_concurrent_socks_echo_roundtrips(client.local_addr, echo_addr, bytes, concurrency)
            .await?;
    println!("payload_bytes: {bytes}");
    println!("concurrency: {concurrency}");
    println!("mode: {}", mode_name(mode));
    println!("client_shaping: {client_shaping}");
    println!("server_shaping: {server_shaping}");
    println!(
        "direct_tcp_roundtrip_ms: {:.3}",
        direct.as_secs_f64() * 1000.0
    );
    println!(
        "maverick_socks_roundtrip_ms: {:.3}",
        proxied.as_secs_f64() * 1000.0
    );
    println!(
        "overhead_ratio: {:.3}",
        proxied.as_secs_f64() / direct.as_secs_f64().max(0.000_001)
    );
    println!(
        "maverick_socks_avg_per_flow_ms: {:.3}",
        (proxied.as_secs_f64() * 1000.0) / concurrency as f64
    );

    client.shutdown().await?;
    server.shutdown().await?;
    Ok(())
}

async fn time_echo_roundtrip(addr: SocketAddr, bytes: usize) -> Result<std::time::Duration> {
    let mut stream = TcpStream::connect(addr).await?;
    let payload = deterministic_payload(bytes);
    let start = Instant::now();
    stream.write_all(&payload).await?;
    let mut echoed = vec![0u8; bytes];
    stream.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == payload, "echo mismatch");
    Ok(start.elapsed())
}

async fn time_socks_echo_roundtrip(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    bytes: usize,
) -> Result<std::time::Duration> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "SOCKS method rejected");
    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&target_addr.port().to_be_bytes());
    stream.write_all(&connect).await?;
    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await?;
    anyhow::ensure!(connect_reply[1] == 0x00, "SOCKS connect failed");

    let payload = deterministic_payload(bytes);
    let start = Instant::now();
    stream.write_all(&payload).await?;
    let mut echoed = vec![0u8; bytes];
    stream.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == payload, "echo mismatch");
    Ok(start.elapsed())
}

async fn time_concurrent_socks_echo_roundtrips(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    bytes: usize,
    concurrency: usize,
) -> Result<std::time::Duration> {
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..concurrency {
        tasks.spawn(time_socks_echo_roundtrip(socks_addr, target_addr, bytes));
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(start.elapsed())
}

fn deterministic_payload(bytes: usize) -> Vec<u8> {
    (0..bytes).map(|idx| (idx % 251) as u8).collect()
}

fn cert_pin_from_pem(input: &[u8]) -> Result<String> {
    let cert = CertificateDer::from_pem_slice(input).context("parse certificate PEM")?;
    let digest = Sha256::digest(cert.as_ref());
    Ok(format!("sha256/{}", URL_SAFE_NO_PAD.encode(digest)))
}

async fn start_echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn warns_for_group_readable_config() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, "version: 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config_permission_warning(&path).unwrap().is_some());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(config_permission_warning(&path).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn start_config_permission_gate_requires_explicit_override() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, "version: 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(enforce_config_permissions(&path, false).is_err());
        assert!(enforce_config_permissions(&path, true).is_ok());
    }

    #[test]
    fn computes_cert_pin_from_pem() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = cert_pin_from_pem(certified.cert.pem().as_bytes()).unwrap();
        assert!(pin.starts_with("sha256/"));
        assert_eq!(pin.len(), "sha256/".len() + 43);
    }

    #[test]
    fn bench_local_parses_shaping_scenario_flags() {
        let cli = Cli::try_parse_from([
            "maverick",
            "bench-local",
            "--bytes",
            "256",
            "--concurrency",
            "2",
            "--mode",
            "private",
            "--client-shaping",
            "--server-shaping",
        ])
        .unwrap();
        match cli.command {
            Commands::BenchLocal {
                bytes,
                concurrency,
                mode,
                client_shaping,
                server_shaping,
            } => {
                assert_eq!(bytes, 256);
                assert_eq!(concurrency, 2);
                assert_eq!(mode, "private");
                assert!(client_shaping);
                assert!(server_shaping);
            }
            _ => panic!("expected bench-local command"),
        }
    }

    #[test]
    fn tun_helper_label_accepts_only_fixed_approved_host() {
        assert!(is_approved_host_label("approved-linux-vm"));
        assert!(!is_approved_host_label("anything"));
        assert!(!is_approved_host_label("localhost"));
    }

    #[test]
    fn config_uri_export_parses_qr_flag() {
        let cli = Cli::try_parse_from([
            "maverick",
            "config-uri",
            "export",
            "--client",
            "client.yaml",
            "--qr",
        ])
        .unwrap();
        match cli.command {
            Commands::ConfigUri {
                command:
                    ConfigUriCommand::Export {
                        client,
                        include_secret,
                        qr,
                    },
            } => {
                assert_eq!(client, PathBuf::from("client.yaml"));
                assert!(!include_secret);
                assert!(qr);
            }
            _ => panic!("expected config-uri export command"),
        }
    }

    #[test]
    fn config_uri_import_parses_clipboard_flag() {
        let cli = Cli::try_parse_from([
            "maverick",
            "config-uri",
            "import",
            "--clipboard",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Commands::ConfigUri {
                command:
                    ConfigUriCommand::Import {
                        uri,
                        clipboard,
                        dry_run,
                        output,
                    },
            } => {
                assert!(uri.is_none());
                assert!(clipboard);
                assert!(dry_run);
                assert!(output.is_none());
            }
            _ => panic!("expected config-uri import command"),
        }
    }

    #[test]
    fn config_uri_import_accepts_stdin_sentinel() {
        let cli = Cli::try_parse_from([
            "maverick",
            "config-uri",
            "import",
            "--uri",
            "-",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Commands::ConfigUri {
                command:
                    ConfigUriCommand::Import {
                        uri,
                        clipboard,
                        dry_run,
                        output,
                    },
            } => {
                assert_eq!(uri.as_deref(), Some("-"));
                assert!(!clipboard);
                assert!(dry_run);
                assert!(output.is_none());
            }
            _ => panic!("expected config-uri import command"),
        }
    }

    #[test]
    fn secret_bearing_profile_uri_is_detected_for_argv_warning() {
        assert!(profile_uri_contains_secret(
            "maverick://profile/v1?server=example.com&secret=mv1_placeholder"
        ));
        assert!(!profile_uri_contains_secret(
            "maverick://profile/v1?server=example.com"
        ));
    }

    #[test]
    fn config_uri_import_rejects_uri_and_clipboard_together() {
        let err = Cli::try_parse_from([
            "maverick",
            "config-uri",
            "import",
            "--uri",
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload",
            "--clipboard",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn tun_plan_command_parses_routes_without_apply() {
        let cli = Cli::try_parse_from([
            "maverick",
            "tun-plan",
            "--device",
            "mavtun0",
            "--include-route",
            "10.0.0.0/8",
            "--include-route",
            "fd00::/8",
            "--exclude-route",
            "127.0.0.0/8",
            "--dns-server",
            "9.9.9.9",
        ])
        .unwrap();
        match cli.command {
            Commands::TunPlan {
                device,
                include_routes,
                exclude_routes,
                dns_servers,
                abstract_runtime_plan,
            } => {
                assert_eq!(device, "mavtun0");
                assert_eq!(include_routes, vec!["10.0.0.0/8", "fd00::/8"]);
                assert_eq!(exclude_routes, vec!["127.0.0.0/8"]);
                assert_eq!(dns_servers, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
                assert!(!abstract_runtime_plan);
            }
            _ => panic!("expected tun-plan command"),
        }
    }

    #[test]
    fn tun_plan_report_is_local_only_and_lists_apply_blockers() {
        let report =
            tun_plan_report("mavtun0", &[String::from("10.0.0.0/8")], &[], &[], false).unwrap();
        let rendered = report.join("\n");
        assert!(rendered.contains("system_apply: false"));
        assert!(rendered.contains("dry_run_step: create tun device mavtun0"));
        assert!(rendered.contains("dry_run_step: record rollback plan"));
        assert!(rendered.contains("apply_allowed: false"));
        assert!(rendered.contains("apply_blocker: OperatorApprovalRequired"));
        assert!(rendered.contains("abstract_runtime_plan: not_requested"));
        assert!(!rendered.contains("sudo"));
        assert!(!rendered.contains(" ip "));
    }

    #[test]
    fn tun_plan_report_can_emit_abstract_runtime_plan() {
        let report =
            tun_plan_report("mavtun0", &[String::from("10.0.0.0/8")], &[], &[], true).unwrap();
        let rendered = report.join("\n");
        assert!(rendered.contains("abstract_runtime_plan: available"));
        assert!(rendered.contains("abstract_runtime_plan_system_apply: false"));
        assert!(rendered.contains("abstract_runtime_plan_context: planning_only_all_gates_assumed"));
        assert!(rendered.contains("abstract_apply_action: create tun device mavtun0"));
        assert!(rendered.contains("abstract_apply_action: add route 10.0.0.0/8 via mavtun0"));
        assert!(rendered.contains("abstract_rollback_action: delete route 10.0.0.0/8 via mavtun0"));
        assert!(rendered.contains("abstract_rollback_action: delete tun device mavtun0"));
        assert!(!rendered.contains("sudo"));
        assert!(!rendered.contains(" ip "));
    }

    #[test]
    fn tun_plan_report_rejects_abstract_dns_and_exclude_apply() {
        let dns_err = tun_plan_report(
            "mavtun0",
            &[String::from("10.0.0.0/8")],
            &[],
            &["9.9.9.9".parse::<IpAddr>().unwrap()],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(dns_err.contains("GlobalDnsPolicyMissing"));

        let exclude_err = tun_plan_report(
            "mavtun0",
            &[String::from("10.0.0.0/8")],
            &[String::from("127.0.0.0/8")],
            &[],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(exclude_err.contains("RouteExclusionPolicyMissing"));
    }

    #[test]
    fn tun_runtime_action_descriptions_cover_policy_actions() {
        assert_eq!(
            describe_tun_runtime_action(&TunRuntimeAction::PreserveRoute {
                cidr: "198.18.0.1/32".into()
            }),
            "preserve route 198.18.0.1/32"
        );
        assert_eq!(
            describe_tun_runtime_action(&TunRuntimeAction::SetDnsServers {
                servers: vec!["9.9.9.9".into(), "149.112.112.112".into()]
            }),
            "set dns servers 9.9.9.9,149.112.112.112"
        );
        assert_eq!(
            describe_tun_runtime_rollback_action(&TunRuntimeRollbackAction::RestoreDnsServers),
            "restore dns servers"
        );
        assert_eq!(
            describe_tun_runtime_rollback_action(&TunRuntimeRollbackAction::RestoreRoute {
                cidr: "198.18.0.1/32".into()
            }),
            "restore route 198.18.0.1/32"
        );
    }

    #[test]
    fn tun_helper_smoke_command_parses_phase_a_flags() {
        let cli = Cli::try_parse_from([
            "maverick",
            "tun-helper-smoke",
            "--apply",
            "--device",
            "mavtun1",
            "--include-route",
            "192.0.2.0/24",
            "--tun-addr",
            "10.255.0.1/30",
            "--approved-host-label",
            "approved-linux-vm",
            "--proxy-vpn-conflict-checked",
            "--rollback-journal",
            "/tmp/maverick-test-rollback.json",
        ])
        .unwrap();
        match cli.command {
            Commands::TunHelperSmoke {
                apply,
                device,
                include_route,
                tun_addr,
                approved_host_label,
                proxy_vpn_conflict_checked,
                rollback_journal,
            } => {
                assert!(apply);
                assert_eq!(device, "mavtun1");
                assert_eq!(include_route, "192.0.2.0/24");
                assert_eq!(tun_addr, "10.255.0.1/30");
                assert_eq!(approved_host_label.as_deref(), Some("approved-linux-vm"));
                assert!(proxy_vpn_conflict_checked);
                assert_eq!(
                    rollback_journal.as_deref(),
                    Some(Path::new("/tmp/maverick-test-rollback.json"))
                );
            }
            _ => panic!("expected tun-helper-smoke command"),
        }
    }

    #[test]
    fn tun_helper_preflight_command_parses_phase_a_flags() {
        let cli = Cli::try_parse_from([
            "maverick",
            "tun-helper-preflight",
            "--device",
            "mavtun1",
            "--include-route",
            "192.0.2.0/24",
            "--tun-addr",
            "10.255.0.1/30",
            "--approved-host-label",
            "approved-linux-vm",
            "--rollback-journal",
            "/tmp/maverick-preflight-rollback.json",
        ])
        .unwrap();
        match cli.command {
            Commands::TunHelperPreflight {
                device,
                include_route,
                tun_addr,
                approved_host_label,
                rollback_journal,
            } => {
                assert_eq!(device, "mavtun1");
                assert_eq!(include_route, "192.0.2.0/24");
                assert_eq!(tun_addr, "10.255.0.1/30");
                assert_eq!(approved_host_label.as_deref(), Some("approved-linux-vm"));
                assert_eq!(
                    rollback_journal.as_deref(),
                    Some(Path::new("/tmp/maverick-preflight-rollback.json"))
                );
            }
            _ => panic!("expected tun-helper-preflight command"),
        }
    }

    #[test]
    fn tun_helper_preflight_report_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let report = tun_helper_preflight_report(&phase_a_preflight_options(
            dir.path().join("rollback.json"),
        ))
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(rendered.contains("tun-helper-preflight"));
        assert!(rendered.contains("system_apply: false"));
        assert!(rendered.contains("rollback_journal:"));
        assert!(rendered.contains("default_route: not_touched"));
        assert!(rendered.contains("global_dns: not_touched"));
        assert!(rendered.contains("firewall: not_touched"));
        assert!(rendered.contains("preflight_ready:"));
        assert!(!rendered.contains(" ip "));
        assert!(!rendered.contains("sudo"));
    }

    #[test]
    fn tun_helper_preflight_blocks_existing_rollback_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("rollback.json");
        fs::write(&journal, "{}\n").unwrap();
        let report = tun_helper_preflight_report(&phase_a_preflight_options(journal)).unwrap();
        assert!(report
            .blockers
            .contains(&TunHelperPreflightBlocker::RollbackJournalUnavailable));
        assert!(report
            .lines
            .join("\n")
            .contains("preflight_blocker: RollbackJournalUnavailable"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn tun_helper_preflight_blocks_non_linux_platforms() {
        let dir = tempfile::tempdir().unwrap();
        let report = tun_helper_preflight_report(&phase_a_preflight_options(
            dir.path().join("rollback.json"),
        ))
        .unwrap();
        assert!(report
            .blockers
            .contains(&TunHelperPreflightBlocker::UnsupportedPlatform));
    }

    #[test]
    fn tun_helper_rollback_command_parses_phase_a_flags() {
        let cli = Cli::try_parse_from([
            "maverick",
            "tun-helper-rollback",
            "--apply",
            "--rollback-journal",
            "/tmp/maverick-phase-a-rollback.json",
            "--approved-host-label",
            "approved-linux-vm",
            "--proxy-vpn-conflict-checked",
        ])
        .unwrap();
        match cli.command {
            Commands::TunHelperRollback {
                apply,
                rollback_journal,
                approved_host_label,
                proxy_vpn_conflict_checked,
            } => {
                assert!(apply);
                assert_eq!(
                    rollback_journal,
                    PathBuf::from("/tmp/maverick-phase-a-rollback.json")
                );
                assert_eq!(approved_host_label.as_deref(), Some("approved-linux-vm"));
                assert!(proxy_vpn_conflict_checked);
            }
            _ => panic!("expected tun-helper-rollback command"),
        }
    }

    #[test]
    fn tun_helper_smoke_blocks_apply_without_operator_env() {
        let report = tun_helper_smoke_report(
            &phase_a_helper_options(true),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(!report.decision.is_allowed());
        assert!(report.runtime_plan.is_none());
        assert!(rendered.contains("system_apply: true"));
        assert!(rendered.contains("apply_blocker: OperatorApprovalRequired"));
        assert!(rendered.contains("runtime_plan: blocked"));
        assert!(!rendered.contains("sudo"));
    }

    #[test]
    fn tun_helper_smoke_report_is_local_only_without_apply() {
        let report = tun_helper_smoke_report(
            &phase_a_helper_options(false),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: cfg!(target_os = "linux"),
                privileges_confirmed: false,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(rendered.contains("system_apply: false"));
        assert!(rendered.contains("rollback_journal:"));
        assert!(rendered.contains("default_route: not_touched"));
        assert!(rendered.contains("global_dns: not_touched"));
        assert!(rendered.contains("firewall: not_touched"));
        assert!(!rendered.contains("sudo"));
    }

    #[test]
    fn tun_helper_smoke_rejects_non_documentation_routes() {
        let mut options = phase_a_helper_options(true);
        options.include_route = "10.0.0.0/8".into();
        let err = tun_helper_smoke_report(
            &options,
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("documentation"));
    }

    #[test]
    fn tun_helper_smoke_allows_phase_a_plan_when_all_gates_pass() {
        let report = tun_helper_smoke_report(
            &phase_a_helper_options(true),
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(report.decision.is_allowed());
        assert!(report.runtime_plan.is_some());
        assert!(rendered.contains("apply_allowed: true"));
        assert!(rendered.contains("runtime_plan: available"));
        assert!(rendered.contains("runtime_plan_scope: helper_phase_a_only"));
    }

    #[test]
    fn tun_helper_smoke_blocks_apply_when_rollback_journal_exists() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("rollback.json");
        fs::write(&journal, "{}\n").unwrap();
        let mut options = phase_a_helper_options(true);
        options.rollback_journal = Some(journal);
        let report = tun_helper_smoke_report(
            &options,
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(!report.decision.is_allowed());
        assert!(rendered.contains("apply_blocker: RollbackPlanRequired"));
    }

    #[test]
    fn tun_helper_smoke_writes_structured_rollback_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("rollback.json");
        let mut options = phase_a_helper_options(true);
        options.rollback_journal = Some(journal.clone());
        let report = tun_helper_smoke_report(
            &options,
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        let runtime_plan = report.runtime_plan.as_ref().unwrap();
        write_tun_helper_rollback_journal(
            &options,
            runtime_plan,
            &journal,
            "192.0.2.1",
            "maverick-tun-helper:test-identity",
        )
        .unwrap();
        let raw = fs::read_to_string(&journal).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["version"], 2);
        assert_eq!(parsed["status"], "pending_rollback");
        assert_eq!(parsed["device"], "mavtun0");
        assert_eq!(
            parsed["device_identity"],
            "maverick-tun-helper:test-identity"
        );
        assert_eq!(parsed["include_route"], TUN_HELPER_DEFAULT_ROUTE);
        assert_eq!(parsed["default_route"], "not_touched");
        assert_eq!(parsed["global_dns"], "not_touched");
        assert_eq!(parsed["firewall"], "not_touched");
        assert_eq!(
            parsed["cleanup_policy"],
            "remove_on_success_retain_on_failed_cleanup"
        );
        assert!(parsed["runtime_plan"]["rollback_actions"].is_array());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn tun_helper_rollback_report_is_local_only_without_apply() {
        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        let report = tun_helper_rollback_report(
            &phase_a_rollback_options(false, journal),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: cfg!(target_os = "linux"),
                privileges_confirmed: false,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(rendered.contains("tun-helper-rollback"));
        assert!(rendered.contains("system_apply: false"));
        assert!(rendered.contains("rollback: idempotent_cleanup"));
        assert!(rendered.contains("apply_blocker: OperatorApprovalRequired"));
        assert!(rendered.contains("default_route: not_touched"));
        assert!(!rendered.contains("sudo"));
    }

    #[test]
    fn tun_helper_rollback_allows_phase_a_plan_when_all_gates_pass() {
        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        let report = tun_helper_rollback_report(
            &phase_a_rollback_options(true, journal),
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        let rendered = report.lines.join("\n");
        assert!(report.decision.is_allowed());
        assert!(rendered.contains("apply_allowed: true"));
        assert!(rendered.contains("route_probe: 192.0.2.1"));
    }

    #[test]
    fn tun_helper_rollback_rejects_journal_that_touches_default_route() {
        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        let mut parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&journal).unwrap()).unwrap();
        parsed["default_route"] = serde_json::Value::String("modified".into());
        fs::write(&journal, serde_json::to_string_pretty(&parsed).unwrap()).unwrap();
        let err = tun_helper_rollback_report(
            &phase_a_rollback_options(false, journal),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: true,
                privileges_confirmed: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("default_route"));
    }

    #[cfg(unix)]
    #[test]
    fn tun_helper_rollback_rejects_group_readable_journal() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o640)).unwrap();
        let err = tun_helper_rollback_report(
            &phase_a_rollback_options(false, journal),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: true,
                privileges_confirmed: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn tun_helper_rollback_rejects_symlink_journal() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        let link = dir.path().join("rollback-link.json");
        symlink(&journal, &link).unwrap();
        let err = tun_helper_rollback_report(
            &phase_a_rollback_options(false, link),
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: true,
                privileges_confirmed: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("regular file"));
    }

    #[test]
    fn tun_helper_rollback_binds_journal_to_approved_label() {
        let dir = tempfile::tempdir().unwrap();
        let journal = write_phase_a_test_journal(dir.path());
        let mut options = phase_a_rollback_options(false, journal);
        options.approved_host_label = None;
        let err = tun_helper_rollback_report(
            &options,
            TunHelperSmokeEnvironment {
                operator_approved: false,
                platform_supported: true,
                privileges_confirmed: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("approved_host_label"));
    }

    #[test]
    fn experimental_list_command_parses() {
        let cli = Cli::try_parse_from(["maverick", "experimental", "list"]).unwrap();
        match cli.command {
            Commands::Experimental {
                command: ExperimentalCommand::List,
            } => {}
            _ => panic!("expected experimental list command"),
        }
    }

    #[test]
    fn experimental_track_report_is_default_off_and_secret_free() {
        let rendered = experimental_track_report().join("\n");
        assert!(rendered.contains("track: h3_quic_carrier"));
        assert!(rendered.contains("track: ech"));
        assert!(rendered.contains("track: blinded_credential_lookup"));
        assert!(rendered.contains("build_gate: blinded-lookup-experimental"));
        assert!(rendered.contains("default: off"));
        assert!(rendered.contains("default_security_claim: excluded"));
        assert!(rendered.contains("requires_external_test_host: true"));
        assert!(!rendered.contains("default: on"));
        assert!(!rendered.contains("mv1_"));
        assert!(!rendered.contains("[REDACTED]"));
    }

    fn phase_a_helper_options(apply: bool) -> TunHelperSmokeOptions {
        TunHelperSmokeOptions {
            apply,
            device: "mavtun0".into(),
            include_route: TUN_HELPER_DEFAULT_ROUTE.into(),
            tun_addr: TUN_HELPER_DEFAULT_ADDR.into(),
            approved_host_label: Some("approved-linux-vm".into()),
            proxy_vpn_conflict_checked: true,
            rollback_journal: Some(
                env::temp_dir().join(format!("maverick-test-{}-rollback.json", random_id())),
            ),
        }
    }

    fn phase_a_preflight_options(journal: PathBuf) -> TunHelperPreflightOptions {
        TunHelperPreflightOptions {
            device: "mavtun0".into(),
            include_route: TUN_HELPER_DEFAULT_ROUTE.into(),
            tun_addr: TUN_HELPER_DEFAULT_ADDR.into(),
            approved_host_label: Some("approved-linux-vm".into()),
            rollback_journal: Some(journal),
        }
    }

    fn phase_a_rollback_options(apply: bool, journal: PathBuf) -> TunHelperRollbackOptions {
        TunHelperRollbackOptions {
            apply,
            rollback_journal: journal,
            approved_host_label: Some("approved-linux-vm".into()),
            proxy_vpn_conflict_checked: true,
        }
    }

    fn write_phase_a_test_journal(dir: &Path) -> PathBuf {
        let journal = dir.join("rollback.json");
        let mut options = phase_a_helper_options(true);
        options.rollback_journal = Some(journal.clone());
        let report = tun_helper_smoke_report(
            &options,
            TunHelperSmokeEnvironment {
                operator_approved: true,
                platform_supported: true,
                privileges_confirmed: true,
            },
        )
        .unwrap();
        write_tun_helper_rollback_journal(
            &options,
            report.runtime_plan.as_ref().unwrap(),
            &journal,
            "192.0.2.1",
            "maverick-tun-helper:test-identity",
        )
        .unwrap();
        journal
    }

    #[test]
    fn migration_report_lists_missing_v2_defaults() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_abc123"
  secret: "{}"
"#,
            secret.expose_secret()
        );
        let report = migration_report("client", &input).unwrap();
        assert!(report.contains(&"advanced.experimental_h3=false".to_owned()));
        assert!(report.contains(&"advanced.udp_idle_timeout_ms=30000".to_owned()));
        assert!(report.contains(&"advanced.shaping.enabled=false".to_owned()));
        assert!(report.contains(&"advanced.experimental_ech=false".to_owned()));
        assert!(report.contains(&"advanced.experimental_tun=false".to_owned()));
        assert!(report.contains(&"advanced.ech_fallback_policy=fail_closed".to_owned()));
        assert!(report.contains(&"advanced.crypto.offered_suites=[tls13]".to_owned()));
        assert!(report.contains(&"auth.v2.enabled=false".to_owned()));
        assert!(report.contains(&"auth.rotation.auto_switch=false".to_owned()));
        assert!(report.contains(&"auth.rotation.next=null".to_owned()));
        assert!(!report.iter().any(|line| line.contains("mv1_")));
    }

    #[test]
    fn server_migration_report_lists_auth_limit_defaults() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_abc123"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"
"#,
            secret.expose_secret()
        );
        let report = migration_report("server", &input).unwrap();
        assert!(report.contains(&"advanced.pre_auth_max_concurrent=512".to_owned()));
        assert!(report.contains(&"advanced.auth_failure_window_secs=60".to_owned()));
        assert!(report.contains(&"advanced.max_auth_failures_per_window=24".to_owned()));
        assert!(report.contains(&"advanced.auth_failure_cache_max_entries=4096".to_owned()));
        assert!(!report.iter().any(|line| line.contains("mv1_")));
    }

    #[test]
    fn client_key_inventory_is_redacted() {
        let secret = SecretString::generate();
        let next_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:1080"
server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_sensitive_client_2026"
  secret: "{}"
auth:
  rotation:
    active_epoch: "202607"
    next_credential_id: "u_sensitive_next_2026"
    auto_switch: true
    next:
      id: "u_sensitive_next_2026"
      secret: "{}"
      not_before: "2026-07-15T00:00:00Z"
"#,
            secret.expose_secret(),
            next_secret.expose_secret()
        );
        let report = key_inventory_report("client", &input).unwrap();
        let rendered = report.join("\n");
        assert!(rendered.contains("credential_secret: [REDACTED]"));
        assert!(rendered.contains("rotation_auto_switch: true"));
        assert!(rendered.contains("rotation_next_secret: [REDACTED]"));
        assert!(rendered.contains("u_se...26"));
        assert!(!rendered.contains(secret.expose_secret()));
        assert!(!rendered.contains(next_secret.expose_secret()));
        assert!(!rendered.contains("u_sensitive_client_2026"));
        assert!(!rendered.contains("u_sensitive_next_2026"));
    }

    #[test]
    fn server_key_inventory_is_redacted() {
        let secret = SecretString::generate();
        let previous_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_sensitive_server_2026"
    name: "alice"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_sensitive_previous_2026"
          secret: "{}"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-01T00:00:00Z"
      next:
        id: "u_sensitive_next_2026"
        not_before: "2026-07-01T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
"#,
            secret.expose_secret(),
            previous_secret.expose_secret()
        );
        let report = key_inventory_report("server", &input).unwrap();
        let rendered = report.join("\n");
        assert!(rendered.contains("tls_private_key: configured"));
        assert!(rendered.contains("active_secret=[REDACTED]"));
        assert!(rendered.contains("secret=[REDACTED]"));
        assert!(!rendered.contains(secret.expose_secret()));
        assert!(!rendered.contains(previous_secret.expose_secret()));
        assert!(!rendered.contains("u_sensitive_server_2026"));
        assert!(!rendered.contains("u_sensitive_previous_2026"));
        assert!(!rendered.contains("u_sensitive_next_2026"));
    }

    #[test]
    fn rotation_lint_reports_windows_without_leaking_secrets() {
        let secret = SecretString::generate();
        let previous_secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_sensitive_server_2026"
    name: "alice"
    secret: "{}"
    enabled: true
    rotation:
      previous:
        - id: "u_sensitive_previous_2026"
          secret: "{}"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-06-20T00:00:00Z"
      next:
        id: "u_sensitive_next_2026"
        not_before: "2026-06-15T00:00:00Z"
fallback:
  type: "static"
  static_dir: "./public"
"#,
            secret.expose_secret(),
            previous_secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        let now = parse_rotation_timestamp("2026-06-26T12:00:00Z").unwrap();
        let report = rotation_lint_report(&cfg, Some("u_sensitive_server_2026"), now).unwrap();
        let rendered = report.join("\n");
        assert!(rendered.contains("warnings: 2"));
        assert!(rendered.contains("state=expired"));
        assert!(rendered.contains("state=ready_for_promotion"));
        assert!(rendered.contains("secret=[REDACTED]"));
        assert!(!rendered.contains(secret.expose_secret()));
        assert!(!rendered.contains(previous_secret.expose_secret()));
        assert!(!rendered.contains("u_sensitive_server_2026"));
        assert!(!rendered.contains("u_sensitive_previous_2026"));
        assert!(!rendered.contains("u_sensitive_next_2026"));
    }

    #[test]
    fn rotation_lint_unknown_user_is_redacted() {
        let secret = SecretString::generate();
        let input = format!(
            r#"
version: 1
listen: "127.0.0.1:8443"
tls:
  cert_path: "./cert.pem"
  key_path: "./key.pem"
maverick:
  tunnel_path: "/assets/upload"
users:
  - id: "u_sensitive_server_2026"
    name: "alice"
    secret: "{}"
    enabled: true
fallback:
  type: "static"
  static_dir: "./public"
"#,
            secret.expose_secret()
        );
        let cfg = ServerConfig::from_yaml_str(&input).unwrap();
        let now = parse_rotation_timestamp("2026-06-26T12:00:00Z").unwrap();
        let err = rotation_lint_report(&cfg, Some("u_sensitive_missing_2026"), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("u_se...26"));
        assert!(!err.contains("u_sensitive_missing_2026"));
        assert!(!err.contains(secret.expose_secret()));
    }

    #[test]
    fn parses_minimal_profile_uri() {
        let profile = ProfileUri::parse(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto",
        )
        .unwrap();
        assert_eq!(profile.server, "example.com:443");
        assert_eq!(profile.server_name, "example.com");
        assert_eq!(profile.tunnel_path, "/assets/upload");
        assert_eq!(profile.mode, Mode::Auto);
        assert!(profile.secret.is_none());
    }

    #[test]
    fn profile_uri_accepts_trimmed_qr_or_clipboard_payload() {
        let profile = ProfileUri::parse(
            "\n  maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto  \n",
        )
        .unwrap();
        assert_eq!(profile.server, "example.com:443");
        assert_eq!(profile.mode, Mode::Auto);
    }

    #[test]
    fn profile_uri_rejects_multi_uri_clipboard_payload() {
        let err = ProfileUri::parse(
            "\
maverick://profile/v1?server=a.example%3A443&name=a.example&path=%2Fassets%2Fupload&mode=auto
maverick://profile/v1?server=b.example%3A443&name=b.example&path=%2Fassets%2Fupload&mode=auto
",
        )
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn profile_uri_rejects_percent_decoded_control_characters() {
        let err = ProfileUri::parse(
            "maverick://profile/v1?server=example.com%0aevil%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto",
        )
        .unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn profile_uri_roundtrips_without_secret_by_default() {
        let secret = SecretString::generate();
        let profile = ProfileUri {
            server: "example.com:443".into(),
            server_name: "example.com".into(),
            tunnel_path: "/assets/upload".into(),
            mode: Mode::Stable,
            credential_id: Some("u_example".into()),
            secret: None,
            cert_pin: None,
            experimental_h3: false,
            experimental_ech: false,
            experimental_tun: false,
        };
        let uri = profile.to_uri();
        assert!(!uri.contains(secret.expose_secret()));
        let parsed = ProfileUri::parse(&uri).unwrap();
        assert_eq!(parsed, profile);
    }

    #[test]
    fn profile_uri_can_include_valid_secret_when_explicit() {
        let secret = SecretString::generate();
        let uri = format!(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=private&credential_id=u_example&secret={}",
            secret.expose_secret()
        );
        let parsed = ProfileUri::parse(&uri).unwrap();
        assert!(parsed.secret.is_some());
        assert_eq!(parsed.mode, Mode::Private);
    }

    #[test]
    fn profile_uri_qr_rendering_is_text_only_and_omits_raw_uri() {
        let uri = "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto";
        let qr = render_profile_qr(uri).unwrap();
        assert!(qr.lines().count() > 10);
        assert!(qr.lines().all(|line| line.len() > 10));
        assert!(!qr.contains(uri));
    }

    #[test]
    fn profile_uri_qr_export_rejects_secret_bearing_uri() {
        validate_qr_export(false, true).unwrap();
        let err = validate_qr_export(true, true).unwrap_err();
        assert!(err.to_string().contains("secret-bearing"));
    }

    #[test]
    fn profile_uri_materializes_valid_client_config() {
        let secret = SecretString::generate();
        let uri = format!(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto&credential_id=u_example&secret={}&experimental_h3=true&experimental_tun=true",
            secret.expose_secret()
        );
        let cfg = ProfileUri::parse(&uri).unwrap().to_client_config().unwrap();
        assert_eq!(cfg.mode, Mode::Auto);
        assert_eq!(cfg.local.socks5.listen.to_string(), "127.0.0.1:1080");
        assert_eq!(cfg.server.credential_id, "u_example");
        assert_eq!(cfg.server.secret.expose_secret(), secret.expose_secret());
        assert!(cfg.advanced.experimental_h3);
        assert!(cfg.advanced.experimental_tun);
    }

    #[test]
    fn profile_uri_materialization_requires_secret_and_credential() {
        let profile = ProfileUri::parse(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto",
        )
        .unwrap();
        let err = profile.to_client_config().unwrap_err();
        assert!(err.to_string().contains("credential_id"));

        let profile = ProfileUri {
            credential_id: Some("u_example".into()),
            ..profile
        };
        let err = profile.to_client_config().unwrap_err();
        assert!(err.to_string().contains("secret"));
    }

    #[test]
    fn import_config_uri_writes_output_and_refuses_overwrite() {
        let secret = SecretString::generate();
        let uri = format!(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto&credential_id=u_example&secret={}",
            secret.expose_secret()
        );
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("client.yaml");
        import_config_uri(&uri, false, Some(&output)).unwrap();
        let written = fs::read_to_string(&output).unwrap();
        let cfg = ClientConfig::from_yaml_str(&written).unwrap();
        assert_eq!(cfg.server.credential_id, "u_example");
        assert_eq!(cfg.server.secret.expose_secret(), secret.expose_secret());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let err = import_config_uri(&uri, false, Some(&output)).unwrap_err();
        assert!(err.to_string().contains("overwrite"));
    }

    struct FakeClipboard {
        payload: String,
    }

    impl ClipboardReader for FakeClipboard {
        fn read_profile_uri(&self) -> Result<String> {
            Ok(self.payload.clone())
        }
    }

    #[test]
    fn clipboard_import_materializes_valid_client_config_without_real_clipboard() {
        let secret = SecretString::generate();
        let uri = format!(
            "\n maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto&credential_id=u_example&secret={} \n",
            secret.expose_secret()
        );
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("client.yaml");
        let clipboard = FakeClipboard { payload: uri };

        import_config_uri_from_clipboard(&clipboard, false, Some(&output)).unwrap();

        let written = fs::read_to_string(&output).unwrap();
        let cfg = ClientConfig::from_yaml_str(&written).unwrap();
        assert_eq!(cfg.server.credential_id, "u_example");
        assert_eq!(cfg.server.secret.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn clipboard_import_rejects_empty_payload_without_real_clipboard() {
        let clipboard = FakeClipboard {
            payload: " \n\t ".into(),
        };
        let err = import_config_uri_from_clipboard(&clipboard, true, None).unwrap_err();
        assert!(err.to_string().contains("clipboard"));
    }

    #[test]
    fn profile_uri_rejects_invalid_version() {
        let err = ProfileUri::parse(
            "maverick://profile/v2?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto",
        )
        .unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn profile_uri_rejects_invalid_secret() {
        let err = ProfileUri::parse(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto&secret=mv1_short",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid high-entropy secret"));
    }

    #[test]
    fn profile_uri_rejects_unsupported_ech() {
        let err = ProfileUri::parse(
            "maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto&experimental_ech=true",
        )
        .unwrap_err();
        assert!(err.to_string().contains("experimental_ech"));
    }
}
