use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command as StdCommand, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use maverick_core::config::{
    ClientAdvancedConfig, ClientAuthConfig, ClientConfig, ClientCredentialRotationConfig,
    ClientServerConfig, FallbackConfig, HttpConnectConfig, LocalConfig, LogConfig,
    MaverickServerConfig, MetricsConfig, SecretString, ServerAdvancedConfig, ServerAuthConfig,
    ServerConfig, ServerDnsConfig, Socks5Config, TlsConfig, TlsFingerprintMode, UserConfig,
};
use maverick_core::Mode;
use maverick_tests::fingerprint::{
    parse_h2_client_preface, parse_tls_client_hello, H2ClientPrefaceObservation,
    TlsClientHelloObservation,
};
use serde::Serialize;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use tokio::time::{sleep, timeout};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileSelection {
    Rustls,
    Browser,
    All,
}

#[derive(Debug)]
struct Args {
    output_dir: PathBuf,
    profile: ProfileSelection,
    samples: usize,
    reference_client_hello: Option<PathBuf>,
    reference_browser_binary: Option<PathBuf>,
    reference_label: String,
}

#[derive(Debug, Serialize)]
struct FingerprintReport {
    schema_version: u32,
    generated_at_utc: String,
    git_revision: String,
    safety_scope: &'static str,
    claims: ReportClaims,
    profiles: Vec<ProfileObservation>,
    browser_reference: ReferenceObservation,
    browser_comparison: BrowserComparison,
}

#[derive(Debug, Serialize)]
struct ReportClaims {
    browser_equivalence: bool,
    censorship_resistance: bool,
    traffic_analysis_resistance: bool,
}

#[derive(Debug, Serialize)]
struct ProfileObservation {
    name: &'static str,
    status: &'static str,
    reason: Option<&'static str>,
    tls_channel_binding_available: Option<bool>,
    sample_count: usize,
    unique_ja3_inputs: Vec<String>,
    unique_tls_observed_sha256: Vec<String>,
    unique_tls_normalized_set_sha256: Vec<String>,
    unique_h2_observed_sha256: Vec<String>,
    unique_h2_normalized_sha256: Vec<String>,
    samples: Vec<ProfileSample>,
}

#[derive(Clone, Debug, Serialize)]
struct ProfileSample {
    tls: TlsClientHelloObservation,
    h2: H2ClientPrefaceObservation,
}

#[derive(Debug, Serialize)]
struct ReferenceObservation {
    label: String,
    status: &'static str,
    reason: Option<&'static str>,
    capture_kind: &'static str,
    sample_count: usize,
    unique_tls_normalized_set_sha256: Vec<String>,
    unique_h2_normalized_sha256: Vec<String>,
    tls: Option<TlsClientHelloObservation>,
    h2: Option<H2ClientPrefaceObservation>,
    samples: Vec<ProfileSample>,
}

#[derive(Debug, Serialize)]
struct BrowserComparison {
    status: &'static str,
    reason: Option<&'static str>,
    tls_normalized_set_match: Option<bool>,
    h2_normalized_match: Option<bool>,
    field_differences: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FingerprintSummary<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    git_revision: &'a str,
    safety_scope: &'a str,
    profiles: Vec<ProfileSummary<'a>>,
    browser_reference_status: &'a str,
    browser_reference_sample_count: usize,
    browser_reference_tls_normalized_set_sha256: &'a [String],
    browser_reference_h2_normalized_sha256: &'a [String],
    browser_tls_normalized_set_match: Option<bool>,
    browser_h2_normalized_match: Option<bool>,
    browser_field_differences: &'a [String],
}

#[derive(Debug, Serialize)]
struct ProfileSummary<'a> {
    name: &'a str,
    status: &'a str,
    reason: Option<&'a str>,
    sample_count: usize,
    tls_channel_binding_available: Option<bool>,
    observed_ja3_variant_count: usize,
    tls_normalized_set_sha256: &'a [String],
    observed_h2_variant_count: usize,
    h2_normalized_sha256: &'a [String],
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let mut profiles = Vec::new();
    if matches!(
        args.profile,
        ProfileSelection::Rustls | ProfileSelection::All
    ) {
        profiles.push(observe_profile(TlsFingerprintMode::RustlsDefault, args.samples).await?);
    }
    if matches!(
        args.profile,
        ProfileSelection::Browser | ProfileSelection::All
    ) {
        profiles.push(observe_browser_profile(args.samples).await?);
    }
    let browser_reference = observe_reference(
        args.reference_client_hello.as_deref(),
        args.reference_browser_binary.as_deref(),
        args.reference_label,
        args.samples,
    )
    .await?;
    let browser_comparison = compare_browser_profile(&profiles, &browser_reference);
    let report = FingerprintReport {
        schema_version: 2,
        generated_at_utc: OffsetDateTime::now_utc().format(&Rfc3339)?,
        git_revision: git_revision(),
        safety_scope: "loopback listeners and OS-assigned ephemeral ports only",
        claims: ReportClaims {
            browser_equivalence: false,
            censorship_resistance: false,
            traffic_analysis_resistance: false,
        },
        profiles,
        browser_reference,
        browser_comparison,
    };

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("create output directory {}", args.output_dir.display()))?;
    let json_path = args.output_dir.join("fingerprint-report.json");
    let summary_path = args.output_dir.join("fingerprint-summary.json");
    let markdown_path = args.output_dir.join("fingerprint-report.md");
    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write {}", json_path.display()))?;
    fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summarize(&report))?,
    )
    .with_context(|| format!("write {}", summary_path.display()))?;
    fs::write(&markdown_path, render_markdown(&report))
        .with_context(|| format!("write {}", markdown_path.display()))?;
    println!("wrote {}", json_path.display());
    println!("wrote {}", summary_path.display());
    println!("wrote {}", markdown_path.display());
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut output_dir = PathBuf::from("runtime-evidence/fingerprint-lab");
    let mut profile = ProfileSelection::Rustls;
    let mut samples = 3usize;
    let mut reference_client_hello = None;
    let mut reference_browser_binary = None;
    let mut reference_label = "real-browser-reference".to_owned();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => {
                output_dir = PathBuf::from(args.next().context("--output-dir requires a path")?);
            }
            "--profile" => {
                profile = match args.next().as_deref() {
                    Some("rustls") => ProfileSelection::Rustls,
                    Some("browser") => ProfileSelection::Browser,
                    Some("all") => ProfileSelection::All,
                    _ => bail!("--profile must be rustls, browser, or all"),
                };
            }
            "--samples" => {
                samples = args
                    .next()
                    .context("--samples requires a number")?
                    .parse()
                    .context("--samples must be a number")?;
                if !(1..=16).contains(&samples) {
                    bail!("--samples must be between 1 and 16");
                }
            }
            "--reference-clienthello" => {
                reference_client_hello = Some(PathBuf::from(
                    args.next()
                        .context("--reference-clienthello requires a path")?,
                ));
            }
            "--reference-browser-binary" => {
                reference_browser_binary = Some(PathBuf::from(
                    args.next()
                        .context("--reference-browser-binary requires a path")?,
                ));
            }
            "--reference-label" => {
                reference_label = args.next().context("--reference-label requires a value")?;
            }
            "-h" | "--help" => {
                println!(
                    "usage: fingerprint-lab [--output-dir PATH] [--profile rustls|browser|all] [--samples N] \
                     [--reference-clienthello FILE | --reference-browser-binary FILE] \
                     [--reference-label LABEL]"
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }
    if reference_label.trim().is_empty() {
        bail!("--reference-label must not be empty");
    }
    if reference_label.len() > 160 || reference_label.chars().any(char::is_control) {
        bail!("--reference-label must be at most 160 characters without control characters");
    }
    if reference_client_hello.is_some() && reference_browser_binary.is_some() {
        bail!("--reference-clienthello and --reference-browser-binary are mutually exclusive");
    }
    Ok(Args {
        output_dir,
        profile,
        samples,
        reference_client_hello,
        reference_browser_binary,
        reference_label,
    })
}

async fn observe_profile(
    mode: TlsFingerprintMode,
    sample_count: usize,
) -> Result<ProfileObservation> {
    let name = match mode {
        TlsFingerprintMode::RustlsDefault => "rustls_default",
        TlsFingerprintMode::BrowserMimic => "browser_mimic",
    };
    let mut samples = Vec::with_capacity(sample_count);
    let mut channel_binding_values = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let (tls, h2, channel_binding_available) = capture_profile(mode).await?;
        samples.push(ProfileSample { tls, h2 });
        channel_binding_values.push(channel_binding_available);
    }
    let unique_ja3_inputs =
        sorted_unique(samples.iter().map(|sample| sample.tls.ja3_input.clone()));
    let unique_tls_observed_sha256 = sorted_unique(
        samples
            .iter()
            .map(|sample| sample.tls.observed_sha256.clone()),
    );
    let normalized_tls_hashes = sorted_unique(
        samples
            .iter()
            .map(|sample| sample.tls.normalized_set_sha256.clone()),
    );
    let unique_h2_observed_sha256 = sorted_unique(
        samples
            .iter()
            .map(|sample| sample.h2.observed_sha256.clone()),
    );
    let normalized_h2_hashes = sorted_unique(
        samples
            .iter()
            .map(|sample| sample.h2.normalized_sha256.clone()),
    );
    let channel_binding_available = channel_binding_values
        .first()
        .copied()
        .context("profile sample set is empty")?;
    if channel_binding_values
        .iter()
        .any(|value| *value != channel_binding_available)
    {
        bail!("TLS channel-binding availability changed across profile samples");
    }
    Ok(ProfileObservation {
        name,
        status: "observed",
        reason: None,
        tls_channel_binding_available: Some(channel_binding_available),
        sample_count,
        unique_ja3_inputs,
        unique_tls_observed_sha256,
        unique_tls_normalized_set_sha256: normalized_tls_hashes,
        unique_h2_observed_sha256,
        unique_h2_normalized_sha256: normalized_h2_hashes,
        samples,
    })
}

async fn observe_browser_profile(_sample_count: usize) -> Result<ProfileObservation> {
    #[cfg(feature = "browser-tls")]
    {
        observe_profile(TlsFingerprintMode::BrowserMimic, _sample_count).await
    }
    #[cfg(not(feature = "browser-tls"))]
    {
        Ok(ProfileObservation {
            name: "browser_mimic",
            status: "skipped",
            reason: Some("maverick-tests was not built with the browser-tls feature"),
            tls_channel_binding_available: None,
            sample_count: 0,
            unique_ja3_inputs: Vec::new(),
            unique_tls_observed_sha256: Vec::new(),
            unique_tls_normalized_set_sha256: Vec::new(),
            unique_h2_observed_sha256: Vec::new(),
            unique_h2_normalized_sha256: Vec::new(),
            samples: Vec::new(),
        })
    }
}

async fn observe_reference(
    path: Option<&Path>,
    browser_binary: Option<&Path>,
    label: String,
    sample_count: usize,
) -> Result<ReferenceObservation> {
    if let Some(browser_binary) = browser_binary {
        if !browser_binary.is_file() {
            bail!("reference browser binary is not a file");
        }
        let mut samples = Vec::with_capacity(sample_count);
        for sample_index in 0..sample_count {
            let (tls, h2) = capture_real_browser(browser_binary)
                .await
                .with_context(|| format!("capture real-browser sample {}", sample_index + 1))?;
            samples.push(ProfileSample { tls, h2 });
        }
        let tls = samples
            .first()
            .map(|sample| sample.tls.clone())
            .context("real-browser sample set is empty")?;
        let h2 = samples
            .first()
            .map(|sample| sample.h2.clone())
            .context("real-browser sample set is empty")?;
        return Ok(ReferenceObservation {
            label,
            status: "observed",
            reason: None,
            capture_kind: "loopback_browser_process",
            sample_count,
            unique_tls_normalized_set_sha256: sorted_unique(
                samples
                    .iter()
                    .map(|sample| sample.tls.normalized_set_sha256.clone()),
            ),
            unique_h2_normalized_sha256: sorted_unique(
                samples
                    .iter()
                    .map(|sample| sample.h2.normalized_sha256.clone()),
            ),
            tls: Some(tls),
            h2: Some(h2),
            samples,
        });
    }

    let Some(path) = path else {
        return Ok(ReferenceObservation {
            label,
            status: "not_provided",
            reason: Some("provide a redacted raw TLS record stream or an explicit browser binary"),
            capture_kind: "none",
            sample_count: 0,
            unique_tls_normalized_set_sha256: Vec::new(),
            unique_h2_normalized_sha256: Vec::new(),
            tls: None,
            h2: None,
            samples: Vec::new(),
        });
    };
    let bytes =
        fs::read(path).with_context(|| format!("read reference capture {}", path.display()))?;
    let tls = parse_tls_client_hello(&bytes)?;
    Ok(ReferenceObservation {
        label,
        status: "observed",
        reason: None,
        capture_kind: "imported_clienthello",
        sample_count: 1,
        unique_tls_normalized_set_sha256: vec![tls.normalized_set_sha256.clone()],
        unique_h2_normalized_sha256: Vec::new(),
        tls: Some(tls),
        h2: None,
        samples: Vec::new(),
    })
}

async fn capture_profile(
    mode: TlsFingerprintMode,
) -> Result<(TlsClientHelloObservation, H2ClientPrefaceObservation, bool)> {
    let fixture = LabFixture::new(mode)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let raw_client_bytes = Arc::new(Mutex::new(Vec::new()));
    let clear_client_bytes = Arc::new(Mutex::new(Vec::new()));
    let server_task = spawn_observation_server(
        listener,
        fixture.server_config,
        Arc::clone(&raw_client_bytes),
        Arc::clone(&clear_client_bytes),
    );

    let mut client_config = fixture.client_config;
    client_config.server.address = listen_addr.to_string();
    let transport = maverick_client::h2_transport::connect(&client_config).await?;
    let channel_binding_available = transport.channel_binding.is_some();
    sleep(Duration::from_millis(100)).await;
    drop(transport);
    timeout(Duration::from_secs(3), server_task)
        .await
        .context("observation server did not finish")???;

    let raw = raw_client_bytes
        .lock()
        .map_err(|_| anyhow::anyhow!("raw capture lock poisoned"))?
        .clone();
    let clear = clear_client_bytes
        .lock()
        .map_err(|_| anyhow::anyhow!("clear capture lock poisoned"))?
        .clone();
    Ok((
        parse_tls_client_hello(&raw)?,
        parse_h2_client_preface(&clear)?,
        channel_binding_available,
    ))
}

async fn capture_real_browser(
    browser_binary: &Path,
) -> Result<(TlsClientHelloObservation, H2ClientPrefaceObservation)> {
    let fixture = LabFixture::new(TlsFingerprintMode::RustlsDefault)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let listen_addr = listener.local_addr()?;
    let raw_client_bytes = Arc::new(Mutex::new(Vec::new()));
    let clear_client_bytes = Arc::new(Mutex::new(Vec::new()));
    let server_task = spawn_observation_server(
        listener,
        fixture.server_config,
        Arc::clone(&raw_client_bytes),
        Arc::clone(&clear_client_bytes),
    );
    let browser_profile = TempDir::new()?;
    let url = format!("https://localhost:{}/", listen_addr.port());
    let mut browser = TokioCommand::new(browser_binary)
        .arg("--headless=new")
        .arg("--disable-background-networking")
        .arg("--disable-component-update")
        .arg("--disable-default-apps")
        .arg("--disable-extensions")
        .arg("--disable-gpu")
        .arg("--disable-quic")
        .arg("--disable-sync")
        .arg("--disable-translate")
        .arg("--ignore-certificate-errors")
        .arg("--metrics-recording-only")
        .arg("--no-default-browser-check")
        .arg("--no-first-run")
        .arg("--no-proxy-server")
        .arg(format!(
            "--user-data-dir={}",
            browser_profile.path().display()
        ))
        .arg("--dump-dom")
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start reference browser process")?;

    let server_result = timeout(Duration::from_secs(8), server_task).await;
    let _ = browser.start_kill();
    let _ = timeout(Duration::from_secs(2), browser.wait()).await;
    server_result
        .context("reference browser did not complete a loopback TLS/H2 request")?
        .context("reference observation server task failed")??;

    let raw = raw_client_bytes
        .lock()
        .map_err(|_| anyhow::anyhow!("raw reference capture lock poisoned"))?
        .clone();
    let clear = clear_client_bytes
        .lock()
        .map_err(|_| anyhow::anyhow!("clear reference capture lock poisoned"))?
        .clone();
    Ok((
        parse_tls_client_hello(&raw)?,
        parse_h2_client_preface(&clear)?,
    ))
}

fn compare_browser_profile(
    profiles: &[ProfileObservation],
    reference: &ReferenceObservation,
) -> BrowserComparison {
    let Some(profile) = profiles
        .iter()
        .find(|profile| profile.name == "browser_mimic" && profile.status == "observed")
    else {
        return BrowserComparison {
            status: "not_available",
            reason: Some("browser-mimic profile was not observed"),
            tls_normalized_set_match: None,
            h2_normalized_match: None,
            field_differences: Vec::new(),
        };
    };
    let Some(profile_sample) = profile.samples.first() else {
        return BrowserComparison {
            status: "not_available",
            reason: Some("browser-mimic profile has no samples"),
            tls_normalized_set_match: None,
            h2_normalized_match: None,
            field_differences: Vec::new(),
        };
    };
    let Some(reference_tls) = reference.tls.as_ref() else {
        return BrowserComparison {
            status: "not_available",
            reason: Some("real-browser TLS reference was not provided"),
            tls_normalized_set_match: None,
            h2_normalized_match: None,
            field_differences: Vec::new(),
        };
    };

    let mut differences = Vec::new();
    let profile_tls = &profile_sample.tls;
    if profile_tls.normalized_cipher_suites != reference_tls.normalized_cipher_suites {
        differences.push("tls_cipher_order_or_values".to_owned());
    }
    if sorted_u16(&profile_tls.normalized_extension_order)
        != sorted_u16(&reference_tls.normalized_extension_order)
    {
        differences.push("tls_extension_set".to_owned());
    }
    if profile_tls.normalized_supported_groups != reference_tls.normalized_supported_groups {
        differences.push("tls_supported_group_order_or_values".to_owned());
    }
    if profile_tls.normalized_signature_algorithms != reference_tls.normalized_signature_algorithms
    {
        differences.push("tls_signature_algorithm_order_or_values".to_owned());
    }
    if profile_tls.normalized_supported_versions != reference_tls.normalized_supported_versions {
        differences.push("tls_supported_versions".to_owned());
    }
    if profile_tls.alpn_protocols != reference_tls.alpn_protocols {
        differences.push("tls_alpn".to_owned());
    }

    let (status, reason, h2_normalized_match) = if let Some(reference_h2) = reference.h2.as_ref() {
        if profile_sample.h2.settings != reference_h2.settings {
            differences.push("h2_settings_order_or_values".to_owned());
        }
        if profile_sample.h2.connection_window_updates != reference_h2.connection_window_updates {
            differences.push("h2_connection_window_updates".to_owned());
        }
        (
            "observed",
            None,
            Some(profile_sample.h2.normalized_sha256 == reference_h2.normalized_sha256),
        )
    } else {
        (
            "partial",
            Some("real-browser H2 reference was not provided"),
            None,
        )
    };

    BrowserComparison {
        status,
        reason,
        tls_normalized_set_match: Some(
            profile_tls.normalized_set_sha256 == reference_tls.normalized_set_sha256,
        ),
        h2_normalized_match,
        field_differences: differences,
    }
}

fn sorted_u16(values: &[u16]) -> Vec<u16> {
    let mut values = values.to_vec();
    values.sort_unstable();
    values
}

fn spawn_observation_server(
    listener: TcpListener,
    config: ServerConfig,
    raw_client_bytes: Arc<Mutex<Vec<u8>>>,
    clear_client_bytes: Arc<Mutex<Vec<u8>>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let acceptor = maverick_server::h2_acceptor::acceptor(&config)?;
        let (tcp, _) = listener.accept().await?;
        let raw_io = RecordingIo::new(tcp, raw_client_bytes);
        let tls = acceptor.accept(raw_io).await?;
        let clear_io = RecordingIo::new(tls, clear_client_bytes);
        let mut connection = h2::server::handshake(clear_io).await?;
        let _ = timeout(Duration::from_millis(500), connection.accept()).await;
        sleep(Duration::from_millis(25)).await;
        Ok(())
    })
}

struct LabFixture {
    _tmp: TempDir,
    server_config: ServerConfig,
    client_config: ClientConfig,
}

impl LabFixture {
    fn new(mode: TlsFingerprintMode) -> Result<Self> {
        let tmp = TempDir::new()?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        fs::write(&cert_path, certified.cert.pem())?;
        fs::write(&key_path, certified.key_pair.serialize_pem())?;
        fs::write(
            tmp.path().join("index.html"),
            "<html><body>lab</body></html>",
        )?;
        let secret = SecretString::generate();
        let mut client_advanced = ClientAdvancedConfig::default();
        client_advanced.stealth.tls_fingerprint = mode;

        let server_config = ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse()?,
            tls: TlsConfig {
                cert_path: cert_path.clone(),
                key_path,
            },
            maverick: MaverickServerConfig {
                tunnel_path: "/assets/upload".into(),
                mode_default: Mode::Auto,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 128,
                replay_cache_max_credentials_per_shard: 16,
                max_concurrent_flows_per_user: 8,
            },
            users: vec![UserConfig {
                id: "u_fingerprint_lab".into(),
                name: None,
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
            auth: ServerAuthConfig::default(),
            dns: None::<ServerDnsConfig>,
            metrics: None::<MetricsConfig>,
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig::default(),
        };
        let client_config = ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse()?,
                },
                dns: None,
                http_connect: None::<HttpConnectConfig>,
            },
            server: ClientServerConfig {
                address: "127.0.0.1:0".into(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_fingerprint_lab".into(),
                secret,
                ca_cert: Some(cert_path),
                cert_pin: None,
            },
            auth: ClientAuthConfig {
                channel_binding: Default::default(),
                v2: Default::default(),
                rotation: ClientCredentialRotationConfig::default(),
            },
            log: LogConfig::default(),
            advanced: client_advanced,
        };
        Ok(Self {
            _tmp: tmp,
            server_config,
            client_config,
        })
    }
}

struct RecordingIo<T> {
    inner: T,
    reads: Arc<Mutex<Vec<u8>>>,
}

impl<T> RecordingIo<T> {
    fn new(inner: T, reads: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, reads }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &result {
            let after = buffer.filled().len();
            if after > before {
                match self.reads.lock() {
                    Ok(mut reads) => reads.extend_from_slice(&buffer.filled()[before..after]),
                    Err(_) => {
                        return Poll::Ready(Err(std::io::Error::other("capture lock poisoned")))
                    }
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
}

fn git_revision() -> String {
    StdCommand::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_owned())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn summarize(report: &FingerprintReport) -> FingerprintSummary<'_> {
    FingerprintSummary {
        schema_version: report.schema_version,
        generated_at_utc: &report.generated_at_utc,
        git_revision: &report.git_revision,
        safety_scope: report.safety_scope,
        profiles: report
            .profiles
            .iter()
            .map(|profile| ProfileSummary {
                name: profile.name,
                status: profile.status,
                reason: profile.reason,
                sample_count: profile.sample_count,
                tls_channel_binding_available: profile.tls_channel_binding_available,
                observed_ja3_variant_count: profile.unique_ja3_inputs.len(),
                tls_normalized_set_sha256: &profile.unique_tls_normalized_set_sha256,
                observed_h2_variant_count: profile.unique_h2_observed_sha256.len(),
                h2_normalized_sha256: &profile.unique_h2_normalized_sha256,
            })
            .collect(),
        browser_reference_status: report.browser_reference.status,
        browser_reference_sample_count: report.browser_reference.sample_count,
        browser_reference_tls_normalized_set_sha256: &report
            .browser_reference
            .unique_tls_normalized_set_sha256,
        browser_reference_h2_normalized_sha256: &report
            .browser_reference
            .unique_h2_normalized_sha256,
        browser_tls_normalized_set_match: report.browser_comparison.tls_normalized_set_match,
        browser_h2_normalized_match: report.browser_comparison.h2_normalized_match,
        browser_field_differences: &report.browser_comparison.field_differences,
    }
}

fn render_markdown(report: &FingerprintReport) -> String {
    let mut output = String::new();
    output.push_str("# Maverick Fingerprint Lab Report\n\n");
    output.push_str("Status: loopback-only engineering evidence. This is not a browser-equivalence, censorship-resistance, or traffic-analysis-resistance claim.\n\n");
    output.push_str(&format!("- Generated UTC: `{}`\n", report.generated_at_utc));
    output.push_str(&format!("- Git revision: `{}`\n", report.git_revision));
    output.push_str(&format!("- Safety scope: {}.\n\n", report.safety_scope));
    output.push_str("| profile | status | samples | unique JA3 | TLS normalized variants | H2 observed variants | H2 normalized variants | channel binding |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for profile in &report.profiles {
        let binding = profile
            .tls_channel_binding_available
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".into());
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            profile.name,
            profile.status,
            profile.sample_count,
            profile.unique_ja3_inputs.len(),
            profile.unique_tls_normalized_set_sha256.len(),
            profile.unique_h2_observed_sha256.len(),
            profile.unique_h2_normalized_sha256.len(),
            binding
        ));
        if let Some(reason) = profile.reason {
            output.push_str(&format!("\n- `{}`: {}.\n", profile.name, reason));
        }
    }
    output.push_str("\n## Browser Reference\n\n");
    output.push_str(&format!(
        "- Label: `{}`\n- Status: `{}`\n- Capture kind: `{}`\n- Samples: `{}`\n",
        report.browser_reference.label,
        report.browser_reference.status,
        report.browser_reference.capture_kind,
        report.browser_reference.sample_count
    ));
    if let Some(reason) = report.browser_reference.reason {
        output.push_str(&format!("- Reason: {}.\n", reason));
    }
    if let Some(tls) = &report.browser_reference.tls {
        output.push_str(&format!(
            "- TLS normalized-set SHA-256: `{}`\n- JA3 input: `{}`\n",
            tls.normalized_set_sha256, tls.ja3_input
        ));
    }
    if let Some(h2) = &report.browser_reference.h2 {
        output.push_str(&format!(
            "- H2 normalized SHA-256: `{}`\n",
            h2.normalized_sha256
        ));
    }
    output.push_str("\n## Browser-Mimic Comparison\n\n");
    output.push_str(&format!(
        "- Status: `{}`\n- TLS normalized-set match: `{}`\n- H2 normalized match: `{}`\n",
        report.browser_comparison.status,
        optional_bool(report.browser_comparison.tls_normalized_set_match),
        optional_bool(report.browser_comparison.h2_normalized_match)
    ));
    if let Some(reason) = report.browser_comparison.reason {
        output.push_str(&format!("- Reason: {}.\n", reason));
    }
    if report.browser_comparison.field_differences.is_empty() {
        output.push_str("- Recorded field differences: none.\n");
    } else {
        output.push_str(&format!(
            "- Recorded field differences: {}.\n",
            report.browser_comparison.field_differences.join(", ")
        ));
    }
    output.push_str("\n## Interpretation\n\n");
    output.push_str(
        "- Compare normalized fields and hashes across commits; do not compare random bytes.\n",
    );
    output
        .push_str("- Multiple JA3 observations can be valid when extension order is randomized.\n");
    output.push_str("- The JA3 field is canonical input text, not an MD5 claim.\n");
    output
        .push_str("- `ja4_inputs` in JSON records inputs only; it is not a canonical JA4 hash.\n");
    output.push_str("- Missing browser evidence is a visible gap, not a passing result.\n");
    output
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "not_available",
    }
}
