use anyhow::{ensure, Context, Result};
use maverick_core::config::{ClientAdvancedConfig, TlsFingerprintMode};
use maverick_core::{ClientConfig, SecretString, ServerConfig};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

async fn cli(directory: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Output> {
    timeout(Duration::from_secs(30), async {
        let mut child = Command::new(env!("CARGO_BIN_EXE_maverick"))
            .args(args)
            .current_dir(directory)
            .env_remove("RUST_LOG")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .context("missing CLI stdin")?
                .write_all(input)
                .await?;
        }
        child.wait_with_output().await.map_err(anyhow::Error::from)
    })
    .await
    .context("configuration command timed out")?
}

fn private_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents.as_bytes())?;
    Ok(())
}

fn client_yaml(secret: &SecretString) -> String {
    format!(
        "version: 1\nmode: auto\nlocal:\n  socks5:\n    listen: '127.0.0.1:0'\nserver:\n  address: 'private.example.invalid:443'\n  server_name: private.example.invalid\n  tunnel_path: /private-tunnel\n  credential_id: private-test-user\n  secret: '{}'\n",
        secret.expose_secret()
    )
}

fn generated_pair(directory: &Path, h3: bool) -> Result<()> {
    let client = ClientConfig::from_yaml_str(&fs::read_to_string(
        directory.join("client.generated.yaml"),
    )?)
    .map_err(|_| anyhow::anyhow!("generated client configuration is invalid"))?;
    let server = ServerConfig::from_yaml_str(&fs::read_to_string(
        directory.join("server.generated.yaml"),
    )?)
    .map_err(|_| anyhow::anyhow!("generated server configuration is invalid"))?;
    ensure!(
        client.advanced.quiche_h3 == h3,
        "generated client selected the wrong carrier"
    );
    ensure!(
        server.advanced.quiche_h3 == h3,
        "generated server selected the wrong carrier"
    );
    ensure!(
        client.server.credential_id == server.users[0].id,
        "generated credential IDs differ"
    );
    ensure!(
        client.server.secret.expose_secret() == server.users[0].secret.expose_secret(),
        "generated credentials differ"
    );
    #[cfg(unix)]
    for name in ["client.generated.yaml", "server.generated.yaml"] {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            fs::metadata(directory.join(name))?.permissions().mode() & 0o777 == 0o600,
            "generated configuration is not owner-only"
        );
    }
    Ok(())
}

#[tokio::test]
async fn generated_default_pair_remains_h2() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config"], None).await?;
    ensure!(
        output.status.success(),
        "default configuration generation failed"
    );
    generated_pair(directory.path(), false)
}

#[tokio::test]
async fn generation_refuses_existing_pair_member_without_partial_writes() -> Result<()> {
    for (existing, absent) in [
        ("client.generated.yaml", "server.generated.yaml"),
        ("server.generated.yaml", "client.generated.yaml"),
    ] {
        let directory = TempDir::new()?;
        let original = "existing owner configuration\n";
        private_file(&directory.path().join(existing), original)?;
        let output = cli(directory.path(), &["gen-config"], None).await?;
        ensure!(
            !output.status.success(),
            "generation accepted an existing configuration"
        );
        ensure!(
            fs::read_to_string(directory.path().join(existing))? == original,
            "existing configuration changed"
        );
        ensure!(
            !directory.path().join(absent).exists(),
            "generation left a partial configuration pair"
        );
    }
    Ok(())
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn explicit_h3_generation_selects_both_endpoints() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config", "--quiche-h3"], None).await?;
    ensure!(
        output.status.success(),
        "explicit H3 configuration generation failed"
    );
    generated_pair(directory.path(), true)
}

#[cfg(not(feature = "experimental-h3"))]
#[tokio::test]
async fn h3_generation_requires_the_build_feature_before_writing() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config", "--quiche-h3"], None).await?;
    ensure!(
        !output.status.success(),
        "unsupported H3 generation succeeded"
    );
    ensure!(
        output.stdout.is_empty(),
        "unsupported H3 generation reported output"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    ensure!(
        error.contains("--quiche-h3") && error.contains("experimental-h3"),
        "missing H3 build-feature explanation"
    );
    ensure!(
        fs::read_dir(directory.path())?.next().is_none(),
        "unsupported H3 generation created files"
    );
    Ok(())
}

#[tokio::test]
async fn version_identifies_compiled_transport_features() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["version"], None).await?;
    ensure!(output.status.success(), "version command failed");
    let text = String::from_utf8(output.stdout).context("version output is not UTF-8")?;
    ensure!(
        text.lines().count() == 3,
        "version output changed its artifact format"
    );
    let features = text
        .lines()
        .find_map(|line| line.strip_prefix("features: "))
        .context("missing compiled features")?;
    ensure!(
        features
            .split(',')
            .any(|feature| feature == "browser-tls-default")
            == cfg!(feature = "browser-tls"),
        "browser TLS capability does not match this build"
    );
    ensure!(
        features.split(',').any(|feature| feature == "quiche-h3")
            == cfg!(feature = "experimental-h3"),
        "H3 capability does not match this build"
    );
    Ok(())
}

#[tokio::test]
async fn profile_uri_preserves_representable_connection_fields() -> Result<()> {
    let directory = TempDir::new()?;
    let secret = SecretString::generate();
    private_file(&directory.path().join("source.yaml"), &client_yaml(&secret))?;
    let omitted = cli(
        directory.path(),
        &["config-uri", "export", "--client", "source.yaml"],
        None,
    )
    .await?;
    ensure!(omitted.status.success(), "default profile export failed");
    ensure!(
        !String::from_utf8_lossy(&omitted.stdout).contains(secret.expose_secret()),
        "default profile export disclosed its secret"
    );
    let exported = cli(
        directory.path(),
        &[
            "config-uri",
            "export",
            "--client",
            "source.yaml",
            "--include-secret",
        ],
        None,
    )
    .await?;
    ensure!(exported.status.success(), "explicit profile export failed");
    let imported = cli(
        directory.path(),
        &[
            "config-uri",
            "import",
            "--uri",
            "-",
            "--output",
            "imported.yaml",
        ],
        Some(&exported.stdout),
    )
    .await?;
    ensure!(
        imported.status.success(),
        "profile import through stdin failed"
    );
    ensure!(
        !String::from_utf8_lossy(&imported.stdout).contains(secret.expose_secret())
            && !String::from_utf8_lossy(&imported.stderr).contains(secret.expose_secret()),
        "profile import disclosed its secret"
    );
    let config =
        ClientConfig::from_yaml_str(&fs::read_to_string(directory.path().join("imported.yaml"))?)
            .map_err(|_| anyhow::anyhow!("imported configuration is invalid"))?;
    ensure!(
        config.server.address == "private.example.invalid:443"
            && config.server.server_name == "private.example.invalid"
            && config.server.tunnel_path == "/private-tunnel"
            && config.server.credential_id == "private-test-user",
        "profile connection fields changed"
    );
    ensure!(
        config.server.secret.expose_secret() == secret.expose_secret(),
        "profile credential changed"
    );
    ensure!(
        !config.advanced.quiche_h3 && !config.auth.v2.enabled,
        "default profile selected a different protocol"
    );
    // A profile intentionally supplies new local defaults, not a full backup.
    ensure!(
        config.local.socks5.listen.port() == 1080,
        "profile local defaults changed"
    );
    Ok(())
}

#[tokio::test]
async fn profile_export_rejects_unrepresentable_connection_policies() -> Result<()> {
    let secret = SecretString::generate();
    let next_secret = SecretString::generate();
    let default_fingerprint = ClientAdvancedConfig::default().stealth.tls_fingerprint;
    let fingerprint = if default_fingerprint == TlsFingerprintMode::BrowserMimic {
        "browser_mimic"
    } else {
        "rustls_default"
    };
    let mut cases = vec![
        ("server.ca_cert", "  ca_cert: /private/synthetic-ca.pem\n".to_owned()),
        ("auth.channel_binding", "auth:\n  channel_binding:\n    enabled: true\n    require: true\n".to_owned()),
        ("auth.channel_binding", "auth:\n  channel_binding:\n    enabled: false\n".to_owned()),
        ("auth.v2", "auth:\n  v2:\n    enabled: true\n  rotation:\n    active_epoch: '202607'\n".to_owned()),
        ("auth.rotation", format!("auth:\n  rotation:\n    auto_switch: true\n    next:\n      id: private-next-user\n      secret: '{}'\n      not_before: '2020-01-01T00:00:00Z'\n", next_secret.expose_secret())),
        ("advanced.stealth.cdn_fronting", format!("advanced:\n  stealth:\n    tls_fingerprint: {fingerprint}\n    cdn_fronting:\n      enabled: true\n      carrier: h2\n      trusted_tls_terminating_provider: true\n")),
        ("advanced.stealth.cdn_fronting", "advanced:\n  experimental_cloudflare_ws: true\n  stealth:\n    tls_fingerprint: rustls_default\n    cdn_fronting:\n      enabled: true\n      carrier: web_socket\n      trusted_tls_terminating_provider: true\n".to_owned()),
    ];
    if default_fingerprint == TlsFingerprintMode::BrowserMimic {
        cases.push((
            "advanced.stealth.tls_fingerprint",
            "advanced:\n  stealth:\n    tls_fingerprint: rustls_default\n".to_owned(),
        ));
    }
    #[cfg(feature = "experimental-h3")]
    cases.push((
        "advanced.quiche_h3",
        "advanced:\n  quiche_h3: true\n  stealth:\n    tls_fingerprint: browser_mimic\n".to_owned(),
    ));
    for (field, extra) in cases {
        let source = format!("{}{extra}", client_yaml(&secret));
        ensure!(
            ClientConfig::from_yaml_str(&source).is_ok(),
            "invalid fixture for {field}"
        );
        let directory = TempDir::new()?;
        private_file(&directory.path().join("source.yaml"), &source)?;
        for option in [None, Some("--include-secret"), Some("--qr")] {
            let mut args = vec!["config-uri", "export", "--client", "source.yaml"];
            args.extend(option);
            let output = cli(directory.path(), &args, None).await?;
            ensure!(
                !output.status.success(),
                "profile export silently discarded {field}"
            );
            ensure!(
                output.stdout.is_empty(),
                "rejected {field} export produced a profile"
            );
            let error = String::from_utf8_lossy(&output.stderr);
            ensure!(
                error.contains(field) && error.contains("YAML"),
                "missing actionable {field} export error"
            );
            for private in [
                secret.expose_secret(),
                next_secret.expose_secret(),
                "private.example.invalid",
                "/private-tunnel",
                "private-test-user",
                "private-next-user",
                "/private/synthetic-ca.pem",
            ] {
                ensure!(
                    !error.contains(private),
                    "rejected profile export disclosed configuration data"
                );
            }
        }
    }
    Ok(())
}
