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
    ensure!(!client.advanced.auto_h3 && !server.advanced.dual_h2_h3);
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
async fn relay_generation_requires_owner_supplied_origin_trust() -> Result<()> {
    let directory = TempDir::new()?;
    for args in [
        vec!["gen-config", "--relay"],
        vec!["gen-config", "--relay", "--origin-name", "localhost"],
    ] {
        ensure!(!cli(directory.path(), &args, None).await?.status.success());
        ensure!(!directory.path().join("client.generated.yaml").exists());
        ensure!(!directory.path().join("server.generated.yaml").exists());
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    private_file(&directory.path().join("origin.pem"), &cert.cert.pem())?;
    let result = cli(
        directory.path(),
        &[
            "gen-config",
            "--relay",
            "--origin-name",
            "localhost",
            "--origin-cert",
            "origin.pem",
            "--origin-ca",
            "origin.pem",
        ],
        None,
    )
    .await?;
    ensure!(result.status.success(), "protected relay generation failed");
    generated_pair(directory.path(), false)?;
    let client = ClientConfig::from_yaml_str(&fs::read_to_string(
        directory.path().join("client.generated.yaml"),
    )?)?;
    let server = ServerConfig::from_yaml_str(&fs::read_to_string(
        directory.path().join("server.generated.yaml"),
    )?)?;
    let inner = client
        .advanced
        .end_to_end
        .context("relay generator omitted origin protection")?;
    ensure!(
        inner.server_name == "localhost"
            && inner.ca_cert.as_deref() == Some(Path::new("origin.pem"))
    );
    let pin = cli(
        directory.path(),
        &["pin-cert", "--cert", "origin.pem"],
        None,
    )
    .await?;
    ensure!(pin.status.success() && inner.cert_pin == String::from_utf8(pin.stdout)?.trim());
    ensure!(server.advanced.end_to_end);
    Ok(())
}

#[tokio::test]
async fn auto_generation_is_explicit_and_requires_h3_build() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config", "--auto-h3"], None).await?;
    if !cfg!(feature = "experimental-h3") {
        ensure!(!output.status.success());
        ensure!(!directory.path().join("client.generated.yaml").exists());
        ensure!(!directory.path().join("server.generated.yaml").exists());
        return Ok(());
    }
    ensure!(output.status.success());
    let client = ClientConfig::from_yaml_str(&fs::read_to_string(
        directory.path().join("client.generated.yaml"),
    )?)?;
    let server = ServerConfig::from_yaml_str(&fs::read_to_string(
        directory.path().join("server.generated.yaml"),
    )?)?;
    ensure!(client.advanced.auto_h3 && server.advanced.dual_h2_h3);
    ensure!(!client.advanced.quiche_h3 && !server.advanced.quiche_h3);
    let export = cli(
        directory.path(),
        &["config-uri", "export", "--client", "client.generated.yaml"],
        None,
    )
    .await?;
    ensure!(
        !export.status.success()
            && String::from_utf8_lossy(&export.stderr).contains("advanced.auto_h3"),
        "URI lost automatic carrier policy"
    );
    Ok(())
}

#[tokio::test]
async fn server_frame_size_is_checked_before_startup() -> Result<()> {
    let carriers: &[bool] = if cfg!(feature = "experimental-h3") {
        &[false, true]
    } else {
        &[false]
    };
    for &h3 in carriers {
        let directory = TempDir::new()?;
        let mut generate = vec!["gen-config"];
        if h3 {
            generate.push("--quiche-h3");
        }
        let output = cli(directory.path(), &generate, None).await?;
        ensure!(output.status.success(), "configuration generation failed");
        let source = fs::read_to_string(directory.path().join("server.generated.yaml"))?;
        let config = ServerConfig::from_yaml_str(&source)
            .map_err(|_| anyhow::anyhow!("generated server configuration is invalid"))?;
        let secret = &config.users[0].secret;
        ensure!(
            source.matches("  max_frame_size: 65536\n").count() == 1,
            "generated server frame-size field changed"
        );
        let source = source.replace("listen: \"0.0.0.0:443\"", "listen: \"127.0.0.1:0\"");
        ensure!(
            ServerConfig::from_yaml_str(&source)?.listen == "127.0.0.1:0".parse()?,
            "frame-size fixture must use an ephemeral loopback listener"
        );
        for (size, valid) in [
            (65_535, false),
            (1_048_577, false),
            (65_536, true),
            (1_048_576, true),
        ] {
            let name = format!("frame-size-{size}.yaml");
            let yaml = source.replace(
                "  max_frame_size: 65536\n",
                &format!("  max_frame_size: {size}\n"),
            );
            private_file(&directory.path().join(&name), &yaml)?;
            let mut commands = vec![vec!["check-config", "--kind", "server", "-c", &name]];
            if !valid {
                // No TLS files exist: an invalid frame size must fail during
                // configuration validation, before TLS setup or listener startup.
                commands.push(vec!["server", "-c", &name]);
            }
            for args in commands {
                let output = cli(directory.path(), &args, None).await?;
                ensure!(
                    output.status.success() == valid,
                    "{} accepted the wrong frame-size range for {size} (H3={h3})",
                    args[0]
                );
                if !valid {
                    let error = String::from_utf8_lossy(&output.stderr);
                    ensure!(
                        error.contains("advanced.max_frame_size")
                            && error.contains("65536")
                            && error.contains("1048576"),
                        "invalid frame size lacked its field and supported range"
                    );
                }
                for captured in [&output.stdout, &output.stderr] {
                    let text = String::from_utf8_lossy(captured);
                    ensure!(
                        !text.contains(secret.expose_secret()),
                        "frame-size validation disclosed its credential"
                    );
                    if !valid {
                        ensure!(
                            !text.contains("Maverick server listening")
                                && !text.contains("Maverick H3 server listening")
                                && !text.contains("Maverick local metrics listening"),
                            "invalid frame size announced readiness"
                        );
                    }
                }
            }
        }
    }
    Ok(())
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
        ("advanced.end_to_end", "advanced:\n  end_to_end:\n    server_name: origin.invalid\n    cert_pin: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".to_owned()),
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
