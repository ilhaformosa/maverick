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

async fn expect_check_error(work: &Path, args: &[&str], message: &str) -> Result<()> {
    let output = cli(work, args, None).await?;
    ensure!(!output.status.success() && output.stdout.is_empty());
    ensure!(
        output.stderr == format!("Error: {message}\n").as_bytes(),
        "expected only the fixed check-config error"
    );
    Ok(())
}

#[tokio::test]
async fn offline_server_tls_uses_staged_files_without_binding() -> Result<()> {
    let valid = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let secret = SecretString::generate();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let listen = tcp.local_addr()?;
    let _udp = std::net::UdpSocket::bind(listen)?;
    let plain = [
        "check-config",
        "--kind",
        "server",
        "-c",
        "config/staged.yaml",
    ];
    let mut inspect = plain.to_vec();
    inspect.push("--check-tls");
    let success = b"server TLS certificate chain and private key: OK (offline)\n";

    for (backend, advanced) in [
        ("H2", ""),
        ("H2", "  end_to_end: true"),
        ("H3", "  quiche_h3: true"),
        ("dual", "  dual_h2_h3: true"),
    ] {
        let directory = TempDir::new()?;
        let work = directory.path();
        fs::create_dir(work.join("config"))?;
        let config = work.join("config/staged.yaml");
        let chain = work.join("test-private-chain.pem");
        let key = work.join("test-private-key.pem");
        let mut yaml = format!("version: 1\nlisten: '{listen}'\ntls:\n  cert_path: test-private-chain.pem\n  key_path: test-private-key.pem\nmaverick:\n  tunnel_path: /test-private-route\nusers:\n  - id: test-private-id\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: public\n", secret.expose_secret());
        if !advanced.is_empty() {
            yaml.push_str(&format!("advanced:\n{advanced}\n"));
        }
        private_file(&config, &yaml)?;
        if backend != "H2" && !cfg!(feature = "experimental-h3") {
            let output = cli(work, &inspect, None).await?;
            ensure!(!output.status.success() && output.stdout.is_empty());
            let error = String::from_utf8(output.stderr)?;
            ensure!(
                error.contains("compiled direct transports: H2 only")
                    && !error.contains("test-private")
                    && !error.contains(secret.expose_secret())
            );
            continue;
        }
        let output = cli(work, &plain, None).await?;
        ensure!(output.status.success() && output.stdout == b"server config OK\n");
        let mut explain = plain.to_vec();
        explain.push("--explain");
        let output = cli(work, &explain, None).await?;
        ensure!(
            output.status.success()
                && !String::from_utf8(output.stdout)?
                    .contains("server TLS certificate chain and private key: OK")
        );
        let first_backend = if backend == "dual" { "H2" } else { backend };
        let error = format!("{first_backend} could not load a matching server TLS certificate chain and private key");
        expect_check_error(work, &inspect, &error)
            .await
            .context("missing files")?;
        private_file(&chain, &valid.cert.pem())?;
        expect_check_error(work, &inspect, &error)
            .await
            .context("missing key")?;
        private_file(&key, "test-private-malformed-key")?;
        expect_check_error(work, &inspect, &error)
            .await
            .context("malformed key")?;
        fs::write(&key, other.signing_key.serialize_pem())?;
        expect_check_error(work, &inspect, &error)
            .await
            .context("mismatched key")?;
        fs::write(&key, valid.signing_key.serialize_pem())?;
        fs::write(&chain, "test-private-malformed-chain")?;
        expect_check_error(work, &inspect, &error)
            .await
            .context("malformed chain")?;
        fs::write(&chain, valid.cert.pem())?;
        let output = cli(work, &inspect, None).await?;
        ensure!(
            output.status.success() && output.stdout == success && output.stderr.is_empty(),
            "matching pair"
        );
        let mut both = inspect.clone();
        both.push("--explain");
        let output = cli(work, &both, None).await?;
        ensure!(
            output.status.success() && output.stderr.is_empty() && output.stdout.ends_with(success)
        );
        let text = String::from_utf8(output.stdout)?;
        ensure!(
            text.contains("remote connection: unverified (offline)")
                && !text.contains("test-private")
                && !text.contains(secret.expose_secret())
        );
        ensure!(fs::read_to_string(config)? == yaml);
    }
    let dir = TempDir::new()?;
    expect_check_error(
        dir.path(),
        &[
            "check-config",
            "--check-tls",
            "--kind",
            "client",
            "-c",
            "missing.yaml",
        ],
        "--check-tls requires --kind server",
    )
    .await
}

async fn expect_explanation(
    directory: &Path,
    kind: &str,
    file: &str,
    route: &str,
    udp: &str,
) -> Result<()> {
    let output = cli(
        directory,
        &["check-config", "--explain", "--kind", kind, "-c", file],
        None,
    )
    .await?;
    let build = if cfg!(feature = "experimental-h3") {
        "H2 and H3"
    } else {
        "H2 only"
    };
    let expected = format!("configured route: {route}\nUDP: {udp}\ncompiled direct transports: {build}\nremote connection: unverified (offline)\n");
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "{kind} explanation failed"
    );
    ensure!(
        output.stdout == expected.as_bytes(),
        "unexpected {kind} explanation for {route}"
    );
    Ok(())
}

#[tokio::test]
async fn explain_old_auto_config_and_keep_plain_check_output() -> Result<()> {
    let directory = TempDir::new()?;
    private_file(
        &directory.path().join("old.yaml"),
        &client_yaml(&SecretString::generate()),
    )?;
    expect_explanation(
        directory.path(),
        "client",
        "old.yaml",
        "direct H2",
        "policy omitted; legacy H2 request/reply",
    )
    .await?;
    let plain = cli(
        directory.path(),
        &["check-config", "--kind", "client", "-c", "old.yaml"],
        None,
    )
    .await?;
    ensure!(
        plain.status.success() && plain.stdout == b"client config OK\n" && plain.stderr.is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn explain_rejections_keep_private_inputs_out_of_diagnostics() -> Result<()> {
    let directory = TempDir::new()?;
    let file = "private-test-path.yaml";
    let secret = SecretString::generate();
    let source = client_yaml(&secret);
    let path = directory.path().join(file);
    let args = ["check-config", "--explain", "--kind", "client", "-c", file];
    let missing = cli(directory.path(), &args, None).await?;
    ensure!(!missing.status.success() && missing.stdout.is_empty());
    ensure!(!String::from_utf8_lossy(&missing.stderr).contains(file));

    private_file(
        &path,
        &format!("{source}advanced:\n  udp_policy: private-invalid-value\n"),
    )?;
    let rejected = cli(directory.path(), &args, None).await?;
    ensure!(!rejected.status.success() && rejected.stdout.is_empty());
    let error = String::from_utf8_lossy(&rejected.stderr);
    ensure!(error.contains("configuration rejected"));
    for private in [
        file,
        "private-invalid-value",
        "private.example.invalid",
        "private-test-user",
        secret.expose_secret(),
    ] {
        ensure!(
            !error.contains(private),
            "rejection disclosed private input"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&path, "version: 0\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let output = cli(directory.path(), &args, None).await?;
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        ensure!(
            !output.status.success()
                && diagnostic.contains("chmod 600")
                && !diagnostic.contains(file)
        );
    }
    Ok(())
}

#[tokio::test]
async fn explain_h3_respects_fixed_carrier_and_omitted_udp_policy() -> Result<()> {
    let directory = TempDir::new()?;
    let source = client_yaml(&SecretString::generate());
    let auto = "direct automatic (new TCP connections prefer H3; H2 only after a pre-response network failure)";
    for (index, (carrier, policy, route, udp)) in [
        ("auto_h3", "", auto, "policy omitted; native H3 only"),
        (
            "auto_h3",
            "  udp_policy: native_required\n",
            auto,
            "native_required; native H3 only",
        ),
        (
            "quiche_h3",
            "",
            "direct H3",
            "policy omitted; native H3 only",
        ),
        (
            "quiche_h3",
            "  udp_policy: allow_reliable\n",
            "direct H3",
            "allow_reliable; fixed H3 uses native datagrams only",
        ),
    ]
    .iter()
    .enumerate()
    {
        let file = format!("client-{index}.yaml");
        private_file(
            &directory.path().join(&file),
            &format!("{source}advanced:\n  {carrier}: true\n{policy}"),
        )?;
        if cfg!(feature = "experimental-h3") {
            expect_explanation(directory.path(), "client", &file, route, udp).await?;
        } else {
            let output = cli(
                directory.path(),
                &["check-config", "--explain", "--kind", "client", "-c", &file],
                None,
            )
            .await?;
            ensure!(!output.status.success() && output.stdout.is_empty());
            ensure!(String::from_utf8_lossy(&output.stderr)
                .contains("compiled direct transports: H2 only"));
        }
    }
    Ok(())
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
async fn generated_user_name_round_trips_as_a_yaml_string() -> Result<()> {
    let directory = TempDir::new()?;
    let name = "Operations: East #1\nNight shift\u{7f}\u{85}\u{9f}\u{2028}\u{2029}\u{feff}\u{fffe}\u{ffff}\"\\✈";
    let output = cli(directory.path(), &["gen-user", "--name", name], None).await?;
    ensure!(output.status.success(), "credential generation failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let user: maverick_core::config::UserConfig = serde_saphyr::from_str(text)
        .map_err(|_| anyhow::anyhow!("generated user was not valid YAML"))?;
    ensure!(user.name.as_deref() == Some(name), "user name changed");
    user.secret.validate()?;
    Ok(())
}

#[tokio::test]
async fn generated_fixed_h2_pair_remains_h2() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config", "--h2"], None).await?;
    ensure!(
        output.status.success(),
        "default configuration generation failed"
    );
    generated_pair(directory.path(), false)?;
    expect_explanation(
        directory.path(),
        "client",
        "client.generated.yaml",
        "direct H2",
        "allow_reliable; reliable H2 session",
    )
    .await?;
    expect_explanation(
        directory.path(),
        "server",
        "server.generated.yaml",
        "direct H2",
        "reliable over H2 (including legacy request/reply)",
    )
    .await
}

#[tokio::test]
async fn generated_direct_defaults_are_dual_auto_with_explicit_udp_policy() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(directory.path(), &["gen-config"], None).await?;
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
    ensure!(client.advanced.udp_policy == Some(maverick_core::config::UdpPolicy::AllowReliable));
    ensure!(!client.advanced.quiche_h3 && !server.advanced.quiche_h3);
    ensure!(client.server.secret.expose_secret() == server.users[0].secret.expose_secret());
    expect_explanation(directory.path(), "client", "client.generated.yaml",
        "direct automatic (new TCP connections prefer H3; H2 only after a pre-response network failure)",
        "allow_reliable; prefer native H3; allow reliable H2 before sending data if H3 is unreachable before a reply or the authenticated peer lacks native UDP").await?;
    expect_explanation(
        directory.path(),
        "server",
        "server.generated.yaml",
        "direct dual H2/H3",
        "reliable over H2 or native over H3; client selects",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn generation_rejects_incompatible_udp_policy_without_outputs() -> Result<()> {
    let directory = TempDir::new()?;
    let output = cli(
        directory.path(),
        &["gen-config", "--h2", "--udp-policy", "native_required"],
        None,
    )
    .await?;
    ensure!(!output.status.success());
    ensure!(!directory.path().join("client.generated.yaml").exists());
    ensure!(!directory.path().join("server.generated.yaml").exists());
    Ok(())
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
    let route = "origin-protected H2 intermediary (pinned inner TLS)";
    expect_explanation(
        directory.path(),
        "client",
        "client.generated.yaml",
        route,
        "allow_reliable; reliable H2 session",
    )
    .await?;
    expect_explanation(
        directory.path(),
        "server",
        "server.generated.yaml",
        route,
        "reliable over H2 (including legacy request/reply)",
    )
    .await?;
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
        generate.push(if h3 { "--quiche-h3" } else { "--h2" });
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
        let output = cli(directory.path(), &["gen-config", "--h2"], None).await?;
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

#[cfg(unix)]
#[tokio::test]
async fn generation_preserves_dangling_link_without_creating_partial_pair() -> Result<()> {
    let directory = TempDir::new()?;
    let server_path = directory.path().join("server.generated.yaml");
    let missing = Path::new("moved-server-config.yaml");
    std::os::unix::fs::symlink(missing, &server_path)?;
    let output = cli(directory.path(), &["gen-config", "--h2"], None).await?;
    ensure!(
        !output.status.success(),
        "generation accepted a dangling link"
    );
    ensure!(
        fs::read_link(server_path)? == missing,
        "server link changed"
    );
    ensure!(
        !directory.path().join("client.generated.yaml").exists(),
        "generation left an unmatched client configuration"
    );
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
    generated_pair(directory.path(), true)?;
    expect_explanation(
        directory.path(),
        "client",
        "client.generated.yaml",
        "direct H3",
        "native_required; native H3 only",
    )
    .await?;
    expect_explanation(
        directory.path(),
        "server",
        "server.generated.yaml",
        "direct H3",
        "native over H3",
    )
    .await
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

async fn compare_pair(client: &str, server: &str, succeeds: bool, lines: &[&str]) -> Result<()> {
    let dir = TempDir::new()?;
    let c = dir.path().join("private-client.yaml");
    let s = dir.path().join("private-server.yaml");
    private_file(&c, client)?;
    private_file(&s, server)?;
    let out = cli(
        dir.path(),
        &[
            "check-pair",
            "--client",
            "private-client.yaml",
            "--server",
            "private-server.yaml",
        ],
        None,
    )
    .await?;
    ensure!(
        out.status.success() == succeeds,
        "unexpected pair verdict for {lines:?}"
    );
    let report = String::from_utf8(out.stdout)?;
    for line in lines {
        ensure!(
            report.lines().any(|actual| actual == *line),
            "missing {line}"
        );
    }
    let error = String::from_utf8(out.stderr)?;
    let inputs = ClientConfig::from_yaml_str(client)?;
    for private in [
        "private",
        inputs.server.secret.expose_secret(),
        &inputs.server.address,
        &inputs.server.tunnel_path,
        &inputs.server.credential_id,
    ] {
        ensure!(
            !report.contains(private) && !error.contains(private),
            "pair disclosed input"
        );
    }
    ensure!(report.ends_with("remote connection: unverified (offline)\n"));
    ensure!(if succeeds {
        error.is_empty()
    } else {
        error == "Error: configuration pair mismatch\n"
    });
    ensure!(fs::read_to_string(c)? == client && fs::read_to_string(s)? == server);
    Ok(())
}

#[tokio::test]
async fn offline_pair_checks_shared_policy_and_the_selected_credential() -> Result<()> {
    let secret = SecretString::generate();
    let other = SecretString::generate();
    let c = client_yaml(&secret);
    let s = format!("version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: private-chain.pem\n  key_path: private-key.pem\nmaverick:\n  tunnel_path: /private-tunnel\nfallback:\n  type: static\n  static_dir: public\nusers:\n  - id: private-test-user\n    secret: '{}'\n", secret.expose_secret());
    compare_pair(
        &c,
        &s,
        true,
        &[
            "shared TCP carriers: H2",
            "shared UDP carriers: H2",
            "selected credential: match",
        ],
    )
    .await?;
    compare_pair(
        &c,
        &format!("{s}    enabled: false\n"),
        false,
        &["selected credential: disabled user"],
    )
    .await?;
    compare_pair(
        &c,
        &s.replace(secret.expose_secret(), other.expose_secret()),
        false,
        &["selected credential: secret mismatch"],
    )
    .await?;
    compare_pair(
        &c,
        &s.replace("/private-tunnel", "/private-other"),
        false,
        &["tunnel path: mismatch"],
    )
    .await?;
    let protected = format!("{c}advanced:\n  end_to_end:\n    server_name: private.invalid\n    cert_pin: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    let protected_server = format!("{s}advanced:\n  end_to_end: true\n");
    compare_pair(
        &protected,
        &protected_server,
        true,
        &["origin protection: match"],
    )
    .await?;
    compare_pair(&protected, &s, false, &["origin protection: mismatch"]).await?;
    let rotated = format!("{c}auth:\n  rotation:\n    auto_switch: true\n    next:\n      id: private-next\n      secret: '{}'\n      not_before: '2000-01-01T00:00:00Z'\n", other.expose_secret());
    compare_pair(
        &rotated,
        &s,
        false,
        &["selected credential: no enabled credential in its acceptance window"],
    )
    .await?;
    let overlap = format!("{s}    rotation:\n      previous:\n        - id: private-next\n          secret: '{}'\n          not_before: '2000-01-01T00:00:00Z'\n          not_after: '9999-01-01T00:00:00Z'\n", other.expose_secret());
    compare_pair(&rotated, &overlap, true, &["selected credential: match"]).await?;
    compare_pair(
        &rotated,
        &overlap.replace("9999-", "2001-"),
        false,
        &["selected credential: no enabled credential in its acceptance window"],
    )
    .await?;
    let v2 =
        format!("{c}auth:\n  v2:\n    enabled: true\n  rotation:\n    active_epoch: '202607'\n");
    compare_pair(&v2, &s, false, &["authentication version/epoch: mismatch"]).await?;
    compare_pair(
        &c,
        &format!("{s}auth:\n  channel_binding:\n    enabled: false\n"),
        false,
        &["TLS channel binding policy: mismatch"],
    )
    .await?;
    if cfg!(feature = "experimental-h3") {
        let h3_server = format!("{s}advanced:\n  quiche_h3: true\n");
        compare_pair(
            &c,
            &h3_server,
            false,
            &["shared TCP carriers: none", "shared UDP carriers: none"],
        )
        .await?;
        let auto = format!("{c}advanced:\n  auto_h3: true\n  stealth:\n    tls_fingerprint: browser_mimic\n  udp_policy: native_required\n");
        compare_pair(
            &auto,
            &s,
            false,
            &["shared TCP carriers: H2", "shared UDP carriers: none"],
        )
        .await?;
        compare_pair(
            &auto.replace("native_required", "allow_reliable"),
            &s,
            true,
            &["shared UDP carriers: H2"],
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn offline_pair_redacts_read_and_parse_errors() -> Result<()> {
    let dir = TempDir::new()?;
    let args = [
        "check-pair",
        "--client",
        "private-client.yaml",
        "--server",
        "private-server.yaml",
    ];
    expect_check_error(dir.path(), &args, "cannot read client configuration").await?;
    private_file(
        &dir.path().join("private-client.yaml"),
        &client_yaml(&SecretString::generate()),
    )?;
    private_file(
        &dir.path().join("private-server.yaml"),
        "private-invalid: [",
    )?;
    let build = if cfg!(feature = "experimental-h3") {
        "H2 and H3"
    } else {
        "H2 only"
    };
    expect_check_error(
        dir.path(),
        &args,
        &format!("server configuration rejected (compiled direct transports: {build})"),
    )
    .await
}

#[tokio::test]
async fn check_staged_origin_chain_with_only_inner_trust() -> Result<()> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let dir = TempDir::new()?;
    let work = dir.path();
    let ca_params = |name| -> Result<CertificateParams> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Ok(p)
    };
    let ca = ca_params("test root")?;
    let key = KeyPair::generate()?;
    private_file(&work.join("private-ca.pem"), &ca.self_signed(&key)?.pem())?;
    let ca = Issuer::from_params(&ca, key);
    let intermediate = ca_params("test intermediate")?;
    let key = KeyPair::generate()?;
    let issuer_pem = intermediate.signed_by(&key, &ca)?.pem();
    let issuer = Issuer::from_params(&intermediate, key);
    let name = "private-origin.invalid";
    let leaf_params = CertificateParams::new(vec![name.into()])?;
    let key = KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&key, &issuer)?;
    let chain_path = work.join("private-chain.pem");
    let chain = leaf.pem() + &issuer_pem;
    private_file(&chain_path, &chain)?;
    let pin = cli(work, &["pin-cert", "--cert", "private-chain.pem"], None).await?;
    ensure!(pin.status.success());
    let pin = String::from_utf8(pin.stdout)?;
    let client = client_yaml(&SecretString::generate());
    let yaml = format!("{client}  ca_cert: private-outer.pem\nadvanced:\n  end_to_end:\n    server_name: {name}\n    ca_cert: private-ca.pem\n    cert_pin: '{}'\n", pin.trim());
    let config_path = work.join("private-client.yaml");
    private_file(&config_path, &yaml)?;
    let args = [
        "check-config",
        "--kind",
        "client",
        "-c",
        "private-client.yaml",
        "--origin-cert",
        "private-chain.pem",
    ];
    let output = cli(work, &args, None).await?;
    ensure!(
        output.status.success()
            && output.stdout
                == b"staged origin certificate chain, name, validity and leaf pin: OK (offline)\n"
            && output.stderr.is_empty()
    );
    ensure!(fs::read_to_string(&config_path)? == yaml && fs::read_to_string(&chain_path)? == chain);
    let other = rcgen::generate_simple_self_signed(vec![name.into()])?;
    private_file(&work.join("private-wrong.pem"), &other.cert.pem())?;
    for (input, error) in [
        (
            yaml.replace(name, "different.invalid"),
            "staged origin certificate name mismatch",
        ),
        (
            yaml.replace(
                pin.trim(),
                "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            "staged origin leaf pin mismatch",
        ),
        (
            yaml.replace("private-outer.pem", "private-ca.pem").replace(
                "    ca_cert: private-ca.pem",
                "    ca_cert: private-wrong.pem",
            ),
            "staged origin certificate chain is untrusted or incomplete",
        ),
        (
            yaml.replace("private-ca.pem", "missing.pem"),
            "cannot load configured origin trust roots",
        ),
        (
            client,
            "--origin-cert requires a protected H2 client configuration",
        ),
    ] {
        fs::write(&config_path, &input)?;
        expect_check_error(work, &args, error).await?;
        ensure!(fs::read_to_string(&config_path)? == input);
    }
    fs::write(&config_path, &yaml)?;
    let mut expired = leaf_params;
    expired.not_after = rcgen::date_time_ymd(2001, 1, 1);
    fs::write(
        &chain_path,
        expired.signed_by(&key, &issuer)?.pem() + &issuer_pem,
    )?;
    expect_check_error(
        work,
        &args,
        "staged origin certificate outside its validity period",
    )
    .await?;
    fs::write(&chain_path, leaf.pem())?;
    expect_check_error(
        work,
        &args,
        "staged origin certificate chain is untrusted or incomplete",
    )
    .await?;
    fs::write(&chain_path, "")?;
    expect_check_error(work, &args, "empty staged origin certificate chain").await?;
    fs::remove_file(&chain_path)?;
    expect_check_error(work, &args, "cannot read staged origin certificate chain").await?;
    let mut server_args = args;
    server_args[2] = "server";
    expect_check_error(work, &server_args, "--origin-cert requires --kind client").await
}
