use super::native_udp::{packet, socks_udp};
use super::udp_diagnostics::next_event;
use super::*;
use std::fs;
use tokio::net::UdpSocket;

async fn check_client(
    dir: &Path,
    client_file: &str,
    metrics: SocketAddr,
    client_slot: &str,
    server_slot: &str,
) -> Result<()> {
    let admitted = server_slot != "none";
    let at =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let output = Command::new(tested_cli())
        .current_dir(dir)
        .args([
            "check-pair",
            "--client",
            client_file,
            "--server",
            "server.yaml",
            "--at",
            &at,
        ])
        .output()?;
    ensure!(
        output.status.code() == Some(if admitted { 0 } else { 1 }),
        "offline rollover verdict"
    );
    let report = std::str::from_utf8(&output.stdout)?;
    let verdict = if admitted {
        "match"
    } else {
        "no enabled credential in its acceptance window"
    };
    ensure!(report
        .lines()
        .any(|s| s == format!("client credential at supplied time: {client_slot}")));
    ensure!(report
        .lines()
        .any(|s| s == format!("server credential at supplied time: {server_slot}")));
    ensure!(report
        .lines()
        .any(|s| s == format!("selected credential: {verdict}")));

    let (tx, mut events) = mpsc::unbounded_channel();
    let mut client = Cli::spawn(dir, "client", client_file, &["--diagnose-udp"], Some(tx))?;
    let socks = client.ready(SOCKS_READY).await?;
    client.ready(HTTP_READY).await?;
    let rejections = async || -> Result<u64> {
        soak::metrics(metrics).await?["unauthenticated_rejections"]
            .as_u64()
            .context("missing auth rejection counter")
    };
    let before = rejections().await?;
    if admitted {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        tokio::try_join!(
            async { echo(tcp.accept().await?.0).await },
            exchange(socks, tcp.local_addr()?, false, b"rollover")
        )?;
    } else {
        rejected_before_target(socks).await?;
    }

    let (control, app) = socks_udp(socks).await?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    app.send(&packet(address, b"request")).await?;
    ensure!(
        next_event(&mut events).await?
            == "1 stage=opening allowed=h2_reliable carrier=unknown target_reply=not_observed"
    );
    let mut buf = [0; 256];
    if admitted {
        ensure!(next_event(&mut events).await? == "1 stage=admitted allowed=h2_reliable carrier=h2_reliable target_reply=not_observed");
        let (n, peer) = target.recv_from(&mut buf).await?;
        ensure!(&buf[..n] == b"request");
        for reply in [b"first".as_slice(), b"second"] {
            target.send_to(reply, peer).await?;
            let n = app.recv(&mut buf).await?;
            ensure!(buf[..n] == packet(address, reply));
        }
    } else {
        ensure!(next_event(&mut events).await? == "1 stage=open_failed allowed=h2_reliable carrier=unknown target_reply=not_observed");
        ensure!(
            matches!(target.try_recv(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
        ensure!(
            rejections().await? >= before + 2,
            "both fresh opens must reach server authentication"
        );
    }
    drop(control);
    client.stop("-INT").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run with a verified native archive"]
async fn packaged_credential_rollover_and_restore() -> Result<()> {
    let drill = async {
        let fixture = Fixture::for_transport(false, 16)?;
        let dir = fixture.directory.path();
        fixture.server_config_with_metrics(false)?;
        let address = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let server_file = dir.join("server.yaml");
        let original_server = fs::read_to_string(&server_file)?.replacen(
            "listen: '127.0.0.1:0'",
            &format!("listen: '{address}'"),
            1,
        );
        fs::write(&server_file, &original_server)?;
        fixture.client_config("client.yaml", address, false, Fault::None)?;
        let client_file = dir.join("client.yaml");
        let original_client = fs::read_to_string(&client_file)?
            .replace("advanced:\n", "advanced:\n  udp_policy: allow_reliable\n");
        fs::write(&client_file, &original_client)?;
        for name in ["client.yaml", "server.yaml"] {
            fs::copy(dir.join(name), dir.join(format!("{name}.bak")))?;
        }

        let replacement = SecretString::generate();
        let rotation = format!(
            "  rotation:
    auto_switch: true
    next:
      id: replacement-user
      secret: '{}'
      not_before: '2000-01-01T00:00:00Z'",
            replacement.expose_secret()
        );
        let rotated = original_client.replace("  rotation:", &rotation);
        let active_user = format!(
            "  - id: local-test-user\n    secret: '{}'",
            fixture.secret.expose_secret()
        );
        let overlap_user = format!(
            "  - id: replacement-user
    secret: '{}'
    rotation:
      previous:
        - id: local-test-user
          secret: '{}'
          not_before: '2000-01-01T00:00:00Z'
          not_after: '2100-01-01T00:00:00Z'",
            replacement.expose_secret(),
            fixture.secret.expose_secret()
        );
        let overlap = original_server.replace(&active_user, &overlap_user);
        let expired = overlap.replace("2100-01-01", "2001-01-01");
        private_file(dir, "rotating.yaml", &rotated)?;
        for (phase, server_yaml, old_slot, new_slot) in [
            ("original", &original_server, "active", "none"),
            ("overlap", &overlap, "previous", "active"),
            ("retired", &expired, "none", "active"),
            ("restored", &original_server, "active", "none"),
        ] {
            let (old_client, switched_client) = match phase {
                "overlap" | "retired" => {
                    fs::write(&server_file, server_yaml)?;
                    fs::copy(dir.join("rotating.yaml"), &client_file)?;
                    ("client.yaml.bak", "client.yaml")
                }
                "restored" => {
                    for name in ["client.yaml", "server.yaml"] {
                        fs::copy(dir.join(format!("{name}.bak")), dir.join(name))?;
                    }
                    ensure!(
                        fs::read(&client_file)? == original_client.as_bytes()
                            && fs::read(&server_file)? == original_server.as_bytes()
                    );
                    ("client.yaml", "rotating.yaml")
                }
                _ => ("client.yaml", "rotating.yaml"),
            };
            let mut server = Cli::start(dir, "server", "server.yaml")?;
            ensure!(server.ready(H2_SERVER_READY).await? == address);
            let metrics = server.ready(METRICS_READY).await?;
            check_client(dir, old_client, metrics, "active", old_slot)
                .await
                .with_context(|| format!("{phase} old client"))?;
            check_client(dir, switched_client, metrics, "next", new_slot)
                .await
                .with_context(|| format!("{phase} switched client"))?;
            server.stop("-TERM").await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    timeout(Duration::from_secs(60), drill)
        .await
        .context("packaged credential rollover timed out")?
}
