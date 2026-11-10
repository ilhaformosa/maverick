use super::*;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_stop_signals_close_sessions_and_release_all_carriers() -> Result<()> {
    timeout(Duration::from_secs(45), async {
        for (h3, dual, signal) in [
            (false, false, "-TERM"),
            (true, false, "-TERM"),
            (true, true, "-TERM"),
            (false, false, "-INT"),
        ] {
            let fixture = Fixture::for_transport(h3, 4)?;
            fixture.server_config(true)?;
            let path = fixture.directory.path().join("server.yaml");
            let mut yaml = std::fs::read_to_string(&path)?
                .replace("idle_timeout_secs: 10", "idle_timeout_secs: 60");
            if dual {
                yaml = yaml.replace("quiche_h3: true", "dual_h2_h3: true");
            }
            std::fs::write(&path, &yaml)?;
            let marker = if dual {
                DUAL_SERVER_READY
            } else if h3 {
                SERVER_READY
            } else {
                H2_SERVER_READY
            };
            let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
            let address = server.ready(marker).await?;
            fixture.client_config("client.yaml", address, true, Fault::None)?;
            let mut config = maverick_core::ClientConfig::from_yaml_str(&std::fs::read_to_string(
                fixture.directory.path().join("client.yaml"),
            )?)?;
            config.server.ca_cert = Some(fixture.directory.path().join("ca.pem"));
            config.advanced.idle_timeout_secs = 60;
            let client = maverick_client::start_client(config).await?;
            let target = TcpListener::bind("127.0.0.1:0").await?;
            let (mut local, status) =
                socks_connect(client.local_addr, target.local_addr()?).await?;
            ensure!(status == 0);
            let (mut peer, _) = target.accept().await?;
            local.write_all(b"x").await?;
            let mut byte = [0];
            peer.read_exact(&mut byte).await?;
            let sent = Command::new("kill")
                .args([signal, &server.child.id().to_string()])
                .status()?;
            ensure!(sent.success(), "failed to signal owned CLI process");
            let status = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(status) = server.child.try_wait()? {
                        break Ok::<_, anyhow::Error>(status);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("server CLI did not stop")??;
            ensure!(
                status.success(),
                "server terminated by signal instead of completing shutdown"
            );
            // Keep UDP bound and silent: peer notification must be QUIC close,
            // not an ICMP error from a port that disappeared.
            let udp_guard = if h3 {
                Some(std::net::UdpSocket::bind(address)?)
            } else {
                None
            };
            ensure!(timeout(Duration::from_secs(3), peer.read(&mut byte)).await?? == 0);
            ensure!(timeout(Duration::from_secs(3), local.read(&mut byte)).await?? == 0);
            client.shutdown().await?;
            if !h3 || dual {
                let guard = timeout(Duration::from_secs(3), async {
                    loop {
                        match TcpListener::bind(address).await {
                            Ok(listener) => break Ok::<_, std::io::Error>(listener),
                            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                                tokio::time::sleep(Duration::from_millis(10)).await
                            }
                            Err(error) => break Err(error),
                        }
                    }
                })
                .await??;
                drop(guard);
            }
            drop(udp_guard);
            yaml = yaml.replacen("listen: '127.0.0.1:0'", &format!("listen: '{address}'"), 1);
            std::fs::write(&path, yaml)?;
            let mut restarted = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
            ensure!(restarted.ready(marker).await? == address);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("CLI server stop/restart test timed out")?
}
