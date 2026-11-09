use super::*;
use maverick_core::{ClientConfig, ServerConfig};
use tokio::net::UdpSocket;

fn server_config(fixture: &Fixture) -> Result<ServerConfig> {
    fixture.server_config(true)?;
    let mut config = ServerConfig::from_yaml_str(&std::fs::read_to_string(
        fixture.directory.path().join("server.yaml"),
    )?)?;
    config.tls.cert_path = fixture.directory.path().join("cert.pem");
    config.tls.key_path = fixture.directory.path().join("key.pem");
    Ok(config)
}

fn client_config(
    fixture: &Fixture,
    address: SocketAddr,
    fault: Fault,
    index: usize,
) -> Result<ClientConfig> {
    let name = format!("selection-{index}.yaml");
    fixture.client_config(&name, address, true, fault)?;
    let mut config = ClientConfig::from_yaml_str(&std::fs::read_to_string(
        fixture.directory.path().join(name),
    )?)?;
    config.server.ca_cert = Some(
        fixture
            .directory
            .path()
            .join(if matches!(fault, Fault::Ca) {
                "wrong-ca.pem"
            } else {
                "ca.pem"
            }),
    );
    config.advanced.quiche_h3 = false;
    config.advanced.auto_h3 = true;
    Ok(config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dual_server_both_carriers_share_user_limit_and_release_listeners() -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::for_transport(true, 8)?;
        let mut config = server_config(&fixture)?;
        config.advanced.quiche_h3 = false;
        config.advanced.dual_h2_h3 = true;
        config.maverick.max_concurrent_flows_per_user = 1;
        let server = maverick_server::start_server(config.clone())
            .await
            .context("initial dual listener bind")?;
        let address = server.local_addr;
        let auto = maverick_client::start_client(client_config(&fixture, address, Fault::None, 0)?)
            .await?;
        let mut h2_config = client_config(&fixture, address, Fault::None, 1)?;
        h2_config.advanced.auto_h3 = false;
        let h2 = maverick_client::start_client(h2_config).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let (mut first, status) = socks_connect(auto.local_addr, target.local_addr()?).await?;
        ensure!(status == 0);
        let (mut origin, _) = target.accept().await?;
        ensure!(
            auto.h2_connection_pool_snapshot().connections_created == 0,
            "auto did not prefer H3"
        );
        let (_, status) = socks_connect(h2.local_addr, target.local_addr()?).await?;
        ensure!(status != 0, "H2 bypassed H3's shared user flow limit");
        first.write_all(b"still active").await?;
        let mut data = [0; 12];
        origin.read_exact(&mut data).await?;
        ensure!(&data == b"still active");
        drop(first);
        drop(origin);
        auto.shutdown().await?;
        // Wait for the server to observe the QUIC cancellation, then reuse the
        // exact shared permit through H2; no timing assumption about local EOF.
        timeout(Duration::from_secs(3), async {
            loop {
                let (local, status) = socks_connect(h2.local_addr, target.local_addr()?).await?;
                if status == 0 {
                    drop(local);
                    drop(target.accept().await?);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        h2.shutdown().await?;
        server.shutdown().await?;
        // The completed task has released its listener, but macOS can briefly
        // retain the TCP endpoint while the final connection close settles.
        // Keep a bounded release assertion instead of assuming instant reuse.
        let tcp = timeout(Duration::from_secs(3), async {
            loop {
                match TcpListener::bind(address).await {
                    Ok(listener) => break Ok::<_, std::io::Error>(listener),
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await
        .context("TCP endpoint retained after dual shutdown")??;
        let udp = UdpSocket::bind(address)
            .await
            .context("UDP bind after dual shutdown")?;
        drop(tcp);
        drop(udp);
        // Failure to bind the second endpoint leaves no half-running server.
        config.listen = address;
        let occupied = UdpSocket::bind(address)
            .await
            .context("reserve UDP for bind-failure check")?;
        ensure!(maverick_server::start_server(config.clone()).await.is_err());
        let tcp = TcpListener::bind(address)
            .await
            .context("TCP bind after failed dual startup")?;
        drop(tcp);
        drop(occupied);
        let restarted = maverick_server::start_server(config)
            .await
            .context("dual listener restart")?;
        restarted.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("dual server lifecycle test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_network_fallback_is_cached_and_existing_h3_flow_is_not_migrated() -> Result<()> {
    timeout(Duration::from_secs(45), async {
        let fixture = Fixture::for_transport(true, 8)?;
        let mut config = server_config(&fixture)?;
        let h3 = maverick_server::start_server(config.clone()).await?;
        config.advanced.quiche_h3 = false;
        let h2 = maverick_server::start_server(config).await?;
        let socket = UdpSocket::bind(h2.local_addr).await?;
        let h3_address = h3.local_addr;
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let blocked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let blocked_copy = Arc::clone(&blocked);
        let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recovered_copy = Arc::clone(&recovered);
        // Forward only the first QUIC connection. Later source ports see a
        // silent UDP path, while its existing H3 connection remains usable.
        let relay = tokio::spawn(async move {
            let mut first_peer = None;
            let mut buffer = [0; 2048];
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    received = socket.recv_from(&mut buffer) => {
                        let (size, from) = received?;
                        if from == h3_address {
                            if let Some(peer) = first_peer { socket.send_to(&buffer[..size], peer).await?; }
                        } else if recovered_copy.load(std::sync::atomic::Ordering::Relaxed) || from == *first_peer.get_or_insert(from) {
                            first_peer = Some(from);
                            socket.send_to(&buffer[..size], h3_address).await?;
                        } else { blocked_copy.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let client = maverick_client::start_client(client_config(&fixture, h2.local_addr, Fault::None, 0)?).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let (mut first, status) = socks_connect(client.local_addr, target.local_addr()?).await?;
        ensure!(status == 0);
        let (mut origin, _) = target.accept().await?;
        ensure!(client.h2_connection_pool_snapshot().connections_created == 0);
        for _ in 0..2 {
            tokio::try_join!(async { echo(target.accept().await?.0).await }, exchange(client.local_addr, target.local_addr()?, false, b"new connection via H2"))?;
        }
        ensure!(blocked.load(std::sync::atomic::Ordering::Relaxed) > 0, "UDP failure was not exercised");
        ensure!(client.h2_connection_pool_snapshot().connections_created == 1, "fallback did not reuse H2");
        let previous = blocked.load(std::sync::atomic::Ordering::Relaxed);
        tokio::try_join!(async { echo(target.accept().await?.0).await }, exchange(client.local_addr, target.local_addr()?, false, b"cached fallback"))?;
        ensure!(blocked.load(std::sync::atomic::Ordering::Relaxed) == previous, "negative cache reprobed UDP");
        first.write_all(b"old H3").await?;
        let mut data = [0; 6];
        origin.read_exact(&mut data).await?;
        origin.write_all(&data).await?;
        first.read_exact(&mut data).await?;
        ensure!(&data == b"old H3", "existing flow was changed by new selection");
        drop(first);
        drop(origin);
        // The cache has a finite lifetime: restore UDP and remove H2, then
        // prove a new flow on the SAME client succeeds through H3 after expiry.
        h2.shutdown().await?;
        recovered.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(30_100)).await;
        tokio::try_join!(async { echo(target.accept().await?.0).await }, exchange(client.local_addr, target.local_addr()?, false, b"H3 after network recovery"))?;
        ensure!(client.h2_connection_pool_snapshot().connections_created == 1);
        client.shutdown().await?;
        let _ = stop.send(());
        relay.await??;
        h3.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }).await.context("automatic new-connection selection test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_tls_pin_auth_and_protocol_failures_never_contact_h2() -> Result<()> {
    timeout(Duration::from_secs(40), async {
        let fixture = Fixture::for_transport(true, 16)?;
        let server = maverick_server::start_server(server_config(&fixture)?).await?;
        let spy = TcpListener::bind(server.local_addr).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        for (index, fault) in [
            Fault::Ca,
            Fault::Hostname,
            Fault::Pin,
            Fault::Secret,
            Fault::Path,
        ]
        .into_iter()
        .enumerate()
        {
            let client = maverick_client::start_client(client_config(
                &fixture,
                server.local_addr,
                fault,
                index,
            )?)
            .await?;
            let (_, status) = socks_connect(client.local_addr, target.local_addr()?).await?;
            ensure!(status != 0, "invalid H3 connection succeeded");
            ensure!(
                timeout(Duration::from_millis(80), spy.accept())
                    .await
                    .is_err(),
                "security/protocol failure contacted H2"
            );
            ensure!(
                timeout(Duration::from_millis(80), target.accept())
                    .await
                    .is_err(),
                "rejected connection reached target"
            );
            client.shutdown().await?;
        }
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("automatic selection security test timed out")?
}
