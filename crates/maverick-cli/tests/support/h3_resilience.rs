use super::*;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

async fn start_server(fixture: &Fixture) -> Result<(Cli, SocketAddr, SocketAddr)> {
    let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
    let address = server.ready(SERVER_READY).await?;
    let metrics = server.ready(METRICS_READY).await?;
    Ok((server, address, metrics))
}

async fn start_client(
    fixture: &Fixture,
    server: SocketAddr,
) -> Result<(Cli, SocketAddr, SocketAddr)> {
    fixture.client_config("client.yaml", server, true, Fault::None)?;
    let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
    let socks = client.ready(SOCKS_READY).await?;
    let http = client.ready(HTTP_READY).await?;
    Ok((client, socks, http))
}

// One client connection only: no CID routing, random loss or host network changes.
async fn perturbed_datagrams(
    socket: UdpSocket,
    server: SocketAddr,
    post_connect: Arc<AtomicBool>,
    mut stop: oneshot::Receiver<()>,
) -> Result<[usize; 3]> {
    let mut client = None;
    let mut injected = [0; 3];
    let mut packet = [0; 65_536];
    loop {
        tokio::select! {
            _ = &mut stop => return Ok(injected),
            received = socket.recv_from(&mut packet) => {
                let (len, from) = received?;
                let to = if from == server {
                    if injected[1] == 0 {
                        // A single delayed response, not a latency/rate simulator.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        injected[1] += 1;
                    }
                    if post_connect.load(Ordering::Relaxed) && injected[2] == 0 {
                        injected[2] += 1;
                        continue;
                    }
                    client.context("server response before a client datagram")?
                } else {
                    ensure!(from.ip().is_loopback(), "unexpected relay peer");
                    if let Some(expected) = client {
                        ensure!(from == expected, "relay supports one client connection");
                    } else {
                        client = Some(from);
                    }
                    if injected[0] == 0 {
                        injected[0] += 1;
                        continue;
                    }
                    server
                };
                socket.send_to(&packet[..len], to).await?;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_h3_recovers_from_selected_datagram_loss_and_delay() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new()?;
        fixture.server_config_with_metrics(true)?;
        let (_server, address, metrics) = start_server(&fixture).await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let relay_address = socket.local_addr()?;
        let post_connect = Arc::new(AtomicBool::new(false));
        let (stop, stopped) = oneshot::channel();
        let mut relay = JoinSet::new();
        relay.spawn(perturbed_datagrams(
            socket,
            address,
            Arc::clone(&post_connect),
            stopped,
        ));
        let (_client, socks, _) = start_client(&fixture, relay_address).await?;
        let result = async {
            let target = TcpListener::bind("127.0.0.1:0").await?;
            let (local, status) = socks_connect(socks, target.local_addr()?).await?;
            ensure!(
                status == 0,
                "perturbed H3 CONNECT rejected: status {status}"
            );
            let (origin, _) = target.accept().await?;
            // Drop a datagram only after CONNECT succeeds. Its encrypted frame
            // contents are deliberately not inspected or described as DATA.
            post_connect.store(true, Ordering::Relaxed);
            tokio::try_join!(
                transfer(local, 512 * 1024, 512 * 1024),
                transfer(origin, 512 * 1024, 512 * 1024)
            )?;
            soak::wait_for_drained(metrics, true).await?;
            let _ = stop.send(());
            let injected = relay
                .join_next()
                .await
                .context("missing relay result")???;
            ensure!(
                injected == [1, 1, 1],
                "requested datagram faults were not all exercised"
            );
            Ok(())
        }
        .await;
        checked_stage(result, metrics, "selected datagram loss and delay").await
    })
    .await
    .context("H3 datagram resilience test timed out")?
}

fn tcp_options(stream: TcpStream) -> Result<(TcpStream, TcpSocket)> {
    let stream = stream.into_std()?;
    let options = TcpSocket::from_std_stream(stream.try_clone()?);
    Ok((TcpStream::from_std(stream)?, options))
}

async fn healthy_pair(socks: SocketAddr, http: SocketAddr) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let origin = async {
        let first = target.accept().await?.0;
        let second = target.accept().await?.0;
        tokio::try_join!(echo(first), echo(second))?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(
        origin,
        exchange(socks, address, false, b"healthy SOCKS beside a slow reader"),
        exchange(http, address, true, b"healthy HTTP beside a slow reader")
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_h3_slow_reader_preserves_other_connections() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::for_transport(true, 4)?;
        fixture.server_config_with_metrics(true)?;
        let (_server, address, metrics) = start_server(&fixture).await?;
        let (_client, socks, http) = start_client(&fixture, address).await?;
        let result = async {
            const PAYLOAD: usize = 8 * 1024 * 1024;
            for cancel in [false, true] {
                let target = TcpListener::bind("127.0.0.1:0").await?;
                // Pausing reads establishes backpressure without shrinking a
                // connected TCP receive window, which disables Linux autotuning.
                let (mut local, status) = socks_connect(socks, target.local_addr()?).await?;
                ensure!(status == 0, "slow-reader CONNECT rejected: status {status}");
                local.shutdown().await?;
                let (origin, _) = target.accept().await?;
                let (mut origin, send_options) = tcp_options(origin)?;
                send_options.set_send_buffer_size(16 * 1024)?;
                drop(send_options);
                let (blocked, observed_block) = oneshot::channel();
                let mut writers = JoinSet::new();
                writers.spawn(async move {
                    let block = [0x5a; 16 * 1024];
                    let mut remaining = PAYLOAD;
                    let mut blocked = Some(blocked);
                    while remaining > 0 {
                        origin.writable().await?;
                        match origin.try_write(&block[..remaining.min(block.len())]) {
                            Ok(0) => bail!("slow target write returned zero"),
                            Ok(count) => remaining -= count,
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                if let Some(blocked) = blocked.take() {
                                    let _ = blocked.send(());
                                }
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    origin.shutdown().await?;
                    Ok::<_, anyhow::Error>(())
                });
                tokio::select! {
                    result = observed_block => result.context("slow writer did not become backpressured")?,
                    result = writers.join_next() => {
                        result.context("missing slow writer")???;
                        bail!("slow writer finished before backpressure was established");
                    }
                }
                healthy_pair(socks, http).await?;
                if let Some(result) = writers.try_join_next() {
                    result??;
                    bail!("slow writer completed while the reader was blocked");
                }
                if cancel {
                    drop(local);
                    let result = timeout(Duration::from_secs(3), writers.join_next())
                        .await
                        .context("cancelled slow reader retained its target writer")?
                        .context("missing cancelled slow writer")??;
                    if let Err(error) = result {
                        ensure!(
                            error.downcast_ref::<std::io::Error>().is_some(),
                            "unexpected cancelled writer failure: {error:#}"
                        );
                    }
                } else {
                    let (read, write) = local.into_split();
                    drop(write);
                    receive_payload(read, PAYLOAD).await?;
                    writers.join_next().await.context("missing slow writer")???;
                }
                soak::wait_for_drained(metrics, true).await?;
                successful_flows(socks, http, metrics).await?;
            }
            Ok(())
        }
        .await;
        checked_stage(
            result,
            metrics,
            "slow reader resume/cancel and independent healthy connections",
        )
        .await
    })
    .await
    .context("H3 slow-reader test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_h3_client_recovers_after_server_restart() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::for_transport(true, 4)?;
        fixture.server_config_with_metrics(true)?;
        let (server, address, metrics) = start_server(&fixture).await?;
        let (_client, socks, http) = start_client(&fixture, address).await?;
        successful_flows(socks, http, metrics).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let (mut held, status) = socks_connect(socks, target.local_addr()?).await?;
        ensure!(status == 0, "server-stop flow rejected: status {status}");
        let (mut peer, _) = target.accept().await?;
        held.write_all(b"active").await?;
        let mut bytes = [0; 6];
        peer.read_exact(&mut bytes).await?;
        ensure!(&bytes == b"active", "server-stop flow payload changed");
        drop(server);
        let mut rest = Vec::new();
        timeout(Duration::from_secs(3), peer.read_to_end(&mut rest))
            .await
            .context("server exit retained its target connection")??;
        ensure!(rest.is_empty(), "unexpected server-stop payload");
        let result = timeout(Duration::from_secs(15), held.read_to_end(&mut rest))
            .await
            .context("server exit retained its client connection")?;
        ensure!(
            rest.is_empty(),
            "unexpected client payload after server exit"
        );
        // Both EOF and a propagated socket error terminate the interrupted flow.
        if let Err(error) = result {
            ensure!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ),
                "unexpected interrupted client failure: {error}"
            );
        }
        drop(held);
        rejected_before_target(socks)
            .await
            .context("request while server is unavailable")?;

        // Reuse the address initially assigned by the OS; the ordinary client
        // remains alive with the same configuration throughout this test.
        let path = fixture.directory.path().join("server.yaml");
        let config = std::fs::read_to_string(&path)?;
        std::fs::write(
            &path,
            config.replacen("listen: '127.0.0.1:0'", &format!("listen: '{address}'"), 1),
        )?;
        let (_restarted, restarted_address, metrics) = start_server(&fixture).await?;
        ensure!(
            restarted_address == address,
            "restarted server changed its address"
        );
        checked_stage(
            successful_flows(socks, http, metrics).await,
            metrics,
            "first new requests after server restart",
        )
        .await
    })
    .await
    .context("H3 server-restart test timed out")?
}
