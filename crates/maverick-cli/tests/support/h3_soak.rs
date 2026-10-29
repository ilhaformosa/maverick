use super::*;
use serde_json::{json, Value};
use tokio::time::{interval, sleep, sleep_until, Instant as Deadline, MissedTickBehavior};

async fn start_observed_pair(fixture: &Fixture) -> Result<(Cli, Cli, SocketAddr, SocketAddr)> {
    fixture.server_config_with_metrics(true)?;
    let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
    let address = server
        .ready(if fixture.h3 {
            SERVER_READY
        } else {
            H2_SERVER_READY
        })
        .await?;
    let metrics = server.ready(METRICS_READY).await?;
    fixture.client_config("client.yaml", address, true, Fault::None)?;
    let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
    let proxy = client.ready(SOCKS_READY).await?;
    client.ready(HTTP_READY).await?;
    Ok((server, client, proxy, metrics))
}

pub(super) async fn metrics(address: SocketAddr) -> Result<Value> {
    timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = String::new();
        stream.take(16 * 1024).read_to_string(&mut response).await?;
        ensure!(
            response.starts_with("HTTP/1.1 200 "),
            "metrics request failed"
        );
        let (_, body) = response
            .split_once("\r\n\r\n")
            .context("missing metrics body")?;
        Ok(serde_json::from_str(body)?)
    })
    .await
    .context("metrics request timed out")?
}

pub(super) async fn wait_for_drained(
    address: SocketAddr,
    require_closed_connections: bool,
) -> Result<()> {
    let mut last_observed = None;
    timeout(Duration::from_secs(3), async {
        loop {
            let state = metrics(address).await?;
            let connections = state["active_connections"]
                .as_u64()
                .context("missing connection gauge")?;
            let admission = state["active_pre_auth"]
                .as_u64()
                .context("missing admission gauge")?;
            last_observed = Some((state["active_flows"].clone(), connections, admission));
            // H2 deliberately holds a connection admission permit for each
            // pooled TLS connection, in addition to temporary request permits.
            let admission_released = if require_closed_connections {
                connections == 0 && admission == 0
            } else {
                admission == connections
            };
            if state["active_flows"] == 0 && admission_released {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .with_context(|| format!("completed flows retained server admission; last (flows, connections, admission): {last_observed:?}"))?
}

fn cpu_seconds(text: &str) -> Result<f64> {
    text.split(':').try_fold(0.0, |seconds, component| {
        Ok(seconds * 60.0 + component.parse::<f64>()?)
    })
}

fn process_usage(pid: u32) -> Result<Value> {
    // Read only numeric process data; never collect command lines or file names.
    let ps = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "rss=", "-o", "time="])
        .output()?;
    ensure!(ps.status.success(), "measured process is no longer running");
    let fields: Vec<_> = std::str::from_utf8(&ps.stdout)?
        .split_whitespace()
        .collect();
    ensure!(fields.len() == 2, "unexpected ps resource output");
    let rss_kib: u64 = fields[0].parse()?;
    let cpu = cpu_seconds(fields[1])?;
    let files = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-F", "f"])
        .output()?;
    ensure!(
        files.status.success(),
        "could not read process descriptor count"
    );
    let descriptors = std::str::from_utf8(&files.stdout)?
        .lines()
        .filter_map(|line| line.strip_prefix('f'))
        .filter(|value| value.parse::<u32>().is_ok())
        .count();
    Ok(json!({"rss_kib": rss_kib, "cpu_seconds": cpu, "descriptors": descriptors}))
}

async fn snapshot(
    h3: bool,
    phase: &str,
    started: Instant,
    server: &Cli,
    client: Option<&Cli>,
    address: SocketAddr,
    resources: bool,
) -> Result<()> {
    let state = metrics(address).await?;
    let mut row = json!({
        "carrier": if h3 { "h3" } else { "h2" }, "phase": phase,
        "elapsed_seconds": started.elapsed().as_secs_f64(),
        "active_connections": state["active_connections"], "active_flows": state["active_flows"],
        "active_pre_auth": state["active_pre_auth"], "tcp_flows": state["tcp_flows"],
    });
    if resources {
        let server_pid = server.child.id();
        let client_pid = client.map(|c| c.child.id());
        let (server_usage, client_usage, host) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                process_usage(server_pid)?,
                client_pid.map(process_usage).transpose()?,
                host_context::sample().context("read host benchmark context")?,
            ))
        })
        .await??;
        row["server"] = server_usage;
        row["client"] = client_usage.unwrap_or(Value::Null);
        row["host"] = host;
    }
    println!("soak {row}");
    Ok(())
}

async fn paced_transfer(
    stream: TcpStream,
    end: Deadline,
    send_byte: u8,
    receive_byte: u8,
    block_bytes: usize,
) -> Result<(u64, u64)> {
    let (mut reader, mut writer) = stream.into_split();
    let send = async {
        let bytes = vec![send_byte; block_bytes];
        let mut ticks = interval(Duration::from_millis(100));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sent = 0;
        while Deadline::now() < end {
            ticks.tick().await;
            if Deadline::now() >= end {
                break;
            }
            writer.write_all(&bytes).await?;
            sent += bytes.len() as u64;
        }
        writer.shutdown().await?;
        Ok::<_, anyhow::Error>(sent)
    };
    let receive = async {
        let mut bytes = [0; 64 * 1024];
        let mut received = 0;
        loop {
            let count = reader.read(&mut bytes).await?;
            if count == 0 {
                break;
            }
            ensure!(
                bytes[..count].iter().all(|byte| *byte == receive_byte),
                "long-flow payload corruption"
            );
            received += count as u64;
        }
        Ok::<_, anyhow::Error>(received)
    };
    Ok(tokio::try_join!(send, receive)?)
}

async fn cancelled_local_flow(proxy: SocketAddr) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let (mut local, status) = socks_connect(proxy, target.local_addr()?).await?;
    ensure!(status == 0, "cancellation setup rejected");
    let (mut peer, _) = target.accept().await?;
    local.write_all(b"cancel").await?;
    let mut bytes = [0; 6];
    peer.read_exact(&mut bytes).await?;
    drop(local);
    let mut rest = Vec::new();
    timeout(Duration::from_secs(3), peer.read_to_end(&mut rest))
        .await
        .context("local cancellation did not reach target")??;
    Ok(())
}

async fn exercise(
    h3: bool,
    seconds: u64,
    cycles: usize,
    concurrency: usize,
    block_bytes: usize,
    resources: bool,
) -> Result<()> {
    // Keep room for short flows while all sustained H3 connections are active.
    let fixture = Fixture::for_transport(h3, concurrency.max(16) * 2)?;
    let (server, client, proxy, address) = start_observed_pair(&fixture).await?;
    let target = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
    let started = Instant::now();
    snapshot(
        h3,
        "baseline",
        started,
        &server,
        Some(&client),
        address,
        resources,
    )
    .await?;
    for cycle in 0..cycles {
        let setup_started = Instant::now();
        let mut pairs = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            // Pair all peers before starting the common payload window or churn.
            let (local, status) = socks_connect(proxy, target.local_addr()?).await?;
            ensure!(status == 0, "long-flow setup rejected");
            let (origin, _) = target.accept().await?;
            pairs.push((local, origin));
        }
        let setup_seconds = setup_started.elapsed().as_secs_f64();
        let load_started = Instant::now();
        let end = Deadline::now() + Duration::from_secs(seconds);
        let mut long = tokio::task::JoinSet::new();
        for (local, origin) in pairs {
            long.spawn(async move {
                let (local, origin) = tokio::try_join!(
                    paced_transfer(local, end, 0x35, 0x6a, block_bytes),
                    paced_transfer(origin, end, 0x6a, 0x35, block_bytes)
                )?;
                ensure!(
                    local.0 == origin.1 && local.1 == origin.0,
                    "long-flow byte counts differ"
                );
                Ok::<_, anyhow::Error>(local.0 + local.1)
            });
        }
        let mut churn = interval(Duration::from_secs(1));
        churn.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut samples = interval(Duration::from_secs(30));
        samples.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut short_flows = 0;
        let mut long_bytes = 0;
        loop {
            tokio::select! {
                _ = sleep_until(end) => break,
                joined = long.join_next(), if !long.is_empty() => {
                    long_bytes += joined.context("missing long-flow result")???;
                    ensure!(Deadline::now() >= end, "long flow ended before its scheduled finish");
                }
                _ = churn.tick() => {
                    checked_stage(
                        flow_batch(proxy, &target, 4, 16 * 1024).await,
                        address,
                        &format!("{} short-flow churn, cycle {cycle}, completed {short_flows}, elapsed {:.3}s", if h3 { "h3" } else { "h2" }, load_started.elapsed().as_secs_f64()),
                    ).await?;
                    short_flows += 4;
                }
                _ = samples.tick() => {
                    snapshot(h3, &format!("load-{cycle}"), started, &server, Some(&client), address, resources).await?;
                }
            }
        }
        timeout(Duration::from_secs(15), async {
            while let Some(result) = long.join_next().await {
                long_bytes += result??;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("long-flow completion timed out")??;
        let transfer_seconds = load_started.elapsed().as_secs_f64();
        cancelled_local_flow(proxy).await?;
        interrupt_flows(proxy, 4).await?;
        flow_batch(proxy, &target, 8, 64 * 1024).await?;
        wait_for_drained(address, h3).await?;
        snapshot(
            h3,
            &format!("drained-{cycle}"),
            started,
            &server,
            Some(&client),
            address,
            resources,
        )
        .await?;
        println!(
            "soak {}",
            json!({"carrier":if h3 {"h3"} else {"h2"}, "cycle":cycle, "load_seconds":seconds, "setup_seconds":setup_seconds, "transfer_seconds":transfer_seconds, "concurrency":concurrency, "block_bytes":block_bytes, "long_bytes":long_bytes, "short_flows":short_flows, "recovery":"passed"})
        );
        if resources {
            sleep(Duration::from_secs(15)).await;
            snapshot(
                h3,
                &format!("idle-{cycle}"),
                started,
                &server,
                Some(&client),
                address,
                true,
            )
            .await?;
        }
    }
    let target_at_exit = TcpListener::bind("127.0.0.1:0").await?;
    let (mut held, status) = socks_connect(proxy, target_at_exit.local_addr()?).await?;
    ensure!(status == 0, "client-exit setup rejected");
    let (mut peer, _) = target_at_exit.accept().await?;
    held.write_all(b"active").await?;
    let mut bytes = [0; 6];
    peer.read_exact(&mut bytes).await?;
    snapshot(
        h3,
        "before-client-stop",
        started,
        &server,
        Some(&client),
        address,
        resources,
    )
    .await?;
    drop(client);
    // Keep the same 15-second deadline, but continue as soon as cleanup
    // reaches the target. H2 need not wait for the QUIC idle timeout.
    let mut rest = Vec::new();
    timeout(Duration::from_secs(15), peer.read_to_end(&mut rest))
        .await
        .context("client exit did not release target")??;
    drop(held);
    wait_for_drained(address, true).await?;
    snapshot(
        h3,
        "client-stopped",
        started,
        &server,
        None,
        address,
        resources,
    )
    .await?;
    let mut restarted = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
    let proxy = restarted.ready(SOCKS_READY).await?;
    restarted.ready(HTTP_READY).await?;
    flow_batch(proxy, &target, 8, 64 * 1024).await?;
    wait_for_drained(address, h3).await?;
    snapshot(
        h3,
        "restarted",
        started,
        &server,
        Some(&restarted),
        address,
        resources,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_carriers_outlive_idle_timeout_and_release_admission() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        for h3 in [false, true] {
            // Preserve the former eight-flow aggregate rate (10 MiB/s) while
            // checking 32 sessions. Release measurements retain 64 KiB blocks.
            exercise(h3, 12, 1, 32, 16 * 1024, false).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("active-flow lifecycle test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual release-mode long run; requires ps and lsof"]
async fn long_running_carrier_resources() -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "run long resource measurement with --release"
    );
    let seconds = std::env::var("MAVERICK_SOAK_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(300);
    ensure!(seconds > 0, "soak phase must be nonzero");
    let concurrency = std::env::var("MAVERICK_SOAK_CONCURRENCY")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(8);
    // Stay below the existing 256-flow/stream defaults, including short flows.
    ensure!(
        (1..=128).contains(&concurrency),
        "soak concurrency must be between 1 and 128"
    );
    timeout(Duration::from_secs(seconds * 4 + 240), async {
        exercise(false, (seconds / 3).max(1), 3, concurrency, 64 * 1024, true).await?;
        exercise(true, seconds, 3, concurrency, 64 * 1024, true).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("long resource measurement timed out")?
}

#[test]
fn reads_cpu_time_in_macos_and_linux_formats() -> Result<()> {
    assert_eq!(cpu_seconds("0:01.25")?, 1.25);
    assert_eq!(cpu_seconds("00:02:03")?, 123.0);
    Ok(())
}
