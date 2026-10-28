#![cfg(feature = "experimental-h3")]

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use maverick_core::SecretString;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const SERVER_READY: &str = "Maverick H3 server listening";
const H2_SERVER_READY: &str = "Maverick server listening";
const SOCKS_READY: &str = "Maverick SOCKS5 client listening";
const HTTP_READY: &str = "Maverick HTTP CONNECT client listening";
const METRICS_READY: &str = "Maverick local metrics listening";

#[path = "support/h3_soak.rs"]
mod soak;

struct Cli {
    child: Child,
    readiness: mpsc::Receiver<(&'static str, SocketAddr)>,
    reader: Option<JoinHandle<()>>,
}

impl Cli {
    fn start(directory: &Path, command: &str, config: &str) -> Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_maverick"))
            .args([command, "-c", config])
            .current_dir(directory)
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("start ordinary Maverick CLI")?;
        let stdout = child.stdout.take().expect("piped CLI stdout");
        let (send, readiness) = mpsc::channel(3);
        let mut process = Self {
            child,
            readiness,
            reader: None,
        };
        process.reader = Some(std::thread::spawn(move || {
            // Consume logs without retaining or printing credentials, paths, or
            // diagnostics. Only readiness addresses leave this thread.
            for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
                for marker in [
                    SERVER_READY,
                    H2_SERVER_READY,
                    SOCKS_READY,
                    HTTP_READY,
                    METRICS_READY,
                ] {
                    if !line.contains(marker) {
                        continue;
                    }
                    if let Some(start) = line.find("127.0.0.1:") {
                        let address: String = line[start..]
                            .chars()
                            .take_while(|c| c.is_ascii_digit() || matches!(c, '.' | ':'))
                            .collect();
                        if let Ok(address) = address.parse() {
                            if send.blocking_send((marker, address)).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }));
        Ok(process)
    }

    async fn ready(&mut self, marker: &str) -> Result<SocketAddr> {
        let (actual, address) = timeout(Duration::from_secs(8), self.readiness.recv())
            .await
            .context("CLI startup timed out")?
            .context("CLI exited before announcing readiness")?;
        ensure!(actual == marker, "unexpected CLI readiness message");
        ensure!(address.port() != 0, "CLI did not report its assigned port");
        Ok(address)
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn private_file(directory: &Path, name: &str, contents: impl AsRef<[u8]>) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(directory.join(name))?
        .write_all(contents.as_ref())?;
    Ok(())
}

struct Fixture {
    directory: TempDir,
    secret: SecretString,
    pin: String,
    h3: bool,
    connections: usize,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Secret,
    Ca,
    Hostname,
    Pin,
}

impl Fixture {
    fn new() -> Result<Self> {
        Self::for_transport(true, 2)
    }

    fn for_transport(h3: bool, connections: usize) -> Result<Self> {
        let directory = TempDir::new()?;
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.distinguished_name
            .push(DnType::CommonName, "Maverick local test CA");
        let ca_key = KeyPair::generate()?;
        let ca = ca.self_signed(&ca_key)?;
        let key = KeyPair::generate()?;
        let cert =
            CertificateParams::new(vec!["localhost".into()])?.signed_by(&key, &ca, &ca_key)?;
        let wrong_ca = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        private_file(directory.path(), "ca.pem", ca.pem())?;
        private_file(directory.path(), "wrong-ca.pem", wrong_ca.cert.pem())?;
        private_file(directory.path(), "cert.pem", cert.pem())?;
        private_file(directory.path(), "key.pem", key.serialize_pem())?;
        Ok(Self {
            directory,
            secret: SecretString::generate(),
            h3,
            connections,
            pin: format!(
                "sha256/{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(cert.der()))
            ),
        })
    }

    fn server_config(&self, v2: bool) -> Result<()> {
        let input = format!(
            "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: cert.pem\n  key_path: key.pem\nmaverick:\n  tunnel_path: /local-h3\nusers:\n  - id: local-test-user\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: public\nauth:\n  channel_binding:\n    enabled: true\n    require: true\n  v2:\n    enabled: {v2}\n    require: {v2}\n    accepted_epochs: [202607]\nadvanced:\n  quiche_h3: {h3}\n  max_concurrent_connections: {connections}\n  max_concurrent_connections_per_source: {connections}\n  pre_auth_max_concurrent: {connections}\n  handshake_timeout_ms: 5000\n  idle_timeout_secs: 10\n  egress:\n    allow_loopback: true\n",
            self.secret.expose_secret(),
            h3 = self.h3,
            connections = self.connections,
        );
        private_file(self.directory.path(), "server.yaml", input)
    }

    fn server_config_with_metrics(&self, v2: bool) -> Result<()> {
        self.server_config(v2)?;
        OpenOptions::new()
            .append(true)
            .open(self.directory.path().join("server.yaml"))?
            .write_all(b"metrics:\n  enabled: true\n  listen: '127.0.0.1:0'\n")?;
        Ok(())
    }

    fn client_config(&self, name: &str, server: SocketAddr, v2: bool, fault: Fault) -> Result<()> {
        let secret = if matches!(fault, Fault::Secret) {
            SecretString::generate()
        } else {
            self.secret.clone()
        };
        let ca = if matches!(fault, Fault::Ca) {
            "wrong-ca.pem"
        } else {
            "ca.pem"
        };
        let hostname = if matches!(fault, Fault::Hostname) {
            "wrong.localhost"
        } else {
            "localhost"
        };
        let pin = if matches!(fault, Fault::Pin) {
            format!("sha256/{}", URL_SAFE_NO_PAD.encode([0u8; 32]))
        } else {
            self.pin.clone()
        };
        let input = format!(
            "version: 1\nlocal:\n  socks5:\n    listen: '127.0.0.1:0'\n  http_connect:\n    enabled: true\n    listen: '127.0.0.1:0'\nserver:\n  address: '{server}'\n  server_name: {hostname}\n  tunnel_path: /local-h3\n  credential_id: local-test-user\n  secret: '{}'\n  ca_cert: {ca}\n  cert_pin: '{pin}'\nauth:\n  channel_binding:\n    enabled: true\n    require: true\n  v2:\n    enabled: {v2}\n  rotation:\n    active_epoch: '202607'\nadvanced:\n  quiche_h3: {h3}\n  connect_timeout_ms: 5000\n  idle_timeout_secs: 10\n  stealth:\n    tls_fingerprint: browser_mimic\n",
            secret.expose_secret(),
            h3 = self.h3,
        );
        private_file(self.directory.path(), name, input)
    }
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> Result<(TcpStream, u8)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting failed");
    let IpAddr::V4(ip) = target.ip() else {
        bail!("expected a loopback IPv4 target")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    ensure!(reply[0] == 5 && reply[3] == 1, "invalid SOCKS reply");
    Ok((stream, reply[1]))
}

async fn http_connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        ensure!(response.len() < 1024, "oversized HTTP CONNECT response");
        response.push(stream.read_u8().await?);
    }
    let status = std::str::from_utf8(&response)
        .ok()
        .and_then(|response| response.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok());
    ensure!(
        response.starts_with(b"HTTP/1.1 200 "),
        "HTTP CONNECT rejected: status {status:?}"
    );
    Ok(stream)
}

async fn exchange(proxy: SocketAddr, target: SocketAddr, http: bool, payload: &[u8]) -> Result<()> {
    let mut stream = if http {
        http_connect(proxy, target).await?
    } else {
        let (stream, status) = socks_connect(proxy, target).await?;
        ensure!(status == 0, "SOCKS CONNECT rejected: status {status}");
        stream
    };
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut received = Vec::new();
    stream.take(1024).read_to_end(&mut received).await?;
    ensure!(
        received == payload,
        "configured H3 flow changed payload bytes"
    );
    Ok(())
}

async fn echo(mut stream: TcpStream) -> Result<()> {
    let mut data = Vec::new();
    (&mut stream).take(1024).read_to_end(&mut data).await?;
    stream.write_all(&data).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn checked_stage(result: Result<()>, metrics: SocketAddr, stage: &str) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    let Ok(state) = soak::metrics(metrics).await else {
        return Err(error.context(format!("{stage}; server counters unavailable")));
    };
    // Only fixed numeric fields leave the fixture, never raw logs or credentials.
    let counters = [
        "active_connections",
        "active_flows",
        "active_pre_auth",
        "connection_limit_rejections",
        "source_connection_limit_rejections",
        "pre_auth_admission_rejections",
        "unauthenticated_rejections",
        "auth_rate_limit_rejections",
        "flow_limit_rejections",
        "target_connect_failures",
        "target_connect_timeouts",
    ]
    .map(|key| (key, state[key].as_u64()));
    Err(error.context(format!("{stage}; server counters: {counters:?}")))
}

async fn successful_flows(socks: SocketAddr, http: SocketAddr, metrics: SocketAddr) -> Result<()> {
    // TCP EOF does not promise that server session guards have been released.
    // Check cleanup before requiring both of this fixture's two slots again.
    for (proxy, is_http) in [(socks, false), (http, true)] {
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let result = async {
            tokio::try_join!(
                async { echo(target.accept().await?.0).await },
                exchange(proxy, address, is_http, b"sequential configured H3 flow")
            )?;
            soak::wait_for_drained(metrics, true)
                .await
                .context("server admission cleanup")
        }
        .await;
        checked_stage(
            result,
            metrics,
            if is_http {
                "sequential HTTP CONNECT"
            } else {
                "sequential SOCKS CONNECT"
            },
        )
        .await?;
    }
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let origin = async {
        let first = target.accept().await?.0;
        let second = target.accept().await?.0;
        tokio::try_join!(echo(first), echo(second))?;
        Ok::<_, anyhow::Error>(())
    };
    let result = async {
        tokio::try_join!(
            origin,
            exchange(socks, address, false, b"concurrent SOCKS flow"),
            exchange(http, address, true, b"concurrent HTTP CONNECT flow")
        )?;
        soak::wait_for_drained(metrics, true)
            .await
            .context("server admission cleanup")
    }
    .await;
    checked_stage(result, metrics, "concurrent SOCKS/HTTP CONNECT pair").await
}

async fn rejected_before_target(socks: SocketAddr) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let rejected = async {
        let attempt = timeout(
            Duration::from_secs(6),
            socks_connect(socks, target.local_addr()?),
        )
        .await
        .context("invalid connection did not finish")?;
        if let Ok((_, status)) = attempt {
            ensure!(status != 0, "invalid credentials or TLS identity accepted");
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = rejected => result?,
        accepted = target.accept() => {
            let _ = accepted?;
            bail!("rejected H3 connection reached the target");
        }
    }
    ensure!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err(),
        "rejected H3 connection opened a delayed target connection"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_cli_processes_forward_tcp_and_reject_invalid_authentication_and_tls(
) -> Result<()> {
    timeout(Duration::from_secs(90), async {
        for v2 in [false, true] {
            let fixture = Fixture::new()?;
            fixture.server_config_with_metrics(v2)?;
            let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
            let server_address = server.ready(SERVER_READY).await?;
            let metrics = server.ready(METRICS_READY).await?;
            let noise = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            noise.send_to(&[0], server_address).await?;
            drop(noise);
            fixture.client_config("client.yaml", server_address, v2, Fault::None)?;
            {
                let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
                let socks = client.ready(SOCKS_READY).await?;
                let http = client.ready(HTTP_READY).await?;
                successful_flows(socks, http, metrics)
                    .await
                    .with_context(|| {
                        format!("auth v{} configured TCP forwarding", if v2 { 2 } else { 1 })
                    })?;
            }
            for (index, fault) in [Fault::Secret, Fault::Ca, Fault::Hostname, Fault::Pin]
                .into_iter()
                .enumerate()
            {
                let name = format!("rejected-{index}.yaml");
                fixture.client_config(&name, server_address, v2, fault)?;
                let mut client = Cli::start(fixture.directory.path(), "client", &name)?;
                let socks = client.ready(SOCKS_READY).await?;
                client.ready(HTTP_READY).await?;
                let result = async {
                    rejected_before_target(socks).await?;
                    // Keep this client alive while the rejected session releases
                    // admission; killing it is a separate lifecycle test.
                    soak::wait_for_drained(metrics, true)
                        .await
                        .context("server admission cleanup after rejection")
                }
                .await;
                checked_stage(
                    result,
                    metrics,
                    &format!("auth v{} rejection: {fault:?}", if v2 { 2 } else { 1 }),
                )
                .await?;
            }
            // Rejections must release the two available connection/handshake
            // slots, so a valid pair of concurrent flows still works.
            let mut recovered = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
            let socks = recovered.ready(SOCKS_READY).await?;
            let http = recovered.ready(HTTP_READY).await?;
            successful_flows(socks, http, metrics)
                .await
                .with_context(|| {
                    format!(
                        "auth v{} valid flows after rejected peers",
                        if v2 { 2 } else { 1 }
                    )
                })?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("configured H3 CLI process test timed out")?
}

// Both carriers use the same CLI binary, equivalent TLS/auth v2 settings and
// payload checks. H2 retains its normal pool and H3 its one-connection-per-flow
// behavior: this compares the currently shipped paths, not protocol limits.
async fn start_pair(fixture: &Fixture) -> Result<(Cli, Cli, SocketAddr)> {
    fixture.server_config(true)?;
    let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
    let address = server
        .ready(if fixture.h3 {
            SERVER_READY
        } else {
            H2_SERVER_READY
        })
        .await?;
    fixture.client_config("client.yaml", address, true, Fault::None)?;
    let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
    let socks = client.ready(SOCKS_READY).await?;
    client.ready(HTTP_READY).await?;
    Ok((server, client, socks))
}

async fn send_payload(mut send: tokio::net::tcp::OwnedWriteHalf, bytes: usize) -> Result<()> {
    let block = [0x5a; 16 * 1024];
    let mut remaining = bytes;
    while remaining > 0 {
        let len = remaining.min(block.len());
        send.write_all(&block[..len]).await?;
        remaining -= len;
    }
    send.shutdown().await?;
    Ok(())
}

async fn receive_payload(mut recv: tokio::net::tcp::OwnedReadHalf, bytes: usize) -> Result<()> {
    let mut block = [0; 16 * 1024];
    let mut received = 0;
    loop {
        let len = recv.read(&mut block).await?;
        if len == 0 {
            break;
        }
        ensure!(
            block[..len].iter().all(|b| *b == 0x5a),
            "payload corruption"
        );
        received += len;
        ensure!(received <= bytes, "unexpected extra payload");
    }
    ensure!(received == bytes, "payload truncated: {received}/{bytes}");
    Ok(())
}

async fn transfer(stream: TcpStream, send: usize, receive: usize) -> Result<()> {
    let (recv, writer) = stream.into_split();
    tokio::try_join!(send_payload(writer, send), receive_payload(recv, receive))?;
    Ok(())
}

async fn measured_flow(
    proxy: SocketAddr,
    target: &TcpListener,
    upload: usize,
    download: usize,
) -> Result<(f64, f64)> {
    timeout(Duration::from_secs(30), async {
        let address = target.local_addr()?;
        let started = Instant::now();
        let origin = async {
            let mut stream = target.accept().await?.0;
            ensure!(stream.read_u8().await? == 1, "missing transfer start");
            transfer(stream, download, upload)
                .await
                .context("target transfer")
        };
        let request = async {
            let (mut stream, status) = socks_connect(proxy, address).await?;
            ensure!(status == 0, "measured SOCKS connection rejected");
            let connect_ms = started.elapsed().as_secs_f64() * 1000.0;
            let data_started = Instant::now();
            // Do not let the target pre-buffer downloads during SOCKS setup.
            stream.write_all(&[1]).await?;
            transfer(stream, upload, download)
                .await
                .context("proxy transfer")?;
            Ok::<_, anyhow::Error>((connect_ms, data_started.elapsed().as_secs_f64()))
        };
        let (_, sample) = tokio::try_join!(origin, request)?;
        Ok(sample)
    })
    .await
    .context("measured flow timed out")?
}

async fn flow_batch(
    proxy: SocketAddr,
    target: &Arc<TcpListener>,
    count: usize,
    bytes: usize,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..count {
        let target = Arc::clone(target);
        tasks.spawn(async move { measured_flow(proxy, &target, bytes, bytes).await });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

async fn interrupt_flows(proxy: SocketAddr, count: usize) -> Result<()> {
    for _ in 0..count {
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let (mut stream, status) = socks_connect(proxy, target.local_addr()?).await?;
        ensure!(status == 0, "interruption setup rejected");
        let (mut peer, _) = target.accept().await?;
        stream.write_all(b"partial upload").await?;
        let mut bytes = [0; 14];
        peer.read_exact(&mut bytes).await?;
        // Target disappears while the local client still holds the flow.
        drop(peer);
        let mut rest = Vec::new();
        let _ = timeout(Duration::from_secs(3), stream.read_to_end(&mut rest))
            .await
            .context("interrupted flow did not finish")?;
    }
    Ok(())
}

async fn upload_after_target_fin(proxy: SocketAddr) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let (mut stream, status) = socks_connect(proxy, target.local_addr()?).await?;
    ensure!(status == 0, "half-close setup rejected");
    let (mut peer, _) = target.accept().await?;
    peer.shutdown().await?;
    let mut byte = [0];
    ensure!(
        stream.read(&mut byte).await? == 0,
        "target FIN not forwarded"
    );
    // Wait for the target FIN before starting the upload: this deterministically
    // reproduces the former H2 truncation instead of relying on scheduling.
    tokio::try_join!(
        transfer(stream, 512 * 1024, 0),
        transfer(peer, 0, 512 * 1024)
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_carriers_survive_repeated_concurrent_and_interrupted_flows() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        for h3 in [false, true] {
            let fixture = Fixture::for_transport(h3, 16)?;
            let (_server, _client, proxy) = start_pair(&fixture).await?;
            let target = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
            upload_after_target_fin(proxy).await?;
            // Target FIN before upload completion must not truncate the upload.
            for (upload, download) in [
                (4 * 1024 * 1024, 0),
                (0, 4 * 1024 * 1024),
                (4 * 1024 * 1024, 4 * 1024 * 1024),
            ] {
                measured_flow(proxy, &target, upload, download).await?;
            }
            for _ in 0..8 {
                flow_batch(proxy, &target, 8, 64 * 1024).await?;
            }
            interrupt_flows(proxy, 8).await?;
            flow_batch(proxy, &target, 8, 256 * 1024).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("carrier stability test timed out")?
}

fn percentile(samples: &[f64], percent: usize) -> f64 {
    let mut ordered = samples.to_vec();
    ordered.sort_by(f64::total_cmp);
    ordered[(ordered.len() * percent).div_ceil(100).saturating_sub(1)]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual release-mode loopback comparison; timings are not CI thresholds"]
async fn compare_h2_h3_loopback() -> Result<()> {
    ensure!(!cfg!(debug_assertions), "run comparison with --release");
    timeout(Duration::from_secs(300), async {
        for h3 in [false, true] {
            let carrier = if h3 { "h3" } else { "h2" };
            println!("comparison starting carrier={carrier}");
            let fixture = Fixture::for_transport(h3, 32)?;
            let (_server, _client, proxy) = start_pair(&fixture).await?;
            let target = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
            let (cold, _) = measured_flow(proxy, &target, 1024, 1024).await?;
            let mut connects = Vec::new();
            for _ in 0..100 {
                connects.push(measured_flow(proxy, &target, 1024, 1024).await?.0);
            }
            println!("comparison carrier={carrier} cold_connect_ms={cold:.3} connect_p50_ms={:.3} connect_p95_ms={:.3}", percentile(&connects, 50), percentile(&connects, 95));
            for (direction, upload, download) in [
                ("upload", 8 * 1024 * 1024, 0),
                ("download", 0, 8 * 1024 * 1024),
                ("duplex", 8 * 1024 * 1024, 8 * 1024 * 1024),
            ] {
                let mut speeds = Vec::new();
                for _ in 0..3 {
                    let (_, seconds) = measured_flow(proxy, &target, upload, download).await?;
                    speeds.push((upload + download) as f64 / (1024.0 * 1024.0) / seconds);
                }
                println!("comparison carrier={carrier} direction={direction} median_mib_s={:.3}", percentile(&speeds, 50));
            }
            let started = Instant::now();
            let mut completed = 0;
            while started.elapsed() < Duration::from_secs(30) {
                flow_batch(proxy, &target, 8, 64 * 1024).await.with_context(|| format!("{carrier} sustained after {completed} successful flows"))?;
                completed += 8;
                // Bound offered load below the existing replay-cache budget.
                // Reuse one target listener instead of exhausting ephemeral ports.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            interrupt_flows(proxy, 8).await?;
            flow_batch(proxy, &target, 8, 256 * 1024).await?;
            println!("comparison carrier={carrier} sustained_seconds={:.3} concurrency=8 batch_pause_ms=100 completed={completed} interrupted=8 recovery=passed", started.elapsed().as_secs_f64());
        }
        Ok::<_, anyhow::Error>(())
    }).await.context("local comparison timed out")?
}
