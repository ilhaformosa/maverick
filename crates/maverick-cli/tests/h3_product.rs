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
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const SERVER_READY: &str = "Maverick H3 server listening";
const SOCKS_READY: &str = "Maverick SOCKS5 client listening";
const HTTP_READY: &str = "Maverick HTTP CONNECT client listening";

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
                for marker in [SERVER_READY, SOCKS_READY, HTTP_READY] {
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
            pin: format!(
                "sha256/{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(cert.der()))
            ),
        })
    }

    fn server_config(&self, v2: bool) -> Result<()> {
        let input = format!(
            "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: cert.pem\n  key_path: key.pem\nmaverick:\n  tunnel_path: /local-h3\nusers:\n  - id: local-test-user\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: public\nauth:\n  channel_binding:\n    enabled: true\n    require: true\n  v2:\n    enabled: {v2}\n    require: {v2}\n    accepted_epochs: [202607]\nadvanced:\n  quiche_h3: true\n  max_concurrent_connections: 2\n  max_concurrent_connections_per_source: 2\n  pre_auth_max_concurrent: 2\n  handshake_timeout_ms: 5000\n  idle_timeout_secs: 10\n  egress:\n    allow_loopback: true\n",
            self.secret.expose_secret()
        );
        private_file(self.directory.path(), "server.yaml", input)
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
            "version: 1\nlocal:\n  socks5:\n    listen: '127.0.0.1:0'\n  http_connect:\n    enabled: true\n    listen: '127.0.0.1:0'\nserver:\n  address: '{server}'\n  server_name: {hostname}\n  tunnel_path: /local-h3\n  credential_id: local-test-user\n  secret: '{}'\n  ca_cert: {ca}\n  cert_pin: '{pin}'\nauth:\n  channel_binding:\n    enabled: true\n    require: true\n  v2:\n    enabled: {v2}\n  rotation:\n    active_epoch: '202607'\nadvanced:\n  quiche_h3: true\n  connect_timeout_ms: 5000\n  idle_timeout_secs: 10\n  stealth:\n    tls_fingerprint: browser_mimic\n",
            secret.expose_secret()
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
    ensure!(
        response.starts_with(b"HTTP/1.1 200 "),
        "HTTP CONNECT rejected"
    );
    Ok(stream)
}

async fn exchange(proxy: SocketAddr, target: SocketAddr, http: bool, payload: &[u8]) -> Result<()> {
    let mut stream = if http {
        http_connect(proxy, target).await?
    } else {
        let (stream, status) = socks_connect(proxy, target).await?;
        ensure!(status == 0, "SOCKS CONNECT rejected");
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

async fn successful_flows(socks: SocketAddr, http: SocketAddr) -> Result<()> {
    // Sequential flows verify that finishing one QUIC connection leaves the
    // ordinary server ready for the next one.
    for (proxy, is_http) in [(socks, false), (http, true)] {
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        tokio::try_join!(
            async { echo(target.accept().await?.0).await },
            exchange(proxy, address, is_http, b"sequential configured H3 flow")
        )?;
    }
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
        exchange(socks, address, false, b"concurrent SOCKS flow"),
        exchange(http, address, true, b"concurrent HTTP CONNECT flow")
    )?;
    Ok(())
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
            fixture.server_config(v2)?;
            let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
            let server_address = server.ready(SERVER_READY).await?;
            let noise = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            noise.send_to(&[0], server_address).await?;
            drop(noise);
            fixture.client_config("client.yaml", server_address, v2, Fault::None)?;
            {
                let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
                let socks = client.ready(SOCKS_READY).await?;
                let http = client.ready(HTTP_READY).await?;
                successful_flows(socks, http).await.with_context(|| {
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
                rejected_before_target(socks).await.with_context(|| {
                    format!("auth v{} rejection: {fault:?}", if v2 { 2 } else { 1 })
                })?;
            }
            // Rejections must release the two available connection/handshake
            // slots, so a valid pair of concurrent flows still works.
            let mut recovered = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
            let socks = recovered.ready(SOCKS_READY).await?;
            let http = recovered.ready(HTTP_READY).await?;
            successful_flows(socks, http)
                .await
                .context("valid flows after rejected peers")?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("configured H3 CLI process test timed out")?
}
