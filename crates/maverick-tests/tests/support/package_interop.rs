use super::{support::socks_connect, Relay};
use anyhow::{ensure, Context, Result};
use maverick_core::ClientConfig;
use rustix::process::{kill_process, Pid, Signal};
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

const LOOPBACK: &str = "127.0.0.1:0";

async fn cli(binary: &Path, dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new(binary)
        .args(args)
        .current_dir(dir)
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        out.status.success(),
        "packaged CLI command {} failed ({})",
        args[0],
        out.status
    );
    Ok(out.stdout)
}

#[derive(Default)]
struct Observations {
    tcp: Vec<&'static str>,
    pool: Vec<u64>,
}

struct Running {
    child: Child,
    observations: JoinHandle<Result<Observations>>,
    address: SocketAddr,
}

impl Running {
    async fn start(directory: &Path, role: &str, marker: &str) -> Result<Self> {
        let mut child = Command::new(directory.join("maverick"))
            .current_dir(directory)
            .args([role, "-c", "config.yaml"])
            .env("RUST_LOG", "info,maverick_client::connection_manager=debug")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut lines = BufReader::new(child.stdout.take().context("missing CLI stdout")?).lines();
        let address = loop {
            let line = lines.next_line().await?.context("missing CLI readiness")?;
            if line.contains(marker) {
                let (_, port) = line
                    .split_once("127.0.0.1:")
                    .context("non-loopback readiness")?;
                let port = port
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<u16>()?;
                ensure!(port != 0);
                break SocketAddr::from(([127, 0, 0, 1], port));
            }
        };
        let observations = tokio::spawn(async move {
            let mut obs = Observations::default();
            while let Some(line) = lines.next_line().await? {
                for carrier in ["H2", "H3"] {
                    if line.contains(&format!(
                        "automatic selection chose {carrier} for new TCP connection"
                    )) {
                        obs.tcp.push(carrier);
                    }
                }
                if line.contains("Maverick H2 pool shutdown summary:") {
                    let (_, count) = line
                        .split_once("connections_created=")
                        .context("missing pool count")?;
                    obs.pool.push(
                        count
                            .chars()
                            .take_while(char::is_ascii_digit)
                            .collect::<String>()
                            .parse()?,
                    );
                }
            }
            Ok(obs)
        });
        Ok(Self {
            child,
            address,
            observations,
        })
    }

    async fn stop(mut self, signal: Signal) -> Result<Observations> {
        let pid = Pid::from_raw(self.child.id().context("CLI exited early")? as i32)
            .context("invalid PID")?;
        kill_process(pid, signal)?;
        ensure!(self.child.wait().await?.success(), "CLI shutdown failed");
        self.observations.await?
    }
}

async fn transfer(socks: SocketAddr) -> Result<()> {
    let tcp = TcpListener::bind(LOOPBACK).await?;
    let mut app = socks_connect(socks, tcp.local_addr()?).await?;
    let (mut target, _) = tcp.accept().await?;
    let upload = vec![0x31; 8193];
    let download = vec![0x92; 6145];
    app.write_all(&upload).await?;
    app.shutdown().await?;
    let mut bytes = Vec::new();
    target.read_to_end(&mut bytes).await?;
    ensure!(bytes == upload, "TCP upload or EOF");
    target.write_all(&download).await?;
    target.shutdown().await?;
    bytes.clear();
    app.read_to_end(&mut bytes).await?;
    ensure!(bytes == download, "TCP download or EOF");

    let mut control = TcpStream::connect(socks).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    control.read_exact(&mut method).await?;
    ensure!(method == [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await?;
    ensure!(
        reply[..8] == [5, 0, 0, 1, 127, 0, 0, 1],
        "UDP association did not return loopback"
    );
    let app = UdpSocket::bind(LOOPBACK).await?;
    app.connect(SocketAddr::from((
        [127, 0, 0, 1],
        u16::from_be_bytes([reply[8], reply[9]]),
    )))
    .await?;
    let target = UdpSocket::bind(LOOPBACK).await?;
    let mut header = vec![0, 0, 0, 1, 127, 0, 0, 1];
    header.extend_from_slice(&target.local_addr()?.port().to_be_bytes());
    let mut buf = [0; 256];
    let mut first_peer = None;
    for request in [b"upload-one".as_slice(), b"upload-two"] {
        app.send(&[&header, request].concat()).await?;
        let (size, peer) = target.recv_from(&mut buf).await?;
        ensure!(&buf[..size] == request && peer.ip().is_loopback());
        ensure!(
            *first_peer.get_or_insert(peer) == peer,
            "UDP source port changed"
        );
        for suffix in [b"-first".as_slice(), b"-second"] {
            let response = [request, suffix].concat();
            target.send_to(&response, peer).await?;
            let size = app.recv(&mut buf).await?;
            ensure!(
                buf[..size] == [header.as_slice(), &response].concat(),
                "independent UDP reply"
            );
        }
    }
    Ok(())
}

fn replace(input: &str, from: &str, to: &str) -> Result<String> {
    ensure!(
        input.matches(from).count() == 1,
        "unexpected generated config template"
    );
    Ok(input.replacen(from, to, 1))
}

struct Installation {
    directory: PathBuf,
    backup: PathBuf,
    updated: String,
}

impl Installation {
    fn new(root: &Path, role: &str, old: &Path, original: &str, setting: &str) -> Result<Self> {
        let directory = root.join(role);
        let backup = root.join(format!("{role}-backup"));
        fs::create_dir(&directory)?;
        fs::create_dir(&backup)?;
        fs::create_dir(directory.join("public"))?;
        fs::copy(old, directory.join("maverick"))?;
        let path = directory.join("config.yaml");
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?
            .write_all(original.as_bytes())?;
        for file in ["maverick", "config.yaml"] {
            fs::copy(directory.join(file), backup.join(file))?;
        }
        let (key, _) = setting.split_once(": ").context("bad fixture setting")?;
        let updated = replace(original, setting, &format!("{key}: 64"))?;
        Ok(Self {
            directory,
            backup,
            updated,
        })
    }

    fn install(&self, candidate: Option<&Path>) -> Result<()> {
        let program = self.directory.join("maverick");
        let config = self.directory.join("config.yaml");
        // macOS can cache the code signature of a previously executed inode.
        // Stage the executable beside the live path for both upgrade and rollback.
        let previous_inode = fs::metadata(&program)?.ino();
        let incoming = self.directory.join("maverick.incoming");
        let original = self.backup.join("maverick");
        fs::copy(candidate.unwrap_or(&original), &incoming)?;
        fs::rename(incoming, &program)?;
        ensure!(
            fs::metadata(&program)?.ino() != previous_inode,
            "installer reused the live executable inode"
        );
        if candidate.is_some() {
            fs::write(config, &self.updated)?;
        } else {
            fs::copy(self.backup.join("config.yaml"), config)?;
        }
        Ok(())
    }

    async fn verify(&self, role: &str, binary: &Path, upgraded: bool) -> Result<()> {
        let program = self.directory.join("maverick");
        let config = self.directory.join("config.yaml");
        ensure!(
            fs::read(&program)? == fs::read(binary)?,
            "installed program mismatch"
        );
        let expected = if upgraded {
            self.updated.clone()
        } else {
            fs::read_to_string(self.backup.join("config.yaml"))?
        };
        ensure!(
            fs::read_to_string(&config)? == expected,
            "installed config mismatch"
        );
        ensure!(
            fs::metadata(&config)?.permissions().mode() & 0o077 == 0,
            "non-private config"
        );
        ensure!(
            cli(
                &program,
                &self.directory,
                &["check-config", "--kind", role, "-c", "config.yaml"]
            )
            .await?
                == format!("{role} config OK\n").as_bytes()
        );
        Ok(())
    }
}

async fn route(old: &Path, new: &Path, name: &str, flags: &[&str]) -> Result<()> {
    let files = tempfile::tempdir()?;
    let root = files.path();
    let leaf = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = root.join("origin.pem");
    fs::write(&cert, leaf.cert.pem())?;
    let key = root.join("origin.key");
    use std::io::Write;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key)?
        .write_all(leaf.signing_key.serialize_pem().as_bytes())?;
    let cert = cert.to_str().context("cert path")?;
    let mut args = vec!["gen-config"];
    args.extend(flags);
    if name == "protected-h2" {
        args.extend([
            "--relay",
            "--origin-name",
            "localhost",
            "--origin-cert",
            cert,
            "--origin-ca",
            cert,
        ]);
    }
    cli(old, root, &args).await?;
    let origin = TcpListener::bind(LOOPBACK).await?.local_addr()?;
    let client = fs::read_to_string(root.join("client.generated.yaml"))?;
    let client = replace(&client, "127.0.0.1:1080", LOOPBACK)?;
    let client = replace(&client, "example.com:443", &origin.to_string())?;
    let client = replace(
        &client,
        "server_name: \"example.com\"",
        "server_name: \"localhost\"",
    )?;
    let mut client = replace(
        &client,
        "ca_cert: null",
        &format!("ca_cert: {}", serde_json::to_string(cert)?),
    )?;
    let relay = if name == "protected-h2" {
        let cfg = ClientConfig::from_yaml_str(&client)
            .map_err(|_| anyhow::anyhow!("protected origin configuration"))?;
        let relay = Relay::start(cfg).await?;
        client = replace(&client, &origin.to_string(), &relay.config.server.address)?;
        // Only outer trust changes for the intermediary. The inner origin pin stays in the YAML.
        let outer =
            serde_json::to_string(relay.config.server.ca_cert.as_deref().context("edge CA")?)?;
        client = client.replacen(
            &format!("ca_cert: {}", serde_json::to_string(cert)?),
            &format!("ca_cert: {outer}"),
            1,
        );
        Some(relay)
    } else {
        None
    };
    let server = fs::read_to_string(root.join("server.generated.yaml"))?;
    let server = replace(&server, "0.0.0.0:443", &origin.to_string())?;
    let server = replace(&server, "./certs/fullchain.pem", cert)?;
    let server = replace(
        &server,
        "./certs/privkey.pem",
        key.to_str().context("key path")?,
    )?;
    let server = replace(&server, "allow_loopback: false", "allow_loopback: true")?;
    let dns = UdpSocket::bind(LOOPBACK).await?;
    let mut server = replace(&server, "1.1.1.1:53", &dns.local_addr()?.to_string())?;
    if name == "auto-h2-only" {
        server = replace(&server, "dual_h2_h3: true", "dual_h2_h3: false")?;
    }
    let client = Installation::new(root, "client", old, &client, "max_concurrent_flows: 256")?;
    let server = Installation::new(
        root,
        "server",
        old,
        &server,
        "max_concurrent_flows_per_user: 128",
    )?;
    let marker = match name {
        "direct-h3" => "Maverick H3 server listening",
        "auto-dual" | "auto-native" => "Maverick H2/H3 server listening",
        _ => "Maverick server listening",
    };
    for (phase, c, s) in [
        ("baseline", false, false),
        ("new-client", true, false),
        ("new-server", false, true),
        ("upgraded", true, true),
        ("restored", false, false),
    ] {
        if phase != "baseline" {
            client.install(c.then_some(new))?;
            server.install(s.then_some(new))?;
        }
        client
            .verify("client", if c { new } else { old }, c)
            .await?;
        server
            .verify("server", if s { new } else { old }, s)
            .await?;
        let before = relay.as_ref().map(|r| r.capture.lock().unwrap().len());
        let running = Running::start(&server.directory, "server", marker).await?;
        ensure!(running.address == origin);
        let proxy = Running::start(
            &client.directory,
            "client",
            "Maverick SOCKS5 client listening",
        )
        .await?;
        transfer(proxy.address)
            .await
            .with_context(|| format!("{name} {phase} transfer"))?;
        let obs = proxy.stop(Signal::INT).await?;
        running.stop(Signal::TERM).await?;
        if name.starts_with("auto-") {
            let expected = if name == "auto-h2-only" { "H2" } else { "H3" };
            ensure!(obs.tcp == [expected], "unexpected automatic TCP carrier");
            if expected == "H3" {
                ensure!(obs.pool == [0], "unexpected pooled H2 connection");
            }
        }
        if let (Some(relay), Some(before)) = (&relay, before) {
            ensure!(
                relay.capture.lock().unwrap().len() > before,
                "relay saw no traffic"
            );
        }
        println!("{name} {phase}: TCP and UDP passed");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires both verified native release archives"]
async fn stable_patch_package_interop() -> Result<()> {
    let old =
        PathBuf::from(std::env::var_os("MAVERICK_BASELINE_CLI").context("missing 1.2.0 program")?)
            .canonicalize()?;
    let new = PathBuf::from(
        std::env::var_os("MAVERICK_CANDIDATE_CLI").context("missing candidate program")?,
    )
    .canonicalize()?;
    let dir = tempfile::tempdir()?;
    for (binary, version) in [(&old, "1.2.0"), (&new, env!("CARGO_PKG_VERSION"))] {
        let output = cli(binary, dir.path(), &["version"]).await?;
        ensure!(
            output.split(|&b| b == b'\n').next() == Some(format!("maverick {version}").as_bytes()),
            "packaged CLI version"
        );
    }
    for (name, flags) in [
        ("direct-h2", &["--h2"][..]),
        ("direct-h3", &["--quiche-h3"]),
        ("auto-dual", &[]),
        ("auto-native", &["--udp-policy", "native_required"]),
        ("auto-h2-only", &[]),
        ("protected-h2", &[]),
    ] {
        timeout(Duration::from_secs(90), route(&old, &new, name, flags))
            .await
            .with_context(|| format!("{name} timed out"))?
            .with_context(|| format!("package route {name}"))?;
    }
    println!("Stable patch package matrix: 30/30 passed");
    Ok(())
}
