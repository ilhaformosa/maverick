use anyhow::{anyhow, bail, ensure, Result};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BETA2_DEFAULT_BIN: &str = "MAVERICK_BETA2_DEFAULT_BIN";
const BETA1_DEFAULT_BIN: &str = "MAVERICK_BETA1_DEFAULT_BIN";
const BETA2_RUSTLS_BIN: &str = "MAVERICK_BETA2_RUSTLS_BIN";
const BETA1_RUSTLS_BIN: &str = "MAVERICK_BETA1_RUSTLS_BIN";
const FIXTURE_SECRET: &str = "mv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const RELAY_PAYLOAD: &[u8] = b"maverick-n-minus-one-direct-h2";

#[derive(Clone, Copy)]
enum Backend {
    Default,
    Rustls,
}

impl Backend {
    const ALL: [Self; 2] = [Self::Default, Self::Rustls];

    fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Rustls => "rustls",
        }
    }
}

#[derive(Clone, Copy)]
enum Version {
    Beta2,
    Beta1,
}

impl Version {
    const ALL: [Self; 2] = [Self::Beta2, Self::Beta1];

    fn label(self) -> &'static str {
        match self {
            Self::Beta2 => "beta2",
            Self::Beta1 => "beta1",
        }
    }
}

#[derive(Clone, Copy)]
enum Auth {
    V1,
    V2,
}

impl Auth {
    const ALL: [Self; 2] = [Self::V1, Self::V2];

    fn label(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

struct HistoricalBinaries {
    beta2_default: PathBuf,
    beta1_default: PathBuf,
    beta2_rustls: PathBuf,
    beta1_rustls: PathBuf,
}

impl HistoricalBinaries {
    fn from_env() -> Result<Self> {
        Ok(Self {
            beta2_default: binary_from_env(BETA2_DEFAULT_BIN)?,
            beta1_default: binary_from_env(BETA1_DEFAULT_BIN)?,
            beta2_rustls: binary_from_env(BETA2_RUSTLS_BIN)?,
            beta1_rustls: binary_from_env(BETA1_RUSTLS_BIN)?,
        })
    }

    fn get(&self, version: Version, backend: Backend) -> &Path {
        match (version, backend) {
            (Version::Beta2, Backend::Default) => &self.beta2_default,
            (Version::Beta1, Backend::Default) => &self.beta1_default,
            (Version::Beta2, Backend::Rustls) => &self.beta2_rustls,
            (Version::Beta1, Backend::Rustls) => &self.beta1_rustls,
        }
    }
}

fn binary_from_env(name: &str) -> Result<PathBuf> {
    let value = env::var_os(name).ok_or_else(|| anyhow!("historical binary input is missing"))?;
    let path = PathBuf::from(value);
    ensure!(
        fs::metadata(&path)
            .map(|item| item.is_file())
            .unwrap_or(false),
        "historical binary input is invalid"
    );
    Ok(path)
}

struct Fixture {
    _temp: TempDir,
}

impl Fixture {
    fn new(auth: Auth, server_port: u16, socks_port: u16) -> Result<Self> {
        let temp = TempDir::new().map_err(|_| anyhow!("create private fixture directory"))?;
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|_| anyhow!("generate anonymous test certificate"))?;

        write_private(
            &temp.path().join("cert.pem"),
            certified.cert.pem().as_bytes(),
        )?;
        write_private(
            &temp.path().join("key.pem"),
            certified.key_pair.serialize_pem().as_bytes(),
        )?;
        fs::create_dir(temp.path().join("public"))
            .map_err(|_| anyhow!("create neutral fallback directory"))?;
        write_private(&temp.path().join("public/index.html"), b"ok\n")?;

        let client_auth = match auth {
            Auth::V1 => String::new(),
            Auth::V2 => r#"auth:
  v2:
    enabled: true
  rotation:
    active_epoch: "1"
"#
            .to_owned(),
        };
        let server_auth = match auth {
            Auth::V1 => String::new(),
            Auth::V2 => r#"auth:
  v2:
    enabled: true
    require: true
    accepted_epochs:
      - 1
"#
            .to_owned(),
        };

        let client = format!(
            r#"version: 1
mode: auto
local:
  socks5:
    listen: "127.0.0.1:{socks_port}"
  dns: null
  http_connect: null
server:
  address: "127.0.0.1:{server_port}"
  server_name: "localhost"
  tunnel_path: "/compat"
  credential_id: "u_compat"
  secret: "{FIXTURE_SECRET}"
  ca_cert: "cert.pem"
  cert_pin: null
{client_auth}log:
  level: "error"
  redact: true
"#
        );
        let server = format!(
            r#"version: 1
listen: "127.0.0.1:{server_port}"
tls:
  cert_path: "cert.pem"
  key_path: "key.pem"
maverick:
  tunnel_path: "/compat"
users:
  - id: "u_compat"
    secret: "{FIXTURE_SECRET}"
fallback:
  type: "static"
  static_dir: "public"
  index: "index.html"
{server_auth}log:
  level: "error"
  redact: true
advanced:
  egress:
    allow_loopback: true
"#
        );

        write_private(&temp.path().join("client.yaml"), client.as_bytes())?;
        write_private(&temp.path().join("server.yaml"), server.as_bytes())?;
        Ok(Self { _temp: temp })
    }

    fn path(&self) -> &Path {
        self._temp.path()
    }
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).map_err(|_| anyhow!("write private fixture file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| anyhow!("set private fixture permissions"))?;
    }
    Ok(())
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(binary: &Path, role: &str, directory: &Path) -> Result<Self> {
        let child = Command::new(binary)
            .arg(role)
            .arg("-c")
            .arg(format!("{role}.yaml"))
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| anyhow!("start historical process"))?;
        Ok(Self { child })
    }

    fn ensure_running(&mut self) -> Result<()> {
        ensure!(
            self.child
                .try_wait()
                .map_err(|_| anyhow!("inspect historical process"))?
                .is_none(),
            "historical process exited early"
        );
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct EchoOrigin {
    address: SocketAddr,
    listener: Option<TcpListener>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}

impl EchoOrigin {
    fn bind() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| anyhow!("bind loopback echo origin"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| anyhow!("configure loopback echo origin"))?;
        let address = listener
            .local_addr()
            .map_err(|_| anyhow!("inspect loopback echo origin"))?;
        Ok(Self {
            address,
            listener: Some(listener),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        })
    }

    fn start(&mut self) -> Result<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| anyhow!("loopback echo origin already started"))?;
        let worker_stop = Arc::clone(&self.stop);
        let worker = thread::Builder::new()
            .spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !worker_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if worker_stop.load(Ordering::Relaxed) {
                                bail!("loopback echo origin stopped");
                            }
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .map_err(|_| anyhow!("configure loopback origin read"))?;
                            stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .map_err(|_| anyhow!("configure loopback origin write"))?;
                            let mut buffer = vec![0_u8; RELAY_PAYLOAD.len()];
                            stream
                                .read_exact(&mut buffer)
                                .map_err(|_| anyhow!("read loopback origin payload"))?;
                            ensure!(buffer == RELAY_PAYLOAD, "loopback origin payload mismatch");
                            stream
                                .write_all(&buffer)
                                .map_err(|_| anyhow!("write loopback origin payload"))?;
                            return Ok(());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => bail!("accept loopback origin connection"),
                    }
                }
                bail!("loopback echo origin timed out")
            })
            .map_err(|_| anyhow!("start loopback echo origin worker"))?;
        self.worker = Some(worker);
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.worker
            .take()
            .ok_or_else(|| anyhow!("loopback echo origin was not started"))?
            .join()
            .map_err(|_| anyhow!("loopback echo origin worker failed"))?
    }
}

impl Drop for EchoOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn reserve_ephemeral_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| anyhow!("reserve loopback port"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| anyhow!("inspect loopback port"))
}

fn check_config(binary: &Path, fixture: &Fixture, kind: &str) -> Result<()> {
    let status = Command::new(binary)
        .arg("check-config")
        .arg("--kind")
        .arg(kind)
        .arg("-c")
        .arg(format!("{kind}.yaml"))
        .current_dir(fixture.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| anyhow!("run historical config check"))?;
    ensure!(status.success(), "historical config check failed");
    Ok(())
}

fn wait_for_socks(
    address: SocketAddr,
    server: &mut ChildGuard,
    client: &mut ChildGuard,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        server.ensure_running()?;
        client.ensure_running()?;
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!("historical SOCKS listener did not become ready")
}

fn wait_for_server(address: SocketAddr, server: &mut ChildGuard) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        server.ensure_running()?;
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!("historical server listener did not become ready")
}

fn assert_socks_relay(socks_address: SocketAddr, target_address: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect_timeout(&socks_address, Duration::from_secs(2))
        .map_err(|_| anyhow!("connect historical SOCKS listener"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|_| anyhow!("set SOCKS read timeout"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|_| anyhow!("set SOCKS write timeout"))?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|_| anyhow!("write SOCKS greeting"))?;
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|_| anyhow!("read SOCKS greeting"))?;
    ensure!(greeting == [0x05, 0x00], "SOCKS greeting was rejected");

    let target = match target_address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => bail!("loopback target was not IPv4"),
    };
    let octets = target.ip().octets();
    let port = target.port().to_be_bytes();
    let request = [
        0x05, 0x01, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], port[0], port[1],
    ];
    stream
        .write_all(&request)
        .map_err(|_| anyhow!("write SOCKS connect request"))?;

    let mut response_head = [0_u8; 4];
    stream
        .read_exact(&mut response_head)
        .map_err(|_| anyhow!("read SOCKS connect response"))?;
    ensure!(
        response_head[0] == 0x05 && response_head[1] == 0x00,
        "SOCKS connect request was rejected"
    );
    let tail_len = match response_head[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .map_err(|_| anyhow!("read SOCKS response address"))?;
            usize::from(length[0]) + 2
        }
        _ => bail!("SOCKS response address type was invalid"),
    };
    let mut response_tail = vec![0_u8; tail_len];
    stream
        .read_exact(&mut response_tail)
        .map_err(|_| anyhow!("read SOCKS response tail"))?;

    stream
        .write_all(RELAY_PAYLOAD)
        .map_err(|_| anyhow!("write relay payload"))?;
    let mut echoed = vec![0_u8; RELAY_PAYLOAD.len()];
    stream
        .read_exact(&mut echoed)
        .map_err(|_| anyhow!("read relay payload"))?;
    ensure!(echoed == RELAY_PAYLOAD, "relay payload changed");
    Ok(())
}

fn run_process_case(client_binary: &Path, server_binary: &Path, auth: Auth) -> Result<()> {
    let mut origin = EchoOrigin::bind()?;
    let server_port = reserve_ephemeral_port()?;
    let socks_port = reserve_ephemeral_port()?;
    ensure!(
        server_port != socks_port,
        "loopback port reservation collided"
    );
    let fixture = Fixture::new(auth, server_port, socks_port)?;

    let mut server = ChildGuard::spawn(server_binary, "server", fixture.path())?;
    wait_for_server(
        SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)),
        &mut server,
    )?;
    let mut client = ChildGuard::spawn(client_binary, "client", fixture.path())?;
    let socks_address = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    wait_for_socks(socks_address, &mut server, &mut client)?;
    origin.start()?;
    let relay_result = assert_socks_relay(socks_address, origin.address);
    let origin_result = origin.finish();
    origin_result?;
    relay_result?;
    server.ensure_running()?;
    client.ensure_running()
}

#[test]
fn echo_origin_rejects_modified_payload_and_reports_failure() -> Result<()> {
    let mut origin = EchoOrigin::bind()?;
    let address = origin.address;
    origin.start()?;

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|_| anyhow!("connect focused loopback origin"))?;
    let mut modified = RELAY_PAYLOAD.to_vec();
    modified[0] ^= 0x01;
    stream
        .write_all(&modified)
        .map_err(|_| anyhow!("write focused loopback payload"))?;

    let error = origin
        .finish()
        .expect_err("modified origin payload must fail");
    ensure!(
        error.to_string() == "loopback origin payload mismatch",
        "focused origin failure classification changed"
    );
    Ok(())
}

#[test]
#[ignore = "run through scripts/test-n-minus-one-compat.sh"]
fn historical_configs_are_accepted() -> Result<()> {
    let binaries = HistoricalBinaries::from_env()?;
    let mut checks = 0_u32;
    for backend in Backend::ALL {
        for version in Version::ALL {
            for auth in Auth::ALL {
                let fixture =
                    Fixture::new(auth, reserve_ephemeral_port()?, reserve_ephemeral_port()?)?;
                let binary = binaries.get(version, backend);
                check_config(binary, &fixture, "client")?;
                check_config(binary, &fixture, "server")?;
                checks += 2;
                println!(
                    "PASS config backend={} version={} auth={} checks=2",
                    backend.label(),
                    version.label(),
                    auth.label()
                );
            }
        }
    }
    ensure!(checks == 16, "config preflight count changed");
    println!(
        "MATRIX_RESULT stage=config completed=true cells=8 checks={checks} binaries=4 auth_modes=2"
    );
    Ok(())
}

#[test]
#[ignore = "run through scripts/test-n-minus-one-compat.sh"]
fn same_version_h2_process_controls() -> Result<()> {
    let binaries = HistoricalBinaries::from_env()?;
    let mut cases = 0_u32;
    for backend in Backend::ALL {
        for version in Version::ALL {
            for auth in Auth::ALL {
                let binary = binaries.get(version, backend);
                run_process_case(binary, binary, auth)?;
                cases += 1;
                println!(
                    "PASS control backend={} auth={} client={} server={}",
                    backend.label(),
                    auth.label(),
                    version.label(),
                    version.label()
                );
            }
        }
    }
    ensure!(cases == 8, "same-version control count changed");
    println!(
        "MATRIX_RESULT stage=same_version completed=true cells={cases} default=4 rustls=4 auth_v1=4 auth_v2=4"
    );
    Ok(())
}

#[test]
#[ignore = "run through scripts/test-n-minus-one-compat.sh"]
fn cross_version_h2_process_matrix() -> Result<()> {
    let binaries = HistoricalBinaries::from_env()?;
    let directions = [
        (Version::Beta2, Version::Beta1),
        (Version::Beta1, Version::Beta2),
    ];
    let mut cases = 0_u32;
    for backend in Backend::ALL {
        for (client_version, server_version) in directions {
            for auth in Auth::ALL {
                run_process_case(
                    binaries.get(client_version, backend),
                    binaries.get(server_version, backend),
                    auth,
                )?;
                cases += 1;
                println!(
                    "PASS cross backend={} auth={} client={} server={}",
                    backend.label(),
                    auth.label(),
                    client_version.label(),
                    server_version.label()
                );
            }
        }
    }
    ensure!(cases == 8, "cross-version matrix count changed");
    println!(
        "MATRIX_RESULT stage=cross_version completed=true cells={cases} default=4 rustls=4 auth_v1=4 auth_v2=4"
    );
    Ok(())
}
