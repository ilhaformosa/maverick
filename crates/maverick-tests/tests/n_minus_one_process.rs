use anyhow::{anyhow, bail, ensure, Result};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BETA2_DEFAULT_BIN: &str = "MAVERICK_BETA2_DEFAULT_BIN";
const BETA1_DEFAULT_BIN: &str = "MAVERICK_BETA1_DEFAULT_BIN";
const BETA2_RUSTLS_BIN: &str = "MAVERICK_BETA2_RUSTLS_BIN";
const BETA1_RUSTLS_BIN: &str = "MAVERICK_BETA1_RUSTLS_BIN";
const FIXTURE_SECRET: &str = "mv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const RELAY_PAYLOAD: &[u8] = b"maverick-n-minus-one-direct-h2";
const MAX_CHILD_STDERR_BYTES: usize = 4 * 1024;
const MAX_CHILD_STDERR_REPORT_BYTES: usize = 256;
const FAKE_CHILD_ENV: &str = "MAVERICK_N_MINUS_ONE_FAKE_CHILD";
const FAKE_CHILD_SENTINEL: &str = "N_MINUS_ONE_CHILD_SENTINEL";

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

#[derive(Clone, Copy)]
struct ProcessCell {
    backend: Backend,
    auth: Auth,
    client: Version,
    server: Version,
}

impl ProcessCell {
    fn label(self) -> String {
        format!(
            "backend={} auth={} client={} server={}",
            self.backend.label(),
            self.auth.label(),
            self.client.label(),
            self.server.label()
        )
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

fn io_failure(action: &'static str, error: std::io::Error) -> anyhow::Error {
    anyhow!("{action}: io_kind={:?}", error.kind())
}

struct ChildGuard {
    child: Child,
    role: &'static str,
    stderr: Arc<Mutex<CapturedStderr>>,
    stderr_worker: Option<thread::JoinHandle<()>>,
    finished: bool,
}

#[derive(Default)]
struct CapturedStderr {
    bytes: Vec<u8>,
    truncated: bool,
    read_failed: bool,
}

impl ChildGuard {
    fn spawn(binary: &Path, role: &'static str, directory: &Path) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .arg(role)
            .arg("-c")
            .arg(format!("{role}.yaml"))
            .current_dir(directory);
        Self::spawn_command(command, role)
    }

    fn spawn_command(mut command: Command, role: &'static str) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| anyhow!("start historical process role={role}"))?;
        let mut child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("capture historical process stderr role={role}"))?;
        let stderr = Arc::new(Mutex::new(CapturedStderr::default()));
        let worker_capture = Arc::clone(&stderr);
        let stderr_worker = match thread::Builder::new()
            .name("historical-stderr".to_owned())
            .spawn(move || {
                let mut buffer = [0_u8; 1024];
                loop {
                    match child_stderr.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            let Ok(mut capture) = worker_capture.lock() else {
                                break;
                            };
                            let remaining =
                                MAX_CHILD_STDERR_BYTES.saturating_sub(capture.bytes.len());
                            let retained = remaining.min(read);
                            capture.bytes.extend_from_slice(&buffer[..retained]);
                            if retained < read {
                                capture.truncated = true;
                            }
                        }
                        Err(_) => {
                            if let Ok(mut capture) = worker_capture.lock() {
                                capture.read_failed = true;
                            }
                            break;
                        }
                    }
                }
            }) {
            Ok(worker) => worker,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("start historical stderr capture role={role}"));
            }
        };
        Ok(Self {
            child,
            role,
            stderr,
            stderr_worker: Some(stderr_worker),
            finished: false,
        })
    }

    fn ensure_running(&mut self) -> Result<()> {
        let status = self
            .child
            .try_wait()
            .map_err(|_| anyhow!("inspect historical process role={}", self.role))?;
        match status {
            None => Ok(()),
            Some(status) => {
                self.finished = true;
                self.join_stderr();
                bail!("historical process {}", self.diagnostic(status))
            }
        }
    }

    fn finish_diagnostic(&mut self) -> String {
        let observed = match self.child.try_wait() {
            Ok(Some(status)) => {
                self.finished = true;
                exit_status_label(status)
            }
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.finished = true;
                "running".to_owned()
            }
            Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.finished = true;
                "inspection-error".to_owned()
            }
        };
        self.join_stderr();
        format!(
            "role={} status={} stderr={}",
            self.role,
            observed,
            self.stderr_report()
        )
    }

    fn diagnostic(&self, status: ExitStatus) -> String {
        format!(
            "role={} status={} stderr={}",
            self.role,
            exit_status_label(status),
            self.stderr_report()
        )
    }

    fn join_stderr(&mut self) {
        if let Some(worker) = self.stderr_worker.take() {
            let _ = worker.join();
        }
    }

    fn stderr_report(&self) -> String {
        let Ok(capture) = self.stderr.lock() else {
            return "<capture-unavailable>".to_owned();
        };
        sanitize_child_stderr(&capture)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.finished = true;
        }
        self.join_stderr();
    }
}

fn exit_status_label(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("code={code}"))
        .unwrap_or_else(|| "signal".to_owned())
}

fn sanitize_child_stderr(capture: &CapturedStderr) -> String {
    let sentinel = FAKE_CHILD_SENTINEL.as_bytes();
    let sentinel_present = capture
        .bytes
        .windows(sentinel.len())
        .any(|window| window == sentinel);
    let state = if capture.bytes.is_empty() {
        "empty"
    } else {
        "nonempty"
    };
    let report = format!(
        "state={state} retained_bytes={} truncated={} capture_read_error={} sentinel_present={sentinel_present}",
        capture.bytes.len(),
        capture.truncated,
        capture.read_failed
    );
    debug_assert!(report.len() <= MAX_CHILD_STDERR_REPORT_BYTES);
    report
}

struct EchoOrigin {
    address: SocketAddr,
    listener: Option<TcpListener>,
    read_hook: Option<EchoOriginReadHook>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}

struct EchoOriginReadHook {
    ready: mpsc::SyncSender<()>,
    finished: mpsc::Sender<Option<std::io::ErrorKind>>,
}

struct EchoOriginReadControl {
    ready: mpsc::Receiver<()>,
    finished: mpsc::Receiver<Option<std::io::ErrorKind>>,
}

impl EchoOrigin {
    fn bind() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| io_failure("bind loopback echo origin", error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| io_failure("configure loopback echo origin", error))?;
        let address = listener
            .local_addr()
            .map_err(|error| io_failure("inspect loopback echo origin", error))?;
        Ok(Self {
            address,
            listener: Some(listener),
            read_hook: None,
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        })
    }

    fn synchronize_next_read(&mut self) -> EchoOriginReadControl {
        let (ready_sender, ready) = mpsc::sync_channel(0);
        let (finished_sender, finished) = mpsc::channel();
        self.read_hook = Some(EchoOriginReadHook {
            ready: ready_sender,
            finished: finished_sender,
        });
        EchoOriginReadControl { ready, finished }
    }

    fn start(&mut self) -> Result<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| anyhow!("loopback echo origin already started"))?;
        let mut read_hook = self.read_hook.take();
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
                            stream.set_nonblocking(false).map_err(|error| {
                                io_failure("configure blocking loopback origin", error)
                            })?;
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .map_err(|error| {
                                    io_failure("configure loopback origin read", error)
                                })?;
                            stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .map_err(|error| {
                                    io_failure("configure loopback origin write", error)
                                })?;
                            let mut buffer = vec![0_u8; RELAY_PAYLOAD.len()];
                            let hook = read_hook.take();
                            if let Some(hook) = hook.as_ref() {
                                hook.ready
                                    .send(())
                                    .map_err(|_| anyhow!("signal loopback origin read ready"))?;
                            }
                            let read_result = stream.read_exact(&mut buffer);
                            if let Some(hook) = hook.as_ref() {
                                let _ = hook
                                    .finished
                                    .send(read_result.as_ref().err().map(|error| error.kind()));
                            }
                            read_result.map_err(|error| {
                                io_failure("read loopback origin payload", error)
                            })?;
                            ensure!(buffer == RELAY_PAYLOAD, "loopback origin payload mismatch");
                            stream.write_all(&buffer).map_err(|error| {
                                io_failure("write loopback origin payload", error)
                            })?;
                            return Ok(());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            return Err(io_failure("accept loopback origin connection", error))
                        }
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
        .map_err(|error| io_failure("reserve loopback port", error))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| io_failure("inspect loopback port", error))
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
        .map_err(|error| io_failure("connect historical SOCKS listener", error))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|error| io_failure("set SOCKS read timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|error| io_failure("set SOCKS write timeout", error))?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|error| io_failure("write SOCKS greeting", error))?;
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|error| io_failure("read SOCKS greeting", error))?;
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
        .map_err(|error| io_failure("write SOCKS connect request", error))?;

    let mut response_head = [0_u8; 4];
    stream
        .read_exact(&mut response_head)
        .map_err(|error| io_failure("read SOCKS connect response", error))?;
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
                .map_err(|error| io_failure("read SOCKS response address", error))?;
            usize::from(length[0]) + 2
        }
        _ => bail!("SOCKS response address type was invalid"),
    };
    let mut response_tail = vec![0_u8; tail_len];
    stream
        .read_exact(&mut response_tail)
        .map_err(|error| io_failure("read SOCKS response tail", error))?;

    stream
        .write_all(RELAY_PAYLOAD)
        .map_err(|error| io_failure("write relay payload", error))?;
    let mut echoed = vec![0_u8; RELAY_PAYLOAD.len()];
    stream
        .read_exact(&mut echoed)
        .map_err(|error| io_failure("read relay payload", error))?;
    ensure!(echoed == RELAY_PAYLOAD, "relay payload changed");
    Ok(())
}

fn combine_relay_and_origin(relay_result: Result<()>, origin_result: Result<()>) -> Result<()> {
    match (relay_result, origin_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(relay), Ok(())) => bail!("relay failure: {relay:#}; origin: ok"),
        (Ok(()), Err(origin)) => bail!("relay: ok; origin failure: {origin:#}"),
        (Err(relay), Err(origin)) => {
            bail!("relay failure: {relay:#}; origin failure: {origin:#}")
        }
    }
}

fn run_process_case(client_binary: &Path, server_binary: &Path, cell: ProcessCell) -> Result<()> {
    let mut origin = EchoOrigin::bind()?;
    let server_port = reserve_ephemeral_port()?;
    let socks_port = reserve_ephemeral_port()?;
    ensure!(
        server_port != socks_port,
        "loopback port reservation collided"
    );
    let fixture = Fixture::new(cell.auth, server_port, socks_port)?;

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
    if let Err(error) = combine_relay_and_origin(relay_result, origin_result) {
        let server_diagnostic = server.finish_diagnostic();
        let client_diagnostic = client.finish_diagnostic();
        bail!(
            "compat cell {}: {error:#}; child {server_diagnostic}; child {client_diagnostic}",
            cell.label()
        );
    }
    server
        .ensure_running()
        .map_err(|error| anyhow!("compat cell {}: {error:#}", cell.label()))?;
    client
        .ensure_running()
        .map_err(|error| anyhow!("compat cell {}: {error:#}", cell.label()))
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
fn echo_origin_waits_for_payload_after_accept() -> Result<()> {
    let mut origin = EchoOrigin::bind()?;
    let read_control = origin.synchronize_next_read();
    let address = origin.address;
    origin.start()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|error| io_failure("connect delayed loopback origin", error))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| io_failure("configure delayed loopback read", error))?;
    read_control
        .ready
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| anyhow!("loopback origin did not reach synchronized read"))?;
    match read_control
        .finished
        .recv_timeout(Duration::from_millis(250))
    {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        Ok(Some(kind)) => {
            bail!("loopback origin read completed before payload: io_kind={kind:?}")
        }
        Ok(None) => bail!("loopback origin read completed before payload without error"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("loopback origin read synchronization disconnected")
        }
    }
    let relay_result = (|| {
        stream
            .write_all(RELAY_PAYLOAD)
            .map_err(|error| io_failure("write delayed loopback payload", error))?;
        let read_kind = read_control
            .finished
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| anyhow!("loopback origin did not finish synchronized read"))?;
        ensure!(
            read_kind.is_none(),
            "synchronized loopback origin read failed after payload"
        );
        let mut echoed = vec![0_u8; RELAY_PAYLOAD.len()];
        stream
            .read_exact(&mut echoed)
            .map_err(|error| io_failure("read delayed loopback payload", error))?;
        ensure!(echoed == RELAY_PAYLOAD, "delayed loopback payload changed");
        Ok(())
    })();
    combine_relay_and_origin(relay_result, origin.finish())
}

#[test]
fn relay_failure_remains_primary_when_origin_observes_eof() -> Result<()> {
    let mut origin = EchoOrigin::bind()?;
    let address = origin.address;
    origin.start()?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map_err(|error| io_failure("connect focused EOF origin", error))?;
    drop(stream);

    let error = combine_relay_and_origin(Err(anyhow!("synthetic relay failure")), origin.finish())
        .expect_err("combined failure must retain relay and origin classifications");
    let rendered = error.to_string();
    let relay_position = rendered
        .find("relay failure: synthetic relay failure")
        .ok_or_else(|| anyhow!("synthetic relay classification was lost"))?;
    let origin_position = rendered
        .find("origin failure: read loopback origin payload: io_kind=UnexpectedEof")
        .ok_or_else(|| anyhow!("origin EOF classification was lost"))?;
    ensure!(
        relay_position < origin_position,
        "relay failure was not the primary classification"
    );
    Ok(())
}

#[test]
fn child_failure_reports_bounded_privacy_safe_stderr() -> Result<()> {
    if env::var(FAKE_CHILD_ENV).ok().as_deref() == Some("1") {
        let private_marker = ["SYNTHETIC", "INTERNAL", "HOSTNAME"].concat();
        let private_path = ["/synthetic", "/private", "/path"].concat();
        eprintln!("{FAKE_CHILD_SENTINEL}");
        eprintln!("{private_marker}");
        eprintln!("{FIXTURE_SECRET}");
        eprintln!("\u{1b}[31m{private_path}\u{1b}[0m");
        eprintln!("{}", "X".repeat(MAX_CHILD_STDERR_BYTES * 2));
        std::process::exit(23);
    }

    let current_exe = env::current_exe().map_err(|_| anyhow!("locate focused test process"))?;
    let mut command = Command::new(current_exe);
    command
        .arg("--exact")
        .arg("child_failure_reports_bounded_privacy_safe_stderr")
        .arg("--nocapture")
        .env(FAKE_CHILD_ENV, "1");
    let mut child = ChildGuard::spawn_command(command, "fake-client")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let rendered = loop {
        match child.ensure_running() {
            Ok(()) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(()) => bail!("fake child did not exit"),
            Err(error) => break error.to_string(),
        }
    };

    ensure!(rendered.contains("role=fake-client"), "child role was lost");
    ensure!(rendered.contains("status=code=23"), "child status was lost");
    ensure!(
        rendered.contains("stderr=state=nonempty"),
        "child stderr state was lost"
    );
    ensure!(
        rendered.contains("retained_bytes=4096"),
        "bounded child stderr byte count was lost"
    );
    ensure!(
        rendered.contains("truncated=true"),
        "bounded child stderr did not report truncation"
    );
    ensure!(
        rendered.contains("capture_read_error=false"),
        "child stderr capture status was lost"
    );
    ensure!(
        rendered.contains("sentinel_present=true"),
        "neutral child sentinel classification was lost"
    );
    ensure!(
        !rendered.contains(FAKE_CHILD_SENTINEL),
        "raw neutral child sentinel escaped metadata-only reporting"
    );
    ensure!(
        !rendered.contains(FIXTURE_SECRET),
        "fixture secret escaped child stderr redaction"
    );
    let private_marker = ["SYNTHETIC", "INTERNAL", "HOSTNAME"].concat();
    let private_path = ["/synthetic", "/private", "/path"].concat();
    ensure!(
        !rendered.contains(&private_marker),
        "unpunctuated private marker escaped child stderr redaction"
    );
    ensure!(
        !rendered.contains(&private_path),
        "private path escaped child stderr redaction"
    );
    ensure!(
        !rendered.contains('\u{1b}'),
        "control character escaped child stderr redaction"
    );
    ensure!(
        rendered.len() <= MAX_CHILD_STDERR_REPORT_BYTES,
        "bounded child stderr report grew unexpectedly"
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
                run_process_case(
                    binary,
                    binary,
                    ProcessCell {
                        backend,
                        auth,
                        client: version,
                        server: version,
                    },
                )?;
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
                    ProcessCell {
                        backend,
                        auth,
                        client: client_version,
                        server: server_version,
                    },
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
