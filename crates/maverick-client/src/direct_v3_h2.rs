//! Dormant client-side rustls/direct-H2 auth-v3 control reference.
//!
//! This crate-private seam is not called by the legacy client, its listeners,
//! connection pool, CLI, SDK, or default runtime. It authenticates exactly one
//! control exchange on one physical generation, closes that generation, and
//! exposes no user-flow or data-plane capability.

use std::fmt;
use std::future::poll_fn;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use h2::client::{Connection, SendRequest};
use http::header::CONTENT_TYPE;
use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, StatusCode, Uri};
use maverick_core::auth_v3::{
    encode_auth_v3_client_control, verify_auth_v3_server_confirmation, AuthV3Carrier,
    AuthV3ClientControlInput, AuthV3ClientReceipt, AuthV3PreselectedProfile, AuthV3TlsVersion,
    AUTH_V3_CLIENT_CONTROL_LEN, AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN,
    AUTH_V3_SERVER_CONFIRMATION_LEN,
};
use maverick_core::config::{DirectV3ClientRoleConfig, DirectV3TransportStrategy};
use rand::rngs::OsRng;
use rand::TryRngCore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const AUTH_CONTENT_TYPE: &str = "application/maverick-auth-v3";
const REFERENCE_CONTROL_DEADLINE: Duration = Duration::from_secs(2);
const REFERENCE_TEARDOWN_DEADLINE: Duration = Duration::from_secs(2);
const REFERENCE_MAX_FRAME_SIZE: u32 = 65_536;
const REFERENCE_MAX_CONCURRENT_FLOWS: u32 = 1;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static CONNECT_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

/// Fixed, bounded, value-free reference failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectV3H2Error {
    PreIoGate,
    TlsConfiguration,
    Connect,
    TlsHandshake,
    ConnectionTrust,
    H2Handshake,
    Random,
    Control,
    Confirmation,
    Deadline,
    Teardown,
}

impl fmt::Display for DirectV3H2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PreIoGate => "direct-v3 H2 pre-I/O gate rejected",
            Self::TlsConfiguration => "direct-v3 H2 TLS configuration failed",
            Self::Connect => "direct-v3 H2 connection failed",
            Self::TlsHandshake => "direct-v3 H2 TLS handshake failed",
            Self::ConnectionTrust => "direct-v3 H2 connection trust failed",
            Self::H2Handshake => "direct-v3 H2 handshake failed",
            Self::Random => "direct-v3 H2 random generation failed",
            Self::Control => "direct-v3 H2 control failed",
            Self::Confirmation => "direct-v3 H2 confirmation failed",
            Self::Deadline => "direct-v3 H2 control deadline reached",
            Self::Teardown => "direct-v3 H2 connection teardown failed",
        })
    }
}

impl std::error::Error for DirectV3H2Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectV3H2Backend {
    Rustls,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationState {
    Fresh,
    Authenticating,
    Authenticated,
    Closed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationEvent {
    Authenticating,
    NonceNonzero,
    RequestSent,
    ConfirmationVerified,
    Authenticated,
    PhysicalConnectionClosedWithSenderAlive,
    Closed,
}

struct GenerationGate {
    state: GenerationState,
    #[cfg(test)]
    events: Vec<GenerationEvent>,
}

impl GenerationGate {
    fn fresh() -> Self {
        Self {
            state: GenerationState::Fresh,
            #[cfg(test)]
            events: Vec::new(),
        }
    }

    fn start_authentication(&mut self) -> Result<(), DirectV3H2Error> {
        if self.state != GenerationState::Fresh {
            return Err(DirectV3H2Error::Control);
        }
        self.state = GenerationState::Authenticating;
        #[cfg(test)]
        self.events.push(GenerationEvent::Authenticating);
        Ok(())
    }

    fn authenticate(&mut self) -> Result<(), DirectV3H2Error> {
        if self.state != GenerationState::Authenticating {
            return Err(DirectV3H2Error::Confirmation);
        }
        self.state = GenerationState::Authenticated;
        #[cfg(test)]
        self.events.push(GenerationEvent::Authenticated);
        Ok(())
    }

    fn close(&mut self) {
        if self.state != GenerationState::Closed {
            self.state = GenerationState::Closed;
            #[cfg(test)]
            self.events.push(GenerationEvent::Closed);
        }
    }
}

pub(crate) struct ReferenceOutcome {
    state: GenerationState,
    result: Result<(), DirectV3H2Error>,
    #[cfg(test)]
    events: Vec<GenerationEvent>,
    #[cfg(test)]
    observed_exporter: Option<[u8; AUTH_V3_EXPORTER_LEN]>,
}

impl ReferenceOutcome {
    pub(crate) const fn result(&self) -> Result<(), DirectV3H2Error> {
        self.result
    }
}

struct PreparedRequest {
    server_name: ServerName<'static>,
    uri: Uri,
}

/// Run one dormant control-only client reference and close its generation.
pub(crate) async fn run_direct_v3_h2_reference(
    config: &DirectV3ClientRoleConfig,
    backend: DirectV3H2Backend,
) -> ReferenceOutcome {
    let mut gate = GenerationGate::fresh();
    let mut observed_exporter = None;
    let mut physical = None;

    let mut result = match prepare_pre_io(config, backend) {
        Ok(prepared) => match crate::h2_transport::rustls_client_config_from_trust(
            config.ca_cert(),
            config.cert_pin(),
        ) {
            Ok(mut tls_config) => {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
                tls_config.enable_early_data = false;
                timeout(
                    REFERENCE_CONTROL_DEADLINE,
                    run_generation(
                        config,
                        prepared,
                        tls_config,
                        &mut gate,
                        &mut physical,
                        &mut observed_exporter,
                    ),
                )
                .await
                .map_err(|_| DirectV3H2Error::Deadline)
                .and_then(|result| result)
            }
            Err(_) => Err(DirectV3H2Error::TlsConfiguration),
        },
        Err(error) => Err(error),
    };

    if let Some(mut generation) = physical {
        let closed_with_sender_alive = generation.close().await;
        #[cfg(test)]
        if closed_with_sender_alive {
            gate.events
                .push(GenerationEvent::PhysicalConnectionClosedWithSenderAlive);
        }
        if !closed_with_sender_alive {
            result = Err(DirectV3H2Error::Teardown);
        }
        #[cfg(not(test))]
        let _ = closed_with_sender_alive;
    }
    gate.close();
    ReferenceOutcome {
        state: gate.state,
        result,
        #[cfg(test)]
        events: gate.events,
        #[cfg(test)]
        observed_exporter,
    }
}

fn prepare_pre_io(
    config: &DirectV3ClientRoleConfig,
    backend: DirectV3H2Backend,
) -> Result<PreparedRequest, DirectV3H2Error> {
    if backend != DirectV3H2Backend::Rustls
        || config.transport_strategy() != DirectV3TransportStrategy::H2
    {
        return Err(DirectV3H2Error::PreIoGate);
    }
    let path_and_query = raw_h2_path(config.tunnel_path())?;
    let server_name = ServerName::try_from(config.server_name().to_owned())
        .map_err(|_| DirectV3H2Error::PreIoGate)?;
    let authority =
        Authority::try_from(config.server_name()).map_err(|_| DirectV3H2Error::PreIoGate)?;
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|_| DirectV3H2Error::PreIoGate)?;
    Ok(PreparedRequest { server_name, uri })
}

fn raw_h2_path(path: &str) -> Result<PathAndQuery, DirectV3H2Error> {
    if path.contains(['?', '#']) {
        return Err(DirectV3H2Error::PreIoGate);
    }
    let parsed = PathAndQuery::try_from(path).map_err(|_| DirectV3H2Error::PreIoGate)?;
    if parsed.as_str() != path || parsed.query().is_some() || parsed.path() != path {
        return Err(DirectV3H2Error::PreIoGate);
    }
    Ok(parsed)
}

async fn run_generation(
    config: &DirectV3ClientRoleConfig,
    prepared: PreparedRequest,
    tls_config: rustls::ClientConfig,
    gate: &mut GenerationGate,
    physical: &mut Option<PhysicalGeneration>,
    observed_exporter: &mut Option<[u8; AUTH_V3_EXPORTER_LEN]>,
) -> Result<(), DirectV3H2Error> {
    let tcp = connect_tcp(config.server_address()).await?;
    tcp.set_nodelay(true)
        .map_err(|_| DirectV3H2Error::Connect)?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = connector
        .connect(prepared.server_name, tcp)
        .await
        .map_err(|_| DirectV3H2Error::TlsHandshake)?;
    let exporter = observe_rustls_generation(&tls)?;
    *observed_exporter = Some(exporter);
    gate.start_authentication()?;

    let preselected = config.preselected_profile();
    let connection = preselected.trusted_connection_context(
        AuthV3Carrier::H2,
        AuthV3TlsVersion::Tls13,
        true,
        false,
        &exporter,
        true,
        Some(&[]),
        config.tunnel_path(),
    );
    let client_nonce = random_nonzero::<32>()?;
    #[cfg(test)]
    gate.events.push(GenerationEvent::NonceNonzero);
    let client_time = trusted_now()?;
    let control = encode_auth_v3_client_control(
        &preselected.trusted_profile(),
        &connection,
        &AuthV3ClientControlInput::new(AuthV3Carrier::H2, client_time, client_nonce),
    )
    .map_err(|_| DirectV3H2Error::Control)?;

    let (sender, driver) = h2::client::Builder::new()
        .initial_window_size(1024)
        .initial_connection_window_size(2048)
        .handshake(tls)
        .await
        .map_err(|_| DirectV3H2Error::H2Handshake)?;
    *physical = Some(PhysicalGeneration::new(sender, driver));
    let generation = physical
        .as_mut()
        .expect("physical generation was installed before control I/O");
    let confirmation = exchange_control(generation, prepared.uri, control, gate).await?;
    let receipt_now = trusted_now()?;
    verify_confirmation(
        &confirmation,
        &control,
        &preselected,
        &connection,
        receipt_now,
    )?;
    #[cfg(test)]
    gate.events.push(GenerationEvent::ConfirmationVerified);
    gate.authenticate()
}

async fn connect_tcp(address: &str) -> Result<TcpStream, DirectV3H2Error> {
    #[cfg(test)]
    CONNECT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    TcpStream::connect(address)
        .await
        .map_err(|_| DirectV3H2Error::Connect)
}

fn observe_rustls_generation<T>(
    tls: &tokio_rustls::client::TlsStream<T>,
) -> Result<[u8; AUTH_V3_EXPORTER_LEN], DirectV3H2Error> {
    let connection = tls.get_ref().1;
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.alpn_protocol() != Some(b"h2")
        || connection.is_early_data_accepted()
    {
        return Err(DirectV3H2Error::ConnectionTrust);
    }
    connection
        .export_keying_material(
            [0u8; AUTH_V3_EXPORTER_LEN],
            AUTH_V3_EXPORTER_LABEL,
            Some(&[]),
        )
        .map_err(|_| DirectV3H2Error::ConnectionTrust)
}

async fn exchange_control(
    generation: &mut PhysicalGeneration,
    uri: Uri,
    control: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
    gate: &mut GenerationGate,
) -> Result<[u8; AUTH_V3_SERVER_CONFIRMATION_LEN], DirectV3H2Error> {
    poll_fn(|context| generation.sender.poll_ready(context))
        .await
        .map_err(|_| DirectV3H2Error::Control)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, AUTH_CONTENT_TYPE)
        .body(())
        .map_err(|_| DirectV3H2Error::Control)?;
    let (response, mut body) = generation
        .sender
        .send_request(request, false)
        .map_err(|_| DirectV3H2Error::Control)?;
    send_control_body(&mut body, &control).await?;
    #[cfg(test)]
    gate.events.push(GenerationEvent::RequestSent);
    #[cfg(not(test))]
    let _ = gate;

    let response = response.await.map_err(|_| DirectV3H2Error::Confirmation)?;
    validate_response_metadata(&response)?;
    collect_confirmation(response.into_body()).await
}

async fn send_control_body(
    stream: &mut h2::SendStream<Bytes>,
    control: &[u8; AUTH_V3_CLIENT_CONTROL_LEN],
) -> Result<(), DirectV3H2Error> {
    let mut offset = 0;
    while offset < control.len() {
        let remaining = control.len() - offset;
        stream.reserve_capacity(remaining);
        while stream.capacity() == 0 {
            match poll_fn(|context| stream.poll_capacity(context)).await {
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Err(DirectV3H2Error::Control),
            }
        }
        let accepted = remaining.min(stream.capacity());
        let end_stream = offset + accepted == control.len();
        stream
            .send_data(
                Bytes::copy_from_slice(&control[offset..offset + accepted]),
                end_stream,
            )
            .map_err(|_| DirectV3H2Error::Control)?;
        offset += accepted;
    }
    Ok(())
}

fn validate_response_metadata(
    response: &http::Response<h2::RecvStream>,
) -> Result<(), DirectV3H2Error> {
    let mut content_types = response.headers().get_all(CONTENT_TYPE).iter();
    let content_type = content_types.next();
    if response.status() != StatusCode::OK
        || content_type.is_none_or(|value| value.as_bytes() != AUTH_CONTENT_TYPE.as_bytes())
        || content_types.next().is_some()
    {
        return Err(DirectV3H2Error::Confirmation);
    }
    Ok(())
}

async fn collect_confirmation(
    mut body: h2::RecvStream,
) -> Result<[u8; AUTH_V3_SERVER_CONFIRMATION_LEN], DirectV3H2Error> {
    let mut collected = BytesMut::with_capacity(AUTH_V3_SERVER_CONFIRMATION_LEN + 1);
    while let Some(data) = body.data().await {
        let data = data.map_err(|_| DirectV3H2Error::Confirmation)?;
        let remaining = AUTH_V3_SERVER_CONFIRMATION_LEN + 1 - collected.len();
        let copy_len = remaining.min(data.len());
        collected.extend_from_slice(&data[..copy_len]);
        if collected.len() > AUTH_V3_SERVER_CONFIRMATION_LEN || data.len() > remaining {
            return Err(DirectV3H2Error::Confirmation);
        }
        body.flow_control()
            .release_capacity(data.len())
            .map_err(|_| DirectV3H2Error::Confirmation)?;
    }
    if body
        .trailers()
        .await
        .map_err(|_| DirectV3H2Error::Confirmation)?
        .is_some()
        || collected.len() != AUTH_V3_SERVER_CONFIRMATION_LEN
    {
        return Err(DirectV3H2Error::Confirmation);
    }
    collected
        .as_ref()
        .try_into()
        .map_err(|_| DirectV3H2Error::Confirmation)
}

fn verify_confirmation(
    confirmation: &[u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
    control: &[u8; AUTH_V3_CLIENT_CONTROL_LEN],
    preselected: &AuthV3PreselectedProfile<'_>,
    connection: &maverick_core::auth_v3::AuthV3TrustedConnectionContext<'_>,
    receipt_now: u64,
) -> Result<(), DirectV3H2Error> {
    verify_auth_v3_server_confirmation(
        confirmation,
        control,
        &preselected.trusted_profile(),
        connection,
        &AuthV3ClientReceipt::new(
            receipt_now,
            REFERENCE_MAX_FRAME_SIZE,
            REFERENCE_MAX_CONCURRENT_FLOWS,
        ),
    )
    .map(|_| ())
    .map_err(|_| DirectV3H2Error::Confirmation)
}

fn trusted_now() -> Result<u64, DirectV3H2Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DirectV3H2Error::Control)
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], DirectV3H2Error> {
    let mut output = [0u8; N];
    OsRng
        .try_fill_bytes(&mut output)
        .map_err(|_| DirectV3H2Error::Random)?;
    require_nonzero_random(output)
}

fn require_nonzero_random<const N: usize>(output: [u8; N]) -> Result<[u8; N], DirectV3H2Error> {
    if output.iter().all(|byte| *byte == 0) {
        return Err(DirectV3H2Error::Random);
    }
    Ok(output)
}

struct ClosedSignal(watch::Sender<bool>);

impl Drop for ClosedSignal {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

struct PhysicalGeneration {
    sender: SendRequest<Bytes>,
    driver: JoinHandle<()>,
    closed: watch::Receiver<bool>,
}

impl PhysicalGeneration {
    fn new<T>(sender: SendRequest<Bytes>, connection: Connection<T, Bytes>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (closed_tx, closed) = watch::channel(false);
        let signal = ClosedSignal(closed_tx);
        let driver = tokio::spawn(async move {
            let _signal = signal;
            let _ = connection.await;
        });
        Self {
            sender,
            driver,
            closed,
        }
    }

    async fn close(&mut self) -> bool {
        self.driver.abort();
        let _ = timeout(REFERENCE_TEARDOWN_DEADLINE, &mut self.driver).await;
        if !*self.closed.borrow() {
            let _ = timeout(REFERENCE_TEARDOWN_DEADLINE, self.closed.changed()).await;
        }
        *self.closed.borrow()
    }
}

impl Drop for PhysicalGeneration {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use h2::server::SendResponse;
    use http::{HeaderMap, HeaderValue, Response};
    use maverick_core::auth_v3::{
        encode_auth_v3_server_confirmation, verify_auth_v3_client_control,
        AuthV3ServerConfirmationInput,
    };
    use maverick_core::config::ClientRoleConfig;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const TEST_PATH: &str = "/reference-auth-v3";
    const TEST_BOUND: Duration = Duration::from_secs(7);
    const SERVER_CLOSE_BOUND: Duration = Duration::from_secs(4);
    static TEST_NETWORK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TestIdentity {
        _directory: TempDir,
        cert_path: PathBuf,
        key_path: PathBuf,
        cert_der: CertificateDer<'static>,
    }

    impl TestIdentity {
        fn new() -> Self {
            let directory = TempDir::new().expect("create neutral test directory");
            let cert_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate loopback certificate");
            std::fs::write(&cert_path, certified.cert.pem()).expect("write loopback certificate");
            std::fs::write(&key_path, certified.key_pair.serialize_pem())
                .expect("write loopback key");
            Self {
                _directory: directory,
                cert_path,
                key_path,
                cert_der: certified.cert.der().clone(),
            }
        }

        fn correct_pin(&self) -> String {
            format!(
                "sha256/{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(&self.cert_der))
            )
        }

        fn server_config(
            &self,
            versions: &[&'static rustls::SupportedProtocolVersion],
            alpn: Vec<Vec<u8>>,
        ) -> rustls::ServerConfig {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_file_iter(&self.cert_path)
                    .expect("open test certificate")
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .expect("parse test certificate");
            let key = PrivateKeyDer::from_pem_file(&self.key_path).expect("parse test key");
            let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("build test TLS server");
            config.alpn_protocols = alpn;
            config.max_early_data_size = 0;
            config.send_half_rtt_data = false;
            config
        }
    }

    struct TestRole {
        role: ClientRoleConfig,
    }

    impl TestRole {
        fn direct(&self) -> &DirectV3ClientRoleConfig {
            self.role
                .direct_v3()
                .expect("test role must be config schema 3")
        }
    }

    fn test_role(
        address: &str,
        server_name: &str,
        strategy: &str,
        path: &str,
        ca_cert: &Path,
        cert_pin: Option<&str>,
    ) -> TestRole {
        let not_after = trusted_now()
            .expect("read test clock")
            .checked_add(3_600)
            .expect("test credential expiry");
        let cert_pin = cert_pin
            .map(|pin| format!("\"{pin}\""))
            .unwrap_or_else(|| "null".to_owned());
        let yaml = format!(
            r#"version: 3
role: client
security:
  posture: standard
transport:
  strategy: {strategy}
trust:
  route: direct_to_maverick
name_privacy:
  minimum: plain_sni
traffic_shaping:
  policy: disabled
local:
  socks5:
    listen: "127.0.0.1:0"
server:
  address: "{address}"
  server_name: "{server_name}"
  tunnel_path: "{path}"
  ca_cert: "{}"
  cert_pin: {cert_pin}
auth:
  minimum: direct_v3_only
  direct_v3:
    binding:
      provisioning_handle: "EREREREREREREREREREREQ"
      principal_id: "IiIiIiIiIiIiIiIiIiIiIg"
      deployment_profile_id: "MzMzMzMzMzMzMzMzMzMzMw"
      credential_namespace_id: "RERERERERERERERERERERA"
      server_identity_id: "VVVVVVVVVVVVVVVVVVVVVQ"
      credential_epoch: 7
      credential_not_after_unix: {not_after}
      secret: "{TEST_SECRET}"
"#,
            ca_cert.display(),
        );
        TestRole {
            role: ClientRoleConfig::from_yaml_str(&yaml).expect("parse test client role"),
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum WrongExporter {
        Label,
        Context,
        Generation,
    }

    #[derive(Clone, Copy, Debug)]
    enum ServerBehavior {
        Valid,
        WrongStatus,
        MissingContentType,
        DuplicateContentType,
        ParameterizedContentType,
        Body319,
        Body321,
        TrailingData,
        Trailers,
        InvalidMac,
        InvalidPolicy,
        InvalidExpiry,
        ZeroResource,
        ExcessiveResource,
        WrongExporter(WrongExporter),
        NoResponseHeaders,
        PartialWithoutEndStream,
    }

    struct ServerObservation {
        actual_tls13: bool,
        actual_h2: bool,
        no_early_data: bool,
        exporter: [u8; AUTH_V3_EXPORTER_LEN],
        method: Method,
        raw_path: String,
        content_types: Vec<Vec<u8>>,
        control_len: usize,
        physical_closed: bool,
        extra_request_seen: bool,
    }

    struct ServerExporters {
        actual: [u8; AUTH_V3_EXPORTER_LEN],
        wrong_label: [u8; AUTH_V3_EXPORTER_LEN],
        wrong_context: [u8; AUTH_V3_EXPORTER_LEN],
    }

    async fn serve_reference(
        listener: TcpListener,
        tls_config: rustls::ServerConfig,
        config: &DirectV3ClientRoleConfig,
        behavior: ServerBehavior,
    ) -> Result<ServerObservation> {
        let (tcp, _) = listener.accept().await.context("accept loopback client")?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let mut tls = acceptor.accept(tcp).await.context("accept loopback TLS")?;
        let server = tls.get_mut().1;
        let actual_tls13 = server.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
        let actual_h2 = server.alpn_protocol() == Some(b"h2");
        let no_early_data = server.early_data().is_none();
        let exporters = ServerExporters {
            actual: server.export_keying_material(
                [0u8; AUTH_V3_EXPORTER_LEN],
                AUTH_V3_EXPORTER_LABEL,
                Some(&[]),
            )?,
            wrong_label: server.export_keying_material(
                [0u8; AUTH_V3_EXPORTER_LEN],
                b"EXPORTER-Wrong-Reference-Label",
                Some(&[]),
            )?,
            wrong_context: server.export_keying_material(
                [0u8; AUTH_V3_EXPORTER_LEN],
                AUTH_V3_EXPORTER_LABEL,
                Some(b"wrong-context"),
            )?,
        };
        let mut h2 = h2::server::Builder::new()
            .initial_window_size(1024)
            .initial_connection_window_size(2048)
            .handshake::<_, Bytes>(tls)
            .await
            .context("server H2 handshake")?;
        let (request, respond) = h2
            .accept()
            .await
            .context("client closed before control")?
            .context("receive control request")?;
        let method = request.method().clone();
        let raw_path = request
            .uri()
            .path_and_query()
            .map(PathAndQuery::as_str)
            .unwrap_or_default()
            .to_owned();
        let content_types = request
            .headers()
            .get_all(CONTENT_TYPE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let control = collect_server_control(request.into_body());
        tokio::pin!(control);
        let mut extra_request_seen = false;
        let control = loop {
            tokio::select! {
                result = &mut control => break result?,
                next = h2.accept() => match next {
                    Some(Ok(_)) => extra_request_seen = true,
                    Some(Err(error)) => return Err(error).context("drive control connection"),
                    None => anyhow::bail!("client closed during control body"),
                }
            }
        };
        let control_len = control.len();

        let mut held_response = None;
        let mut held_send = None;
        match behavior {
            ServerBehavior::NoResponseHeaders => held_response = Some(respond),
            _ => {
                let confirmation = confirmation_for(config, &control, &exporters, behavior)?;
                held_send = send_test_response(respond, confirmation, behavior)?;
            }
        }

        let physical_closed = timeout(SERVER_CLOSE_BOUND, async {
            loop {
                match h2.accept().await {
                    None | Some(Err(_)) => return true,
                    Some(Ok(_)) => extra_request_seen = true,
                }
            }
        })
        .await
        .unwrap_or(false);
        drop(held_send);
        drop(held_response);
        Ok(ServerObservation {
            actual_tls13,
            actual_h2,
            no_early_data,
            exporter: exporters.actual,
            method,
            raw_path,
            content_types,
            control_len,
            physical_closed,
            extra_request_seen,
        })
    }

    async fn collect_server_control(mut body: h2::RecvStream) -> Result<Vec<u8>> {
        let mut control = Vec::new();
        while let Some(data) = body.data().await {
            let data = data.context("read control DATA")?;
            control.extend_from_slice(&data);
            body.flow_control().release_capacity(data.len())?;
        }
        anyhow::ensure!(
            body.trailers().await?.is_none(),
            "unexpected control trailers"
        );
        Ok(control)
    }

    fn confirmation_for(
        config: &DirectV3ClientRoleConfig,
        received_control: &[u8],
        exporters: &ServerExporters,
        behavior: ServerBehavior,
    ) -> Result<[u8; AUTH_V3_SERVER_CONFIRMATION_LEN]> {
        let now = trusted_now().context("read test server clock")?;
        let (control, exporter) = match behavior {
            ServerBehavior::WrongExporter(kind) => {
                let exporter = match kind {
                    WrongExporter::Label => exporters.wrong_label,
                    WrongExporter::Context => exporters.wrong_context,
                    WrongExporter::Generation => {
                        let candidate = [0x5a; AUTH_V3_EXPORTER_LEN];
                        if candidate == exporters.actual {
                            [0xa5; AUTH_V3_EXPORTER_LEN]
                        } else {
                            candidate
                        }
                    }
                };
                let preselected = config.preselected_profile();
                let connection = preselected.trusted_connection_context(
                    AuthV3Carrier::H2,
                    AuthV3TlsVersion::Tls13,
                    true,
                    false,
                    &exporter,
                    true,
                    Some(&[]),
                    config.tunnel_path(),
                );
                let alternate = encode_auth_v3_client_control(
                    &preselected.trusted_profile(),
                    &connection,
                    &AuthV3ClientControlInput::new(AuthV3Carrier::H2, now, [0x63; 32]),
                )?;
                (alternate.to_vec(), exporter)
            }
            _ => (received_control.to_vec(), exporters.actual),
        };
        let preselected = config.preselected_profile();
        let connection = preselected.trusted_connection_context(
            AuthV3Carrier::H2,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter,
            true,
            Some(&[]),
            config.tunnel_path(),
        );
        let verified = verify_auth_v3_client_control(
            &control,
            &preselected.trusted_profile(),
            &connection,
            now,
        )?;
        let mut confirmation = encode_auth_v3_server_confirmation(
            verified,
            &connection,
            &AuthV3ServerConfirmationInput::new(
                now,
                now.checked_add(60).context("admission expiry")?,
                now.checked_add(300).context("hard expiry")?,
                [0x41; 32],
                [0x42; 16],
                REFERENCE_MAX_FRAME_SIZE,
                REFERENCE_MAX_CONCURRENT_FLOWS,
            ),
        )?;
        match behavior {
            ServerBehavior::InvalidMac => confirmation[319] ^= 1,
            ServerBehavior::InvalidPolicy => confirmation[12] ^= 1,
            ServerBehavior::InvalidExpiry => {
                confirmation[40..48].copy_from_slice(&0u64.to_be_bytes())
            }
            ServerBehavior::ZeroResource => {
                confirmation[280..284].copy_from_slice(&0u32.to_be_bytes())
            }
            ServerBehavior::ExcessiveResource => {
                confirmation[284..288].copy_from_slice(&2u32.to_be_bytes());
            }
            _ => {}
        }
        Ok(confirmation)
    }

    fn send_test_response(
        mut respond: SendResponse<Bytes>,
        confirmation: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
        behavior: ServerBehavior,
    ) -> Result<Option<h2::SendStream<Bytes>>> {
        let status = if matches!(behavior, ServerBehavior::WrongStatus) {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::OK
        };
        let mut response = Response::builder().status(status).body(())?;
        match behavior {
            ServerBehavior::MissingContentType => {}
            ServerBehavior::DuplicateContentType => {
                response
                    .headers_mut()
                    .append(CONTENT_TYPE, HeaderValue::from_static(AUTH_CONTENT_TYPE));
                response
                    .headers_mut()
                    .append(CONTENT_TYPE, HeaderValue::from_static(AUTH_CONTENT_TYPE));
            }
            ServerBehavior::ParameterizedContentType => {
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/maverick-auth-v3; v=3"),
                );
            }
            _ => {
                response
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static(AUTH_CONTENT_TYPE));
            }
        }
        let mut send = respond.send_response(response, false)?;
        match behavior {
            ServerBehavior::Body319 => {
                send.send_data(Bytes::copy_from_slice(&confirmation[..319]), true)?;
            }
            ServerBehavior::Body321 => {
                let mut body = confirmation.to_vec();
                body.push(0);
                send.send_data(Bytes::from(body), true)?;
            }
            ServerBehavior::TrailingData => {
                send.send_data(Bytes::copy_from_slice(&confirmation), false)?;
                send.send_data(Bytes::from_static(&[0]), true)?;
            }
            ServerBehavior::Trailers => {
                send.send_data(Bytes::copy_from_slice(&confirmation), false)?;
                send.send_trailers(HeaderMap::new())?;
            }
            ServerBehavior::PartialWithoutEndStream => {
                send.send_data(Bytes::copy_from_slice(&confirmation[..100]), false)?;
                return Ok(Some(send));
            }
            _ => {
                send.send_data(Bytes::copy_from_slice(&confirmation), true)?;
            }
        }
        Ok(None)
    }

    async fn run_case(
        identity: &TestIdentity,
        behavior: ServerBehavior,
        cert_pin: Option<&str>,
    ) -> (ReferenceOutcome, ServerObservation) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback server");
        let address = listener.local_addr().expect("loopback address");
        let role = test_role(
            &address.to_string(),
            "localhost",
            "h2",
            TEST_PATH,
            &identity.cert_path,
            cert_pin,
        );
        let tls_config = identity.server_config(&[&rustls::version::TLS13], vec![b"h2".to_vec()]);
        let started = tokio::time::Instant::now();
        let (outcome, server) = timeout(TEST_BOUND, async {
            tokio::join!(
                run_direct_v3_h2_reference(role.direct(), DirectV3H2Backend::Rustls),
                serve_reference(listener, tls_config, role.direct(), behavior),
            )
        })
        .await
        .expect("reference case exceeded test bound");
        assert!(started.elapsed() < TEST_BOUND);
        (outcome, server.expect("run test server"))
    }

    fn event_position(outcome: &ReferenceOutcome, expected: GenerationEvent) -> usize {
        outcome
            .events
            .iter()
            .position(|event| *event == expected)
            .expect("expected reference event")
    }

    fn assert_closed_without_authentication(
        outcome: &ReferenceOutcome,
        server: &ServerObservation,
    ) {
        assert!(outcome.result.is_err());
        assert_eq!(outcome.state, GenerationState::Closed);
        assert!(!outcome.events.contains(&GenerationEvent::Authenticated));
        assert_eq!(outcome.events.last(), Some(&GenerationEvent::Closed));
        assert!(server.physical_closed);
        assert!(!server.extra_request_seen);
    }

    #[tokio::test]
    async fn real_loopback_verifies_confirmation_then_closes_physical_generation() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let identity = TestIdentity::new();
        let pin = identity.correct_pin();
        let (outcome, server) = run_case(&identity, ServerBehavior::Valid, Some(&pin)).await;
        assert_eq!(outcome.result, Ok(()));
        assert_eq!(outcome.state, GenerationState::Closed);
        assert!(server.actual_tls13);
        assert!(server.actual_h2);
        assert!(server.no_early_data);
        assert_eq!(outcome.observed_exporter, Some(server.exporter));
        assert_eq!(server.method, Method::POST);
        assert_eq!(server.raw_path, TEST_PATH);
        assert_eq!(server.content_types, vec![AUTH_CONTENT_TYPE.as_bytes()]);
        assert_eq!(server.control_len, AUTH_V3_CLIENT_CONTROL_LEN);
        assert!(server.physical_closed);
        assert!(!server.extra_request_seen);
        assert!(outcome.events.contains(&GenerationEvent::NonceNonzero));

        let request = event_position(&outcome, GenerationEvent::RequestSent);
        let verified = event_position(&outcome, GenerationEvent::ConfirmationVerified);
        let authenticated = event_position(&outcome, GenerationEvent::Authenticated);
        let physical = event_position(
            &outcome,
            GenerationEvent::PhysicalConnectionClosedWithSenderAlive,
        );
        let closed = event_position(&outcome, GenerationEvent::Closed);
        assert!(request < verified);
        assert!(verified < authenticated);
        assert!(authenticated < physical);
        assert!(physical < closed);
    }

    #[tokio::test]
    async fn pre_io_gate_rejects_before_ca_read_or_connect() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let baseline = CONNECT_ATTEMPTS.load(Ordering::Relaxed);
        let missing_ca = Path::new("missing-neutral-ca.pem");
        for (strategy, path, server_name, backend) in [
            ("h3", TEST_PATH, "localhost", DirectV3H2Backend::Rustls),
            ("h2", TEST_PATH, "localhost", DirectV3H2Backend::Other),
            ("h2", "/reference?", "localhost", DirectV3H2Backend::Rustls),
            (
                "h2",
                "/reference#part",
                "localhost",
                DirectV3H2Backend::Rustls,
            ),
            (
                "h2",
                "/not representable",
                "localhost",
                DirectV3H2Backend::Rustls,
            ),
        ] {
            let role = test_role("127.0.0.1:9", server_name, strategy, path, missing_ca, None);
            let outcome = run_direct_v3_h2_reference(role.direct(), backend).await;
            assert_eq!(outcome.result, Err(DirectV3H2Error::PreIoGate));
            assert_eq!(outcome.state, GenerationState::Closed);
            assert_eq!(CONNECT_ATTEMPTS.load(Ordering::Relaxed), baseline);
        }
    }

    #[tokio::test]
    async fn trust_tls_and_alpn_fail_closed_with_fixed_categories() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let identity = TestIdentity::new();
        let unrelated = TestIdentity::new();

        for (ca, pin) in [
            (unrelated.cert_path.as_path(), None),
            (
                identity.cert_path.as_path(),
                Some("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let role = test_role(
                &listener.local_addr().unwrap().to_string(),
                "localhost",
                "h2",
                TEST_PATH,
                ca,
                pin,
            );
            let acceptor = TlsAcceptor::from(Arc::new(
                identity.server_config(&[&rustls::version::TLS13], vec![b"h2".to_vec()]),
            ));
            let server = async move {
                let (tcp, _) = listener.accept().await?;
                let _ = acceptor.accept(tcp).await;
                Ok::<_, anyhow::Error>(())
            };
            let (outcome, server) = tokio::join!(
                run_direct_v3_h2_reference(role.direct(), DirectV3H2Backend::Rustls),
                server,
            );
            server.unwrap();
            assert_eq!(outcome.result, Err(DirectV3H2Error::TlsHandshake));
            assert_eq!(outcome.state, GenerationState::Closed);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let role = test_role(
            &listener.local_addr().unwrap().to_string(),
            "localhost",
            "h2",
            TEST_PATH,
            &identity.cert_path,
            None,
        );
        let acceptor = TlsAcceptor::from(Arc::new(
            identity.server_config(&[&rustls::version::TLS13], Vec::new()),
        ));
        let server = async move {
            let (tcp, _) = listener.accept().await?;
            let mut tls = acceptor.accept(tcp).await?;
            let mut byte = [0u8; 1];
            let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut byte).await;
            Ok::<_, anyhow::Error>(())
        };
        let (outcome, server) = tokio::join!(
            run_direct_v3_h2_reference(role.direct(), DirectV3H2Backend::Rustls),
            server,
        );
        server.unwrap();
        assert_eq!(outcome.result, Err(DirectV3H2Error::ConnectionTrust));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let role = test_role(
            &listener.local_addr().unwrap().to_string(),
            "localhost",
            "h2",
            TEST_PATH,
            &identity.cert_path,
            None,
        );
        let acceptor = TlsAcceptor::from(Arc::new(
            identity.server_config(&[&rustls::version::TLS12], vec![b"h2".to_vec()]),
        ));
        let server = async move {
            let (tcp, _) = listener.accept().await?;
            let _ = acceptor.accept(tcp).await;
            Ok::<_, anyhow::Error>(())
        };
        let (outcome, server) = tokio::join!(
            run_direct_v3_h2_reference(role.direct(), DirectV3H2Backend::Rustls),
            server,
        );
        server.unwrap();
        assert_eq!(outcome.result, Err(DirectV3H2Error::TlsHandshake));
    }

    #[tokio::test]
    async fn response_shape_confirmation_and_exporter_failures_close_generation() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let identity = TestIdentity::new();
        for behavior in [
            ServerBehavior::WrongStatus,
            ServerBehavior::MissingContentType,
            ServerBehavior::DuplicateContentType,
            ServerBehavior::ParameterizedContentType,
            ServerBehavior::Body319,
            ServerBehavior::Body321,
            ServerBehavior::TrailingData,
            ServerBehavior::Trailers,
            ServerBehavior::InvalidMac,
            ServerBehavior::InvalidPolicy,
            ServerBehavior::InvalidExpiry,
            ServerBehavior::ZeroResource,
            ServerBehavior::ExcessiveResource,
            ServerBehavior::WrongExporter(WrongExporter::Label),
            ServerBehavior::WrongExporter(WrongExporter::Context),
            ServerBehavior::WrongExporter(WrongExporter::Generation),
        ] {
            let (outcome, server) = run_case(&identity, behavior, None).await;
            assert_closed_without_authentication(&outcome, &server);
            assert_eq!(outcome.result, Err(DirectV3H2Error::Confirmation));
        }
    }

    #[tokio::test]
    async fn response_header_and_partial_body_stalls_hit_whole_control_deadline() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let identity = TestIdentity::new();
        for behavior in [
            ServerBehavior::NoResponseHeaders,
            ServerBehavior::PartialWithoutEndStream,
        ] {
            let started = tokio::time::Instant::now();
            let (outcome, server) = run_case(&identity, behavior, None).await;
            assert!(started.elapsed() < TEST_BOUND);
            assert_closed_without_authentication(&outcome, &server);
            assert_eq!(outcome.result, Err(DirectV3H2Error::Deadline));
        }
    }

    #[test]
    fn fallible_csprng_output_is_nonzero_and_zero_fails_closed() {
        let nonce = random_nonzero::<32>().expect("OS CSPRNG test nonce");
        assert!(nonce.iter().any(|byte| *byte != 0));
        assert_eq!(
            require_nonzero_random([0u8; 32]),
            Err(DirectV3H2Error::Random)
        );
    }

    #[test]
    fn fixed_errors_are_bounded_value_free_and_source_free() {
        let private_marker = "SYNTHETIC_PRIVATE_MARKER_DO_NOT_ECHO";
        for error in [
            DirectV3H2Error::PreIoGate,
            DirectV3H2Error::TlsConfiguration,
            DirectV3H2Error::Connect,
            DirectV3H2Error::TlsHandshake,
            DirectV3H2Error::ConnectionTrust,
            DirectV3H2Error::H2Handshake,
            DirectV3H2Error::Random,
            DirectV3H2Error::Control,
            DirectV3H2Error::Confirmation,
            DirectV3H2Error::Deadline,
            DirectV3H2Error::Teardown,
        ] {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(display.len() <= 64);
            assert!(debug.len() <= 32);
            assert!(!display.contains(private_marker));
            assert!(!debug.contains(private_marker));
            assert!(std::error::Error::source(&error).is_none());
            assert!(display.chars().all(|character| !character.is_control()));
        }
    }

    #[test]
    fn production_seam_has_no_legacy_pool_listener_or_data_plane_calls() {
        let source = include_str!("direct_v3_h2.rs")
            .split("mod tests")
            .next()
            .expect("production source prefix");
        for forbidden in [
            ["run", "_client"].concat(),
            ["start", "_client"].concat(),
            ["ClientTunnel", "Pool"].concat(),
            ["connection", "_manager"].concat(),
            ["open", "_target"].concat(),
            ["crate::", "relay"].concat(),
            ["crate::", "fallback"].concat(),
            ["crate::", "session"].concat(),
            ["crate::", "tunnel"].concat(),
            ["legacy", " decoder"].concat(),
            ["dns", "_query"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }
}
