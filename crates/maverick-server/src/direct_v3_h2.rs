//! Dormant server-side rustls/direct-H2 auth-v3 control reference.
//!
//! This crate-private seam is not called by the legacy server entry points. It
//! authenticates one control exchange on one physical generation and then
//! returns; it exposes no user-flow or data-plane capability.

use std::fmt;
use std::future::poll_fn;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use http::header::CONTENT_TYPE;
use http::uri::PathAndQuery;
use http::{Method, Request, Response, StatusCode};
use maverick_core::auth_v3::{
    encode_auth_v3_server_confirmation, verify_auth_v3_client_control, AuthV3Carrier,
    AuthV3PreselectedProfile, AuthV3ServerConfirmationInput, AuthV3TlsVersion,
    AUTH_V3_CLIENT_CONTROL_LEN, AUTH_V3_EXPORTER_LABEL, AUTH_V3_EXPORTER_LEN,
    AUTH_V3_SERVER_CONFIRMATION_LEN,
};
use maverick_core::config::{DirectV3ServerRoleConfig, DirectV3TransportStrategy};
use rand::rngs::OsRng;
use rand::TryRngCore;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

const AUTH_CONTENT_TYPE: &str = "application/maverick-auth-v3";
const REFERENCE_IO_TIMEOUT: Duration = Duration::from_secs(5);
const REFERENCE_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const REFERENCE_ADMISSION_LIFETIME_SECONDS: u64 = 60;
const REFERENCE_HARD_LIFETIME_SECONDS: u64 = 300;
const REFERENCE_MAX_FRAME_SIZE: u32 = 65_536;
const REFERENCE_MAX_CONCURRENT_FLOWS: u32 = 1;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
static BIND_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

/// Fixed, bounded, value-free reference failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectV3H2Error {
    PreIoGate,
    TlsConfiguration,
    Listener,
    TlsHandshake,
    ConnectionTrust,
    H2Handshake,
    Control,
    DuplicateControl,
    Random,
    Confirmation,
}

impl fmt::Display for DirectV3H2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PreIoGate => "direct-v3 H2 pre-I/O gate rejected",
            Self::TlsConfiguration => "direct-v3 H2 TLS configuration failed",
            Self::Listener => "direct-v3 H2 listener failed",
            Self::TlsHandshake => "direct-v3 H2 TLS handshake failed",
            Self::ConnectionTrust => "direct-v3 H2 connection trust failed",
            Self::H2Handshake => "direct-v3 H2 handshake failed",
            Self::Control => "direct-v3 H2 control failed",
            Self::DuplicateControl => "direct-v3 H2 control slot consumed",
            Self::Random => "direct-v3 H2 random generation failed",
            Self::Confirmation => "direct-v3 H2 confirmation failed",
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
    ResponseHeadersAccepted,
    ResponseDataAccepted { bytes: usize, end_stream: bool },
    RandomMaterialNonzero,
    Authenticated,
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
            return Err(DirectV3H2Error::DuplicateControl);
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

#[derive(Clone, Copy)]
enum ResponseBehavior {
    Full,
    #[cfg(test)]
    HeadersOnly,
    #[cfg(test)]
    Partial,
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

pub(crate) struct DirectV3H2Reference<'a> {
    config: &'a DirectV3ServerRoleConfig,
    preselected: AuthV3PreselectedProfile<'a>,
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
}

pub(crate) async fn bind_direct_v3_h2_reference(
    config: &DirectV3ServerRoleConfig,
    backend: DirectV3H2Backend,
) -> Result<DirectV3H2Reference<'_>, DirectV3H2Error> {
    validate_pre_io(config, backend)?;
    let preselected = config.preselected_profile();
    let tls_config = Arc::new(build_rustls_config(config)?);
    let listener = bind_listener(config.listen()).await?;
    Ok(DirectV3H2Reference {
        config,
        preselected,
        listener,
        tls_config,
    })
}

fn validate_pre_io(
    config: &DirectV3ServerRoleConfig,
    backend: DirectV3H2Backend,
) -> Result<(), DirectV3H2Error> {
    if backend != DirectV3H2Backend::Rustls
        || config.transport_strategy() != DirectV3TransportStrategy::H2
        || !round_trips_as_raw_h2_path(config.tunnel_path())
    {
        return Err(DirectV3H2Error::PreIoGate);
    }
    Ok(())
}

fn round_trips_as_raw_h2_path(path: &str) -> bool {
    if path.contains(['?', '#']) {
        return false;
    }
    PathAndQuery::try_from(path).is_ok_and(|parsed| {
        parsed.as_str() == path && parsed.query().is_none() && parsed.path() == path
    })
}

fn build_rustls_config(
    config: &DirectV3ServerRoleConfig,
) -> Result<rustls::ServerConfig, DirectV3H2Error> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(config.cert_path())
        .map_err(|_| DirectV3H2Error::TlsConfiguration)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DirectV3H2Error::TlsConfiguration)?;
    if certs.is_empty() {
        return Err(DirectV3H2Error::TlsConfiguration);
    }
    let key = PrivateKeyDer::from_pem_file(config.key_path())
        .map_err(|_| DirectV3H2Error::TlsConfiguration)?;
    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| DirectV3H2Error::TlsConfiguration)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config.max_early_data_size = 0;
    tls_config.send_half_rtt_data = false;
    Ok(tls_config)
}

async fn bind_listener(address: std::net::SocketAddr) -> Result<TcpListener, DirectV3H2Error> {
    #[cfg(test)]
    BIND_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    TcpListener::bind(address)
        .await
        .map_err(|_| DirectV3H2Error::Listener)
}

impl DirectV3H2Reference<'_> {
    pub(crate) fn local_addr(&self) -> Result<std::net::SocketAddr, DirectV3H2Error> {
        self.listener
            .local_addr()
            .map_err(|_| DirectV3H2Error::Listener)
    }

    pub(crate) async fn run_once(self) -> ReferenceOutcome {
        self.run_once_with_behavior(ResponseBehavior::Full).await
    }

    async fn run_once_with_behavior(self, behavior: ResponseBehavior) -> ReferenceOutcome {
        let mut gate = GenerationGate::fresh();
        let mut observed_exporter = None;
        let result = self
            .run_generation(&mut gate, behavior, &mut observed_exporter)
            .await;
        // This seam owns no post-authentication capability. Returning drops
        // the control-only physical generation, so the final state is always
        // Closed even when the authenticated transition occurred.
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

    async fn run_generation(
        self,
        gate: &mut GenerationGate,
        behavior: ResponseBehavior,
        observed_exporter: &mut Option<[u8; AUTH_V3_EXPORTER_LEN]>,
    ) -> Result<(), DirectV3H2Error> {
        let (tcp, _) = timeout(REFERENCE_IO_TIMEOUT, self.listener.accept())
            .await
            .map_err(|_| DirectV3H2Error::Listener)?
            .map_err(|_| DirectV3H2Error::Listener)?;
        tcp.set_nodelay(true)
            .map_err(|_| DirectV3H2Error::Listener)?;
        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
        let mut tls = timeout(REFERENCE_IO_TIMEOUT, acceptor.accept(tcp))
            .await
            .map_err(|_| DirectV3H2Error::TlsHandshake)?
            .map_err(|_| DirectV3H2Error::TlsHandshake)?;
        let exporter = observe_rustls_generation(&mut tls)?;
        *observed_exporter = Some(exporter);
        let connection = self.preselected.trusted_connection_context(
            AuthV3Carrier::H2,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &exporter,
            true,
            Some(&[]),
            self.config.tunnel_path(),
        );

        let mut h2 = timeout(
            REFERENCE_IO_TIMEOUT,
            h2::server::Builder::new()
                .max_concurrent_streams(2)
                .initial_window_size(1024)
                .initial_connection_window_size(2048)
                .handshake(tls),
        )
        .await
        .map_err(|_| DirectV3H2Error::H2Handshake)?
        .map_err(|_| DirectV3H2Error::H2Handshake)?;

        let first = timeout(REFERENCE_IO_TIMEOUT, h2.accept())
            .await
            .map_err(|_| DirectV3H2Error::Control)?
            .ok_or(DirectV3H2Error::Control)?
            .map_err(|_| DirectV3H2Error::Control)?;
        gate.start_authentication()?;

        let control = authenticate_control(
            first.0,
            first.1,
            self.config.tunnel_path(),
            &self.preselected,
            &connection,
            behavior,
        );
        tokio::pin!(control);
        let attempt = tokio::select! {
            biased;
            second = h2.accept() => {
                let _ = second;
                return Err(DirectV3H2Error::DuplicateControl);
            }
            attempt = timeout(REFERENCE_CONTROL_TIMEOUT, &mut control) => {
                attempt.map_err(|_| DirectV3H2Error::Control)?
            }
        };
        #[cfg(test)]
        gate.events.extend(attempt.events);
        attempt.result?;
        gate.authenticate()?;

        // The authenticated event is already fixed at the final successful
        // DATA+END_STREAM queue boundary. Continue polling only to flush that
        // queued control response, then close this control-only reference
        // generation without admitting another stream or user flow.
        h2.graceful_shutdown();
        let _ = timeout(REFERENCE_IO_TIMEOUT, h2.accept()).await;
        Ok(())
    }
}

fn observe_rustls_generation(
    tls: &mut TlsStream<TcpStream>,
) -> Result<[u8; AUTH_V3_EXPORTER_LEN], DirectV3H2Error> {
    let connection = tls.get_mut().1;
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        || connection.alpn_protocol() != Some(b"h2")
        || connection.early_data().is_some()
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

struct ControlAttempt {
    result: Result<(), DirectV3H2Error>,
    #[cfg(test)]
    events: Vec<GenerationEvent>,
}

async fn authenticate_control(
    request: Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    expected_path: &str,
    preselected: &AuthV3PreselectedProfile<'_>,
    connection: &maverick_core::auth_v3::AuthV3TrustedConnectionContext<'_>,
    behavior: ResponseBehavior,
) -> ControlAttempt {
    let result = async {
        validate_request_metadata(&request, expected_path)?;
        let control = collect_control(request.into_body()).await?;
        let now = trusted_now()?;
        let profile = preselected.trusted_profile();
        let verified = verify_auth_v3_client_control(&control, &profile, connection, now)
            .map_err(|_| DirectV3H2Error::Control)?;
        let server_nonce = random_nonzero::<32>()?;
        let session_id = random_nonzero::<16>()?;
        let admission_expiry = now
            .checked_add(REFERENCE_ADMISSION_LIFETIME_SECONDS)
            .ok_or(DirectV3H2Error::Confirmation)?;
        let hard_expiry = now
            .checked_add(REFERENCE_HARD_LIFETIME_SECONDS)
            .ok_or(DirectV3H2Error::Confirmation)?;
        let confirmation = encode_auth_v3_server_confirmation(
            verified,
            connection,
            &AuthV3ServerConfirmationInput::new(
                now,
                admission_expiry,
                hard_expiry,
                server_nonce,
                session_id,
                REFERENCE_MAX_FRAME_SIZE,
                REFERENCE_MAX_CONCURRENT_FLOWS,
            ),
        )
        .map_err(|_| DirectV3H2Error::Confirmation)?;
        Ok(confirmation)
    }
    .await;

    let confirmation = match result {
        Ok(confirmation) => confirmation,
        Err(error) => {
            return ControlAttempt {
                result: Err(error),
                #[cfg(test)]
                events: Vec::new(),
            };
        }
    };
    let attempt = send_confirmation(respond, confirmation, behavior).await;
    #[cfg(test)]
    let mut attempt = attempt;
    #[cfg(test)]
    if attempt.result.is_ok() {
        attempt
            .events
            .insert(0, GenerationEvent::RandomMaterialNonzero);
    }
    attempt
}

fn validate_request_metadata(
    request: &Request<h2::RecvStream>,
    expected_path: &str,
) -> Result<(), DirectV3H2Error> {
    let raw_path_and_query = request.uri().path_and_query().map(PathAndQuery::as_str);
    let mut content_types = request.headers().get_all(CONTENT_TYPE).iter();
    let content_type = content_types.next();
    if request.method() != Method::POST
        || raw_path_and_query != Some(expected_path)
        || request.uri().query().is_some()
        || content_type.is_none_or(|value| value.as_bytes() != AUTH_CONTENT_TYPE.as_bytes())
        || content_types.next().is_some()
    {
        return Err(DirectV3H2Error::Control);
    }
    Ok(())
}

async fn collect_control(
    mut body: h2::RecvStream,
) -> Result<[u8; AUTH_V3_CLIENT_CONTROL_LEN], DirectV3H2Error> {
    let mut collected = BytesMut::with_capacity(AUTH_V3_CLIENT_CONTROL_LEN + 1);
    while let Some(data) = body.data().await {
        let data = data.map_err(|_| DirectV3H2Error::Control)?;
        let remaining = AUTH_V3_CLIENT_CONTROL_LEN + 1 - collected.len();
        let copy_len = remaining.min(data.len());
        collected.extend_from_slice(&data[..copy_len]);
        if collected.len() > AUTH_V3_CLIENT_CONTROL_LEN || data.len() > remaining {
            return Err(DirectV3H2Error::Control);
        }
        body.flow_control()
            .release_capacity(data.len())
            .map_err(|_| DirectV3H2Error::Control)?;
    }
    if body
        .trailers()
        .await
        .map_err(|_| DirectV3H2Error::Control)?
        .is_some()
        || collected.len() != AUTH_V3_CLIENT_CONTROL_LEN
    {
        return Err(DirectV3H2Error::Control);
    }
    collected
        .as_ref()
        .try_into()
        .map_err(|_| DirectV3H2Error::Control)
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
    if output.iter().all(|byte| *byte == 0) {
        return Err(DirectV3H2Error::Random);
    }
    Ok(output)
}

struct ConfirmationProgress {
    headers_accepted: bool,
    accepted_body_bytes: usize,
    ended: bool,
}

impl ConfirmationProgress {
    fn new() -> Self {
        Self {
            headers_accepted: false,
            accepted_body_bytes: 0,
            ended: false,
        }
    }

    fn accept_headers(&mut self) {
        self.headers_accepted = true;
    }

    fn accept_data(&mut self, bytes: usize, end_stream: bool) -> Result<(), DirectV3H2Error> {
        if !self.headers_accepted || self.ended {
            return Err(DirectV3H2Error::Confirmation);
        }
        self.accepted_body_bytes = self
            .accepted_body_bytes
            .checked_add(bytes)
            .ok_or(DirectV3H2Error::Confirmation)?;
        if self.accepted_body_bytes > AUTH_V3_SERVER_CONFIRMATION_LEN
            || (end_stream && self.accepted_body_bytes != AUTH_V3_SERVER_CONFIRMATION_LEN)
        {
            return Err(DirectV3H2Error::Confirmation);
        }
        self.ended = end_stream;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.headers_accepted
            && self.accepted_body_bytes == AUTH_V3_SERVER_CONFIRMATION_LEN
            && self.ended
    }
}

async fn send_confirmation(
    mut respond: SendResponse<Bytes>,
    confirmation: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
    behavior: ResponseBehavior,
) -> ControlAttempt {
    #[cfg(test)]
    let mut events = Vec::new();
    let response = match Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, AUTH_CONTENT_TYPE)
        .body(())
    {
        Ok(response) => response,
        Err(_) => {
            return ControlAttempt {
                result: Err(DirectV3H2Error::Confirmation),
                #[cfg(test)]
                events,
            };
        }
    };
    let mut send = match respond.send_response(response, false) {
        Ok(send) => send,
        Err(_) => {
            return ControlAttempt {
                result: Err(DirectV3H2Error::Confirmation),
                #[cfg(test)]
                events,
            };
        }
    };
    let mut progress = ConfirmationProgress::new();
    progress.accept_headers();
    #[cfg(test)]
    events.push(GenerationEvent::ResponseHeadersAccepted);

    #[cfg(test)]
    if matches!(behavior, ResponseBehavior::HeadersOnly) {
        return ControlAttempt {
            result: Err(DirectV3H2Error::Confirmation),
            events,
        };
    }

    let send_len = match behavior {
        ResponseBehavior::Full => AUTH_V3_SERVER_CONFIRMATION_LEN,
        #[cfg(test)]
        ResponseBehavior::Partial => 64,
        #[cfg(test)]
        ResponseBehavior::HeadersOnly => unreachable!("handled before body send"),
    };
    let mut offset = 0;
    while offset < send_len {
        let remaining = send_len - offset;
        send.reserve_capacity(remaining);
        while send.capacity() == 0 {
            match poll_fn(|context| send.poll_capacity(context)).await {
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    return ControlAttempt {
                        result: Err(DirectV3H2Error::Confirmation),
                        #[cfg(test)]
                        events,
                    };
                }
            }
        }
        let accepted = remaining.min(send.capacity());
        let end_stream = matches!(behavior, ResponseBehavior::Full)
            && offset + accepted == AUTH_V3_SERVER_CONFIRMATION_LEN;
        let data = Bytes::copy_from_slice(&confirmation[offset..offset + accepted]);
        if send.send_data(data, end_stream).is_err()
            || progress.accept_data(accepted, end_stream).is_err()
        {
            return ControlAttempt {
                result: Err(DirectV3H2Error::Confirmation),
                #[cfg(test)]
                events,
            };
        }
        #[cfg(test)]
        events.push(GenerationEvent::ResponseDataAccepted {
            bytes: accepted,
            end_stream,
        });
        offset += accepted;
    }

    let result = if progress.complete() {
        Ok(())
    } else {
        Err(DirectV3H2Error::Confirmation)
    };
    ControlAttempt {
        result,
        #[cfg(test)]
        events,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use anyhow::{Context, Result};
    use h2::client::{ResponseFuture, SendRequest};
    use http::{HeaderMap, HeaderValue};
    use maverick_core::auth_v3::{
        encode_auth_v3_client_control, verify_auth_v3_server_confirmation,
        AuthV3ClientControlInput, AuthV3ClientReceipt,
    };
    use maverick_core::config::ServerRoleConfig;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsConnector;

    const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const TEST_PATH: &str = "/reference-auth-v3";
    const STALL_TEST_TIMEOUT: Duration = Duration::from_secs(5);
    static TEST_NETWORK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TestRole {
        _directory: TempDir,
        role: ServerRoleConfig,
        certificate: CertificateDer<'static>,
    }

    struct ClientGeneration {
        sender: Option<SendRequest<Bytes>>,
        driver: JoinHandle<()>,
        exporter: [u8; AUTH_V3_EXPORTER_LEN],
        wrong_label_exporter: [u8; AUTH_V3_EXPORTER_LEN],
        observed_tls13: bool,
        observed_h2: bool,
        observed_no_early_data: bool,
    }

    struct PositiveClientResult {
        exporter: [u8; AUTH_V3_EXPORTER_LEN],
        driver_closed: bool,
        later_stream_failed: bool,
        sender_alive_at_driver_close: bool,
    }

    fn test_role(strategy: &str, path: &str, credential_lifetime: u64) -> TestRole {
        let directory = TempDir::new().expect("create neutral test directory");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate loopback certificate");
        std::fs::write(&cert_path, certified.cert.pem()).expect("write loopback certificate");
        std::fs::write(&key_path, certified.key_pair.serialize_pem())
            .expect("write loopback private key");
        let now = trusted_now().expect("read test clock");
        let yaml = server_yaml(
            strategy,
            path,
            &cert_path,
            &key_path,
            now.checked_add(credential_lifetime)
                .expect("test credential expiry"),
        );
        let role = ServerRoleConfig::from_yaml_str(&yaml).expect("parse test server role");
        TestRole {
            _directory: directory,
            role,
            certificate: certified.cert.der().clone(),
        }
    }

    fn server_yaml(
        strategy: &str,
        path: &str,
        cert_path: &Path,
        key_path: &Path,
        not_after: u64,
    ) -> String {
        format!(
            r#"version: 3
role: server
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
listen: "127.0.0.1:0"
tls:
  cert_path: "{}"
  key_path: "{}"
maverick:
  tunnel_path: "{path}"
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
            cert_path.display(),
            key_path.display(),
        )
    }

    fn direct_config(role: &TestRole) -> &DirectV3ServerRoleConfig {
        role.role
            .direct_v3()
            .expect("test role must be config schema 3")
    }

    async fn connect_client(
        address: std::net::SocketAddr,
        certificate: CertificateDer<'static>,
        initial_window_size: Option<u32>,
    ) -> Result<ClientGeneration> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate).context("add loopback trust root")?;
        let mut tls_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        tls_config.enable_early_data = false;
        let tcp = TcpStream::connect(address)
            .await
            .context("connect loopback reference")?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from("localhost").context("server name")?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("connect loopback TLS")?;
        let observed_tls13 =
            tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
        let observed_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let observed_no_early_data = !tls.get_ref().1.is_early_data_accepted();
        let exporter = tls
            .get_ref()
            .1
            .export_keying_material(
                [0u8; AUTH_V3_EXPORTER_LEN],
                AUTH_V3_EXPORTER_LABEL,
                Some(&[]),
            )
            .context("derive test exporter")?;
        let wrong_label_exporter = tls
            .get_ref()
            .1
            .export_keying_material(
                [0u8; AUTH_V3_EXPORTER_LEN],
                b"EXPORTER-Wrong-Reference-Label",
                Some(&[]),
            )
            .context("derive wrong-label test exporter")?;
        let mut builder = h2::client::Builder::new();
        if let Some(size) = initial_window_size {
            builder.initial_window_size(size);
        }
        let (sender, connection) = builder
            .handshake(tls)
            .await
            .context("client H2 handshake")?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(ClientGeneration {
            sender: Some(sender),
            driver,
            exporter,
            wrong_label_exporter,
            observed_tls13,
            observed_h2,
            observed_no_early_data,
        })
    }

    fn client_control(
        config: &DirectV3ServerRoleConfig,
        exporter: &[u8; AUTH_V3_EXPORTER_LEN],
        exporter_context: Option<&[u8]>,
        client_nonce: [u8; 32],
    ) -> [u8; AUTH_V3_CLIENT_CONTROL_LEN] {
        let preselected = config.preselected_profile();
        let connection = preselected.trusted_connection_context(
            AuthV3Carrier::H2,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            exporter,
            true,
            exporter_context,
            config.tunnel_path(),
        );
        encode_auth_v3_client_control(
            &preselected.trusted_profile(),
            &connection,
            &AuthV3ClientControlInput::new(
                AuthV3Carrier::H2,
                trusted_now().expect("read client clock"),
                client_nonce,
            ),
        )
        .expect("encode test ClientControl")
    }

    async fn start_request(
        generation: &mut ClientGeneration,
        method: Method,
        raw_path_and_query: &str,
        content_types: &[&str],
    ) -> Result<(ResponseFuture, h2::SendStream<Bytes>)> {
        let uri = format!("https://localhost{raw_path_and_query}");
        let mut request = Request::builder().method(method).uri(uri).body(())?;
        for value in content_types {
            request.headers_mut().append(
                CONTENT_TYPE,
                HeaderValue::from_str(value).context("test content type")?,
            );
        }
        let sender = generation
            .sender
            .take()
            .expect("client sender present")
            .ready()
            .await
            .context("client sender ready")?;
        generation.sender = Some(sender);
        generation
            .sender
            .as_mut()
            .expect("client sender restored")
            .send_request(request, false)
            .context("send control headers")
    }

    async fn send_body(
        stream: &mut h2::SendStream<Bytes>,
        chunks: &[&[u8]],
        trailers: Option<HeaderMap>,
    ) -> Result<()> {
        for (index, chunk) in chunks.iter().enumerate() {
            let end_stream = index + 1 == chunks.len() && trailers.is_none();
            stream
                .send_data(Bytes::copy_from_slice(chunk), end_stream)
                .context("send control DATA")?;
        }
        if let Some(trailers) = trailers {
            stream
                .send_trailers(trailers)
                .context("send control trailers")?;
        }
        Ok(())
    }

    async fn positive_client(
        address: std::net::SocketAddr,
        certificate: CertificateDer<'static>,
        config: &DirectV3ServerRoleConfig,
    ) -> Result<PositiveClientResult> {
        let mut generation = connect_client(address, certificate, None).await?;
        assert!(generation.observed_tls13);
        assert!(generation.observed_h2);
        assert!(generation.observed_no_early_data);
        let control = client_control(config, &generation.exporter, Some(&[]), [0x71; 32]);
        let (response, mut request_body) = start_request(
            &mut generation,
            Method::POST,
            config.tunnel_path(),
            &[AUTH_CONTENT_TYPE],
        )
        .await?;
        send_body(&mut request_body, &[&control[..97], &control[97..]], None).await?;
        let mut response = response.await.context("receive confirmation headers")?;
        assert_eq!(response.status(), StatusCode::OK);
        let content_types: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
        assert_eq!(content_types.len(), 1);
        assert_eq!(content_types[0].as_bytes(), AUTH_CONTENT_TYPE.as_bytes());
        let mut confirmation = BytesMut::new();
        while let Some(data) = response.body_mut().data().await {
            let data = data.context("receive confirmation DATA")?;
            confirmation.extend_from_slice(&data);
        }
        assert!(response.body_mut().trailers().await?.is_none());
        assert_eq!(confirmation.len(), AUTH_V3_SERVER_CONFIRMATION_LEN);
        let preselected = config.preselected_profile();
        let connection = preselected.trusted_connection_context(
            AuthV3Carrier::H2,
            AuthV3TlsVersion::Tls13,
            true,
            false,
            &generation.exporter,
            true,
            Some(&[]),
            config.tunnel_path(),
        );
        verify_auth_v3_server_confirmation(
            &confirmation,
            &control,
            &preselected.trusted_profile(),
            &connection,
            &AuthV3ClientReceipt::new(
                trusted_now().expect("read receipt clock"),
                REFERENCE_MAX_FRAME_SIZE,
                REFERENCE_MAX_CONCURRENT_FLOWS,
            ),
        )
        .expect("verify complete ServerConfirmation");
        assert!(generation.sender.is_some());
        let driver_closed = matches!(
            timeout(REFERENCE_IO_TIMEOUT, &mut generation.driver).await,
            Ok(Ok(()))
        );
        let sender_alive_at_driver_close = generation.sender.is_some();
        let later_stream_failed = follow_up_stream_fails_with_sender_alive(&mut generation).await;
        Ok(PositiveClientResult {
            exporter: generation.exporter,
            driver_closed,
            later_stream_failed,
            sender_alive_at_driver_close,
        })
    }

    #[tokio::test]
    async fn real_loopback_authenticates_only_after_complete_confirmation_send() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind reference");
        assert_eq!(reference.tls_config.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(reference.tls_config.max_early_data_size, 0);
        assert!(!reference.tls_config.send_half_rtt_data);
        let address = reference.local_addr().expect("reference address");
        let (outcome, client) = tokio::join!(
            reference.run_once(),
            positive_client(address, role.certificate.clone(), config)
        );
        let client = client.expect("positive client exchange");
        assert_eq!(outcome.result, Ok(()));
        assert_eq!(outcome.state, GenerationState::Closed);
        assert!(client.driver_closed);
        assert!(client.later_stream_failed);
        assert!(client.sender_alive_at_driver_close);
        assert!(outcome.observed_exporter.is_some());
        assert!(outcome.observed_exporter == Some(client.exporter));
        assert!(outcome
            .events
            .contains(&GenerationEvent::RandomMaterialNonzero));
        let final_send = outcome
            .events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    GenerationEvent::ResponseDataAccepted {
                        end_stream: true,
                        ..
                    }
                )
            })
            .expect("final confirmation send event");
        let authenticated = outcome
            .events
            .iter()
            .position(|event| *event == GenerationEvent::Authenticated)
            .expect("authenticated event");
        let closed = outcome
            .events
            .iter()
            .position(|event| *event == GenerationEvent::Closed)
            .expect("closed event");
        assert!(final_send < authenticated);
        assert!(authenticated < closed);
        assert_eq!(outcome.events.last(), Some(&GenerationEvent::Closed));
        let total: usize = outcome
            .events
            .iter()
            .filter_map(|event| match event {
                GenerationEvent::ResponseDataAccepted { bytes, .. } => Some(*bytes),
                _ => None,
            })
            .sum();
        assert_eq!(total, AUTH_V3_SERVER_CONFIRMATION_LEN);
    }

    #[tokio::test]
    async fn pre_io_gate_rejects_carrier_backend_and_raw_path_before_bind() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let baseline = BIND_ATTEMPTS.load(Ordering::Relaxed);
        for (strategy, path, backend) in [
            ("h3", TEST_PATH, DirectV3H2Backend::Rustls),
            ("h2", TEST_PATH, DirectV3H2Backend::Other),
            ("h2", "/reference?", DirectV3H2Backend::Rustls),
            ("h2", "/reference#part", DirectV3H2Backend::Rustls),
            ("h2", "/not representable", DirectV3H2Backend::Rustls),
        ] {
            let role = test_role(strategy, path, 3_600);
            let error = bind_direct_v3_h2_reference(direct_config(&role), backend)
                .await
                .err()
                .expect("pre-I/O rejection");
            assert_eq!(error, DirectV3H2Error::PreIoGate);
            assert_eq!(BIND_ATTEMPTS.load(Ordering::Relaxed), baseline);
        }
    }

    #[test]
    fn confirmation_progress_requires_exact_final_end_stream_success() {
        let mut headers_only = ConfirmationProgress::new();
        headers_only.accept_headers();
        assert!(!headers_only.complete());

        let mut partial = ConfirmationProgress::new();
        partial.accept_headers();
        partial.accept_data(64, false).unwrap();
        assert!(!partial.complete());
        assert_eq!(
            partial.accept_data(0, true),
            Err(DirectV3H2Error::Confirmation)
        );

        let mut overlong = ConfirmationProgress::new();
        overlong.accept_headers();
        assert_eq!(
            overlong.accept_data(AUTH_V3_SERVER_CONFIRMATION_LEN + 1, true),
            Err(DirectV3H2Error::Confirmation)
        );

        let mut complete = ConfirmationProgress::new();
        complete.accept_headers();
        complete.accept_data(128, false).unwrap();
        complete
            .accept_data(AUTH_V3_SERVER_CONFIRMATION_LEN - 128, true)
            .unwrap();
        assert!(complete.complete());
    }

    #[test]
    fn fixed_errors_and_debug_are_bounded_and_value_free() {
        let private_marker = "SYNTHETIC_PRIVATE_MARKER_DO_NOT_ECHO";
        for error in [
            DirectV3H2Error::PreIoGate,
            DirectV3H2Error::TlsConfiguration,
            DirectV3H2Error::Listener,
            DirectV3H2Error::TlsHandshake,
            DirectV3H2Error::ConnectionTrust,
            DirectV3H2Error::H2Handshake,
            DirectV3H2Error::Control,
            DirectV3H2Error::DuplicateControl,
            DirectV3H2Error::Random,
            DirectV3H2Error::Confirmation,
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
    fn production_seam_has_no_legacy_or_data_plane_calls() {
        let source = include_str!("direct_v3_h2.rs")
            .split("mod tests")
            .next()
            .expect("production source prefix");
        let forbidden = [
            ["User", "Store"].concat(),
            ["lookup", "_secret"].concat(),
            ["lookup", "_credential"].concat(),
            ["open", "_target"].concat(),
            ["crate::", "relay"].concat(),
            ["crate::", "fallback"].concat(),
            ["legacy", " decoder"].concat(),
            ["dns", "_query"].concat(),
        ];
        for value in forbidden {
            assert!(!source.contains(&value));
        }
    }

    #[derive(Clone, Copy)]
    enum ControlKind {
        Correct,
        InvalidMac,
        InvalidPolicy,
        WrongLabelExporter,
        ReplacementExporter([u8; AUTH_V3_EXPORTER_LEN]),
    }

    #[derive(Clone, Copy)]
    enum BodyKind {
        Exact,
        Truncated,
        Overlong,
        TrailingChunk,
        Trailers,
    }

    struct FailureCase {
        method: Method,
        raw_path_and_query: String,
        content_types: Vec<&'static str>,
        control: ControlKind,
        body: BodyKind,
    }

    impl FailureCase {
        fn valid() -> Self {
            Self {
                method: Method::POST,
                raw_path_and_query: TEST_PATH.to_owned(),
                content_types: vec![AUTH_CONTENT_TYPE],
                control: ControlKind::Correct,
                body: BodyKind::Exact,
            }
        }
    }

    struct FailureClientResult {
        canonical_success: bool,
        later_stream_failed: bool,
        driver_closed: bool,
        sender_alive_at_driver_close: bool,
    }

    async fn received_response_is_canonical(mut response: Response<h2::RecvStream>) -> bool {
        if response.status() != StatusCode::OK {
            return false;
        }
        let content_types: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
        if content_types.len() != 1 || content_types[0].as_bytes() != AUTH_CONTENT_TYPE.as_bytes() {
            return false;
        }
        let mut length = 0usize;
        while let Some(data) = response.body_mut().data().await {
            let data = match data {
                Ok(data) => data,
                Err(_) => return false,
            };
            length = match length.checked_add(data.len()) {
                Some(length) => length,
                None => return false,
            };
        }
        matches!(response.body_mut().trailers().await, Ok(None))
            && length == AUTH_V3_SERVER_CONFIRMATION_LEN
    }

    async fn response_is_canonical(response: ResponseFuture) -> bool {
        timeout(REFERENCE_IO_TIMEOUT, async move {
            let response = match response.await {
                Ok(response) => response,
                Err(_) => return false,
            };
            received_response_is_canonical(response).await
        })
        .await
        .unwrap_or(false)
    }

    async fn follow_up_stream_fails_with_sender_alive(generation: &mut ClientGeneration) -> bool {
        let sender = generation
            .sender
            .as_mut()
            .expect("client SendRequest guard must remain alive");
        let failed = match timeout(
            REFERENCE_IO_TIMEOUT,
            poll_fn(|context| sender.poll_ready(context)),
        )
        .await
        {
            Err(_) | Ok(Err(_)) => true,
            Ok(Ok(())) => {
                let request = Request::builder()
                    .method(Method::POST)
                    .uri(format!("https://localhost{TEST_PATH}"))
                    .header(CONTENT_TYPE, AUTH_CONTENT_TYPE)
                    .body(())
                    .expect("build follow-up request");
                match sender.send_request(request, true) {
                    Err(_) => true,
                    Ok((response, _)) => {
                        !matches!(timeout(REFERENCE_IO_TIMEOUT, response).await, Ok(Ok(_)))
                    }
                }
            }
        };
        assert!(generation.sender.is_some());
        failed
    }

    async fn later_stream_and_driver_close(
        generation: &mut ClientGeneration,
    ) -> (bool, bool, bool) {
        assert!(generation.sender.is_some());
        let driver_closed = matches!(
            timeout(REFERENCE_IO_TIMEOUT, &mut generation.driver).await,
            Ok(Ok(()))
        );
        let sender_alive_at_driver_close = generation.sender.is_some();
        let later_stream_failed = follow_up_stream_fails_with_sender_alive(generation).await;
        (
            later_stream_failed,
            driver_closed,
            sender_alive_at_driver_close,
        )
    }

    async fn failure_client(
        address: std::net::SocketAddr,
        certificate: CertificateDer<'static>,
        config: &DirectV3ServerRoleConfig,
        case: FailureCase,
    ) -> Result<FailureClientResult> {
        let mut generation = connect_client(address, certificate, None).await?;
        let exporter = match case.control {
            ControlKind::Correct | ControlKind::InvalidMac | ControlKind::InvalidPolicy => {
                generation.exporter
            }
            ControlKind::WrongLabelExporter => generation.wrong_label_exporter,
            ControlKind::ReplacementExporter(exporter) => exporter,
        };
        let mut control = client_control(config, &exporter, Some(&[]), [0x72; 32]);
        match case.control {
            ControlKind::InvalidMac => control[AUTH_V3_CLIENT_CONTROL_LEN - 1] ^= 1,
            ControlKind::InvalidPolicy => control[12] ^= 1,
            _ => {}
        }
        let content_types: Vec<_> = case.content_types.to_vec();
        let (response, mut request_body) = start_request(
            &mut generation,
            case.method,
            &case.raw_path_and_query,
            &content_types,
        )
        .await?;
        let mut body = control.to_vec();
        match case.body {
            BodyKind::Exact | BodyKind::TrailingChunk | BodyKind::Trailers => {}
            BodyKind::Truncated => {
                body.pop();
            }
            BodyKind::Overlong => body.push(0),
        }
        let trailers = matches!(case.body, BodyKind::Trailers).then(HeaderMap::new);
        let trailing = [0u8; 1];
        let chunks = if matches!(case.body, BodyKind::TrailingChunk) {
            vec![body.as_slice(), trailing.as_slice()]
        } else {
            vec![body.as_slice()]
        };
        let _ = send_body(&mut request_body, &chunks, trailers).await;
        let canonical_success = response_is_canonical(response).await;
        let (later_stream_failed, driver_closed, sender_alive_at_driver_close) =
            later_stream_and_driver_close(&mut generation).await;
        Ok(FailureClientResult {
            canonical_success,
            later_stream_failed,
            driver_closed,
            sender_alive_at_driver_close,
        })
    }

    fn assert_closed_outcome(outcome: &ReferenceOutcome, client: &FailureClientResult) {
        assert!(outcome.result.is_err());
        assert_eq!(outcome.state, GenerationState::Closed);
        assert!(!outcome.events.contains(&GenerationEvent::Authenticated));
        assert!(!client.canonical_success);
        assert!(client.later_stream_failed);
        assert!(client.driver_closed);
        assert!(client.sender_alive_at_driver_close);
        assert_eq!(
            outcome
                .events
                .iter()
                .filter(|event| **event == GenerationEvent::Authenticating)
                .count(),
            1
        );
        assert_eq!(outcome.events.last(), Some(&GenerationEvent::Closed));
    }

    async fn run_failure_case(
        role: &TestRole,
        case: FailureCase,
        behavior: ResponseBehavior,
    ) -> (ReferenceOutcome, FailureClientResult) {
        let config = direct_config(role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind failure reference");
        let address = reference.local_addr().expect("failure reference address");
        let (outcome, client) = tokio::join!(
            reference.run_once_with_behavior(behavior),
            failure_client(address, role.certificate.clone(), config, case)
        );
        (outcome, client.expect("run failure client"))
    }

    async fn partial_body_stall_client(
        address: std::net::SocketAddr,
        certificate: CertificateDer<'static>,
        config: &DirectV3ServerRoleConfig,
    ) -> Result<FailureClientResult> {
        let mut generation = connect_client(address, certificate, None).await?;
        let control = client_control(config, &generation.exporter, Some(&[]), [0x77; 32]);
        let (response, mut request_body) = start_request(
            &mut generation,
            Method::POST,
            TEST_PATH,
            &[AUTH_CONTENT_TYPE],
        )
        .await?;
        request_body
            .send_data(Bytes::copy_from_slice(&control[..1]), false)
            .context("hold partial control body without END_STREAM")?;
        assert!(generation.sender.is_some());
        let driver_closed = (&mut generation.driver).await.is_ok();
        let sender_alive_at_driver_close = generation.sender.is_some();
        let _held_stream = request_body.stream_id();
        let canonical_success = response_is_canonical(response).await;
        let later_stream_failed = follow_up_stream_fails_with_sender_alive(&mut generation).await;
        Ok(FailureClientResult {
            canonical_success,
            later_stream_failed,
            driver_closed,
            sender_alive_at_driver_close,
        })
    }

    async fn zero_response_window_stall_client(
        address: std::net::SocketAddr,
        certificate: CertificateDer<'static>,
        config: &DirectV3ServerRoleConfig,
    ) -> Result<FailureClientResult> {
        let mut generation = connect_client(address, certificate, Some(0)).await?;
        let control = client_control(config, &generation.exporter, Some(&[]), [0x78; 32]);
        let (response, mut request_body) = start_request(
            &mut generation,
            Method::POST,
            TEST_PATH,
            &[AUTH_CONTENT_TYPE],
        )
        .await?;
        send_body(&mut request_body, &[&control], None).await?;
        let response = response
            .await
            .context("receive confirmation headers while window remains zero")?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(generation.sender.is_some());
        let driver_closed = (&mut generation.driver).await.is_ok();
        let sender_alive_at_driver_close = generation.sender.is_some();
        let _held_stream = request_body.stream_id();
        let canonical_success = received_response_is_canonical(response).await;
        let later_stream_failed = follow_up_stream_fails_with_sender_alive(&mut generation).await;
        Ok(FailureClientResult {
            canonical_success,
            later_stream_failed,
            driver_closed,
            sender_alive_at_driver_close,
        })
    }

    fn assert_control_deadline(outcome: &ReferenceOutcome, client: &FailureClientResult) {
        assert_closed_outcome(outcome, client);
        assert_eq!(outcome.result, Err(DirectV3H2Error::Control));
        let error = outcome.result.expect_err("stalled control must fail");
        assert_eq!(error.to_string(), "direct-v3 H2 control failed");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[tokio::test]
    async fn partial_body_without_end_stream_hits_control_deadline() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind partial-body stall reference");
        let address = reference.local_addr().expect("partial-body address");
        let started = tokio::time::Instant::now();
        let (outcome, client) = timeout(STALL_TEST_TIMEOUT, async {
            tokio::join!(
                reference.run_once(),
                partial_body_stall_client(address, role.certificate.clone(), config)
            )
        })
        .await
        .expect("partial-body stall must close within the test bound");
        assert!(started.elapsed() < STALL_TEST_TIMEOUT);
        assert_control_deadline(&outcome, &client.expect("partial-body stall client"));
    }

    #[tokio::test]
    async fn zero_response_window_hits_control_deadline_without_client_reset() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind zero-window stall reference");
        let address = reference.local_addr().expect("zero-window address");
        let started = tokio::time::Instant::now();
        let (outcome, client) = timeout(STALL_TEST_TIMEOUT, async {
            tokio::join!(
                reference.run_once(),
                zero_response_window_stall_client(address, role.certificate.clone(), config)
            )
        })
        .await
        .expect("zero-window stall must close within the test bound");
        assert!(started.elapsed() < STALL_TEST_TIMEOUT);
        assert_control_deadline(&outcome, &client.expect("zero-window stall client"));
    }

    #[tokio::test]
    async fn request_shape_auth_policy_and_expiry_failures_close_generation() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let mut cases = Vec::new();

        let mut wrong_method = FailureCase::valid();
        wrong_method.method = Method::GET;
        cases.push(wrong_method);

        let mut wrong_path = FailureCase::valid();
        wrong_path.raw_path_and_query = "/other-control".to_owned();
        cases.push(wrong_path);

        let mut query = FailureCase::valid();
        query.raw_path_and_query = format!("{TEST_PATH}?value=1");
        cases.push(query);

        let mut empty_query = FailureCase::valid();
        empty_query.raw_path_and_query = format!("{TEST_PATH}?");
        cases.push(empty_query);

        let mut missing_content_type = FailureCase::valid();
        missing_content_type.content_types.clear();
        cases.push(missing_content_type);

        let mut duplicate_content_type = FailureCase::valid();
        duplicate_content_type.content_types = vec![AUTH_CONTENT_TYPE, AUTH_CONTENT_TYPE];
        cases.push(duplicate_content_type);

        let mut parameterized_content_type = FailureCase::valid();
        parameterized_content_type.content_types = vec!["application/maverick-auth-v3; v=3"];
        cases.push(parameterized_content_type);

        let mut truncated = FailureCase::valid();
        truncated.body = BodyKind::Truncated;
        cases.push(truncated);

        let mut overlong = FailureCase::valid();
        overlong.body = BodyKind::Overlong;
        cases.push(overlong);

        let mut trailing_chunk = FailureCase::valid();
        trailing_chunk.body = BodyKind::TrailingChunk;
        cases.push(trailing_chunk);

        let mut trailers = FailureCase::valid();
        trailers.body = BodyKind::Trailers;
        cases.push(trailers);

        let mut invalid_mac = FailureCase::valid();
        invalid_mac.control = ControlKind::InvalidMac;
        cases.push(invalid_mac);

        let mut invalid_policy = FailureCase::valid();
        invalid_policy.control = ControlKind::InvalidPolicy;
        cases.push(invalid_policy);

        for case in cases {
            let role = test_role("h2", TEST_PATH, 3_600);
            let (outcome, client) = run_failure_case(&role, case, ResponseBehavior::Full).await;
            assert_closed_outcome(&outcome, &client);
        }

        let short_credential = test_role("h2", TEST_PATH, 120);
        let (outcome, client) = run_failure_case(
            &short_credential,
            FailureCase::valid(),
            ResponseBehavior::Full,
        )
        .await;
        assert_closed_outcome(&outcome, &client);
        assert_eq!(outcome.result, Err(DirectV3H2Error::Confirmation));
    }

    #[tokio::test]
    async fn wrong_exporter_label_fails_closed() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let mut case = FailureCase::valid();
        case.control = ControlKind::WrongLabelExporter;
        let (outcome, client) = run_failure_case(&role, case, ResponseBehavior::Full).await;
        assert_closed_outcome(&outcome, &client);
        assert_eq!(outcome.result, Err(DirectV3H2Error::Control));
    }

    #[test]
    fn untrusted_runtime_facts_fail_frozen_primitive() {
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let exporter = [0x61; AUTH_V3_EXPORTER_LEN];
        let input = AuthV3ClientControlInput::new(
            AuthV3Carrier::H2,
            trusted_now().expect("read test clock"),
            [0x62; 32],
        );
        for (tls_version, direct, early_data, same_generation, context) in [
            (AuthV3TlsVersion::Tls13, true, false, true, None),
            (
                AuthV3TlsVersion::Tls13,
                true,
                false,
                true,
                Some(b"not-empty".as_slice()),
            ),
            (AuthV3TlsVersion::Other, true, false, true, Some(&[])),
            (AuthV3TlsVersion::Tls13, false, false, true, Some(&[])),
            (AuthV3TlsVersion::Tls13, true, true, true, Some(&[])),
            (AuthV3TlsVersion::Tls13, true, false, false, Some(&[])),
        ] {
            let preselected = config.preselected_profile();
            let connection = preselected.trusted_connection_context(
                AuthV3Carrier::H2,
                tls_version,
                direct,
                early_data,
                &exporter,
                same_generation,
                context,
                config.tunnel_path(),
            );
            assert!(matches!(
                encode_auth_v3_client_control(&preselected.trusted_profile(), &connection, &input,),
                Err(maverick_core::auth_v3::AuthV3Error::Context)
            ));
        }
    }

    #[tokio::test]
    async fn replacement_generation_exporter_is_rejected() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role_a = test_role("h2", TEST_PATH, 3_600);
        let role_b = test_role("h2", TEST_PATH, 3_600);
        let config_a = direct_config(&role_a);
        let config_b = direct_config(&role_b);
        let reference_a = bind_direct_v3_h2_reference(config_a, DirectV3H2Backend::Rustls)
            .await
            .expect("bind first generation");
        let reference_b = bind_direct_v3_h2_reference(config_b, DirectV3H2Backend::Rustls)
            .await
            .expect("bind replacement generation");
        let address_a = reference_a.local_addr().expect("first generation address");
        let address_b = reference_b
            .local_addr()
            .expect("replacement generation address");
        let client = async {
            let mut generation_a =
                connect_client(address_a, role_a.certificate.clone(), None).await?;
            let replacement_exporter = generation_a.exporter;
            let mut generation_b =
                connect_client(address_b, role_b.certificate.clone(), None).await?;
            let mut case = FailureCase::valid();
            case.control = ControlKind::ReplacementExporter(replacement_exporter);
            let exporter = match case.control {
                ControlKind::ReplacementExporter(exporter) => exporter,
                _ => unreachable!(),
            };
            let control = client_control(config_b, &exporter, Some(&[]), [0x74; 32]);
            let (response, mut body) = start_request(
                &mut generation_b,
                Method::POST,
                TEST_PATH,
                &[AUTH_CONTENT_TYPE],
            )
            .await?;
            let _ = send_body(&mut body, &[&control], None).await;
            let canonical_success = response_is_canonical(response).await;
            let (later_stream_failed, driver_closed, sender_alive_at_driver_close) =
                later_stream_and_driver_close(&mut generation_b).await;
            let (close_response, mut close_body) = start_request(
                &mut generation_a,
                Method::POST,
                "/other-control",
                &[AUTH_CONTENT_TYPE],
            )
            .await?;
            close_body
                .send_data(Bytes::new(), true)
                .context("finish invalid replacement-source control")?;
            assert!(!response_is_canonical(close_response).await);
            assert!(generation_a.sender.is_some());
            let first_driver_closed = matches!(
                timeout(REFERENCE_IO_TIMEOUT, &mut generation_a.driver).await,
                Ok(Ok(()))
            );
            let first_sender_alive_at_driver_close = generation_a.sender.is_some();
            Ok::<_, anyhow::Error>((
                FailureClientResult {
                    canonical_success,
                    later_stream_failed,
                    driver_closed,
                    sender_alive_at_driver_close,
                },
                first_driver_closed,
                first_sender_alive_at_driver_close,
            ))
        };
        let (outcome_a, outcome_b, client) =
            tokio::join!(reference_a.run_once(), reference_b.run_once(), client);
        let (client, first_driver_closed, first_sender_alive_at_driver_close) =
            client.expect("replacement exporter client");
        assert!(first_driver_closed);
        assert!(first_sender_alive_at_driver_close);
        assert_eq!(outcome_a.state, GenerationState::Closed);
        assert_closed_outcome(&outcome_b, &client);
        assert_eq!(outcome_b.result, Err(DirectV3H2Error::Control));
        assert!(outcome_a.observed_exporter != outcome_b.observed_exporter);
    }

    #[tokio::test]
    async fn concurrent_second_control_closes_both_streams_and_generation() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind duplicate-control reference");
        let address = reference.local_addr().expect("duplicate reference address");
        let client = async {
            let mut generation = connect_client(address, role.certificate.clone(), None).await?;
            let control = client_control(config, &generation.exporter, Some(&[]), [0x75; 32]);
            let (first_response, mut first_body) = start_request(
                &mut generation,
                Method::POST,
                TEST_PATH,
                &[AUTH_CONTENT_TYPE],
            )
            .await?;
            first_body
                .send_data(Bytes::copy_from_slice(&control[..1]), false)
                .context("hold first control partial")?;
            let (second_response, mut second_body) = start_request(
                &mut generation,
                Method::POST,
                TEST_PATH,
                &[AUTH_CONTENT_TYPE],
            )
            .await?;
            let _ = second_body.send_data(Bytes::copy_from_slice(&control), true);
            let (first_success, second_success) = tokio::join!(
                response_is_canonical(first_response),
                response_is_canonical(second_response)
            );
            let (later_stream_failed, driver_closed, sender_alive_at_driver_close) =
                later_stream_and_driver_close(&mut generation).await;
            Ok::<_, anyhow::Error>(FailureClientResult {
                canonical_success: first_success || second_success,
                later_stream_failed,
                driver_closed,
                sender_alive_at_driver_close,
            })
        };
        let (outcome, client) = tokio::join!(reference.run_once(), client);
        let client = client.expect("duplicate-control client");
        assert_closed_outcome(&outcome, &client);
        assert_eq!(outcome.result, Err(DirectV3H2Error::DuplicateControl));
        assert!(!outcome
            .events
            .contains(&GenerationEvent::ResponseHeadersAccepted));
    }

    #[tokio::test]
    async fn headers_only_and_partial_confirmation_never_authenticate() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        for behavior in [ResponseBehavior::HeadersOnly, ResponseBehavior::Partial] {
            let role = test_role("h2", TEST_PATH, 3_600);
            let (outcome, client) = run_failure_case(&role, FailureCase::valid(), behavior).await;
            assert_closed_outcome(&outcome, &client);
            assert_eq!(outcome.result, Err(DirectV3H2Error::Confirmation));
            assert!(outcome
                .events
                .contains(&GenerationEvent::ResponseHeadersAccepted));
            let accepted: usize = outcome
                .events
                .iter()
                .filter_map(|event| match event {
                    GenerationEvent::ResponseDataAccepted { bytes, .. } => Some(*bytes),
                    _ => None,
                })
                .sum();
            assert!(accepted < AUTH_V3_SERVER_CONFIRMATION_LEN);
        }
    }

    #[tokio::test]
    async fn reset_while_waiting_for_capacity_never_authenticates() {
        let _network = TEST_NETWORK_LOCK.lock().await;
        let role = test_role("h2", TEST_PATH, 3_600);
        let config = direct_config(&role);
        let reference = bind_direct_v3_h2_reference(config, DirectV3H2Backend::Rustls)
            .await
            .expect("bind capacity-reset reference");
        let address = reference.local_addr().expect("capacity-reset address");
        let client = async {
            let mut generation = connect_client(address, role.certificate.clone(), Some(0)).await?;
            let control = client_control(config, &generation.exporter, Some(&[]), [0x76; 32]);
            let (response, mut request_body) = start_request(
                &mut generation,
                Method::POST,
                TEST_PATH,
                &[AUTH_CONTENT_TYPE],
            )
            .await?;
            send_body(&mut request_body, &[&control], None).await?;
            let response = response.await.context("receive headers before reset")?;
            assert_eq!(response.status(), StatusCode::OK);
            request_body.send_reset(h2::Reason::CANCEL);
            drop(response);
            let (later_stream_failed, driver_closed, sender_alive_at_driver_close) =
                later_stream_and_driver_close(&mut generation).await;
            Ok::<_, anyhow::Error>(FailureClientResult {
                canonical_success: false,
                later_stream_failed,
                driver_closed,
                sender_alive_at_driver_close,
            })
        };
        let (outcome, client) = tokio::join!(reference.run_once(), client);
        let client = client.expect("capacity-reset client");
        assert_closed_outcome(&outcome, &client);
        assert_eq!(outcome.result, Err(DirectV3H2Error::Confirmation));
        assert!(outcome
            .events
            .contains(&GenerationEvent::ResponseHeadersAccepted));
        assert!(!outcome.events.iter().any(|event| matches!(
            event,
            GenerationEvent::ResponseDataAccepted {
                end_stream: true,
                ..
            }
        )));
    }
}
