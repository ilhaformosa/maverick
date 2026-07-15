use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "h3"))]
use anyhow::bail;
use anyhow::{Context, Result};
#[cfg(feature = "h3")]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use h2::server::SendResponse;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use maverick_core::auth::{
    current_unix, ClientHello, ClientHelloV2, ServerHello, ServerHelloV2, ServerHelloV2Params,
    TlsChannelBinding, AUTH_V2_PROTOCOL_VERSION, FEATURE_TLS_CHANNEL_BINDING, PROTOCOL_VERSION,
    TLS_CHANNEL_BINDING_EXPORTER_LABEL,
};
use maverick_core::frame::{
    ErrorCode, Frame, FrameType, OpenTcpPayload, OpenUdpPayload, UdpPacketPayload, FRAME_HEADER_LEN,
};
use maverick_core::padding::{RuntimeCoverTraffic, RuntimePadding};
use maverick_core::replay::ReplayCache;
use maverick_core::util::{redact_id, redact_ip};
use maverick_core::{SecretString, ServerConfig};
#[cfg(feature = "h3")]
use quinn::crypto::rustls::QuicServerConfig;
#[cfg(feature = "h3")]
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{
            Callback as WsCallback, ErrorResponse as WsErrorResponse, Request as WsRequest,
            Response as WsResponse,
        },
        protocol::WebSocketConfig,
        Message,
    },
    WebSocketStream,
};
use tracing::{debug, info};

use crate::auth_gate::{
    ActiveStreamTracker, AuthFailureDecision, AuthFailureTracker, ConnectionLimitGuard,
    ConnectionLimitRejection, ConnectionLimitTracker,
};
use crate::fallback::FallbackHandler;
use crate::h2_acceptor;
use crate::relay;
use crate::runtime_metrics::ServerRuntimeMetrics;
use crate::users::{CredentialMatch, UserStore};

const LISTENER_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const UNAUTHENTICATED_FIRST_FRAME_TIMEOUT_MS: u64 = 1_000;
const MAX_FALLBACK_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const REPLAY_CACHE_SHARDS: usize = 16;
const METRICS_READ_TIMEOUT: Duration = Duration::from_secs(2);

fn server_padding(state: &ServerState) -> RuntimePadding {
    RuntimePadding::from_config(
        state.config.maverick.mode_default,
        &state.config.advanced.shaping,
    )
}

fn server_cover_traffic(state: &ServerState) -> RuntimeCoverTraffic {
    RuntimeCoverTraffic::from_config(
        state.config.maverick.mode_default,
        &state.config.advanced.shaping,
    )
}

fn send_h2_server_frame(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    state: &ServerState,
) -> Result<()> {
    let padding_bytes = relay::send_frame_with_padding(
        stream,
        frame,
        max_frame_size,
        end_stream,
        &server_padding(state),
        &server_cover_traffic(state),
    )?;
    state.metrics.record_shaping_padding(padding_bytes);
    Ok(())
}

#[derive(Clone)]
struct ServerState {
    config: Arc<ServerConfig>,
    users: Arc<UserStore>,
    replay: Arc<Vec<Mutex<ReplayCache>>>,
    fallback: FallbackHandler,
    metrics: Arc<ServerRuntimeMetrics>,
    policies: Arc<ServerPolicies>,
    connection_limits: Arc<ConnectionLimitTracker>,
    pre_auth_admission: Arc<Semaphore>,
    fallback_admission: Arc<Semaphore>,
    auth_failures: Arc<Mutex<AuthFailureTracker>>,
    dummy_auth_secret: SecretString,
}

struct ActiveConnectionMetricGuard {
    metrics: Arc<ServerRuntimeMetrics>,
}

impl ActiveConnectionMetricGuard {
    fn new(metrics: Arc<ServerRuntimeMetrics>) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ActiveConnectionMetricGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct PreAuthPermit {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ServerRuntimeMetrics>,
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        self.metrics.active_pre_auth.fetch_sub(1, Ordering::Relaxed);
    }
}

struct FallbackPermit {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ServerRuntimeMetrics>,
}

impl Drop for FallbackPermit {
    fn drop(&mut self) {
        self.metrics
            .active_fallbacks
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct UserFlowPermit {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ServerRuntimeMetrics>,
}

impl Drop for UserFlowPermit {
    fn drop(&mut self) {
        self.metrics.active_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct ServerHandle {
    pub local_addr: std::net::SocketAddr,
    pub metrics_addr: Option<std::net::SocketAddr>,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<Result<()>>,
}

impl ServerHandle {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.join.await?
    }
}

pub async fn start_server(config: ServerConfig) -> Result<ServerHandle> {
    config.validate().map_err(anyhow::Error::from)?;
    validate_runtime_features(&config)?;
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let metrics_listener = bind_metrics_listener(&config).await?;
    let metrics_addr = match &metrics_listener {
        Some(listener) => Some(listener.local_addr()?),
        None => None,
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join =
        tokio::spawn(async move { serve(listener, metrics_listener, config, shutdown_rx).await });
    Ok(ServerHandle {
        local_addr,
        metrics_addr,
        shutdown: Some(shutdown_tx),
        join,
    })
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    config.validate().map_err(anyhow::Error::from)?;
    validate_runtime_features(&config)?;
    let listener = TcpListener::bind(config.listen).await?;
    let metrics_listener = bind_metrics_listener(&config).await?;
    info!(listen = %listener.local_addr()?, "Maverick server listening");
    if let Some(listener) = &metrics_listener {
        info!(listen = %listener.local_addr()?, "Maverick local metrics listening");
    }
    let (_tx, rx) = oneshot::channel();
    serve(listener, metrics_listener, config, rx).await
}

fn validate_runtime_features(config: &ServerConfig) -> Result<()> {
    #[cfg(not(feature = "h3"))]
    if config.advanced.experimental_h3 {
        bail!("advanced.experimental_h3 requires the maverick-server h3 feature");
    }
    #[cfg(feature = "h3")]
    let _ = config;
    Ok(())
}

fn pre_auth_admission_limit(config: &ServerConfig) -> usize {
    config.advanced.pre_auth_max_concurrent as usize
}

fn fallback_admission_limit(config: &ServerConfig) -> usize {
    config.advanced.fallback_max_concurrent as usize
}

fn replay_caches(config: &ServerConfig) -> Vec<Mutex<ReplayCache>> {
    (0..REPLAY_CACHE_SHARDS)
        .map(|_| {
            Mutex::new(ReplayCache::new(
                config.maverick.replay_window_secs,
                config.maverick.replay_cache_entries_per_credential,
                config.maverick.replay_cache_max_credentials_per_shard,
            ))
        })
        .collect()
}

fn drain_finished_tasks(tasks: &mut JoinSet<()>) -> Result<()> {
    while let Some(joined) = tasks.try_join_next() {
        joined?;
    }
    Ok(())
}

fn rustls_server_channel_binding(
    connection: &rustls::ServerConnection,
    enabled: bool,
) -> Result<Option<TlsChannelBinding>> {
    if !enabled {
        return Ok(None);
    }
    let output = connection
        .export_keying_material([0u8; 32], TLS_CHANNEL_BINDING_EXPORTER_LABEL, None)
        .context("export TLS channel binding")?;
    Ok(Some(TlsChannelBinding::new(output)))
}

fn replay_shard<'a>(state: &'a ServerState, replay_key: &str) -> &'a Mutex<ReplayCache> {
    let mut hasher = DefaultHasher::new();
    replay_key.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % state.replay.len();
    &state.replay[idx]
}

fn try_pre_auth_admission(state: &ServerState) -> Option<PreAuthPermit> {
    match state.pre_auth_admission.clone().try_acquire_owned() {
        Ok(permit) => {
            state
                .metrics
                .active_pre_auth
                .fetch_add(1, Ordering::Relaxed);
            Some(PreAuthPermit {
                _permit: permit,
                metrics: Arc::clone(&state.metrics),
            })
        }
        Err(_) => {
            state
                .metrics
                .pre_auth_admission_rejections
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn try_connection_limit(state: &ServerState, peer: SocketAddr) -> Option<ConnectionLimitGuard> {
    match state.connection_limits.try_enter(peer.ip()) {
        Ok(guard) => Some(guard),
        Err(ConnectionLimitRejection::Global) => {
            state
                .metrics
                .connection_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            None
        }
        Err(ConnectionLimitRejection::PerSource) => {
            state
                .metrics
                .source_connection_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn try_fallback_admission(state: &ServerState) -> Option<FallbackPermit> {
    match state.fallback_admission.clone().try_acquire_owned() {
        Ok(permit) => {
            state
                .metrics
                .active_fallbacks
                .fetch_add(1, Ordering::Relaxed);
            Some(FallbackPermit {
                _permit: permit,
                metrics: Arc::clone(&state.metrics),
            })
        }
        Err(_) => {
            state
                .metrics
                .fallback_overload_rejections
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn try_user_flow_permit(state: &ServerState, user_policy: &UserPolicy) -> Option<UserFlowPermit> {
    match user_policy.flow_limit.clone().try_acquire_owned() {
        Ok(permit) => {
            state.metrics.active_flows.fetch_add(1, Ordering::Relaxed);
            Some(UserFlowPermit {
                _permit: permit,
                metrics: Arc::clone(&state.metrics),
            })
        }
        Err(_) => {
            state
                .metrics
                .flow_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn websocket_config(max_frame_size: usize) -> WebSocketConfig {
    let encoded_limit = max_frame_size.saturating_add(FRAME_HEADER_LEN);
    WebSocketConfig::default()
        .max_message_size(Some(encoded_limit))
        .max_frame_size(Some(encoded_limit))
}

fn websocket_path_error() -> WsErrorResponse {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Some("Not Found".to_owned()))
        .expect("static websocket error response is valid")
}

struct WebSocketPathValidator {
    tunnel_path: String,
}

impl WsCallback for WebSocketPathValidator {
    #[allow(clippy::result_large_err)]
    fn on_request(
        self,
        request: &WsRequest,
        response: WsResponse,
    ) -> std::result::Result<WsResponse, WsErrorResponse> {
        if request.uri().path() == self.tunnel_path {
            Ok(response)
        } else {
            Err(websocket_path_error())
        }
    }
}

async fn serve(
    listener: TcpListener,
    metrics_listener: Option<TcpListener>,
    config: ServerConfig,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let acceptor = h2_acceptor::acceptor(&config)?;
    let metrics = Arc::new(ServerRuntimeMetrics::default());
    let policies = Arc::new(ServerPolicies::from_config(&config));
    let connection_limits = Arc::new(ConnectionLimitTracker::new(
        config.advanced.max_concurrent_connections as usize,
        config.advanced.max_concurrent_connections_per_source as usize,
    ));
    let pre_auth_admission = Arc::new(Semaphore::new(pre_auth_admission_limit(&config)));
    let fallback_admission = Arc::new(Semaphore::new(fallback_admission_limit(&config)));
    let state = ServerState {
        replay: Arc::new(replay_caches(&config)),
        users: Arc::new(UserStore::new(&config.users)?),
        fallback: FallbackHandler::from_config(&config.fallback),
        metrics: Arc::clone(&metrics),
        policies,
        connection_limits,
        pre_auth_admission,
        fallback_admission,
        auth_failures: Arc::new(Mutex::new(AuthFailureTracker::default())),
        dummy_auth_secret: SecretString::generate(),
        config: Arc::new(config),
    };
    let (metrics_shutdown_tx, metrics_join) = if let Some(listener) = metrics_listener {
        let (tx, rx) = oneshot::channel();
        let join = tokio::spawn(serve_metrics(listener, Arc::clone(&metrics), rx));
        (Some(tx), Some(join))
    } else {
        (None, None)
    };
    let (h3_shutdown_tx, h3_join) = maybe_start_h3_server(listener.local_addr()?, state.clone())?;
    let mut connection_tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Maverick server shutdown requested");
                break;
            }
            joined = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(joined) = joined {
                    joined?;
                }
            }
            accept = listener.accept() => {
                let (tcp, peer) = match accept {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(error = %err, "server accept failed");
                        sleep(LISTENER_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let state = state.clone();
                let Some(connection_limit_guard) = try_connection_limit(&state, peer) else {
                    debug!("server connection limit reached");
                    continue;
                };
                let active_connection_guard =
                    ActiveConnectionMetricGuard::new(Arc::clone(&state.metrics));
                let Some(pre_auth_permit) = try_pre_auth_admission(&state) else {
                    debug!("server pre-auth admission limit reached");
                    continue;
                };
                connection_tasks.spawn(async move {
                    let _connection_limit_guard = connection_limit_guard;
                    let _active_connection_guard = active_connection_guard;
                    if let Err(err) = handle_tcp(tcp, peer, acceptor, state, pre_auth_permit).await {
                        debug!(
                            peer_ip = %redact_ip(peer.ip()),
                            error = %err,
                            "server connection ended"
                        );
                    }
                });
            }
        }
    }
    connection_tasks.abort_all();
    while let Some(joined) = connection_tasks.join_next().await {
        if let Err(err) = joined {
            if !err.is_cancelled() {
                return Err(err.into());
            }
        }
    }
    if let Some(tx) = metrics_shutdown_tx {
        let _ = tx.send(());
    }
    if let Some(tx) = h3_shutdown_tx {
        let _ = tx.send(());
    }
    if let Some(join) = metrics_join {
        join.await??;
    }
    if let Some(join) = h3_join {
        join.await??;
    }
    Ok(())
}

async fn bind_metrics_listener(config: &ServerConfig) -> Result<Option<TcpListener>> {
    let Some(metrics) = &config.metrics else {
        return Ok(None);
    };
    if !metrics.enabled {
        return Ok(None);
    }
    Ok(Some(TcpListener::bind(metrics.listen).await?))
}

async fn handle_tcp(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    state: ServerState,
    pre_auth_permit: PreAuthPermit,
) -> Result<()> {
    let handshake_timeout = Duration::from_millis(state.config.advanced.handshake_timeout_ms);
    let tls = timeout(handshake_timeout, acceptor.accept(tcp))
        .await
        .context("TLS accept timed out")?
        .context("TLS accept failed")?;
    if state.config.advanced.cloudflare_ws_enabled()
        && tls.get_ref().1.alpn_protocol() != Some(b"h2")
    {
        return handle_ws_tcp(tls, peer, state, pre_auth_permit).await;
    }
    let channel_binding =
        rustls_server_channel_binding(tls.get_ref().1, state.config.auth.channel_binding.enabled)?;
    let mut h2 = timeout(
        handshake_timeout,
        h2::server::Builder::new()
            .max_concurrent_streams(state.config.advanced.h2_max_concurrent_streams)
            .max_concurrent_reset_streams(
                state.config.advanced.h2_max_concurrent_reset_streams as usize,
            )
            .max_pending_accept_reset_streams(
                state.config.advanced.h2_max_pending_accept_reset_streams as usize,
            )
            .max_local_error_reset_streams(Some(
                state.config.advanced.h2_max_local_error_reset_streams as usize,
            ))
            .initial_window_size(1024 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024)
            .handshake(tls),
    )
    .await
    .context("h2 server handshake timed out")?
    .context("h2 server handshake failed")?;
    let _connection_permit = pre_auth_permit;
    let idle_timeout = Duration::from_secs(state.config.advanced.idle_timeout_secs);
    let active_streams = ActiveStreamTracker::default();
    let mut stream_tasks = JoinSet::new();
    loop {
        drain_finished_tasks(&mut stream_tasks)?;
        let result = if active_streams.active_count() == 0 {
            tokio::select! {
                result = h2.accept() => result,
                _ = sleep(idle_timeout) => {
                    debug!("h2 connection idle timeout elapsed");
                    break;
                }
            }
        } else {
            tokio::select! {
                result = h2.accept() => result,
                _ = sleep(idle_timeout) => {
                    continue;
                }
            }
        };
        let result = match result {
            Some(result) => result,
            None => break,
        };
        let (request, respond) = result?;
        let state = state.clone();
        let Some(pre_auth_permit) = try_pre_auth_admission(&state) else {
            if state.config.advanced.stealth.active_probe_resistance {
                let method = request.method().clone();
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|value| value.as_str().to_owned())
                    .unwrap_or_else(|| request.uri().path().to_owned());
                let headers = fallback_request_headers(request.headers());
                if let Err(err) = send_fallback(respond, &state, &method, &path, &headers).await {
                    debug!(
                        peer_ip = %redact_ip(peer.ip()),
                        error = %err,
                        "h2 pre-auth admission fallback failed"
                    );
                }
            } else {
                drop(respond);
            }
            drop(request);
            debug!(
                peer_ip = %redact_ip(peer.ip()),
                "h2 pre-auth admission limit reached"
            );
            continue;
        };
        let stream_guard = active_streams.enter();
        stream_tasks.spawn(async move {
            let _stream_guard = stream_guard;
            if let Err(err) = handle_request(
                request,
                respond,
                peer,
                state,
                pre_auth_permit,
                channel_binding,
            )
            .await
            {
                debug!(error = %err, "h2 request ended");
            }
        });
    }
    while let Some(joined) = stream_tasks.join_next().await {
        joined?;
    }
    Ok(())
}

async fn handle_ws_tcp(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    state: ServerState,
    pre_auth_permit: PreAuthPermit,
) -> Result<()> {
    let handshake_timeout = Duration::from_millis(state.config.advanced.handshake_timeout_ms);
    let max_frame_size = state.config.advanced.max_frame_size as usize;
    let tunnel_path = state.config.maverick.tunnel_path.clone();
    let channel_binding =
        rustls_server_channel_binding(tls.get_ref().1, state.config.auth.channel_binding.enabled)?;
    let ws = timeout(
        handshake_timeout,
        accept_hdr_async_with_config(
            tls,
            WebSocketPathValidator { tunnel_path },
            Some(websocket_config(max_frame_size)),
        ),
    )
    .await
    .context("websocket handshake timed out")?
    .context("websocket handshake failed")?;
    handle_ws_tunnel(ws, peer, state, pre_auth_permit, channel_binding).await
}

#[cfg(feature = "h3")]
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

type OptionalH3Server = (
    Option<oneshot::Sender<()>>,
    Option<tokio::task::JoinHandle<Result<()>>>,
);

#[cfg(feature = "h3")]
fn maybe_start_h3_server(
    listen: std::net::SocketAddr,
    state: ServerState,
) -> Result<OptionalH3Server> {
    if !state.config.advanced.experimental_h3 {
        return Ok((None, None));
    }
    let endpoint = h3_endpoint(&state.config, listen)?;
    let (tx, rx) = oneshot::channel();
    let join = tokio::spawn(serve_h3(endpoint, state, rx));
    Ok((Some(tx), Some(join)))
}

#[cfg(not(feature = "h3"))]
fn maybe_start_h3_server(
    _listen: std::net::SocketAddr,
    state: ServerState,
) -> Result<OptionalH3Server> {
    if state.config.advanced.experimental_h3 {
        bail!("advanced.experimental_h3 requires the maverick-server h3 feature");
    }
    Ok((None, None))
}

#[cfg(feature = "h3")]
fn h3_endpoint(config: &ServerConfig, listen: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&config.tls.cert_path)
        .with_context(|| format!("open cert {}", config.tls.cert_path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate chain")?;
    if certs.is_empty() {
        anyhow::bail!("certificate chain is empty");
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(&config.tls.key_path)
        .with_context(|| format!("parse private key {}", config.tls.key_path.display()))?;

    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("build H3 TLS server config")?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.max_early_data_size = 0;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(config.advanced.idle_timeout_secs).try_into()?,
    ));
    transport.max_concurrent_bidi_streams(config.advanced.h2_max_concurrent_streams.into());
    server_config.transport_config(Arc::new(transport));

    quinn::Endpoint::server(server_config, listen).context("bind H3 UDP endpoint")
}

#[cfg(feature = "h3")]
async fn serve_h3(
    endpoint: quinn::Endpoint,
    state: ServerState,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                endpoint.close(0u32.into(), b"maverick-h3-server");
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let state = state.clone();
                let Some(pre_auth_permit) = try_pre_auth_admission(&state) else {
                    debug!("h3 pre-auth admission limit reached");
                    continue;
                };
                tokio::spawn(async move {
                    if let Err(err) = handle_h3_incoming(incoming, state, pre_auth_permit).await {
                        debug!(error = %err, "h3 connection ended");
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_incoming(
    incoming: quinn::Incoming,
    state: ServerState,
    _pre_auth_permit: PreAuthPermit,
) -> Result<()> {
    let connection = incoming.await.context("QUIC accept failed")?;
    let peer = connection.remote_address();
    let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .context("h3 server handshake failed")?;
    let mut request_tasks = JoinSet::new();
    while let Some(request_resolver) = h3.accept().await? {
        drain_finished_tasks(&mut request_tasks)?;
        let (request, stream) = request_resolver.resolve_request().await?;
        let state = state.clone();
        request_tasks.spawn(async move {
            if let Err(err) = handle_h3_request(request, stream, peer, state).await {
                debug!(
                    peer_ip = %redact_ip(peer.ip()),
                    error = %err,
                    "h3 request ended"
                );
            }
        });
    }
    while let Some(joined) = request_tasks.join_next().await {
        joined?;
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_request(
    request: Request<()>,
    stream: H3ServerStream,
    peer: SocketAddr,
    state: ServerState,
) -> Result<()> {
    let path = request.uri().path().to_owned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| path.clone());
    let method = request.method().clone();
    let fallback_headers = fallback_request_headers(request.headers());
    if method == Method::POST && path == state.config.maverick.tunnel_path {
        handle_h3_tunnel(
            stream,
            peer,
            state,
            method,
            path_and_query,
            fallback_headers,
        )
        .await
    } else {
        let mut stream = stream;
        let request_body = collect_h3_fallback_request_body(&mut stream).await?;
        send_h3_fallback_with_body(
            stream,
            &state,
            &method,
            &path_and_query,
            &fallback_headers,
            request_body,
        )
        .await
    }
}

async fn handle_request(
    request: Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    peer: SocketAddr,
    state: ServerState,
    pre_auth_permit: PreAuthPermit,
    channel_binding: Option<TlsChannelBinding>,
) -> Result<()> {
    let path = request.uri().path().to_owned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| path.clone());
    let method = request.method().clone();
    let fallback_headers = fallback_request_headers(request.headers());
    if method == Method::POST && path == state.config.maverick.tunnel_path {
        handle_tunnel(
            request,
            respond,
            peer,
            state,
            pre_auth_permit,
            channel_binding,
            fallback_headers,
        )
        .await
    } else {
        let mut body_stream = request.into_body();
        let request_body = collect_fallback_request_body(&mut body_stream).await?;
        send_fallback_with_body(
            respond,
            &state,
            &method,
            &path_and_query,
            &fallback_headers,
            request_body,
        )
        .await
    }
}

struct AuthenticatedClientHello<'a> {
    credential: CredentialMatch<'a>,
    auth: AuthenticatedClientAuth,
    replay_key: String,
    feature_flags_selected: u64,
}

enum AuthenticatedClientAuth {
    V1 {
        client_nonce: [u8; 32],
        timestamp_unix: i64,
    },
    V2 {
        auth_epoch: u64,
        client_nonce: [u8; 32],
        timestamp_unix: i64,
    },
}

impl AuthenticatedClientHello<'_> {
    fn client_nonce(&self) -> [u8; 32] {
        match self.auth {
            AuthenticatedClientAuth::V1 { client_nonce, .. }
            | AuthenticatedClientAuth::V2 { client_nonce, .. } => client_nonce,
        }
    }

    fn timestamp_unix(&self) -> i64 {
        match self.auth {
            AuthenticatedClientAuth::V1 { timestamp_unix, .. }
            | AuthenticatedClientAuth::V2 { timestamp_unix, .. } => timestamp_unix,
        }
    }

    fn server_hello_payload(
        &self,
        max_frame_size: u32,
        max_concurrent_flows: u32,
        channel_binding: Option<TlsChannelBinding>,
    ) -> Result<Vec<u8>> {
        let client_nonce = self.client_nonce();
        let selected_channel_binding =
            selected_channel_binding_for_flags(self.feature_flags_selected, channel_binding);
        match self.auth {
            AuthenticatedClientAuth::V1 { .. } => Ok(ServerHello::try_new_with_channel_binding(
                self.credential.secret,
                &client_nonce,
                max_frame_size,
                max_concurrent_flows,
                self.feature_flags_selected,
                selected_channel_binding,
            )?
            .encode()),
            AuthenticatedClientAuth::V2 { auth_epoch, .. } => Ok(
                ServerHelloV2::try_new_with_channel_binding(ServerHelloV2Params {
                    secret: self.credential.secret,
                    selected_epoch: auth_epoch,
                    client_nonce: &client_nonce,
                    max_frame_size,
                    max_concurrent_flows,
                    feature_flags_selected: self.feature_flags_selected,
                    rotation_window_secs: 86_400,
                    channel_binding: selected_channel_binding,
                })?
                .encode()?,
            ),
        }
    }
}

fn authenticate_client_hello<'a>(
    payload: &[u8],
    state: &'a ServerState,
    now_unix: i64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<AuthenticatedClientHello<'a>> {
    let version = payload_version(payload)?;
    match version {
        PROTOCOL_VERSION if !state.config.auth.v2.require => {
            authenticate_client_hello_v1(payload, state, now_unix, channel_binding)
        }
        AUTH_V2_PROTOCOL_VERSION if state.config.auth.v2.enabled => {
            authenticate_client_hello_v2(payload, state, now_unix, channel_binding)
        }
        _ => None,
    }
}

fn authenticate_client_hello_v1<'a>(
    payload: &[u8],
    state: &'a ServerState,
    now_unix: i64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<AuthenticatedClientHello<'a>> {
    let hello = ClientHello::decode(payload).ok()?;
    if hello.protocol_version != PROTOCOL_VERSION {
        return None;
    }
    let credential_secret = state.users.lookup_secret(&hello.credential_id, now_unix);
    let verify_secret = credential_secret
        .as_ref()
        .map(|credential| credential.secret)
        .unwrap_or(&state.dummy_auth_secret);
    let feature_flags_selected =
        selected_client_feature_flags(hello.feature_flags, state, channel_binding)?;
    if !hello.verify_with_channel_binding(
        verify_secret,
        &state.config.maverick.tunnel_path,
        selected_channel_binding_for_flags(feature_flags_selected, channel_binding),
    ) {
        return None;
    }
    let credential = state
        .users
        .lookup_credential(&hello.credential_id, now_unix)?;
    Some(AuthenticatedClientHello {
        credential,
        replay_key: hello.credential_id,
        feature_flags_selected,
        auth: AuthenticatedClientAuth::V1 {
            client_nonce: hello.client_nonce,
            timestamp_unix: hello.timestamp_unix,
        },
    })
}

fn authenticate_client_hello_v2<'a>(
    payload: &[u8],
    state: &'a ServerState,
    now_unix: i64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<AuthenticatedClientHello<'a>> {
    let hello = ClientHelloV2::decode(payload).ok()?;
    if hello.protocol_version != AUTH_V2_PROTOCOL_VERSION
        || !state
            .config
            .auth
            .v2
            .accepted_epochs
            .contains(&hello.auth_epoch)
    {
        return None;
    }
    let credential_id = std::str::from_utf8(&hello.credential_hint).ok()?;
    let credential_secret = state.users.lookup_secret(credential_id, now_unix);
    let verify_secret = credential_secret
        .as_ref()
        .map(|credential| credential.secret)
        .unwrap_or(&state.dummy_auth_secret);
    let feature_flags_selected =
        selected_client_feature_flags(hello.feature_flags, state, channel_binding)?;
    if !hello.verify_with_channel_binding(
        verify_secret,
        &state.config.maverick.tunnel_path,
        selected_channel_binding_for_flags(feature_flags_selected, channel_binding),
    ) {
        return None;
    }
    let credential = state.users.lookup_credential(credential_id, now_unix)?;
    Some(AuthenticatedClientHello {
        credential,
        replay_key: format!("v2:{}:{credential_id}", hello.auth_epoch),
        feature_flags_selected,
        auth: AuthenticatedClientAuth::V2 {
            auth_epoch: hello.auth_epoch,
            client_nonce: hello.client_nonce,
            timestamp_unix: hello.timestamp_unix,
        },
    })
}

fn selected_client_feature_flags(
    requested: u64,
    state: &ServerState,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<u64> {
    let requested_channel_binding = requested & FEATURE_TLS_CHANNEL_BINDING != 0;
    if state.config.auth.channel_binding.require && !requested_channel_binding {
        return None;
    }
    if !requested_channel_binding {
        return Some(0);
    }
    if !state.config.auth.channel_binding.enabled || channel_binding.is_none() {
        return None;
    }
    Some(FEATURE_TLS_CHANNEL_BINDING)
}

fn selected_channel_binding_for_flags(
    selected: u64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<TlsChannelBinding> {
    if selected & FEATURE_TLS_CHANNEL_BINDING == 0 {
        return None;
    }
    channel_binding
}

fn payload_version(payload: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = payload.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn unauthenticated_first_frame_timeout(config: &ServerConfig) -> Duration {
    Duration::from_millis(
        config
            .advanced
            .handshake_timeout_ms
            .min(UNAUTHENTICATED_FIRST_FRAME_TIMEOUT_MS),
    )
}

async fn handle_tunnel(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    state: ServerState,
    pre_auth_permit: PreAuthPermit,
    channel_binding: Option<TlsChannelBinding>,
    fallback_headers: HeaderMap,
) -> Result<()> {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let mut recv_stream = request.into_body();
    let max_frame_size = state.config.advanced.max_frame_size as usize;
    let mut recv_buf = BytesMut::new();
    let mut fallback_body = BytesMut::new();
    let first_frame = match timeout(
        unauthenticated_first_frame_timeout(&state.config),
        relay::read_next_frame_capturing(
            &mut recv_stream,
            &mut recv_buf,
            max_frame_size,
            &mut fallback_body,
            MAX_FALLBACK_REQUEST_BODY_BYTES,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            info!("unauthenticated tunnel-like request rejected");
            return reject_tunnel_to_fallback(
                respond,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body,
            )
            .await;
        }
    };
    let now_unix = current_unix();
    let authenticated = match first_frame {
        Ok(Some(frame)) if frame.frame_type == FrameType::ClientHello => {
            match authenticate_client_hello(&frame.payload, &state, now_unix, channel_binding) {
                Some(authenticated) => authenticated,
                None => {
                    info!("unauthenticated tunnel-like request rejected");
                    return reject_tunnel_to_fallback(
                        respond,
                        &state,
                        peer,
                        &method,
                        &path,
                        &fallback_headers,
                        fallback_body,
                    )
                    .await;
                }
            }
        }
        _ => {
            info!("unauthenticated tunnel-like request rejected");
            return reject_tunnel_to_fallback(
                respond,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body,
            )
            .await;
        }
    };
    {
        let mut replay = replay_shard(&state, &authenticated.replay_key).lock().await;
        if replay
            .check_and_insert(
                &authenticated.replay_key,
                authenticated.client_nonce(),
                authenticated.timestamp_unix(),
                now_unix,
            )
            .is_err()
        {
            info!("unauthenticated tunnel-like request rejected");
            return reject_tunnel_to_fallback(
                respond,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body,
            )
            .await;
        }
    }
    info!(
        user = %redact_id(&authenticated.credential.user.id),
        credential_state = authenticated.credential.state.as_str(),
        "Maverick session authenticated"
    );
    drop(pre_auth_permit);
    state
        .metrics
        .authenticated_sessions
        .fetch_add(1, Ordering::Relaxed);
    let user_policy = state
        .policies
        .for_user(&authenticated.credential.user.id)
        .context("missing authenticated user policy")?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())?;
    let mut send_stream = respond.send_response(response, false)?;
    let max_concurrent_flows = authenticated
        .credential
        .user
        .max_concurrent_flows
        .unwrap_or(state.config.maverick.max_concurrent_flows_per_user);
    let server_hello_payload = authenticated.server_hello_payload(
        state.config.advanced.max_frame_size,
        max_concurrent_flows,
        channel_binding,
    )?;
    send_h2_server_frame(
        &mut send_stream,
        Frame::new(FrameType::ServerHello, 0, 0, server_hello_payload),
        max_frame_size,
        false,
        &state,
    )?;

    let open_frame = match timeout(
        Duration::from_millis(state.config.advanced.handshake_timeout_ms),
        relay::read_next_frame(&mut recv_stream, &mut recv_buf, max_frame_size),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) | Err(_) => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(0, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                &state,
            )?;
            return Ok(());
        }
        Ok(Err(err)) => return Err(err),
    };
    if open_frame.frame_type == FrameType::DnsQuery {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                send_h2_server_frame(
                    &mut send_stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )?;
                return Ok(());
            }
        };
        return handle_dns_query(
            open_frame,
            send_stream,
            &state,
            &user_policy,
            max_frame_size,
        )
        .await;
    }
    if open_frame.frame_type == FrameType::OpenUdp {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                send_h2_server_frame(
                    &mut send_stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )?;
                return Ok(());
            }
        };
        return handle_udp_flow(
            open_frame,
            send_stream,
            recv_stream,
            recv_buf,
            &state,
            &user_policy,
            max_frame_size,
        )
        .await;
    }
    if open_frame.frame_type == FrameType::UdpPacket {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                send_h2_server_frame(
                    &mut send_stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )?;
                return Ok(());
            }
        };
        return handle_udp_packet(
            open_frame,
            send_stream,
            &state,
            &user_policy,
            max_frame_size,
        )
        .await;
    }
    if open_frame.frame_type != FrameType::OpenTcp {
        send_h2_server_frame(
            &mut send_stream,
            relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
            max_frame_size,
            true,
            &state,
        )?;
        return Ok(());
    }
    let open = match OpenTcpPayload::decode(&open_frame.payload) {
        Ok(open) => open,
        Err(_) => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                &state,
            )?;
            return Ok(());
        }
    };
    let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
        Some(permit) => permit,
        None => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                max_frame_size,
                true,
                &state,
            )?;
            return Ok(());
        }
    };

    let target = match relay::open_target(
        &open,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(target) => target,
        Err(_) => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::TargetConnectFailed),
                max_frame_size,
                true,
                &state,
            )?;
            return Ok(());
        }
    };
    state.metrics.tcp_flows.fetch_add(1, Ordering::Relaxed);

    send_h2_server_frame(
        &mut send_stream,
        Frame::new(FrameType::WindowUpdate, 0, open_frame.flow_id, Bytes::new()),
        max_frame_size,
        false,
        &state,
    )?;
    relay::relay_target_and_tunnel(
        target,
        send_stream,
        recv_stream,
        recv_buf,
        max_frame_size,
        open_frame.flow_id,
        relay::TunnelRelayPolicy {
            idle_timeout: Duration::from_secs(state.config.advanced.idle_timeout_secs),
            rate_limiter: user_policy.rate_limiter.clone(),
            padding: server_padding(&state),
            cover_traffic: server_cover_traffic(&state),
            shaping_metrics: Some(state.metrics.shaping_sinks()),
        },
    )
    .await
}

async fn reject_ws_auth_failure<S>(
    ws: &mut WebSocketStream<S>,
    state: &ServerState,
    peer: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state
        .metrics
        .unauthenticated_rejections
        .fetch_add(1, Ordering::Relaxed);
    let _ = record_auth_failure(state, peer).await;
    let _ = ws.close(None).await;
}

async fn handle_ws_tunnel<S>(
    mut ws: WebSocketStream<S>,
    peer: SocketAddr,
    state: ServerState,
    pre_auth_permit: PreAuthPermit,
    channel_binding: Option<TlsChannelBinding>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max_frame_size = state.config.advanced.max_frame_size as usize;
    let mut ws_recv_buf = BytesMut::new();
    let first_frame = match timeout(
        unauthenticated_first_frame_timeout(&state.config),
        ws_read_next_frame(&mut ws, &mut ws_recv_buf, max_frame_size),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            info!("unauthenticated websocket tunnel request rejected");
            reject_ws_auth_failure(&mut ws, &state, peer).await;
            return Ok(());
        }
    };
    let now_unix = current_unix();
    let authenticated = match first_frame {
        Ok(Some(frame)) if frame.frame_type == FrameType::ClientHello => {
            match authenticate_client_hello(&frame.payload, &state, now_unix, channel_binding) {
                Some(authenticated) => authenticated,
                None => {
                    info!("unauthenticated websocket tunnel request rejected");
                    reject_ws_auth_failure(&mut ws, &state, peer).await;
                    return Ok(());
                }
            }
        }
        _ => {
            info!("unauthenticated websocket tunnel request rejected");
            reject_ws_auth_failure(&mut ws, &state, peer).await;
            return Ok(());
        }
    };
    {
        let mut replay = replay_shard(&state, &authenticated.replay_key).lock().await;
        if replay
            .check_and_insert(
                &authenticated.replay_key,
                authenticated.client_nonce(),
                authenticated.timestamp_unix(),
                now_unix,
            )
            .is_err()
        {
            info!("unauthenticated websocket tunnel request rejected");
            reject_ws_auth_failure(&mut ws, &state, peer).await;
            return Ok(());
        }
    }
    info!(
        user = %redact_id(&authenticated.credential.user.id),
        credential_state = authenticated.credential.state.as_str(),
        "Maverick websocket session authenticated"
    );
    drop(pre_auth_permit);
    state
        .metrics
        .authenticated_sessions
        .fetch_add(1, Ordering::Relaxed);
    let user_policy = state
        .policies
        .for_user(&authenticated.credential.user.id)
        .context("missing authenticated user policy")?;
    let max_concurrent_flows = authenticated
        .credential
        .user
        .max_concurrent_flows
        .unwrap_or(state.config.maverick.max_concurrent_flows_per_user);
    let server_hello_payload = authenticated.server_hello_payload(
        state.config.advanced.max_frame_size,
        max_concurrent_flows,
        channel_binding,
    )?;
    ws_send_server_frame(
        &mut ws,
        Frame::new(FrameType::ServerHello, 0, 0, server_hello_payload),
        max_frame_size,
        &state,
    )
    .await?;

    let open_frame = match timeout(
        Duration::from_millis(state.config.advanced.handshake_timeout_ms),
        ws_read_next_frame(&mut ws, &mut ws_recv_buf, max_frame_size),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) | Err(_) => {
            ws_send_server_frame(
                &mut ws,
                relay::error_frame(0, ErrorCode::ProtocolError),
                max_frame_size,
                &state,
            )
            .await?;
            return Ok(());
        }
        Ok(Err(err)) => return Err(err),
    };
    if open_frame.frame_type != FrameType::OpenTcp {
        ws_send_server_frame(
            &mut ws,
            relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
            max_frame_size,
            &state,
        )
        .await?;
        return Ok(());
    }
    let open = match OpenTcpPayload::decode(&open_frame.payload) {
        Ok(open) => open,
        Err(_) => {
            ws_send_server_frame(
                &mut ws,
                relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                &state,
            )
            .await?;
            return Ok(());
        }
    };
    let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
        Some(permit) => permit,
        None => {
            ws_send_server_frame(
                &mut ws,
                relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                max_frame_size,
                &state,
            )
            .await?;
            return Ok(());
        }
    };
    let target = match relay::open_target(
        &open,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(target) => target,
        Err(_) => {
            ws_send_server_frame(
                &mut ws,
                relay::error_frame(open_frame.flow_id, ErrorCode::TargetConnectFailed),
                max_frame_size,
                &state,
            )
            .await?;
            return Ok(());
        }
    };
    state.metrics.tcp_flows.fetch_add(1, Ordering::Relaxed);

    ws_send_server_frame(
        &mut ws,
        Frame::new(FrameType::WindowUpdate, 0, open_frame.flow_id, Bytes::new()),
        max_frame_size,
        &state,
    )
    .await?;
    relay_ws_target_and_tunnel(
        target,
        ws,
        max_frame_size,
        open_frame.flow_id,
        relay::TunnelRelayPolicy {
            idle_timeout: Duration::from_secs(state.config.advanced.idle_timeout_secs),
            rate_limiter: user_policy.rate_limiter.clone(),
            padding: server_padding(&state),
            cover_traffic: server_cover_traffic(&state),
            shaping_metrics: Some(state.metrics.shaping_sinks()),
        },
    )
    .await
}

async fn ws_send_frame<S>(
    ws: &mut WebSocketStream<S>,
    frame: Frame,
    max_frame_size: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws.send(Message::Binary(frame.encode(max_frame_size)?))
        .await?;
    Ok(())
}

async fn ws_send_server_frame<S>(
    ws: &mut WebSocketStream<S>,
    frame: Frame,
    max_frame_size: usize,
    state: &ServerState,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut emission = relay::PaddingEmission::default();
    if let Some(padding_frame) =
        server_padding(state).padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        ws_send_frame(ws, padding_frame, max_frame_size).await?;
    }
    for cover_frame in server_cover_traffic(state).padding_frames(
        frame.frame_type,
        frame.payload.len(),
        max_frame_size,
    ) {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        ws_send_frame(ws, cover_frame, max_frame_size).await?;
    }
    ws_send_frame(ws, frame, max_frame_size).await?;
    state.metrics.record_shaping_padding(emission);
    Ok(())
}

async fn ws_read_next_frame<S>(
    ws: &mut WebSocketStream<S>,
    buf: &mut BytesMut,
    max_frame_size: usize,
) -> Result<Option<Frame>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        if let Some(frame) = Frame::decode_from(buf, max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        let Some(message) = ws.next().await else {
            return Ok(None);
        };
        match message? {
            Message::Binary(bytes) => buf.extend_from_slice(&bytes),
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload)).await?;
            }
            Message::Close(_) => return Ok(None),
            _ => {}
        }
    }
}

fn frame_from_ws_message(message: Message, max_frame_size: usize) -> Result<Option<Frame>> {
    let Message::Binary(bytes) = message else {
        return Ok(None);
    };
    let mut buf = BytesMut::from(bytes.as_ref());
    Ok(Frame::decode_from(&mut buf, max_frame_size)?)
}

async fn ws_send_frame_with_policy<W>(
    ws: &mut W,
    frame: Frame,
    max_frame_size: usize,
    policy: &relay::TunnelRelayPolicy,
) -> Result<()>
where
    W: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let mut emission = relay::PaddingEmission::default();
    if let Some(padding_frame) =
        policy
            .padding
            .padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        ws.send(Message::Binary(padding_frame.encode(max_frame_size)?))
            .await?;
    }
    for cover_frame in
        policy
            .cover_traffic
            .padding_frames(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        ws.send(Message::Binary(cover_frame.encode(max_frame_size)?))
            .await?;
    }
    ws.send(Message::Binary(frame.encode(max_frame_size)?))
        .await?;
    policy.record_padding(emission);
    Ok(())
}

async fn relay_ws_target_and_tunnel<S>(
    target: TcpStream,
    ws: WebSocketStream<S>,
    max_frame_size: usize,
    flow_id: u64,
    policy: relay::TunnelRelayPolicy,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut target_read, mut target_write) = target.into_split();
    let mut target_buf = vec![0u8; 16 * 1024];
    let mut client_eof = false;

    loop {
        if client_eof {
            tokio::select! {
                _ = tokio::time::sleep(policy.idle_timeout) => {
                    break;
                }
                target_read_result = target_read.read(&mut target_buf) => {
                    let n = target_read_result?;
                    if n == 0 {
                        ws_send_frame_with_policy(
                            &mut ws_sink,
                            Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                            max_frame_size,
                            &policy,
                        )
                        .await?;
                        break;
                    }
                    if let Some(limiter) = &policy.rate_limiter {
                        limiter.throttle(n).await;
                    }
                    ws_send_frame_with_policy(
                        &mut ws_sink,
                        Frame::new(
                            FrameType::TcpData,
                            0,
                            flow_id,
                            Bytes::copy_from_slice(&target_buf[..n]),
                        ),
                        max_frame_size,
                        &policy,
                    )
                    .await?;
                }
            }
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(policy.idle_timeout) => {
                break;
            }
            target_read_result = target_read.read(&mut target_buf) => {
                let n = target_read_result?;
                if n == 0 {
                    ws_send_frame_with_policy(
                        &mut ws_sink,
                        Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                        max_frame_size,
                        &policy,
                    ).await?;
                    break;
                }
                if let Some(limiter) = &policy.rate_limiter {
                    limiter.throttle(n).await;
                }
                ws_send_frame_with_policy(
                    &mut ws_sink,
                    Frame::new(FrameType::TcpData, 0, flow_id, Bytes::copy_from_slice(&target_buf[..n])),
                    max_frame_size,
                    &policy,
                ).await?;
            }
            tunnel_frame = ws_stream.next() => {
                match tunnel_frame {
                    Some(Ok(Message::Ping(payload))) => {
                        ws_sink.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(message)) => {
                        match frame_from_ws_message(message, max_frame_size)? {
                            Some(frame) if frame.flow_id == flow_id => match frame.frame_type {
                                FrameType::TcpData => {
                                    if let Some(limiter) = &policy.rate_limiter {
                                        limiter.throttle(frame.payload.len()).await;
                                    }
                                    target_write.write_all(&frame.payload).await?;
                                }
                                FrameType::TcpFin | FrameType::CloseFlow | FrameType::TcpReset => {
                                    let _ = target_write.shutdown().await;
                                    client_eof = true;
                                }
                                _ => {}
                            },
                            Some(_) | None => {}
                        }
                    }
                    Some(Err(err)) => return Err(err.into()),
                    None => {
                        let _ = target_write.shutdown().await;
                        client_eof = true;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_tunnel(
    mut stream: H3ServerStream,
    peer: SocketAddr,
    state: ServerState,
    method: Method,
    path: String,
    fallback_headers: HeaderMap,
) -> Result<()> {
    let max_frame_size = state.config.advanced.max_frame_size as usize;
    let mut recv_buf = BytesMut::new();
    let mut fallback_body = BytesMut::new();
    let first_frame = match timeout(
        unauthenticated_first_frame_timeout(&state.config),
        h3_read_next_frame_capturing(
            &mut stream,
            &mut recv_buf,
            max_frame_size,
            &mut fallback_body,
            MAX_FALLBACK_REQUEST_BODY_BYTES,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            info!("unauthenticated h3 tunnel-like request rejected");
            return reject_h3_to_fallback(
                stream,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body.freeze(),
            )
            .await;
        }
    };
    let now_unix = current_unix();
    let authenticated = match first_frame {
        Ok(Some(frame)) if frame.frame_type == FrameType::ClientHello => {
            match authenticate_client_hello(&frame.payload, &state, now_unix, None) {
                Some(authenticated) => authenticated,
                None => {
                    info!("unauthenticated h3 tunnel-like request rejected");
                    return reject_h3_to_fallback(
                        stream,
                        &state,
                        peer,
                        &method,
                        &path,
                        &fallback_headers,
                        fallback_body.freeze(),
                    )
                    .await;
                }
            }
        }
        _ => {
            info!("unauthenticated h3 tunnel-like request rejected");
            return reject_h3_to_fallback(
                stream,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body.freeze(),
            )
            .await;
        }
    };
    {
        let mut replay = replay_shard(&state, &authenticated.replay_key).lock().await;
        if replay
            .check_and_insert(
                &authenticated.replay_key,
                authenticated.client_nonce(),
                authenticated.timestamp_unix(),
                now_unix,
            )
            .is_err()
        {
            info!("unauthenticated h3 tunnel-like request rejected");
            return reject_h3_to_fallback(
                stream,
                &state,
                peer,
                &method,
                &path,
                &fallback_headers,
                fallback_body.freeze(),
            )
            .await;
        }
    }
    info!(
        user = %redact_id(&authenticated.credential.user.id),
        credential_state = authenticated.credential.state.as_str(),
        "Maverick H3 session authenticated"
    );
    state
        .metrics
        .authenticated_sessions
        .fetch_add(1, Ordering::Relaxed);
    let user_policy = state
        .policies
        .for_user(&authenticated.credential.user.id)
        .context("missing authenticated user policy")?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())?;
    stream.send_response(response).await?;
    let max_concurrent_flows = authenticated
        .credential
        .user
        .max_concurrent_flows
        .unwrap_or(state.config.maverick.max_concurrent_flows_per_user);
    let server_hello_payload = authenticated.server_hello_payload(
        state.config.advanced.max_frame_size,
        max_concurrent_flows,
        None,
    )?;
    h3_send_server_frame(
        &mut stream,
        Frame::new(FrameType::ServerHello, 0, 0, server_hello_payload),
        max_frame_size,
        false,
        &state,
    )
    .await?;

    let open_frame = match timeout(
        Duration::from_millis(state.config.advanced.handshake_timeout_ms),
        h3_read_next_frame(&mut stream, &mut recv_buf, max_frame_size),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) | Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(0, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                &state,
            )
            .await?;
            return Ok(());
        }
        Ok(Err(err)) => return Err(err),
    };
    if open_frame.frame_type == FrameType::DnsQuery {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                h3_send_server_frame(
                    &mut stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )
                .await?;
                return Ok(());
            }
        };
        return handle_h3_dns_query(open_frame, stream, &state, &user_policy, max_frame_size).await;
    }
    if open_frame.frame_type == FrameType::OpenUdp {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                h3_send_server_frame(
                    &mut stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )
                .await?;
                return Ok(());
            }
        };
        return handle_h3_udp_flow(
            open_frame,
            stream,
            recv_buf,
            &state,
            &user_policy,
            max_frame_size,
        )
        .await;
    }
    if open_frame.frame_type == FrameType::UdpPacket {
        let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
            Some(permit) => permit,
            None => {
                h3_send_server_frame(
                    &mut stream,
                    relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                    max_frame_size,
                    true,
                    &state,
                )
                .await?;
                return Ok(());
            }
        };
        return handle_h3_udp_packet(open_frame, stream, &state, &user_policy, max_frame_size)
            .await;
    }
    if open_frame.frame_type != FrameType::OpenTcp {
        h3_send_server_frame(
            &mut stream,
            relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
            max_frame_size,
            true,
            &state,
        )
        .await?;
        return Ok(());
    }
    let open = match OpenTcpPayload::decode(&open_frame.payload) {
        Ok(open) => open,
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                &state,
            )
            .await?;
            return Ok(());
        }
    };
    let _flow_permit = match try_user_flow_permit(&state, &user_policy) {
        Some(permit) => permit,
        None => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::FlowLimitExceeded),
                max_frame_size,
                true,
                &state,
            )
            .await?;
            return Ok(());
        }
    };

    let target = match relay::open_target(
        &open,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(target) => target,
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(open_frame.flow_id, ErrorCode::TargetConnectFailed),
                max_frame_size,
                true,
                &state,
            )
            .await?;
            return Ok(());
        }
    };
    state.metrics.tcp_flows.fetch_add(1, Ordering::Relaxed);

    h3_send_server_frame(
        &mut stream,
        Frame::new(FrameType::WindowUpdate, 0, open_frame.flow_id, Bytes::new()),
        max_frame_size,
        false,
        &state,
    )
    .await?;
    relay_h3_target_and_tunnel(
        target,
        stream,
        recv_buf,
        max_frame_size,
        open_frame.flow_id,
        relay::TunnelRelayPolicy {
            idle_timeout: Duration::from_secs(state.config.advanced.idle_timeout_secs),
            rate_limiter: user_policy.rate_limiter.clone(),
            padding: server_padding(&state),
            cover_traffic: server_cover_traffic(&state),
            shaping_metrics: Some(state.metrics.shaping_sinks()),
        },
    )
    .await
}

async fn handle_udp_packet(
    frame: Frame,
    mut send_stream: h2::SendStream<Bytes>,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let packet = match UdpPacketPayload::decode(&frame.payload) {
        Ok(packet) => packet,
        Err(_) => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                state,
            )?;
            return Ok(());
        }
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(packet.data.len()).await;
    }
    match relay::relay_udp_packet(
        &packet,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.data.len()).await;
            }
            send_h2_server_frame(
                &mut send_stream,
                Frame::new(FrameType::UdpPacket, 0, frame.flow_id, response.encode()?),
                max_frame_size,
                true,
                state,
            )?
        }
        Err(_) => send_h2_server_frame(
            &mut send_stream,
            relay::error_frame(frame.flow_id, ErrorCode::TargetConnectFailed),
            max_frame_size,
            true,
            state,
        )?,
    }
    Ok(())
}

async fn handle_udp_flow(
    frame: Frame,
    mut send_stream: h2::SendStream<Bytes>,
    mut recv_stream: h2::RecvStream,
    mut recv_buf: BytesMut,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let idle_timeout_ms = match udp_idle_timeout_ms(&frame, state) {
        Ok(timeout) => timeout,
        Err(_) => {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                state,
            )?;
            return Ok(());
        }
    };
    send_h2_server_frame(
        &mut send_stream,
        Frame::new(FrameType::WindowUpdate, 0, frame.flow_id, Bytes::new()),
        max_frame_size,
        false,
        state,
    )?;

    loop {
        let next_frame = timeout(
            Duration::from_millis(idle_timeout_ms),
            relay::read_next_frame(&mut recv_stream, &mut recv_buf, max_frame_size),
        )
        .await;
        let frame = match next_frame {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                send_h2_server_frame(
                    &mut send_stream,
                    Frame::new(FrameType::CloseFlow, 0, frame.flow_id, Bytes::new()),
                    max_frame_size,
                    true,
                    state,
                )?;
                break;
            }
        };
        if frame.frame_type == FrameType::CloseFlow {
            break;
        }
        if frame.frame_type != FrameType::UdpPacket {
            send_h2_server_frame(
                &mut send_stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                false,
                state,
            )?;
            continue;
        }
        send_udp_packet_response(frame, &mut send_stream, state, user_policy, max_frame_size)
            .await?;
    }
    Ok(())
}

fn udp_idle_timeout_ms(frame: &Frame, state: &ServerState) -> Result<u64> {
    let requested = OpenUdpPayload::decode(&frame.payload)?;
    if requested.idle_timeout_ms == 0 {
        anyhow::bail!("UDP idle timeout must be non-zero");
    }
    Ok(requested
        .idle_timeout_ms
        .min(state.config.advanced.udp_idle_timeout_ms))
}

async fn send_udp_packet_response(
    frame: Frame,
    send_stream: &mut h2::SendStream<Bytes>,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let packet = match UdpPacketPayload::decode(&frame.payload) {
        Ok(packet) => packet,
        Err(_) => {
            send_h2_server_frame(
                send_stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                false,
                state,
            )?;
            return Ok(());
        }
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(packet.data.len()).await;
    }
    match relay::relay_udp_packet(
        &packet,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.data.len()).await;
            }
            send_h2_server_frame(
                send_stream,
                Frame::new(FrameType::UdpPacket, 0, frame.flow_id, response.encode()?),
                max_frame_size,
                false,
                state,
            )?
        }
        Err(_) => send_h2_server_frame(
            send_stream,
            relay::error_frame(frame.flow_id, ErrorCode::TargetConnectFailed),
            max_frame_size,
            false,
            state,
        )?,
    }
    Ok(())
}

async fn handle_dns_query(
    frame: Frame,
    mut send_stream: h2::SendStream<Bytes>,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    state.metrics.dns_queries.fetch_add(1, Ordering::Relaxed);
    let Some(dns) = &state.config.dns else {
        send_h2_server_frame(
            &mut send_stream,
            relay::error_frame(frame.flow_id, ErrorCode::InternalError),
            max_frame_size,
            true,
            state,
        )?;
        return Ok(());
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(frame.payload.len()).await;
    }

    match relay::relay_dns_query(
        &frame.payload,
        &dns.upstream,
        dns.timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.len()).await;
            }
            send_h2_server_frame(
                &mut send_stream,
                Frame::new(FrameType::DnsResponse, 0, frame.flow_id, response),
                max_frame_size,
                true,
                state,
            )?
        }
        Err(_) => send_h2_server_frame(
            &mut send_stream,
            relay::error_frame(frame.flow_id, ErrorCode::InternalError),
            max_frame_size,
            true,
            state,
        )?,
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_udp_packet(
    frame: Frame,
    mut stream: H3ServerStream,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let packet = match UdpPacketPayload::decode(&frame.payload) {
        Ok(packet) => packet,
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                state,
            )
            .await?;
            return Ok(());
        }
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(packet.data.len()).await;
    }
    match relay::relay_udp_packet(
        &packet,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.data.len()).await;
            }
            h3_send_server_frame(
                &mut stream,
                Frame::new(FrameType::UdpPacket, 0, frame.flow_id, response.encode()?),
                max_frame_size,
                true,
                state,
            )
            .await?
        }
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(frame.flow_id, ErrorCode::TargetConnectFailed),
                max_frame_size,
                true,
                state,
            )
            .await?
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_udp_flow(
    frame: Frame,
    mut stream: H3ServerStream,
    mut recv_buf: BytesMut,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let idle_timeout_ms = match udp_idle_timeout_ms(&frame, state) {
        Ok(timeout) => timeout,
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                true,
                state,
            )
            .await?;
            return Ok(());
        }
    };
    h3_send_server_frame(
        &mut stream,
        Frame::new(FrameType::WindowUpdate, 0, frame.flow_id, Bytes::new()),
        max_frame_size,
        false,
        state,
    )
    .await?;

    loop {
        let next_frame = timeout(
            Duration::from_millis(idle_timeout_ms),
            h3_read_next_frame(&mut stream, &mut recv_buf, max_frame_size),
        )
        .await;
        let frame = match next_frame {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                h3_send_server_frame(
                    &mut stream,
                    Frame::new(FrameType::CloseFlow, 0, frame.flow_id, Bytes::new()),
                    max_frame_size,
                    true,
                    state,
                )
                .await?;
                break;
            }
        };
        if frame.frame_type == FrameType::CloseFlow {
            break;
        }
        if frame.frame_type != FrameType::UdpPacket {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                false,
                state,
            )
            .await?;
            continue;
        }
        send_h3_udp_packet_response(frame, &mut stream, state, user_policy, max_frame_size).await?;
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn send_h3_udp_packet_response(
    frame: Frame,
    stream: &mut H3ServerStream,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    let packet = match UdpPacketPayload::decode(&frame.payload) {
        Ok(packet) => packet,
        Err(_) => {
            h3_send_server_frame(
                stream,
                relay::error_frame(frame.flow_id, ErrorCode::ProtocolError),
                max_frame_size,
                false,
                state,
            )
            .await?;
            return Ok(());
        }
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(packet.data.len()).await;
    }
    match relay::relay_udp_packet(
        &packet,
        state.config.advanced.tcp_connect_timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.data.len()).await;
            }
            h3_send_server_frame(
                stream,
                Frame::new(FrameType::UdpPacket, 0, frame.flow_id, response.encode()?),
                max_frame_size,
                false,
                state,
            )
            .await?
        }
        Err(_) => {
            h3_send_server_frame(
                stream,
                relay::error_frame(frame.flow_id, ErrorCode::TargetConnectFailed),
                max_frame_size,
                false,
                state,
            )
            .await?
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn handle_h3_dns_query(
    frame: Frame,
    mut stream: H3ServerStream,
    state: &ServerState,
    user_policy: &UserPolicy,
    max_frame_size: usize,
) -> Result<()> {
    state.metrics.dns_queries.fetch_add(1, Ordering::Relaxed);
    let Some(dns) = &state.config.dns else {
        h3_send_server_frame(
            &mut stream,
            relay::error_frame(frame.flow_id, ErrorCode::InternalError),
            max_frame_size,
            true,
            state,
        )
        .await?;
        return Ok(());
    };
    if let Some(limiter) = &user_policy.rate_limiter {
        limiter.throttle(frame.payload.len()).await;
    }

    match relay::relay_dns_query(
        &frame.payload,
        &dns.upstream,
        dns.timeout_ms,
        &state.config.advanced.egress,
    )
    .await
    {
        Ok(response) => {
            if let Some(limiter) = &user_policy.rate_limiter {
                limiter.throttle(response.len()).await;
            }
            h3_send_server_frame(
                &mut stream,
                Frame::new(FrameType::DnsResponse, 0, frame.flow_id, response),
                max_frame_size,
                true,
                state,
            )
            .await?
        }
        Err(_) => {
            h3_send_server_frame(
                &mut stream,
                relay::error_frame(frame.flow_id, ErrorCode::InternalError),
                max_frame_size,
                true,
                state,
            )
            .await?
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn relay_h3_target_and_tunnel(
    target: TcpStream,
    mut stream: H3ServerStream,
    mut recv_buf: BytesMut,
    max_frame_size: usize,
    flow_id: u64,
    policy: relay::TunnelRelayPolicy,
) -> Result<()> {
    let (mut target_read, mut target_write) = target.into_split();
    let mut target_buf = vec![0u8; 16 * 1024];
    let mut client_eof = false;

    loop {
        if client_eof {
            tokio::select! {
                _ = tokio::time::sleep(policy.idle_timeout) => {
                    break;
                }
                target_read_result = target_read.read(&mut target_buf) => {
                    let n = target_read_result?;
                    if n == 0 {
                        let padding_bytes = h3_send_frame_with_padding(
                            &mut stream,
                            Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                            max_frame_size,
                            true,
                            &policy.padding,
                            &policy.cover_traffic,
                        )
                        .await?;
                        policy.record_padding(padding_bytes);
                        break;
                    }
                    if let Some(limiter) = &policy.rate_limiter {
                        limiter.throttle(n).await;
                    }
                    let padding_bytes = h3_send_frame_with_padding(
                        &mut stream,
                        Frame::new(
                            FrameType::TcpData,
                            0,
                            flow_id,
                            Bytes::copy_from_slice(&target_buf[..n]),
                        ),
                        max_frame_size,
                        false,
                        &policy.padding,
                        &policy.cover_traffic,
                    )
                    .await?;
                    policy.record_padding(padding_bytes);
                }
            }
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(policy.idle_timeout) => {
                break;
            }
            target_read_result = target_read.read(&mut target_buf) => {
                let n = target_read_result?;
                if n == 0 {
                    let padding_bytes = h3_send_frame_with_padding(
                        &mut stream,
                        Frame::new(FrameType::TcpFin, 0, flow_id, Bytes::new()),
                        max_frame_size,
                        true,
                        &policy.padding,
                        &policy.cover_traffic,
                    )
                    .await?;
                    policy.record_padding(padding_bytes);
                    break;
                }
                if let Some(limiter) = &policy.rate_limiter {
                    limiter.throttle(n).await;
                }
                let padding_bytes = h3_send_frame_with_padding(
                    &mut stream,
                    Frame::new(FrameType::TcpData, 0, flow_id, Bytes::copy_from_slice(&target_buf[..n])),
                    max_frame_size,
                    false,
                    &policy.padding,
                    &policy.cover_traffic,
                )
                .await?;
                policy.record_padding(padding_bytes);
            }
            tunnel_frame = h3_read_next_frame(&mut stream, &mut recv_buf, max_frame_size) => {
                match tunnel_frame? {
                    Some(frame) if frame.flow_id == flow_id => {
                        match frame.frame_type {
                            FrameType::TcpData => {
                                if let Some(limiter) = &policy.rate_limiter {
                                    limiter.throttle(frame.payload.len()).await;
                                }
                                target_write.write_all(&frame.payload).await?;
                            }
                            FrameType::TcpFin | FrameType::CloseFlow | FrameType::TcpReset => {
                                let _ = target_write.shutdown().await;
                                client_eof = true;
                            }
                            _ => {}
                        }
                    }
                    Some(_) => {}
                    None => {
                        let _ = target_write.shutdown().await;
                        client_eof = true;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn h3_send_frame(
    stream: &mut H3ServerStream,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
) -> Result<()> {
    stream.send_data(frame.encode(max_frame_size)?).await?;
    if end_stream {
        stream.finish().await?;
    }
    Ok(())
}

#[cfg(feature = "h3")]
async fn h3_send_frame_with_padding(
    stream: &mut H3ServerStream,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    padding: &RuntimePadding,
    cover_traffic: &RuntimeCoverTraffic,
) -> Result<relay::PaddingEmission> {
    let mut emission = relay::PaddingEmission::default();
    if let Some(padding_frame) =
        padding.padding_frame(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.padding_frames += 1;
        emission.padding_bytes += padding_frame.payload.len();
        h3_send_frame(stream, padding_frame, max_frame_size, false).await?;
    }
    for cover_frame in
        cover_traffic.padding_frames(frame.frame_type, frame.payload.len(), max_frame_size)
    {
        emission.cover_traffic_padding_frames += 1;
        emission.cover_traffic_padding_bytes += cover_frame.payload.len();
        h3_send_frame(stream, cover_frame, max_frame_size, false).await?;
    }
    h3_send_frame(stream, frame, max_frame_size, end_stream).await?;
    Ok(emission)
}

#[cfg(feature = "h3")]
async fn h3_send_server_frame(
    stream: &mut H3ServerStream,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    state: &ServerState,
) -> Result<()> {
    let padding_bytes = h3_send_frame_with_padding(
        stream,
        frame,
        max_frame_size,
        end_stream,
        &server_padding(state),
        &server_cover_traffic(state),
    )
    .await?;
    state.metrics.record_shaping_padding(padding_bytes);
    Ok(())
}

#[cfg(feature = "h3")]
async fn h3_read_next_frame(
    stream: &mut H3ServerStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
) -> Result<Option<Frame>> {
    h3_read_next_frame_impl(stream, buf, max_frame_size, None, usize::MAX).await
}

#[cfg(feature = "h3")]
async fn h3_read_next_frame_capturing(
    stream: &mut H3ServerStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
    capture: &mut BytesMut,
    max_capture_size: usize,
) -> Result<Option<Frame>> {
    h3_read_next_frame_impl(stream, buf, max_frame_size, Some(capture), max_capture_size).await
}

#[cfg(feature = "h3")]
async fn h3_read_next_frame_impl(
    stream: &mut H3ServerStream,
    buf: &mut BytesMut,
    max_frame_size: usize,
    mut capture: Option<&mut BytesMut>,
    max_capture_size: usize,
) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = Frame::decode_from(buf, max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        match stream.recv_data().await? {
            Some(mut chunk) => {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                if let Some(capture) = capture.as_deref_mut() {
                    if bytes.len() > max_capture_size.saturating_sub(capture.len()) {
                        anyhow::bail!("captured h3 tunnel request body exceeded size limit");
                    }
                    capture.extend_from_slice(&bytes);
                }
                buf.extend_from_slice(&bytes);
            }
            None => return Ok(None),
        }
    }
}

async fn record_auth_failure(state: &ServerState, peer: SocketAddr) -> AuthFailureDecision {
    let decision = {
        let mut tracker = state.auth_failures.lock().await;
        tracker.record_failure(
            peer.ip(),
            std::time::Instant::now(),
            Duration::from_secs(state.config.advanced.auth_failure_window_secs),
            state.config.advanced.max_auth_failures_per_window,
            state.config.advanced.auth_failure_cache_max_entries as usize,
        )
    };
    if decision == AuthFailureDecision::RateLimited {
        state
            .metrics
            .auth_rate_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
    }
    decision
}

async fn reject_to_fallback(
    respond: SendResponse<Bytes>,
    state: &ServerState,
    peer: SocketAddr,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    request_body: Bytes,
) -> Result<()> {
    state
        .metrics
        .unauthenticated_rejections
        .fetch_add(1, Ordering::Relaxed);
    if record_auth_failure(state, peer).await == AuthFailureDecision::RateLimited
        && !state.config.advanced.stealth.active_probe_resistance
    {
        return Ok(());
    }
    send_fallback_with_body(respond, state, method, path, headers, request_body).await
}

async fn reject_tunnel_to_fallback(
    respond: SendResponse<Bytes>,
    state: &ServerState,
    peer: SocketAddr,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    captured_body: BytesMut,
) -> Result<()> {
    reject_to_fallback(
        respond,
        state,
        peer,
        method,
        path,
        headers,
        captured_body.freeze(),
    )
    .await
}

#[cfg(feature = "h3")]
async fn reject_h3_to_fallback(
    stream: H3ServerStream,
    state: &ServerState,
    peer: SocketAddr,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    request_body: Bytes,
) -> Result<()> {
    state
        .metrics
        .unauthenticated_rejections
        .fetch_add(1, Ordering::Relaxed);
    if record_auth_failure(state, peer).await == AuthFailureDecision::RateLimited
        && !state.config.advanced.stealth.active_probe_resistance
    {
        return Ok(());
    }
    send_h3_fallback_with_body(stream, state, method, path, headers, request_body).await
}

async fn send_fallback(
    respond: SendResponse<Bytes>,
    state: &ServerState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<()> {
    send_fallback_with_body(respond, state, method, path, headers, Bytes::new()).await
}

async fn send_fallback_with_body(
    mut respond: SendResponse<Bytes>,
    state: &ServerState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    request_body: Bytes,
) -> Result<()> {
    let Some(_fallback_permit) = try_fallback_admission(state) else {
        return send_fallback_overload(respond).await;
    };
    state
        .metrics
        .fallback_requests
        .fetch_add(1, Ordering::Relaxed);
    let fallback_response = match state
        .fallback
        .response_for_with_body(method, path, headers, request_body)
        .await
    {
        Ok(response) => response,
        Err(_) => fallback_bad_gateway_response()?,
    };
    let (parts, body) = fallback_response.into_parts();
    let response = Response::from_parts(parts, ());
    let end_stream = body.is_empty();
    let mut stream = respond.send_response(response, end_stream)?;
    if !end_stream {
        stream.send_data(body, true)?;
    }
    Ok(())
}

fn fallback_request_headers(headers: &HeaderMap) -> HeaderMap {
    let mut fallback_headers = HeaderMap::new();
    for (name, value) in headers {
        fallback_headers.append(name, value.clone());
    }
    fallback_headers
}

async fn send_fallback_overload(mut respond: SendResponse<Bytes>) -> Result<()> {
    let body = Bytes::from_static(b"Service unavailable");
    let response = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/plain; charset=utf-8")
        .body(())?;
    let mut stream = respond.send_response(response, false)?;
    stream.send_data(body, true)?;
    Ok(())
}

fn fallback_bad_gateway_response() -> Result<Response<Bytes>> {
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Bytes::from_static(b"Bad Gateway"))?)
}

async fn collect_fallback_request_body(recv_stream: &mut h2::RecvStream) -> Result<Bytes> {
    let mut body = BytesMut::new();
    while let Some(chunk) = recv_stream.data().await {
        let chunk = chunk?;
        let consumed = chunk.len();
        if body.len() + consumed > MAX_FALLBACK_REQUEST_BODY_BYTES {
            anyhow::bail!("fallback request body exceeded size limit");
        }
        recv_stream.flow_control().release_capacity(consumed)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[cfg(feature = "h3")]
async fn collect_h3_fallback_request_body(stream: &mut H3ServerStream) -> Result<Bytes> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if chunk.remaining() > MAX_FALLBACK_REQUEST_BODY_BYTES.saturating_sub(body.len()) {
            anyhow::bail!("h3 fallback request body exceeded size limit");
        }
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(body.freeze())
}

#[cfg(feature = "h3")]
async fn send_h3_fallback_with_body(
    mut stream: H3ServerStream,
    state: &ServerState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    request_body: Bytes,
) -> Result<()> {
    let Some(_fallback_permit) = try_fallback_admission(state) else {
        return send_h3_fallback_overload(stream).await;
    };
    state
        .metrics
        .fallback_requests
        .fetch_add(1, Ordering::Relaxed);
    let fallback_response = match state
        .fallback
        .response_for_with_body(method, path, headers, request_body)
        .await
    {
        Ok(response) => response,
        Err(_) => fallback_bad_gateway_response()?,
    };
    let (parts, body) = fallback_response.into_parts();
    let response = Response::from_parts(parts, ());
    stream.send_response(response).await?;
    if !body.is_empty() {
        stream.send_data(body).await?;
    }
    stream.finish().await?;
    Ok(())
}

#[cfg(feature = "h3")]
async fn send_h3_fallback_overload(mut stream: H3ServerStream) -> Result<()> {
    let response = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/plain; charset=utf-8")
        .body(())?;
    stream.send_response(response).await?;
    stream
        .send_data(Bytes::from_static(b"Service unavailable"))
        .await?;
    stream.finish().await?;
    Ok(())
}

#[derive(Clone)]
struct UserPolicy {
    flow_limit: Arc<Semaphore>,
    rate_limiter: Option<Arc<relay::RateLimiter>>,
}

struct ServerPolicies {
    users: HashMap<String, UserPolicy>,
}

impl ServerPolicies {
    fn from_config(config: &ServerConfig) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| user.enabled)
            .map(|user| {
                let max_flows = user
                    .max_concurrent_flows
                    .unwrap_or(config.maverick.max_concurrent_flows_per_user)
                    .max(1) as usize;
                let rate_limiter = user
                    .rate_limit
                    .as_ref()
                    .map(|rate| Arc::new(relay::RateLimiter::new(rate.bytes_per_second)));
                (
                    user.id.clone(),
                    UserPolicy {
                        flow_limit: Arc::new(Semaphore::new(max_flows)),
                        rate_limiter,
                    },
                )
            })
            .collect();
        Self { users }
    }

    fn for_user(&self, user_id: &str) -> Option<UserPolicy> {
        self.users.get(user_id).cloned()
    }
}

async fn serve_metrics(
    listener: TcpListener,
    metrics: Arc<ServerRuntimeMetrics>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut metric_tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            joined = metric_tasks.join_next(), if !metric_tasks.is_empty() => {
                if let Some(joined) = joined {
                    joined?;
                }
            }
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(error = %err, "metrics accept failed");
                        sleep(LISTENER_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let metrics = Arc::clone(&metrics);
                metric_tasks.spawn(async move {
                    let _ = handle_metrics_connection(stream, metrics).await;
                });
            }
        }
    }
    metric_tasks.abort_all();
    while let Some(joined) = metric_tasks.join_next().await {
        if let Err(err) = joined {
            if !err.is_cancelled() {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    metrics: Arc<ServerRuntimeMetrics>,
) -> Result<()> {
    let mut buf = [0u8; 1024];
    let n = timeout(METRICS_READ_TIMEOUT, stream.read(&mut buf))
        .await
        .context("metrics request read timed out")??;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or_default();
    if request.starts_with("GET /metrics ") {
        let body = metrics.json_snapshot();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
    } else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await?;
    }
    Ok(())
}
