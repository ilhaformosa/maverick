use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
#[cfg(feature = "h3")]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use futures::{future::poll_fn, SinkExt, StreamExt};
use http::Request;
use maverick_core::auth::{
    ClientHello, ClientHelloV2, ClientHelloV2Params, ServerHello, ServerHelloV2, TlsChannelBinding,
    AUTH_V2_PROTOCOL_VERSION, FEATURE_OPEN_UDP_MODE_NEGOTIATION, FEATURE_TLS_CHANNEL_BINDING,
    PROTOCOL_VERSION,
};
use maverick_core::config::{parse_auth_epoch, select_client_credential_at_unix};
use maverick_core::frame::{Frame, FrameType};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::padding::{RuntimeBatcher, RuntimeCoverTraffic, RuntimePadding};
use maverick_core::{ClientConfig, SecretString};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use crate::transport::{self, TunnelRequestSender};

const DEFAULT_MAX_FRAME_SIZE: usize = 65_536;
const MAX_NEGOTIATED_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct H2SendStalled;

impl std::fmt::Display for H2SendStalled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("h2 send stalled while waiting for receiver capacity")
    }
}

impl std::error::Error for H2SendStalled {}

pub enum ClientTunnel {
    H2(Box<H2ClientTunnel>),
    CloudflareWs(Box<WsClientTunnel>),
    #[cfg(feature = "h3")]
    H3(Box<H3ClientTunnel>),
}

pub struct H2ClientTunnel {
    pub send_stream: h2::SendStream<Bytes>,
    pub recv_stream: h2::RecvStream,
    pub recv_buf: BytesMut,
    pub max_frame_size: usize,
    feature_flags_selected: Option<u64>,
    padding: RuntimePadding,
    cover_traffic: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
    send_stall_timeout: Duration,
    connection_lease: Option<crate::connection_manager::H2ConnectionLease>,
}

pub struct WsClientTunnel {
    pub stream: crate::ws_transport::WsClientStream,
    pub recv_buf: BytesMut,
    pub max_frame_size: usize,
    feature_flags_selected: Option<u64>,
    padding: RuntimePadding,
    cover_traffic: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
}

#[cfg(feature = "h3")]
pub struct H3ClientTunnel {
    stream: crate::h3_transport::H3ClientRequestStream,
    recv_buf: BytesMut,
    max_frame_size: usize,
    feature_flags_selected: Option<u64>,
    padding: RuntimePadding,
    cover_traffic: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
    _transport: crate::h3_transport::H3RequestSender,
}

impl ClientTunnel {
    pub fn max_frame_size(&self) -> usize {
        match self {
            Self::H2(tunnel) => tunnel.max_frame_size,
            Self::CloudflareWs(tunnel) => tunnel.max_frame_size,
            #[cfg(feature = "h3")]
            Self::H3(tunnel) => tunnel.max_frame_size,
        }
    }

    pub(crate) fn feature_flags_selected(&self) -> u64 {
        let selected = match self {
            Self::H2(tunnel) => tunnel.feature_flags_selected,
            Self::CloudflareWs(tunnel) => tunnel.feature_flags_selected,
            #[cfg(feature = "h3")]
            Self::H3(tunnel) => tunnel.feature_flags_selected,
        };
        selected.expect("returned client tunnel has a verified ServerHello")
    }

    pub async fn send_frame(&mut self, frame: Frame, end_stream: bool) -> Result<()> {
        let max_frame_size = self.max_frame_size();
        match self {
            Self::H2(tunnel) => {
                let result: Result<()> = async {
                    let frames =
                        prepare_outgoing_frames(frame, &mut tunnel.batcher, &tunnel.padding).await;
                    let last = frames.len().saturating_sub(1);
                    for (idx, frame) in frames.into_iter().enumerate() {
                        if let Some(padding) = tunnel.padding.padding_frame(
                            frame.frame_type,
                            frame.payload.len(),
                            max_frame_size,
                        ) {
                            send_h2_frame(
                                &mut tunnel.send_stream,
                                padding,
                                max_frame_size,
                                false,
                                tunnel.send_stall_timeout,
                            )
                            .await?;
                        }
                        for cover_frame in tunnel.cover_traffic.padding_frames(
                            frame.frame_type,
                            frame.payload.len(),
                            max_frame_size,
                        ) {
                            send_h2_frame(
                                &mut tunnel.send_stream,
                                cover_frame,
                                max_frame_size,
                                false,
                                tunnel.send_stall_timeout,
                            )
                            .await?;
                        }
                        send_h2_frame(
                            &mut tunnel.send_stream,
                            frame,
                            max_frame_size,
                            end_stream && idx == last,
                            tunnel.send_stall_timeout,
                        )
                        .await?;
                    }
                    Ok(())
                }
                .await;
                record_h2_runtime_failure(tunnel, &result);
                result
            }
            Self::CloudflareWs(tunnel) => {
                let frames =
                    prepare_outgoing_frames(frame, &mut tunnel.batcher, &tunnel.padding).await;
                for frame in frames {
                    if let Some(padding) = tunnel.padding.padding_frame(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        tunnel
                            .stream
                            .send(Message::Binary(padding.encode(max_frame_size)?))
                            .await?;
                    }
                    for cover_frame in tunnel.cover_traffic.padding_frames(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        tunnel
                            .stream
                            .send(Message::Binary(cover_frame.encode(max_frame_size)?))
                            .await?;
                    }
                    tunnel
                        .stream
                        .send(Message::Binary(frame.encode(max_frame_size)?))
                        .await?;
                }
                Ok(())
            }
            #[cfg(feature = "h3")]
            Self::H3(tunnel) => {
                let frames =
                    prepare_outgoing_frames(frame, &mut tunnel.batcher, &tunnel.padding).await;
                let last = frames.len().saturating_sub(1);
                for (idx, frame) in frames.into_iter().enumerate() {
                    if let Some(padding) = tunnel.padding.padding_frame(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        tunnel
                            .stream
                            .send_data(padding.encode(max_frame_size)?)
                            .await?;
                    }
                    for cover_frame in tunnel.cover_traffic.padding_frames(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        tunnel
                            .stream
                            .send_data(cover_frame.encode(max_frame_size)?)
                            .await?;
                    }
                    let encoded = frame.encode(max_frame_size)?;
                    tunnel.stream.send_data(encoded).await?;
                    if end_stream && idx == last {
                        tunnel.stream.finish().await?;
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn read_next_frame(&mut self) -> Result<Option<Frame>> {
        match self {
            Self::H2(tunnel) => {
                let result = read_next_h2_frame(tunnel).await;
                record_h2_runtime_failure(tunnel, &result);
                result
            }
            Self::CloudflareWs(tunnel) => read_next_ws_frame(tunnel).await,
            #[cfg(feature = "h3")]
            Self::H3(tunnel) => read_next_h3_frame(tunnel).await,
        }
    }

    pub(crate) async fn finish_response(&mut self) -> Result<()> {
        self.finish_response_with_legacy_udp_reset(false).await
    }

    pub(crate) async fn finish_response_after_explicit_udp_close(&mut self) -> Result<()> {
        self.finish_response_with_legacy_udp_reset(true).await
    }

    async fn finish_response_with_legacy_udp_reset(
        &mut self,
        allow_legacy_udp_reset: bool,
    ) -> Result<()> {
        match self {
            Self::H2(tunnel) => {
                let finish_timeout = tunnel.send_stall_timeout;
                let result = match timeout(
                    finish_timeout,
                    finish_h2_response(tunnel, allow_legacy_udp_reset),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!("gRPC response completion timed out")),
                };
                record_h2_runtime_failure(tunnel, &result);
                result
            }
            Self::CloudflareWs(_) => Ok(()),
            #[cfg(feature = "h3")]
            Self::H3(_) => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H2RuntimeFailureKind {
    StreamReset,
    SendStall,
}

fn classify_h2_runtime_failure(error: &anyhow::Error) -> Option<H2RuntimeFailureKind> {
    if error
        .chain()
        .any(|source| source.downcast_ref::<H2SendStalled>().is_some())
    {
        return Some(H2RuntimeFailureKind::SendStall);
    }
    if error.chain().any(|source| {
        source
            .downcast_ref::<h2::Error>()
            .is_some_and(h2::Error::is_reset)
    }) {
        return Some(H2RuntimeFailureKind::StreamReset);
    }
    None
}

fn record_h2_runtime_failure<T>(tunnel: &H2ClientTunnel, result: &Result<T>) {
    let Err(error) = result else {
        return;
    };
    let Some(lease) = tunnel.connection_lease.as_ref() else {
        return;
    };
    match classify_h2_runtime_failure(error) {
        Some(H2RuntimeFailureKind::StreamReset) => lease.record_runtime_stream_reset(),
        Some(H2RuntimeFailureKind::SendStall) => lease.record_runtime_send_stall(),
        None => {}
    }
}

pub async fn open(config: &ClientConfig) -> Result<ClientTunnel> {
    match transport::connect(config).await? {
        TunnelRequestSender::H2(sender) => open_h2(config, sender, None).await,
        TunnelRequestSender::CloudflareWs(connection) => {
            open_cloudflare_ws(config, *connection).await
        }
        #[cfg(feature = "h3")]
        TunnelRequestSender::H3(sender) => open_h3(config, sender).await,
    }
}

pub(crate) async fn open_managed_h2(
    config: &ClientConfig,
    managed: crate::connection_manager::ManagedH2TunnelRequestSender,
) -> Result<ClientTunnel> {
    open_h2(config, managed.transport, Some(managed.lease)).await
}

async fn open_h2(
    config: &ClientConfig,
    mut transport: transport::H2TunnelRequestSender,
    connection_lease: Option<crate::connection_manager::H2ConnectionLease>,
) -> Result<ClientTunnel> {
    let req = build_h2_tunnel_request(config)?;
    let channel_binding = transport.channel_binding;
    let (response_fut, mut send_stream) = transport.sender.send_request(req, false)?;
    let hello = ClientHandshake::new(
        config,
        channel_binding,
        ClientHandshakeCarrier::LegacyH2OrH3,
    )?;
    // ClientAdvancedConfig has no separate handshake timeout. Its connect timeout
    // is already the client's tunnel-handshake budget.
    let handshake_stall_timeout = Duration::from_millis(config.advanced.connect_timeout_ms);
    send_h2_frame(
        &mut send_stream,
        Frame::new(FrameType::ClientHello, 0, 0, hello.encode()?),
        DEFAULT_MAX_FRAME_SIZE,
        false,
        handshake_stall_timeout,
    )
    .await?;

    let response = response_fut.await.context("missing h2 tunnel response")?;
    if !response.status().is_success() {
        bail!("server returned non-success status: {}", response.status());
    }
    let mut tunnel = H2ClientTunnel {
        send_stream,
        recv_stream: response.into_body(),
        recv_buf: BytesMut::new(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        feature_flags_selected: None,
        padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
        cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
        batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
        send_stall_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
        connection_lease,
    };
    let server_frame = read_next_h2_frame(&mut tunnel)
        .await?
        .context("missing ServerHello")?;
    if server_frame.frame_type == FrameType::Error {
        timeout(
            handshake_stall_timeout,
            finish_h2_response(&mut tunnel, false),
        )
        .await
        .map_err(|_| anyhow::anyhow!("gRPC handshake response completion timed out"))??;
        bail!("server rejected handshake");
    }
    if server_frame.frame_type != FrameType::ServerHello {
        bail!("missing ServerHello");
    }
    let negotiated = hello.verify_server_hello(&server_frame.payload)?;
    tunnel.max_frame_size = validate_negotiated_max_frame_size(negotiated.max_frame_size)?;
    tunnel.feature_flags_selected = Some(negotiated.feature_flags_selected);
    Ok(ClientTunnel::H2(Box::new(tunnel)))
}

fn build_h2_tunnel_request(config: &ClientConfig) -> Result<Request<()>> {
    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    Ok(Request::builder()
        .method("POST")
        .version(http::Version::HTTP_2)
        .uri(uri)
        // Cloudflare gates bidirectional H2 streaming through its gRPC path.
        // The body uses gRPC message envelopes that carry Maverick frames,
        // not protobuf messages.
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?)
}

async fn open_cloudflare_ws(
    config: &ClientConfig,
    connection: transport::CloudflareWsTunnel,
) -> Result<ClientTunnel> {
    let hello = ClientHandshake::new(
        config,
        connection.channel_binding,
        ClientHandshakeCarrier::WebSocket,
    )?;
    let mut tunnel = WsClientTunnel {
        stream: connection.stream,
        recv_buf: BytesMut::new(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        feature_flags_selected: None,
        padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
        cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
        batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
    };
    tunnel
        .stream
        .send(Message::Binary(
            Frame::new(FrameType::ClientHello, 0, 0, hello.encode()?)
                .encode(DEFAULT_MAX_FRAME_SIZE)?,
        ))
        .await?;

    let server_frame = read_next_ws_frame(&mut tunnel)
        .await?
        .context("missing ServerHello")?;
    if server_frame.frame_type != FrameType::ServerHello {
        bail!("missing ServerHello");
    }
    let negotiated = hello.verify_server_hello(&server_frame.payload)?;
    tunnel.max_frame_size = validate_negotiated_max_frame_size(negotiated.max_frame_size)?;
    tunnel.feature_flags_selected = Some(negotiated.feature_flags_selected);
    Ok(ClientTunnel::CloudflareWs(Box::new(tunnel)))
}

#[cfg(feature = "h3")]
async fn open_h3(
    config: &ClientConfig,
    mut transport: crate::h3_transport::H3RequestSender,
) -> Result<ClientTunnel> {
    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(())?;
    let mut stream = transport.send_request(req).await?;
    let hello = ClientHandshake::new(config, None, ClientHandshakeCarrier::LegacyH2OrH3)?;
    stream
        .send_data(
            Frame::new(FrameType::ClientHello, 0, 0, hello.encode()?)
                .encode(DEFAULT_MAX_FRAME_SIZE)?,
        )
        .await?;

    let response = stream
        .recv_response()
        .await
        .context("missing h3 tunnel response")?;
    if !response.status().is_success() {
        bail!("server returned non-success status: {}", response.status());
    }
    let mut tunnel = H3ClientTunnel {
        stream,
        recv_buf: BytesMut::new(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        feature_flags_selected: None,
        padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
        cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
        batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
        _transport: transport,
    };
    let server_frame = read_next_h3_frame(&mut tunnel)
        .await?
        .context("missing ServerHello")?;
    if server_frame.frame_type != FrameType::ServerHello {
        bail!("missing ServerHello");
    }
    let negotiated = hello.verify_server_hello(&server_frame.payload)?;
    tunnel.max_frame_size = validate_negotiated_max_frame_size(negotiated.max_frame_size)?;
    tunnel.feature_flags_selected = Some(negotiated.feature_flags_selected);
    Ok(ClientTunnel::H3(Box::new(tunnel)))
}

enum ClientHandshakeMessage {
    V1(ClientHello),
    V2(ClientHelloV2),
}

struct ClientHandshake {
    message: ClientHandshakeMessage,
    secret: SecretString,
    channel_binding: Option<TlsChannelBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientHandshakeCarrier {
    LegacyH2OrH3,
    WebSocket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NegotiatedServerHello {
    max_frame_size: u32,
    feature_flags_selected: u64,
}

impl ClientHandshake {
    fn new(
        config: &ClientConfig,
        channel_binding: Option<TlsChannelBinding>,
        carrier: ClientHandshakeCarrier,
    ) -> Result<Self> {
        let credential = select_client_credential_at_unix(
            &config.server,
            &config.auth.rotation,
            current_unix_timestamp()?,
        )?;
        let feature_flags = client_feature_flags(config, channel_binding, carrier)?;
        if config.auth.v2.enabled {
            let active_epoch =
                config.auth.rotation.active_epoch.as_deref().context(
                    "auth.rotation.active_epoch is required when auth.v2.enabled is true",
                )?;
            let auth_epoch = parse_auth_epoch(active_epoch)?;
            return Ok(Self {
                message: ClientHandshakeMessage::V2(ClientHelloV2::new_with_channel_binding(
                    ClientHelloV2Params {
                        credential_hint: credential.id.as_bytes().to_vec(),
                        secret: credential.secret,
                        auth_epoch,
                        tunnel_path: &config.server.tunnel_path,
                        mode: config.mode,
                        feature_flags,
                        rotation_flags: 0,
                        channel_binding: selected_channel_binding(feature_flags, channel_binding),
                    },
                )?),
                secret: credential.secret.clone(),
                channel_binding,
            });
        }

        Ok(Self {
            message: ClientHandshakeMessage::V1(ClientHello::try_new_with_channel_binding(
                credential.id.to_owned(),
                credential.secret,
                &config.server.tunnel_path,
                config.mode,
                feature_flags,
                selected_channel_binding(feature_flags, channel_binding),
            )?),
            secret: credential.secret.clone(),
            channel_binding,
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        match &self.message {
            ClientHandshakeMessage::V1(hello) => Ok(hello.encode()),
            ClientHandshakeMessage::V2(hello) => Ok(hello.encode()?),
        }
    }

    fn verify_server_hello(&self, payload: &[u8]) -> Result<NegotiatedServerHello> {
        match &self.message {
            ClientHandshakeMessage::V1(hello) => {
                let server_hello = ServerHello::decode(payload)?;
                if server_hello.protocol_version_selected != PROTOCOL_VERSION
                    || server_hello.max_concurrent_flows == 0
                    || has_unrequested_feature_flags(
                        server_hello.feature_flags_selected,
                        hello.feature_flags,
                    )
                    || !server_hello.verify_with_channel_binding(
                        &self.secret,
                        &hello.client_nonce,
                        selected_channel_binding(
                            server_hello.feature_flags_selected,
                            self.channel_binding,
                        ),
                    )
                {
                    bail!("invalid ServerHello");
                }
                Ok(NegotiatedServerHello {
                    max_frame_size: server_hello.max_frame_size,
                    feature_flags_selected: server_hello.feature_flags_selected,
                })
            }
            ClientHandshakeMessage::V2(hello) => {
                let server_hello = ServerHelloV2::decode(payload)?;
                if server_hello.protocol_version_selected != AUTH_V2_PROTOCOL_VERSION
                    || server_hello.selected_epoch != hello.auth_epoch
                    || server_hello.max_concurrent_flows == 0
                    || server_hello.rotation_window_secs == 0
                    || has_unrequested_feature_flags(
                        server_hello.feature_flags_selected,
                        hello.feature_flags,
                    )
                    || !server_hello.verify_with_channel_binding(
                        &self.secret,
                        &hello.client_nonce,
                        selected_channel_binding(
                            server_hello.feature_flags_selected,
                            self.channel_binding,
                        ),
                    )
                {
                    bail!("invalid ServerHello v2");
                }
                Ok(NegotiatedServerHello {
                    max_frame_size: server_hello.max_frame_size,
                    feature_flags_selected: server_hello.feature_flags_selected,
                })
            }
        }
    }
}

fn client_feature_flags(
    config: &ClientConfig,
    channel_binding: Option<TlsChannelBinding>,
    carrier: ClientHandshakeCarrier,
) -> Result<u64> {
    let mut selected = match carrier {
        ClientHandshakeCarrier::LegacyH2OrH3 => FEATURE_OPEN_UDP_MODE_NEGOTIATION,
        ClientHandshakeCarrier::WebSocket => 0,
    };
    if !config.auth.channel_binding.enabled {
        return Ok(selected);
    }
    if channel_binding.is_some() {
        selected |= FEATURE_TLS_CHANNEL_BINDING;
        return Ok(selected);
    }
    if config.auth.channel_binding.require {
        bail!("auth.channel_binding.require needs a transport with TLS channel binding support");
    }
    Ok(selected)
}

fn selected_channel_binding(
    selected: u64,
    channel_binding: Option<TlsChannelBinding>,
) -> Option<TlsChannelBinding> {
    if selected & FEATURE_TLS_CHANNEL_BINDING == 0 {
        return None;
    }
    channel_binding
}

fn has_unrequested_feature_flags(selected: u64, requested: u64) -> bool {
    selected & !requested != 0
}

async fn prepare_outgoing_frames(
    frame: Frame,
    batcher: &mut RuntimeBatcher,
    padding: &RuntimePadding,
) -> Vec<Frame> {
    if !batcher.is_enabled() {
        if let Some(delay) = padding.pacing_delay(frame.frame_type, frame.payload.len()) {
            tokio::time::sleep(delay).await;
        }
        return vec![frame];
    }

    let mut ready = batcher.push(frame);
    if ready.is_empty() {
        if let Some(delay) = batcher.flush_delay() {
            tokio::time::sleep(delay).await;
            ready = batcher.flush_due(delay);
        }
    }
    ready
}

fn current_unix_timestamp() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    let seconds = elapsed
        .as_secs()
        .try_into()
        .context("system timestamp does not fit i64")?;
    Ok(seconds)
}

async fn send_h2_frame(
    stream: &mut h2::SendStream<Bytes>,
    frame: Frame,
    max_frame_size: usize,
    end_stream: bool,
    stall_timeout: Duration,
) -> Result<()> {
    send_h2_bytes_with_capacity(
        stream,
        encode_grpc_frame(frame, max_frame_size)?,
        end_stream,
        stall_timeout,
    )
    .await
}

async fn wait_h2_capacity(stream: &mut h2::SendStream<Bytes>, desired: usize) -> Result<usize> {
    stream.reserve_capacity(desired);
    loop {
        let current = stream.capacity();
        if current > 0 {
            return Ok(current.min(desired));
        }
        let assigned = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("h2 send stream closed before capacity was available")??;
        if assigned > 0 {
            return Ok(assigned.min(desired));
        }
    }
}

async fn send_h2_bytes_with_capacity(
    stream: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
    stall_timeout: Duration,
) -> Result<()> {
    if bytes.is_empty() {
        stream.send_data(bytes, end_stream)?;
        return Ok(());
    }

    while !bytes.is_empty() {
        let capacity = match timeout(stall_timeout, wait_h2_capacity(stream, bytes.len())).await {
            Ok(result) => result?,
            Err(_) => {
                stream.reserve_capacity(0);
                return Err(H2SendStalled.into());
            }
        };
        let chunk_len = capacity.min(bytes.len());
        let chunk = bytes.split_to(chunk_len);
        stream.send_data(chunk, end_stream && bytes.is_empty())?;
    }
    Ok(())
}

async fn read_next_h2_frame(tunnel: &mut H2ClientTunnel) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = decode_grpc_frame_from(&mut tunnel.recv_buf, tunnel.max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        match tunnel.recv_stream.data().await {
            Some(Ok(bytes)) => {
                let consumed = bytes.len();
                tunnel
                    .recv_stream
                    .flow_control()
                    .release_capacity(consumed)?;
                tunnel.recv_buf.extend_from_slice(&bytes);
            }
            Some(Err(err)) => return Err(err.into()),
            None => return Ok(None),
        }
    }
}

async fn finish_h2_response(
    tunnel: &mut H2ClientTunnel,
    allow_legacy_udp_reset: bool,
) -> Result<()> {
    loop {
        while let Some(frame) = decode_grpc_frame_from(&mut tunnel.recv_buf, tunnel.max_frame_size)?
        {
            if frame.frame_type != FrameType::Padding {
                bail!("gRPC response contained data after terminal frame");
            }
        }
        match tunnel.recv_stream.data().await {
            Some(Ok(bytes)) => {
                let consumed = bytes.len();
                tunnel
                    .recv_stream
                    .flow_control()
                    .release_capacity(consumed)
                    .context("gRPC response flow control failed")?;
                tunnel.recv_buf.extend_from_slice(&bytes);
            }
            Some(Err(err))
                if allow_legacy_udp_reset
                    && err.is_reset()
                    && err.is_remote()
                    && tunnel.recv_buf.is_empty() =>
            {
                // Alpha.3 dropped its persistent UDP response after receiving
                // an explicit CloseFlow. Limit that compatibility exception to
                // this caller-selected close path.
                return Ok(());
            }
            Some(Err(err)) => {
                return Err(anyhow::Error::new(err).context("gRPC response body failed"));
            }
            None => break,
        }
    }

    if !tunnel.recv_buf.is_empty() {
        bail!("gRPC response ended with incomplete data");
    }

    let Some(trailers) = tunnel
        .recv_stream
        .trailers()
        .await
        .context("gRPC response trailers failed")?
    else {
        // Alpha.3 ended a complete response with DATA END_STREAM and did not
        // send gRPC trailers. Keep that wire behavior compatible.
        return Ok(());
    };

    let mut statuses = trailers.get_all("grpc-status").iter();
    match (statuses.next(), statuses.next()) {
        (Some(status), None) if status.as_bytes() == b"0" => Ok(()),
        (None, _) => bail!("gRPC response trailers missing status"),
        _ => bail!("gRPC response status was not successful"),
    }
}

async fn read_next_ws_frame(tunnel: &mut WsClientTunnel) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = Frame::decode_from(&mut tunnel.recv_buf, tunnel.max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        let Some(message) = tunnel.stream.next().await else {
            return Ok(None);
        };
        match message? {
            Message::Binary(bytes) => tunnel.recv_buf.extend_from_slice(&bytes),
            Message::Ping(payload) => {
                tunnel.stream.send(Message::Pong(payload)).await?;
            }
            Message::Close(_) => return Ok(None),
            _ => {}
        }
    }
}

fn validate_negotiated_max_frame_size(value: u32) -> Result<usize> {
    let value = value as usize;
    if value < DEFAULT_MAX_FRAME_SIZE {
        bail!("server negotiated max_frame_size below the client minimum");
    }
    if value > MAX_NEGOTIATED_FRAME_SIZE {
        bail!("server negotiated max_frame_size above the client limit");
    }
    Ok(value)
}

#[cfg(feature = "h3")]
async fn read_next_h3_frame(tunnel: &mut H3ClientTunnel) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = Frame::decode_from(&mut tunnel.recv_buf, tunnel.max_frame_size)? {
            if frame.frame_type == FrameType::Padding {
                continue;
            }
            return Ok(Some(frame));
        }
        match tunnel.stream.recv_data().await? {
            Some(mut chunk) => {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                tunnel.recv_buf.extend_from_slice(&bytes);
            }
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};
    use maverick_core::auth::{ServerHello, ServerHelloV2};
    use maverick_core::config::{
        AuthV2Config, ClientAdvancedConfig, ClientAuthConfig, ClientCredentialRotationConfig,
        ClientServerConfig, LocalConfig, LogConfig, Mode, Socks5Config,
    };

    fn client_config(secret: SecretString) -> ClientConfig {
        ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                dns: None,
                http_connect: None,
            },
            server: ClientServerConfig {
                address: "example.com:443".into(),
                server_name: "example.com".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_abc123".into(),
                secret,
                ca_cert: None,
                cert_pin: None,
            },
            auth: ClientAuthConfig::default(),
            log: LogConfig::default(),
            advanced: ClientAdvancedConfig::default(),
        }
    }

    async fn test_h2_tunnel(
        terminal_frame: Frame,
        trailing_padding: bool,
        end_with_data: bool,
        trailers: Option<HeaderMap>,
        trailer_gate: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<(
        ClientTunnel,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    )> {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .context("client closed before sending a request")??;
            let held_request_body = request.into_body();
            let driver = tokio::spawn(async move {
                while let Some(request) = connection.accept().await {
                    request?;
                }
                Result::<()>::Ok(())
            });

            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())?;
            let mut response_body = respond.send_response(response, false)?;
            response_body.send_data(
                encode_grpc_frame(terminal_frame, DEFAULT_MAX_FRAME_SIZE)?,
                end_with_data,
            )?;
            if trailing_padding {
                response_body.send_data(
                    encode_grpc_frame(
                        Frame::new(FrameType::Padding, 0, 0, Bytes::from_static(b"pad")),
                        DEFAULT_MAX_FRAME_SIZE,
                    )?,
                    false,
                )?;
            }
            if let Some(gate) = trailer_gate {
                let _ = gate.await;
            }
            if let Some(trailers) = trailers {
                response_body.send_trailers(trailers)?;
            }

            drop(response_body);
            drop(held_request_body);
            driver.await??;
            Ok(())
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await?;
        let client = tokio::spawn(async move {
            connection.await?;
            Result::<()>::Ok(())
        });
        sender = sender.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, send_stream) = sender.send_request(request, false)?;
        let recv_stream = response.await?.into_body();
        drop(sender);

        let config = client_config(SecretString::generate());
        let tunnel = ClientTunnel::H2(Box::new(H2ClientTunnel {
            send_stream,
            recv_stream,
            recv_buf: BytesMut::new(),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            feature_flags_selected: Some(0),
            padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
            cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
            batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
            send_stall_timeout: Duration::from_secs(1),
            connection_lease: None,
        }));
        Ok((tunnel, server, client))
    }

    async fn finish_test_h2_tasks(
        tunnel: ClientTunnel,
        server: tokio::task::JoinHandle<Result<()>>,
        client: tokio::task::JoinHandle<Result<()>>,
    ) -> Result<()> {
        drop(tunnel);
        timeout(Duration::from_secs(1), server)
            .await
            .context("test H2 server did not stop")???;
        timeout(Duration::from_secs(1), client)
            .await
            .context("test H2 client did not stop")???;
        Ok(())
    }

    #[test]
    fn negotiated_frame_size_is_bounded() {
        assert_eq!(
            validate_negotiated_max_frame_size(DEFAULT_MAX_FRAME_SIZE as u32).unwrap(),
            DEFAULT_MAX_FRAME_SIZE
        );
        assert_eq!(
            validate_negotiated_max_frame_size(MAX_NEGOTIATED_FRAME_SIZE as u32).unwrap(),
            MAX_NEGOTIATED_FRAME_SIZE
        );
        assert!(validate_negotiated_max_frame_size((DEFAULT_MAX_FRAME_SIZE - 1) as u32).is_err());
        assert!(
            validate_negotiated_max_frame_size((MAX_NEGOTIATED_FRAME_SIZE + 1) as u32).is_err()
        );
    }

    #[tokio::test]
    async fn h2_runtime_failure_classification_uses_error_types() -> Result<()> {
        let stalled = anyhow::Error::new(H2SendStalled).context("outer operation failed");
        assert_eq!(
            classify_h2_runtime_failure(&stalled),
            Some(H2RuntimeFailureKind::SendStall)
        );
        let misleading_text =
            anyhow::anyhow!("h2 send stalled while waiting for receiver capacity");
        assert_eq!(classify_h2_runtime_failure(&misleading_text), None);

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await?;
            let (_request, mut respond) = connection
                .accept()
                .await
                .context("client closed before sending a request")??;
            let response = http::Response::builder()
                .header("content-type", "application/grpc")
                .body(())?;
            let mut response_body = respond.send_response(response, false)?;
            let resetter = tokio::spawn(async move {
                let _ = reset_rx.await;
                response_body.send_reset(h2::Reason::CANCEL);
            });
            while let Some(request) = connection.accept().await {
                request?;
            }
            resetter.await?;
            Result::<()>::Ok(())
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await?;
        let client = tokio::spawn(connection);
        sender = sender.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, request_body) = sender.send_request(request, true)?;
        let response = response.await?;
        let config = client_config(SecretString::generate());
        let pool =
            crate::connection_manager::ClientTunnelPool::new(std::sync::Arc::new(config.clone()));
        let mut tunnel = ClientTunnel::H2(Box::new(H2ClientTunnel {
            send_stream: request_body,
            recv_stream: response.into_body(),
            recv_buf: BytesMut::new(),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            feature_flags_selected: Some(0),
            padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
            cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
            batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
            send_stall_timeout: Duration::from_secs(1),
            connection_lease: Some(pool.test_h2_runtime_metrics_lease()),
        }));
        reset_tx.send(()).expect("reset receiver dropped");
        let reset = timeout(Duration::from_secs(1), tunnel.read_next_frame())
            .await
            .context("remote H2 reset did not arrive")?
            .expect_err("remote H2 stream returned data instead of a reset");
        assert!(reset
            .downcast_ref::<h2::Error>()
            .is_some_and(h2::Error::is_reset));
        assert_eq!(
            classify_h2_runtime_failure(&reset),
            Some(H2RuntimeFailureKind::StreamReset)
        );
        let snapshot = pool.h2_snapshot();
        assert_eq!(snapshot.runtime_stream_resets, 1);
        assert_eq!(snapshot.runtime_send_stalls, 0);

        drop(tunnel);
        drop(sender);
        server.abort();
        client.abort();
        let _ = server.await;
        let _ = client.await;
        Ok(())
    }

    #[test]
    fn h2_tunnel_request_has_https_authority_and_http2_version() -> Result<()> {
        let config = client_config(SecretString::generate());
        let request = build_h2_tunnel_request(&config)?;

        assert_eq!(request.version(), http::Version::HTTP_2);
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
            Some("example.com")
        );
        assert_eq!(request.uri().path(), "/assets/upload");
        assert_eq!(request.headers()["content-type"], "application/grpc");
        assert_eq!(request.headers()["te"], "trailers");
        Ok(())
    }

    #[tokio::test]
    async fn h2_tunnel_request_preserves_https_authority_on_wire() -> Result<()> {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .context("client closed before sending a request")??;

            assert_eq!(request.version(), http::Version::HTTP_2);
            assert_eq!(request.uri().scheme_str(), Some("https"));
            assert_eq!(
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str()),
                Some("example.com")
            );
            assert_eq!(request.uri().path(), "/assets/upload");

            respond.send_response(http::Response::new(()), true)?;
            while let Some(request) = connection.accept().await {
                request?;
            }
            Result::<()>::Ok(())
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await?;
        let client = tokio::spawn(connection);
        let (response, _body) = sender.send_request(
            build_h2_tunnel_request(&client_config(SecretString::generate()))?,
            true,
        )?;

        assert!(response.await?.status().is_success());
        drop(sender);
        server.abort();
        client.abort();
        let _ = server.await;
        let _ = client.await;
        Ok(())
    }

    #[tokio::test]
    async fn h2_finish_drains_padding_and_waits_for_delayed_ok_trailer() -> Result<()> {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let (release_trailer, wait_for_release) = tokio::sync::oneshot::channel();
        let (mut tunnel, server, client) = test_h2_tunnel(
            Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()),
            true,
            false,
            Some(trailers),
            Some(wait_for_release),
        )
        .await?;

        let frame = timeout(Duration::from_secs(1), tunnel.read_next_frame())
            .await
            .context("terminal DATA did not arrive before the trailer")??
            .context("terminal DATA was missing")?;
        assert_eq!(frame.frame_type, FrameType::TcpFin);
        release_trailer
            .send(())
            .expect("test trailer receiver dropped");
        tunnel.finish_response().await?;

        finish_test_h2_tasks(tunnel, server, client).await
    }

    #[tokio::test]
    async fn h2_finish_accepts_alpha3_data_end_stream_without_trailer() -> Result<()> {
        let (mut tunnel, server, client) = test_h2_tunnel(
            Frame::new(FrameType::TcpFin, 0, 1, Bytes::new()),
            false,
            true,
            None,
            None,
        )
        .await?;

        let frame = tunnel
            .read_next_frame()
            .await?
            .context("terminal DATA was missing")?;
        assert_eq!(frame.frame_type, FrameType::TcpFin);
        tunnel.finish_response().await?;

        finish_test_h2_tasks(tunnel, server, client).await
    }

    #[tokio::test]
    async fn h2_finish_rejects_nonzero_grpc_status_without_echoing_it() -> Result<()> {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("7"));
        trailers.insert(
            "grpc-message",
            HeaderValue::from_static("private upstream detail"),
        );
        let (mut tunnel, server, client) = test_h2_tunnel(
            Frame::new(FrameType::Error, 0, 1, Bytes::new()),
            false,
            false,
            Some(trailers),
            None,
        )
        .await?;

        let frame = tunnel
            .read_next_frame()
            .await?
            .context("terminal DATA was missing")?;
        assert_eq!(frame.frame_type, FrameType::Error);
        let error = tunnel
            .finish_response()
            .await
            .expect_err("nonzero grpc-status must fail");
        assert_eq!(error.to_string(), "gRPC response status was not successful");
        assert!(!error.to_string().contains("private upstream detail"));

        finish_test_h2_tasks(tunnel, server, client).await
    }

    #[tokio::test]
    async fn h2_finish_rejects_trailers_without_grpc_status() -> Result<()> {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "grpc-message",
            HeaderValue::from_static("private upstream detail"),
        );
        let (mut tunnel, server, client) = test_h2_tunnel(
            Frame::new(FrameType::Error, 0, 1, Bytes::new()),
            false,
            false,
            Some(trailers),
            None,
        )
        .await?;

        let frame = tunnel
            .read_next_frame()
            .await?
            .context("terminal DATA was missing")?;
        assert_eq!(frame.frame_type, FrameType::Error);
        let error = tunnel
            .finish_response()
            .await
            .expect_err("missing grpc-status must fail");
        assert_eq!(error.to_string(), "gRPC response trailers missing status");
        assert!(!error.to_string().contains("private upstream detail"));

        finish_test_h2_tasks(tunnel, server, client).await
    }

    #[tokio::test]
    async fn h2_send_times_out_when_receiver_never_releases_capacity() -> Result<()> {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(0);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .context("client closed before sending a request")??;
            respond.send_response(http::Response::new(()), true)?;
            let held_request_body = request.into_body();
            while let Some(request) = connection.accept().await {
                request?;
            }
            drop(held_request_body);
            Result::<()>::Ok(())
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await?;
        let client = tokio::spawn(connection);
        sender = sender.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, request_body) = sender.send_request(request, false)?;
        let response = response.await?;
        assert!(response.status().is_success());
        let config = client_config(SecretString::generate());
        let pool =
            crate::connection_manager::ClientTunnelPool::new(std::sync::Arc::new(config.clone()));
        let mut tunnel = ClientTunnel::H2(Box::new(H2ClientTunnel {
            send_stream: request_body,
            recv_stream: response.into_body(),
            recv_buf: BytesMut::new(),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            feature_flags_selected: Some(0),
            padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
            cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
            batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
            send_stall_timeout: Duration::from_millis(25),
            connection_lease: Some(pool.test_h2_runtime_metrics_lease()),
        }));

        let result = timeout(
            Duration::from_secs(1),
            tunnel.send_frame(
                Frame::new(
                    FrameType::TcpData,
                    0,
                    1,
                    Bytes::from_static(b"capacity must be granted"),
                ),
                true,
            ),
        )
        .await
        .context("H2 send did not honor its stall timeout")?;
        let error = result.expect_err("a zero receive window must stall the H2 send");
        assert!(error
            .to_string()
            .contains("h2 send stalled while waiting for receiver capacity"));
        assert!(error.downcast_ref::<H2SendStalled>().is_some());
        let snapshot = pool.h2_snapshot();
        assert_eq!(snapshot.runtime_send_stalls, 1);
        assert_eq!(snapshot.runtime_stream_resets, 0);

        drop(tunnel);
        drop(sender);
        server.abort();
        client.abort();
        let _ = server.await;
        let _ = client.await;
        Ok(())
    }

    #[tokio::test]
    async fn h2_send_timeout_resets_after_each_capacity_progress() -> Result<()> {
        const WINDOW_SIZE: u32 = 256;
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(WINDOW_SIZE);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .context("client closed before sending a request")??;
            respond.send_response(http::Response::new(()), true)?;
            let mut request_body = request.into_body();
            tokio::spawn(async move {
                let mut received = BytesMut::new();
                while let Some(chunk) = request_body.data().await {
                    let chunk = chunk?;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    request_body.flow_control().release_capacity(chunk.len())?;
                    received.extend_from_slice(&chunk);
                }
                let _ = received_tx.send(received);
                Result::<()>::Ok(())
            });
            while let Some(request) = connection.accept().await {
                request?;
            }
            Result::<()>::Ok(())
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await?;
        let client = tokio::spawn(connection);
        sender = sender.ready().await?;
        let request = http::Request::builder().method("POST").uri("/").body(())?;
        let (response, mut request_body) = sender.send_request(request, false)?;
        assert!(response.await?.status().is_success());

        let payload = Bytes::from(vec![0x5a; 8 * 1024]);
        let stall_timeout = Duration::from_millis(150);
        let started = tokio::time::Instant::now();
        timeout(
            Duration::from_secs(3),
            send_h2_frame(
                &mut request_body,
                Frame::new(FrameType::TcpData, 0, 1, payload.clone()),
                DEFAULT_MAX_FRAME_SIZE,
                true,
                stall_timeout,
            ),
        )
        .await
        .context("H2 send did not finish while capacity kept advancing")??;
        assert!(
            started.elapsed() > stall_timeout,
            "the transfer must outlast one stall window to test progress resets"
        );

        let mut received = timeout(Duration::from_secs(1), received_rx)
            .await
            .context("server did not receive the complete H2 frame")??;
        let frame = decode_grpc_frame_from(&mut received, DEFAULT_MAX_FRAME_SIZE)?
            .context("server did not receive a complete Maverick frame")?;
        assert_eq!(frame.payload, payload);
        assert!(received.is_empty());

        drop(request_body);
        drop(sender);
        server.abort();
        client.abort();
        let _ = server.await;
        let _ = client.await;
        Ok(())
    }

    #[test]
    fn selected_features_must_have_been_requested() {
        assert!(!has_unrequested_feature_flags(0b0101, 0b0111));
        assert!(has_unrequested_feature_flags(0b1000, 0b0111));
    }

    #[test]
    fn client_feature_offer_is_carrier_scoped_and_preserves_tls_binding() -> Result<()> {
        let secret = SecretString::generate();
        let mut config = client_config(secret);
        assert_eq!(
            client_feature_flags(&config, None, ClientHandshakeCarrier::LegacyH2OrH3)?,
            FEATURE_OPEN_UDP_MODE_NEGOTIATION
        );
        assert_eq!(
            client_feature_flags(&config, None, ClientHandshakeCarrier::WebSocket)?,
            0
        );

        config.auth.channel_binding.enabled = true;
        let binding = TlsChannelBinding::new([17u8; 32]);
        assert_eq!(
            client_feature_flags(&config, Some(binding), ClientHandshakeCarrier::LegacyH2OrH3,)?,
            FEATURE_OPEN_UDP_MODE_NEGOTIATION | FEATURE_TLS_CHANNEL_BINDING
        );
        assert_eq!(
            client_feature_flags(&config, Some(binding), ClientHandshakeCarrier::WebSocket,)?,
            FEATURE_TLS_CHANNEL_BINDING
        );
        Ok(())
    }

    #[test]
    fn client_handshake_rejects_unrequested_server_feature_flags() -> Result<()> {
        let secret = SecretString::generate();
        let config = client_config(secret.clone());
        let hello = ClientHandshake::new(&config, None, ClientHandshakeCarrier::LegacyH2OrH3)?;
        let client_nonce = match &hello.message {
            ClientHandshakeMessage::V1(hello) => {
                assert_eq!(hello.feature_flags, FEATURE_OPEN_UDP_MODE_NEGOTIATION);
                hello.client_nonce
            }
            ClientHandshakeMessage::V2(_) => unreachable!("auth v2 is disabled"),
        };
        let old_server =
            ServerHello::new(&secret, &client_nonce, DEFAULT_MAX_FRAME_SIZE as u32, 1, 0)?;
        assert_eq!(
            hello.verify_server_hello(&old_server.encode())?,
            NegotiatedServerHello {
                max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
                feature_flags_selected: 0,
            }
        );

        let new_server = ServerHello::new(
            &secret,
            &client_nonce,
            DEFAULT_MAX_FRAME_SIZE as u32,
            1,
            FEATURE_OPEN_UDP_MODE_NEGOTIATION,
        )?;
        assert_eq!(
            hello.verify_server_hello(&new_server.encode())?,
            NegotiatedServerHello {
                max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
                feature_flags_selected: FEATURE_OPEN_UDP_MODE_NEGOTIATION,
            }
        );

        let unrequested_feature = ServerHello::new(
            &secret,
            &client_nonce,
            DEFAULT_MAX_FRAME_SIZE as u32,
            1,
            1 << 1,
        )?;

        assert!(hello
            .verify_server_hello(&unrequested_feature.encode())
            .is_err());
        Ok(())
    }

    #[test]
    fn client_handshake_retains_mode_gate_and_tls_binding_selected_mask() -> Result<()> {
        let secret = SecretString::generate();
        let mut config = client_config(secret.clone());
        config.auth.channel_binding.enabled = true;
        let binding = TlsChannelBinding::new([19u8; 32]);
        let hello =
            ClientHandshake::new(&config, Some(binding), ClientHandshakeCarrier::LegacyH2OrH3)?;
        let client_nonce = match &hello.message {
            ClientHandshakeMessage::V1(hello) => hello.client_nonce,
            ClientHandshakeMessage::V2(_) => unreachable!("auth v2 is disabled"),
        };
        let selected = FEATURE_OPEN_UDP_MODE_NEGOTIATION | FEATURE_TLS_CHANNEL_BINDING;
        let server_hello = ServerHello::try_new_with_channel_binding(
            &secret,
            &client_nonce,
            DEFAULT_MAX_FRAME_SIZE as u32,
            1,
            selected,
            Some(binding),
        )?;

        assert_eq!(
            hello.verify_server_hello(&server_hello.encode())?,
            NegotiatedServerHello {
                max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
                feature_flags_selected: selected,
            }
        );
        Ok(())
    }

    #[test]
    fn auth_v2_client_handshake_rejects_epoch_mismatch() -> Result<()> {
        let secret = SecretString::generate();
        let mut config = client_config(secret.clone());
        config.auth = ClientAuthConfig {
            channel_binding: Default::default(),
            v2: AuthV2Config {
                enabled: true,
                require: false,
                accepted_epochs: Vec::new(),
            },
            rotation: ClientCredentialRotationConfig {
                active_epoch: Some("202607".into()),
                ..ClientCredentialRotationConfig::default()
            },
        };
        let hello = ClientHandshake::new(&config, None, ClientHandshakeCarrier::LegacyH2OrH3)?;
        let client_nonce = match &hello.message {
            ClientHandshakeMessage::V2(hello) => hello.client_nonce,
            ClientHandshakeMessage::V1(_) => unreachable!("auth v2 is enabled"),
        };
        let wrong_epoch = ServerHelloV2::new(
            &secret,
            202608,
            &client_nonce,
            DEFAULT_MAX_FRAME_SIZE as u32,
            1,
            0,
            120,
        )?;

        assert!(hello.verify_server_hello(&wrong_epoch.encode()?).is_err());

        for selected in [0, FEATURE_OPEN_UDP_MODE_NEGOTIATION] {
            let accepted = ServerHelloV2::new(
                &secret,
                202607,
                &client_nonce,
                DEFAULT_MAX_FRAME_SIZE as u32,
                1,
                selected,
                120,
            )?;
            assert_eq!(
                hello.verify_server_hello(&accepted.encode()?)?,
                NegotiatedServerHello {
                    max_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
                    feature_flags_selected: selected,
                }
            );
        }
        Ok(())
    }
}
