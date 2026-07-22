use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
#[cfg(feature = "h3")]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use futures::{future::poll_fn, SinkExt, StreamExt};
use http::Request;
use maverick_core::auth::{
    ClientHello, ClientHelloV2, ClientHelloV2Params, ServerHello, ServerHelloV2, TlsChannelBinding,
    AUTH_V2_PROTOCOL_VERSION, FEATURE_TLS_CHANNEL_BINDING, PROTOCOL_VERSION,
};
use maverick_core::config::{parse_auth_epoch, select_client_credential_at_unix};
use maverick_core::frame::{Frame, FrameType};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::padding::{RuntimeBatcher, RuntimeCoverTraffic, RuntimePadding};
use maverick_core::{ClientConfig, SecretString};
use tokio_tungstenite::tungstenite::Message;

use crate::transport::{self, TunnelRequestSender};

const DEFAULT_MAX_FRAME_SIZE: usize = 65_536;
const MAX_NEGOTIATED_FRAME_SIZE: usize = 1024 * 1024;

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
    padding: RuntimePadding,
    cover_traffic: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
    _connection_lease: Option<crate::connection_manager::H2ConnectionLease>,
}

pub struct WsClientTunnel {
    pub stream: crate::ws_transport::WsClientStream,
    pub recv_buf: BytesMut,
    pub max_frame_size: usize,
    padding: RuntimePadding,
    cover_traffic: RuntimeCoverTraffic,
    batcher: RuntimeBatcher,
}

#[cfg(feature = "h3")]
pub struct H3ClientTunnel {
    stream: crate::h3_transport::H3ClientRequestStream,
    recv_buf: BytesMut,
    max_frame_size: usize,
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

    pub async fn send_frame(&mut self, frame: Frame, end_stream: bool) -> Result<()> {
        let max_frame_size = self.max_frame_size();
        match self {
            Self::H2(tunnel) => {
                let frames =
                    prepare_outgoing_frames(frame, &mut tunnel.batcher, &tunnel.padding).await;
                let last = frames.len().saturating_sub(1);
                for (idx, frame) in frames.into_iter().enumerate() {
                    if let Some(padding) = tunnel.padding.padding_frame(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        send_h2_frame(&mut tunnel.send_stream, padding, max_frame_size, false)
                            .await?;
                    }
                    for cover_frame in tunnel.cover_traffic.padding_frames(
                        frame.frame_type,
                        frame.payload.len(),
                        max_frame_size,
                    ) {
                        send_h2_frame(&mut tunnel.send_stream, cover_frame, max_frame_size, false)
                            .await?;
                    }
                    send_h2_frame(
                        &mut tunnel.send_stream,
                        frame,
                        max_frame_size,
                        end_stream && idx == last,
                    )
                    .await?;
                }
                Ok(())
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
            Self::H2(tunnel) => read_next_h2_frame(tunnel).await,
            Self::CloudflareWs(tunnel) => read_next_ws_frame(tunnel).await,
            #[cfg(feature = "h3")]
            Self::H3(tunnel) => read_next_h3_frame(tunnel).await,
        }
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
    let hello = ClientHandshake::new(config, channel_binding)?;
    send_h2_frame(
        &mut send_stream,
        Frame::new(FrameType::ClientHello, 0, 0, hello.encode()?),
        DEFAULT_MAX_FRAME_SIZE,
        false,
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
        padding: RuntimePadding::from_config(config.mode, &config.advanced.shaping),
        cover_traffic: RuntimeCoverTraffic::from_config(config.mode, &config.advanced.shaping),
        batcher: RuntimeBatcher::from_config(config.mode, &config.advanced.shaping),
        _connection_lease: connection_lease,
    };
    let server_frame = read_next_h2_frame(&mut tunnel)
        .await?
        .context("missing ServerHello")?;
    if server_frame.frame_type != FrameType::ServerHello {
        bail!("missing ServerHello");
    }
    tunnel.max_frame_size =
        validate_negotiated_max_frame_size(hello.verify_server_hello(&server_frame.payload)?)?;
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
    let hello = ClientHandshake::new(config, connection.channel_binding)?;
    let mut tunnel = WsClientTunnel {
        stream: connection.stream,
        recv_buf: BytesMut::new(),
        max_frame_size: DEFAULT_MAX_FRAME_SIZE,
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
    tunnel.max_frame_size =
        validate_negotiated_max_frame_size(hello.verify_server_hello(&server_frame.payload)?)?;
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
    let hello = ClientHandshake::new(config, None)?;
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
    tunnel.max_frame_size =
        validate_negotiated_max_frame_size(hello.verify_server_hello(&server_frame.payload)?)?;
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

impl ClientHandshake {
    fn new(config: &ClientConfig, channel_binding: Option<TlsChannelBinding>) -> Result<Self> {
        let credential = select_client_credential_at_unix(
            &config.server,
            &config.auth.rotation,
            current_unix_timestamp()?,
        )?;
        let feature_flags = client_feature_flags(config, channel_binding)?;
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

    fn verify_server_hello(&self, payload: &[u8]) -> Result<u32> {
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
                Ok(server_hello.max_frame_size)
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
                Ok(server_hello.max_frame_size)
            }
        }
    }
}

fn client_feature_flags(
    config: &ClientConfig,
    channel_binding: Option<TlsChannelBinding>,
) -> Result<u64> {
    if !config.auth.channel_binding.enabled {
        return Ok(0);
    }
    if channel_binding.is_some() {
        return Ok(FEATURE_TLS_CHANNEL_BINDING);
    }
    if config.auth.channel_binding.require {
        bail!("auth.channel_binding.require needs a transport with TLS channel binding support");
    }
    Ok(0)
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
) -> Result<()> {
    send_h2_bytes_with_capacity(
        stream,
        encode_grpc_frame(frame, max_frame_size)?,
        end_stream,
    )
    .await
}

async fn send_h2_bytes_with_capacity(
    stream: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
    end_stream: bool,
) -> Result<()> {
    if bytes.is_empty() {
        stream.send_data(bytes, end_stream)?;
        return Ok(());
    }

    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("h2 send stream closed before capacity was available")??;
        if capacity == 0 {
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn selected_features_must_have_been_requested() {
        assert!(!has_unrequested_feature_flags(0b0101, 0b0111));
        assert!(has_unrequested_feature_flags(0b1000, 0b0111));
    }

    #[test]
    fn client_handshake_rejects_unrequested_server_feature_flags() -> Result<()> {
        let secret = SecretString::generate();
        let config = client_config(secret.clone());
        let hello = ClientHandshake::new(&config, None)?;
        let client_nonce = match &hello.message {
            ClientHandshakeMessage::V1(hello) => hello.client_nonce,
            ClientHandshakeMessage::V2(_) => unreachable!("auth v2 is disabled"),
        };
        let accepted =
            ServerHello::new(&secret, &client_nonce, DEFAULT_MAX_FRAME_SIZE as u32, 1, 0)?;
        assert_eq!(
            hello.verify_server_hello(&accepted.encode())?,
            DEFAULT_MAX_FRAME_SIZE as u32
        );

        let unrequested_feature =
            ServerHello::new(&secret, &client_nonce, DEFAULT_MAX_FRAME_SIZE as u32, 1, 1)?;

        assert!(hello
            .verify_server_hello(&unrequested_feature.encode())
            .is_err());
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
        let hello = ClientHandshake::new(&config, None)?;
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
        Ok(())
    }
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
