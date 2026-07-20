use std::net::SocketAddr;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(feature = "h3")]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use http::Request;
use maverick_client::transport;
use maverick_core::auth::{
    ClientHello, ServerHello, ServerHelloV2, AUTH_V2_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use maverick_core::config::{
    AuthV2Config, CdnFrontingCarrier, CdnFrontingConfig, ClientAdvancedConfig, ClientAuthConfig,
    ClientConfig, ClientCredentialRotationConfig, ClientDnsConfig, ClientServerConfig,
    FallbackConfig, HttpConnectConfig, LocalConfig, LogConfig, MaverickServerConfig, MetricsConfig,
    PreviousCredentialConfig, SecretString, ServerAdvancedConfig, ServerAuthConfig, ServerConfig,
    ServerDnsConfig, ShapingConfig, Socks5Config, TlsConfig, TlsFingerprintMode, UserConfig,
    UserCredentialRotationConfig,
};
use maverick_core::frame::{Frame, FrameType};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
use maverick_core::Mode;
use maverick_server::{start_server, ServerHandle};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Debug, Clone)]
pub struct HarnessOptions {
    pub dns_upstream: Option<SocketAddr>,
    pub metrics: bool,
    pub http_connect: bool,
    pub user_max_concurrent_flows: Option<u32>,
    pub client_max_concurrent_flows: Option<u32>,
    pub client_connect_timeout_ms: Option<u64>,
    pub client_idle_timeout_secs: Option<u64>,
    pub client_tls_fingerprint: Option<TlsFingerprintMode>,
    pub user_enabled: bool,
    pub experimental_h3: bool,
    pub experimental_tun: bool,
    pub previous_credentials: Vec<PreviousCredentialConfig>,
    pub auth_v2_epoch: Option<u64>,
    pub auth_v2_extra_accepted_epochs: Vec<u64>,
    pub auth_v2_require: bool,
    pub client_shaping: Option<ShapingConfig>,
    pub server_shaping: Option<ShapingConfig>,
    pub server_idle_timeout_secs: Option<u64>,
    pub server_handshake_timeout_ms: Option<u64>,
    pub server_max_concurrent_connections: Option<u32>,
    pub server_max_concurrent_connections_per_source: Option<u32>,
    pub server_fallback_max_concurrent: Option<u32>,
    pub server_h2_max_concurrent_streams: Option<u32>,
    pub server_max_auth_failures_per_window: Option<u32>,
    pub server_auth_failure_window_secs: Option<u64>,
    pub experimental_cloudflare_ws: bool,
    pub cdn_fronting: bool,
    pub cdn_fronting_h2: bool,
    pub fallback: Option<FallbackConfig>,
    pub auth_channel_binding_require: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            dns_upstream: None,
            metrics: false,
            http_connect: false,
            user_max_concurrent_flows: None,
            client_max_concurrent_flows: None,
            client_connect_timeout_ms: None,
            client_idle_timeout_secs: None,
            client_tls_fingerprint: None,
            user_enabled: true,
            experimental_h3: false,
            experimental_tun: false,
            previous_credentials: Vec::new(),
            auth_v2_epoch: None,
            auth_v2_extra_accepted_epochs: Vec::new(),
            auth_v2_require: true,
            client_shaping: None,
            server_shaping: None,
            server_idle_timeout_secs: None,
            server_handshake_timeout_ms: None,
            server_max_concurrent_connections: None,
            server_max_concurrent_connections_per_source: None,
            server_fallback_max_concurrent: None,
            server_h2_max_concurrent_streams: None,
            server_max_auth_failures_per_window: None,
            server_auth_failure_window_secs: None,
            experimental_cloudflare_ws: false,
            cdn_fronting: false,
            cdn_fronting_h2: false,
            fallback: None,
            auth_channel_binding_require: false,
        }
    }
}

pub struct MaverickHarness {
    _tmp: TempDir,
    cert_der: Vec<u8>,
    pub server: ServerHandle,
    pub client: maverick_client::ClientHandle,
    client_config: ClientConfig,
}

impl MaverickHarness {
    pub async fn start() -> Result<Self> {
        Self::start_with_options(HarnessOptions::default()).await
    }

    pub async fn start_with_dns(upstream: Option<SocketAddr>) -> Result<Self> {
        Self::start_with_options(HarnessOptions {
            dns_upstream: upstream,
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_with_features(
        upstream: Option<SocketAddr>,
        metrics: bool,
        http_connect: bool,
    ) -> Result<Self> {
        Self::start_with_options(HarnessOptions {
            dns_upstream: upstream,
            metrics,
            http_connect,
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_with_user_flow_limit(max_concurrent_flows: u32) -> Result<Self> {
        Self::start_with_options(HarnessOptions {
            user_max_concurrent_flows: Some(max_concurrent_flows),
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_with_client_flow_limit(max_concurrent_flows: u32) -> Result<Self> {
        Self::start_with_options(HarnessOptions {
            client_max_concurrent_flows: Some(max_concurrent_flows),
            ..HarnessOptions::default()
        })
        .await
    }

    #[cfg(feature = "h3")]
    pub async fn start_with_h3() -> Result<Self> {
        Self::start_with_options(HarnessOptions {
            experimental_h3: true,
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_with_options(options: HarnessOptions) -> Result<Self> {
        anyhow::ensure!(
            !(options.cdn_fronting && options.cdn_fronting_h2),
            "select only one CDN fronting carrier"
        );
        let tmp = TempDir::new()?;
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = certified.cert.der().to_vec();
        tokio::fs::write(&cert_path, certified.cert.pem()).await?;
        tokio::fs::write(&key_path, certified.key_pair.serialize_pem()).await?;
        tokio::fs::write(tmp.path().join("index.html"), fallback_html()).await?;

        let secret = SecretString::generate();
        let cloudflare_ws_enabled = options.experimental_cloudflare_ws || options.cdn_fronting;
        let cdn_fronting_enabled = cloudflare_ws_enabled || options.cdn_fronting_h2;
        let cdn_fronting_carrier = if options.cdn_fronting_h2 {
            CdnFrontingCarrier::H2
        } else {
            CdnFrontingCarrier::WebSocket
        };
        let mut server_advanced = ServerAdvancedConfig {
            experimental_h3: options.experimental_h3,
            experimental_cloudflare_ws: options.experimental_cloudflare_ws,
            ..ServerAdvancedConfig::default()
        };
        if cdn_fronting_enabled {
            server_advanced.stealth.cdn_fronting = CdnFrontingConfig {
                enabled: true,
                carrier: cdn_fronting_carrier,
                trusted_tls_terminating_provider: true,
                ..CdnFrontingConfig::default()
            };
        }
        if let Some(shaping) = options.server_shaping.clone() {
            server_advanced.shaping = shaping;
        }
        if let Some(idle_timeout_secs) = options.server_idle_timeout_secs {
            server_advanced.idle_timeout_secs = idle_timeout_secs;
        }
        if let Some(handshake_timeout_ms) = options.server_handshake_timeout_ms {
            server_advanced.handshake_timeout_ms = handshake_timeout_ms;
        }
        if let Some(max_connections) = options.server_max_concurrent_connections {
            server_advanced.max_concurrent_connections = max_connections;
        }
        if let Some(max_connections_per_source) =
            options.server_max_concurrent_connections_per_source
        {
            server_advanced.max_concurrent_connections_per_source = max_connections_per_source;
        }
        if let Some(fallback_max_concurrent) = options.server_fallback_max_concurrent {
            server_advanced.fallback_max_concurrent = fallback_max_concurrent;
        }
        if let Some(max_concurrent_streams) = options.server_h2_max_concurrent_streams {
            server_advanced.h2_max_concurrent_streams = max_concurrent_streams;
        }
        if let Some(max_auth_failures) = options.server_max_auth_failures_per_window {
            server_advanced.max_auth_failures_per_window = max_auth_failures;
        }
        if let Some(auth_failure_window_secs) = options.server_auth_failure_window_secs {
            server_advanced.auth_failure_window_secs = auth_failure_window_secs;
        }
        server_advanced.egress.allow_loopback = true;
        let rotation =
            (!options.previous_credentials.is_empty()).then(|| UserCredentialRotationConfig {
                previous: options.previous_credentials.clone(),
                next: None,
            });
        let server_auth = options
            .auth_v2_epoch
            .map(|epoch| {
                let mut accepted_epochs = vec![epoch];
                accepted_epochs.extend(options.auth_v2_extra_accepted_epochs.clone());
                accepted_epochs.sort_unstable();
                accepted_epochs.dedup();
                ServerAuthConfig {
                    channel_binding: Default::default(),
                    v2: AuthV2Config {
                        enabled: true,
                        require: options.auth_v2_require,
                        accepted_epochs,
                    },
                }
            })
            .unwrap_or_default();
        let mut server_auth = server_auth;
        server_auth.channel_binding.require = options.auth_channel_binding_require;
        let fallback = options
            .fallback
            .clone()
            .unwrap_or_else(|| FallbackConfig::Static {
                static_dir: tmp.path().to_path_buf(),
                index: "index.html".into(),
            });
        let server_config = ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse()?,
            tls: TlsConfig {
                cert_path: cert_path.clone(),
                key_path,
            },
            maverick: MaverickServerConfig {
                tunnel_path: "/assets/upload".into(),
                mode_default: Mode::Auto,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 16_384,
                replay_cache_max_credentials_per_shard: 1_024,
                max_concurrent_flows_per_user: 128,
            },
            users: vec![UserConfig {
                id: "u_test".into(),
                name: Some("test".into()),
                secret: secret.clone(),
                enabled: options.user_enabled,
                rate_limit: None,
                max_concurrent_flows: options.user_max_concurrent_flows,
                rotation,
            }],
            fallback,
            auth: server_auth,
            dns: options.dns_upstream.map(|upstream| ServerDnsConfig {
                upstream: upstream.to_string(),
                timeout_ms: 1_000,
            }),
            metrics: options.metrics.then(|| MetricsConfig {
                enabled: true,
                listen: "127.0.0.1:0".parse().unwrap(),
            }),
            log: LogConfig::default(),
            advanced: server_advanced,
        };
        let server = start_server(server_config).await?;
        let mut client_advanced = ClientAdvancedConfig::default();
        if let Some(max_concurrent_flows) = options.client_max_concurrent_flows {
            client_advanced.max_concurrent_flows = max_concurrent_flows;
        }
        if let Some(connect_timeout_ms) = options.client_connect_timeout_ms {
            client_advanced.connect_timeout_ms = connect_timeout_ms;
        }
        if let Some(idle_timeout_secs) = options.client_idle_timeout_secs {
            client_advanced.idle_timeout_secs = idle_timeout_secs;
        }
        if let Some(tls_fingerprint) = options.client_tls_fingerprint {
            client_advanced.stealth.tls_fingerprint = tls_fingerprint;
        }
        client_advanced.experimental_h3 = options.experimental_h3;
        client_advanced.experimental_tun = options.experimental_tun;
        client_advanced.experimental_cloudflare_ws = options.experimental_cloudflare_ws;
        if cdn_fronting_enabled {
            if cloudflare_ws_enabled && options.client_tls_fingerprint.is_none() {
                client_advanced.stealth.tls_fingerprint = TlsFingerprintMode::RustlsDefault;
            }
            client_advanced.stealth.cdn_fronting = CdnFrontingConfig {
                enabled: true,
                carrier: cdn_fronting_carrier,
                trusted_tls_terminating_provider: true,
                ..CdnFrontingConfig::default()
            };
        }
        if let Some(shaping) = options.client_shaping.clone() {
            client_advanced.shaping = shaping;
        }
        let client_auth = options
            .auth_v2_epoch
            .map(|epoch| ClientAuthConfig {
                channel_binding: Default::default(),
                v2: AuthV2Config {
                    enabled: true,
                    require: false,
                    accepted_epochs: Vec::new(),
                },
                rotation: ClientCredentialRotationConfig {
                    active_epoch: Some(epoch.to_string()),
                    next_credential_id: None,
                    ..ClientCredentialRotationConfig::default()
                },
            })
            .unwrap_or_default();
        let mut client_auth = client_auth;
        client_auth.channel_binding.require = options.auth_channel_binding_require;

        let client_config = ClientConfig {
            version: 1,
            mode: Mode::Auto,
            local: LocalConfig {
                socks5: Socks5Config {
                    listen: "127.0.0.1:0".parse()?,
                },
                dns: options.dns_upstream.map(|_| ClientDnsConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:0".parse().unwrap()),
                }),
                http_connect: options.http_connect.then(|| HttpConnectConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:0".parse().unwrap()),
                }),
            },
            server: ClientServerConfig {
                address: server.local_addr.to_string(),
                server_name: "localhost".into(),
                tunnel_path: "/assets/upload".into(),
                credential_id: "u_test".into(),
                secret: secret.clone(),
                ca_cert: Some(cert_path.clone()),
                cert_pin: None,
            },
            auth: client_auth,
            log: LogConfig::default(),
            advanced: client_advanced,
        };
        let client = maverick_client::start_client(client_config.clone()).await?;

        Ok(Self {
            _tmp: tmp,
            cert_der,
            server,
            client,
            client_config,
        })
    }

    pub fn client_config(&self) -> ClientConfig {
        self.client_config.clone()
    }

    pub fn cert_pin(&self) -> String {
        let digest = Sha256::digest(&self.cert_der);
        format!("sha256/{}", URL_SAFE_NO_PAD.encode(digest))
    }

    pub async fn shutdown(self) -> Result<()> {
        self.client.shutdown().await?;
        self.server.shutdown().await
    }
}

pub async fn socks_connect(socks_addr: SocketAddr, target_addr: SocketAddr) -> Result<TcpStream> {
    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    socks.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&target_addr.port().to_be_bytes());
    socks.write_all(&connect).await?;
    let mut connect_reply = [0u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], 0x00);
    Ok(socks)
}

pub async fn start_fake_dns_server() -> Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let mut response = b"dns-response:".to_vec();
            response.extend_from_slice(&buf[..len]);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    Ok(addr)
}

pub async fn start_udp_echo_server() -> Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    Ok(addr)
}

pub async fn start_hold_open_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut one = [0u8; 1];
                let _ = stream.read(&mut one).await;
            });
        }
    });
    Ok(addr)
}

pub async fn start_stalling_tcp_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    Ok(addr)
}

pub async fn start_echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

pub async fn tunnel_attempt_body(config: &ClientConfig, hello: Option<Vec<u8>>) -> Result<Bytes> {
    tunnel_attempt_body_at(config, config.server.tunnel_path.as_str(), hello).await
}

pub async fn tunnel_attempt_body_at(
    config: &ClientConfig,
    tunnel_uri: &str,
    hello: Option<Vec<u8>>,
) -> Result<Bytes> {
    let hello = match hello {
        Some(hello) => hello,
        None => ClientHello::new(
            config.server.credential_id.clone(),
            &config.server.secret,
            &config.server.tunnel_path,
            config.mode,
            0,
        )?
        .encode(),
    };
    let frame = Frame::new(FrameType::ClientHello, 0, 0, hello);

    match transport::connect(config).await? {
        transport::TunnelRequestSender::H2(mut h2) => {
            let req = Request::builder()
                .method("POST")
                .uri(tunnel_uri)
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(())?;
            let (response_fut, mut send_stream) = h2.sender.send_request(req, false)?;
            send_stream.send_data(encode_grpc_frame(frame, 65_536)?, true)?;
            let mut response = response_fut.await?;
            let mut body = BytesMut::new();
            while let Some(chunk) = response.body_mut().data().await {
                body.extend_from_slice(&chunk?);
            }
            decode_optional_server_hello(&response, &body)?;
            Ok(body.freeze())
        }
        transport::TunnelRequestSender::CloudflareWs(_) => {
            anyhow::bail!("tunnel_attempt_body does not support websocket carrier")
        }
        #[cfg(feature = "h3")]
        transport::TunnelRequestSender::H3(mut h3) => {
            let uri = format!("https://{}{}", config.server.server_name, tunnel_uri);
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/octet-stream")
                .body(())?;
            let mut stream = h3.send_request(req).await?;
            stream.send_data(frame.encode(65_536)?).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            let mut body = BytesMut::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                body.extend_from_slice(&bytes);
            }
            decode_optional_server_hello(&response, &body)?;
            Ok(body.freeze())
        }
    }
}

fn decode_optional_server_hello<B>(response: &http::Response<B>, body: &BytesMut) -> Result<()> {
    if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        == Some("application/octet-stream")
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some("application/grpc")
    {
        let mut framed = BytesMut::from(body.as_ref());
        let maybe_frame = if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some("application/grpc")
        {
            decode_grpc_frame_from(&mut framed, 65_536)?
        } else {
            Frame::decode_from(&mut framed, 65_536)?
        };
        if let Some(frame) = maybe_frame {
            if frame.frame_type == FrameType::ServerHello {
                match server_hello_version(&frame.payload) {
                    Some(PROTOCOL_VERSION) => {
                        let _ =
                            ServerHello::decode(&frame.payload).context("decode ServerHello")?;
                    }
                    Some(AUTH_V2_PROTOCOL_VERSION) => {
                        let _ = ServerHelloV2::decode(&frame.payload)
                            .context("decode ServerHelloV2")?;
                    }
                    _ => anyhow::bail!("unknown ServerHello version"),
                }
            }
        }
    }
    Ok(())
}

fn server_hello_version(payload: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = payload.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn fallback_html() -> &'static str {
    "<!doctype html><html><body><h1>Maverick</h1></body></html>"
}
