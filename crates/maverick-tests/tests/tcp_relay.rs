#[cfg(feature = "h3")]
use std::future::poll_fn;
use std::net::SocketAddr;
#[cfg(feature = "h3")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(feature = "h3")]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, Method, Request, StatusCode};
#[cfg(feature = "h3")]
use maverick_client::udp::LegacyH3DuplexUdpAssociation;
use maverick_client::{
    connection_manager::H2ConnectionPoolSnapshot, transport, udp::UdpAssociation,
};
#[cfg(feature = "h3")]
use maverick_core::auth::FEATURE_OPEN_UDP_MODE_NEGOTIATION;
use maverick_core::auth::{ClientHello, ClientHelloV2, ServerHello};
#[cfg(feature = "browser-tls")]
use maverick_core::config::TlsFingerprintMode;
use maverick_core::config::{
    AuthV2Config, ClientAuthConfig, ClientConfig, ClientCredentialRotationConfig,
    ClientNextCredentialConfig, FallbackConfig, PreviousCredentialConfig, ShapingConfig,
};
#[cfg(feature = "h3")]
use maverick_core::frame::OPEN_UDP_FLAG_DUPLEX;
use maverick_core::frame::{
    ErrorCode, Frame, FrameType, OpenUdpPayload, TargetAddr, UdpPacketPayload,
};
use maverick_core::grpc::{decode_grpc_frame_from, encode_grpc_frame};
#[cfg(feature = "h3")]
use maverick_core::GuiTransportCarrier;
use maverick_core::{Mode, SecretString};
#[cfg(feature = "h3")]
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::RootCertStore;
#[cfg(feature = "h3")]
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch, Notify};
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{client_async, tungstenite::Message};

mod support;

use support::{
    socks_connect, start_echo_server, start_fake_dns_server, start_hold_open_server,
    start_stalling_tcp_server, start_udp_echo_server, tunnel_attempt_body, tunnel_attempt_body_at,
    HarnessOptions, MaverickHarness,
};

async fn fetch_metrics(metrics_addr: SocketAddr) -> Result<String> {
    let mut stream = TcpStream::connect(metrics_addr).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

fn metric_value(response: &str, name: &str) -> Result<u64> {
    let needle = format!("\"{name}\":");
    let start = response.find(&needle).context("missing metric")? + needle.len();
    let digits: String = response[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    Ok(digits.parse()?)
}

async fn wait_for_metric(metrics_addr: SocketAddr, name: &str, minimum: u64) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let response = fetch_metrics(metrics_addr).await?;
        if metric_value(&response, name)? >= minimum {
            return Ok(response);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("metric {name} did not reach {minimum}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_metric_value(
    metrics_addr: SocketAddr,
    name: &str,
    expected: u64,
) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let response = fetch_metrics(metrics_addr).await?;
        if metric_value(&response, name)? == expected {
            return Ok(response);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("metric {name} did not reach {expected}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn collect_h2_response(body: &mut h2::RecvStream) -> Result<(BytesMut, HeaderMap)> {
    let mut response_bytes = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        response_bytes.extend_from_slice(&chunk);
    }
    let trailers = body
        .trailers()
        .await?
        .context("complete gRPC response did not contain trailers")?;
    Ok((response_bytes, trailers))
}

fn assert_grpc_status_ok(trailers: &HeaderMap) {
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

async fn wait_for_pool_snapshot(
    client: &maverick_client::ClientHandle,
    predicate: impl Fn(H2ConnectionPoolSnapshot) -> bool,
) -> Result<H2ConnectionPoolSnapshot> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let snapshot = client.h2_connection_pool_snapshot();
        if predicate(snapshot) {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("H2 connection pool did not reach expected state: {snapshot:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn assert_fallback_body(body: &[u8]) {
    let text = String::from_utf8_lossy(body);
    assert!(
        text.contains("Maverick")
            || text.contains("Not Found")
            || text.contains("captured fallback"),
        "unexpected fallback body: {text:?}"
    );
}

#[derive(Debug, Eq, PartialEq)]
struct FallbackShape {
    status: StatusCode,
    content_type: Option<String>,
    body: Bytes,
}

async fn h2_request_shape(
    config: &ClientConfig,
    method: Method,
    uri: &str,
    hello: Option<Vec<u8>>,
) -> Result<FallbackShape> {
    match transport::connect(config).await? {
        transport::TunnelRequestSender::H2(mut h2) => {
            let mut request = Request::builder().method(method).uri(uri);
            if hello.is_some() {
                request = request
                    .header("content-type", "application/grpc")
                    .header("te", "trailers");
            }
            let end_stream = hello.is_none();
            let (response_fut, mut send_stream) =
                h2.sender.send_request(request.body(())?, end_stream)?;
            if let Some(hello) = hello {
                let frame = Frame::new(FrameType::ClientHello, 0, 0, hello);
                send_stream.send_data(encode_grpc_frame(frame, 65_536)?, true)?;
            }
            let mut response = response_fut.await?;
            let status = response.status();
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut body = BytesMut::new();
            while let Some(chunk) = response.body_mut().data().await {
                body.extend_from_slice(&chunk?);
            }
            Ok(FallbackShape {
                status,
                content_type,
                body: body.freeze(),
            })
        }
        transport::TunnelRequestSender::CloudflareWs(_) => {
            anyhow::bail!("h2_request_shape does not support websocket carrier")
        }
        #[cfg(feature = "h3")]
        transport::TunnelRequestSender::H3(_) => {
            anyhow::bail!("h2_request_shape does not support h3 carrier")
        }
    }
}

async fn start_capture_fallback() -> Result<(SocketAddr, oneshot::Receiver<String>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (request_line_tx, request_line_rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let request_line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            let _ = request_line_tx.send(request_line);
            let body = b"captured fallback";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        }
    });
    Ok((addr, request_line_rx))
}

async fn start_repeating_fallback(body: &'static [u8]) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    Ok(addr)
}

#[cfg(feature = "h3")]
async fn start_body_length_fallback() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                let header_end = loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let body = format!("body_length={content_length}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(addr)
}

async fn start_blocking_fallback(
    body: &'static [u8],
) -> Result<(SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let _ = entered_tx.send(());
            let _ = release_rx.await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        }
    });
    Ok((addr, entered_rx, release_tx))
}

async fn start_slow_stream_server(chunks: usize, interval: Duration) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first_byte = [0u8; 1];
                if stream.read_exact(&mut first_byte).await.is_err() {
                    return;
                }
                for _ in 0..chunks {
                    tokio::time::sleep(interval).await;
                    if stream.write_all(b"x").await.is_err() {
                        break;
                    }
                }
                tokio::time::sleep(interval).await;
            });
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn tcp_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = TcpStream::connect(fixture.client.local_addr).await?;

    socks.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    socks.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&echo_addr.port().to_be_bytes());
    socks.write_all(&connect).await?;
    let mut connect_reply = [0u8; 10];
    socks.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply[1], 0x00);

    socks.write_all(b"maverick-echo").await?;
    let mut echoed = [0u8; 13];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-echo");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn tcp_relay_large_roundtrip_exceeds_h2_window() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;
    let payload = vec![0x5au8; 2 * 1024 * 1024];
    let mut echoed = vec![0u8; payload.len()];

    socks.write_all(&payload).await?;
    timeout(Duration::from_secs(10), socks.read_exact(&mut echoed)).await??;

    assert_eq!(echoed, payload);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cloudflare_ws_tcp_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_cloudflare_ws: true,
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    let payload = b"maverick-websocket-echo";
    socks.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, payload);
    let snapshot = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(snapshot.connections_created, 0);
    assert_eq!(snapshot.streams_opened, 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cdn_fronting_websocket_tcp_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        cdn_fronting: true,
        ..HarnessOptions::default()
    })
    .await?;
    assert!(!fixture.client_config().advanced.experimental_cloudflare_ws);
    assert!(fixture.client_config().advanced.cloudflare_ws_enabled());

    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    let payload = b"maverick-cdn-websocket-echo";
    socks.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, payload);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "browser-tls")]
#[tokio::test]
async fn cdn_fronted_h2_uses_browser_tls_and_relays_tcp() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        cdn_fronting_h2: true,
        client_tls_fingerprint: Some(TlsFingerprintMode::BrowserMimic),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    assert!(config.advanced.cdn_fronted_h2_enabled());
    assert!(config.advanced.tls_terminating_fronting_enabled());
    assert!(!config.advanced.cloudflare_ws_enabled());

    let echo_addr = start_echo_server().await?;
    run_single_socks_roundtrip(
        fixture.client.local_addr,
        echo_addr,
        b"maverick-cdn-h2-browser-echo",
    )
    .await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.connections_created == 1 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.streams_opened, 1);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cloudflare_ws_rejects_non_tunnel_path() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_cloudflare_ws: true,
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let ca_path = config.server.ca_cert.as_ref().context("missing CA cert")?;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(ca_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    assert!(added > 0);
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(fixture.server.local_addr).await?;
    let server_name = ServerName::try_from("localhost".to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;

    let result = timeout(
        Duration::from_secs(2),
        client_async("wss://localhost/not-maverick", tls),
    )
    .await?;
    assert!(result.is_err(), "websocket handshake accepted wrong path");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cloudflare_ws_authenticated_stream_times_out_before_open_frame() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_cloudflare_ws: true,
        server_handshake_timeout_ms: Some(100),
        ..HarnessOptions::default()
    })
    .await?;
    let mut config = fixture.client_config();
    config.advanced.experimental_cloudflare_ws = true;
    let mut ws = maverick_client::ws_transport::connect(&config)
        .await?
        .stream;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        0,
    )?
    .encode();
    ws.send(Message::Binary(
        Frame::new(FrameType::ClientHello, 0, 0, hello).encode(65_536)?,
    ))
    .await?;
    let server_hello = timeout(Duration::from_secs(1), ws.next())
        .await?
        .context("missing websocket server hello")??;
    assert!(matches!(server_hello, Message::Binary(_)));

    let started = Instant::now();
    let _ = timeout(Duration::from_secs(2), ws.next()).await?;
    assert!(started.elapsed() < Duration::from_secs(1));

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_active_tcp_flow_survives_connection_accept_idle_timeout() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        server_idle_timeout_secs: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let slow_addr = start_slow_stream_server(6, Duration::from_millis(200)).await?;
    let mut socks = socks_connect(fixture.client.local_addr, slow_addr).await?;

    socks.write_all(b"go").await?;
    let mut received = Vec::new();
    timeout(Duration::from_secs(4), socks.read_to_end(&mut received)).await??;
    assert_eq!(received, vec![b'x'; 6]);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(not(feature = "h3"))]
#[tokio::test]
async fn server_rejects_h3_config_without_h3_feature() -> Result<()> {
    let result = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        ..HarnessOptions::default()
    })
    .await;
    let err = match result {
        Ok(fixture) => {
            fixture.shutdown().await?;
            anyhow::bail!("expected h3 config without h3 feature to fail");
        }
        Err(err) => err,
    };
    assert!(err.to_string().contains("h3 feature"));
    Ok(())
}

#[tokio::test]
async fn auth_v2_tcp_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-v2-echo").await?;
    let mut echoed = [0u8; 16];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-v2-echo");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v1_stable_client_private_server_legacy_unconfirmed_policy_echo() -> Result<()> {
    // Auth v1 does not confirm a shared mode. This records legacy compatibility,
    // not agreement on a security policy.
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_mode: Mode::Stable,
        server_mode: Mode::Private,
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    run_single_socks_roundtrip(
        fixture.client.local_addr,
        echo_addr,
        b"maverick-v1-legacy-mode-mismatch",
    )
    .await?;

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_private_client_stable_server_legacy_unconfirmed_policy_echo() -> Result<()> {
    // Auth v2 authenticates the client's mode but does not confirm it matches the
    // server default. This records legacy compatibility, not policy agreement.
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        client_mode: Mode::Private,
        server_mode: Mode::Stable,
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    run_single_socks_roundtrip(
        fixture.client.local_addr,
        echo_addr,
        b"maverick-v2-legacy-mode-mismatch",
    )
    .await?;

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_unaccepted_epoch_is_rejected() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        ..HarnessOptions::default()
    })
    .await?;
    let mut cfg = fixture.client_config();
    cfg.auth = auth_v2_client_config(202608);

    let result = maverick_client::tunnel::open(&cfg).await;
    assert!(result.is_err());

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_replayed_client_hello_is_rejected_to_fallback() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        ..HarnessOptions::default()
    })
    .await?;
    let cfg = fixture.client_config();
    let encoded = auth_v2_hello(&cfg, 202607)?;

    let first = tunnel_attempt_body(&cfg, Some(encoded.clone())).await?;
    assert!(!String::from_utf8_lossy(&first).contains("Maverick"));

    let second = tunnel_attempt_body(&cfg, Some(encoded)).await?;
    assert_fallback_body(&second);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_bad_auth_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        ..HarnessOptions::default()
    })
    .await?;
    let mut bad = fixture.client_config();
    bad.auth = auth_v2_client_config(202607);
    bad.server.secret = SecretString::generate();
    let encoded = auth_v2_hello(&bad, 202607)?;

    let body = tunnel_attempt_body(&bad, Some(encoded)).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn repeated_bad_auth_keeps_fallback_shape_when_rate_limited() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_max_auth_failures_per_window: Some(1),
        server_auth_failure_window_secs: Some(60),
        ..HarnessOptions::default()
    })
    .await?;
    let mut bad = fixture.client_config();
    bad.server.secret = SecretString::generate();
    let encoded = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();

    let first = tunnel_attempt_body(&bad, Some(encoded.clone())).await?;
    assert_fallback_body(&first);

    let second = tunnel_attempt_body(&bad, Some(encoded)).await?;
    assert_eq!(second, first);

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let response = fetch_metrics(metrics_addr).await?;
    assert_eq!(metric_value(&response, "unauthenticated_rejections")?, 2);
    assert_eq!(metric_value(&response, "fallback_requests")?, 2);
    assert_eq!(metric_value(&response, "auth_rate_limit_rejections")?, 1);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_global_connection_limit_rejects_extra_connections() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_max_concurrent_connections: Some(1),
        server_max_concurrent_connections_per_source: Some(8),
        server_handshake_timeout_ms: Some(1_000),
        ..HarnessOptions::default()
    })
    .await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;

    let first = TcpStream::connect(fixture.server.local_addr).await?;
    wait_for_metric(metrics_addr, "active_connections", 1).await?;
    let second = TcpStream::connect(fixture.server.local_addr).await?;
    let metrics = wait_for_metric(metrics_addr, "connection_limit_rejections", 1).await?;

    assert_eq!(metric_value(&metrics, "active_connections")?, 1);
    assert_eq!(
        metric_value(&metrics, "source_connection_limit_rejections")?,
        0
    );

    drop(second);
    drop(first);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_per_source_connection_limit_rejects_extra_connections() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_max_concurrent_connections: Some(8),
        server_max_concurrent_connections_per_source: Some(1),
        server_handshake_timeout_ms: Some(1_000),
        ..HarnessOptions::default()
    })
    .await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;

    let first = TcpStream::connect(fixture.server.local_addr).await?;
    wait_for_metric(metrics_addr, "active_connections", 1).await?;
    let second = TcpStream::connect(fixture.server.local_addr).await?;
    let metrics = wait_for_metric(metrics_addr, "source_connection_limit_rejections", 1).await?;

    assert_eq!(metric_value(&metrics, "active_connections")?, 1);
    assert_eq!(metric_value(&metrics, "connection_limit_rejections")?, 0);

    drop(second);
    drop(first);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn fallback_overload_returns_generic_http_without_protocol_detail() -> Result<()> {
    let (fallback_addr, fallback_entered_rx, fallback_release_tx) =
        start_blocking_fallback(b"captured fallback").await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_fallback_max_concurrent: Some(1),
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{fallback_addr}/mirror"),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let ordinary_config = config.clone();
    let ordinary =
        tokio::spawn(
            async move { h2_request_shape(&ordinary_config, Method::GET, "/", None).await },
        );
    timeout(Duration::from_secs(2), fallback_entered_rx).await??;

    let mut bad = config.clone();
    bad.server.secret = SecretString::generate();
    let bad_hello = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();
    let overloaded = h2_request_shape(
        &bad,
        Method::POST,
        bad.server.tunnel_path.as_str(),
        Some(bad_hello),
    )
    .await?;
    assert_eq!(overloaded.status, StatusCode::SERVICE_UNAVAILABLE);
    let overload_body = String::from_utf8_lossy(&overloaded.body);
    assert!(!overload_body.contains("Maverick"));
    assert!(!overload_body.contains("auth"));
    assert!(!overload_body.contains("tunnel"));

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let metrics = fetch_metrics(metrics_addr).await?;
    assert_eq!(metric_value(&metrics, "active_fallbacks")?, 1);
    assert_eq!(metric_value(&metrics, "fallback_overload_rejections")?, 1);

    let _ = fallback_release_tx.send(());
    let ordinary = ordinary.await??;
    assert_eq!(ordinary.status, StatusCode::OK);
    assert_eq!(&ordinary.body[..], b"captured fallback");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_disabled_user_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        user_enabled: false,
        auth_v2_epoch: Some(202607),
        ..HarnessOptions::default()
    })
    .await?;
    let mut cfg = fixture.client_config();
    cfg.auth = auth_v2_client_config(202607);
    let encoded = auth_v2_hello(&cfg, 202607)?;

    let body = tunnel_attempt_body(&cfg, Some(encoded)).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_require_rejects_v1_client_hello_to_fallback() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        auth_v2_require: true,
        ..HarnessOptions::default()
    })
    .await?;
    let cfg = fixture.client_config();

    let body = tunnel_attempt_body(&cfg, None).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_accepts_current_and_previous_configured_epochs() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        auth_v2_extra_accepted_epochs: vec![202606],
        ..HarnessOptions::default()
    })
    .await?;

    let mut previous_epoch = fixture.client_config();
    previous_epoch.auth = auth_v2_client_config(202606);
    maverick_client::tunnel::open(&previous_epoch).await?;

    let mut current_epoch = fixture.client_config();
    current_epoch.auth = auth_v2_client_config(202607);
    maverick_client::tunnel::open(&current_epoch).await?;

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn auth_v2_expired_epoch_is_rejected_outside_rotation_window() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_v2_epoch: Some(202607),
        auth_v2_extra_accepted_epochs: vec![202606],
        ..HarnessOptions::default()
    })
    .await?;
    let mut expired_epoch = fixture.client_config();
    expired_epoch.auth = auth_v2_client_config(202605);

    let result = maverick_client::tunnel::open(&expired_epoch).await;
    assert!(result.is_err());

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn runtime_shaping_padding_tcp_relay_roundtrip() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 32,
        max_overhead_ratio: 0.5,
        ..ShapingConfig::default()
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-shaped").await?;
    let mut echoed = [0u8; 15];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-shaped");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn runtime_shaping_batching_tcp_relay_roundtrip() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 16,
        max_overhead_ratio: 0.25,
        max_delay_ms: 1,
        max_batch_bytes: 128,
        ..ShapingConfig::default()
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-batched").await?;
    let mut echoed = [0u8; 16];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-batched");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn runtime_cover_traffic_tcp_relay_roundtrip() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 32,
        max_overhead_ratio: 0.5,
        max_delay_ms: 1,
        max_batch_bytes: 128,
        cover_traffic: true,
        cover_traffic_operator_approved: true,
        cover_traffic_window_ms: 1_000,
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-cover-client").await?;
    let mut echoed = [0u8; 21];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-cover-client");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_side_runtime_padding_tcp_relay_roundtrip() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 32,
        max_overhead_ratio: 0.5,
        max_delay_ms: 1,
        max_batch_bytes: 128,
        ..ShapingConfig::default()
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-server-padding").await?;
    let mut echoed = [0u8; 23];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-server-padding");

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let metrics = fetch_metrics(metrics_addr).await?;
    assert!(metric_value(&metrics, "shaping_padding_frames")? > 0);
    assert!(metric_value(&metrics, "shaping_padding_bytes")? > 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_side_runtime_cover_traffic_metrics() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 32,
        max_overhead_ratio: 0.5,
        max_delay_ms: 1,
        max_batch_bytes: 128,
        cover_traffic: true,
        cover_traffic_operator_approved: true,
        cover_traffic_window_ms: 1_000,
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        server_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-cover-server").await?;
    let mut echoed = [0u8; 21];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-cover-server");

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let metrics = fetch_metrics(metrics_addr).await?;
    assert!(metric_value(&metrics, "shaping_padding_frames")? > 0);
    assert!(metric_value(&metrics, "shaping_padding_bytes")? > 0);
    assert!(metric_value(&metrics, "cover_traffic_padding_frames")? > 0);
    assert!(metric_value(&metrics, "cover_traffic_padding_bytes")? > 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bad_auth_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut bad = fixture.client_config();
    bad.server.secret = SecretString::generate();

    let body = tunnel_attempt_body(&bad, None).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn active_probe_h2_rejections_match_same_path_static_fallback_shape() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let ordinary = h2_request_shape(
        &config,
        Method::GET,
        config.server.tunnel_path.as_str(),
        None,
    )
    .await?;

    let mut bad = config.clone();
    bad.server.secret = SecretString::generate();
    let bad_hello = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();
    let bad_auth = h2_request_shape(
        &bad,
        Method::POST,
        bad.server.tunnel_path.as_str(),
        Some(bad_hello),
    )
    .await?;
    assert_eq!(bad_auth, ordinary);

    let malformed = h2_request_shape(
        &config,
        Method::POST,
        config.server.tunnel_path.as_str(),
        Some(vec![0x00]),
    )
    .await?;
    assert_eq!(malformed, ordinary);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn active_probe_h2_rejections_match_reverse_proxy_fallback_shape() -> Result<()> {
    let fallback_addr = start_repeating_fallback(b"captured fallback").await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{fallback_addr}/mirror"),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let ordinary = h2_request_shape(&config, Method::GET, "/", None).await?;

    let mut bad = config.clone();
    bad.server.secret = SecretString::generate();
    let bad_hello = ClientHello::new(
        bad.server.credential_id.clone(),
        &bad.server.secret,
        &bad.server.tunnel_path,
        bad.mode,
        0,
    )?
    .encode();
    let bad_auth = h2_request_shape(
        &bad,
        Method::POST,
        bad.server.tunnel_path.as_str(),
        Some(bad_hello),
    )
    .await?;
    assert_eq!(bad_auth, ordinary);

    let malformed = h2_request_shape(
        &config,
        Method::POST,
        config.server.tunnel_path.as_str(),
        Some(vec![0x00]),
    )
    .await?;
    assert_eq!(malformed, ordinary);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bad_auth_reverse_proxy_fallback_preserves_tunnel_path_and_query() -> Result<()> {
    let (fallback_addr, request_line_rx) = start_capture_fallback().await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{fallback_addr}/mirror"),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let mut bad = fixture.client_config();
    bad.server.secret = SecretString::generate();

    let body = tunnel_attempt_body_at(&bad, "/assets/upload?case=bad-auth", None).await?;
    assert_fallback_body(&body);
    let request_line = timeout(Duration::from_secs(2), request_line_rx).await??;
    assert_eq!(
        request_line,
        "POST /mirror/assets/upload?case=bad-auth HTTP/1.1"
    );

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_client_hello_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let cfg = fixture.client_config();

    let body = tunnel_attempt_body(&cfg, Some(vec![0x00])).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn previous_credential_inside_rotation_window_authenticates() -> Result<()> {
    let previous_secret = SecretString::generate();
    let previous_id = "u_test_previous";
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        previous_credentials: vec![previous_credential(
            previous_id,
            previous_secret.clone(),
            -60,
            3_600,
        )?],
        ..HarnessOptions::default()
    })
    .await?;
    let mut cfg = fixture.client_config();
    cfg.server.credential_id = previous_id.into();
    cfg.server.secret = previous_secret;

    let body = tunnel_attempt_body(&cfg, None).await?;
    assert!(!String::from_utf8_lossy(&body).contains("Maverick"));

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_tunnel_authenticates_when_channel_binding_is_required() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_channel_binding_require: true,
        ..HarnessOptions::default()
    })
    .await?;

    maverick_client::tunnel::open(&fixture.client_config()).await?;

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn previous_credential_after_rotation_window_returns_fallback() -> Result<()> {
    let previous_secret = SecretString::generate();
    let previous_id = "u_test_previous";
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        previous_credentials: vec![previous_credential(
            previous_id,
            previous_secret.clone(),
            -3_600,
            -60,
        )?],
        ..HarnessOptions::default()
    })
    .await?;
    let mut cfg = fixture.client_config();
    cfg.server.credential_id = previous_id.into();
    cfg.server.secret = previous_secret;

    let body = tunnel_attempt_body(&cfg, None).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn client_auto_switches_to_next_credential_after_not_before() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let current = fixture.client_config();
    let mut cfg = current.clone();
    cfg.server.credential_id = "u_test_previous_local".into();
    cfg.server.secret = SecretString::generate();
    cfg.auth.rotation = ClientCredentialRotationConfig {
        next_credential_id: Some(current.server.credential_id.clone()),
        auto_switch: true,
        next: Some(ClientNextCredentialConfig {
            id: current.server.credential_id.clone(),
            secret: current.server.secret.clone(),
            not_before: rfc3339_offset(-60)?,
        }),
        ..ClientCredentialRotationConfig::default()
    };

    maverick_client::tunnel::open(&cfg).await?;

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn client_keeps_active_credential_before_next_not_before() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let current = fixture.client_config();
    let mut cfg = current.clone();
    cfg.server.credential_id = "u_test_previous_local".into();
    cfg.server.secret = SecretString::generate();
    cfg.auth.rotation = ClientCredentialRotationConfig {
        next_credential_id: Some(current.server.credential_id.clone()),
        auto_switch: true,
        next: Some(ClientNextCredentialConfig {
            id: current.server.credential_id.clone(),
            secret: current.server.secret.clone(),
            not_before: rfc3339_offset(3_600)?,
        }),
        ..ClientCredentialRotationConfig::default()
    };

    let result = maverick_client::tunnel::open(&cfg).await;
    assert!(result.is_err());

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn replayed_client_hello_is_rejected_to_fallback() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let cfg = fixture.client_config();
    let hello = ClientHello::new(
        cfg.server.credential_id.clone(),
        &cfg.server.secret,
        &cfg.server.tunnel_path,
        cfg.mode,
        0,
    )?;
    let encoded = hello.encode();

    let first = tunnel_attempt_body(&cfg, Some(encoded.clone())).await?;
    assert!(!String::from_utf8_lossy(&first).contains("Maverick"));

    let second = tunnel_attempt_body(&cfg, Some(encoded)).await?;
    assert_fallback_body(&second);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_authenticated_stream_times_out_before_open_frame() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        server_handshake_timeout_ms: Some(100),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let sender = transport::connect(&config).await?;
    let mut h2 = match sender {
        transport::TunnelRequestSender::H2(h2) => h2,
        _ => anyhow::bail!("expected h2 transport"),
    };
    let request = Request::builder()
        .method("POST")
        .uri(config.server.tunnel_path.as_str())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?;
    let (response_fut, mut send_stream) = h2.sender.send_request(request, false)?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        0,
    )?
    .encode();
    send_stream.send_data(
        encode_grpc_frame(Frame::new(FrameType::ClientHello, 0, 0, hello), 65_536)?,
        false,
    )?;
    let response = response_fut.await?;
    let mut body = response.into_body();
    let started = Instant::now();
    let (mut response_bytes, trailers) =
        timeout(Duration::from_secs(2), collect_h2_response(&mut body)).await??;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_grpc_status_ok(&trailers);

    let mut frame_types = Vec::new();
    while let Some(frame) = decode_grpc_frame_from(&mut response_bytes, 65_536)? {
        frame_types.push(frame.frame_type);
    }
    assert!(response_bytes.is_empty());
    assert_eq!(frame_types, vec![FrameType::ServerHello, FrameType::Error]);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_udp_explicit_close_flow_ends_with_grpc_ok_trailers() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let sender = transport::connect(&config).await?;
    let mut h2 = match sender {
        transport::TunnelRequestSender::H2(h2) => h2,
        _ => anyhow::bail!("expected h2 transport"),
    };
    let request = Request::builder()
        .method("POST")
        .uri(config.server.tunnel_path.as_str())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?;
    let (response_fut, mut send_stream) = h2.sender.send_request(request, false)?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        0,
    )?
    .encode();
    send_stream.send_data(
        encode_grpc_frame(Frame::new(FrameType::ClientHello, 0, 0, hello), 65_536)?,
        false,
    )?;
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(
                FrameType::OpenUdp,
                0,
                1,
                OpenUdpPayload::new(1_000).encode(),
            ),
            65_536,
        )?,
        false,
    )?;
    send_stream.send_data(
        encode_grpc_frame(Frame::new(FrameType::CloseFlow, 0, 1, Bytes::new()), 65_536)?,
        true,
    )?;

    let response = response_fut.await?;
    let mut body = response.into_body();
    let (mut response_bytes, trailers) =
        timeout(Duration::from_secs(2), collect_h2_response(&mut body)).await??;
    assert_grpc_status_ok(&trailers);

    let mut frame_types = Vec::new();
    while let Some(frame) = decode_grpc_frame_from(&mut response_bytes, 65_536)? {
        frame_types.push(frame.frame_type);
    }
    assert!(response_bytes.is_empty());
    assert_eq!(
        frame_types,
        vec![FrameType::ServerHello, FrameType::WindowUpdate]
    );

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_udp_bare_request_eof_resets_without_grpc_ok_trailers() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let sender = transport::connect(&config).await?;
    let mut h2 = match sender {
        transport::TunnelRequestSender::H2(h2) => h2,
        _ => anyhow::bail!("expected h2 transport"),
    };
    let request = Request::builder()
        .method("POST")
        .uri(config.server.tunnel_path.as_str())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?;
    let (response_fut, mut send_stream) = h2.sender.send_request(request, false)?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        0,
    )?
    .encode();
    send_stream.send_data(
        encode_grpc_frame(Frame::new(FrameType::ClientHello, 0, 0, hello), 65_536)?,
        false,
    )?;
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(
                FrameType::OpenUdp,
                0,
                1,
                OpenUdpPayload::new(1_000).encode(),
            ),
            65_536,
        )?,
        true,
    )?;

    let response = response_fut.await?;
    let mut body = response.into_body();
    let mut saw_reset = false;
    loop {
        match timeout(Duration::from_secs(2), body.data()).await? {
            Some(Ok(chunk)) => {
                body.flow_control().release_capacity(chunk.len())?;
            }
            Some(Err(_)) => {
                saw_reset = true;
                break;
            }
            None => break,
        }
    }
    assert!(
        saw_reset,
        "bare UDP request EOF must reset instead of sending grpc-status: 0"
    );

    fixture.shutdown().await?;
    Ok(())
}

fn previous_credential(
    id: &str,
    secret: SecretString,
    not_before_offset_secs: i64,
    not_after_offset_secs: i64,
) -> Result<PreviousCredentialConfig> {
    Ok(PreviousCredentialConfig {
        id: id.into(),
        secret,
        not_before: rfc3339_offset(not_before_offset_secs)?,
        not_after: rfc3339_offset(not_after_offset_secs)?,
    })
}

fn rfc3339_offset(offset_secs: i64) -> Result<String> {
    Ok((OffsetDateTime::now_utc() + TimeDuration::seconds(offset_secs)).format(&Rfc3339)?)
}

fn auth_v2_client_config(epoch: u64) -> ClientAuthConfig {
    ClientAuthConfig {
        channel_binding: Default::default(),
        v2: AuthV2Config {
            enabled: true,
            require: false,
            accepted_epochs: Vec::new(),
        },
        rotation: ClientCredentialRotationConfig {
            active_epoch: Some(epoch.to_string()),
            ..ClientCredentialRotationConfig::default()
        },
    }
}

fn auth_v2_hello(config: &ClientConfig, epoch: u64) -> Result<Vec<u8>> {
    Ok(ClientHelloV2::new(
        config.server.credential_id.as_bytes().to_vec(),
        &config.server.secret,
        epoch,
        &config.server.tunnel_path,
        config.mode,
        0,
        0,
    )?
    .encode()?)
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_tcp_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-h3-echo").await?;
    let mut echoed = [0u8; 16];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-h3-echo");

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_server_side_runtime_padding_tcp_relay_roundtrip() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 32,
        max_overhead_ratio: 0.5,
        max_delay_ms: 1,
        max_batch_bytes: 128,
        ..ShapingConfig::default()
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        server_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let mut socks = socks_connect(fixture.client.local_addr, echo_addr).await?;

    socks.write_all(b"maverick-h3-server-pad").await?;
    let mut echoed = [0u8; 22];
    socks.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"maverick-h3-server-pad");

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_bad_auth_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let mut bad = fixture.client_config();
    bad.advanced.experimental_h3 = true;
    bad.server.secret = SecretString::generate();

    let body = tunnel_attempt_body(&bad, None).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_reverse_proxy_bad_auth_preserves_available_request_body() -> Result<()> {
    let fallback_addr = start_body_length_fallback().await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        fallback: Some(FallbackConfig::ReverseProxy {
            upstream: format!("http://{fallback_addr}"),
        }),
        ..HarnessOptions::default()
    })
    .await?;
    let mut bad = fixture.client_config();
    bad.advanced.experimental_h3 = true;
    bad.server.secret = SecretString::generate();

    let body = tunnel_attempt_body(&bad, None).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.starts_with("body_length="));
    assert_ne!(body, "body_length=0");

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_malformed_client_hello_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let mut cfg = fixture.client_config();
    cfg.advanced.experimental_h3 = true;

    let body = tunnel_attempt_body(&cfg, Some(vec![0x00])).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_replayed_client_hello_is_rejected_to_fallback() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let mut cfg = fixture.client_config();
    cfg.advanced.experimental_h3 = true;
    let hello = ClientHello::new(
        cfg.server.credential_id.clone(),
        &cfg.server.secret,
        &cfg.server.tunnel_path,
        cfg.mode,
        0,
    )?;
    let encoded = hello.encode();

    let first = tunnel_attempt_body(&cfg, Some(encoded.clone())).await?;
    assert!(!String::from_utf8_lossy(&first).contains("Maverick"));

    let second = tunnel_attempt_body(&cfg, Some(encoded)).await?;
    assert_fallback_body(&second);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_transport_failure_falls_back_to_h2() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut config = fixture.client_config();
    config.advanced.experimental_h3 = true;
    config.advanced.connect_timeout_ms = 50;

    let sender = timeout(Duration::from_secs(2), transport::connect(&config)).await??;
    assert!(matches!(sender, transport::TunnelRequestSender::H2(_)));

    let sender = timeout(Duration::from_secs(2), transport::connect(&config)).await??;
    assert!(matches!(sender, transport::TunnelRequestSender::H2(_)));

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_dns_relay_roundtrip() -> Result<()> {
    let upstream = start_fake_dns_server().await?;
    let options = HarnessOptions {
        dns_upstream: Some(upstream),
        experimental_h3: true,
        ..HarnessOptions::default()
    };
    let fixture = MaverickHarness::start_with_options(options).await?;
    let dns_addr = fixture.client.dns_addr.context("missing DNS listener")?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(b"h3-example-query", dns_addr).await?;
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).await?;
    assert_eq!(&buf[..len], b"dns-response:h3-example-query");

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_socks5_udp_associate_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let udp_echo_addr = start_udp_echo_server().await?;
    let mut control = TcpStream::connect(fixture.client.local_addr).await?;

    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    assert_eq!(associate_reply[1], 0x00);
    let udp_port = u16::from_be_bytes([associate_reply[8], associate_reply[9]]);
    let udp_bind = SocketAddr::from(([127, 0, 0, 1], udp_port));

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    datagram.extend_from_slice(&udp_echo_addr.port().to_be_bytes());
    datagram.extend_from_slice(b"h3-udp-echo");
    udp.send_to(&datagram, udp_bind).await?;

    let mut response = [0u8; 1024];
    let (len, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut response)).await??;
    assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&response[len - 11..len], b"h3-udp-echo");

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_association_opens_real_h3() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);

    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_ip = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST);
    let open_result = timeout(
        Duration::from_secs(2),
        LegacyH3DuplexUdpAssociation::open(&config, target_ip, target_addr.port()),
    )
    .await
    .context("public legacy-H3 duplex association open must remain bounded")?;
    let mut association = match open_result {
        Ok(association) => association,
        Err(error) => {
            assert_eq!(error.to_string(), "legacy-H3 duplex UDP client unavailable");
            let public_error: &(dyn std::error::Error + Send + Sync + 'static) = error.as_ref();
            assert!(std::error::Error::source(public_error).is_none());

            let mut target_buf = [0_u8; 64];
            match timeout(Duration::from_secs(1), target.recv_from(&mut target_buf)).await {
                Err(_) => {}
                Ok(Ok((len, _))) => panic!(
                    "unavailable public legacy-H3 duplex association reached the real target with {len} bytes"
                ),
                Ok(Err(error)) => {
                    return Err(error)
                        .context("observe unavailable public legacy-H3 duplex target")
                }
            }
            assert_h3_transport(&config);
            fixture.shutdown().await?;
            panic!("public legacy-H3 duplex association stayed unavailable");
        }
    };

    let exact_source = {
        let (send_half, receive_half) = association.split();
        let client_direction = async {
            send_half
                .send_packet(Bytes::from_static(b"public-duplex-a"))
                .await?;
            send_half
                .send_packet(Bytes::from_static(b"public-duplex-b"))
                .await?;

            for expected in [
                b"target-push-one".as_slice(),
                b"target-push-two".as_slice(),
                b"target-push-three".as_slice(),
            ] {
                let payload = timeout(Duration::from_secs(2), receive_half.receive_packet())
                    .await
                    .context("public duplex receive must remain bounded")??
                    .context("public duplex receive ended before target push")?;
                anyhow::ensure!(payload.as_ref() == expected, "target push payload mismatch");
            }

            send_half
                .send_packet(Bytes::from_static(b"public-duplex-c"))
                .await?;
            Result::<()>::Ok(())
        };
        let target_direction = async {
            let mut target_buf = [0_u8; 64];
            let (len, exact_source) =
                timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                    .await
                    .context("real target did not receive public duplex packet A")??;
            anyhow::ensure!(
                &target_buf[..len] == b"public-duplex-a",
                "public duplex packet A mismatch"
            );

            let (len, source_b) =
                timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                    .await
                    .context(
                        "real target did not receive public duplex packet B before replying",
                    )??;
            anyhow::ensure!(
                &target_buf[..len] == b"public-duplex-b",
                "public duplex packet B mismatch"
            );
            anyhow::ensure!(
                source_b == exact_source,
                "public duplex packets did not reuse one server UDP source"
            );

            for payload in [
                b"target-push-one".as_slice(),
                b"target-push-two".as_slice(),
                b"target-push-three".as_slice(),
            ] {
                let sent = target.send_to(payload, exact_source).await?;
                anyhow::ensure!(sent == payload.len(), "target push was truncated");
            }

            let (len, source_c) =
                timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                    .await
                    .context("real target did not receive public duplex packet C after pushes")??;
            anyhow::ensure!(
                &target_buf[..len] == b"public-duplex-c",
                "public duplex packet C mismatch"
            );
            anyhow::ensure!(
                source_c == exact_source,
                "public duplex packet C changed the server UDP source"
            );
            Result::<SocketAddr>::Ok(exact_source)
        };
        let (client_result, target_result) = timeout(Duration::from_secs(5), async {
            tokio::join!(client_direction, target_direction)
        })
        .await
        .context("public legacy-H3 duplex exchange must remain bounded")?;
        client_result?;
        target_result?
    };

    timeout(Duration::from_secs(2), association.close())
        .await
        .context("public legacy-H3 duplex close must remain bounded")??;
    let rebound = rebind_released_udp_source(exact_source, "public duplex close").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);

    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_receive_cancel_remains_usable() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut association = timeout(
        Duration::from_secs(2),
        LegacyH3DuplexUdpAssociation::open(
            &config,
            TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            target_addr.port(),
        ),
    )
    .await
    .context("receive-cancel association open must remain bounded")??;

    let exact_source = {
        let (send_half, receive_half) = association.split();
        send_half
            .send_packet(Bytes::from_static(b"receive-cancel-a"))
            .await?;
        let mut target_buf = [0_u8; 64];
        let (len, exact_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                .await
                .context("receive-cancel target did not receive packet A")??;
        assert_eq!(&target_buf[..len], b"receive-cancel-a");

        let mut pending_receive = Box::pin(receive_half.receive_packet());
        assert!(
            futures::poll!(pending_receive.as_mut()).is_pending(),
            "receive-cancel future completed without a target push"
        );
        drop(pending_receive);

        let pushed = target
            .send_to(b"receive-after-cancel", exact_source)
            .await?;
        assert_eq!(pushed, b"receive-after-cancel".len());
        let received = timeout(Duration::from_secs(2), receive_half.receive_packet())
            .await
            .context("receive after cancellation must remain bounded")??
            .context("receive after cancellation ended cleanly instead of returning the push")?;
        assert_eq!(received.as_ref(), b"receive-after-cancel");

        send_half
            .send_packet(Bytes::from_static(b"receive-cancel-b"))
            .await?;
        let (len, source_b) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
            .await
            .context("receive-cancel target did not receive packet B")??;
        assert_eq!(&target_buf[..len], b"receive-cancel-b");
        assert_eq!(source_b, exact_source);
        exact_source
    };

    timeout(Duration::from_secs(2), association.close())
        .await
        .context("receive-cancel close must remain bounded")??;
    let rebound = rebind_released_udp_source(exact_source, "receive-cancel close").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_send_cancel_poison_is_sticky() -> Result<()> {
    let shaping = ShapingConfig {
        enabled: true,
        max_padding_bytes_per_frame: 16,
        max_overhead_ratio: 0.0,
        max_delay_ms: 250,
        max_batch_bytes: 4_096,
        ..ShapingConfig::default()
    };
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        client_shaping: Some(shaping),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut association = timeout(
        Duration::from_secs(3),
        LegacyH3DuplexUdpAssociation::open(
            &config,
            TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            target_addr.port(),
        ),
    )
    .await
    .context("send-cancel association open must remain bounded")??;

    let exact_source = {
        let (send_half, receive_half) = association.split();
        send_half
            .send_packet(Bytes::from_static(b"send-cancel-a"))
            .await?;
        let mut target_buf = [0_u8; 64];
        let (len, exact_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                .await
                .context("send-cancel target did not receive packet A")??;
        assert_eq!(&target_buf[..len], b"send-cancel-a");

        let mut pending_send =
            Box::pin(send_half.send_packet(Bytes::from_static(b"send-cancel-b")));
        assert!(
            futures::poll!(pending_send.as_mut()).is_pending(),
            "send-cancel future did not reach its armed shaping wait"
        );
        drop(pending_send);

        let send_error = send_half
            .send_packet(Bytes::from_static(b"send-after-cancel"))
            .await
            .unwrap_err();
        assert_source_free_fixed_error(
            &send_error,
            "legacy-H3 duplex UDP association is no longer usable",
        );
        let receive_error = receive_half.receive_packet().await.unwrap_err();
        assert_source_free_fixed_error(
            &receive_error,
            "legacy-H3 duplex UDP association is no longer usable",
        );
        match timeout(
            Duration::from_millis(500),
            target.recv_from(&mut target_buf),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok((len, _))) => {
                anyhow::bail!("cancelled public duplex send reached target with {len} bytes")
            }
            Ok(Err(error)) => return Err(error).context("observe send-cancel target"),
        }
        exact_source
    };

    let close_error = association.close().await.unwrap_err();
    assert_source_free_fixed_error(
        &close_error,
        "legacy-H3 duplex UDP association is no longer usable",
    );
    let rebound = rebind_released_udp_source(exact_source, "send-cancel abort").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_oversize_send_fails_and_aborts_owner() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut association = LegacyH3DuplexUdpAssociation::open(
        &config,
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
    )
    .await?;

    let exact_source = {
        let (send_half, receive_half) = association.split();
        send_half
            .send_packet(Bytes::from_static(b"oversize-owner-a"))
            .await?;
        let mut target_buf = [0_u8; 64];
        let (len, exact_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                .await
                .context("oversize-send target did not receive packet A")??;
        assert_eq!(&target_buf[..len], b"oversize-owner-a");

        let send_error = send_half
            .send_packet(Bytes::from(vec![0_u8; 65_536]))
            .await
            .unwrap_err();
        assert_source_free_fixed_error(&send_error, "legacy-H3 duplex UDP send failed");
        let later_send_error = send_half
            .send_packet(Bytes::from_static(b"oversize-after-failure"))
            .await
            .unwrap_err();
        assert_source_free_fixed_error(
            &later_send_error,
            "legacy-H3 duplex UDP association is no longer usable",
        );
        let receive_error = receive_half.receive_packet().await.unwrap_err();
        assert_source_free_fixed_error(
            &receive_error,
            "legacy-H3 duplex UDP association is no longer usable",
        );
        match timeout(
            Duration::from_millis(500),
            target.recv_from(&mut target_buf),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok((len, _))) => {
                anyhow::bail!("oversize public duplex send reached target with {len} bytes")
            }
            Ok(Err(error)) => return Err(error).context("observe oversize-send target"),
        }
        exact_source
    };

    let close_error = association.close().await.unwrap_err();
    assert_source_free_fixed_error(
        &close_error,
        "legacy-H3 duplex UDP association is no longer usable",
    );
    let rebound = rebind_released_udp_source(exact_source, "oversize-send abort").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test(flavor = "current_thread")]
async fn h3_public_duplex_udp_close_cancel_aborts_owner() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut association = LegacyH3DuplexUdpAssociation::open(
        &config,
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
    )
    .await?;
    let exact_source = {
        let (send_half, _) = association.split();
        send_half
            .send_packet(Bytes::from_static(b"close-cancel-a"))
            .await?;
        let mut target_buf = [0_u8; 64];
        let (len, exact_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                .await
                .context("close-cancel target did not receive packet A")??;
        assert_eq!(&target_buf[..len], b"close-cancel-a");
        exact_source
    };

    let mut pending_close = Box::pin(association.close());
    assert!(
        futures::poll!(pending_close.as_mut()).is_pending(),
        "close-cancel future completed before its peer could run"
    );
    drop(pending_close);

    let rebound = rebind_released_udp_source(exact_source, "close-cancel abort").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_idle_close_returns_none() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let mut config = fixture.client_config();
    config.advanced.udp_idle_timeout_ms = 100;
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut association = LegacyH3DuplexUdpAssociation::open(
        &config,
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
    )
    .await?;

    let (received, exact_source) = {
        let (send_half, receive_half) = association.split();
        send_half
            .send_packet(Bytes::from_static(b"idle-active-owner"))
            .await?;
        let mut target_buf = [0_u8; 64];
        let (len, exact_source) =
            timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
                .await
                .context("idle-close target did not receive the owner-establishing packet")??;
        assert_eq!(&target_buf[..len], b"idle-active-owner");
        let received = timeout(Duration::from_secs(2), receive_half.receive_packet())
            .await
            .context("public duplex active-owner idle close must remain bounded")??;
        (received, exact_source)
    };
    assert!(received.is_none());
    association.close().await?;
    let rebound = rebind_released_udp_source(exact_source, "active-owner idle close").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_preflight_rejects_before_network() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        ..HarnessOptions::default()
    })
    .await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing preflight metrics listener")?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let server_sentinel = UdpSocket::bind("127.0.0.1:0").await?;
    let server_sentinel_addr = server_sentinel.local_addr()?;
    let target_ip = TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST);
    let mut baseline = fixture.client_config();
    baseline.server.address = server_sentinel_addr.to_string();

    let mut invalid = baseline.clone();
    invalid.advanced.experimental_h3 = true;
    invalid.version = 2;
    let invalid_error = expect_legacy_h3_duplex_open_error(
        LegacyH3DuplexUdpAssociation::open(&invalid, target_ip.clone(), target_addr.port()).await,
        "invalid-config public duplex preflight",
    )?;
    assert_source_free_fixed_error(&invalid_error, "legacy-H3 duplex UDP open failed");

    let disabled_error = expect_legacy_h3_duplex_open_error(
        LegacyH3DuplexUdpAssociation::open(&baseline, target_ip.clone(), target_addr.port()).await,
        "disabled public duplex preflight",
    )?;
    assert_source_free_fixed_error(&disabled_error, "legacy-H3 duplex UDP open failed");

    let mut fronted = baseline.clone();
    fronted.advanced.stealth.tls_fingerprint = Default::default();
    fronted.advanced.stealth.cdn_fronting.enabled = true;
    fronted
        .advanced
        .stealth
        .cdn_fronting
        .trusted_tls_terminating_provider = true;
    fronted.validate()?;
    assert!(!fronted.advanced.experimental_h3);
    assert!(fronted.advanced.cloudflare_ws_enabled());
    let fronted_error = expect_legacy_h3_duplex_open_error(
        LegacyH3DuplexUdpAssociation::open(&fronted, target_ip.clone(), target_addr.port()).await,
        "fronted public duplex preflight",
    )?;
    assert_source_free_fixed_error(&fronted_error, "legacy-H3 duplex UDP open failed");

    let mut binding_required = baseline;
    binding_required.advanced.experimental_h3 = true;
    binding_required.auth.channel_binding.require = true;
    let binding_error = expect_legacy_h3_duplex_open_error(
        LegacyH3DuplexUdpAssociation::open(&binding_required, target_ip, target_addr.port()).await,
        "binding-required public duplex preflight",
    )?;
    assert_source_free_fixed_error(&binding_error, "legacy-H3 duplex UDP open failed");

    let metrics = fetch_metrics(metrics_addr).await?;
    assert_eq!(metric_value(&metrics, "authenticated_sessions")?, 0);
    assert_eq!(metric_value(&metrics, "active_connections")?, 0);
    let mut target_buf = [0_u8; 1];
    assert!(
        timeout(
            Duration::from_millis(200),
            target.recv_from(&mut target_buf)
        )
        .await
        .is_err(),
        "preflight rejection unexpectedly contacted its fixed target"
    );
    let mut sentinel_buf = [0_u8; 1];
    assert!(
        timeout(
            Duration::from_millis(200),
            server_sentinel.recv_from(&mut sentinel_buf)
        )
        .await
        .is_err(),
        "preflight rejection unexpectedly attempted its configured H3 server"
    );
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_public_duplex_udp_unavailable_h3_never_falls_back_to_h2() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        ..HarnessOptions::default()
    })
    .await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing strict-H3 metrics listener")?;
    let mut config = fixture.client_config();
    config.advanced.experimental_h3 = true;
    config.advanced.connect_timeout_ms = 100;
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;

    let error = expect_legacy_h3_duplex_open_error(
        timeout(
            Duration::from_secs(2),
            LegacyH3DuplexUdpAssociation::open(
                &config,
                TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                target_addr.port(),
            ),
        )
        .await
        .context("strict unavailable H3 open must remain bounded")?,
        "unavailable strict H3 open",
    )?;
    assert_source_free_fixed_error(&error, "legacy-H3 duplex UDP open failed");
    assert_h3_transport(&config);

    let metrics = fetch_metrics(metrics_addr).await?;
    assert_eq!(metric_value(&metrics, "authenticated_sessions")?, 0);
    assert_eq!(metric_value(&metrics, "active_connections")?, 0);
    let mut target_buf = [0_u8; 1];
    assert!(
        timeout(
            Duration::from_millis(200),
            target.recv_from(&mut target_buf)
        )
        .await
        .is_err(),
        "unavailable strict H3 open unexpectedly contacted its target"
    );
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_socks5_udp_associate_receives_target_push_without_client_packet() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        metrics: true,
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;

    let mut control = TcpStream::connect(fixture.client.local_addr).await?;
    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    assert_eq!(associate_reply[1], 0x00);
    let udp_port = u16::from_be_bytes([associate_reply[8], associate_reply[9]]);
    let udp_bind = SocketAddr::from(([127, 0, 0, 1], udp_port));
    let udp = UdpSocket::bind("127.0.0.1:0").await?;

    let mut request_a = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    request_a.extend_from_slice(&target_addr.port().to_be_bytes());
    request_a.extend_from_slice(b"socks-duplex-a");
    udp.send_to(&request_a, udp_bind).await?;

    let mut target_buf = [0u8; 256];
    let (len, exact_source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
        .await
        .context("normal SOCKS H3 packet A did not reach the real target")??;
    assert_eq!(&target_buf[..len], b"socks-duplex-a");
    target.send_to(b"socks-reply-a", exact_source).await?;

    let mut response = [0u8; 256];
    let (len, response_source) = timeout(Duration::from_secs(2), udp.recv_from(&mut response))
        .await
        .context("normal SOCKS H3 packet A reply stayed unavailable")??;
    assert_eq!(response_source, udp_bind);
    assert!(len >= 10);
    assert_eq!(&response[..8], &[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1]);
    assert_eq!(
        u16::from_be_bytes([response[8], response[9]]),
        target_addr.port()
    );
    assert_eq!(&response[10..len], b"socks-reply-a");

    let metrics = wait_for_metric(metrics_addr, "authenticated_sessions", 1).await?;
    assert_eq!(metric_value(&metrics, "authenticated_sessions")?, 1);
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_eq!(pool.active_streams, 0);
    match UdpSocket::bind(exact_source).await {
        Ok(socket) => {
            drop(socket);
            anyhow::bail!("normal SOCKS H3 target source was not retained before push")
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
        Err(error) => return Err(error).context("probe active normal SOCKS H3 target source"),
    }

    for push in [b"socks-push-one".as_slice(), b"socks-push-two".as_slice()] {
        let sent = target.send_to(push, exact_source).await?;
        assert_eq!(sent, push.len());
    }

    let pushes_delivered = match timeout(Duration::from_secs(1), async {
        for expected in [b"socks-push-one".as_slice(), b"socks-push-two".as_slice()] {
            let (len, response_source) = udp.recv_from(&mut response).await?;
            anyhow::ensure!(
                response_source == udp_bind,
                "SOCKS push used the wrong relay source"
            );
            anyhow::ensure!(len >= 10, "SOCKS push response was truncated");
            anyhow::ensure!(
                response[..8] == [0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1],
                "SOCKS push carried the wrong target"
            );
            anyhow::ensure!(
                u16::from_be_bytes([response[8], response[9]]) == target_addr.port(),
                "SOCKS push carried the wrong target port"
            );
            anyhow::ensure!(
                &response[10..len] == expected,
                "SOCKS target pushes arrived out of order"
            );
        }
        Result::<()>::Ok(())
    })
    .await
    {
        Ok(result) => {
            result?;
            true
        }
        Err(_) => false,
    };

    assert_h3_transport(&config);
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    drop(control);
    let rebound = rebind_released_udp_source(exact_source, "normal SOCKS H3 control EOF").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    drop(rebound);
    assert_h3_transport(&config);
    fixture.shutdown().await?;

    if !pushes_delivered {
        panic!("normal SOCKS legacy-H3 UDP target push stayed unavailable");
    }
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_socks5_duplex_udp_handoffs_single_active_target() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        metrics: true,
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing target-handoff metrics listener")?;
    let target_a = UdpSocket::bind("127.0.0.1:0").await?;
    let target_a_addr = target_a.local_addr()?;
    let target_b = UdpSocket::bind("127.0.0.1:0").await?;
    let target_b_addr = target_b.local_addr()?;
    let (control, udp, udp_bind) =
        open_normal_socks_udp_associate(fixture.client.local_addr).await?;
    let mut exact_sources = Vec::new();

    udp.send_to(
        &socks_udp_ipv4_request(target_a_addr, b"handoff-target-a-one"),
        udp_bind,
    )
    .await?;
    let mut target_a_buf = [0u8; 128];
    let (len, source_a_one) = timeout(
        Duration::from_secs(2),
        target_a.recv_from(&mut target_a_buf),
    )
    .await
    .context("target A did not receive the first handoff packet")??;
    assert_eq!(&target_a_buf[..len], b"handoff-target-a-one");
    exact_sources.push(source_a_one);
    target_a
        .send_to(b"handoff-reply-a-one", source_a_one)
        .await?;
    receive_socks_udp_ipv4_payload(&udp, udp_bind, target_a_addr, b"handoff-reply-a-one").await?;

    wait_for_metric_value(metrics_addr, "authenticated_sessions", 1).await?;

    udp.send_to(
        &socks_udp_ipv4_request(target_b_addr, b"handoff-target-b"),
        udp_bind,
    )
    .await?;
    let mut target_a_probe = [0u8; 128];
    let mut target_b_buf = [0u8; 128];
    let (target_a_contact, target_b_contact) = tokio::join!(
        timeout(
            Duration::from_millis(500),
            target_a.recv_from(&mut target_a_probe),
        ),
        timeout(
            Duration::from_secs(2),
            target_b.recv_from(&mut target_b_buf),
        ),
    );
    match target_a_contact {
        Err(_) => {}
        Ok(Ok((len, _))) => {
            anyhow::bail!("target-B handoff packet touched target A with {len} bytes")
        }
        Ok(Err(err)) => return Err(err).context("observe target A during target-B handoff"),
    }
    let handoff_completed = match target_b_contact {
        Err(_) => false,
        Ok(Err(err)) => return Err(err).context("observe target B during target handoff"),
        Ok(Ok((len, source_b))) => {
            assert_eq!(&target_b_buf[..len], b"handoff-target-b");
            if !exact_sources.contains(&source_b) {
                exact_sources.push(source_b);
            }
            target_b.send_to(b"handoff-reply-b", source_b).await?;
            receive_socks_udp_ipv4_payload(&udp, udp_bind, target_b_addr, b"handoff-reply-b")
                .await?;
            target_b.send_to(b"handoff-push-b", source_b).await?;
            receive_socks_udp_ipv4_payload(&udp, udp_bind, target_b_addr, b"handoff-push-b")
                .await?;
            true
        }
    };

    udp.send_to(
        &socks_udp_ipv4_request(target_a_addr, b"handoff-target-a-two"),
        udp_bind,
    )
    .await?;
    let mut target_b_probe = [0u8; 128];
    let (target_b_contact, target_a_contact) = tokio::join!(
        timeout(
            Duration::from_millis(500),
            target_b.recv_from(&mut target_b_probe),
        ),
        timeout(
            Duration::from_secs(2),
            target_a.recv_from(&mut target_a_buf),
        ),
    );
    match target_b_contact {
        Err(_) => {}
        Ok(Ok((len, _))) => {
            anyhow::bail!("target-A handoff packet touched target B with {len} bytes")
        }
        Ok(Err(err)) => return Err(err).context("observe target B during target-A handoff"),
    }
    let (len, source_a_two) =
        target_a_contact.context("target A stayed unavailable after target handoff")??;
    assert_eq!(&target_a_buf[..len], b"handoff-target-a-two");
    if !handoff_completed {
        assert_eq!(
            source_a_two, source_a_one,
            "parent fixed-target association changed source during A recovery"
        );
    }
    if !exact_sources.contains(&source_a_two) {
        exact_sources.push(source_a_two);
    }
    target_a
        .send_to(b"handoff-reply-a-two", source_a_two)
        .await?;
    receive_socks_udp_ipv4_payload(&udp, udp_bind, target_a_addr, b"handoff-reply-a-two").await?;

    let expected_authenticated_sessions = if handoff_completed { 3 } else { 1 };
    wait_for_metric_value(
        metrics_addr,
        "authenticated_sessions",
        expected_authenticated_sessions,
    )
    .await?;
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_eq!(pool.active_streams, 0);
    assert_h3_transport(&config);

    drop(control);
    for source in exact_sources {
        let rebound =
            rebind_released_udp_source(source, "SOCKS target handoff control EOF").await?;
        assert_eq!(rebound.local_addr()?, source);
        drop(rebound);
    }
    assert_h3_transport(&config);
    fixture.shutdown().await?;

    if !handoff_completed {
        panic!("normal SOCKS legacy-H3 UDP target handoff stayed unavailable");
    }
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_socks5_duplex_open_failure_ends_control_without_fallback() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        metrics: true,
        user_max_concurrent_flows: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let hold_target = start_hold_open_server().await?;
    let mut held_flow = socks_connect(fixture.client.local_addr, hold_target).await?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let (mut control, udp, udp_bind) =
        open_normal_socks_udp_associate(fixture.client.local_addr).await?;

    udp.send_to(
        &socks_udp_ipv4_request(target_addr, b"must-not-replay"),
        udp_bind,
    )
    .await?;
    let mut control_buf = [0u8; 1];
    let control_read = timeout(Duration::from_secs(2), control.read(&mut control_buf))
        .await
        .context("failed H3 duplex open did not end the SOCKS control association")??;
    assert_eq!(control_read, 0);
    assert_udp_target_uncontacted(&target, "failed normal SOCKS duplex open target").await?;

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let metrics = wait_for_metric(metrics_addr, "authenticated_sessions", 2).await?;
    assert_eq!(metric_value(&metrics, "authenticated_sessions")?, 2);
    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_h3_transport(&config);

    held_flow.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_setup_fallback_keeps_one_normal_socks_serial_association() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        ..HarnessOptions::default()
    })
    .await?;
    let mut fallback_config = fixture.client_config();
    fallback_config.local.socks5.listen = "127.0.0.1:0".parse()?;
    fallback_config.advanced.experimental_h3 = true;
    fallback_config.advanced.connect_timeout_ms = 250;
    let before = transport::transport_debug_snapshot(&fallback_config);
    assert_eq!(before.active_transport, GuiTransportCarrier::H3);
    assert!(before.h3_candidate_enabled);
    assert!(!before.h3_in_cooldown);
    let fallback_client = maverick_client::start_client(fallback_config.clone()).await?;
    let target_a = UdpSocket::bind("127.0.0.1:0").await?;
    let target_a_addr = target_a.local_addr()?;
    let target_b = UdpSocket::bind("127.0.0.1:0").await?;
    let target_b_addr = target_b.local_addr()?;
    let (control, udp, udp_bind) =
        open_normal_socks_udp_associate(fallback_client.local_addr).await?;
    let mut target_buf = [0u8; 128];
    let mut last_source = None;

    for (target, target_addr, request, response) in [
        (
            &target_a,
            target_a_addr,
            b"fallback-target-a".as_slice(),
            b"fallback-reply-a".as_slice(),
        ),
        (
            &target_b,
            target_b_addr,
            b"fallback-target-b".as_slice(),
            b"fallback-reply-b".as_slice(),
        ),
    ] {
        udp.send_to(&socks_udp_ipv4_request(target_addr, request), udp_bind)
            .await?;
        let (len, source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
            .await
            .context("H3 setup fallback serial target did not receive its packet")??;
        assert_eq!(&target_buf[..len], request);
        target.send_to(response, source).await?;
        receive_socks_udp_ipv4_payload(&udp, udp_bind, target_addr, response).await?;
        last_source = Some(source);
    }

    let after = transport::transport_debug_snapshot(&fallback_config);
    assert_eq!(after.active_transport, GuiTransportCarrier::H2);
    assert!(after.h3_candidate_enabled);
    assert!(after.h3_in_cooldown);
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let metrics = wait_for_metric(metrics_addr, "authenticated_sessions", 1).await?;
    assert_eq!(metric_value(&metrics, "authenticated_sessions")?, 1);
    let pool = fallback_client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);

    drop(control);
    let source = last_source.context("fallback serial target source was not observed")?;
    let rebound =
        rebind_released_udp_source(source, "H3 setup fallback serial control EOF").await?;
    assert_eq!(rebound.local_addr()?, source);
    drop(rebound);
    fallback_client.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_udp_association_keeps_one_connected_target_owner() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let before = transport::transport_debug_snapshot(&config);
    assert_eq!(before.active_transport, GuiTransportCarrier::H3);
    assert!(before.h3_candidate_enabled);
    assert!(!before.h3_in_cooldown);

    assert_udp_association_keeps_one_connected_target_owner(&config).await?;

    let after = transport::transport_debug_snapshot(&config);
    assert_eq!(after.active_transport, GuiTransportCarrier::H3);
    assert!(after.h3_candidate_enabled);
    assert!(!after.h3_in_cooldown);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_interrupted_udp_relay_fails_closed_before_next_target() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let mut config = fixture.client_config();
    config.advanced.udp_idle_timeout_ms = 5_000;
    assert_h3_transport(&config);

    let observation = observe_interrupted_udp_relay(&config).await?;

    assert_h3_transport(&config);
    assert_interrupted_udp_relay_failed_closed(observation);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
struct RawH3LimitedClient {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver_task: tokio::task::JoinHandle<()>,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

#[cfg(feature = "h3")]
async fn connect_raw_h3_limited_client(
    fixture: &MaverickHarness,
    config: &ClientConfig,
    stream_receive_window: u32,
) -> Result<RawH3LimitedClient> {
    let ca_path = config.server.ca_cert.as_ref().context("missing CA cert")?;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(ca_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    assert!(added > 0, "raw H3 client did not load the test CA");

    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.enable_early_data = false;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(10).try_into()?))
        .stream_receive_window(stream_receive_window.into())
        .keep_alive_interval(Some(Duration::from_millis(100)));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(fixture.server.local_addr, "localhost")?
        .await
        .context("complete raw QUIC handshake")?;
    let (mut driver, send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    Ok(RawH3LimitedClient {
        endpoint,
        connection,
        driver_task,
        send_request,
    })
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_blocked_udp_response_releases_exact_target_source_at_state_deadline() -> Result<()> {
    const RESPONSE_COUNT: usize = 6;
    const RESPONSE_BYTES: usize = 8 * 1024;
    const STREAM_RECEIVE_WINDOW: u32 = 44 * 1024;
    const SERVER_IDLE_TIMEOUT_SECS: u64 = 1;

    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        server_idle_timeout_secs: Some(SERVER_IDLE_TIMEOUT_SECS),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let mut raw = connect_raw_h3_limited_client(&fixture, &config, STREAM_RECEIVE_WINDOW).await?;

    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_task = tokio::spawn(async move {
        let mut exact_source = None;
        for sequence in 0..RESPONSE_COUNT {
            let mut request = [0u8; 64];
            let (len, source) = timeout(Duration::from_secs(2), target.recv_from(&mut request))
                .await
                .context("real UDP target did not receive every OpenUdp request")??;
            anyhow::ensure!(
                request.get(..len) == Some([sequence as u8].as_slice()),
                "real UDP target received the wrong request payload"
            );
            anyhow::ensure!(
                exact_source.is_none_or(|expected| expected == source),
                "OpenUdp target owner did not reuse one exact source"
            );
            exact_source = Some(source);
            let response = vec![0x5a; RESPONSE_BYTES];
            let sent = target.send_to(&response, source).await?;
            anyhow::ensure!(
                sent == response.len(),
                "real UDP target reply was truncated"
            );
        }
        Ok::<(SocketAddr, usize), anyhow::Error>((
            exact_source.context("real UDP target observed no request")?,
            RESPONSE_COUNT * RESPONSE_BYTES,
        ))
    });

    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let mut stream = raw
        .send_request
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/octet-stream")
                .body(())?,
        )
        .await?;
    let max_frame_size = 65_536;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        0,
    )?;
    stream
        .send_data(Frame::new(FrameType::ClientHello, 0, 0, hello.encode()).encode(max_frame_size)?)
        .await?;
    stream
        .send_data(
            Frame::new(
                FrameType::OpenUdp,
                0,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            )
            .encode(max_frame_size)?,
        )
        .await?;
    for sequence in 0..RESPONSE_COUNT {
        let packet = UdpPacketPayload::new(
            TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            target_addr.port(),
            Bytes::from(vec![sequence as u8]),
        );
        stream
            .send_data(
                Frame::new(FrameType::UdpPacket, 0, OPEN_UDP_FLOW_ID, packet.encode()?)
                    .encode(max_frame_size)?,
            )
            .await?;
    }

    let (exact_source, total_response_bytes) = timeout(Duration::from_secs(3), target_task)
        .await
        .context("real UDP target task did not complete")?
        .context("real UDP target task failed")??;
    assert_eq!(total_response_bytes, 48 * 1024);
    match UdpSocket::bind(exact_source).await {
        Ok(_) => panic!("active OpenUdp owner did not initially hold its exact UDP source"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse),
    }
    let release_deadline =
        Instant::now() + Duration::from_secs(SERVER_IDLE_TIMEOUT_SECS) + Duration::from_secs(2);
    let rebound = loop {
        match UdpSocket::bind(exact_source).await {
            Ok(socket) => break socket,
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && Instant::now() < release_deadline =>
            {
                tokio::task::yield_now().await;
            }
            Err(err) => {
                assert!(
                    raw.connection.close_reason().is_none(),
                    "raw QUIC connection closed instead of remaining alive under keepalive"
                );
                panic!(
                    "legacy-H3 response deadline did not release exact UDP source {exact_source}: {err}"
                );
            }
        }
    };
    assert_eq!(rebound.local_addr()?, exact_source);
    assert!(
        raw.connection.close_reason().is_none(),
        "raw QUIC connection closed instead of remaining alive under keepalive"
    );

    drop(rebound);
    drop(stream);
    raw.connection
        .close(0u32.into(), b"blocked-response-test-complete");
    raw.endpoint
        .close(0u32.into(), b"blocked-response-test-complete");
    raw.driver_task.abort();
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_blocked_push_releases_exact_target_source_at_send_deadline() -> Result<()> {
    const RESPONSE_COUNT: usize = 6;
    const RESPONSE_BYTES: usize = 8 * 1024;
    const STREAM_RECEIVE_WINDOW: u32 = 44 * 1024;
    const SERVER_IDLE_TIMEOUT_SECS: u64 = 1;

    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        experimental_h3: true,
        server_idle_timeout_secs: Some(SERVER_IDLE_TIMEOUT_SECS),
        ..HarnessOptions::default()
    })
    .await?;
    let config = fixture.client_config();
    let mut raw = connect_raw_h3_limited_client(&fixture, &config, STREAM_RECEIVE_WINDOW).await?;

    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_task = tokio::spawn(async move {
        let mut request = [0u8; 64];
        let (len, exact_source) = timeout(Duration::from_secs(2), target.recv_from(&mut request))
            .await
            .context("real UDP target did not receive the duplex setup packet")??;
        anyhow::ensure!(
            request.get(..len) == Some(b"duplex-blocked-response".as_slice()),
            "real UDP target received the wrong duplex setup payload"
        );
        for sequence in 0..RESPONSE_COUNT {
            let mut response = vec![0x5a; RESPONSE_BYTES];
            response[0] = sequence as u8;
            let sent = target.send_to(&response, exact_source).await?;
            anyhow::ensure!(sent == response.len(), "real UDP target push was truncated");
        }
        Ok::<(SocketAddr, usize), anyhow::Error>((exact_source, RESPONSE_COUNT * RESPONSE_BYTES))
    });

    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let mut stream = raw
        .send_request
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/octet-stream")
                .body(())?,
        )
        .await?;
    let max_frame_size = 65_536;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        FEATURE_OPEN_UDP_MODE_NEGOTIATION,
    )?;
    stream
        .send_data(Frame::new(FrameType::ClientHello, 0, 0, hello.encode()).encode(max_frame_size)?)
        .await?;
    stream
        .send_data(
            Frame::new(
                FrameType::OpenUdp,
                OPEN_UDP_FLAG_DUPLEX,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            )
            .encode(max_frame_size)?,
        )
        .await?;
    let packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"duplex-blocked-response"),
    );
    stream
        .send_data(
            Frame::new(FrameType::UdpPacket, 0, OPEN_UDP_FLOW_ID, packet.encode()?)
                .encode(max_frame_size)?,
        )
        .await?;

    let (exact_source, total_response_bytes) = timeout(Duration::from_secs(3), target_task)
        .await
        .context("duplex target-push task did not complete")?
        .context("duplex target-push task failed")??;
    assert_eq!(total_response_bytes, 48 * 1024);
    match UdpSocket::bind(exact_source).await {
        Ok(_) => panic!("active duplex target owner did not retain its exact UDP source"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse),
    }

    let release_deadline =
        Instant::now() + Duration::from_secs(SERVER_IDLE_TIMEOUT_SECS) + Duration::from_secs(2);
    let rebound = loop {
        match UdpSocket::bind(exact_source).await {
            Ok(socket) => break socket,
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && Instant::now() < release_deadline =>
            {
                tokio::task::yield_now().await;
            }
            Err(err) => {
                assert!(
                    raw.connection.close_reason().is_none(),
                    "raw QUIC connection closed instead of keeping the physical owner alive"
                );
                panic!(
                    "duplex H3 response deadline did not release exact UDP source {exact_source}: {err}"
                );
            }
        }
    };
    assert_eq!(rebound.local_addr()?, exact_source);
    assert!(
        raw.connection.close_reason().is_none(),
        "raw QUIC connection closed instead of keeping the physical owner alive"
    );

    drop(rebound);
    drop(stream);
    raw.connection
        .close(0u32.into(), b"duplex-blocked-response-test-complete");
    raw.endpoint
        .close(0u32.into(), b"duplex-blocked-response-test-complete");
    raw.driver_task.abort();
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn dns_relay_roundtrip() -> Result<()> {
    let upstream = start_fake_dns_server().await?;
    let fixture = MaverickHarness::start_with_dns(Some(upstream)).await?;
    let dns_addr = fixture.client.dns_addr.context("missing DNS listener")?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(b"example-query", dns_addr).await?;
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).await?;
    assert_eq!(&buf[..len], b"dns-response:example-query");

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_user_flow_limit_rejects_dns_query_when_tcp_flow_is_active() -> Result<()> {
    let upstream = start_fake_dns_server().await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        dns_upstream: Some(upstream),
        user_max_concurrent_flows: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let hold_addr = start_hold_open_server().await?;
    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;
    let dns_addr = fixture.client.dns_addr.context("missing DNS listener")?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(b"blocked-dns-query", dns_addr).await?;
    let mut buf = [0u8; 512];
    let result = timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await;
    assert!(
        result.is_err(),
        "DNS query unexpectedly succeeded while user flow limit was exhausted"
    );

    first.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn metrics_endpoint_reports_loopback_counts() -> Result<()> {
    let fixture = MaverickHarness::start_with_features(None, true, false).await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    assert!(metrics_addr.ip().is_loopback());

    let response = fetch_metrics(metrics_addr).await?;
    assert!(response.contains("\"authenticated_sessions\":0"));
    assert!(response.contains("\"fallback_requests\":0"));
    assert_eq!(metric_value(&response, "target_resolution_timeouts")?, 0);
    assert_eq!(metric_value(&response, "target_resolution_failures")?, 0);
    assert_eq!(metric_value(&response, "target_connect_timeouts")?, 0);
    assert_eq!(metric_value(&response, "target_connect_failures")?, 0);
    assert_eq!(
        metric_value(&response, "target_resolution_duration_ms_count")?,
        0
    );
    assert_eq!(
        metric_value(&response, "target_resolution_duration_ms_le_inf")?,
        0
    );
    assert_eq!(
        metric_value(&response, "target_connect_duration_ms_count")?,
        0
    );
    assert_eq!(
        metric_value(&response, "target_connect_duration_ms_le_inf")?,
        0
    );
    assert_eq!(metric_value(&response, "h2_stream_resets")?, 0);
    assert_eq!(metric_value(&response, "h2_send_stalls")?, 0);
    assert_eq!(metric_value(&response, "active_flows")?, 0);
    assert_eq!(metric_value(&response, "active_connections")?, 0);
    assert_eq!(metric_value(&response, "connection_limit_rejections")?, 0);
    assert_eq!(
        metric_value(&response, "source_connection_limit_rejections")?,
        0
    );
    assert_eq!(metric_value(&response, "active_pre_auth")?, 0);
    assert_eq!(metric_value(&response, "active_fallbacks")?, 0);
    assert_eq!(metric_value(&response, "fallback_overload_rejections")?, 0);
    assert_eq!(metric_value(&response, "shaping_padding_frames")?, 0);
    assert_eq!(metric_value(&response, "shaping_padding_bytes")?, 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn metrics_endpoint_reports_active_flow_pressure() -> Result<()> {
    let fixture = MaverickHarness::start_with_features(None, true, false).await?;
    let hold_addr = start_hold_open_server().await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;

    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;
    let response = wait_for_metric(metrics_addr, "active_flows", 1).await?;

    assert_eq!(metric_value(&response, "active_flows")?, 1);
    assert_eq!(metric_value(&response, "tcp_flows")?, 1);
    assert_eq!(
        metric_value(&response, "target_resolution_duration_ms_count")?,
        1
    );
    assert_eq!(
        metric_value(&response, "target_resolution_duration_ms_le_inf")?,
        1
    );
    assert_eq!(
        metric_value(&response, "target_connect_duration_ms_count")?,
        1
    );
    assert_eq!(
        metric_value(&response, "target_connect_duration_ms_le_inf")?,
        1
    );

    first.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn http_connect_relay_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start_with_features(None, false, true).await?;
    let echo_addr = start_echo_server().await?;
    let http_addr = fixture
        .client
        .http_connect_addr
        .context("missing HTTP CONNECT listener")?;
    let mut stream = TcpStream::connect(http_addr).await?;
    stream
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nhttp-connect",
                echo_addr.port(),
                echo_addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
    }
    assert!(String::from_utf8(response)?.starts_with("HTTP/1.1 200"));

    let mut echoed = [0u8; 12];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"http-connect");

    fixture.shutdown().await?;
    Ok(())
}

async fn run_single_socks_roundtrip(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let mut socks = socks_connect(socks_addr, echo_addr).await?;
    socks.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == payload, "echo payload mismatch");
    socks.shutdown().await?;
    Ok(())
}

async fn start_stallable_first_connection_proxy(
    upstream_addr: SocketAddr,
) -> Result<(SocketAddr, watch::Sender<bool>, Arc<Notify>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let (stall_tx, stall_rx) = watch::channel(false);
    let first_stalled = Arc::new(Notify::new());
    let proxy_first_stalled = Arc::clone(&first_stalled);
    tokio::spawn(async move {
        let mut first_connection = true;
        while let Ok((mut client, _)) = listener.accept().await {
            let Ok(mut upstream) = TcpStream::connect(upstream_addr).await else {
                continue;
            };
            if first_connection {
                first_connection = false;
                let mut stall_rx = stall_rx.clone();
                let first_stalled = Arc::clone(&proxy_first_stalled);
                tokio::spawn(async move {
                    let stalled = {
                        let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
                        tokio::pin!(copy);
                        tokio::select! {
                            _ = &mut copy => false,
                            changed = async {
                                while !*stall_rx.borrow() {
                                    stall_rx.changed().await?;
                                }
                                Result::<()>::Ok(())
                            } => changed.is_ok(),
                        }
                    };
                    if stalled {
                        first_stalled.notify_one();
                        let _client = client;
                        let _upstream = upstream;
                        std::future::pending::<()>().await;
                    }
                });
            } else {
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        }
    });
    Ok((proxy_addr, stall_tx, first_stalled))
}

#[tokio::test]
async fn concurrent_tcp_relay_roundtrips() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let echo_addr = start_echo_server().await?;
    run_concurrent_socks_roundtrips(fixture.client.local_addr, echo_addr, "h2").await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.streams_opened == 16 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.connections_created, 1);
    assert_eq!(snapshot.streams_opened, 16);
    assert_eq!(snapshot.streams_reused, 15);
    assert_eq!(snapshot.reconnects, 0);
    assert_eq!(snapshot.active_streams, 0);
    assert!(snapshot.cached_connection);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_is_shared_across_local_frontends() -> Result<()> {
    let upstream = start_fake_dns_server().await?;
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        dns_upstream: Some(upstream),
        http_connect: true,
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;

    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"pool-socks").await?;

    let dns_addr = fixture.client.dns_addr.context("missing DNS listener")?;
    let dns_socket = UdpSocket::bind("127.0.0.1:0").await?;
    dns_socket.send_to(b"pool-dns", dns_addr).await?;
    let mut dns_response = [0u8; 64];
    let (dns_len, _) = dns_socket.recv_from(&mut dns_response).await?;
    assert_eq!(&dns_response[..dns_len], b"dns-response:pool-dns");

    let http_addr = fixture
        .client
        .http_connect_addr
        .context("missing HTTP CONNECT listener")?;
    let mut http = TcpStream::connect(http_addr).await?;
    http.write_all(
        format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\npool-http",
            echo_addr.port(),
            echo_addr.port()
        )
        .as_bytes(),
    )
    .await?;
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        http.read_exact(&mut byte).await?;
        headers.push(byte[0]);
    }
    assert!(String::from_utf8(headers)?.starts_with("HTTP/1.1 200"));
    let mut echoed = [0u8; 9];
    http.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"pool-http");
    http.shutdown().await?;

    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.streams_opened == 3 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.connections_created, 1);
    assert_eq!(snapshot.streams_reused, 2);
    assert_eq!(snapshot.reconnects, 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_reconnects_after_server_closes_idle_connection() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        client_idle_timeout_secs: Some(30),
        server_idle_timeout_secs: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;
    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;

    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"before-close").await?;
    wait_for_pool_snapshot(&fixture.client, |snapshot| snapshot.active_streams == 0).await?;
    wait_for_metric_value(metrics_addr, "active_connections", 0).await?;

    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"after-close").await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.connections_created == 2 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.reconnects, 1);
    assert!(snapshot.closed_retirements + snapshot.readiness_failures >= 1);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_retires_idle_client_connection() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_idle_timeout_secs: Some(1),
        server_idle_timeout_secs: Some(30),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;

    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"before-retire").await?;
    let retired = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.idle_retirements == 1 && !snapshot.cached_connection
    })
    .await?;
    assert_eq!(retired.connections_created, 1);

    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"after-retire").await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.connections_created == 2 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.reconnects, 1);
    assert_eq!(snapshot.idle_retirements, 1);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_capacity_timeout_keeps_healthy_connection() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        client_max_concurrent_flows: Some(2),
        client_connect_timeout_ms: Some(250),
        server_h2_max_concurrent_streams: Some(1),
        ..HarnessOptions::default()
    })
    .await?;
    let hold_addr = start_hold_open_server().await?;
    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;

    let second = TcpStream::connect(fixture.client.local_addr).await?;
    expect_second_socks_flow_rejected(second, hold_addr).await?;
    let timed_out = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(timed_out.connections_created, 1);
    assert_eq!(timed_out.streams_opened, 2);
    assert_eq!(timed_out.streams_reused, 1);
    assert_eq!(timed_out.readiness_failures, 0);
    assert_eq!(timed_out.stream_open_failures, 0);
    assert_eq!(timed_out.handshake_timeouts, 1);
    assert_eq!(timed_out.timeout_retirements, 0);
    assert_eq!(timed_out.timeout_recoveries, 0);
    assert_eq!(timed_out.active_streams, 1);

    first.shutdown().await?;
    drop(first);
    wait_for_pool_snapshot(&fixture.client, |snapshot| snapshot.active_streams == 0).await?;

    let echo_addr = start_echo_server().await?;
    run_single_socks_roundtrip(fixture.client.local_addr, echo_addr, b"after-capacity").await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.streams_opened == 3 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.connections_created, 1);
    assert_eq!(snapshot.streams_reused, 2);
    assert_eq!(snapshot.reconnects, 0);
    assert_eq!(snapshot.readiness_failures, 0);
    assert_eq!(snapshot.stream_open_failures, 0);
    assert_eq!(snapshot.handshake_timeouts, 1);
    assert_eq!(snapshot.timeout_retirements, 0);
    assert_eq!(snapshot.timeout_recoveries, 0);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_recovers_once_after_unshared_tunnel_handshake_timeout() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let (proxy_addr, stall_tx, first_stalled) =
        start_stallable_first_connection_proxy(fixture.server.local_addr).await?;
    let mut client_config = fixture.client_config();
    client_config.local.socks5.listen = "127.0.0.1:0".parse()?;
    client_config.server.address = proxy_addr.to_string();
    client_config.advanced.connect_timeout_ms = 250;
    let client = maverick_client::start_client(client_config).await?;
    let echo_addr = start_echo_server().await?;

    run_single_socks_roundtrip(client.local_addr, echo_addr, b"before-stall").await?;
    wait_for_pool_snapshot(&client, |snapshot| {
        snapshot.connections_created == 1
            && snapshot.active_streams == 0
            && snapshot.cached_connection
    })
    .await?;

    stall_tx.send(true)?;
    timeout(Duration::from_secs(1), first_stalled.notified())
        .await
        .context("first proxy connection did not enter its deterministic stall")?;

    run_single_socks_roundtrip(client.local_addr, echo_addr, b"after-stall").await?;
    let recovered = wait_for_pool_snapshot(&client, |snapshot| {
        snapshot.connections_created == 2
            && snapshot.timeout_retirements == 1
            && snapshot.timeout_recoveries == 1
            && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(recovered.reconnects, 1);
    assert_eq!(recovered.handshake_timeouts, 1);
    assert_eq!(recovered.readiness_failures, 0);
    assert_eq!(recovered.stream_open_failures, 0);

    client.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_pool_does_not_retry_authentication_failure() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut bad_config = fixture.client_config();
    bad_config.local.socks5.listen = "127.0.0.1:0".parse()?;
    bad_config.server.secret = SecretString::generate();
    let bad_client = maverick_client::start_client(bad_config).await?;
    let echo_addr = start_echo_server().await?;

    let stream = TcpStream::connect(bad_client.local_addr).await?;
    expect_second_socks_flow_rejected(stream, echo_addr).await?;
    let snapshot = wait_for_pool_snapshot(&bad_client, |snapshot| {
        snapshot.streams_opened == 1 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.connections_created, 1);
    assert_eq!(snapshot.reconnects, 0);
    assert_eq!(snapshot.readiness_failures, 0);
    assert_eq!(snapshot.stream_open_failures, 0);
    assert_eq!(snapshot.handshake_timeouts, 0);

    bad_client.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "browser-tls")]
#[tokio::test]
async fn browser_tls_h2_pool_uses_channel_binding() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        auth_channel_binding_require: true,
        client_tls_fingerprint: Some(TlsFingerprintMode::BrowserMimic),
        ..HarnessOptions::default()
    })
    .await?;
    let echo_addr = start_echo_server().await?;

    run_single_socks_roundtrip(
        fixture.client.local_addr,
        echo_addr,
        b"browser-channel-binding",
    )
    .await?;
    let snapshot = wait_for_pool_snapshot(&fixture.client, |snapshot| {
        snapshot.streams_opened == 1 && snapshot.active_streams == 0
    })
    .await?;
    assert_eq!(snapshot.connections_created, 1);
    assert_eq!(snapshot.reconnects, 0);

    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_concurrent_tcp_relay_roundtrips() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let echo_addr = start_echo_server().await?;
    run_concurrent_socks_roundtrips(fixture.client.local_addr, echo_addr, "h3").await?;
    let snapshot = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(snapshot.connections_created, 0);
    assert_eq!(snapshot.streams_opened, 0);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn socks5_udp_associate_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let udp_echo_addr = start_udp_echo_server().await?;
    let mut control = TcpStream::connect(fixture.client.local_addr).await?;

    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    assert_eq!(associate_reply[1], 0x00);
    let udp_port = u16::from_be_bytes([associate_reply[8], associate_reply[9]]);
    let udp_bind = SocketAddr::from(([127, 0, 0, 1], udp_port));

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    datagram.extend_from_slice(&udp_echo_addr.port().to_be_bytes());
    datagram.extend_from_slice(b"udp-echo");
    udp.send_to(&datagram, udp_bind).await?;

    let mut response = [0u8; 1024];
    let (len, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut response)).await??;
    assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&response[len - 8..len], b"udp-echo");

    fixture.shutdown().await?;
    Ok(())
}

async fn read_socks_udp_associate_bind(control: &mut TcpStream) -> Result<SocketAddr> {
    let mut header = [0u8; 4];
    control.read_exact(&mut header).await?;
    anyhow::ensure!(
        header[..3] == [0x05, 0x00, 0x00],
        "SOCKS UDP association failed"
    );
    match header[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            control.read_exact(&mut tail).await?;
            Ok(SocketAddr::from((
                [tail[0], tail[1], tail[2], tail[3]],
                u16::from_be_bytes([tail[4], tail[5]]),
            )))
        }
        0x04 => {
            let mut tail = [0u8; 18];
            control.read_exact(&mut tail).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&tail[..16]);
            Ok(SocketAddr::from((
                std::net::Ipv6Addr::from(octets),
                u16::from_be_bytes([tail[16], tail[17]]),
            )))
        }
        _ => anyhow::bail!("SOCKS UDP association returned an unsupported bind address"),
    }
}

#[tokio::test]
async fn socks5_udp_associate_ipv6_loopback_control_roundtrip() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut config = fixture.client_config();
    config.local.socks5.listen = "[::1]:0".parse()?;
    let ipv6_client = maverick_client::start_client(config).await?;
    anyhow::ensure!(
        ipv6_client.local_addr.ip() == std::net::Ipv6Addr::LOCALHOST,
        "normal client did not bind the configured IPv6 loopback"
    );

    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut control = TcpStream::connect(ipv6_client.local_addr).await?;
    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "SOCKS UDP method failed");
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let udp_bind = read_socks_udp_associate_bind(&mut control).await?;
    anyhow::ensure!(udp_bind.port() != 0, "SOCKS UDP bind port stayed zero");

    let ipv6_relay_available = match udp_bind {
        SocketAddr::V4(bind) => {
            anyhow::ensure!(
                bind.ip().is_loopback(),
                "SOCKS UDP relay escaped IPv4 loopback"
            );
            false
        }
        SocketAddr::V6(bind) => {
            anyhow::ensure!(
                *bind.ip() == std::net::Ipv6Addr::LOCALHOST,
                "SOCKS UDP relay escaped IPv6 loopback"
            );
            true
        }
    };
    let request = socks_udp_ipv4_request(target_addr, b"ipv6-control-ipv4-target");
    let mut exact_target_source = None;

    if ipv6_relay_available {
        let udp = UdpSocket::bind("[::1]:0").await?;
        udp.send_to(&request, udp_bind).await?;
        let mut target_buf = [0u8; 128];
        let (len, source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
            .await
            .context("IPv6 SOCKS UDP relay did not reach the IPv4 target")??;
        anyhow::ensure!(
            &target_buf[..len] == b"ipv6-control-ipv4-target",
            "IPv6 SOCKS UDP relay changed the target payload"
        );
        exact_target_source = Some(source);
        target.send_to(b"ipv6-control-ipv4-reply", source).await?;
        receive_socks_udp_ipv4_payload(&udp, udp_bind, target_addr, b"ipv6-control-ipv4-reply")
            .await?;
        let pool = wait_for_pool_snapshot(&ipv6_client, |snapshot| {
            snapshot.connections_created == 1
                && snapshot.streams_opened == 1
                && snapshot.active_streams == 1
        })
        .await?;
        assert_eq!(pool.connections_created, 1);
        assert_eq!(pool.streams_opened, 1);
        assert_eq!(pool.active_streams, 1);
    } else {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(&request, udp_bind).await?;
        let mut target_buf = [0u8; 128];
        match timeout(
            Duration::from_millis(250),
            target.recv_from(&mut target_buf),
        )
        .await
        {
            Err(_) => {}
            Ok(Ok((len, _))) => {
                anyhow::bail!("IPv4 relay reached the target with {len} unexpected bytes")
            }
            Ok(Err(err)) => return Err(err).context("observe IPv4-target relay rejection"),
        }
        let pool = ipv6_client.h2_connection_pool_snapshot();
        assert_eq!(pool.connections_created, 0);
        assert_eq!(pool.streams_opened, 0);
        assert_eq!(pool.active_streams, 0);
    }

    control.shutdown().await?;
    drop(control);
    if let Some(source) = exact_target_source {
        let deadline = Instant::now() + Duration::from_secs(2);
        let rebound = loop {
            match UdpSocket::bind(source).await {
                Ok(socket) => break socket,
                Err(err)
                    if err.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
                {
                    tokio::task::yield_now().await;
                }
                Err(err) => {
                    return Err(err).context("IPv6 SOCKS control EOF did not release target source")
                }
            }
        };
        assert_eq!(rebound.local_addr()?, source);
        drop(rebound);
    }
    ipv6_client.shutdown().await?;
    fixture.shutdown().await?;

    if !ipv6_relay_available {
        panic!("normal SOCKS IPv6 UDP relay stayed unavailable");
    }
    Ok(())
}

async fn open_normal_socks_udp_associate(
    socks_addr: SocketAddr,
) -> Result<(TcpStream, UdpSocket, SocketAddr)> {
    let mut control = TcpStream::connect(socks_addr).await?;
    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "SOCKS UDP method failed");

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    anyhow::ensure!(associate_reply[1] == 0x00, "SOCKS UDP association failed");
    let udp_port = u16::from_be_bytes([associate_reply[8], associate_reply[9]]);
    let udp_bind = SocketAddr::from(([127, 0, 0, 1], udp_port));
    Ok((control, UdpSocket::bind("127.0.0.1:0").await?, udp_bind))
}

fn socks_udp_ipv4_request(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut request = vec![0x00, 0x00, 0x00, 0x01];
    let SocketAddr::V4(target) = target else {
        panic!("SOCKS UDP loopback test target must be IPv4");
    };
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(payload);
    request
}

#[cfg(feature = "h3")]
#[derive(Clone, Copy)]
enum StalledH3SetupExit {
    ConnectDeadline,
    ControlEof,
}

#[cfg(feature = "h3")]
#[derive(Clone, Copy)]
enum StalledH3SetupStage {
    PartialServerHello,
    SerialOpenUdpAck,
}

#[cfg(feature = "h3")]
async fn observe_normal_socks_stalled_h3_setup(
    stage: StalledH3SetupStage,
    exit: StalledH3SetupExit,
) -> Result<bool> {
    const DEADLINE_MS: u64 = 250;
    const DEADLINE_LOWER_BOUND: Duration = Duration::from_millis(200);
    const DEADLINE_UPPER_BOUND: Duration = Duration::from_millis(DEADLINE_MS + 750);
    const CONTROL_EOF_BOUND: Duration = Duration::from_millis(500);

    let fixture = MaverickHarness::start().await?;
    let tmp = TempDir::new()?;
    let cert_path = tmp.path().join("scripted-ca.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    tokio::fs::write(&cert_path, certified.cert.pem()).await?;
    let cert: CertificateDer<'static> = certified.cert.into();
    let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());

    let fallback_sentinel = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = fallback_sentinel.local_addr()?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let mut server_transport = quinn::TransportConfig::default();
    server_transport
        .max_idle_timeout(Some(Duration::from_secs(10).try_into()?))
        .initial_rtt(Duration::from_millis(10));
    server_config.transport_config(Arc::new(server_transport));
    let endpoint = quinn::Endpoint::server(server_config, server_addr)?;

    let mut config = fixture.client_config();
    config.local.socks5.listen = "127.0.0.1:0".parse()?;
    config.server.address = server_addr.to_string();
    config.server.ca_cert = Some(cert_path);
    config.advanced.experimental_h3 = true;
    config.advanced.connect_timeout_ms = match exit {
        StalledH3SetupExit::ConnectDeadline => DEADLINE_MS,
        StalledH3SetupExit::ControlEof => 5_000,
    };
    assert_h3_transport(&config);

    let secret = config.server.secret.clone();
    let credential_id = config.server.credential_id.clone();
    let tunnel_path = config.server.tunnel_path.clone();
    let expected_udp_idle_timeout_ms = config.advanced.udp_idle_timeout_ms;
    let server_endpoint = endpoint.clone();
    let (stall_reached_tx, stall_reached_rx) = oneshot::channel();
    let (connection_aborted_tx, connection_aborted_rx) = oneshot::channel();
    let mut connection_aborted_rx = Some(connection_aborted_rx);
    let request_count = Arc::new(AtomicUsize::new(0));
    let server_request_count = Arc::clone(&request_count);
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .context("scripted H3 peer did not accept the normal client")?;
        let connection = incoming
            .await
            .context("scripted H3 peer did not complete QUIC")?;
        let mut h3 =
            h3::server::Connection::new(h3_quinn::Connection::new(connection.clone())).await?;
        let resolver = h3
            .accept()
            .await?
            .context("normal SOCKS client did not send an H3 request")?;
        server_request_count.fetch_add(1, Ordering::SeqCst);
        let (request, mut stream) = resolver.resolve_request().await?;
        anyhow::ensure!(request.method() == Method::POST, "unexpected H3 method");
        anyhow::ensure!(
            request.uri().path() == tunnel_path,
            "unexpected H3 tunnel path"
        );

        let mut request_bytes = BytesMut::new();
        let client_hello = 'read_hello: loop {
            while let Some(frame) = Frame::decode_from(&mut request_bytes, 65_536)? {
                if frame.frame_type == FrameType::Padding {
                    continue;
                }
                anyhow::ensure!(
                    frame.frame_type == FrameType::ClientHello,
                    "scripted H3 peer did not receive ClientHello first"
                );
                break 'read_hello ClientHello::decode(&frame.payload)?;
            }
            let mut chunk = stream
                .recv_data()
                .await?
                .context("normal H3 request ended before ClientHello")?;
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            request_bytes.extend_from_slice(&bytes);
        };
        anyhow::ensure!(
            client_hello.credential_id == credential_id,
            "normal client used the wrong credential"
        );
        anyhow::ensure!(
            client_hello.verify(&secret, &tunnel_path),
            "normal client sent an invalid ClientHello"
        );

        anyhow::ensure!(
            client_hello.feature_flags & FEATURE_OPEN_UDP_MODE_NEGOTIATION != 0,
            "normal H3 client did not request UDP mode negotiation"
        );
        let selected_features = match stage {
            StalledH3SetupStage::PartialServerHello => {
                client_hello.feature_flags & FEATURE_OPEN_UDP_MODE_NEGOTIATION
            }
            StalledH3SetupStage::SerialOpenUdpAck => 0,
        };
        let server_hello = ServerHello::new(
            &secret,
            &client_hello.client_nonce,
            65_536,
            128,
            selected_features,
        )?;
        anyhow::ensure!(
            server_hello.verify(&secret, &client_hello.client_nonce),
            "scripted peer constructed an invalid ServerHello"
        );
        let encoded =
            Frame::new(FrameType::ServerHello, 0, 0, server_hello.encode()).encode(65_536)?;
        anyhow::ensure!(encoded.len() > 1, "ServerHello frame had no proper prefix");
        stream
            .send_response(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/octet-stream")
                    .body(())?,
            )
            .await?;
        match stage {
            StalledH3SetupStage::PartialServerHello => {
                stream.send_data(encoded.slice(..encoded.len() - 1)).await?;
            }
            StalledH3SetupStage::SerialOpenUdpAck => {
                stream.send_data(encoded).await?;
                let open_udp = 'read_open_udp: loop {
                    while let Some(frame) = Frame::decode_from(&mut request_bytes, 65_536)? {
                        if frame.frame_type == FrameType::Padding {
                            continue;
                        }
                        break 'read_open_udp frame;
                    }
                    let mut chunk = stream
                        .recv_data()
                        .await?
                        .context("normal H3 request ended before flags-zero OpenUdp")?;
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    request_bytes.extend_from_slice(&bytes);
                };
                anyhow::ensure!(
                    open_udp.frame_type == FrameType::OpenUdp,
                    "normal H3 client did not send OpenUdp after selected mask zero"
                );
                anyhow::ensure!(
                    open_udp.flags == 0,
                    "normal H3 client did not send exact flags-zero OpenUdp"
                );
                anyhow::ensure!(open_udp.flow_id != 0, "OpenUdp used the reserved flow id");
                let payload = OpenUdpPayload::decode(&open_udp.payload)?;
                anyhow::ensure!(
                    payload.idle_timeout_ms == expected_udp_idle_timeout_ms,
                    "flags-zero OpenUdp changed its configured idle value"
                );
            }
        }
        let _ = stall_reached_tx.send(());

        loop {
            tokio::select! {
                request = h3.accept() => {
                    match request {
                        Ok(Some(_)) => {
                            server_request_count.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
                data = stream.recv_data() => {
                    match data {
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
        let _ = connection.closed().await;
        let _ = connection_aborted_tx.send(());
        Result::<()>::Ok(())
    });

    let client = maverick_client::start_client(config.clone()).await?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let (mut control, udp, udp_bind) = open_normal_socks_udp_associate(client.local_addr).await?;
    let started = Instant::now();
    udp.send_to(
        &socks_udp_ipv4_request(target_addr, b"must-not-leave-client"),
        udp_bind,
    )
    .await?;
    timeout(Duration::from_secs(2), stall_reached_rx)
        .await
        .context("scripted H3 peer did not reach the stalled setup stage")??;

    let stopped = match exit {
        StalledH3SetupExit::ConnectDeadline => {
            let mut control_byte = [0_u8; 1];
            let control_ended = matches!(
                timeout(Duration::from_secs(1), control.read(&mut control_byte)).await,
                Ok(Ok(0))
            );
            let deadline_elapsed = started.elapsed();
            let abort_result = timeout(
                Duration::from_millis(250),
                connection_aborted_rx
                    .as_mut()
                    .expect("connection abort receiver must be pending"),
            )
            .await;
            let abort_receiver_consumed = abort_result.is_ok();
            let peer_aborted = matches!(abort_result, Ok(Ok(())));
            if abort_receiver_consumed {
                connection_aborted_rx = None;
            }
            control_ended
                && peer_aborted
                && deadline_elapsed >= DEADLINE_LOWER_BOUND
                && deadline_elapsed <= DEADLINE_UPPER_BOUND
        }
        StalledH3SetupExit::ControlEof => {
            control.shutdown().await?;
            let mut control_byte = [0_u8; 1];
            let abort_receiver = connection_aborted_rx
                .as_mut()
                .expect("connection abort receiver must be pending");
            let (control_result, abort_result) = tokio::join!(
                timeout(CONTROL_EOF_BOUND, control.read(&mut control_byte)),
                timeout(CONTROL_EOF_BOUND, abort_receiver),
            );
            let abort_receiver_consumed = abort_result.is_ok();
            let peer_aborted = matches!(abort_result, Ok(Ok(())));
            if abort_receiver_consumed {
                connection_aborted_rx = None;
            }
            matches!(control_result, Ok(Ok(0))) && peer_aborted
        }
    };

    let mut target_buf = [0_u8; 1];
    assert!(
        timeout(
            Duration::from_millis(150),
            target.recv_from(&mut target_buf)
        )
        .await
        .is_err(),
        "stalled H3 setup contacted the real UDP target"
    );
    assert!(
        timeout(Duration::from_millis(150), fallback_sentinel.accept())
            .await
            .is_err(),
        "stalled H3 setup attempted TCP/H2 fallback"
    );
    assert_eq!(
        request_count.load(Ordering::SeqCst),
        1,
        "stalled H3 setup replayed a second request on one connection"
    );
    assert!(
        timeout(Duration::from_millis(150), endpoint.accept())
            .await
            .is_err(),
        "stalled H3 setup opened a second H3 connection"
    );
    let pool = client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 0);
    assert_eq!(pool.streams_opened, 0);
    assert_eq!(pool.active_streams, 0);
    assert_h3_transport(&config);

    drop(control);
    timeout(Duration::from_secs(2), client.shutdown())
        .await
        .context("normal client cleanup stayed pending")??;
    if let Some(mut connection_aborted_rx) = connection_aborted_rx.take() {
        timeout(Duration::from_secs(1), &mut connection_aborted_rx)
            .await
            .context("normal client shutdown did not abort the H3 connection")??;
    }
    endpoint.close(0u32.into(), b"scripted-peer-complete");
    timeout(Duration::from_secs(2), server_task)
        .await
        .context("scripted H3 peer task stayed pending")???;
    fixture.shutdown().await?;
    Ok(stopped)
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn normal_socks_h3_partial_server_hello_obeys_deadline_and_control_eof() -> Result<()> {
    let deadline_stopped = observe_normal_socks_stalled_h3_setup(
        StalledH3SetupStage::PartialServerHello,
        StalledH3SetupExit::ConnectDeadline,
    )
    .await?;
    let control_eof_stopped = observe_normal_socks_stalled_h3_setup(
        StalledH3SetupStage::PartialServerHello,
        StalledH3SetupExit::ControlEof,
    )
    .await?;

    if !(deadline_stopped && control_eof_stopped) {
        panic!("normal SOCKS stalled H3 setup stayed alive");
    }
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn normal_socks_h3_flags_zero_open_udp_ack_obeys_deadline() -> Result<()> {
    let deadline_stopped = observe_normal_socks_stalled_h3_setup(
        StalledH3SetupStage::SerialOpenUdpAck,
        StalledH3SetupExit::ConnectDeadline,
    )
    .await?;

    if !deadline_stopped {
        panic!("normal SOCKS flags-zero H3 OpenUdp setup stayed alive");
    }
    Ok(())
}

async fn receive_socks_udp_ipv4_payload(
    socket: &UdpSocket,
    udp_bind: SocketAddr,
    target: SocketAddr,
    expected: &[u8],
) -> Result<()> {
    let mut response = [0u8; 256];
    let (len, source) = timeout(Duration::from_secs(2), socket.recv_from(&mut response))
        .await
        .context("SOCKS UDP response stayed unavailable")??;
    anyhow::ensure!(source == udp_bind, "SOCKS UDP response source changed");
    anyhow::ensure!(len >= 10, "SOCKS UDP response was truncated");
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("SOCKS UDP loopback test target must be IPv4");
    };
    anyhow::ensure!(
        response[..8]
            == [
                0x00,
                0x00,
                0x00,
                0x01,
                target.ip().octets()[0],
                target.ip().octets()[1],
                target.ip().octets()[2],
                target.ip().octets()[3],
            ],
        "SOCKS UDP response target changed"
    );
    anyhow::ensure!(
        u16::from_be_bytes([response[8], response[9]]) == target.port(),
        "SOCKS UDP response target port changed"
    );
    anyhow::ensure!(
        &response[10..len] == expected,
        "SOCKS UDP response payload changed"
    );
    Ok(())
}

async fn assert_normal_h2_socks_udp_serial_switches_targets() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let target_a = UdpSocket::bind("127.0.0.1:0").await?;
    let target_a_addr = target_a.local_addr()?;
    let target_b = UdpSocket::bind("127.0.0.1:0").await?;
    let target_b_addr = target_b.local_addr()?;
    let (control, udp, udp_bind) =
        open_normal_socks_udp_associate(fixture.client.local_addr).await?;
    let mut target_buf = [0u8; 128];
    let mut last_source = None;

    for (target, target_addr, request, response) in [
        (
            &target_a,
            target_a_addr,
            b"serial-target-a".as_slice(),
            b"serial-reply-a".as_slice(),
        ),
        (
            &target_b,
            target_b_addr,
            b"serial-target-b".as_slice(),
            b"serial-reply-b".as_slice(),
        ),
    ] {
        udp.send_to(&socks_udp_ipv4_request(target_addr, request), udp_bind)
            .await?;
        let (len, source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
            .await
            .context("serial SOCKS UDP target did not receive its packet")??;
        assert_eq!(&target_buf[..len], request);
        target.send_to(response, source).await?;
        receive_socks_udp_ipv4_payload(&udp, udp_bind, target_addr, response).await?;
        last_source = Some(source);
    }

    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 1);
    assert_eq!(pool.streams_opened, 1);
    drop(control);
    let source = last_source.context("serial SOCKS UDP target source was not observed")?;
    let rebound = timeout(Duration::from_secs(2), async {
        loop {
            match UdpSocket::bind(source).await {
                Ok(socket) => break Ok(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await
    .context("serial SOCKS UDP control EOF did not release target source")??;
    assert_eq!(rebound.local_addr()?, source);
    drop(rebound);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_socks5_udp_associate_keeps_serial_target_switching() -> Result<()> {
    assert_normal_h2_socks_udp_serial_switches_targets().await
}

#[tokio::test]
async fn server_user_flow_limit_rejects_udp_association_when_tcp_flow_is_active() -> Result<()> {
    let fixture = MaverickHarness::start_with_user_flow_limit(1).await?;
    let hold_addr = start_hold_open_server().await?;

    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;
    let result = timeout(
        Duration::from_secs(2),
        UdpAssociation::open(&fixture.client_config()),
    )
    .await?;
    assert!(
        result.is_err(),
        "UDP association unexpectedly opened while user flow limit was exhausted"
    );

    first.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

async fn run_concurrent_socks_roundtrips(
    socks_addr: SocketAddr,
    echo_addr: SocketAddr,
    label: &'static str,
) -> Result<()> {
    let mut tasks = Vec::new();
    for idx in 0..16 {
        tasks.push(tokio::spawn(async move {
            let payload = format!("maverick-{label}-{idx:02}");
            let mut socks = socks_connect(socks_addr, echo_addr).await?;
            socks.write_all(payload.as_bytes()).await?;
            let mut echoed = vec![0u8; payload.len()];
            socks.read_exact(&mut echoed).await?;
            anyhow::ensure!(echoed == payload.as_bytes(), "echo payload mismatch");
            Result::<()>::Ok(())
        }));
    }
    for task in tasks {
        task.await??;
    }
    Ok(())
}

#[tokio::test]
async fn socks5_udp_associate_reuses_single_tunnel_flow() -> Result<()> {
    let fixture = MaverickHarness::start_with_features(None, true, false).await?;
    let udp_echo_addr = start_udp_echo_server().await?;
    let mut control = TcpStream::connect(fixture.client.local_addr).await?;

    control.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    control.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut associate_reply = [0u8; 10];
    control.read_exact(&mut associate_reply).await?;
    assert_eq!(associate_reply[1], 0x00);
    let udp_port = u16::from_be_bytes([associate_reply[8], associate_reply[9]]);
    let udp_bind = SocketAddr::from(([127, 0, 0, 1], udp_port));
    let udp = UdpSocket::bind("127.0.0.1:0").await?;

    for payload in [b"udp-one".as_slice(), b"udp-two".as_slice()] {
        let mut datagram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        datagram.extend_from_slice(&udp_echo_addr.port().to_be_bytes());
        datagram.extend_from_slice(payload);
        udp.send_to(&datagram, udp_bind).await?;

        let mut response = [0u8; 1024];
        let (len, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut response)).await??;
        assert_eq!(&response[..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&response[len - payload.len()..len], payload);
    }

    let pool = fixture.client.h2_connection_pool_snapshot();
    assert_eq!(pool.connections_created, 1);
    assert_eq!(pool.streams_opened, 1);
    assert_eq!(pool.streams_reused, 0);
    assert_eq!(pool.active_streams, 1);

    let metrics_addr = fixture
        .server
        .metrics_addr
        .context("missing metrics listener")?;
    let response = fetch_metrics(metrics_addr).await?;
    assert!(response.contains("\"authenticated_sessions\":1"));

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_udp_association_keeps_one_connected_target_owner() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    assert_udp_association_keeps_one_connected_target_owner(&config).await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_interrupted_udp_relay_fails_closed_before_next_target() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut config = fixture.client_config();
    config.advanced.udp_idle_timeout_ms = 5_000;

    let observation = observe_interrupted_udp_relay(&config).await?;

    assert_interrupted_udp_relay_failed_closed(observation);
    fixture.shutdown().await?;
    Ok(())
}

async fn assert_udp_association_keeps_one_connected_target_owner(
    config: &ClientConfig,
) -> Result<()> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_ip = TargetAddr::Ipv4(target_addr.ip().to_string().parse()?);
    let mut association = UdpAssociation::open(config).await?;

    let first_packet = UdpPacketPayload::new(
        target_ip.clone(),
        target_addr.port(),
        Bytes::from_static(b"owner-a"),
    );
    let (first_response, first_source) = timeout(Duration::from_secs(2), async {
        let relay = association.relay_packet(first_packet);
        let target_roundtrip = async {
            let mut buf = [0u8; 64];
            let (len, source) = target.recv_from(&mut buf).await?;
            anyhow::ensure!(&buf[..len] == b"owner-a", "first UDP payload mismatch");
            target.send_to(b"reply-a", source).await?;
            Result::<SocketAddr>::Ok(source)
        };
        let (response, source) = tokio::join!(relay, target_roundtrip);
        Result::<(UdpPacketPayload, SocketAddr)>::Ok((response?, source?))
    })
    .await??;
    assert_eq!(first_response.target, target_ip);
    assert_eq!(first_response.port, target_addr.port());
    assert_eq!(first_response.data.as_ref(), b"reply-a");

    let first_source_guard = match UdpSocket::bind(first_source).await {
        Ok(socket) => Some(socket),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => None,
        Err(err) => return Err(err.into()),
    };

    let second_packet = UdpPacketPayload::new(
        target_ip.clone(),
        target_addr.port(),
        Bytes::from_static(b"owner-b"),
    );
    let (second_response, second_source) = timeout(Duration::from_secs(2), async {
        let relay = association.relay_packet(second_packet);
        let target_roundtrip = async {
            let mut buf = [0u8; 64];
            let (len, source) = target.recv_from(&mut buf).await?;
            anyhow::ensure!(&buf[..len] == b"owner-b", "second UDP payload mismatch");
            target.send_to(b"reply-b", source).await?;
            Result::<SocketAddr>::Ok(source)
        };
        let (response, source) = tokio::join!(relay, target_roundtrip);
        Result::<(UdpPacketPayload, SocketAddr)>::Ok((response?, source?))
    })
    .await??;
    assert_eq!(second_response.target, target_ip);
    assert_eq!(second_response.port, target_addr.port());
    assert_eq!(second_response.data.as_ref(), b"reply-b");
    assert!(
        first_source_guard.is_none() && first_source == second_source,
        "active OpenUdp target owner must keep and reuse one source address"
    );

    timeout(Duration::from_secs(2), association.close())
        .await
        .context("explicit UDP association close must remain bounded")??;
    let rebound = timeout(Duration::from_secs(2), async {
        loop {
            match UdpSocket::bind(first_source).await {
                Ok(socket) => break Ok(socket),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(err) => break Err(err),
            }
        }
    })
    .await
    .context("explicit UDP association close must release the target source")??;
    assert_eq!(rebound.local_addr()?, first_source);
    drop(rebound);
    drop(target);
    Ok(())
}

#[derive(Debug)]
struct InterruptedUdpRelayObservation {
    second_result: InterruptedUdpRelayResult,
    target_b_payload: Option<Bytes>,
    close_result: InterruptedUdpCloseResult,
}

#[derive(Debug)]
enum InterruptedUdpRelayResult {
    Response(UdpPacketPayload),
    FixedUnusable,
    OtherError,
}

#[derive(Debug, Eq, PartialEq)]
enum InterruptedUdpCloseResult {
    NotAttempted,
    FixedUnusable,
    OtherError,
    UnexpectedSuccess,
}

async fn observe_interrupted_udp_relay(
    config: &ClientConfig,
) -> Result<InterruptedUdpRelayObservation> {
    let target_a = UdpSocket::bind("127.0.0.1:0").await?;
    let target_a_addr = target_a.local_addr()?;
    let target_a_ip = TargetAddr::Ipv4(target_a_addr.ip().to_string().parse()?);
    let target_b = UdpSocket::bind("127.0.0.1:0").await?;
    let target_b_addr = target_b.local_addr()?;
    let target_b_ip = TargetAddr::Ipv4(target_b_addr.ip().to_string().parse()?);
    let mut association = UdpAssociation::open(config).await?;

    let request_a = UdpPacketPayload::new(
        target_a_ip.clone(),
        target_a_addr.port(),
        Bytes::from_static(b"cancelled-request-a"),
    );
    let exact_source = timeout(Duration::from_secs(2), async {
        let relay = association.relay_packet(request_a);
        tokio::pin!(relay);
        tokio::select! {
            _ = &mut relay => {
                anyhow::bail!("first UDP relay completed before its real target replied")
            }
            received = async {
                let mut buf = [0u8; 64];
                let (len, source) = target_a.recv_from(&mut buf).await?;
                anyhow::ensure!(
                    &buf[..len] == b"cancelled-request-a",
                    "target A received the wrong request payload"
                );
                Result::<SocketAddr>::Ok(source)
            } => received,
        }
    })
    .await
    .context("target A must receive request A before relay cancellation")??;

    target_a.send_to(b"delayed-reply-a", exact_source).await?;

    let request_b = UdpPacketPayload::new(
        target_b_ip,
        target_b_addr.port(),
        Bytes::from_static(b"request-b"),
    );
    let (second_result, target_b_observation) = tokio::join!(
        association.relay_packet(request_b),
        timeout(Duration::from_secs(1), async {
            let mut buf = [0u8; 64];
            let (len, source) = target_b.recv_from(&mut buf).await?;
            anyhow::ensure!(
                &buf[..len] == b"request-b",
                "target B received the wrong request payload"
            );
            target_b.send_to(b"reply-b", source).await?;
            Result::<Bytes>::Ok(Bytes::copy_from_slice(&buf[..len]))
        })
    );
    let target_b_payload = match target_b_observation {
        Ok(result) => Some(result?),
        Err(_) => None,
    };
    let second_result = match second_result {
        Ok(response) => InterruptedUdpRelayResult::Response(response),
        Err(err) if err.to_string() == "UDP association is no longer usable" => {
            InterruptedUdpRelayResult::FixedUnusable
        }
        Err(_) => InterruptedUdpRelayResult::OtherError,
    };
    if let InterruptedUdpRelayResult::Response(response) = &second_result {
        assert_eq!(response.target, target_a_ip);
        assert_eq!(response.port, target_a_addr.port());
    }

    let rebound = timeout(Duration::from_secs(2), async {
        loop {
            match UdpSocket::bind(exact_source).await {
                Ok(socket) => break Ok(socket),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(err) => break Err(err),
            }
        }
    })
    .await
    .context("interrupted UDP relay must release target A's exact source")??;
    assert_eq!(rebound.local_addr()?, exact_source);
    drop(rebound);

    let close_result = match &second_result {
        InterruptedUdpRelayResult::Response(_) => {
            drop(association);
            InterruptedUdpCloseResult::NotAttempted
        }
        InterruptedUdpRelayResult::FixedUnusable | InterruptedUdpRelayResult::OtherError => {
            match association.close().await {
                Ok(()) => InterruptedUdpCloseResult::UnexpectedSuccess,
                Err(err) if err.to_string() == "UDP association is no longer usable" => {
                    InterruptedUdpCloseResult::FixedUnusable
                }
                Err(_) => InterruptedUdpCloseResult::OtherError,
            }
        }
    };

    Ok(InterruptedUdpRelayObservation {
        second_result,
        target_b_payload,
        close_result,
    })
}

fn assert_interrupted_udp_relay_failed_closed(observation: InterruptedUdpRelayObservation) {
    match observation.second_result {
        InterruptedUdpRelayResult::Response(response) => {
            let target_b_payload = observation
                .target_b_payload
                .as_ref()
                .expect("reused UDP association did not contact target B");
            assert_eq!(response.data.as_ref(), b"delayed-reply-a");
            assert_eq!(target_b_payload.as_ref(), b"request-b");
            assert_eq!(
                observation.close_result,
                InterruptedUdpCloseResult::NotAttempted
            );
            panic!(
                "interrupted UDP association reused delayed reply A for request B and contacted target B"
            );
        }
        InterruptedUdpRelayResult::FixedUnusable => {}
        InterruptedUdpRelayResult::OtherError => {
            panic!("interrupted UDP association returned an unexpected error category")
        }
    }
    assert!(
        observation.target_b_payload.is_none(),
        "interrupted UDP association contacted target B before failing closed"
    );
    assert_eq!(
        observation.close_result,
        InterruptedUdpCloseResult::FixedUnusable,
        "unusable UDP association close returned an unexpected fixed category"
    );
}

const OPEN_UDP_FLOW_ID: u64 = 41;
const MISMATCHED_UDP_FLOW_ID: u64 = 42;
const TEST_OPEN_UDP_MODE_FEATURE: u64 = 1 << 0;
const TEST_OPEN_UDP_DUPLEX_FLAG: u8 = 1 << 0;
const TEST_OPEN_UDP_RESERVED_FLAG: u8 = 1 << 7;

#[derive(Debug, Eq, PartialEq)]
enum UnsupportedOpenUdpModeTargetObservation {
    Reached(Bytes),
    NoTarget,
}

#[derive(Debug)]
struct RawOpenUdpModeObservation {
    feature_flags_selected: u64,
    target_port: u16,
    frames: Vec<Frame>,
    target: UnsupportedOpenUdpModeTargetObservation,
}

fn assert_raw_open_udp_serial_shape(observation: &RawOpenUdpModeObservation) -> Result<()> {
    let payload = match &observation.target {
        UnsupportedOpenUdpModeTargetObservation::Reached(payload) => payload,
        UnsupportedOpenUdpModeTargetObservation::NoTarget => {
            anyhow::bail!("flags-zero OpenUdp did not reach the real UDP target")
        }
    };
    assert_eq!(payload.as_ref(), b"open-udp-mode-request");
    assert_eq!(observation.frames.len(), 3);
    assert_eq!(observation.frames[1].frame_type, FrameType::WindowUpdate);
    assert_eq!(observation.frames[1].flags, 0);
    assert_eq!(observation.frames[1].flow_id, OPEN_UDP_FLOW_ID);
    assert!(observation.frames[1].payload.is_empty());
    assert_eq!(observation.frames[2].frame_type, FrameType::UdpPacket);
    assert_eq!(observation.frames[2].flags, 0);
    assert_eq!(observation.frames[2].flow_id, OPEN_UDP_FLOW_ID);
    let response_packet = UdpPacketPayload::decode(&observation.frames[2].payload)?;
    assert_eq!(
        response_packet.target,
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert_eq!(response_packet.port, observation.target_port);
    assert_eq!(response_packet.data.as_ref(), b"open-udp-mode-reply");
    Ok(())
}

fn assert_raw_open_udp_rejected(
    observation: RawOpenUdpModeObservation,
    expected_selected: u64,
) -> Result<()> {
    assert_eq!(observation.feature_flags_selected, expected_selected);
    if matches!(
        &observation.target,
        UnsupportedOpenUdpModeTargetObservation::Reached(_)
    ) {
        assert_raw_open_udp_serial_shape(&observation)?;
        panic!("server acknowledged an unsupported OpenUdp mode and reached the real UDP target");
    }
    assert_eq!(observation.frames.len(), 2);
    assert_eq!(
        observation.frames[1],
        Frame::new(
            FrameType::Error,
            0,
            OPEN_UDP_FLOW_ID,
            ErrorCode::ProtocolError.encode()
        )
    );
    Ok(())
}

fn assert_raw_open_udp_serial(
    observation: RawOpenUdpModeObservation,
    expected_selected: u64,
) -> Result<()> {
    assert_eq!(observation.feature_flags_selected, expected_selected);
    assert_raw_open_udp_serial_shape(&observation)
}

async fn observe_h2_raw_open_udp_mode(
    requested_features: u64,
    open_udp_flags: u8,
) -> Result<RawOpenUdpModeObservation> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;

    let sender = transport::connect(&config).await?;
    let mut h2 = match sender {
        transport::TunnelRequestSender::H2(h2) => h2,
        _ => anyhow::bail!("nonzero OpenUdp mode test requires the H2 transport"),
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(config.server.tunnel_path.as_str())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?;
    let (response_fut, mut send_stream) = h2.sender.send_request(request, false)?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        requested_features,
    )?;
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(FrameType::ClientHello, 0, 0, hello.encode()),
            65_536,
        )?,
        false,
    )?;
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(
                FrameType::OpenUdp,
                open_udp_flags,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            ),
            65_536,
        )?,
        false,
    )?;
    let request_packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"open-udp-mode-request"),
    );
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                request_packet.encode()?,
            ),
            65_536,
        )?,
        false,
    )?;
    send_stream.send_data(
        encode_grpc_frame(
            Frame::new(FrameType::CloseFlow, 0, OPEN_UDP_FLOW_ID, Bytes::new()),
            65_536,
        )?,
        true,
    )?;

    let response = response_fut.await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "authenticated H2 path fell back"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc"),
        "authenticated H2 path returned a fallback content type"
    );
    let mut body = response.into_body();
    let response_frames = async {
        let (mut response_bytes, trailers) =
            timeout(Duration::from_secs(2), collect_h2_response(&mut body))
                .await
                .context("nonzero OpenUdp mode response must remain bounded")??;
        assert_grpc_status_ok(&trailers);
        let mut frames = Vec::new();
        while let Some(frame) = decode_grpc_frame_from(&mut response_bytes, 65_536)? {
            frames.push(frame);
        }
        anyhow::ensure!(
            response_bytes.is_empty(),
            "nonzero OpenUdp mode left an incomplete response frame"
        );
        Result::<Vec<Frame>>::Ok(frames)
    };
    let target_observation = async {
        let mut buf = [0u8; 64];
        match timeout(Duration::from_secs(1), target.recv_from(&mut buf)).await {
            Ok(received) => {
                let (len, source) = received?;
                anyhow::ensure!(
                    &buf[..len] == b"open-udp-mode-request",
                    "OpenUdp mode reached the target with the wrong payload"
                );
                let reply = b"open-udp-mode-reply";
                let sent = target.send_to(reply, source).await?;
                anyhow::ensure!(
                    sent == reply.len(),
                    "OpenUdp mode target reply was truncated"
                );
                Result::<UnsupportedOpenUdpModeTargetObservation>::Ok(
                    UnsupportedOpenUdpModeTargetObservation::Reached(Bytes::copy_from_slice(
                        &buf[..len],
                    )),
                )
            }
            Err(_) => Ok(UnsupportedOpenUdpModeTargetObservation::NoTarget),
        }
    };
    let (frames, target_observation) = tokio::join!(response_frames, target_observation);
    let frames = frames?;
    let target_observation = target_observation?;

    let server_hello_frame = frames.first().context("missing ServerHello")?;
    assert_eq!(server_hello_frame.frame_type, FrameType::ServerHello);
    let server_hello = ServerHello::decode(&server_hello_frame.payload)?;
    assert!(
        server_hello.verify(&config.server.secret, &hello.client_nonce),
        "raw H2 ServerHello authentication failed"
    );

    fixture.shutdown().await?;
    Ok(RawOpenUdpModeObservation {
        feature_flags_selected: server_hello.feature_flags_selected,
        target_port: target_addr.port(),
        frames,
        target: target_observation,
    })
}

#[cfg(feature = "h3")]
async fn observe_h3_raw_open_udp_mode(
    requested_features: u64,
    open_udp_flags: u8,
) -> Result<RawOpenUdpModeObservation> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;

    let sender = transport::connect(&config).await?;
    let mut h3 = match sender {
        transport::TunnelRequestSender::H3(h3) => h3,
        _ => anyhow::bail!("nonzero OpenUdp mode test requires the Quinn/H3 transport"),
    };
    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(())?;
    let mut stream = h3.send_request(request).await?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        requested_features,
    )?;
    stream
        .send_data(Frame::new(FrameType::ClientHello, 0, 0, hello.encode()).encode(65_536)?)
        .await?;
    stream
        .send_data(
            Frame::new(
                FrameType::OpenUdp,
                open_udp_flags,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            )
            .encode(65_536)?,
        )
        .await?;
    let request_packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"open-udp-mode-request"),
    );
    stream
        .send_data(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                request_packet.encode()?,
            )
            .encode(65_536)?,
        )
        .await?;
    stream
        .send_data(
            Frame::new(FrameType::CloseFlow, 0, OPEN_UDP_FLOW_ID, Bytes::new()).encode(65_536)?,
        )
        .await?;
    stream.finish().await?;

    let response = timeout(Duration::from_secs(2), stream.recv_response())
        .await
        .context("nonzero OpenUdp mode H3 response headers must remain bounded")??;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "authenticated H3 path fell back"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/octet-stream"),
        "authenticated H3 path returned a fallback content type"
    );
    let response_frames = async {
        let mut response_bytes = BytesMut::new();
        timeout(Duration::from_secs(2), async {
            while let Some(mut chunk) = stream.recv_data().await? {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                response_bytes.extend_from_slice(&bytes);
            }
            Result::<()>::Ok(())
        })
        .await
        .context("nonzero OpenUdp mode H3 response body must remain bounded")??;
        let mut frames = Vec::new();
        while let Some(frame) = Frame::decode_from(&mut response_bytes, 65_536)? {
            frames.push(frame);
        }
        anyhow::ensure!(
            response_bytes.is_empty(),
            "nonzero OpenUdp mode left an incomplete H3 response frame"
        );
        Result::<Vec<Frame>>::Ok(frames)
    };
    let target_observation = async {
        let mut buf = [0u8; 64];
        match timeout(Duration::from_secs(1), target.recv_from(&mut buf)).await {
            Ok(received) => {
                let (len, source) = received?;
                anyhow::ensure!(
                    &buf[..len] == b"open-udp-mode-request",
                    "OpenUdp mode reached the H3 target with the wrong payload"
                );
                let reply = b"open-udp-mode-reply";
                let sent = target.send_to(reply, source).await?;
                anyhow::ensure!(
                    sent == reply.len(),
                    "OpenUdp mode H3 target reply was truncated"
                );
                Result::<UnsupportedOpenUdpModeTargetObservation>::Ok(
                    UnsupportedOpenUdpModeTargetObservation::Reached(Bytes::copy_from_slice(
                        &buf[..len],
                    )),
                )
            }
            Err(_) => Ok(UnsupportedOpenUdpModeTargetObservation::NoTarget),
        }
    };
    let (frames, target_observation) = tokio::join!(response_frames, target_observation);
    let frames = frames?;
    let target_observation = target_observation?;

    let server_hello_frame = frames.first().context("missing H3 ServerHello")?;
    assert_eq!(server_hello_frame.frame_type, FrameType::ServerHello);
    let server_hello = ServerHello::decode(&server_hello_frame.payload)?;
    assert!(
        server_hello.verify(&config.server.secret, &hello.client_nonce),
        "raw H3 ServerHello authentication failed"
    );

    assert_h3_transport(&config);
    drop(stream);
    drop(h3);
    fixture.shutdown().await?;
    Ok(RawOpenUdpModeObservation {
        feature_flags_selected: server_hello.feature_flags_selected,
        target_port: target_addr.port(),
        frames,
        target: target_observation,
    })
}

#[cfg(feature = "h3")]
async fn read_next_raw_h3_frame(
    stream: &mut maverick_client::h3_transport::H3ClientRequestStream,
    response_bytes: &mut BytesMut,
) -> Result<Option<Frame>> {
    loop {
        if let Some(frame) = Frame::decode_from(response_bytes, 65_536)? {
            return Ok(Some(frame));
        }
        let Some(mut chunk) = stream.recv_data().await? else {
            anyhow::ensure!(
                response_bytes.is_empty(),
                "raw H3 response ended with an incomplete Maverick frame"
            );
            return Ok(None);
        };
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        response_bytes.extend_from_slice(&bytes);
    }
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_negotiated_duplex_open_udp_allows_server_push() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);

    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let sender = transport::connect(&config).await?;
    let mut h3 = match sender {
        transport::TunnelRequestSender::H3(h3) => h3,
        _ => anyhow::bail!("negotiated duplex test requires the Quinn/H3 transport"),
    };
    let uri = format!(
        "https://{}{}",
        config.server.server_name, config.server.tunnel_path
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(())?;
    let mut stream = h3.send_request(request).await?;
    let hello = ClientHello::new(
        config.server.credential_id.clone(),
        &config.server.secret,
        &config.server.tunnel_path,
        config.mode,
        FEATURE_OPEN_UDP_MODE_NEGOTIATION,
    )?;
    stream
        .send_data(Frame::new(FrameType::ClientHello, 0, 0, hello.encode()).encode(65_536)?)
        .await?;
    stream
        .send_data(
            Frame::new(
                FrameType::OpenUdp,
                OPEN_UDP_FLAG_DUPLEX,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            )
            .encode(65_536)?,
        )
        .await?;
    let packet_a = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"peer-a"),
    );
    stream
        .send_data(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                packet_a.encode()?,
            )
            .encode(65_536)?,
        )
        .await?;

    let response = timeout(Duration::from_secs(2), stream.recv_response())
        .await
        .context("negotiated duplex H3 response headers must remain bounded")??;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "authenticated negotiated-duplex H3 path fell back"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/octet-stream"),
        "authenticated negotiated-duplex H3 path returned a fallback content type"
    );

    let mut response_bytes = BytesMut::new();
    let server_hello_frame = timeout(
        Duration::from_secs(2),
        read_next_raw_h3_frame(&mut stream, &mut response_bytes),
    )
    .await
    .context("negotiated duplex ServerHello must remain bounded")??
    .context("missing negotiated duplex ServerHello")?;
    assert_eq!(server_hello_frame.frame_type, FrameType::ServerHello);
    let server_hello = ServerHello::decode(&server_hello_frame.payload)?;
    assert!(
        server_hello.verify(&config.server.secret, &hello.client_nonce),
        "negotiated duplex ServerHello authentication failed"
    );
    assert_eq!(
        server_hello.feature_flags_selected, FEATURE_OPEN_UDP_MODE_NEGOTIATION,
        "negotiated duplex H3 handshake selected the wrong feature mask"
    );

    let open_response = timeout(
        Duration::from_secs(2),
        read_next_raw_h3_frame(&mut stream, &mut response_bytes),
    )
    .await
    .context("negotiated duplex OpenUdp response must remain bounded")??
    .context("server closed before answering negotiated duplex OpenUdp")?;
    let old_rejection = Frame::new(
        FrameType::Error,
        0,
        OPEN_UDP_FLOW_ID,
        ErrorCode::ProtocolError.encode(),
    );
    if open_response == old_rejection {
        let response_fin = timeout(
            Duration::from_secs(2),
            read_next_raw_h3_frame(&mut stream, &mut response_bytes),
        )
        .await
        .context("legacy-H3 rejection FIN must remain bounded")??;
        assert!(
            response_fin.is_none(),
            "legacy-H3 rejection Error must be followed by response FIN"
        );
        let trailers = timeout(Duration::from_secs(2), stream.recv_trailers())
            .await
            .context("legacy-H3 rejection trailers must remain bounded")??;
        assert!(
            trailers.is_none(),
            "legacy-H3 rejection unexpectedly appended response trailers"
        );
        let mut target_buf = [0u8; 64];
        match timeout(Duration::from_secs(1), target.recv_from(&mut target_buf)).await {
            Err(_) => {}
            Ok(Ok((len, _))) => panic!(
                "rejected negotiated duplex OpenUdp reached the real target with {len} bytes"
            ),
            Ok(Err(err)) => return Err(err).context("observe rejected duplex UDP target"),
        }
        assert_h3_transport(&config);
        drop(stream);
        drop(h3);
        fixture.shutdown().await?;
        panic!("negotiated legacy-H3 duplex OpenUdp stayed rejected");
    }
    assert_eq!(
        open_response,
        Frame::new(
            FrameType::WindowUpdate,
            OPEN_UDP_FLAG_DUPLEX,
            OPEN_UDP_FLOW_ID,
            Bytes::new(),
        ),
        "negotiated duplex OpenUdp acknowledgement had the wrong exact shape"
    );

    let mut target_buf = [0u8; 64];
    let (len, exact_source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
        .await
        .context("real target did not receive peer packet A")??;
    assert_eq!(&target_buf[..len], b"peer-a");

    let packet_b = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"peer-b"),
    );
    stream
        .send_data(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                packet_b.encode()?,
            )
            .encode(65_536)?,
        )
        .await?;
    let (len, source_b) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
        .await
        .context("real target did not receive peer packet B before replying")??;
    assert_eq!(&target_buf[..len], b"peer-b");
    assert_eq!(source_b, exact_source);

    for expected in [
        b"reply-b".as_slice(),
        b"reply-a".as_slice(),
        b"unsolicited-push".as_slice(),
    ] {
        let sent = target.send_to(expected, exact_source).await?;
        assert_eq!(sent, expected.len());
        let response = timeout(
            Duration::from_secs(2),
            read_next_raw_h3_frame(&mut stream, &mut response_bytes),
        )
        .await
        .context("target push response must remain bounded")??
        .context("server closed before forwarding target push")?;
        assert_eq!(response.frame_type, FrameType::UdpPacket);
        assert_eq!(response.flags, 0);
        assert_eq!(response.flow_id, OPEN_UDP_FLOW_ID);
        let packet = UdpPacketPayload::decode(&response.payload)?;
        assert_eq!(
            packet.target,
            TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(packet.port, target_addr.port());
        assert_eq!(packet.data.as_ref(), expected);
    }

    let packet_c = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"peer-c"),
    );
    stream
        .send_data(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                packet_c.encode()?,
            )
            .encode(65_536)?,
        )
        .await?;
    let (len, source_c) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
        .await
        .context("real target did not receive peer packet C after server push")??;
    assert_eq!(&target_buf[..len], b"peer-c");
    assert_eq!(source_c, exact_source);

    stream
        .send_data(
            Frame::new(FrameType::CloseFlow, 0, OPEN_UDP_FLOW_ID, Bytes::new()).encode(65_536)?,
        )
        .await?;
    stream.finish().await?;
    let response_fin = timeout(
        Duration::from_secs(2),
        read_next_raw_h3_frame(&mut stream, &mut response_bytes),
    )
    .await
    .context("explicit duplex CloseFlow FIN must remain bounded")??;
    assert!(
        response_fin.is_none(),
        "explicit duplex CloseFlow must be followed by response FIN"
    );
    let trailers = timeout(Duration::from_secs(2), stream.recv_trailers())
        .await
        .context("explicit duplex CloseFlow trailers must remain bounded")??;
    assert!(
        trailers.is_none(),
        "explicit duplex CloseFlow unexpectedly appended response trailers"
    );

    let release_deadline = Instant::now() + Duration::from_secs(2);
    let rebound = loop {
        match UdpSocket::bind(exact_source).await {
            Ok(socket) => break socket,
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && Instant::now() < release_deadline =>
            {
                tokio::task::yield_now().await;
            }
            Err(err) => {
                return Err(err).context("duplex CloseFlow did not release exact UDP source")
            }
        }
    };
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);

    drop(rebound);
    drop(stream);
    drop(h3);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
async fn open_h3_duplex_test_tunnel(
    config: &ClientConfig,
    idle_timeout_ms: u64,
) -> Result<maverick_client::tunnel::ClientTunnel> {
    assert_h3_transport(config);
    let mut tunnel = maverick_client::tunnel::open(config).await?;
    assert!(
        matches!(&tunnel, maverick_client::tunnel::ClientTunnel::H3(_)),
        "duplex OpenUdp test must use an actual H3 tunnel"
    );
    tunnel
        .send_frame(
            Frame::new(
                FrameType::OpenUdp,
                OPEN_UDP_FLAG_DUPLEX,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(idle_timeout_ms).encode(),
            ),
            false,
        )
        .await?;
    let acknowledgement = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("duplex OpenUdp acknowledgement must remain bounded")??
        .context("server closed before acknowledging duplex OpenUdp")?;
    assert_eq!(
        acknowledgement,
        Frame::new(
            FrameType::WindowUpdate,
            OPEN_UDP_FLAG_DUPLEX,
            OPEN_UDP_FLOW_ID,
            Bytes::new(),
        )
    );
    Ok(tunnel)
}

#[cfg(feature = "h3")]
async fn assert_h3_duplex_terminal_error(
    tunnel: &mut maverick_client::tunnel::ClientTunnel,
    code: ErrorCode,
) -> Result<()> {
    let response = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("duplex terminal Error must remain bounded")??
        .context("server closed before returning duplex terminal Error")?;
    assert_eq!(
        response,
        Frame::new(FrameType::Error, 0, OPEN_UDP_FLOW_ID, code.encode())
    );
    assert_h3_fin_after_terminal_error(tunnel).await
}

#[cfg(feature = "h3")]
async fn assert_udp_target_uncontacted(target: &UdpSocket, label: &str) -> Result<()> {
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(1), target.recv_from(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok((len, _))) => anyhow::bail!("{label} received {len} unexpected bytes"),
        Ok(Err(err)) => Err(err).with_context(|| format!("observe {label}")),
    }
}

#[cfg(feature = "h3")]
async fn rebind_released_udp_source(source: SocketAddr, label: &str) -> Result<UdpSocket> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match UdpSocket::bind(source).await {
            Ok(socket) => return Ok(socket),
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
            {
                tokio::task::yield_now().await;
            }
            Err(err) => return Err(err).with_context(|| format!("{label} did not release source")),
        }
    }
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_open_udp_rejects_target_change_before_new_target_io() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let target_a = UdpSocket::bind("127.0.0.1:0").await?;
    let target_b = UdpSocket::bind("127.0.0.1:0").await?;
    let target_a_addr = target_a.local_addr()?;
    let target_b_addr = target_b.local_addr()?;
    let mut tunnel =
        open_h3_duplex_test_tunnel(&config, config.advanced.udp_idle_timeout_ms).await?;

    let packet_a = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_a_addr.port(),
        Bytes::from_static(b"fixed-target-a"),
    );
    tunnel
        .send_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                packet_a.encode()?,
            ),
            false,
        )
        .await?;
    let mut target_buf = [0u8; 64];
    let (len, exact_source) = timeout(Duration::from_secs(2), target_a.recv_from(&mut target_buf))
        .await
        .context("fixed target A did not receive its first packet")??;
    assert_eq!(&target_buf[..len], b"fixed-target-a");

    let packet_b = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_b_addr.port(),
        Bytes::from_static(b"forbidden-target-b"),
    );
    tunnel
        .send_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                packet_b.encode()?,
            ),
            false,
        )
        .await?;
    assert_h3_duplex_terminal_error(&mut tunnel, ErrorCode::ProtocolError).await?;
    assert_udp_target_uncontacted(&target_b, "changed duplex target").await?;
    assert_udp_target_uncontacted(&target_a, "original duplex target after target change").await?;
    let rebound = rebind_released_udp_source(exact_source, "target-change rejection").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);

    drop(rebound);
    drop(tunnel);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_open_udp_rejects_wrong_flow_before_target_io() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut tunnel =
        open_h3_duplex_test_tunnel(&config, config.advanced.udp_idle_timeout_ms).await?;

    let packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"wrong-flow-duplex-packet"),
    );
    tunnel
        .send_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                MISMATCHED_UDP_FLOW_ID,
                packet.encode()?,
            ),
            false,
        )
        .await?;
    assert_h3_duplex_terminal_error(&mut tunnel, ErrorCode::ProtocolError).await?;
    assert_udp_target_uncontacted(&target, "wrong-flow duplex target").await?;
    assert_h3_transport(&config);

    drop(tunnel);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_open_udp_rejects_malformed_packet_terminally() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let mut tunnel =
        open_h3_duplex_test_tunnel(&config, config.advanced.udp_idle_timeout_ms).await?;

    tunnel
        .send_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                OPEN_UDP_FLOW_ID,
                Bytes::from_static(b"malformed"),
            ),
            false,
        )
        .await?;
    assert_h3_duplex_terminal_error(&mut tunnel, ErrorCode::ProtocolError).await?;
    assert_h3_transport(&config);

    drop(tunnel);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_open_udp_target_open_failure_is_terminal() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let mut tunnel =
        open_h3_duplex_test_tunnel(&config, config.advanced.udp_idle_timeout_ms).await?;
    let packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        0,
        Bytes::from_static(b"invalid-port"),
    );
    tunnel
        .send_frame(
            Frame::new(FrameType::UdpPacket, 0, OPEN_UDP_FLOW_ID, packet.encode()?),
            false,
        )
        .await?;
    assert_h3_duplex_terminal_error(&mut tunnel, ErrorCode::TargetConnectFailed).await?;
    assert_h3_transport(&config);

    drop(tunnel);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_duplex_open_udp_idle_sends_close_flow_and_fin() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let mut tunnel = open_h3_duplex_test_tunnel(&config, 300).await?;
    let packet = UdpPacketPayload::new(
        TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
        target_addr.port(),
        Bytes::from_static(b"idle-owner-setup"),
    );
    tunnel
        .send_frame(
            Frame::new(FrameType::UdpPacket, 0, OPEN_UDP_FLOW_ID, packet.encode()?),
            false,
        )
        .await?;
    let mut target_buf = [0u8; 64];
    let (len, exact_source) = timeout(Duration::from_secs(2), target.recv_from(&mut target_buf))
        .await
        .context("duplex idle test did not establish a real target owner")??;
    assert_eq!(&target_buf[..len], b"idle-owner-setup");

    let close = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("duplex idle CloseFlow must remain bounded")??
        .context("server closed before sending duplex idle CloseFlow")?;
    assert_eq!(
        close,
        Frame::new(FrameType::CloseFlow, 0, OPEN_UDP_FLOW_ID, Bytes::new())
    );
    assert_h3_fin_after_terminal_error(&mut tunnel).await?;
    let rebound = rebind_released_udp_source(exact_source, "duplex idle expiry").await?;
    assert_eq!(rebound.local_addr()?, exact_source);
    assert_h3_transport(&config);

    drop(rebound);
    drop(tunnel);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_open_udp_nonzero_mode_fails_before_target_io() -> Result<()> {
    for (requested_features, open_udp_flags, expected_selected) in [
        (0, TEST_OPEN_UDP_DUPLEX_FLAG, 0),
        (0, TEST_OPEN_UDP_RESERVED_FLAG, 0),
        (
            TEST_OPEN_UDP_MODE_FEATURE,
            TEST_OPEN_UDP_DUPLEX_FLAG,
            TEST_OPEN_UDP_MODE_FEATURE,
        ),
        (
            TEST_OPEN_UDP_MODE_FEATURE,
            TEST_OPEN_UDP_RESERVED_FLAG,
            TEST_OPEN_UDP_MODE_FEATURE,
        ),
    ] {
        assert_raw_open_udp_rejected(
            observe_h2_raw_open_udp_mode(requested_features, open_udp_flags).await?,
            expected_selected,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn h2_open_udp_flags_zero_keeps_serial_flow() -> Result<()> {
    for (requested_features, expected_selected) in [
        (0, 0),
        (TEST_OPEN_UDP_MODE_FEATURE, TEST_OPEN_UDP_MODE_FEATURE),
    ] {
        assert_raw_open_udp_serial(
            observe_h2_raw_open_udp_mode(requested_features, 0).await?,
            expected_selected,
        )?;
    }
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_open_udp_nonzero_mode_fails_before_target_io() -> Result<()> {
    for (requested_features, open_udp_flags, expected_selected) in [
        (0, TEST_OPEN_UDP_DUPLEX_FLAG, 0),
        (0, TEST_OPEN_UDP_RESERVED_FLAG, 0),
        (
            TEST_OPEN_UDP_MODE_FEATURE,
            TEST_OPEN_UDP_RESERVED_FLAG,
            TEST_OPEN_UDP_MODE_FEATURE,
        ),
    ] {
        assert_raw_open_udp_rejected(
            observe_h3_raw_open_udp_mode(requested_features, open_udp_flags).await?,
            expected_selected,
        )?;
    }
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_open_udp_flags_zero_keeps_serial_flow() -> Result<()> {
    for (requested_features, expected_selected) in [
        (0, 0),
        (TEST_OPEN_UDP_MODE_FEATURE, TEST_OPEN_UDP_MODE_FEATURE),
    ] {
        assert_raw_open_udp_serial(
            observe_h3_raw_open_udp_mode(requested_features, 0).await?,
            expected_selected,
        )?;
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum MismatchedUdpTargetObservation {
    Received(Bytes),
    NoTarget,
}

async fn open_udp_test_tunnel(
    config: &ClientConfig,
) -> Result<maverick_client::tunnel::ClientTunnel> {
    let mut tunnel = maverick_client::tunnel::open(config).await?;
    if config.advanced.experimental_h3 {
        #[cfg(feature = "h3")]
        assert!(
            matches!(&tunnel, maverick_client::tunnel::ClientTunnel::H3(_)),
            "experimental H3 test must use an actual H3 tunnel"
        );
        #[cfg(not(feature = "h3"))]
        anyhow::bail!("experimental H3 config requires the H3 test feature");
    } else {
        assert!(
            matches!(&tunnel, maverick_client::tunnel::ClientTunnel::H2(_)),
            "default OpenUdp test must use an actual H2 tunnel"
        );
    }
    tunnel
        .send_frame(
            Frame::new(
                FrameType::OpenUdp,
                0,
                OPEN_UDP_FLOW_ID,
                OpenUdpPayload::new(config.advanced.udp_idle_timeout_ms).encode(),
            ),
            false,
        )
        .await?;
    let opened = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("OpenUdp acknowledgement must remain bounded")??
        .context("server closed before acknowledging OpenUdp")?;
    assert_eq!(
        opened,
        Frame::new(FrameType::WindowUpdate, 0, OPEN_UDP_FLOW_ID, Bytes::new())
    );
    Ok(tunnel)
}

fn assert_open_udp_protocol_error(frame: Frame) {
    assert_eq!(
        frame,
        Frame::new(
            FrameType::Error,
            0,
            OPEN_UDP_FLOW_ID,
            ErrorCode::ProtocolError.encode()
        )
    );
}

async fn send_mismatched_udp_packet(
    config: &ClientConfig,
) -> Result<maverick_client::tunnel::ClientTunnel> {
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let target_ip = TargetAddr::Ipv4(target_addr.ip().to_string().parse()?);
    let mut tunnel = open_udp_test_tunnel(config).await?;
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let target_observer = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        tokio::select! {
            biased;
            received = target.recv_from(&mut buf) => {
                let (len, source) = received?;
                target.send_to(b"mismatch-reply", source).await?;
                Result::<MismatchedUdpTargetObservation>::Ok(
                    MismatchedUdpTargetObservation::Received(Bytes::copy_from_slice(&buf[..len])),
                )
            }
            _ = cancel_rx => {
                Result::<MismatchedUdpTargetObservation>::Ok(
                    MismatchedUdpTargetObservation::NoTarget,
                )
            }
        }
    });

    let packet = UdpPacketPayload::new(
        target_ip,
        target_addr.port(),
        Bytes::from_static(b"mismatched-flow-packet"),
    );
    tunnel
        .send_frame(
            Frame::new(
                FrameType::UdpPacket,
                0,
                MISMATCHED_UDP_FLOW_ID,
                packet.encode()?,
            ),
            false,
        )
        .await?;
    let response = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("mismatched UdpPacket response must remain bounded")??
        .context("server closed without rejecting mismatched UdpPacket")?;
    let _ = cancel_tx.send(());
    let target_observation = timeout(Duration::from_secs(2), target_observer)
        .await
        .context("UDP target observer must remain bounded")?
        .context("UDP target observer task failed")??;
    assert_eq!(
        target_observation,
        MismatchedUdpTargetObservation::NoTarget,
        "mismatched UdpPacket reached the real UDP target before rejection"
    );
    assert_open_udp_protocol_error(response);
    Ok(tunnel)
}

async fn send_mismatched_close_flow(
    config: &ClientConfig,
) -> Result<maverick_client::tunnel::ClientTunnel> {
    let mut tunnel = open_udp_test_tunnel(config).await?;
    tunnel
        .send_frame(
            Frame::new(
                FrameType::CloseFlow,
                0,
                MISMATCHED_UDP_FLOW_ID,
                Bytes::new(),
            ),
            true,
        )
        .await?;
    let response = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("mismatched CloseFlow response must remain bounded")??
        .context("server accepted mismatched CloseFlow without a protocol error")?;
    assert_open_udp_protocol_error(response);
    Ok(tunnel)
}

async fn assert_h2_grpc_ok_after_terminal_error(
    mut tunnel: maverick_client::tunnel::ClientTunnel,
) -> Result<()> {
    let h2 = match &mut tunnel {
        maverick_client::tunnel::ClientTunnel::H2(h2) => h2,
        _ => anyhow::bail!("expected H2 tunnel"),
    };
    assert!(
        h2.recv_buf.is_empty(),
        "terminal Error must leave no buffered response frame"
    );
    let (remaining, trailers) = timeout(
        Duration::from_secs(2),
        collect_h2_response(&mut h2.recv_stream),
    )
    .await
    .context("terminal H2 response must remain bounded")??;
    assert!(
        remaining.is_empty(),
        "terminal Error must be the final H2 response frame"
    );
    assert_grpc_status_ok(&trailers);
    Ok(())
}

#[tokio::test]
async fn h2_open_udp_mismatched_packet_fails_before_target_io() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let tunnel = send_mismatched_udp_packet(&fixture.client_config()).await?;
    assert_h2_grpc_ok_after_terminal_error(tunnel).await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn h2_open_udp_mismatched_close_returns_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let tunnel = send_mismatched_close_flow(&fixture.client_config()).await?;
    assert_h2_grpc_ok_after_terminal_error(tunnel).await?;
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
fn assert_h3_transport(config: &ClientConfig) {
    let snapshot = transport::transport_debug_snapshot(config);
    assert_eq!(snapshot.active_transport, GuiTransportCarrier::H3);
    assert!(snapshot.h3_candidate_enabled);
    assert!(!snapshot.h3_in_cooldown);
}

#[cfg(feature = "h3")]
fn assert_source_free_fixed_error(error: &anyhow::Error, expected: &str) {
    assert_eq!(error.to_string(), expected);
    let public_error: &(dyn std::error::Error + Send + Sync + 'static) = error.as_ref();
    assert!(std::error::Error::source(public_error).is_none());
}

#[cfg(feature = "h3")]
fn expect_legacy_h3_duplex_open_error(
    result: Result<LegacyH3DuplexUdpAssociation>,
    label: &str,
) -> Result<anyhow::Error> {
    match result {
        Ok(association) => {
            drop(association);
            anyhow::bail!("{label} unexpectedly opened a public duplex association")
        }
        Err(error) => Ok(error),
    }
}

#[cfg(feature = "h3")]
async fn assert_h3_fin_after_terminal_error(
    tunnel: &mut maverick_client::tunnel::ClientTunnel,
) -> Result<()> {
    let next = timeout(Duration::from_secs(2), tunnel.read_next_frame())
        .await
        .context("terminal H3 response must remain bounded")??;
    assert!(next.is_none(), "terminal Error must be followed by H3 FIN");
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_open_udp_mismatched_packet_fails_before_target_io() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let mut tunnel = send_mismatched_udp_packet(&config).await?;
    assert_h3_fin_after_terminal_error(&mut tunnel).await?;
    assert_h3_transport(&config);
    fixture.shutdown().await?;
    Ok(())
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_open_udp_mismatched_close_returns_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_h3().await?;
    let config = fixture.client_config();
    assert_h3_transport(&config);
    let mut tunnel = send_mismatched_close_flow(&config).await?;
    assert_h3_fin_after_terminal_error(&mut tunnel).await?;
    assert_h3_transport(&config);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cert_pin_accepts_expected_certificate_and_rejects_wrong_pin() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let mut pinned = fixture.client_config();
    pinned.server.cert_pin = Some(fixture.cert_pin());
    let body = tunnel_attempt_body(&pinned, None).await?;
    assert!(!String::from_utf8_lossy(&body).contains("Maverick"));

    let mut wrong = fixture.client_config();
    wrong.server.cert_pin = Some(format!("sha256/{}", URL_SAFE_NO_PAD.encode([7u8; 32])));
    assert!(tunnel_attempt_body(&wrong, None).await.is_err());

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn client_connect_timeout_covers_stalled_tls_handshake() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let stalling_addr = start_stalling_tcp_server().await?;
    let mut config = fixture.client_config();
    config.server.address = stalling_addr.to_string();
    config.advanced.connect_timeout_ms = 50;

    let started = Instant::now();
    let result = timeout(Duration::from_secs(2), transport::connect(&config)).await?;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn server_rejects_tls12_only_client() -> Result<()> {
    let fixture = MaverickHarness::start().await?;
    let config = fixture.client_config();
    let ca_path = config.server.ca_cert.as_ref().context("missing CA cert")?;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(ca_path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    assert!(added > 0);
    let tls_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(fixture.server.local_addr).await?;
    let server_name = ServerName::try_from("localhost".to_owned())?;

    let result = timeout(Duration::from_secs(2), connector.connect(server_name, tcp)).await?;
    assert!(
        result.is_err(),
        "TLS 1.2-only client unexpectedly connected"
    );

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn disabled_user_returns_fallback_not_protocol_error() -> Result<()> {
    let fixture = MaverickHarness::start_with_options(HarnessOptions {
        user_enabled: false,
        ..HarnessOptions::default()
    })
    .await?;
    let body = tunnel_attempt_body(&fixture.client_config(), None).await?;
    assert_fallback_body(&body);

    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn per_user_flow_limit_rejects_second_tcp_flow() -> Result<()> {
    let fixture = MaverickHarness::start_with_user_flow_limit(1).await?;
    let hold_addr = start_hold_open_server().await?;

    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;
    let mut second = TcpStream::connect(fixture.client.local_addr).await?;
    second.write_all(&[0x05, 1, 0x00]).await?;
    let mut method_reply = [0u8; 2];
    second.read_exact(&mut method_reply).await?;
    assert_eq!(method_reply, [0x05, 0x00]);
    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&hold_addr.port().to_be_bytes());
    second.write_all(&connect).await?;
    let mut connect_reply = [0u8; 10];
    second.read_exact(&mut connect_reply).await?;
    assert_ne!(connect_reply[1], 0x00);

    first.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn client_flow_limit_rejects_second_tcp_flow_locally() -> Result<()> {
    let fixture = MaverickHarness::start_with_client_flow_limit(1).await?;
    let hold_addr = start_hold_open_server().await?;

    let mut first = socks_connect(fixture.client.local_addr, hold_addr).await?;
    let second = TcpStream::connect(fixture.client.local_addr).await?;
    expect_second_socks_flow_rejected(second, hold_addr).await?;

    first.shutdown().await?;
    fixture.shutdown().await?;
    Ok(())
}

async fn expect_second_socks_flow_rejected(
    mut stream: TcpStream,
    target_addr: SocketAddr,
) -> Result<()> {
    let attempt = timeout(Duration::from_secs(2), async {
        stream.write_all(&[0x05, 1, 0x00]).await?;
        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        if method_reply != [0x05, 0x00] {
            return Ok::<bool, anyhow::Error>(true);
        }

        let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        connect.extend_from_slice(&target_addr.port().to_be_bytes());
        stream.write_all(&connect).await?;
        let mut connect_reply = [0u8; 10];
        stream.read_exact(&mut connect_reply).await?;
        Ok::<bool, anyhow::Error>(connect_reply[1] != 0x00)
    })
    .await;

    match attempt {
        Ok(Ok(true)) | Ok(Err(_)) => Ok(()),
        Ok(Ok(false)) => anyhow::bail!("second SOCKS flow unexpectedly succeeded"),
        Err(_) => anyhow::bail!("timed out waiting for second SOCKS flow rejection"),
    }
}
