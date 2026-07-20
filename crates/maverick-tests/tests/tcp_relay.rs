use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http::{Method, Request, StatusCode};
use maverick_client::{
    connection_manager::H2ConnectionPoolSnapshot, transport, udp::UdpAssociation,
};
use maverick_core::auth::{ClientHello, ClientHelloV2};
#[cfg(feature = "browser-tls")]
use maverick_core::config::TlsFingerprintMode;
use maverick_core::config::{
    AuthV2Config, ClientAuthConfig, ClientConfig, ClientCredentialRotationConfig,
    ClientNextCredentialConfig, FallbackConfig, PreviousCredentialConfig, ShapingConfig,
};
use maverick_core::frame::{Frame, FrameType};
use maverick_core::grpc::encode_grpc_frame;
use maverick_core::SecretString;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::RootCertStore;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
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
    let mut response = response_fut.await?;
    let server_hello = timeout(Duration::from_secs(1), response.body_mut().data())
        .await?
        .context("missing server hello")??;
    assert!(!server_hello.is_empty());

    let started = Instant::now();
    let _ = timeout(Duration::from_secs(2), response.body_mut().data()).await?;
    assert!(started.elapsed() < Duration::from_secs(1));

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
