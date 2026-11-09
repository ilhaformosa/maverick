//! A TLS-terminating intermediary with its own independently trusted certificate.
//! Captures stay in memory and are never printed or persisted.
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use maverick_client::transport::{self, TunnelRequestSender};
use maverick_core::h2_io::{H2Io, CONTENT_TYPE};
use maverick_core::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

#[allow(dead_code)]
mod support;
use support::{socks_connect, HarnessOptions, MaverickHarness};

const DEADLINE: Duration = Duration::from_secs(10);

struct Relay {
    config: ClientConfig,
    upstream: ClientConfig,
    capture: Arc<Mutex<Vec<u8>>>,
    response_capture: Arc<Mutex<Vec<u8>>>,
    tamper: Arc<AtomicBool>,
    join: JoinHandle<()>,
    _files: tempfile::TempDir,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.join.abort();
    }
}

impl Relay {
    async fn start(origin: ClientConfig) -> Result<Self> {
        let files = tempfile::TempDir::new()?;
        let edge = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let edge_ca = files.path().join("edge.pem");
        std::fs::write(&edge_ca, edge.cert.pem())?;
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(edge.cert.der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(edge.key_pair.serialize_der())),
                )?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut config = origin.clone();
        config.server.address = listener.local_addr()?.to_string();
        config.server.ca_cert = Some(edge_ca);
        config.server.cert_pin = None;
        let mut upstream = origin;
        upstream.advanced.end_to_end = None;
        let forward = upstream.clone();
        let capture = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&capture);
        let response_capture = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::clone(&response_capture);
        let tamper = Arc::new(AtomicBool::new(false));
        let corrupt = Arc::clone(&tamper);
        let join = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        let upstream = forward.clone();
                        let captured = Arc::clone(&captured);
                        let corrupt = Arc::clone(&corrupt);
                        let responses = Arc::clone(&responses);
                        connections.spawn(async move {
                            let tls = acceptor.accept(tcp).await?;
                            let mut connection = h2::server::handshake(tls).await?;
                            let mut requests = JoinSet::new();
                            while let Some(request) = connection.accept().await {
                                let (request, mut response) = request?;
                                let upstream = upstream.clone();
                                let captured = Arc::clone(&captured);
                                let corrupt = Arc::clone(&corrupt);
                                let responses = Arc::clone(&responses);
                                requests.spawn(async move {
                                    let TunnelRequestSender::H2(transport) = transport::connect(&upstream).await? else {
                                        anyhow::bail!("test relay requires H2");
                                    };
                                    let mut sender = transport.sender.ready().await?;
                                    let (parts, incoming) = request.into_parts();
                                    let (reply, outgoing) = sender.send_request(http::Request::from_parts(parts, ()), false)?;
                                    let reply = reply.await?;
                                    let (parts, returning) = reply.into_parts();
                                    let downstream = response.send_response(http::Response::from_parts(parts, ()), false)?;
                                    let (mut read, mut write) = tokio::io::split(H2Io::new(incoming, downstream));
                                    let (mut upstream_read, mut upstream_write) = tokio::io::split(H2Io::new(returning, outgoing));
                                    let upload = async {
                                        let mut buffer = [0; 16 * 1024];
                                        loop {
                                            let n = read.read(&mut buffer).await?;
                                            if n == 0 { upstream_write.shutdown().await?; break; }
                                            {
                                                let mut capture = captured.lock().unwrap();
                                                ensure!(capture.len() + n <= 4 * 1024 * 1024, "capture limit exceeded");
                                                capture.extend_from_slice(&buffer[..n]);
                                            }
                                            if corrupt.swap(false, Ordering::SeqCst) { buffer[n - 1] ^= 1; }
                                            upstream_write.write_all(&buffer[..n]).await?;
                                        }
                                        Ok::<_, anyhow::Error>(())
                                    };
                                    let download = async {
                                        let mut buffer = [0; 16 * 1024];
                                        loop {
                                            let n = upstream_read.read(&mut buffer).await?;
                                            if n == 0 { break; }
                                            {
                                                let mut capture = responses.lock().unwrap();
                                                ensure!(capture.len() + n <= 4 * 1024 * 1024, "capture limit exceeded");
                                                capture.extend_from_slice(&buffer[..n]);
                                            }
                                            write.write_all(&buffer[..n]).await?;
                                        }
                                        write.shutdown().await?;
                                        Ok::<_, anyhow::Error>(())
                                    };
                                    tokio::try_join!(upload, download)?;
                                    Ok::<_, anyhow::Error>(())
                                });
                            }
                            requests.abort_all();
                            while requests.join_next().await.is_some() {}
                            Ok::<_, anyhow::Error>(())
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            config,
            upstream,
            capture,
            response_capture,
            tamper,
            join,
            _files: files,
        })
    }
}

async fn harness(v2: bool) -> Result<MaverickHarness> {
    MaverickHarness::start_with_options(HarnessOptions {
        end_to_end: true,
        cdn_fronting_h2: true,
        auth_channel_binding_require: true,
        auth_v2_epoch: v2.then_some(7),
        client_connect_timeout_ms: Some(3_000),
        server_handshake_timeout_ms: Some(3_000),
        ..Default::default()
    })
    .await
}

async fn exchange(config: ClientConfig, target_first_fin: bool) -> Result<()> {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let address = target.local_addr()?;
    let payload = vec![0x5b; 256 * 1024];
    let expected = payload.clone();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await?;
        if target_first_fin {
            socket.write_all(b"protected target response").await?;
            socket.shutdown().await?;
        }
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await?;
        ensure!(received == expected, "target payload mismatch");
        if !target_first_fin {
            socket.write_all(b"protected target response").await?;
            socket.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let client = maverick_client::start_client(config).await?;
    let mut socket = socks_connect(client.local_addr, address).await?;
    if target_first_fin {
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await?;
        ensure!(
            response == b"protected target response",
            "response mismatch"
        );
    }
    socket.write_all(&payload).await?;
    socket.shutdown().await?;
    if !target_first_fin {
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await?;
        ensure!(
            response == b"protected target response",
            "response mismatch"
        );
    }
    target_task.await??;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn terminating_relay_preserves_v1_v2_and_both_half_close_orders() -> Result<()> {
    timeout(DEADLINE, async {
        for v2 in [false, true] {
            let origin = harness(v2).await?;
            let relay = Relay::start(origin.client_config()).await?;
            tokio::try_join!(
                exchange(relay.config.clone(), false),
                exchange(relay.config.clone(), true)
            )?;
            {
                let mut captured = relay.capture.lock().unwrap().clone();
                captured.extend_from_slice(&relay.response_capture.lock().unwrap());
                for marker in [
                    b"u_test".as_slice(),
                    b"protected target response".as_slice(),
                    &[0x5b; 32],
                ] {
                    ensure!(
                        !captured.windows(marker.len()).any(|w| w == marker),
                        "relay saw protected content"
                    );
                }
            }
            drop(relay);
            origin.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("protected relay exchange timed out")?
}

#[tokio::test]
async fn valid_outer_tls_cannot_replace_inner_identity() -> Result<()> {
    timeout(DEADLINE, async {
        let origin = harness(false).await?;
        let relay = Relay::start(origin.client_config()).await?;
        for fault in ["ca", "name", "pin"] {
            let mut bad = relay.config.clone();
            let inner = bad.advanced.end_to_end.as_mut().unwrap();
            match fault {
                "ca" => inner.ca_cert.clone_from(&bad.server.ca_cert),
                "name" => inner.server_name = "wrong.invalid".into(),
                "pin" => {
                    inner.cert_pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
                }
                _ => unreachable!(),
            }
            let error = match maverick_client::tunnel::open(&bad).await {
                Ok(_) => anyhow::bail!("invalid inner identity accepted"),
                Err(error) => error,
            };
            ensure!(
                format!("{error:#}").contains("end-to-end origin TLS verification failed"),
                "failure did not come from inner verification"
            );
        }
        exchange(relay.config.clone(), false).await?;
        drop(relay);
        origin.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("inner identity tests timed out")?
}

#[tokio::test]
async fn record_tampering_and_plaintext_mismatch_fail_closed() -> Result<()> {
    timeout(DEADLINE, async {
        let origin = harness(false).await?;
        let relay = Relay::start(origin.client_config()).await?;
        relay.tamper.store(true, Ordering::SeqCst);
        ensure!(
            maverick_client::tunnel::open(&relay.config).await.is_err(),
            "tampered TLS accepted"
        );
        ensure!(
            !relay.tamper.load(Ordering::SeqCst),
            "tamper was not exercised"
        );
        let mut plain = relay.config.clone();
        plain.advanced.end_to_end = None;
        plain.auth.channel_binding.require = false;
        ensure!(
            maverick_client::tunnel::open(&plain).await.is_err(),
            "protected origin accepted plaintext"
        );
        exchange(relay.config.clone(), false).await?;
        drop(relay);
        origin.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("tamper tests timed out")?
}

#[tokio::test]
async fn authenticated_record_tamper_and_replay_do_not_open_target() -> Result<()> {
    use maverick_core::frame::{Frame, FrameType, OpenTcpPayload, TargetAddr};
    timeout(DEADLINE, async {
        let origin = harness(false).await?;
        let relay = Relay::start(origin.client_config()).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let mut tunnel = maverick_client::tunnel::open(&relay.config).await?;
        let open = OpenTcpPayload {
            target: TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: address.port(),
            initial_data: Bytes::new(),
        };
        relay.tamper.store(true, Ordering::SeqCst);
        let sent = tunnel
            .send_frame(Frame::new(FrameType::OpenTcp, 0, 1, open.encode()?), false)
            .await;
        if sent.is_ok() {
            ensure!(
                !matches!(tunnel.read_next_frame().await, Ok(Some(_))),
                "tampered target request accepted"
            );
        }
        ensure!(
            !relay.tamper.load(Ordering::SeqCst),
            "authenticated record was not corrupted"
        );
        drop(tunnel);
        let recorded = relay.capture.lock().unwrap().clone();
        ensure!(
            !recorded
                .windows(open.encode()?.len())
                .any(|w| w == open.encode().unwrap()),
            "relay saw proxy target"
        );
        // Replay the genuine captured client bytes into a fresh origin TLS
        // session. A distinct server handshake must prevent authentication.
        let TunnelRequestSender::H2(upstream) = transport::connect(&relay.upstream).await? else {
            anyhow::bail!("expected H2");
        };
        let mut sender = upstream.sender.ready().await?;
        let request = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://localhost{}",
                relay.upstream.server.tunnel_path
            ))
            .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
            .body(())?;
        let (reply, send) = sender.send_request(request, false)?;
        let reply = reply.await?;
        ensure!(
            reply.status() == http::StatusCode::OK,
            "replay did not reach protected envelope"
        );
        let mut io = H2Io::new(reply.into_body(), send);
        io.write_all(&recorded).await?;
        io.shutdown().await?;
        let mut output = Vec::new();
        let _closed = io.read_to_end(&mut output).await;
        ensure!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "tamper or replay reached proxy target"
        );
        drop(io);
        drop(sender);
        exchange(relay.config.clone(), false).await?;
        drop(relay);
        origin.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("record replay test timed out")?
}

#[tokio::test]
async fn protected_pool_reuse_and_shutdown_release_connections() -> Result<()> {
    timeout(DEADLINE, async {
        let origin = harness(false).await?;
        let relay = Relay::start(origin.client_config()).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = target.local_addr()?;
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (mut first, _) = target.accept().await?;
            let mut byte = [0];
            first.read_exact(&mut byte).await?;
            first.write_all(&byte).await?;
            let mut remaining = Vec::new();
            first.read_to_end(&mut remaining).await?;
            drop(first);
            let (mut second, _) = target.accept().await?;
            let _ = second_tx.send(());
            second.read_to_end(&mut remaining).await?;
            ensure!(remaining.is_empty(), "unexpected target data");
            Ok::<_, anyhow::Error>(())
        });
        let client = maverick_client::start_client(relay.config.clone()).await?;
        let local = client.local_addr;
        let mut first = socks_connect(local, target_addr).await?;
        first.write_all(b"x").await?;
        first.shutdown().await?;
        let mut reply = Vec::new();
        first.read_to_end(&mut reply).await?;
        ensure!(reply == b"x", "echo mismatch");
        let second = socks_connect(local, target_addr).await?;
        second_rx.await?;
        let snapshot = client.h2_connection_pool_snapshot();
        ensure!(
            snapshot.connections_created == 1 && snapshot.streams_reused >= 1,
            "protected H2 did not reuse the origin connection"
        );
        client.shutdown().await?;
        target_task.await??;
        let rebound = TcpListener::bind(local).await?;
        drop(rebound);
        drop(second);
        drop(relay);
        let origin_addr = origin.server.local_addr;
        origin.shutdown().await?;
        let rebound = TcpListener::bind(origin_addr).await?;
        drop(rebound);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("protected lifecycle test timed out")?
}

#[tokio::test]
async fn protected_client_does_not_downgrade_to_legacy_origin() -> Result<()> {
    timeout(DEADLINE, async {
        let origin = MaverickHarness::start_with_options(HarnessOptions {
            server_handshake_timeout_ms: Some(200),
            ..Default::default()
        })
        .await?;
        let mut protected = origin.client_config();
        protected.advanced.end_to_end = Some(maverick_core::config::EndToEndClientConfig {
            server_name: "localhost".into(),
            ca_cert: protected.server.ca_cert.clone(),
            cert_pin: origin.cert_pin(),
        });
        let error = match maverick_client::tunnel::open(&protected).await {
            Ok(_) => anyhow::bail!("protected client downgraded to legacy origin"),
            Err(error) => error,
        };
        ensure!(
            format!("{error:#}").contains("protected H2 envelope"),
            "mismatch did not stop at the outer envelope"
        );
        origin.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("protection mismatch test timed out")?
}

#[tokio::test]
async fn public_transport_apis_reject_incompatible_protection_before_connecting() -> Result<()> {
    timeout(DEADLINE, async {
        let legacy = MaverickHarness::start_with_options(HarnessOptions {
            experimental_cloudflare_ws: true,
            ..Default::default()
        })
        .await?;
        let mut protected = legacy.client_config();
        protected.advanced.end_to_end = Some(maverick_core::config::EndToEndClientConfig {
            server_name: "origin.invalid".into(),
            ca_cert: None,
            cert_pin: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        });
        ensure!(
            protected.validate().is_err(),
            "fixture must be an unsupported combination"
        );
        // Low-level callers can construct ClientConfig without start_client.
        // The legacy endpoint must not receive authentication under an ignored
        // protection setting, even though it accepts the outer credential.
        ensure!(
            maverick_client::tunnel::open(&protected).await.is_err(),
            "public tunnel API ignored end-to-end protection"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        protected.server.address = listener.local_addr()?.to_string();
        ensure!(
            maverick_client::ws_transport::connect(&protected)
                .await
                .is_err(),
            "public WebSocket API ignored protection"
        );
        ensure!(
            maverick_client::h2_transport::connect(&protected)
                .await
                .is_err(),
            "public H2 API accepted incompatible protection"
        );
        protected.advanced.experimental_cloudflare_ws = false;
        protected.advanced.stealth.cdn_fronting.enabled = false;
        protected.validate()?;
        ensure!(
            maverick_client::ws_transport::connect(&protected)
                .await
                .is_err(),
            "direct WebSocket API ignored a valid H2 protection setting"
        );
        #[cfg(feature = "experimental-h3")]
        {
            let (channel, mut wire) = maverick_core::h3_channel::channel();
            let binding = maverick_core::auth::TlsChannelBinding::new([0; 32]);
            ensure!(
                maverick_client::h3::open(&protected, channel, binding)
                    .await
                    .is_err(),
                "direct H3 API ignored a valid H2 protection setting"
            );
            ensure!(
                wire.outbound.try_recv().is_err(),
                "H3 emitted authentication before rejecting protection"
            );
        }
        ensure!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "invalid protected configuration opened a socket"
        );
        legacy.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("public API protection test timed out")?
}
