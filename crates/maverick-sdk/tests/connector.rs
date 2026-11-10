use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use maverick_sdk::*;
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, time::Duration};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

#[path = "support/udp_sessions.rs"]
mod udp_sessions;

struct Fixture {
    _files: TempDir,
    server: MaverickServer,
    client: ClientConfig,
}

impl Fixture {
    async fn start(protected: bool, carrier: u8) -> Result<Self> {
        Self::start_with_idle(protected, carrier, 30_000).await
    }

    async fn start_with_idle(
        protected: bool,
        carrier: u8,
        udp_idle_timeout_ms: u64,
    ) -> Result<Self> {
        let files = TempDir::new()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_path = files.path().join("cert.pem");
        let key_path = files.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem())?;
        std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
        let pin = format!(
            "sha256/{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(cert.cert.der()))
        );
        let secret = SecretString::generate();
        let mut options = ServerAdvancedConfig {
            udp_idle_timeout_ms,
            end_to_end: protected,
            quiche_h3: carrier == 1,
            dual_h2_h3: carrier == 2,
            ..Default::default()
        };
        options.egress.allow_loopback = true;
        let server = MaverickServer::start(
            server_config_builder()
                .tls_paths(&cert_path, &key_path)
                .user("sdk-test", secret.clone())
                .static_fallback_dir(files.path())
                .advanced(options)
                .build()?,
        )
        .await?;
        let mut options = ClientAdvancedConfig {
            max_concurrent_flows: 1,
            quiche_h3: carrier == 1,
            auto_h3: carrier == 2,
            connect_timeout_ms: 3000,
            ..Default::default()
        };
        if protected {
            options.end_to_end = Some(EndToEndClientConfig {
                server_name: "localhost".into(),
                ca_cert: Some(cert_path.clone()),
                cert_pin: pin.clone(),
            });
            // Protected fronting must survive stored-profile materialization,
            // including required INNER exporter binding.
            options.stealth.cdn_fronting.enabled = true;
            options.stealth.cdn_fronting.carrier = config::CdnFrontingCarrier::H2;
            options
                .stealth
                .cdn_fronting
                .trusted_tls_terminating_provider = true;
        }
        let mut auth = ClientAuthConfig::default();
        auth.channel_binding.require = true;
        let client = client_config_builder()
            .server_address(server.local_addr().context("missing server")?.to_string())
            .server_name("localhost")
            .credential("sdk-test", secret)
            .ca_cert(cert_path)
            .cert_pin(pin)
            .auth(auth)
            .advanced(options)
            .build()?;
        Ok(Self {
            _files: files,
            server,
            client,
        })
    }
}

async fn transfer(session: TcpSession, target: &TcpListener, target_first: bool) -> Result<()> {
    let (mut app, local) = tokio::io::duplex(64);
    let relay = session.relay(local);
    let peer = async {
        let (mut peer, _) = target.accept().await?;
        if target_first {
            peer.write_all(b"reply").await?;
            peer.shutdown().await?;
        }
        let mut data = Vec::new();
        peer.read_to_end(&mut data).await?;
        ensure!(data == b"request");
        if !target_first {
            peer.write_all(b"reply").await?;
            peer.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let application = async {
        if target_first {
            let mut data = Vec::new();
            app.read_to_end(&mut data).await?;
            ensure!(data == b"reply");
        }
        app.write_all(b"request").await?;
        app.shutdown().await?;
        if !target_first {
            let mut data = Vec::new();
            app.read_to_end(&mut data).await?;
            ensure!(data == b"reply");
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(relay, peer, application)?;
    Ok(())
}

async fn tcp_matrix(protected: bool, carrier: u8) -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start(protected, carrier).await?;
        let occupied = TcpListener::bind("127.0.0.1:0").await?;
        fixture.client.local.socks5.listen = occupied.local_addr()?;
        let mut secrets = InMemoryProfileSecretStore::new();
        let profile =
            StoredClientProfile::store_from_config("sdk-test", &fixture.client, &mut secrets)?;
        let json = serde_json::to_string(&profile)?;
        ensure!(!json.contains(fixture.client.server.secret.expose_secret()));
        let restored: StoredClientProfile = serde_json::from_str(&json)?;
        ensure!(restored.compatibility_status() == StoredClientProfileCompatibility::Current);
        let restored = restored.to_client_config(&secrets)?;
        ensure!(restored.advanced.auto_h3 == (carrier == 2));
        ensure!(restored.advanced.end_to_end.is_some() == protected);
        let connector = ProxyConnector::new(restored)?;
        ensure!(connector.h2_pool_snapshot().connections_created == 0);
        let target = TcpListener::bind("127.0.0.1:0").await?;
        for target_first in [false, true] {
            let session = connector
                .connect_tcp(
                    TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                    target.local_addr()?.port(),
                )
                .await?;
            ensure!(
                session.carrier()
                    == if carrier == 0 {
                        TransportKind::H2
                    } else {
                        TransportKind::H3
                    }
            );
            ensure!(
                connector
                    .connect_tcp(
                        TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                        target.local_addr()?.port()
                    )
                    .await
                    .is_err(),
                "local flow limit bypassed"
            );
            transfer(session, &target, target_first).await?;
        }
        if carrier == 0 {
            ensure!(
                connector.h2_pool_snapshot().connections_created == 1,
                "SDK did not reuse H2"
            );
        } else {
            ensure!(
                connector.h2_pool_snapshot().connections_created == 0,
                "SDK did not select H3"
            );
        }
        let session = connector
            .connect_tcp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port(),
            )
            .await?;
        connector.close();
        ensure!(connector
            .connect_tcp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port()
            )
            .await
            .is_err());
        transfer(session, &target, false).await?;
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK TCP connector test timed out")?
}

#[tokio::test]
async fn h2_connector_preserves_pool_admission_half_close_and_owner_lifecycle() -> Result<()> {
    tcp_matrix(false, 0).await
}

#[tokio::test]
async fn protected_profile_roundtrip_and_connector_preserve_inner_binding() -> Result<()> {
    tcp_matrix(true, 0).await
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn h3_and_auto_sdk_features_forward_real_tcp() -> Result<()> {
    tcp_matrix(false, 1).await?;
    tcp_matrix(false, 2).await
}

#[tokio::test]
async fn connector_errors_do_not_open_target_and_dropped_opens_release_capacity() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let fixture = Fixture::start(false, 0).await?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        for pin_error in [false, true] {
            let mut config = fixture.client.clone();
            if pin_error { config.server.cert_pin = Some(format!("sha256/{}", URL_SAFE_NO_PAD.encode([0; 32]))); }
            else { config.server.secret = SecretString::generate(); }
            let connector = ProxyConnector::new(config)?;
            ensure!(connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await.is_err());
            ensure!(timeout(Duration::from_millis(60), target.accept()).await.is_err());
        }
        let silent = TcpListener::bind("127.0.0.1:0").await?;
        let mut config = fixture.client.clone();
        config.server.address = silent.local_addr()?.to_string();
        let connector = ProxyConnector::new(config)?;
        for _ in 0..2 {
            let open = connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port());
            tokio::pin!(open);
            let peer = tokio::select! {
                result = &mut open => { ensure!(result.is_ok(), "capacity was not released after cancellation"); anyhow::bail!("silent TLS peer accepted"); }
                accepted = silent.accept() => accepted?.0,
            };
            drop(peer);
            // Dropping the pinned future cancels the unfinished connection.
        }
        connector.close();
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }).await.context("SDK denial/cancellation test timed out")?
}

#[tokio::test]
async fn sdk_legacy_udp_exchange_uses_existing_h2_semantics() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let fixture = Fixture::start(false, 0).await?;
        let connector = ProxyConnector::new(fixture.client)?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let request = UdpPacketPayload::new(
            TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
            target.local_addr()?.port(),
            Bytes::from_static(b"udp"),
        );
        let echo = async {
            let mut data = [0; 16];
            let (n, peer) = target.recv_from(&mut data).await?;
            target.send_to(&data[..n], peer).await?;
            Ok::<_, anyhow::Error>(())
        };
        let (response, _) = tokio::try_join!(connector.exchange_udp(request), echo)?;
        ensure!(response.data.as_ref() == b"udp");
        connector.close();
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn sdk_native_udp_is_independent_and_retains_its_flow_permit() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let fixture = Fixture::start(false, 2).await?;
        let connector = ProxyConnector::new(fixture.client)?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let mut session = connector
            .open_native_udp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port(),
            )
            .await?;
        ensure!(connector
            .open_native_udp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port()
            )
            .await
            .is_err());
        connector.close();
        ensure!(!session.send(vec![0; session.max_payload() + 1].into())?);
        ensure!(session.send(Bytes::from_static(b"udp"))?);
        let mut data = [0; 1200];
        let (n, peer) = target.recv_from(&mut data).await?;
        ensure!(&data[..n] == b"udp");
        for value in [&b"first"[..], &b""[..], &b"last"[..]] {
            target.send_to(value, peer).await?;
            ensure!(session.recv().await?.as_ref() == value);
        }
        session.close().await?;
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[test]
fn connector_requires_runtime_without_spawning_or_binding() -> Result<()> {
    let config = client_config_builder()
        .server_address("127.0.0.1:1")
        .server_name("localhost")
        .credential("sdk-test", SecretString::generate())
        .build()?;
    let error = ProxyConnector::new(config)
        .err()
        .context("connector unexpectedly constructed without runtime")?;
    ensure!(error.to_string().contains("Tokio runtime"));
    Ok(())
}

async fn udp_session_matrix(protected: bool, carrier: u8, policy: UdpPolicy) -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start(protected, carrier).await?;
        fixture.client.advanced.udp_policy = Some(policy);
        let mut secrets = InMemoryProfileSecretStore::new();
        let stored =
            StoredClientProfile::store_from_config("udp-policy", &fixture.client, &mut secrets)?;
        let json = serde_json::to_string(&stored)?;
        ensure!(!json.contains(fixture.client.server.secret.expose_secret()));
        let restored: StoredClientProfile = serde_json::from_str(&json)?;
        let restored = restored.to_client_config(&secrets)?;
        ensure!(restored.advanced.udp_policy == Some(policy));
        let connector = ProxyConnector::new(restored)?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        socket2::SockRef::from(&target).set_send_buffer_size(131_072)?;
        socket2::SockRef::from(&target).set_recv_buffer_size(131_072)?;
        let address = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
        let port = target.local_addr()?.port();
        let mut session = connector.open_udp(address.clone(), port).await?;
        ensure!(
            session.carrier()
                == if carrier == 0 {
                    UdpCarrier::H2Reliable
                } else {
                    UdpCarrier::H3Native
                }
        );
        ensure!(connector.open_udp(address.clone(), port).await.is_err());
        let mut buffer = vec![0; 65_535];
        let mut source = None;
        // Upload continues without any target response. One source socket is
        // retained across all packets; no request/response pairing is assumed.
        for number in 0..8u8 {
            ensure!(session.send(Bytes::from(vec![number]))?);
            let (size, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
                .await
                .context("continuous UDP upload not received")??;
            ensure!(size == 1 && buffer[0] == number);
            if let Some(source) = source {
                ensure!(peer == source);
            }
            source = Some(peer);
        }
        let source = source.unwrap();
        target.send_to(b"first", source).await?;
        target.send_to(b"second", source).await?;
        ensure!(session.recv().await?.as_ref() == b"first");
        ensure!(session.recv().await?.as_ref() == b"second");
        // Target silence neither causes replay nor destroys the admitted path.
        ensure!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        ensure!(session.send(Bytes::new())?);
        let (size, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
            .await
            .context("empty UDP upload not received")??;
        ensure!(size == 0 && peer == source);
        target.send_to(b"", source).await?;
        ensure!(session.recv().await?.is_empty());
        let maximum = session.max_payload();
        ensure!(!session.send(Bytes::from(vec![0; maximum + 1]))?);
        ensure!(session.send(Bytes::from(vec![42; maximum]))?);
        let (size, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
            .await
            .context("maximum UDP upload not received")??;
        ensure!(size == maximum && peer == source && buffer[..size].iter().all(|b| *b == 42));
        target.send_to(&buffer[..size], source).await?;
        ensure!(session.recv().await?.as_ref() == &buffer[..size]);
        session.close().await?;
        let next = connector.open_udp(address, port).await?;
        next.close().await?;
        connector.close();
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("UDP session matrix timed out")?
}

#[tokio::test]
async fn reliable_udp_sessions_preserve_port_and_independent_duplex() -> Result<()> {
    udp_session_matrix(false, 0, UdpPolicy::AllowReliable).await?;
    udp_session_matrix(true, 0, UdpPolicy::AllowReliable).await
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn selected_udp_sessions_preserve_native_datagrams() -> Result<()> {
    for policy in [UdpPolicy::NativeRequired, UdpPolicy::AllowReliable] {
        udp_session_matrix(false, 1, policy).await?;
        udp_session_matrix(false, 2, policy).await?;
    }
    Ok(())
}

#[tokio::test]
async fn target_reset_is_a_relay_error_and_releases_the_sdk_slot() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let fixture = Fixture::start(false, 0).await?;
        let connector = ProxyConnector::new(fixture.client)?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let session = connector
            .connect_tcp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port(),
            )
            .await?;
        let (mut app, local) = tokio::io::duplex(64);
        let reset = async {
            let (mut peer, _) = target.accept().await?;
            peer.read_exact(&mut [0]).await?;
            socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO))?;
            drop(peer);
            Ok::<_, anyhow::Error>(())
        };
        let application = async {
            app.write_all(b"x").await?;
            let _ = app.read(&mut [0]).await;
            Ok::<_, anyhow::Error>(())
        };
        let relay = async {
            ensure!(
                session.relay(local).await.is_err(),
                "target reset reported successful forwarding"
            );
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(reset, application, relay)?;
        let session = connector
            .connect_tcp(
                TargetAddr::Ipv4(Ipv4Addr::LOCALHOST),
                target.local_addr()?.port(),
            )
            .await?;
        transfer(session, &target, false).await?;
        connector.close();
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SDK reset propagation test timed out")?
}
