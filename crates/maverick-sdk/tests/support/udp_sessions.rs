use super::*;

async fn stalled_reliable_udp_close(cancel: bool) -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start(false, 0).await?;
        let origin = fixture.server.local_addr().context("missing server")?;
        let relay = TcpListener::bind("127.0.0.1:0").await?;
        fixture.client.server.address = relay.local_addr()?.to_string();
        fixture.client.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
        fixture.client.advanced.connect_timeout_ms = 1_000;
        let (gate, mut download_allowed) = tokio::sync::watch::channel(true);
        let held = std::sync::Arc::new(tokio::sync::Notify::new());
        let held_copy = std::sync::Arc::clone(&held);
        let mut drivers = tokio::task::JoinSet::new();
        drivers.spawn(async move {
            let (client, _) = relay.accept().await?;
            let server = tokio::net::TcpStream::connect(origin).await?;
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let upload = async {
                tokio::io::copy(&mut client_read, &mut server_write).await?;
                server_write.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            };
            let download = async {
                let mut bytes = [0; 16 * 1024];
                loop {
                    let count = server_read.read(&mut bytes).await?;
                    if count == 0 {
                        return client_write.shutdown().await.map_err(Into::into);
                    }
                    if !*download_allowed.borrow() {
                        // Stall opaque TLS bytes, without changing the real server.
                        held_copy.notify_one();
                    }
                    while !*download_allowed.borrow_and_update() {
                        download_allowed.changed().await?;
                    }
                    client_write.write_all(&bytes[..count]).await?;
                }
            };
            tokio::try_join!(upload, download)?;
            Ok::<_, anyhow::Error>(())
        });
        let connector = ProxyConnector::new(fixture.client.clone())?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let mut session = connector
            .open_udp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port())
            .await?;
        ensure!(session.send(Bytes::from_static(b"before close"))?);
        let mut bytes = [0; 32];
        let (count, source) = target.recv_from(&mut bytes).await?;
        target.send_to(&bytes[..count], source).await?;
        ensure!(session.recv().await? == Bytes::from_static(b"before close"));
        ensure!(connector.h2_pool_snapshot().active_streams == 1);

        gate.send(false)?;
        let mut close = Box::pin(session.close());
        tokio::select! {
            result = &mut close => anyhow::bail!("close ended before the withheld response: {}", result.is_ok()),
            _ = held.notified() => {},
        }
        if cancel {
            drop(close);
        } else {
            let error = close.await.expect_err("stalled close unexpectedly succeeded");
            ensure!(error.to_string() == "reliable UDP close timed out");
        }
        let released = timeout(Duration::from_millis(1_500), async {
            while connector.h2_pool_snapshot().active_streams != 0 {
                tokio::task::yield_now().await;
            }
        }).await;
        // Keep the response stalled beyond the canceled shutdown deadline.
        // Explicit cleanup also leaves the failing old-code test bounded.
        gate.send(true)?;
        drivers.abort_all();
        while drivers.join_next().await.is_some() {}
        connector.close();
        fixture.server.shutdown().await?;
        ensure!(released.is_ok(), "canceled or timed-out UDP close retained its H2 stream beyond the shutdown deadline");
        Ok(())
    }).await.context("UDP close cancellation regression timed out")?
}

#[tokio::test]
async fn cancelling_reliable_udp_close_releases_the_h2_stream() -> Result<()> {
    stalled_reliable_udp_close(true).await
}

#[tokio::test]
async fn timing_out_reliable_udp_close_releases_the_h2_stream() -> Result<()> {
    stalled_reliable_udp_close(false).await
}

#[tokio::test]
async fn explicit_udp_policy_requires_protected_intermediary_before_connecting() -> Result<()> {
    let fixture = Fixture::start(false, 0).await?;
    let trap = TcpListener::bind("127.0.0.1:0").await?;
    let mut config = fixture.client.clone();
    config.server.address = trap.local_addr()?.to_string();
    config.auth.channel_binding.enabled = false;
    config.auth.channel_binding.require = false;
    config.advanced.stealth.cdn_fronting.enabled = true;
    config.advanced.stealth.cdn_fronting.carrier = config::CdnFrontingCarrier::H2;
    config
        .advanced
        .stealth
        .cdn_fronting
        .trusted_tls_terminating_provider = true;
    // Legacy omission keeps its explicit trusted-provider compatibility meaning.
    config.validate()?;
    config.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
    ensure!(config.validate().is_err());
    ensure!(ProxyConnector::new(config.clone()).is_err());
    let opening = maverick_client::h2_transport::connect(&config);
    tokio::pin!(opening);
    tokio::select! {
        result = &mut opening => ensure!(result.is_err()),
        _ = trap.accept() => anyhow::bail!("modern UDP policy contacted an unprotected intermediary"),
        _ = tokio::time::sleep(Duration::from_secs(2)) => anyhow::bail!("protection rejection stalled"),
    }
    fixture.server.shutdown().await?;
    Ok(())
}

async fn released_udp_port(address: std::net::SocketAddr) -> Result<()> {
    timeout(Duration::from_secs(2), async {
        loop {
            match UdpSocket::bind(address).await {
                Ok(socket) => {
                    drop(socket);
                    return Ok::<_, anyhow::Error>(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("UDP target socket was not released")?
}

#[tokio::test]
async fn udp_idle_releases_target_and_caller_drop_releases_sdk_admission() -> Result<()> {
    let carriers: &[u8] = if cfg!(feature = "experimental-h3") {
        &[0, 1, 2]
    } else {
        &[0]
    };
    for &carrier in carriers {
        timeout(Duration::from_secs(5), async {
            let mut fixture = Fixture::start_with_idle(false, carrier, 150).await?;
            fixture.client.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
            let connector = ProxyConnector::new(fixture.client)?;
            let target = UdpSocket::bind("127.0.0.1:0").await?;
            let address = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
            let mut session = connector
                .open_udp(address.clone(), target.local_addr()?.port())
                .await?;
            let mut data = [0; 16];
            let mut peer = None;
            for _ in 0..5 {
                ensure!(session.send(Bytes::from_static(b"active"))?);
                let (_, current) = target.recv_from(&mut data).await?;
                if let Some(peer) = peer {
                    ensure!(peer == current);
                }
                peer = Some(current);
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            ensure!(timeout(Duration::from_secs(2), session.recv())
                .await?
                .is_err());
            released_udp_port(peer.unwrap()).await?;
            drop(session);
            let next = connector
                .open_udp(address, target.local_addr()?.port())
                .await?;
            drop(next);
            fixture.server.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("UDP idle cleanup test timed out")??;
    }
    Ok(())
}

#[tokio::test]
async fn socks_h2_udp_has_persistent_targets_large_packets_and_control_cleanup() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::start(false, 0).await?;
        fixture.client.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
        fixture.client.advanced.max_concurrent_flows = 2;
        let client = MaverickClient::start(fixture.client).await?;
        let mut control = tokio::net::TcpStream::connect(client.local_addr().unwrap()).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0; 2];
        control.read_exact(&mut greeting).await?;
        ensure!(greeting == [5, 0]);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await?;
        ensure!(reply[..4] == [5, 0, 0, 1]);
        let proxy =
            std::net::SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));
        let local = UdpSocket::bind("127.0.0.1:0").await?;
        let options = socket2::SockRef::from(&local);
        options.set_send_buffer_size(131_072)?;
        options.set_recv_buffer_size(131_072)?;
        let mut sources = Vec::new();
        for _ in 0..2 {
            let target = UdpSocket::bind("127.0.0.1:0").await?;
            let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
            packet.extend_from_slice(&target.local_addr()?.port().to_be_bytes());
            packet.extend_from_slice(&vec![71; 60_000]);
            let options = socket2::SockRef::from(&target);
            options.set_send_buffer_size(131_072)?;
            options.set_recv_buffer_size(131_072)?;
            let mut data = vec![0; 65_535];
            local.send_to(&packet, proxy).await?;
            let (size, source) = target.recv_from(&mut data).await?;
            ensure!(size == 60_000 && data[..size].iter().all(|b| *b == 71));
            local.send_to(&packet[..10], proxy).await?;
            let (size, peer) = target.recv_from(&mut data).await?;
            ensure!(size == 0 && peer == source);
            target.send_to(&packet[10..], source).await?;
            let (size, peer) = local.recv_from(&mut data).await?;
            ensure!(peer == proxy && size == packet.len() && data[..size] == packet);
            target.send_to(&vec![0; 65_507], source).await?;
            ensure!(
                timeout(Duration::from_millis(80), local.recv_from(&mut data))
                    .await
                    .is_err(),
                "SOCKS cannot fit a maximum UDP payload plus its header"
            );
            for payload in [b"one".as_slice(), b"two".as_slice()] {
                target.send_to(payload, source).await?;
                let (size, _) = local.recv_from(&mut data).await?;
                ensure!(&data[10..size] == payload);
            }
            sources.push(source);
        }
        control.shutdown().await?;
        drop(control);
        for source in sources {
            released_udp_port(source).await?;
        }
        client.shutdown().await?;
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SOCKS reliable UDP test timed out")?
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn udp_selection_shares_avoidance_retries_and_keeps_existing_sessions() -> Result<()> {
    timeout(Duration::from_secs(40), async {
        let mut fixture = Fixture::start_with_idle(false, 0, 60_000).await?;
        let endpoint = fixture.server.local_addr().unwrap();
        let blackhole = UdpSocket::bind(endpoint).await?;
        fixture.client.advanced.auto_h3 = true;
        fixture.client.advanced.max_concurrent_flows = 4;
        fixture.client.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
        let connector = ProxyConnector::new(fixture.client.clone())?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
        let port = target.local_addr()?.port();
        let mut first = connector.open_udp(address.clone(), port).await?;
        ensure!(first.carrier() == UdpCarrier::H2Reliable);
        let mut buffer = [0; 2048];
        ensure!(first.send(Bytes::from_static(b"once"))?);
        let (_, original_source) = target.recv_from(&mut buffer).await?;
        ensure!(timeout(Duration::from_millis(80), first.recv())
            .await
            .is_err());
        ensure!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        while timeout(Duration::from_millis(20), blackhole.recv_from(&mut buffer))
            .await
            .is_ok()
        {}
        let tcp_target = TcpListener::bind("127.0.0.1:0").await?;
        let tcp = connector
            .connect_tcp(address.clone(), tcp_target.local_addr()?.port())
            .await?;
        let (_, _) = tcp_target.accept().await?;
        let second = connector.open_udp(address.clone(), port).await?;
        ensure!(second.carrier() == UdpCarrier::H2Reliable);
        ensure!(
            timeout(Duration::from_millis(80), blackhole.recv_from(&mut buffer))
                .await
                .is_err(),
            "cached reachability failure reprobed H3"
        );
        second.close().await?;
        drop(tcp);

        drop(blackhole);
        let mut options = ServerAdvancedConfig {
            quiche_h3: true,
            ..Default::default()
        };
        options.egress.allow_loopback = true;
        let h3 = MaverickServer::start(
            server_config_builder()
                .listen(endpoint)
                .tls_paths(
                    fixture._files.path().join("cert.pem"),
                    fixture._files.path().join("key.pem"),
                )
                .user("sdk-test", fixture.client.server.secret.clone())
                .static_fallback_dir(fixture._files.path())
                .advanced(options)
                .build()?,
        )
        .await?;
        // Exercise the actual public SDK timer; no test hook changes production time.
        tokio::time::sleep(Duration::from_secs(31)).await;
        let mut recovered = connector.open_udp(address, port).await?;
        ensure!(recovered.carrier() == UdpCarrier::H3Native);
        ensure!(recovered.send(Bytes::from_static(b"new"))?);
        let (size, new_source) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"new" && new_source != original_source);
        target.send_to(b"reply", new_source).await?;
        ensure!(recovered.recv().await?.as_ref() == b"reply");
        ensure!(first.carrier() == UdpCarrier::H2Reliable);
        ensure!(first.send(Bytes::from_static(b"old"))?);
        let (size, peer) = target.recv_from(&mut buffer).await?;
        ensure!(peer == original_source && &buffer[..size] == b"old");
        recovered.close().await?;
        first.close().await?;
        h3.shutdown().await?;
        fixture.server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("UDP selection/recovery test timed out")?
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn native_required_and_security_failures_never_choose_h2() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut fixture = Fixture::start(false, 0).await?;
        let _blackhole = UdpSocket::bind(fixture.server.local_addr().unwrap()).await?;
        fixture.client.advanced.auto_h3 = true;
        fixture.client.advanced.udp_policy = Some(UdpPolicy::NativeRequired);
        let connector = ProxyConnector::new(fixture.client.clone())?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = TargetAddr::Ipv4(Ipv4Addr::LOCALHOST);
        ensure!(connector
            .open_udp(address.clone(), target.local_addr()?.port())
            .await
            .is_err());
        ensure!(connector.h2_pool_snapshot().connections_created == 0);
        let mut fallback_config = fixture.client;
        fallback_config.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
        fallback_config.server.cert_pin =
            Some(format!("sha256/{}", URL_SAFE_NO_PAD.encode([0; 32])));
        let fallback = ProxyConnector::new(fallback_config)?;
        ensure!(
            fallback
                .open_udp(address.clone(), target.local_addr()?.port())
                .await
                .is_err(),
            "H2 fallback bypassed its certificate pin check"
        );
        fixture.server.shutdown().await?;

        for fault in ["secret", "pin", "name", "ca"] {
            let mut fixture = Fixture::start(false, 1).await?;
            let h2_trap = TcpListener::bind(fixture.server.local_addr().unwrap()).await?;
            fixture.client.advanced.quiche_h3 = false;
            fixture.client.advanced.auto_h3 = true;
            fixture.client.advanced.udp_policy = Some(UdpPolicy::AllowReliable);
            match fault {
                "pin" => {
                    fixture.client.server.cert_pin =
                        Some(format!("sha256/{}", URL_SAFE_NO_PAD.encode([0; 32])))
                }
                "secret" => fixture.client.server.secret = SecretString::generate(),
                "name" => fixture.client.server.server_name = "wrong.example.invalid".into(),
                "ca" => {
                    let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
                    let path = fixture._files.path().join("untrusted.pem");
                    std::fs::write(&path, wrong.cert.pem())?;
                    fixture.client.server.ca_cert = Some(path);
                }
                _ => unreachable!(),
            }
            let connector = ProxyConnector::new(fixture.client)?;
            ensure!(connector
                .open_udp(address.clone(), target.local_addr()?.port())
                .await
                .is_err());
            ensure!(timeout(Duration::from_millis(80), h2_trap.accept())
                .await
                .is_err());
            let mut data = [0; 1];
            ensure!(
                timeout(Duration::from_millis(80), target.recv_from(&mut data))
                    .await
                    .is_err()
            );
            fixture.server.shutdown().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("UDP no-downgrade test timed out")?
}
