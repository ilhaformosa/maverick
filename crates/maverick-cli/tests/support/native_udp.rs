use super::*;
use maverick_client::h3::NativeUdpAssociation;
use maverick_core::frame::TargetAddr;
use tokio::net::UdpSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_native_udp_respects_single_slot_and_control_cancellation() -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::for_transport(true, 4)?;
        fixture.server_config_with_metrics(true)?;
        let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
        let address = server.ready(SERVER_READY).await?;
        let metrics = server.ready(METRICS_READY).await?;
        let spy = TcpListener::bind(address).await?;
        fixture.client_config("client.yaml", address, true, Fault::None)?;
        let path = fixture.directory.path().join("client.yaml");
        let source = std::fs::read_to_string(&path)?.replace(
            "quiche_h3: true",
            "auto_h3: true\n  max_concurrent_flows: 1",
        );
        std::fs::write(path, source)?;
        let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
        let socks = client.ready(SOCKS_READY).await?;
        client.ready(HTTP_READY).await?;
        let first = UdpSocket::bind("127.0.0.1:0").await?;
        let second = UdpSocket::bind("127.0.0.1:0").await?;
        let (control, udp) = socks_udp(socks).await?;
        let mut buffer = [0; 1200];
        udp.send(&packet(first.local_addr()?, b"one slot")).await?;
        first.recv_from(&mut buffer).await?;
        udp.send(&packet(second.local_addr()?, b"over limit"))
            .await?;
        ensure!(
            timeout(Duration::from_millis(100), second.recv_from(&mut buffer))
                .await
                .is_err()
        );
        ensure!(soak::metrics(metrics).await?["active_flows"] == 1);
        drop(control);
        soak::wait_for_drained(metrics, true).await?;
        let (control, udp) = socks_udp(socks).await?;
        udp.send(&packet(second.local_addr()?, b"reused slot"))
            .await?;
        let (size, _) = second.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"reused slot");
        drop(control);
        soak::wait_for_drained(metrics, true).await?;
        // A native UDP open against a silent QUIC endpoint never tries H2.
        drop(server);
        let silent = UdpSocket::bind(address).await?;
        let mut config = maverick_core::ClientConfig::from_yaml_str(&std::fs::read_to_string(
            fixture.directory.path().join("client.yaml"),
        )?)?;
        config.server.ca_cert = Some(fixture.directory.path().join("ca.pem"));
        config.advanced.connect_timeout_ms = 200;
        ensure!(NativeUdpAssociation::open(
            &config,
            TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            second.local_addr()?.port()
        )
        .await
        .is_err());
        ensure!(
            timeout(Duration::from_millis(80), spy.accept())
                .await
                .is_err(),
            "native UDP fell back to H2"
        );
        drop(silent);
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("native UDP admission/cancellation test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_udp_drops_lost_packets_and_survives_packet_reordering() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::new()?;
        fixture.server_config(true)?;
        let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
        let address = server.ready(SERVER_READY).await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        fixture.client_config("client.yaml", socket.local_addr()?, true, Fault::None)?;
        let mut config = maverick_core::ClientConfig::from_yaml_str(&std::fs::read_to_string(fixture.directory.path().join("client.yaml"))?)?;
        config.server.ca_cert = Some(fixture.directory.path().join("ca.pem"));
        let mode = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let reordered = Arc::new(AtomicUsize::new(0));
        let (m, d, r) = (Arc::clone(&mode), Arc::clone(&dropped), Arc::clone(&reordered));
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let mut peer = None;
            let mut held = None;
            let mut buffer = [0; 2048];
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    received = socket.recv_from(&mut buffer) => {
                        let (size, from) = received?;
                        if from == address {
                            if let Some(peer) = peer { socket.send_to(&buffer[..size], peer).await?; }
                        } else {
                            peer = Some(from);
                            match m.load(Ordering::Relaxed) {
                                1 => { d.fetch_add(1, Ordering::Relaxed); }
                                2 if held.is_none() => { held = Some(buffer[..size].to_vec()); }
                                _ => {
                                    socket.send_to(&buffer[..size], address).await?;
                                    if let Some(packet) = held.take() {
                                        socket.send_to(&packet, address).await?;
                                        r.fetch_add(1, Ordering::Relaxed);
                                        m.store(0, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let association = NativeUdpAssociation::open(&config, TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await?;
        mode.store(1, Ordering::Relaxed);
        ensure!(association.send(b"lost".as_slice().into())?);
        let mut buffer = [0; 1200];
        ensure!(timeout(Duration::from_millis(250), target.recv_from(&mut buffer)).await.is_err());
        ensure!(dropped.load(Ordering::Relaxed) > 0);
        mode.store(0, Ordering::Relaxed);
        ensure!(association.send(b"delivered".as_slice().into())?);
        let (size, _) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"delivered", "lost UDP payload was retransmitted");
        mode.store(2, Ordering::Relaxed);
        ensure!(association.send(b"a".as_slice().into())?);
        tokio::time::sleep(Duration::from_millis(30)).await;
        ensure!(association.send(b"b".as_slice().into())?);
        // The relay reorders encrypted QUIC packets, without claiming which
        // frames share a packet. Both application datagrams must still arrive.
        let mut values = Vec::new();
        for _ in 0..2 {
            let (size, _) = target.recv_from(&mut buffer).await?;
            values.push(buffer[..size].to_vec());
        }
        values.sort();
        ensure!(values == [b"a".to_vec(), b"b".to_vec()]);
        ensure!(reordered.load(Ordering::Relaxed) > 0);
        ensure!(timeout(Duration::from_millis(150), target.recv_from(&mut buffer)).await.is_err());
        association.close().await?;
        let _ = stop.send(());
        relay.await??;
        Ok::<_, anyhow::Error>(())
    }).await.context("native UDP loss/reordering test timed out")?
}

pub(super) async fn socks_udp(proxy: SocketAddr) -> Result<(TcpStream, UdpSocket)> {
    let mut control = TcpStream::connect(proxy).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await?;
    ensure!(reply[..4] == [5, 0, 0, 1], "native UDP ASSOCIATE rejected");
    let address = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(address).await?;
    Ok((control, udp))
}

pub(super) fn packet(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 fixture")
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&ip.octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_native_udp_independent_replies_limits_and_cleanup() -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::for_transport(true, 2)?;
        fixture.server_config_with_metrics(false)?;
        let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
        let address = server.ready(SERVER_READY).await?;
        let metrics = server.ready(METRICS_READY).await?;
        fixture.client_config("client.yaml", address, false, Fault::None)?;
        let path = fixture.directory.path().join("client.yaml");
        let input = std::fs::read_to_string(&path)?.replacen(
            "advanced:\n",
            "advanced:\n  max_concurrent_flows: 2\n  udp_idle_timeout_ms: 1000\n",
            1,
        );
        std::fs::write(path, input)?;
        let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
        let socks = client.ready(SOCKS_READY).await?;
        client.ready(HTTP_READY).await?;
        let (control, udp) = socks_udp(socks).await?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let second = UdpSocket::bind("127.0.0.1:0").await?;
        let mut buffer = [0; 1400];
        // One upload, several independent replies, including an empty packet.
        udp.send(&packet(target.local_addr()?, b"one request"))
            .await?;
        let (size, peer) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"one request");
        for payload in [&b"first"[..], &b""[..], &b"third"[..]] {
            target.send_to(payload, peer).await?;
            let count = udp.recv(&mut buffer).await?;
            ensure!(&buffer[..count] == packet(target.local_addr()?, payload));
        }
        // The second destination has its own authenticated association.
        udp.send(&packet(second.local_addr()?, b"second target"))
            .await?;
        let (size, peer2) = second.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"second target");
        second.send_to(b"second reply", peer2).await?;
        let count = udp.recv(&mut buffer).await?;
        ensure!(&buffer[..count] == packet(second.local_addr()?, b"second reply"));
        // Oversize packets in either direction drop without corrupting the session.
        udp.send(&packet(target.local_addr()?, &[7; 1201])).await?;
        target.send_to(&[7; 1201], peer).await?;
        ensure!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        ensure!(timeout(Duration::from_millis(80), udp.recv(&mut buffer))
            .await
            .is_err());
        udp.send(&packet(target.local_addr()?, &[])).await?;
        let (size, _) = target.recv_from(&mut buffer).await?;
        ensure!(size == 0, "empty native datagram lost");
        // Idle associations release server slots while the SOCKS control remains open.
        soak::wait_for_drained(metrics, true).await?;
        udp.send(&packet(target.local_addr()?, b"after idle"))
            .await?;
        let (size, _) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"after idle");
        drop(control);
        soak::wait_for_drained(metrics, true).await?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        tokio::try_join!(
            async { echo(tcp.accept().await?.0).await },
            exchange(socks, tcp.local_addr()?, false, b"TCP after native UDP")
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("native UDP CLI test timed out")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_udp_sdk_authentication_and_egress_are_required() -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::for_transport(true, 8)?;
        fixture.server_config(true)?;
        let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
        let address = server.ready(SERVER_READY).await?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        for (index, fault) in [
            Fault::Secret,
            Fault::Ca,
            Fault::Hostname,
            Fault::Pin,
            Fault::None,
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("client-{index}.yaml");
            fixture.client_config(&name, address, true, fault)?;
            let mut config = maverick_core::ClientConfig::from_yaml_str(&std::fs::read_to_string(
                fixture.directory.path().join(name),
            )?)?;
            config.server.ca_cert = Some(fixture.directory.path().join(
                if matches!(fault, Fault::Ca) {
                    "wrong-ca.pem"
                } else {
                    "ca.pem"
                },
            ));
            let result = NativeUdpAssociation::open(
                &config,
                TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                target.local_addr()?.port(),
            )
            .await;
            if matches!(fault, Fault::None) {
                let mut association = result?;
                ensure!(!association.send(vec![0; association.max_payload() + 1].into())?);
                ensure!(association.send(b"authorized".as_slice().into())?);
                let mut buffer = [0; 1200];
                let (size, peer) = target.recv_from(&mut buffer).await?;
                ensure!(&buffer[..size] == b"authorized");
                target.send_to(&buffer[..size], peer).await?;
                ensure!(association.recv().await? == b"authorized"[..]);
                let maximum = vec![19; association.max_payload()];
                ensure!(association.send(maximum.clone().into())?);
                let (size, peer) = target.recv_from(&mut buffer).await?;
                ensure!(buffer[..size] == maximum);
                target.send_to(&buffer[..size], peer).await?;
                ensure!(association.recv().await?.as_ref() == maximum);
                association.close().await?;
            } else {
                ensure!(
                    result.is_err(),
                    "native UDP accepted invalid identity/authentication"
                );
            }
        }
        drop(server);
        let mut denied = maverick_core::ServerConfig::from_yaml_str(&std::fs::read_to_string(
            fixture.directory.path().join("server.yaml"),
        )?)?;
        denied.tls.cert_path = fixture.directory.path().join("cert.pem");
        denied.tls.key_path = fixture.directory.path().join("key.pem");
        denied.advanced.egress.allow_loopback = false;
        let server = maverick_server::start_server(denied).await?;
        fixture.client_config("denied.yaml", server.local_addr, true, Fault::None)?;
        let mut config = maverick_core::ClientConfig::from_yaml_str(&std::fs::read_to_string(
            fixture.directory.path().join("denied.yaml"),
        )?)?;
        config.server.ca_cert = Some(fixture.directory.path().join("ca.pem"));
        ensure!(
            NativeUdpAssociation::open(
                &config,
                TargetAddr::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                target.local_addr()?.port()
            )
            .await
            .is_err(),
            "native UDP bypassed egress policy"
        );
        server.shutdown().await?;
        let mut buffer = [0; 1];
        ensure!(
            timeout(Duration::from_millis(80), target.recv_from(&mut buffer))
                .await
                .is_err()
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("native UDP authentication test timed out")?
}
