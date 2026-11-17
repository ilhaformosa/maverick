//! Loopback-only observation of the actual product QUIC client and server.
#![cfg(feature = "experimental-h3")]
use anyhow::{ensure, Context, Result};
use maverick_client::connector::{ProxyConnector, TargetAddr, UdpCarrier};
use maverick_client::transport::TransportKind;
use maverick_core::config::{TlsFingerprintMode, UdpPolicy};
use maverick_core::SecretString;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

#[allow(dead_code)]
mod support;
use support::{HarnessOptions, MaverickHarness};
#[path = "support/client_hello.rs"]
mod client_hello;
#[path = "support/handshake_experiment.rs"]
mod experiment;
#[path = "support/quic_initial.rs"]
mod quic_initial;
use experiment::{drained, transfer, transfer_udp, udp_target, PAYLOAD_SIZE};
use quic_initial::{FlightSummary, InitialFlight};

#[derive(Clone, Copy, Debug, Serialize)]
enum Layout {
    Unchanged,
    ReverseFirstTwo,
}

#[derive(Serialize)]
struct RelayReport {
    ingress: FlightSummary,
    delivered: FlightSummary,
    first_flight_emission_order: Vec<usize>,
    dropped_initials: usize,
}

struct DatagramRelay {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    tasks: JoinSet<Result<RelayReport>>,
}

impl DatagramRelay {
    async fn start(origin: SocketAddr, layout: Layout, drop_first: bool) -> Result<Self> {
        ensure!(origin.ip() == Ipv4Addr::LOCALHOST);
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let (stop, mut stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut observer = InitialFlight::default();
            let mut delivered = InitialFlight::default();
            let mut pending = Vec::new();
            let mut first_count = 0;
            let mut emission_order = Vec::new();
            let mut dropped = 0;
            let mut client = None;
            let mut packet = [0; 65_536];
            loop {
                tokio::select! {
                    _ = &mut stopped => {
                        let ingress = observer.summary().cloned().context("ClientHello was not observed")?;
                        let delivered = delivered.summary().cloned().context("ClientHello was not delivered")?;
                        ensure!(ingress.hello_hash == delivered.hello_hash, "handshake content changed");
                        ensure!(ingress.datagram_lengths.len() == 2, "candidate requires the observed two-datagram flight");
                        ensure!(dropped == usize::from(drop_first));
                        let expected = if drop_first { vec![1] } else { match layout { Layout::Unchanged => vec![0, 1], Layout::ReverseFirstTwo => vec![1, 0] } };
                        ensure!(emission_order == expected);
                        if drop_first { ensure!(delivered.packets.iter().any(|packet| packet.packet_number > 1), "missing retransmitted Initial"); }
                        return Ok(RelayReport { ingress, delivered, first_flight_emission_order: emission_order, dropped_initials: dropped });
                    },
                    received = socket.recv_from(&mut packet) => {
                        let (length, from) = received?;
                        if from == origin {
                            socket.send_to(&packet[..length], client.context("response before client datagram")?).await?;
                        } else {
                            ensure!(from.ip() == Ipv4Addr::LOCALHOST);
                            if let Some(peer) = client { ensure!(peer == from, "one connection per case"); }
                            else { client = Some(from); }
                            let first_flight = observer.summary().is_none();
                            observer.observe(&packet[..length])?;
                            if first_flight {
                                let index = first_count;
                                first_count += 1;
                                ensure!(first_count <= 2, "first flight exceeds candidate scope");
                                if matches!(layout, Layout::ReverseFirstTwo) {
                                    pending.push(packet[..length].to_vec());
                                    if first_count == 1 {
                                        ensure!(observer.summary().is_none(), "no second fragment to reorder");
                                        continue;
                                    }
                                    ensure!(observer.summary().is_some(), "two fragments did not complete ClientHello");
                                    for index in [1, 0] {
                                        if drop_first && index == 0 { dropped += 1; continue; }
                                        delivered.observe(&pending[index])?;
                                        socket.send_to(&pending[index], origin).await?;
                                        emission_order.push(index);
                                    }
                                    pending.clear();
                                    continue;
                                }
                                if drop_first && index == 0 { dropped += 1; continue; }
                                emission_order.push(index);
                            }
                            delivered.observe(&packet[..length])?;
                            socket.send_to(&packet[..length], origin).await?;
                        }
                    }
                }
            }
        });
        Ok(Self {
            address,
            stop,
            tasks,
        })
    }

    async fn finish(mut self) -> Result<RelayReport> {
        let _ = self.stop.send(());
        let result = self
            .tasks
            .join_next()
            .await
            .context("missing UDP relay")???;
        let _rebound = UdpSocket::bind(self.address).await?;
        Ok(result)
    }
}

async fn harness(v2: bool) -> Result<MaverickHarness> {
    MaverickHarness::start_with_options(HarnessOptions {
        quiche_h3: true,
        metrics: true,
        client_tls_fingerprint: Some(TlsFingerprintMode::BrowserMimic),
        auth_channel_binding_require: true,
        auth_v2_epoch: v2.then_some(7),
        client_connect_timeout_ms: Some(3_000),
        server_handshake_timeout_ms: Some(3_000),
        ..Default::default()
    })
    .await
}

async fn run_case(
    layout: Layout,
    drop_first: bool,
    v2: bool,
    order: Option<bool>,
    fault: Option<&str>,
) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let origin = harness(v2).await?;
        let relay = DatagramRelay::start(origin.server.local_addr, layout, drop_first).await?;
        let mut config = origin.client_config();
        config.server.address = relay.address.to_string();
        config.server.cert_pin = Some(origin.cert_pin());
        let files = tempfile::TempDir::new()?;
        match fault {
            Some("ca") => {
                let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
                let path = files.path().join("unrelated-ca.pem");
                std::fs::write(&path, certificate.cert.pem())?;
                config.server.ca_cert = Some(path);
            },
            Some("name") => config.server.server_name = "wrong.invalid".into(),
            Some("pin") => config.server.cert_pin = Some("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            Some("credential") => config.server.secret = SecretString::generate(),
            None => {},
            Some(_) => anyhow::bail!("unknown experiment fault"),
        }
        let connector = ProxyConnector::new(config)?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let opened = connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await;
        if fault.is_some() {
            ensure!(opened.is_err(), "invalid identity/credential accepted");
            ensure!(timeout(Duration::from_millis(60), target.accept()).await.is_err());
        } else {
            let session = match opened {
                Ok(session) => session,
                Err(error) => {
                    connector.close();
                    let observed = relay.finish().await;
                    origin.shutdown().await?;
                    observed.context("Initial observer failed before session establishment")?;
                    return Err(error);
                }
            };
            transfer(session, &target, order, TransportKind::H3).await?;
        }
        connector.close();
        let snapshot = drained(&origin).await?;
        let accepted = u64::from(fault.is_none());
        ensure!(snapshot["authenticated_sessions"] == accepted && snapshot["tcp_flows"] == accepted);
        if fault == Some("credential") { ensure!(snapshot["unauthenticated_rejections"].as_u64().unwrap_or(0) > 0); }
        let report = relay.finish().await?;
        origin.shutdown().await?;
        println!("{}", serde_json::json!({
            "experiment":"quic_initial_layout", "candidate":layout, "drop_first_initial":drop_first,
            "auth_v2":v2, "target_first_half_close":order, "fault":fault, "report":report,
            "outcome":if fault.is_none() { "complete_verified_session" } else { "identity_or_authentication_rejected" },
            "verified_bytes_each_direction":if fault.is_none() { PAYLOAD_SIZE } else { 0 },
            "resources_drained":true, "real_censor_evidence":false
        }));
        Ok::<_, anyhow::Error>(())
    }).await.context("QUIC layout experiment timed out")?
}

#[tokio::test]
async fn product_quic_layout_comparison_preserves_full_sessions() -> Result<()> {
    for v2 in [false, true] {
        for order in [None, Some(false), Some(true)] {
            for layout in [Layout::Unchanged, Layout::ReverseFirstTwo] {
                run_case(layout, false, v2, order, None).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn product_quic_layout_comparison_recovers_missing_initial() -> Result<()> {
    for v2 in [false, true] {
        for layout in [Layout::Unchanged, Layout::ReverseFirstTwo] {
            run_case(layout, true, v2, None, None).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn product_quic_layout_comparison_preserves_rejections() -> Result<()> {
    for v2 in [false, true] {
        for fault in ["ca", "name", "pin", "credential"] {
            for layout in [Layout::Unchanged, Layout::ReverseFirstTwo] {
                run_case(layout, false, v2, None, Some(fault)).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn quic_layouts_preserve_native_udp_boundaries_and_cleanup() -> Result<()> {
    for v2 in [false, true] {
        for layout in [Layout::Unchanged, Layout::ReverseFirstTwo] {
            for drop_first in [false, true] {
                for cancel in [false, true] {
                    timeout(Duration::from_secs(15), async {
                        let origin = harness(v2).await?;
                        let relay = DatagramRelay::start(origin.server.local_addr, layout, drop_first).await?;
                        let mut config = origin.client_config();
                        config.server.address = relay.address.to_string();
                        config.server.cert_pin = Some(origin.cert_pin());
                        config.advanced.udp_policy = Some(UdpPolicy::NativeRequired);
                        let connector = ProxyConnector::new(config)?;
                        let target = udp_target().await?;
                        let session = match connector.open_udp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await {
                            Ok(session) => session,
                            Err(error) => {
                                connector.close();
                                let observed = relay.finish().await;
                                origin.shutdown().await?;
                                observed.context("Initial observer failed before UDP establishment")?;
                                return Err(error);
                            }
                        };
                        let session = transfer_udp(session, &target, UdpCarrier::H3Native, cancel).await?;
                        connector.close();
                        let snapshot = drained(&origin).await?;
                        ensure!(snapshot["authenticated_sessions"] == 1 && snapshot["tcp_flows"] == 0);
                        let report = relay.finish().await?;
                        origin.shutdown().await?;
                        println!("{}", serde_json::json!({"experiment":"quic_layout_udp", "candidate":layout, "drop_first_initial":drop_first, "auth_v2":v2, "session":session, "report":report, "resources_drained":true, "real_censor_evidence":false}));
                        Ok::<_, anyhow::Error>(())
                    }).await.context("QUIC UDP experiment timed out")??;
                }
            }
        }
    }
    Ok(())
}
