//! Local experiment only: reframe the outer ClientHello in a transparent TCP
//! relay. Both modes use the same relay; neither terminates TLS or changes the
//! product client/server. Raw handshake bytes remain in memory and are not logged.
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use maverick_client::connector::{ProxyConnector, TargetAddr};
use maverick_client::transport::TransportKind;
use maverick_core::config::TlsFingerprintMode;
use maverick_core::SecretString;
use maverick_tests::fingerprint::parse_tls_client_hello;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

#[allow(dead_code)]
mod support;
use support::{HarnessOptions, MaverickHarness};

const DEADLINE: Duration = Duration::from_secs(15);
#[path = "support/handshake_experiment.rs"]
mod experiment;
use experiment::{drained, transfer, PAYLOAD_SIZE};
#[path = "support/client_hello.rs"]
mod client_hello;

#[derive(Clone, Copy, Debug, serde::Serialize)]
enum RecordMode {
    Unchanged,
    SplitAfterTwoBytes,
    SplitInsideSni,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
enum Inspection {
    None,
    FirstRecordOnly,
    Reassembled,
}

#[derive(Debug, serde::Serialize)]
struct Observation {
    input_lengths: Vec<usize>,
    output_lengths: Vec<usize>,
    extra_bytes: usize,
    inspection: Inspection,
    blocked: bool,
}

/// Intentionally limited to a single-record initial ClientHello from the test
/// TLS backends. Unsupported input fails the experiment, never silently bypasses
/// the transformation. All later bytes, including encrypted records, pass intact.
async fn forward_client_hello(
    client: &mut TcpStream,
    server: &mut TcpStream,
    mode: RecordMode,
    inspection: Inspection,
) -> Result<Observation> {
    let mut header = [0; 5];
    client.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    ensure!(header[0] == 22 && (4..=16_384).contains(&length));
    let mut original = header.to_vec();
    original.resize(5 + length, 0);
    client.read_exact(&mut original[5..]).await?;
    let before = parse_tls_client_hello(&original)?;
    ensure!(before.handshake_length + 4 == length);
    ensure!(before.server_name_present, "fixture must send SNI");

    let output = match mode {
        RecordMode::Unchanged => original.clone(),
        RecordMode::SplitAfterTwoBytes | RecordMode::SplitInsideSni => {
            let split = match mode {
                RecordMode::SplitInsideSni => {
                    let name = client_hello::sni_range(&original[5..])?;
                    name.start + name.len() / 2
                }
                _ => 2,
            };
            let mut output = Vec::with_capacity(original.len() + 5);
            for part in [&original[5..5 + split], &original[5 + split..]] {
                output.extend_from_slice(&header[..3]);
                output.extend_from_slice(&(part.len() as u16).to_be_bytes());
                output.extend_from_slice(part);
            }
            output
        }
    };

    // Check the exact reconstructed handshake, including random/key-share bytes,
    // independently of the fingerprint parser's normalized representation.
    let mut reconstructed = Vec::new();
    let mut cursor = 0;
    while cursor < output.len() {
        ensure!(output[cursor..cursor + 3] == header[..3]);
        let size = u16::from_be_bytes([output[cursor + 3], output[cursor + 4]]) as usize;
        reconstructed.extend_from_slice(&output[cursor + 5..cursor + 5 + size]);
        cursor += 5 + size;
    }
    ensure!(reconstructed == original[5..], "ClientHello bytes changed");
    let mut after = parse_tls_client_hello(&output)?;
    let observation = Observation {
        input_lengths: before.record_lengths.clone(),
        output_lengths: after.record_lengths.clone(),
        extra_bytes: output.len() - original.len(),
        inspection,
        // These are intentionally simple local models, not OpenGFW or a claim
        // about any deployed censor. Both block the fixture's SNI when parsed.
        blocked: match inspection {
            Inspection::None => false,
            Inspection::FirstRecordOnly => {
                let first = 5 + after.record_lengths[0];
                parse_tls_client_hello(&output[..first])
                    .is_ok_and(|hello| hello.server_name_present)
            }
            Inspection::Reassembled => after.server_name_present,
        },
    };
    after.record_lengths.clone_from(&before.record_lengths);
    ensure!(before == after, "handshake observation changed");
    match mode {
        RecordMode::Unchanged => {
            ensure!(observation.output_lengths == [length]);
            ensure!(observation.extra_bytes == 0);
        }
        RecordMode::SplitAfterTwoBytes => {
            ensure!(observation.output_lengths == [2, length - 2]);
            ensure!(observation.extra_bytes == 5);
        }
        RecordMode::SplitInsideSni => {
            let name = client_hello::sni_range(&reconstructed)?;
            ensure!(name.start < observation.output_lengths[0]);
            ensure!(observation.output_lengths[0] < name.end);
            ensure!(observation.extra_bytes == 5);
        }
    }
    // TLS record boundaries, not assumptions about TCP write/packet boundaries.
    if !observation.blocked {
        server.write_all(&output).await?;
    }
    Ok(observation)
}

struct RecordRelay {
    address: SocketAddr,
    observation: oneshot::Receiver<Observation>,
    tasks: JoinSet<Result<()>>,
}

impl RecordRelay {
    async fn start(origin: SocketAddr, mode: RecordMode) -> Result<Self> {
        Self::with_inspection(origin, mode, Inspection::None).await
    }

    async fn with_inspection(
        origin: SocketAddr,
        mode: RecordMode,
        inspection: Inspection,
    ) -> Result<Self> {
        ensure!(origin.ip() == Ipv4Addr::LOCALHOST && origin.port() != 0);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (observed, observation) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut client, peer) = listener.accept().await?;
            ensure!(peer.ip() == Ipv4Addr::LOCALHOST);
            // One physical H2 connection per case. The listener stays owned until
            // completion so accidental reconnects cannot hit a reused port.
            let mut server = TcpStream::connect(origin).await?;
            let result = forward_client_hello(&mut client, &mut server, mode, inspection).await?;
            let blocked = result.blocked;
            let _ = observed.send(result);
            if blocked {
                return Ok(());
            }
            let copied = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            drop(listener);
            match copied {
                Ok(_) => Ok(()),
                // A TLS denial or cancelled stream may close the transport abruptly.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        });
        Ok(Self {
            address,
            observation,
            tasks,
        })
    }

    async fn finish(mut self) -> Result<Observation> {
        let observed = (&mut self.observation)
            .await
            .context("ClientHello not forwarded")?;
        self.tasks
            .join_next()
            .await
            .context("missing relay task")???;
        // Completion, not abort, must release the experiment's listener.
        let _rebound = TcpListener::bind(self.address).await?;
        Ok(observed)
    }
}

async fn harness(backend: TlsFingerprintMode, v2: bool) -> Result<MaverickHarness> {
    MaverickHarness::start_with_options(HarnessOptions {
        metrics: true,
        client_tls_fingerprint: Some(backend),
        auth_channel_binding_require: true,
        auth_v2_epoch: v2.then_some(7),
        client_connect_timeout_ms: Some(3_000),
        server_handshake_timeout_ms: Some(3_000),
        ..Default::default()
    })
    .await
}

fn backends() -> Vec<TlsFingerprintMode> {
    let backends = vec![TlsFingerprintMode::RustlsDefault];
    #[cfg(feature = "browser-tls")]
    let backends = {
        let mut backends = backends;
        backends.push(TlsFingerprintMode::BrowserMimic);
        backends
    };
    backends
}

#[tokio::test]
async fn default_and_fragmented_records_preserve_full_sessions() -> Result<()> {
    for backend in backends() {
        for v2 in [false, true] {
            for mode in [
                RecordMode::Unchanged,
                RecordMode::SplitAfterTwoBytes,
                RecordMode::SplitInsideSni,
            ] {
                timeout(DEADLINE, async {
                    let origin = harness(backend, v2).await?;
                    let relay = RecordRelay::start(origin.server.local_addr, mode).await?;
                    let mut config = origin.client_config();
                    config.server.address = relay.address.to_string();
                    config.server.cert_pin = Some(origin.cert_pin());
                    let connector = ProxyConnector::new(config)?;
                    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                    for order in [None, Some(false), Some(true)] {
                        let session = connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await?;
                        transfer(session, &target, order, TransportKind::H2).await?;
                    }
                    // Cancellation after target admission must release the target too.
                    let session = connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await?;
                    let (mut peer, _) = target.accept().await?;
                    drop(session);
                    ensure!(peer.read(&mut [0; 1]).await? == 0);
                    let pool = connector.h2_pool_snapshot();
                    ensure!(pool.connections_created == 1 && pool.streams_opened == 4);
                    ensure!(pool.active_streams == 0);
                    connector.close();
                    let observed = relay.finish().await?;
                    let snapshot = drained(&origin).await?;
                    ensure!(snapshot["authenticated_sessions"] == 4 && snapshot["tcp_flows"] == 4);
                    ensure!(snapshot["unauthenticated_rejections"] == 0);
                    origin.shutdown().await?;
                    println!("backend={backend:?} auth_v2={v2} mode={mode:?} records={:?}->{:?} extra_bytes={} verified_bytes_each_direction={} authenticated_sessions=4 physical_h2_connections=1 half_close_orders=2 cancelled_sessions=1 resources_drained=true", observed.input_lengths, observed.output_lengths, observed.extra_bytes, 3 * PAYLOAD_SIZE);
                    Ok::<_, anyhow::Error>(())
                }).await.context("TLS record experiment timed out")??;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn default_and_fragmented_records_reject_invalid_identity_and_credentials() -> Result<()> {
    let files = tempfile::TempDir::new()?;
    let wrong_ca = files.path().join("unrelated-ca.pem");
    let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&wrong_ca, unrelated.cert.pem())?;
    for backend in backends() {
        for v2 in [false, true] {
            for mode in [
                RecordMode::Unchanged,
                RecordMode::SplitAfterTwoBytes,
                RecordMode::SplitInsideSni,
            ] {
                for fault in ["ca", "name", "pin", "credential"] {
                    timeout(DEADLINE, async {
                        let origin = harness(backend, v2).await?;
                        let relay = RecordRelay::start(origin.server.local_addr, mode).await?;
                        let mut config = origin.client_config();
                        config.server.address = relay.address.to_string();
                        config.server.cert_pin = Some(origin.cert_pin());
                        match fault {
                            "ca" => config.server.ca_cert = Some(wrong_ca.clone()),
                            "name" => config.server.server_name = "wrong.invalid".into(),
                            "pin" => config.server.cert_pin = Some("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
                            "credential" => config.server.secret = SecretString::generate(),
                            _ => unreachable!(),
                        }
                        let connector = ProxyConnector::new(config)?;
                        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                        ensure!(connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await.is_err(), "invalid identity/credential accepted");
                        ensure!(timeout(Duration::from_millis(60), target.accept()).await.is_err(), "rejected client reached target");
                        connector.close();
                        let observed = relay.finish().await?;
                        let snapshot = drained(&origin).await?;
                        ensure!(snapshot["authenticated_sessions"] == 0 && snapshot["tcp_flows"] == 0);
                        if fault == "credential" { ensure!(snapshot["unauthenticated_rejections"].as_u64().unwrap_or(0) > 0); }
                        origin.shutdown().await?;
                        println!("backend={backend:?} auth_v2={v2} mode={mode:?} rejected={fault} records={:?} target_connections=0 resources_drained=true", observed.output_lengths);
                        Ok::<_, anyhow::Error>(())
                    }).await.context("TLS rejection experiment timed out")??;
                }
            }
        }
    }
    Ok(())
}

async fn inspected_case(
    backend: TlsFingerprintMode,
    mode: RecordMode,
    inspection: Inspection,
) -> Result<bool> {
    timeout(DEADLINE, async {
        let origin = harness(backend, true).await?;
        let relay = RecordRelay::with_inspection(origin.server.local_addr, mode, inspection).await?;
        let mut config = origin.client_config();
        config.server.address = relay.address.to_string();
        config.server.cert_pin = Some(origin.cert_pin());
        let connector = ProxyConnector::new(config)?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let opened = connector.connect_tcp(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), target.local_addr()?.port()).await;
        let complete = opened.is_ok();
        if let Ok(session) = opened {
            transfer(session, &target, None, TransportKind::H2).await?;
        } else {
            ensure!(timeout(Duration::from_millis(60), target.accept()).await.is_err());
        }
        connector.close();
        let observation = relay.finish().await?;
        // A failed full session cannot be promoted merely for hiding the SNI.
        ensure!(complete != observation.blocked, "unexpected failure beyond the inspection model");
        let snapshot = drained(&origin).await?;
        ensure!(snapshot["authenticated_sessions"] == u64::from(complete));
        ensure!(snapshot["tcp_flows"] == u64::from(complete));
        origin.shutdown().await?;
        println!("{}", serde_json::json!({
            "experiment": "tls_record_feedback", "backend": format!("{backend:?}"),
            "candidate": mode, "observation": observation,
            "outcome": if complete { "complete_verified_session" } else { "blocked_by_local_inspection" },
            "verified_bytes_each_direction": if complete { PAYLOAD_SIZE } else { 0 },
            "resources_drained": true,
            "real_censor_evidence": false
        }));
        Ok::<_, anyhow::Error>(observation.blocked)
    }).await.context("inspection feedback experiment timed out")?
}

#[tokio::test]
async fn observed_first_record_failure_drives_candidates_with_reassembly_control() -> Result<()> {
    for backend in backends() {
        let blocked =
            inspected_case(backend, RecordMode::Unchanged, Inspection::FirstRecordOnly).await?;
        ensure!(
            blocked,
            "baseline must reproduce the intended local failure"
        );
        // A bounded, explicit candidate list selected for that observed failure.
        // The evaluator and identity rules are never mutable candidate inputs.
        for candidate in [RecordMode::SplitAfterTwoBytes, RecordMode::SplitInsideSni] {
            ensure!(!inspected_case(backend, candidate, Inspection::FirstRecordOnly).await?);
            ensure!(
                inspected_case(backend, candidate, Inspection::Reassembled).await?,
                "reassembly control must still see the fixture's SNI"
            );
        }
    }
    Ok(())
}
