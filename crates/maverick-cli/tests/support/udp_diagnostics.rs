use super::native_udp::{packet, socks_udp};
use super::*;
use tokio::net::UdpSocket;

#[derive(Clone, Copy)]
enum Expected {
    OpenFailed,
    Replies(&'static str),
    SilentTarget(&'static str),
}

struct DiagnosticCase {
    name: &'static str,
    settings: &'static str,
    allowed: &'static str,
    expected: Expected,
    fault: Fault,
}

async fn next_event(events: &mut mpsc::UnboundedReceiver<String>) -> Result<String> {
    timeout(Duration::from_secs(8), events.recv())
        .await
        .context("timed out waiting for a SOCKS UDP diagnostic")?
        .context("CLI exited before its diagnostic")
}

impl DiagnosticCase {
    fn event(&self, id: u64, stage: &str, carrier: &str, reply: &str) -> String {
        format!(
            "{id} stage={stage} allowed={} carrier={carrier} target_reply={reply}",
            self.allowed
        )
    }

    async fn run(&self, fixture: &Fixture, server: SocketAddr) -> Result<()> {
        let filename = format!("{}.yaml", self.name);
        fixture.client_config(&filename, server, true, self.fault)?;
        let path = fixture.directory.path().join(&filename);
        let yaml = std::fs::read_to_string(&path)?;
        ensure!(yaml.contains("  quiche_h3: true"));
        std::fs::write(path, yaml.replace("  quiche_h3: true", self.settings))?;
        let (send, mut events) = mpsc::unbounded_channel();
        let mut client = Cli::spawn(
            fixture.directory.path(),
            "client",
            &filename,
            &["--diagnose-udp"],
            Some(send),
        )?;
        let socks = client.ready(SOCKS_READY).await?;
        client.ready(HTTP_READY).await?;
        let (control, local) = socks_udp(socks).await?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        local
            .send(&packet(target.local_addr()?, b"synthetic upload"))
            .await?;
        ensure!(
            next_event(&mut events).await? == self.event(1, "opening", "unknown", "not_observed"),
            "incorrect opening diagnostic"
        );
        let mut buffer = [0; 512];
        let carrier = match self.expected {
            Expected::Replies(carrier) | Expected::SilentTarget(carrier) => carrier,
            Expected::OpenFailed => {
                ensure!(
                    next_event(&mut events).await?
                        == self.event(1, "open_failed", "unknown", "not_observed"),
                    "failed session reported admission or receipt"
                );
                ensure!(
                    matches!(target.try_recv(&mut buffer), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
                );
                return Ok(());
            }
        };
        ensure!(
            next_event(&mut events).await? == self.event(1, "admitted", carrier, "not_observed"),
            "incorrect admitted carrier"
        );
        let (size, peer) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..size] == b"synthetic upload");

        // Two overlapping fixed-target sessions: the first target stays silent
        // while the second returns an empty datagram.
        if matches!(self.expected, Expected::SilentTarget(_)) {
            let second = UdpSocket::bind("127.0.0.1:0").await?;
            local
                .send(&packet(second.local_addr()?, b"second target"))
                .await?;
            ensure!(
                next_event(&mut events).await?
                    == self.event(2, "opening", "unknown", "not_observed")
            );
            ensure!(
                next_event(&mut events).await?
                    == self.event(2, "admitted", carrier, "not_observed")
            );
            let (size, second_peer) = second.recv_from(&mut buffer).await?;
            ensure!(&buffer[..size] == b"second target");
            second.send_to(b"", second_peer).await?;
            let n = local.recv(&mut buffer).await?;
            ensure!(buffer[..n] == packet(second.local_addr()?, b""));
            ensure!(
                next_event(&mut events).await? == self.event(2, "first_reply", carrier, "observed")
            );
            drop(control);
            let ends = [
                next_event(&mut events).await?,
                next_event(&mut events).await?,
            ];
            ensure!(
                ends.contains(&self.event(1, "ended", carrier, "not_observed"))
                    && ends.contains(&self.event(2, "ended", carrier, "observed"))
            );
            return Ok(());
        }

        for (i, response) in [b"first".as_slice(), b"second"].into_iter().enumerate() {
            if i != 0 {
                local.send(&packet(target.local_addr()?, b"again")).await?;
                let (size, from) = target.recv_from(&mut buffer).await?;
                ensure!(&buffer[..size] == b"again");
                target.send_to(response, from).await?;
            } else {
                target.send_to(response, peer).await?;
            }
            let n = local.recv(&mut buffer).await?;
            ensure!(buffer[..n] == packet(target.local_addr()?, response));
            if i == 0 {
                ensure!(
                    next_event(&mut events).await?
                        == self.event(1, "first_reply", carrier, "observed")
                );
            }
        }
        drop(control);
        ensure!(
            next_event(&mut events).await? == self.event(1, "ended", carrier, "observed"),
            "expected one first-reply event per session"
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_diagnose_udp_observes_admission_and_target_replies() -> Result<()> {
    let fixture = Fixture::for_transport(true, 16)?;
    let mut config = selection::server_config(&fixture)?;
    let (h3, tcp_guard) = selection::server_with_guard(config.clone(), TcpListener::bind).await?;
    config.advanced.quiche_h3 = false;
    let (h2, _silent_udp) = selection::server_with_guard(config, UdpSocket::bind).await?;
    let auto = "  auto_h3: true\n  udp_policy: allow_reliable";
    for (server, case) in [
        (
            h3.local_addr,
            DiagnosticCase {
                name: "healthy-auto",
                settings: auto,
                allowed: "h3_native,h2_reliable",
                expected: Expected::Replies("h3_native"),
                fault: Fault::None,
            },
        ),
        (
            h2.local_addr,
            DiagnosticCase {
                name: "fallback",
                settings: auto,
                allowed: "h3_native,h2_reliable",
                expected: Expected::Replies("h2_reliable"),
                fault: Fault::None,
            },
        ),
        (
            h2.local_addr,
            DiagnosticCase {
                name: "native-required",
                settings: "  auto_h3: true\n  udp_policy: native_required",
                allowed: "h3_native",
                expected: Expected::OpenFailed,
                fault: Fault::None,
            },
        ),
        (
            h3.local_addr,
            DiagnosticCase {
                name: "wrong-pin",
                settings: auto,
                allowed: "h3_native,h2_reliable",
                expected: Expected::OpenFailed,
                fault: Fault::Pin,
            },
        ),
        (
            h3.local_addr,
            DiagnosticCase {
                name: "fixed-h3-silent",
                settings: "  quiche_h3: true\n  udp_policy: allow_reliable",
                allowed: "h3_native",
                expected: Expected::SilentTarget("h3_native"),
                fault: Fault::None,
            },
        ),
        (
            h2.local_addr,
            DiagnosticCase {
                name: "fixed-reliable",
                settings: "  udp_policy: allow_reliable",
                allowed: "h2_reliable",
                expected: Expected::Replies("h2_reliable"),
                fault: Fault::None,
            },
        ),
        (
            h3.local_addr,
            DiagnosticCase {
                name: "auto-omitted",
                settings: "  auto_h3: true",
                allowed: "h3_native",
                expected: Expected::Replies("h3_native"),
                fault: Fault::None,
            },
        ),
        (
            h2.local_addr,
            DiagnosticCase {
                name: "legacy",
                settings: "",
                allowed: "h2_legacy",
                expected: Expected::Replies("h2_legacy"),
                fault: Fault::None,
            },
        ),
    ] {
        timeout(Duration::from_secs(20), case.run(&fixture, server))
            .await
            .context(case.name)?
            .with_context(|| case.name)?;
    }
    ensure!(
        timeout(Duration::from_millis(80), tcp_guard.accept())
            .await
            .is_err(),
        "unexpected H2 connection on H3 test port"
    );
    // No flag: exercise an actual exchange and drain the reader before checking
    // that the ordinary CLI emitted no session observations.
    let (send, mut events) = mpsc::unbounded_channel();
    let mut ordinary = Cli::spawn(
        fixture.directory.path(),
        "client",
        "legacy.yaml",
        &[],
        Some(send),
    )?;
    timeout(Duration::from_secs(8), async {
        let socks = ordinary.ready(SOCKS_READY).await?;
        ordinary.ready(HTTP_READY).await?;
        let (_control, local) = socks_udp(socks).await?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        local
            .send(&packet(target.local_addr()?, b"ordinary"))
            .await?;
        let mut buffer = [0; 128];
        let (n, peer) = target.recv_from(&mut buffer).await?;
        ensure!(&buffer[..n] == b"ordinary");
        target.send_to(b"reply", peer).await?;
        let n = local.recv(&mut buffer).await?;
        ensure!(buffer[..n] == packet(target.local_addr()?, b"reply"));
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("ordinary CLI timed out")??;
    drop(ordinary);
    ensure!(
        events.recv().await.is_none(),
        "ordinary CLI emitted UDP diagnostics"
    );
    h3.shutdown().await?;
    h2.shutdown().await
}
