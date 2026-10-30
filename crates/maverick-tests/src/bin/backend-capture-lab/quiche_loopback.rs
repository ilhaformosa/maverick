//! A bounded, real-UDP local experiment. This is not a Maverick carrier or
//! B-001 qualification adapter. It accepts no addresses or external fixtures.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use boring::ssl::{SslContext, SslMethod};
use quiche::h3::{self, Header, NameValue};
use tempfile::TempDir;

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_PACKETS: usize = 512;
const MAX_ROUNDS: usize = 8_000;
const MAX_EVENTS: usize = 64;
const MAX_BODY: usize = 4_096;
const MAX_UDP: usize = 1_350;
const REQUEST: &[u8] = b"Maverick local H3 request";
const RESPONSE: &[u8] = b"Maverick local H3 response";

pub struct Report {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub datagrams_sent: usize,
}

pub(super) struct Endpoint {
    pub(super) socket: UdpSocket,
    pub(super) address: SocketAddr,
    pub(super) peer: SocketAddr,
    pub(super) conn: quiche::Connection,
    sent: usize,
    received: usize,
}

impl Endpoint {
    fn close(&mut self) -> Result<()> {
        self.conn.close(true, 0x100, b"")?;
        // Send the close before an overdue handshake timer can schedule probes
        // while the closing connection no longer processes acknowledgements.
        self.flush()?;
        Ok(())
    }

    fn tick(&mut self) -> Result<bool> {
        if self
            .conn
            .timeout_instant()
            .is_some_and(|at| at <= Instant::now())
        {
            self.conn.on_timeout();
        }
        let mut activity = false;
        // The extra byte detects oversized datagrams rather than parsing a
        // silently truncated prefix. Unrelated local senders fail the probe.
        let mut packet = [0; MAX_UDP + 1];
        loop {
            match self.socket.recv_from(&mut packet) {
                Ok((len, from)) => {
                    self.received += 1;
                    ensure!(self.received <= MAX_PACKETS, "UDP receive budget exhausted");
                    ensure!(
                        from == self.peer && len <= MAX_UDP,
                        "unexpected UDP peer or size"
                    );
                    let info = quiche::RecvInfo {
                        from,
                        to: self.address,
                    };
                    match self.conn.recv(&mut packet[..len], info) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(error) => return Err(error.into()),
                    }
                    activity = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let sent = self.flush()?;
        Ok(activity || sent)
    }

    fn flush(&mut self) -> Result<bool> {
        let mut activity = false;
        let mut packet = [0; MAX_UDP];
        loop {
            match self.conn.send(&mut packet) {
                Ok((len, info)) => {
                    self.sent += 1;
                    ensure!(
                        self.sent <= MAX_PACKETS,
                        "UDP send budget exhausted: sent={}, received={}, established={}, lost={}, closing={}, draining={}, bytes={}",
                        self.sent,
                        self.received,
                        self.conn.is_established(),
                        self.conn.stats().lost,
                        self.conn.local_error().is_some(),
                        self.conn.is_draining(),
                        len
                    );
                    ensure!(
                        info.to == self.peer && info.from == self.address,
                        "unexpected UDP path"
                    );
                    ensure!(
                        self.socket.send_to(&packet[..len], info.to)? == len,
                        "partial UDP send"
                    );
                    activity = true;
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(activity)
    }
}

pub(super) struct Pair {
    pub(super) client: Endpoint,
    pub(super) server: Endpoint,
    fixture: TempDir,
    deadline: Instant,
    rounds: usize,
}

impl Pair {
    fn new(trust_server: bool, hostname: &str) -> Result<Self> {
        // Force the same Boring 5 native linkage as the existing candidate
        // tests. quiche's optional Boring 4 wrapper remains disabled.
        let _boring = SslContext::builder(SslMethod::tls())?.build();
        let fixture = TempDir::new().context("create local certificate directory")?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_path = fixture.path().join("cert.pem");
        let key_path = fixture.path().join("key.pem");
        write_private(&cert_path, cert.cert.pem().as_bytes())?;
        write_private(&key_path, cert.key_pair.serialize_pem().as_bytes())?;
        let trust_path = fixture.path().join("trust.pem");
        let trust = if trust_server {
            cert.cert.pem()
        } else {
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?
                .cert
                .pem()
        };
        write_private(&trust_path, trust.as_bytes())?;

        let mut client_config = transport_config()?;
        client_config.verify_peer(true);
        client_config.load_verify_locations_from_file(path_text(&trust_path)?)?;
        let mut server_config = transport_config()?;
        server_config.load_cert_chain_from_pem_file(path_text(&cert_path)?)?;
        server_config.load_priv_key_from_pem_file(path_text(&key_path)?)?;
        Self::with_configs(fixture, hostname, client_config, server_config)
    }

    pub(super) fn with_configs(
        fixture: TempDir,
        hostname: &str,
        mut client_config: quiche::Config,
        mut server_config: quiche::Config,
    ) -> Result<Self> {
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        client_socket.set_nonblocking(true)?;
        server_socket.set_nonblocking(true)?;
        let client_address = client_socket.local_addr()?;
        let server_address = server_socket.local_addr()?;
        // Fixed IDs are confined to this one isolated pair, never reused by a
        // listener that accepts other connections.
        let client = quiche::connect(
            Some(hostname),
            &quiche::ConnectionId::from_ref(&[0x11; 16]),
            client_address,
            server_address,
            &mut client_config,
        )?;
        let server = quiche::accept(
            &quiche::ConnectionId::from_ref(&[0x22; 16]),
            None,
            server_address,
            client_address,
            &mut server_config,
        )?;
        Ok(Self {
            client: Endpoint {
                socket: client_socket,
                address: client_address,
                peer: server_address,
                conn: client,
                sent: 0,
                received: 0,
            },
            server: Endpoint {
                socket: server_socket,
                address: server_address,
                peer: client_address,
                conn: server,
                sent: 0,
                received: 0,
            },
            fixture,
            deadline: Instant::now() + DEADLINE,
            rounds: 0,
        })
    }

    fn begin_round(&mut self) -> Result<()> {
        self.rounds += 1;
        ensure!(
            Instant::now() < self.deadline && self.rounds <= MAX_ROUNDS,
            "loopback time or iteration budget exhausted"
        );
        Ok(())
    }

    pub(super) fn advance(&mut self) -> Result<()> {
        self.begin_round()?;
        let client = self.client.tick()?;
        let server = self.server.tick()?;
        if !client && !server {
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    pub(super) fn handshake(&mut self) -> Result<()> {
        while !self.client.conn.is_established() || !self.server.conn.is_established() {
            self.advance()?;
            ensure!(
                !self.client.conn.is_closed() && !self.server.conn.is_closed(),
                "connection closed before handshake completion"
            );
        }
        ensure!(
            self.client.conn.application_proto() == b"h3"
                && self.server.conn.application_proto() == b"h3",
            "unexpected ALPN"
        );
        ensure!(
            self.client.conn.peer_cert().is_some(),
            "missing verified peer certificate"
        );
        Ok(())
    }

    pub(super) fn receive(
        &mut self,
        h3: &mut h3::Connection,
        at_server: bool,
        expected_headers: &[Header],
        expected_body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut headers_seen = false;
        let mut body = Vec::new();
        let mut events = 0;
        loop {
            self.advance()?;
            let transport = if at_server {
                &mut self.server.conn
            } else {
                &mut self.client.conn
            };
            loop {
                let (stream, event) = match h3.poll(transport) {
                    Ok(event) => event,
                    Err(h3::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                };
                events += 1;
                ensure!(
                    events <= MAX_EVENTS && stream == 0,
                    "unexpected H3 event or stream"
                );
                match event {
                    h3::Event::Headers { list, .. } => {
                        ensure!(
                            !headers_seen && list.len() == expected_headers.len(),
                            "unexpected H3 headers"
                        );
                        for (got, expected) in list.iter().zip(expected_headers) {
                            ensure!(
                                got.name() == expected.name() && got.value() == expected.value(),
                                "H3 header mismatch"
                            );
                        }
                        headers_seen = true;
                    }
                    h3::Event::Data => loop {
                        let mut buf = [0; MAX_BODY];
                        match h3.recv_body(transport, stream, &mut buf) {
                            Ok(len) => {
                                ensure!(
                                    len > 0 && body.len() + len <= MAX_BODY,
                                    "H3 body budget exhausted"
                                );
                                body.extend_from_slice(&buf[..len]);
                            }
                            Err(h3::Error::Done) => break,
                            Err(error) => return Err(error.into()),
                        }
                    },
                    h3::Event::Finished => {
                        ensure!(
                            headers_seen && body == expected_body,
                            "incomplete H3 message"
                        );
                        return Ok(body);
                    }
                    _ => bail!("unexpected H3 event"),
                }
            }
        }
    }

    pub(super) fn into_parts(self) -> (Endpoint, Endpoint, TempDir) {
        (self.client, self.server, self.fixture)
    }

    fn close_connections(&mut self) -> Result<()> {
        self.begin_round()?;
        self.client.close()?; // H3_NO_ERROR
        while !self.client.conn.is_closed() || !self.server.conn.is_closed() {
            self.advance()?;
        }
        ensure!(
            self.server
                .conn
                .peer_error()
                .is_some_and(|error| error.is_app && error.error_code == 0x100),
            "server did not receive the clean H3 close"
        );
        Ok(())
    }

    pub(super) fn shutdown(mut self) -> Result<usize> {
        self.close_connections()?;
        let sent = self.client.sent + self.server.sent;
        // Close temporary files explicitly so a cleanup failure is reported.
        // All error exits also release sockets/connections and the TempDir via RAII.
        let (client, server, fixture) = self.into_parts();
        drop(client);
        drop(server);
        fixture
            .close()
            .context("remove temporary certificate directory")?;
        Ok(sent)
    }
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("create local certificate file")?
        .write_all(bytes)?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("local certificate path is not UTF-8")
}

fn transport_config() -> Result<quiche::Config> {
    configure_transport(quiche::Config::new(quiche::PROTOCOL_VERSION)?)
}

pub(super) fn configure_transport(mut config: quiche::Config) -> Result<quiche::Config> {
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(1_000);
    config.set_max_recv_udp_payload_size(MAX_UDP);
    config.set_max_send_udp_payload_size(MAX_UDP);
    config.set_initial_max_data(65_536);
    config.set_initial_max_stream_data_bidi_local(8_192);
    config.set_initial_max_stream_data_bidi_remote(8_192);
    config.set_initial_max_stream_data_uni(4_096);
    config.set_max_connection_window(65_536);
    config.set_max_stream_window(8_192);
    config.set_initial_max_streams_bidi(1);
    config.set_initial_max_streams_uni(3);
    config.set_disable_active_migration(true);
    config.enable_pacing(false); // Functional loopback probe, not a performance benchmark.
    Ok(config)
}

pub fn run() -> Result<Report> {
    exchange(Pair::new(true, "localhost")?)
}

fn exchange(mut pair: Pair) -> Result<Report> {
    pair.handshake()?;
    let mut config = h3::Config::new()?;
    config.set_max_field_section_size(4_096);
    let mut client_h3 = h3::Connection::with_transport(&mut pair.client.conn, &config)?;
    let mut server_h3 = h3::Connection::with_transport(&mut pair.server.conn, &config)?;
    let request = [
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"localhost"),
        Header::new(b":path", b"/loopback"),
    ];
    let stream = client_h3.send_request(&mut pair.client.conn, &request, false)?;
    ensure!(stream == 0, "unexpected request stream");
    ensure!(
        client_h3.send_body(&mut pair.client.conn, stream, REQUEST, true)? == REQUEST.len(),
        "partial request body"
    );
    pair.receive(&mut server_h3, true, &request, REQUEST)?;
    let response = [Header::new(b":status", b"200")];
    server_h3.send_response(&mut pair.server.conn, stream, &response, false)?;
    ensure!(
        server_h3.send_body(&mut pair.server.conn, stream, RESPONSE, true)? == RESPONSE.len(),
        "partial response body"
    );
    pair.receive(&mut client_h3, false, &response, RESPONSE)?;
    drop(client_h3);
    drop(server_h3);
    Ok(Report {
        request_bytes: REQUEST.len(),
        response_bytes: RESPONSE.len(),
        datagrams_sent: pair.shutdown()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_h3_roundtrip_over_udp() -> Result<()> {
        let pair = Pair::new(true, "localhost")?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(fixture.join("key.pem"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let report = exchange(pair)?;
        assert_eq!(report.request_bytes, REQUEST.len());
        assert_eq!(report.response_bytes, RESPONSE.len());
        assert!(report.datagrams_sent > 0 && report.datagrams_sent <= 2 * MAX_PACKETS);
        assert_released(addresses, &fixture)
    }

    #[test]
    fn rejects_untrusted_certificate_and_releases_resources() -> Result<()> {
        rejected_handshake(false, "localhost")
    }

    #[test]
    fn rejects_wrong_hostname_and_releases_resources() -> Result<()> {
        rejected_handshake(true, "wrong.localhost")
    }

    #[test]
    fn expired_budget_stops_before_io_and_releases_resources() -> Result<()> {
        let mut pair = Pair::new(true, "localhost")?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        pair.deadline = Instant::now();
        let error = pair.handshake().expect_err("expired probe continued");
        assert_eq!(
            error.to_string(),
            "loopback time or iteration budget exhausted"
        );
        assert_eq!(pair.client.sent + pair.server.sent, 0);
        drop(pair);
        assert_released(addresses, &fixture)
    }

    #[test]
    fn shutdown_after_handshake_pto_releases_resources() -> Result<()> {
        let mut pair = Pair::new(true, "localhost")?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        pair.handshake()?;
        let timeout = pair
            .client
            .conn
            .timeout_instant()
            .expect("pending handshake PTO");
        ensure!(
            timeout < pair.deadline,
            "handshake PTO exceeds probe deadline"
        );
        std::thread::sleep(
            timeout.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        pair.shutdown()?;
        assert_released(addresses, &fixture)
    }

    #[test]
    fn expired_shutdown_stops_before_io_and_releases_resources() -> Result<()> {
        let mut pair = Pair::new(true, "localhost")?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        pair.handshake()?;
        let sent = (pair.client.sent, pair.server.sent);
        pair.deadline = Instant::now();
        let error = pair
            .close_connections()
            .expect_err("expired probe sent a close");
        assert_eq!(
            error.to_string(),
            "loopback time or iteration budget exhausted"
        );
        assert_eq!((pair.client.sent, pair.server.sent), sent);
        drop(pair);
        assert_released(addresses, &fixture)
    }

    #[test]
    fn close_flushes_before_overdue_handshake_timer() -> Result<()> {
        let mut pair = Pair::new(true, "localhost")?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        pair.handshake()?;
        // Hold confirmation beyond the former one-turn shutdown workaround.
        let mut pending = Vec::new();
        let mut packet = [0; MAX_UDP + 1];
        while pending.is_empty() {
            ensure!(
                Instant::now() < pair.deadline,
                "confirmation deadline exhausted"
            );
            pair.server.tick()?;
            loop {
                match pair.client.socket.recv_from(&mut packet) {
                    Ok((len, from)) => {
                        ensure!(
                            from == pair.server.address && len <= MAX_UDP,
                            "unexpected confirmation packet"
                        );
                        ensure!(pending.len() < MAX_PACKETS, "too many confirmation packets");
                        pending.push(packet[..len].to_vec());
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if pending.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        pair.advance()?;
        let at = pair.client.conn.timeout_instant().expect("handshake PTO");
        let wake_at = at + Duration::from_millis(1);
        ensure!(
            wake_at < pair.deadline,
            "handshake PTO exceeds probe deadline"
        );
        std::thread::sleep(wake_at.saturating_duration_since(Instant::now()));
        // Confirmation arrives only after that turn, with the timer overdue.
        for packet in pending {
            ensure!(
                pair.server.socket.send_to(&packet, pair.client.address)? == packet.len(),
                "partial confirmation send"
            );
        }
        pair.client.close()?;
        while !pair.client.conn.is_closed() || !pair.server.conn.is_closed() {
            pair.advance()?;
        }
        ensure!(
            pair.server
                .conn
                .peer_error()
                .is_some_and(|error| error.is_app && error.error_code == 0x100),
            "server did not receive clean H3 close"
        );
        drop(pair);
        assert_released(addresses, &fixture)
    }

    fn rejected_handshake(trust_server: bool, hostname: &str) -> Result<()> {
        let mut pair = Pair::new(trust_server, hostname)?;
        let addresses = [pair.client.address, pair.server.address];
        let fixture = pair.fixture.path().to_owned();
        let error = pair
            .handshake()
            .expect_err("invalid peer identity was accepted");
        assert!(
            matches!(
                error.downcast_ref::<quiche::Error>(),
                Some(quiche::Error::TlsFail)
            ),
            "expected TLS verification failure, got {error}"
        );
        assert!(!pair.client.conn.is_established());
        drop(pair);
        assert_released(addresses, &fixture)
    }

    fn assert_released(addresses: [SocketAddr; 2], fixture: &Path) -> Result<()> {
        assert!(!fixture.exists());
        for address in addresses {
            drop(UdpSocket::bind(address).context("probe retained a UDP socket")?);
        }
        Ok(())
    }
}
