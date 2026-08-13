use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, Once, OnceLock};

use anyhow::{anyhow, ensure, Context, Result};
use boring::ssl::{SslContext, SslMethod};
use log::{Level, LevelFilter, Log, Metadata, Record};
use quiche::h3::{self, Header, NameValue};
use tempfile::TempDir;

const CLIENT_ADDR: &str = "127.0.0.1:41000";
const SERVER_ADDR: &str = "127.0.0.1:41001";
const MAX_PUMP_ROUNDS: usize = 256;
const MAX_PACKETS_PER_DIRECTION: usize = 256;
const MAX_H3_EVENTS: usize = 256;
const MAX_H3_BODY_BYTES: usize = 64;
const MAX_H3_HEADER_FIELDS: usize = 16;
const MAX_H3_HEADER_BYTES: usize = 4_096;
const MAX_LOG_RECORDS: usize = 4_096;
const MAX_FORMATS: usize = 8;
const CLIENT_CONTROL_STREAM: u64 = 2;

static LOGGER: HostileLogger = HostileLogger;
static LOGGER_INIT: Once = Once::new();
static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TRACE_RECORDS: AtomicUsize = AtomicUsize::new(0);
static DEBUG_RECORDS: AtomicUsize = AtomicUsize::new(0);
static LOG_RECORDS: AtomicUsize = AtomicUsize::new(0);
static LOG_BUDGET_ACTIVE: AtomicBool = AtomicBool::new(false);

struct HostileLogger;

impl Log for HostileLogger {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        if LOG_BUDGET_ACTIVE.load(Ordering::SeqCst) {
            let previous = LOG_RECORDS.fetch_add(1, Ordering::SeqCst);
            assert!(
                previous < MAX_LOG_RECORDS,
                "candidate logger exceeded its fixed record bound"
            );
        }
        let _ = record.args().to_string();
        match record.level() {
            Level::Trace => {
                TRACE_RECORDS.fetch_add(1, Ordering::SeqCst);
            }
            Level::Debug => {
                DEBUG_RECORDS.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    fn flush(&self) {}
}

struct CountedDisplay<'a> {
    formats: &'a AtomicUsize,
}

impl fmt::Display for CountedDisplay<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let previous = self.formats.fetch_add(1, Ordering::SeqCst);
        if previous >= MAX_FORMATS {
            return Err(fmt::Error);
        }
        out.write_str("peer-controlled-marker")
    }
}

struct LogBudgetGuard;

impl LogBudgetGuard {
    fn activate() -> Self {
        LOG_RECORDS.store(0, Ordering::SeqCst);
        LOG_BUDGET_ACTIVE.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for LogBudgetGuard {
    fn drop(&mut self) {
        LOG_BUDGET_ACTIVE.store(false, Ordering::SeqCst);
    }
}

struct Pair {
    _fixture: TempDir,
    client: quiche::Connection,
    server: quiche::Connection,
    client_h3: h3::Connection,
    server_h3: h3::Connection,
}

impl Pair {
    fn new() -> Result<Self> {
        let fixture = TempDir::new().context("create candidate fixture")?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .context("generate candidate certificate")?;
        let cert_path = fixture.path().join("cert.pem");
        let key_path = fixture.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).context("write candidate certificate")?;
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).context("write candidate key")?;

        let mut client_config = transport_config()?;
        client_config.verify_peer(false);
        let mut server_config = transport_config()?;
        server_config
            .load_cert_chain_from_pem_file(path_text(&cert_path)?)
            .context("load candidate certificate")?;
        server_config
            .load_priv_key_from_pem_file(path_text(&key_path)?)
            .context("load candidate key")?;

        let client_addr: SocketAddr = CLIENT_ADDR.parse()?;
        let server_addr: SocketAddr = SERVER_ADDR.parse()?;
        let client_id = quiche::ConnectionId::from_ref(&[0x11; 16]);
        let server_id = quiche::ConnectionId::from_ref(&[0x22; 16]);
        let mut client = quiche::connect(
            Some("localhost"),
            &client_id,
            client_addr,
            server_addr,
            &mut client_config,
        )?;
        let mut server = quiche::accept(
            &server_id,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )?;

        for _ in 0..MAX_PUMP_ROUNDS {
            pump(&mut client, &mut server)?;
            if client.is_established() && server.is_established() {
                break;
            }
        }
        ensure!(
            client.is_established(),
            "candidate client handshake incomplete"
        );
        ensure!(
            server.is_established(),
            "candidate server handshake incomplete"
        );

        let mut h3_config = h3::Config::new()?;
        h3_config.set_max_field_section_size(32_768);
        let client_h3 = h3::Connection::with_transport(&mut client, &h3_config)?;
        let server_h3 = h3::Connection::with_transport(&mut server, &h3_config)?;
        let mut pair = Self {
            _fixture: fixture,
            client,
            server,
            client_h3,
            server_h3,
        };
        pair.advance()?;
        pair.drain()?;
        Ok(pair)
    }

    fn advance(&mut self) -> Result<()> {
        pump(&mut self.client, &mut self.server)
    }

    fn drain(&mut self) -> Result<()> {
        drain_h3(&mut self.client_h3, &mut self.client)?;
        drain_h3(&mut self.server_h3, &mut self.server)
    }

    fn logging_surface(&mut self) -> Result<()> {
        let request = [
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", b"/candidate-logging"),
            Header::new(b"x-peer-controlled-request", b"client-literal-value"),
        ];
        ensure_headers_bounded(&request)?;
        let stream_id = self
            .client_h3
            .send_request(&mut self.client, &request, false)?;
        ensure!(stream_id == 0, "first candidate request was not stream 0");
        self.advance()?;
        expect_headers(
            &mut self.server_h3,
            &mut self.server,
            stream_id,
            b"x-peer-controlled-request",
            b"client-literal-value",
        )?;

        self.client_h3.send_priority_update_for_request(
            &mut self.client,
            stream_id,
            &h3::Priority::new(3, true),
        )?;
        self.advance()?;
        expect_priority_update_then_done(&mut self.server_h3, &mut self.server, stream_id)?;

        let request_body = b"client-peer-controlled-data";
        ensure!(
            request_body.len() <= MAX_H3_BODY_BYTES,
            "candidate request body exceeded its fixed byte bound"
        );
        ensure!(
            self.client_h3
                .send_body(&mut self.client, stream_id, request_body, true,)?
                == request_body.len(),
            "candidate request DATA was only partially buffered"
        );
        self.advance()?;
        expect_body(
            &mut self.server_h3,
            &mut self.server,
            stream_id,
            request_body,
        )?;

        let response = [
            Header::new(b":status", b"200"),
            Header::new(b"x-peer-controlled-response", b"server-literal-value"),
        ];
        ensure_headers_bounded(&response)?;
        self.server_h3
            .send_response(&mut self.server, stream_id, &response, false)?;
        self.advance()?;
        expect_headers(
            &mut self.client_h3,
            &mut self.client,
            stream_id,
            b"x-peer-controlled-response",
            b"server-literal-value",
        )?;

        let response_body = b"server-peer-controlled-data";
        ensure!(
            response_body.len() <= MAX_H3_BODY_BYTES,
            "candidate response body exceeded its fixed byte bound"
        );
        ensure!(
            self.server_h3
                .send_body(&mut self.server, stream_id, response_body, true,)?
                == response_body.len(),
            "candidate response DATA was only partially buffered"
        );
        self.advance()?;
        expect_body(
            &mut self.client_h3,
            &mut self.client,
            stream_id,
            response_body,
        )?;

        self.server_h3.send_goaway(&mut self.server, stream_id)?;
        self.advance()?;
        expect_goaway(&mut self.client_h3, &mut self.client, stream_id)?;

        self.client_h3.send_goaway(&mut self.client, 0)?;
        self.advance()?;
        expect_goaway(&mut self.server_h3, &mut self.server, 0)
    }

    fn send_fragmented_client_control(&mut self, frame: &[u8]) -> Result<()> {
        for byte in frame {
            ensure!(
                self.client
                    .stream_send(CLIENT_CONTROL_STREAM, &[*byte], false)?
                    == 1,
                "candidate control fragment was not fully buffered"
            );
            self.advance()?;
            ensure!(
                matches!(self.server_h3.poll(&mut self.server), Err(h3::Error::Done)),
                "pristine candidate unexpectedly surfaced a control event"
            );
            ensure!(
                self.server.local_error().is_none(),
                "pristine candidate rejected a fragmented push control frame"
            );
        }
        Ok(())
    }

    fn send_fragmented_server_request_data(&mut self, stream_id: u64, frame: &[u8]) -> Result<()> {
        for byte in frame {
            ensure!(
                self.server.stream_send(stream_id, &[*byte], false)? == 1,
                "candidate request-stream fragment was not fully buffered"
            );
            self.advance()?;
            ensure!(
                matches!(self.client_h3.poll(&mut self.client), Err(h3::Error::Done)),
                "pristine candidate unexpectedly surfaced a PUSH_PROMISE event"
            );
            ensure!(
                self.client.local_error().is_none(),
                "pristine candidate rejected a fragmented PUSH_PROMISE"
            );
        }
        Ok(())
    }
}

fn path_text(path: &std::path::Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("candidate path is not UTF-8"))
}

fn transport_config() -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_stream_data_uni(100_000);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.grease(false);
    Ok(config)
}

fn pump(client: &mut quiche::Connection, server: &mut quiche::Connection) -> Result<()> {
    for _ in 0..MAX_PUMP_ROUNDS {
        let client_sent = pump_one(client, server)?;
        let server_sent = pump_one(server, client)?;
        if !client_sent && !server_sent {
            return Ok(());
        }
    }
    Err(anyhow!("candidate transport pump exceeded its fixed bound"))
}

fn pump_one(from: &mut quiche::Connection, to: &mut quiche::Connection) -> Result<bool> {
    let mut packet = [0_u8; 65_535];
    let mut sent = false;
    for _ in 0..MAX_PACKETS_PER_DIRECTION {
        match from.send(&mut packet) {
            Ok((written, info)) => {
                sent = true;
                let recv = quiche::RecvInfo {
                    from: info.from,
                    to: info.to,
                };
                to.recv(&mut packet[..written], recv)?;
            }
            Err(quiche::Error::Done) => return Ok(sent),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!(
        "candidate direction packet pump exceeded its fixed bound"
    ))
}

fn drain_h3(h3_conn: &mut h3::Connection, transport: &mut quiche::Connection) -> Result<()> {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok(_) => {}
            Err(h3::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!("candidate H3 drain exceeded its fixed bound"))
}

fn ensure_headers_bounded(headers: &[Header]) -> Result<()> {
    ensure!(
        headers.len() <= MAX_H3_HEADER_FIELDS,
        "candidate H3 headers exceeded their fixed field bound"
    );
    let bytes = headers.iter().try_fold(0_usize, |total, header| {
        total
            .checked_add(header.name().len())
            .and_then(|value| value.checked_add(header.value().len()))
            .ok_or_else(|| anyhow!("candidate H3 header byte count overflowed"))
    })?;
    ensure!(
        bytes <= MAX_H3_HEADER_BYTES,
        "candidate H3 headers exceeded their fixed byte bound"
    );
    Ok(())
}

fn expect_headers(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_stream: u64,
    marker_name: &[u8],
    marker_value: &[u8],
) -> Result<()> {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                ensure!(stream_id == expected_stream, "unexpected H3 stream");
                ensure_headers_bounded(&list)?;
                ensure!(
                    list.iter().any(|header| {
                        header.name() == marker_name && header.value() == marker_value
                    }),
                    "expected H3 role marker was absent"
                );
                return Ok(());
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return Err(anyhow!("expected H3 headers were absent")),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!("candidate H3 header wait exceeded its fixed bound"))
}

fn expect_priority_update_then_done(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_stream: u64,
) -> Result<()> {
    ensure!(
        matches!(
            h3_conn.poll(transport),
            Ok((stream_id, h3::Event::PriorityUpdate)) if stream_id == expected_stream
        ),
        "candidate request PRIORITY_UPDATE was absent"
    );
    ensure!(
        matches!(h3_conn.poll(transport), Err(h3::Error::Done)),
        "candidate request PRIORITY_UPDATE did not drain to Done"
    );
    ensure!(
        h3_conn.take_last_priority_update(expected_stream)? == b"u=3,i",
        "candidate request PRIORITY_UPDATE value changed"
    );
    Ok(())
}

fn expect_body(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_stream: u64,
    expected: &[u8],
) -> Result<()> {
    ensure!(
        expected.len() <= MAX_H3_BODY_BYTES,
        "candidate expected DATA exceeded its fixed byte bound"
    );
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((stream_id, h3::Event::Data)) => {
                ensure!(stream_id == expected_stream, "unexpected H3 DATA stream");
                let mut body = [0_u8; MAX_H3_BODY_BYTES];
                let received = h3_conn.recv_body(transport, stream_id, &mut body)?;
                ensure!(received == expected.len(), "unexpected H3 DATA length");
                ensure!(
                    body[..received] == *expected,
                    "candidate H3 DATA bytes changed"
                );
                return Ok(());
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return Err(anyhow!("expected H3 DATA was absent")),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!("candidate H3 DATA wait exceeded its fixed bound"))
}

fn expect_goaway(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_id: u64,
) -> Result<()> {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((id, h3::Event::GoAway)) => {
                ensure!(id == expected_id, "candidate GOAWAY id changed");
                return Ok(());
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return Err(anyhow!("expected H3 GOAWAY was absent")),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!("candidate H3 GOAWAY wait exceeded its fixed bound"))
}

fn install_hostile_logger() -> &'static Mutex<()> {
    LOGGER_INIT.call_once(|| {
        log::set_logger(&LOGGER).expect("install candidate logger once");
        log::set_max_level(LevelFilter::Trace);
    });
    LOG_LOCK.get_or_init(|| Mutex::new(()))
}

fn encode_varint(value: u64) -> Vec<u8> {
    let width = if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < 1_073_741_824 {
        4
    } else {
        8
    };
    let mut out = value.to_be_bytes()[8 - width..].to_vec();
    out[0] |= match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    out
}

fn h3_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = encode_varint(frame_type);
    frame.extend_from_slice(&encode_varint(payload.len() as u64));
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn candidate_h3_logging_surface_is_complete_for_both_roles() -> Result<()> {
    let _serial = install_hostile_logger()
        .lock()
        .map_err(|_| anyhow!("candidate logger lock poisoned"))?;
    ensure!(
        log::STATIC_MAX_LEVEL == LevelFilter::Debug,
        "candidate static log cap was not Debug"
    );
    TRACE_RECORDS.store(0, Ordering::SeqCst);
    DEBUG_RECORDS.store(0, Ordering::SeqCst);
    let _log_budget = LogBudgetGuard::activate();

    let formats = AtomicUsize::new(0);
    log::trace!("{}", CountedDisplay { formats: &formats });
    log::debug!("{}", CountedDisplay { formats: &formats });
    ensure!(
        formats.load(Ordering::SeqCst) == 1,
        "Trace formatting was not eliminated or Debug formatting was absent"
    );
    ensure!(
        TRACE_RECORDS.load(Ordering::SeqCst) == 0,
        "Trace reached logger"
    );
    ensure!(
        DEBUG_RECORDS.load(Ordering::SeqCst) == 1,
        "Debug was not delivered"
    );

    let _boring = SslContext::builder(SslMethod::tls())?.build();
    let mut pair = Pair::new()?;
    ensure!(
        pair.client_h3.peer_settings_raw() == Some(&[(6, 32_768)][..]),
        "candidate client did not process the exact server SETTINGS"
    );
    ensure!(
        pair.server_h3.peer_settings_raw() == Some(&[(6, 32_768)][..]),
        "candidate server did not process the exact client SETTINGS"
    );
    pair.logging_surface()?;
    ensure!(
        TRACE_RECORDS.load(Ordering::SeqCst) == 0,
        "real two-role H3 emitted a Trace record"
    );
    ensure!(
        LOG_RECORDS.load(Ordering::SeqCst) <= MAX_LOG_RECORDS,
        "candidate logger exceeded its fixed record bound"
    );
    ensure!(
        formats.load(Ordering::SeqCst) <= MAX_FORMATS,
        "candidate formatting exceeded its fixed bound"
    );
    Ok(())
}

#[test]
fn pristine_upstream_accepts_fragmented_push_control_frames() -> Result<()> {
    let mut max_push_pair = Pair::new()?;
    max_push_pair.send_fragmented_client_control(&h3_frame(0x0d, &[0x01]))?;

    let mut cancel_push_pair = Pair::new()?;
    cancel_push_pair.send_fragmented_client_control(&h3_frame(0x03, &[0x01]))?;

    let mut priority_push_pair = Pair::new()?;
    let mut priority_payload = encode_varint(3);
    priority_payload.extend_from_slice(b"u=3");
    priority_push_pair.send_fragmented_client_control(&h3_frame(0x0f0701, &priority_payload))?;
    Ok(())
}

#[test]
fn pristine_upstream_accepts_fragmented_push_promise() -> Result<()> {
    let mut pair = Pair::new()?;
    let request = [
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"localhost"),
        Header::new(b":path", b"/push-witness"),
    ];
    ensure!(
        pair.client_h3
            .send_request(&mut pair.client, &request, true)?
            == 0,
        "first request stream was not zero"
    );
    pair.advance()?;
    expect_headers(
        &mut pair.server_h3,
        &mut pair.server,
        0,
        b":path",
        b"/push-witness",
    )?;

    // QPACK prefix (Required Insert Count=0, Base=0) plus static :method GET.
    let mut payload = encode_varint(1);
    payload.extend_from_slice(&[0x00, 0x00, 0xd1]);
    pair.send_fragmented_server_request_data(0, &h3_frame(0x05, &payload))?;
    Ok(())
}

#[test]
fn pristine_upstream_rejects_fragmented_push_stream_with_fixed_wire_error() -> Result<()> {
    let mut pair = Pair::new()?;
    let push_stream = [0x01, 0x00];
    for byte in push_stream {
        ensure!(
            pair.server.stream_send(15, &[byte], false)? == 1,
            "candidate push-stream fragment was not fully buffered"
        );
        pair.advance()?;
        let _ = pair.client_h3.poll(&mut pair.client);
        if pair.client.local_error().is_some() {
            break;
        }
    }
    let error = pair
        .client
        .local_error()
        .context("pristine candidate did not reject the push stream")?;
    ensure!(
        error.is_app,
        "push-stream rejection was not an application error"
    );
    ensure!(
        error.error_code == 0x103,
        "push-stream error was not H3_STREAM_CREATION_ERROR"
    );
    ensure!(
        !error.reason.is_empty(),
        "push-stream rejection reason was empty"
    );
    Ok(())
}
