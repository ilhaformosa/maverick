#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use boring::ssl::{SslContext, SslMethod};
use quiche::h3::{self, Header, NameValue};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CLIENT_ADDR: &str = "127.0.0.1:42000";
const SERVER_ADDR: &str = "127.0.0.1:42001";
const CLIENT_CONTROL_STREAM: u64 = 2;
const SERVER_CONTROL_STREAM: u64 = 3;
const CLIENT_PUSH_STREAM: u64 = 14;
const SERVER_PUSH_STREAM: u64 = 15;
const MAX_PUMP_ROUNDS: usize = 256;
const MAX_PACKETS_PER_DIRECTION: usize = 256;
const MAX_H3_EVENTS: usize = 256;
const MAX_BODY_BYTES: usize = 64;
const EXPECTED_SETTINGS: &[(u64, u64)] = &[(6, 32_768)];

const CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC1TCCAb2gAwIBAgIJAObgR14+qghMMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
BAMMD2ZpeHR1cmUuaW52YWxpZDAeFw0yNjA4MTMxMDQ0MDlaFw0zNjA4MTAxMDQ0
MDlaMBoxGDAWBgNVBAMMD2ZpeHR1cmUuaW52YWxpZDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAO3F0cMMURzX6TjWyUUVB7B5IykVIui6MjkSpdhuH7O6
VS21eJBt2EaZpfEqO4i6B4P+YrzOqvSY0FfusmJ2mGTaGWlagsKwbHB/JE/wWKj6
XRjy0i997p9Q+2r7nDn0LB4UO0t/6x0Fco71yf0bSkAY9vp9dcXDDajt+heRdlGv
fk2phFuut+MaiOPl+ASBzpJJoodRX5kh6Z7FPnub64rSxD3OCsXrXQ9FXYdz5/wV
HHA4+DgGb/o3ufQ8rC4jwXH8odbiTnxGUMg/Cdi3dQv6Tsf/BEfU1Kj4/MxAAbfM
tVBY1PO7I4vrlyinCT1szSUzw2IkLVY7mNw68U3At60CAwEAAaMeMBwwGgYDVR0R
BBMwEYIPZml4dHVyZS5pbnZhbGlkMA0GCSqGSIb3DQEBCwUAA4IBAQCPoAe83AUH
Y6Kz/QADY3FZOTLwAlS613Yf9+X45Tpj6ovuIr9hOp7ft5AViS2TPQ1m8VbZTF11
l+LiFRQ9uIsLsI0LGuwQ1PbGO8VAlbFEa4rQGI41ChMbhU6rihQRykz9A+nGpLVV
Y37rNnTwk/OiSkD4AdBT78sD5xGgA8g7lClgLrR7HOIu8j0DjnG7C1p6nIunXbez
/E5LYwuExx8LXgeQt5ug2Ak7TcuGHpbBGN98jO0mH357oPgaeBijwPRu9XhGeaCo
l19MorTL1qJIeX7FvBeRfm+7Iho2ZZnDtgna3lKL9K8W6RmdcfR5XDxVbvQj1QUK
0Nzkd08Pr9P3
-----END CERTIFICATE-----
"#;

const PRIVATE_KEY_BODY: &str = r#"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDtxdHDDFEc1+k4
1slFFQeweSMpFSLoujI5EqXYbh+zulUttXiQbdhGmaXxKjuIugeD/mK8zqr0mNBX
7rJidphk2hlpWoLCsGxwfyRP8Fio+l0Y8tIvfe6fUPtq+5w59CweFDtLf+sdBXKO
9cn9G0pAGPb6fXXFww2o7foXkXZRr35NqYRbrrfjGojj5fgEgc6SSaKHUV+ZIeme
xT57m+uK0sQ9zgrF610PRV2Hc+f8FRxwOPg4Bm/6N7n0PKwuI8Fx/KHW4k58RlDI
PwnYt3UL+k7H/wRH1NSo+PzMQAG3zLVQWNTzuyOL65copwk9bM0lM8NiJC1WO5jc
OvFNwLetAgMBAAECggEAW6YNVV4xAaojhjob+FnDzfzTVamE/CmQ5DjQ3hyMca1X
2beCEkGUxJnCwbNioS/7Z6AtFNOgR4mDfPFPpu5JjU4Xz2kIz9xK4A3RxFJDClb+
fXhTFeU3jgcb8b+sFxaLzshDlrVmvZf08S/CPKJBO3Wj9SdYtvKZGE0qQd1aut7o
zCgJN8p+h3FM1ObHCjSjIs9GZ20tfM216rlez08XDS7C9vAhnMLnr1ho55Bi1QAF
79BImkrI7lkTm54TvawKLCsXHoLr2UmgkraQfjF0qxWX30j9ozwv56nHd5XotZxX
urkaDAfoMsYGbEPRThuL+G6ZNS60QREEsSvdkcgv4QKBgQD+CeH6W/Zzz7s7KUQg
NeqGqg+AfUHGGL6RHmtv2VzZADe03hx/20kluEXYrT5oS9Ar6O/lTF6MAY1P054m
NycIVvMpRsRz+RRgLNHWXiNzkW/pMrPEv9tchb7QFl2Anv6nlOf4tM1b+rFP25U4
oozp9pbtUFyovJeM6JQY932weQKBgQDvm8lZatS/+h6dQAMpjLOfboLdK5lnw1e8
GIsVmMBr8+RMZRV9nIYuMj2MQCf0mlchjzKxgTj4LXb75AUZGHuinZ+lkBX3K30o
RVXMlCCB+Y9c7gfGhDI6wZuSt7cbTcFsSJoRfVNXmQdaKGlouu43ZcHW/m8fgPN9
ufuE2Ek71QKBgQC5n2EGvdGsN9q4VOPZoWvXsEWZfmzkIcqFYTPhy3LDgRwzRaSP
bBzbufUXaSdTsCnRG+jGpHHlXXDzJk7F38DeoCIXRAViNFtGFxnQyIKg/GFIhWrD
1eikh3mwtNbnl8W9j9mcaggwMFMFZg54DpZmkm8fwnuiNAOMy5kDUTv/CQKBgQC8
qirhqFe6jeQbJ3MV/T7WE3shURoqdMqZRa4GJE+m8NRbPuCsFlok99Q0obOUSw6+
UvW0hK5p48qjTgihmQCIq5owEALrqyeSVP3Y5u2tyeYTYy1mJ2Mxlo67+MJJ0nCx
pX0Ctm6wM8NxPw64sy+tGQeHFLJE2RFgdtfP40nOvQKBgQCQ2mJ+rTYKiijvNTNq
7YHkJN6GOGQXOWc08RNDUl+b/II7EWgQywqE9KwFTynK2HFPGnOyIMjFP/wfFets
88VL4wmNDB+kH2xx6camGkEj2DenYdMtak0sVlyaMCSaW3e+cvcTBtFuhGCkisSV
5n6Mi3iyXcNaUtzwggMLh3c9Sg==
"#;

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug)]
enum GateMode {
    Omitted,
    ExplicitFalse,
    Enabled,
}

#[derive(Clone, Copy, Debug)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Copy, Debug)]
enum Surface {
    MaxPushId,
    CancelPush,
    PushPromise,
    PriorityUpdatePush,
    PushStream,
}

const DIRECTIONS: [Direction; 2] = [Direction::ClientToServer, Direction::ServerToClient];
const SURFACES: [Surface; 5] = [
    Surface::MaxPushId,
    Surface::CancelPush,
    Surface::PushPromise,
    Surface::PriorityUpdatePush,
    Surface::PushStream,
];

fn fail<T>(message: impl Into<String>) -> TestResult<T> {
    Err(std::io::Error::other(message.into()).into())
}

fn check(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        fail(message)
    }
}

struct FixtureDir {
    root: PathBuf,
}

impl FixtureDir {
    fn new() -> TestResult<Self> {
        for _ in 0..16 {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "maverick-quiche-p1-{}-{serial}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                    let fixture = Self { root };
                    fixture.write_file("cert.pem", CERTIFICATE_PEM.as_bytes())?;
                    let private_key_pem = private_key_pem();
                    fixture.write_file("key.pem", private_key_pem.as_bytes())?;
                    return Ok(fixture);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        fail("could not allocate the bounded certificate fixture")
    }

    fn write_file(&self, name: &str, bytes: &[u8]) -> TestResult {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.root.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Pair {
    _fixture: FixtureDir,
    client: quiche::Connection,
    server: quiche::Connection,
    client_h3: h3::Connection,
    server_h3: h3::Connection,
}

impl Pair {
    fn new(mode: GateMode) -> TestResult<Self> {
        let fixture = FixtureDir::new()?;
        let mut client_config = transport_config()?;
        client_config.verify_peer(false);
        let mut server_config = transport_config()?;
        server_config.load_cert_chain_from_pem_file(path_text(&fixture.path("cert.pem"))?)?;
        server_config.load_priv_key_from_pem_file(path_text(&fixture.path("key.pem"))?)?;

        let client_addr: SocketAddr = CLIENT_ADDR.parse()?;
        let server_addr: SocketAddr = SERVER_ADDR.parse()?;
        let client_id = quiche::ConnectionId::from_ref(&[0x11; 16]);
        let server_id = quiche::ConnectionId::from_ref(&[0x22; 16]);
        let mut client = quiche::connect(
            Some("fixture.invalid"),
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
        check(client.is_established(), "client handshake did not finish")?;
        check(server.is_established(), "server handshake did not finish")?;

        let client_h3_config = h3_config(mode)?;
        let server_h3_config = h3_config(mode)?;
        let client_h3 = h3::Connection::with_transport(&mut client, &client_h3_config)?;
        let server_h3 = h3::Connection::with_transport(&mut server, &server_h3_config)?;
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

    fn advance(&mut self) -> TestResult {
        pump(&mut self.client, &mut self.server)
    }

    fn drain(&mut self) -> TestResult {
        drain_h3(&mut self.client_h3, &mut self.client)?;
        drain_h3(&mut self.server_h3, &mut self.server)
    }

    fn stream_send(&mut self, direction: Direction, stream_id: u64, bytes: &[u8]) -> TestResult {
        let written = match direction {
            Direction::ClientToServer => self.client.stream_send(stream_id, bytes, false)?,
            Direction::ServerToClient => self.server.stream_send(stream_id, bytes, false)?,
        };
        check(
            written == bytes.len(),
            "raw H3 input was only partially sent",
        )?;
        self.advance()
    }

    fn poll_receiver(&mut self, direction: Direction) -> Result<(u64, h3::Event), h3::Error> {
        match direction {
            Direction::ClientToServer => self.server_h3.poll(&mut self.server),
            Direction::ServerToClient => self.client_h3.poll(&mut self.client),
        }
    }

    fn expect_receiver_done(&mut self, direction: Direction) -> TestResult {
        match self.poll_receiver(direction) {
            Err(h3::Error::Done) => Ok(()),
            value => fail(format!("receiver was not Done: {value:?}")),
        }
    }

    fn assert_no_wire_error(&self, direction: Direction) -> TestResult {
        let (receiver, sender) = match direction {
            Direction::ClientToServer => (&self.server, &self.client),
            Direction::ServerToClient => (&self.client, &self.server),
        };
        check(receiver.local_error().is_none(), "receiver closed early")?;
        check(
            sender.peer_error().is_none(),
            "sender observed an early close",
        )
    }

    fn assert_local_and_peer_error(
        &mut self,
        direction: Direction,
        code: u64,
        reason: &[u8],
    ) -> TestResult {
        let receiver = match direction {
            Direction::ClientToServer => &self.server,
            Direction::ServerToClient => &self.client,
        };
        assert_wire_error(
            receiver
                .local_error()
                .ok_or_else(|| std::io::Error::other("receiver did not close"))?,
            code,
            reason,
        )?;
        self.advance()?;
        let sender = match direction {
            Direction::ClientToServer => &self.client,
            Direction::ServerToClient => &self.server,
        };
        assert_wire_error(
            sender
                .peer_error()
                .ok_or_else(|| std::io::Error::other("sender did not observe close"))?,
            code,
            reason,
        )
    }

    fn prepare_request_stream(&mut self) -> TestResult {
        let request = [
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"fixture.invalid"),
            Header::new(b":path", b"/p1-candidate"),
        ];
        let stream_id = self
            .client_h3
            .send_request(&mut self.client, &request, false)?;
        check(stream_id == 0, "first request did not use stream zero")?;
        self.advance()?;
        expect_headers(
            &mut self.server_h3,
            &mut self.server,
            0,
            b":path",
            b"/p1-candidate",
        )
    }
}

fn path_text(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| std::io::Error::other("fixture path is not UTF-8").into())
}

fn transport_config() -> TestResult<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(1_350);
    config.set_max_send_udp_payload_size(1_350);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_stream_data_uni(100_000);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.grease(false);
    Ok(config)
}

fn h3_config(mode: GateMode) -> TestResult<h3::Config> {
    let mut config = h3::Config::new()?;
    config.set_max_field_section_size(32_768);
    match mode {
        GateMode::Omitted => {}
        GateMode::ExplicitFalse | GateMode::Enabled => {
            config.set_reject_peer_push_activity(matches!(mode, GateMode::Enabled));
        }
    }
    Ok(config)
}

fn private_key_pem() -> String {
    let label = "PRIVATE KEY";
    format!("-----BEGIN {label}-----\n{PRIVATE_KEY_BODY}-----END {label}-----\n")
}

fn pump(client: &mut quiche::Connection, server: &mut quiche::Connection) -> TestResult {
    for _ in 0..MAX_PUMP_ROUNDS {
        let client_sent = pump_one(client, server)?;
        let server_sent = pump_one(server, client)?;
        if !client_sent && !server_sent {
            return Ok(());
        }
    }
    fail("transport pump exceeded its fixed round bound")
}

fn pump_one(from: &mut quiche::Connection, to: &mut quiche::Connection) -> TestResult<bool> {
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
    fail("transport direction exceeded its fixed packet bound")
}

fn drain_h3(h3_conn: &mut h3::Connection, transport: &mut quiche::Connection) -> TestResult {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok(_) => {}
            Err(h3::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    fail("H3 drain exceeded its fixed event bound")
}

fn assert_wire_error(error: &quiche::ConnectionError, code: u64, reason: &[u8]) -> TestResult {
    check(error.is_app, "wire error was not an application error")?;
    check(error.error_code == code, "wire error code changed")?;
    check(
        error.reason.as_slice() == reason,
        "wire error reason changed",
    )
}

fn expect_headers(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_stream: u64,
    name: &[u8],
    value: &[u8],
) -> TestResult {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                check(stream_id == expected_stream, "unexpected HEADERS stream")?;
                check(
                    list.iter()
                        .any(|header| header.name() == name && header.value() == value),
                    "expected literal header was absent",
                )?;
                return Ok(());
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return fail("expected HEADERS were absent"),
            Err(error) => return Err(error.into()),
        }
    }
    fail("HEADERS wait exceeded its fixed event bound")
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
    encode_varint_width(value, width)
}

fn encode_varint_width(value: u64, width: usize) -> Vec<u8> {
    let limit = match width {
        1 => 64,
        2 => 16_384,
        4 => 1_073_741_824,
        8 => 4_611_686_018_427_387_904,
        _ => panic!("unsupported QUIC varint width"),
    };
    assert!(value < limit);
    let mut bytes = value.to_be_bytes()[8 - width..].to_vec();
    bytes[0] |= match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    bytes
}

fn frame_with_eight_byte_type(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = encode_varint_width(frame_type, 8);
    bytes.extend_from_slice(&encode_varint(payload.len() as u64));
    bytes.extend_from_slice(payload);
    bytes
}

impl Surface {
    fn discriminator(self) -> Vec<u8> {
        encode_varint_width(
            match self {
                Self::MaxPushId => 0x0d,
                Self::CancelPush => 0x03,
                Self::PushPromise => 0x05,
                Self::PriorityUpdatePush => 0x0f0701,
                Self::PushStream => 0x01,
            },
            8,
        )
    }

    fn stream_id(self, direction: Direction) -> u64 {
        match self {
            Self::PushPromise => 0,
            Self::PushStream => match direction {
                Direction::ClientToServer => CLIENT_PUSH_STREAM,
                Direction::ServerToClient => SERVER_PUSH_STREAM,
            },
            Self::MaxPushId | Self::CancelPush | Self::PriorityUpdatePush => match direction {
                Direction::ClientToServer => CLIENT_CONTROL_STREAM,
                Direction::ServerToClient => SERVER_CONTROL_STREAM,
            },
        }
    }

    fn pristine_input(self) -> Vec<u8> {
        match self {
            Self::MaxPushId => frame_with_eight_byte_type(0x0d, &encode_varint(1)),
            Self::CancelPush => frame_with_eight_byte_type(0x03, &encode_varint(0)),
            Self::PushPromise => {
                let mut payload = encode_varint(1);
                // Required Insert Count=0, Base=0, static :method GET.
                payload.extend_from_slice(&[0x00, 0x00, 0xd1]);
                frame_with_eight_byte_type(0x05, &payload)
            }
            Self::PriorityUpdatePush => {
                let mut payload = encode_varint(3);
                payload.extend_from_slice(b"u=3");
                frame_with_eight_byte_type(0x0f0701, &payload)
            }
            Self::PushStream => {
                let mut bytes = self.discriminator();
                bytes.extend_from_slice(&encode_varint(0));
                bytes
            }
        }
    }
}

fn prepare_surface(pair: &mut Pair, surface: Surface) -> TestResult {
    if matches!(surface, Surface::PushPromise) {
        pair.prepare_request_stream()?;
    }
    Ok(())
}

fn run_strict_case(surface: Surface, direction: Direction, chunks: &[usize]) -> TestResult {
    let mut pair = Pair::new(GateMode::Enabled)?;
    prepare_surface(&mut pair, surface)?;
    let discriminator = surface.discriminator();
    check(
        discriminator.len() == 8,
        "strict discriminator was not eight bytes",
    )?;
    check(
        chunks.iter().sum::<usize>() == discriminator.len(),
        "strict chunk plan did not cover the discriminator",
    )?;

    let stream_id = surface.stream_id(direction);
    let mut offset = 0;
    for (index, chunk_len) in chunks.iter().copied().enumerate() {
        let end = offset + chunk_len;
        pair.stream_send(direction, stream_id, &discriminator[offset..end])?;
        offset = end;
        if index + 1 == chunks.len() {
            match pair.poll_receiver(direction) {
                Err(h3::Error::FrameUnexpected) => {}
                value => {
                    return fail(format!(
                        "strict {surface:?} {direction:?} did not reject at completion: {value:?}"
                    ));
                }
            }
            pair.assert_local_and_peer_error(direction, 0x105, b"")?;
        } else {
            pair.expect_receiver_done(direction)?;
            pair.assert_no_wire_error(direction)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PristineOutcome {
    Done,
    FrameUnexpected(&'static [u8]),
    StreamCreationError,
}

fn pristine_outcome(surface: Surface, direction: Direction) -> PristineOutcome {
    match (surface, direction) {
        (Surface::MaxPushId, Direction::ClientToServer)
        | (Surface::CancelPush, _)
        | (Surface::PushPromise, Direction::ServerToClient)
        | (Surface::PriorityUpdatePush, Direction::ClientToServer) => PristineOutcome::Done,
        (Surface::MaxPushId, Direction::ServerToClient) => {
            PristineOutcome::FrameUnexpected(b"MAX_PUSH_ID received by client")
        }
        (Surface::PushPromise, Direction::ClientToServer) => {
            PristineOutcome::FrameUnexpected(b"PUSH_PROMISE received by server")
        }
        (Surface::PriorityUpdatePush, Direction::ServerToClient) => {
            PristineOutcome::FrameUnexpected(b"PRIORITY_UPDATE received by client")
        }
        (Surface::PushStream, _) => PristineOutcome::StreamCreationError,
    }
}

fn run_pristine_case(mode: GateMode, surface: Surface, direction: Direction) -> TestResult {
    let mut pair = Pair::new(mode)?;
    prepare_surface(&mut pair, surface)?;
    let input = surface.pristine_input();
    check(
        input.starts_with(&surface.discriminator()),
        "pristine input did not use the fixed eight-byte discriminator",
    )?;
    pair.stream_send(direction, surface.stream_id(direction), &input)?;

    match pristine_outcome(surface, direction) {
        PristineOutcome::Done => {
            pair.expect_receiver_done(direction)?;
            pair.assert_no_wire_error(direction)?;
            if matches!(surface, Surface::MaxPushId)
                && matches!(direction, Direction::ClientToServer)
            {
                let reduced = frame_with_eight_byte_type(0x0d, &encode_varint(0));
                pair.stream_send(direction, surface.stream_id(direction), &reduced)?;
                match pair.poll_receiver(direction) {
                    Err(h3::Error::IdError) => {}
                    value => {
                        return fail(format!(
                            "pristine MAX_PUSH_ID state update was absent: {value:?}"
                        ));
                    }
                }
                pair.assert_local_and_peer_error(direction, 0x108, b"MAX_PUSH_ID reduced limit")?;
            }
            Ok(())
        }
        PristineOutcome::FrameUnexpected(reason) => {
            match pair.poll_receiver(direction) {
                Err(h3::Error::FrameUnexpected) => {}
                value => return fail(format!("pristine role error changed: {value:?}")),
            }
            pair.assert_local_and_peer_error(direction, 0x105, reason)
        }
        PristineOutcome::StreamCreationError => {
            match pair.poll_receiver(direction) {
                Err(h3::Error::StreamCreationError) => {}
                value => return fail(format!("pristine push-stream error changed: {value:?}")),
            }
            pair.assert_local_and_peer_error(direction, 0x103, b"Received push stream.")
        }
    }
}

#[test]
fn strict_peer_push_gate_rejects_every_surface_at_every_fragment_boundary() -> TestResult {
    let mut cases = 0;
    for surface in SURFACES {
        for direction in DIRECTIONS {
            for split in 1..8 {
                run_strict_case(surface, direction, &[split, 8 - split])?;
                cases += 1;
            }
            run_strict_case(surface, direction, &[1, 1, 1, 1, 1, 1, 1, 1])?;
            cases += 1;
        }
    }
    check(
        cases == 80,
        "strict matrix did not execute exactly 80 cases",
    )
}

#[test]
fn omitted_and_explicit_false_preserve_every_pristine_peer_push_outcome() -> TestResult {
    let mut cases = 0;
    for mode in [GateMode::Omitted, GateMode::ExplicitFalse] {
        for surface in SURFACES {
            for direction in DIRECTIONS {
                run_pristine_case(mode, surface, direction)?;
                cases += 1;
            }
        }
    }
    check(
        cases == 20,
        "pristine matrix did not execute exactly 20 cases",
    )
}

fn expect_priority_update(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    stream_id: u64,
) -> TestResult {
    match h3_conn.poll(transport) {
        Ok((id, h3::Event::PriorityUpdate)) if id == stream_id => {}
        value => return fail(format!("request PRIORITY_UPDATE was absent: {value:?}")),
    }
    match h3_conn.poll(transport) {
        Err(h3::Error::Done) => {}
        value => return fail(format!("request PRIORITY_UPDATE did not drain: {value:?}")),
    }
    check(
        h3_conn.take_last_priority_update(stream_id)? == b"u=3,i",
        "request PRIORITY_UPDATE value changed",
    )
}

fn expect_body(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    stream_id: u64,
    expected: &[u8],
) -> TestResult {
    check(
        expected.len() <= MAX_BODY_BYTES,
        "expected body exceeded its fixed byte bound",
    )?;
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((id, h3::Event::Data)) => {
                check(id == stream_id, "unexpected DATA stream")?;
                let mut bytes = [0_u8; MAX_BODY_BYTES];
                let received = h3_conn.recv_body(transport, id, &mut bytes)?;
                check(received == expected.len(), "DATA length changed")?;
                return check(bytes[..received] == *expected, "DATA bytes changed");
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return fail("expected DATA were absent"),
            Err(error) => return Err(error.into()),
        }
    }
    fail("DATA wait exceeded its fixed event bound")
}

fn expect_goaway(
    h3_conn: &mut h3::Connection,
    transport: &mut quiche::Connection,
    expected_id: u64,
) -> TestResult {
    for _ in 0..MAX_H3_EVENTS {
        match h3_conn.poll(transport) {
            Ok((id, h3::Event::GoAway)) => {
                return check(id == expected_id, "GOAWAY id changed");
            }
            Ok(_) => {}
            Err(h3::Error::Done) => return fail("expected GOAWAY was absent"),
            Err(error) => return Err(error.into()),
        }
    }
    fail("GOAWAY wait exceeded its fixed event bound")
}

fn run_preserved_request_response() -> TestResult {
    let mut pair = Pair::new(GateMode::Enabled)?;
    check(
        pair.client_h3.peer_settings_raw() == Some(EXPECTED_SETTINGS),
        "client peer SETTINGS changed",
    )?;
    check(
        pair.server_h3.peer_settings_raw() == Some(EXPECTED_SETTINGS),
        "server peer SETTINGS changed",
    )?;

    let request = [
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"fixture.invalid"),
        Header::new(b":path", b"/preserved"),
        Header::new(b"x-candidate-request", b"literal-client-value"),
    ];
    let stream_id = pair
        .client_h3
        .send_request(&mut pair.client, &request, false)?;
    check(stream_id == 0, "preserved request was not stream zero")?;
    pair.advance()?;
    expect_headers(
        &mut pair.server_h3,
        &mut pair.server,
        stream_id,
        b"x-candidate-request",
        b"literal-client-value",
    )?;

    pair.client_h3.send_priority_update_for_request(
        &mut pair.client,
        stream_id,
        &h3::Priority::new(3, true),
    )?;
    pair.advance()?;
    expect_priority_update(&mut pair.server_h3, &mut pair.server, stream_id)?;

    let request_body = b"client-candidate-body";
    check(
        pair.client_h3
            .send_body(&mut pair.client, stream_id, request_body, true)?
            == request_body.len(),
        "request body was only partially buffered",
    )?;
    pair.advance()?;
    expect_body(
        &mut pair.server_h3,
        &mut pair.server,
        stream_id,
        request_body,
    )?;

    let response = [
        Header::new(b":status", b"200"),
        Header::new(b"x-candidate-response", b"literal-server-value"),
    ];
    pair.server_h3
        .send_response(&mut pair.server, stream_id, &response, false)?;
    pair.advance()?;
    expect_headers(
        &mut pair.client_h3,
        &mut pair.client,
        stream_id,
        b"x-candidate-response",
        b"literal-server-value",
    )?;

    let response_body = b"server-candidate-body";
    check(
        pair.server_h3
            .send_body(&mut pair.server, stream_id, response_body, true)?
            == response_body.len(),
        "response body was only partially buffered",
    )?;
    pair.advance()?;
    expect_body(
        &mut pair.client_h3,
        &mut pair.client,
        stream_id,
        response_body,
    )?;

    pair.server_h3.send_goaway(&mut pair.server, stream_id)?;
    pair.advance()?;
    expect_goaway(&mut pair.client_h3, &mut pair.client, stream_id)?;
    pair.client_h3.send_goaway(&mut pair.client, 0)?;
    pair.advance()?;
    expect_goaway(&mut pair.server_h3, &mut pair.server, 0)
}

fn run_preserved_reserved_frames() -> TestResult {
    let reserved = frame_with_eight_byte_type(0x21, &[]);
    let mut client_to_server = Pair::new(GateMode::Enabled)?;
    client_to_server.stream_send(Direction::ClientToServer, CLIENT_CONTROL_STREAM, &reserved)?;
    client_to_server.expect_receiver_done(Direction::ClientToServer)?;
    client_to_server.assert_no_wire_error(Direction::ClientToServer)?;

    let mut server_to_client = Pair::new(GateMode::Enabled)?;
    server_to_client.stream_send(Direction::ServerToClient, SERVER_CONTROL_STREAM, &reserved)?;
    server_to_client.expect_receiver_done(Direction::ServerToClient)?;
    server_to_client.assert_no_wire_error(Direction::ServerToClient)
}

#[test]
fn strict_peer_push_gate_preserves_non_push_h3_behavior() -> TestResult {
    let _boring = SslContext::builder(SslMethod::tls())?.build();
    run_preserved_request_response()?;
    run_preserved_reserved_frames()
}
