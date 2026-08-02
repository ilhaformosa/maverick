#![cfg(feature = "unstable-quiche-strict-push-test-support")]
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, Once};

use quiche::h3;
use quiche::h3::frame;
use quiche::h3::testing::Session;
use tempfile::TempDir;

const FRAME_UNEXPECTED_WIRE_CODE: u64 = 0x105;
const TRACE_SAFE_SENTINEL: &str = "tx frm SETTINGS";
const TRACE_REQUEST_MARKER: &str = "rq-026b2-marker";
const TRACE_REQUEST_DEBUG_MARKER: &str =
    "[114, 113, 45, 48, 50, 54, 98, 50, 45, 109, 97, 114, 107, 101, 114]";
const TRACE_RESPONSE_MARKER: &str = "rs-026b2-marker";
const TRACE_RESPONSE_DEBUG_MARKER: &str =
    "[114, 115, 45, 48, 50, 54, 98, 50, 45, 109, 97, 114, 107, 101, 114]";
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct CaptureLogger;

impl log::Log for CaptureLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) || !record.target().starts_with("quiche::h3") {
            return;
        }

        let message = record.args().to_string();
        H3_TRACE_RECORDS.fetch_add(1, Ordering::Relaxed);
        if record.target().contains("::qpack") {
            QPACK_TRACE_RECORDS.fetch_add(1, Ordering::Relaxed);
        }
        SAW_TRACE_SAFE_SENTINEL.fetch_or(message.contains(TRACE_SAFE_SENTINEL), Ordering::Relaxed);
        SAW_TRACE_REQUEST_MARKER.fetch_or(
            message.contains(TRACE_REQUEST_DEBUG_MARKER),
            Ordering::Relaxed,
        );
        SAW_TRACE_RESPONSE_MARKER.fetch_or(
            message.contains(TRACE_RESPONSE_DEBUG_MARKER),
            Ordering::Relaxed,
        );
    }

    fn flush(&self) {}
}

static CAPTURE_LOGGER: CaptureLogger = CaptureLogger;
static LOGGER_INIT: Once = Once::new();
static H3_TRACE_RECORDS: AtomicUsize = AtomicUsize::new(0);
static QPACK_TRACE_RECORDS: AtomicUsize = AtomicUsize::new(0);
static SAW_TRACE_SAFE_SENTINEL: AtomicBool = AtomicBool::new(false);
static SAW_TRACE_REQUEST_MARKER: AtomicBool = AtomicBool::new(false);
static SAW_TRACE_RESPONSE_MARKER: AtomicBool = AtomicBool::new(false);

fn serial_test() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn reset_capture_logger() {
    LOGGER_INIT.call_once(|| {
        log::set_logger(&CAPTURE_LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
    clear_capture_logger();
}

fn clear_capture_logger() {
    H3_TRACE_RECORDS.store(0, Ordering::Relaxed);
    QPACK_TRACE_RECORDS.store(0, Ordering::Relaxed);
    SAW_TRACE_SAFE_SENTINEL.store(false, Ordering::Relaxed);
    SAW_TRACE_REQUEST_MARKER.store(false, Ordering::Relaxed);
    SAW_TRACE_RESPONSE_MARKER.store(false, Ordering::Relaxed);
}

fn session_with_h3_config(h3_config: &h3::Config) -> (TempDir, Session) {
    let temp = TempDir::new().unwrap();
    let cert_path = temp.path().join("cert.pem");
    let key_path = temp.path().join("key.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert_path, certified.cert.pem()).unwrap();
    std::fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

    let mut transport_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    transport_config
        .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
        .unwrap();
    transport_config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .unwrap();
    transport_config.set_application_protos(&[b"h3"]).unwrap();
    transport_config.set_initial_max_data(1_500);
    transport_config.set_initial_max_stream_data_bidi_local(150);
    transport_config.set_initial_max_stream_data_bidi_remote(150);
    transport_config.set_initial_max_stream_data_uni(150);
    transport_config.set_initial_max_streams_bidi(5);
    transport_config.set_initial_max_streams_uni(5);
    transport_config.verify_peer(false);
    transport_config.enable_dgram(true, 3, 3);

    let session = Session::with_configs(&mut transport_config, h3_config).unwrap();
    (temp, session)
}

fn default_session() -> (TempDir, Session) {
    session_with_h3_config(&h3::Config::new().unwrap())
}

fn strict_session() -> (TempDir, Session) {
    let mut h3_config = h3::Config::new().unwrap();
    h3_config.set_reject_peer_push_activity(true);
    session_with_h3_config(&h3_config)
}

fn exercise_bidirectional_trace_path(session: &mut Session) {
    let request = vec![
        h3::Header::new(b":method", b"POST"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"synthetic-trace.invalid"),
        h3::Header::new(b":path", b"/synthetic-trace-path"),
        h3::Header::new(b"x-synthetic-request", TRACE_REQUEST_MARKER.as_bytes()),
    ];
    session.handshake().unwrap();
    let stream_id = session
        .client
        .send_request(&mut session.pipe.client, &request, false)
        .unwrap();
    session.advance().unwrap();
    assert_eq!(
        session.poll_server(),
        Ok((
            stream_id,
            h3::Event::Headers {
                list: request,
                more_frames: true,
            },
        ))
    );

    session
        .send_arbitrary_stream_data_client(&[0x00], stream_id, false)
        .unwrap();
    assert_eq!(session.poll_server(), Err(h3::Error::Done));
    session
        .send_arbitrary_stream_data_client(&[0x06], stream_id, false)
        .unwrap();
    assert_eq!(session.poll_server(), Ok((stream_id, h3::Event::Data)));

    session
        .send_arbitrary_stream_data_client(b"abc", stream_id, false)
        .unwrap();
    let mut body = [0_u8; 6];
    assert_eq!(session.recv_body_server(stream_id, &mut body[..3]), Ok(3));
    session
        .send_arbitrary_stream_data_client(b"def", stream_id, true)
        .unwrap();
    assert_eq!(session.recv_body_server(stream_id, &mut body[3..]), Ok(3));
    assert_eq!(&body, b"abcdef");
    assert_eq!(session.poll_server(), Ok((stream_id, h3::Event::Finished)));

    let response = vec![
        h3::Header::new(b":status", b"200"),
        h3::Header::new(b"x-synthetic-response", TRACE_RESPONSE_MARKER.as_bytes()),
    ];
    session
        .server
        .send_response(&mut session.pipe.server, stream_id, &response, true)
        .unwrap();
    session.advance().unwrap();
    assert_eq!(
        session.poll_client(),
        Ok((
            stream_id,
            h3::Event::Headers {
                list: response,
                more_frames: false,
            },
        ))
    );
}

fn assert_fixed_empty_rejection(error: &quiche::ConnectionError) {
    assert!(error.is_app);
    assert_eq!(error.error_code, FRAME_UNEXPECTED_WIRE_CODE);
    assert!(error.reason.is_empty());
    assert_eq!(
        format!("{:?}", h3::Error::FrameUnexpected),
        "FrameUnexpected"
    );
}

fn assert_peer_received_fixed_empty_rejection(error: &quiche::ConnectionError) {
    assert_fixed_empty_rejection(error);
}

#[test]
fn default_false_keeps_known_push_frames_hidden() {
    let _guard = serial_test();
    let frames = [
        frame::Frame::MaxPushId { push_id: 2 },
        frame::Frame::CancelPush { push_id: 7 },
        frame::Frame::PriorityUpdatePush {
            prioritized_element_id: 3,
            priority_field_value: b"u=3".to_vec(),
        },
    ];

    for frame in frames {
        let (_temp, mut session) = default_session();
        session.handshake().unwrap();
        session.send_frame_client(frame, 2, false).unwrap();
        assert_eq!(session.poll_server(), Err(h3::Error::Done));
        assert_eq!(session.pipe.server.local_error(), None);
    }
}

#[test]
fn default_false_keeps_push_promise_compatibility() {
    let _guard = serial_test();
    let (_temp, mut session) = default_session();
    session.handshake().unwrap();
    let (stream_id, _) = session.send_request(false).unwrap();
    session
        .send_frame_server(
            frame::Frame::PushPromise {
                push_id: 11,
                header_block: vec![0, 0],
            },
            stream_id,
            false,
        )
        .unwrap();

    assert_eq!(session.poll_client(), Err(h3::Error::Done));
    assert_eq!(session.pipe.client.local_error(), None);
}

#[test]
fn default_false_keeps_existing_push_stream_rejection() {
    let _guard = serial_test();
    let (_temp, mut session) = default_session();
    session.handshake().unwrap();
    session.pipe.server.stream_send(19, &[1], false).unwrap();
    session.advance().unwrap();

    assert_eq!(session.poll_client(), Err(h3::Error::StreamCreationError));
}

#[test]
fn connection_local_trace_gate_is_default_false_and_suppresses_both_roles() {
    let _guard = serial_test();
    let default_config = h3::Config::new().unwrap();
    reset_capture_logger();
    let (_default_temp, mut default_session) = session_with_h3_config(&default_config);
    exercise_bidirectional_trace_path(&mut default_session);

    assert!(H3_TRACE_RECORDS.load(Ordering::Relaxed) > 0);
    assert!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed) > 0);
    assert!(SAW_TRACE_SAFE_SENTINEL.load(Ordering::Relaxed));
    assert!(SAW_TRACE_REQUEST_MARKER.load(Ordering::Relaxed));
    assert!(SAW_TRACE_RESPONSE_MARKER.load(Ordering::Relaxed));

    let mut suppressed_config = h3::Config::new().unwrap();
    suppressed_config.set_suppress_trace_logging(true);
    clear_capture_logger();
    let (_suppressed_temp, mut suppressed_session) = session_with_h3_config(&suppressed_config);
    exercise_bidirectional_trace_path(&mut suppressed_session);

    assert_eq!(H3_TRACE_RECORDS.load(Ordering::Relaxed), 0);
    assert_eq!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed), 0);
}

#[test]
fn strict_max_push_id_is_rejected_before_state_update_and_close_propagates() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .send_frame_client(frame::Frame::MaxPushId { push_id: 2 }, 2, false)
        .unwrap();

    assert_eq!(session.poll_server(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.server.local_error().unwrap());
    let _ = session.advance();
    assert_peer_received_fixed_empty_rejection(session.pipe.client.peer_error().unwrap());
}

#[test]
fn strict_cancel_push_is_rejected_before_todo_acceptance() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .send_frame_client(frame::Frame::CancelPush { push_id: 7 }, 2, false)
        .unwrap();

    assert_eq!(session.poll_server(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.server.local_error().unwrap());
}

#[test]
fn strict_push_promise_is_rejected_before_qpack_decode() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    let (stream_id, _) = session.send_request(false).unwrap();
    session
        .send_frame_server(
            frame::Frame::PushPromise {
                push_id: 11,
                header_block: vec![0xff],
            },
            stream_id,
            false,
        )
        .unwrap();

    assert_eq!(session.poll_client(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.client.local_error().unwrap());
}

#[test]
fn strict_push_priority_update_is_rejected_before_todo_acceptance() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .send_frame_client(
            frame::Frame::PriorityUpdatePush {
                prioritized_element_id: 3,
                priority_field_value: b"u=3".to_vec(),
            },
            2,
            false,
        )
        .unwrap();

    assert_eq!(session.poll_server(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.server.local_error().unwrap());
}

#[test]
fn strict_peer_push_stream_is_rejected_and_close_propagates() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session.pipe.server.stream_send(19, &[1], false).unwrap();
    session.advance().unwrap();

    assert_eq!(session.poll_client(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.client.local_error().unwrap());
    let _ = session.advance();
    assert_peer_received_fixed_empty_rejection(session.pipe.server.peer_error().unwrap());
}

#[test]
fn strict_pre_settings_fragmented_non_shortest_max_push_id_is_rejected() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.pipe.handshake().unwrap();

    // 0x00 opens the client control stream. 0x40 0x0d is the non-shortest,
    // two-byte QUIC varint encoding of the MAX_PUSH_ID frame type. Deliver it
    // in two pieces before either H3 peer has sent SETTINGS.
    session
        .pipe
        .client
        .stream_send(2, &[0x00, 0x40], false)
        .unwrap();
    session.advance().unwrap();
    assert_eq!(session.poll_server(), Err(h3::Error::Done));
    assert_eq!(session.pipe.server.local_error(), None);

    session.pipe.client.stream_send(2, &[0x0d], false).unwrap();
    session.advance().unwrap();
    assert_eq!(session.poll_server(), Err(h3::Error::FrameUnexpected));
    assert_fixed_empty_rejection(session.pipe.server.local_error().unwrap());
}

#[test]
fn strict_unknown_reserved_frame_is_ignored() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .send_frame_client(
            frame::Frame::Unknown {
                raw_type: 0x21,
                payload: vec![1, 2, 3],
            },
            2,
            false,
        )
        .unwrap();

    assert_eq!(session.poll_server(), Err(h3::Error::Done));
    assert_eq!(session.pipe.server.local_error(), None);
}

#[test]
fn strict_settings_qpack_and_request_path_are_preserved() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    assert_eq!(session.pipe.client.local_error(), None);
    assert_eq!(session.pipe.server.local_error(), None);

    let (stream_id, headers) = session.send_request(true).unwrap();
    assert_eq!(
        session.poll_server(),
        Ok((
            stream_id,
            h3::Event::Headers {
                list: headers,
                more_frames: false,
            },
        ))
    );
    assert_eq!(session.poll_server(), Ok((stream_id, h3::Event::Finished)));
}

#[test]
fn strict_request_priority_update_event_is_preserved() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .client
        .send_priority_update_for_request(&mut session.pipe.client, 0, &h3::Priority::new(3, false))
        .unwrap();
    session.advance().unwrap();

    assert_eq!(session.poll_server(), Ok((0, h3::Event::PriorityUpdate)));
    assert_eq!(session.pipe.server.local_error(), None);
}

#[test]
fn strict_goaway_path_is_preserved() {
    let _guard = serial_test();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    session
        .server
        .send_goaway(&mut session.pipe.server, 4_000)
        .unwrap();
    session.advance().unwrap();

    assert_eq!(session.poll_client(), Ok((4_000, h3::Event::GoAway)));
    assert_eq!(session.pipe.client.local_error(), None);
}

#[test]
fn strict_rejection_surfaces_do_not_expose_peer_input() {
    let _guard = serial_test();
    reset_capture_logger();
    let (_temp, mut session) = strict_session();
    session.handshake().unwrap();
    let (stream_id, _) = session.send_request(false).unwrap();
    let marker = b"synthetic-sensitive-marker";
    let raw_push_id = 0x1234_5678;
    session
        .send_frame_server(
            frame::Frame::PushPromise {
                push_id: raw_push_id,
                header_block: marker.to_vec(),
            },
            stream_id,
            false,
        )
        .unwrap();
    clear_capture_logger();

    let error = session.poll_client().unwrap_err();
    let error_debug = format!("{error:?}");
    let local_error = session.pipe.client.local_error().unwrap();
    let raw_id_decimal = raw_push_id.to_string();

    assert_eq!(error, h3::Error::FrameUnexpected);
    assert!(std::error::Error::source(&error).is_none());
    assert_fixed_empty_rejection(local_error);
    assert!(!error_debug
        .as_bytes()
        .windows(marker.len())
        .any(|v| v == marker));
    assert!(!error_debug.contains(&raw_id_decimal));
    assert!(!local_error
        .reason
        .windows(marker.len())
        .any(|v| v == marker));
    assert_eq!(H3_TRACE_RECORDS.load(Ordering::Relaxed), 0);
    assert_eq!(QPACK_TRACE_RECORDS.load(Ordering::Relaxed), 0);
}
