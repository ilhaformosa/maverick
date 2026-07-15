use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use maverick_core::auth::{
    CLIENT_HELLO_AUTH_LABEL, CLIENT_HELLO_V2_AUTH_LABEL, SERVER_HELLO_AUTH_LABEL,
    SERVER_HELLO_V2_AUTH_LABEL,
};
use maverick_core::frame::ErrorCode;
use maverick_core::frame::FRAME_HEADER_LEN;
use maverick_core::replay::ReplayCache;
use maverick_core::{
    ClientHello, ClientHelloV2, Frame, FrameType, Mode, OpenTcpPayload, OpenUdpPayload,
    SecretString, ServerHello, ServerHelloV2, TargetAddr, UdpPacketPayload,
};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const AUTH_V2_EPOCH_SALT_LABEL: &[u8] = b"Maverick auth v2 epoch";
const AUTH_V2_CLIENT_INFO: &[u8] = b"Maverick auth v2 client mac";
const AUTH_V2_SERVER_INFO: &[u8] = b"Maverick auth v2 server mac";

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Vector {
    Frame {
        id: String,
        max_frame_size: usize,
        frame: FrameVector,
        encoded_hex: String,
    },
    OpenUdp {
        id: String,
        idle_timeout_ms: u64,
        encoded_hex: String,
    },
    OpenTcp {
        id: String,
        target: TargetVector,
        port: u16,
        initial_data_hex: String,
        encoded_hex: String,
    },
    UdpPacket {
        id: String,
        target: Ipv4Addr,
        port: u16,
        data_hex: String,
        encoded_hex: String,
    },
    ErrorCode {
        id: String,
        code: String,
        encoded_hex: String,
    },
    ClientHelloV1 {
        id: String,
        secret_test_only: String,
        tunnel_path: String,
        protocol_version: u16,
        client_nonce_hex: String,
        timestamp_unix: i64,
        credential_id: String,
        mode: Mode,
        feature_flags: u64,
        auth_tag_hex: String,
        encoded_hex: String,
    },
    ClientHelloV2 {
        id: String,
        secret_test_only: String,
        tunnel_path: String,
        protocol_version: u16,
        auth_epoch: u64,
        client_nonce_hex: String,
        timestamp_unix: i64,
        credential_hint_hex: String,
        mode: Mode,
        feature_flags: u64,
        rotation_flags: u32,
        auth_tag_hex: String,
        encoded_hex: String,
    },
    ServerHelloV1 {
        id: String,
        secret_test_only: String,
        client_nonce_hex: String,
        protocol_version_selected: u16,
        server_nonce_hex: String,
        session_id_hex: String,
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
        server_auth_tag_hex: String,
        encoded_hex: String,
    },
    ServerHelloV2 {
        id: String,
        secret_test_only: String,
        client_nonce_hex: String,
        protocol_version_selected: u16,
        selected_epoch: u64,
        server_nonce_hex: String,
        session_id_hex: String,
        max_frame_size: u32,
        max_concurrent_flows: u32,
        feature_flags_selected: u64,
        rotation_window_secs: u32,
        server_auth_tag_hex: String,
        encoded_hex: String,
    },
    ReplaySequence {
        id: String,
        window_secs: i64,
        max_entries: usize,
        steps: Vec<ReplayStep>,
    },
}

#[derive(Debug, Deserialize)]
struct FrameVector {
    #[serde(rename = "type")]
    frame_type: String,
    flags: u8,
    flow_id: u64,
    payload_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TargetVector {
    Domain { host: String },
    Ipv4 { addr: Ipv4Addr },
    Ipv6 { addr: Ipv6Addr },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum ReplayStep {
    CheckInsert {
        credential_id: String,
        nonce_hex: String,
        timestamp_unix: i64,
        now_unix: i64,
        expect: String,
        len_after: usize,
    },
    Cleanup {
        now_unix: i64,
        len_after: usize,
    },
}

#[test]
fn conformance_vectors_roundtrip() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vector_dir = repo_root.join("conformance/vectors");
    let mut paths = std::fs::read_dir(&vector_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();
    assert!(!paths.is_empty());

    for path in paths {
        let input = std::fs::read_to_string(&path).unwrap();
        let vector: Vector = serde_json::from_str(&input).unwrap();
        match vector {
            Vector::Frame {
                id,
                max_frame_size,
                frame,
                encoded_hex,
            } => {
                let payload = hex_decode(&frame.payload_hex);
                let frame_type = frame_type(&frame.frame_type);
                let actual = Frame::new(frame_type, frame.flags, frame.flow_id, payload.clone())
                    .encode(max_frame_size)
                    .unwrap();
                let expected = hex_decode(&encoded_hex);
                assert_eq!(actual.as_ref(), expected.as_slice(), "{id}");

                let mut buf = BytesMut::from(expected.as_slice());
                let decoded = Frame::decode_from(&mut buf, max_frame_size)
                    .unwrap()
                    .unwrap();
                assert_eq!(decoded.frame_type, frame_type, "{id}");
                assert_eq!(decoded.flags, frame.flags, "{id}");
                assert_eq!(decoded.flow_id, frame.flow_id, "{id}");
                assert_eq!(decoded.payload.as_ref(), payload.as_slice(), "{id}");
                assert!(buf.is_empty(), "{id}");
                assert_eq!(FRAME_HEADER_LEN + payload.len(), expected.len(), "{id}");
            }
            Vector::OpenUdp {
                id,
                idle_timeout_ms,
                encoded_hex,
            } => {
                let payload = OpenUdpPayload::new(idle_timeout_ms);
                let expected = hex_decode(&encoded_hex);
                assert_eq!(payload.encode().as_ref(), expected.as_slice(), "{id}");
                assert_eq!(OpenUdpPayload::decode(&expected).unwrap(), payload, "{id}");
            }
            Vector::OpenTcp {
                id,
                target,
                port,
                initial_data_hex,
                encoded_hex,
            } => {
                let payload = OpenTcpPayload {
                    target: target.into_target_addr(),
                    port,
                    initial_data: Bytes::from(hex_decode(&initial_data_hex)),
                };
                let expected = hex_decode(&encoded_hex);
                assert_eq!(
                    payload.encode().unwrap().as_ref(),
                    expected.as_slice(),
                    "{id}"
                );
                assert_eq!(OpenTcpPayload::decode(&expected).unwrap(), payload, "{id}");
            }
            Vector::UdpPacket {
                id,
                target,
                port,
                data_hex,
                encoded_hex,
            } => {
                let data = hex_decode(&data_hex);
                let payload =
                    UdpPacketPayload::new(TargetAddr::Ipv4(target), port, Bytes::from(data));
                let expected = hex_decode(&encoded_hex);
                assert_eq!(
                    payload.encode().unwrap().as_ref(),
                    expected.as_slice(),
                    "{id}"
                );
                assert_eq!(
                    UdpPacketPayload::decode(&expected).unwrap(),
                    payload,
                    "{id}"
                );
            }
            Vector::ErrorCode {
                id,
                code,
                encoded_hex,
            } => {
                let code = error_code(&code);
                let expected = hex_decode(&encoded_hex);
                assert_eq!(code.encode().as_ref(), expected.as_slice(), "{id}");
                assert_eq!(ErrorCode::decode(&expected).unwrap(), code, "{id}");
            }
            Vector::ClientHelloV1 {
                id,
                secret_test_only,
                tunnel_path,
                protocol_version,
                client_nonce_hex,
                timestamp_unix,
                credential_id,
                mode,
                feature_flags,
                auth_tag_hex,
                encoded_hex,
            } => {
                let secret = SecretString::new(secret_test_only).unwrap();
                let hello = ClientHello {
                    protocol_version,
                    client_nonce: hex_array(&client_nonce_hex),
                    timestamp_unix,
                    credential_id,
                    mode,
                    feature_flags,
                    auth_tag: hex_array(&auth_tag_hex),
                };
                let expected = hex_decode(&encoded_hex);
                assert_eq!(hello.encode().as_slice(), expected.as_slice(), "{id}");
                let decoded = ClientHello::decode(&expected).unwrap();
                assert_eq!(decoded, hello, "{id}");
                assert!(decoded.verify(&secret, &tunnel_path), "{id}");
            }
            Vector::ClientHelloV2 {
                id,
                secret_test_only,
                tunnel_path,
                protocol_version,
                auth_epoch,
                client_nonce_hex,
                timestamp_unix,
                credential_hint_hex,
                mode,
                feature_flags,
                rotation_flags,
                auth_tag_hex,
                encoded_hex,
            } => {
                let secret = SecretString::new(secret_test_only).unwrap();
                let hello = ClientHelloV2 {
                    protocol_version,
                    auth_epoch,
                    client_nonce: hex_array(&client_nonce_hex),
                    timestamp_unix,
                    credential_hint: hex_decode(&credential_hint_hex),
                    mode,
                    feature_flags,
                    rotation_flags,
                    auth_tag: hex_array(&auth_tag_hex),
                };
                let expected = hex_decode(&encoded_hex);
                assert_eq!(
                    hello.encode().unwrap().as_slice(),
                    expected.as_slice(),
                    "{id}"
                );
                let decoded = ClientHelloV2::decode(&expected).unwrap();
                assert_eq!(decoded, hello, "{id}");
                assert!(decoded.verify(&secret, &tunnel_path), "{id}");
            }
            Vector::ServerHelloV1 {
                id,
                secret_test_only,
                client_nonce_hex,
                protocol_version_selected,
                server_nonce_hex,
                session_id_hex,
                max_frame_size,
                max_concurrent_flows,
                feature_flags_selected,
                server_auth_tag_hex,
                encoded_hex,
            } => {
                let secret = SecretString::new(secret_test_only).unwrap();
                let client_nonce = hex_array(&client_nonce_hex);
                let hello = ServerHello {
                    protocol_version_selected,
                    server_nonce: hex_array(&server_nonce_hex),
                    session_id: hex_decode(&session_id_hex),
                    max_frame_size,
                    max_concurrent_flows,
                    feature_flags_selected,
                    server_auth_tag: hex_array(&server_auth_tag_hex),
                };
                let expected = hex_decode(&encoded_hex);
                assert_eq!(hello.encode().as_slice(), expected.as_slice(), "{id}");
                let decoded = ServerHello::decode(&expected).unwrap();
                assert_eq!(decoded, hello, "{id}");
                assert!(decoded.verify(&secret, &client_nonce), "{id}");
            }
            Vector::ServerHelloV2 {
                id,
                secret_test_only,
                client_nonce_hex,
                protocol_version_selected,
                selected_epoch,
                server_nonce_hex,
                session_id_hex,
                max_frame_size,
                max_concurrent_flows,
                feature_flags_selected,
                rotation_window_secs,
                server_auth_tag_hex,
                encoded_hex,
            } => {
                let secret = SecretString::new(secret_test_only).unwrap();
                let client_nonce = hex_array(&client_nonce_hex);
                let hello = ServerHelloV2 {
                    protocol_version_selected,
                    selected_epoch,
                    server_nonce: hex_array(&server_nonce_hex),
                    session_id: hex_decode(&session_id_hex),
                    max_frame_size,
                    max_concurrent_flows,
                    feature_flags_selected,
                    rotation_window_secs,
                    server_auth_tag: hex_array(&server_auth_tag_hex),
                };
                let expected = hex_decode(&encoded_hex);
                assert_eq!(
                    hello.encode().unwrap().as_slice(),
                    expected.as_slice(),
                    "{id}"
                );
                let decoded = ServerHelloV2::decode(&expected).unwrap();
                assert_eq!(decoded, hello, "{id}");
                assert!(decoded.verify(&secret, &client_nonce), "{id}");
            }
            Vector::ReplaySequence {
                id,
                window_secs,
                max_entries,
                steps,
            } => {
                let mut cache = ReplayCache::new(window_secs, max_entries, max_entries);
                for step in steps {
                    match step {
                        ReplayStep::CheckInsert {
                            credential_id,
                            nonce_hex,
                            timestamp_unix,
                            now_unix,
                            expect,
                            len_after,
                        } => {
                            let result = cache.check_and_insert(
                                &credential_id,
                                hex_array(&nonce_hex),
                                timestamp_unix,
                                now_unix,
                            );
                            assert_replay_expectation(&id, &expect, result);
                            assert_eq!(cache.len(), len_after, "{id}: {expect}");
                        }
                        ReplayStep::Cleanup {
                            now_unix,
                            len_after,
                        } => {
                            cache.cleanup(now_unix);
                            assert_eq!(cache.len(), len_after, "{id}: cleanup");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn conformance_vectors_match_generated_wire_values() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vector_dir = repo_root.join("conformance/vectors");

    for (file_name, generated) in generated_vectors() {
        let checked_in = std::fs::read_to_string(vector_dir.join(file_name)).unwrap();
        assert_eq!(checked_in, generated, "{file_name}");
    }
}

fn generated_vectors() -> Vec<(&'static str, String)> {
    vec![
        generated_auth_v1_client_hello(),
        generated_auth_v1_server_hello(),
        generated_auth_v2_client_hello(),
        generated_auth_v2_server_hello(),
        generated_frame_dns_query(),
        generated_frame_dns_response(),
        generated_error_code_flow_limit(),
        generated_frame_padding(),
        generated_frame_tcp_data(),
        generated_open_tcp_domain(),
        generated_open_udp(),
        generated_replay_window(),
        generated_udp_packet_ipv4(),
    ]
}

fn generated_auth_v1_client_hello() -> (&'static str, String) {
    let secret = SecretString::new(TEST_SECRET).unwrap();
    let client_nonce = seq_array::<32>(0x00);
    let credential_id = "u_conformance";
    let tunnel_path = "/assets/upload";
    let timestamp_unix = 1_735_689_600;
    let feature_flags = 5;
    let auth_tag = client_v1_auth_tag(
        &secret,
        1,
        &client_nonce,
        timestamp_unix,
        credential_id,
        tunnel_path,
        Mode::Auto,
        feature_flags,
    );
    let hello = ClientHello {
        protocol_version: 1,
        client_nonce,
        timestamp_unix,
        credential_id: credential_id.into(),
        mode: Mode::Auto,
        feature_flags,
        auth_tag,
    };
    assert!(hello.verify(&secret, tunnel_path));
    (
        "auth_v1_client_hello.json",
        format!(
            r#"{{
  "id": "auth_v1_client_hello",
  "kind": "client_hello_v1",
  "secret_test_only": "{TEST_SECRET}",
  "tunnel_path": "{tunnel_path}",
  "protocol_version": 1,
  "client_nonce_hex": "{}",
  "timestamp_unix": {timestamp_unix},
  "credential_id": "{credential_id}",
  "mode": "auto",
  "feature_flags": {feature_flags},
  "auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            hex_encode(client_nonce),
            hex_encode(auth_tag),
            hex_encode(hello.encode()),
        ),
    )
}

fn generated_auth_v1_server_hello() -> (&'static str, String) {
    let secret = SecretString::new(TEST_SECRET).unwrap();
    let client_nonce = seq_array::<32>(0x00);
    let server_nonce = seq_array::<32>(0x20);
    let session_id = seq_vec(0xa0, 16);
    let max_frame_size = 65_536;
    let max_concurrent_flows = 128;
    let feature_flags_selected = 1;
    let server_auth_tag = server_v1_auth_tag(
        &secret,
        &client_nonce,
        &server_nonce,
        &session_id,
        1,
        max_frame_size,
        max_concurrent_flows,
        feature_flags_selected,
    );
    let hello = ServerHello {
        protocol_version_selected: 1,
        server_nonce,
        session_id: session_id.clone(),
        max_frame_size,
        max_concurrent_flows,
        feature_flags_selected,
        server_auth_tag,
    };
    assert!(hello.verify(&secret, &client_nonce));
    (
        "auth_v1_server_hello.json",
        format!(
            r#"{{
  "id": "auth_v1_server_hello",
  "kind": "server_hello_v1",
  "secret_test_only": "{TEST_SECRET}",
  "client_nonce_hex": "{}",
  "protocol_version_selected": 1,
  "server_nonce_hex": "{}",
  "session_id_hex": "{}",
  "max_frame_size": {max_frame_size},
  "max_concurrent_flows": {max_concurrent_flows},
  "feature_flags_selected": {feature_flags_selected},
  "server_auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            hex_encode(client_nonce),
            hex_encode(server_nonce),
            hex_encode(&session_id),
            hex_encode(server_auth_tag),
            hex_encode(hello.encode()),
        ),
    )
}

fn generated_auth_v2_client_hello() -> (&'static str, String) {
    let secret = SecretString::new(TEST_SECRET).unwrap();
    let client_nonce = seq_array::<32>(0x40);
    let credential_hint = b"hint:u_conformance:202607".to_vec();
    let tunnel_path = "/assets/upload";
    let timestamp_unix = 1_767_225_600;
    let auth_epoch = 202_607;
    let feature_flags = 9;
    let rotation_flags = 3;
    let auth_tag = client_v2_auth_tag(
        &secret,
        2,
        auth_epoch,
        &client_nonce,
        timestamp_unix,
        &credential_hint,
        tunnel_path,
        Mode::Private,
        feature_flags,
        rotation_flags,
    );
    let hello = ClientHelloV2 {
        protocol_version: 2,
        auth_epoch,
        client_nonce,
        timestamp_unix,
        credential_hint: credential_hint.clone(),
        mode: Mode::Private,
        feature_flags,
        rotation_flags,
        auth_tag,
    };
    assert!(hello.verify(&secret, tunnel_path));
    (
        "auth_v2_client_hello.json",
        format!(
            r#"{{
  "id": "auth_v2_client_hello",
  "kind": "client_hello_v2",
  "secret_test_only": "{TEST_SECRET}",
  "tunnel_path": "{tunnel_path}",
  "protocol_version": 2,
  "auth_epoch": {auth_epoch},
  "client_nonce_hex": "{}",
  "timestamp_unix": {timestamp_unix},
  "credential_hint_hex": "{}",
  "mode": "private",
  "feature_flags": {feature_flags},
  "rotation_flags": {rotation_flags},
  "auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            hex_encode(client_nonce),
            hex_encode(&credential_hint),
            hex_encode(auth_tag),
            hex_encode(hello.encode().unwrap()),
        ),
    )
}

fn generated_auth_v2_server_hello() -> (&'static str, String) {
    let secret = SecretString::new(TEST_SECRET).unwrap();
    let client_nonce = seq_array::<32>(0x40);
    let server_nonce = seq_array::<32>(0x60);
    let session_id = seq_vec(0xb0, 16);
    let selected_epoch = 202_607;
    let max_frame_size = 65_536;
    let max_concurrent_flows = 128;
    let feature_flags_selected = 9;
    let rotation_window_secs = 86_400;
    let server_auth_tag = server_v2_auth_tag(
        &secret,
        &client_nonce,
        &server_nonce,
        &session_id,
        2,
        selected_epoch,
        max_frame_size,
        max_concurrent_flows,
        feature_flags_selected,
        rotation_window_secs,
    );
    let hello = ServerHelloV2 {
        protocol_version_selected: 2,
        selected_epoch,
        server_nonce,
        session_id: session_id.clone(),
        max_frame_size,
        max_concurrent_flows,
        feature_flags_selected,
        rotation_window_secs,
        server_auth_tag,
    };
    assert!(hello.verify(&secret, &client_nonce));
    (
        "auth_v2_server_hello.json",
        format!(
            r#"{{
  "id": "auth_v2_server_hello",
  "kind": "server_hello_v2",
  "secret_test_only": "{TEST_SECRET}",
  "client_nonce_hex": "{}",
  "protocol_version_selected": 2,
  "selected_epoch": {selected_epoch},
  "server_nonce_hex": "{}",
  "session_id_hex": "{}",
  "max_frame_size": {max_frame_size},
  "max_concurrent_flows": {max_concurrent_flows},
  "feature_flags_selected": {feature_flags_selected},
  "rotation_window_secs": {rotation_window_secs},
  "server_auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            hex_encode(client_nonce),
            hex_encode(server_nonce),
            hex_encode(&session_id),
            hex_encode(server_auth_tag),
            hex_encode(hello.encode().unwrap()),
        ),
    )
}

fn generated_error_code_flow_limit() -> (&'static str, String) {
    let encoded_hex = hex_encode(ErrorCode::FlowLimitExceeded.encode());
    (
        "error_code_flow_limit.json",
        format!(
            r#"{{
  "id": "error_code_flow_limit_exceeded_v1",
  "kind": "error_code",
  "code": "flow_limit_exceeded",
  "encoded_hex": "{encoded_hex}"
}}
"#
        ),
    )
}

fn generated_frame_dns_query() -> (&'static str, String) {
    let payload = hex_decode("123401000001000000000000076578616d706c6503636f6d0000010001");
    let encoded_hex = hex_encode(
        Frame::new(FrameType::DnsQuery, 0, 7, payload.clone())
            .encode(65_536)
            .unwrap(),
    );
    (
        "frame_dns_query.json",
        format!(
            r#"{{
  "id": "frame_dns_query_v1",
  "kind": "frame",
  "max_frame_size": 65536,
  "frame": {{
    "type": "dns_query",
    "flags": 0,
    "flow_id": 7,
    "payload_hex": "{}"
  }},
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload),
        ),
    )
}

fn generated_frame_dns_response() -> (&'static str, String) {
    let payload = hex_decode(
        "123481800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c00045db8d822",
    );
    let encoded_hex = hex_encode(
        Frame::new(FrameType::DnsResponse, 0, 7, payload.clone())
            .encode(65_536)
            .unwrap(),
    );
    (
        "frame_dns_response.json",
        format!(
            r#"{{
  "id": "frame_dns_response_v1",
  "kind": "frame",
  "max_frame_size": 65536,
  "frame": {{
    "type": "dns_response",
    "flags": 0,
    "flow_id": 7,
    "payload_hex": "{}"
  }},
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload),
        ),
    )
}

fn generated_frame_padding() -> (&'static str, String) {
    let payload = hex_decode("0001020304050607");
    let encoded_hex = hex_encode(
        Frame::new(FrameType::Padding, 0, 0, payload.clone())
            .encode(65_536)
            .unwrap(),
    );
    (
        "frame_padding.json",
        format!(
            r#"{{
  "id": "frame_padding_v1",
  "kind": "frame",
  "max_frame_size": 65536,
  "frame": {{
    "type": "padding",
    "flags": 0,
    "flow_id": 0,
    "payload_hex": "{}"
  }},
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload),
        ),
    )
}

fn generated_frame_tcp_data() -> (&'static str, String) {
    let payload = b"hello".to_vec();
    let encoded_hex = hex_encode(
        Frame::new(FrameType::TcpData, 0, 42, payload.clone())
            .encode(65_536)
            .unwrap(),
    );
    (
        "frame_tcp_data.json",
        format!(
            r#"{{
  "id": "frame_tcp_data_v1",
  "kind": "frame",
  "max_frame_size": 65536,
  "frame": {{
    "type": "tcp_data",
    "flags": 0,
    "flow_id": 42,
    "payload_hex": "{}"
  }},
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload),
        ),
    )
}

fn generated_open_tcp_domain() -> (&'static str, String) {
    let payload = OpenTcpPayload {
        target: TargetAddr::Domain("example.com".into()),
        port: 443,
        initial_data: Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
    };
    let encoded_hex = hex_encode(payload.encode().unwrap());
    (
        "open_tcp_domain.json",
        format!(
            r#"{{
  "id": "open_tcp_domain_v1",
  "kind": "open_tcp",
  "target": {{
    "kind": "domain",
    "host": "example.com"
  }},
  "port": 443,
  "initial_data_hex": "{}",
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload.initial_data.as_ref()),
        ),
    )
}

fn generated_open_udp() -> (&'static str, String) {
    let encoded_hex = hex_encode(OpenUdpPayload::new(30_000).encode());
    (
        "open_udp.json",
        format!(
            r#"{{
  "id": "open_udp_v1",
  "kind": "open_udp",
  "idle_timeout_ms": 30000,
  "encoded_hex": "{encoded_hex}"
}}
"#
        ),
    )
}

fn generated_udp_packet_ipv4() -> (&'static str, String) {
    let payload = UdpPacketPayload::new(TargetAddr::Ipv4(Ipv4Addr::LOCALHOST), 53, b"dns".as_ref());
    let encoded_hex = hex_encode(payload.encode().unwrap());
    (
        "udp_packet_ipv4.json",
        format!(
            r#"{{
  "id": "udp_packet_ipv4_v1",
  "kind": "udp_packet",
  "target": "127.0.0.1",
  "port": 53,
  "data_hex": "{}",
  "encoded_hex": "{encoded_hex}"
}}
"#,
            hex_encode(payload.data.as_ref()),
        ),
    )
}

fn generated_replay_window() -> (&'static str, String) {
    (
        "replay_window.json",
        format!(
            r#"{{
  "id": "replay_window_v1",
  "kind": "replay_sequence",
  "window_secs": 10,
  "max_entries": 2,
  "steps": [
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 100,
      "now_unix": 100,
      "expect": "accepted",
      "len_after": 1
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 100,
      "now_unix": 100,
      "expect": "rejected_duplicate_nonce",
      "len_after": 1
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 89,
      "now_unix": 100,
      "expect": "rejected_timestamp_too_old",
      "len_after": 1
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 111,
      "now_unix": 100,
      "expect": "rejected_timestamp_too_new",
      "len_after": 1
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 101,
      "now_unix": 101,
      "expect": "accepted",
      "len_after": 2
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 102,
      "now_unix": 102,
      "expect": "rejected_cache_full",
      "len_after": 2
    }},
    {{
      "operation": "check_insert",
      "credential_id": "u_conformance",
      "nonce_hex": "{}",
      "timestamp_unix": 103,
      "now_unix": 103,
      "expect": "rejected_duplicate_nonce",
      "len_after": 2
    }},
    {{
      "operation": "cleanup",
      "now_unix": 200,
      "len_after": 0
    }}
  ]
}}
"#,
            hex_encode([1u8; 32]),
            hex_encode([1u8; 32]),
            hex_encode([2u8; 32]),
            hex_encode([3u8; 32]),
            hex_encode([4u8; 32]),
            hex_encode([5u8; 32]),
            hex_encode([1u8; 32]),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn client_v1_auth_tag(
    secret: &SecretString,
    protocol_version: u16,
    client_nonce: &[u8; 32],
    timestamp_unix: i64,
    credential_id: &str,
    tunnel_path: &str,
    mode: Mode,
    feature_flags: u64,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(CLIENT_HELLO_AUTH_LABEL);
    mac.update(&protocol_version.to_be_bytes());
    mac.update(client_nonce);
    mac.update(&timestamp_unix.to_be_bytes());
    mac.update(&(credential_id.len() as u16).to_be_bytes());
    mac.update(credential_id.as_bytes());
    mac.update(&(tunnel_path.len() as u16).to_be_bytes());
    mac.update(tunnel_path.as_bytes());
    mac.update(&[mode.wire_id()]);
    mac.update(&feature_flags.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[allow(clippy::too_many_arguments)]
fn server_v1_auth_tag(
    secret: &SecretString,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    session_id: &[u8],
    protocol_version_selected: u16,
    max_frame_size: u32,
    max_concurrent_flows: u32,
    feature_flags_selected: u64,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(SERVER_HELLO_AUTH_LABEL);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.update(&(session_id.len() as u8).to_be_bytes());
    mac.update(session_id);
    mac.update(&protocol_version_selected.to_be_bytes());
    mac.update(&max_frame_size.to_be_bytes());
    mac.update(&max_concurrent_flows.to_be_bytes());
    mac.update(&feature_flags_selected.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[allow(clippy::too_many_arguments)]
fn client_v2_auth_tag(
    secret: &SecretString,
    protocol_version: u16,
    auth_epoch: u64,
    client_nonce: &[u8; 32],
    timestamp_unix: i64,
    credential_hint: &[u8],
    tunnel_path: &str,
    mode: Mode,
    feature_flags: u64,
    rotation_flags: u32,
) -> [u8; 32] {
    let key = auth_v2_epoch_key(secret, auth_epoch, AUTH_V2_CLIENT_INFO);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(CLIENT_HELLO_V2_AUTH_LABEL);
    mac.update(&protocol_version.to_be_bytes());
    mac.update(&auth_epoch.to_be_bytes());
    mac.update(client_nonce);
    mac.update(&timestamp_unix.to_be_bytes());
    mac.update(&(credential_hint.len() as u16).to_be_bytes());
    mac.update(credential_hint);
    mac.update(&(tunnel_path.len() as u16).to_be_bytes());
    mac.update(tunnel_path.as_bytes());
    mac.update(&[mode.wire_id()]);
    mac.update(&feature_flags.to_be_bytes());
    mac.update(&rotation_flags.to_be_bytes());
    mac.finalize().into_bytes().into()
}

#[allow(clippy::too_many_arguments)]
fn server_v2_auth_tag(
    secret: &SecretString,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    session_id: &[u8],
    protocol_version_selected: u16,
    selected_epoch: u64,
    max_frame_size: u32,
    max_concurrent_flows: u32,
    feature_flags_selected: u64,
    rotation_window_secs: u32,
) -> [u8; 32] {
    let key = auth_v2_epoch_key(secret, selected_epoch, AUTH_V2_SERVER_INFO);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(SERVER_HELLO_V2_AUTH_LABEL);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.update(&(session_id.len() as u8).to_be_bytes());
    mac.update(session_id);
    mac.update(&protocol_version_selected.to_be_bytes());
    mac.update(&selected_epoch.to_be_bytes());
    mac.update(&max_frame_size.to_be_bytes());
    mac.update(&max_concurrent_flows.to_be_bytes());
    mac.update(&feature_flags_selected.to_be_bytes());
    mac.update(&rotation_window_secs.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn auth_v2_epoch_key(secret: &SecretString, auth_epoch: u64, info: &[u8]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(AUTH_V2_EPOCH_SALT_LABEL.len() + 8);
    salt.extend_from_slice(AUTH_V2_EPOCH_SALT_LABEL);
    salt.extend_from_slice(&auth_epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret.expose_secret().as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .expect("32-byte HKDF output length is valid");
    key
}

fn hex_encode(input: impl AsRef<[u8]>) -> String {
    input
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn seq_array<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (idx, value) in out.iter_mut().enumerate() {
        *value = start + idx as u8;
    }
    out
}

fn seq_vec(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|idx| start + idx as u8).collect()
}

fn frame_type(value: &str) -> FrameType {
    match value {
        "dns_query" => FrameType::DnsQuery,
        "dns_response" => FrameType::DnsResponse,
        "tcp_data" => FrameType::TcpData,
        "padding" => FrameType::Padding,
        other => panic!("unknown frame type in vector: {other}"),
    }
}

fn error_code(value: &str) -> ErrorCode {
    match value {
        "target_connect_failed" => ErrorCode::TargetConnectFailed,
        "flow_not_found" => ErrorCode::FlowNotFound,
        "flow_limit_exceeded" => ErrorCode::FlowLimitExceeded,
        "protocol_error" => ErrorCode::ProtocolError,
        "internal_error" => ErrorCode::InternalError,
        other => panic!("unknown error code in vector: {other}"),
    }
}

fn assert_replay_expectation(id: &str, expect: &str, result: maverick_core::Result<()>) {
    match expect {
        "accepted" => result.unwrap_or_else(|err| panic!("{id}: expected accepted: {err}")),
        "rejected_duplicate_nonce" => {
            let err = result.expect_err("expected duplicate nonce rejection");
            assert!(err.to_string().contains("duplicate nonce"), "{id}: {err}");
        }
        "rejected_timestamp_too_old" => {
            let err = result.expect_err("expected old timestamp rejection");
            assert!(err.to_string().contains("timestamp too old"), "{id}: {err}");
        }
        "rejected_timestamp_too_new" => {
            let err = result.expect_err("expected new timestamp rejection");
            assert!(err.to_string().contains("timestamp too new"), "{id}: {err}");
        }
        "rejected_cache_full" => {
            let err = result.expect_err("expected replay cache full rejection");
            assert!(err.to_string().contains("replay cache full"), "{id}: {err}");
        }
        other => panic!("{id}: unknown replay expectation {other}"),
    }
}

fn hex_decode(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex input must have even length"
    );
    (0..input.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&input[idx..idx + 2], 16).unwrap())
        .collect()
}

fn hex_array<const N: usize>(input: &str) -> [u8; N] {
    hex_decode(input).try_into().unwrap()
}

impl TargetVector {
    fn into_target_addr(self) -> TargetAddr {
        match self {
            Self::Domain { host } => TargetAddr::Domain(host),
            Self::Ipv4 { addr } => TargetAddr::Ipv4(addr),
            Self::Ipv6 { addr } => TargetAddr::Ipv6(addr),
        }
    }
}
