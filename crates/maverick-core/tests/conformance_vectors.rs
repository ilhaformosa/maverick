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
    ClientHello, ClientHelloV2, Error, Frame, FrameType, Mode, OpenTcpPayload, OpenUdpPayload,
    SecretString, ServerHello, ServerHelloV2, TargetAddr, UdpPacketPayload,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
const TEST_SECRET: &str = "mv1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const ALT_TEST_SECRET: &str = "mv1_AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const AUTH_V2_EPOCH_SALT_LABEL: &[u8] = b"Maverick auth v2 epoch";
const AUTH_V2_CLIENT_INFO: &[u8] = b"Maverick auth v2 client mac";
const AUTH_V2_SERVER_INFO: &[u8] = b"Maverick auth v2 server mac";
const AUTH_V3_MAGIC: &[u8; 4] = b"MVA3";
const AUTH_V3_VERSION: u16 = 3;
const AUTH_V3_CLIENT_CONTROL_TYPE: u8 = 1;
const AUTH_V3_SERVER_CONFIRMATION_TYPE: u8 = 2;
const AUTH_V3_CLIENT_CONTROL_LEN: usize = 256;
const AUTH_V3_SERVER_CONFIRMATION_LEN: usize = 320;
const AUTH_V3_H2_CARRIER: u8 = 1;
const AUTH_V3_H3_CARRIER: u8 = 2;
const AUTH_V3_DIRECT_TRUST_ROUTE: u8 = 1;
const AUTH_V3_TLS_EXPORTER_BINDING: u8 = 1;
const AUTH_V3_KEX_CLASSICAL_FLOOR: u16 = 1;
const AUTH_V3_DIRECT_CAPABILITY: u32 = 1;
const AUTH_V3_BOUNDED_RESOURCE_CLASS: u16 = 1;
const AUTH_V3_SENTINEL: &[u8; 16] = b"MVRK-AUTH-V3-REQ";
const AUTH_V3_EXPORTER_LABEL: &str = "EXPORTER-Channel-Binding";
const AUTH_V3_PRINCIPAL_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 principal commitment";
const AUTH_V3_DEPLOYMENT_COMMITMENT_LABEL: &[u8] =
    b"Maverick auth v3 deployment profile commitment";
const AUTH_V3_NAMESPACE_COMMITMENT_LABEL: &[u8] =
    b"Maverick auth v3 credential namespace commitment";
const AUTH_V3_HKDF_SALT_LABEL: &[u8] = b"Maverick auth v3 hkdf salt";
const AUTH_V3_CLIENT_KEY_INFO: &[u8] = b"Maverick auth v3 client control mac key";
const AUTH_V3_SERVER_KEY_INFO: &[u8] = b"Maverick auth v3 server confirmation mac key";
const AUTH_V3_POLICY_HASH_LABEL: &[u8] = b"Maverick auth v3 policy hash";
const AUTH_V3_CLIENT_TRANSCRIPT_LABEL: &[u8] = b"Maverick auth v3 client control transcript";
const AUTH_V3_CLIENT_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 client control commitment";
const AUTH_V3_SERVER_TRANSCRIPT_LABEL: &[u8] = b"Maverick auth v3 server confirmation transcript";

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
    AuthV3DirectClientControl {
        #[serde(flatten)]
        vector: AuthV3ClientControlVector,
    },
    AuthV3DirectServerConfirmation {
        #[serde(flatten)]
        vector: AuthV3ServerConfirmationVector,
    },
    ReplaySequence {
        id: String,
        window_secs: i64,
        max_entries: usize,
        steps: Vec<ReplayStep>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthV3ClientControlVector {
    id: String,
    carrier: String,
    actual_carrier: String,
    actual_tls_version: String,
    expected_trust_route: String,
    actual_trust_route: String,
    early_data: bool,
    secret_test_only: String,
    exporter_label_ascii: String,
    exporter_context_present: bool,
    exporter_context_hex: String,
    exporter_length: usize,
    tls_exporter_hex: String,
    principal_id_hex: String,
    deployment_profile_id_hex: String,
    credential_namespace_id_hex: String,
    connection_deployment_profile_id_hex: String,
    expected_server_identity_id_hex: String,
    actual_server_identity_id_hex: String,
    expected_control_path: String,
    actual_control_path: String,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    client_time_unix: u64,
    server_now_unix: u64,
    client_nonce_hex: String,
    policy_minimum_hex: String,
    principal_commitment_hex: String,
    deployment_profile_commitment_hex: String,
    credential_namespace_commitment_hex: String,
    policy_minimum_hash_hex: String,
    client_mac_key_hex: String,
    client_auth_tag_hex: String,
    encoded_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthV3ServerConfirmationVector {
    id: String,
    carrier: String,
    actual_carrier: String,
    actual_tls_version: String,
    expected_trust_route: String,
    actual_trust_route: String,
    early_data: bool,
    secret_test_only: String,
    exporter_label_ascii: String,
    exporter_context_present: bool,
    exporter_context_hex: String,
    exporter_length: usize,
    tls_exporter_hex: String,
    principal_id_hex: String,
    deployment_profile_id_hex: String,
    credential_namespace_id_hex: String,
    connection_deployment_profile_id_hex: String,
    expected_server_identity_id_hex: String,
    actual_server_identity_id_hex: String,
    expected_control_path: String,
    actual_control_path: String,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    server_now_unix: u64,
    client_now_unix: u64,
    admission_expiry_unix: u64,
    hard_expiry_unix: u64,
    server_nonce_hex: String,
    session_id_hex: String,
    policy_selected_hex: String,
    principal_commitment_hex: String,
    deployment_profile_commitment_hex: String,
    credential_namespace_commitment_hex: String,
    policy_selected_hash_hex: String,
    client_control_encoded_hex: String,
    client_control_commitment_hex: String,
    max_frame_size: u32,
    max_concurrent_flows: u32,
    client_max_frame_size_cap: u32,
    client_max_concurrent_flows_cap: u32,
    server_mac_key_hex: String,
    server_auth_tag_hex: String,
    encoded_hex: String,
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
            Vector::AuthV3DirectClientControl { vector } => {
                verify_auth_v3_client_vector(&vector);
            }
            Vector::AuthV3DirectServerConfirmation { vector } => {
                verify_auth_v3_server_vector(&vector);
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
fn auth_v1_mode_tamper_reaches_tag_and_unknown_mode_gates() {
    let vector = read_vector("auth_v1_client_hello.json");
    let Vector::ClientHelloV1 {
        id,
        secret_test_only,
        tunnel_path,
        credential_id,
        mode,
        encoded_hex,
        ..
    } = vector
    else {
        panic!("expected auth v1 client hello vector");
    };
    let secret = SecretString::new(secret_test_only).unwrap();
    let encoded = hex_decode(&encoded_hex);
    let mode_offset = 2 + 32 + 8 + 2 + credential_id.len();
    assert_eq!(encoded[mode_offset], mode.wire_id(), "{id}");

    let original = ClientHello::decode(&encoded).unwrap();
    assert!(original.verify(&secret, &tunnel_path), "{id}");

    let known_mode = different_known_mode(mode);
    let mut known_mode_tamper = encoded.clone();
    known_mode_tamper[mode_offset] = known_mode.wire_id();
    let decoded = ClientHello::decode(&known_mode_tamper).unwrap();
    assert_eq!(decoded.mode, known_mode, "{id}");
    assert_eq!(decoded.auth_tag, original.auth_tag, "{id}");
    assert!(!decoded.verify(&secret, &tunnel_path), "{id}");

    let mut unknown_mode_tamper = encoded;
    unknown_mode_tamper[mode_offset] = 0xff;
    assert!(
        matches!(
            ClientHello::decode(&unknown_mode_tamper),
            Err(Error::MalformedFrame("unknown mode"))
        ),
        "{id}"
    );
}

#[test]
fn auth_v2_mode_tamper_reaches_tag_and_unknown_mode_gates() {
    let vector = read_vector("auth_v2_client_hello.json");
    let Vector::ClientHelloV2 {
        id,
        secret_test_only,
        tunnel_path,
        credential_hint_hex,
        mode,
        encoded_hex,
        ..
    } = vector
    else {
        panic!("expected auth v2 client hello vector");
    };
    let secret = SecretString::new(secret_test_only).unwrap();
    let encoded = hex_decode(&encoded_hex);
    let credential_hint_len = hex_decode(&credential_hint_hex).len();
    let mode_offset = 2 + 8 + 32 + 8 + 2 + credential_hint_len;
    assert_eq!(encoded[mode_offset], mode.wire_id(), "{id}");

    let original = ClientHelloV2::decode(&encoded).unwrap();
    assert!(original.verify(&secret, &tunnel_path), "{id}");

    let known_mode = different_known_mode(mode);
    let mut known_mode_tamper = encoded.clone();
    known_mode_tamper[mode_offset] = known_mode.wire_id();
    let decoded = ClientHelloV2::decode(&known_mode_tamper).unwrap();
    assert_eq!(decoded.mode, known_mode, "{id}");
    assert_eq!(decoded.auth_tag, original.auth_tag, "{id}");
    assert!(!decoded.verify(&secret, &tunnel_path), "{id}");

    let mut unknown_mode_tamper = encoded;
    unknown_mode_tamper[mode_offset] = 0xff;
    assert!(
        matches!(
            ClientHelloV2::decode(&unknown_mode_tamper),
            Err(Error::MalformedFrame("unknown mode"))
        ),
        "{id}"
    );
}

#[test]
fn auth_v3_direct_client_rejects_malformed_and_unsafe_inputs() {
    let inputs = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    let encoded = build_auth_v3_client_control(&inputs).encoded.to_vec();
    assert!(verify_auth_v3_client_control(&encoded, &inputs).is_ok());

    let mut cases = vec![
        (mutated(&encoded, 0, 0xff), AuthV3TestError::Header),
        (mutated(&encoded, 5, 0x04), AuthV3TestError::Header),
        (mutated(&encoded, 6, 0x02), AuthV3TestError::Header),
        (mutated(&encoded, 8, 0x00), AuthV3TestError::Header),
        (mutated(&encoded, 7, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 10, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 21, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 30, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 12, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 13, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 14, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 15, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 16, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 17, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 18, 0x01), AuthV3TestError::Policy),
        (mutated(&encoded, 19, 0x01), AuthV3TestError::Policy),
        (mutated(&encoded, 20, 0xff), AuthV3TestError::Binding),
    ];

    let mut unassigned_route_and_binding = encoded.clone();
    unassigned_route_and_binding[15] = 0x02;
    unassigned_route_and_binding[20] = 0x02;
    cases.push((unassigned_route_and_binding, AuthV3TestError::Policy));

    let mut bad_kex = encoded.clone();
    write_u16(&mut bad_kex, 22, 0x0002);
    cases.push((bad_kex, AuthV3TestError::Kex));
    let mut bad_capabilities = encoded.clone();
    write_u32(&mut bad_capabilities, 24, 0x0000_0003);
    cases.push((bad_capabilities, AuthV3TestError::Capabilities));
    let mut bad_resource = encoded.clone();
    write_u16(&mut bad_resource, 28, 0x0002);
    cases.push((bad_resource, AuthV3TestError::ResourceClass));
    let mut epoch_zero = encoded.clone();
    write_u64(&mut epoch_zero, 32, 0);
    cases.push((epoch_zero, AuthV3TestError::Epoch));
    let mut stale_time = encoded.clone();
    write_u64(&mut stale_time, 40, inputs.server_now_unix - 301);
    cases.push((stale_time, AuthV3TestError::Time));
    let mut future_time = encoded.clone();
    write_u64(&mut future_time, 40, inputs.server_now_unix + 301);
    cases.push((future_time, AuthV3TestError::Time));
    let mut zero_time = encoded.clone();
    write_u64(&mut zero_time, 40, 0);
    cases.push((zero_time, AuthV3TestError::Time));
    let mut maximum_time = encoded.clone();
    write_u64(&mut maximum_time, 40, u64::MAX);
    cases.push((maximum_time, AuthV3TestError::Time));
    for offset in [48, 80, 112] {
        cases.push((mutated(&encoded, offset, 0xff), AuthV3TestError::Identity));
    }
    let mut zero_nonce = encoded.clone();
    zero_nonce[144..176].fill(0);
    cases.push((zero_nonce, AuthV3TestError::Nonce));
    cases.push((mutated(&encoded, 176, b'X'), AuthV3TestError::Sentinel));
    cases.push((mutated(&encoded, 192, 0xff), AuthV3TestError::Policy));
    cases.push((mutated(&encoded, 224, 0xff), AuthV3TestError::Mac));

    for (candidate, expected) in cases {
        assert_eq!(
            verify_auth_v3_client_control(&candidate, &inputs),
            Err(expected)
        );
    }

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(
        verify_auth_v3_client_control(&truncated, &inputs),
        Err(AuthV3TestError::Shape)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        verify_auth_v3_client_control(&trailing, &inputs),
        Err(AuthV3TestError::Shape)
    );

    let mut expired = inputs.clone();
    expired.credential_not_after_unix = expired.server_now_unix;
    assert_eq!(
        verify_auth_v3_client_control(&encoded, &expired),
        Err(AuthV3TestError::Credential)
    );
    let mut zero_id = inputs;
    zero_id.principal_id = [0; 16];
    assert_eq!(
        verify_auth_v3_client_control(&encoded, &zero_id),
        Err(AuthV3TestError::Credential)
    );
}

#[test]
fn auth_v3_direct_requires_trusted_connection_and_exact_registry() {
    let h2 = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    let h2_encoded = build_auth_v3_client_control(&h2).encoded;

    let mut h2_claims_h3 = h2.clone();
    h2_claims_h3.wire_carrier = AUTH_V3_H3_CARRIER;
    let correctly_macd_h3_claim = build_auth_v3_client_control(&h2_claims_h3).encoded;
    assert_eq!(
        verify_auth_v3_client_control(&correctly_macd_h3_claim, &h2_claims_h3),
        Err(AuthV3TestError::Context)
    );

    let mut h3_claims_h2 = auth_v3_test_inputs(AUTH_V3_H3_CARRIER);
    h3_claims_h2.wire_carrier = AUTH_V3_H2_CARRIER;
    let correctly_macd_h2_claim = build_auth_v3_client_control(&h3_claims_h2).encoded;
    assert_eq!(
        verify_auth_v3_client_control(&correctly_macd_h2_claim, &h3_claims_h2),
        Err(AuthV3TestError::Context)
    );

    let mut contexts = Vec::new();
    let mut tls12 = h2.clone();
    tls12.connection.actual_tls_version = AuthV3TestTlsVersion::Tls12;
    contexts.push(tls12);
    let mut non_direct = h2.clone();
    non_direct.connection.actual_trust_route = 0x02;
    contexts.push(non_direct);
    let mut early_data = h2.clone();
    early_data.connection.early_data = true;
    contexts.push(early_data);
    let mut missing_exporter_context = h2.clone();
    missing_exporter_context.connection.exporter_context = None;
    contexts.push(missing_exporter_context);
    let mut nonempty_exporter_context = h2.clone();
    nonempty_exporter_context.connection.exporter_context = Some(vec![0]);
    contexts.push(nonempty_exporter_context);
    let mut wrong_deployment = h2.clone();
    wrong_deployment.connection.deployment_profile_id[0] ^= 1;
    contexts.push(wrong_deployment);
    let mut wrong_server = h2.clone();
    wrong_server.connection.server_identity_id[0] ^= 1;
    contexts.push(wrong_server);
    let mut wrong_path = h2.clone();
    wrong_path.connection.control_path = "/different-test-control".to_owned();
    contexts.push(wrong_path);
    for context in contexts {
        assert_eq!(
            verify_auth_v3_client_control(&h2_encoded, &context),
            Err(AuthV3TestError::Context)
        );
    }

    let mut reused_psk = h2.clone();
    reused_psk.deployment_profile_id[0] ^= 1;
    assert_eq!(
        validate_auth_v3_provisioning_registry(&[h2.clone(), reused_psk]),
        Err(AuthV3TestError::Credential)
    );

    let mut different_psk = h2.clone();
    different_psk.secret = ALT_TEST_SECRET.to_owned();
    assert_eq!(
        validate_auth_v3_provisioning_registry(&[h2.clone(), different_psk]),
        Err(AuthV3TestError::Credential)
    );
    assert_eq!(
        validate_auth_v3_provisioning_registry(&[h2.clone(), h2.clone()]),
        Err(AuthV3TestError::Credential)
    );

    let mut conflicting_profile = h2.clone();
    conflicting_profile.expected_control_path = "/conflicting-test-control".to_owned();
    assert_eq!(
        validate_auth_v3_provisioning_registry(&[h2, conflicting_profile]),
        Err(AuthV3TestError::Context)
    );

    assert!(!auth_v3_time_within_skew(0, 0));
    assert!(auth_v3_time_within_skew(300, 0));
    assert!(auth_v3_time_within_skew(u64::MAX - 300, u64::MAX));
    assert!(!auth_v3_time_within_skew(u64::MAX, u64::MAX));
    assert!(!auth_v3_time_within_skew(301, 0));
    assert!(!auth_v3_time_within_skew(u64::MAX, 0));
}

#[test]
fn auth_v3_direct_server_rejects_malformed_and_unsafe_inputs() {
    let inputs = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    let client = build_auth_v3_client_control(&inputs).encoded;
    let encoded = generate_auth_v3_server_confirmation(&inputs, &client)
        .unwrap()
        .encoded
        .to_vec();
    assert!(verify_auth_v3_server_confirmation(&encoded, &client, &inputs).is_ok());

    let mut server_ahead_by_300 = inputs.clone();
    server_ahead_by_300.client_now_unix = server_ahead_by_300.server_now_unix - 300;
    server_ahead_by_300.client_time_unix = server_ahead_by_300.client_now_unix;
    let skewed_client = build_auth_v3_client_control(&server_ahead_by_300).encoded;
    let skewed_server = generate_auth_v3_server_confirmation(&server_ahead_by_300, &skewed_client)
        .unwrap()
        .encoded;
    assert!(verify_auth_v3_server_confirmation(
        &skewed_server,
        &skewed_client,
        &server_ahead_by_300,
    )
    .is_ok());
    assert!(auth_v3_valid_server_expiries(
        10_000, 11_800, 96_400, 96_400
    ));
    assert!(!auth_v3_valid_server_expiries(
        10_000, 11_800, 96_400, 11_799
    ));
    assert!(!auth_v3_valid_server_expiries(
        10_000, 11_800, 96_400, 96_399
    ));
    assert!(auth_v3_valid_client_expiries(
        10_000, 12_100, 96_700, 96_700
    ));
    assert!(!auth_v3_valid_client_expiries(
        10_000, 12_100, 96_700, 12_099
    ));
    assert!(!auth_v3_valid_client_expiries(
        10_000, 12_100, 96_700, 96_699
    ));
    assert!(!auth_v3_valid_client_expiries(
        10_000, 12_101, 96_700, 96_700
    ));
    assert!(!auth_v3_valid_client_expiries(
        10_000, 12_100, 96_701, 96_701
    ));
    assert!(!auth_v3_valid_client_expiries(
        u64::MAX - 10,
        0,
        1,
        u64::MAX
    ));

    let mut credential_boundary = inputs.clone();
    credential_boundary.credential_not_after_unix = credential_boundary.hard_expiry_unix;
    let boundary_client = build_auth_v3_client_control(&credential_boundary).encoded;
    let boundary_server =
        generate_auth_v3_server_confirmation(&credential_boundary, &boundary_client)
            .unwrap()
            .encoded;
    assert!(verify_auth_v3_server_confirmation(
        &boundary_server,
        &boundary_client,
        &credential_boundary,
    )
    .is_ok());

    let mut admission_after_credential = inputs.clone();
    admission_after_credential.credential_not_after_unix =
        admission_after_credential.admission_expiry_unix - 1;
    assert!(matches!(
        generate_auth_v3_server_confirmation(&admission_after_credential, &client),
        Err(AuthV3TestError::Expiry)
    ));
    assert_eq!(
        verify_auth_v3_server_confirmation(&encoded, &client, &admission_after_credential),
        Err(AuthV3TestError::Expiry)
    );

    let mut hard_after_credential = inputs.clone();
    hard_after_credential.credential_not_after_unix = hard_after_credential.hard_expiry_unix - 1;
    assert!(matches!(
        generate_auth_v3_server_confirmation(&hard_after_credential, &client),
        Err(AuthV3TestError::Expiry)
    ));
    assert_eq!(
        verify_auth_v3_server_confirmation(&encoded, &client, &hard_after_credential),
        Err(AuthV3TestError::Expiry)
    );

    let mut cases = vec![
        (mutated(&encoded, 0, 0xff), AuthV3TestError::Header),
        (mutated(&encoded, 5, 0x04), AuthV3TestError::Header),
        (mutated(&encoded, 6, 0x01), AuthV3TestError::Header),
        (mutated(&encoded, 8, 0x00), AuthV3TestError::Header),
        (mutated(&encoded, 7, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 10, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 21, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 30, 0x01), AuthV3TestError::Reserved),
        (mutated(&encoded, 12, 0xff), AuthV3TestError::Policy),
        (mutated(&encoded, 14, 0x02), AuthV3TestError::Policy),
        (mutated(&encoded, 18, 0x01), AuthV3TestError::Policy),
        (mutated(&encoded, 19, 0x01), AuthV3TestError::Policy),
        (mutated(&encoded, 20, 0x02), AuthV3TestError::Binding),
    ];

    let mut bad_kex = encoded.clone();
    write_u16(&mut bad_kex, 22, 0x0002);
    cases.push((bad_kex, AuthV3TestError::Kex));
    let mut bad_capabilities = encoded.clone();
    write_u32(&mut bad_capabilities, 24, 0x0000_0003);
    cases.push((bad_capabilities, AuthV3TestError::Capabilities));
    let mut bad_resource = encoded.clone();
    write_u16(&mut bad_resource, 28, 0x0002);
    cases.push((bad_resource, AuthV3TestError::ResourceClass));
    let mut wrong_epoch = encoded.clone();
    write_u64(&mut wrong_epoch, 32, inputs.credential_epoch + 1);
    cases.push((wrong_epoch, AuthV3TestError::Epoch));
    let mut expired_admission = encoded.clone();
    write_u64(&mut expired_admission, 40, inputs.server_now_unix);
    cases.push((expired_admission, AuthV3TestError::Expiry));
    let mut reversed_expiry = encoded.clone();
    write_u64(&mut reversed_expiry, 40, inputs.hard_expiry_unix);
    cases.push((reversed_expiry, AuthV3TestError::Expiry));
    let mut excessive_admission = encoded.clone();
    write_u64(&mut excessive_admission, 40, inputs.server_now_unix + 1_801);
    cases.push((excessive_admission, AuthV3TestError::Expiry));
    let mut excessive_hard = encoded.clone();
    write_u64(&mut excessive_hard, 48, inputs.server_now_unix + 86_401);
    cases.push((excessive_hard, AuthV3TestError::Expiry));
    for offset in [56, 88, 120] {
        cases.push((mutated(&encoded, offset, 0xff), AuthV3TestError::Echo));
    }
    let mut zero_server_nonce = encoded.clone();
    zero_server_nonce[152..184].fill(0);
    cases.push((zero_server_nonce, AuthV3TestError::Nonce));
    let mut zero_session = encoded.clone();
    zero_session[184..200].fill(0);
    cases.push((zero_session, AuthV3TestError::Nonce));
    cases.push((mutated(&encoded, 200, b'X'), AuthV3TestError::Sentinel));
    cases.push((mutated(&encoded, 216, 0xff), AuthV3TestError::Policy));
    cases.push((mutated(&encoded, 248, 0xff), AuthV3TestError::Commitment));
    let mut zero_frame_limit = encoded.clone();
    write_u32(&mut zero_frame_limit, 280, 0);
    cases.push((zero_frame_limit, AuthV3TestError::Limits));
    let mut excessive_frame_limit = encoded.clone();
    write_u32(
        &mut excessive_frame_limit,
        280,
        inputs.client_max_frame_size_cap + 1,
    );
    cases.push((excessive_frame_limit, AuthV3TestError::Limits));
    let mut zero_flow_limit = encoded.clone();
    write_u32(&mut zero_flow_limit, 284, 0);
    cases.push((zero_flow_limit, AuthV3TestError::Limits));
    let mut excessive_flow_limit = encoded.clone();
    write_u32(
        &mut excessive_flow_limit,
        284,
        inputs.client_max_concurrent_flows_cap + 1,
    );
    cases.push((excessive_flow_limit, AuthV3TestError::Limits));
    cases.push((mutated(&encoded, 288, 0xff), AuthV3TestError::Mac));

    for (candidate, expected) in cases {
        assert_eq!(
            verify_auth_v3_server_confirmation(&candidate, &client, &inputs),
            Err(expected)
        );
    }

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(
        verify_auth_v3_server_confirmation(&truncated, &client, &inputs),
        Err(AuthV3TestError::Shape)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        verify_auth_v3_server_confirmation(&trailing, &client, &inputs),
        Err(AuthV3TestError::Shape)
    );

    let mut client_clock_rejects = inputs.clone();
    client_clock_rejects.client_now_unix = client_clock_rejects.admission_expiry_unix;
    assert_eq!(
        verify_auth_v3_server_confirmation(
            &generate_auth_v3_server_confirmation(&client_clock_rejects, &client)
                .unwrap()
                .encoded,
            &client,
            &client_clock_rejects,
        ),
        Err(AuthV3TestError::Expiry)
    );

    let mut overflow = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    overflow.server_now_unix = u64::MAX - 1;
    overflow.client_now_unix = u64::MAX - 1;
    overflow.client_time_unix = u64::MAX - 1;
    overflow.credential_not_after_unix = u64::MAX;
    overflow.admission_expiry_unix = 0;
    overflow.hard_expiry_unix = 1;
    let overflow_client = build_auth_v3_client_control(&overflow).encoded;
    assert!(matches!(
        generate_auth_v3_server_confirmation(&overflow, &overflow_client),
        Err(AuthV3TestError::Expiry)
    ));
}

#[test]
fn auth_v3_direct_exporter_generation_and_legacy_isolation() {
    let h2 = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    let h2_client = build_auth_v3_client_control(&h2).encoded;
    let h2_server = generate_auth_v3_server_confirmation(&h2, &h2_client)
        .unwrap()
        .encoded;

    let h3 = auth_v3_test_inputs(AUTH_V3_H3_CARRIER);
    let mut h3_exporter_on_h2 = h2.clone();
    h3_exporter_on_h2.connection.tls_exporter = h3.connection.tls_exporter;
    assert_eq!(
        verify_auth_v3_client_control(&h2_client, &h3_exporter_on_h2),
        Err(AuthV3TestError::Mac)
    );
    assert_eq!(
        verify_auth_v3_server_confirmation(&h2_server, &h2_client, &h3_exporter_on_h2),
        Err(AuthV3TestError::Mac)
    );

    let mut replacement_generation = h2.clone();
    replacement_generation.connection.tls_exporter = seq_array::<32>(0xe0);
    assert_eq!(
        verify_auth_v3_client_control(&h2_client, &replacement_generation),
        Err(AuthV3TestError::Mac)
    );

    let mut changed_client_tag = h2_client;
    changed_client_tag[224] ^= 1;
    assert_ne!(
        auth_v3_client_control_commitment(&changed_client_tag),
        auth_v3_client_control_commitment(&h2_client)
    );

    for legacy_name in [
        "auth_v1_client_hello.json",
        "auth_v1_server_hello.json",
        "auth_v2_client_hello.json",
        "auth_v2_server_hello.json",
    ] {
        let legacy = match read_vector(legacy_name) {
            Vector::ClientHelloV1 { encoded_hex, .. }
            | Vector::ServerHelloV1 { encoded_hex, .. }
            | Vector::ClientHelloV2 { encoded_hex, .. }
            | Vector::ServerHelloV2 { encoded_hex, .. } => hex_decode(&encoded_hex),
            _ => panic!("expected legacy auth vector"),
        };
        assert_eq!(
            verify_auth_v3_client_control(&legacy, &h2),
            Err(AuthV3TestError::Shape)
        );
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let spec = std::fs::read_to_string(repo_root.join("docs/AUTH_V3_DIRECT_SPEC.md")).unwrap();
    assert!(spec.contains("does **not** prove that current runtime"));
    assert!(spec.contains("code prevents authenticated state transfer"));
}

#[test]
fn auth_v3_direct_control_is_single_use_and_failure_closes_test_generation() {
    let inputs = auth_v3_test_inputs(AUTH_V3_H2_CARRIER);
    let encoded = build_auth_v3_client_control(&inputs).encoded;
    let mut gate = AuthV3TestControlGate::default();
    assert!(gate.verify_once(&encoded, &inputs).is_ok());
    assert_eq!(
        gate.verify_once(&encoded, &inputs),
        Err(AuthV3TestError::Duplicate)
    );

    let mut occupied_gate = AuthV3TestControlGate::default();
    assert!(occupied_gate.occupy_slot().is_ok());
    assert_eq!(
        occupied_gate.verify_once(&encoded, &inputs),
        Err(AuthV3TestError::Duplicate)
    );

    let mut bad = encoded;
    bad[224] ^= 1;
    let mut failed_gate = AuthV3TestControlGate::default();
    assert_eq!(
        failed_gate.verify_once(&bad, &inputs),
        Err(AuthV3TestError::Mac)
    );
    assert_eq!(
        failed_gate.verify_once(&encoded, &inputs),
        Err(AuthV3TestError::Closed)
    );
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

fn read_vector(file_name: &str) -> Vector {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input =
        std::fs::read_to_string(repo_root.join("conformance/vectors").join(file_name)).unwrap();
    serde_json::from_str(&input).unwrap()
}

fn different_known_mode(mode: Mode) -> Mode {
    match mode {
        Mode::Auto => Mode::Stable,
        Mode::Stable | Mode::Private => Mode::Auto,
    }
}

#[derive(Clone)]
struct AuthV3TestInputs {
    secret: String,
    wire_carrier: u8,
    connection: AuthV3TrustedConnectionContext,
    principal_id: [u8; 16],
    deployment_profile_id: [u8; 16],
    credential_namespace_id: [u8; 16],
    expected_server_identity_id: [u8; 16],
    expected_trust_route: u8,
    expected_control_path: String,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    client_time_unix: u64,
    server_now_unix: u64,
    client_now_unix: u64,
    client_nonce: [u8; 32],
    admission_expiry_unix: u64,
    hard_expiry_unix: u64,
    server_nonce: [u8; 32],
    session_id: [u8; 16],
    max_frame_size: u32,
    max_concurrent_flows: u32,
    client_max_frame_size_cap: u32,
    client_max_concurrent_flows_cap: u32,
}

#[derive(Clone)]
struct AuthV3TrustedConnectionContext {
    actual_carrier: u8,
    actual_tls_version: AuthV3TestTlsVersion,
    actual_trust_route: u8,
    early_data: bool,
    tls_exporter: [u8; 32],
    exporter_context: Option<Vec<u8>>,
    deployment_profile_id: [u8; 16],
    server_identity_id: [u8; 16],
    control_path: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthV3TestTlsVersion {
    Tls12,
    Tls13,
}

struct AuthV3ClientMaterial {
    policy: [u8; 8],
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    policy_hash: [u8; 32],
    mac_key: [u8; 32],
    auth_tag: [u8; 32],
    encoded: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
}

struct AuthV3ServerMaterial {
    policy: [u8; 8],
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    policy_hash: [u8; 32],
    client_control_commitment: [u8; 32],
    mac_key: [u8; 32],
    auth_tag: [u8; 32],
    encoded: [u8; AUTH_V3_SERVER_CONFIRMATION_LEN],
}

#[derive(PartialEq, Eq)]
struct ParsedAuthV3ClientControl {
    policy: [u8; 8],
    credential_epoch: u64,
    client_time_unix: u64,
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    auth_tag: [u8; 32],
}

#[derive(PartialEq, Eq)]
struct ParsedAuthV3ServerConfirmation {
    policy: [u8; 8],
    credential_epoch: u64,
    admission_expiry_unix: u64,
    hard_expiry_unix: u64,
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    client_control_commitment: [u8; 32],
    max_frame_size: u32,
    max_concurrent_flows: u32,
    auth_tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthV3TestError {
    Shape,
    Header,
    Reserved,
    Policy,
    Binding,
    Kex,
    Capabilities,
    ResourceClass,
    Context,
    Credential,
    Epoch,
    Time,
    Identity,
    Nonce,
    Sentinel,
    Expiry,
    Echo,
    Limits,
    Commitment,
    Mac,
    Duplicate,
    Closed,
}

impl std::fmt::Debug for ParsedAuthV3ClientControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("parsed auth v3 client control")
    }
}

impl std::fmt::Debug for ParsedAuthV3ServerConfirmation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("parsed auth v3 server confirmation")
    }
}

#[derive(Default)]
struct AuthV3TestControlGate {
    state: AuthV3TestControlState,
}

#[derive(Default)]
enum AuthV3TestControlState {
    #[default]
    Awaiting,
    Occupied,
    Authenticated,
    Closed,
}

impl AuthV3TestControlGate {
    fn verify_once(
        &mut self,
        input: &[u8],
        inputs: &AuthV3TestInputs,
    ) -> Result<(), AuthV3TestError> {
        self.occupy_slot()?;
        match verify_auth_v3_client_control(input, inputs) {
            Ok(_) => {
                self.state = AuthV3TestControlState::Authenticated;
                Ok(())
            }
            Err(error) => {
                self.state = AuthV3TestControlState::Closed;
                Err(error)
            }
        }
    }

    fn occupy_slot(&mut self) -> Result<(), AuthV3TestError> {
        match self.state {
            AuthV3TestControlState::Awaiting => {
                self.state = AuthV3TestControlState::Occupied;
                Ok(())
            }
            AuthV3TestControlState::Occupied | AuthV3TestControlState::Authenticated => {
                Err(AuthV3TestError::Duplicate)
            }
            AuthV3TestControlState::Closed => Err(AuthV3TestError::Closed),
        }
    }
}

fn auth_v3_test_inputs(carrier: u8) -> AuthV3TestInputs {
    let tls_exporter = match carrier {
        AUTH_V3_H2_CARRIER => seq_array::<32>(0x60),
        AUTH_V3_H3_CARRIER => seq_array::<32>(0x80),
        _ => panic!("unsupported test carrier"),
    };
    let server_now_unix = 1_800_000_000;
    let deployment_profile_id = seq_array::<16>(0x20);
    let server_identity_id = seq_array::<16>(0x50);
    let control_path = "/maverick-test-control".to_owned();
    AuthV3TestInputs {
        secret: TEST_SECRET.to_owned(),
        wire_carrier: carrier,
        connection: AuthV3TrustedConnectionContext {
            actual_carrier: carrier,
            actual_tls_version: AuthV3TestTlsVersion::Tls13,
            actual_trust_route: AUTH_V3_DIRECT_TRUST_ROUTE,
            early_data: false,
            tls_exporter,
            exporter_context: Some(Vec::new()),
            deployment_profile_id,
            server_identity_id,
            control_path: control_path.clone(),
        },
        principal_id: seq_array::<16>(0x10),
        deployment_profile_id,
        credential_namespace_id: seq_array::<16>(0x30),
        expected_server_identity_id: server_identity_id,
        expected_trust_route: AUTH_V3_DIRECT_TRUST_ROUTE,
        expected_control_path: control_path,
        credential_epoch: 7,
        credential_not_after_unix: server_now_unix + 172_800,
        client_time_unix: server_now_unix,
        server_now_unix,
        client_now_unix: server_now_unix,
        client_nonce: seq_array::<32>(0x40),
        admission_expiry_unix: server_now_unix + 1_800,
        hard_expiry_unix: server_now_unix + 86_400,
        server_nonce: seq_array::<32>(0xa0),
        session_id: seq_array::<16>(0xc0),
        max_frame_size: 65_536,
        max_concurrent_flows: 128,
        client_max_frame_size_cap: 131_072,
        client_max_concurrent_flows_cap: 256,
    }
}

fn build_auth_v3_client_control(inputs: &AuthV3TestInputs) -> AuthV3ClientMaterial {
    let policy = auth_v3_policy(inputs.wire_carrier);
    let principal_commitment =
        auth_v3_identity_commitment(AUTH_V3_PRINCIPAL_COMMITMENT_LABEL, &inputs.principal_id);
    let deployment_profile_commitment = auth_v3_identity_commitment(
        AUTH_V3_DEPLOYMENT_COMMITMENT_LABEL,
        &inputs.deployment_profile_id,
    );
    let credential_namespace_commitment = auth_v3_identity_commitment(
        AUTH_V3_NAMESPACE_COMMITMENT_LABEL,
        &inputs.credential_namespace_id,
    );
    let policy_hash = auth_v3_policy_hash(&policy);
    let mac_key = auth_v3_mac_key(
        inputs,
        AUTH_V3_CLIENT_KEY_INFO,
        &principal_commitment,
        &deployment_profile_commitment,
        &credential_namespace_commitment,
    );

    let mut encoded = [0u8; AUTH_V3_CLIENT_CONTROL_LEN];
    encoded[0..4].copy_from_slice(AUTH_V3_MAGIC);
    write_u16(&mut encoded, 4, AUTH_V3_VERSION);
    encoded[6] = AUTH_V3_CLIENT_CONTROL_TYPE;
    write_u16(&mut encoded, 8, AUTH_V3_CLIENT_CONTROL_LEN as u16);
    encoded[12..20].copy_from_slice(&policy);
    encoded[20] = AUTH_V3_TLS_EXPORTER_BINDING;
    write_u16(&mut encoded, 22, AUTH_V3_KEX_CLASSICAL_FLOOR);
    write_u32(&mut encoded, 24, AUTH_V3_DIRECT_CAPABILITY);
    write_u16(&mut encoded, 28, AUTH_V3_BOUNDED_RESOURCE_CLASS);
    write_u64(&mut encoded, 32, inputs.credential_epoch);
    write_u64(&mut encoded, 40, inputs.client_time_unix);
    encoded[48..80].copy_from_slice(&principal_commitment);
    encoded[80..112].copy_from_slice(&deployment_profile_commitment);
    encoded[112..144].copy_from_slice(&credential_namespace_commitment);
    encoded[144..176].copy_from_slice(&inputs.client_nonce);
    encoded[176..192].copy_from_slice(AUTH_V3_SENTINEL);
    encoded[192..224].copy_from_slice(&policy_hash);
    let auth_tag = auth_v3_client_tag(&mac_key, &inputs.connection.tls_exporter, &encoded[..224]);
    encoded[224..256].copy_from_slice(&auth_tag);

    AuthV3ClientMaterial {
        policy,
        principal_commitment,
        deployment_profile_commitment,
        credential_namespace_commitment,
        policy_hash,
        mac_key,
        auth_tag,
        encoded,
    }
}

fn generate_auth_v3_server_confirmation(
    inputs: &AuthV3TestInputs,
    client_control: &[u8; AUTH_V3_CLIENT_CONTROL_LEN],
) -> Result<AuthV3ServerMaterial, AuthV3TestError> {
    if !auth_v3_valid_server_expiries(
        inputs.server_now_unix,
        inputs.admission_expiry_unix,
        inputs.hard_expiry_unix,
        inputs.credential_not_after_unix,
    ) {
        return Err(AuthV3TestError::Expiry);
    }
    let client =
        parse_auth_v3_client_control(client_control).expect("builder requires valid client shape");
    let policy_hash = auth_v3_policy_hash(&client.policy);
    let client_control_commitment = auth_v3_client_control_commitment(client_control);
    let mac_key = auth_v3_mac_key(
        inputs,
        AUTH_V3_SERVER_KEY_INFO,
        &client.principal_commitment,
        &client.deployment_profile_commitment,
        &client.credential_namespace_commitment,
    );

    let mut encoded = [0u8; AUTH_V3_SERVER_CONFIRMATION_LEN];
    encoded[0..4].copy_from_slice(AUTH_V3_MAGIC);
    write_u16(&mut encoded, 4, AUTH_V3_VERSION);
    encoded[6] = AUTH_V3_SERVER_CONFIRMATION_TYPE;
    write_u16(&mut encoded, 8, AUTH_V3_SERVER_CONFIRMATION_LEN as u16);
    encoded[12..20].copy_from_slice(&client.policy);
    encoded[20] = AUTH_V3_TLS_EXPORTER_BINDING;
    write_u16(&mut encoded, 22, AUTH_V3_KEX_CLASSICAL_FLOOR);
    write_u32(&mut encoded, 24, AUTH_V3_DIRECT_CAPABILITY);
    write_u16(&mut encoded, 28, AUTH_V3_BOUNDED_RESOURCE_CLASS);
    write_u64(&mut encoded, 32, client.credential_epoch);
    write_u64(&mut encoded, 40, inputs.admission_expiry_unix);
    write_u64(&mut encoded, 48, inputs.hard_expiry_unix);
    encoded[56..88].copy_from_slice(&client.principal_commitment);
    encoded[88..120].copy_from_slice(&client.deployment_profile_commitment);
    encoded[120..152].copy_from_slice(&client.credential_namespace_commitment);
    encoded[152..184].copy_from_slice(&inputs.server_nonce);
    encoded[184..200].copy_from_slice(&inputs.session_id);
    encoded[200..216].copy_from_slice(AUTH_V3_SENTINEL);
    encoded[216..248].copy_from_slice(&policy_hash);
    encoded[248..280].copy_from_slice(&client_control_commitment);
    write_u32(&mut encoded, 280, inputs.max_frame_size);
    write_u32(&mut encoded, 284, inputs.max_concurrent_flows);
    let auth_tag = auth_v3_server_tag(&mac_key, &inputs.connection.tls_exporter, &encoded[..288]);
    encoded[288..320].copy_from_slice(&auth_tag);

    Ok(AuthV3ServerMaterial {
        policy: client.policy,
        principal_commitment: client.principal_commitment,
        deployment_profile_commitment: client.deployment_profile_commitment,
        credential_namespace_commitment: client.credential_namespace_commitment,
        policy_hash,
        client_control_commitment,
        mac_key,
        auth_tag,
        encoded,
    })
}

fn parse_auth_v3_client_control(
    input: &[u8],
) -> Result<ParsedAuthV3ClientControl, AuthV3TestError> {
    if input.len() != AUTH_V3_CLIENT_CONTROL_LEN {
        return Err(AuthV3TestError::Shape);
    }
    if &input[0..4] != AUTH_V3_MAGIC
        || read_u16(input, 4) != AUTH_V3_VERSION
        || input[6] != AUTH_V3_CLIENT_CONTROL_TYPE
        || read_u16(input, 8) as usize != AUTH_V3_CLIENT_CONTROL_LEN
    {
        return Err(AuthV3TestError::Header);
    }
    if input[7] != 0
        || input[10..12].iter().any(|value| *value != 0)
        || input[21] != 0
        || input[30..32].iter().any(|value| *value != 0)
    {
        return Err(AuthV3TestError::Reserved);
    }

    let policy = read_array::<8>(input, 12);
    validate_auth_v3_policy(&policy)?;
    if input[20] != AUTH_V3_TLS_EXPORTER_BINDING {
        return Err(AuthV3TestError::Binding);
    }
    if read_u16(input, 22) != AUTH_V3_KEX_CLASSICAL_FLOOR {
        return Err(AuthV3TestError::Kex);
    }
    if read_u32(input, 24) != AUTH_V3_DIRECT_CAPABILITY {
        return Err(AuthV3TestError::Capabilities);
    }
    if read_u16(input, 28) != AUTH_V3_BOUNDED_RESOURCE_CLASS {
        return Err(AuthV3TestError::ResourceClass);
    }

    let credential_epoch = read_u64(input, 32);
    if credential_epoch == 0 {
        return Err(AuthV3TestError::Epoch);
    }
    let client_nonce = read_array::<32>(input, 144);
    if all_zero(&client_nonce) {
        return Err(AuthV3TestError::Nonce);
    }
    if &input[176..192] != AUTH_V3_SENTINEL {
        return Err(AuthV3TestError::Sentinel);
    }
    if read_array::<32>(input, 192) != auth_v3_policy_hash(&policy) {
        return Err(AuthV3TestError::Policy);
    }

    Ok(ParsedAuthV3ClientControl {
        policy,
        credential_epoch,
        client_time_unix: read_u64(input, 40),
        principal_commitment: read_array(input, 48),
        deployment_profile_commitment: read_array(input, 80),
        credential_namespace_commitment: read_array(input, 112),
        auth_tag: read_array(input, 224),
    })
}

fn verify_auth_v3_client_control(
    input: &[u8],
    inputs: &AuthV3TestInputs,
) -> Result<ParsedAuthV3ClientControl, AuthV3TestError> {
    let parsed = parse_auth_v3_client_control(input)?;
    validate_auth_v3_trusted_context(inputs, parsed.policy[2])?;
    if inputs.credential_epoch == 0 || parsed.credential_epoch != inputs.credential_epoch {
        return Err(AuthV3TestError::Epoch);
    }
    if inputs.server_now_unix >= inputs.credential_not_after_unix {
        return Err(AuthV3TestError::Credential);
    }
    if !auth_v3_time_within_skew(parsed.client_time_unix, inputs.server_now_unix) {
        return Err(AuthV3TestError::Time);
    }
    if all_zero(&inputs.principal_id)
        || all_zero(&inputs.deployment_profile_id)
        || all_zero(&inputs.credential_namespace_id)
    {
        return Err(AuthV3TestError::Identity);
    }

    let principal_commitment =
        auth_v3_identity_commitment(AUTH_V3_PRINCIPAL_COMMITMENT_LABEL, &inputs.principal_id);
    let deployment_profile_commitment = auth_v3_identity_commitment(
        AUTH_V3_DEPLOYMENT_COMMITMENT_LABEL,
        &inputs.deployment_profile_id,
    );
    let credential_namespace_commitment = auth_v3_identity_commitment(
        AUTH_V3_NAMESPACE_COMMITMENT_LABEL,
        &inputs.credential_namespace_id,
    );
    if parsed.principal_commitment != principal_commitment
        || parsed.deployment_profile_commitment != deployment_profile_commitment
        || parsed.credential_namespace_commitment != credential_namespace_commitment
    {
        return Err(AuthV3TestError::Identity);
    }

    let mac_key = auth_v3_mac_key(
        inputs,
        AUTH_V3_CLIENT_KEY_INFO,
        &principal_commitment,
        &deployment_profile_commitment,
        &credential_namespace_commitment,
    );
    auth_v3_verify_client_tag(
        &mac_key,
        &inputs.connection.tls_exporter,
        &input[..224],
        &parsed.auth_tag,
    )?;
    Ok(parsed)
}

fn parse_auth_v3_server_confirmation(
    input: &[u8],
) -> Result<ParsedAuthV3ServerConfirmation, AuthV3TestError> {
    if input.len() != AUTH_V3_SERVER_CONFIRMATION_LEN {
        return Err(AuthV3TestError::Shape);
    }
    if &input[0..4] != AUTH_V3_MAGIC
        || read_u16(input, 4) != AUTH_V3_VERSION
        || input[6] != AUTH_V3_SERVER_CONFIRMATION_TYPE
        || read_u16(input, 8) as usize != AUTH_V3_SERVER_CONFIRMATION_LEN
    {
        return Err(AuthV3TestError::Header);
    }
    if input[7] != 0
        || input[10..12].iter().any(|value| *value != 0)
        || input[21] != 0
        || input[30..32].iter().any(|value| *value != 0)
    {
        return Err(AuthV3TestError::Reserved);
    }

    let policy = read_array::<8>(input, 12);
    validate_auth_v3_policy(&policy)?;
    if input[20] != AUTH_V3_TLS_EXPORTER_BINDING {
        return Err(AuthV3TestError::Binding);
    }
    if read_u16(input, 22) != AUTH_V3_KEX_CLASSICAL_FLOOR {
        return Err(AuthV3TestError::Kex);
    }
    if read_u32(input, 24) != AUTH_V3_DIRECT_CAPABILITY {
        return Err(AuthV3TestError::Capabilities);
    }
    if read_u16(input, 28) != AUTH_V3_BOUNDED_RESOURCE_CLASS {
        return Err(AuthV3TestError::ResourceClass);
    }

    let credential_epoch = read_u64(input, 32);
    if credential_epoch == 0 {
        return Err(AuthV3TestError::Epoch);
    }
    let server_nonce = read_array::<32>(input, 152);
    let session_id = read_array::<16>(input, 184);
    if all_zero(&server_nonce) || all_zero(&session_id) {
        return Err(AuthV3TestError::Nonce);
    }
    if &input[200..216] != AUTH_V3_SENTINEL {
        return Err(AuthV3TestError::Sentinel);
    }
    if read_array::<32>(input, 216) != auth_v3_policy_hash(&policy) {
        return Err(AuthV3TestError::Policy);
    }
    let max_frame_size = read_u32(input, 280);
    let max_concurrent_flows = read_u32(input, 284);
    if max_frame_size == 0 || max_concurrent_flows == 0 {
        return Err(AuthV3TestError::Limits);
    }

    Ok(ParsedAuthV3ServerConfirmation {
        policy,
        credential_epoch,
        admission_expiry_unix: read_u64(input, 40),
        hard_expiry_unix: read_u64(input, 48),
        principal_commitment: read_array(input, 56),
        deployment_profile_commitment: read_array(input, 88),
        credential_namespace_commitment: read_array(input, 120),
        client_control_commitment: read_array(input, 248),
        max_frame_size,
        max_concurrent_flows,
        auth_tag: read_array(input, 288),
    })
}

fn verify_auth_v3_server_confirmation(
    input: &[u8],
    client_control: &[u8],
    inputs: &AuthV3TestInputs,
) -> Result<ParsedAuthV3ServerConfirmation, AuthV3TestError> {
    let client = verify_auth_v3_client_control(client_control, inputs)?;
    let parsed = parse_auth_v3_server_confirmation(input)?;
    validate_auth_v3_trusted_context(inputs, parsed.policy[2])?;
    if parsed.policy != client.policy {
        return Err(AuthV3TestError::Echo);
    }
    if parsed.credential_epoch != client.credential_epoch {
        return Err(AuthV3TestError::Epoch);
    }
    if inputs.client_now_unix >= inputs.credential_not_after_unix {
        return Err(AuthV3TestError::Credential);
    }
    if !auth_v3_valid_server_expiries(
        inputs.server_now_unix,
        parsed.admission_expiry_unix,
        parsed.hard_expiry_unix,
        inputs.credential_not_after_unix,
    ) || !auth_v3_valid_client_expiries(
        inputs.client_now_unix,
        parsed.admission_expiry_unix,
        parsed.hard_expiry_unix,
        inputs.credential_not_after_unix,
    ) || !auth_v3_time_within_skew(client.client_time_unix, inputs.client_now_unix)
    {
        return Err(AuthV3TestError::Expiry);
    }
    if parsed.principal_commitment != client.principal_commitment
        || parsed.deployment_profile_commitment != client.deployment_profile_commitment
        || parsed.credential_namespace_commitment != client.credential_namespace_commitment
    {
        return Err(AuthV3TestError::Echo);
    }
    if parsed.max_frame_size > inputs.client_max_frame_size_cap
        || parsed.max_concurrent_flows > inputs.client_max_concurrent_flows_cap
    {
        return Err(AuthV3TestError::Limits);
    }
    if parsed.client_control_commitment != auth_v3_client_control_commitment(client_control) {
        return Err(AuthV3TestError::Commitment);
    }

    let mac_key = auth_v3_mac_key(
        inputs,
        AUTH_V3_SERVER_KEY_INFO,
        &client.principal_commitment,
        &client.deployment_profile_commitment,
        &client.credential_namespace_commitment,
    );
    auth_v3_verify_server_tag(
        &mac_key,
        &inputs.connection.tls_exporter,
        &input[..288],
        &parsed.auth_tag,
    )?;
    Ok(parsed)
}

fn auth_v3_policy(carrier: u8) -> [u8; 8] {
    match carrier {
        AUTH_V3_H2_CARRIER | AUTH_V3_H3_CARRIER => {
            [1, 1, carrier, AUTH_V3_DIRECT_TRUST_ROUTE, 1, 1, 0, 0]
        }
        _ => panic!("unsupported test carrier"),
    }
}

fn validate_auth_v3_policy(policy: &[u8; 8]) -> Result<(), AuthV3TestError> {
    if !matches!(policy[2], AUTH_V3_H2_CARRIER | AUTH_V3_H3_CARRIER)
        || policy != &auth_v3_policy(policy[2])
    {
        return Err(AuthV3TestError::Policy);
    }
    Ok(())
}

fn validate_auth_v3_trusted_context(
    inputs: &AuthV3TestInputs,
    claimed_carrier: u8,
) -> Result<(), AuthV3TestError> {
    let context = &inputs.connection;
    if !matches!(
        context.actual_carrier,
        AUTH_V3_H2_CARRIER | AUTH_V3_H3_CARRIER
    ) || claimed_carrier != context.actual_carrier
        || context.actual_tls_version != AuthV3TestTlsVersion::Tls13
        || inputs.expected_trust_route != AUTH_V3_DIRECT_TRUST_ROUTE
        || context.actual_trust_route != AUTH_V3_DIRECT_TRUST_ROUTE
        || context.early_data
        || !matches!(&context.exporter_context, Some(value) if value.is_empty())
        || context.deployment_profile_id != inputs.deployment_profile_id
        || context.server_identity_id != inputs.expected_server_identity_id
        || context.control_path != inputs.expected_control_path
    {
        return Err(AuthV3TestError::Context);
    }
    validate_auth_v3_provisioning_registry(std::slice::from_ref(inputs))
}

fn validate_auth_v3_provisioning_registry(
    entries: &[AuthV3TestInputs],
) -> Result<(), AuthV3TestError> {
    for entry in entries {
        if entry.credential_epoch == 0
            || all_zero(&entry.principal_id)
            || all_zero(&entry.deployment_profile_id)
            || all_zero(&entry.credential_namespace_id)
            || all_zero(&entry.expected_server_identity_id)
            || entry.expected_trust_route != AUTH_V3_DIRECT_TRUST_ROUTE
            || entry.expected_control_path.is_empty()
        {
            return Err(AuthV3TestError::Credential);
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        for other in &entries[index + 1..] {
            if entry.deployment_profile_id == other.deployment_profile_id
                && (entry.expected_server_identity_id != other.expected_server_identity_id
                    || entry.expected_trust_route != other.expected_trust_route
                    || entry.expected_control_path != other.expected_control_path)
            {
                return Err(AuthV3TestError::Context);
            }
            let same_tuple =
                auth_v3_trusted_credential_tuple(entry) == auth_v3_trusted_credential_tuple(other);
            let same_psk = entry.secret.as_bytes() == other.secret.as_bytes();
            if same_tuple || same_psk {
                return Err(AuthV3TestError::Credential);
            }
        }
    }
    Ok(())
}

fn auth_v3_time_within_skew(peer_time: u64, trusted_now: u64) -> bool {
    if peer_time == 0 || peer_time == u64::MAX {
        return false;
    }
    if peer_time <= trusted_now {
        trusted_now
            .checked_sub(peer_time)
            .is_some_and(|delta| delta <= 300)
    } else {
        peer_time
            .checked_sub(trusted_now)
            .is_some_and(|delta| delta <= 300)
    }
}

fn auth_v3_trusted_credential_tuple(
    inputs: &AuthV3TestInputs,
) -> ([u8; 32], [u8; 32], [u8; 32], u64) {
    (
        auth_v3_identity_commitment(AUTH_V3_PRINCIPAL_COMMITMENT_LABEL, &inputs.principal_id),
        auth_v3_identity_commitment(
            AUTH_V3_DEPLOYMENT_COMMITMENT_LABEL,
            &inputs.deployment_profile_id,
        ),
        auth_v3_identity_commitment(
            AUTH_V3_NAMESPACE_COMMITMENT_LABEL,
            &inputs.credential_namespace_id,
        ),
        inputs.credential_epoch,
    )
}

fn auth_v3_valid_server_expiries(
    trusted_now: u64,
    admission: u64,
    hard: u64,
    credential_not_after: u64,
) -> bool {
    trusted_now < admission
        && admission < hard
        && admission <= credential_not_after
        && hard <= credential_not_after
        && admission
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= 1_800)
        && hard
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= 86_400)
}

fn auth_v3_valid_client_expiries(
    trusted_now: u64,
    admission: u64,
    hard: u64,
    credential_not_after: u64,
) -> bool {
    trusted_now < admission
        && admission < hard
        && admission <= credential_not_after
        && hard <= credential_not_after
        && admission
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= 1_800 + 300)
        && hard
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= 86_400 + 300)
}

fn auth_v3_identity_commitment(label: &[u8], opaque_id: &[u8; 16]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(16u16.to_be_bytes());
    digest.update(opaque_id);
    digest.finalize().into()
}

fn auth_v3_policy_hash(policy: &[u8; 8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTH_V3_POLICY_HASH_LABEL);
    digest.update(8u16.to_be_bytes());
    digest.update(policy);
    digest.finalize().into()
}

fn auth_v3_mac_key(
    inputs: &AuthV3TestInputs,
    info_label: &[u8],
    principal_commitment: &[u8; 32],
    deployment_profile_commitment: &[u8; 32],
    credential_namespace_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut salt = Vec::with_capacity(AUTH_V3_HKDF_SALT_LABEL.len() + 8);
    salt.extend_from_slice(AUTH_V3_HKDF_SALT_LABEL);
    salt.extend_from_slice(&inputs.credential_epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), inputs.secret.as_bytes());
    let mut info = Vec::with_capacity(info_label.len() + 96);
    info.extend_from_slice(info_label);
    info.extend_from_slice(principal_commitment);
    info.extend_from_slice(deployment_profile_commitment);
    info.extend_from_slice(credential_namespace_commitment);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32-byte HKDF output length is valid");
    key
}

fn auth_v3_client_tag(key: &[u8; 32], exporter: &[u8; 32], prefix: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(AUTH_V3_CLIENT_TRANSCRIPT_LABEL);
    mac.update(&32u16.to_be_bytes());
    mac.update(exporter);
    mac.update(&224u16.to_be_bytes());
    mac.update(prefix);
    mac.finalize().into_bytes().into()
}

fn auth_v3_server_tag(key: &[u8; 32], exporter: &[u8; 32], prefix: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(AUTH_V3_SERVER_TRANSCRIPT_LABEL);
    mac.update(&32u16.to_be_bytes());
    mac.update(exporter);
    mac.update(&288u16.to_be_bytes());
    mac.update(prefix);
    mac.finalize().into_bytes().into()
}

fn auth_v3_verify_client_tag(
    key: &[u8; 32],
    exporter: &[u8; 32],
    prefix: &[u8],
    tag: &[u8; 32],
) -> Result<(), AuthV3TestError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(AUTH_V3_CLIENT_TRANSCRIPT_LABEL);
    mac.update(&32u16.to_be_bytes());
    mac.update(exporter);
    mac.update(&224u16.to_be_bytes());
    mac.update(prefix);
    mac.verify_slice(tag).map_err(|_| AuthV3TestError::Mac)
}

fn auth_v3_verify_server_tag(
    key: &[u8; 32],
    exporter: &[u8; 32],
    prefix: &[u8],
    tag: &[u8; 32],
) -> Result<(), AuthV3TestError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(AUTH_V3_SERVER_TRANSCRIPT_LABEL);
    mac.update(&32u16.to_be_bytes());
    mac.update(exporter);
    mac.update(&288u16.to_be_bytes());
    mac.update(prefix);
    mac.verify_slice(tag).map_err(|_| AuthV3TestError::Mac)
}

fn auth_v3_client_control_commitment(input: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTH_V3_CLIENT_COMMITMENT_LABEL);
    digest.update(256u16.to_be_bytes());
    digest.update(input);
    digest.finalize().into()
}

fn verify_auth_v3_client_vector(vector: &AuthV3ClientControlVector) {
    let carrier = auth_v3_carrier_id(&vector.carrier);
    let actual_carrier = auth_v3_carrier_id(&vector.actual_carrier);
    assert_eq!(carrier, actual_carrier, "{}", vector.id);
    assert_auth_v3_exporter_metadata(
        &vector.id,
        &vector.exporter_label_ascii,
        vector.exporter_context_present,
        &vector.exporter_context_hex,
        vector.exporter_length,
    );
    let mut inputs = auth_v3_test_inputs(carrier);
    inputs.wire_carrier = carrier;
    inputs.connection.actual_carrier = actual_carrier;
    inputs.connection.actual_tls_version = auth_v3_tls_version(&vector.actual_tls_version);
    inputs.expected_trust_route = auth_v3_trust_route(&vector.expected_trust_route);
    inputs.connection.actual_trust_route = auth_v3_trust_route(&vector.actual_trust_route);
    inputs.connection.early_data = vector.early_data;
    inputs.secret.clone_from(&vector.secret_test_only);
    inputs.connection.exporter_context = vector
        .exporter_context_present
        .then(|| hex_decode(&vector.exporter_context_hex));
    inputs.connection.tls_exporter = hex_array(&vector.tls_exporter_hex);
    inputs.principal_id = hex_array(&vector.principal_id_hex);
    inputs.deployment_profile_id = hex_array(&vector.deployment_profile_id_hex);
    inputs.credential_namespace_id = hex_array(&vector.credential_namespace_id_hex);
    inputs.connection.deployment_profile_id =
        hex_array(&vector.connection_deployment_profile_id_hex);
    inputs.expected_server_identity_id = hex_array(&vector.expected_server_identity_id_hex);
    inputs.connection.server_identity_id = hex_array(&vector.actual_server_identity_id_hex);
    inputs
        .expected_control_path
        .clone_from(&vector.expected_control_path);
    inputs
        .connection
        .control_path
        .clone_from(&vector.actual_control_path);
    inputs.credential_epoch = vector.credential_epoch;
    inputs.credential_not_after_unix = vector.credential_not_after_unix;
    inputs.client_time_unix = vector.client_time_unix;
    inputs.server_now_unix = vector.server_now_unix;
    inputs.client_nonce = hex_array(&vector.client_nonce_hex);

    let material = build_auth_v3_client_control(&inputs);
    assert_eq!(
        hex_decode(&vector.policy_minimum_hex),
        material.policy,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.principal_commitment_hex),
        material.principal_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.deployment_profile_commitment_hex),
        material.deployment_profile_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.credential_namespace_commitment_hex),
        material.credential_namespace_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.policy_minimum_hash_hex),
        material.policy_hash,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.client_mac_key_hex),
        material.mac_key,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.client_auth_tag_hex),
        material.auth_tag,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.encoded_hex),
        material.encoded,
        "{}",
        vector.id
    );
    verify_auth_v3_client_control(&material.encoded, &inputs).unwrap();
}

fn verify_auth_v3_server_vector(vector: &AuthV3ServerConfirmationVector) {
    let carrier = auth_v3_carrier_id(&vector.carrier);
    let actual_carrier = auth_v3_carrier_id(&vector.actual_carrier);
    assert_eq!(carrier, actual_carrier, "{}", vector.id);
    assert_auth_v3_exporter_metadata(
        &vector.id,
        &vector.exporter_label_ascii,
        vector.exporter_context_present,
        &vector.exporter_context_hex,
        vector.exporter_length,
    );
    let mut inputs = auth_v3_test_inputs(carrier);
    inputs.wire_carrier = carrier;
    inputs.connection.actual_carrier = actual_carrier;
    inputs.connection.actual_tls_version = auth_v3_tls_version(&vector.actual_tls_version);
    inputs.expected_trust_route = auth_v3_trust_route(&vector.expected_trust_route);
    inputs.connection.actual_trust_route = auth_v3_trust_route(&vector.actual_trust_route);
    inputs.connection.early_data = vector.early_data;
    inputs.secret.clone_from(&vector.secret_test_only);
    inputs.connection.exporter_context = vector
        .exporter_context_present
        .then(|| hex_decode(&vector.exporter_context_hex));
    inputs.connection.tls_exporter = hex_array(&vector.tls_exporter_hex);
    inputs.principal_id = hex_array(&vector.principal_id_hex);
    inputs.deployment_profile_id = hex_array(&vector.deployment_profile_id_hex);
    inputs.credential_namespace_id = hex_array(&vector.credential_namespace_id_hex);
    inputs.connection.deployment_profile_id =
        hex_array(&vector.connection_deployment_profile_id_hex);
    inputs.expected_server_identity_id = hex_array(&vector.expected_server_identity_id_hex);
    inputs.connection.server_identity_id = hex_array(&vector.actual_server_identity_id_hex);
    inputs
        .expected_control_path
        .clone_from(&vector.expected_control_path);
    inputs
        .connection
        .control_path
        .clone_from(&vector.actual_control_path);
    inputs.credential_epoch = vector.credential_epoch;
    inputs.credential_not_after_unix = vector.credential_not_after_unix;
    inputs.server_now_unix = vector.server_now_unix;
    inputs.client_now_unix = vector.client_now_unix;
    inputs.admission_expiry_unix = vector.admission_expiry_unix;
    inputs.hard_expiry_unix = vector.hard_expiry_unix;
    inputs.server_nonce = hex_array(&vector.server_nonce_hex);
    inputs.session_id = hex_array(&vector.session_id_hex);
    inputs.max_frame_size = vector.max_frame_size;
    inputs.max_concurrent_flows = vector.max_concurrent_flows;
    inputs.client_max_frame_size_cap = vector.client_max_frame_size_cap;
    inputs.client_max_concurrent_flows_cap = vector.client_max_concurrent_flows_cap;

    let client_control = hex_array(&vector.client_control_encoded_hex);
    let material = generate_auth_v3_server_confirmation(&inputs, &client_control).unwrap();
    assert_eq!(
        hex_decode(&vector.policy_selected_hex),
        material.policy,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.principal_commitment_hex),
        material.principal_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.deployment_profile_commitment_hex),
        material.deployment_profile_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.credential_namespace_commitment_hex),
        material.credential_namespace_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.policy_selected_hash_hex),
        material.policy_hash,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.client_control_commitment_hex),
        material.client_control_commitment,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.server_mac_key_hex),
        material.mac_key,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.server_auth_tag_hex),
        material.auth_tag,
        "{}",
        vector.id
    );
    assert_eq!(
        hex_decode(&vector.encoded_hex),
        material.encoded,
        "{}",
        vector.id
    );
    verify_auth_v3_server_confirmation(&material.encoded, &client_control, &inputs).unwrap();
}

fn assert_auth_v3_exporter_metadata(
    id: &str,
    label: &str,
    context_present: bool,
    context_hex: &str,
    length: usize,
) {
    assert_eq!(label, AUTH_V3_EXPORTER_LABEL, "{id}");
    assert!(context_present, "{id}");
    assert!(context_hex.is_empty(), "{id}");
    assert_eq!(length, 32, "{id}");
}

fn auth_v3_tls_version(version: &str) -> AuthV3TestTlsVersion {
    match version {
        "1.2" => AuthV3TestTlsVersion::Tls12,
        "1.3" => AuthV3TestTlsVersion::Tls13,
        _ => panic!("unknown auth v3 test TLS version"),
    }
}

fn auth_v3_trust_route(route: &str) -> u8 {
    match route {
        "direct" => AUTH_V3_DIRECT_TRUST_ROUTE,
        _ => panic!("unknown auth v3 test trust route"),
    }
}

fn auth_v3_carrier_id(carrier: &str) -> u8 {
    match carrier {
        "h2" => AUTH_V3_H2_CARRIER,
        "h3" => AUTH_V3_H3_CARRIER,
        _ => panic!("unknown auth v3 vector carrier"),
    }
}

fn auth_v3_carrier_name(carrier: u8) -> &'static str {
    match carrier {
        AUTH_V3_H2_CARRIER => "h2",
        AUTH_V3_H3_CARRIER => "h3",
        _ => panic!("unsupported test carrier"),
    }
}

fn auth_v3_client_file_name(carrier: u8) -> &'static str {
    match carrier {
        AUTH_V3_H2_CARRIER => "auth_v3_direct_h2_client_control.json",
        AUTH_V3_H3_CARRIER => "auth_v3_direct_h3_client_control.json",
        _ => panic!("unsupported test carrier"),
    }
}

fn auth_v3_server_file_name(carrier: u8) -> &'static str {
    match carrier {
        AUTH_V3_H2_CARRIER => "auth_v3_direct_h2_server_confirmation.json",
        AUTH_V3_H3_CARRIER => "auth_v3_direct_h3_server_confirmation.json",
        _ => panic!("unsupported test carrier"),
    }
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    input[offset..offset + N]
        .try_into()
        .expect("validated fixed-length input")
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(input, offset))
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(input, offset))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(input, offset))
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn all_zero(input: &[u8]) -> bool {
    input.iter().all(|value| *value == 0)
}

fn mutated(input: &[u8], offset: usize, value: u8) -> Vec<u8> {
    let mut output = input.to_vec();
    output[offset] = value;
    output
}

fn generated_vectors() -> Vec<(&'static str, String)> {
    vec![
        generated_auth_v1_client_hello(),
        generated_auth_v1_server_hello(),
        generated_auth_v2_client_hello(),
        generated_auth_v2_server_hello(),
        generated_auth_v3_client_control(AUTH_V3_H2_CARRIER),
        generated_auth_v3_server_confirmation(AUTH_V3_H2_CARRIER),
        generated_auth_v3_client_control(AUTH_V3_H3_CARRIER),
        generated_auth_v3_server_confirmation(AUTH_V3_H3_CARRIER),
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

fn generated_auth_v3_client_control(carrier: u8) -> (&'static str, String) {
    let inputs = auth_v3_test_inputs(carrier);
    let material = build_auth_v3_client_control(&inputs);
    let carrier_name = auth_v3_carrier_name(carrier);
    let id = format!("auth_v3_direct_{carrier_name}_client_control");
    (
        auth_v3_client_file_name(carrier),
        format!(
            r#"{{
  "id": "{id}",
  "kind": "auth_v3_direct_client_control",
  "carrier": "{carrier_name}",
  "actual_carrier": "{carrier_name}",
  "actual_tls_version": "1.3",
  "expected_trust_route": "direct",
  "actual_trust_route": "direct",
  "early_data": false,
  "secret_test_only": "{}",
  "exporter_label_ascii": "{AUTH_V3_EXPORTER_LABEL}",
  "exporter_context_present": true,
  "exporter_context_hex": "",
  "exporter_length": 32,
  "tls_exporter_hex": "{}",
  "principal_id_hex": "{}",
  "deployment_profile_id_hex": "{}",
  "credential_namespace_id_hex": "{}",
  "connection_deployment_profile_id_hex": "{}",
  "expected_server_identity_id_hex": "{}",
  "actual_server_identity_id_hex": "{}",
  "expected_control_path": "{}",
  "actual_control_path": "{}",
  "credential_epoch": {},
  "credential_not_after_unix": {},
  "client_time_unix": {},
  "server_now_unix": {},
  "client_nonce_hex": "{}",
  "policy_minimum_hex": "{}",
  "principal_commitment_hex": "{}",
  "deployment_profile_commitment_hex": "{}",
  "credential_namespace_commitment_hex": "{}",
  "policy_minimum_hash_hex": "{}",
  "client_mac_key_hex": "{}",
  "client_auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            inputs.secret,
            hex_encode(inputs.connection.tls_exporter),
            hex_encode(inputs.principal_id),
            hex_encode(inputs.deployment_profile_id),
            hex_encode(inputs.credential_namespace_id),
            hex_encode(inputs.connection.deployment_profile_id),
            hex_encode(inputs.expected_server_identity_id),
            hex_encode(inputs.connection.server_identity_id),
            inputs.expected_control_path,
            inputs.connection.control_path,
            inputs.credential_epoch,
            inputs.credential_not_after_unix,
            inputs.client_time_unix,
            inputs.server_now_unix,
            hex_encode(inputs.client_nonce),
            hex_encode(material.policy),
            hex_encode(material.principal_commitment),
            hex_encode(material.deployment_profile_commitment),
            hex_encode(material.credential_namespace_commitment),
            hex_encode(material.policy_hash),
            hex_encode(material.mac_key),
            hex_encode(material.auth_tag),
            hex_encode(material.encoded),
        ),
    )
}

fn generated_auth_v3_server_confirmation(carrier: u8) -> (&'static str, String) {
    let inputs = auth_v3_test_inputs(carrier);
    let client = build_auth_v3_client_control(&inputs).encoded;
    let material = generate_auth_v3_server_confirmation(&inputs, &client).unwrap();
    let carrier_name = auth_v3_carrier_name(carrier);
    let id = format!("auth_v3_direct_{carrier_name}_server_confirmation");
    (
        auth_v3_server_file_name(carrier),
        format!(
            r#"{{
  "id": "{id}",
  "kind": "auth_v3_direct_server_confirmation",
  "carrier": "{carrier_name}",
  "actual_carrier": "{carrier_name}",
  "actual_tls_version": "1.3",
  "expected_trust_route": "direct",
  "actual_trust_route": "direct",
  "early_data": false,
  "secret_test_only": "{}",
  "exporter_label_ascii": "{AUTH_V3_EXPORTER_LABEL}",
  "exporter_context_present": true,
  "exporter_context_hex": "",
  "exporter_length": 32,
  "tls_exporter_hex": "{}",
  "principal_id_hex": "{}",
  "deployment_profile_id_hex": "{}",
  "credential_namespace_id_hex": "{}",
  "connection_deployment_profile_id_hex": "{}",
  "expected_server_identity_id_hex": "{}",
  "actual_server_identity_id_hex": "{}",
  "expected_control_path": "{}",
  "actual_control_path": "{}",
  "credential_epoch": {},
  "credential_not_after_unix": {},
  "server_now_unix": {},
  "client_now_unix": {},
  "admission_expiry_unix": {},
  "hard_expiry_unix": {},
  "server_nonce_hex": "{}",
  "session_id_hex": "{}",
  "policy_selected_hex": "{}",
  "principal_commitment_hex": "{}",
  "deployment_profile_commitment_hex": "{}",
  "credential_namespace_commitment_hex": "{}",
  "policy_selected_hash_hex": "{}",
  "client_control_encoded_hex": "{}",
  "client_control_commitment_hex": "{}",
  "max_frame_size": {},
  "max_concurrent_flows": {},
  "client_max_frame_size_cap": {},
  "client_max_concurrent_flows_cap": {},
  "server_mac_key_hex": "{}",
  "server_auth_tag_hex": "{}",
  "encoded_hex": "{}"
}}
"#,
            inputs.secret,
            hex_encode(inputs.connection.tls_exporter),
            hex_encode(inputs.principal_id),
            hex_encode(inputs.deployment_profile_id),
            hex_encode(inputs.credential_namespace_id),
            hex_encode(inputs.connection.deployment_profile_id),
            hex_encode(inputs.expected_server_identity_id),
            hex_encode(inputs.connection.server_identity_id),
            inputs.expected_control_path,
            inputs.connection.control_path,
            inputs.credential_epoch,
            inputs.credential_not_after_unix,
            inputs.server_now_unix,
            inputs.client_now_unix,
            inputs.admission_expiry_unix,
            inputs.hard_expiry_unix,
            hex_encode(inputs.server_nonce),
            hex_encode(inputs.session_id),
            hex_encode(material.policy),
            hex_encode(material.principal_commitment),
            hex_encode(material.deployment_profile_commitment),
            hex_encode(material.credential_namespace_commitment),
            hex_encode(material.policy_hash),
            hex_encode(client),
            hex_encode(material.client_control_commitment),
            inputs.max_frame_size,
            inputs.max_concurrent_flows,
            inputs.client_max_frame_size_cap,
            inputs.client_max_concurrent_flows_cap,
            hex_encode(material.mac_key),
            hex_encode(material.auth_tag),
            hex_encode(material.encoded),
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
