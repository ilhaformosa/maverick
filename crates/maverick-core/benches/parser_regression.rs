use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, Criterion};
use maverick_core::{ClientHello, Frame, OpenTcpPayload, ServerHello};
use std::hint::black_box;

const FRAME_TCP_DATA_HEX: &str = "0400000000000000002a0000000568656c6c6f";
const OPEN_TCP_DOMAIN_HEX: &str =
    "03000b6578616d706c652e636f6d01bb00000012474554202f20485454502f312e310d0a0d0a";
const AUTH_V1_CLIENT_HELLO_HEX: &str = "\
0001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
0000000067748580000d755f636f6e666f726d616e6365000000000000000005\
ecb54c72c64398715d30cf862691b1663df0f351e3a6be008933c36eb059c3d5";
const AUTH_V1_SERVER_HELLO_HEX: &str = "\
0001202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
10a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00010000000000800000000000000001\
e732847672ee5b5fbefb4a35f0c94173b9243b3dce12edbc9c0e9bd07f88a107";

fn parser_regression(c: &mut Criterion) {
    let frame_tcp_data = decode_hex(FRAME_TCP_DATA_HEX);
    c.bench_function("frame_decode_tcp_data", |b| {
        b.iter(|| {
            let mut buf = BytesMut::from(black_box(frame_tcp_data.as_slice()));
            let frame = Frame::decode_from(&mut buf, 65_536).unwrap().unwrap();
            black_box(frame);
        });
    });

    let open_tcp_domain = decode_hex(OPEN_TCP_DOMAIN_HEX);
    c.bench_function("open_tcp_payload_decode_domain", |b| {
        b.iter(|| {
            let payload = OpenTcpPayload::decode(black_box(open_tcp_domain.as_slice())).unwrap();
            black_box(payload);
        });
    });

    let client_hello = decode_hex(AUTH_V1_CLIENT_HELLO_HEX);
    c.bench_function("auth_v1_client_hello_decode", |b| {
        b.iter(|| {
            let hello = ClientHello::decode(black_box(client_hello.as_slice())).unwrap();
            black_box(hello);
        });
    });

    let server_hello = decode_hex(AUTH_V1_SERVER_HELLO_HEX);
    c.bench_function("auth_v1_server_hello_decode", |b| {
        b.iter(|| {
            let hello = ServerHello::decode(black_box(server_hello.as_slice())).unwrap();
            black_box(hello);
        });
    });
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "hex length must be even");
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_value(pair[0]);
        let low = hex_value(pair[1]);
        out.push((high << 4) | low);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

criterion_group!(benches, parser_regression);
criterion_main!(benches);
