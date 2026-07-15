#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use maverick_core::Frame;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    while !buf.is_empty() {
        match Frame::decode_from(&mut buf, 65_536) {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
});
