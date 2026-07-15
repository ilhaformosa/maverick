#![no_main]

use libfuzzer_sys::fuzz_target;
use maverick_core::{ClientHello, ClientHelloV2, ServerHello, ServerHelloV2};

fuzz_target!(|data: &[u8]| {
    let _ = ClientHello::decode(data);
    let _ = ServerHello::decode(data);
    let _ = ClientHelloV2::decode(data);
    let _ = ServerHelloV2::decode(data);
});
