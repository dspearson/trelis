#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_ratchet::header::RatchetMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = RatchetMessage::from_bytes(data) {
        let _ = msg.header.to_bytes();
    }
});
