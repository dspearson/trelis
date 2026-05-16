#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_hybrid::HybridPreKeyBundle;

fuzz_target!(|data: &[u8]| {
    let _ = HybridPreKeyBundle::from_bytes(data);
});
