#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_cocoa::operations::decrypt_welcome_info;
use trelis_hybrid::HybridKemKeypair;
use std::sync::OnceLock;

static KEYPAIR: OnceLock<HybridKemKeypair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let keypair = KEYPAIR.get_or_init(|| {
        let seed = [0x42u8; 32];
        HybridKemKeypair::generate_from_seed(&seed).expect("fuzz keypair init")
    });
    let mid = data.len() / 2;
    let (enc_info, encap) = data.split_at(mid);
    let _ = decrypt_welcome_info(enc_info, encap, keypair);
});
