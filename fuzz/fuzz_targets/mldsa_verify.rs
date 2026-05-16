#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_primitives::mldsa65::{
    MlDsa65Signature, MlDsa65VerifyingKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < PUBLIC_KEY_SIZE + SIGNATURE_SIZE {
        return;
    }
    let (pk_bytes, rest) = data.split_at(PUBLIC_KEY_SIZE);
    let (sig_bytes, message) = rest.split_at(SIGNATURE_SIZE);
    if let (Ok(pk), Ok(sig)) = (
        MlDsa65VerifyingKey::from_bytes(pk_bytes),
        MlDsa65Signature::from_bytes(sig_bytes),
    ) {
        let _ = pk.verify(message, &sig);
    }
});
