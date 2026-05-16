#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_primitives::sntrup761::pure_rust::{
    Sntrup761Ciphertext, Sntrup761SecretKey, CIPHERTEXT_SIZE, SECRET_KEY_SIZE,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < SECRET_KEY_SIZE + CIPHERTEXT_SIZE {
        return;
    }
    let (sk_bytes, ct_bytes) = data.split_at(SECRET_KEY_SIZE);
    if let (Ok(sk), Ok(ct)) = (
        Sntrup761SecretKey::from_bytes(sk_bytes),
        Sntrup761Ciphertext::from_bytes(ct_bytes),
    ) {
        let _ = sk.decapsulate(&ct);
    }
});
