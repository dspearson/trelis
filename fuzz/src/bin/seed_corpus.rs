//! One-shot fuzz-corpus seeder.
//!
//! Generates one valid sample for each fuzz harness using the library's own
//! constructors, then writes the bytes to `fuzz/corpus/<harness>/seed-<n>`.
//! Run once to populate the corpus directories. The seeds are checked in.
//!
//! Usage: `cargo run --bin seed_corpus --manifest-path fuzz/Cargo.toml --release`

use std::fs;
use std::path::PathBuf;

use trelis_hybrid::{HybridIdentityKeypair, HybridOneTimeKeyPair, HybridPreKeyBundle};
use trelis_primitives::mldsa65::MlDsa65SigningKey;
use trelis_primitives::sntrup761::pure_rust::Sntrup761SecretKey;

fn write_seed(harness: &str, name: &str, bytes: &[u8]) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("corpus");
    path.push(harness);
    fs::create_dir_all(&path).expect("mkdir corpus");
    path.push(name);
    fs::write(&path, bytes).expect("write seed");
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

fn seed_x3dh_bundle() {
    let identity = HybridIdentityKeypair::generate().expect("identity keypair");
    let one_time = HybridOneTimeKeyPair::generate().expect("one-time keypair");
    let bundle = HybridPreKeyBundle::new(identity.public_key(), one_time.public_key());
    write_seed("x3dh_bundle_parser", "seed-valid", &bundle.to_bytes());

    // Edge cases.
    write_seed("x3dh_bundle_parser", "seed-empty", &[]);
    write_seed("x3dh_bundle_parser", "seed-zeros-128", &[0u8; 128]);
}

fn seed_mldsa_verify() {
    let signing = MlDsa65SigningKey::generate().expect("mldsa keygen");
    let vk = signing.verifying_key();
    let msg = b"trelis-fuzz-corpus-seed";
    let sig = signing.sign(msg).expect("mldsa sign");
    let mut combined = vk.to_bytes().to_vec();
    combined.extend_from_slice(&sig.to_bytes());
    combined.extend_from_slice(msg);
    write_seed("mldsa_verify", "seed-valid", &combined);
}

fn seed_sntrup_decap() {
    let sk = Sntrup761SecretKey::generate().expect("sntrup keygen");
    let pk = sk.public_key();
    let (_ss, ct) = pk.encapsulate().expect("sntrup encap");
    let mut combined = sk.as_bytes().to_vec();
    combined.extend_from_slice(ct.as_bytes());
    write_seed("sntrup761_decap", "seed-valid", &combined);
}

fn seed_ratchet_decrypt() {
    // The fuzz harness only invokes `RatchetMessage::from_bytes` then
    // `header.to_bytes()`. We don't need a semantically-valid message —
    // structural well-formedness is what the parser checks. Seed with a
    // header-sized zero buffer and a few edge cases to anchor coverage.
    write_seed("ratchet_decrypt", "seed-empty", &[]);
    write_seed("ratchet_decrypt", "seed-1byte", &[0x00]);
    write_seed(
        "ratchet_decrypt",
        "seed-header-zeros",
        &vec![0u8; trelis_ratchet::header::HEADER_SIZE],
    );
    write_seed(
        "ratchet_decrypt",
        "seed-header-plus-32",
        &vec![0x42u8; trelis_ratchet::header::HEADER_SIZE + 32],
    );
}

fn main() {
    seed_x3dh_bundle();
    seed_mldsa_verify();
    seed_sntrup_decap();
    seed_ratchet_decrypt();
    println!("seed corpus generation complete");
}
