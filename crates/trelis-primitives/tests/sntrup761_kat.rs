//! Frozen known-answer tests for sntrup761 against the PQClean C reference.
//!
//! # Why these vectors exist
//!
//! trelis originally carried two sntrup761 backends: a C FFI binding to
//! PQClean (`pqcrypto-ntruprime`) on native Unix, and a pure-Rust backend
//! (`ntrulp` plus in-tree encoding) everywhere else. Their equivalence was
//! enforced by a *live* differential test that ran both backends side by side.
//!
//! PQClean is being archived (RUSTSEC-2026-0162, RUSTSEC-2026-0163), so the C
//! backend was removed. Before removing it, its exact outputs were captured
//! into `tests/vectors/sntrup761_pqclean-kat.json`. These frozen vectors
//! preserve the differential assurance the live test used to provide: the
//! pure-Rust backend must still reproduce the C reference byte-for-byte.
//!
//! The corpus is therefore **immutable**. It is not regenerable from the
//! current tree — the implementation that produced it is gone. A failure here
//! means the pure-Rust backend has diverged from the canonical Streamlined
//! NTRU Prime reference, not that the vectors are stale.

// Test code; pedantic lints silenced wholesale.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

use trelis_primitives::sntrup761::encoding::{rq_decode, rq_encode};
use trelis_primitives::sntrup761::{
    CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE, Sntrup761Ciphertext,
    Sntrup761PublicKey, Sntrup761SecretKey,
};

#[derive(Debug, Deserialize)]
struct KatFile {
    reference_vectors: Vec<ReferenceVector>,
    seed_vectors: Vec<SeedVector>,
}

/// A case captured wholesale from the PQClean C implementation.
#[derive(Debug, Deserialize)]
struct ReferenceVector {
    name: String,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    ss: Vec<u8>,
}

/// A deterministic-keygen case, anchoring seeded derivation against drift.
#[derive(Debug, Deserialize)]
struct SeedVector {
    name: String,
    #[serde(with = "hex::serde")]
    seed: Vec<u8>,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
}

fn load() -> KatFile {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/vectors/sntrup761_pqclean-kat.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&content).expect("failed to parse sntrup761 KAT corpus")
}

#[test]
fn kat_corpus_is_present_and_well_formed() {
    let kat = load();
    assert!(
        !kat.reference_vectors.is_empty(),
        "reference vector corpus must not be empty"
    );
    assert!(
        !kat.seed_vectors.is_empty(),
        "seed vector corpus must not be empty"
    );

    for v in &kat.reference_vectors {
        assert_eq!(v.sk.len(), SECRET_KEY_SIZE, "{}: secret key size", v.name);
        assert_eq!(v.pk.len(), PUBLIC_KEY_SIZE, "{}: public key size", v.name);
        assert_eq!(v.ct.len(), CIPHERTEXT_SIZE, "{}: ciphertext size", v.name);
        assert_eq!(
            v.ss.len(),
            SHARED_SECRET_SIZE,
            "{}: shared secret size",
            v.name
        );
    }
}

/// The critical check: decapsulating a C-produced ciphertext with a C-produced
/// secret key must yield the exact shared secret the C implementation computed.
#[test]
fn pure_rust_decapsulation_matches_c_reference() {
    let kat = load();

    for v in &kat.reference_vectors {
        let sk = Sntrup761SecretKey::from_bytes(&v.sk)
            .unwrap_or_else(|e| panic!("{}: failed to parse reference secret key: {e:?}", v.name));
        let ct = Sntrup761Ciphertext::from_bytes(&v.ct)
            .unwrap_or_else(|e| panic!("{}: failed to parse reference ciphertext: {e:?}", v.name));

        let ss = sk
            .decapsulate(&ct)
            .unwrap_or_else(|e| panic!("{}: decapsulation failed: {e:?}", v.name));

        assert_eq!(
            ss.as_bytes().as_slice(),
            v.ss.as_slice(),
            "{}: shared secret diverges from the PQClean reference",
            v.name
        );
    }
}

/// The public key embedded in a C-produced secret key must be recovered
/// identically by the pure-Rust key parser.
#[test]
fn pure_rust_public_key_derivation_matches_c_reference() {
    let kat = load();

    for v in &kat.reference_vectors {
        let sk = Sntrup761SecretKey::from_bytes(&v.sk).unwrap();
        assert_eq!(
            sk.public_key().as_bytes().as_slice(),
            v.pk.as_slice(),
            "{}: derived public key diverges from the PQClean reference",
            v.name
        );
    }
}

/// C-produced public keys must parse, and survive a decode/encode roundtrip
/// through the in-tree Rq encoding unchanged.
#[test]
fn c_reference_public_keys_roundtrip_through_rust_encoding() {
    let kat = load();

    for v in &kat.reference_vectors {
        let pk = Sntrup761PublicKey::from_bytes(&v.pk)
            .unwrap_or_else(|e| panic!("{}: failed to parse reference public key: {e:?}", v.name));
        assert_eq!(pk.as_bytes().as_slice(), v.pk.as_slice());

        let bytes: [u8; PUBLIC_KEY_SIZE] = v.pk.clone().try_into().unwrap();
        let reencoded = rq_encode(&rq_decode(&bytes));
        assert_eq!(
            reencoded.as_slice(),
            v.pk.as_slice(),
            "{}: Rq decode/encode roundtrip altered a reference public key",
            v.name
        );
    }
}

/// A C-produced key must still work for fresh encapsulation under the
/// pure-Rust backend, and round-trip back to the same shared secret.
#[test]
fn fresh_encapsulation_to_c_reference_keys_roundtrips() {
    let kat = load();

    for v in &kat.reference_vectors {
        let sk = Sntrup761SecretKey::from_bytes(&v.sk).unwrap();
        let pk = Sntrup761PublicKey::from_bytes(&v.pk).unwrap();

        let (ss_encap, ct) = pk.encapsulate().unwrap();
        let ss_decap = sk.decapsulate(&ct).unwrap();

        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "{}: encapsulate/decapsulate against a reference key failed",
            v.name
        );
    }
}

/// Deterministic keygen must remain bit-stable against the frozen anchors.
#[test]
fn seeded_keygen_matches_frozen_anchors() {
    let kat = load();

    for v in &kat.seed_vectors {
        let seed: [u8; 32] = v.seed.clone().try_into().expect("seed must be 32 bytes");
        let sk = Sntrup761SecretKey::generate_from_seed(&seed)
            .unwrap_or_else(|e| panic!("{}: seeded keygen failed: {e:?}", v.name));

        assert_eq!(
            sk.as_bytes().as_slice(),
            v.sk.as_slice(),
            "{}: seeded secret key drifted",
            v.name
        );
        assert_eq!(
            sk.public_key().as_bytes().as_slice(),
            v.pk.as_slice(),
            "{}: seeded public key drifted",
            v.name
        );
    }
}
