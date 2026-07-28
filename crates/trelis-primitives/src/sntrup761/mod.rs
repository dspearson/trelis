//! sntrup761 Key Encapsulation Mechanism.
//!
//! This module provides sntrup761 post-quantum KEM as specified by NTRU Prime.
//! sntrup761 is a lattice-based key encapsulation mechanism at NIST
//! Category 2-3 (Core-SVP 2^153; the designers' conservative floor is
//! Category 2, Category 3 only under the disputed P80 claim). It is not
//! NIST-standardised and sits at or below ML-DSA-65's Category 3 — the
//! lowest (or joint-lowest) post-quantum link in the hybrid.
//!
//! # Pedantic-lint policy
//!
//! Source files in this module are ports of the canonical Streamlined NTRU
//! Prime reference implementation (PQClean). The arithmetic casts (u16↔u32,
//! i16↔i32, u8↔u32) are mandated by the algorithm's field representations;
//! truncations are provably safe within the reduction loops; the
//! representational choices mirror the reference for audit-against-spec
//! traceability. Pedantic rewrites would diverge from PQClean and complicate
//! future audits. Cross-validated against PQClean test vectors at
//! `tests/sntrup761_cross_validation.rs`.
#![allow(clippy::pedantic)]
//!
//! # Key Sizes
//!
//! - Public key: 1,158 bytes
//! - Secret key: 1,763 bytes
//! - Ciphertext: 1,039 bytes
//! - Shared secret: 32 bytes
//!
//! # Backend
//!
//! There is a single implementation: the pure Rust backend (`pure_rust`),
//! built on `ntrulp` with in-tree encoding. It is used uniformly on every
//! target — native, Windows, WASM and `no_std`.
//!
//! A second backend previously bound the PQClean C reference via
//! `pqcrypto-ntruprime` on native Unix. PQClean is being archived
//! (RUSTSEC-2026-0162, RUSTSEC-2026-0163), so that backend was removed rather
//! than carry an unmaintained C dependency under the post-quantum KEM.
//!
//! Equivalence with the C reference is not lost: its outputs were captured
//! before removal and are enforced as frozen known-answer tests in
//! `tests/sntrup761_kat.rs` against `tests/vectors/sntrup761_pqclean-kat.json`.
//! Wire format and shared secrets remain byte-for-byte interoperable with any
//! conforming sntrup761 implementation.
//!
//! # Submodules
//!
//! - `encoding` — Wire format encoding/decoding
//! - `fq` — Optimised field arithmetic for Fq = Z/4591Z
//! - `poly` — Polynomial arithmetic (Karatsuba, NTT)
//! - `pure_rust` — The sntrup761 implementation

/// Wire format encoding/decoding for sntrup761 keys and ciphertexts.
pub mod encoding;

/// Optimised field arithmetic for sntrup761 (Fq = Z/4591Z).
///
/// Provides fast extended GCD for field inversion (O(log q) vs O(q) Fermat).
pub mod fq;

/// Polynomial arithmetic for sntrup761 (Karatsuba, NTT).
pub mod poly;

/// Pure Rust sntrup761 KEM.
pub mod pure_rust;

// Unified sntrup761 API. Single backend, so no platform dispatch: the same
// implementation is used on every target.
pub use pure_rust::{
    CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE, Sntrup761Ciphertext,
    Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};
