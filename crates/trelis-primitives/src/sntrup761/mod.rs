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
//! # Backend Selection
//!
//! The sntrup761 KEM has two implementations:
//!
//! - **C FFI backend** (`ffi`): Uses `pqcrypto-ntruprime` for native builds.
//!   Available on Unix/Linux with the `std` feature.
//!
//! - **Pure Rust backend** (`pure_rust`): Uses `ntrulp` with custom encoding.
//!   Works in `no_std` and WASM environments.
//!
//! Both backends produce **byte-for-byte identical outputs** and are fully interoperable.
//!
//! # Submodules
//!
//! - `encoding` — Wire format encoding/decoding (shared by both backends)
//! - `fq` — Optimised field arithmetic for Fq = Z/4591Z
//! - `poly` — Polynomial arithmetic (Karatsuba, NTT)
//! - `ffi` — C FFI backend (native Unix/Linux only)
//! - `pure_rust` — Pure Rust backend (WASM, Windows, no-std)

/// Wire format encoding/decoding for sntrup761 keys and ciphertexts.
pub mod encoding;

/// Optimised field arithmetic for sntrup761 (Fq = Z/4591Z).
///
/// Provides fast extended GCD for field inversion (O(log q) vs O(q) Fermat).
pub mod fq;

/// Polynomial arithmetic for sntrup761 (Karatsuba, NTT).
pub mod poly;

/// C FFI sntrup761 KEM using pqcrypto-ntruprime (native Unix/Linux only).
#[cfg(all(not(target_os = "windows"), not(target_arch = "wasm32")))]
pub mod ffi;

/// Pure Rust sntrup761 KEM (always included for deterministic keygen).
pub mod pure_rust;

// Re-export unified types based on platform
//
// - Native Unix/Linux with std: C FFI backend
// - Windows / WASM / no-std: Pure Rust backend

/// sntrup761 types using the C FFI backend (native Unix/Linux with std).
#[cfg(all(
    feature = "std",
    not(target_os = "windows"),
    not(target_arch = "wasm32")
))]
pub use ffi::{Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret};

/// sntrup761 types using the pure Rust backend (Windows, WASM, or no-std).
#[cfg(any(target_os = "windows", target_arch = "wasm32", not(feature = "std")))]
pub use pure_rust::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};
