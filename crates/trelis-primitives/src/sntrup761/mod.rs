//! sntrup761 Key Encapsulation Mechanism.
//!
//! This module provides sntrup761 post-quantum KEM as specified by NTRU Prime.
//! sntrup761 is a lattice-based key encapsulation mechanism providing
//! approximately 128-bit security against quantum attacks (NIST Level 3).
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
