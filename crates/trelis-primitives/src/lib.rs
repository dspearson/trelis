//! Cryptographic primitives for the Trelis protocol.
//!
//! This crate provides the foundational cryptographic operations used throughout
//! the Trelis hybrid post-quantum protocol:
//!
//! - **AEAD**: XChaCha20-Poly1305 authenticated encryption
//! - **KDF**: BLAKE3-based key derivation with domain separation
//! - **Random**: Cryptographically secure random number generation
//! - **sntrup761**: Post-quantum KEM (C FFI or pure Rust depending on features)
//!
//! # Security
//!
//! All secret material is zeroized on drop. Operations are designed to be
//! constant-time where security requires it.
//!
//! # no_std Support
//!
//! This crate supports `no_std` environments with the `alloc` feature.
//!
//! # sntrup761 Backend Selection
//!
//! The sntrup761 KEM has two implementations:
//!
//! - **C FFI backend** (`std` feature): Uses `pqcrypto-ntruprime` for native builds.
//!   This is faster but requires a C compiler and `std`.
//!
//! - **Pure Rust backend** (`wasm` feature): Uses `ntrulp` with custom encoding.
//!   This works in `no_std` and WASM environments.
//!
//! Both backends produce **byte-for-byte identical outputs** and are fully interoperable.
//!
//! ## Feature Selection
//!
//! | Features | Backend Used | Use Case |
//! |----------|--------------|----------|
//! | `std` only | C FFI | Native server/desktop |
//! | `wasm` only | Pure Rust | Browser WASM |
//! | `std` + `wasm` | C FFI (testing) | Cross-validation testing |
//!
//! The unified `Sntrup761*` types are always available when either feature is enabled.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod aead;
pub mod blake3_kdf;
pub mod ed448;
pub mod mldsa65;
pub mod random;
pub mod x448;

// sntrup761 implementations (backend-specific modules)
/// C FFI sntrup761 KEM using pqcrypto-ntruprime (requires std).
#[cfg(feature = "std")]
pub mod sntrup761;
/// Wire format encoding for sntrup761 (standard encoding, shared by both backends).
pub mod sntrup761_encoding;
/// Optimised polynomial arithmetic for sntrup761 (Karatsuba, NTT).
#[cfg(feature = "wasm")]
pub mod sntrup761_poly;
/// Pure Rust sntrup761 KEM for WASM builds (uses ntrulp with standard wire encoding).
#[cfg(feature = "wasm")]
pub mod sntrup761_wasm;

// Re-export key types for convenience
pub use aead::{decrypt, encrypt, AeadKey, Nonce, Tag};
pub use blake3_kdf::{derive_key, hash, keyed_hash};
pub use ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};
pub use mldsa65::{MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey};
pub use random::{fill_bytes, generate_bytes};
pub use trelis_error::{CryptoError, Result};
pub use x448::{X448Public, X448Secret, X448SharedSecret};

// ============================================================================
// Unified sntrup761 API
// ============================================================================
//
// This provides a single set of `Sntrup761*` types that automatically select
// the appropriate backend based on enabled features:
//
// - When `std` is enabled (with or without `wasm`): use C FFI backend
// - When only `wasm` is enabled: use pure Rust backend
//
// This allows dependent crates (like trelis-hybrid) to use `Sntrup761*` types
// without caring about the underlying implementation.

/// sntrup761 types using the C FFI backend (when `std` is enabled).
#[cfg(feature = "std")]
pub use sntrup761::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};

/// sntrup761 types using the pure Rust backend (when only `wasm` is enabled).
#[cfg(all(feature = "wasm", not(feature = "std")))]
pub use sntrup761_wasm::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};

// Additional exports for cross-validation testing (both backends available)
/// Pure Rust sntrup761 types for cross-validation testing.
/// Only available when both `std` and `wasm` features are enabled.
#[cfg(all(feature = "std", feature = "wasm"))]
pub mod sntrup761_pure_rust {
    //! Pure Rust sntrup761 implementation for cross-validation testing.
    //!
    //! This module re-exports the pure Rust implementation with prefixed names
    //! to allow comparing outputs between C FFI and pure Rust backends.
    pub use crate::sntrup761_wasm::{
        Sntrup761Ciphertext as PureRustSntrup761Ciphertext,
        Sntrup761PublicKey as PureRustSntrup761PublicKey,
        Sntrup761SecretKey as PureRustSntrup761SecretKey,
        Sntrup761SharedSecret as PureRustSntrup761SharedSecret,
        CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
    };
}
