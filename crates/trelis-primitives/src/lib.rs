//! Cryptographic primitives for the Trelis protocol.
//!
//! This crate provides the foundational cryptographic operations used throughout
//! the Trelis hybrid post-quantum protocol:
//!
//! - **AEAD**: XChaCha20-Poly1305 authenticated encryption
//! - **KDF**: BLAKE3-based key derivation with domain separation
//! - **Random**: Cryptographically secure random number generation
//!
//! # Security
//!
//! All secret material is zeroized on drop. Operations are designed to be
//! constant-time where security requires it.
//!
//! # no_std Support
//!
//! This crate supports `no_std` environments with the `alloc` feature.

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
pub mod random;
pub mod x448;

// Re-export key types for convenience
pub use aead::{decrypt, encrypt, AeadKey, Nonce, Tag};
pub use blake3_kdf::{derive_key, hash, keyed_hash};
pub use ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};
pub use random::{fill_bytes, generate_bytes};
pub use trelis_error::{CryptoError, Result};
pub use x448::{X448Public, X448Secret, X448SharedSecret};
