//! Hybrid post-quantum cryptographic constructions for the Trelis protocol.
//!
//! This crate provides hybrid cryptographic types that combine classical and
//! post-quantum algorithms for defence-in-depth security:
//!
//! - **Signatures**: Ed448 + ML-DSA-65 (2,009-byte public keys, 3,407-byte signatures)
//! - **KEM**: X448 + sntrup761 (1,214-byte public keys, 1,095-byte encapsulations)
//! - **Identity**: Combined signing and KEM keypairs (3,223-byte public keys)
//!
//! # Security Model
//!
//! The hybrid construction ensures security as long as *either* the classical
//! or post-quantum algorithm remains secure. This provides:
//!
//! - Protection against future quantum computers breaking classical crypto
//! - Protection against undiscovered weaknesses in newer PQ algorithms
//!
//! # no_std Support
//!
//! This crate supports `no_std` environments with the `alloc` feature.
//! The `std` feature is required for sntrup761 operations due to C FFI.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Pedantic-lint policy:
// - `doc_markdown` / `missing_errors_doc` — deferred to Phase 12 (DOCS-02).
// - `must_use_candidate` — deferred to Phase 11 (ERGO-01).
// - `cast_lossless` (u8→u32) — hybrid combiner / safety-number digit
//   conversion mixes 8-bit indices into 32-bit accumulators; mechanical
//   `From` rewrite hurts readability.
// - `unreadable_literal` — recovery code uses BLAKE3 test-vector literals
//   (T-10-06) and KDF context-string constants.
// - `similar_names` — safety-number protocol names follow Signal-style
//   conventions; renames affect the public API surface.
// See Phase 10 disposition in `10-PEDANTIC-DRAFT.md`.
#![allow(
    clippy::cast_lossless,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal
)]
// Test modules: silence the full pedantic set (uninlined_format_args on
// `format!("{:?}", x)` is dominant; not worth churning the corpus).
#![cfg_attr(test, allow(clippy::pedantic))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod combiner;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod kem;
pub mod signature;

#[cfg(any(feature = "std", feature = "wasm"))]
pub mod identity;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod one_time_key;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod prekey_bundle;
#[cfg(feature = "alloc")]
pub mod recovery;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod safety_number;

// Re-export key types
pub use combiner::HybridSharedSecret;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};
pub use signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

#[cfg(any(feature = "std", feature = "wasm"))]
pub use identity::{HybridIdentityKeypair, HybridIdentityPublicKey};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use one_time_key::{HybridOneTimeKey, HybridOneTimeKeyPair};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use prekey_bundle::HybridPreKeyBundle;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use recovery::derive_recovery_keypair;
#[cfg(feature = "alloc")]
pub use recovery::{
    CompromiseNotice, CompromiseReason, FINGERPRINT_SIZE, RECOVERY_SEED_SIZE, key_fingerprint,
};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use safety_number::SafetyNumber;

pub use trelis_error::{CryptoError, Result};
