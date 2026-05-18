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
//!
//! # Two PreKeyBundle Types — Which to Use
//!
//! The Trelis workspace contains **two distinct pre-key bundle types**, in
//! separate crates, with different intended uses. Both are first-class APIs
//! and both will remain supported — neither is deprecated.
//!
//! | Type                                            | Crate                | OTK shape                                  | Metadata                       | Total bytes |
//! |-------------------------------------------------|----------------------|--------------------------------------------|--------------------------------|-------------|
//! | [`HybridPreKeyBundle`]                          | `trelis-hybrid`      | [`HybridOneTimeKey`] (wraps KEM + 8B id)   | none                           | 4,445       |
//! | `trelis_x3dh_pq::PreKeyBundle` (and `trelis_x3dh_pq::SignedPreKeyBundle`) | `trelis-x3dh-pq`     | Bare [`HybridKemPublicKey`] + separate `otk_key_id: u64` | `timestamp`, `expiration` | 4,461 unsigned / 7,884 signed |
//!
//! **When to use [`HybridPreKeyBundle`] (this crate)**: as a self-contained
//! cryptographic value that bundles an identity public key plus a one-time
//! KEM key. It is a building block for callers that want the typed
//! `HybridOneTimeKey` wrapper but do NOT need the X3DH-PQ-flavour metadata
//! (timestamp, expiration, or canonical wire serialisation for publication
//! to a server).
//!
//! **When to use `trelis_x3dh_pq::PreKeyBundle` / `SignedPreKeyBundle`**:
//! as the protocol-level object published to a server for the X3DH-PQ
//! handshake. It carries the timestamp + expiration the server needs to
//! age out stale bundles, and the signed variant carries the 3,423-byte
//! `HybridSignature` over the bundle body for replay protection (using
//! the `trelis-prekey-bundle-v1` BLAKE3-derive_key domain separator).
//!
//! The two types are deliberately not convertible at the type level — Rust's
//! type checker prevents passing one where the other is expected. Reach for
//! [`HybridPreKeyBundle`] only when you have a specific reason; for any
//! protocol-tier work, prefer the `trelis-x3dh-pq` types.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `cast_lossless` (u8→u32) is allowed because the hybrid combiner and
// safety-number digit conversion mix 8-bit indices into 32-bit
// accumulators and the mechanical `From` rewrite hurts readability.
// `unreadable_literal` is allowed because recovery-code BLAKE3 test
// vectors and KDF context-string constants are kept verbatim.
// `similar_names` is allowed because the safety-number protocol names
// follow Signal-style conventions; renames affect the public API.
#![allow(
    clippy::cast_lossless,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::unreadable_literal
)]
// Tests silence the full pedantic set (uninlined_format_args on
// `format!("{:?}", x)` dominates; not worth churning the corpus).
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
pub mod identity_cert;
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
pub use identity_cert::{
    CERTIFICATE_WIRE_SIZE, CERTIFIED_SAFETY_NUMBER_CONTEXT, CertifiedSafetyNumber,
    IdentityCertificate,
};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use one_time_key::{HybridOneTimeKey, HybridOneTimeKeyPair};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use prekey_bundle::HybridPreKeyBundle;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use recovery::derive_recovery_keypair;
#[cfg(feature = "alloc")]
pub use recovery::{
    CompromiseNotice, CompromiseReason, FINGERPRINT_SIZE, RECOVERY_SEED_SIZE,
    RecoveryKeyAttestation, key_fingerprint,
};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use safety_number::SafetyNumber;

pub use trelis_error::{CryptoError, Result};
