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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod combiner;
#[cfg(feature = "std")]
pub mod kem;
pub mod signature;

#[cfg(feature = "std")]
pub mod identity;
#[cfg(feature = "std")]
pub mod one_time_key;
#[cfg(feature = "std")]
pub mod prekey_bundle;
#[cfg(feature = "std")]
pub mod safety_number;

// Re-export key types
pub use combiner::HybridSharedSecret;
#[cfg(feature = "std")]
pub use kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};
pub use signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

#[cfg(feature = "std")]
pub use identity::{HybridIdentityKeypair, HybridIdentityPublicKey};
#[cfg(feature = "std")]
pub use one_time_key::{HybridOneTimeKey, HybridOneTimeKeyPair};
#[cfg(feature = "std")]
pub use prekey_bundle::HybridPreKeyBundle;
#[cfg(feature = "std")]
pub use safety_number::SafetyNumber;

pub use trelis_error::{CryptoError, Result};
