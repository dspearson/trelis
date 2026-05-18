//! X3DH-PQ session establishment for the Trelis protocol.
//!
//! This crate implements the X3DH protocol extended with post-quantum security
//! via sntrup761 KEM. It establishes a shared secret between two parties with:
//!
//! - **Forward secrecy**: Ephemeral keys protect past sessions
//! - **Post-quantum security**: sntrup761 protects against quantum computers
//! - **Mutual authentication**: Identity keys bound to shared secret
//!
//! # Protocol Flow
//!
//! 1. Alice fetches Bob's pre-key bundle from the server
//! 2. Alice verifies the bundle signature (REQUIRED)
//! 3. Alice computes DH shared secrets and encapsulates to sntrup761
//! 4. Alice derives session keys with transcript binding
//! 5. Alice sends initial message containing ephemeral public key and ciphertext
//! 6. Bob decapsulates and derives the same session keys
//!
//! # Security Properties
//!
//! - **Identity binding**: KDF includes H(I_a) || H(I_b) to prevent UKS attacks
//! - **Bundle commitment**: KDF includes H(bundle) to bind to specific OTK
//! - **Hybrid security**: Both X448 and sntrup761 must be broken to compromise
//!
//! # Two PreKeyBundle Types — Which to Use
//!
//! There is also a `HybridPreKeyBundle` in the `trelis-hybrid` crate. Both
//! types are first-class and remain supported; neither is deprecated. They
//! differ in shape and intended use:
//!
//! | Type                                            | Crate                | OTK shape                                  | Metadata                       | Total bytes |
//! |-------------------------------------------------|----------------------|--------------------------------------------|--------------------------------|-------------|
//! | `trelis_hybrid::HybridPreKeyBundle`             | `trelis-hybrid`      | `HybridOneTimeKey` (wraps KEM + 8B id)     | none                           | 4,445       |
//! | [`PreKeyBundle`] (and [`SignedPreKeyBundle`])   | `trelis-x3dh-pq` (this crate) | Bare `HybridKemPublicKey` + separate `otk_key_id: u64` | `timestamp`, `expiration` | 4,461 unsigned / 7,884 signed |
//!
//! **For the X3DH-PQ handshake at the protocol tier, use the types in this
//! crate** ([`PreKeyBundle`] and [`SignedPreKeyBundle`]). They carry the
//! timestamp/expiration the server needs to age out stale bundles, and the
//! signed variant carries the 3,423-byte `HybridSignature` over the bundle
//! body for replay protection (using the `trelis-prekey-bundle-v1` BLAKE3
//! domain separator).
//!
//! Reach for `trelis_hybrid::HybridPreKeyBundle` only when you need a
//! self-contained cryptographic value with the typed `HybridOneTimeKey`
//! wrapper and do NOT need the X3DH-PQ-flavour metadata.
//!
//! The two types are deliberately not convertible at the type level — Rust's
//! type checker prevents passing one where the other is expected, so a
//! caller cannot accidentally submit a `HybridPreKeyBundle` to an API
//! expecting a `SignedPreKeyBundle` (or vice versa).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `struct_field_names` is allowed because the protocol field names follow
// Signal X3DH naming conventions; renames affect the public API surface.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::struct_field_names
)]
#![cfg_attr(test, allow(clippy::pedantic))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// The X3DH-PQ session protocol uses `HybridKemKeypair`,
// `HybridIdentityKeypair`, and `HybridKemPublicKey` from `trelis-hybrid`,
// which are gated behind `std`/`wasm` because they need the system CSPRNG.
// Mirror that gate so `cargo check --no-default-features` succeeds on this
// crate (compiling to a near-empty library that only re-exports
// `CryptoError`/`Result`) instead of failing with cascading import errors.
// Full MIRI coverage of this crate must be invoked with `--features std`
// (the default).
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod builder;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod bundle;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod initiator;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod responder;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod session_keys;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod transcript;

#[cfg(any(feature = "std", feature = "wasm"))]
pub use builder::PrekeyBundleBuilder;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use bundle::{PreKeyBundle, SignedPreKeyBundle};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use initiator::{InitialMessage, Initiator};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use responder::Responder;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use session_keys::SessionKeys;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use transcript::Transcript;

pub use trelis_error::{CryptoError, Result};
