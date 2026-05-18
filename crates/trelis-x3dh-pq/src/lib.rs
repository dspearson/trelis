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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Pedantic-lint policy:
// - `doc_markdown` / `missing_errors_doc` — deferred to Phase 12 (DOCS-02).
// - `struct_field_names` — protocol field names follow Signal X3DH naming
//   conventions; renames affect the public API surface (Phase 11 ERGO-04).
// See Phase 10 disposition in `10-PEDANTIC-DRAFT.md`.
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

// DYN-01-MIRI-01: the X3DH-PQ session protocol uses `HybridKemKeypair`,
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
