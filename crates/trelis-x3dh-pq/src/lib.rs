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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bundle;
pub mod initiator;
pub mod responder;
pub mod session_keys;
pub mod transcript;

pub use bundle::{PreKeyBundle, SignedPreKeyBundle};
pub use initiator::{InitialMessage, Initiator};
pub use responder::Responder;
pub use session_keys::SessionKeys;
pub use transcript::Transcript;

pub use trelis_error::{CryptoError, Result};
