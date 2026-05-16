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
//! All secret material is zeroized on drop.
//!
//! ## Constant-Time Guarantees
//!
//! The library targets a **co-located-process timing adversary**: an attacker
//! who runs on the same machine as the secret-holding process (different uid,
//! different sandbox), observes wall-clock or CPU-counter timing of individual
//! calls, and tries to derive any secret bit from those timings. Network-level
//! and remote-cache adversaries are weaker and also defended; physical side
//! channels (power, EM, fault injection) are out of scope.
//!
//! Operations that are CT-guaranteed against the threat model above (in source,
//! verified by `subtle::ConstantTimeEq` / `ConditionallySelectable` and the
//! statistical harnesses in `ct-tests/`):
//!
//! | Operation | Primitive |
//! |---|---|
//! | AEAD tag comparison | `aead::Tag::ct_eq` |
//! | AEAD key comparison | `aead::AeadKey::ct_eq` |
//! | Ed448 scalar multiplication | `ed448-goldilocks-plus` upstream |
//! | ML-DSA-65 verify | `fips204` upstream |
//! | SNTRUP761 decapsulation (incl. implicit rejection) | `sntrup761::pure_rust::decapsulate` |
//! | X448 Diffie-Hellman + all-zeros check | `x448::diffie_hellman` |
//! | Hybrid signature verify (bitwise AND of components) | `trelis_hybrid::signature::verify` |
//! | Shared-secret comparison | `*::SharedSecret::ct_eq` |
//!
//! Operations that are NOT CT-guaranteed (inputs are attacker-controlled but
//! not secret, or operate exclusively on public data):
//!
//! - Wire-format parsing (`trelis-wire`, every `from_bytes` and
//!   `deserialize_*`): the BYTES are attacker-controlled, but no SECRET is in
//!   scope at the parse point.
//! - SNTRUP761 KEY GENERATION (`Sntrup761SecretKey::generate*`): variable-time
//!   by design — multiple polynomial trials until one is invertible. Caller
//!   should generate keys ahead of time, not on a hot timing-observable path.
//! - Cocoa group-tree path computation: operates on group membership which is
//!   public.
//!
//! ## WASM Target Caveats
//!
//! WASM in a browser inherits the source-level CT discipline of the underlying
//! Rust primitives BUT:
//!
//! - WASM execution is typically JIT-compiled by the host JS engine (V8,
//!   SpiderMonkey). The JIT may introduce data-dependent optimisations that
//!   defeat CT (e.g. inlining a `secret == constant` check and folding it).
//!   `subtle::ConstantTimeEq` is robust against optimisers for native targets;
//!   in browsers, the additional JIT layer is **out of `subtle`'s reach**.
//! - Browser timing measurement granularity defaults to ~100 µs since Spectre,
//!   but `SharedArrayBuffer`-backed clocks can be much finer if the page has
//!   COOP/COEP headers.
//! - Recommended posture for WASM: treat the browser tab as semi-trusted,
//!   prefer the native build for high-value secrets, and audit the rendered
//!   wasm binary if precise CT is critical.
//!
//! ## Verification
//!
//! Source-level CT is reviewed in `FINDINGS-v1.1.md` Phase 7. Empirical CT is
//! measured by the dudect harnesses in `ct-tests/`; results are captured in
//! `audit-artifacts-v1.1/phase-7/`.
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
//!
//! # Memory Locking (Optional)
//!
//! With the `mlock` feature, this crate provides OS-level memory protection:
//!
//! ```toml
//! [dependencies]
//! trelis-primitives = { version = "0.1", features = ["mlock"] }
//! ```
//!
//! This enables `LockedBox<T>` for secrets that cannot be
//! swapped to disc. See the `memlock` module for details.

#![no_std]
// NOTE: unsafe_code is denied at workspace level (Cargo.toml)
// Only memlock.rs overrides this with #![allow(unsafe_code)] for mlock FFI
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::needless_borrow,
        clippy::needless_range_loop,
        clippy::manual_clamp,
        clippy::manual_range_contains,
        clippy::useless_asref,
        clippy::clone_on_copy,
        clippy::unnecessary_cast,
        clippy::needless_as_bytes
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod aead;
pub mod blake3_kdf;
pub mod ed448;
/// Ed448 scheme abstraction trait and implementations.
///
/// Provides [`Ed448Scheme`] trait for generic code over Ed448 variants.
pub mod ed448_scheme;
/// Ed448-B (experimental BLAKE3 variant) signature primitives.
///
/// This module provides Ed448-B signatures using BLAKE3 instead of SHAKE256.
/// **Note:** Ed448-B is NOT compatible with standard Ed448 (RFC 8032).
pub mod ed448b;
/// ML-DSA scheme abstraction trait and implementations.
///
/// Provides [`MlDsaScheme`] trait for generic code over ML-DSA variants.
pub mod mldsa;
pub mod mldsa65;
/// ML-DSA-65 BLAKE3 variant signature primitives.
///
/// This module provides ML-DSA-B-65 signatures using BLAKE3 instead of SHA-3/SHAKE.
/// **Note:** ML-DSA-B-65 is NOT compatible with standard ML-DSA-65 (FIPS 204).
pub mod mldsa65b;
/// ML-DSA core implementation with SHAKE and BLAKE3 hash variants.
///
/// This module contains the full ML-DSA algorithm implementation as specified
/// in FIPS 204, with support for both SHAKE (standard) and BLAKE3 hashes.
pub mod mldsa_core;
pub mod random;
pub mod x448;

/// Memory locking to prevent secrets from being swapped to disc.
///
/// This module provides `LockedBox<T>` and related types
/// for OS-level memory protection using `mlock(2)` on Unix.
///
/// # Example
///
/// ```ignore
/// use trelis_primitives::memlock::LockedBox;
///
/// // Create a secret key that cannot be swapped to disc
/// let secret = LockedBox::new([0u8; 32])?;
/// // Use secret...
/// // Automatically zeroized and unlocked on drop
/// ```
#[cfg(feature = "mlock")]
pub mod memlock;

/// sntrup761 post-quantum KEM (NTRU Prime).
///
/// Contains submodules for encoding, field arithmetic, polynomial arithmetic,
/// and both C FFI and pure Rust backends. See [`sntrup761`] module docs for details.
pub mod sntrup761;

// Re-export key types for convenience
pub use aead::{AeadKey, Nonce, Tag};
#[cfg(feature = "alloc")]
pub use aead::{decrypt, encrypt};
pub use blake3_kdf::{
    // Domain separation contexts
    BUNDLE_WRAP_CONTEXT,
    COMPROMISE_NOTICE_CONTEXT,
    DerivedKey,
    HYBRID_KEM_CONTEXT,
    OUTPUT_SIZE,
    PREKEY_BUNDLE_SIG_CONTEXT,
    RATCHET_MESSAGE_CONTEXT,
    RATCHET_NONCE_CONTEXT,
    RATCHET_ROOT_CONTEXT,
    RECOVERY_ED448_CONTEXT,
    RECOVERY_MLDSA_CONTEXT,
    SAFETY_NUMBER_CONTEXT,
    SAFETY_NUMBER_SYNC_CONTEXT,
    SESSION_CONTEXT,
    derive_key,
    hash,
    keyed_hash,
};
pub use ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};
pub use ed448_scheme::{DefaultEd448Scheme, Ed448Blake3, Ed448Scheme, Ed448Standard};
pub use ed448b::{Ed448BSignature, Ed448BSigningKey, Ed448BVerifyingKey};
pub use mldsa::{DefaultMlDsaScheme, MlDsa65Blake3, MlDsa65Fips204, MlDsaScheme};
pub use mldsa65::{MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey};
pub use mldsa65b::{MlDsa65BSignature, MlDsa65BSigningKey, MlDsa65BVerifyingKey};
pub use random::{fill_bytes, generate_bytes};
pub use trelis_error::{CryptoError, Result};
pub use x448::{X448Public, X448Secret, X448SharedSecret};

// Memory locking re-exports (when mlock feature is enabled)
#[cfg(feature = "mlock")]
pub use memlock::{
    GuardedBox, LockedBox, LockedVec, MemlockError, is_mlock_available, lock_memory, memlock_limit,
    page_size, protect_noaccess, protect_readonly, protect_readwrite, unlock_memory,
};

// Unified sntrup761 API — re-exported from sntrup761::mod.rs based on platform.
pub use sntrup761::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};

// Additional exports for cross-validation testing (both backends available on native Unix/Linux)
#[cfg(all(
    feature = "std",
    feature = "wasm",
    not(target_os = "windows"),
    not(target_arch = "wasm32")
))]
pub mod sntrup761_pure_rust {
    //! Pure Rust sntrup761 types for cross-validation testing.
    //!
    //! Only available when both `std` and `wasm` features are enabled on native Unix/Linux.
    //! This module re-exports the pure Rust implementation with prefixed names
    //! to allow comparing outputs between C FFI and pure Rust backends.
    pub use crate::sntrup761::pure_rust::{
        CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
        Sntrup761Ciphertext as PureRustSntrup761Ciphertext,
        Sntrup761PublicKey as PureRustSntrup761PublicKey,
        Sntrup761SecretKey as PureRustSntrup761SecretKey,
        Sntrup761SharedSecret as PureRustSntrup761SharedSecret,
    };
}
