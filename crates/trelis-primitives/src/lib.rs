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
//! swapped to disk. See the `memlock` module for details.

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
pub mod mldsa65;
/// ML-DSA-B-65 (PQC-Suite-B BLAKE3 variant) signature primitives.
///
/// This module provides ML-DSA-B-65 signatures using BLAKE3 instead of SHA-3/SHAKE.
/// **Note:** ML-DSA-B-65 is NOT compatible with standard ML-DSA-65 (FIPS 204).
#[cfg(feature = "mldsa-suite-b")]
pub mod mldsa65b;
pub mod random;
pub mod x448;

/// Memory locking to prevent secrets from being swapped to disk.
///
/// This module provides `LockedBox<T>` and related types
/// for OS-level memory protection using `mlock(2)` on Unix.
///
/// # Example
///
/// ```ignore
/// use trelis_primitives::memlock::LockedBox;
///
/// // Create a secret key that cannot be swapped to disk
/// let secret = LockedBox::new([0u8; 32])?;
/// // Use secret...
/// // Automatically zeroized and unlocked on drop
/// ```
#[cfg(feature = "mlock")]
pub mod memlock;

// sntrup761 implementations (backend-specific modules)
//
// Backend selection:
// - Native Unix/Linux: C FFI backend (pqcrypto-ntruprime) for performance
// - Windows: Pure Rust backend (ntrulp) since C code doesn't compile with MSVC
// - WASM: Pure Rust backend (ntrulp)

/// C FFI sntrup761 KEM using pqcrypto-ntruprime (native Unix/Linux only).
#[cfg(all(not(target_os = "windows"), not(target_arch = "wasm32")))]
pub mod sntrup761;
/// Wire format encoding for sntrup761 (standard encoding, shared by both backends).
pub mod sntrup761_encoding;
/// Optimised polynomial arithmetic for sntrup761 (Karatsuba, NTT).
#[cfg(any(feature = "wasm", target_os = "windows", target_arch = "wasm32"))]
pub mod sntrup761_poly;
/// Pure Rust sntrup761 KEM (WASM builds and Windows).
#[cfg(any(feature = "wasm", target_os = "windows", target_arch = "wasm32"))]
pub mod sntrup761_wasm;

// Re-export key types for convenience
pub use aead::{AeadKey, Nonce, Tag, decrypt, encrypt};
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
    SESSION_CONTEXT,
    derive_key,
    hash,
    keyed_hash,
};
pub use ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};
pub use mldsa65::{MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey};
#[cfg(feature = "mldsa-suite-b")]
pub use mldsa65b::{MlDsa65BSignature, MlDsa65BSigningKey, MlDsa65BVerifyingKey};
pub use random::{fill_bytes, generate_bytes};
pub use trelis_error::{CryptoError, Result};
pub use x448::{X448Public, X448Secret, X448SharedSecret};

// Memory locking re-exports (when mlock feature is enabled)
#[cfg(feature = "mlock")]
pub use memlock::{
    LockedBox, LockedVec, MemlockError, is_mlock_available, lock_memory, memlock_limit, page_size,
    unlock_memory,
};

// ============================================================================
// Unified sntrup761 API
// ============================================================================
//
// This provides a single set of `Sntrup761*` types that automatically select
// the appropriate backend based on target platform:
//
// - Native Unix/Linux: C FFI backend (pqcrypto-ntruprime)
// - Windows: Pure Rust backend (ntrulp) - C code doesn't compile with MSVC
// - WASM: Pure Rust backend (ntrulp)
//
// This allows dependent crates (like trelis-hybrid) to use `Sntrup761*` types
// without caring about the underlying implementation.

/// sntrup761 types using the C FFI backend (native Unix/Linux).
#[cfg(all(not(target_os = "windows"), not(target_arch = "wasm32")))]
pub use sntrup761::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, Sntrup761SharedSecret,
};

/// sntrup761 types using the pure Rust backend (Windows and WASM).
#[cfg(any(target_os = "windows", target_arch = "wasm32"))]
pub use sntrup761_wasm::{
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
    pub use crate::sntrup761_wasm::{
        CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
        Sntrup761Ciphertext as PureRustSntrup761Ciphertext,
        Sntrup761PublicKey as PureRustSntrup761PublicKey,
        Sntrup761SecretKey as PureRustSntrup761SecretKey,
        Sntrup761SharedSecret as PureRustSntrup761SharedSecret,
    };
}
