//! ML-DSA signature scheme abstraction.
//!
//! This module provides a trait-based abstraction over different ML-DSA variants:
//! - [`MlDsa65Fips204`]: Standard FIPS 204 with SHA-3/SHAKE
//! - [`MlDsa65Blake3`]: BLAKE3 variant (requires `mldsa-blake3` feature)
//!
//! # Example
//!
//! ```ignore
//! use trelis_primitives::mldsa::{MlDsaScheme, MlDsa65Fips204};
//!
//! // Using the trait explicitly
//! let sk = MlDsa65Fips204::generate()?;
//! let vk = MlDsa65Fips204::verifying_key(&sk);
//! let sig = MlDsa65Fips204::sign(&sk, b"message")?;
//! assert!(MlDsa65Fips204::verify(&vk, b"message", &sig));
//! ```

use trelis_error::Result;
use zeroize::Zeroize;

/// Trait abstracting over ML-DSA signature scheme variants.
///
/// This trait allows generic code to work with different ML-DSA implementations
/// (FIPS 204 or BLAKE3) without knowing which variant is being used.
pub trait MlDsaScheme: Sized + Clone + 'static {
    /// The signing key type for this scheme.
    ///
    /// Must implement `Zeroize` to ensure proper cleanup of secret key material.
    type SigningKey: Clone + Zeroize;
    /// The verifying key type for this scheme.
    type VerifyingKey: Clone + PartialEq + Eq;
    /// The signature type for this scheme.
    type Signature: Clone + PartialEq + Eq;

    /// Size of the public (verifying) key in bytes.
    const PUBLIC_KEY_SIZE: usize;
    /// Size of the secret (signing) key in bytes.
    const SECRET_KEY_SIZE: usize;
    /// Size of the signature in bytes.
    const SIGNATURE_SIZE: usize;

    /// Generates a new random signing key.
    fn generate() -> Result<Self::SigningKey>;

    /// Generates a signing key deterministically from a 32-byte seed.
    ///
    /// This is used for recovery key derivation where the same seed must
    /// always produce the same key.
    fn generate_from_seed(seed: &[u8; 32]) -> Result<Self::SigningKey>;

    /// Derives the verifying key from a signing key.
    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey;

    /// Signs a message.
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature>;

    /// Signs a message with hedged per-call entropy (defence-in-depth vs a
    /// weak or compromised RNG).
    ///
    /// The default delegates to [`sign`](MlDsaScheme::sign) — a safe fallback
    /// that is never weaker than the standard path. Schemes with a native hedge
    /// (e.g. FIPS 204 ML-DSA-65) override this to bind fresh per-call entropy
    /// and the message into the signing RNG.
    fn sign_hedged(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        Self::sign(sk, message)
    }

    /// Signs a message with a context string.
    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature>;

    /// Verifies a signature on a message.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> Result<()>;

    /// Verifies a signature with a context string.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Serializes a signing key to bytes.
    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 4032];

    /// Deserializes a signing key from bytes.
    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey>;

    /// Serializes a verifying key to bytes.
    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 1952];

    /// Deserializes a verifying key from bytes.
    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey>;

    /// Serializes a signature to bytes.
    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 3309];

    /// Deserializes a signature from bytes.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature>;
}

// ============================================================================
// FIPS 204 Implementation
// ============================================================================

use crate::mldsa65::{
    MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey, PUBLIC_KEY_SIZE as FIPS204_PK_SIZE,
    SECRET_KEY_SIZE as FIPS204_SK_SIZE, SIGNATURE_SIZE as FIPS204_SIG_SIZE,
};

/// ML-DSA-65 using FIPS 204 (SHA-3/SHAKE).
///
/// This is the standard, well-audited ML-DSA-65 implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65Fips204;

impl MlDsaScheme for MlDsa65Fips204 {
    type SigningKey = MlDsa65SigningKey;
    type VerifyingKey = MlDsa65VerifyingKey;
    type Signature = MlDsa65Signature;

    const PUBLIC_KEY_SIZE: usize = FIPS204_PK_SIZE;
    const SECRET_KEY_SIZE: usize = FIPS204_SK_SIZE;
    const SIGNATURE_SIZE: usize = FIPS204_SIG_SIZE;

    fn generate() -> Result<Self::SigningKey> {
        MlDsa65SigningKey::generate()
    }

    fn generate_from_seed(seed: &[u8; 32]) -> Result<Self::SigningKey> {
        MlDsa65SigningKey::generate_from_seed(seed)
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        sk.verifying_key()
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        sk.sign(message)
    }

    /// Overrides the trait default with the native FIPS 204 hedge
    /// ([`MlDsa65SigningKey::sign_hedged`]): fresh per-call entropy and the
    /// message are folded into the ML-DSA-65 signing RNG (see `mldsa65.rs`).
    fn sign_hedged(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        sk.sign_hedged(message)
    }

    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature> {
        sk.sign_with_context(message, context)
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> Result<()> {
        vk.verify(message, signature)
    }

    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> Result<()> {
        vk.verify_with_context(message, context, signature)
    }

    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 4032] {
        *sk.as_bytes()
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey> {
        MlDsa65SigningKey::from_bytes(bytes)
    }

    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 1952] {
        vk.to_bytes()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey> {
        MlDsa65VerifyingKey::from_bytes(bytes)
    }

    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 3309] {
        sig.to_bytes()
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        MlDsa65Signature::from_bytes(bytes)
    }
}

// ============================================================================
// BLAKE3 Implementation
// ============================================================================

use crate::mldsa65b::{
    MlDsa65BSignature, MlDsa65BSigningKey, MlDsa65BVerifyingKey, PUBLIC_KEY_SIZE as BLAKE3_PK_SIZE,
    SECRET_KEY_SIZE as BLAKE3_SK_SIZE, SIGNATURE_SIZE as BLAKE3_SIG_SIZE,
};

/// ML-DSA-B-65 using BLAKE3.
///
/// This is the faster, experimental BLAKE3 variant with BLAKE3 hashing.
///
/// **Note:** Signatures from this variant are NOT compatible with FIPS 204.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65Blake3;

// ============================================================================
// Default Scheme Type Alias
// ============================================================================

/// Default ML-DSA scheme based on compile-time feature selection.
///
/// - With `mldsa-blake3-default` feature: uses [`MlDsa65Blake3`] (BLAKE3)
/// - Without that feature (default): uses [`MlDsa65Fips204`] (SHA-3/SHAKE)
///
/// This allows downstream crates to write generic code that uses the
/// compile-time selected default without specifying the type explicitly.
#[cfg(feature = "mldsa-blake3-default")]
pub type DefaultMlDsaScheme = MlDsa65Blake3;

/// Default ML-DSA scheme (FIPS 204 with SHA-3/SHAKE).
#[cfg(not(feature = "mldsa-blake3-default"))]
pub type DefaultMlDsaScheme = MlDsa65Fips204;

impl MlDsaScheme for MlDsa65Blake3 {
    type SigningKey = MlDsa65BSigningKey;
    type VerifyingKey = MlDsa65BVerifyingKey;
    type Signature = MlDsa65BSignature;

    const PUBLIC_KEY_SIZE: usize = BLAKE3_PK_SIZE;
    const SECRET_KEY_SIZE: usize = BLAKE3_SK_SIZE;
    const SIGNATURE_SIZE: usize = BLAKE3_SIG_SIZE;

    fn generate() -> Result<Self::SigningKey> {
        MlDsa65BSigningKey::generate()
    }

    fn generate_from_seed(seed: &[u8; 32]) -> Result<Self::SigningKey> {
        MlDsa65BSigningKey::generate_from_seed(seed)
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        sk.verifying_key()
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        sk.sign(message)
    }

    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature> {
        sk.sign_with_context(message, context)
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> Result<()> {
        vk.verify(message, signature)
    }

    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> Result<()> {
        vk.verify_with_context(message, context, signature)
    }

    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 4032] {
        *sk.as_bytes()
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey> {
        MlDsa65BSigningKey::from_bytes(bytes)
    }

    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 1952] {
        vk.to_bytes()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey> {
        MlDsa65BVerifyingKey::from_bytes(bytes)
    }

    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 3309] {
        sig.to_bytes()
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        MlDsa65BSignature::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scheme_roundtrip<S: MlDsaScheme>() {
        let sk = S::generate().unwrap();
        let vk = S::verifying_key(&sk);

        let message = b"Hello, ML-DSA!";
        let signature = S::sign(&sk, message).unwrap();

        assert!(S::verify(&vk, message, &signature).is_ok());
        assert!(S::verify(&vk, b"wrong message", &signature).is_err());
    }

    fn test_scheme_serialization<S: MlDsaScheme>() {
        let sk = S::generate().unwrap();
        let vk = S::verifying_key(&sk);
        let sig = S::sign(&sk, b"test").unwrap();

        // Round-trip signing key
        let sk_bytes = S::signing_key_to_bytes(&sk);
        let sk2 = S::signing_key_from_bytes(&sk_bytes).unwrap();
        let vk2 = S::verifying_key(&sk2);
        assert!(S::verifying_key_to_bytes(&vk) == S::verifying_key_to_bytes(&vk2));

        // Round-trip verifying key
        let vk_bytes = S::verifying_key_to_bytes(&vk);
        let vk3 = S::verifying_key_from_bytes(&vk_bytes).unwrap();
        assert!(vk == vk3);

        // Round-trip signature
        let sig_bytes = S::signature_to_bytes(&sig);
        let sig2 = S::signature_from_bytes(&sig_bytes).unwrap();
        assert!(sig == sig2);
    }

    fn test_scheme_seeded_keygen<S: MlDsaScheme>() {
        let seed = [0x42u8; 32];

        // Same seed produces identical keys
        let sk1 = S::generate_from_seed(&seed).unwrap();
        let sk2 = S::generate_from_seed(&seed).unwrap();
        assert_eq!(S::signing_key_to_bytes(&sk1), S::signing_key_to_bytes(&sk2));
        assert_eq!(
            S::verifying_key_to_bytes(&S::verifying_key(&sk1)),
            S::verifying_key_to_bytes(&S::verifying_key(&sk2))
        );

        // Different seeds produce different keys
        let seed2 = [0x43u8; 32];
        let sk3 = S::generate_from_seed(&seed2).unwrap();
        assert_ne!(S::signing_key_to_bytes(&sk1), S::signing_key_to_bytes(&sk3));

        // Seeded key can sign and verify
        let message = b"Seeded key test";
        let sig = S::sign(&sk1, message).unwrap();
        let vk = S::verifying_key(&sk1);
        assert!(S::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_fips204_roundtrip() {
        test_scheme_roundtrip::<MlDsa65Fips204>();
    }

    #[test]
    fn test_fips204_serialization() {
        test_scheme_serialization::<MlDsa65Fips204>();
    }

    #[test]
    fn test_fips204_seeded_keygen() {
        test_scheme_seeded_keygen::<MlDsa65Fips204>();
    }

    #[test]
    fn test_blake3_roundtrip() {
        test_scheme_roundtrip::<MlDsa65Blake3>();
    }

    #[test]
    fn test_blake3_serialization() {
        test_scheme_serialization::<MlDsa65Blake3>();
    }

    #[test]
    fn test_blake3_seeded_keygen() {
        test_scheme_seeded_keygen::<MlDsa65Blake3>();
    }
}
