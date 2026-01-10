//! Ed448 signature scheme abstraction.
//!
//! This module provides a trait-based abstraction over different Ed448 variants:
//! - [`Ed448Standard`]: Standard Ed448 with SHAKE256 (RFC 8032)
//! - [`Ed448Blake3`]: Experimental variant with BLAKE3
//!
//! # Example
//!
//! ```ignore
//! use trelis_primitives::ed448_scheme::{Ed448Scheme, Ed448Standard};
//!
//! // Using the trait explicitly
//! let sk = Ed448Standard::generate()?;
//! let vk = Ed448Standard::verifying_key(&sk);
//! let sig = Ed448Standard::sign(&sk, b"message")?;
//! assert!(Ed448Standard::verify(&vk, b"message", &sig));
//! ```

use trelis_error::Result;

/// Trait abstracting over Ed448 signature scheme variants.
///
/// This trait allows generic code to work with different Ed448 implementations
/// (Standard SHAKE256 or experimental BLAKE3) without knowing which variant is being used.
///
/// The API is designed to be consistent with [`crate::MlDsaScheme`] for easier generic programming.
pub trait Ed448Scheme: Sized + Clone + 'static {
    /// The signing key type for this scheme.
    type SigningKey: Clone;
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

    /// Generates a signing key deterministically from a 57-byte seed.
    ///
    /// This is used for recovery key derivation where the same seed must
    /// always produce the same key.
    fn generate_from_seed(seed: &[u8; 57]) -> Result<Self::SigningKey>;

    /// Derives the verifying key from a signing key.
    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey;

    /// Signs a message.
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature>;

    /// Signs a message with a context string.
    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature>;

    /// Verifies a signature on a message.
    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> bool;

    /// Verifies a signature with a context string.
    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool;

    /// Serializes a signing key to bytes.
    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 57];

    /// Deserializes a signing key from bytes.
    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey>;

    /// Serializes a verifying key to bytes.
    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 57];

    /// Deserializes a verifying key from bytes.
    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey>;

    /// Serializes a signature to bytes.
    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 114];

    /// Deserializes a signature from bytes.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature>;
}

// ============================================================================
// Standard Ed448 Implementation (SHAKE256)
// ============================================================================

use crate::ed448::{
    Ed448Signature, Ed448SigningKey, Ed448VerifyingKey, PUBLIC_KEY_SIZE as STD_PK_SIZE,
    SECRET_KEY_SIZE as STD_SK_SIZE, SIGNATURE_SIZE as STD_SIG_SIZE,
};

/// Ed448 using standard SHAKE256 (RFC 8032).
///
/// This is the standard, well-specified Ed448 implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed448Standard;

impl Ed448Scheme for Ed448Standard {
    type SigningKey = Ed448SigningKey;
    type VerifyingKey = Ed448VerifyingKey;
    type Signature = Ed448Signature;

    const PUBLIC_KEY_SIZE: usize = STD_PK_SIZE;
    const SECRET_KEY_SIZE: usize = STD_SK_SIZE;
    const SIGNATURE_SIZE: usize = STD_SIG_SIZE;

    fn generate() -> Result<Self::SigningKey> {
        Ed448SigningKey::generate()
    }

    fn generate_from_seed(seed: &[u8; 57]) -> Result<Self::SigningKey> {
        Ok(Ed448SigningKey::from_seed(*seed))
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        sk.verifying_key()
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        Ok(sk.sign(message))
    }

    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature> {
        sk.sign_with_context(message, context)
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> bool {
        vk.verify(message, signature).is_ok()
    }

    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        vk.verify_with_context(message, context, signature).is_ok()
    }

    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 57] {
        *sk.seed()
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey> {
        use trelis_error::CryptoError;
        if bytes.len() != 57 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 57,
                actual: bytes.len(),
            });
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(bytes);
        Ok(Ed448SigningKey::from_seed(seed))
    }

    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 57] {
        vk.to_bytes()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey> {
        Ed448VerifyingKey::from_bytes(bytes)
    }

    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 114] {
        sig.to_bytes()
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        Ed448Signature::from_bytes(bytes)
    }
}

// ============================================================================
// BLAKE3 Implementation
// ============================================================================

use crate::ed448b::{
    Ed448BSignature, Ed448BSigningKey, Ed448BVerifyingKey, PUBLIC_KEY_SIZE as BLAKE3_PK_SIZE,
    SECRET_KEY_SIZE as BLAKE3_SK_SIZE, SIGNATURE_SIZE as BLAKE3_SIG_SIZE,
};

/// Ed448-B using BLAKE3 (experimental).
///
/// This is an experimental, faster variant with BLAKE3 hashing.
///
/// **Note:** Signatures from this variant are NOT compatible with standard Ed448.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed448Blake3;

impl Ed448Scheme for Ed448Blake3 {
    type SigningKey = Ed448BSigningKey;
    type VerifyingKey = Ed448BVerifyingKey;
    type Signature = Ed448BSignature;

    const PUBLIC_KEY_SIZE: usize = BLAKE3_PK_SIZE;
    const SECRET_KEY_SIZE: usize = BLAKE3_SK_SIZE;
    const SIGNATURE_SIZE: usize = BLAKE3_SIG_SIZE;

    fn generate() -> Result<Self::SigningKey> {
        Ed448BSigningKey::generate()
    }

    fn generate_from_seed(seed: &[u8; 57]) -> Result<Self::SigningKey> {
        Ok(Ed448BSigningKey::from_seed(*seed))
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        sk.verifying_key()
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        Ok(sk.sign(message))
    }

    fn sign_with_context(
        sk: &Self::SigningKey,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature> {
        sk.sign_with_context(message, context)
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> bool {
        vk.verify(message, signature).is_ok()
    }

    fn verify_with_context(
        vk: &Self::VerifyingKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        vk.verify_with_context(message, context, signature).is_ok()
    }

    fn signing_key_to_bytes(sk: &Self::SigningKey) -> [u8; 57] {
        *sk.seed()
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey> {
        use trelis_error::CryptoError;
        if bytes.len() != 57 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 57,
                actual: bytes.len(),
            });
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(bytes);
        Ok(Ed448BSigningKey::from_seed(seed))
    }

    fn verifying_key_to_bytes(vk: &Self::VerifyingKey) -> [u8; 57] {
        vk.to_bytes()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey> {
        Ed448BVerifyingKey::from_bytes(bytes)
    }

    fn signature_to_bytes(sig: &Self::Signature) -> [u8; 114] {
        sig.to_bytes()
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature> {
        Ed448BSignature::from_bytes(bytes)
    }
}

// ============================================================================
// Default Scheme Type Alias
// ============================================================================

/// Default Ed448 scheme based on compile-time feature selection.
///
/// - With `ed448-blake3-default` feature: uses [`Ed448Blake3`] (BLAKE3)
/// - Without that feature (default): uses [`Ed448Standard`] (SHAKE256)
///
/// This allows downstream crates to write generic code that uses the
/// compile-time selected default without specifying the type explicitly.
#[cfg(feature = "ed448-blake3-default")]
pub type DefaultEd448Scheme = Ed448Blake3;

/// Default Ed448 scheme (Standard with SHAKE256).
#[cfg(not(feature = "ed448-blake3-default"))]
pub type DefaultEd448Scheme = Ed448Standard;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scheme_roundtrip<S: Ed448Scheme>() {
        let sk = S::generate().unwrap();
        let vk = S::verifying_key(&sk);

        let message = b"Hello, Ed448!";
        let signature = S::sign(&sk, message).unwrap();

        assert!(S::verify(&vk, message, &signature));
        assert!(!S::verify(&vk, b"wrong message", &signature));
    }

    fn test_scheme_serialisation<S: Ed448Scheme>() {
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

    fn test_scheme_generate_from_seed<S: Ed448Scheme>() {
        let seed = [0x42u8; 57];

        // Same seed produces identical keys
        let sk1 = S::generate_from_seed(&seed).unwrap();
        let sk2 = S::generate_from_seed(&seed).unwrap();
        assert_eq!(
            S::verifying_key_to_bytes(&S::verifying_key(&sk1)),
            S::verifying_key_to_bytes(&S::verifying_key(&sk2))
        );

        // Different seeds produce different keys
        let seed2 = [0x43u8; 57];
        let sk3 = S::generate_from_seed(&seed2).unwrap();
        assert_ne!(
            S::verifying_key_to_bytes(&S::verifying_key(&sk1)),
            S::verifying_key_to_bytes(&S::verifying_key(&sk3))
        );

        // Seeded key can sign and verify
        let message = b"Seeded key test";
        let sig = S::sign(&sk1, message).unwrap();
        let vk = S::verifying_key(&sk1);
        assert!(S::verify(&vk, message, &sig));
    }

    #[test]
    fn test_standard_roundtrip() {
        test_scheme_roundtrip::<Ed448Standard>();
    }

    #[test]
    fn test_standard_serialisation() {
        test_scheme_serialisation::<Ed448Standard>();
    }

    #[test]
    fn test_standard_generate_from_seed() {
        test_scheme_generate_from_seed::<Ed448Standard>();
    }

    #[test]
    fn test_blake3_roundtrip() {
        test_scheme_roundtrip::<Ed448Blake3>();
    }

    #[test]
    fn test_blake3_serialisation() {
        test_scheme_serialisation::<Ed448Blake3>();
    }

    #[test]
    fn test_blake3_generate_from_seed() {
        test_scheme_generate_from_seed::<Ed448Blake3>();
    }

    #[test]
    fn test_schemes_incompatible() {
        // Ensure standard and BLAKE3 produce different outputs from same seed
        let seed = [0x42u8; 57];

        let std_sk = Ed448Standard::generate_from_seed(&seed).unwrap();
        let std_vk = Ed448Standard::verifying_key(&std_sk);

        let blake3_sk = Ed448Blake3::generate_from_seed(&seed).unwrap();
        let blake3_vk = Ed448Blake3::verifying_key(&blake3_sk);

        // Same seed should produce different public keys due to different hash
        assert_ne!(
            Ed448Standard::verifying_key_to_bytes(&std_vk),
            Ed448Blake3::verifying_key_to_bytes(&blake3_vk)
        );
    }
}
