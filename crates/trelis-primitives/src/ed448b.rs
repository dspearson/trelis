//! Ed448-B signature primitives (experimental).
//!
//! This module provides an experimental Ed448 variant that uses BLAKE3 instead
//! of SHAKE256 for all internal hashing operations. This is NOT standard Ed448
//! and signatures are NOT compatible with RFC 8032.
//!
//! # Motivation
//!
//! BLAKE3 is significantly faster than SHAKE256, especially for large messages.
//! This variant provides the same security level as Ed448 (~224-bit) but with
//! improved performance characteristics.
//!
//! # Warning
//!
//! This is an experimental, non-standard signature scheme. Use standard Ed448
//! for interoperability. Ed448-B signatures cannot be verified by standard
//! Ed448 implementations.
//!
//! # Key Sizes
//!
//! - Public key: 57 bytes (same as Ed448)
//! - Secret key: 57 bytes (same as Ed448)
//! - Signature: 114 bytes (same as Ed448)

use ed448_goldilocks_plus::{EdwardsPoint, Scalar, ScalarBytes, WideScalarBytes};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of Ed448-B public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// Size of Ed448-B secret key (seed) in bytes.
pub const SECRET_KEY_SIZE: usize = 57;

/// Size of Ed448-B signature in bytes.
pub const SIGNATURE_SIZE: usize = 114;

/// Domain separator for Ed448-B signatures.
/// "SigEd448B" - distinguishes from standard Ed448.
const HASH_HEAD: &[u8] = b"SigEd448B";

/// Ed448-B signing key (secret key).
///
/// This key is used to create signatures. It contains the secret seed
/// and is zeroized on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed448BSigningKey {
    seed: [u8; SECRET_KEY_SIZE],
}

/// Internal expanded secret key with precomputed values.
struct ExpandedSecretKey {
    scalar: Scalar,
    hash_prefix: ScalarBytes,
    public_key: Ed448BVerifyingKey,
}

impl ExpandedSecretKey {
    /// Expands a seed into a signing scalar and hash prefix using BLAKE3.
    fn from_seed(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        // Use BLAKE3 XOF to expand seed into 114 bytes (57 for scalar, 57 for prefix)
        let mut output = [0u8; 114];
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut output);

        let mut scalar_bytes = ScalarBytes::default();
        scalar_bytes.copy_from_slice(&output[..SECRET_KEY_SIZE]);

        // Apply Ed448 clamping:
        // - Clear the two least significant bits of the first byte
        // - Clear all eight bits of the last byte
        // - Set the highest bit of the second-to-last byte
        scalar_bytes[0] &= 0xFC;
        scalar_bytes[56] = 0;
        scalar_bytes[55] |= 0x80;

        let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);

        let mut hash_prefix = ScalarBytes::default();
        hash_prefix.copy_from_slice(&output[SECRET_KEY_SIZE..]);

        // Compute public key: A = scalar * G
        let point = EdwardsPoint::GENERATOR * scalar;
        let compressed = point.compress();

        let public_key = Ed448BVerifyingKey {
            compressed,
            point,
        };

        Self {
            scalar,
            hash_prefix,
            public_key,
        }
    }

    /// Signs a message using BLAKE3.
    fn sign(&self, message: &[u8]) -> Ed448BSignature {
        self.sign_inner(0, &[], message)
    }

    /// Signs a message with context using BLAKE3.
    fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Ed448BSignature {
        self.sign_inner(0, context, message)
    }

    fn sign_inner(&self, phflag: u8, ctx: &[u8], message: &[u8]) -> Ed448BSignature {
        // Compute r = BLAKE3(dom || prefix || message) mod order
        // dom = HASH_HEAD || phflag || ctx_len || ctx
        let mut hasher = blake3::Hasher::new();
        hasher.update(HASH_HEAD);
        hasher.update(&[phflag]);
        hasher.update(&[ctx.len() as u8]);
        hasher.update(ctx);
        hasher.update(&self.hash_prefix);
        hasher.update(message);

        let mut r_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

        // R = r * G
        let big_r = EdwardsPoint::GENERATOR * r;
        let compressed_r = big_r.compress();

        // Compute k = BLAKE3(dom || R || A || message) mod order
        let mut hasher = blake3::Hasher::new();
        hasher.update(HASH_HEAD);
        hasher.update(&[phflag]);
        hasher.update(&[ctx.len() as u8]);
        hasher.update(ctx);
        hasher.update(compressed_r.as_bytes());
        hasher.update(self.public_key.compressed.as_bytes());
        hasher.update(message);

        let mut k_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // s = r + k * scalar
        let s = r + k * self.scalar;

        Ed448BSignature::new(compressed_r, s)
    }
}

impl Ed448BSigningKey {
    /// Generates a new random signing key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SECRET_KEY_SIZE];
        fill_bytes(&mut seed)?;
        Ok(Self { seed })
    }

    /// Creates a signing key from a seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 57-byte secret seed.
    #[must_use]
    pub const fn from_seed(seed: [u8; SECRET_KEY_SIZE]) -> Self {
        Self { seed }
    }

    /// Returns the seed bytes.
    #[must_use]
    pub fn seed(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Get the expanded secret key for operations.
    fn expanded(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from_seed(&self.seed)
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed448BVerifyingKey {
        self.expanded().public_key
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The Ed448-B signature (114 bytes).
    pub fn sign(&self, message: &[u8]) -> Ed448BSignature {
        self.expanded().sign(message)
    }

    /// Signs a message with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    /// * `context` - The context string (max 255 bytes).
    ///
    /// # Returns
    ///
    /// The Ed448-B signature (114 bytes), or an error if context is too long.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the context string is longer than 255 bytes.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Ed448BSignature> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(self.expanded().sign_with_context(message, context))
    }
}

/// Ed448-B verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
#[derive(Clone)]
pub struct Ed448BVerifyingKey {
    compressed: ed448_goldilocks_plus::CompressedEdwardsY,
    point: EdwardsPoint,
}

impl Ed448BVerifyingKey {
    /// Creates a verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 57 bytes,
    /// or `SignatureVerificationFailed` if the bytes don't represent a valid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        let compressed = ed448_goldilocks_plus::CompressedEdwardsY(key_bytes);
        let point = Option::<EdwardsPoint>::from(compressed.decompress())
            .ok_or(CryptoError::SignatureVerificationFailed)?;

        Ok(Self { compressed, point })
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.compressed.0
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.compressed.0
    }

    /// Verifies a signature on a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Ed448BSignature) -> Result<()> {
        self.verify_inner(0, &[], message, signature)
    }

    /// Verifies a signature on a message with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing.
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Ed448BSignature,
    ) -> Result<()> {
        self.verify_inner(0, context, message, signature)
    }

    fn verify_inner(
        &self,
        phflag: u8,
        ctx: &[u8],
        message: &[u8],
        signature: &Ed448BSignature,
    ) -> Result<()> {
        // Decompress R from signature
        let r_point = Option::<EdwardsPoint>::from(signature.r.decompress())
            .ok_or(CryptoError::SignatureVerificationFailed)?;

        // Compute k = BLAKE3(dom || R || A || message) mod order
        let mut hasher = blake3::Hasher::new();
        hasher.update(HASH_HEAD);
        hasher.update(&[phflag]);
        hasher.update(&[ctx.len() as u8]);
        hasher.update(ctx);
        hasher.update(signature.r.as_bytes());
        hasher.update(self.compressed.as_bytes());
        hasher.update(message);

        let mut k_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // Deserialize s scalar from signature
        let s_bytes = ScalarBytes::clone_from_slice(&signature.s);
        let s = Scalar::from_bytes_mod_order(&s_bytes);

        // Verify: s * G == R + k * A
        let lhs = EdwardsPoint::GENERATOR * s;
        let rhs = r_point + self.point * k;

        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl PartialEq for Ed448BVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Ed448BVerifyingKey {}

impl core::fmt::Debug for Ed448BVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448BVerifyingKey")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Ed448-B signature.
#[derive(Clone)]
pub struct Ed448BSignature {
    r: ed448_goldilocks_plus::CompressedEdwardsY,
    /// s scalar as 57 bytes (56 bytes + trailing 0x00, matching RFC 8032 format)
    s: [u8; 57],
}

impl Ed448BSignature {
    /// Creates a signature from the internal components.
    fn new(r: ed448_goldilocks_plus::CompressedEdwardsY, s: Scalar) -> Self {
        let mut s_bytes = [0u8; 57];
        s_bytes[..56].copy_from_slice(&s.to_bytes());
        // 57th byte is always 0x00 for valid scalars (curve order fits in 56 bytes)
        Self { r, s: s_bytes }
    }

    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 114 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let mut r_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&bytes[..57]);
        let r = ed448_goldilocks_plus::CompressedEdwardsY(r_bytes);

        let mut s = [0u8; 57];
        s.copy_from_slice(&bytes[57..]);

        Ok(Self { r, s })
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.to_bytes()
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[..57].copy_from_slice(self.r.as_bytes());
        bytes[57..].copy_from_slice(&self.s);
        bytes
    }
}

impl ConstantTimeEq for Ed448BSignature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for Ed448BSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Ed448BSignature {}

impl core::fmt::Debug for Ed448BSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448BSignature")
            .field("bytes", &"[114 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_key_generation() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Ed448-B!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature = signing_key.sign(message);

        let wrong_message = b"wrong message";
        assert!(matches!(
            verifying_key.verify(wrong_message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key1 = Ed448BSigningKey::generate().unwrap();
        let signing_key2 = Ed448BSigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message);

        assert!(matches!(
            verifying_key2.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_deterministic_signatures() {
        let signing_key = Ed448BSigningKey::generate().unwrap();

        let message = b"test message";
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Ed448-B signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_empty_message() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message);

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_context_string() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let context = b"trelis-test-context";

        let signature = signing_key.sign_with_context(message, context).unwrap();

        // Verify with same context should succeed
        assert!(verifying_key
            .verify_with_context(message, context, &signature)
            .is_ok());

        // Verify with wrong context should fail
        assert!(matches!(
            verifying_key.verify_with_context(message, b"wrong-context", &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));

        // Verify without context should fail
        assert!(matches!(
            verifying_key.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = Ed448BVerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        let bytes = signature.to_bytes();
        let recovered = Ed448BSignature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = Ed448BSignature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Ed448BVerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 57,
                actual: 50
            })
        ));
    }

    #[test]
    fn test_different_from_standard_ed448() {
        // Ensure Ed448-B signatures are NOT compatible with standard Ed448
        use crate::ed448::Ed448SigningKey;

        let seed = [0x42u8; 57];

        let ed448_sk = Ed448SigningKey::from_seed(seed);
        let ed448b_sk = Ed448BSigningKey::from_seed(seed);

        // Same seed should produce different public keys due to different hash
        let ed448_vk = ed448_sk.verifying_key();
        let ed448b_vk = ed448b_sk.verifying_key();

        assert_ne!(ed448_vk.to_bytes(), ed448b_vk.to_bytes());
    }
}
