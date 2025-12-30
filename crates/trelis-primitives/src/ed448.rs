//! Ed448 signature primitives.
//!
//! This module provides Ed448 digital signatures as specified in RFC 8032.
//! Ed448 is the Edwards-curve Digital Signature Algorithm using Curve448,
//! providing approximately 224-bit security (NIST Level 4).
//!
//! # Key Sizes
//!
//! - Public key: 57 bytes
//! - Secret key: 57 bytes (seed)
//! - Signature: 114 bytes
//!
//! # Security Properties
//!
//! - Deterministic signatures (no randomness needed for signing)
//! - Strong unforgeability under chosen message attacks (SUF-CMA)
//! - Resistance to side-channel attacks when implemented correctly
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::ed448::{Ed448SigningKey, Ed448VerifyingKey};
//!
//! // Generate a new signing key
//! let signing_key = Ed448SigningKey::generate().unwrap();
//!
//! // Get the corresponding verifying key
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, Trelis!";
//! let signature = signing_key.sign(message);
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```

use ed448_goldilocks_plus::{ScalarBytes, SigningKey, VerifyingKey, Signature};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of Ed448 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// Size of Ed448 secret key (seed) in bytes.
pub const SECRET_KEY_SIZE: usize = 57;

/// Size of Ed448 signature in bytes.
pub const SIGNATURE_SIZE: usize = 114;

/// Ed448 signing key (secret key).
///
/// This key is used to create signatures. It contains the secret seed
/// and is zeroized on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed448SigningKey {
    seed: [u8; SECRET_KEY_SIZE],
}

impl Ed448SigningKey {
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

    /// Get the internal signing key for operations.
    fn inner_signing_key(&self) -> SigningKey {
        let scalar_bytes = ScalarBytes::clone_from_slice(&self.seed);
        SigningKey::from(scalar_bytes)
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed448VerifyingKey {
        let sk = self.inner_signing_key();
        let pk = sk.verifying_key();
        Ed448VerifyingKey { inner: pk }
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The Ed448 signature (114 bytes).
    pub fn sign(&self, message: &[u8]) -> Ed448Signature {
        let sk = self.inner_signing_key();
        let sig = sk.sign_raw(message);
        Ed448Signature { inner: sig }
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
    /// The Ed448 signature (114 bytes), or an error if context is too long.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the context string is invalid.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Ed448Signature> {
        let sk = self.inner_signing_key();
        let sig = sk.sign_ctx(context, message)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Ed448Signature { inner: sig })
    }
}

/// Ed448 verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
#[derive(Clone)]
pub struct Ed448VerifyingKey {
    inner: VerifyingKey,
}

impl Ed448VerifyingKey {
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
        let inner = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        Ok(Self { inner })
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
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
    pub fn verify(&self, message: &[u8], signature: &Ed448Signature) -> Result<()> {
        self.inner.verify_raw(&signature.inner, message)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
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
        signature: &Ed448Signature,
    ) -> Result<()> {
        self.inner.verify_ctx(&signature.inner, context, message)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

impl PartialEq for Ed448VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Ed448VerifyingKey {}

impl core::fmt::Debug for Ed448VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak key material in debug output
        f.debug_struct("Ed448VerifyingKey")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Ed448 signature.
#[derive(Clone)]
pub struct Ed448Signature {
    inner: Signature,
}

impl Ed448Signature {
    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 114 bytes
    /// or if the bytes don't represent a valid signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        let inner = Signature::from_bytes(&sig_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self { inner })
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.inner.to_bytes()
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.inner.to_bytes()
    }
}

impl ConstantTimeEq for Ed448Signature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for Ed448Signature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Ed448Signature {}

impl core::fmt::Debug for Ed448Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448Signature")
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
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Ed448!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = Ed448SigningKey::generate().unwrap();
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
        let signing_key1 = Ed448SigningKey::generate().unwrap();
        let signing_key2 = Ed448SigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message);

        // Verify with wrong key should fail
        assert!(matches!(
            verifying_key2.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_deterministic_signatures() {
        let signing_key = Ed448SigningKey::generate().unwrap();

        let message = b"test message";
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Ed448 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_empty_message() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message);

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_context_string() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let context = b"trelis-test-context";

        let signature = signing_key.sign_with_context(message, context).unwrap();

        // Verify with same context should succeed
        assert!(verifying_key.verify_with_context(message, context, &signature).is_ok());

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
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = Ed448VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        let bytes = signature.to_bytes();
        let recovered = Ed448Signature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = Ed448Signature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Ed448VerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength { expected: 57, actual: 50 })
        ));
    }
}
