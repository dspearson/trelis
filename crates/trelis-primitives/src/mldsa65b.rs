//! ML-DSA-B-65 signature primitives (BLAKE3 variant).
//!
//! This module provides ML-DSA-B-65 digital signatures using the BLAKE3
//! variant which replaces SHA-3/SHAKE with BLAKE3 for improved performance.
//!
//! **Note:** ML-DSA-B-65 signatures are NOT compatible with standard ML-DSA-65
//! (FIPS 204). Keys and signatures from one cannot be used with the other.
//!
//! # Key Sizes
//!
//! - Public key: 1,952 bytes
//! - Secret key: 4,032 bytes
//! - Signature: 3,309 bytes
//!
//! # Security Properties
//!
//! - Post-quantum security (lattice-based)
//! - Strong unforgeability under chosen message attacks (SUF-CMA)
//! - NIST Level 3 (~128-bit quantum security)
//! - Faster than FIPS 204 due to BLAKE3 (~30-60% faster hashing)
//!
//! # Examples
//!
//! ```ignore
//! use trelis_primitives::mldsa65b::{MlDsa65BSigningKey, MlDsa65BVerifyingKey};
//!
//! // Generate a new signing key
//! let signing_key = MlDsa65BSigningKey::generate().unwrap();
//!
//! // Get the corresponding verifying key
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, Trelis!";
//! let signature = signing_key.sign(message).unwrap();
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature));
//! ```

use crate::mldsa_core::{
    B32, EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, MlDsa65, Signature,
    blake3::{KeyGen, SigningKey, VerifyingKey},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of ML-DSA-B-65 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Size of ML-DSA-B-65 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 4032;

/// Size of ML-DSA-B-65 signature in bytes.
pub const SIGNATURE_SIZE: usize = 3309;

/// ML-DSA-B-65 signing key (secret key).
///
/// This key is used to create signatures. It contains the secret key material
/// and is zeroized on drop to prevent key material leakage.
///
/// **Note:** This is the BLAKE3 variant, NOT compatible with
/// standard ML-DSA-65 (FIPS 204).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65BSigningKey {
    bytes: [u8; SECRET_KEY_SIZE],
}

impl MlDsa65BSigningKey {
    /// Generates a new random signing key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        // Generate 32-byte seed for deterministic keygen
        let mut seed = [0u8; 32];
        fill_bytes(&mut seed)?;

        Self::generate_from_seed(&seed)
    }

    /// Generates a signing key deterministically from a 32-byte seed.
    ///
    /// This is used for recovery key derivation where the same seed must
    /// always produce the same key.
    ///
    /// # Errors
    ///
    /// Returns `KeyGenerationFailed` if key generation fails internally.
    pub fn generate_from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Convert to B32 (hybrid_array::Array<u8, U32>)
        let seed_array: B32 = (*seed).into();
        let keypair = MlDsa65::key_gen_internal(&seed_array);
        let sk_encoded = keypair.signing_key().encode();

        Ok(Self {
            bytes: sk_encoded.into(),
        })
    }

    /// Creates a signing key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        // Note: decode can't validate mathematical correctness of the key.
        // Invalid keys will fail at sign time, not here.
        Ok(Self { bytes: key_bytes })
    }

    /// Returns the secret key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> MlDsa65BVerifyingKey {
        let enc: EncodedSigningKey<MlDsa65> = self.bytes.into();
        let sk = SigningKey::<MlDsa65>::decode(&enc);
        let pk = sk.verifying_key();
        let pk_encoded = pk.encode();
        MlDsa65BVerifyingKey {
            bytes: pk_encoded.into(),
        }
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The ML-DSA-B-65 signature (3,309 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsa65BSignature> {
        self.sign_with_context(message, &[])
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
    /// The ML-DSA-B-65 signature (3,309 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes,
    /// or `InvalidSignature` if signing fails.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<MlDsa65BSignature> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }

        let enc: EncodedSigningKey<MlDsa65> = self.bytes.into();
        let sk = SigningKey::<MlDsa65>::decode(&enc);
        let sig = sk
            .sign_deterministic(message, context)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig_encoded = sig.encode();

        Ok(MlDsa65BSignature {
            bytes: sig_encoded.into(),
        })
    }

    /// Wraps this signing key in a `GuardedBox` for enhanced memory protection.
    ///
    /// The returned `GuardedBox` provides:
    /// - Guard pages before and after the key to detect buffer overflows
    /// - Memory locking to prevent swapping to disc (if privileges allow)
    /// - Automatic zeroisation on drop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sk = MlDsa65BSigningKey::generate()?;
    /// let guarded = sk.into_guarded()?;
    /// guarded.protect_readonly()?; // Optional: make read-only after init
    /// let sig = guarded.sign(message)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MemlockError` if memory allocation or protection fails.
    #[cfg(feature = "mlock")]
    pub fn into_guarded(self) -> crate::memlock::Result<crate::memlock::GuardedBox<Self>> {
        crate::memlock::GuardedBox::new(self)
    }
}

/// ML-DSA-B-65 verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
///
/// **Note:** This is the BLAKE3 variant, NOT compatible with
/// standard ML-DSA-65 (FIPS 204).
#[derive(Clone)]
pub struct MlDsa65BVerifyingKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl MlDsa65BVerifyingKey {
    /// Creates a verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 1,952 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        // Note: decode can't validate mathematical correctness of the key.
        // Invalid keys will fail at verify time, not here.
        Ok(Self { bytes: key_bytes })
    }

    /// Creates a verifying key from a fixed-size array.
    ///
    /// Note: This does not validate the mathematical correctness of the key.
    /// Invalid keys will fail at verify time, not here.
    #[must_use]
    pub fn from_array(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
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
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self, message: &[u8], signature: &MlDsa65BSignature) -> Result<()> {
        self.verify_with_context(message, &[], signature)
    }

    /// Verifies a signature on a message with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing (max 255 bytes).
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsa65BSignature,
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }

        // Decode verifying key
        let enc: EncodedVerifyingKey<MlDsa65> = self.bytes.into();
        let pk = VerifyingKey::<MlDsa65>::decode(&enc);

        // Decode signature (can fail for invalid signatures)
        let sig_enc: EncodedSignature<MlDsa65> = signature.bytes.into();
        let sig = match Signature::<MlDsa65>::decode(&sig_enc) {
            Some(sig) => sig,
            None => return Err(CryptoError::SignatureVerificationFailed),
        };

        if pk.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Verifies a signature without context prefix (internal API).
    ///
    /// This method is for compatibility with test vectors that were generated
    /// using the internal signing API without context string handling.
    ///
    /// For normal use, prefer [`Self::verify`] or [`Self::verify_with_context`].
    #[must_use]
    pub fn verify_internal(&self, message: &[u8], signature: &MlDsa65BSignature) -> bool {
        // Decode verifying key
        let enc: EncodedVerifyingKey<MlDsa65> = self.bytes.into();
        let pk = VerifyingKey::<MlDsa65>::decode(&enc);

        // Decode signature (can fail for invalid signatures)
        let sig_enc: EncodedSignature<MlDsa65> = signature.bytes.into();
        let sig = match Signature::<MlDsa65>::decode(&sig_enc) {
            Some(sig) => sig,
            None => return false,
        };

        pk.verify_internal(&[message], &sig)
    }
}

impl PartialEq for MlDsa65BVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for MlDsa65BVerifyingKey {}

impl core::fmt::Debug for MlDsa65BVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65BVerifyingKey")
            .field("bytes", &"[1952 bytes]")
            .finish()
    }
}

/// ML-DSA-B-65 signature.
///
/// **Note:** This is the BLAKE3 variant, NOT compatible with
/// standard ML-DSA-65 (FIPS 204).
#[derive(Clone)]
pub struct MlDsa65BSignature {
    bytes: [u8; SIGNATURE_SIZE],
}

impl MlDsa65BSignature {
    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 3,309 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: sig_bytes })
    }

    /// Creates a signature from a fixed-size array.
    #[must_use]
    pub const fn from_array(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.bytes
    }
}

impl ConstantTimeEq for MlDsa65BSignature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for MlDsa65BSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MlDsa65BSignature {}

impl core::fmt::Debug for MlDsa65BSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65BSignature")
            .field("bytes", &"[3309 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_key_sizes() {
        // Verify sizes match ML-DSA-65 specification (same as FIPS 204)
        assert_eq!(PUBLIC_KEY_SIZE, 1952);
        assert_eq!(SECRET_KEY_SIZE, 4032);
        assert_eq!(SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_key_generation() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, ML-DSA-B-65!";
        let signature = signing_key.sign(message).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test").unwrap();

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature = signing_key.sign(message).unwrap();

        let wrong_message = b"wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key1 = MlDsa65BSigningKey::generate().unwrap();
        let signing_key2 = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message).unwrap();

        // Verify with wrong key should fail
        assert!(verifying_key2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_empty_message() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_context_string() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let context = b"trelis-test-context";

        let signature = signing_key.sign_with_context(message, context).unwrap();

        // Verify with same context should succeed
        assert!(
            verifying_key
                .verify_with_context(message, context, &signature)
                .is_ok()
        );

        // Verify with wrong context should fail
        assert!(
            verifying_key
                .verify_with_context(message, b"wrong-context", &signature)
                .is_err()
        );

        // Verify without context should fail
        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = MlDsa65BVerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test").unwrap();

        let bytes = signature.to_bytes();
        let recovered = MlDsa65BSignature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = MlDsa65BSignature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_key_length() {
        let result = MlDsa65BVerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1952,
                actual: 50
            })
        ));
    }

    #[test]
    fn test_signing_key_from_bytes_roundtrip() {
        let signing_key = MlDsa65BSigningKey::generate().unwrap();
        let bytes = *signing_key.as_bytes();

        let recovered = MlDsa65BSigningKey::from_bytes(&bytes).unwrap();

        // Sign with both keys and verify they produce working signatures
        let message = b"test roundtrip";
        let sig1 = signing_key.sign(message).unwrap();
        let sig2 = recovered.sign(message).unwrap();

        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &sig1).is_ok());
        assert!(verifying_key.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_generate_from_seed_deterministic() {
        let seed = [0x42u8; 32];

        let key1 = MlDsa65BSigningKey::generate_from_seed(&seed).unwrap();
        let key2 = MlDsa65BSigningKey::generate_from_seed(&seed).unwrap();

        // Same seed should produce identical keys
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_from_seed_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let key1 = MlDsa65BSigningKey::generate_from_seed(&seed1).unwrap();
        let key2 = MlDsa65BSigningKey::generate_from_seed(&seed2).unwrap();

        // Different seeds should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_from_seed_sign_verify() {
        let seed = [0xAAu8; 32];
        let key = MlDsa65BSigningKey::generate_from_seed(&seed).unwrap();

        let message = b"Test message for seeded key";
        let signature = key.sign(message).unwrap();

        assert!(key.verifying_key().verify(message, &signature).is_ok());
        assert!(
            key.verifying_key()
                .verify(b"wrong message", &signature)
                .is_err()
        );
    }
}
