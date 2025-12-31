//! Hybrid signature scheme (Ed448 + ML-DSA-65).
//!
//! This module provides hybrid signatures that combine classical Ed448 with
//! post-quantum ML-DSA-65. Both signatures are required to be valid for the
//! hybrid signature to verify successfully.
//!
//! # Key Sizes
//!
//! - Public key: 2,009 bytes (Ed448 57B + ML-DSA-65 1,952B)
//! - Signature: 3,423 bytes (Ed448 114B + ML-DSA-65 3,309B)
//!
//! # Example
//!
//! ```
//! use trelis_hybrid::signature::HybridSigningKeypair;
//!
//! let keypair = HybridSigningKeypair::generate().unwrap();
//! let message = b"Hello, Trelis!";
//!
//! let signature = keypair.sign(message).unwrap();
//! assert!(keypair.public_key().verify(message, &signature));
//! ```

use subtle::ConstantTimeEq;
use trelis_primitives::{
    Ed448Signature, Ed448SigningKey, Ed448VerifyingKey, MlDsa65Signature, MlDsa65SigningKey,
    MlDsa65VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use trelis_error::{CryptoError, Result};

/// Size of Ed448 public key in bytes.
pub const ED448_PK_SIZE: usize = 57;

/// Size of ML-DSA-65 public key in bytes.
pub const MLDSA_PK_SIZE: usize = 1952;

/// Size of hybrid signing public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = ED448_PK_SIZE + MLDSA_PK_SIZE;

/// Size of Ed448 signature in bytes.
pub const ED448_SIG_SIZE: usize = 114;

/// Size of ML-DSA-65 signature in bytes.
pub const MLDSA_SIG_SIZE: usize = 3309;

/// Size of hybrid signature in bytes.
pub const SIGNATURE_SIZE: usize = ED448_SIG_SIZE + MLDSA_SIG_SIZE;

/// Size of Ed448 secret key seed in bytes.
pub const ED448_SK_SIZE: usize = 57;

/// Size of ML-DSA-65 secret key in bytes.
pub const MLDSA_SK_SIZE: usize = 4032;

/// Size of hybrid signing secret key in bytes.
pub const SECRET_KEY_SIZE: usize = ED448_SK_SIZE + MLDSA_SK_SIZE;

/// Hybrid signing keypair (Ed448 + ML-DSA-65).
///
/// This keypair contains both classical and post-quantum signing keys.
/// Both algorithms are used to sign messages, providing security as long
/// as either algorithm remains secure.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSigningKeypair {
    #[zeroize(skip)]
    public_key: HybridSigningPublicKey,
    ed448_secret: Ed448SigningKey,
    mldsa_secret: MlDsa65SigningKey,
}

impl HybridSigningKeypair {
    /// Generates a new random hybrid signing keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    pub fn generate() -> Result<Self> {
        let ed448_secret = Ed448SigningKey::generate()?;
        let mldsa_secret = MlDsa65SigningKey::generate()?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: mldsa_secret.verifying_key(),
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Creates a hybrid signing keypair from individual components.
    ///
    /// This is used for deterministic key derivation (e.g., recovery keys).
    ///
    /// # Arguments
    ///
    /// * `ed448_secret` - The Ed448 signing key
    /// * `mldsa_secret` - The ML-DSA-65 signing key
    ///
    /// # Returns
    ///
    /// A hybrid keypair combining both components.
    pub fn from_components(
        ed448_secret: Ed448SigningKey,
        mldsa_secret: MlDsa65SigningKey,
    ) -> Result<Self> {
        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: mldsa_secret.verifying_key(),
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &HybridSigningPublicKey {
        &self.public_key
    }

    /// Serialises the secret key to bytes.
    ///
    /// Format: Ed448 seed (57 bytes) || ML-DSA-65 secret (4,032 bytes)
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material and should be
    /// handled securely (encrypted storage, zeroization after use).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes[..ED448_SK_SIZE].copy_from_slice(self.ed448_secret.seed());
        bytes[ED448_SK_SIZE..].copy_from_slice(self.mldsa_secret.as_bytes());
        bytes
    }

    /// Deserialises a keypair from secret key bytes.
    ///
    /// The public key is derived from the secret key components.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 4,089 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut ed448_seed = [0u8; ED448_SK_SIZE];
        ed448_seed.copy_from_slice(&bytes[..ED448_SK_SIZE]);
        let ed448_secret = Ed448SigningKey::from_seed(ed448_seed);

        let mldsa_secret = MlDsa65SigningKey::from_bytes(&bytes[ED448_SK_SIZE..])?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: mldsa_secret.verifying_key(),
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Signs a message with both Ed448 and ML-DSA-65.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// A hybrid signature containing both Ed448 and ML-DSA-65 signatures.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let ed448_sig = self.ed448_secret.sign(message);
        let mldsa_sig = self.mldsa_secret.sign(message)?;

        Ok(HybridSignature {
            ed448: ed448_sig,
            mldsa: mldsa_sig,
        })
    }

    /// Signs a message with a context string.
    ///
    /// Both Ed448 and ML-DSA-65 support context strings for domain separation.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    /// * `context` - The context string (max 255 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the context is too long or signing fails.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature> {
        let ed448_sig = self.ed448_secret.sign_with_context(message, context)?;
        let mldsa_sig = self.mldsa_secret.sign_with_context(message, context)?;

        Ok(HybridSignature {
            ed448: ed448_sig,
            mldsa: mldsa_sig,
        })
    }
}

impl core::fmt::Debug for HybridSigningKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningKeypair")
            .field("public_key", &self.public_key)
            .field("ed448_secret", &"[redacted]")
            .field("mldsa_secret", &"[redacted]")
            .finish()
    }
}

/// Hybrid signing public key (Ed448 + ML-DSA-65).
///
/// This public key is used to verify hybrid signatures. Both the Ed448
/// and ML-DSA-65 signatures must be valid for verification to succeed.
#[derive(Clone)]
pub struct HybridSigningPublicKey {
    /// Ed448 verifying key (57 bytes)
    pub ed448: Ed448VerifyingKey,
    /// ML-DSA-65 verifying key (1,952 bytes)
    pub mldsa: MlDsa65VerifyingKey,
}

impl HybridSigningPublicKey {
    /// Serialises the public key to bytes.
    ///
    /// Format: Ed448 (57 bytes) || ML-DSA-65 (1,952 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes[..ED448_PK_SIZE].copy_from_slice(&self.ed448.as_bytes());
        bytes[ED448_PK_SIZE..].copy_from_slice(self.mldsa.as_bytes());
        bytes
    }

    /// Deserialises a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 2,009 bytes,
    /// or `SignatureVerificationFailed` if the keys are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let ed448 = Ed448VerifyingKey::from_bytes(&bytes[..ED448_PK_SIZE])?;
        let mldsa = MlDsa65VerifyingKey::from_bytes(&bytes[ED448_PK_SIZE..])?;

        Ok(Self { ed448, mldsa })
    }

    /// Verifies a hybrid signature on a message.
    ///
    /// Both the Ed448 and ML-DSA-65 signatures must be valid.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Returns
    ///
    /// `true` if both signatures are valid, `false` otherwise.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        let ed448_valid = self.ed448.verify(message, &signature.ed448).is_ok();
        let mldsa_valid = self.mldsa.verify(message, &signature.mldsa);

        // Both must be valid
        ed448_valid && mldsa_valid
    }

    /// Verifies a hybrid signature with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing.
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Returns
    ///
    /// `true` if both signatures are valid, `false` otherwise.
    #[must_use]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &HybridSignature,
    ) -> bool {
        let ed448_valid = self
            .ed448
            .verify_with_context(message, context, &signature.ed448)
            .is_ok();
        let mldsa_valid = self
            .mldsa
            .verify_with_context(message, context, &signature.mldsa);

        ed448_valid && mldsa_valid
    }
}

impl PartialEq for HybridSigningPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ed448 == other.ed448 && self.mldsa == other.mldsa
    }
}

impl Eq for HybridSigningPublicKey {}

impl core::fmt::Debug for HybridSigningPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningPublicKey")
            .field("ed448", &self.ed448)
            .field("mldsa", &self.mldsa)
            .finish()
    }
}

/// Hybrid signature (Ed448 + ML-DSA-65).
///
/// Contains both classical and post-quantum signatures. Both must be
/// valid for the hybrid signature to verify successfully.
#[derive(Clone)]
pub struct HybridSignature {
    /// Ed448 signature (114 bytes)
    pub ed448: Ed448Signature,
    /// ML-DSA-65 signature (3,309 bytes)
    pub mldsa: MlDsa65Signature,
}

impl HybridSignature {
    /// Serialises the signature to bytes.
    ///
    /// Format: Ed448 (114 bytes) || ML-DSA-65 (3,293 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[..ED448_SIG_SIZE].copy_from_slice(&self.ed448.as_bytes());
        bytes[ED448_SIG_SIZE..].copy_from_slice(self.mldsa.as_bytes());
        bytes
    }

    /// Deserialises a signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let ed448 = Ed448Signature::from_bytes(&bytes[..ED448_SIG_SIZE])?;
        let mldsa = MlDsa65Signature::from_bytes(&bytes[ED448_SIG_SIZE..])?;

        Ok(Self { ed448, mldsa })
    }
}

impl ConstantTimeEq for HybridSignature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ed448.ct_eq(&other.ed448) & self.mldsa.ct_eq(&other.mldsa)
    }
}

impl PartialEq for HybridSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for HybridSignature {}

impl core::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSignature")
            .field("ed448", &"[114 bytes]")
            .field("mldsa", &"[3293 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(PUBLIC_KEY_SIZE, 2009);
    }

    #[test]
    fn test_signature_size() {
        // Ed448 (114) + ML-DSA-65 (3309) = 3423
        assert_eq!(SIGNATURE_SIZE, 3423);
    }

    #[test]
    fn test_key_generation() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let pk_bytes = keypair.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"Hello, hybrid signatures!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.public_key().verify(message, &signature));
    }

    #[test]
    fn test_signature_serialisation() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let signature = keypair.sign(b"test").unwrap();

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);

        let recovered = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_public_key_serialisation() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let pk = keypair.public_key();

        let bytes = pk.to_bytes();
        let recovered = HybridSigningPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, &recovered);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let signature = keypair.sign(b"correct message").unwrap();

        assert!(!keypair.public_key().verify(b"wrong message", &signature));
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = HybridSigningKeypair::generate().unwrap();
        let keypair2 = HybridSigningKeypair::generate().unwrap();

        let signature = keypair1.sign(b"test").unwrap();
        assert!(!keypair2.public_key().verify(b"test", &signature));
    }

    #[test]
    fn test_context_string() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"test message";
        let context = b"test-context";

        let signature = keypair.sign_with_context(message, context).unwrap();

        // Correct context succeeds
        assert!(
            keypair
                .public_key()
                .verify_with_context(message, context, &signature)
        );

        // Wrong context fails
        assert!(
            !keypair
                .public_key()
                .verify_with_context(message, b"wrong", &signature)
        );

        // No context fails
        assert!(!keypair.public_key().verify(message, &signature));
    }

    #[test]
    fn test_empty_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let signature = keypair.sign(b"").unwrap();
        assert!(keypair.public_key().verify(b"", &signature));
    }
}
