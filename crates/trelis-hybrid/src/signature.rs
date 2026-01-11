//! Hybrid signature scheme (Ed448 + ML-DSA-65).
//!
//! This module provides hybrid signatures that combine classical Ed448 with
//! post-quantum ML-DSA-65. Both signatures are required to be valid for the
//! hybrid signature to verify successfully.
//!
//! # ML-DSA Variants
//!
//! The hybrid signature types are generic over the ML-DSA variant:
//! - [`trelis_primitives::MlDsa65Fips204`]: Standard FIPS 204 with SHA-3/SHAKE (default)
//! - [`trelis_primitives::MlDsa65Blake3`]: BLAKE3 variant (requires `mldsa-blake3` feature)
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
//! use trelis_primitives::MlDsa65Fips204;
//!
//! // Use FIPS 204 (standard ML-DSA-65)
//! let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
//! let message = b"Hello, Trelis!";
//!
//! let signature = keypair.sign(message).unwrap();
//! assert!(keypair.public_key().verify(message, &signature).is_ok());
//! ```
//!
//! # Using Suite-B variant
//!
//! ```ignore
//! use trelis_hybrid::signature::HybridSigningKeypair;
//! use trelis_primitives::MlDsa65SuiteB;
//!
//! // Explicitly use Suite-B
//! let keypair = HybridSigningKeypair::<MlDsa65SuiteB>::generate().unwrap();
//! ```

use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use trelis_primitives::{
    DefaultMlDsaScheme, Ed448Signature, Ed448SigningKey, Ed448VerifyingKey, MlDsaScheme,
};
use zeroize::Zeroize;

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
///
/// The type parameter `S` selects the ML-DSA variant:
/// - `MlDsa65Fips204` (default): Standard FIPS 204
/// - `MlDsa65SuiteB`: PQC-Suite-B with BLAKE3
#[derive(Clone)]
pub struct HybridSigningKeypair<S: MlDsaScheme = DefaultMlDsaScheme> {
    public_key: HybridSigningPublicKey<S>,
    ed448_secret: Ed448SigningKey,
    mldsa_secret: S::SigningKey,
}

impl<S: MlDsaScheme> Zeroize for HybridSigningKeypair<S> {
    fn zeroize(&mut self) {
        self.ed448_secret.zeroize();
        self.mldsa_secret.zeroize();
    }
}

impl<S: MlDsaScheme> Drop for HybridSigningKeypair<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S: MlDsaScheme> HybridSigningKeypair<S> {
    /// Generates a new random hybrid signing keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    ///
    /// # Note
    ///
    /// On Windows with default 1MB stack, this may overflow when combined with
    /// other large key operations. Use `HybridIdentityKeypair` which handles
    /// this via heap allocation, or run in a thread with larger stack.
    pub fn generate() -> Result<Self> {
        let ed448_secret = Ed448SigningKey::generate()?;
        let mldsa_secret = S::generate()?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
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
    pub fn from_components(ed448_secret: Ed448SigningKey, mldsa_secret: S::SigningKey) -> Self {
        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
        };

        Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        }
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &HybridSigningPublicKey<S> {
        &self.public_key
    }

    /// Returns the Ed448 signing key component.
    #[must_use]
    pub fn ed448_secret(&self) -> &Ed448SigningKey {
        &self.ed448_secret
    }

    /// Returns the ML-DSA signing key component.
    #[must_use]
    pub fn mldsa_secret(&self) -> &S::SigningKey {
        &self.mldsa_secret
    }

    /// Serialises the secret key to bytes.
    ///
    /// Format: Ed448 seed (57 bytes) || ML-DSA-65 secret (4,032 bytes)
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material and should be
    /// handled securely (encrypted storage, zeroisation after use).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes[..ED448_SK_SIZE].copy_from_slice(self.ed448_secret.seed());
        bytes[ED448_SK_SIZE..].copy_from_slice(&S::signing_key_to_bytes(&self.mldsa_secret));
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

        let mldsa_secret = S::signing_key_from_bytes(&bytes[ED448_SK_SIZE..])?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
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
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature<S>> {
        let ed448_sig = self.ed448_secret.sign(message);
        let mldsa_sig = S::sign(&self.mldsa_secret, message)?;

        Ok(HybridSignature {
            ed448: ed448_sig,
            mldsa: mldsa_sig,
            _marker: PhantomData,
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
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature<S>> {
        let ed448_sig = self.ed448_secret.sign_with_context(message, context)?;
        let mldsa_sig = S::sign_with_context(&self.mldsa_secret, message, context)?;

        Ok(HybridSignature {
            ed448: ed448_sig,
            mldsa: mldsa_sig,
            _marker: PhantomData,
        })
    }

    /// Wraps this keypair in a `GuardedBox` for enhanced memory protection.
    ///
    /// The returned `GuardedBox` provides:
    /// - Guard pages before and after the keypair to detect buffer overflows
    /// - Memory locking to prevent swapping to disc (if privileges allow)
    /// - Automatic zeroisation on drop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = HybridSigningKeypair::generate()?;
    /// let guarded = keypair.into_guarded()?;
    /// guarded.protect_readonly()?; // Optional: make read-only after init
    /// let sig = guarded.sign(message)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MemlockError` if memory allocation or protection fails.
    #[cfg(feature = "mlock")]
    pub fn into_guarded(
        self,
    ) -> trelis_primitives::memlock::Result<trelis_primitives::GuardedBox<Self>> {
        trelis_primitives::GuardedBox::new(self)
    }
}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSigningKeypair<S> {
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
pub struct HybridSigningPublicKey<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// Ed448 verifying key (57 bytes)
    pub ed448: Ed448VerifyingKey,
    /// ML-DSA-65 verifying key (1,952 bytes)
    pub mldsa: S::VerifyingKey,
    _marker: PhantomData<S>,
}

impl<S: MlDsaScheme> HybridSigningPublicKey<S> {
    /// Creates a public key from individual components.
    pub fn from_components(ed448: Ed448VerifyingKey, mldsa: S::VerifyingKey) -> Self {
        Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        }
    }

    /// Serialises the public key to bytes.
    ///
    /// Format: Ed448 (57 bytes) || ML-DSA-65 (1,952 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes[..ED448_PK_SIZE].copy_from_slice(&self.ed448.as_bytes());
        bytes[ED448_PK_SIZE..].copy_from_slice(&S::verifying_key_to_bytes(&self.mldsa));
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
        let mldsa = S::verifying_key_from_bytes(&bytes[ED448_PK_SIZE..])?;

        Ok(Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        })
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
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if either signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature<S>) -> Result<()> {
        let ed448_valid = self.ed448.verify(message, &signature.ed448).is_ok();
        let mldsa_valid = S::verify(&self.mldsa, message, &signature.mldsa).is_ok();

        // Both must be valid - use bitwise AND to prevent short-circuit timing leak
        if ed448_valid & mldsa_valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Verifies a hybrid signature with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing (max 255 bytes).
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if either signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &HybridSignature<S>,
    ) -> Result<()> {
        // Validate context length first (both schemes have the same limit)
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }

        let ed448_valid = self
            .ed448
            .verify_with_context(message, context, &signature.ed448)
            .is_ok();
        let mldsa_valid =
            S::verify_with_context(&self.mldsa, message, context, &signature.mldsa).is_ok();

        // Use bitwise AND to avoid short-circuit timing leak
        if ed448_valid & mldsa_valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl<S: MlDsaScheme> PartialEq for HybridSigningPublicKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.ed448 == other.ed448 && self.mldsa == other.mldsa
    }
}

impl<S: MlDsaScheme> Eq for HybridSigningPublicKey<S> {}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSigningPublicKey<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningPublicKey")
            .field("ed448", &self.ed448)
            .field("mldsa", &"[1952 bytes]")
            .finish()
    }
}

/// Hybrid signature (Ed448 + ML-DSA-65).
///
/// Contains both classical and post-quantum signatures. Both must be
/// valid for the hybrid signature to verify successfully.
#[derive(Clone)]
pub struct HybridSignature<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// Ed448 signature (114 bytes)
    pub ed448: Ed448Signature,
    /// ML-DSA-65 signature (3,309 bytes)
    pub mldsa: S::Signature,
    _marker: PhantomData<S>,
}

impl<S: MlDsaScheme> HybridSignature<S> {
    /// Creates a signature from individual components.
    pub fn from_components(ed448: Ed448Signature, mldsa: S::Signature) -> Self {
        Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        }
    }

    /// Serialises the signature to bytes.
    ///
    /// Format: Ed448 (114 bytes) || ML-DSA-65 (3,309 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[..ED448_SIG_SIZE].copy_from_slice(&self.ed448.as_bytes());
        bytes[ED448_SIG_SIZE..].copy_from_slice(&S::signature_to_bytes(&self.mldsa));
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
        let mldsa = S::signature_from_bytes(&bytes[ED448_SIG_SIZE..])?;

        Ok(Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        })
    }
}

impl<S: MlDsaScheme> PartialEq for HybridSignature<S> {
    fn eq(&self, other: &Self) -> bool {
        // Use bitwise AND to avoid short-circuit timing leak
        let ed448_eq: bool = self.ed448.ct_eq(&other.ed448).into();
        let mldsa_eq: bool = self.mldsa == other.mldsa;
        ed448_eq & mldsa_eq
    }
}

impl<S: MlDsaScheme> Eq for HybridSignature<S> {}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSignature<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSignature")
            .field("ed448", &"[114 bytes]")
            .field("mldsa", &"[3309 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_primitives::MlDsa65Fips204;

    // Type aliases for tests - use FIPS 204 (standard) for test vectors
    type TestKeypair = HybridSigningKeypair<MlDsa65Fips204>;
    type TestPublicKey = HybridSigningPublicKey<MlDsa65Fips204>;
    type TestSignature = HybridSignature<MlDsa65Fips204>;

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
        let keypair = TestKeypair::generate().unwrap();
        let pk_bytes = keypair.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = TestKeypair::generate().unwrap();
        let message = b"Hello, hybrid signatures!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_serialisation() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"test").unwrap();

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);

        let recovered = TestSignature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_public_key_serialisation() {
        let keypair = TestKeypair::generate().unwrap();
        let pk = keypair.public_key();

        let bytes = pk.to_bytes();
        let recovered = TestPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, &recovered);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"correct message").unwrap();

        assert!(
            keypair
                .public_key()
                .verify(b"wrong message", &signature)
                .is_err()
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = TestKeypair::generate().unwrap();
        let keypair2 = TestKeypair::generate().unwrap();

        let signature = keypair1.sign(b"test").unwrap();
        assert!(keypair2.public_key().verify(b"test", &signature).is_err());
    }

    #[test]
    fn test_context_string() {
        let keypair = TestKeypair::generate().unwrap();
        let message = b"test message";
        let context = b"test-context";

        let signature = keypair.sign_with_context(message, context).unwrap();

        // Correct context succeeds
        assert!(
            keypair
                .public_key()
                .verify_with_context(message, context, &signature)
                .is_ok()
        );

        // Wrong context fails
        assert!(
            keypair
                .public_key()
                .verify_with_context(message, b"wrong", &signature)
                .is_err()
        );

        // No context fails
        assert!(keypair.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_empty_message() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"").unwrap();
        assert!(keypair.public_key().verify(b"", &signature).is_ok());
    }

    #[test]
    fn test_keypair_serialisation_roundtrip() {
        let keypair = TestKeypair::generate().unwrap();
        let bytes = keypair.to_bytes();

        let recovered = TestKeypair::from_bytes(&bytes).unwrap();

        // Verify the recovered keypair works
        let message = b"test roundtrip";
        let sig = recovered.sign(message).unwrap();
        assert!(recovered.public_key().verify(message, &sig).is_ok());

        // And the public keys match
        assert_eq!(
            keypair.public_key().to_bytes(),
            recovered.public_key().to_bytes()
        );
    }

    // Test with BLAKE3 variant if available
    #[cfg(feature = "mldsa-blake3")]
    mod blake3_tests {
        use super::*;
        use trelis_primitives::MlDsa65Blake3;

        #[test]
        fn test_blake3_sign_verify() {
            let keypair = HybridSigningKeypair::<MlDsa65Blake3>::generate().unwrap();
            let message = b"Hello, BLAKE3!";

            let signature = keypair.sign(message).unwrap();
            assert!(keypair.public_key().verify(message, &signature).is_ok());
        }

        #[test]
        fn test_blake3_serialisation() {
            let keypair = HybridSigningKeypair::<MlDsa65Blake3>::generate().unwrap();
            let bytes = keypair.to_bytes();

            let recovered = HybridSigningKeypair::<MlDsa65Blake3>::from_bytes(&bytes).unwrap();
            assert_eq!(
                keypair.public_key().to_bytes(),
                recovered.public_key().to_bytes()
            );
        }
    }
}
