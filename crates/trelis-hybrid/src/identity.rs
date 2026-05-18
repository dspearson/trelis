//! Hybrid identity keypair (signing + KEM).
//!
//! This module provides the complete hybrid identity keypair that combines
//! hybrid signing (Ed448 + ML-DSA-65) with hybrid KEM (X448 + sntrup761).
//!
//! # Key Sizes
//!
//! - Public key: 3,223 bytes (signing 2,009B + KEM 1,214B)
//!
//! # Example
//!
//! ```no_run
//! # // no_run: Windows doctest threads have 1MB stack which overflows with
//! # // combined ML-DSA-65 + sntrup761 key generation. Unit tests cover this.
//! use trelis_hybrid::identity::HybridIdentityKeypair;
//!
//! let identity = HybridIdentityKeypair::generate().unwrap();
//!
//! // Sign with the identity
//! let signature = identity.sign(b"message").unwrap();
//! assert!(identity.public_key().verify(b"message", &signature).is_ok());
//!
//! // Receive encrypted key material
//! let (shared_secret, encapsulation) = identity.public_key().kem().encapsulate().unwrap();
//! let recovered = identity.decapsulate(&encapsulation).unwrap();
//! assert_eq!(shared_secret.as_bytes(), recovered.as_bytes());
//! ```

use alloc::boxed::Box;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::combiner::HybridSharedSecret;
use crate::kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};
use crate::signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};
use trelis_error::{CryptoError, Result};
use trelis_primitives::{DEVICE_IDENTITY_KEY_CONTEXT, DEVICE_SIGNING_KEY_CONTEXT, derive_key};

/// Size of hybrid signing public key in bytes.
pub const SIGNING_PK_SIZE: usize = crate::signature::PUBLIC_KEY_SIZE;

/// Size of hybrid KEM public key in bytes.
pub const KEM_PK_SIZE: usize = crate::kem::PUBLIC_KEY_SIZE;

/// Size of hybrid identity public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = SIGNING_PK_SIZE + KEM_PK_SIZE;

/// Size of hybrid signing secret key in bytes.
pub const SIGNING_SK_SIZE: usize = crate::signature::SECRET_KEY_SIZE;

/// Size of hybrid KEM secret key in bytes.
pub const KEM_SK_SIZE: usize = crate::kem::SECRET_KEY_SIZE;

/// Size of hybrid identity secret key in bytes.
pub const SECRET_KEY_SIZE: usize = SIGNING_SK_SIZE + KEM_SK_SIZE;

/// Complete hybrid identity keypair (signing + KEM).
///
/// This is the primary identity type in the Trelis protocol. It contains
/// both hybrid signing keys (for authentication) and hybrid KEM keys
/// (for key exchange).
///
/// The keypairs are heap-allocated to avoid stack overflow on platforms
/// with limited stack size (e.g., Windows default 1MB).
// No `Clone`: cloning a keypair duplicates secret key material into a second
// allocation whose lifetime the original's drop cannot protect (cf.
// FIPS 140-3 §4.7). Callers must use references; reconstruct via
// `from_bytes` only when an owned copy is genuinely required.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridIdentityKeypair {
    #[zeroize(skip)]
    public_key: HybridIdentityPublicKey,
    signing: Box<HybridSigningKeypair>,
    kem: Box<HybridKemKeypair>,
}

impl HybridIdentityKeypair {
    /// Generates a new random hybrid identity keypair.
    ///
    /// On Windows, this spawns a thread with larger stack to avoid overflow
    /// (the default 1MB stack is insufficient for hybrid key generation).
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    #[cfg(target_os = "windows")]
    pub fn generate() -> Result<Self> {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(Self::generate_inner)
            .map_err(|_| trelis_error::CryptoError::KeyGenerationFailed)?
            .join()
            .map_err(|_| trelis_error::CryptoError::KeyGenerationFailed)?
    }

    /// Generates a new random hybrid identity keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    #[cfg(not(target_os = "windows"))]
    pub fn generate() -> Result<Self> {
        Self::generate_inner()
    }

    /// Internal generation logic.
    fn generate_inner() -> Result<Self> {
        let signing = Box::new(HybridSigningKeypair::generate()?);
        let kem = Box::new(HybridKemKeypair::generate()?);

        let public_key = HybridIdentityPublicKey {
            signing: signing.public_key().clone(),
            kem: kem.public_key().clone(),
        };

        Ok(Self {
            public_key,
            signing,
            kem,
        })
    }

    /// Generates a hybrid identity keypair deterministically from a 32-byte
    /// device seed.
    ///
    /// Pair this with [`trelis_primitives::derive_device_seed`] which expands
    /// raw hardware entropy through `DEVICE_SEED_CONTEXT` into a canonical
    /// device seed; that seed is then split here via two domain-separated
    /// BLAKE3 derivations:
    ///
    /// - `DEVICE_SIGNING_KEY_CONTEXT` → signing-keypair sub-seed (Ed448 + ML-DSA-65)
    /// - `DEVICE_IDENTITY_KEY_CONTEXT` → KEM-keypair sub-seed (X448 + sntrup761)
    ///
    /// The two sub-seeds are independent (different BLAKE3 contexts), so a
    /// compromise of one component's seed does not leak the other's.
    ///
    /// The same input seed always produces the same identity keypair, which
    /// is the property hardware-attested device identities depend on: the
    /// device's secure enclave holds the entropy, and the identity keypair
    /// can be regenerated on demand without persisting the secret bytes in
    /// process memory.
    ///
    /// # Errors
    ///
    /// Returns `KeyGenerationFailed` if either underlying primitive's seeded
    /// constructor fails (typically only if the seeded RNG path encounters an
    /// unexpected rejection-sampling exhaustion, which should not happen with
    /// healthy seeds).
    pub fn generate_from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_seed = derive_key(DEVICE_SIGNING_KEY_CONTEXT, seed);
        let kem_seed = derive_key(DEVICE_IDENTITY_KEY_CONTEXT, seed);

        let signing = Box::new(HybridSigningKeypair::generate_from_seed(&signing_seed)?);
        let kem = Box::new(HybridKemKeypair::generate_from_seed(&kem_seed)?);

        let public_key = HybridIdentityPublicKey {
            signing: signing.public_key().clone(),
            kem: kem.public_key().clone(),
        };

        Ok(Self {
            public_key,
            signing,
            kem,
        })
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &HybridIdentityPublicKey {
        &self.public_key
    }

    /// Returns the signing keypair reference.
    #[must_use]
    pub fn signing(&self) -> &HybridSigningKeypair {
        &self.signing
    }

    /// Returns the KEM keypair reference.
    #[must_use]
    pub fn kem(&self) -> &HybridKemKeypair {
        &self.kem
    }

    /// Serialises the secret key to bytes.
    ///
    /// Format: Signing secret (4,089 bytes) || KEM secret (1,819 bytes)
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material and should be
    /// handled securely (encrypted storage, zeroisation after use).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        let mut bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        bytes[..SIGNING_SK_SIZE].copy_from_slice(&self.signing.to_bytes()[..]);
        bytes[SIGNING_SK_SIZE..].copy_from_slice(&self.kem.to_bytes()[..]);
        bytes
    }

    /// Deserialises a keypair from secret key bytes.
    ///
    /// The public key is derived from the secret key components.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 5,908 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let signing = Box::new(HybridSigningKeypair::from_bytes(&bytes[..SIGNING_SK_SIZE])?);
        let kem = Box::new(HybridKemKeypair::from_bytes(&bytes[SIGNING_SK_SIZE..])?);

        let public_key = HybridIdentityPublicKey {
            signing: signing.public_key().clone(),
            kem: kem.public_key().clone(),
        };

        Ok(Self {
            public_key,
            signing,
            kem,
        })
    }

    /// Signs a message with the identity's signing key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// A hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        self.signing.sign(message)
    }

    /// Signs a message with a context string.
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
        self.signing.sign_with_context(message, context)
    }

    /// Decapsulates a hybrid encapsulation using the identity's KEM key.
    ///
    /// # Arguments
    ///
    /// * `encapsulation` - The hybrid encapsulation to decapsulate.
    ///
    /// # Returns
    ///
    /// The combined shared secret.
    ///
    /// # Errors
    ///
    /// Returns `DecapsulationFailed` if decapsulation fails.
    #[must_use = "the decapsulated shared secret must be checked"]
    pub fn decapsulate(&self, encapsulation: &HybridEncapsulation) -> Result<HybridSharedSecret> {
        self.kem.decapsulate(encapsulation)
    }
}

impl core::fmt::Debug for HybridIdentityKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridIdentityKeypair")
            .field("public_key", &self.public_key)
            .field("signing", &"[redacted]")
            .field("kem", &"[redacted]")
            .finish()
    }
}

/// Complete hybrid identity public key (signing + KEM).
///
/// This is published for others to verify signatures and establish
/// encrypted sessions with this identity.
#[derive(Clone)]
pub struct HybridIdentityPublicKey {
    /// Hybrid signing public key (2,009 bytes)
    pub signing: HybridSigningPublicKey,
    /// Hybrid KEM public key (1,214 bytes)
    pub kem: HybridKemPublicKey,
}

impl HybridIdentityPublicKey {
    /// Serialises the public key to bytes.
    ///
    /// Format: Signing (2,009 bytes) || KEM (1,214 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes[..SIGNING_PK_SIZE].copy_from_slice(&self.signing.to_bytes());
        bytes[SIGNING_PK_SIZE..].copy_from_slice(&self.kem.to_bytes());
        bytes
    }

    /// Deserialises a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 3,223 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let signing = HybridSigningPublicKey::from_bytes(&bytes[..SIGNING_PK_SIZE])?;
        let kem = HybridKemPublicKey::from_bytes(&bytes[SIGNING_PK_SIZE..])?;

        Ok(Self { signing, kem })
    }

    /// Returns the signing public key.
    #[must_use]
    pub fn signing(&self) -> &HybridSigningPublicKey {
        &self.signing
    }

    /// Returns the KEM public key.
    #[must_use]
    pub fn kem(&self) -> &HybridKemPublicKey {
        &self.kem
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
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<()> {
        self.signing.verify(message, signature)
    }

    /// Verifies a signature with a context string.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &HybridSignature,
    ) -> Result<()> {
        self.signing
            .verify_with_context(message, context, signature)
    }
}

impl PartialEq for HybridIdentityPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.signing == other.signing && self.kem == other.kem
    }
}

impl Eq for HybridIdentityPublicKey {}

impl core::fmt::Debug for HybridIdentityPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridIdentityPublicKey")
            .field("signing", &self.signing)
            .field("kem", &self.kem)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(PUBLIC_KEY_SIZE, 3223);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_key_generation() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let pk_bytes = identity.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sign_verify() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let message = b"Hello, identity!";

        let signature = identity.sign(message).unwrap();
        assert!(identity.public_key().verify(message, &signature).is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encapsulate_decapsulate() {
        let identity = HybridIdentityKeypair::generate().unwrap();

        let (shared_secret_sender, encapsulation) =
            identity.public_key().kem().encapsulate().unwrap();
        let shared_secret_recipient = identity.decapsulate(&encapsulation).unwrap();

        assert_eq!(
            shared_secret_sender.as_bytes(),
            shared_secret_recipient.as_bytes()
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_public_key_serialisation() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let pk = identity.public_key();

        let bytes = pk.to_bytes();
        let recovered = HybridIdentityPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, &recovered);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_wrong_identity_fails() {
        let identity1 = HybridIdentityKeypair::generate().unwrap();
        let identity2 = HybridIdentityKeypair::generate().unwrap();

        let signature = identity1.sign(b"test").unwrap();
        assert!(identity2.public_key().verify(b"test", &signature).is_err());
    }

    /// HW-01 / HW-03 regression: `generate_from_seed` is deterministic — the
    /// same input seed always produces the same identity keypair (signing
    /// public key bytes AND KEM public key bytes both equal).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_from_seed_deterministic() {
        let seed = [0x42u8; 32];

        let identity1 = HybridIdentityKeypair::generate_from_seed(&seed).unwrap();
        let identity2 = HybridIdentityKeypair::generate_from_seed(&seed).unwrap();

        assert_eq!(
            identity1.public_key().to_bytes(),
            identity2.public_key().to_bytes(),
            "same seed must yield identical public key (signing + KEM)"
        );
        assert_eq!(
            identity1.to_bytes(),
            identity2.to_bytes(),
            "same seed must yield identical secret key"
        );
    }

    /// HW-02 regression: different seeds produce different identities.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_from_seed_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let identity1 = HybridIdentityKeypair::generate_from_seed(&seed1).unwrap();
        let identity2 = HybridIdentityKeypair::generate_from_seed(&seed2).unwrap();

        assert_ne!(
            identity1.public_key().to_bytes(),
            identity2.public_key().to_bytes(),
            "different seeds must yield distinct identities"
        );
    }

    /// Seeded identity is functionally usable: sign + verify works.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_seeded_identity_sign_verify() {
        let seed = [0xABu8; 32];
        let identity = HybridIdentityKeypair::generate_from_seed(&seed).unwrap();
        let message = b"seeded identity sign-verify round trip";

        let signature = identity.sign(message).unwrap();
        assert!(identity.public_key().verify(message, &signature).is_ok());
    }

    /// Seeded identity is functionally usable: encapsulate + decapsulate works.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_seeded_identity_kem_roundtrip() {
        let seed = [0xCDu8; 32];
        let identity = HybridIdentityKeypair::generate_from_seed(&seed).unwrap();

        let (ss_sender, encap) = identity.public_key().kem().encapsulate().unwrap();
        let ss_recipient = identity.decapsulate(&encap).unwrap();

        assert_eq!(ss_sender.as_bytes(), ss_recipient.as_bytes());
    }
}
