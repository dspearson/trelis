//! Hybrid one-time keys for session establishment.
//!
//! One-time keys (OTKs) are ephemeral hybrid KEM keypairs used during X3DH-PQ
//! session establishment. Each OTK is used exactly once and then discarded.
//!
//! # Key Sizes
//!
//! - One-time public key: 1,214 bytes (same as HybridKemPublicKey)
//!
//! # Lifecycle
//!
//! 1. Device generates a batch of OTKs
//! 2. Device signs OTKs with its identity signing key
//! 3. OTKs are uploaded to the server
//! 4. When another party initiates a session, the server provides one OTK
//! 5. The OTK is used for session establishment and then deleted

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::combiner::HybridSharedSecret;
use crate::kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};
use crate::signature::{HybridSignature, HybridSigningKeypair};
use trelis_error::Result;

/// A hybrid one-time keypair for session establishment.
///
/// This is a complete keypair (public + secret) held by the device that
/// generated it. The public portion is uploaded to the server; the secret
/// portion is kept locally until the OTK is used or expires.
// No `Clone`: this wraps a `HybridKemKeypair` containing secret key material;
// cloning would duplicate that secret into a second allocation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridOneTimeKeyPair {
    /// The underlying hybrid KEM keypair
    kem: HybridKemKeypair,
    /// Unique identifier for this OTK (first 8 bytes of public key hash)
    #[zeroize(skip)]
    key_id: [u8; 8],
}

impl HybridOneTimeKeyPair {
    /// Generates a new random one-time keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let kem = HybridKemKeypair::generate()?;

        // Derive key ID from first 8 bytes of BLAKE3 hash of public key
        let pk_bytes = kem.public_key().to_bytes();
        let hash = trelis_primitives::hash(&pk_bytes);
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&hash[..8]);

        Ok(Self { kem, key_id })
    }

    /// Returns the unique key identifier.
    #[must_use]
    pub fn key_id(&self) -> &[u8; 8] {
        &self.key_id
    }

    /// Returns the public one-time key.
    #[must_use]
    pub fn public_key(&self) -> HybridOneTimeKey {
        HybridOneTimeKey {
            kem: self.kem.public_key().clone(),
            key_id: self.key_id,
        }
    }

    /// Signs the one-time key with the device's signing key.
    ///
    /// This creates a signed OTK suitable for upload to the server.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The device's hybrid signing keypair.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if signing fails.
    pub fn sign(&self, signing_key: &HybridSigningKeypair) -> Result<SignedOneTimeKey> {
        let otk = self.public_key();
        let signature = signing_key.sign(&otk.to_bytes())?;

        Ok(SignedOneTimeKey {
            one_time_key: otk,
            signature,
        })
    }

    /// Decapsulates a hybrid encapsulation using this one-time key.
    ///
    /// After calling this, the one-time key should be discarded.
    ///
    /// # Arguments
    ///
    /// * `encapsulation` - The hybrid encapsulation from the initiator.
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

impl core::fmt::Debug for HybridOneTimeKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridOneTimeKeyPair")
            .field("key_id", &self.key_id)
            .field("kem", &"[redacted]")
            .finish()
    }
}

/// A hybrid one-time public key.
///
/// This is the public portion of a one-time keypair, suitable for
/// sending to initiators who want to establish a session.
#[derive(Clone)]
pub struct HybridOneTimeKey {
    /// The underlying hybrid KEM public key
    pub kem: HybridKemPublicKey,
    /// Unique identifier for this OTK
    key_id: [u8; 8],
}

impl HybridOneTimeKey {
    /// Returns the unique key identifier.
    #[must_use]
    pub fn key_id(&self) -> &[u8; 8] {
        &self.key_id
    }

    /// Serialises the one-time key to bytes.
    ///
    /// Format: key_id (8 bytes) || KEM public key (1,214 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8 + crate::kem::PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; 8 + crate::kem::PUBLIC_KEY_SIZE];
        bytes[..8].copy_from_slice(&self.key_id);
        bytes[8..].copy_from_slice(&self.kem.to_bytes());
        bytes
    }

    /// Deserialises a one-time key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use trelis_error::CryptoError;

        const SIZE: usize = 8 + crate::kem::PUBLIC_KEY_SIZE;
        if bytes.len() != SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[..8]);

        let kem = HybridKemPublicKey::from_bytes(&bytes[8..])?;

        Ok(Self { kem, key_id })
    }

    /// Encapsulates to this one-time key.
    ///
    /// # Returns
    ///
    /// A tuple of (shared_secret, encapsulation).
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if random number generation fails.
    pub fn encapsulate(&self) -> Result<(HybridSharedSecret, HybridEncapsulation)> {
        self.kem.encapsulate()
    }
}

impl PartialEq for HybridOneTimeKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id && self.kem == other.kem
    }
}

impl Eq for HybridOneTimeKey {}

impl core::fmt::Debug for HybridOneTimeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridOneTimeKey")
            .field("key_id", &self.key_id)
            .field("kem", &self.kem)
            .finish()
    }
}

/// A signed one-time key ready for upload.
///
/// Contains the one-time public key and a signature from the device's
/// identity signing key, proving ownership.
#[derive(Clone)]
pub struct SignedOneTimeKey {
    /// The one-time public key
    pub one_time_key: HybridOneTimeKey,
    /// Signature from the device's signing key
    pub signature: HybridSignature,
}

impl SignedOneTimeKey {
    /// Verifies the signature on the one-time key.
    ///
    /// # Arguments
    ///
    /// * `signing_public_key` - The device's hybrid signing public key.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(
        &self,
        signing_public_key: &crate::signature::HybridSigningPublicKey,
    ) -> Result<()> {
        signing_public_key.verify(&self.one_time_key.to_bytes(), &self.signature)
    }
}

impl core::fmt::Debug for SignedOneTimeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedOneTimeKey")
            .field("one_time_key", &self.one_time_key)
            .field("signature", &"[3423 bytes]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_otk_generation() {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        assert_eq!(otk.key_id().len(), 8);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_otk_public_key() {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        let public = otk.public_key();

        assert_eq!(public.key_id(), otk.key_id());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_otk_encapsulate_decapsulate() {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        let public = otk.public_key();

        let (ss_sender, encapsulation) = public.encapsulate().unwrap();
        let ss_recipient = otk.decapsulate(&encapsulation).unwrap();

        assert_eq!(ss_sender.as_bytes(), ss_recipient.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_otk_serialisation() {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        let public = otk.public_key();

        let bytes = public.to_bytes();
        let recovered = HybridOneTimeKey::from_bytes(&bytes).unwrap();

        assert_eq!(public, recovered);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_signed_otk() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let otk = HybridOneTimeKeyPair::generate().unwrap();

        let signed = otk.sign(&signing_key).unwrap();
        assert!(signed.verify(signing_key.public_key()).is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_signed_otk_wrong_key_fails() {
        let signing_key1 = HybridSigningKeypair::generate().unwrap();
        let signing_key2 = HybridSigningKeypair::generate().unwrap();
        let otk = HybridOneTimeKeyPair::generate().unwrap();

        let signed = otk.sign(&signing_key1).unwrap();
        assert!(signed.verify(signing_key2.public_key()).is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_unique_key_ids() {
        let otk1 = HybridOneTimeKeyPair::generate().unwrap();
        let otk2 = HybridOneTimeKeyPair::generate().unwrap();

        // Key IDs should be different (with overwhelming probability)
        assert_ne!(otk1.key_id(), otk2.key_id());
    }
}
