//! Hybrid pre-key bundle for X3DH-PQ session establishment.
//!
//! A pre-key bundle contains the public keys needed for an initiator to
//! establish an encrypted session with a recipient without requiring
//! real-time interaction.
//!
//! # Key Sizes
//!
//! - identity_signing: 2,009 bytes
//! - identity_kem: 1,214 bytes
//! - one_time_key: 1,222 bytes (8B key_id + 1,214B KEM)
//! - Total: 4,445 bytes
//!
//! # Usage
//!
//! 1. Recipient publishes pre-key bundles to the server
//! 2. Initiator fetches a bundle and uses it for X3DH-PQ
//! 3. The one-time key is consumed (removed from server)

use crate::identity::HybridIdentityPublicKey;
use crate::kem::HybridKemPublicKey;
use crate::one_time_key::HybridOneTimeKey;
use crate::signature::HybridSigningPublicKey;
use trelis_error::{CryptoError, Result};

/// Size of the pre-key bundle without the one-time key.
pub const IDENTITY_SIZE: usize = crate::identity::PUBLIC_KEY_SIZE;

/// Size of the one-time key portion.
pub const OTK_SIZE: usize = 8 + crate::kem::PUBLIC_KEY_SIZE;

/// Total size of the pre-key bundle.
pub const BUNDLE_SIZE: usize = IDENTITY_SIZE + OTK_SIZE;

/// Hybrid pre-key bundle for session establishment.
///
/// Contains all the public keys needed for an initiator to establish
/// a session with the bundle owner using X3DH-PQ.
#[derive(Clone)]
pub struct HybridPreKeyBundle {
    /// The recipient's identity signing public key (for signature verification)
    pub identity_signing: HybridSigningPublicKey,
    /// The recipient's identity KEM public key
    pub identity_kem: HybridKemPublicKey,
    /// A one-time key for this session
    pub one_time_key: HybridOneTimeKey,
}

impl HybridPreKeyBundle {
    /// Creates a pre-key bundle from an identity public key and one-time key.
    ///
    /// # Arguments
    ///
    /// * `identity` - The recipient's identity public key.
    /// * `one_time_key` - A one-time key for session establishment.
    #[must_use]
    pub fn new(identity: &HybridIdentityPublicKey, one_time_key: HybridOneTimeKey) -> Self {
        Self {
            identity_signing: identity.signing.clone(),
            identity_kem: identity.kem.clone(),
            one_time_key,
        }
    }

    /// Serialises the pre-key bundle to bytes.
    ///
    /// Format: identity_signing (2,009B) || identity_kem (1,214B) || one_time_key (1,222B)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BUNDLE_SIZE] {
        let mut bytes = [0u8; BUNDLE_SIZE];

        let signing_bytes = self.identity_signing.to_bytes();
        let kem_bytes = self.identity_kem.to_bytes();
        let otk_bytes = self.one_time_key.to_bytes();

        let mut offset = 0;
        bytes[offset..offset + signing_bytes.len()].copy_from_slice(&signing_bytes);
        offset += signing_bytes.len();

        bytes[offset..offset + kem_bytes.len()].copy_from_slice(&kem_bytes);
        offset += kem_bytes.len();

        bytes[offset..offset + otk_bytes.len()].copy_from_slice(&otk_bytes);

        bytes
    }

    /// Deserialises a pre-key bundle from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BUNDLE_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: BUNDLE_SIZE,
                actual: bytes.len(),
            });
        }

        let signing_size = crate::signature::PUBLIC_KEY_SIZE;
        let kem_size = crate::kem::PUBLIC_KEY_SIZE;

        let identity_signing = HybridSigningPublicKey::from_bytes(&bytes[..signing_size])?;
        let identity_kem =
            HybridKemPublicKey::from_bytes(&bytes[signing_size..signing_size + kem_size])?;
        let one_time_key = HybridOneTimeKey::from_bytes(&bytes[signing_size + kem_size..])?;

        Ok(Self {
            identity_signing,
            identity_kem,
            one_time_key,
        })
    }

    /// Returns the identity signing public key.
    #[must_use]
    pub fn identity_signing(&self) -> &HybridSigningPublicKey {
        &self.identity_signing
    }

    /// Returns the identity KEM public key.
    #[must_use]
    pub fn identity_kem(&self) -> &HybridKemPublicKey {
        &self.identity_kem
    }

    /// Returns the one-time key.
    #[must_use]
    pub fn one_time_key(&self) -> &HybridOneTimeKey {
        &self.one_time_key
    }
}

impl PartialEq for HybridPreKeyBundle {
    fn eq(&self, other: &Self) -> bool {
        self.identity_signing == other.identity_signing
            && self.identity_kem == other.identity_kem
            && self.one_time_key == other.one_time_key
    }
}

impl Eq for HybridPreKeyBundle {}

impl core::fmt::Debug for HybridPreKeyBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridPreKeyBundle")
            .field("identity_signing", &self.identity_signing)
            .field("identity_kem", &self.identity_kem)
            .field("one_time_key", &self.one_time_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::HybridIdentityKeypair;
    use crate::one_time_key::HybridOneTimeKeyPair;

    #[test]
    fn test_bundle_size() {
        // identity_signing (2009) + identity_kem (1214) + otk (8 + 1214)
        assert_eq!(BUNDLE_SIZE, 2009 + 1214 + 8 + 1214);
        assert_eq!(BUNDLE_SIZE, 4445);
    }

    #[test]
    fn test_bundle_creation() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let otk = HybridOneTimeKeyPair::generate().unwrap();

        let bundle = HybridPreKeyBundle::new(identity.public_key(), otk.public_key());

        assert_eq!(bundle.identity_signing(), &identity.public_key().signing);
        assert_eq!(bundle.identity_kem(), &identity.public_key().kem);
        assert_eq!(bundle.one_time_key(), &otk.public_key());
    }

    #[test]
    fn test_bundle_serialisation() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let otk = HybridOneTimeKeyPair::generate().unwrap();

        let bundle = HybridPreKeyBundle::new(identity.public_key(), otk.public_key());

        let bytes = bundle.to_bytes();
        assert_eq!(bytes.len(), BUNDLE_SIZE);

        let recovered = HybridPreKeyBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle, recovered);
    }

    #[test]
    fn test_bundle_encapsulation() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let otk_pair = HybridOneTimeKeyPair::generate().unwrap();

        let bundle = HybridPreKeyBundle::new(identity.public_key(), otk_pair.public_key());

        // Initiator encapsulates to the one-time key
        let (ss_sender, encapsulation) = bundle.one_time_key().encapsulate().unwrap();

        // Recipient decapsulates
        let ss_recipient = otk_pair.decapsulate(&encapsulation).unwrap();

        assert_eq!(ss_sender.as_bytes(), ss_recipient.as_bytes());
    }
}
