//! Pre-key bundle types for X3DH-PQ.
//!
//! A pre-key bundle contains all the public keys and metadata needed
//! to establish a session with a recipient. The bundle is signed by
//! the owner's identity key to prevent server substitution attacks.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{
    HybridKemPublicKey, HybridSignature, HybridSigningKeypair, HybridSigningPublicKey,
};
use trelis_wire::constants::{
    HYBRID_KEM_PK_SIZE, HYBRID_SIG_SIZE, HYBRID_SIGNING_PK_SIZE, KEY_ID_SIZE,
};

/// Domain separation prefix for bundle signing.
pub const BUNDLE_DOMAIN: &[u8] = b"trelis-prekey-bundle-v1";

/// Size of the pre-key bundle (unsigned).
pub const PREKEY_BUNDLE_SIZE: usize = HYBRID_SIGNING_PK_SIZE  // Identity signing: 2,009 B
    + HYBRID_KEM_PK_SIZE      // Identity KEM: 1,214 B
    + HYBRID_KEM_PK_SIZE      // One-time key: 1,214 B
    + KEY_ID_SIZE             // OTK key ID: 8 B
    + 8                        // Timestamp: 8 B
    + 8;                       // Expiration: 8 B

/// Size of the signed pre-key bundle.
pub const SIGNED_BUNDLE_SIZE: usize = PREKEY_BUNDLE_SIZE + HYBRID_SIG_SIZE;

/// Pre-key bundle without signature.
///
/// This is the data that gets signed. It includes:
/// - Identity signing public key (for verification)
/// - Identity KEM public key (for DH2)
/// - One-time KEM key (for DH1, DH3, and PQ encapsulation)
/// - OTK key ID
/// - Timestamp and expiration
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Owner's identity signing public key.
    pub identity_signing: HybridSigningPublicKey,
    /// Owner's identity KEM public key.
    pub identity_kem: HybridKemPublicKey,
    /// One-time KEM key (consumed after one use).
    pub one_time_key: HybridKemPublicKey,
    /// Key ID for the one-time key.
    pub otk_key_id: u64,
    /// Unix timestamp when bundle was created.
    pub timestamp: u64,
    /// Unix timestamp when bundle expires.
    pub expiration: u64,
}

impl PreKeyBundle {
    /// Creates a new pre-key bundle.
    #[must_use]
    pub fn new(
        identity_signing: HybridSigningPublicKey,
        identity_kem: HybridKemPublicKey,
        one_time_key: HybridKemPublicKey,
        otk_key_id: u64,
        timestamp: u64,
        expiration: u64,
    ) -> Self {
        Self {
            identity_signing,
            identity_kem,
            one_time_key,
            otk_key_id,
            timestamp,
            expiration,
        }
    }

    /// Returns the data that should be signed.
    ///
    /// This includes all fields with domain separation prefix.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(BUNDLE_DOMAIN.len() + PREKEY_BUNDLE_SIZE);

        // Domain separation
        data.extend_from_slice(BUNDLE_DOMAIN);

        // All public keys
        data.extend_from_slice(&self.identity_signing.to_bytes());
        data.extend_from_slice(&self.identity_kem.to_bytes());
        data.extend_from_slice(&self.one_time_key.to_bytes());

        // Metadata (REQUIRED for replay resistance)
        data.extend_from_slice(&self.otk_key_id.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.expiration.to_le_bytes());

        data
    }

    /// Signs the bundle with the identity signing keypair.
    ///
    /// Returns a signed bundle containing the signature.
    #[cfg(feature = "alloc")]
    pub fn sign(self, keypair: &HybridSigningKeypair) -> Result<SignedPreKeyBundle> {
        let data = self.signing_data();
        let signature = keypair.sign(&data)?;
        Ok(SignedPreKeyBundle {
            bundle: self,
            signature,
        })
    }
}

/// Signed pre-key bundle ready for publication.
///
/// The signature authenticates all bundle contents, preventing
/// a malicious server from substituting bundles.
#[derive(Clone)]
pub struct SignedPreKeyBundle {
    /// The unsigned bundle data.
    pub bundle: PreKeyBundle,
    /// Hybrid signature over the bundle.
    pub signature: HybridSignature,
}

impl SignedPreKeyBundle {
    /// Returns the signing data (for verification).
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn signing_data(&self) -> Vec<u8> {
        self.bundle.signing_data()
    }

    /// Verifies the bundle signature.
    ///
    /// This MUST be called before using the bundle for session establishment.
    ///
    /// # Errors
    ///
    /// Returns `HybridSignatureVerificationFailed` if the signature is invalid.
    #[cfg(feature = "alloc")]
    pub fn verify(&self) -> Result<()> {
        let data = self.signing_data();
        if self.bundle.identity_signing.verify(&data, &self.signature) {
            Ok(())
        } else {
            Err(CryptoError::BundleSignatureInvalid)
        }
    }

    /// Validates bundle timestamps against the current time.
    ///
    /// # Arguments
    ///
    /// * `now` - Current Unix timestamp in seconds
    ///
    /// # Errors
    ///
    /// Returns `BundleTimestampInFuture` if the bundle was created in the future.
    /// Returns `BundleExpired` if the bundle has expired.
    pub fn validate_timestamps(&self, now: u64) -> Result<()> {
        if self.bundle.timestamp > now {
            return Err(CryptoError::BundleTimestampInFuture);
        }
        if self.bundle.expiration < now {
            return Err(CryptoError::BundleExpired);
        }
        Ok(())
    }

    /// Returns the identity signing public key.
    #[must_use]
    pub fn identity_signing(&self) -> &HybridSigningPublicKey {
        &self.bundle.identity_signing
    }

    /// Returns the identity KEM public key.
    #[must_use]
    pub fn identity_kem(&self) -> &HybridKemPublicKey {
        &self.bundle.identity_kem
    }

    /// Returns the one-time KEM public key.
    #[must_use]
    pub fn one_time_key(&self) -> &HybridKemPublicKey {
        &self.bundle.one_time_key
    }

    /// Returns the one-time key ID.
    #[must_use]
    pub fn otk_key_id(&self) -> u64 {
        self.bundle.otk_key_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::HybridKemKeypair;

    #[test]
    fn test_bundle_domain() {
        assert_eq!(BUNDLE_DOMAIN, b"trelis-prekey-bundle-v1");
    }

    #[test]
    fn test_bundle_size() {
        // identity_signing (2009) + identity_kem (1214) + otk (1214) + key_id (8) + timestamp (8) + expiration (8)
        assert_eq!(PREKEY_BUNDLE_SIZE, 2009 + 1214 + 1214 + 8 + 8 + 8);
        assert_eq!(PREKEY_BUNDLE_SIZE, 4461);
    }

    #[test]
    fn test_signed_bundle_size() {
        // bundle + signature (3423)
        assert_eq!(SIGNED_BUNDLE_SIZE, PREKEY_BUNDLE_SIZE + 3423);
        assert_eq!(SIGNED_BUNDLE_SIZE, 7884);
    }

    #[test]
    fn test_bundle_sign_verify() {
        let identity_signing = HybridSigningKeypair::generate().unwrap();
        let identity_kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            identity_signing.public_key().clone(),
            identity_kem.public_key().clone(),
            otk.public_key().clone(),
            12345,
            1000,
            2000,
        );

        let signed = bundle.sign(&identity_signing).expect("signing should succeed");
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_bundle_timestamp_validation() {
        let identity_signing = HybridSigningKeypair::generate().unwrap();
        let identity_kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        // Valid bundle
        let bundle = PreKeyBundle::new(
            identity_signing.public_key().clone(),
            identity_kem.public_key().clone(),
            otk.public_key().clone(),
            1,
            1000,
            2000,
        );
        let signed = bundle.sign(&identity_signing).unwrap();

        // Within validity period
        assert!(signed.validate_timestamps(1500).is_ok());

        // Too early (timestamp in future)
        assert!(matches!(
            signed.validate_timestamps(500),
            Err(CryptoError::BundleTimestampInFuture)
        ));

        // Expired
        assert!(matches!(
            signed.validate_timestamps(2500),
            Err(CryptoError::BundleExpired)
        ));
    }

    #[test]
    fn test_bundle_tamper_detection() {
        let identity_signing = HybridSigningKeypair::generate().unwrap();
        let identity_kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            identity_signing.public_key().clone(),
            identity_kem.public_key().clone(),
            otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        let mut signed = bundle.sign(&identity_signing).unwrap();

        // Tamper with the timestamp
        signed.bundle.timestamp = 999;

        // Verification should fail
        assert!(matches!(
            signed.verify(),
            Err(CryptoError::BundleSignatureInvalid)
        ));
    }
}
