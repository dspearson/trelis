//! Device approval certificates for new device onboarding.
//!
//! When a user adds a new device, an existing device signs an approval
//! certificate to authorise the new device. This provides:
//!
//! - **Audit trail**: Who approved which device and when
//! - **Verification**: New device can verify it was approved by a legitimate device
//! - **Non-repudiation**: Approving device cannot deny the approval
//!
//! # Security
//!
//! The approval certificate binds:
//! - The new device's public key fingerprint
//! - The approving device's identity
//! - A timestamp (for expiry and ordering)
//!
//! # Example
//!
//! ```ignore
//! use trelis_multidevice::DeviceApprovalCertificate;
//! use trelis_hybrid::HybridSigningKeypair;
//!
//! // Existing device approves new device
//! let existing_device = HybridSigningKeypair::generate().unwrap();
//! let new_device_fingerprint = [0u8; 32]; // Hash of new device's public key
//!
//! let cert = DeviceApprovalCertificate::new(
//!     [0x42u8; 16], // existing device ID
//!     new_device_fingerprint,
//!     1234567890,
//!     &existing_device,
//! ).unwrap();
//!
//! // New device verifies the approval
//! assert!(cert.verify(&existing_device.public_key()).is_ok());
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use trelis_error::{CryptoError, Result};
use trelis_hybrid::HybridSignature;
#[cfg(feature = "alloc")]
use trelis_hybrid::{HybridSigningKeypair, HybridSigningPublicKey};

use crate::DeviceId;

/// Context string for device approval signatures.
#[cfg(feature = "alloc")]
const APPROVAL_CONTEXT: &str = "trelis-v1-device-approval";

/// Size of a device fingerprint (BLAKE3 hash of public key).
pub const FINGERPRINT_SIZE: usize = 32;

/// A signed certificate approving a new device.
///
/// Created by an existing device to authorise a new device to join
/// the user's device set. The certificate is stored for audit purposes
/// and can be verified by any party with the approving device's public key.
#[derive(Clone)]
pub struct DeviceApprovalCertificate {
    /// ID of the device that created this approval.
    pub approving_device_id: DeviceId,

    /// Fingerprint (BLAKE3 hash) of the new device's public key.
    pub new_device_fingerprint: [u8; FINGERPRINT_SIZE],

    /// Unix timestamp when approval was granted.
    pub approved_at: u64,

    /// Signature from the approving device.
    pub signature: HybridSignature,
}

impl DeviceApprovalCertificate {
    /// Creates a new device approval certificate.
    ///
    /// The certificate is signed by the approving device's signing key.
    ///
    /// # Arguments
    ///
    /// * `approving_device_id` - ID of the device granting approval
    /// * `new_device_fingerprint` - BLAKE3 hash of the new device's public key
    /// * `approved_at` - Unix timestamp for the approval
    /// * `signing_key` - Approving device's signing keypair
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if signing fails.
    #[cfg(feature = "alloc")]
    pub fn new(
        approving_device_id: DeviceId,
        new_device_fingerprint: [u8; FINGERPRINT_SIZE],
        approved_at: u64,
        signing_key: &HybridSigningKeypair,
    ) -> Result<Self> {
        let sig_data =
            Self::signing_data(&approving_device_id, &new_device_fingerprint, approved_at);

        let signature = signing_key.sign(&sig_data)?;

        Ok(Self {
            approving_device_id,
            new_device_fingerprint,
            approved_at,
            signature,
        })
    }

    /// Verifies the approval certificate signature.
    ///
    /// # Arguments
    ///
    /// * `approving_device_key` - Public key of the approving device
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    #[cfg(feature = "alloc")]
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self, approving_device_key: &HybridSigningPublicKey) -> Result<()> {
        let sig_data = Self::signing_data(
            &self.approving_device_id,
            &self.new_device_fingerprint,
            self.approved_at,
        );

        approving_device_key.verify(&sig_data, &self.signature)
    }

    /// Creates the data to be signed.
    ///
    /// Format: context || approving_device_id || new_device_fingerprint || approved_at
    #[cfg(feature = "alloc")]
    fn signing_data(
        approving_device_id: &DeviceId,
        new_device_fingerprint: &[u8; FINGERPRINT_SIZE],
        approved_at: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(APPROVAL_CONTEXT.len() + 16 + 32 + 8);

        data.extend_from_slice(APPROVAL_CONTEXT.as_bytes());
        data.extend_from_slice(approving_device_id);
        data.extend_from_slice(new_device_fingerprint);
        data.extend_from_slice(&approved_at.to_le_bytes());

        data
    }

    /// Serialises the certificate to bytes.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let total_size = 16 + 32 + 8 + sig_bytes.len();

        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.approving_device_id);
        bytes.extend_from_slice(&self.new_device_fingerprint);
        bytes.extend_from_slice(&self.approved_at.to_le_bytes());
        bytes.extend_from_slice(&sig_bytes);

        bytes
    }

    /// Deserialises a certificate from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Minimum size: device_id (16) + fingerprint (32) + approved_at (8) + signature
        if bytes.len() < 56 {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Approving device ID
        let mut approving_device_id = [0u8; 16];
        approving_device_id.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;

        // New device fingerprint
        let mut new_device_fingerprint = [0u8; 32];
        new_device_fingerprint.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Approved at
        let approved_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Signature
        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            approving_device_id,
            new_device_fingerprint,
            approved_at,
            signature,
        })
    }
}

impl core::fmt::Debug for DeviceApprovalCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceApprovalCertificate")
            .field(
                "approving_device_id",
                &hex::encode(self.approving_device_id),
            )
            .field(
                "new_device_fingerprint",
                &hex::encode(self.new_device_fingerprint),
            )
            .field("approved_at", &self.approved_at)
            .field("signature", &"[3423 bytes]")
            .finish()
    }
}

/// Calculates the fingerprint of a device's public key.
///
/// Uses BLAKE3 hash of the serialised hybrid signing public key.
#[cfg(feature = "alloc")]
#[must_use]
pub fn device_fingerprint(public_key: &HybridSigningPublicKey) -> [u8; FINGERPRINT_SIZE] {
    let pk_bytes = public_key.to_bytes();
    blake3::hash(&pk_bytes).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_create() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let cert =
            DeviceApprovalCertificate::new([0x42u8; 16], [0xAAu8; 32], 1000, &signing_key).unwrap();

        assert_eq!(cert.approving_device_id, [0x42u8; 16]);
        assert_eq!(cert.new_device_fingerprint, [0xAAu8; 32]);
        assert_eq!(cert.approved_at, 1000);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_verify() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let cert =
            DeviceApprovalCertificate::new([0x42u8; 16], [0xAAu8; 32], 1000, &signing_key).unwrap();

        // Verify with correct key
        assert!(cert.verify(&signing_key.public_key()).is_ok());

        // Verify with wrong key should fail
        let other_key = HybridSigningKeypair::generate().unwrap();
        assert!(cert.verify(&other_key.public_key()).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_serialisation() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let cert =
            DeviceApprovalCertificate::new([0x42u8; 16], [0xAAu8; 32], 5000, &signing_key).unwrap();

        let bytes = cert.to_bytes();
        let recovered = DeviceApprovalCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.approving_device_id, cert.approving_device_id);
        assert_eq!(
            recovered.new_device_fingerprint,
            cert.new_device_fingerprint
        );
        assert_eq!(recovered.approved_at, cert.approved_at);

        // Signature should still verify
        assert!(recovered.verify(&signing_key.public_key()).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_fingerprint() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let fp1 = device_fingerprint(&keypair.public_key());
        let fp2 = device_fingerprint(&keypair.public_key());

        // Same key should produce same fingerprint
        assert_eq!(fp1, fp2);

        // Different key should produce different fingerprint
        let other = HybridSigningKeypair::generate().unwrap();
        let fp3 = device_fingerprint(&other.public_key());
        assert_ne!(fp1, fp3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_from_bytes_too_short() {
        // Less than minimum size (56 bytes)
        let bytes = [0u8; 20];
        assert!(DeviceApprovalCertificate::from_bytes(&bytes).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_debug() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let cert =
            DeviceApprovalCertificate::new([0x42u8; 16], [0xAAu8; 32], 1000, &signing_key).unwrap();

        let debug_str = format!("{:?}", cert);
        assert!(debug_str.contains("DeviceApprovalCertificate"));
        assert!(debug_str.contains("approved_at"));
        assert!(debug_str.contains("1000"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_fingerprint_size() {
        assert_eq!(FINGERPRINT_SIZE, 32);
    }
}
