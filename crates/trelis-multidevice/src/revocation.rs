//! Device revocation for removing compromised or lost devices.
//!
//! Revocation uses the normal ratchet mechanism - revoked devices are
//! simply excluded from future ratchet operations.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

use crate::DeviceId;

/// Context string for device revocation signatures.
const REVOCATION_CONTEXT: &str = "trelis-v1-device-revocation";

/// Reason for device revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    /// User explicitly revoked the device.
    UserInitiated = 0,

    /// Device was reported lost.
    DeviceLost = 1,

    /// Device is believed to be compromised.
    DeviceCompromised = 2,

    /// Device was replaced with a new one.
    DeviceReplaced = 3,
}

impl RevocationReason {
    /// Converts from a byte representation.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::UserInitiated),
            1 => Some(Self::DeviceLost),
            2 => Some(Self::DeviceCompromised),
            3 => Some(Self::DeviceReplaced),
            _ => None,
        }
    }

    /// Converts to a byte representation.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns a human-readable description of the reason.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::UserInitiated => "User initiated revocation",
            Self::DeviceLost => "Device reported lost",
            Self::DeviceCompromised => "Device believed compromised",
            Self::DeviceReplaced => "Device replaced",
        }
    }
}

/// Device revocation certificate.
///
/// This certificate is signed by the user's identity key and published
/// to the server to indicate a device should be excluded from future
/// ratchet operations.
///
/// # Important Limitations
///
/// Revocation prevents **future** access but cannot:
/// - Delete messages already fetched by the device
/// - Invalidate keys already shared with the device
/// - Remotely wipe the device's local storage
#[derive(Clone)]
pub struct DeviceRevocation {
    /// The device being revoked.
    pub device_id: DeviceId,

    /// Unix timestamp when revocation was issued.
    pub revoked_at: u64,

    /// Reason for the revocation.
    pub reason: RevocationReason,

    /// Signature from the user's identity key.
    pub signature: HybridSignature,
}

impl DeviceRevocation {
    /// Size of the fixed portion (before signature).
    const FIXED_SIZE: usize = 16 + 8 + 1; // device_id + timestamp + reason

    /// Creates a new device revocation certificate.
    ///
    /// # Arguments
    ///
    /// * `device_id` - The device to revoke
    /// * `reason` - Reason for revocation
    /// * `revoked_at` - Unix timestamp
    /// * `signing_key` - The user's identity signing key
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if signing fails.
    pub fn new(
        device_id: DeviceId,
        reason: RevocationReason,
        revoked_at: u64,
        signing_key: &HybridSigningKeypair,
    ) -> Result<Self> {
        let sig_data = Self::signing_data(&device_id, revoked_at, reason);
        let signature = signing_key.sign(&sig_data)?;

        Ok(Self {
            device_id,
            revoked_at,
            reason,
            signature,
        })
    }

    /// Verifies the revocation certificate signature.
    ///
    /// # Arguments
    ///
    /// * `user_key` - The user's identity signing public key
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if verification fails.
    pub fn verify(&self, user_key: &HybridSigningPublicKey) -> Result<()> {
        let sig_data = Self::signing_data(&self.device_id, self.revoked_at, self.reason);
        if user_key.verify(&sig_data, &self.signature) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Creates the data to be signed.
    #[cfg(feature = "alloc")]
    fn signing_data(device_id: &DeviceId, revoked_at: u64, reason: RevocationReason) -> Vec<u8> {
        let mut data = Vec::with_capacity(Self::FIXED_SIZE + REVOCATION_CONTEXT.len());

        data.extend_from_slice(REVOCATION_CONTEXT.as_bytes());
        data.extend_from_slice(device_id);
        data.extend_from_slice(&revoked_at.to_le_bytes());
        data.push(reason.to_byte());

        data
    }

    /// Serialises the revocation certificate to bytes.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let total_size = Self::FIXED_SIZE + sig_bytes.len();

        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.revoked_at.to_le_bytes());
        bytes.push(self.reason.to_byte());
        bytes.extend_from_slice(&sig_bytes);

        bytes
    }

    /// Deserialises a revocation certificate from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::FIXED_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Device ID
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;

        // Revoked at
        let revoked_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Reason
        let reason =
            RevocationReason::from_byte(bytes[offset]).ok_or(CryptoError::MalformedMessage)?;
        offset += 1;

        // Signature
        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            device_id,
            revoked_at,
            reason,
            signature,
        })
    }
}

impl core::fmt::Debug for DeviceRevocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceRevocation")
            .field("device_id", &"[16 bytes]")
            .field("revoked_at", &self.revoked_at)
            .field("reason", &self.reason)
            .field("signature", &"[HybridSignature]")
            .finish()
    }
}

/// Event indicating that a device revocation should trigger a CoCoA rekey.
///
/// When a device is revoked, all active CoCoA sessions involving that device
/// must be updated to exclude it from future epochs. This struct provides
/// the information needed for that update.
///
/// # Workflow
///
/// 1. User creates `DeviceRevocation` certificate
/// 2. Certificate is published and verified by other devices
/// 3. Each device extracts `RevocationRekeyEvent` from the certificate
/// 4. Each active CoCoA session calls `remove_member` with the revoked device's position
/// 5. Epoch advances, excluding the revoked device from future keys
///
/// # Example
///
/// ```ignore
/// use trelis_multidevice::{DeviceRevocation, RevocationRekeyEvent};
///
/// // Process a verified revocation certificate
/// let rekey_event = RevocationRekeyEvent::from_revocation(&revocation);
///
/// // For each active session involving this device
/// for session in active_sessions_with_device(&rekey_event.device_id) {
///     let position = session.find_device_position(&rekey_event.device_id)?;
///     trelis_cocoa::operations::remove_member(session, rekey_event.device_id, position)?;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RevocationRekeyEvent {
    /// Device ID that was revoked.
    pub device_id: crate::DeviceId,

    /// Reason for revocation (affects priority of rekey).
    pub reason: RevocationReason,

    /// When the revocation occurred.
    pub revoked_at: u64,
}

impl RevocationRekeyEvent {
    /// Creates a rekey event from a verified revocation certificate.
    ///
    /// # Note
    ///
    /// The caller MUST verify the revocation certificate before calling this.
    /// This function does not verify signatures.
    #[must_use]
    pub fn from_revocation(revocation: &DeviceRevocation) -> Self {
        Self {
            device_id: revocation.device_id,
            reason: revocation.reason,
            revoked_at: revocation.revoked_at,
        }
    }

    /// Returns true if this revocation requires immediate rekey.
    ///
    /// Compromised devices require immediate rekey to limit exposure.
    /// Other reasons can be batched with normal updates.
    #[must_use]
    pub fn requires_immediate_rekey(&self) -> bool {
        matches!(self.reason, RevocationReason::DeviceCompromised)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_roundtrip() {
        for reason in [
            RevocationReason::UserInitiated,
            RevocationReason::DeviceLost,
            RevocationReason::DeviceCompromised,
            RevocationReason::DeviceReplaced,
        ] {
            let byte = reason.to_byte();
            let recovered = RevocationReason::from_byte(byte).unwrap();
            assert_eq!(recovered, reason);
        }
    }

    #[test]
    fn test_revocation_reason_invalid_byte() {
        assert!(RevocationReason::from_byte(99).is_none());
    }

    #[test]
    fn test_revocation_reason_descriptions() {
        assert!(!RevocationReason::UserInitiated.description().is_empty());
        assert!(!RevocationReason::DeviceLost.description().is_empty());
        assert!(!RevocationReason::DeviceCompromised.description().is_empty());
        assert!(!RevocationReason::DeviceReplaced.description().is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_create() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceLost,
            5000,
            &signing_key,
        )
        .unwrap();

        assert_eq!(revocation.device_id, [0x42u8; 16]);
        assert_eq!(revocation.revoked_at, 5000);
        assert_eq!(revocation.reason, RevocationReason::DeviceLost);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_verify() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::UserInitiated,
            5000,
            &signing_key,
        )
        .unwrap();

        // Verify with correct key
        assert!(revocation.verify(&signing_key.public_key()).is_ok());

        // Verify with wrong key should fail
        let other_key = HybridSigningKeypair::generate().unwrap();
        assert!(revocation.verify(&other_key.public_key()).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_serialisation() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceCompromised,
            5000,
            &signing_key,
        )
        .unwrap();

        let bytes = revocation.to_bytes();
        let recovered = DeviceRevocation::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.device_id, revocation.device_id);
        assert_eq!(recovered.revoked_at, revocation.revoked_at);
        assert_eq!(recovered.reason, revocation.reason);

        // Verify signature still valid
        assert!(recovered.verify(&signing_key.public_key()).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_different_reasons() {
        let signing_key = HybridSigningKeypair::generate().unwrap();

        for reason in [
            RevocationReason::UserInitiated,
            RevocationReason::DeviceLost,
            RevocationReason::DeviceCompromised,
            RevocationReason::DeviceReplaced,
        ] {
            let revocation =
                DeviceRevocation::new([0x42u8; 16], reason, 5000, &signing_key).unwrap();

            let bytes = revocation.to_bytes();
            let recovered = DeviceRevocation::from_bytes(&bytes).unwrap();

            assert_eq!(recovered.reason, reason);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_revocation_rekey_event_from_revocation() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let device_id = [0x42u8; 16];

        let revocation = DeviceRevocation::new(
            device_id,
            RevocationReason::DeviceCompromised,
            5000,
            &signing_key,
        )
        .unwrap();

        let rekey_event = RevocationRekeyEvent::from_revocation(&revocation);

        assert_eq!(rekey_event.device_id, device_id);
        assert_eq!(rekey_event.reason, RevocationReason::DeviceCompromised);
        assert_eq!(rekey_event.revoked_at, 5000);
    }

    #[test]
    fn test_revocation_rekey_event_requires_immediate_rekey() {
        // Only DeviceCompromised requires immediate rekey
        let signing_key = HybridSigningKeypair::generate().unwrap();

        let compromised_revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceCompromised,
            5000,
            &signing_key,
        )
        .unwrap();
        let compromised_event = RevocationRekeyEvent::from_revocation(&compromised_revocation);
        assert!(compromised_event.requires_immediate_rekey());

        let lost_revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceLost,
            5000,
            &signing_key,
        )
        .unwrap();
        let lost_event = RevocationRekeyEvent::from_revocation(&lost_revocation);
        assert!(!lost_event.requires_immediate_rekey());

        let user_revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::UserInitiated,
            5000,
            &signing_key,
        )
        .unwrap();
        let user_event = RevocationRekeyEvent::from_revocation(&user_revocation);
        assert!(!user_event.requires_immediate_rekey());

        let replaced_revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceReplaced,
            5000,
            &signing_key,
        )
        .unwrap();
        let replaced_event = RevocationRekeyEvent::from_revocation(&replaced_revocation);
        assert!(!replaced_event.requires_immediate_rekey());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_from_bytes_too_short() {
        // Less than FIXED_SIZE (25 bytes)
        let bytes = [0u8; 10];
        assert!(DeviceRevocation::from_bytes(&bytes).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_revocation_from_bytes_invalid_reason() {
        // Valid length but invalid reason byte
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::UserInitiated,
            5000,
            &signing_key,
        )
        .unwrap();

        let mut bytes = revocation.to_bytes();
        // Corrupt the reason byte (at offset 24: 16 device_id + 8 timestamp)
        bytes[24] = 0xFF; // Invalid reason

        assert!(DeviceRevocation::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_device_revocation_debug() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceLost,
            5000,
            &signing_key,
        )
        .unwrap();

        let debug_str = format!("{:?}", revocation);
        assert!(debug_str.contains("DeviceRevocation"));
        assert!(debug_str.contains("revoked_at"));
        assert!(debug_str.contains("5000"));
        assert!(debug_str.contains("DeviceLost"));
    }

    #[test]
    fn test_revocation_rekey_event_debug() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let revocation = DeviceRevocation::new(
            [0x42u8; 16],
            RevocationReason::DeviceLost,
            5000,
            &signing_key,
        )
        .unwrap();

        let event = RevocationRekeyEvent::from_revocation(&revocation);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("RevocationRekeyEvent"));
    }
}
