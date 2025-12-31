//! Device key wrapping for multi-device key distribution.
//!
//! DeviceKeyWrap encapsulates secret key material to a specific device
//! using hybrid KEM (X448 + sntrup761), providing confidentiality and
//! recipient binding via AEAD with context-bound AAD.
//!
//! # Security Properties
//!
//! - **Confidentiality**: Hybrid KEM ensures only the recipient can decrypt
//! - **Recipient binding**: AAD includes recipient_key_id, preventing misrouting
//! - **Purpose binding**: AAD includes purpose enum, preventing type confusion
//! - **Context binding**: AAD includes thread_id, bundle_id, epoch
//! - **PQ security**: sntrup761 provides post-quantum protection
//!
//! # Warning
//!
//! DeviceKeyWrap does NOT provide sender authentication. Any party with
//! the recipient's public key can create a valid wrap. When sender
//! authentication is required (e.g., HistoryKeyShare), the wrapping
//! message MUST include a signature from the sender's signing key.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use rand_core::RngCore;
use trelis_error::{CryptoError, Result};
use trelis_hybrid::{
    HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey, HybridSharedSecret,
};
use trelis_primitives::aead::{self, AeadKey, NONCE_SIZE, Nonce, TAG_SIZE};
use trelis_primitives::random::OsRng;

use crate::ThreadId;

/// Context string for AEAD encryption in DeviceKeyWrap.
pub const WRAP_CONTEXT: &str = "trelis-bundle-wrap-v1";

/// Size of recipient key ID in bytes.
pub const KEY_ID_SIZE: usize = 8;

/// Size of X448 ephemeral public key.
pub const X448_EPHEMERAL_SIZE: usize = 56;

/// Size of sntrup761 ciphertext.
pub const SNTRUP_CT_SIZE: usize = 1039;

/// Size of encrypted payload (32-byte secret + 16-byte tag).
pub const ENCRYPTED_PAYLOAD_SIZE: usize = 32 + TAG_SIZE;

/// Total size of a DeviceKeyWrap.
/// 8 + 56 + 1039 + 24 + 48 = 1,175 bytes
pub const DEVICE_KEY_WRAP_SIZE: usize =
    KEY_ID_SIZE + X448_EPHEMERAL_SIZE + SNTRUP_CT_SIZE + NONCE_SIZE + ENCRYPTED_PAYLOAD_SIZE;

/// Purpose of the wrapped key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WrapPurpose {
    /// Bundle key for message encryption.
    BundleKey = 0x01,
    /// Session seed for ratchet initialisation.
    SessionSeed = 0x02,
    /// History key for history sync.
    HistoryKey = 0x03,
}

impl WrapPurpose {
    /// Converts from byte representation.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::BundleKey),
            0x02 => Some(Self::SessionSeed),
            0x03 => Some(Self::HistoryKey),
            _ => None,
        }
    }

    /// Converts to byte representation.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Context for wrapping - binds wrap to specific purpose and location.
#[derive(Clone)]
pub struct WrapContext {
    /// Recipient device key ID (8 bytes).
    pub recipient_key_id: [u8; KEY_ID_SIZE],
    /// Purpose of the wrapped key.
    pub purpose: WrapPurpose,
    /// Thread ID this wrap belongs to.
    pub thread_id: ThreadId,
    /// Bundle ID within the thread.
    pub bundle_id: [u8; 32],
    /// CoCoA epoch at time of wrap.
    pub epoch: u64,
}

impl WrapContext {
    /// Creates a new wrap context.
    #[must_use]
    pub fn new(
        recipient_key_id: [u8; KEY_ID_SIZE],
        purpose: WrapPurpose,
        thread_id: ThreadId,
        bundle_id: [u8; 32],
        epoch: u64,
    ) -> Self {
        Self {
            recipient_key_id,
            purpose,
            thread_id,
            bundle_id,
            epoch,
        }
    }

    /// Builds the canonical AAD from this context.
    ///
    /// Format: recipient_key_id || purpose || thread_id || bundle_id || epoch_le
    /// Size: 8 + 1 + 32 + 32 + 8 = 81 bytes
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(81);
        aad.extend_from_slice(&self.recipient_key_id);
        aad.push(self.purpose.to_byte());
        aad.extend_from_slice(&self.thread_id);
        aad.extend_from_slice(&self.bundle_id);
        aad.extend_from_slice(&self.epoch.to_le_bytes());
        aad
    }
}

/// Wrapped key material for a specific device.
///
/// Uses hybrid KEM (X448 + sntrup761) to encapsulate a shared secret,
/// then uses XChaCha20-Poly1305 to encrypt the actual secret.
#[derive(Clone)]
pub struct DeviceKeyWrap {
    /// Recipient device's KEM public key ID (for identification).
    pub recipient_key_id: [u8; KEY_ID_SIZE],

    /// X448 ephemeral public key.
    pub x448_ephemeral: [u8; X448_EPHEMERAL_SIZE],

    /// sntrup761 ciphertext.
    pub sntrup_ciphertext: [u8; SNTRUP_CT_SIZE],

    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; NONCE_SIZE],

    /// Encrypted payload: 32-byte secret + 16-byte auth tag.
    pub encrypted_payload: [u8; ENCRYPTED_PAYLOAD_SIZE],
}

impl DeviceKeyWrap {
    /// Wraps a 32-byte secret to a recipient device's public key.
    ///
    /// # Arguments
    ///
    /// * `secret` - The 32-byte secret to wrap
    /// * `recipient_pk` - Recipient device's hybrid KEM public key
    /// * `context` - Wrap context for AAD binding
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if encapsulation or encryption fails.
    #[cfg(feature = "alloc")]
    pub fn wrap(
        secret: &[u8; 32],
        recipient_pk: &HybridKemPublicKey,
        context: &WrapContext,
    ) -> Result<Self> {
        // Step 1: Hybrid encapsulate to recipient's public key
        let (shared_secret, encapsulation) = recipient_pk.encapsulate()?;

        // Step 2: Derive wrapping key from shared secret
        let wrapping_key = Self::derive_wrapping_key(&shared_secret);

        // Step 3: Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_bytes(nonce_bytes);

        // Step 4: Build AAD from context
        let aad = context.to_aad();

        // Step 5: Encrypt the secret with XChaCha20-Poly1305
        let ciphertext = aead::encrypt(&wrapping_key, &nonce, secret, &aad)?;

        // Extract the encrypted payload (ciphertext + tag)
        let encrypted_payload: [u8; ENCRYPTED_PAYLOAD_SIZE] = ciphertext
            .try_into()
            .map_err(|_| CryptoError::MalformedMessage)?;

        // Extract encapsulation components
        let encap_bytes = encapsulation.to_bytes();
        let x448_ephemeral: [u8; X448_EPHEMERAL_SIZE] = encap_bytes[..X448_EPHEMERAL_SIZE]
            .try_into()
            .map_err(|_| CryptoError::MalformedMessage)?;
        let sntrup_ciphertext: [u8; SNTRUP_CT_SIZE] = encap_bytes[X448_EPHEMERAL_SIZE..]
            .try_into()
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            recipient_key_id: context.recipient_key_id,
            x448_ephemeral,
            sntrup_ciphertext,
            nonce: nonce_bytes,
            encrypted_payload,
        })
    }

    /// Unwraps a secret using the recipient's keypair.
    ///
    /// # Arguments
    ///
    /// * `recipient_keypair` - Recipient device's hybrid KEM keypair
    /// * `context` - Wrap context for AAD verification
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if decapsulation or decryption fails.
    #[cfg(feature = "alloc")]
    pub fn unwrap(
        &self,
        recipient_keypair: &HybridKemKeypair,
        context: &WrapContext,
    ) -> Result<[u8; 32]> {
        // Verify recipient key ID matches
        if self.recipient_key_id != context.recipient_key_id {
            return Err(CryptoError::DecryptionFailed);
        }

        // Reconstruct encapsulation
        let mut encap_bytes = Vec::with_capacity(X448_EPHEMERAL_SIZE + SNTRUP_CT_SIZE);
        encap_bytes.extend_from_slice(&self.x448_ephemeral);
        encap_bytes.extend_from_slice(&self.sntrup_ciphertext);

        let encapsulation = HybridEncapsulation::from_bytes(&encap_bytes)?;

        // Decapsulate to get shared secret
        let shared_secret = recipient_keypair.decapsulate(&encapsulation)?;

        // Derive wrapping key
        let wrapping_key = Self::derive_wrapping_key(&shared_secret);

        // Build AAD
        let aad = context.to_aad();

        // Build nonce
        let nonce = Nonce::from_bytes(self.nonce);

        // Decrypt the payload
        let plaintext = aead::decrypt(&wrapping_key, &nonce, &self.encrypted_payload, &aad)?;

        // Convert to fixed-size array
        let secret: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(secret)
    }

    /// Derives the wrapping key from the hybrid shared secret.
    fn derive_wrapping_key(shared_secret: &HybridSharedSecret) -> AeadKey {
        let key_bytes = blake3::derive_key(WRAP_CONTEXT, shared_secret.as_bytes());
        AeadKey::from_bytes(key_bytes)
    }

    /// Serialises the wrap to bytes.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DEVICE_KEY_WRAP_SIZE);

        bytes.extend_from_slice(&self.recipient_key_id);
        bytes.extend_from_slice(&self.x448_ephemeral);
        bytes.extend_from_slice(&self.sntrup_ciphertext);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.encrypted_payload);

        bytes
    }

    /// Deserialises a wrap from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DEVICE_KEY_WRAP_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        let mut recipient_key_id = [0u8; KEY_ID_SIZE];
        recipient_key_id.copy_from_slice(&bytes[offset..offset + KEY_ID_SIZE]);
        offset += KEY_ID_SIZE;

        let mut x448_ephemeral = [0u8; X448_EPHEMERAL_SIZE];
        x448_ephemeral.copy_from_slice(&bytes[offset..offset + X448_EPHEMERAL_SIZE]);
        offset += X448_EPHEMERAL_SIZE;

        let mut sntrup_ciphertext = [0u8; SNTRUP_CT_SIZE];
        sntrup_ciphertext.copy_from_slice(&bytes[offset..offset + SNTRUP_CT_SIZE]);
        offset += SNTRUP_CT_SIZE;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        let mut encrypted_payload = [0u8; ENCRYPTED_PAYLOAD_SIZE];
        encrypted_payload.copy_from_slice(&bytes[offset..offset + ENCRYPTED_PAYLOAD_SIZE]);

        Ok(Self {
            recipient_key_id,
            x448_ephemeral,
            sntrup_ciphertext,
            nonce,
            encrypted_payload,
        })
    }
}

impl core::fmt::Debug for DeviceKeyWrap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceKeyWrap")
            .field("recipient_key_id", &hex::encode(self.recipient_key_id))
            .field("x448_ephemeral", &"[56 bytes]")
            .field("sntrup_ciphertext", &"[1039 bytes]")
            .field("nonce", &"[24 bytes]")
            .field("encrypted_payload", &"[48 bytes]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrap_context_aad_size() {
        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let aad = context.to_aad();
        // 8 + 1 + 32 + 32 + 8 = 81 bytes
        assert_eq!(aad.len(), 81);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let secret = [0xABu8; 32];

        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let wrap = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context).unwrap();

        let recovered = wrap.unwrap(&keypair, &context).unwrap();
        assert_eq!(recovered, secret);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrap_serialisation() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let secret = [0xCDu8; 32];

        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::SessionSeed,
            [0x11u8; 32],
            [0x22u8; 32],
            99999,
        );

        let wrap = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context).unwrap();

        let bytes = wrap.to_bytes();
        assert_eq!(bytes.len(), DEVICE_KEY_WRAP_SIZE);

        let recovered_wrap = DeviceKeyWrap::from_bytes(&bytes).unwrap();

        let recovered_secret = recovered_wrap.unwrap(&keypair, &context).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrong_context_fails() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let secret = [0xEFu8; 32];

        let context1 = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let context2 = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12346, // Different epoch
        );

        let wrap = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context1).unwrap();

        // Should fail with wrong context (different AAD)
        let result = wrap.unwrap(&keypair, &context2);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrong_key_id_fails() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let secret = [0x99u8; 32];

        let context1 = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let context2 = WrapContext::new(
            [0x43u8; KEY_ID_SIZE], // Different key ID
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let wrap = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context1).unwrap();

        // Should fail with DecryptionFailed (key ID mismatch)
        let result = wrap.unwrap(&keypair, &context2);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_wrap_purpose_roundtrip() {
        for purpose in [
            WrapPurpose::BundleKey,
            WrapPurpose::SessionSeed,
            WrapPurpose::HistoryKey,
        ] {
            let byte = purpose.to_byte();
            let recovered = WrapPurpose::from_byte(byte).unwrap();
            assert_eq!(recovered, purpose);
        }
    }

    #[test]
    fn test_wrap_purpose_invalid_byte() {
        assert!(WrapPurpose::from_byte(0x00).is_none());
        assert!(WrapPurpose::from_byte(0x04).is_none());
        assert!(WrapPurpose::from_byte(0xFF).is_none());
    }

    #[test]
    fn test_device_key_wrap_size() {
        // 8 + 56 + 1039 + 24 + 48 = 1,175 bytes
        assert_eq!(DEVICE_KEY_WRAP_SIZE, 1175);
    }

    #[test]
    fn test_device_key_wrap_from_bytes_wrong_size() {
        // Too short
        let short_bytes = [0u8; 100];
        assert!(DeviceKeyWrap::from_bytes(&short_bytes).is_err());

        // Too long
        let long_bytes = [0u8; DEVICE_KEY_WRAP_SIZE + 10];
        assert!(DeviceKeyWrap::from_bytes(&long_bytes).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_key_wrap_debug() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let secret = [0xABu8; 32];

        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        let wrap = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context).unwrap();

        let debug_str = format!("{:?}", wrap);
        assert!(debug_str.contains("DeviceKeyWrap"));
        assert!(debug_str.contains("recipient_key_id"));
        assert!(debug_str.contains("[56 bytes]"));
        assert!(debug_str.contains("[1039 bytes]"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrap_context_new() {
        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::HistoryKey,
            [0x11u8; 32],
            [0x22u8; 32],
            99999,
        );

        assert_eq!(context.recipient_key_id, [0x42u8; KEY_ID_SIZE]);
        assert_eq!(context.purpose, WrapPurpose::HistoryKey);
        assert_eq!(context.thread_id, [0x11u8; 32]);
        assert_eq!(context.bundle_id, [0x22u8; 32]);
        assert_eq!(context.epoch, 99999);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_wrong_keypair_fails() {
        let keypair1 = HybridKemKeypair::generate().unwrap();
        let keypair2 = HybridKemKeypair::generate().unwrap();
        let secret = [0xABu8; 32];

        let context = WrapContext::new(
            [0x42u8; KEY_ID_SIZE],
            WrapPurpose::BundleKey,
            [0x11u8; 32],
            [0x22u8; 32],
            12345,
        );

        // Wrap to keypair1's public key
        let wrap = DeviceKeyWrap::wrap(&secret, keypair1.public_key(), &context).unwrap();

        // Try to unwrap with keypair2 (wrong key)
        let result = wrap.unwrap(&keypair2, &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_purpose_debug() {
        assert_eq!(format!("{:?}", WrapPurpose::BundleKey), "BundleKey");
        assert_eq!(format!("{:?}", WrapPurpose::SessionSeed), "SessionSeed");
        assert_eq!(format!("{:?}", WrapPurpose::HistoryKey), "HistoryKey");
    }

    #[test]
    fn test_key_id_size() {
        assert_eq!(KEY_ID_SIZE, 8);
    }

    #[test]
    fn test_x448_ephemeral_size() {
        assert_eq!(X448_EPHEMERAL_SIZE, 56);
    }

    #[test]
    fn test_sntrup_ct_size() {
        assert_eq!(SNTRUP_CT_SIZE, 1039);
    }

    #[test]
    fn test_encrypted_payload_size() {
        assert_eq!(ENCRYPTED_PAYLOAD_SIZE, 48); // 32 secret + 16 tag
    }
}
