//! History key sharing for new device onboarding.
//!
//! When a new device is approved, historical message keys are sent
//! as a special encrypted message type.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

use crate::ThreadId;
use crate::retained_key::RetainedKey;

/// Context string for history key share signatures.
const HISTORY_KEY_SHARE_CONTEXT: &str = "trelis-v1-history-key-share";

/// History key share message for sending retained keys to a new device.
///
/// This message is encrypted using the X3DH-PQ session established
/// between the existing device and the new device.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct HistoryKeyShareMessage {
    /// Thread these keys belong to.
    pub thread_id: ThreadId,

    /// The retained message keys.
    pub keys: Vec<RetainedKey>,

    /// Signature from sharing device (for audit trail).
    pub signature: HybridSignature,

    /// Unix timestamp when keys were shared.
    pub shared_at: u64,
}

#[cfg(feature = "alloc")]
impl HistoryKeyShareMessage {
    /// Creates a new history key share message.
    ///
    /// The message is signed by the sharing device for audit purposes.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread these keys belong to
    /// * `keys` - The retained message keys to share
    /// * `signing_key` - The sharing device's signing keypair
    /// * `shared_at` - Unix timestamp for the share event
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if signing fails.
    pub fn new(
        thread_id: ThreadId,
        keys: Vec<RetainedKey>,
        signing_key: &HybridSigningKeypair,
        shared_at: u64,
    ) -> Result<Self> {
        // Create signing data
        let sig_data = Self::signing_data(&thread_id, &keys, shared_at);

        // Sign with the sharing device's key
        let signature = signing_key.sign(&sig_data)?;

        Ok(Self {
            thread_id,
            keys,
            signature,
            shared_at,
        })
    }

    /// Verifies the signature on a received history key share.
    ///
    /// # Arguments
    ///
    /// * `sender_key` - The signing public key of the sharing device
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if verification fails.
    pub fn verify(&self, sender_key: &HybridSigningPublicKey) -> Result<()> {
        let sig_data = Self::signing_data(&self.thread_id, &self.keys, self.shared_at);
        if sender_key.verify(&sig_data, &self.signature) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Creates the data to be signed for audit purposes.
    ///
    /// Format: context || thread_id || key_count || shared_at
    #[cfg(feature = "alloc")]
    fn signing_data(thread_id: &ThreadId, keys: &[RetainedKey], shared_at: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(64 + HISTORY_KEY_SHARE_CONTEXT.len());

        data.extend_from_slice(HISTORY_KEY_SHARE_CONTEXT.as_bytes());
        data.extend_from_slice(thread_id);
        data.extend_from_slice(&(keys.len() as u64).to_le_bytes());
        data.extend_from_slice(&shared_at.to_le_bytes());

        data
    }

    /// Returns the number of keys being shared.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Serialises the message to bytes.
    ///
    /// Format:
    /// - thread_id: 32 bytes
    /// - key_count: 8 bytes (u64 LE)
    /// - keys: 80 bytes × key_count
    /// - shared_at: 8 bytes (u64 LE)
    /// - signature: variable (HybridSignature)
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let key_data_size = self.keys.len() * RetainedKey::SERIALISED_SIZE;
        let total_size = 32 + 8 + key_data_size + 8 + sig_bytes.len();

        let mut bytes = Vec::with_capacity(total_size);

        // Thread ID
        bytes.extend_from_slice(&self.thread_id);

        // Key count
        bytes.extend_from_slice(&(self.keys.len() as u64).to_le_bytes());

        // Keys
        for key in &self.keys {
            bytes.extend_from_slice(&key.to_bytes());
        }

        // Shared at
        bytes.extend_from_slice(&self.shared_at.to_le_bytes());

        // Signature
        bytes.extend_from_slice(&sig_bytes);

        bytes
    }

    /// Deserialises a message from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Minimum size: thread_id (32) + key_count (8) + shared_at (8) + signature
        if bytes.len() < 48 {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Thread ID
        let mut thread_id = [0u8; 32];
        thread_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Key count
        let key_count = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        ) as usize;
        offset += 8;

        // Validate we have enough data for keys
        let keys_size = key_count * RetainedKey::SERIALISED_SIZE;
        if bytes.len() < offset + keys_size + 8 {
            return Err(CryptoError::MalformedMessage);
        }

        // Keys
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let key =
                RetainedKey::from_bytes(&bytes[offset..offset + RetainedKey::SERIALISED_SIZE])
                    .ok_or(CryptoError::MalformedMessage)?;
            keys.push(key);
            offset += RetainedKey::SERIALISED_SIZE;
        }

        // Shared at
        let shared_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Signature (remaining bytes)
        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            thread_id,
            keys,
            signature,
            shared_at,
        })
    }
}

/// Summary of a history key share operation.
#[derive(Debug, Clone)]
pub struct HistoryKeyShare {
    /// Thread ID that was shared.
    pub thread_id: ThreadId,

    /// Number of keys shared.
    pub key_count: usize,

    /// Unix timestamp of the share.
    pub shared_at: u64,
}

impl HistoryKeyShare {
    /// Creates a summary from a message.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn from_message(msg: &HistoryKeyShareMessage) -> Self {
        Self {
            thread_id: msg.thread_id,
            key_count: msg.keys.len(),
            shared_at: msg.shared_at,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    fn create_test_keys(count: usize) -> Vec<RetainedKey> {
        (0..count)
            .map(|i| {
                let mut message_id = [0u8; 32];
                message_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());

                RetainedKey::new(message_id, [0xAAu8; 32], i as u64, 1000 + i as u64)
            })
            .collect()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_history_key_share_message_create() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let keys = create_test_keys(5);

        let msg = HistoryKeyShareMessage::new([0x42u8; 32], keys, &signing_key, 5000).unwrap();

        assert_eq!(msg.thread_id, [0x42u8; 32]);
        assert_eq!(msg.key_count(), 5);
        assert_eq!(msg.shared_at, 5000);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_history_key_share_verify() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let keys = create_test_keys(3);

        let msg = HistoryKeyShareMessage::new([0x42u8; 32], keys, &signing_key, 5000).unwrap();

        // Verify with correct key
        assert!(msg.verify(&signing_key.public_key()).is_ok());

        // Verify with wrong key should fail
        let other_key = HybridSigningKeypair::generate().unwrap();
        assert!(msg.verify(&other_key.public_key()).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_history_key_share_serialisation() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let keys = create_test_keys(10);

        let msg = HistoryKeyShareMessage::new([0x42u8; 32], keys, &signing_key, 5000).unwrap();

        let bytes = msg.to_bytes();
        let recovered = HistoryKeyShareMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.thread_id, msg.thread_id);
        assert_eq!(recovered.key_count(), msg.key_count());
        assert_eq!(recovered.shared_at, msg.shared_at);

        // Verify signature still valid
        assert!(recovered.verify(&signing_key.public_key()).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_history_key_share_empty_keys() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let keys = Vec::new();

        let msg = HistoryKeyShareMessage::new([0x42u8; 32], keys, &signing_key, 5000).unwrap();

        assert_eq!(msg.key_count(), 0);

        let bytes = msg.to_bytes();
        let recovered = HistoryKeyShareMessage::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.key_count(), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_history_key_share_summary() {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let keys = create_test_keys(7);

        let msg = HistoryKeyShareMessage::new([0x42u8; 32], keys, &signing_key, 5000).unwrap();

        let summary = HistoryKeyShare::from_message(&msg);

        assert_eq!(summary.thread_id, [0x42u8; 32]);
        assert_eq!(summary.key_count, 7);
        assert_eq!(summary.shared_at, 5000);
    }
}
