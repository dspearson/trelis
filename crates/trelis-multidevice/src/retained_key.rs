//! Retained message keys for history sharing.
//!
//! When history sync is enabled, message keys are retained locally
//! for potential sharing with new devices.

use trelis_error::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Retained message key for history sharing.
///
/// This structure holds a message key that can be shared with new devices
/// to allow them to decrypt historical messages.
///
/// # Storage Overhead
///
/// Each retained key uses 80 bytes:
/// - message_id: 32 bytes
/// - message_key: 32 bytes
/// - sequence: 8 bytes
/// - timestamp: 8 bytes
///
/// Example: 10,000 messages = 800 KB of retained keys per thread.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RetainedKey {
    /// Unique identifier for the message.
    #[zeroize(skip)]
    pub message_id: [u8; 32],

    /// The symmetric key used to encrypt this message.
    pub message_key: [u8; 32],

    /// Sequence number within the thread (for ordering).
    #[zeroize(skip)]
    pub sequence: u64,

    /// Unix timestamp when the message was sent/received.
    #[zeroize(skip)]
    pub timestamp: u64,
}

impl RetainedKey {
    /// Size of a retained key when serialised.
    pub const SERIALISED_SIZE: usize = 32 + 32 + 8 + 8; // 80 bytes

    /// Creates a new retained key.
    #[must_use]
    pub fn new(message_id: [u8; 32], message_key: [u8; 32], sequence: u64, timestamp: u64) -> Self {
        Self {
            message_id,
            message_key,
            sequence,
            timestamp,
        }
    }

    /// Serialises the retained key to bytes.
    ///
    /// Format: message_id (32B) || message_key (32B) || sequence (8B) || timestamp (8B)
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; Self::SERIALISED_SIZE]> {
        let mut bytes = Zeroizing::new([0u8; Self::SERIALISED_SIZE]);

        bytes[0..32].copy_from_slice(&self.message_id);
        bytes[32..64].copy_from_slice(&self.message_key);
        bytes[64..72].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.timestamp.to_le_bytes());

        bytes
    }

    /// Deserialises a retained key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the input is not exactly 80 bytes.
    #[allow(clippy::expect_used)] // Slices guaranteed correct size after length check
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SERIALISED_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut message_id = [0u8; 32];
        let mut message_key = [0u8; 32];

        message_id.copy_from_slice(&bytes[0..32]);
        message_key.copy_from_slice(&bytes[32..64]);

        let sequence =
            u64::from_le_bytes(bytes[64..72].try_into().expect("slice is exactly 8 bytes"));
        let timestamp =
            u64::from_le_bytes(bytes[72..80].try_into().expect("slice is exactly 8 bytes"));

        Ok(Self {
            message_id,
            message_key,
            sequence,
            timestamp,
        })
    }
}

// Manual Debug implementation to avoid exposing the message key
impl core::fmt::Debug for RetainedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetainedKey")
            .field("message_id", &format_redacted())
            .field("message_key", &"[REDACTED]")
            .field("sequence", &self.sequence)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Formats a byte array as a redacted placeholder for Debug output.
fn format_redacted() -> &'static str {
    "[32 bytes]"
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_retained_key_new() {
        let key = RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 42, 1000);

        assert_eq!(key.message_id, [0x01u8; 32]);
        assert_eq!(key.message_key, [0xAAu8; 32]);
        assert_eq!(key.sequence, 42);
        assert_eq!(key.timestamp, 1000);
    }

    #[test]
    fn test_retained_key_serialisation() {
        let key = RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 42, 1000);

        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), RetainedKey::SERIALISED_SIZE);

        let recovered = RetainedKey::from_bytes(&bytes[..]).unwrap();

        assert_eq!(recovered.message_id, key.message_id);
        assert_eq!(recovered.message_key, key.message_key);
        assert_eq!(recovered.sequence, key.sequence);
        assert_eq!(recovered.timestamp, key.timestamp);
    }

    #[test]
    fn test_retained_key_from_bytes_wrong_size() {
        assert!(RetainedKey::from_bytes(&[0u8; 79]).is_err());
        assert!(RetainedKey::from_bytes(&[0u8; 81]).is_err());
    }

    #[test]
    fn test_retained_key_debug_redacted() {
        let key = RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 42, 1000);
        let debug = format!("{:?}", key);

        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0xaa"));
    }

    #[test]
    fn test_serialised_size_constant() {
        assert_eq!(RetainedKey::SERIALISED_SIZE, 80);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // Prove: from_bytes on an exactly SERIALISED_SIZE-byte slice never panics.
    // The two .expect() calls inside are guarded by the length check; this proves
    // they are unreachable and the slice indexing is always in bounds.
    #[kani::proof]
    fn from_bytes_exact_size_no_panic() {
        let bytes: [u8; RetainedKey::SERIALISED_SIZE] = kani::any();
        let result = RetainedKey::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    // Prove: from_bytes rejects any input whose length differs from SERIALISED_SIZE.
    // Bounded to 0..=255 to keep the model check tractable.
    #[kani::proof]
    fn from_bytes_wrong_size_returns_err() {
        let len: usize = kani::any();
        kani::assume(len <= 255);
        kani::assume(len != RetainedKey::SERIALISED_SIZE);
        let buf = [0u8; 255];
        let result = RetainedKey::from_bytes(&buf[..len]);
        assert!(result.is_err());
    }
}
