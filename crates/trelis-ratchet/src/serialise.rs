//! Session state serialisation for persistence and device migration.
//!
//! This module provides binary serialisation of `DoubleRatchet` state
//! for secure storage. The serialised data MUST be encrypted before
//! persisting to disk.

use trelis_error::{CryptoError, Result};

/// Magic bytes identifying a Trelis ratchet state file.
pub const MAGIC: [u8; 4] = *b"TRLS";

/// Current state serialisation version.
pub const STATE_VERSION: u16 = 1;

/// Flag indicating peer public keys are present.
pub const FLAG_HAS_PEER: u16 = 0x0001;

/// Flag indicating skipped keys section is present.
pub const FLAG_HAS_SKIPPED: u16 = 0x0002;

/// Size of skipped key entry in serialised form.
/// sender_key_hash (32) + message_number (8) + message_key (32) + created_at (8) = 80
pub const SKIPPED_KEY_ENTRY_SIZE: usize = 80;

/// Serialised state header.
#[derive(Clone, Debug)]
pub struct StateHeader {
    /// Magic bytes (must be "TRLS").
    pub magic: [u8; 4],
    /// Serialisation version.
    pub version: u16,
    /// Flags bitfield.
    pub flags: u16,
}

impl StateHeader {
    /// Creates a new header with the given flags.
    #[must_use]
    pub fn new(flags: u16) -> Self {
        Self {
            magic: MAGIC,
            version: STATE_VERSION,
            flags,
        }
    }

    /// Serialises the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf
    }

    /// Parses a header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(CryptoError::MalformedMessage);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);

        if magic != MAGIC {
            return Err(CryptoError::InvalidMagic);
        }

        let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        if version != STATE_VERSION {
            return Err(CryptoError::UnsupportedStateVersion);
        }

        let flags = u16::from_be_bytes(bytes[6..8].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            flags,
        })
    }

    /// Checks if the peer flag is set.
    #[must_use]
    pub fn has_peer(&self) -> bool {
        self.flags & FLAG_HAS_PEER != 0
    }

    /// Checks if the skipped keys flag is set.
    #[must_use]
    pub fn has_skipped(&self) -> bool {
        self.flags & FLAG_HAS_SKIPPED != 0
    }
}

/// Serialises a u64 as big-endian bytes.
#[must_use]
pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Deserialises a u64 from big-endian bytes.
pub fn decode_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() < 8 {
        return Err(CryptoError::MalformedMessage);
    }
    Ok(u64::from_be_bytes(bytes[..8].try_into().unwrap()))
}

/// Serialises a u32 as big-endian bytes.
#[must_use]
pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Deserialises a u32 from big-endian bytes.
pub fn decode_u32(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(CryptoError::MalformedMessage);
    }
    Ok(u32::from_be_bytes(bytes[..4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic() {
        assert_eq!(MAGIC, *b"TRLS");
    }

    #[test]
    fn test_state_version() {
        assert_eq!(STATE_VERSION, 1);
    }

    #[test]
    fn test_header_round_trip() {
        let header = StateHeader::new(FLAG_HAS_PEER | FLAG_HAS_SKIPPED);
        let bytes = header.to_bytes();
        let parsed = StateHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, MAGIC);
        assert_eq!(parsed.version, STATE_VERSION);
        assert!(parsed.has_peer());
        assert!(parsed.has_skipped());
    }

    #[test]
    fn test_header_no_flags() {
        let header = StateHeader::new(0);
        let bytes = header.to_bytes();
        let parsed = StateHeader::from_bytes(&bytes).unwrap();

        assert!(!parsed.has_peer());
        assert!(!parsed.has_skipped());
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(b"XXXX");
        bytes[4..6].copy_from_slice(&STATE_VERSION.to_be_bytes());

        let result = StateHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::InvalidMagic)));
    }

    #[test]
    fn test_header_unsupported_version() {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&99u16.to_be_bytes());

        let result = StateHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::UnsupportedStateVersion)));
    }

    #[test]
    fn test_encode_decode_u64() {
        let value = 0x123456789ABCDEF0u64;
        let bytes = encode_u64(value);
        let decoded = decode_u64(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_encode_decode_u32() {
        let value = 0x12345678u32;
        let bytes = encode_u32(value);
        let decoded = decode_u32(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_skipped_key_entry_size() {
        // 32 + 8 + 32 + 8 = 80
        assert_eq!(SKIPPED_KEY_ENTRY_SIZE, 80);
    }
}
