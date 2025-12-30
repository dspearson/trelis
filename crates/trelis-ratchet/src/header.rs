//! Message header and AAD construction for Double Ratchet messages.
//!
//! The header contains all the information needed to decrypt a message,
//! including the sender's new public key and the hybrid encapsulation.
//! The entire header is authenticated as Associated Data (AAD).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridEncapsulation, HybridKemPublicKey};
use trelis_wire::constants::{
    CIPHER_SUITE, HYBRID_ENCAP_SIZE, HYBRID_KEM_PK_SIZE, PROTOCOL_VERSION,
};

use crate::nonce::NONCE_SIZE;

/// Size of the message header (AAD).
///
/// version (1) + suite (1) + header_len (4) + recipient_key_id (8) +
/// sender_pk_len (4) + sender_pk (1214) + encap_len (4) + encap (1095) +
/// message_number (8) = 2339 bytes
pub const HEADER_SIZE: usize = 2339;

/// Alias for AAD size (same as header size).
pub const AAD_SIZE: usize = HEADER_SIZE;

/// Message header containing sender's new public key and encapsulation.
#[derive(Clone)]
pub struct MessageHeader {
    /// Protocol version (0x01).
    pub version: u8,
    /// Cipher suite (0x01 = TRELIS_HYBRID_V1).
    pub cipher_suite: u8,
    /// Recipient's key ID for async keypair selection.
    pub recipient_key_id: u64,
    /// Sender's new hybrid public key.
    pub sender_public_key: HybridKemPublicKey,
    /// Hybrid encapsulation (X448 ephemeral + sntrup761 ciphertext).
    pub encapsulation: HybridEncapsulation,
    /// Message number in the current chain.
    pub message_number: u64,
}

impl MessageHeader {
    /// Creates a new message header.
    #[must_use]
    pub fn new(
        recipient_key_id: u64,
        sender_public_key: HybridKemPublicKey,
        encapsulation: HybridEncapsulation,
        message_number: u64,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            cipher_suite: CIPHER_SUITE,
            recipient_key_id,
            sender_public_key,
            encapsulation,
            message_number,
        }
    }

    /// Serialises the header to wire format.
    ///
    /// This is also the AAD for AEAD encryption.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);

        // Field 1: Version (1 byte)
        buf.push(self.version);

        // Field 2: Cipher Suite (1 byte)
        buf.push(self.cipher_suite);

        // Field 3: Header Length (4 bytes, little-endian u32)
        buf.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());

        // Field 4: Recipient Key ID (8 bytes, little-endian u64)
        buf.extend_from_slice(&self.recipient_key_id.to_le_bytes());

        // Field 5: Sender PK Length (4 bytes, little-endian u32)
        buf.extend_from_slice(&(HYBRID_KEM_PK_SIZE as u32).to_le_bytes());

        // Field 6-7: Sender X448 + sntrup761 Public Key (1214 bytes)
        buf.extend_from_slice(&self.sender_public_key.to_bytes());

        // Field 8: Encapsulation Length (4 bytes, little-endian u32)
        buf.extend_from_slice(&(HYBRID_ENCAP_SIZE as u32).to_le_bytes());

        // Field 9-10: Encapsulation (1095 bytes)
        buf.extend_from_slice(&self.encapsulation.to_bytes());

        // Field 11: Message Number (8 bytes, little-endian u64)
        buf.extend_from_slice(&self.message_number.to_le_bytes());

        debug_assert_eq!(buf.len(), HEADER_SIZE);

        buf
    }

    /// Parses a header from wire format bytes.
    ///
    /// # Errors
    ///
    /// Returns errors if the header is malformed or has invalid values.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Field 1: Version
        let version = bytes[offset];
        offset += 1;
        if version != PROTOCOL_VERSION {
            return Err(CryptoError::UnsupportedProtocolVersion {
                received: version,
                supported: PROTOCOL_VERSION,
            });
        }

        // Field 2: Cipher Suite
        let cipher_suite = bytes[offset];
        offset += 1;
        if cipher_suite != CIPHER_SUITE {
            return Err(CryptoError::UnsupportedCipherSuite {
                received: cipher_suite,
                supported: CIPHER_SUITE,
            });
        }

        // Field 3: Header Length (skip, we already validated)
        offset += 4;

        // Field 4: Recipient Key ID
        let recipient_key_id = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Field 5: Sender PK Length (skip, we know it's 1214)
        offset += 4;

        // Field 6-7: Sender Public Key
        let sender_public_key =
            HybridKemPublicKey::from_bytes(&bytes[offset..offset + HYBRID_KEM_PK_SIZE])?;
        offset += HYBRID_KEM_PK_SIZE;

        // Field 8: Encapsulation Length (skip, we know it's 1095)
        offset += 4;

        // Field 9-10: Encapsulation
        let encapsulation =
            HybridEncapsulation::from_bytes(&bytes[offset..offset + HYBRID_ENCAP_SIZE])?;
        offset += HYBRID_ENCAP_SIZE;

        // Field 11: Message Number
        let message_number = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );

        Ok(Self {
            version,
            cipher_suite,
            recipient_key_id,
            sender_public_key,
            encapsulation,
            message_number,
        })
    }
}

/// Complete ratchet message with header, nonce, and ciphertext.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct RatchetMessage {
    /// Message header (also serves as AAD).
    pub header: MessageHeader,
    /// XChaCha20 nonce (24 bytes).
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted message with Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl RatchetMessage {
    /// Returns the header bytes for use as AAD.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        self.header.to_bytes()
    }

    /// Serialises the complete message to wire format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let total_size = header_bytes.len() + NONCE_SIZE + 4 + self.ciphertext.len();
        let mut buf = Vec::with_capacity(total_size);

        // Header (AAD)
        buf.extend_from_slice(&header_bytes);

        // Nonce
        buf.extend_from_slice(&self.nonce);

        // Ciphertext length + ciphertext
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);

        buf
    }

    /// Parses a complete message from wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_size = HEADER_SIZE + NONCE_SIZE + 4;
        if bytes.len() < min_size {
            return Err(CryptoError::MalformedMessage);
        }

        // Parse header
        let header = MessageHeader::from_bytes(&bytes[..HEADER_SIZE])?;
        let mut offset = HEADER_SIZE;

        // Parse nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        // Parse ciphertext length
        let ct_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        ) as usize;
        offset += 4;

        // Parse ciphertext
        if bytes.len() < offset + ct_len {
            return Err(CryptoError::MalformedMessage);
        }
        let ciphertext = bytes[offset..offset + ct_len].to_vec();

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::HybridKemKeypair;

    #[test]
    fn test_header_size() {
        // 1 + 1 + 4 + 8 + 4 + 1214 + 4 + 1095 + 8 = 2339
        assert_eq!(HEADER_SIZE, 2339);
        assert_eq!(AAD_SIZE, HEADER_SIZE);
    }

    #[test]
    fn test_header_round_trip() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let (_, encap) = keypair.public_key().encapsulate().unwrap();

        let header = MessageHeader::new(
            0x1234567890ABCDEF,
            keypair.public_key().clone(),
            encap,
            42,
        );

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = MessageHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.cipher_suite, CIPHER_SUITE);
        assert_eq!(parsed.recipient_key_id, 0x1234567890ABCDEF);
        assert_eq!(parsed.message_number, 42);
    }

    #[test]
    fn test_header_version_check() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 0xFF; // Invalid version

        let result = MessageHeader::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedProtocolVersion { .. })
        ));
    }

    #[test]
    fn test_header_cipher_suite_check() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0xFF; // Invalid cipher suite

        let result = MessageHeader::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedCipherSuite { .. })
        ));
    }

    #[test]
    fn test_message_round_trip() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let (_, encap) = keypair.public_key().encapsulate().unwrap();

        let header = MessageHeader::new(12345, keypair.public_key().clone(), encap, 0);

        let message = RatchetMessage {
            header,
            nonce: [0x42u8; NONCE_SIZE],
            ciphertext: b"encrypted data here".to_vec(),
        };

        let bytes = message.to_bytes();
        let parsed = RatchetMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.nonce, message.nonce);
        assert_eq!(parsed.ciphertext, message.ciphertext);
        assert_eq!(parsed.header.message_number, 0);
    }
}
