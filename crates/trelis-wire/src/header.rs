//! Protocol header types and validation.
//!
//! All Trelis protocol messages begin with a 2-byte header containing
//! the protocol version and cipher suite.

use crate::constants::{CIPHER_SUITE, HEADER_SIZE, PROTOCOL_VERSION};
use trelis_error::{CryptoError, Result};

/// Protocol version identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolVersion {
    /// Protocol version 1 (current, hybrid post-quantum).
    V1 = 0x01,
}

impl ProtocolVersion {
    /// Creates a version from a raw byte.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedProtocolVersion` if the version is not supported.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::V1),
            _ => Err(CryptoError::UnsupportedProtocolVersion {
                received: byte,
                supported: PROTOCOL_VERSION,
            }),
        }
    }

    /// Returns the version as a byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::V1
    }
}

/// Cipher suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// TRELIS_HYBRID_V1: Ed448+ML-DSA-65, X448+sntrup761, XChaCha20-Poly1305, BLAKE3.
    TrelisHybridV1 = 0x01,
}

impl CipherSuite {
    /// Creates a cipher suite from a raw byte.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedCipherSuite` if the suite is not supported.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::TrelisHybridV1),
            _ => Err(CryptoError::UnsupportedCipherSuite { suite: byte }),
        }
    }

    /// Returns the cipher suite as a byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::TrelisHybridV1
    }
}

/// Protocol header (version + cipher suite).
///
/// All protocol messages begin with this 2-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Protocol version.
    pub version: ProtocolVersion,
    /// Cipher suite.
    pub suite: CipherSuite,
}

impl Header {
    /// Creates a new header with the current protocol version and cipher suite.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            version: ProtocolVersion::V1,
            suite: CipherSuite::TrelisHybridV1,
        }
    }

    /// Serialises the header to bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        [self.version.as_byte(), self.suite.as_byte()]
    }

    /// Deserialises a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the version or cipher suite is unsupported.
    pub fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Result<Self> {
        let version = ProtocolVersion::from_byte(bytes[0])?;
        let suite = CipherSuite::from_byte(bytes[1])?;
        Ok(Self { version, suite })
    }

    /// Validates that the header matches the expected values.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedProtocolVersion` or `UnsupportedCipherSuite`
    /// if the header doesn't match expected values.
    pub fn validate(&self) -> Result<()> {
        if self.version.as_byte() != PROTOCOL_VERSION {
            return Err(CryptoError::UnsupportedProtocolVersion {
                received: self.version.as_byte(),
                supported: PROTOCOL_VERSION,
            });
        }
        if self.suite.as_byte() != CIPHER_SUITE {
            return Err(CryptoError::UnsupportedCipherSuite {
                suite: self.suite.as_byte(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_SIZE, 2);
    }

    #[test]
    fn test_default_header() {
        let header = Header::new();
        assert_eq!(header.version, ProtocolVersion::V1);
        assert_eq!(header.suite, CipherSuite::TrelisHybridV1);
    }

    #[test]
    fn test_header_serialisation() {
        let header = Header::new();
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0x01, 0x01]);

        let recovered = Header::from_bytes(&bytes).unwrap();
        assert_eq!(header, recovered);
    }

    #[test]
    fn test_header_validation() {
        let header = Header::new();
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_unsupported_version() {
        let result = ProtocolVersion::from_byte(0x02);
        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedProtocolVersion {
                received: 0x02,
                supported: 0x01
            })
        ));
    }

    #[test]
    fn test_unsupported_suite() {
        let result = CipherSuite::from_byte(0x02);
        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedCipherSuite { suite: 0x02 })
        ));
    }

    #[test]
    fn test_version_byte_roundtrip() {
        let version = ProtocolVersion::V1;
        let byte = version.as_byte();
        let recovered = ProtocolVersion::from_byte(byte).unwrap();
        assert_eq!(version, recovered);
    }

    #[test]
    fn test_suite_byte_roundtrip() {
        let suite = CipherSuite::TrelisHybridV1;
        let byte = suite.as_byte();
        let recovered = CipherSuite::from_byte(byte).unwrap();
        assert_eq!(suite, recovered);
    }
}
