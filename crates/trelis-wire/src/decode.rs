//! Wire format decoding utilities.
//!
//! All multi-byte integers are decoded from little-endian.

use crate::header::Header;

/// Error type for decoding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderError {
    /// Not enough bytes remaining in the buffer.
    UnexpectedEof,
    /// Invalid or malformed header.
    InvalidHeader,
    /// Protocol version not supported.
    UnsupportedProtocolVersion(u8),
    /// Cipher suite not supported.
    UnsupportedCipherSuite(u8),
}

impl core::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::InvalidHeader => write!(f, "invalid protocol header"),
            Self::UnsupportedProtocolVersion(v) => {
                write!(f, "unsupported protocol version: {}", v)
            }
            Self::UnsupportedCipherSuite(s) => write!(f, "unsupported cipher suite: {}", s),
        }
    }
}

/// Decoder for reading from a byte buffer.
///
/// Provides methods for decoding integers and byte arrays from the
/// canonical Trelis wire format (little-endian).
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a new decoder reading from the given buffer.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the current position in the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns the number of bytes remaining in the buffer.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Returns true if there are at least `n` bytes remaining.
    #[must_use]
    pub const fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Returns true if all bytes have been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads a single byte.
    pub fn read_u8(&mut self) -> Result<u8, DecoderError> {
        if self.pos >= self.buf.len() {
            return Err(DecoderError::UnexpectedEof);
        }
        let value = self.buf[self.pos];
        self.pos += 1;
        Ok(value)
    }

    /// Reads a u16 in little-endian format.
    pub fn read_u16(&mut self) -> Result<u16, DecoderError> {
        if self.remaining() < 2 {
            return Err(DecoderError::UnexpectedEof);
        }
        let bytes: [u8; 2] = self.buf[self.pos..self.pos + 2]
            .try_into()
            .map_err(|_| DecoderError::UnexpectedEof)?;
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads a u32 in little-endian format.
    pub fn read_u32(&mut self) -> Result<u32, DecoderError> {
        if self.remaining() < 4 {
            return Err(DecoderError::UnexpectedEof);
        }
        let bytes: [u8; 4] = self.buf[self.pos..self.pos + 4]
            .try_into()
            .map_err(|_| DecoderError::UnexpectedEof)?;
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads a u64 in little-endian format.
    pub fn read_u64(&mut self) -> Result<u64, DecoderError> {
        if self.remaining() < 8 {
            return Err(DecoderError::UnexpectedEof);
        }
        let bytes: [u8; 8] = self.buf[self.pos..self.pos + 8]
            .try_into()
            .map_err(|_| DecoderError::UnexpectedEof)?;
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Reads a byte slice of the given length.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DecoderError> {
        if self.remaining() < len {
            return Err(DecoderError::UnexpectedEof);
        }
        let data = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(data)
    }

    /// Reads a fixed-size byte array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecoderError> {
        if self.remaining() < N {
            return Err(DecoderError::UnexpectedEof);
        }
        let array: [u8; N] = self.buf[self.pos..self.pos + N]
            .try_into()
            .map_err(|_| DecoderError::UnexpectedEof)?;
        self.pos += N;
        Ok(array)
    }

    /// Reads a protocol header.
    pub fn read_header(&mut self) -> Result<Header, DecoderError> {
        let bytes: [u8; 2] = self.read_array()?;
        Header::from_bytes(&bytes).map_err(|e| {
            use trelis_error::CryptoError;
            match e {
                CryptoError::UnsupportedProtocolVersion { received, .. } => {
                    DecoderError::UnsupportedProtocolVersion(received)
                }
                CryptoError::UnsupportedCipherSuite { received, .. } => {
                    DecoderError::UnsupportedCipherSuite(received)
                }
                _ => DecoderError::InvalidHeader,
            }
        })
    }

    /// Reads a length-prefixed byte slice (u32 length prefix).
    pub fn read_length_prefixed(&mut self) -> Result<&'a [u8], DecoderError> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }

    /// Skips `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<(), DecoderError> {
        if self.remaining() < n {
            return Err(DecoderError::UnexpectedEof);
        }
        self.pos += n;
        Ok(())
    }

    /// Returns the remaining bytes without consuming them.
    #[must_use]
    pub fn peek_remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

/// Decodes a u16 from little-endian bytes.
#[must_use]
pub const fn decode_u16(bytes: [u8; 2]) -> u16 {
    u16::from_le_bytes(bytes)
}

/// Decodes a u32 from little-endian bytes.
#[must_use]
pub const fn decode_u32(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Decodes a u64 from little-endian bytes.
#[must_use]
pub const fn decode_u64(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_u16() {
        assert_eq!(decode_u16([0x02, 0x01]), 0x0102);
        assert_eq!(decode_u16([0, 0]), 0);
        assert_eq!(decode_u16([0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_decode_u32() {
        assert_eq!(decode_u32([0x04, 0x03, 0x02, 0x01]), 0x01020304);
        assert_eq!(decode_u32([0, 0, 0, 0]), 0);
        assert_eq!(decode_u32([0xFF, 0xFF, 0xFF, 0xFF]), 0xFFFFFFFF);
    }

    #[test]
    fn test_decode_u64() {
        assert_eq!(
            decode_u64([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            0x0102030405060708
        );
    }

    #[test]
    fn test_decoder_read_u8() {
        let buf = [0x01, 0x02, 0x03];
        let mut dec = Decoder::new(&buf);

        assert_eq!(dec.read_u8().unwrap(), 0x01);
        assert_eq!(dec.read_u8().unwrap(), 0x02);
        assert_eq!(dec.position(), 2);
    }

    #[test]
    fn test_decoder_read_u32() {
        let buf = [0x04, 0x03, 0x02, 0x01, 0xFF];
        let mut dec = Decoder::new(&buf);

        assert_eq!(dec.read_u32().unwrap(), 0x01020304);
        assert_eq!(dec.position(), 4);
    }

    #[test]
    fn test_decoder_read_u64() {
        let buf = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let mut dec = Decoder::new(&buf);

        assert_eq!(dec.read_u64().unwrap(), 0x0102030405060708);
        assert_eq!(dec.position(), 8);
    }

    #[test]
    fn test_decoder_read_bytes() {
        let buf = [1, 2, 3, 4, 5];
        let mut dec = Decoder::new(&buf);

        let data = dec.read_bytes(3).unwrap();
        assert_eq!(data, &[1, 2, 3]);
        assert_eq!(dec.position(), 3);
    }

    #[test]
    fn test_decoder_read_array() {
        let buf = [1, 2, 3, 4, 5];
        let mut dec = Decoder::new(&buf);

        let arr: [u8; 4] = dec.read_array().unwrap();
        assert_eq!(arr, [1, 2, 3, 4]);
    }

    #[test]
    fn test_decoder_underflow() {
        let buf = [0x01, 0x02];
        let mut dec = Decoder::new(&buf);

        assert!(dec.read_u32().is_err());
        assert_eq!(dec.position(), 0);
    }

    #[test]
    fn test_decoder_header() {
        let buf = [0x01, 0x01, 0xFF];
        let mut dec = Decoder::new(&buf);

        let header = dec.read_header().unwrap();
        assert_eq!(header, Header::new());
        assert_eq!(dec.position(), 2);
    }

    #[test]
    fn test_decoder_invalid_header() {
        let buf = [0x02, 0x01]; // Invalid version
        let mut dec = Decoder::new(&buf);

        assert!(matches!(
            dec.read_header(),
            Err(DecoderError::UnsupportedProtocolVersion(0x02))
        ));
    }

    #[test]
    fn test_decoder_length_prefixed() {
        let buf = [0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xFF];
        let mut dec = Decoder::new(&buf);

        let data = dec.read_length_prefixed().unwrap();
        assert_eq!(data, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(dec.position(), 7);
    }

    #[test]
    fn test_decoder_skip() {
        let buf = [1, 2, 3, 4, 5];
        let mut dec = Decoder::new(&buf);

        dec.skip(3).unwrap();
        assert_eq!(dec.position(), 3);
        assert_eq!(dec.read_u8().unwrap(), 4);
    }

    #[test]
    fn test_roundtrip() {
        use crate::encode::Encoder;

        let mut buf = [0u8; 32];

        // Encode
        {
            let mut enc = Encoder::new(&mut buf);
            enc.write_header(&Header::new()).unwrap();
            enc.write_u32(0xDEADBEEF).unwrap();
            enc.write_u64(0x0102030405060708).unwrap();
            enc.write_bytes(&[0xAA, 0xBB, 0xCC]).unwrap();
        }

        // Decode
        {
            let mut dec = Decoder::new(&buf);
            let header = dec.read_header().unwrap();
            assert_eq!(header, Header::new());

            let val32 = dec.read_u32().unwrap();
            assert_eq!(val32, 0xDEADBEEF);

            let val64 = dec.read_u64().unwrap();
            assert_eq!(val64, 0x0102030405060708);

            let bytes = dec.read_bytes(3).unwrap();
            assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
        }
    }

    #[test]
    fn test_decoder_read_u16() {
        let buf = [0x02, 0x01, 0xFF];
        let mut dec = Decoder::new(&buf);

        assert_eq!(dec.read_u16().unwrap(), 0x0102);
        assert_eq!(dec.position(), 2);
    }

    #[test]
    fn test_decoder_read_u16_underflow() {
        let buf = [0x01]; // Only 1 byte
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.read_u16(), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_error_debug() {
        // Test Debug trait instead of Display (no alloc needed)
        let err1 = DecoderError::UnexpectedEof;
        let err2 = DecoderError::InvalidHeader;
        let err3 = DecoderError::UnsupportedProtocolVersion(5);
        let err4 = DecoderError::UnsupportedCipherSuite(99);

        // Verify all variants are Debug printable and Clone/Copy/PartialEq work
        assert_eq!(err1, err1.clone());
        assert_eq!(err2, err2.clone());
        assert_eq!(err3, DecoderError::UnsupportedProtocolVersion(5));
        assert_eq!(err4, DecoderError::UnsupportedCipherSuite(99));

        // Different errors should not be equal
        assert_ne!(err1, err2);
        assert_ne!(err3, err4);
    }

    #[test]
    fn test_decoder_has_remaining() {
        let buf = [1, 2, 3, 4, 5];
        let dec = Decoder::new(&buf);

        assert!(dec.has_remaining(5));
        assert!(dec.has_remaining(1));
        assert!(!dec.has_remaining(6));
    }

    #[test]
    fn test_decoder_is_empty() {
        let buf = [1, 2];
        let mut dec = Decoder::new(&buf);

        assert!(!dec.is_empty());

        dec.read_u8().unwrap();
        assert!(!dec.is_empty());

        dec.read_u8().unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_decoder_peek_remaining() {
        let buf = [1, 2, 3, 4, 5];
        let mut dec = Decoder::new(&buf);

        dec.read_u8().unwrap();
        dec.read_u8().unwrap();

        let remaining = dec.peek_remaining();
        assert_eq!(remaining, &[3, 4, 5]);
    }

    #[test]
    fn test_decoder_skip_underflow() {
        let buf = [1, 2, 3];
        let mut dec = Decoder::new(&buf);

        assert!(dec.skip(10).is_err());
        assert_eq!(dec.position(), 0); // Position unchanged on error
    }

    #[test]
    fn test_decoder_invalid_cipher_suite_header() {
        let buf = [0x01, 0x99]; // Valid version, invalid cipher suite
        let mut dec = Decoder::new(&buf);

        assert!(matches!(
            dec.read_header(),
            Err(DecoderError::UnsupportedCipherSuite(0x99))
        ));
    }

    #[test]
    fn test_decoder_read_bytes_underflow() {
        let buf = [1, 2, 3];
        let mut dec = Decoder::new(&buf);

        assert!(dec.read_bytes(5).is_err());
    }

    #[test]
    fn test_decoder_read_array_underflow() {
        let buf = [1, 2];
        let mut dec = Decoder::new(&buf);

        let result: Result<[u8; 4], _> = dec.read_array();
        assert!(result.is_err());
    }

    #[test]
    fn test_decoder_length_prefixed_underflow() {
        // Length prefix says 100 bytes but only 4 bytes of data
        let buf = [0x64, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut dec = Decoder::new(&buf);

        assert!(dec.read_length_prefixed().is_err());
    }
}
