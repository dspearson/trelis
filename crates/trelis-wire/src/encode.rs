//! Wire format encoding utilities.
//!
//! All multi-byte integers are encoded as little-endian.

use crate::header::Header;

/// Encoder for writing to a byte buffer.
///
/// Provides methods for encoding integers and byte arrays in the
/// canonical Trelis wire format (little-endian).
pub struct Encoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Encoder<'a> {
    /// Creates a new encoder writing to the given buffer.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
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

    /// Returns true if the encoder has space for `n` more bytes.
    #[must_use]
    pub const fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Writes a single byte.
    ///
    /// Returns `None` if the buffer is full.
    pub fn write_u8(&mut self, value: u8) -> Option<()> {
        if self.pos >= self.buf.len() {
            return None;
        }
        self.buf[self.pos] = value;
        self.pos += 1;
        Some(())
    }

    /// Writes a u16 in little-endian format.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_u16(&mut self, value: u16) -> Option<()> {
        if self.remaining() < 2 {
            return None;
        }
        let bytes = value.to_le_bytes();
        self.buf[self.pos..self.pos + 2].copy_from_slice(&bytes);
        self.pos += 2;
        Some(())
    }

    /// Writes a u32 in little-endian format.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_u32(&mut self, value: u32) -> Option<()> {
        if self.remaining() < 4 {
            return None;
        }
        let bytes = value.to_le_bytes();
        self.buf[self.pos..self.pos + 4].copy_from_slice(&bytes);
        self.pos += 4;
        Some(())
    }

    /// Writes a u64 in little-endian format.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_u64(&mut self, value: u64) -> Option<()> {
        if self.remaining() < 8 {
            return None;
        }
        let bytes = value.to_le_bytes();
        self.buf[self.pos..self.pos + 8].copy_from_slice(&bytes);
        self.pos += 8;
        Some(())
    }

    /// Writes a byte slice.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_bytes(&mut self, data: &[u8]) -> Option<()> {
        if self.remaining() < data.len() {
            return None;
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Some(())
    }

    /// Writes a fixed-size byte array.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_array<const N: usize>(&mut self, data: &[u8; N]) -> Option<()> {
        self.write_bytes(data)
    }

    /// Writes a protocol header.
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_header(&mut self, header: &Header) -> Option<()> {
        self.write_bytes(&header.to_bytes())
    }

    /// Writes a length-prefixed byte slice (u32 length prefix).
    ///
    /// Returns `None` if there isn't enough space.
    pub fn write_length_prefixed(&mut self, data: &[u8]) -> Option<()> {
        let len = u32::try_from(data.len()).ok()?;
        self.write_u32(len)?;
        self.write_bytes(data)
    }
}

/// Encodes a u16 to little-endian bytes.
#[must_use]
pub const fn encode_u16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

/// Encodes a u32 to little-endian bytes.
#[must_use]
pub const fn encode_u32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Encodes a u64 to little-endian bytes.
#[must_use]
pub const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_u16() {
        assert_eq!(encode_u16(0x0102), [0x02, 0x01]);
        assert_eq!(encode_u16(0), [0, 0]);
        assert_eq!(encode_u16(0xFFFF), [0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_u32() {
        assert_eq!(encode_u32(0x01020304), [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(encode_u32(0), [0, 0, 0, 0]);
        assert_eq!(encode_u32(0xFFFFFFFF), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_u64() {
        assert_eq!(
            encode_u64(0x0102030405060708),
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn test_encoder_write_u8() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u8(0x01).is_some());
        assert!(enc.write_u8(0x02).is_some());
        assert_eq!(enc.position(), 2);
        assert_eq!(&buf[..2], &[0x01, 0x02]);
    }

    #[test]
    fn test_encoder_write_u32() {
        let mut buf = [0u8; 8];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u32(0x01020304).is_some());
        assert_eq!(enc.position(), 4);
        assert_eq!(&buf[..4], &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_encoder_write_u64() {
        let mut buf = [0u8; 16];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u64(0x0102030405060708).is_some());
        assert_eq!(enc.position(), 8);
        assert_eq!(&buf[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_encoder_write_bytes() {
        let mut buf = [0u8; 8];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_bytes(&[1, 2, 3, 4]).is_some());
        assert_eq!(enc.position(), 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_encoder_overflow() {
        let mut buf = [0u8; 2];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u32(0x01020304).is_none());
        assert_eq!(enc.position(), 0);
    }

    #[test]
    fn test_encoder_header() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);

        let header = Header::new();
        assert!(enc.write_header(&header).is_some());
        assert_eq!(enc.position(), 2);
        assert_eq!(&buf[..2], &[0x01, 0x01]);
    }

    #[test]
    fn test_encoder_length_prefixed() {
        let mut buf = [0u8; 16];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_length_prefixed(&[0xAA, 0xBB, 0xCC]).is_some());
        assert_eq!(enc.position(), 7); // 4 bytes length + 3 bytes data
        assert_eq!(&buf[..7], &[0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_encoder_write_u16() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u16(0x0102).is_some());
        assert_eq!(enc.position(), 2);
        assert_eq!(&buf[..2], &[0x02, 0x01]);
    }

    #[test]
    fn test_encoder_write_u16_overflow() {
        let mut buf = [0u8; 1]; // Only 1 byte
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u16(0x0102).is_none());
        assert_eq!(enc.position(), 0); // Position unchanged on failure
    }

    #[test]
    fn test_encoder_write_array() {
        let mut buf = [0u8; 8];
        let mut enc = Encoder::new(&mut buf);

        let arr: [u8; 4] = [1, 2, 3, 4];
        assert!(enc.write_array(&arr).is_some());
        assert_eq!(enc.position(), 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_encoder_write_u8_overflow() {
        let mut buf = [0u8; 0]; // Empty buffer
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u8(0x42).is_none());
    }

    #[test]
    fn test_encoder_write_u64_overflow() {
        let mut buf = [0u8; 4]; // Only 4 bytes, need 8
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_u64(0x0102030405060708).is_none());
        assert_eq!(enc.position(), 0);
    }

    #[test]
    fn test_encoder_write_bytes_overflow() {
        let mut buf = [0u8; 2];
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_bytes(&[1, 2, 3, 4, 5]).is_none());
        assert_eq!(enc.position(), 0);
    }

    #[test]
    fn test_encoder_remaining() {
        let mut buf = [0u8; 10];
        let mut enc = Encoder::new(&mut buf);

        assert_eq!(enc.remaining(), 10);

        enc.write_u32(0).unwrap();
        assert_eq!(enc.remaining(), 6);

        enc.write_u16(0).unwrap();
        assert_eq!(enc.remaining(), 4);
    }

    #[test]
    fn test_encoder_has_remaining() {
        let mut buf = [0u8; 4];
        let enc = Encoder::new(&mut buf);

        assert!(enc.has_remaining(4));
        assert!(enc.has_remaining(1));
        assert!(!enc.has_remaining(5));
    }

    #[test]
    fn test_encoder_header_overflow() {
        let mut buf = [0u8; 1]; // Only 1 byte, need 2
        let mut enc = Encoder::new(&mut buf);

        let header = Header::new();
        assert!(enc.write_header(&header).is_none());
    }

    #[test]
    fn test_encoder_length_prefixed_overflow() {
        let mut buf = [0u8; 6]; // Need 4 (prefix) + 5 (data) = 9 bytes
        let mut enc = Encoder::new(&mut buf);

        assert!(enc.write_length_prefixed(&[1, 2, 3, 4, 5]).is_none());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod proptests {
    use super::*;
    use crate::decode::{Decoder, decode_u16, decode_u32, decode_u64};
    use proptest::prelude::*;

    proptest! {
        /// Property: Encoding and decoding a u16 should return the original value.
        #[test]
        fn roundtrip_u16(value: u16) {
            let encoded = encode_u16(value);
            let decoded = decode_u16(encoded);
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoding and decoding a u32 should return the original value.
        #[test]
        fn roundtrip_u32(value: u32) {
            let encoded = encode_u32(value);
            let decoded = decode_u32(encoded);
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoding and decoding a u64 should return the original value.
        #[test]
        fn roundtrip_u64(value: u64) {
            let encoded = encode_u64(value);
            let decoded = decode_u64(encoded);
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoder/Decoder roundtrip for u16.
        #[test]
        fn encoder_decoder_roundtrip_u16(value: u16) {
            let mut buf = [0u8; 2];
            let mut enc = Encoder::new(&mut buf);
            enc.write_u16(value).expect("write should succeed");

            let mut dec = Decoder::new(&buf);
            let decoded = dec.read_u16().expect("read should succeed");
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoder/Decoder roundtrip for u32.
        #[test]
        fn encoder_decoder_roundtrip_u32(value: u32) {
            let mut buf = [0u8; 4];
            let mut enc = Encoder::new(&mut buf);
            enc.write_u32(value).expect("write should succeed");

            let mut dec = Decoder::new(&buf);
            let decoded = dec.read_u32().expect("read should succeed");
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoder/Decoder roundtrip for u64.
        #[test]
        fn encoder_decoder_roundtrip_u64(value: u64) {
            let mut buf = [0u8; 8];
            let mut enc = Encoder::new(&mut buf);
            enc.write_u64(value).expect("write should succeed");

            let mut dec = Decoder::new(&buf);
            let decoded = dec.read_u64().expect("read should succeed");
            prop_assert_eq!(decoded, value);
        }

        /// Property: Encoding is deterministic (same input always produces same output).
        #[test]
        fn encoding_deterministic_u16(value: u16) {
            let encoded1 = encode_u16(value);
            let encoded2 = encode_u16(value);
            prop_assert_eq!(encoded1, encoded2);
        }

        /// Property: Encoding is deterministic for u32.
        #[test]
        fn encoding_deterministic_u32(value: u32) {
            let encoded1 = encode_u32(value);
            let encoded2 = encode_u32(value);
            prop_assert_eq!(encoded1, encoded2);
        }

        /// Property: Encoding is deterministic for u64.
        #[test]
        fn encoding_deterministic_u64(value: u64) {
            let encoded1 = encode_u64(value);
            let encoded2 = encode_u64(value);
            prop_assert_eq!(encoded1, encoded2);
        }

        /// Property: Variable-length byte arrays round-trip correctly.
        /// Uses a fixed-size buffer since we're no_std.
        #[test]
        fn roundtrip_bytes(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            // Fixed buffer: 4 bytes for length prefix + max 64 bytes data
            let mut buf = [0u8; 68];
            let mut enc = Encoder::new(&mut buf);
            enc.write_length_prefixed(&data).expect("write should succeed");

            let mut dec = Decoder::new(&buf);
            let decoded = dec.read_length_prefixed().expect("read should succeed");
            prop_assert_eq!(decoded, data.as_slice());
        }

        /// Property: Encoder position advances correctly for u16.
        #[test]
        fn encoder_position_u16(value: u16) {
            let mut buf = [0u8; 4];
            let mut enc = Encoder::new(&mut buf);
            let initial_pos = enc.position();
            enc.write_u16(value).expect("write should succeed");
            prop_assert_eq!(enc.position(), initial_pos + 2);
        }

        /// Property: Encoder position advances correctly for u32.
        #[test]
        fn encoder_position_u32(value: u32) {
            let mut buf = [0u8; 8];
            let mut enc = Encoder::new(&mut buf);
            let initial_pos = enc.position();
            enc.write_u32(value).expect("write should succeed");
            prop_assert_eq!(enc.position(), initial_pos + 4);
        }

        /// Property: Encoder position advances correctly for u64.
        #[test]
        fn encoder_position_u64(value: u64) {
            let mut buf = [0u8; 16];
            let mut enc = Encoder::new(&mut buf);
            let initial_pos = enc.position();
            enc.write_u64(value).expect("write should succeed");
            prop_assert_eq!(enc.position(), initial_pos + 8);
        }

        /// Property: Multiple values roundtrip correctly in sequence.
        #[test]
        fn multiple_values_roundtrip(v16: u16, v32: u32, v64: u64) {
            let mut buf = [0u8; 32];
            {
                let mut enc = Encoder::new(&mut buf);
                enc.write_u16(v16).expect("write u16 should succeed");
                enc.write_u32(v32).expect("write u32 should succeed");
                enc.write_u64(v64).expect("write u64 should succeed");
            }

            let mut dec = Decoder::new(&buf);
            prop_assert_eq!(dec.read_u16().expect("read u16 should succeed"), v16);
            prop_assert_eq!(dec.read_u32().expect("read u32 should succeed"), v32);
            prop_assert_eq!(dec.read_u64().expect("read u64 should succeed"), v64);
        }
    }
}
