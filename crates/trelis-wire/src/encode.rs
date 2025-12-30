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
        assert_eq!(
            &buf[..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
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
}
