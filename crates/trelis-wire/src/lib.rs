//! Wire format encoding and decoding for the Trelis protocol.
//!
//! This crate provides the canonical wire format for Trelis protocol messages.
//! All multi-byte integers are encoded as little-endian.
//!
//! # Protocol Header
//!
//! All messages begin with a 2-byte header:
//! - Byte 0: Protocol version (`0x01`)
//! - Byte 1: Cipher suite (`0x01` = TRELIS_HYBRID_V1)
//!
//! # no_std Support
//!
//! This crate is fully `no_std` compatible without requiring an allocator.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod constants;
pub mod decode;
pub mod encode;
pub mod header;

pub use constants::*;
pub use decode::{Decoder, DecoderError};
pub use encode::Encoder;
pub use header::{CipherSuite, Header, ProtocolVersion};

pub use trelis_error::{CryptoError, Result};
