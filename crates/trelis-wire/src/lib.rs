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
// `unreadable_literal` is allowed because the entire purpose of this crate
// is to encode wire-format magic numbers (cipher-suite identifiers, version
// constants, tag bytes); rewriting these literals with `_` separators
// would break the spec-to-source mapping.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal
)]
// Tests silence the full pedantic set.
#![cfg_attr(test, allow(clippy::pedantic))]

pub mod constants;
pub mod decode;
pub mod encode;
pub mod header;

pub use constants::*;
pub use decode::{Decoder, DecoderError, decode_u16, decode_u32, decode_u64};
pub use encode::{Encoder, encode_u16, encode_u32, encode_u64};
pub use header::{CipherSuite, Header, ProtocolVersion};

pub use trelis_error::{CryptoError, Result};
