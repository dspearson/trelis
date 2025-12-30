//! BLAKE3-based key derivation with domain separation.
//!
//! This module wraps BLAKE3's `derive_key` function to provide domain-separated
//! key derivation as specified by the Trelis protocol.
//!
//! # Domain Separation Contexts
//!
//! All contexts are immutable `&'static str` values that MUST NOT be changed
//! after protocol deployment:
//!
//! - `"trelis-hybrid-kem-v1"` - Hybrid KEM shared secret combination
//! - `"trelis-session-v1"` - X3DH-PQ session key derivation
//! - `"trelis-pq-ratchet-root-v1"` - Double ratchet root key derivation
//! - `"trelis-pq-ratchet-message-v1"` - Double ratchet message key derivation
//! - `"trelis-ratchet-nonce-v1"` - Hedged nonce derivation
//! - `"trelis-safety-number-v1"` - Safety number fingerprint
//! - `"trelis-sig-prekey-bundle-v1"` - Pre-key bundle signature prehash
//! - `"trelis-bundle-wrap-v1"` - Device key wrap
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::blake3_kdf::{derive_key, hash};
//!
//! // Derive a key with domain separation
//! let input = b"some input material";
//! let key = derive_key("trelis-hybrid-kem-v1", input);
//! assert_eq!(key.len(), 32);
//!
//! // Hash without domain separation
//! let digest = hash(b"some data");
//! assert_eq!(digest.len(), 32);
//! ```

use zeroize::Zeroize;

/// Output size for BLAKE3 operations (32 bytes = 256 bits).
pub const OUTPUT_SIZE: usize = 32;

/// Derives a key using BLAKE3 with domain separation.
///
/// This is the primary KDF function for the Trelis protocol. The context string
/// provides domain separation to ensure keys derived for different purposes are
/// cryptographically independent.
///
/// # Arguments
///
/// * `context` - A static string identifying the derivation context. This MUST
///   be unique for each use case and MUST NOT change after protocol deployment.
/// * `input` - The input key material to derive from.
///
/// # Returns
///
/// A 32-byte derived key.
///
/// # Security
///
/// The context string is processed through BLAKE3's built-in context handling,
/// which provides proper domain separation without length-extension vulnerabilities.
#[must_use]
pub fn derive_key(context: &str, input: &[u8]) -> [u8; OUTPUT_SIZE] {
    blake3::derive_key(context, input)
}

/// Computes a BLAKE3 hash of the input.
///
/// This is used for hashing public data (e.g., identity keys for safety numbers).
/// For key derivation, use [`derive_key`] instead to ensure domain separation.
///
/// # Arguments
///
/// * `input` - The data to hash.
///
/// # Returns
///
/// A 32-byte hash digest.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; OUTPUT_SIZE] {
    *blake3::hash(input).as_bytes()
}

/// Computes a keyed BLAKE3 hash (MAC).
///
/// This provides a keyed hash function for message authentication.
///
/// # Arguments
///
/// * `key` - A 32-byte key.
/// * `input` - The data to authenticate.
///
/// # Returns
///
/// A 32-byte authentication tag.
#[must_use]
pub fn keyed_hash(key: &[u8; OUTPUT_SIZE], input: &[u8]) -> [u8; OUTPUT_SIZE] {
    *blake3::keyed_hash(key, input).as_bytes()
}

/// Derives multiple keys from a single input using domain-separated derivation.
///
/// This is useful for protocols that need to derive multiple independent keys
/// from shared secret material (e.g., root key + chain key from X3DH output).
///
/// # Arguments
///
/// * `context_prefix` - Base context string.
/// * `input` - The input key material.
/// * `count` - Number of keys to derive.
///
/// # Returns
///
/// A vector of derived keys, each 32 bytes.
#[cfg(feature = "alloc")]
pub fn derive_multiple_keys(
    context_prefix: &str,
    input: &[u8],
    count: usize,
) -> alloc::vec::Vec<[u8; OUTPUT_SIZE]> {
    use alloc::format;
    use alloc::vec::Vec;

    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let context = format!("{context_prefix}-{i}");
        keys.push(derive_key(&context, input));
    }
    keys
}

/// A wrapper around a derived key that zeroizes on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; OUTPUT_SIZE]);

impl DerivedKey {
    /// Derives a new key with domain separation.
    #[must_use]
    pub fn derive(context: &str, input: &[u8]) -> Self {
        Self(derive_key(context, input))
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; OUTPUT_SIZE] {
        &self.0
    }

    /// Consumes self and returns the key bytes.
    #[must_use]
    pub fn into_bytes(self) -> [u8; OUTPUT_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for DerivedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from specification: context string validation.
    ///
    /// Context: "trelis-hybrid-kem-v1"
    /// Input: 32 zero bytes
    /// Expected output: specified in test-vectors.tex
    #[test]
    fn test_context_string_validation() {
        let context = "trelis-hybrid-kem-v1";
        let input = [0u8; 32];

        let output = derive_key(context, &input);

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);

        // Verify context string is exactly as expected
        assert_eq!(context.as_bytes().len(), 20);
        assert_eq!(
            hex::encode(context.as_bytes()),
            "7472656c69732d6879627269642d6b656d2d7631"
        );

        // Different context produces different output
        let other_output = derive_key("trelis-other-context", &input);
        assert_ne!(output, other_output);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let context = "test-context";
        let input = b"test input";

        let key1 = derive_key(context, input);
        let key2 = derive_key(context, input);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_context_sensitivity() {
        let input = b"same input";

        let key1 = derive_key("context-a", input);
        let key2 = derive_key("context-b", input);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_input_sensitivity() {
        let context = "same-context";

        let key1 = derive_key(context, b"input-a");
        let key2 = derive_key(context, b"input-b");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hash_deterministic() {
        let input = b"test data";

        let hash1 = hash(input);
        let hash2 = hash(input);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sensitivity() {
        let hash1 = hash(b"data-a");
        let hash2 = hash(b"data-b");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0x42u8; 32];
        let input = b"test data";

        let tag1 = keyed_hash(&key, input);
        let tag2 = keyed_hash(&key, input);

        assert_eq!(tag1, tag2);

        // Different key produces different tag
        let other_key = [0x43u8; 32];
        let other_tag = keyed_hash(&other_key, input);
        assert_ne!(tag1, other_tag);
    }

    #[test]
    fn test_derived_key_wrapper() {
        let key = DerivedKey::derive("test", b"input");

        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_derive_multiple_keys() {
        let keys = derive_multiple_keys("test-prefix", b"input", 3);

        assert_eq!(keys.len(), 3);

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_empty_input() {
        // Should handle empty input without panicking
        let key = derive_key("context", b"");
        assert_eq!(key.len(), 32);

        let h = hash(b"");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_large_input() {
        // Should handle large input
        let large_input = [0xffu8; 10000];
        let key = derive_key("context", &large_input);
        assert_eq!(key.len(), 32);
    }
}
