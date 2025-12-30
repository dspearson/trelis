//! Key derivation functions for the Double Ratchet.
//!
//! The KDF uses BLAKE3's derive_key function with domain-separated
//! context strings to derive new root keys and message keys.

use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Context string for root key derivation.
pub const KDF_ROOT: &str = "trelis-pq-ratchet-root-v1";

/// Context string for message key derivation.
pub const KDF_MESSAGE: &str = "trelis-pq-ratchet-message-v1";

/// Size of the root key in bytes.
pub const ROOT_KEY_SIZE: usize = 32;

/// Size of the message key in bytes.
pub const MESSAGE_KEY_SIZE: usize = 32;

/// Root key KDF output.
///
/// Contains both the new root key and the message key derived from
/// mixing the current root key with the shared secret.
pub struct KdfOutput {
    /// The new root key for the next ratchet step.
    pub new_root_key: [u8; ROOT_KEY_SIZE],
    /// The message key for encrypting/decrypting the current message.
    pub message_key: [u8; MESSAGE_KEY_SIZE],
}

impl Zeroize for KdfOutput {
    fn zeroize(&mut self) {
        self.new_root_key.zeroize();
        self.message_key.zeroize();
    }
}

impl Drop for KdfOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derives new root key and message key from current root key and shared secret.
///
/// This is the core KDF function for the Double Ratchet. It takes:
/// - The current root key (32 bytes)
/// - A shared secret from hybrid KEM (combined X448 and sntrup761)
///
/// And produces:
/// - A new root key for the next ratchet step
/// - A message key for the current message
///
/// # Arguments
///
/// * `root_key` - Current 32-byte root key
/// * `shared_secret` - Shared secret from hybrid encapsulation/decapsulation
///
/// # Returns
///
/// A tuple of (new_root_key, message_key), both 32 bytes.
#[cfg(feature = "alloc")]
pub fn kdf_rk(root_key: &[u8; 32], shared_secret: &[u8]) -> KdfOutput {
    // Concatenate root_key || shared_secret
    let mut input = Vec::with_capacity(root_key.len() + shared_secret.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(shared_secret);

    // Derive new root key
    let new_root_key = blake3::derive_key(KDF_ROOT, &input);

    // Derive message key
    let message_key = blake3::derive_key(KDF_MESSAGE, &input);

    // Zeroize input material
    input.zeroize();

    KdfOutput {
        new_root_key,
        message_key,
    }
}

/// Derives the initial root key from X3DH-PQ session key.
///
/// This is used once at session establishment to convert the
/// X3DH-PQ shared secret into the initial root key.
///
/// # Arguments
///
/// * `session_key` - 32-byte shared secret from X3DH-PQ
///
/// # Returns
///
/// The initial 32-byte root key.
pub fn derive_initial_root_key(session_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("trelis-ratchet-init-v1", session_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_context_strings() {
        assert_eq!(KDF_ROOT, "trelis-pq-ratchet-root-v1");
        assert_eq!(KDF_MESSAGE, "trelis-pq-ratchet-message-v1");
    }

    #[test]
    fn test_kdf_sizes() {
        assert_eq!(ROOT_KEY_SIZE, 32);
        assert_eq!(MESSAGE_KEY_SIZE, 32);
    }

    #[test]
    fn test_kdf_rk_produces_different_keys() {
        let root_key = [0x42u8; 32];
        let shared_secret = [0xABu8; 64];

        let output = kdf_rk(&root_key, &shared_secret);

        // Root and message keys should be different
        assert_ne!(output.new_root_key, output.message_key);

        // Neither should be the original root key
        assert_ne!(output.new_root_key, root_key);
    }

    #[test]
    fn test_kdf_rk_deterministic() {
        let root_key = [0x42u8; 32];
        let shared_secret = [0xABu8; 64];

        let output1 = kdf_rk(&root_key, &shared_secret);
        let output2 = kdf_rk(&root_key, &shared_secret);

        assert_eq!(output1.new_root_key, output2.new_root_key);
        assert_eq!(output1.message_key, output2.message_key);
    }

    #[test]
    fn test_kdf_rk_different_inputs_different_outputs() {
        let root_key = [0x42u8; 32];
        let shared_secret1 = [0xABu8; 64];
        let shared_secret2 = [0xCDu8; 64];

        let output1 = kdf_rk(&root_key, &shared_secret1);
        let output2 = kdf_rk(&root_key, &shared_secret2);

        assert_ne!(output1.new_root_key, output2.new_root_key);
        assert_ne!(output1.message_key, output2.message_key);
    }

    #[test]
    fn test_derive_initial_root_key() {
        let session_key = [0x42u8; 32];
        let root_key = derive_initial_root_key(&session_key);

        // Should not be the same as input
        assert_ne!(root_key, session_key);
        assert_eq!(root_key.len(), 32);
    }

    #[test]
    fn test_derive_initial_root_key_deterministic() {
        let session_key = [0x42u8; 32];
        let root_key1 = derive_initial_root_key(&session_key);
        let root_key2 = derive_initial_root_key(&session_key);

        assert_eq!(root_key1, root_key2);
    }
}
