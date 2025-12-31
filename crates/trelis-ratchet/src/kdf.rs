//! Key derivation functions for the KEM Ratchet.
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
/// mixing the current root key with the shared secret from hybrid KEM.
///
/// # Security
///
/// This structure holds sensitive key material and implements [`Zeroize`]
/// to securely clear memory on drop. The message key should be used
/// immediately for encryption/decryption and then zeroized.
///
/// # Key Derivation
///
/// The KDF uses BLAKE3 with domain-separated contexts:
/// - **Root key**: Derived with `trelis-pq-ratchet-root-v1`
/// - **Message key**: Derived with `trelis-pq-ratchet-message-v1`
///
/// Both keys are derived from `root_key || shared_secret`, ensuring
/// that knowledge of one key doesn't compromise the other.
pub struct KdfOutput {
    /// The new root key for the next ratchet step.
    ///
    /// This replaces the current root key after a successful ratchet operation.
    /// It provides forward secrecy: old messages cannot be decrypted even if
    /// this new key is compromised.
    pub new_root_key: [u8; ROOT_KEY_SIZE],
    /// The message key for encrypting/decrypting the current message.
    ///
    /// Used with XChaCha20-Poly1305 for authenticated encryption. Must be
    /// zeroized immediately after use to limit exposure.
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

/// Maximum stack buffer size for KDF input (root_key + shared_secret).
/// 256 bytes covers 32-byte root key + up to 224-byte shared secret,
/// which is more than sufficient for hybrid KEM (typically ~88 bytes).
const KDF_MAX_STACK_INPUT: usize = 256;

/// Derives new root key and message key from current root key and shared secret.
///
/// This is the core KDF function for the KEM Ratchet. It takes:
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
    let total_len = root_key.len() + shared_secret.len();

    // Use stack buffer for typical cases, heap fallback for unusually large inputs
    if total_len <= KDF_MAX_STACK_INPUT {
        // Stack-allocated path (no heap allocation)
        let mut input = [0u8; KDF_MAX_STACK_INPUT];
        input[..32].copy_from_slice(root_key);
        input[32..total_len].copy_from_slice(shared_secret);

        let input_slice = &input[..total_len];

        // Derive keys
        let new_root_key = blake3::derive_key(KDF_ROOT, input_slice);
        let message_key = blake3::derive_key(KDF_MESSAGE, input_slice);

        // Zeroize input material
        input.zeroize();

        KdfOutput {
            new_root_key,
            message_key,
        }
    } else {
        // Heap fallback for unusually large shared secrets
        let mut input = Vec::with_capacity(total_len);
        input.extend_from_slice(root_key);
        input.extend_from_slice(shared_secret);

        let new_root_key = blake3::derive_key(KDF_ROOT, &input);
        let message_key = blake3::derive_key(KDF_MESSAGE, &input);

        input.zeroize();

        KdfOutput {
            new_root_key,
            message_key,
        }
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

    #[test]
    fn test_kdf_rk_heap_fallback() {
        // Test the heap fallback path by using a shared secret larger than KDF_MAX_STACK_INPUT
        // KDF_MAX_STACK_INPUT is 256, root_key is 32 bytes, so we need > 224 bytes
        let root_key = [0x42u8; 32];
        let large_shared_secret = [0xABu8; 300]; // 300 bytes > 224 remaining

        let output = kdf_rk(&root_key, &large_shared_secret);

        // Verify keys are produced correctly
        assert_ne!(output.new_root_key, output.message_key);
        assert_ne!(output.new_root_key, root_key);
        assert_eq!(output.new_root_key.len(), ROOT_KEY_SIZE);
        assert_eq!(output.message_key.len(), MESSAGE_KEY_SIZE);
    }

    #[test]
    fn test_kdf_rk_heap_fallback_deterministic() {
        // Verify heap path is also deterministic
        let root_key = [0x42u8; 32];
        let large_shared_secret = [0xABu8; 300];

        let output1 = kdf_rk(&root_key, &large_shared_secret);
        let output2 = kdf_rk(&root_key, &large_shared_secret);

        assert_eq!(output1.new_root_key, output2.new_root_key);
        assert_eq!(output1.message_key, output2.message_key);
    }

    #[test]
    fn test_kdf_output_zeroize() {
        let root_key = [0x42u8; 32];
        let shared_secret = [0xABu8; 64];

        let mut output = kdf_rk(&root_key, &shared_secret);

        // Verify we have valid keys before zeroizing
        assert_ne!(output.new_root_key, [0u8; 32]);
        assert_ne!(output.message_key, [0u8; 32]);

        // Zeroize and verify
        output.zeroize();
        assert_eq!(output.new_root_key, [0u8; 32]);
        assert_eq!(output.message_key, [0u8; 32]);
    }
}
