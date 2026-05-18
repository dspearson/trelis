//! BLAKE3-based key derivation with domain separation.
//!
//! This module wraps BLAKE3's `derive_key` function to provide domain-separated
//! key derivation as specified by the Trelis protocol.
//!
//! # Domain Separation Contexts
//!
//! All contexts are immutable `&'static str` values that MUST NOT be changed
//! after protocol deployment. Per Spec Section 14, Table 14.1:
//!
//! ## Core Protocol Contexts
//! - `"trelis-hybrid-kem-v1"` - Hybrid KEM shared secret combination
//! - `"trelis-session-v1"` - X3DH-PQ session key derivation
//! - `"trelis-pq-ratchet-root-v1"` - KEM ratchet root key derivation
//! - `"trelis-pq-ratchet-message-v1"` - KEM ratchet message key derivation
//! - `"trelis-ratchet-nonce-v1"` - Hedged nonce derivation
//! - `"trelis-safety-number-v1"` - Safety number fingerprint
//!
//! ## Signature Contexts
//! - `"trelis-sig-prekey-bundle-v1"` - Pre-key bundle signature prehash
//! - `"trelis-sig-ratchet-message-v1"` - Per-message ratchet signatures
//! - `"trelis-sig-cocoa-update-v1"` - CoCoA tree update signatures
//! - `"trelis-sig-safety-number-v1"` - Safety number attestation
//! - `"trelis-sig-device-attest-v1"` - Device key attestation
//!
//! ## Device Key Contexts
//! - `"trelis-device-seed-v1"` - Device seed from hardware entropy
//! - `"trelis-device-identity-key-v1"` - Device identity key derivation
//! - `"trelis-device-signing-key-v1"` - Device signing key derivation
//! - `"trelis-bundle-wrap-v1"` - Device key wrap
//!
//! ## Recovery Contexts
//! - `"trelis-recovery-ed448-v1"` - Recovery keypair Ed448 component
//! - `"trelis-recovery-mldsa-v1"` - Recovery keypair ML-DSA-65 component
//! - `"trelis-recovery-x448-v1"` - Recovery keypair X448 component
//! - `"trelis-recovery-sntrup-v1"` - Recovery keypair sntrup761 component
//! - `"trelis-recovery-key-attest-v1"` - Recovery key attestation
//! - `"trelis-recovery-notice-v1"` - Recovery notice signatures
//! - `"trelis-recovery-escrow-v1"` - Recovery key escrow
//!
//! ## Other Contexts
//! - `"trelis-compromise-notice-v1"` - Compromise notice signature
//! - `"trelis-mldsa-hedge-v1"` - Hedged ML-DSA-65 signing
//! - `"trelis-attachment-key-v1"` - Attachment encryption keys
//! - `"trelis-history-sync-v1"` - History sync threads
//! - `"trelis-safety-number-sync-v1"` - Safety number sync
//! - `"trelis-warrant-auth-v1"` - Lawful intercept warrant auth
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

// ============================================================================
// Domain Separation Context Constants
// ============================================================================
//
// These context strings provide cryptographic domain separation for all
// key derivation operations. They MUST NOT be changed after protocol deployment.

/// Context for hybrid KEM shared secret combination.
pub const HYBRID_KEM_CONTEXT: &str = "trelis-hybrid-kem-v1";

/// Context for X3DH-PQ session key derivation.
pub const SESSION_CONTEXT: &str = "trelis-session-v1";

/// Context for double ratchet root key derivation.
pub const RATCHET_ROOT_CONTEXT: &str = "trelis-pq-ratchet-root-v1";

/// Context for double ratchet message key derivation.
pub const RATCHET_MESSAGE_CONTEXT: &str = "trelis-pq-ratchet-message-v1";

/// Context for hedged nonce derivation.
pub const RATCHET_NONCE_CONTEXT: &str = "trelis-ratchet-nonce-v1";

/// Context for safety number fingerprint.
pub const SAFETY_NUMBER_CONTEXT: &str = "trelis-safety-number-v1";

/// Context for pre-key bundle signature prehash.
pub const PREKEY_BUNDLE_SIG_CONTEXT: &str = "trelis-sig-prekey-bundle-v1";

/// Context for device key wrap.
pub const BUNDLE_WRAP_CONTEXT: &str = "trelis-bundle-wrap-v1";

/// Context for recovery keypair Ed448 component derivation.
///
/// Used when deriving the classical (Ed448) portion of a recovery identity
/// keypair from a recovery seed.
pub const RECOVERY_ED448_CONTEXT: &str = "trelis-recovery-ed448-v1";

/// Context for recovery keypair ML-DSA-65 component derivation.
///
/// Used when deriving the post-quantum (ML-DSA-65) portion of a recovery
/// identity keypair from a recovery seed.
pub const RECOVERY_MLDSA_CONTEXT: &str = "trelis-recovery-mldsa-v1";

/// Context for compromise notice signatures.
///
/// Used as the domain separator when signing a `CompromiseNotice` message
/// to announce that a key has been compromised.
pub const COMPROMISE_NOTICE_CONTEXT: &str = "trelis-compromise-notice-v1";

// ============================================================================
// Signature Context Constants (Spec Section 14, Table 14.1)
// ============================================================================

/// Context for per-message ratchet signatures.
///
/// Used when signing individual ratchet messages for authentication.
pub const SIG_RATCHET_MESSAGE_CONTEXT: &str = "trelis-sig-ratchet-message-v1";

/// Context for CoCoA tree update signatures.
///
/// Used when signing CoCoA group key agreement update operations.
pub const SIG_COCOA_UPDATE_CONTEXT: &str = "trelis-sig-cocoa-update-v1";

/// Context for safety number attestation signatures.
///
/// Used when signing safety number verification attestations.
pub const SIG_SAFETY_NUMBER_CONTEXT: &str = "trelis-sig-safety-number-v1";

/// Context for device key attestation signatures.
///
/// Used when a device signs an attestation about its keys.
pub const SIG_DEVICE_ATTEST_CONTEXT: &str = "trelis-sig-device-attest-v1";

// ============================================================================
// Device Key Derivation Contexts (Spec Section 14.3)
// ============================================================================

/// Context for device seed derivation from hardware entropy.
///
/// Used to derive a device-specific seed from hardware random sources.
pub const DEVICE_SEED_CONTEXT: &str = "trelis-device-seed-v1";

/// Context for device identity key derivation.
///
/// Used to derive the device's identity key from the device seed.
pub const DEVICE_IDENTITY_KEY_CONTEXT: &str = "trelis-device-identity-key-v1";

/// Context for device signing key derivation.
///
/// Used to derive the device's signing key from the device seed.
pub const DEVICE_SIGNING_KEY_CONTEXT: &str = "trelis-device-signing-key-v1";

// ============================================================================
// Additional Recovery Contexts (Spec Appendix C)
// ============================================================================

/// Context for recovery key attestation.
///
/// Used when attesting to the validity of a recovery key.
pub const RECOVERY_KEY_ATTEST_CONTEXT: &str = "trelis-recovery-key-attest-v1";

/// Context for recovery notice signatures.
///
/// Used when signing recovery notice messages.
pub const RECOVERY_NOTICE_CONTEXT: &str = "trelis-recovery-notice-v1";

/// Context for recovery keypair X448 component derivation.
///
/// Used when deriving the X448 KEM portion of recovery keys.
pub const RECOVERY_X448_CONTEXT: &str = "trelis-recovery-x448-v1";

/// Context for recovery keypair sntrup761 component derivation.
///
/// Used when deriving the sntrup761 KEM portion of recovery keys.
pub const RECOVERY_SNTRUP_CONTEXT: &str = "trelis-recovery-sntrup-v1";

/// Context for recovery key escrow.
///
/// Used when escrowing recovery keys with trusted parties.
pub const RECOVERY_ESCROW_CONTEXT: &str = "trelis-recovery-escrow-v1";

// ============================================================================
// Hedged Cryptography Contexts (Spec Section 5.3)
// ============================================================================

/// Context for hedged ML-DSA-65 signing.
///
/// Used to combine fresh entropy with message hash for defence against
/// RNG compromise when generating ML-DSA-65 signatures.
pub const MLDSA_HEDGE_CONTEXT: &str = "trelis-mldsa-hedge-v1";

// ============================================================================
// Sync Contexts (Spec Table 14.1)
// ============================================================================

/// Context for history sync threads.
///
/// Used in multi-device message history synchronisation.
pub const HISTORY_SYNC_CONTEXT: &str = "trelis-history-sync-v1";

/// Context for safety number sync.
///
/// Used when synchronising safety number verifications across devices.
pub const SAFETY_NUMBER_SYNC_CONTEXT: &str = "trelis-safety-number-sync-v1";

// ============================================================================
// Lawful Intercept Context (Spec Section 22)
// ============================================================================

/// Context for warrant authorisation signatures.
///
/// Used for cryptographic authorisation of lawful intercept warrants.
pub const WARRANT_AUTH_CONTEXT: &str = "trelis-warrant-auth-v1";

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
#[must_use]
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: BLAKE3 hash is deterministic - same input always produces same output.
        #[test]
        fn hash_is_deterministic(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let hash1 = hash(&input);
            let hash2 = hash(&input);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: BLAKE3 derive_key is deterministic with same context and input.
        #[test]
        fn derive_key_is_deterministic(
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let context = "test-context-for-proptest";
            let key1 = derive_key(context, &input);
            let key2 = derive_key(context, &input);
            prop_assert_eq!(key1, key2);
        }

        /// Property: Different contexts produce different outputs (with high probability).
        #[test]
        fn different_contexts_different_outputs(
            input in proptest::collection::vec(any::<u8>(), 1..256),
            context1 in "[a-z]{5,20}",
            context2 in "[a-z]{5,20}",
        ) {
            prop_assume!(context1 != context2);
            let key1 = derive_key(&context1, &input);
            let key2 = derive_key(&context2, &input);
            prop_assert_ne!(key1, key2);
        }

        /// Property: Different inputs produce different outputs (with high probability).
        #[test]
        fn different_inputs_different_outputs(
            input1 in proptest::collection::vec(any::<u8>(), 1..256),
            input2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(input1 != input2);
            let context = "same-context-for-both";
            let key1 = derive_key(context, &input1);
            let key2 = derive_key(context, &input2);
            prop_assert_ne!(key1, key2);
        }

        /// Property: Hash output is always OUTPUT_SIZE bytes.
        #[test]
        fn hash_output_size_constant(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let h = hash(&input);
            prop_assert_eq!(h.len(), OUTPUT_SIZE);
        }

        /// Property: derive_key output is always OUTPUT_SIZE bytes.
        #[test]
        fn derive_key_output_size_constant(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let context = "test-context";
            let key = derive_key(context, &input);
            prop_assert_eq!(key.len(), OUTPUT_SIZE);
        }

        /// Property: keyed_hash is deterministic.
        #[test]
        fn keyed_hash_is_deterministic(
            key in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tag1 = keyed_hash(&key, &input);
            let tag2 = keyed_hash(&key, &input);
            prop_assert_eq!(tag1, tag2);
        }

        /// Property: Different keys produce different keyed_hash outputs.
        #[test]
        fn different_keys_different_keyed_hash(
            key1 in proptest::array::uniform32(any::<u8>()),
            key2 in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(key1 != key2);
            let tag1 = keyed_hash(&key1, &input);
            let tag2 = keyed_hash(&key2, &input);
            prop_assert_ne!(tag1, tag2);
        }

        /// Property: keyed_hash output is always OUTPUT_SIZE bytes.
        #[test]
        fn keyed_hash_output_size_constant(
            key in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tag = keyed_hash(&key, &input);
            prop_assert_eq!(tag.len(), OUTPUT_SIZE);
        }

        /// Property: DerivedKey wrapper preserves key bytes.
        #[test]
        fn derived_key_wrapper_preserves_bytes(
            input in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let context = "wrapper-test";
            let key = DerivedKey::derive(context, &input);
            let raw = derive_key(context, &input);
            prop_assert_eq!(*key.as_bytes(), raw);
        }

        /// Property: DerivedKey into_bytes returns same bytes as as_bytes.
        #[test]
        fn derived_key_into_bytes_consistent(
            input in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let context = "into-bytes-test";
            let key = DerivedKey::derive(context, &input);
            let expected = *key.as_bytes();
            let actual = key.into_bytes();
            prop_assert_eq!(actual, expected);
        }

        /// Property: hash of different inputs produces different outputs.
        #[test]
        fn hash_different_inputs_different_outputs(
            input1 in proptest::collection::vec(any::<u8>(), 1..256),
            input2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(input1 != input2);
            let hash1 = hash(&input1);
            let hash2 = hash(&input2);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Empty input produces valid output.
        #[test]
        fn empty_input_valid_output(_dummy: u8) {
            // Empty input should not panic and should produce valid 32-byte output
            let h = hash(b"");
            prop_assert_eq!(h.len(), OUTPUT_SIZE);

            let key = derive_key("context", b"");
            prop_assert_eq!(key.len(), OUTPUT_SIZE);
        }

        /// Property: Context string affects output even with empty input.
        #[test]
        fn context_affects_empty_input(
            context1 in "[a-z]{5,20}",
            context2 in "[a-z]{5,20}",
        ) {
            prop_assume!(context1 != context2);
            let key1 = derive_key(&context1, b"");
            let key2 = derive_key(&context2, b"");
            prop_assert_ne!(key1, key2);
        }
    }
}
