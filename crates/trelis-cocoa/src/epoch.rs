//! Epoch management and secrets for CoCoA-SA.
//!
//! Each epoch represents a group state after a commit. Epochs provide:
//! - Forward secrecy: Old epoch secrets are deleted
//! - Per-message keys: Derived from epoch's app_secret
//! - Confirmation tags: For verifying commit success

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key_schedule::{
    derive_app_secret, derive_conf_key, derive_init_secret, derive_message_key,
    derive_message_nonce,
};

/// Secrets derived for each epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    /// Raw epoch secret — retained for server-side epoch history capture (HIST-01).
    epoch_secret: [u8; 32],
    /// Application secret for message encryption.
    app_secret: [u8; 32],
    /// Confirmation key for commit verification.
    conf_key: [u8; 32],
    /// Init secret for deriving next epoch.
    init_secret: [u8; 32],
}

impl EpochSecrets {
    /// Creates epoch secrets from the epoch secret.
    #[must_use]
    pub fn derive(epoch_secret: &[u8; 32]) -> Self {
        Self {
            epoch_secret: *epoch_secret,
            app_secret: *derive_app_secret(epoch_secret),
            conf_key: *derive_conf_key(epoch_secret),
            init_secret: *derive_init_secret(epoch_secret),
        }
    }

    /// Returns the raw epoch secret. Used by server-side epoch history capture
    /// (HIST-01). Must be read BEFORE any epoch advance — ZeroizeOnDrop clears
    /// this value when EpochSecrets is dropped.
    #[must_use]
    pub fn epoch_secret(&self) -> &[u8; 32] {
        &self.epoch_secret
    }

    /// Returns the app secret.
    #[must_use]
    pub fn app_secret(&self) -> &[u8; 32] {
        &self.app_secret
    }

    /// Returns the confirmation key.
    #[must_use]
    pub fn conf_key(&self) -> &[u8; 32] {
        &self.conf_key
    }

    /// Returns the init secret for next epoch derivation.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        &self.init_secret
    }

    /// Derives a per-sender message key for the given `(sender_leaf_position, counter)`.
    ///
    /// Two senders at the same epoch and same local counter derive disjoint keys
    /// and nonces because `sender_leaf_position` is bound into both KDF inputs.
    /// See `key_schedule::derive_message_key` for the KDF layout.
    #[must_use]
    pub fn derive_message_key(&self, sender_leaf_position: u32, counter: u64) -> MessageKey {
        let key = *derive_message_key(&self.app_secret, sender_leaf_position, counter);
        let nonce = *derive_message_nonce(&self.app_secret, sender_leaf_position, counter);

        MessageKey {
            key,
            nonce,
            sender_leaf_position,
            counter,
        }
    }
}

impl core::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochSecrets")
            .field("epoch_secret", &"[REDACTED]")
            .field("app_secret", &"[REDACTED]")
            .field("conf_key", &"[REDACTED]")
            .field("init_secret", &"[REDACTED]")
            .finish()
    }
}

/// A per-sender message key for encrypting/decrypting a single message.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    /// The 32-byte encryption key.
    key: [u8; 32],
    /// The 24-byte nonce for XChaCha20-Poly1305.
    nonce: [u8; 24],
    /// Sender's leaf position in the tree (bound into key + nonce derivation).
    sender_leaf_position: u32,
    /// Sender's local message counter (for ordering within their chain).
    counter: u64,
}

impl MessageKey {
    /// Returns the encryption key.
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Returns the nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns the sender's leaf position bound into this key.
    #[must_use]
    pub fn sender_leaf_position(&self) -> u32 {
        self.sender_leaf_position
    }

    /// Returns the message counter.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

impl core::fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageKey")
            .field("key", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("sender_leaf_position", &self.sender_leaf_position)
            .field("counter", &self.counter)
            .finish()
    }
}

/// State for a single epoch.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Epoch {
    /// Epoch number (monotonically increasing).
    number: u64,
    /// Epoch secrets.
    secrets: EpochSecrets,
    /// Message counter for this epoch.
    message_counter: u64,
    /// Transcript hash at this epoch.
    transcript_hash: [u8; 32],
}

impl Epoch {
    /// Creates the initial epoch (epoch 0).
    #[must_use]
    pub fn initial(epoch_secret: &[u8; 32], transcript_hash: [u8; 32]) -> Self {
        Self {
            number: 0,
            secrets: EpochSecrets::derive(epoch_secret),
            message_counter: 0,
            transcript_hash,
        }
    }

    /// Creates a new epoch from the previous epoch's init_secret.
    #[must_use]
    #[allow(clippy::expect_used)] // u64 overflow is impossible in practice
    pub fn advance(
        prev_init_secret: &[u8; 32],
        delta_root: &[u8; 32],
        transcript_hash: [u8; 32],
        prev_epoch_number: u64,
    ) -> Self {
        let epoch_secret =
            crate::key_schedule::h5_epoch_secret(prev_init_secret, delta_root, &transcript_hash);

        Self {
            number: prev_epoch_number
                .checked_add(1)
                .expect("epoch counter overflow"),
            secrets: EpochSecrets::derive(&epoch_secret),
            message_counter: 0,
            transcript_hash,
        }
    }

    /// Returns the epoch number.
    #[must_use]
    pub fn number(&self) -> u64 {
        self.number
    }

    /// Returns the epoch secrets.
    #[must_use]
    pub fn secrets(&self) -> &EpochSecrets {
        &self.secrets
    }

    /// Returns the init secret for next epoch derivation.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        self.secrets.init_secret()
    }

    /// Returns the current message counter.
    #[must_use]
    pub fn message_counter(&self) -> u64 {
        self.message_counter
    }

    /// Returns the transcript hash at this epoch.
    #[must_use]
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Derives the next per-sender message key and increments OUR local counter.
    ///
    /// `our_leaf_position` is the local member's leaf position in the tree;
    /// it is bound into both the key and the nonce derivation so that this
    /// member's `(epoch, counter)` chain is disjoint from every other member's.
    #[allow(clippy::expect_used)] // u64 overflow is impossible in practice
    pub fn next_message_key(&mut self, our_leaf_position: u32) -> MessageKey {
        let key = self
            .secrets
            .derive_message_key(our_leaf_position, self.message_counter);
        self.message_counter = self
            .message_counter
            .checked_add(1)
            .expect("message counter overflow");
        key
    }

    /// Derives a per-sender message key for a specific
    /// `(sender_leaf_position, counter)` pair (for decryption). The
    /// `sender_leaf_position` is read from the incoming ciphertext's metadata.
    #[must_use]
    pub fn message_key_for_counter(&self, sender_leaf_position: u32, counter: u64) -> MessageKey {
        self.secrets
            .derive_message_key(sender_leaf_position, counter)
    }

    /// Sets the message counter directly (for deserialization).
    ///
    /// This is more efficient than calling `next_message_key()` in a loop,
    /// and avoids potential overflow issues with large counter values.
    ///
    /// Note: Since key derivation is a pure function of the counter,
    /// there's no need to derive intermediate keys.
    pub fn set_message_counter(&mut self, counter: u64) {
        self.message_counter = counter;
    }

    /// Computes a confirmation tag for a commit.
    #[must_use]
    pub fn compute_confirmation_tag(&self, commit_content: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(self.secrets.conf_key());
        hasher.update(commit_content);
        *hasher.finalize().as_bytes()
    }

    /// Verifies a confirmation tag.
    #[must_use]
    pub fn verify_confirmation_tag(&self, commit_content: &[u8], tag: &[u8; 32]) -> bool {
        let expected = self.compute_confirmation_tag(commit_content);
        // Constant-time comparison
        subtle::ConstantTimeEq::ct_eq(&expected[..], &tag[..]).into()
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // Prove: Epoch::advance always produces an epoch number exactly one greater
    // than prev_epoch_number, for any valid (non-overflowing) input.
    // This is the epoch counter monotonicity invariant: epoch numbers must strictly
    // increase by exactly 1 on each group state advance.
    // The checked_add(1).expect(...) in Epoch::advance will panic on u64::MAX — Kani
    // will detect this and the assume() prevents that case from being considered.
    #[kani::proof]
    #[kani::unwind(1)]
    fn epoch_advance_increments_counter() {
        let prev_epoch_number: u64 = kani::any();
        // Exclude u64::MAX to prevent overflow — the code uses checked_add().expect() which
        // would panic; this is intentional overflow protection, not a bug.
        kani::assume(prev_epoch_number < u64::MAX);
        let prev_init_secret: [u8; 32] = kani::any();
        let delta_root: [u8; 32] = kani::any();
        let transcript_hash: [u8; 32] = kani::any();
        let new_epoch = Epoch::advance(
            &prev_init_secret,
            &delta_root,
            transcript_hash,
            prev_epoch_number,
        );
        assert_eq!(new_epoch.number(), prev_epoch_number + 1);
    }

    // Prove: epoch number after advance is strictly greater than the previous number.
    // This is a weaker corollary of the above but makes the monotonicity property explicit.
    #[kani::proof]
    #[kani::unwind(1)]
    fn epoch_number_is_strictly_monotonic() {
        let prev_epoch_number: u64 = kani::any();
        kani::assume(prev_epoch_number < u64::MAX);
        let prev_init_secret: [u8; 32] = kani::any();
        let delta_root: [u8; 32] = kani::any();
        let transcript_hash: [u8; 32] = kani::any();
        let new_epoch = Epoch::advance(
            &prev_init_secret,
            &delta_root,
            transcript_hash,
            prev_epoch_number,
        );
        assert!(new_epoch.number() > prev_epoch_number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_secrets_derive() {
        let epoch_secret = [0x42u8; 32];
        let secrets = EpochSecrets::derive(&epoch_secret);

        // All secrets should be different
        assert_ne!(secrets.app_secret(), secrets.conf_key());
        assert_ne!(secrets.app_secret(), secrets.init_secret());
        assert_ne!(secrets.conf_key(), secrets.init_secret());
    }

    #[test]
    fn test_message_key_derivation() {
        let epoch_secret = [0x42u8; 32];
        let secrets = EpochSecrets::derive(&epoch_secret);
        let leaf = 0u32;

        let key0 = secrets.derive_message_key(leaf, 0);
        let key1 = secrets.derive_message_key(leaf, 1);

        // Different counters produce different keys (for the same sender).
        assert_ne!(key0.key(), key1.key());
        assert_ne!(key0.nonce(), key1.nonce());
    }

    /// Per-sender chains: same epoch, same counter, different leaf positions
    /// must derive disjoint keys and nonces. Regression guard against the v0.4
    /// cross-sender nonce-reuse risk (audit-notes-impl-gaps §4.2 / COCOA-01).
    #[test]
    fn test_message_key_per_sender_distinct() {
        let epoch_secret = [0x42u8; 32];
        let secrets = EpochSecrets::derive(&epoch_secret);
        let counter = 0u64;

        let key_a = secrets.derive_message_key(0, counter);
        let key_b = secrets.derive_message_key(1, counter);

        assert_ne!(
            key_a.key(),
            key_b.key(),
            "two senders at same counter must derive disjoint keys"
        );
        assert_ne!(
            key_a.nonce(),
            key_b.nonce(),
            "two senders at same counter must derive disjoint nonces"
        );
        assert_eq!(key_a.sender_leaf_position(), 0);
        assert_eq!(key_b.sender_leaf_position(), 1);
    }

    #[test]
    fn test_initial_epoch() {
        let epoch_secret = [0x42u8; 32];
        let transcript = [0x00u8; 32];

        let epoch = Epoch::initial(&epoch_secret, transcript);

        assert_eq!(epoch.number(), 0);
        assert_eq!(epoch.message_counter(), 0);
        assert_eq!(epoch.transcript_hash(), &transcript);
    }

    #[test]
    fn test_epoch_advance() {
        let init_secret = [0x42u8; 32];
        let delta_root = [0x11u8; 32];
        let transcript = [0x22u8; 32];

        let epoch = Epoch::advance(&init_secret, &delta_root, transcript, 5);

        assert_eq!(epoch.number(), 6);
        assert_eq!(epoch.message_counter(), 0);
    }

    #[test]
    fn test_next_message_key_increments() {
        let epoch_secret = [0x42u8; 32];
        let transcript = [0x00u8; 32];
        let our_leaf = 0u32;

        let mut epoch = Epoch::initial(&epoch_secret, transcript);

        let key0 = epoch.next_message_key(our_leaf);
        assert_eq!(key0.counter(), 0);
        assert_eq!(key0.sender_leaf_position(), our_leaf);
        assert_eq!(epoch.message_counter(), 1);

        let key1 = epoch.next_message_key(our_leaf);
        assert_eq!(key1.counter(), 1);
        assert_eq!(key1.sender_leaf_position(), our_leaf);
        assert_eq!(epoch.message_counter(), 2);
    }

    #[test]
    fn test_confirmation_tag() {
        let epoch_secret = [0x42u8; 32];
        let transcript = [0x00u8; 32];

        let epoch = Epoch::initial(&epoch_secret, transcript);

        let content = b"commit data here";
        let tag = epoch.compute_confirmation_tag(content);

        assert!(epoch.verify_confirmation_tag(content, &tag));
        assert!(!epoch.verify_confirmation_tag(b"wrong content", &tag));
    }

    #[test]
    fn test_epoch_secrets_debug_redacted() {
        let secrets = EpochSecrets::derive(&[0x42u8; 32]);
        let debug = format!("{:?}", secrets);

        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42")); // Shouldn't leak actual values
    }

    #[test]
    fn test_epoch_secret_round_trip() {
        let epoch_secret = [0x42u8; 32];
        let secrets = EpochSecrets::derive(&epoch_secret);
        assert_eq!(
            secrets.epoch_secret(),
            &epoch_secret,
            "epoch_secret() must return the exact input passed to derive()"
        );
    }

    #[test]
    fn test_epoch_secrets_debug_redacted_includes_epoch_secret() {
        let secrets = EpochSecrets::derive(&[0x42u8; 32]);
        let debug = format!("{:?}", secrets);
        // epoch_secret field must appear and must not leak the value
        assert!(
            debug.contains("epoch_secret"),
            "debug output missing epoch_secret field name"
        );
        assert!(debug.contains("REDACTED"));
        assert!(
            !debug.contains("42"),
            "debug must not leak actual byte values"
        );
    }

    #[test]
    fn test_message_key_debug_redacted() {
        let secrets = EpochSecrets::derive(&[0x42u8; 32]);
        let key = secrets.derive_message_key(0, 42);
        let debug = format!("{:?}", key);

        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("42")); // Counter is visible
    }
}
