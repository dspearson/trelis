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
            app_secret: derive_app_secret(epoch_secret),
            conf_key: derive_conf_key(epoch_secret),
            init_secret: derive_init_secret(epoch_secret),
        }
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

    /// Derives a message key for the given counter.
    #[must_use]
    pub fn derive_message_key(&self, counter: u64) -> MessageKey {
        let key = derive_message_key(&self.app_secret, counter);
        let nonce = derive_message_nonce(&self.app_secret, counter);

        MessageKey {
            key,
            nonce,
            counter,
        }
    }
}

impl core::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochSecrets")
            .field("app_secret", &"[REDACTED]")
            .field("conf_key", &"[REDACTED]")
            .field("init_secret", &"[REDACTED]")
            .finish()
    }
}

/// A message key for encrypting/decrypting a single message.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    /// The 32-byte encryption key.
    key: [u8; 32],
    /// The 24-byte nonce for XChaCha20-Poly1305.
    nonce: [u8; 24],
    /// Message counter (for ordering).
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
            .field("counter", &self.counter)
            .finish()
    }
}

/// State for a single epoch.
#[derive(Debug)]
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

    /// Derives the next message key and increments the counter.
    #[allow(clippy::expect_used)] // u64 overflow is impossible in practice
    pub fn next_message_key(&mut self) -> MessageKey {
        let key = self.secrets.derive_message_key(self.message_counter);
        self.message_counter = self
            .message_counter
            .checked_add(1)
            .expect("message counter overflow");
        key
    }

    /// Derives a message key for a specific counter (for decryption).
    #[must_use]
    pub fn message_key_for_counter(&self, counter: u64) -> MessageKey {
        self.secrets.derive_message_key(counter)
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

        let key0 = secrets.derive_message_key(0);
        let key1 = secrets.derive_message_key(1);

        // Different counters produce different keys
        assert_ne!(key0.key(), key1.key());
        assert_ne!(key0.nonce(), key1.nonce());
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

        let mut epoch = Epoch::initial(&epoch_secret, transcript);

        let key0 = epoch.next_message_key();
        assert_eq!(key0.counter(), 0);
        assert_eq!(epoch.message_counter(), 1);

        let key1 = epoch.next_message_key();
        assert_eq!(key1.counter(), 1);
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
    fn test_message_key_debug_redacted() {
        let secrets = EpochSecrets::derive(&[0x42u8; 32]);
        let key = secrets.derive_message_key(42);
        let debug = format!("{:?}", key);

        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("42")); // Counter is visible
    }
}
