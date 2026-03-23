//! CoCoA-SA session state management.
//!
//! A session represents a user's view of a CoCoA group, including:
//! - Their partial tree view
//! - Current epoch and secrets
//! - Message encryption/decryption state

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::HybridKemKeypair;
use trelis_primitives::aead::{self, AeadKey, Nonce};
use zeroize::Zeroize;

use crate::epoch::Epoch;
use crate::tree::PartialTreeView;
use crate::{GroupId, UserId};

/// A CoCoA-SA session representing a user's participation in a group.
#[cfg(feature = "alloc")]
pub struct CocoaSession {
    /// Group identifier.
    group_id: GroupId,
    /// Our user identifier.
    our_user_id: UserId,
    /// Our position in the tree (leaf index).
    our_leaf_position: u32,
    /// Our current hybrid KEM keypair.
    our_keypair: HybridKemKeypair,
    /// Partial tree view (our path + resolved co-path).
    tree: PartialTreeView,
    /// Current epoch.
    epoch: Epoch,
    /// Transcript hash chain.
    transcript_hash: [u8; 32],
}

#[cfg(feature = "alloc")]
impl CocoaSession {
    /// Creates a new session for a group creator.
    ///
    /// # Arguments
    ///
    /// * `group_id` - Unique identifier for the group
    /// * `our_user_id` - Our user identifier
    /// * `our_keypair` - Our hybrid KEM keypair
    /// * `initial_members` - Number of initial members (including us)
    /// * `epoch_secret` - Initial epoch secret from X3DH or group creation
    pub fn create_group(
        group_id: GroupId,
        our_user_id: UserId,
        our_keypair: HybridKemKeypair,
        initial_members: u32,
        epoch_secret: &[u8; 32],
    ) -> Result<Self> {
        if initial_members == 0 {
            return Err(CryptoError::InvalidGroupSize);
        }

        let tree_depth = PartialTreeView::depth_for_members(initial_members);
        let our_leaf_position = 0; // Creator is always at position 0

        let mut tree = PartialTreeView::new(our_leaf_position, tree_depth);
        tree.set_member_count(initial_members);

        // Initial transcript hash
        let transcript_hash = [0u8; 32];
        let epoch = Epoch::initial(epoch_secret, transcript_hash);

        Ok(Self {
            group_id,
            our_user_id,
            our_leaf_position,
            our_keypair,
            tree,
            epoch,
            transcript_hash,
        })
    }

    /// Joins an existing group via a welcome message.
    ///
    /// # Arguments
    ///
    /// * `group_id` - Group identifier
    /// * `our_user_id` - Our user identifier
    /// * `our_keypair` - Our hybrid KEM keypair
    /// * `our_position` - Our assigned leaf position
    /// * `tree_depth` - Depth of the tree
    /// * `member_count` - Current member count
    /// * `epoch_secret` - Epoch secret from welcome message
    /// * `transcript_hash` - Current transcript hash
    ///
    /// # Note
    ///
    /// The joining member starts at epoch 0. To join at a specific epoch,
    /// call `advance_epoch()` after joining to synchronise with the group.
    #[allow(clippy::too_many_arguments)]
    pub fn join_group(
        group_id: GroupId,
        our_user_id: UserId,
        our_keypair: HybridKemKeypair,
        our_position: u32,
        tree_depth: u32,
        member_count: u32,
        epoch_secret: &[u8; 32],
        transcript_hash: [u8; 32],
    ) -> Self {
        let mut tree = PartialTreeView::new(our_position, tree_depth);
        tree.set_member_count(member_count);

        let epoch = Epoch::initial(epoch_secret, transcript_hash);

        Self {
            group_id,
            our_user_id,
            our_leaf_position: our_position,
            our_keypair,
            tree,
            epoch,
            transcript_hash,
        }
    }

    /// Returns the group identifier.
    #[must_use]
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Returns our user identifier.
    #[must_use]
    pub fn our_user_id(&self) -> &UserId {
        &self.our_user_id
    }

    /// Returns our leaf position in the tree.
    #[must_use]
    pub fn our_leaf_position(&self) -> u32 {
        self.our_leaf_position
    }

    /// Returns a reference to our keypair.
    #[must_use]
    pub fn our_keypair(&self) -> &HybridKemKeypair {
        &self.our_keypair
    }

    /// Returns a reference to our tree view.
    #[must_use]
    pub fn tree(&self) -> &PartialTreeView {
        &self.tree
    }

    /// Returns a mutable reference to our tree view.
    pub fn tree_mut(&mut self) -> &mut PartialTreeView {
        &mut self.tree
    }

    /// Returns the current epoch number.
    #[must_use]
    pub fn epoch_number(&self) -> u64 {
        self.epoch.number()
    }

    /// Returns the current transcript hash.
    #[must_use]
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Returns the member count.
    #[must_use]
    pub fn member_count(&self) -> u32 {
        self.tree.member_count()
    }

    /// Returns the current epoch's init_secret for serialisation.
    ///
    /// This is needed to properly serialise and restore session state.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        self.epoch.init_secret()
    }

    /// Returns the current epoch secret. Used by server-side epoch history capture
    /// (HIST-01/HIST-03). Must be read BEFORE any epoch advance — the secret is
    /// zeroized when EpochSecrets is dropped during the advance.
    #[must_use]
    pub fn current_epoch_secret(&self) -> &[u8; 32] {
        self.epoch.secrets().epoch_secret()
    }

    /// Returns the current message counter for serialisation.
    #[must_use]
    pub fn message_counter(&self) -> u64 {
        self.epoch.message_counter()
    }

    /// Sets the message counter (for deserialisation).
    ///
    /// This directly sets the counter without deriving intermediate keys,
    /// which is both more efficient and avoids potential overflow issues.
    pub fn set_message_counter(&mut self, counter: u64) {
        self.epoch.set_message_counter(counter);
    }

    /// Encrypts a message for the group.
    ///
    /// Uses the current epoch's message key derived from the epoch secret.
    /// Each call advances the message counter, generating a unique key and
    /// nonce for each message.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message content to encrypt
    ///
    /// # Returns
    ///
    /// An [`EncryptedMessage`] containing the epoch, counter, and ciphertext.
    ///
    /// # Security
    ///
    /// - Each message uses a unique (key, nonce) pair derived from counter
    /// - AAD binds ciphertext to group_id, epoch, and counter
    /// - Forward secrecy: past messages cannot be decrypted after epoch advance
    ///
    /// # Errors
    ///
    /// Returns `EncryptionFailed` if AEAD encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let message_key = self.epoch.next_message_key();

        // Construct AAD: group_id || epoch || counter
        let mut aad = Vec::with_capacity(48);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.epoch.number().to_le_bytes());
        aad.extend_from_slice(&message_key.counter().to_le_bytes());

        // Encrypt
        let aead_key = AeadKey::from_bytes(*message_key.key());
        let aead_nonce = Nonce::from_bytes(*message_key.nonce());
        let ciphertext = aead::encrypt(&aead_key, &aead_nonce, plaintext, &aad)?;

        Ok(EncryptedMessage {
            epoch: self.epoch.number(),
            counter: message_key.counter(),
            ciphertext,
        })
    }

    /// Decrypts a message from the group.
    ///
    /// Verifies the epoch matches and derives the message key from the counter.
    /// Unlike encrypt, this does not advance state - it's idempotent for the
    /// same message.
    ///
    /// # Arguments
    ///
    /// * `message` - The encrypted message containing epoch, counter, and ciphertext
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as a byte vector.
    ///
    /// # Errors
    ///
    /// - `EpochMismatch` if message epoch doesn't match session epoch
    /// - `DecryptionFailed` if AEAD verification fails (tampered or wrong key)
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        // Verify epoch matches
        if message.epoch != self.epoch.number() {
            return Err(CryptoError::EpochMismatch {
                expected: self.epoch.number(),
                received: message.epoch,
            });
        }

        // Get message key for this counter
        let message_key = self.epoch.message_key_for_counter(message.counter);

        // Construct AAD
        let mut aad = Vec::with_capacity(48);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&message.epoch.to_le_bytes());
        aad.extend_from_slice(&message.counter.to_le_bytes());

        // Decrypt
        let aead_key = AeadKey::from_bytes(*message_key.key());
        let aead_nonce = Nonce::from_bytes(*message_key.nonce());
        aead::decrypt(&aead_key, &aead_nonce, &message.ciphertext, &aad)
    }

    /// Advances to a new epoch after processing a commit.
    pub fn advance_epoch(&mut self, delta_root: &[u8; 32], new_transcript_hash: [u8; 32]) {
        self.epoch = Epoch::advance(
            self.epoch.init_secret(),
            delta_root,
            new_transcript_hash,
            self.epoch.number(),
        );
        self.transcript_hash = new_transcript_hash;
    }

    /// Rotates our keypair (generates new keys).
    pub fn rotate_keypair(&mut self) -> Result<()> {
        self.our_keypair = HybridKemKeypair::generate()?;
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for CocoaSession {
    fn zeroize(&mut self) {
        // Zeroize all sensitive cryptographic material
        self.our_keypair.zeroize();
        self.epoch.zeroize();
        self.transcript_hash.zeroize();
        // group_id, our_user_id, our_leaf_position, and tree are not secrets
    }
}

#[cfg(feature = "alloc")]
impl Drop for CocoaSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An encrypted group message.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Epoch number when encrypted.
    pub epoch: u64,
    /// Message counter within the epoch.
    pub counter: u64,
    /// Encrypted ciphertext (includes AEAD tag).
    pub ciphertext: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl EncryptedMessage {
    /// Serialises the encrypted message.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + 4 + self.ciphertext.len());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialises an encrypted message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(CryptoError::MalformedMessage);
        }

        let epoch = u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let counter = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let ct_len = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        ) as usize;

        if bytes.len() < 20 + ct_len {
            return Err(CryptoError::MalformedMessage);
        }

        let ciphertext = bytes[20..20 + ct_len].to_vec();

        Ok(Self {
            epoch,
            counter,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session() -> CocoaSession {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap()
    }

    #[test]
    fn test_create_group() {
        let session = create_test_session();

        assert_eq!(session.our_leaf_position(), 0);
        assert_eq!(session.epoch_number(), 0);
        assert_eq!(session.member_count(), 1);
    }

    #[test]
    fn test_create_group_empty_fails() {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let result = CocoaSession::create_group(group_id, user_id, keypair, 0, &epoch_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut session = create_test_session();
        let plaintext = b"Hello, CoCoA group!";

        let encrypted = session.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.epoch, 0);
        assert_eq!(encrypted.counter, 0);

        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let mut session = create_test_session();

        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            let encrypted = session.encrypt(plaintext.as_bytes()).unwrap();
            assert_eq!(encrypted.counter, i);

            let decrypted = session.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_epoch_advance() {
        let mut session = create_test_session();
        assert_eq!(session.epoch_number(), 0);

        let delta_root = [0x11u8; 32];
        let new_transcript = [0x22u8; 32];

        session.advance_epoch(&delta_root, new_transcript);

        assert_eq!(session.epoch_number(), 1);
        assert_eq!(session.transcript_hash(), &new_transcript);
    }

    #[test]
    fn test_encrypted_message_serialisation() {
        let message = EncryptedMessage {
            epoch: 42,
            counter: 7,
            ciphertext: b"encrypted data".to_vec(),
        };

        let bytes = message.to_bytes();
        let recovered = EncryptedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.epoch, 42);
        assert_eq!(recovered.counter, 7);
        assert_eq!(recovered.ciphertext, b"encrypted data");
    }

    #[test]
    fn test_wrong_epoch_decryption_fails() {
        let mut session = create_test_session();
        let plaintext = b"test message";

        let encrypted = session.encrypt(plaintext).unwrap();

        // Advance epoch
        session.advance_epoch(&[0x11u8; 32], [0x22u8; 32]);

        // Try to decrypt with wrong epoch
        let result = session.decrypt(&encrypted);
        assert!(matches!(result, Err(CryptoError::EpochMismatch { .. })));
    }

    #[test]
    fn test_join_group() {
        let group_id = [0x42u8; 32];
        let user_id = [0x02u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];
        let transcript = [0xCDu8; 32];

        let session = CocoaSession::join_group(
            group_id,
            user_id,
            keypair,
            5,  // position
            4,  // depth
            10, // members
            &epoch_secret,
            transcript,
        );

        assert_eq!(session.our_leaf_position(), 5);
        assert_eq!(session.member_count(), 10);
        assert_eq!(session.epoch_number(), 0);
    }

    #[test]
    fn test_two_members_same_epoch_secret() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let transcript = [0x00u8; 32];

        // Member 1 creates the group
        let mut member1 = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &epoch_secret,
        )
        .unwrap();

        // Member 2 joins with the same epoch secret (simulating welcome)
        let member2 = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            1, // depth 1 for 2 members
            2,
            &epoch_secret,
            transcript,
        );

        // Both should derive the same message keys
        let plaintext = b"Hello from member 1";
        let encrypted = member1.encrypt(plaintext).unwrap();
        let decrypted = member2.decrypt(&encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_epoch_synchronisation() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];

        let mut member1 = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &epoch_secret,
        )
        .unwrap();

        let mut member2 = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            1,
            2,
            &epoch_secret,
            [0x00u8; 32],
        );

        // Both advance to epoch 1 with the same delta_root
        let delta_root = [0x11u8; 32];
        let new_transcript = [0x22u8; 32];

        member1.advance_epoch(&delta_root, new_transcript);
        member2.advance_epoch(&delta_root, new_transcript);

        // They should still be able to communicate
        let plaintext = b"Epoch 1 message";
        let encrypted = member1.encrypt(plaintext).unwrap();
        let decrypted = member2.decrypt(&encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
        assert_eq!(member1.epoch_number(), 1);
        assert_eq!(member2.epoch_number(), 1);
    }

    #[test]
    fn test_tree_depth_for_different_sizes() {
        // 1 member: depth 0
        let session = CocoaSession::create_group(
            [0x42u8; 32],
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            &[0xABu8; 32],
        )
        .unwrap();
        assert_eq!(session.tree().tree_depth(), 0);
        assert_eq!(session.tree().capacity(), 1);

        // 2 members: depth 1
        let session = CocoaSession::create_group(
            [0x42u8; 32],
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &[0xABu8; 32],
        )
        .unwrap();
        assert_eq!(session.tree().tree_depth(), 1);
        assert_eq!(session.tree().capacity(), 2);

        // 3 members: depth 2 (needs room for 4)
        let session = CocoaSession::create_group(
            [0x42u8; 32],
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            3,
            &[0xABu8; 32],
        )
        .unwrap();
        assert_eq!(session.tree().tree_depth(), 2);
        assert_eq!(session.tree().capacity(), 4);

        // 5 members: depth 3 (needs room for 8)
        let session = CocoaSession::create_group(
            [0x42u8; 32],
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            5,
            &[0xABu8; 32],
        )
        .unwrap();
        assert_eq!(session.tree().tree_depth(), 3);
        assert_eq!(session.tree().capacity(), 8);
    }
}
