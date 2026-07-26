//! CoCoA-SA session state management.
//!
//! A session represents a user's view of a CoCoA group, including:
//! - Their partial tree view
//! - Current epoch and secrets
//! - Message encryption/decryption state

#[cfg(feature = "alloc")]
use alloc::collections::BTreeSet;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::HybridKemKeypair;
use trelis_primitives::aead::{self, AeadKey, Nonce};
use zeroize::Zeroize;

use crate::epoch::Epoch;
use crate::limits::check_size_limits;
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
    /// Known group members, keyed by derived user ID.
    ///
    /// GAP-03 double-join guard. Populated with the creator on `create_group`,
    /// the joiner on `join_group`, each added member on `add_member` /
    /// `process_add`, and pruned on `process_remove`. On a session restored
    /// from a serialised blob only `our_user_id` is known (the leaf owners are
    /// not recoverable from the tree, which stores `last_updater_id`), so the
    /// guard is best-effort across (de)serialisation — its load-bearing value
    /// is on active sessions (OQ-3 residual).
    members: BTreeSet<UserId>,
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

        // GAP-03: the creator is the group's first member.
        let mut members = BTreeSet::new();
        members.insert(our_user_id);

        Ok(Self {
            group_id,
            our_user_id,
            our_leaf_position,
            our_keypair,
            tree,
            epoch,
            transcript_hash,
            members,
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
    // GroupSession join state requires every argument; a builder pattern is
    // deliberately scoped to PrekeyBundle and not used here.
    #[must_use]
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

        // GAP-03: best-effort — a joiner knows its own user ID. The remaining
        // leaf owners are learned as future add/remove commits are processed.
        let mut members = BTreeSet::new();
        members.insert(our_user_id);

        Self {
            group_id,
            our_user_id,
            our_leaf_position: our_position,
            our_keypair,
            tree,
            epoch,
            transcript_hash,
            members,
        }
    }

    /// Restores a session directly at `epoch_number` from a stored epoch secret
    /// (session (de)serialisation, GAP-04b / WR-06).
    ///
    /// Unlike [`join_group`](Self::join_group) followed by repeated
    /// [`advance_epoch`](Self::advance_epoch), this reconstructs the epoch
    /// secrets from the EXACT stored epoch secret and sets the epoch number
    /// WITHOUT re-deriving. Advancing from epoch 0 would move the secret away
    /// (via `h5_epoch_secret`) and corrupt the restored `app_secret` for any
    /// epoch > 0, so a round-tripped session at epoch > 0 could no longer
    /// decrypt any peer's messages. Gated behind `session-serialization` (the
    /// sole consumer is the `trelis-wasm` session deserialiser).
    ///
    /// The message counter starts at 0; the caller restores it via
    /// [`set_message_counter`](Self::set_message_counter). Like `join_group`,
    /// only `our_user_id` is seeded into the member registry (OQ-3 residual).
    #[cfg(feature = "session-serialization")]
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn restore_session(
        group_id: GroupId,
        our_user_id: UserId,
        our_keypair: HybridKemKeypair,
        our_position: u32,
        tree_depth: u32,
        member_count: u32,
        epoch_secret: &[u8; 32],
        transcript_hash: [u8; 32],
        epoch_number: u64,
    ) -> Self {
        let mut tree = PartialTreeView::new(our_position, tree_depth);
        tree.set_member_count(member_count);

        let epoch = Epoch::restore(epoch_secret, transcript_hash, epoch_number);

        let mut members = BTreeSet::new();
        members.insert(our_user_id);

        Self {
            group_id,
            our_user_id,
            our_leaf_position: our_position,
            our_keypair,
            tree,
            epoch,
            transcript_hash,
            members,
        }
    }

    /// Restores a session through the single safe door: the watermark check runs
    /// BEFORE any reconstruction, so this entry cannot be used to roll a session
    /// back below the highest `(epoch, counter)` the caller has already committed
    /// for this identity (RBK-01 / GAP-05). It then delegates to the
    /// byte-unchanged [`restore_session`](Self::restore_session) and
    /// [`set_message_counter`](Self::set_message_counter) — the 52-05 in-object
    /// guard still runs on the reconstructed object (SC2).
    ///
    /// The watermark comparison is lexicographic `(epoch_number, message_counter)`
    /// and rejects strictly-below while accepting equal or above (see
    /// `SessionWatermark::check`).
    ///
    /// # Caller contract
    ///
    /// The `watermark` MUST be the one the caller persisted for THIS identity
    /// `(group_id, our_user_id)`. The crate reconstructs strictly at the blob's
    /// own identity, so a watermark only ever gates the exact `(epoch, counter)`
    /// supplied here — but the caller MUST key its persisted watermark store by
    /// `(group_id, our_user_id)`. Comparing a watermark from a DIFFERENT identity
    /// is a caller error: the 16-byte watermark carries no identity by design,
    /// and identity-binding it is a noted future hardening.
    ///
    /// After the caller emits or serialises, it MUST advance and persist the
    /// watermark to the new `(epoch, counter)` — the `advanced` / `of_session` of
    /// the post-op state — atomically with, or before, releasing the emitted
    /// ciphertext. Accepting an EQUAL `(epoch, counter)` on restore is safe ONLY
    /// because emit advances the persisted watermark past the reloaded blob; a
    /// crash between emit and persist would otherwise re-open the same-counter
    /// re-emit. Route every durable-storage load through this checked door.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MessageCounterTooOld`] if the restore would roll
    /// below the watermark (via `SessionWatermark::check`), plus any error
    /// [`set_message_counter`](Self::set_message_counter) surfaces.
    #[cfg(feature = "session-serialization")]
    #[allow(clippy::too_many_arguments)]
    pub fn restore_session_checked(
        watermark: &crate::session_watermark::SessionWatermark,
        group_id: GroupId,
        our_user_id: UserId,
        our_keypair: HybridKemKeypair,
        our_position: u32,
        tree_depth: u32,
        member_count: u32,
        epoch_secret: &[u8; 32],
        transcript_hash: [u8; 32],
        epoch_number: u64,
        message_counter: u64,
    ) -> Result<CocoaSession> {
        // Reject the rollback BEFORE any reconstruction. Reconstruction emits no
        // ciphertext, but checking first makes this door unusable unsafely.
        watermark.check(epoch_number, message_counter)?;
        let mut s = CocoaSession::restore_session(
            group_id,
            our_user_id,
            our_keypair,
            our_position,
            tree_depth,
            member_count,
            epoch_secret,
            transcript_hash,
            epoch_number,
        );
        // The 52-05 in-object guard still runs on the fresh `0 -> N` forward-set.
        s.set_message_counter(message_counter)?;
        Ok(s)
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

    /// Returns `true` if `id` is a known member of this group.
    ///
    /// GAP-03 double-join guard. Reflects the members this session has learned
    /// about (see the `members` field docs for the best-effort caveat on
    /// restored sessions).
    #[must_use]
    pub fn is_member(&self, id: &UserId) -> bool {
        self.members.contains(id)
    }

    /// Records `id` as a known member (idempotent).
    pub(crate) fn insert_member(&mut self, id: UserId) {
        self.members.insert(id);
    }

    /// Removes `id` from the known-member set (idempotent).
    pub(crate) fn remove_member(&mut self, id: &UserId) {
        self.members.remove(id);
    }

    /// Returns the current epoch's init_secret for serialisation.
    ///
    /// This is needed to properly serialise and restore session state.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        self.epoch.init_secret()
    }

    /// Returns the current epoch secret. Gated behind the
    /// `session-serialization` feature so the raw secret is not on the default
    /// public surface — the sole consumer is the `trelis-wasm` session
    /// serialiser, which enables the feature (GAP-04b / F07 prong b, OQ-4
    /// Option 1). Moving (de)serialisation fully in-crate (OQ-4 Option 3) is the
    /// stronger follow-up.
    ///
    /// Must be read BEFORE any epoch advance — the secret is zeroized when
    /// `EpochSecrets` is dropped during the advance.
    #[cfg(feature = "session-serialization")]
    #[must_use]
    pub fn current_epoch_secret(&self) -> &[u8; 32] {
        self.epoch.secrets().epoch_secret()
    }

    /// Returns the current message counter for serialisation.
    #[must_use]
    pub fn message_counter(&self) -> u64 {
        self.epoch.message_counter()
    }

    /// Sets the message counter (for deserialisation), monotonic-forward only.
    ///
    /// Delegates to [`Epoch::set_message_counter`], which rejects an
    /// intra-epoch regression (a value strictly below the current counter) so a
    /// rolled-back counter cannot re-emit an already-used `(key, nonce)` pair
    /// under XChaCha20-Poly1305.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MessageCounterTooOld`] if `counter` is strictly
    /// less than the current message counter.
    pub fn set_message_counter(&mut self, counter: u64) -> Result<()> {
        self.epoch.set_message_counter(counter)
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
    /// - Each message uses a unique (key, nonce) pair derived from the sender's
    ///   leaf position **and** their local counter, so two members of the same
    ///   group at the same `(epoch, counter)` derive disjoint keys (per-sender
    ///   chains).
    /// - AAD binds ciphertext to `group_id`, `epoch`, `sender_leaf_position`,
    ///   and `counter`. A man-in-the-middle that flips the sender field on
    ///   the wire causes AEAD verification to fail.
    /// - Forward secrecy: past messages cannot be decrypted after epoch advance.
    ///
    /// # Errors
    ///
    /// Returns `EncryptionFailed` if AEAD encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        // DOS-01: reject an oversized plaintext BEFORE any cryptographic work —
        // unconditionally before `aead::encrypt`. The four structural arguments
        // are 0 on this channel path, so only the message-size ceiling applies.
        // Encrypt takes local/trusted plaintext, but the gate is spec-mandated on
        // this path as defence-in-depth and for a uniform pre-crypto entry
        // contract across every `CocoaSession` channel entry.
        check_size_limits(plaintext.len(), 0, 0, 0, 0)?;

        let our_leaf_position = self.our_leaf_position;
        let message_key = self.epoch.next_message_key(our_leaf_position);

        // Construct AAD: group_id || epoch || sender_leaf_position || counter (52 bytes)
        let mut aad = Vec::with_capacity(52);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.epoch.number().to_le_bytes());
        aad.extend_from_slice(&our_leaf_position.to_le_bytes());
        aad.extend_from_slice(&message_key.counter().to_le_bytes());

        // Encrypt
        let aead_key = AeadKey::from_bytes(*message_key.key());
        let aead_nonce = Nonce::from_bytes(*message_key.nonce());
        let ciphertext = aead::encrypt(&aead_key, &aead_nonce, plaintext, &aad)?;

        Ok(EncryptedMessage {
            epoch: self.epoch.number(),
            sender_leaf_position: our_leaf_position,
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
    /// - `DecryptionFailed` if AEAD verification fails (tampered or wrong key,
    ///   including any tampering of the `sender_leaf_position` field, since
    ///   that field is bound into both the KDF inputs and the AAD)
    #[must_use = "the decrypted plaintext must be checked or used"]
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        // DOS-01: reject an oversized ciphertext BEFORE any cryptographic work —
        // before the epoch check and unconditionally before `aead::decrypt`. The
        // four structural arguments are 0 on this channel path, so only the
        // message-size ceiling applies here.
        check_size_limits(message.ciphertext.len(), 0, 0, 0, 0)?;

        // Verify epoch matches
        if message.epoch != self.epoch.number() {
            return Err(CryptoError::EpochMismatch {
                expected: self.epoch.number(),
                received: message.epoch,
            });
        }

        // Get per-sender message key for this counter.
        let message_key = self
            .epoch
            .message_key_for_counter(message.sender_leaf_position, message.counter);

        // Construct AAD: group_id || epoch || sender_leaf_position || counter
        let mut aad = Vec::with_capacity(52);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&message.epoch.to_le_bytes());
        aad.extend_from_slice(&message.sender_leaf_position.to_le_bytes());
        aad.extend_from_slice(&message.counter.to_le_bytes());

        // Decrypt
        let aead_key = AeadKey::from_bytes(*message_key.key());
        let aead_nonce = Nonce::from_bytes(*message_key.nonce());
        aead::decrypt(&aead_key, &aead_nonce, &message.ciphertext, &aad)
    }

    /// Decrypts a historical message using a supplied raw epoch secret.
    ///
    /// Used for history decryption where the session is at a later epoch but we
    /// have the raw epoch secret for an older epoch (delivered via the history array
    /// in sealed_welcome). The message's epoch number and counter are taken from
    /// the [`EncryptedMessage`] fields — the group_id for AAD is taken from this session.
    ///
    /// # Arguments
    ///
    /// * `epoch_secret` - The 32-byte epoch secret for the epoch this message was encrypted in
    /// * `message` - The encrypted message (epoch, counter, ciphertext)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as a byte vector.
    ///
    /// # Errors
    ///
    /// - `DecryptionFailed` if AEAD verification fails (tampered or wrong key)
    #[must_use = "the decrypted plaintext must be checked or used"]
    pub fn decrypt_with_epoch_secret(
        &self,
        epoch_secret: &[u8; 32],
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        use crate::epoch::EpochSecrets;

        // DOS-01: reject an oversized ciphertext BEFORE any cryptographic work —
        // unconditionally before `EpochSecrets::derive` and `aead::decrypt`. The
        // four structural arguments are 0 on this channel path, so only the
        // message-size ceiling applies here.
        check_size_limits(message.ciphertext.len(), 0, 0, 0, 0)?;

        // Derive epoch secrets from the raw epoch secret (same as the sender did)
        let secrets = EpochSecrets::derive(epoch_secret);

        // Derive per-sender message key using the leaf position + counter
        // from the message.
        let message_key = secrets.derive_message_key(message.sender_leaf_position, message.counter);

        // Construct AAD: group_id || epoch || sender_leaf_position || counter
        // (same scheme as decrypt()).
        let mut aad = Vec::with_capacity(52);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&message.epoch.to_le_bytes());
        aad.extend_from_slice(&message.sender_leaf_position.to_le_bytes());
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
        // group_id, our_user_id, our_leaf_position, tree, and members are not
        // secrets (member IDs are derived public identifiers)
    }
}

#[cfg(feature = "alloc")]
impl Drop for CocoaSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An encrypted group message.
///
/// Wire layout (24-byte header + variable ciphertext):
/// `epoch_le_u64 (8) || sender_leaf_position_le_u32 (4) || counter_le_u64 (8) ||
/// ciphertext_len_le_u32 (4) || ciphertext (variable)`
///
/// `sender_leaf_position` was added in v0.5.0 to fix the cross-sender
/// nonce-reuse risk that existed in v0.4.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Epoch number when encrypted.
    pub epoch: u64,
    /// Sender's leaf position in the tree (bound into KDF + AAD).
    pub sender_leaf_position: u32,
    /// Sender's local message counter within their per-sender chain.
    pub counter: u64,
    /// Encrypted ciphertext (includes AEAD tag).
    pub ciphertext: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl EncryptedMessage {
    /// Wire-format header size: `epoch (8) + sender_leaf_position (4) +
    /// counter (8) + ciphertext_len (4)`.
    const HEADER_SIZE: usize = 24;

    /// Serialises the encrypted message.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // The wire format encodes ciphertext length as a u32. A ciphertext
        // larger than u32::MAX would silently truncate. Surface the bug
        // explicitly rather than producing an unparseable encoding.
        debug_assert!(
            u32::try_from(self.ciphertext.len()).is_ok(),
            "EncryptedMessage::to_bytes: ciphertext length exceeds u32 wire-format limit"
        );
        let mut bytes = Vec::with_capacity(Self::HEADER_SIZE + self.ciphertext.len());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.sender_leaf_position.to_le_bytes());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialises an encrypted message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let epoch = u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let sender_leaf_position = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let counter = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let ct_len = u32::from_le_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        ) as usize;

        // Guard against usize overflow on 32-bit targets (e.g. wasm32): on
        // those targets `usize::MAX == u32::MAX`, so a maximal ct_len plus
        // the 24-byte header wraps around and the subsequent length check
        // would pass spuriously, leading to a slice-bounds panic on a
        // malformed input. checked_add returns None on overflow.
        let end = Self::HEADER_SIZE
            .checked_add(ct_len)
            .ok_or(CryptoError::MalformedMessage)?;
        if bytes.len() < end {
            return Err(CryptoError::MalformedMessage);
        }

        let ciphertext = bytes[Self::HEADER_SIZE..end].to_vec();

        Ok(Self {
            epoch,
            sender_leaf_position,
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

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group() {
        let session = create_test_session();

        assert_eq!(session.our_leaf_position(), 0);
        assert_eq!(session.epoch_number(), 0);
        assert_eq!(session.member_count(), 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_empty_fails() {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let result = CocoaSession::create_group(group_id, user_id, keypair, 0, &epoch_secret);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
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

    #[cfg_attr(miri, ignore)]
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

    #[cfg_attr(miri, ignore)]
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

    /// GAP-05 / F09: after a legitimate restore that forward-sets the counter
    /// to N, `encrypt()` derives at N and then advances — it never re-emits a
    /// lower `(leaf, counter)` triple.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypt_after_restore_advances() {
        let mut session = create_test_session();
        session.set_message_counter(10).unwrap();
        assert_eq!(session.message_counter(), 10);

        let encrypted = session.encrypt(b"after restore").unwrap();
        assert_eq!(
            encrypted.counter, 10,
            "encrypt must use the restored counter"
        );
        assert_eq!(
            session.message_counter(),
            11,
            "encrypt must advance past the restored counter"
        );
    }

    /// GAP-05 / F09: the session-level setter delegates the monotonic-forward
    /// guard — a regression is rejected at the `CocoaSession` boundary (the
    /// exact boundary the WASM deserialiser drives), leaving the counter
    /// unchanged.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_session_counter_regression_rejected() {
        let mut session = create_test_session();
        session.set_message_counter(5).unwrap();
        let result = session.set_message_counter(3);
        assert!(matches!(result, Err(CryptoError::MessageCounterTooOld)));
        assert_eq!(session.message_counter(), 5);
    }

    /// GAP-05 / RBK-01: the single safe restore door rejects a strictly-below
    /// `(epoch, counter)` — the cross-invocation rollback — before any
    /// reconstruction, while accepting the honest equal / same-epoch-forward /
    /// higher-epoch reloads. The 52-05 in-object guard still runs on the
    /// reconstructed object (equal is accepted on the fresh `0 -> N` forward-set).
    #[cfg(feature = "session-serialization")]
    #[cfg_attr(miri, ignore)]
    #[test]
    fn restore_session_checked_gates_rollback() {
        use crate::SessionWatermark;

        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let epoch_secret = [0u8; 32];
        let transcript_hash = [0u8; 32];
        let our_position = 0;
        let tree_depth = 1;
        let member_count = 2;

        let wm = SessionWatermark::new(0, 150);

        // (a) strictly-below rollback → rejected before any reconstruction.
        let rolled = CocoaSession::restore_session_checked(
            &wm,
            group_id,
            user_id,
            HybridKemKeypair::generate().unwrap(),
            our_position,
            tree_depth,
            member_count,
            &epoch_secret,
            transcript_hash,
            0,
            50,
        );
        assert!(matches!(rolled, Err(CryptoError::MessageCounterTooOld)));

        // (b) equal → accepted (honest newest-blob reload); counter restored.
        let equal = CocoaSession::restore_session_checked(
            &wm,
            group_id,
            user_id,
            HybridKemKeypair::generate().unwrap(),
            our_position,
            tree_depth,
            member_count,
            &epoch_secret,
            transcript_hash,
            0,
            150,
        )
        .unwrap();
        assert_eq!(equal.message_counter(), 150);

        // (c) same epoch, forward → accepted.
        let forward = CocoaSession::restore_session_checked(
            &wm,
            group_id,
            user_id,
            HybridKemKeypair::generate().unwrap(),
            our_position,
            tree_depth,
            member_count,
            &epoch_secret,
            transcript_hash,
            0,
            200,
        );
        assert!(forward.is_ok());

        // (d) higher epoch dominates (disjoint key space) → accepted.
        let higher = CocoaSession::restore_session_checked(
            &wm,
            group_id,
            user_id,
            HybridKemKeypair::generate().unwrap(),
            our_position,
            tree_depth,
            member_count,
            &epoch_secret,
            transcript_hash,
            1,
            0,
        );
        assert!(higher.is_ok());
    }

    #[test]
    fn test_encrypted_message_serialisation() {
        let message = EncryptedMessage {
            epoch: 42,
            sender_leaf_position: 3,
            counter: 7,
            ciphertext: b"encrypted data".to_vec(),
        };

        let bytes = message.to_bytes();
        let recovered = EncryptedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.epoch, 42);
        assert_eq!(recovered.sender_leaf_position, 3);
        assert_eq!(recovered.counter, 7);
        assert_eq!(recovered.ciphertext, b"encrypted data");
    }

    /// Regression: a malformed message whose declared ciphertext length is
    /// u32::MAX would, with naive `bytes.len() < HEADER + ct_len`, overflow
    /// usize on 32-bit targets (notably wasm32) and either pass the bounds
    /// check spuriously or trigger a slice-bounds panic. The deserialiser
    /// must reject this with MalformedMessage, not panic.
    #[test]
    fn test_encrypted_message_overflow_rejected() {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&0u64.to_le_bytes()); // epoch
        bytes.extend_from_slice(&0u32.to_le_bytes()); // sender_leaf_position
        bytes.extend_from_slice(&0u64.to_le_bytes()); // counter
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // ct_len = 4 GiB
        // No body — length should be flagged before any indexing.

        let result = EncryptedMessage::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::MalformedMessage)));
    }

    #[cfg_attr(miri, ignore)]
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

    /// DOS-01 ordering proof (reproduce-don't-assert): an `EncryptedMessage`
    /// whose ciphertext is BOTH oversized (> `MAX_MESSAGE_SIZE`) AND
    /// crypto-invalid (its AEAD tag cannot authenticate) must be rejected by the
    /// size gate with `MessageTooLarge` BEFORE `aead::decrypt` runs. Absent the
    /// gate this exact input returns `AeadAuthenticationFailed`; that
    /// discrimination is the proof that `check_size_limits` precedes the AEAD
    /// operation. The epoch is set to the session's own epoch so that, without
    /// the gate, control flow would reach `aead::decrypt` rather than being
    /// short-circuited by the epoch check.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decrypt_rejects_oversized_before_aead() {
        let session = create_test_session();

        let oversized = EncryptedMessage {
            epoch: session.epoch_number(),
            sender_leaf_position: 0,
            counter: 0,
            ciphertext: vec![0xFFu8; crate::MAX_MESSAGE_SIZE + 1],
        };

        let result = session.decrypt(&oversized);
        assert!(
            matches!(result, Err(CryptoError::MessageTooLarge)),
            "size gate MUST fire before AEAD; got {result:?}"
        );
    }

    /// DOS-01 (channel, encrypt path): a plaintext larger than
    /// `MAX_MESSAGE_SIZE` must be rejected by the size gate with
    /// `MessageTooLarge` BEFORE `aead::encrypt` runs. Encrypt has no failure
    /// mode on an oversized plaintext absent the gate (AEAD encrypts any
    /// length), so returning `MessageTooLarge` is itself the proof that
    /// `check_size_limits` precedes the AEAD op — the uniform pre-crypto entry
    /// contract, applied as defence-in-depth on the (trusted-plaintext) send
    /// path. The Ok payload is reduced to a bool in the failure message so a RED
    /// run never formats the 64 MiB ciphertext.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypt_rejects_oversized() {
        let mut session = create_test_session();

        let oversized = vec![0u8; crate::MAX_MESSAGE_SIZE + 1];
        let result = session.encrypt(&oversized);
        assert!(
            matches!(result, Err(CryptoError::MessageTooLarge)),
            "size gate MUST reject oversized plaintext before aead::encrypt \
             (encrypt returned Ok={})",
            result.is_ok()
        );
    }

    /// DOS-01 (channel, epoch-secret decrypt path) ordering proof
    /// (reproduce-don't-assert): an `EncryptedMessage` whose ciphertext is BOTH
    /// oversized (> `MAX_MESSAGE_SIZE`) AND crypto-invalid (its AEAD tag cannot
    /// authenticate) must be rejected by the size gate with `MessageTooLarge`
    /// BEFORE `EpochSecrets::derive` / `aead::decrypt` runs. Absent the gate this
    /// exact input returns `AeadAuthenticationFailed` (the raw 0xFF bytes cannot
    /// authenticate under the derived key); that discrimination is the proof that
    /// `check_size_limits` precedes the derive/AEAD path. This path takes no epoch
    /// check (it uses the supplied raw epoch secret), so absent the gate control
    /// flow reaches `aead::decrypt` directly.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_decrypt_with_epoch_secret_rejects_oversized_before_aead() {
        let session = create_test_session();
        let epoch_secret = [0xABu8; 32];

        let oversized = EncryptedMessage {
            epoch: session.epoch_number(),
            sender_leaf_position: 0,
            counter: 0,
            ciphertext: vec![0xFFu8; crate::MAX_MESSAGE_SIZE + 1],
        };

        let result = session.decrypt_with_epoch_secret(&epoch_secret, &oversized);
        assert!(
            matches!(result, Err(CryptoError::MessageTooLarge)),
            "size gate MUST fire before derive/AEAD; got {result:?}"
        );
    }

    #[cfg_attr(miri, ignore)]
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

    #[cfg_attr(miri, ignore)]
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

    #[cfg_attr(miri, ignore)]
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

    /// Regression for the cross-sender nonce-reuse risk that existed in
    /// v0.4. Two members of the same group
    /// at the same epoch both call encrypt() once each, so both derive at
    /// their own local counter = 0. Their ciphertexts MUST NOT share the
    /// `(key, nonce)` pair, which they would have done before per-sender
    /// chains were introduced.
    ///
    /// The post-fix evidence: each member's `EncryptedMessage` carries its
    /// own `sender_leaf_position`, and the derived AEAD key/nonce inside the
    /// session are bound to that position. We verify three things:
    ///   1. The two members report different `sender_leaf_position` values.
    ///   2. The two ciphertexts differ even if the plaintexts are identical.
    ///   3. Each member can decrypt the other member's message (cross-decrypt
    ///      proves the per-sender derivation is symmetric: the receiver re-
    ///      derives using the sender's leaf, not its own).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_two_members_same_counter_distinct_keys() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let transcript = [0x00u8; 32];

        let mut member_at_0 = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &epoch_secret,
        )
        .unwrap();

        let mut member_at_1 = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1, // leaf position 1
            1, // depth 1 for 2 members
            2,
            &epoch_secret,
            transcript,
        );

        // The vulnerability was: same plaintext at counter=0 from two members
        // would have produced identical ciphertext (same key, same nonce, same
        // plaintext → same AEAD output).
        let plaintext = b"identical plaintext from both members";
        let ct_from_0 = member_at_0.encrypt(plaintext).unwrap();
        let ct_from_1 = member_at_1.encrypt(plaintext).unwrap();

        assert_eq!(
            ct_from_0.counter, 0,
            "member_at_0's local counter should start at 0"
        );
        assert_eq!(
            ct_from_1.counter, 0,
            "member_at_1's local counter should start at 0"
        );
        assert_eq!(
            ct_from_0.sender_leaf_position, 0,
            "creator's leaf position should be 0"
        );
        assert_eq!(
            ct_from_1.sender_leaf_position, 1,
            "joiner's leaf position should be 1"
        );

        // Ciphertexts must differ — the heart of the fix.
        assert_ne!(
            ct_from_0.ciphertext, ct_from_1.ciphertext,
            "v0.4 regression: two members at same (epoch, counter) must \
             produce distinct ciphertexts (per-sender chains)"
        );

        // Cross-decrypt: each member can read the other's message because the
        // receiver re-derives the per-sender key from the sender's leaf
        // position carried in the wire metadata.
        let plain_at_1 = member_at_1.decrypt(&ct_from_0).unwrap();
        let plain_at_0 = member_at_0.decrypt(&ct_from_1).unwrap();
        assert_eq!(plain_at_1, plaintext);
        assert_eq!(plain_at_0, plaintext);
    }

    /// Sender-tamper regression: the sender leaf position is bound into the
    /// per-message AAD. If a man-in-the-middle flips that field on the wire (to
    /// e.g. impersonate a different member), AEAD verification MUST fail —
    /// both because the receiver derives a different per-sender key for the
    /// tampered leaf position, and because the AAD includes the (now-mismatched)
    /// leaf position alongside the ciphertext.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_aad_sender_tamper_rejects() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let transcript = [0x00u8; 32];

        let mut member_at_0 = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &epoch_secret,
        )
        .unwrap();

        let member_at_1 = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            1,
            2,
            &epoch_secret,
            transcript,
        );

        let plaintext = b"genuine message from member 0";
        let mut tampered = member_at_0.encrypt(plaintext).unwrap();
        assert_eq!(tampered.sender_leaf_position, 0);

        // Attacker flips the sender field to claim the message came from
        // member 1. Both fields are within the wire-format header and the
        // ciphertext bytes themselves are unchanged.
        tampered.sender_leaf_position = 1;

        let result = member_at_1.decrypt(&tampered);
        assert!(
            matches!(result, Err(CryptoError::AeadAuthenticationFailed)),
            "tampered sender_leaf_position must fail AEAD authentication, got {:?}",
            result
        );
    }

    #[cfg_attr(miri, ignore)]
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

    /// Extended multi-sender variant of `test_two_members_same_counter_distinct_keys`:
    /// three concurrent senders at the same `(epoch, counter)` must produce
    /// pairwise-distinct ciphertexts and each recipient must successfully
    /// decrypt the other two via the wire-carried sender leaf position.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_three_members_same_counter_pairwise_distinct() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let transcript = [0x00u8; 32];

        let mut member_0 = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            3,
            &epoch_secret,
        )
        .unwrap();
        let mut member_1 = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            2,
            3,
            &epoch_secret,
            transcript,
        );
        let mut member_2 = CocoaSession::join_group(
            group_id,
            [0x03u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            2,
            3,
            &epoch_secret,
            transcript,
        );

        let plaintext = b"identical plaintext from three members";
        let ct_0 = member_0.encrypt(plaintext).unwrap();
        let ct_1 = member_1.encrypt(plaintext).unwrap();
        let ct_2 = member_2.encrypt(plaintext).unwrap();

        // All three local counters start at 0; only the per-sender chain
        // disambiguates the derived key.
        assert_eq!(ct_0.counter, 0);
        assert_eq!(ct_1.counter, 0);
        assert_eq!(ct_2.counter, 0);

        // Pairwise distinctness.
        assert_ne!(ct_0.ciphertext, ct_1.ciphertext);
        assert_ne!(ct_0.ciphertext, ct_2.ciphertext);
        assert_ne!(ct_1.ciphertext, ct_2.ciphertext);

        // Cross-decryption: each member can read every other member's message.
        assert_eq!(member_1.decrypt(&ct_0).unwrap(), plaintext);
        assert_eq!(member_2.decrypt(&ct_0).unwrap(), plaintext);
        assert_eq!(member_0.decrypt(&ct_1).unwrap(), plaintext);
        assert_eq!(member_2.decrypt(&ct_1).unwrap(), plaintext);
        assert_eq!(member_0.decrypt(&ct_2).unwrap(), plaintext);
        assert_eq!(member_1.decrypt(&ct_2).unwrap(), plaintext);
    }

    /// Per-sender chain advance: a single sender producing N messages at
    /// counters 0..N MUST derive N distinct ciphertexts (different keys and
    /// nonces at each step), and the receiver MUST be able to decrypt each
    /// one in order without state confusion across the run.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_per_sender_chain_advances_across_many_messages() {
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let transcript = [0x00u8; 32];

        let mut sender = CocoaSession::create_group(
            group_id,
            [0x01u8; 32],
            HybridKemKeypair::generate().unwrap(),
            2,
            &epoch_secret,
        )
        .unwrap();
        let receiver = CocoaSession::join_group(
            group_id,
            [0x02u8; 32],
            HybridKemKeypair::generate().unwrap(),
            1,
            1,
            2,
            &epoch_secret,
            transcript,
        );

        const N: u64 = 8;
        let mut ciphertexts = Vec::with_capacity(N as usize);
        for i in 0..N {
            let plaintext = format!("message {i}");
            let ct = sender.encrypt(plaintext.as_bytes()).unwrap();
            assert_eq!(ct.counter, i, "sender local counter must advance by 1");
            ciphertexts.push((plaintext, ct));
        }

        // All N ciphertext bodies must be pairwise distinct — same plaintext
        // length but different per-step keys / nonces.
        for i in 0..N as usize {
            for j in i + 1..N as usize {
                assert_ne!(
                    ciphertexts[i].1.ciphertext, ciphertexts[j].1.ciphertext,
                    "ciphertext at counter {i} must differ from counter {j}"
                );
            }
        }

        // Receiver decrypts each in sequence.
        for (expected_plaintext, ct) in &ciphertexts {
            let decrypted = receiver.decrypt(ct).unwrap();
            assert_eq!(decrypted, expected_plaintext.as_bytes());
        }
    }
}
