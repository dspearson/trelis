//! Member removal (CGKA.Rem).
//!
//! Removes a member from a CoCoA group.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::HybridSignature;

use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
use crate::session::CocoaSession;
use crate::tree::NodeIndex;
use crate::{GroupId, UserId};

use super::add::PathUpdate;

/// Commit message for removing a member.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct RemoveCommit {
    /// Group identifier.
    pub group_id: GroupId,
    /// User ID of removed member.
    pub removed_member_id: UserId,
    /// Leaf position of removed member.
    pub removed_leaf_position: u32,
    /// Epoch after this commit.
    pub epoch: u64,
    /// Path updates (removing member's path becomes blank, remover updates their path).
    pub path_updates: Vec<PathUpdate>,
    /// Signature over the commit.
    pub signature: HybridSignature,
    /// Round hash for this commit.
    pub round_hash: [u8; 32],
}

/// Removes a member from the group.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `removed_member_id` - User ID of member to remove
/// * `removed_position` - Leaf position of member to remove
///
/// # Returns
///
/// A remove commit for broadcast.
#[cfg(feature = "alloc")]
pub fn remove_member(
    session: &mut CocoaSession,
    removed_member_id: UserId,
    removed_position: u32,
) -> Result<RemoveCommit> {
    // Cannot remove ourselves
    if removed_position == session.our_leaf_position() {
        return Err(trelis_error::CryptoError::CannotRemoveSelf);
    }

    // Cannot remove if position is invalid
    if removed_position >= session.member_count() {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    // Mark the removed member's leaf as blank
    let leaf_index = NodeIndex::leaf(session.tree().tree_depth(), removed_position);
    session.tree_mut().blank_node(&leaf_index);

    // In full implementation:
    // 1. Blank all nodes in removed member's path
    // 2. Update our path with new keys
    // 3. Encrypt seeds to new resolution sets (excluding removed member)

    // Compute round hash
    let root_label = [0u8; 32]; // Would compute from tree state
    let round_hash = h3_round_hash(&root_label, &[removed_member_id], &[]);

    // Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    let commit = RemoveCommit {
        group_id: *session.group_id(),
        removed_member_id,
        removed_leaf_position: removed_position,
        epoch: session.epoch_number() + 1,
        path_updates: Vec::new(), // Would contain actual updates
        signature: create_placeholder_signature()?,
        round_hash,
    };

    // Note: member_count stays the same - blank leaves remain in tree
    // This preserves tree structure for other members' indices

    // Advance epoch
    let delta_root = [0u8; 32]; // Would be derived from path seeds
    session.advance_epoch(&delta_root, new_transcript);

    Ok(commit)
}

/// Processes a remove commit from another member.
#[cfg(feature = "alloc")]
pub fn process_remove(session: &mut CocoaSession, commit: &RemoveCommit) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Verify we're not the one being removed
    if commit.removed_leaf_position == session.our_leaf_position() {
        // We've been removed - session is now invalid
        return Err(trelis_error::CryptoError::RemovedFromGroup);
    }

    // Verify signature (would verify against remover's identity key)
    // verify_commit_signature(&commit)?;

    // Blank the removed member's path
    let leaf_index = NodeIndex::leaf(session.tree().tree_depth(), commit.removed_leaf_position);
    session.tree_mut().blank_node(&leaf_index);

    // Process path updates
    // In full implementation, would decrypt seeds and update tree nodes

    // Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &commit.round_hash);

    // Advance epoch
    let delta_root = [0u8; 32]; // Would be derived from received/computed seeds
    session.advance_epoch(&delta_root, new_transcript);

    Ok(())
}

/// Creates a placeholder signature for testing.
#[cfg(feature = "alloc")]
fn create_placeholder_signature() -> Result<HybridSignature> {
    let identity = trelis_hybrid::HybridIdentityKeypair::generate()?;
    let sig = identity.sign(b"placeholder")?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::add::add_member;
    use trelis_hybrid::{
        HybridIdentityKeypair, HybridKemKeypair, HybridOneTimeKeyPair, HybridPreKeyBundle,
    };

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    fn create_test_session_with_members(count: u32) -> CocoaSession {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();

        // Add additional members
        for i in 1..count {
            let member_identity = HybridIdentityKeypair::generate().unwrap();
            let bundle = create_test_bundle(&member_identity);
            let member_id = [i as u8; 32];
            add_member(&mut session, &bundle, member_id).unwrap();
        }

        session
    }

    #[test]
    fn test_remove_member() {
        let mut session = create_test_session_with_members(3);
        assert_eq!(session.member_count(), 3);

        let removed_id = [0x02u8; 32];
        let commit = remove_member(&mut session, removed_id, 2).unwrap();

        assert_eq!(commit.removed_leaf_position, 2);
        // Member count doesn't decrease (blank leaves remain)
        assert_eq!(session.member_count(), 3);
    }

    #[test]
    fn test_cannot_remove_self() {
        let mut session = create_test_session_with_members(2);

        let result = remove_member(&mut session, [0x01u8; 32], 0);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::CannotRemoveSelf)
        ));
    }

    #[test]
    fn test_cannot_remove_invalid_position() {
        let mut session = create_test_session_with_members(2);

        let result = remove_member(&mut session, [0x99u8; 32], 99);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    #[test]
    fn test_process_remove() {
        let mut session = create_test_session_with_members(3);
        let initial_epoch = session.epoch_number();

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
        };

        process_remove(&mut session, &commit).unwrap();

        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[test]
    fn test_process_remove_self_fails() {
        let mut session = create_test_session_with_members(2);

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x01u8; 32],
            removed_leaf_position: 0, // Our position
            epoch: 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
        };

        let result = process_remove(&mut session, &commit);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::RemovedFromGroup)
        ));
    }
}
