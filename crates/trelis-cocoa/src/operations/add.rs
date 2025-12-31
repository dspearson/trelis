//! Member addition (CGKA.Add).
//!
//! Adds a new member to an existing CoCoA group.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::{HybridPreKeyBundle, HybridSignature};

use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
use crate::session::CocoaSession;
use crate::tree::{NodeIndex, PartialTreeView};
use crate::{GroupId, UserId};

use super::Welcome;

/// Commit message for adding a member.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct AddCommit {
    /// Group identifier.
    pub group_id: GroupId,
    /// New member's user identifier.
    pub new_member_id: UserId,
    /// New member's assigned leaf position.
    pub new_leaf_position: u32,
    /// Epoch after this commit.
    pub epoch: u64,
    /// Path updates for the adding member.
    pub path_updates: Vec<PathUpdate>,
    /// Signature over the commit.
    pub signature: HybridSignature,
    /// Round hash for this commit.
    pub round_hash: [u8; 32],
}

/// A single path node update in a commit.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct PathUpdate {
    /// Node being updated.
    pub node_index: NodeIndex,
    /// New public key at this node.
    pub new_public_key: Vec<u8>,
    /// Parent hash for this node.
    pub parent_hash: ([u8; 32], [u8; 32]),
    /// Encrypted seeds for recipients.
    pub encrypted_seeds: Vec<EncryptedSeed>,
}

/// An encrypted seed for a specific recipient.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct EncryptedSeed {
    /// Recipient leaf position.
    pub recipient_position: u32,
    /// Encapsulation.
    pub encapsulation: Vec<u8>,
    /// Encrypted seed.
    pub ciphertext: Vec<u8>,
}

/// Adds a member to the group.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `new_member_bundle` - Pre-key bundle of the new member
/// * `new_member_id` - User ID of the new member
///
/// # Returns
///
/// A tuple of (add commit for broadcast, welcome message for new member).
#[cfg(feature = "alloc")]
pub fn add_member(
    session: &mut CocoaSession,
    _new_member_bundle: &HybridPreKeyBundle,
    new_member_id: UserId,
) -> Result<(AddCommit, Welcome)> {
    // Find next available leaf position
    let new_position = session.member_count();

    // Check if tree needs to grow
    let current_depth = session.tree().tree_depth();
    let required_depth = PartialTreeView::depth_for_members(new_position + 1);

    if required_depth > current_depth {
        // Tree needs to grow - this would involve restructuring
        // For now, we'll work with the existing structure
    }

    // Update member count
    session.tree_mut().set_member_count(new_position + 1);

    // Compute round hash
    let root_label = [0u8; 32]; // Would compute from tree state
    let round_hash = h3_round_hash(&root_label, &[], &[new_member_id]);

    // Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // In a full implementation, we would:
    // 1. Generate new keys for our path
    // 2. Encrypt seeds to resolution sets
    // 3. Sign the commit
    // 4. Create welcome message with encrypted group state

    let commit = AddCommit {
        group_id: *session.group_id(),
        new_member_id,
        new_leaf_position: new_position,
        epoch: session.epoch_number() + 1,
        path_updates: Vec::new(), // Would contain actual updates
        signature: create_placeholder_signature()?,
        round_hash,
    };

    let welcome = Welcome {
        group_id: *session.group_id(),
        epoch: session.epoch_number() + 1,
        leaf_position: new_position,
        tree_depth: required_depth.max(current_depth),
        member_count: new_position + 1,
        encrypted_info: Vec::new(),
        encapsulation: Vec::new(),
    };

    // Advance epoch
    let delta_root = [0u8; 32]; // Would be derived from path seeds
    session.advance_epoch(&delta_root, new_transcript);

    Ok((commit, welcome))
}

/// Processes an add commit from another member.
#[cfg(feature = "alloc")]
pub fn process_add(session: &mut CocoaSession, commit: &AddCommit) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Verify signature (would verify against adder's identity key)
    // verify_commit_signature(&commit)?;

    // Update tree with new member
    session
        .tree_mut()
        .set_member_count(commit.new_leaf_position + 1);

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
    // In real implementation, would sign with identity key
    let identity = trelis_hybrid::HybridIdentityKeypair::generate()?;
    let sig = identity.sign(b"placeholder")?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair, HybridOneTimeKeyPair};

    fn create_test_session() -> CocoaSession {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap()
    }

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    #[test]
    fn test_add_member() {
        let mut session = create_test_session();
        assert_eq!(session.member_count(), 1);

        let new_identity = HybridIdentityKeypair::generate().unwrap();
        let new_bundle = create_test_bundle(&new_identity);
        let new_user_id = [0x02u8; 32];

        let (commit, welcome) = add_member(&mut session, &new_bundle, new_user_id).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(commit.new_leaf_position, 1);
        assert_eq!(welcome.leaf_position, 1);
    }

    #[test]
    fn test_process_add() {
        let mut session = create_test_session();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
        };

        process_add(&mut session, &commit).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.epoch_number(), 1);
    }

    #[test]
    fn test_process_add_wrong_group() {
        let mut session = create_test_session();

        let commit = AddCommit {
            group_id: [0xFFu8; 32], // Wrong group
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
        };

        let result = process_add(&mut session, &commit);
        assert!(result.is_err());
    }
}
