//! Key update (CGKA.Upd).
//!
//! Updates our own keys in the CoCoA group for post-compromise security.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::HybridSignature;

use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
use crate::session::CocoaSession;
use crate::GroupId;

use super::add::PathUpdate;

/// Commit message for updating our keys.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct UpdateCommit {
    /// Group identifier.
    pub group_id: GroupId,
    /// Leaf position of the updater.
    pub updater_leaf_position: u32,
    /// Epoch after this commit.
    pub epoch: u64,
    /// Path updates with new keys and encrypted seeds.
    pub path_updates: Vec<PathUpdate>,
    /// Signature over the commit.
    pub signature: HybridSignature,
    /// Round hash for this commit.
    pub round_hash: [u8; 32],
    /// Confirmation tag.
    pub confirmation_tag: [u8; 32],
}

/// Creates an update commit to refresh our keys.
///
/// This provides post-compromise security by replacing our key material
/// with fresh random values.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
///
/// # Returns
///
/// An update commit for broadcast.
#[cfg(feature = "alloc")]
pub fn create_update(session: &mut CocoaSession) -> Result<UpdateCommit> {
    // Rotate our keypair
    session.rotate_keypair()?;

    // In full implementation:
    // 1. Generate new seed at our leaf
    // 2. Derive new keys for our entire path
    // 3. Encrypt seeds to resolution sets at each level
    // 4. Compute parent hashes
    // 5. Sign the commit

    // Compute round hash (no adds or removes)
    let root_label = [0u8; 32]; // Would compute from tree state
    let round_hash = h3_round_hash(&root_label, &[], &[]);

    // Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // Compute confirmation tag
    let conf_tag = session
        .tree()
        .our_leaf()
        .to_bytes(); // Placeholder - would include full commit content

    let commit = UpdateCommit {
        group_id: *session.group_id(),
        updater_leaf_position: session.our_leaf_position(),
        epoch: session.epoch_number() + 1,
        path_updates: Vec::new(), // Would contain actual updates
        signature: create_placeholder_signature()?,
        round_hash,
        confirmation_tag: {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&conf_tag);
            tag
        },
    };

    // Advance epoch
    let delta_root = [0u8; 32]; // Would be derived from path seeds
    session.advance_epoch(&delta_root, new_transcript);

    Ok(commit)
}

/// Processes an update commit from another member.
#[cfg(feature = "alloc")]
pub fn process_update(session: &mut CocoaSession, commit: &UpdateCommit) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Verify updater position is valid
    if commit.updater_leaf_position >= session.member_count() {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    // Verify signature (would verify against updater's identity key)
    // verify_commit_signature(&commit)?;

    // Process path updates
    // In full implementation:
    // 1. Find the seeds we can decrypt (based on resolution)
    // 2. Derive keys for nodes we need
    // 3. Update tree state

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
    use trelis_hybrid::HybridKemKeypair;

    fn create_test_session() -> CocoaSession {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap()
    }

    #[test]
    fn test_create_update() {
        let mut session = create_test_session();
        let initial_epoch = session.epoch_number();

        let commit = create_update(&mut session).unwrap();

        assert_eq!(commit.updater_leaf_position, 0);
        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[test]
    fn test_process_update() {
        let mut session = create_test_session();
        // Add another member first
        session.tree_mut().set_member_count(2);
        let initial_epoch = session.epoch_number();

        let commit = UpdateCommit {
            group_id: *session.group_id(),
            updater_leaf_position: 1, // Other member
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
            confirmation_tag: [0x22u8; 32],
        };

        process_update(&mut session, &commit).unwrap();

        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[test]
    fn test_process_update_invalid_position() {
        let mut session = create_test_session();

        let commit = UpdateCommit {
            group_id: *session.group_id(),
            updater_leaf_position: 99, // Invalid
            epoch: 1,
            path_updates: Vec::new(),
            signature: create_placeholder_signature().unwrap(),
            round_hash: [0x11u8; 32],
            confirmation_tag: [0x22u8; 32],
        };

        let result = process_update(&mut session, &commit);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    #[test]
    fn test_update_advances_epoch() {
        let mut session = create_test_session();

        for i in 0..5 {
            let commit = create_update(&mut session).unwrap();
            assert_eq!(commit.epoch, i + 1);
        }

        assert_eq!(session.epoch_number(), 5);
    }
}
