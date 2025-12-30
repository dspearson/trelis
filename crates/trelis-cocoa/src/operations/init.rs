//! Group initialisation (CGKA.Init).
//!
//! Creates a new CoCoA group with the creator as the first member.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair, HybridPreKeyBundle};
use trelis_primitives::random::generate_bytes;

use crate::session::CocoaSession;
use crate::{GroupId, UserId};

/// Welcome message sent to new members when joining a group.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Welcome {
    /// Group identifier.
    pub group_id: GroupId,
    /// Epoch number at time of welcome.
    pub epoch: u64,
    /// Recipient's assigned leaf position.
    pub leaf_position: u32,
    /// Tree depth.
    pub tree_depth: u32,
    /// Current member count.
    pub member_count: u32,
    /// Encrypted group info (epoch secret, tree state, transcript).
    /// Encrypted to the recipient's KEM key.
    pub encrypted_info: Vec<u8>,
    /// Encapsulation for decrypting the info.
    pub encapsulation: Vec<u8>,
}

/// Creates a new CoCoA group.
///
/// # Arguments
///
/// * `creator_identity` - Creator's identity keypair (for signing)
/// * `creator_kem` - Creator's KEM keypair (for encryption)
/// * `creator_user_id` - Creator's user identifier
/// * `member_bundles` - Pre-key bundles of initial members (excluding creator)
///
/// # Returns
///
/// A tuple of (creator's session, welcome messages for other members).
#[cfg(all(feature = "alloc", feature = "std"))]
pub fn create_group(
    _creator_identity: &HybridIdentityKeypair,
    creator_kem: HybridKemKeypair,
    creator_user_id: UserId,
    member_bundles: &[&HybridPreKeyBundle],
) -> Result<(CocoaSession, Vec<Welcome>)> {
    // Generate group ID
    let group_id: GroupId = generate_bytes()?;

    // Total members = creator + others
    let total_members = 1 + member_bundles.len() as u32;

    // Generate initial epoch secret
    let epoch_secret: [u8; 32] = generate_bytes()?;

    // Create creator's session
    let session =
        CocoaSession::create_group(group_id, creator_user_id, creator_kem, total_members, &epoch_secret)?;

    // Generate welcome messages for other members
    let mut welcomes = Vec::with_capacity(member_bundles.len());

    for (i, _bundle) in member_bundles.iter().enumerate() {
        let leaf_position = (i + 1) as u32; // Creator is at position 0

        // In a full implementation, we would:
        // 1. Encrypt the epoch secret and tree state to the bundle's KEM key
        // 2. Include the encrypted data in the welcome message
        // For now, create a placeholder welcome

        let welcome = Welcome {
            group_id,
            epoch: 0,
            leaf_position,
            tree_depth: session.tree().tree_depth(),
            member_count: total_members,
            encrypted_info: Vec::new(), // Placeholder
            encapsulation: Vec::new(),   // Placeholder
        };

        welcomes.push(welcome);
    }

    Ok((session, welcomes))
}

/// Processes a welcome message to join a group.
///
/// # Arguments
///
/// * `our_user_id` - Our user identifier
/// * `our_kem` - Our KEM keypair (matching the one in our pre-key bundle)
/// * `welcome` - The welcome message
///
/// # Returns
///
/// A session for participating in the group.
#[cfg(feature = "alloc")]
pub fn process_welcome(
    our_user_id: UserId,
    our_kem: HybridKemKeypair,
    welcome: &Welcome,
) -> Result<CocoaSession> {
    // In a full implementation, we would:
    // 1. Decapsulate to get the encryption key
    // 2. Decrypt the epoch secret and tree state
    // 3. Verify the tree structure
    // For now, create a session with placeholder values

    let epoch_secret = [0u8; 32]; // Would be decrypted from welcome.encrypted_info
    let transcript_hash = [0u8; 32]; // Would be included in welcome.encrypted_info

    let session = CocoaSession::join_group(
        welcome.group_id,
        our_user_id,
        our_kem,
        welcome.leaf_position,
        welcome.tree_depth,
        welcome.member_count,
        welcome.epoch,
        &epoch_secret,
        transcript_hash,
    );

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::HybridOneTimeKeyPair;

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    #[test]
    fn test_create_group_single_member() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let (session, welcomes) = create_group(&identity, kem, user_id, &[]).unwrap();

        assert_eq!(session.our_leaf_position(), 0);
        assert_eq!(session.member_count(), 1);
        assert!(welcomes.is_empty());
    }

    #[test]
    fn test_create_group_multiple_members() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        // Create member bundles
        let member1_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle1 = create_test_bundle(&member1_identity);

        let member2_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle2 = create_test_bundle(&member2_identity);

        let bundles: Vec<&HybridPreKeyBundle> = vec![&bundle1, &bundle2];

        let (session, welcomes) = create_group(&identity, kem, user_id, &bundles).unwrap();

        assert_eq!(session.member_count(), 3);
        assert_eq!(welcomes.len(), 2);
        assert_eq!(welcomes[0].leaf_position, 1);
        assert_eq!(welcomes[1].leaf_position, 2);
    }

    #[test]
    fn test_welcome_has_correct_group_id() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        let (session, welcomes) = create_group(&identity, kem, user_id, &[&bundle]).unwrap();

        assert_eq!(welcomes[0].group_id, *session.group_id());
    }
}
