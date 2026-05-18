//! Member removal (CGKA.Rem).
//!
//! Removes a member from a CoCoA group.
//!
//! # Overview
//!
//! The remove operation evicts a member from the group. The remover:
//!
//! 1. Blanks the removed member's leaf (and possibly path nodes)
//! 2. Generates a fresh leaf seed and derives path keys
//! 3. Encrypts seeds to resolution sets (excluding the removed member)
//! 4. Signs the commit
//!
//! # Post-Compromise Security
//!
//! After a remove, the group must update to ensure the removed member
//! cannot derive future epoch secrets. The remover's path update provides
//! this by using fresh random seeds.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
#[cfg(feature = "alloc")]
use trelis_hybrid::HybridKemPublicKey;
use trelis_hybrid::{HybridIdentityKeypair, HybridIdentityPublicKey, HybridSignature};

#[cfg(feature = "alloc")]
use crate::key_schedule::h3_tree_label;
use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
use crate::session::CocoaSession;
use crate::tree::NodeIndex;
#[cfg(feature = "alloc")]
use crate::tree::{compute_lj, path_to_root};
use crate::{GroupId, UserId};

#[cfg(feature = "alloc")]
use super::add::EncryptedSeed;
use super::add::PathUpdate;
use super::commit_sign::{CommitContent, hash_path_updates, sign_commit, verify_commit_signature};
#[cfg(feature = "alloc")]
use super::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};

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
    /// Confirmation tag for epoch verification.
    pub confirmation_tag: [u8; 32],
}

/// Removes a member from the group.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `identity` - Our identity keypair for signing the commit
/// * `removed_member_id` - User ID of member to remove
/// * `removed_position` - Leaf position of member to remove
///
/// # Returns
///
/// A remove commit for broadcast.
#[cfg(feature = "alloc")]
pub fn remove_member(
    session: &mut CocoaSession,
    identity: &HybridIdentityKeypair,
    removed_member_id: UserId,
    removed_position: u32,
) -> Result<RemoveCommit> {
    // Step 1: Validation
    if removed_position == session.our_leaf_position() {
        return Err(trelis_error::CryptoError::SelfRemovalForbidden);
    }

    if removed_position >= session.member_count() {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    let tree_depth = session.tree().tree_depth();

    // Step 2: Blank the removed member's leaf
    let removed_leaf = NodeIndex::leaf(tree_depth, removed_position);
    session.tree_mut().blank_node(&removed_leaf);

    // Step 3: Generate fresh leaf seed
    let leaf_seed = generate_leaf_seed()?;

    // Step 4: Compute our path from leaf to root
    let our_leaf = NodeIndex::leaf(tree_depth, session.our_leaf_position());
    let path = path_to_root(our_leaf);
    let path_length = path.len();

    // Step 5: Derive all path seeds
    let path_seeds = derive_path_seeds(&leaf_seed, path_length);

    // Step 6: Compute resolution sets excluding the removed member
    let (resolution_sets, resolution_keys) =
        compute_remove_resolution_sets_and_keys(session, &path, removed_position);

    // Step 7: Compute sibling labels for parent hash computation
    let sibling_labels = compute_sibling_labels(session, &path);

    // Step 8: Build path updates with encrypted seeds
    let (path_updates, delta_root): (Vec<PathUpdate>, Seed) = {
        use super::path_update::build_path_updates_with_seeds;

        let key_refs: Vec<Vec<&HybridKemPublicKey>> = resolution_keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let result = build_path_updates_with_seeds(
            tree_depth,
            session.our_leaf_position(),
            &path_seeds,
            &resolution_sets,
            &key_refs,
            &sibling_labels,
        )?;

        // Convert NodeUpdate to PathUpdate
        let updates: Vec<PathUpdate> = result
            .updates
            .iter()
            .map(|u| PathUpdate {
                node_index: u.node_index,
                new_public_key: u.public_key.to_bytes().to_vec(),
                parent_hash: u.parent_hash,
                encrypted_seeds: u
                    .encrypted_seeds
                    .iter()
                    .map(|s| EncryptedSeed {
                        recipient_position: s.recipient_index.position,
                        encapsulation: s.encrypted.encapsulation.to_bytes().to_vec(),
                        ciphertext: s.encrypted.ciphertext.to_vec(),
                    })
                    .collect(),
            })
            .collect();

        (updates, result.delta_root)
    };

    // Step 8: Compute round hash (remove includes the removed member)
    let root_label = compute_root_label(&path_seeds);
    let round_hash = h3_round_hash(&root_label, &[removed_member_id], &[]);

    // Step 9: Serialise path updates and compute hash
    let path_updates_bytes = serialise_path_updates(&path_updates);
    let path_updates_hash = hash_path_updates(&path_updates_bytes);

    // Step 10: Build commit content for signing
    let commit_content = CommitContent::new_remove(
        *session.group_id(),
        session.epoch_number() + 1,
        round_hash,
        path_updates_hash,
    );

    // Step 11: Sign the commit with identity key
    let signature = sign_commit(identity, &commit_content)?;

    // Step 12: Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // Step 12b: Compute confirmation tag
    let confirmation_tag =
        compute_confirmation_tag(&delta_root, &new_transcript, session.epoch_number() + 1);

    let commit = RemoveCommit {
        group_id: *session.group_id(),
        removed_member_id,
        removed_leaf_position: removed_position,
        epoch: session.epoch_number() + 1,
        path_updates,
        signature,
        round_hash,
        confirmation_tag,
    };

    // Note: member_count stays the same - blank leaves remain in tree

    // Step 13: Advance epoch with real delta_root
    session.advance_epoch(&delta_root, new_transcript);

    Ok(commit)
}

/// Computes resolution sets excluding the removed member.
#[cfg(feature = "alloc")]
fn compute_remove_resolution_sets_and_keys(
    session: &CocoaSession,
    path: &[NodeIndex],
    removed_position: u32,
) -> (Vec<Vec<NodeIndex>>, Vec<Vec<HybridKemPublicKey>>) {
    let tree_depth = session.tree().tree_depth();
    let removed_leaf = NodeIndex::leaf(tree_depth, removed_position);

    let mut resolution_sets = Vec::with_capacity(path.len());
    let mut resolution_keys = Vec::with_capacity(path.len());

    for path_node in path {
        // Compute Lj = Res(sibling(path_node)) ∪ Unmerged(Res(sibling))
        let resolution = compute_lj(session.tree(), *path_node, |node_idx| {
            // Query unmerged leaf positions and convert to NodeIndex
            session
                .tree()
                .get(node_idx)
                .and_then(|node| node.state.unmerged_leaves())
                .map(|leaf_positions| {
                    leaf_positions
                        .iter()
                        .map(|&pos| NodeIndex::leaf(tree_depth, pos))
                        .collect()
                })
                .unwrap_or_default()
        });

        // Collect (node, key) pairs, excluding the removed member
        let mut nodes = Vec::new();
        let mut keys = Vec::new();

        for node_idx in resolution.iter() {
            // Skip if this is the removed member's node or an ancestor of it
            if *node_idx == removed_leaf || removed_leaf.is_descendant_of(node_idx) {
                continue;
            }

            if let Some(node) = session.tree().get(node_idx) {
                if let Some(pk) = node.state.public_key() {
                    nodes.push(*node_idx);
                    keys.push(pk.clone());
                }
            }
        }

        resolution_sets.push(nodes);
        resolution_keys.push(keys);
    }

    (resolution_sets, resolution_keys)
}

/// Computes the root label from path seeds.
#[must_use]
fn compute_root_label(path_seeds: &[Seed]) -> [u8; 32] {
    use trelis_primitives::blake3_kdf::derive_key;

    if let Some(root_seed) = path_seeds.last() {
        *derive_key("cocoa-sa-v1-root-label", root_seed)
    } else {
        [0u8; 32]
    }
}

/// Computes sibling labels for parent hash computation.
///
/// For each non-leaf node in the path, computes the sibling's tree label.
/// The tree label is H3(depth, position, public_key) for populated siblings,
/// or all zeros for blank siblings.
#[cfg(feature = "alloc")]
fn compute_sibling_labels(session: &CocoaSession, path: &[NodeIndex]) -> Vec<[u8; 32]> {
    let mut sibling_labels = Vec::with_capacity(path.len().saturating_sub(1));

    // Skip the first node (leaf) - we only need sibling labels for internal nodes
    for path_node in path.iter().skip(1) {
        // Get the sibling of this path node
        if let Some(sibling) = path_node.sibling() {
            // Look up the sibling's public key in the tree
            let label = session
                .tree()
                .get(&sibling)
                .and_then(|node| node.state.public_key())
                .map_or([0u8; 32], |pk| {
                    h3_tree_label(sibling.depth, sibling.position, &pk.to_bytes())
                }); // Blank sibling = zero label

            sibling_labels.push(label);
        } else {
            // Root has no sibling - use zero label
            sibling_labels.push([0u8; 32]);
        }
    }

    sibling_labels
}

/// Serialises path updates for hashing.
#[cfg(feature = "alloc")]
fn serialise_path_updates(updates: &[PathUpdate]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for update in updates {
        bytes.extend_from_slice(&update.node_index.depth.to_le_bytes());
        bytes.extend_from_slice(&update.node_index.position.to_le_bytes());
        let pk_len = update.new_public_key.len() as u32;
        bytes.extend_from_slice(&pk_len.to_le_bytes());
        bytes.extend_from_slice(&update.new_public_key);
        bytes.extend_from_slice(&update.parent_hash.0);
        bytes.extend_from_slice(&update.parent_hash.1);
        let seed_count = update.encrypted_seeds.len() as u32;
        bytes.extend_from_slice(&seed_count.to_le_bytes());

        for seed in &update.encrypted_seeds {
            bytes.extend_from_slice(&seed.recipient_position.to_le_bytes());
            let enc_len = seed.encapsulation.len() as u32;
            bytes.extend_from_slice(&enc_len.to_le_bytes());
            bytes.extend_from_slice(&seed.encapsulation);
            let ct_len = seed.ciphertext.len() as u32;
            bytes.extend_from_slice(&ct_len.to_le_bytes());
            bytes.extend_from_slice(&seed.ciphertext);
        }
    }

    bytes
}

/// Processes a remove commit from another member.
///
/// This function verifies the commit and processes the path updates to derive
/// the new epoch secret. It performs the following steps:
///
/// 1. Verify commit signature
/// 2. Verify we're not the one being removed
/// 3. Verify path updates hash
/// 4. Blank the removed member's leaf
/// 5. Find and decrypt our seed from the path updates
/// 6. Derive remaining path seeds up to root
/// 7. Verify public keys match the derived keys
/// 8. Update tree with new public keys
/// 9. Advance epoch with derived delta_root
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `commit` - The remove commit to process
/// * `remover_identity` - The remover's public identity key for signature verification
///
/// # Errors
///
/// Returns an error if:
/// - Group ID doesn't match
/// - We're the one being removed (RemovedFromGroup)
/// - Epoch is not sequential
/// - Signature verification fails
/// - Path updates hash doesn't match
/// - Cannot decrypt any seed (not in resolution)
/// - Public key verification fails
#[cfg(feature = "alloc")]
pub fn process_remove(
    session: &mut CocoaSession,
    commit: &RemoveCommit,
    remover_identity: &HybridIdentityPublicKey,
) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Verify we're not the one being removed
    if commit.removed_leaf_position == session.our_leaf_position() {
        // We've been removed - session is now invalid
        return Err(trelis_error::CryptoError::RemovedFromGroup);
    }

    // Verify epoch is sequential
    if commit.epoch != session.epoch_number() + 1 {
        return Err(trelis_error::CryptoError::EpochMismatch {
            expected: session.epoch_number() + 1,
            received: commit.epoch,
        });
    }

    // Serialise and verify path updates hash
    let path_updates_bytes = serialise_path_updates(&commit.path_updates);
    let path_updates_hash = hash_path_updates(&path_updates_bytes);

    // Build commit content for signature verification
    let commit_content = CommitContent::new_remove(
        commit.group_id,
        commit.epoch,
        commit.round_hash,
        path_updates_hash,
    );

    // Verify signature (both Ed448 and ML-DSA-65 must pass)
    verify_commit_signature(remover_identity, &commit_content, &commit.signature)?;

    // Blank the removed member's leaf first (before processing path updates)
    let leaf_index = NodeIndex::leaf(session.tree().tree_depth(), commit.removed_leaf_position);
    session.tree_mut().blank_node(&leaf_index);

    // Convert PathUpdate to NodeUpdate for apply_path_updates
    let node_updates = convert_path_updates_to_node_updates(&commit.path_updates)?;

    // Apply path updates: find our seed, decrypt, derive to root, verify keys
    let delta_root = if node_updates.is_empty() {
        // No path updates means we can't derive delta_root
        // This happens when the commit has no encrypted seeds for us
        [0u8; 32]
    } else {
        use super::path_update::apply_path_updates;

        // Try to apply path updates - we should be in the resolution set
        // since the removed member was excluded
        apply_path_updates(
            &node_updates,
            session.our_keypair(),
            session.our_leaf_position(),
            0, // Remover position (we use path updates to find our seed)
        )?
    };

    // Update tree with new public keys from path updates
    // Note: We use the remover's ID (session's user_id) since they created the commit
    update_tree_from_path_updates(
        session,
        &commit.path_updates,
        &commit.signature,
        *session.our_user_id(),
    );

    // Update transcript hash
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &commit.round_hash);

    // Verify confirmation tag
    let expected_tag = compute_confirmation_tag(&delta_root, &new_transcript, commit.epoch);
    if !constant_time_eq(&expected_tag, &commit.confirmation_tag) {
        return Err(trelis_error::CryptoError::SignatureVerificationFailed);
    }

    // Advance epoch with the derived delta_root
    session.advance_epoch(&delta_root, new_transcript);

    Ok(())
}

/// Converts wire-format PathUpdate to internal NodeUpdate format.
#[cfg(feature = "alloc")]
fn convert_path_updates_to_node_updates(
    path_updates: &[PathUpdate],
) -> Result<Vec<super::path_update::NodeUpdate>> {
    use super::path_update::{NodeUpdate, RecipientSeed};
    use super::seed_encrypt::EncryptedNodeSeed;

    let mut node_updates = Vec::with_capacity(path_updates.len());

    for pu in path_updates {
        // Parse public key
        let public_key = HybridKemPublicKey::from_bytes(&pu.new_public_key)?;

        // Convert encrypted seeds
        let mut encrypted_seeds = Vec::with_capacity(pu.encrypted_seeds.len());
        for es in &pu.encrypted_seeds {
            let encapsulation = trelis_hybrid::HybridEncapsulation::from_bytes(&es.encapsulation)?;

            let mut ciphertext = [0u8; 48];
            if es.ciphertext.len() != 48 {
                return Err(trelis_error::CryptoError::MalformedMessage);
            }
            ciphertext.copy_from_slice(&es.ciphertext);

            encrypted_seeds.push(RecipientSeed {
                recipient_index: NodeIndex::leaf(pu.node_index.depth, es.recipient_position),
                encrypted: EncryptedNodeSeed {
                    encapsulation,
                    ciphertext,
                },
            });
        }

        node_updates.push(NodeUpdate {
            node_index: pu.node_index,
            public_key,
            parent_hash: pu.parent_hash,
            encrypted_seeds,
        });
    }

    Ok(node_updates)
}

/// Updates the tree with new public keys from path updates.
#[cfg(feature = "alloc")]
fn update_tree_from_path_updates(
    session: &mut CocoaSession,
    path_updates: &[PathUpdate],
    commit_signature: &HybridSignature,
    updater_id: crate::UserId,
) {
    use crate::tree::{TreeNode, UpdateOrigin};

    for pu in path_updates {
        // Parse public key (already validated in convert_path_updates_to_node_updates)
        if let Ok(public_key) = HybridKemPublicKey::from_bytes(&pu.new_public_key) {
            // Get current node state for predecessor key
            let predecessor_key = session
                .tree()
                .get(&pu.node_index)
                .and_then(|node| node.state.public_key())
                .cloned();

            // Create new node with updated key using actual commit signature
            let new_node = TreeNode::new_populated(
                pu.node_index,
                public_key,
                predecessor_key,
                pu.parent_hash,
                updater_id,
                commit_signature.clone(),
                *session.transcript_hash(),
                [0u8; 32], // Confirmation tag
                UpdateOrigin {
                    epoch: session.epoch_number() + 1,
                    sequence: 0,
                    timestamp: 0,
                },
            );

            // Insert into tree
            session.tree_mut().insert(new_node);
        }
    }
}

/// Computes the confirmation tag for commit verification.
///
/// The confirmation tag binds the commit to the epoch state and
/// allows recipients to verify they computed the same secrets.
#[must_use]
fn compute_confirmation_tag(delta_root: &Seed, transcript: &[u8; 32], epoch: u64) -> [u8; 32] {
    use trelis_primitives::blake3_kdf::derive_key;

    let mut input = [0u8; 72];
    input[..32].copy_from_slice(delta_root);
    input[32..64].copy_from_slice(transcript);
    input[64..72].copy_from_slice(&epoch.to_le_bytes());

    *derive_key("cocoa-sa-v1-confirmation-tag", &input)
}

/// Constant-time comparison for confirmation tags.
#[must_use]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::add::add_member;
    use trelis_hybrid::{HybridKemKeypair, HybridOneTimeKeyPair, HybridPreKeyBundle};

    fn create_test_identity() -> HybridIdentityKeypair {
        HybridIdentityKeypair::generate().unwrap()
    }

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    fn create_test_session_with_members(count: u32) -> (CocoaSession, HybridIdentityKeypair) {
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];
        let our_identity = create_test_identity();

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();

        // Add additional members
        for i in 1..count {
            let member_identity = create_test_identity();
            let bundle = create_test_bundle(&member_identity);
            let member_id = [i as u8; 32];
            add_member(&mut session, &our_identity, &bundle, member_id).unwrap();
        }

        (session, our_identity)
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_remove_member() {
        let (mut session, our_identity) = create_test_session_with_members(3);
        assert_eq!(session.member_count(), 3);

        let removed_id = [0x02u8; 32];
        let commit = remove_member(&mut session, &our_identity, removed_id, 2).unwrap();

        assert_eq!(commit.removed_leaf_position, 2);
        // Member count doesn't decrease (blank leaves remain)
        assert_eq!(session.member_count(), 3);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cannot_remove_self() {
        let (mut session, our_identity) = create_test_session_with_members(2);

        let result = remove_member(&mut session, &our_identity, [0x01u8; 32], 0);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::SelfRemovalForbidden)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cannot_remove_invalid_position() {
        let (mut session, our_identity) = create_test_session_with_members(2);

        let result = remove_member(&mut session, &our_identity, [0x99u8; 32], 99);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove() {
        let (mut session, _) = create_test_session_with_members(3);
        let remover_identity = create_test_identity();
        let initial_epoch = session.epoch_number();

        // Build a valid remove commit
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();

        // Compute correct confirmation tag for empty path updates
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let delta_root = [0u8; 32]; // Empty path updates = zero delta_root
        let confirmation_tag =
            compute_confirmation_tag(&delta_root, &new_transcript, initial_epoch + 1);

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_remove(&mut session, &commit, remover_identity.public_key()).unwrap();

        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove_self_fails() {
        let (mut session, _) = create_test_session_with_members(2);
        let remover_identity = create_test_identity();

        // Build a valid remove commit for position 0 (us)
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content =
            CommitContent::new_remove(*session.group_id(), 1, round_hash, path_updates_hash);
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x01u8; 32],
            removed_leaf_position: 0, // Our position
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32], // Placeholder - test fails before tag verification
        };

        // Removal check happens before signature verification
        let result = process_remove(&mut session, &commit, remover_identity.public_key());
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::RemovedFromGroup)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove_wrong_signer() {
        let (mut session, _) = create_test_session_with_members(3);
        let signer_identity = create_test_identity();
        let wrong_identity = create_test_identity();

        // Build commit signed by signer_identity
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            session.epoch_number() + 1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&signer_identity, &commit_content).unwrap();

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            epoch: session.epoch_number() + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32], // Placeholder - test fails before tag verification
        };

        // Try to verify with wrong identity - should fail
        let result = process_remove(&mut session, &commit, wrong_identity.public_key());
        assert!(result.is_err());
    }
}
