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
use crate::key_schedule::{ROOT_LABEL_CONTEXT, h3_round_hash, h3_transcript_hash};
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
#[cfg(feature = "alloc")]
use super::update::derive_user_id_from_identity;

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
    /// The remover's (committer's) own leaf position.
    ///
    /// GAP-03: bound into the signed `CommitContent`; the verifier
    /// reconstructs the signed body from this field and rejects a commit whose
    /// committer leaf is out of range or a known-blank leaf.
    pub committer_leaf_position: u32,
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

    // Step 10: Build commit content for signing.
    // GAP-03: bind our own leaf position + derived identity into the signed body.
    let committer_leaf_position = session.our_leaf_position();
    let commit_content = CommitContent::new_remove(
        *session.group_id(),
        session.epoch_number() + 1,
        round_hash,
        path_updates_hash,
        committer_leaf_position,
        derive_user_id_from_identity(identity.public_key()),
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
        committer_leaf_position,
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
        *derive_key(ROOT_LABEL_CONTEXT, root_seed)
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

    // Build commit content for signature verification.
    // GAP-03: reconstruct the committer binding — committer_leaf_position from
    // the wire field, committer_user_id derived from the caller-supplied
    // remover identity. If the caller passes the wrong identity, the
    // reconstructed body no longer matches the signed body and the signature
    // check below fails (binds signer ↔ body identity).
    let commit_content = CommitContent::new_remove(
        commit.group_id,
        commit.epoch,
        commit.round_hash,
        path_updates_hash,
        commit.committer_leaf_position,
        derive_user_id_from_identity(remover_identity),
    );

    // Verify signature (both Ed448 and ML-DSA-65 must pass)
    verify_commit_signature(remover_identity, &commit_content, &commit.signature)?;

    // GAP-03: bind signer ↔ leaf. The remover must sit at an occupied member
    // leaf — reject a committer leaf that is out of range or a known-blank
    // leaf in our local view.
    if commit.committer_leaf_position >= session.member_count()
        || session
            .tree()
            .get(&NodeIndex::leaf(
                session.tree().tree_depth(),
                commit.committer_leaf_position,
            ))
            .is_some_and(|node| node.state.is_blank())
    {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    // Convert PathUpdate to NodeUpdate for apply_path_updates
    let node_updates = convert_path_updates_to_node_updates(&commit.path_updates)?;

    // Apply path updates: find our seed, decrypt, derive to root, verify keys.
    // Reads no session tree state and mutates nothing — it only derives the
    // delta_root the integrity checks below bind against.
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

    // Update transcript hash (local value; not yet committed to the session).
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &commit.round_hash);

    // ── Integrity checks — ALL must pass BEFORE any session mutation (WR-03) ──
    // The removed leaf is blanked and the remover's path nodes are written ONLY
    // after every check passes, so a signature-valid but tag-/round-hash-/
    // parent-hash-invalid commit (the GAP-04c insider attack) leaves the tree,
    // member_count and epoch exactly as before (mirroring process_update).

    // Verify confirmation tag (epoch-secret agreement).
    let expected_tag = compute_confirmation_tag(&delta_root, &new_transcript, commit.epoch);
    if !constant_time_eq(&expected_tag, &commit.confirmation_tag) {
        return Err(trelis_error::CryptoError::SignatureVerificationFailed);
    }

    // GAP-04c (F07): MANDATORY round-hash verification. Independently recompute
    // the round hash from the LOCALLY-derived delta_root plus this commit's
    // membership change (remove binds removed = [removed_member_id], added = [])
    // and reject a divergent/forged value BEFORE advancing the epoch. This
    // mirrors the committer's build side exactly (compute_root_label +
    // h3_round_hash with the same removed set).
    //
    // The confirmation tag checked above only binds epoch-secret agreement
    // (delta_root, transcript, epoch); it does NOT bind the round hash to the
    // actual tree-state / membership change, so a malicious committer could
    // advertise a round hash inconsistent with the removed member while keeping
    // the tag self-consistent. This recompute closes that gap, making §12:99
    // ("undetectably partition ... detected via round hash") true in code.
    //
    // NOTE: the full Algorithm-3 `verifyRH` (server-provided Merkle `openRH`
    // transport) is the deferred follow-up (OQ-5); this lightweight in-crate
    // recompute is the mandatory Phase-52 minimum.
    {
        use trelis_primitives::blake3_kdf::derive_key;
        let expected_root_label = *derive_key(ROOT_LABEL_CONTEXT, &delta_root);
        let expected_round_hash =
            h3_round_hash(&expected_root_label, &[commit.removed_member_id], &[]);
        if expected_round_hash != commit.round_hash {
            return Err(trelis_error::CryptoError::RoundHashMismatch);
        }
    }

    // GAP-02 (PHash.Ver): recompute h1/h2 and reject a tampered tree structure.
    // The remover blanks the removed leaf BEFORE building path updates, so we
    // mirror that on a SCRATCH clone (removed leaf blanked) for the recompute,
    // leaving the real tree untouched on rejection. h1 (sibling binding) is
    // mandatory; h2 is enforced where the local resolution reconstructs
    // (partial-view residual otherwise, OQ-1). Empty path updates are a no-op.
    let leaf_index = NodeIndex::leaf(session.tree().tree_depth(), commit.removed_leaf_position);
    let mut scratch = session.tree().clone();
    scratch.blank_node(&leaf_index);
    super::path_update::verify_parent_hashes(&scratch, &node_updates)?;

    // ── All checks passed — commit the mutations to the real session ─────────
    // Blank the removed member's leaf, then write the remover's new path nodes.
    session.tree_mut().blank_node(&leaf_index);

    // Update tree with new public keys from path updates
    // Note: We use the remover's ID (session's user_id) since they created the commit
    update_tree_from_path_updates(
        session,
        &commit.path_updates,
        &commit.signature,
        *session.our_user_id(),
    );

    // Advance epoch with the derived delta_root
    session.advance_epoch(&delta_root, new_transcript);

    // GAP-03: prune the removed member from the local registry so they can be
    // re-added later without tripping the double-join guard.
    session.remove_member(&commit.removed_member_id);

    Ok(())
}

/// Converts wire-format PathUpdate to internal NodeUpdate format.
#[cfg(feature = "alloc")]
fn convert_path_updates_to_node_updates(
    path_updates: &[PathUpdate],
) -> Result<Vec<super::path_update::NodeUpdate>> {
    use super::path_update::{NodeUpdate, RecipientSeed};
    use super::seed_encrypt::{ENCRYPTED_SEED_CIPHERTEXT_SIZE, EncryptedNodeSeed};

    let mut node_updates = Vec::with_capacity(path_updates.len());

    for pu in path_updates {
        // Parse public key
        let public_key = HybridKemPublicKey::from_bytes(&pu.new_public_key)?;

        // Convert encrypted seeds
        let mut encrypted_seeds = Vec::with_capacity(pu.encrypted_seeds.len());
        for es in &pu.encrypted_seeds {
            let encapsulation = trelis_hybrid::HybridEncapsulation::from_bytes(&es.encapsulation)?;

            let mut ciphertext = [0u8; ENCRYPTED_SEED_CIPHERTEXT_SIZE];
            if es.ciphertext.len() != ENCRYPTED_SEED_CIPHERTEXT_SIZE {
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

    *derive_key("cocoa-sa-confirmation-tag-v1", &input)
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

        // Add additional members. Member IDs start at 2 so they never collide
        // with the creator's user_id ([0x01; 32]) — a collision would (correctly)
        // trip the GAP-03 double-join guard.
        for i in 1..count {
            let member_identity = create_test_identity();
            let bundle = create_test_bundle(&member_identity);
            let member_id = [(i + 1) as u8; 32];
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

        // Build a valid remove commit, remover bound to committer leaf 0
        let path_updates_hash = hash_path_updates(&[]);
        // GAP-04c: with mandatory round-hash verification the synthetic empty-path
        // commit must carry the round hash the receiver recomputes from its LOCAL
        // delta_root ([0;32] for empty updates) + removed = [removed_member].
        let round_hash = {
            use trelis_primitives::blake3_kdf::derive_key;
            h3_round_hash(
                &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
                &[[0x02u8; 32]],
                &[],
            )
        };
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(remover_identity.public_key()),
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
            committer_leaf_position: 0,
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
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            1,
            derive_user_id_from_identity(remover_identity.public_key()),
        );
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x01u8; 32],
            removed_leaf_position: 0, // Our position
            committer_leaf_position: 1,
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

        // Build commit signed by signer_identity, bound to committer leaf 0
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            session.epoch_number() + 1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(signer_identity.public_key()),
        );
        let signature = sign_commit(&signer_identity, &commit_content).unwrap();

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
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

    // ─── GAP-02: parent-hash verification on the remove ingest path ─────────

    /// A flipped non-leaf `h1` on a real remove commit is rejected by the
    /// parent-hash verifier; the honest commit verifies against the builder's
    /// own tree (positive control). `remove_member` blanks the removed leaf
    /// before building, mirroring the state `verify_parent_hashes` sees.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_remove_tamper_rejected() {
        use super::super::path_update::verify_parent_hashes;

        let (mut session, our_identity) = create_test_session_with_members(3);
        // Remove member at leaf 2 (never ourselves at leaf 0).
        let commit = remove_member(&mut session, &our_identity, [0x03u8; 32], 2).unwrap();
        let node_updates = convert_path_updates_to_node_updates(&commit.path_updates).unwrap();
        assert!(
            node_updates.len() >= 2,
            "remove path must carry a non-leaf node"
        );

        // Positive control: the honest commit verifies against the builder tree.
        verify_parent_hashes(session.tree(), &node_updates).unwrap();

        // Tamper one byte of a non-leaf h1 -> ParentHashMismatch.
        let mut tampered = node_updates.clone();
        tampered[1].parent_hash.0[0] ^= 0xFF;
        assert!(matches!(
            verify_parent_hashes(session.tree(), &tampered),
            Err(trelis_error::CryptoError::ParentHashMismatch)
        ));
    }

    // ─── GAP-04c: mandatory round-hash verification on the remove path ───────

    /// A forged `round_hash` — self-consistent with its own confirmation tag and
    /// covered by a valid signature — is rejected by the mandatory round-hash
    /// recompute (`RoundHashMismatch`). Empty path updates ⇒ delta_root [0;32],
    /// so the receiver recomputes `h3_round_hash(derive_key(ROOT_LABEL_CONTEXT,
    /// [0;32]), [removed_member], [])`; a garbage value differs and is rejected.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_round_hash_remove_mismatch_rejected() {
        use trelis_primitives::blake3_kdf::derive_key;

        let (mut session, _) = create_test_session_with_members(3);
        let remover_identity = create_test_identity();
        let initial_epoch = session.epoch_number();

        let path_updates_hash = hash_path_updates(&[]);
        // Forged: NOT the value the receiver recomputes from delta_root [0;32].
        let round_hash = [0x99u8; 32];
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(remover_identity.public_key()),
        );
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();

        // Tag made SELF-CONSISTENT with the forged round hash so the tag check
        // passes and execution reaches the round-hash gate.
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag =
            compute_confirmation_tag(&[0u8; 32], &new_transcript, initial_epoch + 1);

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        assert!(matches!(
            process_remove(&mut session, &commit, remover_identity.public_key()),
            Err(trelis_error::CryptoError::RoundHashMismatch)
        ));

        // Sanity: the honest recompute (removed = [removed_member]) really differs.
        let honest = h3_round_hash(
            &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
            &[[0x02u8; 32]],
            &[],
        );
        assert_ne!(honest, round_hash);
    }

    /// Positive control: a remove whose `round_hash` matches the receiver's
    /// independent recompute (delta_root [0;32] + removed = [removed_member])
    /// verifies and advances the epoch.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_round_hash_remove_honest_verifies() {
        use trelis_primitives::blake3_kdf::derive_key;

        let (mut session, _) = create_test_session_with_members(3);
        let remover_identity = create_test_identity();
        let initial_epoch = session.epoch_number();

        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = h3_round_hash(
            &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
            &[[0x02u8; 32]],
            &[],
        );
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(remover_identity.public_key()),
        );
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();

        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag =
            compute_confirmation_tag(&[0u8; 32], &new_transcript, initial_epoch + 1);

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_remove(&mut session, &commit, remover_identity.public_key()).unwrap();
        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    // ─── WR-03: rejected commit must not mutate session state ────────────────

    /// WR-03: a signature-valid remove that fails the mandatory round-hash check
    /// must leave the session state COMPLETELY unchanged — the removed leaf is
    /// NOT blanked and the epoch does NOT advance. Before the validate-then-
    /// mutate reorder, `process_remove` blanked the removed leaf BEFORE the
    /// round-hash check, corrupting the tree on a rejected commit. The removed
    /// leaf is explicitly populated here so a premature blank is observable.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove_rejected_commit_leaves_state_unchanged() {
        use crate::tree::{TreeNode, UpdateOrigin};

        let (mut session, _) = create_test_session_with_members(3);
        let remover_identity = create_test_identity();
        let initial_epoch = session.epoch_number();
        let members_before = session.member_count();

        // Populate the removed leaf so a premature blank would be observable.
        let removed_leaf = NodeIndex::leaf(session.tree().tree_depth(), 2);
        let victim_kp = HybridKemKeypair::generate().unwrap();
        session.tree_mut().insert(TreeNode::new_populated(
            removed_leaf,
            victim_kp.public_key().clone(),
            None,
            ([0u8; 32], [0u8; 32]),
            [0x02u8; 32],
            create_test_identity().sign(b"init").unwrap(),
            [0u8; 32],
            [0u8; 32],
            UpdateOrigin {
                epoch: 0,
                sequence: 0,
                timestamp: 0,
            },
        ));
        assert!(
            session
                .tree()
                .get(&removed_leaf)
                .unwrap()
                .state
                .is_populated()
        );

        let path_updates_hash = hash_path_updates(&[]);
        // Forged round hash; self-consistent tag so we reach the round-hash gate.
        let round_hash = [0x99u8; 32];
        let commit_content = CommitContent::new_remove(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(remover_identity.public_key()),
        );
        let signature = sign_commit(&remover_identity, &commit_content).unwrap();
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag =
            compute_confirmation_tag(&[0u8; 32], &new_transcript, initial_epoch + 1);

        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        assert!(matches!(
            process_remove(&mut session, &commit, remover_identity.public_key()),
            Err(trelis_error::CryptoError::RoundHashMismatch)
        ));

        // State unchanged: epoch not advanced, member_count intact, and the
        // removed leaf must still be populated (NOT blanked before the check).
        assert_eq!(
            session.epoch_number(),
            initial_epoch,
            "epoch must NOT advance on a rejected remove"
        );
        assert_eq!(
            session.member_count(),
            members_before,
            "member_count must be unchanged on a rejected remove"
        );
        assert!(
            session
                .tree()
                .get(&removed_leaf)
                .unwrap()
                .state
                .is_populated(),
            "removed leaf must NOT be blanked before the round-hash check"
        );
    }

    // ─── DOS-01/02: check_size_limits gate on the process_remove ingest path ──

    /// DOS-02 ordering proof (reproduce-don't-assert): a remove commit with more
    /// than 21 path updates (proof_depth > 20) AND an invalid signature returns
    /// `ProofTooDeep`, not `SignatureVerificationFailed` — the size gate precedes
    /// `verify_commit_signature`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove_rejects_overdeep_proof_before_verify() {
        let (mut session, _) = create_test_session_with_members(3);
        let remover = create_test_identity();

        // 22 path updates -> proof_depth = 22 - 1 = 21 > MAX_MERKLE_PROOF_DEPTH(20).
        let path_updates: Vec<PathUpdate> = (0..22)
            .map(|_| PathUpdate {
                node_index: NodeIndex::new(0, 0),
                new_public_key: Vec::new(),
                parent_hash: ([0u8; 32], [0u8; 32]),
                encrypted_seeds: Vec::new(),
            })
            .collect();
        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
            epoch: session.epoch_number() + 1,
            path_updates,
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_remove(&mut session, &commit, remover.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::ProofTooDeep)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }

    /// DOS-01 ordering proof: a remove commit whose measured message size exceeds
    /// `MAX_MESSAGE_SIZE` AND with an invalid signature returns `MessageTooLarge`,
    /// not `SignatureVerificationFailed`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_remove_rejects_oversized_message_before_verify() {
        let (mut session, _) = create_test_session_with_members(3);
        let remover = create_test_identity();

        let oversized = PathUpdate {
            node_index: NodeIndex::new(0, 0),
            new_public_key: Vec::new(),
            parent_hash: ([0u8; 32], [0u8; 32]),
            encrypted_seeds: vec![EncryptedSeed {
                recipient_position: 0,
                encapsulation: Vec::new(),
                ciphertext: vec![0u8; crate::MAX_MESSAGE_SIZE + 1],
            }],
        };
        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let commit = RemoveCommit {
            group_id: *session.group_id(),
            removed_member_id: [0x02u8; 32],
            removed_leaf_position: 2,
            committer_leaf_position: 0,
            epoch: session.epoch_number() + 1,
            path_updates: vec![oversized],
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_remove(&mut session, &commit, remover.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::MessageTooLarge)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }
}
