//! Key update (CGKA.Upd).
//!
//! Updates our own keys in the CoCoA group for post-compromise security.
//!
//! # Overview
//!
//! The update operation allows a member to refresh their key material,
//! providing post-compromise security (PCS). When a member performs an
//! update:
//!
//! 1. Generate a fresh random leaf seed
//! 2. Derive seeds for each node in our path (leaf to root)
//! 3. Derive new keypairs from each seed
//! 4. Encrypt seeds to resolution sets (sibling subtree members)
//! 5. Compute parent hashes for tree integrity
//! 6. Sign the commit
//!
//! # Seed Encryption
//!
//! For each path node, we encrypt the seed to the resolution of its
//! sibling subtree. This allows other members to:
//!
//! - Decrypt the seed at the level where they first appear
//! - Derive all subsequent seeds up to the root
//! - Compute the same delta_root for epoch key derivation

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::{HybridIdentityKeypair, HybridIdentityPublicKey, HybridSignature};
#[cfg(feature = "alloc")]
use trelis_hybrid::HybridKemPublicKey;

use crate::GroupId;
use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
use crate::session::CocoaSession;
#[cfg(feature = "alloc")]
use crate::tree::{NodeIndex, compute_lj, path_to_root};

use super::add::PathUpdate;
use super::commit_sign::{CommitContent, hash_path_updates, sign_commit, verify_commit_signature};
#[cfg(feature = "alloc")]
use super::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};


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
/// * `identity` - Our identity keypair for signing the commit
///
/// # Returns
///
/// An update commit for broadcast.
#[cfg(feature = "alloc")]
pub fn create_update(
    session: &mut CocoaSession,
    identity: &HybridIdentityKeypair,
) -> Result<UpdateCommit> {
    // Step 1: Generate fresh leaf seed
    let leaf_seed = generate_leaf_seed()?;

    // Step 2: Compute our path from leaf to root
    let our_leaf = NodeIndex::leaf(session.tree().tree_depth(), session.our_leaf_position());
    let path = path_to_root(our_leaf);
    let path_length = path.len();

    // Step 3: Derive all path seeds
    let path_seeds = derive_path_seeds(&leaf_seed, path_length);

    // Step 4: Compute resolution sets and get public keys for encryption
    let (resolution_sets, resolution_keys) =
        compute_resolution_sets_and_keys(session, &path);

    // Step 5: Compute sibling labels for parent hash computation
    let sibling_labels = compute_sibling_labels(session, &path);

    // Step 6: Build path updates with encrypted seeds
    #[cfg(any(
        feature = "deterministic-keygen",
        target_os = "windows",
        target_arch = "wasm32"
    ))]
    let (path_updates, delta_root): (Vec<PathUpdate>, Seed) = {
        use super::path_update::build_path_updates_with_seeds;

        // Convert keys to references for the builder
        let key_refs: Vec<Vec<&HybridKemPublicKey>> = resolution_keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        // Use pre-computed path seeds for consistency
        let result = build_path_updates_with_seeds(
            session.tree().tree_depth(),
            session.our_leaf_position(),
            &path_seeds,
            &resolution_sets,
            &key_refs,
            &sibling_labels,
        )?;

        // Convert NodeUpdate to PathUpdate for the commit
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
                    .map(|s| super::add::EncryptedSeed {
                        recipient_position: s.recipient_index.position,
                        encapsulation: s.encrypted.encapsulation.to_bytes().to_vec(),
                        ciphertext: s.encrypted.ciphertext.to_vec(),
                    })
                    .collect(),
            })
            .collect();

        (updates, result.delta_root)
    };

    // Error on platforms without deterministic keygen
    // Path update generation requires deterministic key derivation from seeds
    #[cfg(not(any(
        feature = "deterministic-keygen",
        target_os = "windows",
        target_arch = "wasm32"
    )))]
    return Err(trelis_error::CryptoError::UnsupportedOperation);

    // Suppress unused variable warnings for the non-deterministic path
    #[cfg(not(any(
        feature = "deterministic-keygen",
        target_os = "windows",
        target_arch = "wasm32"
    )))]
    let (path_updates, delta_root): (Vec<PathUpdate>, Seed) = {
        let _ = (&resolution_sets, &resolution_keys, &sibling_labels, &path_seeds);
        unreachable!()
    };

    // Step 6: Rotate our keypair to match the new leaf key
    session.rotate_keypair()?;

    // Step 7: Compute round hash (no adds or removes for update)
    let root_label = compute_root_label(&path_seeds);
    let round_hash = h3_round_hash(&root_label, &[], &[]);

    // Step 8: Serialise path updates and compute hash
    let path_updates_bytes = serialise_path_updates(&path_updates);
    let path_updates_hash = hash_path_updates(&path_updates_bytes);

    // Step 9: Build commit content for signing
    let commit_content = CommitContent::new_update(
        *session.group_id(),
        session.epoch_number() + 1,
        round_hash,
        path_updates_hash,
    );

    // Step 10: Sign the commit with identity key
    let signature = sign_commit(identity, &commit_content)?;

    // Step 11: Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // Step 12: Compute confirmation tag
    let confirmation_tag = compute_confirmation_tag(
        &delta_root,
        &new_transcript,
        session.epoch_number() + 1,
    );

    let commit = UpdateCommit {
        group_id: *session.group_id(),
        updater_leaf_position: session.our_leaf_position(),
        epoch: session.epoch_number() + 1,
        path_updates,
        signature,
        round_hash,
        confirmation_tag,
    };

    // Step 13: Advance epoch with real delta_root
    session.advance_epoch(&delta_root, new_transcript);

    Ok(commit)
}

/// Computes resolution sets and their public keys for path encryption.
///
/// For each node in the path, computes the resolution of its sibling subtree
/// and collects the public keys for encryption.
#[cfg(feature = "alloc")]
fn compute_resolution_sets_and_keys(
    session: &CocoaSession,
    path: &[NodeIndex],
) -> (Vec<Vec<NodeIndex>>, Vec<Vec<HybridKemPublicKey>>) {
    let mut resolution_sets = Vec::with_capacity(path.len());
    let mut resolution_keys = Vec::with_capacity(path.len());

    for path_node in path {
        // Compute Lj = Res(sibling(path_node))
        let resolution = compute_lj(session.tree(), *path_node, |_| Vec::new());

        // Collect public keys from resolution nodes
        let keys: Vec<HybridKemPublicKey> = resolution
            .iter()
            .filter_map(|node_idx| {
                session
                    .tree()
                    .get(node_idx)
                    .and_then(|node| node.state.public_key())
                    .cloned()
            })
            .collect();

        resolution_sets.push(resolution.nodes);
        resolution_keys.push(keys);
    }

    (resolution_sets, resolution_keys)
}

/// Computes sibling labels for parent hash computation.
///
/// For each non-leaf node in the path, computes the sibling's tree label.
/// The tree label is H3(depth, position, public_key) for populated siblings,
/// or all zeros for blank siblings.
///
/// # Arguments
///
/// * `session` - The current session with tree state
/// * `path` - The path from leaf to root
///
/// # Returns
///
/// A vector of sibling labels, one per non-leaf level (path_length - 1 entries).
#[cfg(feature = "alloc")]
fn compute_sibling_labels(session: &CocoaSession, path: &[NodeIndex]) -> Vec<[u8; 32]> {
    use crate::key_schedule::h3_tree_label;

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
                .map(|pk| h3_tree_label(sibling.depth, sibling.position, &pk.to_bytes()))
                .unwrap_or([0u8; 32]); // Blank sibling = zero label

            sibling_labels.push(label);
        } else {
            // Root has no sibling - use zero label
            sibling_labels.push([0u8; 32]);
        }
    }

    sibling_labels
}

/// Computes the root label from path seeds.
///
/// The root label is derived from the root seed and is used in the
/// round hash computation.
#[must_use]
fn compute_root_label(path_seeds: &[Seed]) -> [u8; 32] {
    use trelis_primitives::blake3_kdf::derive_key;

    if let Some(root_seed) = path_seeds.last() {
        derive_key("cocoa-sa-v1-root-label", root_seed)
    } else {
        [0u8; 32]
    }
}

/// Serialises path updates for hashing.
#[cfg(feature = "alloc")]
fn serialise_path_updates(updates: &[PathUpdate]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for update in updates {
        // Node index (8 bytes: depth u32 + position u32)
        bytes.extend_from_slice(&update.node_index.depth.to_le_bytes());
        bytes.extend_from_slice(&update.node_index.position.to_le_bytes());

        // Public key length and data
        let pk_len = update.new_public_key.len() as u32;
        bytes.extend_from_slice(&pk_len.to_le_bytes());
        bytes.extend_from_slice(&update.new_public_key);

        // Parent hash (64 bytes: h1 + h2)
        bytes.extend_from_slice(&update.parent_hash.0);
        bytes.extend_from_slice(&update.parent_hash.1);

        // Encrypted seeds count
        let seed_count = update.encrypted_seeds.len() as u32;
        bytes.extend_from_slice(&seed_count.to_le_bytes());

        for seed in &update.encrypted_seeds {
            // Recipient position
            bytes.extend_from_slice(&seed.recipient_position.to_le_bytes());

            // Encapsulation length and data
            let enc_len = seed.encapsulation.len() as u32;
            bytes.extend_from_slice(&enc_len.to_le_bytes());
            bytes.extend_from_slice(&seed.encapsulation);

            // Ciphertext length and data
            let ct_len = seed.ciphertext.len() as u32;
            bytes.extend_from_slice(&ct_len.to_le_bytes());
            bytes.extend_from_slice(&seed.ciphertext);
        }
    }

    bytes
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

    derive_key("cocoa-sa-v1-confirmation-tag", &input)
}

/// Processes an update commit from another member.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `commit` - The update commit to process
/// * `updater_identity` - The updater's public identity key for signature verification
#[cfg(feature = "alloc")]
pub fn process_update(
    session: &mut CocoaSession,
    commit: &UpdateCommit,
    updater_identity: &HybridIdentityPublicKey,
) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Verify updater position is valid
    if commit.updater_leaf_position >= session.member_count() {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    // Compute path updates hash for verification
    let path_updates_hash = hash_path_updates(&[]); // Would serialise actual path updates

    // Build commit content for verification
    let commit_content = CommitContent::new_update(
        commit.group_id,
        commit.epoch,
        commit.round_hash,
        path_updates_hash,
    );

    // Verify signature
    verify_commit_signature(updater_identity, &commit_content, &commit.signature)?;

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

    fn create_test_identity() -> HybridIdentityKeypair {
        HybridIdentityKeypair::generate().unwrap()
    }

    #[test]
    fn test_create_update() {
        let mut session = create_test_session();
        let identity = create_test_identity();
        let initial_epoch = session.epoch_number();

        let commit = create_update(&mut session, &identity).unwrap();

        assert_eq!(commit.updater_leaf_position, 0);
        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[test]
    fn test_process_update() {
        let mut session = create_test_session();
        let other_identity = create_test_identity();

        // Add another member first
        session.tree_mut().set_member_count(2);
        let initial_epoch = session.epoch_number();

        // Build a valid commit from the other member
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_update(
            *session.group_id(),
            initial_epoch + 1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&other_identity, &commit_content).unwrap();

        let commit = UpdateCommit {
            group_id: *session.group_id(),
            updater_leaf_position: 1, // Other member
            epoch: initial_epoch + 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0x22u8; 32],
        };

        process_update(&mut session, &commit, other_identity.public_key()).unwrap();

        assert_eq!(session.epoch_number(), initial_epoch + 1);
    }

    #[test]
    fn test_process_update_wrong_signer() {
        let mut session = create_test_session();
        let signer_identity = create_test_identity();
        let wrong_identity = create_test_identity();

        session.tree_mut().set_member_count(2);

        // Build commit signed by signer_identity
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_update(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&signer_identity, &commit_content).unwrap();

        let commit = UpdateCommit {
            group_id: *session.group_id(),
            updater_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0x22u8; 32],
        };

        // Try to verify with wrong identity - should fail
        let result = process_update(&mut session, &commit, wrong_identity.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_process_update_invalid_position() {
        let mut session = create_test_session();
        let other_identity = create_test_identity();

        // Build commit with valid signature but invalid position
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_update(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&other_identity, &commit_content).unwrap();

        let commit = UpdateCommit {
            group_id: *session.group_id(),
            updater_leaf_position: 99, // Invalid
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0x22u8; 32],
        };

        // Position check happens before signature verification
        let result = process_update(&mut session, &commit, other_identity.public_key());
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    #[test]
    fn test_update_advances_epoch() {
        let mut session = create_test_session();
        let identity = create_test_identity();

        for i in 0..5 {
            let commit = create_update(&mut session, &identity).unwrap();
            assert_eq!(commit.epoch, i + 1);
        }

        assert_eq!(session.epoch_number(), 5);
    }
}
