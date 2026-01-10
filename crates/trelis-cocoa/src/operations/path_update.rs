//! Path update building and application for CoCoA commits.
//!
//! This module provides the high-level path update functionality that
//! coordinates seed chain derivation and encryption.
//!
//! # Overview
//!
//! When a member performs a commit operation (add, remove, update), they:
//! 1. Generate a fresh leaf seed
//! 2. Derive path seeds from leaf to root
//! 3. Derive new keypairs for each path node
//! 4. Encrypt seeds to resolution sets at each level
//! 5. Compute parent hashes for tree integrity
//!
//! # Recipient Processing
//!
//! When a recipient processes a commit:
//! 1. Find their encrypted seed in the path updates
//! 2. Decrypt to recover the node seed
//! 3. Derive path seeds up to the root
//! 4. Derive keypairs and verify public keys match
//! 5. Update their partial tree view

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridKemKeypair, HybridKemPublicKey};

use crate::key_schedule::{h4_parent_hash_h1, h4_parent_hash_h2};
use crate::operations::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};
use crate::operations::seed_encrypt::{EncryptedNodeSeed, decrypt_seed, encrypt_seed_to_recipient};
use crate::tree::{NodeIndex, PartialTreeView};

/// A complete path update for a single node.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct NodeUpdate {
    /// The node being updated.
    pub node_index: NodeIndex,
    /// The new public key at this node.
    pub public_key: HybridKemPublicKey,
    /// Parent hash components (h1, h2) for tree integrity.
    pub parent_hash: ([u8; 32], [u8; 32]),
    /// Encrypted seeds for each recipient in the resolution set.
    pub encrypted_seeds: Vec<RecipientSeed>,
}

/// An encrypted seed for a specific recipient.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct RecipientSeed {
    /// The recipient's node index (their leaf or unmerged node).
    pub recipient_index: NodeIndex,
    /// The encrypted seed.
    pub encrypted: EncryptedNodeSeed,
}

/// Result of building path updates.
#[cfg(feature = "alloc")]
pub struct PathUpdateResult {
    /// The updates for each node in the path (leaf to root).
    pub updates: Vec<NodeUpdate>,
    /// The delta root for epoch key derivation.
    pub delta_root: Seed,
}

/// Builds path updates for a commit.
///
/// This function generates the complete path update package:
/// 1. Generates a fresh leaf seed
/// 2. Derives seeds for each path node
/// 3. Derives new keypairs
/// 4. Encrypts seeds to resolution sets
/// 5. Computes parent hashes
///
/// # Arguments
///
/// * `tree` - The current tree view
/// * `our_leaf_position` - Our position in the tree
/// * `resolution_sets` - For each path node, the resolution set (nodes whose members need the seed)
/// * `resolution_keys` - For each resolution set, the public keys of the recipients
/// * `sibling_labels` - For each path level (except leaf), the sibling's tree label.
///   Computed as `h3_tree_label(sibling.depth, sibling.position, sibling.public_key)`.
///   For blank siblings, use all zeros.
///
/// # Returns
///
/// A `PathUpdateResult` containing the updates and delta root.
///
/// # Note
///
#[cfg(feature = "alloc")]
pub fn build_path_updates(
    tree: &PartialTreeView,
    our_leaf_position: u32,
    resolution_sets: &[Vec<NodeIndex>],
    resolution_keys: &[Vec<&HybridKemPublicKey>],
    sibling_labels: &[[u8; 32]],
) -> Result<PathUpdateResult> {
    use crate::operations::seed_chain::derive_node_keypair;

    // Generate fresh leaf seed
    let leaf_seed = generate_leaf_seed()?;

    // Calculate path length (leaf to root)
    let tree_depth = tree.tree_depth();
    let path_length = (tree_depth + 1) as usize;

    // Derive all path seeds
    let path_seeds = derive_path_seeds(&leaf_seed, path_length);

    // Validate inputs
    if resolution_sets.len() != path_length || resolution_keys.len() != path_length {
        return Err(CryptoError::MalformedMessage);
    }
    // sibling_labels should have path_length - 1 entries (one per non-leaf level)
    if sibling_labels.len() != path_length.saturating_sub(1) {
        return Err(CryptoError::MalformedMessage);
    }

    let mut updates = Vec::with_capacity(path_length);

    // Track the previous h2 for parent hash chaining
    let mut prev_h2 = [0u8; 32]; // Leaf has zero h2

    // Track predecessor public keys (accumulated as we go up the path)
    let mut predecessor_keys: Vec<HybridKemPublicKey> = Vec::with_capacity(path_length);

    // Build update for each path node (from leaf to root)
    for (level, seed) in path_seeds.iter().enumerate() {
        // Compute node index
        let depth = tree_depth - level as u32;
        let position = our_leaf_position >> level;
        let node_index = NodeIndex::new(depth, position);

        // Derive keypair from seed
        let keypair = derive_node_keypair(seed);
        let public_key = keypair.public_key().clone();

        // Get resolution set and keys for this level
        let resolution = &resolution_sets[level];
        let keys = &resolution_keys[level];

        if resolution.len() != keys.len() {
            return Err(CryptoError::MalformedMessage);
        }

        // Encrypt seed to each recipient
        let mut encrypted_seeds = Vec::with_capacity(resolution.len());
        for (i, recipient_idx) in resolution.iter().enumerate() {
            let encrypted = encrypt_seed_to_recipient(seed, keys[i], &node_index)?;
            encrypted_seeds.push(RecipientSeed {
                recipient_index: *recipient_idx,
                encrypted,
            });
        }

        // Compute parent hash
        let (h1, h2) = if level == 0 {
            // Leaf node: h1 = 0, h2 = 0
            ([0u8; 32], [0u8; 32])
        } else {
            // Get sibling label from caller-provided array
            let sibling_label = &sibling_labels[level - 1];

            // Compute h1 (sibling binding)
            let h1 = h4_parent_hash_h1(&public_key, sibling_label);

            // Compute h2 (predecessor binding)
            // Predecessor keys are the public keys from earlier levels in this same commit
            let pred_refs: Vec<&HybridKemPublicKey> = predecessor_keys.iter().collect();
            let resolution_key_refs: Vec<&HybridKemPublicKey> = keys.to_vec();
            let h2 = h4_parent_hash_h2(&public_key, &pred_refs, &prev_h2, &resolution_key_refs);

            (h1, h2)
        };

        prev_h2 = h2;

        // Add current public key to predecessors for next level
        predecessor_keys.push(public_key.clone());

        updates.push(NodeUpdate {
            node_index,
            public_key,
            parent_hash: (h1, h2),
            encrypted_seeds,
        });
    }

    // Delta root is the root seed
    let delta_root = path_seeds.last().copied().unwrap_or([0u8; 32]);

    Ok(PathUpdateResult {
        updates,
        delta_root,
    })
}

/// Builds path updates using pre-computed seeds.
///
/// This variant allows the caller to specify the tree depth and pre-computed
/// path seeds, which is useful when the tree is growing (e.g., during add
/// operations where the tree depth changes).
///
/// # Arguments
///
/// * `tree_depth` - The tree depth to use (may differ from current tree)
/// * `our_leaf_position` - Our position in the tree
/// * `path_seeds` - Pre-computed path seeds (from leaf to root)
/// * `resolution_sets` - For each path node, the resolution set
/// * `resolution_keys` - For each resolution set, the public keys
/// * `sibling_labels` - For each path level (except leaf), the sibling's tree label.
///   Computed as `h3_tree_label(sibling.depth, sibling.position, sibling.public_key)`.
///   For blank siblings, use all zeros.
///
/// # Returns
///
/// A `PathUpdateResult` containing the updates and delta root.
#[cfg(feature = "alloc")]
pub fn build_path_updates_with_seeds(
    tree_depth: u32,
    our_leaf_position: u32,
    path_seeds: &[Seed],
    resolution_sets: &[Vec<NodeIndex>],
    resolution_keys: &[Vec<&HybridKemPublicKey>],
    sibling_labels: &[[u8; 32]],
) -> Result<PathUpdateResult> {
    use crate::operations::seed_chain::derive_node_keypair;

    let path_length = path_seeds.len();

    // Validate inputs
    if resolution_sets.len() != path_length || resolution_keys.len() != path_length {
        return Err(CryptoError::MalformedMessage);
    }
    // sibling_labels should have path_length - 1 entries (one per non-leaf level)
    if sibling_labels.len() != path_length.saturating_sub(1) {
        return Err(CryptoError::MalformedMessage);
    }

    let mut updates = Vec::with_capacity(path_length);

    // Track the previous h2 for parent hash chaining
    let mut prev_h2 = [0u8; 32]; // Leaf has zero h2

    // Track predecessor public keys (accumulated as we go up the path)
    let mut predecessor_keys: Vec<HybridKemPublicKey> = Vec::with_capacity(path_length);

    // Build update for each path node (from leaf to root)
    for (level, seed) in path_seeds.iter().enumerate() {
        // Compute node index
        let depth = tree_depth - level as u32;
        let position = our_leaf_position >> level;
        let node_index = NodeIndex::new(depth, position);

        // Derive keypair from seed
        let keypair = derive_node_keypair(seed);
        let public_key = keypair.public_key().clone();

        // Get resolution set and keys for this level
        let resolution = &resolution_sets[level];
        let keys = &resolution_keys[level];

        if resolution.len() != keys.len() {
            return Err(CryptoError::MalformedMessage);
        }

        // Encrypt seed to each recipient
        let mut encrypted_seeds = Vec::with_capacity(resolution.len());
        for (i, recipient_idx) in resolution.iter().enumerate() {
            let encrypted = encrypt_seed_to_recipient(seed, keys[i], &node_index)?;
            encrypted_seeds.push(RecipientSeed {
                recipient_index: *recipient_idx,
                encrypted,
            });
        }

        // Compute parent hash
        let (h1, h2) = if level == 0 {
            // Leaf node: h1 = 0, h2 = 0
            ([0u8; 32], [0u8; 32])
        } else {
            // Get sibling label from caller-provided array
            let sibling_label = &sibling_labels[level - 1];

            // Compute h1 (sibling binding)
            let h1 = h4_parent_hash_h1(&public_key, sibling_label);

            // Compute h2 (predecessor binding)
            // Predecessor keys are the public keys from earlier levels in this same commit
            let pred_refs: Vec<&HybridKemPublicKey> = predecessor_keys.iter().collect();
            let resolution_key_refs: Vec<&HybridKemPublicKey> = keys.to_vec();
            let h2 = h4_parent_hash_h2(&public_key, &pred_refs, &prev_h2, &resolution_key_refs);

            (h1, h2)
        };

        prev_h2 = h2;

        // Add current public key to predecessors for next level
        predecessor_keys.push(public_key.clone());

        updates.push(NodeUpdate {
            node_index,
            public_key,
            parent_hash: (h1, h2),
            encrypted_seeds,
        });
    }

    // Delta root is the root seed
    let delta_root = path_seeds.last().copied().unwrap_or([0u8; 32]);

    Ok(PathUpdateResult {
        updates,
        delta_root,
    })
}

/// Applies path updates from a commit to our tree view.
///
/// This function:
/// 1. Finds our encrypted seed in the path updates
/// 2. Decrypts to recover our node seed
/// 3. Derives the rest of the path seeds
/// 4. Verifies public keys match
/// 5. Returns the delta root
///
/// # Arguments
///
/// * `path_updates` - The path updates from the commit
/// * `our_keypair` - Our current keypair (to decrypt seeds)
/// * `our_position` - Our position in the tree
/// * `updater_leaf` - The leaf position of the member who created the update
///
/// # Returns
///
/// The delta root for epoch key derivation.
#[cfg(feature = "alloc")]
pub fn apply_path_updates(
    path_updates: &[NodeUpdate],
    our_keypair: &HybridKemKeypair,
    _our_position: u32,
    _updater_leaf: u32,
) -> Result<Seed> {
    use crate::operations::seed_chain::derive_node_keypair;

    if path_updates.is_empty() {
        return Err(CryptoError::MalformedMessage);
    }

    // Find which level we can decrypt at
    // We need to find an encrypted seed where we're in the resolution set
    let mut decrypted_seed: Option<(usize, Seed)> = None;

    for (level, update) in path_updates.iter().enumerate() {
        for recipient in &update.encrypted_seeds {
            // Check if this is for us by trying to decrypt
            if let Ok(seed) = decrypt_seed(&recipient.encrypted, our_keypair, &update.node_index) {
                decrypted_seed = Some((level, seed));
                break;
            }
        }
        if decrypted_seed.is_some() {
            break;
        }
    }

    let (decrypt_level, seed) = decrypted_seed.ok_or(CryptoError::DecryptionFailed)?;

    // Derive path seeds from our decrypted level to root
    let remaining_path = path_updates.len() - decrypt_level;
    let path_seeds = derive_path_seeds(&seed, remaining_path);

    // Verify public keys match
    for (i, path_seed) in path_seeds.iter().enumerate() {
        let expected_keypair = derive_node_keypair(path_seed);
        let update_level = decrypt_level + i;

        if update_level < path_updates.len() {
            let expected_pk = expected_keypair.public_key().to_bytes();
            let actual_pk = path_updates[update_level].public_key.to_bytes();

            if expected_pk != actual_pk {
                return Err(CryptoError::SignatureVerificationFailed);
            }
        }
    }

    // Delta root is derived from the root seed
    let delta_root = path_seeds.last().copied().unwrap_or([0u8; 32]);

    Ok(delta_root)
}

/// Finds a suitable node to use as our reception point in a resolution set.
///
/// This is used to determine which encrypted seed we should look for.
#[must_use]
pub fn find_our_resolution_node(
    our_position: u32,
    tree_depth: u32,
    updater_position: u32,
) -> Option<NodeIndex> {
    // Our leaf node
    let our_leaf = NodeIndex::leaf(tree_depth, our_position);

    // The updater's path
    let updater_leaf = NodeIndex::leaf(tree_depth, updater_position);

    // Find the lowest common ancestor
    let mut our_path_node = our_leaf;
    let mut updater_path_node = updater_leaf;

    // Walk up until we find the common ancestor
    while our_path_node != updater_path_node {
        if our_path_node.depth < updater_path_node.depth {
            updater_path_node = updater_path_node.parent()?;
        } else if our_path_node.depth > updater_path_node.depth {
            our_path_node = our_path_node.parent()?;
        } else {
            // Same depth, different nodes - go up both
            our_path_node = our_path_node.parent()?;
            updater_path_node = updater_path_node.parent()?;
        }
    }

    // Return our leaf as the resolution node
    // (in practice, might be an unmerged node)
    Some(our_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_our_resolution_node() {
        // Two members at positions 0 and 1 in depth-2 tree
        let node = find_our_resolution_node(0, 2, 1);
        assert!(node.is_some());
        assert_eq!(node.unwrap(), NodeIndex::new(2, 0));
    }

    #[test]
    fn test_build_and_apply_path_updates() {
        // Create a simple 2-member tree
        let tree = PartialTreeView::new(0, 2);

        // Generate keypairs for the other member
        let other_keypair = HybridKemKeypair::generate().unwrap();

        // Resolution sets: at each level, who needs the seed
        // For a 2-member tree with depth 2, we have 3 levels (leaf, internal, root)
        let resolution_sets = vec![
            vec![NodeIndex::new(2, 1)], // Level 0 (our leaf): other member
            vec![NodeIndex::new(2, 1)], // Level 1: sibling subtree = other member
            vec![],                     // Level 2 (root): no one
        ];

        let resolution_keys: Vec<Vec<&HybridKemPublicKey>> = vec![
            vec![other_keypair.public_key()],
            vec![other_keypair.public_key()],
            vec![],
        ];

        // Sibling labels: one per non-leaf level (2 levels: 1 and 0/root)
        // Use zeros for testing (represents blank siblings)
        let sibling_labels = vec![
            [0u8; 32], // Level 1 sibling label
            [0u8; 32], // Root sibling label (root has no sibling, but we still need the array)
        ];

        let result = build_path_updates(
            &tree,
            0,
            &resolution_sets,
            &resolution_keys,
            &sibling_labels,
        )
        .unwrap();

        assert_eq!(result.updates.len(), 3);

        // The other member should be able to decrypt
        let delta_root = apply_path_updates(&result.updates, &other_keypair, 1, 0).unwrap();

        assert_eq!(delta_root, result.delta_root);
    }
}
