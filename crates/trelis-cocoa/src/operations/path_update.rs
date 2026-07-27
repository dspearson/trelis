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
use alloc::collections::BTreeSet;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridKemKeypair, HybridKemPublicKey};

use crate::key_schedule::{h3_tree_label, h4_parent_hash_h1, h4_parent_hash_h2};
use crate::operations::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};
use crate::operations::seed_encrypt::{EncryptedNodeSeed, decrypt_seed, encrypt_seed_to_recipient};
use crate::tree::{NodeIndex, PartialTreeView, compute_lj};

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
        let keypair = derive_node_keypair(seed)?;
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
            let resolution_key_refs: Vec<&HybridKemPublicKey> = keys.clone();
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
        let keypair = derive_node_keypair(seed)?;
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
            let resolution_key_refs: Vec<&HybridKemPublicKey> = keys.clone();
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

// Test-only decapsulation-attempt counter (PRF-02). Incremented at each
// `decrypt_seed` call site in `apply_path_updates` (both the fast path and the
// fallback) so the structural test can prove the honest fast path decapsulates
// exactly ONE recipient. Guarded by `#[cfg(test)]`, so it is compiled out of
// production builds and adds zero runtime cost to the shipped path. A
// `thread_local!` (not a shared `static AtomicU32`) keeps the count isolated per
// test thread, so cargo's parallel runner — e.g. the concurrent
// `test_build_and_apply_path_updates`, which also calls `apply_path_updates` —
// cannot perturb the measured value (no `serial_test`/`--test-threads=1`
// needed). The production call is synchronous, so the counter observes only the
// measuring test's own decap attempts. A plain `//` comment (not `///`): rustdoc
// does not document macro invocations, so a doc comment here trips
// `unused_doc_comments` under `-D warnings`.
#[cfg(test)]
thread_local! {
    static DECAP_ATTEMPTS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
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
///
/// # Internal primitive
///
/// Low-level path-decap primitive. Callers MUST use the gated entry points that
/// perform validate-before-mutate (`process_add` / `process_update`), never
/// invoke this directly — there is no live bypass caller. It stays `pub` for
/// internal cross-module reuse and is not part of the intended external surface
/// (LOW-01, doc-only: symbol unchanged).
#[cfg(feature = "alloc")]
pub fn apply_path_updates(
    path_updates: &[NodeUpdate],
    our_keypair: &HybridKemKeypair,
    our_position: u32,
    updater_leaf: u32,
) -> Result<Seed> {
    use crate::operations::seed_chain::derive_node_keypair;

    if path_updates.is_empty() {
        return Err(CryptoError::MalformedMessage);
    }

    // Compute our expected resolution node ONCE (PRF-02 fast path). Path updates
    // run leaf→root, so index 0 is the leaf update and its `depth` is the tree
    // depth. The builder pairs `recipient_index[i]` 1:1 with the encryption key
    // (`build_path_updates`), so the entry that decrypts for us is exactly the one
    // whose `recipient_index` equals this node.
    let tree_depth = path_updates[0].node_index.depth;
    let our_node = find_our_resolution_node(our_position, tree_depth, updater_leaf);

    // Find which level we can decrypt at (lowest level first, leaf→root).
    // We need to find an encrypted seed where we're in the resolution set.
    let mut decrypted_seed: Option<(usize, Seed)> = None;

    for (level, update) in path_updates.iter().enumerate() {
        // FAST PATH (PRF-02): select OUR single recipient slot by `recipient_index`
        // and decapsulate only it — O(1) instead of trial-decrypting every
        // recipient. `find` compares `NodeIndex` only (no decap), so foreign
        // entries are never decapsulated, and a checked `.iter().find` never
        // panics on a wire-controlled index.
        let ours = our_node.and_then(|idx| {
            update
                .encrypted_seeds
                .iter()
                .find(|r| r.recipient_index == idx)
        });
        if let Some(seed) = ours.and_then(|recipient| {
            #[cfg(test)]
            DECAP_ATTEMPTS.with(|c| c.set(c.get() + 1));
            decrypt_seed(&recipient.encrypted, our_keypair, &update.node_index).ok()
        }) {
            decrypted_seed = Some((level, seed));
            break;
        }

        // FALLBACK: trial-decrypt every recipient at THIS level, exactly as
        // before. Covers `our_node == None`, no index match, or a matched entry
        // that failed to decrypt (e.g. unmerged-ancestor recipiency the fast path
        // does not model), so the HONEST case decaps exactly once and produces
        // the same `(level, seed)` as the trial loop. Note the two paths are NOT
        // seed-identical for an *adversarially* crafted level where a foreign
        // `recipient_index` entry that ALSO decrypts under our key is placed
        // before our own indexed entry: the fast path selects our indexed seed,
        // the trial loop would take the earlier-decryptable one. This is not a
        // regression — a wrong seed is rejected downstream by the public-key /
        // parent-hash gate (both paths cannot accept differing `delta_root`s),
        // and the indexed path is in fact MORE robust to a relay-injected decoy.
        for recipient in &update.encrypted_seeds {
            #[cfg(test)]
            DECAP_ATTEMPTS.with(|c| c.set(c.get() + 1));
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

    // Verify public keys match and validate parent hash constraints
    for (i, path_seed) in path_seeds.iter().enumerate() {
        let expected_keypair = derive_node_keypair(path_seed)?;
        let update_level = decrypt_level + i;

        if update_level < path_updates.len() {
            let update = &path_updates[update_level];
            let expected_pk = expected_keypair.public_key().to_bytes();
            let actual_pk = update.public_key.to_bytes();

            if expected_pk != actual_pk {
                return Err(CryptoError::SignatureVerificationFailed);
            }

            // Verify parent hash constraints
            // Leaf nodes (level 0) must have zero parent hashes
            if update_level == 0 {
                let (h1, h2) = update.parent_hash;
                if h1 != [0u8; 32] || h2 != [0u8; 32] {
                    return Err(CryptoError::SignatureVerificationFailed);
                }
            }
            // Note: Full parent-hash verification (h1, h2) for non-leaf nodes is
            // performed by `verify_parent_hashes` (GAP-02 `PHash.Ver`), which each
            // `process_*` ingest path calls against LOCAL tree state before any
            // tree write. `apply_path_updates` intentionally stays decryption /
            // leaf-check only so it remains independently testable.
        }
    }

    // Delta root is derived from the root seed
    let delta_root = path_seeds.last().copied().unwrap_or([0u8; 32]);

    Ok(delta_root)
}

/// Verifies the parent-hash chain (`PHash.Ver`, `12-cocoa.tex:850-909`) of a
/// commit's path updates against LOCAL tree state, rejecting a tampered tree
/// structure before any tree write.
///
/// This re-runs the SAME `h4_parent_hash_h1` / `h4_parent_hash_h2` builder
/// functions that `build_path_updates[_with_seeds]` used, against the
/// verifier's own [`PartialTreeView`], so an honest committer's parent hashes
/// reproduce byte-for-byte while a malicious server/member that repositions a
/// leaf (tampering a node's sibling binding) is rejected.
///
/// # Enforcement (OQ-1)
///
/// - **Leaf (level 0)** must carry `(h1, h2) == ([0;32], [0;32])`, else
///   [`CryptoError::ParentHashMismatch`].
/// - **`h1` (sibling binding) — MANDATORY on every non-leaf level.** The
///   sibling label is recomputed from the LOCAL co-path node
///   (`tree.get(sibling)`), which lies on the verifier's resolved co-path and
///   is therefore robustly available; a blank / absent sibling maps to the
///   `[0;32]` label on BOTH build and verify. A mismatch is rejected. This
///   delivers the anti-leaf-repositioning property GAP-02 (Insider-B) names.
/// - **`h2` (predecessor + resolution binding) — enforced UNCONDITIONALLY
///   wherever the resolution is locally determinable, INDEPENDENT of the wire
///   recipient count (CGA-01/SC1).** The resolution set is rebuilt as the
///   spec-literal `R = Res(sibling(v)) \ Unmerged(v)` (see
///   [`reconstruct_resolution_keys`]) together with a `complete` flag (see
///   [`reconstruct_resolution_complete`]) that distinguishes a node *absent*
///   from the partial view from a *known-blank* one. Where the level is
///   `complete`, `h2` is enforced regardless of `update.encrypted_seeds.len()`:
///   the wire's claimed recipient set MUST equal the local resolution set (a
///   structural check that rejects a padded recipient list — the exact
///   count-gate hole the 52-02 `local.len() == wire.len()` test left open) AND a
///   recomputed-`h2` mismatch is rejected. Where the resolution is genuinely NOT
///   locally reconstructable (a resolution key truly outside the partial view —
///   e.g. an add's fresh-member OTK not yet in our tree), `h2` is DEFERRED
///   (never false-rejected) with the predecessor chain still advanced from the
///   wire value; `h1` remains the load-bearing gate. This is the NARROWED
///   CGA-01/SC1 residual — closing it fully would require carrying the whole
///   public tree (a wire change), OUT OF SCOPE for this strengthen-only phase.
///
/// An empty `updates` slice is a no-op (`Ok`), so synthetic empty-path commits
/// still pass. `updates` is expected leaf → root (as the honest builder emits).
#[cfg(feature = "alloc")]
pub(crate) fn verify_parent_hashes(tree: &PartialTreeView, updates: &[NodeUpdate]) -> Result<()> {
    // Chain state, identical to the builder: the previous level's h2 (leaf child
    // h2 starts zero) and the accumulating predecessor public keys of THIS commit.
    let mut prev_h2 = [0u8; 32];
    let mut predecessors: Vec<HybridKemPublicKey> = Vec::with_capacity(updates.len());

    for (level, update) in updates.iter().enumerate() {
        let (wire_h1, wire_h2) = update.parent_hash;

        if level == 0 {
            // Leaf node: both parent-hash components MUST be zero.
            if wire_h1 != [0u8; 32] || wire_h2 != [0u8; 32] {
                return Err(CryptoError::ParentHashMismatch);
            }
        } else {
            // h1 (sibling binding) — MANDATORY. Recompute the sibling label from
            // our LOCAL co-path node, mirroring the build side exactly: a blank /
            // absent sibling — and the root, which has no sibling — map to the
            // `[0;32]` label (see `compute_sibling_labels`).
            let sibling_label = match update.node_index.sibling() {
                Some(sibling) => tree
                    .get(&sibling)
                    .and_then(|node| node.state.public_key())
                    .map_or([0u8; 32], |pk| {
                        h3_tree_label(sibling.depth, sibling.position, &pk.to_bytes())
                    }),
                None => [0u8; 32],
            };
            let exp_h1 = h4_parent_hash_h1(&update.public_key, &sibling_label);
            if exp_h1 != wire_h1 {
                return Err(CryptoError::ParentHashMismatch);
            }

            // h2 (predecessor + resolution binding) — enforced UNCONDITIONALLY
            // wherever the resolution is locally determinable, INDEPENDENT of the
            // wire recipient count. The old count gate (52-02) enforced only when
            // `local.len() == wire.len()`, so padding `encrypted_seeds` forced a
            // count mismatch that SKIPPED h2 entirely (the OQ-1/GAP-02 hole). We
            // now reconstruct the spec-literal R node set with a `complete` flag:
            // where determinable, we require the wire recipient SET to equal our
            // local set AND recompute-compare h2; where genuinely non-determinable,
            // we DEFER (h1 above stays the load-bearing gate) rather than
            // false-reject an honest partial-view commit.
            let (r_local_nodes, complete) =
                reconstruct_resolution_complete(tree, update.node_index);
            if complete {
                // (a) Structural check: reject a recipient list whose POSITION SET
                // differs from the local resolution's. The commit wire carries only
                // each recipient's `position` (depth is reconstructed on ingest and
                // is true-depth on the direct builder path — the two representations
                // agree ONLY on position), so we compare position sets, NOT full
                // (depth, position) node sets — a full node-set compare would
                // false-reject honest internal-node resolutions (the wire depth is the
                // PATH node's, not the recipient's true depth), so position-set
                // comparison is REQUIRED here, not a shortcut.
                //
                // EXACT guarantee (WR-02): this rejects only a recipient list that
                // introduces a NEW position absent from the local resolution. It does
                // NOT reject duplicate-position padding (an extra seed at a position
                // already present — set semantics collapse it) nor a same-position /
                // different-depth substitution. Those shapes are backstopped by the
                // (b) h2 recompute over the LOCAL resolution keys below — NOT by (a).
                // (a) is therefore a position-set gate, not a complete "reject any
                // padded recipient list" gate.
                let r_wire: BTreeSet<u32> = update
                    .encrypted_seeds
                    .iter()
                    .map(|s| s.recipient_index.position)
                    .collect();
                let r_local: BTreeSet<u32> = r_local_nodes.iter().map(|n| n.position).collect();
                if r_wire != r_local {
                    return Err(CryptoError::ParentHashMismatch);
                }

                // (b) Hash check: recompute h2 over our LOCAL resolution keys
                // (spec-literal R) and reject a mismatch.
                let pred_refs: Vec<&HybridKemPublicKey> = predecessors.iter().collect();
                let local_res_keys = reconstruct_resolution_keys(tree, update.node_index);
                let res_refs: Vec<&HybridKemPublicKey> = local_res_keys.iter().collect();
                let exp_h2 = h4_parent_hash_h2(&update.public_key, &pred_refs, &prev_h2, &res_refs);
                if exp_h2 != wire_h2 {
                    return Err(CryptoError::ParentHashMismatch);
                }
            }
            // else: genuinely non-determinable resolution — DEFER h2 (the narrowed
            // OQ-1/CGA-01 residual); h1 was already enforced above.
        }

        // Advance the chain with the wire values (identical to the builder, whose
        // computed h2 equals the wire h2 for an honest commit).
        prev_h2 = wire_h2;
        predecessors.push(update.public_key.clone());
    }

    Ok(())
}

/// Joiner-side Welcome `tree_info` parent-hash verification (GAP-02 SC2 joiner
/// clause, Insider-B).
///
/// The ingest-path [`verify_parent_hashes`] recomputes a non-leaf `h1` against
/// the verifier's LOCAL co-path (robustly available) and treats an absent
/// sibling as a legitimate blank `[0;32]` label — correct THERE because a
/// resident member's co-path really is blank/absent. A fresh joiner is
/// different: the Welcome `tree_info` carries only the adder's PATH nodes and
/// NO co-path, so the joiner cannot honestly recompute a non-leaf `h1`. Running
/// the ingest verifier against a guaranteed-empty view (the superseded
/// `process_welcome` behaviour) both (a) provided ZERO real protection — every
/// expected label collapsed to `[0;32]`, which a malicious committer trivially
/// matches — AND (b) FALSE-REJECTED honest welcomes whose non-leaf `h1` was
/// built against populated co-path siblings (CR-01).
///
/// This verifier is HONEST about the join-path partial view:
///
/// - it reconstructs a lookup from the `tree_info` nodes themselves, so it is
///   forward-compatible with a future full co-path reconstruction;
/// - it enforces the leaf invariant `(h1, h2) == (0, 0)`, keyed off the node's
///   TRUE depth (`node_index.depth == tree_depth`) rather than a positional
///   index, so a blank adder leaf dropped by `parse_welcome_tree_info` does not
///   desync leaf detection (IN-01); and
/// - it recomputes and enforces a non-leaf `h1` ONLY where the sibling is
///   actually present in the reconstructed `tree_info` view, and SKIPS (never
///   `ParentHashMismatch`) where it is absent — the documented GAP-02 join-path
///   residual — so honest multi-member welcomes are NOT false-rejected.
///
/// `h2` (predecessor/resolution binding) is not reconstructable from the
/// path-only `tree_info` and is left to the residual. Full join-path tree
/// reconstruction + mandatory parent-hash enforcement remains the tracked
/// GAP-02 residual (the OQ-1 partial-view philosophy applied to the join path).
///
/// An empty `nodes` slice is a no-op (`Ok`).
#[cfg(feature = "alloc")]
pub(crate) fn verify_welcome_tree_info(nodes: &[NodeUpdate], tree_depth: u32) -> Result<()> {
    use alloc::collections::BTreeMap;

    // Reconstruct a linear-index -> public-key lookup from the tree_info nodes
    // themselves (the adder's path). Co-path siblings are NOT carried in the
    // path-only tree_info, so non-leaf sibling lookups miss and `h1` is skipped;
    // this becomes enforcing if/when a full co-path reconstruction is supplied.
    let mut view: BTreeMap<u64, HybridKemPublicKey> = BTreeMap::new();
    for node in nodes {
        view.insert(node.node_index.to_linear(), node.public_key.clone());
    }

    for node in nodes {
        let (wire_h1, wire_h2) = node.parent_hash;

        if node.node_index.depth == tree_depth {
            // Leaf (identified by TRUE depth — robust to dropped blank nodes,
            // IN-01): both parent-hash components MUST be zero.
            if wire_h1 != [0u8; 32] || wire_h2 != [0u8; 32] {
                return Err(CryptoError::ParentHashMismatch);
            }
        } else if let Some(sibling) = node.node_index.sibling() {
            // Non-leaf: enforce `h1` ONLY where the sibling is present in the
            // reconstructed tree_info view; otherwise SKIP (join-path partial-
            // view residual) rather than false-reject an honest welcome.
            if let Some(sibling_pk) = view.get(&sibling.to_linear()) {
                let sibling_label =
                    h3_tree_label(sibling.depth, sibling.position, &sibling_pk.to_bytes());
                let exp_h1 = h4_parent_hash_h1(&node.public_key, &sibling_label);
                if exp_h1 != wire_h1 {
                    return Err(CryptoError::ParentHashMismatch);
                }
            }
            // else: sibling absent from the joiner's partial view — residual.
        }
        // `h2` is not reconstructable from path-only tree_info (GAP-02 residual).
    }

    Ok(())
}

/// Rebuilds the `h2` resolution-key slice for a path node from LOCAL tree state,
/// realising the **spec-literal §12 `R = Res(sibling(v)) \ Unmerged(v)`** (both
/// boxed §12 formulas — `Lj` at §12:394 and `R` at §12:441), with `v = path_node`.
///
/// `compute_lj` already yields `Res(sibling(v))` (its `∪ Unmerged(Res(sibling(v)))`
/// term is vacuous — `resolve` returns only populated nodes, whose
/// `unmerged_leaves()` is `None`). We then apply the spec's `\ Unmerged(v)`
/// subtraction EXPLICITLY: drop any resolution leaf whose position is an unmerged
/// leaf of `v`. This is provably a no-op — `Unmerged(v)` lies under `v`'s own
/// subtree while `Res(sibling(v))` lies under the disjoint sibling subtree — so
/// `R == Lj == Res(sibling(v))`, asserted below and proven by the
/// `test_parent_hash_R_equals_Lj_invariant` invariant test. This RESOLVES the
/// former §12-`R`-vs-impl-`Lj` discrepancy for CGA-01/SC2 as a proven, tested
/// invariant rather than a silent `Lj` mirror or dead code, while keeping the
/// emitted key slice byte-identical to the builder's `compute_lj` output (the
/// verifier ≡ builder / no-false-reject guarantee, 52-02 principle preserved).
///
/// Note: this keeps §12's LITERAL `Unmerged(v)` (vacuous here). MLS-strict
/// `Unmerged(parent)` alignment — which WOULD be load-bearing — is a separate
/// future item; it would require decoupling the builder and is deliberately not
/// done in this strengthen-only phase.
#[cfg(feature = "alloc")]
fn reconstruct_resolution_keys(
    tree: &PartialTreeView,
    path_node: NodeIndex,
) -> Vec<HybridKemPublicKey> {
    let tree_depth = tree.tree_depth();

    // WR-01 coupling guard: this hash-check path (gate (b)) realises
    // `Res(sibling(v)) ∪ Unmerged(Res(sibling(v)))` via `compute_lj`'s unmerged
    // closure, whereas its completeness twin `reconstruct_resolution_complete`
    // (gate (a)) realises the PLAIN `Res(sibling(v))` via `resolve_complete` with
    // NO such closure. The two node sets agree TODAY only because
    // `Unmerged(Res(sibling))` is always empty — resolution nodes are populated and
    // `NodeState::unmerged_leaves()` is `None` for populated nodes. IF a future
    // change integrates unmerged-leaf handling per the spec
    // `Lj = Res(wj) ∪ Unmerged(Res(wj))` (the documented future item flagged at
    // `update.rs:200-206`), THIS set would gain unmerged leaves that (a)'s
    // `resolve_complete` would NOT — so gate (a)'s `r_wire == r_local` check would
    // false-reject every honest commit carrying an unmerged member. These two
    // reconstructions MUST then be unified (share one traversal / apply the
    // identical unmerged closure) before unmerged leaves are populated — do NOT let
    // them drift. (See the twin note in `reconstruct_resolution_complete`.)
    let resolution = compute_lj(tree, path_node, |node_idx| {
        tree.get(node_idx)
            .and_then(|node| node.state.unmerged_leaves())
            .map(|leaf_positions| {
                leaf_positions
                    .iter()
                    .map(|&pos| NodeIndex::leaf(tree_depth, pos))
                    .collect()
            })
            .unwrap_or_default()
    });

    // §12 `\ Unmerged(v)`, v = path_node. `Unmerged(v)` is empty unless `v` is a
    // present blank node carrying unmerged leaves; even then the subtraction is
    // vacuous (its leaves lie under `v`, disjoint from `Res(sibling(v))`).
    let unmerged_v: BTreeSet<u32> = tree
        .get(&path_node)
        .and_then(|node| node.state.unmerged_leaves())
        .map(|positions| positions.iter().copied().collect())
        .unwrap_or_default();

    let r: Vec<NodeIndex> = resolution
        .iter()
        .filter(|idx| !(idx.depth == tree_depth && unmerged_v.contains(&idx.position)))
        .copied()
        .collect();

    debug_assert_eq!(
        r.len(),
        resolution.len(),
        "R == Lj invariant: Unmerged(v) is disjoint from Res(sibling(v)), so the subtraction is vacuous"
    );

    r.iter()
        .filter_map(|node_idx| {
            tree.get(node_idx)
                .and_then(|node| node.state.public_key())
                .cloned()
        })
        .collect()
}

/// Reconstructs the spec-literal parent-hash resolution set
/// `R = Res(sibling(v)) \ Unmerged(v)` for a path node `v` from LOCAL tree
/// state, together with a `complete` flag that is `true` iff the local
/// [`PartialTreeView`] fully determined that set — i.e. every node the
/// sibling-subtree traversal had to classify was present in the view (populated
/// OR explicit-blank), so NONE was absent-from-view.
///
/// This is the CGA-01/SC1 completeness lever. [`resolve`](crate::tree::resolve)
/// (resolution.rs) conflates an absent node (`get(idx).is_none()`) with a
/// known-blank leaf — both yield an empty resolution — so on its own it cannot
/// tell "this subtree is genuinely empty" from "I do not hold it". Here a `None`
/// node flips `complete = false`. The caller enforces `h2` UNCONDITIONALLY where
/// the resolution is determinable (`complete`) and DEFERS only where it genuinely
/// is not, independent of the wire recipient count.
///
/// The returned node set is the SAME spec-literal `R` that
/// [`reconstruct_resolution_keys`] maps to keys (both realise
/// `Res(sibling(v)) \ Unmerged(v)`), so a `complete`-gated recompute stays
/// verifier ≡ builder. The inner `resolve_complete` mirrors `resolve`
/// node-for-node so the resolution itself never diverges from the builder's
/// `compute_lj`.
#[cfg(feature = "alloc")]
fn reconstruct_resolution_complete(
    tree: &PartialTreeView,
    path_node: NodeIndex,
) -> (Vec<NodeIndex>, bool) {
    // Completeness-tracking resolution of a subtree root. Mirrors `resolve`
    // (resolution.rs) exactly, except a node absent from the LOCAL view reports
    // `complete = false` (where `resolve` would silently treat it as an empty
    // blank leaf). Populated subtrees are disjoint, so the child resolutions
    // never overlap — a plain concatenation matches `resolve`'s dedup union.
    fn resolve_complete(
        tree: &PartialTreeView,
        index: NodeIndex,
        tree_depth: u32,
    ) -> (Vec<NodeIndex>, bool) {
        match tree.get(&index) {
            Some(node) if node.state.is_populated() => (alloc::vec![index], true),
            Some(_) => {
                // Blank node.
                if index.is_leaf(tree_depth) {
                    // Known blank leaf — genuinely empty, and we KNOW it.
                    (Vec::new(), true)
                } else {
                    let (mut nodes, left_complete) =
                        resolve_complete(tree, index.left_child(), tree_depth);
                    let (right_nodes, right_complete) =
                        resolve_complete(tree, index.right_child(), tree_depth);
                    nodes.extend(right_nodes);
                    (nodes, left_complete && right_complete)
                }
            }
            // Absent from our partial view: we cannot pin this subtree's
            // resolution locally ⇒ genuinely non-determinable here.
            None => (Vec::new(), false),
        }
    }

    let tree_depth = tree.tree_depth();

    let Some(sibling) = path_node.sibling() else {
        // Root has no sibling: empty resolution, trivially complete.
        return (Vec::new(), true);
    };

    // WR-01 coupling guard: `resolve_complete` realises the PLAIN `Res(sibling(v))`
    // with NO `∪ Unmerged(Res(sibling(v)))` closure, whereas the hash-check twin
    // `reconstruct_resolution_keys` (gate (b)) applies that closure via
    // `compute_lj`. They agree TODAY only because `Unmerged(Res(sibling))` is
    // vacuous (populated resolution nodes have no unmerged leaves). IF a future
    // change populates unmerged leaves on resolution nodes per the spec
    // `Lj = Res(wj) ∪ Unmerged(Res(wj))` (the future item flagged at
    // `update.rs:200-206`), (b)'s key set would include unmerged leaves THIS node
    // set does NOT, so gate (a)'s `r_wire == r_local` check would false-reject
    // honest commits carrying an unmerged member. Unify the two reconstructions
    // (one shared traversal / identical unmerged closure) before integrating
    // unmerged leaves. (See the twin note in `reconstruct_resolution_keys`.)
    let (res_nodes, complete) = resolve_complete(tree, sibling, tree_depth);

    // Apply the spec-literal `\ Unmerged(v)` filter, identical to
    // `reconstruct_resolution_keys` (a no-op by subtree disjointness), so the two
    // R node sets stay byte-identical.
    let unmerged_v: BTreeSet<u32> = tree
        .get(&path_node)
        .and_then(|node| node.state.unmerged_leaves())
        .map(|positions| positions.iter().copied().collect())
        .unwrap_or_default();

    let r_nodes: Vec<NodeIndex> = res_nodes
        .iter()
        .filter(|idx| !(idx.depth == tree_depth && unmerged_v.contains(&idx.position)))
        .copied()
        .collect();

    debug_assert_eq!(
        r_nodes.len(),
        res_nodes.len(),
        "R == Lj invariant: Unmerged(v) is disjoint from Res(sibling(v))"
    );

    (r_nodes, complete)
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
        match our_path_node.depth.cmp(&updater_path_node.depth) {
            core::cmp::Ordering::Less => {
                updater_path_node = updater_path_node.parent()?;
            }
            core::cmp::Ordering::Greater => {
                our_path_node = our_path_node.parent()?;
            }
            core::cmp::Ordering::Equal => {
                // Same depth, different nodes - go up both
                our_path_node = our_path_node.parent()?;
                updater_path_node = updater_path_node.parent()?;
            }
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

    #[cfg_attr(miri, ignore)]
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

    /// PRF-02 structural proof: on the honest fast path, `apply_path_updates`
    /// decapsulates EXACTLY the indexed recipient — never trial-decrypting a
    /// foreign entry. The decrypt level carries two recipients with OURS SECOND,
    /// so a trial-only revert (which decaps in vector order) would attempt the
    /// foreign entry first and read `>= 2`; the `recipient_index` fast path reads
    /// exactly 1. It also asserts `delta_root` equals the builder's, proving the
    /// O(1) selection is behaviour-identical to the trial loop (SC2).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn apply_path_updates_decaps_only_indexed_recipient() {
        // 2-member tree, depth 2. We are leaf 1; the updater is leaf 0.
        let tree = PartialTreeView::new(0, 2);

        // OUR keypair (leaf 1) plus a FOREIGN member's keypair (a decoy recipient
        // whose ciphertext the fast path must never decapsulate).
        let our_keypair = HybridKemKeypair::generate().unwrap();
        let foreign_keypair = HybridKemKeypair::generate().unwrap();

        // Level 0 (our leaf) carries TWO recipients with OURS positioned SECOND:
        // the fast path must skip the foreign entry via `recipient_index` and
        // decapsulate ONLY our slot. Every recipient at a level shares the same
        // per-level seed, so which entry is chosen cannot change the result.
        let resolution_sets = vec![
            vec![NodeIndex::new(2, 3), NodeIndex::new(2, 1)], // [foreign, ours]
            vec![NodeIndex::new(2, 1)],                       // level 1: ours
            vec![],                                           // root: no one
        ];
        let resolution_keys: Vec<Vec<&HybridKemPublicKey>> = vec![
            vec![foreign_keypair.public_key(), our_keypair.public_key()],
            vec![our_keypair.public_key()],
            vec![],
        ];
        let sibling_labels = vec![[0u8; 32], [0u8; 32]];

        let result = build_path_updates(
            &tree,
            0,
            &resolution_sets,
            &resolution_keys,
            &sibling_labels,
        )
        .unwrap();
        assert_eq!(result.updates.len(), 3);

        // Reset the per-thread counter immediately before the single measured call.
        DECAP_ATTEMPTS.with(|c| c.set(0));

        // Apply as OUR member: our_position = 1 (leaf 1), updater_leaf = 0.
        let delta_root = apply_path_updates(&result.updates, &our_keypair, 1, 0).unwrap();

        // Behaviour unchanged: same delta root the builder produced.
        assert_eq!(delta_root, result.delta_root);

        // Structural proof: exactly ONE decap attempt — the fast path selected our
        // indexed slot and never trial-decrypted the foreign entry.
        assert_eq!(DECAP_ATTEMPTS.with(|c| c.get()), 1);
    }

    // ─── GAP-02: parent-hash verification (PHash.Ver) ───────────────────────

    /// Builds a populated tree node with the given public key (test helper).
    fn populated(index: NodeIndex, pk: HybridKemPublicKey) -> crate::tree::TreeNode {
        use crate::tree::{TreeNode, UpdateOrigin};
        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let sig = identity.sign(b"t").unwrap();
        TreeNode::new_populated(
            index,
            pk,
            None,
            ([0u8; 32], [0u8; 32]),
            [0u8; 32],
            sig,
            [0u8; 32],
            [0u8; 32],
            UpdateOrigin {
                epoch: 0,
                sequence: 0,
                timestamp: 0,
            },
        )
    }

    /// Builds an honest 2-member path-update chain via `build_path_updates`
    /// against an empty view with an external resolution key (mirrors
    /// `test_build_and_apply_path_updates`). h1 uses zero sibling labels on both
    /// sides; the external key at the non-leaf level is not in the tree, so h2
    /// defers there (count mismatch) and matches at the empty-resolution root.
    fn build_two_member_updates() -> (PartialTreeView, Vec<NodeUpdate>) {
        let tree = PartialTreeView::new(0, 2);
        let other = HybridKemKeypair::generate().unwrap();

        let resolution_sets = vec![
            vec![NodeIndex::new(2, 1)],
            vec![NodeIndex::new(2, 1)],
            vec![],
        ];
        let resolution_keys: Vec<Vec<&HybridKemPublicKey>> =
            vec![vec![other.public_key()], vec![other.public_key()], vec![]];
        let sibling_labels = vec![[0u8; 32], [0u8; 32]];

        let result = build_path_updates(
            &tree,
            0,
            &resolution_sets,
            &resolution_keys,
            &sibling_labels,
        )
        .unwrap();
        (tree, result.updates)
    }

    /// An empty updates slice is a no-op — synthetic empty-path commits pass.
    #[test]
    fn test_parent_hash_verify_empty_ok() {
        let tree = PartialTreeView::new(0, 2);
        verify_parent_hashes(&tree, &[]).unwrap();
    }

    /// An honest `build_path_updates` result verifies against the same view
    /// with NO false reject.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_verify_accepts_honest() {
        let (tree, updates) = build_two_member_updates();
        verify_parent_hashes(&tree, &updates).unwrap();
    }

    /// Flipping one byte of a non-leaf `h1` (sibling binding) is rejected — the
    /// load-bearing SC2 anti-leaf-repositioning gate.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_verify_rejects_tampered_h1() {
        let (tree, mut updates) = build_two_member_updates();
        // updates[1] is the first non-leaf level (root's child at (1,0)).
        updates[1].parent_hash.0[0] ^= 0xFF;
        assert!(matches!(
            verify_parent_hashes(&tree, &updates),
            Err(CryptoError::ParentHashMismatch)
        ));
    }

    /// A leaf node (level 0) carrying a non-zero parent hash is rejected.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_verify_leaf_nonzero_rejected() {
        let (tree, mut updates) = build_two_member_updates();
        updates[0].parent_hash.0 = [0x01u8; 32];
        assert!(matches!(
            verify_parent_hashes(&tree, &updates),
            Err(CryptoError::ParentHashMismatch)
        ));

        let (tree2, mut updates2) = build_two_member_updates();
        updates2[0].parent_hash.1 = [0x01u8; 32];
        assert!(matches!(
            verify_parent_hashes(&tree2, &updates2),
            Err(CryptoError::ParentHashMismatch)
        ));
    }

    /// The verifier's recomputed `h2` EQUALS the wire `h2` the honest builder
    /// produced when unmerged tracking is exercised (a member tracked on a blank
    /// ancestor, a populated node in the sibling subtree). This is the direct
    /// regression guard for the mirror-vs-diverge blocker: the resolution keys
    /// are built here via `compute_lj` DIRECTLY (the production-caller pattern),
    /// independent of the verifier's `reconstruct_resolution_keys`, so a future
    /// change that diverged the verifier to a `Res\Unmerged` set-difference
    /// would make `exp_h2 != wire_h2` and fail this test.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_verify_h2_matches_builder() {
        use crate::tree::TreeNode;

        // Depth-2 tree, our leaf 0. Path: (2,0) -> (1,0) -> (0,0).
        let mut tree = PartialTreeView::new(0, 2);

        // Leaf sibling (2,1): populated (level-0 resolution recipient).
        let kp_a = HybridKemKeypair::generate().unwrap();
        tree.insert(populated(NodeIndex::new(2, 1), kp_a.public_key().clone()));

        // Level-1 sibling (1,1): BLANK internal carrying an unmerged leaf
        // (exercises the unmerged closure), with one populated child (2,3) that
        // forms its resolution — the "add-then-update" shape.
        let mut blank_11 = TreeNode::new_blank(NodeIndex::new(1, 1));
        blank_11.state.add_unmerged_leaf(3);
        tree.insert(blank_11);
        let kp_b = HybridKemKeypair::generate().unwrap();
        tree.insert(populated(NodeIndex::new(2, 3), kp_b.public_key().clone()));

        // Build resolution sets/keys by MIRRORING the production caller
        // (update.rs::compute_resolution_sets_and_keys) via compute_lj DIRECTLY.
        let path = [
            NodeIndex::new(2, 0),
            NodeIndex::new(1, 0),
            NodeIndex::new(0, 0),
        ];
        let mut resolution_sets: Vec<Vec<NodeIndex>> = Vec::new();
        let mut resolution_keys: Vec<Vec<HybridKemPublicKey>> = Vec::new();
        for pn in &path {
            let res = compute_lj(&tree, *pn, |idx| {
                tree.get(idx)
                    .and_then(|n| n.state.unmerged_leaves())
                    .map(|ps| ps.iter().map(|&p| NodeIndex::leaf(2, p)).collect())
                    .unwrap_or_default()
            });
            let keys: Vec<HybridKemPublicKey> = res
                .iter()
                .filter_map(|idx| tree.get(idx).and_then(|n| n.state.public_key()).cloned())
                .collect();
            resolution_sets.push(res.nodes);
            resolution_keys.push(keys);
        }
        // The non-leaf level (1,0) resolves to exactly the populated (2,3).
        assert_eq!(resolution_keys[1].len(), 1);

        // Sibling labels: (1,1) blank -> [0;32]; root -> [0;32].
        let sibling_labels = vec![[0u8; 32], [0u8; 32]];
        let key_refs: Vec<Vec<&HybridKemPublicKey>> = resolution_keys
            .iter()
            .map(|ks| ks.iter().collect())
            .collect();

        let result =
            build_path_updates(&tree, 0, &resolution_sets, &key_refs, &sibling_labels).unwrap();
        assert_eq!(result.updates.len(), 3);

        // No false reject even though unmerged tracking is exercised.
        verify_parent_hashes(&tree, &result.updates).unwrap();

        // Direct mirror assertion: the verifier's recomputed h2 at (1,0) EQUALS
        // the wire h2 the builder produced.
        let level1 = &result.updates[1];
        let preds = [result.updates[0].public_key.clone()];
        let pred_refs: Vec<&HybridKemPublicKey> = preds.iter().collect();
        let recon = reconstruct_resolution_keys(&tree, level1.node_index);
        let recon_refs: Vec<&HybridKemPublicKey> = recon.iter().collect();
        let prev_h2 = result.updates[0].parent_hash.1; // leaf h2 == [0;32]
        let exp_h2 = h4_parent_hash_h2(&level1.public_key, &pred_refs, &prev_h2, &recon_refs);
        assert_eq!(
            exp_h2, level1.parent_hash.1,
            "verifier h2 must equal wire h2"
        );

        // The reconstructed resolution key is exactly the populated (2,3) key.
        assert_eq!(recon.len(), 1);
        assert_eq!(recon[0].to_bytes(), kp_b.public_key().to_bytes());
    }

    /// SC2 invariant: the verifier's spec-literal `R = Res(sibling(v)) \
    /// Unmerged(v)` equals the unfiltered `Lj` (and equals `Res(sibling(v))`)
    /// even when `Unmerged(v) != ∅`. The path node `v = (1,0)` is a blank
    /// carrying unmerged leaves {0,1} (leaves UNDER v's own subtree), while the
    /// sibling `(1,1)` resolves to two populated leaves (2,2),(2,3) UNDER the
    /// disjoint sibling subtree — so the `\ Unmerged(v)` subtraction removes
    /// nothing. This converts the former dead-code §12-R-vs-impl-Lj discrepancy
    /// into a proven, tested invariant.
    #[cfg_attr(miri, ignore)]
    #[test]
    #[allow(non_snake_case)] // name mirrors the mathematical `R == Lj` invariant
    fn test_parent_hash_R_equals_Lj_invariant() {
        use crate::tree::{TreeNode, resolve};

        // Depth-2 tree. v = (1,0): its subtree covers leaf positions {0,1};
        // sibling (1,1)'s subtree covers {2,3} — disjoint by construction.
        let mut tree = PartialTreeView::new(0, 2);

        // v = (1,0): BLANK with unmerged leaves {0,1} ⇒ Unmerged(v) != ∅.
        let mut v_blank = TreeNode::new_blank(NodeIndex::new(1, 0));
        v_blank.state.add_unmerged_leaf(0);
        v_blank.state.add_unmerged_leaf(1);
        tree.insert(v_blank);

        // sibling (1,1): BLANK internal with two populated leaf children, so
        // Res(sibling(v)) = {(2,2),(2,3)} — two LEAF nodes.
        tree.insert(TreeNode::new_blank(NodeIndex::new(1, 1)));
        let kp2 = HybridKemKeypair::generate().unwrap();
        let kp3 = HybridKemKeypair::generate().unwrap();
        tree.insert(populated(NodeIndex::new(2, 2), kp2.public_key().clone()));
        tree.insert(populated(NodeIndex::new(2, 3), kp3.public_key().clone()));

        let v = NodeIndex::new(1, 0);

        // Unfiltered Lj (compute_lj with the verifier's own unmerged closure).
        let lj = compute_lj(&tree, v, |idx| {
            tree.get(idx)
                .and_then(|n| n.state.unmerged_leaves())
                .map(|ps| ps.iter().map(|&p| NodeIndex::leaf(2, p)).collect())
                .unwrap_or_default()
        });
        // Res(sibling(v)) directly.
        let res_sibling = resolve(&tree, NodeIndex::new(1, 1));

        // Lj == Res(sibling(v)) as node sets (the ∪ Unmerged(Res) term is vacuous).
        let lj_nodes: BTreeSet<NodeIndex> = lj.iter().copied().collect();
        let res_nodes: BTreeSet<NodeIndex> = res_sibling.iter().copied().collect();
        assert_eq!(lj_nodes, res_nodes, "Lj must equal Res(sibling(v))");
        assert_eq!(
            lj_nodes,
            BTreeSet::from([NodeIndex::new(2, 2), NodeIndex::new(2, 3)]),
        );

        // R (spec-literal, via reconstruct_resolution_keys): the \ Unmerged(v)
        // filter is a NO-OP despite Unmerged(v) = {0,1} != ∅ (disjoint subtrees),
        // so R's keys equal Lj's keys, in the same order.
        let r_keys = reconstruct_resolution_keys(&tree, v);
        let lj_keys: Vec<HybridKemPublicKey> = lj
            .iter()
            .filter_map(|idx| tree.get(idx).and_then(|n| n.state.public_key()).cloned())
            .collect();
        assert_eq!(
            r_keys.len(),
            lj_keys.len(),
            "R and Lj must have equal length"
        );
        assert_eq!(r_keys.len(), 2);
        for (a, b) in r_keys.iter().zip(lj_keys.iter()) {
            assert_eq!(a.to_bytes(), b.to_bytes(), "R keys must equal Lj keys");
        }
        // And they are exactly the sibling-subtree leaf keys, in resolution order.
        assert_eq!(r_keys[0].to_bytes(), kp2.public_key().to_bytes());
        assert_eq!(r_keys[1].to_bytes(), kp3.public_key().to_bytes());
    }

    /// Builds a FULLY-DETERMINABLE non-leaf level fixture: the same shape as
    /// `test_parent_hash_verify_h2_matches_builder`, but with (2,2) inserted as
    /// an explicit blank leaf so (1,1)'s WHOLE subtree is present in the view —
    /// `reconstruct_resolution_complete` then reads `complete == true` at level
    /// (1,0), so the SC1 gate ENFORCES `h2` (rather than deferring on absence).
    /// Returns the view and the honest `build_path_updates` output.
    fn build_determinable_updates() -> (PartialTreeView, Vec<NodeUpdate>) {
        use crate::tree::TreeNode;

        // Depth-2 tree, our leaf 0. Path: (2,0) -> (1,0) -> (0,0).
        let mut tree = PartialTreeView::new(0, 2);

        // Leaf sibling (2,1): populated (level-0 resolution recipient).
        let kp_a = HybridKemKeypair::generate().unwrap();
        tree.insert(populated(NodeIndex::new(2, 1), kp_a.public_key().clone()));

        // Level-1 sibling (1,1): BLANK internal carrying an unmerged leaf, with
        // BOTH children present — (2,2) an explicit blank leaf and (2,3)
        // populated — so the sibling subtree is FULLY determined (complete).
        let mut blank_11 = TreeNode::new_blank(NodeIndex::new(1, 1));
        blank_11.state.add_unmerged_leaf(3);
        tree.insert(blank_11);
        tree.insert(TreeNode::new_blank(NodeIndex::new(2, 2))); // explicit blank leaf
        let kp_b = HybridKemKeypair::generate().unwrap();
        tree.insert(populated(NodeIndex::new(2, 3), kp_b.public_key().clone()));

        // Resolution sets/keys mirror the production caller (compute_lj DIRECTLY).
        let path = [
            NodeIndex::new(2, 0),
            NodeIndex::new(1, 0),
            NodeIndex::new(0, 0),
        ];
        let mut resolution_sets: Vec<Vec<NodeIndex>> = Vec::new();
        let mut resolution_keys: Vec<Vec<HybridKemPublicKey>> = Vec::new();
        for pn in &path {
            let res = compute_lj(&tree, *pn, |idx| {
                tree.get(idx)
                    .and_then(|n| n.state.unmerged_leaves())
                    .map(|ps| ps.iter().map(|&p| NodeIndex::leaf(2, p)).collect())
                    .unwrap_or_default()
            });
            let keys: Vec<HybridKemPublicKey> = res
                .iter()
                .filter_map(|idx| tree.get(idx).and_then(|n| n.state.public_key()).cloned())
                .collect();
            resolution_sets.push(res.nodes);
            resolution_keys.push(keys);
        }
        // The non-leaf level (1,0) resolves to exactly the populated (2,3).
        assert_eq!(resolution_keys[1].len(), 1);

        let sibling_labels = vec![[0u8; 32], [0u8; 32]];
        let key_refs: Vec<Vec<&HybridKemPublicKey>> = resolution_keys
            .iter()
            .map(|ks| ks.iter().collect())
            .collect();

        let result =
            build_path_updates(&tree, 0, &resolution_sets, &key_refs, &sibling_labels).unwrap();
        (tree, result.updates)
    }

    /// SC1 (the GAP-02 close): on a FULLY-DETERMINABLE non-leaf level, a forged
    /// `h2` is rejected — BOTH a flipped `h2` (caught by recompute-compare) AND a
    /// padded `encrypted_seeds` recipient list (caught by the structural
    /// wire-set == local-set check). Arm (b) is the EXACT class the 52-02 count
    /// gate SKIPPED: padding makes `local.len() != wire.len()`, which the old gate
    /// treated as "not reconstructable" and let through.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_partial_view_forged_h2_rejected() {
        let (tree, updates) = build_determinable_updates();
        // The determinable non-leaf level is (1,0) = updates[1].
        let k = 1;

        // Honest commit verifies (h2 is now ENFORCED at level k, not deferred).
        verify_parent_hashes(&tree, &updates).unwrap();

        // Arm (a): flip a byte of the level-k h2 → recompute-compare rejects.
        let mut flipped = updates.clone();
        flipped[k].parent_hash.1[0] ^= 0xFF;
        assert!(matches!(
            verify_parent_hashes(&tree, &flipped),
            Err(CryptoError::ParentHashMismatch)
        ));

        // Arm (b): pad the level-k recipient list with an EXTRA recipient at a
        // position NOT in the local resolution ((2,1), position 1; the local
        // resolution is {(2,3)}, position 3). This makes local.len() != wire.len()
        // — the exact GAP-02 case the 52-02 count gate skipped — and the new
        // structural set check rejects it.
        let mut padded = updates.clone();
        let mut extra = padded[k].encrypted_seeds[0].clone();
        extra.recipient_index = NodeIndex::new(2, 1);
        padded[k].encrypted_seeds.push(extra);
        assert!(matches!(
            verify_parent_hashes(&tree, &padded),
            Err(CryptoError::ParentHashMismatch)
        ));
    }

    /// SC1 no-false-reject control: the same fully-determinable fixture with an
    /// honest commit verifies `Ok` even though `h2` is now ENFORCED at the
    /// determinable level (the counterpart to the honest genuinely-partial
    /// external-OTK deferral control `test_parent_hash_verify_accepts_honest`).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_partial_view_honest_accepts() {
        let (tree, updates) = build_determinable_updates();
        verify_parent_hashes(&tree, &updates).unwrap();
    }
}
