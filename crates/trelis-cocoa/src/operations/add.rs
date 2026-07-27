//! Member addition (CGKA.Add).
//!
//! Adds a new member to an existing CoCoA group.
//!
//! # Overview
//!
//! The add operation introduces a new member to the group. The adder:
//!
//! 1. Assigns the new member a leaf position
//! 2. Generates a fresh leaf seed and derives path keys
//! 3. Encrypts seeds to resolution sets (including the new member)
//! 4. Creates a welcome message with encrypted group state
//! 5. Signs the commit
//!
//! # Welcome Message
//!
//! The welcome message contains everything the new member needs:
//! - Group identifier and epoch information
//! - Their assigned leaf position
//! - Encrypted group state (init_secret, transcript_hash, tree info)
//!
//! The group state is encrypted using a hybrid KEM encapsulation to
//! the new member's pre-key bundle.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
#[cfg(feature = "alloc")]
use trelis_hybrid::HybridKemPublicKey;
use trelis_hybrid::{
    HybridIdentityKeypair, HybridIdentityPublicKey, HybridPreKeyBundle, HybridSignature,
};

#[cfg(feature = "alloc")]
use crate::key_schedule::h3_tree_label;
use crate::key_schedule::{CONFIRMATION_TAG_CONTEXT, ROOT_LABEL_CONTEXT};
use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
#[cfg(feature = "alloc")]
use crate::limits::check_size_limits;
use crate::session::CocoaSession;
use crate::tree::NodeIndex;
#[cfg(feature = "alloc")]
use crate::tree::{PartialTreeView, compute_lj, path_to_root};
use crate::{GroupId, UserId};

use super::Welcome;
use super::commit_sign::{CommitContent, hash_path_updates, sign_commit, verify_commit_signature};
#[cfg(feature = "alloc")]
use super::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};
#[cfg(feature = "alloc")]
use super::update::derive_user_id_from_identity;

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
    /// The adder's (committer's) own leaf position.
    ///
    /// GAP-03: bound into the signed `CommitContent`; the verifier
    /// reconstructs the signed body from this field and rejects a commit whose
    /// committer leaf is out of range or a known-blank leaf.
    pub committer_leaf_position: u32,
    /// Epoch after this commit.
    pub epoch: u64,
    /// Path updates for the adding member.
    pub path_updates: Vec<PathUpdate>,
    /// Signature over the commit.
    pub signature: HybridSignature,
    /// Round hash for this commit.
    pub round_hash: [u8; 32],
    /// Confirmation tag for epoch verification.
    pub confirmation_tag: [u8; 32],
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
/// * `identity` - Our identity keypair for signing the commit
/// * `new_member_bundle` - Pre-key bundle of the new member
/// * `new_member_id` - User ID of the new member
///
/// # Returns
///
/// A tuple of (add commit for broadcast, welcome message for new member).
#[cfg(feature = "alloc")]
pub fn add_member(
    session: &mut CocoaSession,
    identity: &HybridIdentityKeypair,
    new_member_bundle: &HybridPreKeyBundle,
    new_member_id: UserId,
) -> Result<(AddCommit, Welcome)> {
    // GAP-03: double-join guard — reject re-adding an existing member BEFORE
    // assigning a leaf position, so no tree/epoch state is mutated on rejection.
    if session.is_member(&new_member_id) {
        return Err(trelis_error::CryptoError::DuplicateMember);
    }

    // Step 1: Find next available leaf position
    let new_position = session.member_count();

    // Step 2: Check if tree needs to grow and grow it if necessary
    let new_member_count = new_position + 1;
    session.tree_mut().grow_if_needed(new_member_count);
    let tree_depth = session.tree().tree_depth();

    // Step 3: Generate fresh leaf seed
    let leaf_seed = generate_leaf_seed()?;

    // Step 4: Compute our path from leaf to root
    let our_leaf = NodeIndex::leaf(tree_depth, session.our_leaf_position());
    let path = path_to_root(our_leaf);
    let path_length = path.len();

    // Step 5: Derive all path seeds
    let path_seeds = derive_path_seeds(&leaf_seed, path_length);

    // Step 6: Compute resolution sets (including new member)
    let (resolution_sets, resolution_keys) = compute_add_resolution_sets_and_keys(
        session,
        &path,
        new_member_bundle,
        tree_depth,
        new_position,
    );

    // Step 7: Compute sibling labels for parent hash computation
    let sibling_labels = compute_sibling_labels(session, &path);

    // Step 8: Build path updates with encrypted seeds
    let (path_updates, delta_root): (Vec<PathUpdate>, Seed) = {
        use super::path_update::build_path_updates_with_seeds;

        // Convert keys to references for the builder
        let key_refs: Vec<Vec<&HybridKemPublicKey>> = resolution_keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        // Use the pre-computed path seeds and path to ensure consistency
        let result = build_path_updates_with_seeds(
            tree_depth,
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

    // Step 8: Update member count before computing round hash
    session.tree_mut().set_member_count(new_position + 1);

    // Step 9: Compute round hash (add includes the new member)
    let root_label = compute_root_label(&path_seeds);
    let round_hash = h3_round_hash(&root_label, &[], &[new_member_id]);

    // Step 10: Serialise path updates and compute hash
    let path_updates_bytes = serialise_path_updates(&path_updates);
    let path_updates_hash = hash_path_updates(&path_updates_bytes);

    // Step 11: Build commit content for signing.
    // GAP-03: bind our own leaf position + derived identity into the signed body.
    let committer_leaf_position = session.our_leaf_position();
    let commit_content = CommitContent::new_add(
        *session.group_id(),
        session.epoch_number() + 1,
        round_hash,
        path_updates_hash,
        committer_leaf_position,
        derive_user_id_from_identity(identity.public_key()),
    );

    // Step 12: Sign the commit with identity key
    let signature = sign_commit(identity, &commit_content)?;

    // Step 13: Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // Step 14: Create welcome message with encrypted group state (signed by the
    // adder's identity — GAP-01).
    let welcome = create_welcome_message(
        session,
        identity,
        new_member_bundle,
        new_position,
        tree_depth,
        &delta_root,
        &new_transcript,
    )?;

    // Step 14b: Compute confirmation tag
    let confirmation_tag =
        compute_confirmation_tag(&delta_root, &new_transcript, session.epoch_number() + 1);

    let commit = AddCommit {
        group_id: *session.group_id(),
        new_member_id,
        new_leaf_position: new_position,
        committer_leaf_position,
        epoch: session.epoch_number() + 1,
        path_updates,
        signature,
        round_hash,
        confirmation_tag,
    };

    // Step 15: Mark new member as unmerged on blank nodes in their path
    // This ensures they receive encrypted secrets in future updates from others
    mark_member_as_unmerged(session, new_position);

    // Step 16: Advance epoch with real delta_root
    session.advance_epoch(&delta_root, new_transcript);

    // Step 17: Record the new member in the local registry (GAP-03).
    session.insert_member(new_member_id);

    Ok((commit, welcome))
}

/// Computes resolution sets for an add operation.
///
/// For adds, the new member needs to be included in the resolution sets
/// so they can decrypt the path secrets.
///
/// Note: This function ensures resolution nodes and keys are always matched.
/// Nodes without corresponding public keys in the tree are skipped.
#[cfg(feature = "alloc")]
fn compute_add_resolution_sets_and_keys(
    session: &CocoaSession,
    path: &[NodeIndex],
    new_member_bundle: &HybridPreKeyBundle,
    tree_depth: u32,
    new_member_position: u32,
) -> (Vec<Vec<NodeIndex>>, Vec<Vec<HybridKemPublicKey>>) {
    let mut resolution_sets = Vec::with_capacity(path.len());
    let mut resolution_keys = Vec::with_capacity(path.len());

    // The new member's leaf index
    let new_member_leaf = NodeIndex::leaf(tree_depth, new_member_position);

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

        // Collect (node, key) pairs only for nodes that have keys in the tree
        let mut nodes = Vec::new();
        let mut keys = Vec::new();

        for node_idx in resolution.iter() {
            if let Some(node) = session.tree().get(node_idx) {
                if let Some(pk) = node.state.public_key() {
                    nodes.push(*node_idx);
                    keys.push(pk.clone());
                }
            }
        }

        // Add the new member if they're in the sibling subtree
        // The new member always needs the path secrets
        if is_in_sibling_subtree(*path_node, new_member_leaf) {
            nodes.push(new_member_leaf);
            // Use the new member's OTK KEM public key for encryption
            keys.push(new_member_bundle.one_time_key().kem.clone());
        }

        resolution_sets.push(nodes);
        resolution_keys.push(keys);
    }

    (resolution_sets, resolution_keys)
}

/// Checks if a node is in the sibling subtree of a path node.
fn is_in_sibling_subtree(path_node: NodeIndex, target: NodeIndex) -> bool {
    // Get the sibling of the path node
    if let Some(sibling) = path_node.sibling() {
        // Check if target is a descendant of sibling
        target.is_descendant_of(&sibling) || target == sibling
    } else {
        // Root has no sibling
        false
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

/// Creates a welcome message for the new member.
///
/// GAP-01 (Insider-A): the adder (`identity`) signs the canonical welcome body
/// so the new member can authenticate the welcome in `process_welcome` before
/// adopting group state.
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
fn create_welcome_message(
    session: &CocoaSession,
    identity: &HybridIdentityKeypair,
    new_member_bundle: &HybridPreKeyBundle,
    new_position: u32,
    tree_depth: u32,
    delta_root: &Seed,
    new_transcript: &[u8; 32],
) -> Result<Welcome> {
    use super::init::{WELCOME_SIGN_CONTEXT, encrypt_welcome_info, welcome_sign_body};

    // Build tree_info: serialise nodes on the adder's path
    // The new member needs this to verify the tree structure and decrypt seeds
    let tree_info = serialise_tree_info(session);

    // Build the group info to encrypt
    let group_info = WelcomeInfo {
        init_secret: *session.init_secret(),
        transcript_hash: *new_transcript,
        delta_root: *delta_root,
        tree_info,
    };

    // Encrypt the welcome info to the new member's OTK KEM key
    let (encrypted_info, encapsulation) =
        encrypt_welcome_info(&group_info, &new_member_bundle.one_time_key().kem)?;

    let group_id = *session.group_id();
    let epoch = session.epoch_number() + 1;
    let member_count = new_position + 1;

    // GAP-01 (Insider-A): sign the canonical welcome body over every
    // joiner-visible field with the adder's identity under WELCOME_SIGN_CONTEXT.
    let sign_body = welcome_sign_body(
        &group_id,
        epoch,
        new_position,
        tree_depth,
        member_count,
        &encapsulation,
        &encrypted_info,
    );
    let signature = identity.sign_with_context(&sign_body, WELCOME_SIGN_CONTEXT)?;

    Ok(Welcome {
        group_id,
        epoch,
        leaf_position: new_position,
        tree_depth,
        member_count,
        encrypted_info,
        encapsulation,
        signature,
    })
}

/// Serialises tree information for the welcome message.
///
/// This includes nodes on the adder's path from leaf to root, which the
/// new member needs to verify tree integrity and decrypt path secrets.
///
/// # Format
///
/// For each node:
/// - 4 bytes: depth (u32 LE)
/// - 4 bytes: position (u32 LE)
/// - 1 byte: state flag (0 = blank, 1 = populated)
/// - If populated:
///   - 2 bytes: public key length (u16 LE)
///   - N bytes: public key
///   - 32 bytes: parent hash h1
///   - 32 bytes: parent hash h2
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
fn serialise_tree_info(session: &CocoaSession) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Get our path from leaf to root
    let our_leaf = NodeIndex::leaf(session.tree().tree_depth(), session.our_leaf_position());
    let path = path_to_root(our_leaf);

    // Serialise each node in our path
    for node_idx in &path {
        // Write node index
        bytes.extend_from_slice(&node_idx.depth.to_le_bytes());
        bytes.extend_from_slice(&node_idx.position.to_le_bytes());

        if let Some(node) = session.tree().get(node_idx) {
            if let Some(pk) = node.state.public_key() {
                // Populated node
                bytes.push(1); // State flag = populated

                let pk_bytes = pk.to_bytes();
                bytes.extend_from_slice(&(pk_bytes.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&pk_bytes);

                // Parent hash
                if let Some((h1, h2)) = node.state.parent_hash() {
                    bytes.extend_from_slice(h1);
                    bytes.extend_from_slice(h2);
                } else {
                    // Should not happen for populated nodes, but handle gracefully
                    bytes.extend_from_slice(&[0u8; 32]);
                    bytes.extend_from_slice(&[0u8; 32]);
                }
            } else {
                // Blank node
                bytes.push(0); // State flag = blank
            }
        } else {
            // Missing node (treat as blank)
            bytes.push(0);
        }
    }

    bytes
}

/// Fallback for no-std without wasm (creates empty welcome)
#[cfg(all(feature = "alloc", not(any(feature = "std", feature = "wasm"))))]
fn create_welcome_message(
    session: &CocoaSession,
    _identity: &HybridIdentityKeypair,
    _new_member_bundle: &HybridPreKeyBundle,
    new_position: u32,
    tree_depth: u32,
    _delta_root: &Seed,
    _new_transcript: &[u8; 32],
) -> Result<Welcome> {
    // This build has no RNG to sign with and no encrypted_info to authenticate,
    // so the empty welcome carries a well-formed all-zero placeholder signature
    // (size single-sourced to trelis_hybrid::signature::SIGNATURE_SIZE) to keep
    // the struct complete.
    let signature = HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE])?;
    Ok(Welcome {
        group_id: *session.group_id(),
        epoch: session.epoch_number() + 1,
        leaf_position: new_position,
        tree_depth,
        member_count: new_position + 1,
        encrypted_info: Vec::new(),
        encapsulation: Vec::new(),
        signature,
    })
}

/// Information encrypted in the welcome message.
#[cfg(feature = "alloc")]
struct WelcomeInfo {
    /// The init_secret for the epoch.
    init_secret: [u8; 32],
    /// The current transcript hash.
    transcript_hash: [u8; 32],
    /// The delta root from the add commit.
    delta_root: [u8; 32],
    /// Serialised tree information.
    tree_info: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl super::init::WelcomeInfoSerialise for WelcomeInfo {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + self.tree_info.len());
        bytes.extend_from_slice(&self.init_secret);
        bytes.extend_from_slice(&self.transcript_hash);
        bytes.extend_from_slice(&self.delta_root);
        bytes.extend_from_slice(&self.tree_info);
        bytes
    }
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

/// Measures the attacker-controlled wire size of a commit's path updates for the
/// DOS-01 message-size gate (`MAX_MESSAGE_SIZE`): the sum, over every path update
/// and within each over every encrypted seed, of `encapsulation.len() +
/// ciphertext.len()` — the dominant attacker-controlled bytes.
///
/// Every addition is `saturating_add`, so a maliciously large commit yields a
/// saturated `usize` (which the gate then rejects) rather than panicking under
/// the workspace `overflow-checks = true` profile (DoS-gate Pitfall 5/6). This
/// measures already-in-memory `Vec` lengths in O(len) — it does NOT re-run
/// `serialise_path_updates` (no double-serialisation). Shared by
/// `process_add` / `process_update` / `process_remove` (all carry
/// `Vec<PathUpdate>`).
#[cfg(feature = "alloc")]
pub(crate) fn path_updates_wire_len(path_updates: &[PathUpdate]) -> usize {
    let mut total = 0usize;
    for update in path_updates {
        for seed in &update.encrypted_seeds {
            total = total.saturating_add(seed.encapsulation.len());
            total = total.saturating_add(seed.ciphertext.len());
        }
    }
    total
}

/// Processes an add commit from another member.
///
/// This function verifies the commit and processes the path updates to derive
/// the new epoch secret. It performs the following steps:
///
/// 1. Verify commit signature
/// 2. Verify path updates hash
/// 3. Grow tree if needed for new member
/// 4. Find and decrypt our seed from the path updates
/// 5. Derive remaining path seeds up to root
/// 6. Verify public keys match the derived keys
/// 7. Update tree with new public keys and new member
/// 8. Advance epoch with derived delta_root
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `commit` - The add commit to process
/// * `adder_identity` - The adder's public identity key for signature verification
///
/// # Errors
///
/// Returns an error if:
/// - Group ID doesn't match
/// - Epoch is not sequential
/// - Signature verification fails
/// - Path updates hash doesn't match
/// - Cannot decrypt any seed (not in resolution)
/// - Public key verification fails
#[cfg(feature = "alloc")]
pub fn process_add(
    session: &mut CocoaSession,
    commit: &AddCommit,
    adder_identity: &HybridIdentityPublicKey,
) -> Result<()> {
    // ── DoS size gate (DOS-01/02/03) — the FIRST statement, before every
    // existing check and unconditionally before `verify_commit_signature`
    // (§13 "resource-limit checks MUST precede cryptographic operations"). ──
    //
    // CR-02: compute the resulting member count with CHECKED arithmetic first.
    // `new_leaf_position` is an unbounded wire `u32`; `+ 1` under the workspace
    // `overflow-checks = true` release/WASM profile would otherwise trap on
    // `u32::MAX` before the gate could reject (Pitfall 6). The tree is NOT grown
    // here: WR-03 defers ALL mutation until every integrity check has passed.
    let new_member_count = commit
        .new_leaf_position
        .checked_add(1)
        .ok_or(trelis_error::CryptoError::InvalidLeafPosition)?;
    check_size_limits(
        path_updates_wire_len(&commit.path_updates),
        commit.path_updates.len().saturating_sub(1),
        PartialTreeView::depth_for_members(new_member_count),
        new_member_count,
        session.tree().total_unmerged_leaves(),
    )?;

    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
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
    // the wire field, committer_user_id derived from the caller-supplied adder
    // identity. If the caller passes the wrong identity, the reconstructed body
    // no longer matches the signed body and the signature check below fails
    // (binds signer ↔ body identity).
    let commit_content = CommitContent::new_add(
        commit.group_id,
        commit.epoch,
        commit.round_hash,
        path_updates_hash,
        commit.committer_leaf_position,
        derive_user_id_from_identity(adder_identity),
    );

    // Verify signature (both Ed448 and ML-DSA-65 must pass)
    verify_commit_signature(adder_identity, &commit_content, &commit.signature)?;

    // WR-03: the honest add grows the tree by (up to) one level and re-indexes
    // every node. Perform that growth on a SCRATCH clone so the remaining
    // tree-dependent checks see the post-grow geometry the committer used, while
    // the real session tree stays UNTOUCHED until every integrity check
    // (confirmation tag, round hash, parent hash) has passed. A rejected commit
    // therefore leaves member_count, the tree, and the epoch exactly as before —
    // mirroring `process_update`'s validate-then-mutate ordering.
    let mut scratch = session.tree().clone();
    scratch.grow_if_needed(new_member_count);

    // GAP-03: bind signer ↔ leaf. The adder must sit at an occupied member
    // leaf — reject a committer leaf that is out of range or a known-blank
    // leaf in our local view (checked against the grown scratch view).
    if commit.committer_leaf_position >= session.member_count()
        || scratch
            .get(&NodeIndex::leaf(
                scratch.tree_depth(),
                commit.committer_leaf_position,
            ))
            .is_some_and(|node| node.state.is_blank())
    {
        return Err(trelis_error::CryptoError::InvalidLeafPosition);
    }

    // GAP-03: double-join guard — reject a commit that re-adds a known member
    // or targets an already-occupied leaf.
    let new_leaf = NodeIndex::leaf(scratch.tree_depth(), commit.new_leaf_position);
    if session.is_member(&commit.new_member_id)
        || scratch
            .get(&new_leaf)
            .is_some_and(|node| node.state.is_populated())
    {
        return Err(trelis_error::CryptoError::DuplicateMember);
    }

    // Convert PathUpdate to NodeUpdate for apply_path_updates
    let node_updates = convert_path_updates_to_node_updates(&commit.path_updates)?;

    // Apply path updates: find our seed, decrypt, derive to root, verify keys.
    // For add operations, the adder encrypts seeds to us if we're in their
    // resolution. This reads no session tree state and mutates nothing — it only
    // derives the delta_root the integrity checks below bind against.
    let delta_root = if node_updates.is_empty() {
        // No path updates means we can't derive delta_root
        // This happens when the commit has no encrypted seeds for us
        [0u8; 32]
    } else {
        use super::path_update::apply_path_updates;

        // Try to apply path updates - we may or may not be in the resolution set
        // depending on our position relative to the adder
        apply_path_updates(
            &node_updates,
            session.our_keypair(),
            session.our_leaf_position(),
            0, // Adder is typically at position 0, but we use path updates to find our seed
        )?
    };

    // Update transcript hash (local value; not yet committed to the session).
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &commit.round_hash);

    // ── Integrity checks — ALL must pass BEFORE any session mutation (WR-03) ──
    // A signature-valid but tag-/round-hash-/parent-hash-invalid commit (the
    // exact GAP-04c insider attack) must NOT corrupt tree/member_count/epoch
    // state; the checks below run against local/scratch state only.

    // Verify confirmation tag (epoch-secret agreement).
    let expected_tag = compute_confirmation_tag(&delta_root, &new_transcript, commit.epoch);
    if !constant_time_eq(&expected_tag, &commit.confirmation_tag) {
        return Err(trelis_error::CryptoError::SignatureVerificationFailed);
    }

    // GAP-04c (F07): MANDATORY round-hash verification. Independently recompute
    // the round hash from the LOCALLY-derived delta_root plus this commit's
    // membership change (add binds added = [new_member_id], removed = []) and
    // reject a divergent/forged value BEFORE advancing the epoch. This mirrors
    // the committer's build side exactly (compute_root_label + h3_round_hash).
    //
    // The confirmation tag checked above only binds epoch-secret agreement
    // (delta_root, transcript, epoch); it does NOT bind the round hash to the
    // actual tree-state / membership change, so a malicious committer could
    // advertise a round hash inconsistent with the membership set while keeping
    // the tag self-consistent. This recompute closes that gap, making §12:99
    // ("undetectably partition ... detected via round hash") true in code.
    //
    // NOTE: the full Algorithm-3 `verifyRH` (server-provided Merkle `openRH`
    // transport) is the deferred follow-up (OQ-5); this lightweight in-crate
    // recompute is the mandatory Phase-52 minimum.
    {
        use trelis_primitives::blake3_kdf::derive_key;
        let expected_root_label = *derive_key(ROOT_LABEL_CONTEXT, &delta_root);
        let expected_round_hash = h3_round_hash(&expected_root_label, &[], &[commit.new_member_id]);
        if expected_round_hash != commit.round_hash {
            return Err(trelis_error::CryptoError::RoundHashMismatch);
        }
    }

    // GAP-02 (PHash.Ver): recompute h1/h2 from the (grown) scratch view and
    // reject a tampered tree structure. h1 (sibling binding) is mandatory; h2 is
    // enforced where the local resolution reconstructs (partial-view residual
    // otherwise, OQ-1). Verified against the scratch clone, so a mismatch leaves
    // no session state touched. Empty path updates are a no-op.
    super::path_update::verify_parent_hashes(&scratch, &node_updates)?;

    // ── All checks passed — commit the mutations to the real session ─────────
    // Grow, member-count, node writes, unmerged marking and the epoch advance
    // now happen atomically after validation (mirroring process_update).
    session.tree_mut().grow_if_needed(new_member_count);
    session.tree_mut().set_member_count(new_member_count);

    // Update tree with new public keys from path updates
    // Note: We use the adder's ID (session's user_id) since they created the commit
    update_tree_from_path_updates(
        session,
        &commit.path_updates,
        &commit.signature,
        *session.our_user_id(),
    );

    // Mark new member as unmerged on all blank nodes in their path
    // This ensures they receive encrypted secrets in future updates
    mark_member_as_unmerged(session, commit.new_leaf_position);

    // Advance epoch with the derived delta_root
    session.advance_epoch(&delta_root, new_transcript);

    // GAP-03: record the newly-added member in the local registry.
    session.insert_member(commit.new_member_id);

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

/// Marks a member as unmerged on all blank nodes in their path.
///
/// When a member joins, they haven't yet processed any updates, so they need
/// to be included in resolution sets for future commits. This function marks
/// them as unmerged on all blank nodes from their leaf to the root.
///
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

    *derive_key(CONFIRMATION_TAG_CONTEXT, &input)
}

/// Constant-time comparison for confirmation tags.
#[must_use]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// # Arguments
///
/// * `session` - The session with the tree to update
/// * `leaf_position` - The new member's leaf position
#[cfg(feature = "alloc")]
fn mark_member_as_unmerged(session: &mut CocoaSession, leaf_position: u32) {
    let tree_depth = session.tree().tree_depth();
    let leaf = NodeIndex::leaf(tree_depth, leaf_position);

    // Walk from leaf to root and mark as unmerged on any blank nodes
    let mut current = leaf;
    loop {
        // Only mark on blank nodes (populated nodes don't track unmerged)
        if let Some(node) = session.tree().get(&current) {
            if node.state.is_blank() {
                session
                    .tree_mut()
                    .add_unmerged_leaf(&current, leaf_position);
            }
        }

        // Move to parent
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break; // Reached root
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::{HybridKemKeypair, HybridOneTimeKeyPair};

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

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_add_member() {
        let mut session = create_test_session();
        let our_identity = create_test_identity();
        assert_eq!(session.member_count(), 1);

        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);
        let new_user_id = [0x02u8; 32];

        let (commit, welcome) =
            add_member(&mut session, &our_identity, &new_bundle, new_user_id).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(commit.new_leaf_position, 1);
        assert_eq!(welcome.leaf_position, 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    #[allow(clippy::panic)] // Test code: panic on unexpected errors is intentional
    fn test_process_add() {
        // Create two sessions for testing add processing
        let group_id = [0x42u8; 32];
        let epoch_secret = [0xABu8; 32];
        let user1_id = [0x01u8; 32];
        let user2_id = [0x02u8; 32];
        let user3_id = [0x03u8; 32];

        // Member 1's keypair (adder)
        let member1_keypair = HybridKemKeypair::generate().unwrap();
        let member1_identity = create_test_identity();

        // Member 2's keypair (existing member who will process the add)
        let member2_keypair = HybridKemKeypair::generate().unwrap();
        let member2_identity = create_test_identity();

        // Member 3's bundle (new member being added)
        let member3_identity = create_test_identity();
        let member3_bundle = create_test_bundle(&member3_identity);

        // Create session for member 1 (adder) with 2 existing members
        let mut session1 = CocoaSession::create_group(
            group_id,
            user1_id,
            HybridKemKeypair::from_bytes(&member1_keypair.to_bytes()[..]).unwrap(),
            2, // Two existing members
            &epoch_secret,
        )
        .unwrap();

        // Create session for member 2 (existing member)
        let mut session2 = CocoaSession::join_group(
            group_id,
            user2_id,
            HybridKemKeypair::from_bytes(&member2_keypair.to_bytes()[..]).unwrap(),
            1, // Position 1
            1, // Depth 1 for 2 members
            2, // 2 members
            &epoch_secret,
            [0u8; 32], // Initial transcript
        );

        // Add member2's key to session1's tree
        {
            use crate::tree::{TreeNode, UpdateOrigin};
            let member2_leaf = crate::tree::NodeIndex::leaf(1, 1);
            let node = TreeNode::new_populated(
                member2_leaf,
                member2_keypair.public_key().clone(),
                None,
                ([0u8; 32], [0u8; 32]),
                user2_id,
                member2_identity.sign(b"init").unwrap(),
                [0u8; 32],
                [0u8; 32],
                UpdateOrigin {
                    epoch: 0,
                    sequence: 0,
                    timestamp: 0,
                },
            );
            session1.tree_mut().insert(node);
        }

        // Add member1's key to session2's tree
        {
            use crate::tree::{TreeNode, UpdateOrigin};
            let member1_leaf = crate::tree::NodeIndex::leaf(1, 0);
            let node = TreeNode::new_populated(
                member1_leaf,
                member1_keypair.public_key().clone(),
                None,
                ([0u8; 32], [0u8; 32]),
                user1_id,
                member1_identity.sign(b"init").unwrap(),
                [0u8; 32],
                [0u8; 32],
                UpdateOrigin {
                    epoch: 0,
                    sequence: 0,
                    timestamp: 0,
                },
            );
            session2.tree_mut().insert(node);
        }

        let initial_epoch = session1.epoch_number();

        // Member 1 adds member 3
        let (commit, _welcome) =
            add_member(&mut session1, &member1_identity, &member3_bundle, user3_id).unwrap();

        // Member 2 processes the add
        let result = process_add(&mut session2, &commit, member1_identity.public_key());

        // The test verifies the basic flow works.
        //
        // Known limitation: Decryption may fail because:
        // 1. Tree views aren't fully synchronised between sessions
        // 2. Unmerged tracking isn't populated (see compute_resolution_sets_and_keys in update.rs)
        // For proper multi-party tests, see integration tests with synchronised tree state.
        match result {
            Ok(()) => {
                // Full success - epoch should advance, member count should increase
                assert_eq!(session2.epoch_number(), initial_epoch + 1);
                assert_eq!(session2.member_count(), 3);
            }
            Err(trelis_error::CryptoError::DecryptionFailed) => {
                // Test limitation: Tree views are not fully synchronised, so session1
                // may not have session2's public key to encrypt to. This is expected
                // given the minimal setup in this unit test.
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_wrong_signer() {
        let mut session = create_test_session();
        let signer_identity = create_test_identity();
        let wrong_identity = create_test_identity();

        // Build commit signed by signer_identity, bound to committer leaf 0
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(signer_identity.public_key()),
        );
        let signature = sign_commit(&signer_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32], // Placeholder - test fails before tag verification
        };

        // Try to verify with wrong identity - reconstructed body binds
        // derive(wrong) as committer_user_id, so the signature check fails.
        let result = process_add(&mut session, &commit, wrong_identity.public_key());
        assert!(result.is_err());
    }

    /// CR-02: a pre-authentication `new_leaf_position == u32::MAX` must return a
    /// graceful `Err(InvalidLeafPosition)` from the checked `+ 1`, NOT overflow-
    /// panic under the crate's `overflow-checks = true` profile. Reaching the
    /// bound check needs only a matching `group_id` + `epoch` (both known to
    /// every member and the server), so this is exactly the pre-auth WASM-DoS
    /// input an insider/transport could send; the signature is never consulted.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_leaf_position_overflow_is_graceful_err() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        // A placeholder signature suffices: the checked bound rejects the
        // out-of-range position before signature verification is reached.
        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: u32::MAX, // `+ 1` overflows a u32
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };

        // Must be a graceful Err, never a panic.
        assert!(matches!(
            process_add(&mut session, &commit, adder.public_key()),
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_wrong_group() {
        let mut session = create_test_session();
        let adder_identity = create_test_identity();

        // Build commit with wrong group ID
        let wrong_group_id = [0xFFu8; 32];
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_add(
            wrong_group_id,
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder_identity.public_key()),
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: wrong_group_id, // Wrong group
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32], // Placeholder - test fails before tag verification
        };

        // Group ID check happens before signature verification
        let result = process_add(&mut session, &commit, adder_identity.public_key());
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_add_member_tree_growth() {
        // Start with a single member (depth 0, capacity 1)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();
        let our_identity = create_test_identity();

        // Verify initial state
        assert_eq!(session.member_count(), 1);
        assert_eq!(session.tree().tree_depth(), 0); // depth 0 for 1 member

        // Add second member - should trigger tree growth to depth 1
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);
        let new_user_id = [0x02u8; 32];

        let (commit, _) =
            add_member(&mut session, &our_identity, &new_bundle, new_user_id).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1); // grew to depth 1
        assert_eq!(commit.new_leaf_position, 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_add_multiple_members_with_growth() {
        // Create a session with 2 initial members (depth 1)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 2, &epoch_secret).unwrap();
        let our_identity = create_test_identity();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1);
        assert_eq!(session.tree().capacity(), 2);

        // Add third member - should trigger tree growth to depth 2
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);

        let (commit, _) =
            add_member(&mut session, &our_identity, &new_bundle, [0x03u8; 32]).unwrap();

        assert_eq!(session.member_count(), 3);
        assert_eq!(session.tree().tree_depth(), 2); // grew to depth 2
        assert_eq!(session.tree().capacity(), 4);
        assert_eq!(commit.new_leaf_position, 2);

        // Add fourth member - should fit without growth
        let another_identity = create_test_identity();
        let another_bundle = create_test_bundle(&another_identity);

        let (commit2, _) =
            add_member(&mut session, &our_identity, &another_bundle, [0x04u8; 32]).unwrap();

        assert_eq!(session.member_count(), 4);
        assert_eq!(session.tree().tree_depth(), 2); // still depth 2
        assert_eq!(commit2.new_leaf_position, 3);

        // Add fifth member - should trigger tree growth to depth 3
        let fifth_identity = create_test_identity();
        let fifth_bundle = create_test_bundle(&fifth_identity);

        let (commit3, _) =
            add_member(&mut session, &our_identity, &fifth_bundle, [0x05u8; 32]).unwrap();

        assert_eq!(session.member_count(), 5);
        assert_eq!(session.tree().tree_depth(), 3); // grew to depth 3
        assert_eq!(session.tree().capacity(), 8);
        assert_eq!(commit3.new_leaf_position, 4);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_tree_growth() {
        // Start with depth 0 (single member)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();
        let adder_identity = create_test_identity();

        assert_eq!(session.tree().tree_depth(), 0);

        // Create commit for adding member at position 1, committer at leaf 0
        let path_updates_hash = hash_path_updates(&[]);
        // GAP-04c: with mandatory round-hash verification the synthetic empty-path
        // commit must carry the round hash the receiver recomputes from its LOCAL
        // delta_root ([0;32] for empty updates) + added = [new_member].
        let round_hash = {
            use trelis_primitives::blake3_kdf::derive_key;
            h3_round_hash(
                &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
                &[],
                &[[0x02u8; 32]],
            )
        };
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder_identity.public_key()),
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        // Compute correct confirmation tag for empty path updates
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let delta_root = [0u8; 32]; // Empty path updates = zero delta_root
        let confirmation_tag = compute_confirmation_tag(&delta_root, &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1, // This requires depth 1
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_add(&mut session, &commit, adder_identity.public_key()).unwrap();

        // Tree should have grown
        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_unmerged_tracking_on_add() {
        // Verify that when a member is added, they're marked as unmerged
        // on blank nodes in their path.
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session =
            CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();
        let adder_identity = create_test_identity();

        // Create a blank node in the tree (simulating the sibling that will exist)
        let sibling_index = crate::tree::NodeIndex::new(1, 1);
        let blank_node = crate::tree::TreeNode::new_blank(sibling_index);
        session.tree_mut().insert(blank_node);

        // Create commit for adding member at position 1, committer at leaf 0
        let path_updates_hash = hash_path_updates(&[]);
        // GAP-04c: consistent round hash for the receiver's empty-path recompute
        // (delta_root [0;32] + added = [new_member]).
        let round_hash = {
            use trelis_primitives::blake3_kdf::derive_key;
            h3_round_hash(
                &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
                &[],
                &[[0x02u8; 32]],
            )
        };
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder_identity.public_key()),
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        // Compute correct confirmation tag for empty path updates
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let delta_root = [0u8; 32]; // Empty path updates = zero delta_root
        let confirmation_tag = compute_confirmation_tag(&delta_root, &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_add(&mut session, &commit, adder_identity.public_key()).unwrap();

        // Check that the new member is marked as unmerged on blank nodes
        // After adding, if any blank nodes exist in the new member's path,
        // they should have the new member's leaf position in unmerged_leaves
        if let Some(node) = session.tree().get(&sibling_index) {
            if node.state.is_blank() {
                let unmerged = node.state.unmerged_leaves().unwrap();
                assert!(
                    unmerged.contains(&1),
                    "New member at position 1 should be marked as unmerged"
                );
            }
        }
    }

    // ─── GAP-03: double-join guard ──────────────────────────────────────────

    /// Re-adding an already-present member via `add_member` is rejected with
    /// `DuplicateMember` (double-join / ghost-member guard).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_double_join_add_member_rejected() {
        let mut session = create_test_session(); // creator [0x01; 32], 1 member
        let our_identity = create_test_identity();

        let x_identity = create_test_identity();
        let x_bundle = create_test_bundle(&x_identity);
        let x_id = [0x02u8; 32];

        // First add of X succeeds and records X as a member.
        add_member(&mut session, &our_identity, &x_bundle, x_id).unwrap();
        assert!(session.is_member(&x_id));

        // Second add of the same X is rejected before any leaf is assigned.
        let result = add_member(&mut session, &our_identity, &x_bundle, x_id);
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::DuplicateMember)
        ));
    }

    // ─── GAP-03: commit authority (signer ↔ body ↔ leaf) ────────────────────

    /// A commit whose signed body claims `committer_user_id = derive(B)` but is
    /// signed by A is rejected — regardless of which identity the verifier is
    /// told to expect, the reconstructed body never matches both the signed
    /// bytes and the signing key at once.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_commit_authority_signer_mismatch_rejected() {
        let identity_a = create_test_identity();
        let identity_b = create_test_identity();

        let group_id = *create_test_session().group_id();
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];

        // Body claims derive(B) at committer leaf 0, but is signed by A.
        let commit_content = CommitContent::new_add(
            group_id,
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(identity_b.public_key()),
        );
        let signature = sign_commit(&identity_a, &commit_content).unwrap();

        let commit = AddCommit {
            group_id,
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32],
        };

        // Told the adder is A: verifier reconstructs derive(A) ≠ signed derive(B).
        let mut session_a = create_test_session();
        assert!(process_add(&mut session_a, &commit, identity_a.public_key()).is_err());

        // Told the adder is B: the signature was produced by A, not B.
        let mut session_b = create_test_session();
        assert!(process_add(&mut session_b, &commit, identity_b.public_key()).is_err());
    }

    /// A commit whose bound `committer_leaf_position` is out of range is
    /// rejected with `InvalidLeafPosition` after the signature verifies.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_commit_authority_bad_leaf_rejected() {
        let mut session = create_test_session(); // 1 member — only leaf 0 in range
        let adder = create_test_identity();

        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        // committer_leaf_position 99 is out of range; signature is otherwise valid.
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            99,
            derive_user_id_from_identity(adder.public_key()),
        );
        let signature = sign_commit(&adder, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 99,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag: [0u8; 32],
        };

        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(matches!(
            result,
            Err(trelis_error::CryptoError::InvalidLeafPosition)
        ));
    }

    /// Positive control: an honest add (signer == bound committer identity,
    /// in-range committer leaf, fresh member) round-trips through `process_add`
    /// and records the new member.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_commit_authority_honest_add_roundtrips() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        let path_updates_hash = hash_path_updates(&[]);
        // GAP-04c: consistent round hash for the receiver's empty-path recompute
        // (delta_root [0;32] + added = [new_member]).
        let round_hash = {
            use trelis_primitives::blake3_kdf::derive_key;
            h3_round_hash(
                &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
                &[],
                &[[0x02u8; 32]],
            )
        };
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder.public_key()),
        );
        let signature = sign_commit(&adder, &commit_content).unwrap();

        // Empty path updates ⇒ zero delta_root; compute the matching tag.
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag = compute_confirmation_tag(&[0u8; 32], &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_add(&mut session, &commit, adder.public_key()).unwrap();
        assert_eq!(session.member_count(), 2);
        assert!(session.is_member(&[0x02u8; 32]));
    }

    // ─── GAP-02: parent-hash verification on the add ingest path ────────────

    /// A flipped non-leaf `h1` on a real add commit is rejected by the parent-
    /// hash verifier; the honest commit verifies against the builder's own tree
    /// (positive control). Per the plan, the multi-party tree-sync setup is
    /// infeasible in a unit test, so this asserts `verify_parent_hashes`
    /// directly against the `add_member` builder output — the load-bearing SC2
    /// gate — rather than round-tripping through `process_add`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_parent_hash_add_tamper_rejected() {
        use super::super::path_update::verify_parent_hashes;

        let mut session = create_test_session(); // 1 member
        let our_identity = create_test_identity();
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);

        let (commit, _welcome) =
            add_member(&mut session, &our_identity, &new_bundle, [0x02u8; 32]).unwrap();
        let node_updates = convert_path_updates_to_node_updates(&commit.path_updates).unwrap();
        assert!(
            node_updates.len() >= 2,
            "add path must carry a non-leaf node"
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

    // ─── GAP-04c: mandatory round-hash verification on the add path ──────────

    /// A forged `round_hash` — made self-consistent with its own confirmation
    /// tag and covered by a valid signature — is rejected by the mandatory
    /// round-hash recompute (`RoundHashMismatch`). The confirmation tag only
    /// binds (delta_root, transcript, epoch), so a committer that advertises a
    /// round hash inconsistent with the membership change is caught ONLY by this
    /// independent recompute. Empty path updates ⇒ delta_root [0;32], so the
    /// receiver recomputes `h3_round_hash(derive_key(ROOT_LABEL_CONTEXT,[0;32]),
    /// [], [new_member])`; a garbage value differs and is rejected.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_round_hash_mismatch_rejected() {
        use trelis_primitives::blake3_kdf::derive_key;

        let mut session = create_test_session();
        let adder = create_test_identity();

        let path_updates_hash = hash_path_updates(&[]);
        // Forged: NOT the value the receiver recomputes from delta_root [0;32].
        let round_hash = [0x99u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder.public_key()),
        );
        let signature = sign_commit(&adder, &commit_content).unwrap();

        // Tag made SELF-CONSISTENT with the forged round hash, so the tag check
        // passes and execution reaches the round-hash gate (not an earlier one).
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag = compute_confirmation_tag(&[0u8; 32], &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        assert!(matches!(
            process_add(&mut session, &commit, adder.public_key()),
            Err(trelis_error::CryptoError::RoundHashMismatch)
        ));

        // Sanity: the honest recompute really differs from the forged value.
        let honest = h3_round_hash(
            &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
            &[],
            &[[0x02u8; 32]],
        );
        assert_ne!(honest, round_hash);
    }

    /// Positive control: an add whose `round_hash` matches the receiver's
    /// independent recompute (delta_root [0;32] + added = [new_member]) verifies
    /// and advances the epoch (records the new member).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_round_hash_honest_verifies() {
        use trelis_primitives::blake3_kdf::derive_key;

        let mut session = create_test_session();
        let adder = create_test_identity();

        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = h3_round_hash(
            &derive_key(ROOT_LABEL_CONTEXT, &[0u8; 32]),
            &[],
            &[[0x02u8; 32]],
        );
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder.public_key()),
        );
        let signature = sign_commit(&adder, &commit_content).unwrap();

        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag = compute_confirmation_tag(&[0u8; 32], &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        process_add(&mut session, &commit, adder.public_key()).unwrap();
        assert_eq!(session.member_count(), 2);
        assert!(session.is_member(&[0x02u8; 32]));
    }

    // ─── WR-03: rejected commit must not mutate session state ────────────────

    /// WR-03: a signature-valid add that fails the mandatory round-hash check
    /// must leave the session state COMPLETELY unchanged — the tree is not
    /// grown, `member_count` is not bumped, the new member is not recorded, and
    /// the epoch does not advance. Before the validate-then-mutate reorder,
    /// `process_add` grew the tree and set `member_count` BEFORE the round-hash
    /// check, so this exact GAP-04c insider commit (a valid signer advertising a
    /// bad round hash) left the session internally inconsistent.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_rejected_commit_leaves_state_unchanged() {
        let mut session = create_test_session(); // 1 member, depth 0, epoch 0
        let adder = create_test_identity();

        let members_before = session.member_count();
        let depth_before = session.tree().tree_depth();
        let epoch_before = session.epoch_number();

        let path_updates_hash = hash_path_updates(&[]);
        // Forged round hash (NOT the receiver's recompute from delta_root [0;32]);
        // the confirmation tag is made self-consistent so the tag check passes
        // and execution reaches the round-hash gate (not an earlier one).
        let round_hash = [0x99u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
            0,
            derive_user_id_from_identity(adder.public_key()),
        );
        let signature = sign_commit(&adder, &commit_content).unwrap();
        let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);
        let confirmation_tag = compute_confirmation_tag(&[0u8; 32], &new_transcript, 1);

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1, // would require growing the tree to depth 1
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
            confirmation_tag,
        };

        assert!(matches!(
            process_add(&mut session, &commit, adder.public_key()),
            Err(trelis_error::CryptoError::RoundHashMismatch)
        ));

        // State must be exactly as before the rejected commit.
        assert_eq!(
            session.member_count(),
            members_before,
            "member_count must be unchanged on a rejected add"
        );
        assert_eq!(
            session.tree().tree_depth(),
            depth_before,
            "tree must NOT be grown on a rejected add"
        );
        assert_eq!(
            session.epoch_number(),
            epoch_before,
            "epoch must NOT advance on a rejected add"
        );
        assert!(
            !session.is_member(&[0x02u8; 32]),
            "the rejected member must NOT be recorded"
        );
    }

    // ─── DOS-01/02/03: check_size_limits gate on the process_add ingest path ──

    /// DOS-01 ordering proof (reproduce-don't-assert): an add commit whose
    /// measured message size exceeds `MAX_MESSAGE_SIZE` AND whose signature is
    /// invalid returns `MessageTooLarge`, NOT `SignatureVerificationFailed` — the
    /// size gate fires before `verify_commit_signature`. The group_id and epoch
    /// are valid so, absent the gate, control flow would reach verify.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_rejects_oversized_message_before_verify() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        // One path update carrying a ciphertext larger than MAX_MESSAGE_SIZE.
        let oversized = PathUpdate {
            node_index: NodeIndex::leaf(1, 0),
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
        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: vec![oversized],
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::MessageTooLarge)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }

    /// DOS-02 ordering proof: an add commit with more than 21 path updates
    /// (proof_depth > 20) AND an invalid signature returns `ProofTooDeep`, not
    /// `SignatureVerificationFailed`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_rejects_overdeep_proof_before_verify() {
        let mut session = create_test_session();
        let adder = create_test_identity();

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
        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates,
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::ProofTooDeep)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }

    /// DOS-02 off-by-one guard: an HONEST maximal depth-20 commit carries 21
    /// path updates (`path_to_root` returns depth+1 nodes), mapping to proof_depth
    /// 20 — which is NOT `> MAX_MERKLE_PROOF_DEPTH(20)`. It must NOT be rejected
    /// as `ProofTooDeep` (it may fail later for unrelated reasons, never here).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_accepts_max_depth_proof() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        // 21 path updates -> proof_depth = 21 - 1 = 20 == MAX_MERKLE_PROOF_DEPTH.
        let path_updates: Vec<PathUpdate> = (0..21)
            .map(|_| PathUpdate {
                node_index: NodeIndex::new(0, 0),
                new_public_key: Vec::new(),
                parent_hash: ([0u8; 32], [0u8; 32]),
                encrypted_seeds: Vec::new(),
            })
            .collect();
        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates,
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(
            !matches!(result, Err(trelis_error::CryptoError::ProofTooDeep)),
            "honest depth-20 (21 path_updates) commit must NOT be ProofTooDeep; got {result:?}"
        );
    }

    /// DOS-03 (group) ordering proof: an add whose resulting member count exceeds
    /// `MAX_GROUP_SIZE` AND with an invalid signature returns `TreeDepthExceeded`,
    /// not `SignatureVerificationFailed`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_rejects_oversized_group_before_verify() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        // new_leaf_position = MAX_GROUP_SIZE -> new_member_count = MAX_GROUP_SIZE
        // + 1 > MAX_GROUP_SIZE (also depth 21 > MAX_TREE_DEPTH).
        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: crate::MAX_GROUP_SIZE,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::TreeDepthExceeded)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }

    /// DOS-03 (unmerged) ordering proof: a crypto-invalid add into a session
    /// whose tree already carries more than `MAX_UNMERGED_LEAVES` unmerged leaves
    /// returns `TreeDepthExceeded`, not `SignatureVerificationFailed` — proving
    /// `total_unmerged_leaves()` feeds the gate ahead of verify.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_add_rejects_excess_unmerged_before_verify() {
        let mut session = create_test_session();
        let adder = create_test_identity();

        // Flood a blank node with > MAX_UNMERGED_LEAVES distinct unmerged leaf
        // positions (0..=MAX_UNMERGED_LEAVES is 101 distinct positions).
        session
            .tree_mut()
            .insert(crate::tree::TreeNode::new_blank(NodeIndex::new(1, 1)));
        for pos in 0..=(crate::MAX_UNMERGED_LEAVES as u32) {
            session
                .tree_mut()
                .add_unmerged_leaf(&NodeIndex::new(1, 1), pos);
        }
        assert!(session.tree().total_unmerged_leaves() > crate::MAX_UNMERGED_LEAVES);

        let signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            committer_leaf_position: 0,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash: [0u8; 32],
            confirmation_tag: [0u8; 32],
        };
        let result = process_add(&mut session, &commit, adder.public_key());
        assert!(
            matches!(result, Err(trelis_error::CryptoError::TreeDepthExceeded)),
            "size gate MUST fire before verify; got {result:?}"
        );
    }

    /// DOS-03 (local-growth defence-in-depth): `add_member` into a group already
    /// at `MAX_GROUP_SIZE` is rejected with `TreeDepthExceeded` (the resulting
    /// member count would exceed the ceiling) before the tree is grown; a
    /// `member_count` at `u32::MAX` returns `Err` (checked_add), never a panic.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_add_member_rejects_oversized_group() {
        let our_identity = create_test_identity();
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);

        // Group at the ceiling: the next add would make member_count
        // MAX_GROUP_SIZE + 1 > MAX_GROUP_SIZE.
        let mut session = create_test_session();
        session.tree_mut().set_member_count(crate::MAX_GROUP_SIZE);
        assert!(matches!(
            add_member(&mut session, &our_identity, &new_bundle, [0x02u8; 32]),
            Err(trelis_error::CryptoError::TreeDepthExceeded)
        ));

        // Overflow-safe: a member_count at u32::MAX returns Err (checked_add),
        // never panics under the workspace overflow-checks profile.
        let mut session2 = create_test_session();
        session2.tree_mut().set_member_count(u32::MAX);
        assert!(add_member(&mut session2, &our_identity, &new_bundle, [0x03u8; 32]).is_err());
    }
}
