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
use trelis_hybrid::{HybridIdentityKeypair, HybridIdentityPublicKey, HybridPreKeyBundle, HybridSignature};
#[cfg(feature = "alloc")]
use trelis_hybrid::HybridKemPublicKey;

use crate::key_schedule::{h3_round_hash, h3_transcript_hash};
#[cfg(feature = "alloc")]
use crate::key_schedule::h3_tree_label;
use crate::session::CocoaSession;
use crate::tree::NodeIndex;
#[cfg(feature = "alloc")]
use crate::tree::{compute_lj, path_to_root};
use crate::{GroupId, UserId};

use super::Welcome;
use super::commit_sign::{CommitContent, hash_path_updates, sign_commit, verify_commit_signature};
#[cfg(feature = "alloc")]
use super::seed_chain::{Seed, derive_path_seeds, generate_leaf_seed};

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
    let (resolution_sets, resolution_keys) =
        compute_add_resolution_sets_and_keys(session, &path, new_member_bundle, tree_depth, new_position);

    // Step 7: Compute sibling labels for parent hash computation
    let sibling_labels = compute_sibling_labels(session, &path);

    // Step 8: Build path updates with encrypted seeds
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

    // Step 8: Update member count before computing round hash
    session.tree_mut().set_member_count(new_position + 1);

    // Step 9: Compute round hash (add includes the new member)
    let root_label = compute_root_label(&path_seeds);
    let round_hash = h3_round_hash(&root_label, &[], &[new_member_id]);

    // Step 10: Serialise path updates and compute hash
    let path_updates_bytes = serialise_path_updates(&path_updates);
    let path_updates_hash = hash_path_updates(&path_updates_bytes);

    // Step 11: Build commit content for signing
    let commit_content = CommitContent::new_add(
        *session.group_id(),
        session.epoch_number() + 1,
        round_hash,
        path_updates_hash,
    );

    // Step 12: Sign the commit with identity key
    let signature = sign_commit(identity, &commit_content)?;

    // Step 13: Update transcript
    let new_transcript = h3_transcript_hash(session.transcript_hash(), &round_hash);

    // Step 14: Create welcome message with encrypted group state
    let welcome = create_welcome_message(
        session,
        new_member_bundle,
        new_position,
        tree_depth,
        &delta_root,
        &new_transcript,
    )?;

    let commit = AddCommit {
        group_id: *session.group_id(),
        new_member_id,
        new_leaf_position: new_position,
        epoch: session.epoch_number() + 1,
        path_updates,
        signature,
        round_hash,
    };

    // Step 15: Advance epoch with real delta_root
    session.advance_epoch(&delta_root, new_transcript);

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
        // Compute Lj = Res(sibling(path_node))
        let resolution = compute_lj(session.tree(), *path_node, |_| Vec::new());

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
        if is_in_sibling_subtree(path_node, &new_member_leaf) {
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
fn is_in_sibling_subtree(path_node: &NodeIndex, target: &NodeIndex) -> bool {
    // Get the sibling of the path node
    if let Some(sibling) = path_node.sibling() {
        // Check if target is a descendant of sibling
        target.is_descendant_of(&sibling) || *target == sibling
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

/// Creates a welcome message for the new member.
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
fn create_welcome_message(
    session: &CocoaSession,
    new_member_bundle: &HybridPreKeyBundle,
    new_position: u32,
    tree_depth: u32,
    delta_root: &Seed,
    new_transcript: &[u8; 32],
) -> Result<Welcome> {
    use super::init::encrypt_welcome_info;

    // Build tree_info: serialize nodes on the adder's path
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

    Ok(Welcome {
        group_id: *session.group_id(),
        epoch: session.epoch_number() + 1,
        leaf_position: new_position,
        tree_depth,
        member_count: new_position + 1,
        encrypted_info,
        encapsulation,
    })
}

/// Serializes tree information for the welcome message.
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

    // Serialize each node in our path
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
    _new_member_bundle: &HybridPreKeyBundle,
    new_position: u32,
    tree_depth: u32,
    _delta_root: &Seed,
    _new_transcript: &[u8; 32],
) -> Result<Welcome> {
    Ok(Welcome {
        group_id: *session.group_id(),
        epoch: session.epoch_number() + 1,
        leaf_position: new_position,
        tree_depth,
        member_count: new_position + 1,
        encrypted_info: Vec::new(),
        encapsulation: Vec::new(),
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

/// Processes an add commit from another member.
///
/// # Arguments
///
/// * `session` - Our current session (mutated)
/// * `commit` - The add commit to process
/// * `adder_identity` - The adder's public identity key for signature verification
#[cfg(feature = "alloc")]
pub fn process_add(
    session: &mut CocoaSession,
    commit: &AddCommit,
    adder_identity: &HybridIdentityPublicKey,
) -> Result<()> {
    // Verify the commit is for our group
    if commit.group_id != *session.group_id() {
        return Err(trelis_error::CryptoError::GroupIdMismatch);
    }

    // Grow tree if needed for the new member
    let new_member_count = commit.new_leaf_position + 1;
    session.tree_mut().grow_if_needed(new_member_count);

    // Compute path updates hash for verification
    let path_updates_hash = hash_path_updates(&[]); // Would serialise actual path updates

    // Build commit content for verification
    let commit_content = CommitContent::new_add(
        commit.group_id,
        commit.epoch,
        commit.round_hash,
        path_updates_hash,
    );

    // Verify signature
    verify_commit_signature(adder_identity, &commit_content, &commit.signature)?;

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

    #[test]
    fn test_add_member() {
        let mut session = create_test_session();
        let our_identity = create_test_identity();
        assert_eq!(session.member_count(), 1);

        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);
        let new_user_id = [0x02u8; 32];

        let (commit, welcome) = add_member(&mut session, &our_identity, &new_bundle, new_user_id).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(commit.new_leaf_position, 1);
        assert_eq!(welcome.leaf_position, 1);
    }

    #[test]
    fn test_process_add() {
        let mut session = create_test_session();
        let adder_identity = create_test_identity();

        // Build a valid add commit
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
        };

        process_add(&mut session, &commit, adder_identity.public_key()).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.epoch_number(), 1);
    }

    #[test]
    fn test_process_add_wrong_signer() {
        let mut session = create_test_session();
        let signer_identity = create_test_identity();
        let wrong_identity = create_test_identity();

        // Build commit signed by signer_identity
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&signer_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
        };

        // Try to verify with wrong identity - should fail
        let result = process_add(&mut session, &commit, wrong_identity.public_key());
        assert!(result.is_err());
    }

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
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: wrong_group_id, // Wrong group
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1,
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
        };

        // Group ID check happens before signature verification
        let result = process_add(&mut session, &commit, adder_identity.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_member_tree_growth() {
        // Start with a single member (depth 0, capacity 1)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session = CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();
        let our_identity = create_test_identity();

        // Verify initial state
        assert_eq!(session.member_count(), 1);
        assert_eq!(session.tree().tree_depth(), 0); // depth 0 for 1 member

        // Add second member - should trigger tree growth to depth 1
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);
        let new_user_id = [0x02u8; 32];

        let (commit, _) = add_member(&mut session, &our_identity, &new_bundle, new_user_id).unwrap();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1); // grew to depth 1
        assert_eq!(commit.new_leaf_position, 1);
    }

    #[test]
    fn test_add_multiple_members_with_growth() {
        // Create a session with 2 initial members (depth 1)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session = CocoaSession::create_group(group_id, user_id, keypair, 2, &epoch_secret).unwrap();
        let our_identity = create_test_identity();

        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1);
        assert_eq!(session.tree().capacity(), 2);

        // Add third member - should trigger tree growth to depth 2
        let new_identity = create_test_identity();
        let new_bundle = create_test_bundle(&new_identity);

        let (commit, _) = add_member(&mut session, &our_identity, &new_bundle, [0x03u8; 32]).unwrap();

        assert_eq!(session.member_count(), 3);
        assert_eq!(session.tree().tree_depth(), 2); // grew to depth 2
        assert_eq!(session.tree().capacity(), 4);
        assert_eq!(commit.new_leaf_position, 2);

        // Add fourth member - should fit without growth
        let another_identity = create_test_identity();
        let another_bundle = create_test_bundle(&another_identity);

        let (commit2, _) = add_member(&mut session, &our_identity, &another_bundle, [0x04u8; 32]).unwrap();

        assert_eq!(session.member_count(), 4);
        assert_eq!(session.tree().tree_depth(), 2); // still depth 2
        assert_eq!(commit2.new_leaf_position, 3);

        // Add fifth member - should trigger tree growth to depth 3
        let fifth_identity = create_test_identity();
        let fifth_bundle = create_test_bundle(&fifth_identity);

        let (commit3, _) = add_member(&mut session, &our_identity, &fifth_bundle, [0x05u8; 32]).unwrap();

        assert_eq!(session.member_count(), 5);
        assert_eq!(session.tree().tree_depth(), 3); // grew to depth 3
        assert_eq!(session.tree().capacity(), 8);
        assert_eq!(commit3.new_leaf_position, 4);
    }

    #[test]
    fn test_process_add_tree_growth() {
        // Start with depth 0 (single member)
        let group_id = [0x42u8; 32];
        let user_id = [0x01u8; 32];
        let keypair = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0xABu8; 32];

        let mut session = CocoaSession::create_group(group_id, user_id, keypair, 1, &epoch_secret).unwrap();
        let adder_identity = create_test_identity();

        assert_eq!(session.tree().tree_depth(), 0);

        // Create commit for adding member at position 1
        let path_updates_hash = hash_path_updates(&[]);
        let round_hash = [0x11u8; 32];
        let commit_content = CommitContent::new_add(
            *session.group_id(),
            1,
            round_hash,
            path_updates_hash,
        );
        let signature = sign_commit(&adder_identity, &commit_content).unwrap();

        let commit = AddCommit {
            group_id: *session.group_id(),
            new_member_id: [0x02u8; 32],
            new_leaf_position: 1, // This requires depth 1
            epoch: 1,
            path_updates: Vec::new(),
            signature,
            round_hash,
        };

        process_add(&mut session, &commit, adder_identity.public_key()).unwrap();

        // Tree should have grown
        assert_eq!(session.member_count(), 2);
        assert_eq!(session.tree().tree_depth(), 1);
    }
}
