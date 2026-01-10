//! Commit signing and verification for CoCoA operations.
//!
//! This module provides the cryptographic signing and verification
//! of CoCoA commit messages. All commits (add, remove, update) are
//! signed by the committer's identity key to provide authenticity
//! and prevent commit forgery.
//!
//! # Signing Context
//!
//! Commits are signed with a domain-separated context to prevent
//! cross-protocol signature attacks:
//!
//! ```text
//! context = "cocoa-sa-v1-commit-sign"
//! message = group_id || epoch (u64 BE) || round_hash || path_updates_hash
//! ```
//!
//! # Security Properties
//!
//! - **Authenticity**: Only the identity key holder can sign commits
//! - **Integrity**: Any modification to commit content invalidates signature
//! - **Domain separation**: Signatures cannot be reused in other protocols
//! - **Epoch binding**: Commits are bound to specific epochs

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridIdentityKeypair, HybridIdentityPublicKey, HybridSignature};
use trelis_primitives::blake3_kdf::derive_key;

use crate::{GroupId, UserId};

/// Signing context for commit signatures.
///
/// This context is used with EdDSA/ML-DSA context signing to provide
/// domain separation for CoCoA commit signatures.
const COMMIT_SIGN_CONTEXT: &[u8] = b"cocoa-sa-v1-commit-sign";

/// Content of a commit to be signed.
///
/// This structure contains all the data that is cryptographically
/// bound by the commit signature.
#[derive(Debug, Clone)]
pub struct CommitContent {
    /// The group this commit applies to.
    pub group_id: GroupId,
    /// The epoch after this commit.
    pub epoch: u64,
    /// Commit type identifier.
    pub commit_type: CommitType,
    /// The round hash (H3) binding the operation.
    pub round_hash: [u8; 32],
    /// Hash of the path updates (for integrity).
    pub path_updates_hash: [u8; 32],
}

/// Type of commit operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitType {
    /// Add a new member to the group.
    Add,
    /// Remove a member from the group.
    Remove,
    /// Update the committer's own keys.
    Update,
}

impl CommitType {
    /// Returns the byte representation for serialisation.
    #[must_use]
    pub const fn as_byte(&self) -> u8 {
        match self {
            CommitType::Add => 0x01,
            CommitType::Remove => 0x02,
            CommitType::Update => 0x03,
        }
    }

    /// Creates a `CommitType` from a byte.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the byte is not a valid commit type.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(CommitType::Add),
            0x02 => Ok(CommitType::Remove),
            0x03 => Ok(CommitType::Update),
            _ => Err(CryptoError::MalformedMessage),
        }
    }
}

/// Size of serialised commit content in bytes.
///
/// Layout: group_id (32) + epoch (8) + commit_type (1) + round_hash (32) + path_updates_hash (32)
pub const COMMIT_CONTENT_SIZE: usize = 32 + 8 + 1 + 32 + 32;

impl CommitContent {
    /// Creates a new commit content for an add operation.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group identifier
    /// * `epoch` - The epoch after this commit
    /// * `round_hash` - The round hash binding the add operation
    /// * `path_updates_hash` - Hash of the path updates
    #[must_use]
    pub fn new_add(
        group_id: GroupId,
        epoch: u64,
        round_hash: [u8; 32],
        path_updates_hash: [u8; 32],
    ) -> Self {
        Self {
            group_id,
            epoch,
            commit_type: CommitType::Add,
            round_hash,
            path_updates_hash,
        }
    }

    /// Creates a new commit content for a remove operation.
    #[must_use]
    pub fn new_remove(
        group_id: GroupId,
        epoch: u64,
        round_hash: [u8; 32],
        path_updates_hash: [u8; 32],
    ) -> Self {
        Self {
            group_id,
            epoch,
            commit_type: CommitType::Remove,
            round_hash,
            path_updates_hash,
        }
    }

    /// Creates a new commit content for an update operation.
    #[must_use]
    pub fn new_update(
        group_id: GroupId,
        epoch: u64,
        round_hash: [u8; 32],
        path_updates_hash: [u8; 32],
    ) -> Self {
        Self {
            group_id,
            epoch,
            commit_type: CommitType::Update,
            round_hash,
            path_updates_hash,
        }
    }

    /// Serialises the commit content to bytes.
    ///
    /// This is the data that gets signed.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; COMMIT_CONTENT_SIZE] {
        let mut bytes = [0u8; COMMIT_CONTENT_SIZE];
        let mut offset = 0;

        // Group ID (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.group_id);
        offset += 32;

        // Epoch (8 bytes, big-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.epoch.to_be_bytes());
        offset += 8;

        // Commit type (1 byte)
        bytes[offset] = self.commit_type.as_byte();
        offset += 1;

        // Round hash (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.round_hash);
        offset += 32;

        // Path updates hash (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.path_updates_hash);

        bytes
    }

    /// Deserialises commit content from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the bytes are not valid commit content.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMMIT_CONTENT_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Group ID
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Epoch
        let epoch = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Commit type
        let commit_type = CommitType::from_byte(bytes[offset])?;
        offset += 1;

        // Round hash
        let mut round_hash = [0u8; 32];
        round_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Path updates hash
        let mut path_updates_hash = [0u8; 32];
        path_updates_hash.copy_from_slice(&bytes[offset..offset + 32]);

        Ok(Self {
            group_id,
            epoch,
            commit_type,
            round_hash,
            path_updates_hash,
        })
    }
}

/// Signs a commit with an identity keypair.
///
/// Uses the hybrid signing scheme (Ed448 + ML-DSA-65) with domain-separated
/// context to produce a signature over the commit content.
///
/// # Arguments
///
/// * `identity` - The signer's hybrid identity keypair
/// * `content` - The commit content to sign
///
/// # Returns
///
/// A hybrid signature over the commit content.
///
/// # Errors
///
/// Returns `SigningFailed` if signature generation fails.
pub fn sign_commit(
    identity: &HybridIdentityKeypair,
    content: &CommitContent,
) -> Result<HybridSignature> {
    let message = content.to_bytes();
    identity.sign_with_context(&message, COMMIT_SIGN_CONTEXT)
}

/// Verifies a commit signature.
///
/// # Arguments
///
/// * `identity_public` - The signer's public identity key
/// * `content` - The commit content that was signed
/// * `signature` - The signature to verify
///
/// # Errors
///
/// Returns `SignatureVerificationFailed` if the signature is invalid.
pub fn verify_commit_signature(
    identity_public: &HybridIdentityPublicKey,
    content: &CommitContent,
    signature: &HybridSignature,
) -> Result<()> {
    let message = content.to_bytes();
    identity_public.verify_with_context(&message, COMMIT_SIGN_CONTEXT, signature)
}

/// Computes the hash of path updates for signing.
///
/// This creates a compact commitment to the path updates that can be
/// included in the commit content for signing.
///
/// # Arguments
///
/// * `path_updates_bytes` - The serialised path updates (must be canonically ordered)
///
/// # Returns
///
/// A 32-byte hash of the path updates.
///
/// # Note
///
/// The path updates MUST be serialised in canonical order (by node index:
/// depth ascending, then position ascending) before passing to this function.
/// Use [`canonicalise_path_update_order`] to ensure correct ordering.
#[must_use]
pub fn hash_path_updates(path_updates_bytes: &[u8]) -> [u8; 32] {
    derive_key("cocoa-sa-v1-path-updates-hash", path_updates_bytes)
}

/// Canonicalizes path update indices for deterministic signing.
///
/// Per CoCoA spec section 12.6.3, path updates must be canonically ordered
/// before hashing for signing. This ensures all implementations produce
/// the same signature for equivalent commits.
///
/// # Canonical Order
///
/// Path updates are ordered by node index:
/// 1. First by depth (ascending - leaf to root)
/// 2. Then by position (ascending)
///
/// # Arguments
///
/// * `indices` - Slice of node indices from path updates
///
/// # Returns
///
/// A vector of indices sorted in canonical order.
#[cfg(feature = "alloc")]
#[must_use]
pub fn canonicalise_path_update_order(indices: &[crate::tree::NodeIndex]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..indices.len()).collect();

    // Sort by (depth descending, position ascending) to go from leaf to root
    // The linear index already captures this ordering: leaf nodes have higher
    // linear indices than their ancestors
    order.sort_by(|&a, &b| {
        let idx_a = &indices[a];
        let idx_b = &indices[b];

        // First compare by depth (descending - leaves first)
        match idx_b.depth.cmp(&idx_a.depth) {
            core::cmp::Ordering::Equal => {
                // Then by position (ascending)
                idx_a.position.cmp(&idx_b.position)
            }
            other => other,
        }
    });

    order
}

/// Extended commit content that includes operation-specific data.
///
/// This is used when additional metadata needs to be bound to the signature.
#[derive(Debug, Clone)]
pub struct ExtendedCommitContent {
    /// Base commit content.
    pub base: CommitContent,
    /// For add: the new member's user ID.
    pub added_member: Option<UserId>,
    /// For add: the new member's leaf position.
    pub added_position: Option<u32>,
    /// For remove: the removed member's user ID.
    pub removed_member: Option<UserId>,
    /// For remove: the removed member's leaf position.
    pub removed_position: Option<u32>,
}

impl ExtendedCommitContent {
    /// Creates extended content for an add operation.
    #[must_use]
    pub fn new_add(base: CommitContent, added_member: UserId, added_position: u32) -> Self {
        Self {
            base,
            added_member: Some(added_member),
            added_position: Some(added_position),
            removed_member: None,
            removed_position: None,
        }
    }

    /// Creates extended content for a remove operation.
    #[must_use]
    pub fn new_remove(base: CommitContent, removed_member: UserId, removed_position: u32) -> Self {
        Self {
            base,
            added_member: None,
            added_position: None,
            removed_member: Some(removed_member),
            removed_position: Some(removed_position),
        }
    }

    /// Creates extended content for an update operation.
    #[must_use]
    pub fn new_update(base: CommitContent) -> Self {
        Self {
            base,
            added_member: None,
            added_position: None,
            removed_member: None,
            removed_position: None,
        }
    }

    /// Serialises the extended commit content.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let base_bytes = self.base.to_bytes();
        let mut bytes = Vec::with_capacity(COMMIT_CONTENT_SIZE + 72);
        bytes.extend_from_slice(&base_bytes);

        // Add member (optional: 32 bytes user ID + 4 bytes position)
        if let (Some(member), Some(pos)) = (self.added_member, self.added_position) {
            bytes.extend_from_slice(&member);
            bytes.extend_from_slice(&pos.to_be_bytes());
        }

        // Removed member (optional: 32 bytes user ID + 4 bytes position)
        if let (Some(member), Some(pos)) = (self.removed_member, self.removed_position) {
            bytes.extend_from_slice(&member);
            bytes.extend_from_slice(&pos.to_be_bytes());
        }

        bytes
    }
}

/// Signs extended commit content.
///
/// This includes operation-specific data in the signed message.
#[cfg(feature = "alloc")]
pub fn sign_extended_commit(
    identity: &HybridIdentityKeypair,
    content: &ExtendedCommitContent,
) -> Result<HybridSignature> {
    let message = content.to_bytes();
    identity.sign_with_context(&message, COMMIT_SIGN_CONTEXT)
}

/// Verifies an extended commit signature.
#[cfg(feature = "alloc")]
pub fn verify_extended_commit_signature(
    identity_public: &HybridIdentityPublicKey,
    content: &ExtendedCommitContent,
    signature: &HybridSignature,
) -> Result<()> {
    let message = content.to_bytes();
    identity_public.verify_with_context(&message, COMMIT_SIGN_CONTEXT, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> HybridIdentityKeypair {
        HybridIdentityKeypair::generate().unwrap()
    }

    #[test]
    fn test_commit_type_roundtrip() {
        assert_eq!(
            CommitType::from_byte(CommitType::Add.as_byte()).unwrap(),
            CommitType::Add
        );
        assert_eq!(
            CommitType::from_byte(CommitType::Remove.as_byte()).unwrap(),
            CommitType::Remove
        );
        assert_eq!(
            CommitType::from_byte(CommitType::Update.as_byte()).unwrap(),
            CommitType::Update
        );
    }

    #[test]
    fn test_commit_type_invalid() {
        assert!(CommitType::from_byte(0x00).is_err());
        assert!(CommitType::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_commit_content_serialisation() {
        let content = CommitContent::new_add([0x42u8; 32], 42, [0xAAu8; 32], [0xBBu8; 32]);

        let bytes = content.to_bytes();
        assert_eq!(bytes.len(), COMMIT_CONTENT_SIZE);

        let recovered = CommitContent::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.group_id, content.group_id);
        assert_eq!(recovered.epoch, content.epoch);
        assert_eq!(recovered.commit_type, content.commit_type);
        assert_eq!(recovered.round_hash, content.round_hash);
        assert_eq!(recovered.path_updates_hash, content.path_updates_hash);
    }

    #[test]
    fn test_sign_verify_commit() {
        let identity = test_identity();
        let content = CommitContent::new_update([0x42u8; 32], 1, [0xAAu8; 32], [0xBBu8; 32]);

        let signature = sign_commit(&identity, &content).unwrap();
        assert!(verify_commit_signature(identity.public_key(), &content, &signature).is_ok());
    }

    #[test]
    fn test_wrong_identity_fails() {
        let identity1 = test_identity();
        let identity2 = test_identity();
        let content = CommitContent::new_update([0x42u8; 32], 1, [0xAAu8; 32], [0xBBu8; 32]);

        let signature = sign_commit(&identity1, &content).unwrap();
        assert!(verify_commit_signature(identity2.public_key(), &content, &signature).is_err());
    }

    #[test]
    fn test_modified_content_fails() {
        let identity = test_identity();
        let content = CommitContent::new_update([0x42u8; 32], 1, [0xAAu8; 32], [0xBBu8; 32]);

        let signature = sign_commit(&identity, &content).unwrap();

        // Modify the content
        let modified = CommitContent::new_update(
            [0x42u8; 32],
            2, // Changed epoch
            [0xAAu8; 32],
            [0xBBu8; 32],
        );

        assert!(verify_commit_signature(identity.public_key(), &modified, &signature).is_err());
    }

    #[test]
    fn test_hash_path_updates() {
        let updates1 = [0x11u8; 100];
        let updates2 = [0x22u8; 100];

        let hash1 = hash_path_updates(&updates1);
        let hash2 = hash_path_updates(&updates2);
        let hash1_again = hash_path_updates(&updates1);

        // Same input produces same hash
        assert_eq!(hash1, hash1_again);
        // Different inputs produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_extended_commit_add() {
        let identity = test_identity();
        let base = CommitContent::new_add([0x42u8; 32], 1, [0xAAu8; 32], [0xBBu8; 32]);
        let extended = ExtendedCommitContent::new_add(base, [0xCCu8; 32], 5);

        let signature = sign_extended_commit(&identity, &extended).unwrap();
        assert!(
            verify_extended_commit_signature(identity.public_key(), &extended, &signature).is_ok()
        );
    }

    #[test]
    fn test_extended_commit_remove() {
        let identity = test_identity();
        let base = CommitContent::new_remove([0x42u8; 32], 2, [0xAAu8; 32], [0xBBu8; 32]);
        let extended = ExtendedCommitContent::new_remove(base, [0xDDu8; 32], 3);

        let signature = sign_extended_commit(&identity, &extended).unwrap();
        assert!(
            verify_extended_commit_signature(identity.public_key(), &extended, &signature).is_ok()
        );
    }

    #[test]
    fn test_extended_commit_update() {
        let identity = test_identity();
        let base = CommitContent::new_update([0x42u8; 32], 3, [0xAAu8; 32], [0xBBu8; 32]);
        let extended = ExtendedCommitContent::new_update(base);

        let signature = sign_extended_commit(&identity, &extended).unwrap();
        assert!(
            verify_extended_commit_signature(identity.public_key(), &extended, &signature).is_ok()
        );
    }

    #[test]
    fn test_commit_content_size() {
        // Verify the constant matches actual serialisation
        let content = CommitContent::new_add([0u8; 32], 0, [0u8; 32], [0u8; 32]);
        assert_eq!(content.to_bytes().len(), COMMIT_CONTENT_SIZE);
    }

    #[test]
    fn test_canonicalise_path_update_order() {
        use crate::tree::NodeIndex;

        // Create indices in random order
        let indices = vec![
            NodeIndex::new(0, 0), // root
            NodeIndex::new(2, 1), // leaf
            NodeIndex::new(1, 0), // intermediate
            NodeIndex::new(2, 0), // leaf
        ];

        let order = canonicalise_path_update_order(&indices);

        // Should be sorted: depth 2 first (leaves), then depth 1, then depth 0 (root)
        // Within same depth, by position ascending
        assert_eq!(order, vec![3, 1, 2, 0]); // (2,0), (2,1), (1,0), (0,0)

        // Verify the ordering
        assert_eq!(indices[order[0]], NodeIndex::new(2, 0));
        assert_eq!(indices[order[1]], NodeIndex::new(2, 1));
        assert_eq!(indices[order[2]], NodeIndex::new(1, 0));
        assert_eq!(indices[order[3]], NodeIndex::new(0, 0));
    }

    #[test]
    fn test_canonicalise_empty() {
        use crate::tree::NodeIndex;

        let indices: Vec<NodeIndex> = vec![];
        let order = canonicalise_path_update_order(&indices);
        assert!(order.is_empty());
    }

    #[test]
    fn test_canonicalise_single() {
        use crate::tree::NodeIndex;

        let indices = vec![NodeIndex::new(1, 0)];
        let order = canonicalise_path_update_order(&indices);
        assert_eq!(order, vec![0]);
    }
}
