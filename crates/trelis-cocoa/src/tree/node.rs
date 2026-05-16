//! Tree node state and structure.
//!
//! Each node in the ratchet tree can be either populated (with key material)
//! or blank (after member removal).

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

use trelis_hybrid::{HybridKemPublicKey, HybridSignature};

use super::NodeIndex;
use crate::UserId;

/// Origin information for tracking update provenance.
#[derive(Debug, Clone)]
pub struct UpdateOrigin {
    /// Epoch when this update was made.
    pub epoch: u64,
    /// Sequence number within epoch.
    pub sequence: u32,
    /// Server timestamp (Unix seconds).
    pub timestamp: u64,
}

/// Data for a populated node (boxed to reduce enum size).
#[derive(Debug, Clone)]
pub struct PopulatedNodeData {
    /// Hybrid public key at this node (PK_v).
    pub public_key: HybridKemPublicKey,
    /// Predecessor public key - key before last update (PK_pr).
    /// Used for verifying updates from users who haven't yet
    /// processed the most recent commit at this node.
    pub predecessor_key: Option<HybridKemPublicKey>,
    /// Parent hash for tree integrity (h_v = (h_1, h_2)).
    /// Two-component structure per CoCoA paper Section 3.4:
    /// - h_1: sibling subtree commitment
    /// - h_2: predecessor/children commitment
    pub parent_hash: ([u8; 32], [u8; 32]),
    /// Identity of the user who last updated this node (ID_v).
    pub last_updater_id: UserId,
    /// Signature over update message (sigma_v).
    pub update_signature: HybridSignature,
    /// Transcript hash at time of last update (H_trans,v).
    pub transcript_hash: [u8; 32],
    /// Confirmation tag for this node's update (confTag_v).
    pub confirmation_tag: [u8; 32],
    /// Origin information - metadata about update source.
    pub origin: UpdateOrigin,
}

/// State of a node in the ratchet tree.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub enum NodeState {
    /// Active node with key material (boxed due to large size).
    Populated(Box<PopulatedNodeData>),

    /// Blank node (member removed or position never filled).
    Blank {
        /// Unmerged leaf positions - leaves that haven't processed an update through this node.
        /// Critical for correct resolution computation. Stores leaf positions (not UserId)
        /// so they can be directly used in compute_lj() for resolution set computation.
        unmerged_leaves: Vec<u32>,
    },
}

#[cfg(feature = "alloc")]
impl NodeState {
    /// Creates a new blank node state.
    #[must_use]
    pub fn blank() -> Self {
        Self::Blank {
            unmerged_leaves: Vec::new(),
        }
    }

    /// Returns true if this node is blank.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        matches!(self, Self::Blank { .. })
    }

    /// Returns true if this node is populated.
    #[must_use]
    pub fn is_populated(&self) -> bool {
        matches!(self, Self::Populated(_))
    }

    /// Returns the public key if populated.
    #[must_use]
    pub fn public_key(&self) -> Option<&HybridKemPublicKey> {
        match self {
            Self::Populated(data) => Some(&data.public_key),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the predecessor key if populated.
    #[must_use]
    pub fn predecessor_key(&self) -> Option<&HybridKemPublicKey> {
        match self {
            Self::Populated(data) => data.predecessor_key.as_ref(),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the parent hash if populated.
    #[must_use]
    pub fn parent_hash(&self) -> Option<&([u8; 32], [u8; 32])> {
        match self {
            Self::Populated(data) => Some(&data.parent_hash),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the last updater ID if populated.
    #[must_use]
    pub fn last_updater_id(&self) -> Option<&UserId> {
        match self {
            Self::Populated(data) => Some(&data.last_updater_id),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the unmerged leaf positions for blank nodes.
    #[must_use]
    pub fn unmerged_leaves(&self) -> Option<&[u32]> {
        match self {
            Self::Blank { unmerged_leaves } => Some(unmerged_leaves),
            Self::Populated(_) => None,
        }
    }

    /// Adds an unmerged leaf position to a blank node.
    ///
    /// When a member joins the group, they should be marked as unmerged on all
    /// nodes in the path from their leaf to the root. This ensures they receive
    /// encrypted path secrets when other members send updates.
    pub fn add_unmerged_leaf(&mut self, leaf_position: u32) {
        if let Self::Blank { unmerged_leaves } = self {
            if !unmerged_leaves.contains(&leaf_position) {
                unmerged_leaves.push(leaf_position);
            }
        }
    }

    /// Removes an unmerged leaf position from a blank node.
    ///
    /// Called when a member processes an update that covers this node,
    /// indicating they now have the current key material.
    pub fn remove_unmerged_leaf(&mut self, leaf_position: u32) {
        if let Self::Blank { unmerged_leaves } = self {
            unmerged_leaves.retain(|&pos| pos != leaf_position);
        }
    }
}

/// A complete tree node with index and state.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Position in tree.
    pub index: NodeIndex,
    /// Node state (populated or blank).
    pub state: NodeState,
}

#[cfg(feature = "alloc")]
impl TreeNode {
    /// Creates a new populated tree node.
    #[allow(clippy::too_many_arguments)]
    pub fn new_populated(
        index: NodeIndex,
        public_key: HybridKemPublicKey,
        predecessor_key: Option<HybridKemPublicKey>,
        parent_hash: ([u8; 32], [u8; 32]),
        last_updater_id: UserId,
        update_signature: HybridSignature,
        transcript_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        origin: UpdateOrigin,
    ) -> Self {
        Self {
            index,
            state: NodeState::Populated(Box::new(PopulatedNodeData {
                public_key,
                predecessor_key,
                parent_hash,
                last_updater_id,
                update_signature,
                transcript_hash,
                confirmation_tag,
                origin,
            })),
        }
    }

    /// Creates a new blank tree node.
    #[must_use]
    pub fn new_blank(index: NodeIndex) -> Self {
        Self {
            index,
            state: NodeState::blank(),
        }
    }

    /// Returns true if this is a leaf node at the given tree depth.
    #[must_use]
    pub fn is_leaf(&self, tree_depth: u32) -> bool {
        self.index.is_leaf(tree_depth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blank_node() {
        let state = NodeState::blank();
        assert!(state.is_blank());
        assert!(!state.is_populated());
        assert!(state.public_key().is_none());
    }

    #[test]
    fn test_unmerged_leaves() {
        let mut state = NodeState::blank();
        let leaf1 = 0u32;
        let leaf2 = 1u32;

        state.add_unmerged_leaf(leaf1);
        state.add_unmerged_leaf(leaf2);
        state.add_unmerged_leaf(leaf1); // Duplicate

        let leaves = state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&leaf1));
        assert!(leaves.contains(&leaf2));

        // Test removal
        state.remove_unmerged_leaf(leaf1);
        let leaves = state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 1);
        assert!(!leaves.contains(&leaf1));
        assert!(leaves.contains(&leaf2));
    }

    #[test]
    fn test_tree_node_blank() {
        let node = TreeNode::new_blank(NodeIndex::new(2, 3));
        assert_eq!(node.index.depth, 2);
        assert_eq!(node.index.position, 3);
        assert!(node.state.is_blank());
    }

    fn create_populated_node(index: NodeIndex) -> TreeNode {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let signature = identity.sign(b"test message").unwrap();
        let user_id = [0x42u8; 32];
        let parent_hash = ([0x11u8; 32], [0x22u8; 32]);
        let transcript_hash = [0x33u8; 32];
        let confirmation_tag = [0x44u8; 32];
        let origin = UpdateOrigin {
            epoch: 1,
            sequence: 0,
            timestamp: 1234567890,
        };

        TreeNode::new_populated(
            index,
            keypair.public_key().clone(),
            None,
            parent_hash,
            user_id,
            signature,
            transcript_hash,
            confirmation_tag,
            origin,
        )
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_populated_node_basic() {
        let node = create_populated_node(NodeIndex::new(1, 2));

        assert!(node.state.is_populated());
        assert!(!node.state.is_blank());
        assert!(node.state.public_key().is_some());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_populated_node_accessors() {
        let node = create_populated_node(NodeIndex::new(1, 2));

        // Test all accessors for populated nodes
        assert!(node.state.public_key().is_some());
        assert!(node.state.predecessor_key().is_none()); // We created without predecessor
        assert!(node.state.parent_hash().is_some());
        assert!(node.state.last_updater_id().is_some());
        assert!(node.state.unmerged_leaves().is_none()); // Only for blank nodes
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_populated_node_parent_hash() {
        let node = create_populated_node(NodeIndex::new(1, 2));

        let parent_hash = node.state.parent_hash().unwrap();
        assert_eq!(parent_hash.0, [0x11u8; 32]);
        assert_eq!(parent_hash.1, [0x22u8; 32]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_populated_node_last_updater_id() {
        let node = create_populated_node(NodeIndex::new(1, 2));

        let updater_id = node.state.last_updater_id().unwrap();
        assert_eq!(*updater_id, [0x42u8; 32]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_populated_node_with_predecessor() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let signature = identity.sign(b"test message").unwrap();
        let user_id = [0x42u8; 32];
        let parent_hash = ([0x11u8; 32], [0x22u8; 32]);
        let transcript_hash = [0x33u8; 32];
        let confirmation_tag = [0x44u8; 32];
        let origin = UpdateOrigin {
            epoch: 1,
            sequence: 0,
            timestamp: 1234567890,
        };

        let node = TreeNode::new_populated(
            NodeIndex::new(1, 2),
            keypair.public_key().clone(),
            Some(pred_keypair.public_key().clone()),
            parent_hash,
            user_id,
            signature,
            transcript_hash,
            confirmation_tag,
            origin,
        );

        assert!(node.state.predecessor_key().is_some());
    }

    #[test]
    fn test_blank_node_accessors() {
        let state = NodeState::blank();

        // All populated-specific accessors return None
        assert!(state.predecessor_key().is_none());
        assert!(state.parent_hash().is_none());
        assert!(state.last_updater_id().is_none());
    }

    #[test]
    fn test_tree_node_is_leaf() {
        // For a tree of depth 3, leaves are at depth 3
        let leaf_node = TreeNode::new_blank(NodeIndex::new(3, 5));
        assert!(leaf_node.is_leaf(3));

        // Internal node at depth 2 is not a leaf
        let internal_node = TreeNode::new_blank(NodeIndex::new(2, 2));
        assert!(!internal_node.is_leaf(3));

        // Root is not a leaf
        let root_node = TreeNode::new_blank(NodeIndex::new(0, 0));
        assert!(!root_node.is_leaf(3));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_add_unmerged_leaf_to_populated_node() {
        let mut node = create_populated_node(NodeIndex::new(1, 2));

        // Adding unmerged leaf to populated node should be a no-op
        let leaf_pos = 5u32;
        node.state.add_unmerged_leaf(leaf_pos);

        // Should still be populated, unmerged_leaves should be None
        assert!(node.state.is_populated());
        assert!(node.state.unmerged_leaves().is_none());
    }
}
