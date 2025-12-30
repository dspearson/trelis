//! Tree node state and structure.
//!
//! Each node in the ratchet tree can be either populated (with key material)
//! or blank (after member removal).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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

/// State of a node in the ratchet tree.
#[derive(Debug, Clone)]
pub enum NodeState {
    /// Active node with key material.
    Populated {
        /// Hybrid public key at this node (PK_v).
        public_key: HybridKemPublicKey,
        /// Predecessor public key - key before last update (PK_pr).
        /// Used for verifying updates from users who haven't yet
        /// processed the most recent commit at this node.
        predecessor_key: Option<HybridKemPublicKey>,
        /// Parent hash for tree integrity (h_v = (h_1, h_2)).
        /// Two-component structure per CoCoA paper Section 3.4:
        /// - h_1: sibling subtree commitment
        /// - h_2: predecessor/children commitment
        parent_hash: ([u8; 32], [u8; 32]),
        /// Identity of the user who last updated this node (ID_v).
        last_updater_id: UserId,
        /// Signature over update message (sigma_v).
        update_signature: HybridSignature,
        /// Transcript hash at time of last update (H_trans,v).
        transcript_hash: [u8; 32],
        /// Confirmation tag for this node's update (confTag_v).
        confirmation_tag: [u8; 32],
        /// Origin information - metadata about update source.
        origin: UpdateOrigin,
    },

    /// Blank node (member removed or position never filled).
    Blank {
        /// Unmerged leaves - leaves that haven't processed through this node.
        /// Critical for correct resolution computation.
        #[cfg(feature = "alloc")]
        unmerged_leaves: Vec<UserId>,
    },
}

impl NodeState {
    /// Creates a new blank node state.
    #[cfg(feature = "alloc")]
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
        matches!(self, Self::Populated { .. })
    }

    /// Returns the public key if populated.
    #[must_use]
    pub fn public_key(&self) -> Option<&HybridKemPublicKey> {
        match self {
            Self::Populated { public_key, .. } => Some(public_key),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the predecessor key if populated.
    #[must_use]
    pub fn predecessor_key(&self) -> Option<&HybridKemPublicKey> {
        match self {
            Self::Populated {
                predecessor_key, ..
            } => predecessor_key.as_ref(),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the parent hash if populated.
    #[must_use]
    pub fn parent_hash(&self) -> Option<&([u8; 32], [u8; 32])> {
        match self {
            Self::Populated { parent_hash, .. } => Some(parent_hash),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the last updater ID if populated.
    #[must_use]
    pub fn last_updater_id(&self) -> Option<&UserId> {
        match self {
            Self::Populated {
                last_updater_id, ..
            } => Some(last_updater_id),
            Self::Blank { .. } => None,
        }
    }

    /// Returns the unmerged leaves for blank nodes.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn unmerged_leaves(&self) -> Option<&[UserId]> {
        match self {
            Self::Blank { unmerged_leaves } => Some(unmerged_leaves),
            Self::Populated { .. } => None,
        }
    }

    /// Adds an unmerged leaf to a blank node.
    #[cfg(feature = "alloc")]
    pub fn add_unmerged_leaf(&mut self, user_id: UserId) {
        if let Self::Blank { unmerged_leaves } = self {
            if !unmerged_leaves.contains(&user_id) {
                unmerged_leaves.push(user_id);
            }
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
            state: NodeState::Populated {
                public_key,
                predecessor_key,
                parent_hash,
                last_updater_id,
                update_signature,
                transcript_hash,
                confirmation_tag,
                origin,
            },
        }
    }

    /// Creates a new blank tree node.
    #[cfg(feature = "alloc")]
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
        let user1 = [1u8; 32];
        let user2 = [2u8; 32];

        state.add_unmerged_leaf(user1);
        state.add_unmerged_leaf(user2);
        state.add_unmerged_leaf(user1); // Duplicate

        let leaves = state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&user1));
        assert!(leaves.contains(&user2));
    }

    #[test]
    fn test_tree_node_blank() {
        let node = TreeNode::new_blank(NodeIndex::new(2, 3));
        assert_eq!(node.index.depth, 2);
        assert_eq!(node.index.position, 3);
        assert!(node.state.is_blank());
    }
}
