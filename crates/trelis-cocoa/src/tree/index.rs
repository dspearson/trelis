//! Tree node indexing for binary ratchet tree.
//!
//! Nodes are indexed by (depth, position) where:
//! - depth 0 = root
//! - depth d has 2^d nodes at positions 0..2^d-1
//! - leaves are at depth = ceil(log2(n)) for n users

use core::cmp::Ordering;

/// Index identifying a node in the binary tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeIndex {
    /// Depth in tree (0 = root).
    pub depth: u32,
    /// Position at this depth (0..2^depth - 1).
    pub position: u32,
}

impl NodeIndex {
    /// Creates a new node index.
    #[must_use]
    pub const fn new(depth: u32, position: u32) -> Self {
        Self { depth, position }
    }

    /// Returns the root node index.
    #[must_use]
    pub const fn root() -> Self {
        Self::new(0, 0)
    }

    /// Creates a leaf node index for a given leaf position.
    ///
    /// The leaf depth depends on the total tree depth.
    #[must_use]
    pub const fn leaf(tree_depth: u32, leaf_position: u32) -> Self {
        Self::new(tree_depth, leaf_position)
    }

    /// Returns true if this is the root node.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// Returns true if this is a leaf node at the given tree depth.
    #[must_use]
    pub const fn is_leaf(&self, tree_depth: u32) -> bool {
        self.depth == tree_depth
    }

    /// Returns the parent node index, or None if this is the root.
    #[must_use]
    pub const fn parent(&self) -> Option<Self> {
        if self.depth == 0 {
            None
        } else {
            Some(Self::new(self.depth - 1, self.position / 2))
        }
    }

    /// Returns the left child node index.
    #[must_use]
    pub const fn left_child(&self) -> Self {
        Self::new(self.depth + 1, self.position * 2)
    }

    /// Returns the right child node index.
    #[must_use]
    pub const fn right_child(&self) -> Self {
        Self::new(self.depth + 1, self.position * 2 + 1)
    }

    /// Returns the sibling node index, or None if this is the root.
    #[must_use]
    pub const fn sibling(&self) -> Option<Self> {
        if self.depth == 0 {
            None
        } else {
            // XOR with 1 to flip between even/odd positions
            Some(Self::new(self.depth, self.position ^ 1))
        }
    }

    /// Returns true if this node is a left child.
    #[must_use]
    pub const fn is_left_child(&self) -> bool {
        self.position % 2 == 0
    }

    /// Returns true if this node is a right child.
    #[must_use]
    pub const fn is_right_child(&self) -> bool {
        self.position % 2 == 1
    }

    /// Returns true if `other` is an ancestor of this node.
    #[must_use]
    pub fn is_descendant_of(&self, other: &Self) -> bool {
        if other.depth >= self.depth {
            return false;
        }

        // Calculate expected position at other's depth
        let depth_diff = self.depth - other.depth;
        let ancestor_pos = self.position >> depth_diff;

        ancestor_pos == other.position
    }

    /// Returns true if `other` is a descendant of this node.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        other.is_descendant_of(self)
    }

    /// Returns the linear index for array storage.
    ///
    /// Uses level-order numbering: root = 0, then level 1, etc.
    #[must_use]
    pub const fn to_linear(&self) -> u64 {
        // Number of nodes before this level
        let nodes_before = (1u64 << self.depth) - 1;
        nodes_before + self.position as u64
    }

    /// Creates a node index from linear index.
    #[must_use]
    pub fn from_linear(linear: u64) -> Self {
        if linear == 0 {
            return Self::root();
        }

        // Find depth: depth d starts at index 2^d - 1
        let depth = (64 - (linear + 1).leading_zeros() - 1) as u32;
        let nodes_before = (1u64 << depth) - 1;
        let position = (linear - nodes_before) as u32;

        Self::new(depth, position)
    }

    /// Serialises the index to 8 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&self.depth.to_le_bytes());
        bytes[4..].copy_from_slice(&self.position.to_le_bytes());
        bytes
    }

    /// Deserialises an index from 8 bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let depth = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let position = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self::new(depth, position)
    }
}

impl Ord for NodeIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order by linear index (level-order)
        self.to_linear().cmp(&other.to_linear())
    }
}

impl PartialOrd for NodeIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root() {
        let root = NodeIndex::root();
        assert!(root.is_root());
        assert_eq!(root.depth, 0);
        assert_eq!(root.position, 0);
        assert!(root.parent().is_none());
        assert!(root.sibling().is_none());
    }

    #[test]
    fn test_children() {
        let root = NodeIndex::root();
        let left = root.left_child();
        let right = root.right_child();

        assert_eq!(left.depth, 1);
        assert_eq!(left.position, 0);
        assert!(left.is_left_child());

        assert_eq!(right.depth, 1);
        assert_eq!(right.position, 1);
        assert!(right.is_right_child());
    }

    #[test]
    fn test_parent() {
        let node = NodeIndex::new(2, 3);
        let parent = node.parent().unwrap();

        assert_eq!(parent.depth, 1);
        assert_eq!(parent.position, 1);
    }

    #[test]
    fn test_sibling() {
        let left = NodeIndex::new(2, 2);
        let right = left.sibling().unwrap();

        assert_eq!(right.depth, 2);
        assert_eq!(right.position, 3);

        // Sibling of sibling is self
        assert_eq!(right.sibling().unwrap(), left);
    }

    #[test]
    fn test_ancestry() {
        let root = NodeIndex::root();
        let child = NodeIndex::new(1, 0);
        let grandchild = NodeIndex::new(2, 1);

        assert!(grandchild.is_descendant_of(&root));
        assert!(grandchild.is_descendant_of(&child));
        assert!(child.is_descendant_of(&root));

        assert!(root.is_ancestor_of(&grandchild));
        assert!(child.is_ancestor_of(&grandchild));

        // Not descendants of each other
        let other_child = NodeIndex::new(1, 1);
        assert!(!grandchild.is_descendant_of(&other_child));
    }

    #[test]
    fn test_linear_index() {
        // Root
        assert_eq!(NodeIndex::root().to_linear(), 0);

        // Level 1
        assert_eq!(NodeIndex::new(1, 0).to_linear(), 1);
        assert_eq!(NodeIndex::new(1, 1).to_linear(), 2);

        // Level 2
        assert_eq!(NodeIndex::new(2, 0).to_linear(), 3);
        assert_eq!(NodeIndex::new(2, 1).to_linear(), 4);
        assert_eq!(NodeIndex::new(2, 2).to_linear(), 5);
        assert_eq!(NodeIndex::new(2, 3).to_linear(), 6);
    }

    #[test]
    fn test_from_linear() {
        for i in 0..100 {
            let idx = NodeIndex::from_linear(i);
            assert_eq!(idx.to_linear(), i);
        }
    }

    #[test]
    fn test_serialisation() {
        let idx = NodeIndex::new(5, 17);
        let bytes = idx.to_bytes();
        let recovered = NodeIndex::from_bytes(&bytes);
        assert_eq!(idx, recovered);
    }

    #[test]
    fn test_leaf_index() {
        let leaf = NodeIndex::leaf(4, 7);
        assert!(leaf.is_leaf(4));
        assert!(!leaf.is_leaf(5));
        assert_eq!(leaf.depth, 4);
        assert_eq!(leaf.position, 7);
    }

    #[test]
    fn test_ordering() {
        let nodes: Vec<NodeIndex> = vec![
            NodeIndex::new(2, 1),
            NodeIndex::root(),
            NodeIndex::new(1, 1),
            NodeIndex::new(2, 0),
        ];

        let mut sorted = nodes.clone();
        sorted.sort();

        assert_eq!(sorted[0], NodeIndex::root());
        assert_eq!(sorted[1], NodeIndex::new(1, 1));
        assert_eq!(sorted[2], NodeIndex::new(2, 0));
        assert_eq!(sorted[3], NodeIndex::new(2, 1));
    }
}
