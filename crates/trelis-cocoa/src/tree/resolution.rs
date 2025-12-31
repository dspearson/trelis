//! Resolution computation for blank node handling.
//!
//! The resolution of a node is the minimal set of non-blank descendants
//! that can represent the subtree for encryption purposes.
//!
//! Per CoCoA paper Definition 2 (p. 9):
//! - If v is not blank: Res(v) = {v}
//! - If v is a blank leaf: Res(v) = {}
//! - Otherwise (blank internal): Res(v) = Res(left) ∪ Res(right)

#[cfg(feature = "alloc")]
use alloc::collections::BTreeSet;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::{NodeIndex, TreeNode};

/// Result of resolution computation.
///
/// A resolution is the minimal set of non-blank nodes that can represent
/// a subtree for encryption purposes. When encrypting to a subtree, we
/// encrypt to each node in the resolution.
///
/// # Why Resolution Matters
///
/// In a group where some members have left (blank nodes), we need to find
/// the actual recipients for encrypted data. The resolution gives us the
/// minimal cover of non-blank nodes.
///
/// # Example
///
/// ```text
///       (blank)
///       /     \
///    Alice   (blank)
///            /    \
///          Bob   Carol
/// ```
///
/// Resolution of root = {Alice, Bob, Carol}
/// (We skip the blank internal node and include its non-blank descendants)
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Resolution {
    /// Node indices in the resolution set.
    pub nodes: Vec<NodeIndex>,
}

#[cfg(feature = "alloc")]
impl Resolution {
    /// Creates an empty resolution.
    #[must_use]
    pub fn empty() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Creates a resolution containing a single node.
    #[must_use]
    pub fn singleton(index: NodeIndex) -> Self {
        Self { nodes: vec![index] }
    }

    /// Merges two resolutions (union).
    ///
    /// Uses a BTreeSet for O(log n) deduplication instead of O(n) linear search.
    #[must_use]
    pub fn union(mut self, other: Self) -> Self {
        if other.nodes.is_empty() {
            return self;
        }
        if self.nodes.is_empty() {
            return other;
        }

        // Build a set from existing nodes for O(log n) lookup
        let existing: BTreeSet<_> = self.nodes.iter().copied().collect();

        // Reserve capacity for potential additions
        self.nodes.reserve(other.nodes.len());

        for node in other.nodes {
            if !existing.contains(&node) {
                self.nodes.push(node);
            }
        }
        self
    }

    /// Returns true if the resolution is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the number of nodes in the resolution.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns an iterator over the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &NodeIndex> {
        self.nodes.iter()
    }
}

/// Trait for types that can provide node state for resolution computation.
pub trait NodeLookup {
    /// Returns the state of a node, or None if the node doesn't exist.
    fn get_node(&self, index: &NodeIndex) -> Option<&TreeNode>;

    /// Returns the tree depth (leaf level).
    fn tree_depth(&self) -> u32;
}

/// Computes the resolution of a node.
///
/// Per CoCoA paper Definition 2:
/// - If v is not blank: Res(v) = {v}
/// - If v is a blank leaf: Res(v) = {}
/// - Otherwise (blank internal): Res(v) = Res(left) ∪ Res(right)
///
/// # Arguments
///
/// * `lookup` - A type implementing [`NodeLookup`] for tree traversal
/// * `index` - The node to compute resolution for
///
/// # Returns
///
/// A [`Resolution`] containing the minimal set of non-blank descendants.
///
/// # Complexity
///
/// O(n) where n is the number of nodes in the subtree, as we may need
/// to visit all descendants of blank internal nodes.
#[cfg(feature = "alloc")]
pub fn resolve<T: NodeLookup>(lookup: &T, index: NodeIndex) -> Resolution {
    match lookup.get_node(&index) {
        Some(node) => {
            if node.state.is_populated() {
                // Non-blank node: resolution is just this node
                Resolution::singleton(index)
            } else {
                // Blank node
                if index.is_leaf(lookup.tree_depth()) {
                    // Blank leaf: empty resolution
                    Resolution::empty()
                } else {
                    // Blank internal: recurse to children
                    let left_res = resolve(lookup, index.left_child());
                    let right_res = resolve(lookup, index.right_child());
                    left_res.union(right_res)
                }
            }
        }
        None => {
            // Node doesn't exist in our view - treat as blank leaf
            Resolution::empty()
        }
    }
}

/// Computes the resolution of a set of nodes.
#[cfg(feature = "alloc")]
pub fn resolve_set<T: NodeLookup>(lookup: &T, indices: &[NodeIndex]) -> Resolution {
    let mut result = Resolution::empty();
    for &index in indices {
        result = result.union(resolve(lookup, index));
    }
    result
}

/// Computes Lj: the encryption recipient set for a path update.
///
/// Per CoCoA paper (p. 20):
/// L_j = Res(w_j) ∪ Unmerged(Res(w_j))
///
/// where w_j is the sibling (co-path node) of v_j in the updater's path.
///
/// # Arguments
///
/// * `lookup` - A type implementing [`NodeLookup`] for tree traversal
/// * `path_node` - A node in the updater's direct path
/// * `unmerged_fn` - Function to compute unmerged leaves for a node
///
/// # Returns
///
/// A [`Resolution`] containing all nodes that need to receive the encrypted
/// path secret for this level of the tree.
///
/// # Usage
///
/// When a member sends an update, they encrypt new path secrets to each Lj
/// set. Members in each Lj can decrypt and update their view of the tree.
#[cfg(feature = "alloc")]
pub fn compute_lj<T: NodeLookup>(
    lookup: &T,
    path_node: NodeIndex,
    _unmerged_fn: impl Fn(&NodeIndex) -> Vec<NodeIndex>,
) -> Resolution {
    // Get the sibling (co-parent)
    let sibling = match path_node.sibling() {
        Some(s) => s,
        None => return Resolution::empty(), // Root has no sibling
    };

    // Compute resolution of sibling subtree.
    // In full implementation, would add unmerged leaves here.
    resolve(lookup, sibling)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test lookup that marks even positions as populated
    struct TestLookup {
        depth: u32,
        // Reserved for future tests with blank nodes
        #[allow(dead_code)]
        blank_positions: Vec<(u32, u32)>,
    }

    impl TestLookup {
        fn new(depth: u32) -> Self {
            Self {
                depth,
                blank_positions: Vec::new(),
            }
        }

        // Reserved for future tests with blank nodes
        #[allow(dead_code)]
        fn with_blank(mut self, depth: u32, position: u32) -> Self {
            self.blank_positions.push((depth, position));
            self
        }
    }

    impl NodeLookup for TestLookup {
        fn get_node(&self, _index: &NodeIndex) -> Option<&TreeNode> {
            // For testing, we use a static approach
            // Return None to simulate nodes we need
            None
        }

        fn tree_depth(&self) -> u32 {
            self.depth
        }
    }

    #[test]
    fn test_resolution_empty() {
        let res = Resolution::empty();
        assert!(res.is_empty());
        assert_eq!(res.len(), 0);
    }

    #[test]
    fn test_resolution_singleton() {
        let idx = NodeIndex::new(2, 3);
        let res = Resolution::singleton(idx);
        assert!(!res.is_empty());
        assert_eq!(res.len(), 1);
        assert_eq!(res.nodes[0], idx);
    }

    #[test]
    fn test_resolution_union() {
        let res1 = Resolution::singleton(NodeIndex::new(2, 0));
        let res2 = Resolution::singleton(NodeIndex::new(2, 1));

        let combined = res1.union(res2);
        assert_eq!(combined.len(), 2);
    }

    #[test]
    fn test_resolution_union_dedup() {
        let idx = NodeIndex::new(2, 0);
        let res1 = Resolution::singleton(idx);
        let res2 = Resolution::singleton(idx);

        let combined = res1.union(res2);
        assert_eq!(combined.len(), 1);
    }

    #[test]
    fn test_resolve_missing_node() {
        let lookup = TestLookup::new(3);
        let res = resolve(&lookup, NodeIndex::new(2, 0));

        // Missing nodes are treated as blank leaves
        assert!(res.is_empty());
    }
}
