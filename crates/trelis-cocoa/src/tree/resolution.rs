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
/// * `unmerged_fn` - Function to compute unmerged leaves for a node.
///   Takes a node index and returns a list of leaf indices that have joined
///   but haven't yet processed an update covering that node. These members
///   need to receive the encrypted seed directly at their leaf position.
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
/// Unmerged members (those who joined but haven't processed an update yet)
/// need to be included so they can also receive the encrypted secrets.
#[cfg(feature = "alloc")]
pub fn compute_lj<T: NodeLookup, F>(lookup: &T, path_node: NodeIndex, unmerged_fn: F) -> Resolution
where
    F: Fn(&NodeIndex) -> Vec<NodeIndex>,
{
    // Get the sibling (co-parent)
    let sibling = match path_node.sibling() {
        Some(s) => s,
        None => return Resolution::empty(), // Root has no sibling
    };

    // Compute resolution of sibling subtree
    let resolution = resolve(lookup, sibling);

    // Collect unmerged leaves for each node in the resolution
    // Per spec: Lj = Res(wj) ∪ Unmerged(Res(wj))
    let mut unmerged = Resolution::empty();
    for node_idx in resolution.iter() {
        let unmerged_leaves = unmerged_fn(node_idx);
        for leaf_idx in unmerged_leaves {
            unmerged = unmerged.union(Resolution::singleton(leaf_idx));
        }
    }

    // Return the union of resolution and unmerged leaves
    resolution.union(unmerged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    use crate::tree::node::UpdateOrigin;

    /// A test lookup that stores actual TreeNode objects.
    struct RealNodeLookup {
        depth: u32,
        nodes: BTreeMap<NodeIndex, TreeNode>,
    }

    impl RealNodeLookup {
        fn new(depth: u32) -> Self {
            Self {
                depth,
                nodes: BTreeMap::new(),
            }
        }

        fn add_populated(&mut self, index: NodeIndex) {
            let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
            let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
            let signature = identity.sign(b"test").unwrap();

            let node = TreeNode::new_populated(
                index,
                keypair.public_key().clone(),
                None,
                ([0u8; 32], [0u8; 32]),
                [0u8; 32],
                signature,
                [0u8; 32],
                [0u8; 32],
                UpdateOrigin {
                    epoch: 0,
                    sequence: 0,
                    timestamp: 0,
                },
            );
            self.nodes.insert(index, node);
        }

        fn add_blank(&mut self, index: NodeIndex) {
            let node = TreeNode::new_blank(index);
            self.nodes.insert(index, node);
        }
    }

    impl NodeLookup for RealNodeLookup {
        fn get_node(&self, index: &NodeIndex) -> Option<&TreeNode> {
            self.nodes.get(index)
        }

        fn tree_depth(&self) -> u32 {
            self.depth
        }
    }

    // Simple test lookup that always returns None
    struct EmptyLookup {
        depth: u32,
    }

    impl EmptyLookup {
        fn new(depth: u32) -> Self {
            Self { depth }
        }
    }

    impl NodeLookup for EmptyLookup {
        fn get_node(&self, _index: &NodeIndex) -> Option<&TreeNode> {
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
    fn test_resolution_union_empty_first() {
        let empty = Resolution::empty();
        let singleton = Resolution::singleton(NodeIndex::new(2, 0));

        // When first is empty, should return other
        let combined = empty.union(singleton);
        assert_eq!(combined.len(), 1);
    }

    #[test]
    fn test_resolution_union_empty_second() {
        let singleton = Resolution::singleton(NodeIndex::new(2, 0));
        let empty = Resolution::empty();

        // When second is empty, should return self
        let combined = singleton.union(empty);
        assert_eq!(combined.len(), 1);
    }

    #[test]
    fn test_resolution_union_multiple_nodes() {
        let mut res1 = Resolution::singleton(NodeIndex::new(2, 0));
        res1.nodes.push(NodeIndex::new(2, 1));

        let mut res2 = Resolution::singleton(NodeIndex::new(2, 1)); // Duplicate
        res2.nodes.push(NodeIndex::new(2, 2));

        let combined = res1.union(res2);
        assert_eq!(combined.len(), 3); // 0, 1, 2 (1 deduplicated)
    }

    #[test]
    fn test_resolution_iter() {
        let res = Resolution::singleton(NodeIndex::new(2, 0));
        let indices: Vec<_> = res.iter().collect();
        assert_eq!(indices.len(), 1);
        assert_eq!(*indices[0], NodeIndex::new(2, 0));
    }

    #[test]
    fn test_resolve_missing_node() {
        let lookup = EmptyLookup::new(3);
        let res = resolve(&lookup, NodeIndex::new(2, 0));

        // Missing nodes are treated as blank leaves
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_populated_node() {
        let mut lookup = RealNodeLookup::new(3);
        let index = NodeIndex::new(2, 0);
        lookup.add_populated(index);

        let res = resolve(&lookup, index);

        // Populated node resolves to itself
        assert_eq!(res.len(), 1);
        assert_eq!(res.nodes[0], index);
    }

    #[test]
    fn test_resolve_blank_leaf() {
        let mut lookup = RealNodeLookup::new(3);
        let index = NodeIndex::new(3, 0); // Leaf at max depth
        lookup.add_blank(index);

        let res = resolve(&lookup, index);

        // Blank leaf resolves to empty
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_blank_internal_with_populated_children() {
        // Tree depth 2 means leaves at depth 2
        let mut lookup = RealNodeLookup::new(2);

        // Root (0,0) is blank internal
        let root = NodeIndex::new(0, 0);
        lookup.add_blank(root);

        // Left child (1,0) is populated
        let left = NodeIndex::new(1, 0);
        lookup.add_populated(left);

        // Right child (1,1) is populated
        let right = NodeIndex::new(1, 1);
        lookup.add_populated(right);

        let res = resolve(&lookup, root);

        // Blank internal resolves to union of children's resolutions
        assert_eq!(res.len(), 2);
        assert!(res.nodes.contains(&left));
        assert!(res.nodes.contains(&right));
    }

    #[test]
    fn test_resolve_blank_internal_with_mixed_children() {
        let mut lookup = RealNodeLookup::new(2);

        let root = NodeIndex::new(0, 0);
        lookup.add_blank(root);

        // Left is populated
        let left = NodeIndex::new(1, 0);
        lookup.add_populated(left);

        // Right is blank (and it's also a leaf in this tree)
        let right = NodeIndex::new(1, 1);
        lookup.add_blank(right);

        let res = resolve(&lookup, root);

        // Resolution should only contain the populated left child
        // (blank leaf right child contributes empty)
        assert_eq!(res.len(), 1);
        assert!(res.nodes.contains(&left));
    }

    #[test]
    fn test_resolve_set_empty() {
        let lookup = EmptyLookup::new(3);
        let res = resolve_set(&lookup, &[]);
        assert!(res.is_empty());
    }

    #[test]
    fn test_resolve_set_single() {
        let mut lookup = RealNodeLookup::new(3);
        let index = NodeIndex::new(2, 0);
        lookup.add_populated(index);

        let res = resolve_set(&lookup, &[index]);
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn test_resolve_set_multiple() {
        let mut lookup = RealNodeLookup::new(3);

        let idx1 = NodeIndex::new(2, 0);
        let idx2 = NodeIndex::new(2, 1);
        lookup.add_populated(idx1);
        lookup.add_populated(idx2);

        let res = resolve_set(&lookup, &[idx1, idx2]);
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_compute_lj_root_no_sibling() {
        let mut lookup = RealNodeLookup::new(3);
        let root = NodeIndex::new(0, 0);
        lookup.add_populated(root);

        let res = compute_lj(&lookup, root, |_| Vec::new());

        // Root has no sibling, so resolution is empty
        assert!(res.is_empty());
    }

    #[test]
    fn test_compute_lj_with_sibling() {
        let mut lookup = RealNodeLookup::new(2);

        // Path node at (1, 0), sibling at (1, 1)
        let path_node = NodeIndex::new(1, 0);
        let sibling = NodeIndex::new(1, 1);

        lookup.add_populated(path_node);
        lookup.add_populated(sibling);

        let res = compute_lj(&lookup, path_node, |_| Vec::new());

        // Should return resolution of sibling
        assert_eq!(res.len(), 1);
        assert!(res.nodes.contains(&sibling));
    }

    #[test]
    fn test_compute_lj_sibling_blank_internal() {
        let mut lookup = RealNodeLookup::new(3);

        // Path node at depth 1, sibling is blank internal
        let path_node = NodeIndex::new(1, 0);
        let sibling = NodeIndex::new(1, 1);

        lookup.add_populated(path_node);
        lookup.add_blank(sibling);

        // Sibling's children are populated
        let sibling_left = NodeIndex::new(2, 2);
        let sibling_right = NodeIndex::new(2, 3);
        lookup.add_populated(sibling_left);
        lookup.add_populated(sibling_right);

        let res = compute_lj(&lookup, path_node, |_| Vec::new());

        // Should return resolution of sibling (its populated children)
        assert_eq!(res.len(), 2);
        assert!(res.nodes.contains(&sibling_left));
        assert!(res.nodes.contains(&sibling_right));
    }

    #[test]
    fn test_compute_lj_with_unmerged_leaves() {
        let mut lookup = RealNodeLookup::new(2);

        // Path node at (1, 0), sibling at (1, 1)
        let path_node = NodeIndex::new(1, 0);
        let sibling = NodeIndex::new(1, 1);

        lookup.add_populated(path_node);
        lookup.add_populated(sibling);

        // Define unmerged leaves for the sibling
        let unmerged_leaf1 = NodeIndex::new(2, 2);
        let unmerged_leaf2 = NodeIndex::new(2, 3);

        let res = compute_lj(&lookup, path_node, |node_idx| {
            if *node_idx == sibling {
                // Sibling has unmerged leaves
                vec![unmerged_leaf1, unmerged_leaf2]
            } else {
                Vec::new()
            }
        });

        // Should return resolution of sibling (1) + unmerged leaves (2) = 3 total
        assert_eq!(res.len(), 3);
        assert!(res.nodes.contains(&sibling));
        assert!(res.nodes.contains(&unmerged_leaf1));
        assert!(res.nodes.contains(&unmerged_leaf2));
    }

    #[test]
    fn test_compute_lj_unmerged_dedup() {
        let mut lookup = RealNodeLookup::new(2);

        let path_node = NodeIndex::new(1, 0);
        let sibling = NodeIndex::new(1, 1);

        lookup.add_populated(path_node);
        lookup.add_populated(sibling);

        // Same unmerged leaf returned for multiple resolution nodes
        let unmerged_leaf = NodeIndex::new(2, 2);

        let res = compute_lj(&lookup, path_node, |_| {
            vec![unmerged_leaf]
        });

        // Should deduplicate: sibling (1) + unmerged (1) = 2 total
        assert_eq!(res.len(), 2);
        assert!(res.nodes.contains(&sibling));
        assert!(res.nodes.contains(&unmerged_leaf));
    }
}
