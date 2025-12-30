//! Path and co-path computation for binary ratchet tree.
//!
//! - Path: nodes from a leaf to the root
//! - Co-path: siblings of nodes in the path

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::NodeIndex;

/// Returns the path from a leaf to the root (inclusive of both).
///
/// The path is ordered from leaf to root.
#[cfg(feature = "alloc")]
#[must_use]
pub fn path_to_root(leaf: NodeIndex) -> Vec<NodeIndex> {
    let mut path = Vec::with_capacity((leaf.depth + 1) as usize);
    let mut current = leaf;

    path.push(current);
    while let Some(parent) = current.parent() {
        path.push(parent);
        current = parent;
    }

    path
}

/// Returns the co-path (siblings of path nodes, excluding root's sibling).
///
/// The co-path is ordered from leaf's sibling up.
#[cfg(feature = "alloc")]
#[must_use]
pub fn copath(leaf: NodeIndex) -> Vec<NodeIndex> {
    let mut copath = Vec::with_capacity(leaf.depth as usize);
    let mut current = leaf;

    // Collect siblings of each node in the path (except root)
    while let Some(sibling) = current.sibling() {
        copath.push(sibling);
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break;
        }
    }

    copath
}

/// Returns the direct path (path excluding the leaf itself).
#[cfg(feature = "alloc")]
#[must_use]
pub fn direct_path(leaf: NodeIndex) -> Vec<NodeIndex> {
    let full_path = path_to_root(leaf);
    if full_path.len() > 1 {
        full_path[1..].to_vec()
    } else {
        Vec::new()
    }
}

/// Returns nodes at a specific depth in a subtree rooted at `root`.
#[cfg(feature = "alloc")]
#[must_use]
pub fn nodes_at_depth(root: NodeIndex, target_depth: u32) -> Vec<NodeIndex> {
    if target_depth < root.depth {
        return Vec::new();
    }

    let depth_diff = target_depth - root.depth;
    let count = 1u32 << depth_diff;
    let start_pos = root.position << depth_diff;

    (0..count)
        .map(|i| NodeIndex::new(target_depth, start_pos + i))
        .collect()
}

/// Returns all leaf indices in the subtree rooted at `node`.
#[cfg(feature = "alloc")]
#[must_use]
pub fn leaves_in_subtree(node: NodeIndex, tree_depth: u32) -> Vec<NodeIndex> {
    nodes_at_depth(node, tree_depth)
}

/// Calculates the lowest common ancestor of two nodes.
#[must_use]
pub fn lowest_common_ancestor(a: NodeIndex, b: NodeIndex) -> NodeIndex {
    let mut node_a = a;
    let mut node_b = b;

    // Bring both to the same depth
    while node_a.depth > node_b.depth {
        node_a = node_a.parent().expect("not at root");
    }
    while node_b.depth > node_a.depth {
        node_b = node_b.parent().expect("not at root");
    }

    // Walk up together until they meet
    while node_a != node_b {
        node_a = node_a.parent().expect("not at root");
        node_b = node_b.parent().expect("not at root");
    }

    node_a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_to_root() {
        // Leaf at depth 3, position 5
        let leaf = NodeIndex::new(3, 5);
        let path = path_to_root(leaf);

        assert_eq!(path.len(), 4);
        assert_eq!(path[0], NodeIndex::new(3, 5)); // Leaf
        assert_eq!(path[1], NodeIndex::new(2, 2)); // Parent
        assert_eq!(path[2], NodeIndex::new(1, 1)); // Grandparent
        assert_eq!(path[3], NodeIndex::root()); // Root
    }

    #[test]
    fn test_copath() {
        let leaf = NodeIndex::new(3, 5);
        let cp = copath(leaf);

        assert_eq!(cp.len(), 3); // No sibling for root
        assert_eq!(cp[0], NodeIndex::new(3, 4)); // Sibling of leaf
        assert_eq!(cp[1], NodeIndex::new(2, 3)); // Sibling of parent
        assert_eq!(cp[2], NodeIndex::new(1, 0)); // Sibling of grandparent
    }

    #[test]
    fn test_direct_path() {
        let leaf = NodeIndex::new(2, 3);
        let dp = direct_path(leaf);

        assert_eq!(dp.len(), 2);
        assert_eq!(dp[0], NodeIndex::new(1, 1));
        assert_eq!(dp[1], NodeIndex::root());
    }

    #[test]
    fn test_nodes_at_depth() {
        let root = NodeIndex::root();
        let nodes = nodes_at_depth(root, 2);

        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[0], NodeIndex::new(2, 0));
        assert_eq!(nodes[1], NodeIndex::new(2, 1));
        assert_eq!(nodes[2], NodeIndex::new(2, 2));
        assert_eq!(nodes[3], NodeIndex::new(2, 3));
    }

    #[test]
    fn test_nodes_at_depth_subtree() {
        let subtree = NodeIndex::new(1, 1);
        let nodes = nodes_at_depth(subtree, 3);

        assert_eq!(nodes.len(), 4);
        // Subtree at (1,1) covers positions 4-7 at depth 3
        assert_eq!(nodes[0], NodeIndex::new(3, 4));
        assert_eq!(nodes[1], NodeIndex::new(3, 5));
        assert_eq!(nodes[2], NodeIndex::new(3, 6));
        assert_eq!(nodes[3], NodeIndex::new(3, 7));
    }

    #[test]
    fn test_leaves_in_subtree() {
        let node = NodeIndex::new(1, 0);
        let leaves = leaves_in_subtree(node, 3);

        assert_eq!(leaves.len(), 4);
        assert!(leaves.iter().all(|l| l.is_leaf(3)));
        assert!(leaves.iter().all(|l| l.position < 4)); // Left half
    }

    #[test]
    fn test_lowest_common_ancestor() {
        // Same node
        let a = NodeIndex::new(3, 2);
        assert_eq!(lowest_common_ancestor(a, a), a);

        // Siblings
        let b = NodeIndex::new(3, 3);
        assert_eq!(lowest_common_ancestor(a, b), NodeIndex::new(2, 1));

        // Distant cousins
        let c = NodeIndex::new(3, 0);
        let d = NodeIndex::new(3, 7);
        assert_eq!(lowest_common_ancestor(c, d), NodeIndex::root());

        // Different depths
        // e=(2,1) path: (2,1) → (1,0) → (0,0)
        // f=(3,5) path: (3,5) → (2,2) → (1,1) → (0,0)
        // LCA is (0,0) - the root
        let e = NodeIndex::new(2, 1);
        let f = NodeIndex::new(3, 5);
        assert_eq!(lowest_common_ancestor(e, f), NodeIndex::root());
    }

    #[test]
    fn test_root_path() {
        let root = NodeIndex::root();
        let path = path_to_root(root);

        assert_eq!(path.len(), 1);
        assert_eq!(path[0], root);
    }

    #[test]
    fn test_root_copath() {
        let root = NodeIndex::root();
        let cp = copath(root);

        assert!(cp.is_empty());
    }
}
