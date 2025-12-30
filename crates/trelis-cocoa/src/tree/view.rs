//! Partial tree view for efficient storage.
//!
//! Each user stores only the nodes relevant to them:
//! P(ID) = path(ID) ∪ Res(co-path(ID))
//!
//! This is O(log n) nodes for a group of size n.

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::path::{copath, path_to_root};
use super::resolution::NodeLookup;
use super::{NodeIndex, NodeState, TreeNode};
use crate::UserId;

/// A partial view of the ratchet tree.
///
/// Contains only the nodes needed by a specific user:
/// - Their path from leaf to root
/// - The resolution of their co-path
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct PartialTreeView {
    /// Nodes in this view, keyed by linear index for efficient lookup.
    nodes: BTreeMap<u64, TreeNode>,
    /// Our leaf position.
    our_leaf: NodeIndex,
    /// Tree depth (leaf level).
    tree_depth: u32,
    /// Number of active members (non-blank leaves).
    member_count: u32,
}

#[cfg(feature = "alloc")]
impl PartialTreeView {
    /// Creates a new empty partial tree view.
    #[must_use]
    pub fn new(our_leaf_position: u32, tree_depth: u32) -> Self {
        Self {
            nodes: BTreeMap::new(),
            our_leaf: NodeIndex::leaf(tree_depth, our_leaf_position),
            tree_depth,
            member_count: 0,
        }
    }

    /// Returns our leaf index.
    #[must_use]
    pub fn our_leaf(&self) -> NodeIndex {
        self.our_leaf
    }

    /// Returns the tree depth.
    #[must_use]
    pub fn tree_depth(&self) -> u32 {
        self.tree_depth
    }

    /// Returns the number of active members.
    #[must_use]
    pub fn member_count(&self) -> u32 {
        self.member_count
    }

    /// Sets the member count.
    pub fn set_member_count(&mut self, count: u32) {
        self.member_count = count;
    }

    /// Returns our path from leaf to root.
    #[must_use]
    pub fn our_path(&self) -> Vec<NodeIndex> {
        path_to_root(self.our_leaf)
    }

    /// Returns our co-path (siblings of path nodes).
    #[must_use]
    pub fn our_copath(&self) -> Vec<NodeIndex> {
        copath(self.our_leaf)
    }

    /// Gets a node from the view.
    #[must_use]
    pub fn get(&self, index: &NodeIndex) -> Option<&TreeNode> {
        self.nodes.get(&index.to_linear())
    }

    /// Gets a mutable reference to a node.
    #[must_use]
    pub fn get_mut(&mut self, index: &NodeIndex) -> Option<&mut TreeNode> {
        self.nodes.get_mut(&index.to_linear())
    }

    /// Inserts or updates a node in the view.
    pub fn insert(&mut self, node: TreeNode) {
        self.nodes.insert(node.index.to_linear(), node);
    }

    /// Removes a node from the view.
    pub fn remove(&mut self, index: &NodeIndex) -> Option<TreeNode> {
        self.nodes.remove(&index.to_linear())
    }

    /// Returns true if the view contains a node at the given index.
    #[must_use]
    pub fn contains(&self, index: &NodeIndex) -> bool {
        self.nodes.contains_key(&index.to_linear())
    }

    /// Returns the number of nodes in the view.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the view is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns an iterator over all nodes in the view.
    pub fn iter(&self) -> impl Iterator<Item = &TreeNode> {
        self.nodes.values()
    }

    /// Returns an iterator over nodes in our path.
    pub fn path_nodes(&self) -> impl Iterator<Item = Option<&TreeNode>> + '_ {
        self.our_path().into_iter().map(|idx| self.get(&idx))
    }

    /// Makes a node blank (for member removal).
    pub fn blank_node(&mut self, index: &NodeIndex) {
        if let Some(node) = self.get_mut(index) {
            node.state = NodeState::blank();
        }
    }

    /// Adds an unmerged leaf to a node.
    pub fn add_unmerged_leaf(&mut self, node_index: &NodeIndex, user_id: UserId) {
        if let Some(node) = self.get_mut(node_index) {
            node.state.add_unmerged_leaf(user_id);
        }
    }

    /// Calculates the required tree depth for a given member count.
    #[must_use]
    pub fn depth_for_members(count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        // ceil(log2(count))
        32 - (count - 1).leading_zeros()
    }

    /// Validates that our path is complete (all nodes present).
    #[must_use]
    pub fn path_is_complete(&self) -> bool {
        self.our_path().iter().all(|idx| self.contains(idx))
    }
}

#[cfg(feature = "alloc")]
impl NodeLookup for PartialTreeView {
    fn get_node(&self, index: &NodeIndex) -> Option<&TreeNode> {
        self.get(index)
    }

    fn tree_depth(&self) -> u32 {
        self.tree_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_view() {
        let view = PartialTreeView::new(3, 4);

        assert_eq!(view.our_leaf(), NodeIndex::leaf(4, 3));
        assert_eq!(view.tree_depth(), 4);
        assert!(view.is_empty());
    }

    #[test]
    fn test_our_path() {
        let view = PartialTreeView::new(5, 3);
        let path = view.our_path();

        assert_eq!(path.len(), 4);
        assert_eq!(path[0], NodeIndex::new(3, 5));
        assert_eq!(path[3], NodeIndex::root());
    }

    #[test]
    fn test_our_copath() {
        let view = PartialTreeView::new(5, 3);
        let cp = view.our_copath();

        assert_eq!(cp.len(), 3);
        assert_eq!(cp[0], NodeIndex::new(3, 4)); // Sibling
    }

    #[test]
    fn test_insert_get() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));

        view.insert(node.clone());

        assert!(view.contains(&NodeIndex::new(1, 0)));
        assert!(!view.contains(&NodeIndex::new(1, 1)));
    }

    #[test]
    fn test_depth_for_members() {
        // depth = ceil(log2(count)) - minimum depth needed to hold count leaves
        // 0 members: degenerate case, depth 0
        // 1 member: single node (root is leaf), depth 0
        // 2 members: root + 2 leaves, depth 1
        // 3-4 members: depth 2
        // 5-8 members: depth 3
        assert_eq!(PartialTreeView::depth_for_members(0), 0);
        assert_eq!(PartialTreeView::depth_for_members(1), 0);
        assert_eq!(PartialTreeView::depth_for_members(2), 1);
        assert_eq!(PartialTreeView::depth_for_members(3), 2);
        assert_eq!(PartialTreeView::depth_for_members(4), 2);
        assert_eq!(PartialTreeView::depth_for_members(5), 3);
        assert_eq!(PartialTreeView::depth_for_members(8), 3);
        assert_eq!(PartialTreeView::depth_for_members(9), 4);
    }

    #[test]
    fn test_blank_node() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        let retrieved = view.get(&NodeIndex::new(1, 0)).unwrap();
        assert!(retrieved.state.is_blank());
    }

    #[test]
    fn test_node_lookup_trait() {
        let view = PartialTreeView::new(0, 3);

        // Test trait methods
        assert_eq!(view.tree_depth(), 3);
        assert!(view.get_node(&NodeIndex::root()).is_none());
    }
}
