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

    /// Grows the tree by one level to accommodate more members.
    ///
    /// When the tree grows:
    /// - Tree depth increases by 1
    /// - All existing nodes move down one level (depth increases by 1)
    /// - The old root becomes the left child of the new root
    /// - Leaf positions remain the same (just at a deeper level)
    ///
    /// # Example
    ///
    /// Before (depth 2, capacity 4 leaves):
    /// ```text
    ///        (0,0)         <- root
    ///       /     \
    ///    (1,0)   (1,1)     <- internal
    ///    /  \    /  \
    ///  (2,0)(2,1)(2,2)(2,3) <- leaves
    /// ```
    ///
    /// After grow (depth 3, capacity 8 leaves):
    /// ```text
    ///              (0,0)            <- NEW root
    ///            /       \
    ///        (1,0)       (1,1)      <- old root becomes (1,0), (1,1) is blank
    ///       /     \      /    \
    ///    (2,0)   (2,1) (2,2) (2,3)  <- old internals, (2,2) and (2,3) are blank
    ///    /  \    /  \   ...
    ///  old leaves at depth 3       <- old leaves at new depth
    /// ```
    pub fn grow_tree(&mut self) {
        use alloc::collections::BTreeMap;

        let old_depth = self.tree_depth;
        let new_depth = old_depth + 1;

        // Remap all existing nodes to new indices (depth + 1)
        let mut new_nodes = BTreeMap::new();

        for (_, mut node) in core::mem::take(&mut self.nodes) {
            // Increase depth by 1 (position stays the same)
            let old_index = node.index;
            let new_index = NodeIndex::new(old_index.depth + 1, old_index.position);
            node.index = new_index;
            new_nodes.insert(new_index.to_linear(), node);
        }

        self.nodes = new_nodes;
        self.tree_depth = new_depth;

        // Update our leaf index
        self.our_leaf = NodeIndex::leaf(new_depth, self.our_leaf.position);
    }

    /// Grows the tree if needed to accommodate a given member count.
    ///
    /// Returns true if the tree was grown, false otherwise.
    pub fn grow_if_needed(&mut self, member_count: u32) -> bool {
        let required_depth = Self::depth_for_members(member_count);
        if required_depth > self.tree_depth {
            self.grow_tree();
            true
        } else {
            false
        }
    }

    /// Returns the maximum number of leaves this tree can hold.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        if self.tree_depth == 0 {
            1
        } else {
            1 << self.tree_depth
        }
    }

    /// Returns true if the tree is at capacity and needs to grow.
    #[must_use]
    pub fn needs_growth(&self, member_count: u32) -> bool {
        member_count > self.capacity()
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

    #[test]
    fn test_get_mut() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        // Test get_mut exists
        let node_mut = view.get_mut(&NodeIndex::new(1, 0));
        assert!(node_mut.is_some());

        // Test get_mut returns None for non-existent
        let missing = view.get_mut(&NodeIndex::new(1, 1));
        assert!(missing.is_none());
    }

    #[test]
    fn test_get_mut_modify() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        // Use get_mut to add an unmerged leaf
        if let Some(n) = view.get_mut(&NodeIndex::new(1, 0)) {
            n.state.add_unmerged_leaf([0x42u8; 32]);
        }

        // Verify the modification persisted
        let retrieved = view.get(&NodeIndex::new(1, 0)).unwrap();
        let leaves = retrieved.state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        assert!(view.contains(&NodeIndex::new(1, 0)));

        let removed = view.remove(&NodeIndex::new(1, 0));
        assert!(removed.is_some());
        assert!(!view.contains(&NodeIndex::new(1, 0)));
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut view = PartialTreeView::new(0, 2);

        let removed = view.remove(&NodeIndex::new(1, 0));
        assert!(removed.is_none());
    }

    #[test]
    fn test_len() {
        let mut view = PartialTreeView::new(0, 2);

        assert_eq!(view.len(), 0);

        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0)));
        assert_eq!(view.len(), 1);

        view.insert(TreeNode::new_blank(NodeIndex::new(1, 1)));
        assert_eq!(view.len(), 2);

        view.remove(&NodeIndex::new(1, 0));
        assert_eq!(view.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let mut view = PartialTreeView::new(0, 2);

        assert!(view.is_empty());

        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0)));
        assert!(!view.is_empty());

        view.remove(&NodeIndex::new(1, 0));
        assert!(view.is_empty());
    }

    #[test]
    fn test_iter() {
        let mut view = PartialTreeView::new(0, 2);

        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0)));
        view.insert(TreeNode::new_blank(NodeIndex::new(1, 1)));
        view.insert(TreeNode::new_blank(NodeIndex::new(0, 0)));

        let nodes: Vec<_> = view.iter().collect();
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn test_path_nodes() {
        let mut view = PartialTreeView::new(0, 2);

        // Our path: leaf (2,0) -> parent (1,0) -> root (0,0)
        view.insert(TreeNode::new_blank(NodeIndex::new(2, 0))); // leaf
        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0))); // parent
        // Skip root to test incomplete path

        let path_nodes: Vec<_> = view.path_nodes().collect();
        assert_eq!(path_nodes.len(), 3); // All 3 indices, but one is None

        // First node (leaf) is present
        assert!(path_nodes[0].is_some());
        // Second node (parent) is present
        assert!(path_nodes[1].is_some());
        // Third node (root) is missing
        assert!(path_nodes[2].is_none());
    }

    #[test]
    fn test_set_member_count() {
        let mut view = PartialTreeView::new(0, 2);

        assert_eq!(view.member_count(), 0);

        view.set_member_count(5);
        assert_eq!(view.member_count(), 5);

        view.set_member_count(10);
        assert_eq!(view.member_count(), 10);
    }

    #[test]
    fn test_add_unmerged_leaf() {
        let mut view = PartialTreeView::new(0, 2);
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        let user_id = [0x42u8; 32];
        view.add_unmerged_leaf(&NodeIndex::new(1, 0), user_id);

        let retrieved = view.get(&NodeIndex::new(1, 0)).unwrap();
        let leaves = retrieved.state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 1);
        assert!(leaves.contains(&user_id));
    }

    #[test]
    fn test_add_unmerged_leaf_nonexistent_node() {
        let mut view = PartialTreeView::new(0, 2);

        // Adding to non-existent node should be a no-op
        let user_id = [0x42u8; 32];
        view.add_unmerged_leaf(&NodeIndex::new(1, 0), user_id);

        // Nothing should happen, no crash
        assert!(view.is_empty());
    }

    #[test]
    fn test_blank_node_operation() {
        let mut view = PartialTreeView::new(0, 2);

        // Insert a populated node (using blank for simplicity since both have state)
        let node = TreeNode::new_blank(NodeIndex::new(1, 0));
        view.insert(node);

        // Blank the node
        view.blank_node(&NodeIndex::new(1, 0));

        let retrieved = view.get(&NodeIndex::new(1, 0)).unwrap();
        assert!(retrieved.state.is_blank());
    }

    #[test]
    fn test_blank_node_nonexistent() {
        let mut view = PartialTreeView::new(0, 2);

        // Blanking non-existent node should be a no-op
        view.blank_node(&NodeIndex::new(1, 0));

        // Nothing should happen, no crash
        assert!(view.is_empty());
    }

    #[test]
    fn test_path_is_complete() {
        let mut view = PartialTreeView::new(0, 2);

        // Initially incomplete (empty)
        assert!(!view.path_is_complete());

        // Add all path nodes: leaf (2,0) -> parent (1,0) -> root (0,0)
        view.insert(TreeNode::new_blank(NodeIndex::new(2, 0)));
        assert!(!view.path_is_complete()); // Still incomplete

        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0)));
        assert!(!view.path_is_complete()); // Still incomplete

        view.insert(TreeNode::new_blank(NodeIndex::new(0, 0)));
        assert!(view.path_is_complete()); // Now complete
    }

    #[test]
    fn test_path_is_complete_with_removal() {
        let mut view = PartialTreeView::new(0, 2);

        // Add all path nodes
        view.insert(TreeNode::new_blank(NodeIndex::new(2, 0)));
        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0)));
        view.insert(TreeNode::new_blank(NodeIndex::new(0, 0)));
        assert!(view.path_is_complete());

        // Remove one node
        view.remove(&NodeIndex::new(1, 0));
        assert!(!view.path_is_complete());
    }

    #[test]
    fn test_capacity() {
        // depth 0 = 1 leaf
        let view = PartialTreeView::new(0, 0);
        assert_eq!(view.capacity(), 1);

        // depth 1 = 2 leaves
        let view = PartialTreeView::new(0, 1);
        assert_eq!(view.capacity(), 2);

        // depth 2 = 4 leaves
        let view = PartialTreeView::new(0, 2);
        assert_eq!(view.capacity(), 4);

        // depth 3 = 8 leaves
        let view = PartialTreeView::new(0, 3);
        assert_eq!(view.capacity(), 8);
    }

    #[test]
    fn test_needs_growth() {
        let view = PartialTreeView::new(0, 2); // capacity 4

        assert!(!view.needs_growth(1));
        assert!(!view.needs_growth(4));
        assert!(view.needs_growth(5)); // needs 5, capacity is 4
        assert!(view.needs_growth(8));
    }

    #[test]
    fn test_grow_tree_depth() {
        let mut view = PartialTreeView::new(0, 2);
        assert_eq!(view.tree_depth(), 2);
        assert_eq!(view.capacity(), 4);

        view.grow_tree();

        assert_eq!(view.tree_depth(), 3);
        assert_eq!(view.capacity(), 8);
    }

    #[test]
    fn test_grow_tree_updates_our_leaf() {
        let mut view = PartialTreeView::new(3, 2);
        assert_eq!(view.our_leaf(), NodeIndex::leaf(2, 3));

        view.grow_tree();

        // Same position, deeper level
        assert_eq!(view.our_leaf(), NodeIndex::leaf(3, 3));
    }

    #[test]
    fn test_grow_tree_remaps_nodes() {
        let mut view = PartialTreeView::new(0, 2);

        // Add nodes at original positions
        view.insert(TreeNode::new_blank(NodeIndex::new(2, 0))); // leaf
        view.insert(TreeNode::new_blank(NodeIndex::new(1, 0))); // internal
        view.insert(TreeNode::new_blank(NodeIndex::new(0, 0))); // root

        assert_eq!(view.len(), 3);
        assert!(view.contains(&NodeIndex::new(2, 0)));
        assert!(view.contains(&NodeIndex::new(1, 0)));
        assert!(view.contains(&NodeIndex::new(0, 0)));

        view.grow_tree();

        // All nodes should be at depth + 1
        assert_eq!(view.len(), 3);
        assert!(view.contains(&NodeIndex::new(3, 0))); // was (2, 0)
        assert!(view.contains(&NodeIndex::new(2, 0))); // was (1, 0)
        assert!(view.contains(&NodeIndex::new(1, 0))); // was (0, 0) - old root

        // Old indices should be gone
        assert!(!view.contains(&NodeIndex::new(0, 0))); // new root position is empty
    }

    #[test]
    fn test_grow_if_needed_grows() {
        let mut view = PartialTreeView::new(0, 2); // capacity 4
        assert_eq!(view.tree_depth(), 2);

        let grew = view.grow_if_needed(5);
        assert!(grew);
        assert_eq!(view.tree_depth(), 3);
        assert_eq!(view.capacity(), 8);
    }

    #[test]
    fn test_grow_if_needed_no_growth() {
        let mut view = PartialTreeView::new(0, 2); // capacity 4
        assert_eq!(view.tree_depth(), 2);

        let grew = view.grow_if_needed(4);
        assert!(!grew);
        assert_eq!(view.tree_depth(), 2);
    }

    #[test]
    fn test_grow_tree_multiple_times() {
        let mut view = PartialTreeView::new(1, 1); // depth 1, capacity 2
        view.insert(TreeNode::new_blank(NodeIndex::new(1, 1))); // our leaf

        assert_eq!(view.tree_depth(), 1);
        assert_eq!(view.our_leaf(), NodeIndex::leaf(1, 1));

        // Grow once
        view.grow_tree();
        assert_eq!(view.tree_depth(), 2);
        assert_eq!(view.our_leaf(), NodeIndex::leaf(2, 1));
        assert!(view.contains(&NodeIndex::new(2, 1)));

        // Grow again
        view.grow_tree();
        assert_eq!(view.tree_depth(), 3);
        assert_eq!(view.our_leaf(), NodeIndex::leaf(3, 1));
        assert!(view.contains(&NodeIndex::new(3, 1)));
    }

    #[test]
    fn test_grow_tree_preserves_node_state() {
        let mut view = PartialTreeView::new(0, 1);

        // Insert a node with unmerged leaves
        let mut node = TreeNode::new_blank(NodeIndex::new(1, 0));
        node.state.add_unmerged_leaf([0x42u8; 32]);
        view.insert(node);

        view.grow_tree();

        // Check that the node at the new position still has the unmerged leaf
        let moved_node = view.get(&NodeIndex::new(2, 0)).unwrap();
        let leaves = moved_node.state.unmerged_leaves().unwrap();
        assert_eq!(leaves.len(), 1);
        assert!(leaves.contains(&[0x42u8; 32]));
    }
}
