//! Binary ratchet tree structure for CoCoA-SA.
//!
//! The tree is a complete binary tree where:
//! - Leaves hold user key material
//! - Internal nodes hold derived keys for subtree encryption
//! - Each user stores only their path and resolved co-path (O(log n) nodes)

mod index;
mod node;
mod path;
mod resolution;
mod view;

pub use index::NodeIndex;
pub use node::{NodeState, TreeNode, UpdateOrigin};
pub use path::{
    copath, direct_path, leaves_in_subtree, lowest_common_ancestor, nodes_at_depth, path_to_root,
};
pub use resolution::{NodeLookup, Resolution, compute_lj, resolve, resolve_set};
pub use view::PartialTreeView;
