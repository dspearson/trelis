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
pub use path::{copath, path_to_root};
pub use resolution::Resolution;
pub use view::PartialTreeView;
