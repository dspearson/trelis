//! CGKA operations for CoCoA-SA.
//!
//! This module provides the core group key agreement operations:
//! - Init: Create a new group
//! - Add: Add a member to the group
//! - Rem: Remove a member from the group
//! - Upd: Update our own keys

mod add;
mod init;
mod remove;
mod update;

pub use add::{process_add, AddCommit};
pub use init::{create_group, Welcome};
pub use remove::{process_remove, RemoveCommit};
pub use update::{create_update, process_update, UpdateCommit};
