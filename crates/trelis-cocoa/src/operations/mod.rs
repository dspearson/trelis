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

pub use add::{add_member, process_add, AddCommit, EncryptedSeed, PathUpdate};
pub use init::{create_group, process_welcome, Welcome};
pub use remove::{process_remove, remove_member, RemoveCommit};
pub use update::{create_update, process_update, UpdateCommit};
