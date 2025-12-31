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

pub use add::{AddCommit, EncryptedSeed, PathUpdate, add_member, process_add};
pub use init::{Welcome, create_group, process_welcome};
pub use remove::{RemoveCommit, process_remove, remove_member};
pub use update::{UpdateCommit, create_update, process_update};
