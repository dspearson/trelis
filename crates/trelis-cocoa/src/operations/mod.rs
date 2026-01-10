//! CGKA operations for CoCoA-SA.
//!
//! This module provides the core group key agreement operations:
//! - Init: Create a new group
//! - Add: Add a member to the group
//! - Rem: Remove a member from the group
//! - Upd: Update our own keys
//!
//! ## Path Update Submodules
//!
//! The path update mechanism is split into three submodules:
//! - [`seed_chain`]: Seed generation and path derivation
//! - [`seed_encrypt`]: Seed encryption to resolution sets
//! - [`path_update`]: Path update building and application
//! - [`commit_sign`]: Commit signing and verification

mod add;
pub mod commit_sign;
mod init;
pub mod path_update;
mod remove;
pub mod seed_chain;
pub mod seed_encrypt;
mod update;

pub use add::{AddCommit, EncryptedSeed, PathUpdate, add_member, process_add};
pub use init::{Welcome, WelcomeInfoSerialise, create_group, encrypt_welcome_info, process_welcome};
pub use remove::{RemoveCommit, process_remove, remove_member};
#[cfg(any(
    feature = "deterministic-keygen",
    target_os = "windows",
    target_arch = "wasm32"
))]
pub use seed_chain::{
    Seed, SEED_SIZE, derive_delta_root, derive_node_keypair, derive_path_seeds,
    generate_leaf_seed, get_seed_at_level,
};
#[cfg(not(any(
    feature = "deterministic-keygen",
    target_os = "windows",
    target_arch = "wasm32"
)))]
pub use seed_chain::{
    Seed, SEED_SIZE, derive_delta_root, derive_path_seeds, generate_leaf_seed, get_seed_at_level,
};
pub use update::{UpdateCommit, create_update, process_update};
