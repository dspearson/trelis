//! CoCoA-SA: Concurrent Continuous Group Key Agreement (Server-Assisted)
//!
//! This crate implements the Trelis adaptation of the CoCoA protocol for
//! efficient group encryption with:
//!
//! - Concurrent updates: Multiple users can update simultaneously
//! - Post-compromise security: Healing in ⌈log(n)⌉ + 1 rounds
//! - Per-message forward secrecy: Through epoch key schedule
//! - Server-mediated delivery: O(log² n) personalised packets
//!
//! # Deviations from Original CoCoA
//!
//! This implementation is based on the CoCoA paper but includes significant
//! modifications. We name it **CoCoA-SA** (Server-Assisted) to distinguish
//! it from the original academic protocol:
//!
//! | Aspect | Original CoCoA | CoCoA-SA (Trelis) |
//! |--------|----------------|-------------------|
//! | **Delivery Model** | Peer-to-peer broadcast | Server-mediated relay |
//! | **KEM Primitives** | Classical (e.g., X25519) | Hybrid PQ (X448 + sntrup761) |
//! | **Key Schedule** | Paper-specified hash | BLAKE3 with domain separation |
//! | **Context Strings** | Paper-specified | `cocoa-sa-v1-*` namespace |
//! | **Signatures** | Classical | Hybrid PQ (Ed448 + ML-DSA-65) |
//! | **Wire Format** | Not specified | Trelis wire format with TLV |
//!
//! The core tree structure and CGKA operations (Init, Add, Remove, Update)
//! follow the CoCoA paper's algorithms, but all cryptographic instantiations
//! have been replaced with Trelis's hybrid post-quantum primitives.
//!
//! # Architecture
//!
//! The implementation is split into modules:
//!
//! - [`tree`]: Binary ratchet tree structure and node operations
//! - [`key_schedule`]: H1-H5 hash functions for key derivation
//! - [`operations`]: CGKA operations (Init, Add, Rem, Upd)
//! - [`epoch`]: Epoch management and secrets
//! - [`session`]: Session state management
//!
//! # Example
//!
//! ```ignore
//! use trelis_cocoa::{CocoaSession, operations};
//!
//! // Create a new group
//! let (session, welcomes) = operations::init_group(
//!     &creator_identity,
//!     &[member1_bundle, member2_bundle],
//! )?;
//!
//! // Encrypt a message
//! let ciphertext = session.encrypt(b"Hello, group!")?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::needless_borrow,
        clippy::assertions_on_constants
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod epoch;
pub mod key_schedule;
pub mod operations;
pub mod session;
pub mod tree;

// Re-exports
pub use epoch::{EpochSecrets, MessageKey};
pub use key_schedule::{
    H1_CONTEXT, H2_CONTEXT_PREFIX, H2_CONTEXT_SNTRUP, H2_CONTEXT_X448, H3_CONTEXT, H4_CONTEXT,
    H5_CONTEXT,
};
pub use session::CocoaSession;
pub use tree::{NodeIndex, NodeState, PartialTreeView};

/// Maximum group size (2^20 = ~1 million members).
pub const MAX_GROUP_SIZE: u32 = 1 << 20;

/// Maximum tree depth for MAX_GROUP_SIZE.
pub const MAX_TREE_DEPTH: u32 = 20;

/// Initial epoch number for new groups.
pub const INITIAL_EPOCH: u64 = 0;

/// Size of group ID in bytes.
pub const GROUP_ID_SIZE: usize = 32;

/// Size of user ID in bytes.
pub const USER_ID_SIZE: usize = 32;

/// A group identifier (32-byte random value).
pub type GroupId = [u8; GROUP_ID_SIZE];

/// A user identifier (32-byte value, typically a hash of identity public key).
pub type UserId = [u8; USER_ID_SIZE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_group_size() {
        assert_eq!(MAX_GROUP_SIZE, 1_048_576);
    }

    #[test]
    fn test_max_tree_depth() {
        // 2^20 members requires depth 20
        assert!(1u32 << MAX_TREE_DEPTH >= MAX_GROUP_SIZE);
    }

    #[test]
    fn test_id_sizes() {
        assert_eq!(GROUP_ID_SIZE, 32);
        assert_eq!(USER_ID_SIZE, 32);
    }
}
