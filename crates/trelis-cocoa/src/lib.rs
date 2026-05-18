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
#![forbid(unsafe_code)]
// Pedantic-lint policy: cocoa uses `u32` for tree indices to match the wire
// format; the usize→u32 truncations are bounded by the wire-format-limited
// tree depth (T-10-06). Doc lints (`doc_markdown`, `missing_errors_doc`,
// `missing_panics_doc`) are deferred to Phase 12 (DOCS-02). `must_use_*`
// findings are deferred to Phase 11 (ERGO-01); see PEDANTIC-DEFER-TO-PHASE-11
// markers in epoch.rs / session.rs. `trivially_copy_pass_by_ref` on pub fns
// is also Phase 11 (ERGO-04). Group-id and version literals match the wire
// format (T-10-06). See Phase 10 disposition in `10-PEDANTIC-DRAFT.md`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::unreadable_literal
)]
#![cfg_attr(
    test,
    allow(
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::needless_borrow,
        clippy::assertions_on_constants
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

// DYN-01-MIRI-01 follow-on: every module in this crate ultimately imports
// `HybridKemKeypair`, `HybridIdentityKeypair`, or `HybridKemPublicKey` from
// `trelis-hybrid`, which are gated behind `std`/`wasm` because they wrap
// CSPRNG-dependent constructors. Mirror that gate here so `cargo check
// --no-default-features` succeeds (compiling to a near-empty library re-
// exporting only `MAX_GROUP_SIZE` and similar constants) instead of failing
// with cascading import errors.
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod epoch;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod key_schedule;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod operations;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod session;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod tree;

// Re-exports
#[cfg(any(feature = "std", feature = "wasm"))]
pub use epoch::{EpochSecrets, MessageKey};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use key_schedule::{
    H1_CONTEXT, H2_CONTEXT_PREFIX, H2_CONTEXT_SNTRUP, H2_CONTEXT_X448, H3_CONTEXT, H4_CONTEXT,
    H5_CONTEXT,
};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use session::CocoaSession;
#[cfg(any(feature = "std", feature = "wasm"))]
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
