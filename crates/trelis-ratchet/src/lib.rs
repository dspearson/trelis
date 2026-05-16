//! Hybrid PQ Per-Message KEM Ratchet for the Trelis protocol.
//!
//! This crate implements a per-message post-quantum KEM ratchet,
//! generating fresh hybrid keypairs for every message to provide
//! strong forward secrecy guarantees.
//!
//! # Design Choice: Per-Message PQ KEM (NOT Double Ratchet)
//!
//! This is a **single KEM ratchet** (NOT Signal's double ratchet).
//! Trelis generates a fresh hybrid keypair (X448 + sntrup761) for
//! every outbound message. This provides:
//!
//! - Per-message forward secrecy (not per role-switch)
//! - Key exposure window of 1 message (not N messages)
//! - Quantum protection for every message
//!
//! At the cost of ~2.3 KB overhead per message.
//!
//! # Deprecation Note
//!
//! As of Trelis v1.1, the unified CoCoA architecture is preferred for
//! all message encryption (2-party and N-party). This ratchet is retained
//! for the legacy pairwise protocol and test vectors. See the spec's
//! appendix "Design Comparison: Why CoCoA Over Pairwise Ratchets".
//!
//! # Transport Requirements
//!
//! This design **requires** ordered, reliable message delivery from the
//! transport layer (e.g., NATS JetStream). Unlike Signal, we cannot
//! derive skipped message keys because each message has a unique KEM
//! encapsulation. Out-of-order messages are rejected.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
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

// DYN-01-MIRI-01: header/state/receive/send/(parts of kdf,nonce) use
// `HybridKemKeypair` and related types from `trelis-hybrid`, which are gated
// behind `std`/`wasm` because they wrap SNTRUP761 (whose generation requires
// the system CSPRNG). Mirror that gate here so `cargo check
// --no-default-features` succeeds on this crate (compiling to a near-empty
// library) instead of failing with cascading import errors. With this gate
// in place MIRI can complete a `--no-default-features` workspace run; full
// MIRI coverage of this crate must be invoked with `--features std` (the
// default).
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod header;
pub mod kdf;
pub mod nonce;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod receive;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod send;
pub mod serialise;
#[cfg(any(feature = "std", feature = "wasm"))]
pub mod state;

#[cfg(any(feature = "std", feature = "wasm"))]
pub use header::{AAD_SIZE, HEADER_SIZE, MessageHeader, RatchetMessage};
#[cfg(feature = "alloc")]
pub use kdf::kdf_rk;
pub use kdf::{KDF_MESSAGE, KDF_ROOT};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use nonce::derive_hedged_nonce;
pub use nonce::{NONCE_CONTEXT, NONCE_SIZE};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use receive::receive_message;
#[cfg(any(feature = "std", feature = "wasm"))]
pub use send::{SendResult, send_message};
pub use serialise::{MAGIC, STATE_VERSION};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use state::{KemRatchet, RatchetStatus};

/// Type alias for backwards compatibility.
#[cfg(any(feature = "std", feature = "wasm"))]
#[deprecated(
    since = "1.1.0",
    note = "Use KemRatchet instead - this is a KEM ratchet, not a double ratchet"
)]
pub type DoubleRatchet = KemRatchet;

/// Maximum previous keypairs to retain for async message handling.
/// Messages may arrive encrypted to a previous keypair after rotation.
pub const MAX_PREVIOUS_KEYPAIRS: usize = 5;

/// Maximum pending messages for sender-side retention.
/// Senders retain messages until acknowledged by recipient.
pub const MAX_PENDING_MESSAGES: usize = 100;

/// Maximum age for pending messages (7 days in seconds).
pub const PENDING_MESSAGE_MAX_AGE: u64 = 604_800;

/// Session exhaustion threshold (u64::MAX - 1,000,000).
pub const SESSION_EXHAUSTION_THRESHOLD: u64 = u64::MAX - 1_000_000;

/// Default inactivity threshold before session becomes stale (7 days).
pub const DEFAULT_INACTIVITY_THRESHOLD: u64 = 7 * 24 * 60 * 60;

/// Minimum allowed inactivity threshold (24 hours).
pub const MIN_INACTIVITY_THRESHOLD: u64 = 24 * 60 * 60;

/// Maximum recommended inactivity threshold (30 days).
pub const MAX_INACTIVITY_THRESHOLD: u64 = 30 * 24 * 60 * 60;

/// Warning threshold for unreplied messages (PCS degradation).
pub const UNREPLIED_WARNING_THRESHOLD: u64 = 1_000;

/// Maximum retries before session re-establishment on order violation.
pub const MAX_ORDER_RETRIES: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_PREVIOUS_KEYPAIRS, 5);
        assert_eq!(MAX_PENDING_MESSAGES, 100);
        assert_eq!(PENDING_MESSAGE_MAX_AGE, 604_800);
    }

    #[test]
    fn test_inactivity_thresholds() {
        // 7 days default
        assert_eq!(DEFAULT_INACTIVITY_THRESHOLD, 7 * 24 * 60 * 60);
        // 24 hours minimum
        assert_eq!(MIN_INACTIVITY_THRESHOLD, 24 * 60 * 60);
        // 30 days maximum
        assert_eq!(MAX_INACTIVITY_THRESHOLD, 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_session_exhaustion() {
        // Should be u64::MAX - 1,000,000
        assert_eq!(SESSION_EXHAUSTION_THRESHOLD, u64::MAX - 1_000_000);
        // Verify there's still room for 1 million messages
        assert!(SESSION_EXHAUSTION_THRESHOLD < u64::MAX);
    }
}
