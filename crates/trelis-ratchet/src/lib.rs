//! Hybrid PQ Double Ratchet for the Trelis protocol.
//!
//! This crate implements a per-message post-quantum double ratchet,
//! generating fresh hybrid keypairs for every message to provide
//! strong forward secrecy guarantees.
//!
//! # Design Choice: Per-Message PQ KEM
//!
//! Unlike Signal's role-switch ratchet, Trelis generates a fresh
//! hybrid keypair (X448 + sntrup761) for every outbound message.
//! This provides:
//!
//! - Per-message forward secrecy (not per role-switch)
//! - Key exposure window of 1 message (not N messages)
//! - Quantum protection for every message
//!
//! At the cost of ~2.3 KB overhead per message.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod header;
pub mod kdf;
pub mod nonce;
pub mod receive;
pub mod send;
pub mod serialise;
pub mod skipped_keys;
pub mod state;

pub use header::{MessageHeader, RatchetMessage, AAD_SIZE, HEADER_SIZE};
pub use kdf::{kdf_rk, KDF_MESSAGE, KDF_ROOT};
pub use nonce::{derive_hedged_nonce, NONCE_CONTEXT, NONCE_SIZE};
pub use send::SendResult;
pub use serialise::{MAGIC, STATE_VERSION};
pub use skipped_keys::{SkippedKeyIndex, SkippedKeys};
pub use state::{DoubleRatchet, RatchetStatus};

/// Maximum message counter gap allowed per message.
/// If a received message has a gap larger than this, it MUST be rejected.
pub const MAX_SKIP: u64 = 1_000;

/// Number of keys to pre-compute when the sender key changes.
/// This handles late arrivals from the previous chain.
pub const MAX_CHAIN_LOOKAHEAD: u64 = 100;

/// Maximum total skipped keys stored across all sender keys.
pub const MAX_SKIPPED_KEYS_TOTAL: usize = 2_000;

/// Maximum age for skipped keys before expiry (7 days in seconds).
pub const SKIPPED_KEY_MAX_AGE: u64 = 604_800;

/// Counter threshold for pruning old skipped keys.
pub const COUNTER_PRUNE_THRESHOLD: u64 = 10_000;

/// Maximum out-of-order messages per minute (rate limiting).
pub const MAX_OUT_OF_ORDER_PER_MIN: usize = 10;

/// Maximum gap allowed for a single message (smaller than MAX_SKIP).
pub const MAX_GAP_SINGLE_MSG: u64 = 100;

/// Maximum previous keypairs to retain for async message handling.
pub const MAX_PREVIOUS_KEYPAIRS: usize = 5;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_SKIP, 1_000);
        assert_eq!(MAX_CHAIN_LOOKAHEAD, 100);
        assert_eq!(MAX_SKIPPED_KEYS_TOTAL, 2_000);
        assert_eq!(SKIPPED_KEY_MAX_AGE, 604_800);
        assert_eq!(MAX_PREVIOUS_KEYPAIRS, 5);
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
