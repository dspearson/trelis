//! Hybrid PQ Per-Message Ratchet for the Trelis protocol.
//!
//! This crate implements a per-message post-quantum ratchet,
//! generating fresh hybrid keypairs for every message to provide
//! strong forward secrecy guarantees.
//!
//! # Design Choice: Per-Message PQ KEM
//!
//! Unlike Signal's double ratchet (which uses DH ratchet + symmetric chain),
//! Trelis uses a single ratchet that generates a fresh hybrid keypair
//! (X448 + sntrup761) for every outbound message. This provides:
//!
//! - Per-message forward secrecy (not per role-switch)
//! - Key exposure window of 1 message (not N messages)
//! - Quantum protection for every message
//!
//! At the cost of ~2.3 KB overhead per message.
//!
//! # Transport Requirements
//!
//! This design **requires** ordered, reliable message delivery from the
//! transport layer (e.g., NATS JetStream). Unlike Signal, we cannot
//! derive skipped message keys because each message has a unique KEM
//! encapsulation. Out-of-order messages are rejected.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod header;
pub mod kdf;
pub mod nonce;
pub mod receive;
pub mod send;
pub mod serialise;
pub mod state;

pub use header::{MessageHeader, RatchetMessage, AAD_SIZE, HEADER_SIZE};
pub use kdf::{kdf_rk, KDF_MESSAGE, KDF_ROOT};
pub use nonce::{derive_hedged_nonce, NONCE_CONTEXT, NONCE_SIZE};
pub use receive::receive_message;
pub use send::{send_message, SendResult};
pub use serialise::{MAGIC, STATE_VERSION};
pub use state::{DoubleRatchet, RatchetStatus};

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
