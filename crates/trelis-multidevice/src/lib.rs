//! Multi-device support and history synchronisation for Trelis.
//!
//! This crate provides:
//! - Per-thread history sync configuration
//! - Message key retention for sharing with new devices
//! - History key share messages for device onboarding
//! - Device revocation certificates
//!
//! # Design Goals
//!
//! 1. **Per-thread flexibility**: Users choose history sync on/off per thread
//! 2. **Simple architecture**: History sharing uses normal message infrastructure
//! 3. **Device verification**: New devices require approval from existing device
//! 4. **Revocation via ratchet**: Revoked devices excluded from ratchet
//! 5. **Auditable**: Key sharing events visible in thread transcript
//! 6. **Post-quantum safety**: All key exchange uses hybrid KEM
//!
//! # Example
//!
//! ```ignore
//! use trelis_multidevice::{ThreadSettings, ThreadKeyStore, RetainedKey};
//!
//! // Create thread with history sync enabled
//! let settings = ThreadSettings::new([0u8; 32]);
//! assert!(settings.history_sync_enabled);
//!
//! // Retain keys for potential sharing
//! let mut store = ThreadKeyStore::new([0u8; 32]);
//! store.retain_key(RetainedKey {
//!     message_id: [0u8; 32],
//!     message_key: [0u8; 32],
//!     sequence: 0,
//!     timestamp: 0,
//! });
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
// Tests silence the full pedantic set (uninlined_format_args on
// `format!("{:?}", x)` dominates the noise; not worth churning the corpus).
#![cfg_attr(test, allow(clippy::pedantic))]

#[cfg(feature = "alloc")]
extern crate alloc;

mod approval;
// `device_key_wrap` uses `HybridKemKeypair`, `HybridEncapsulation`,
// `HybridKemPublicKey` from `trelis-hybrid`, which are gated behind
// `std`/`wasm`. Mirror that gate; without it the crate fails to compile
// under `--no-default-features`.
#[cfg(any(feature = "std", feature = "wasm"))]
mod device_key_wrap;
mod history;
// `retained_key` only has internal users that are themselves alloc-gated
// (Vec<RetainedKey>, alloc-gated re-export). Gating the module matches the
// existing `device_key_wrap` precedent and keeps `--no-default-features`
// clean of dead-code.
#[cfg(feature = "alloc")]
mod retained_key;
mod revocation;
mod settings;

pub use approval::{FINGERPRINT_SIZE, NonceWindow, SERVER_NONCE_SIZE, USER_ID_SIZE};
// `DeviceApprovalCertificate`, `device_fingerprint`,
// `HistoryKeyShareMessage`, `ThreadKeyStore`, and `RetainedKey` are
// themselves `#[cfg(feature = "alloc")]`-gated in their modules (they own
// `Vec`-based fields or use alloc-only helpers). Match the gate on the
// re-exports.
#[cfg(feature = "alloc")]
pub use approval::{DeviceApprovalCertificate, device_fingerprint};
#[cfg(any(feature = "std", feature = "wasm"))]
pub use device_key_wrap::{
    DEVICE_KEY_WRAP_SIZE, DeviceKeyWrap, KEY_ID_SIZE, WRAP_CONTEXT, WrapContext, WrapPurpose,
};
pub use history::HistoryKeyShare;
#[cfg(feature = "alloc")]
pub use history::HistoryKeyShareMessage;
#[cfg(feature = "alloc")]
pub use retained_key::RetainedKey;
pub use revocation::{DeviceRevocation, RevocationReason, RevocationRekeyEvent};
#[cfg(feature = "alloc")]
pub use settings::ThreadKeyStore;
pub use settings::ThreadSettings;

/// Thread identifier type.
pub type ThreadId = [u8; 32];

/// Device identifier type.
pub type DeviceId = [u8; 16];

/// Maximum number of retained keys per thread (configurable limit).
pub const MAX_RETAINED_KEYS: usize = 100_000;

/// Default retention period in seconds (30 days).
pub const DEFAULT_RETENTION_PERIOD: u64 = 30 * 24 * 60 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_id_size() {
        assert_eq!(core::mem::size_of::<ThreadId>(), 32);
    }

    #[test]
    fn test_device_id_size() {
        assert_eq!(core::mem::size_of::<DeviceId>(), 16);
    }
}
