//! Cross-invocation monotonic high-water mark for a CoCoA session identity.
//!
//! [`SessionWatermark`] is a 16-byte, secret-free value carrying the highest
//! committed `(epoch_number, message_counter)` a session identity has emitted.
//! It is the cross-invocation half of the counter-rollback guard (RBK-01 /
//! GAP-05): the in-object [`Epoch::set_message_counter`](crate::epoch::Epoch)
//! guard rejects an intra-epoch regression on a *live* object, but the
//! restore/deserialise path builds a fresh counter-0 epoch and forward-sets
//! `0 -> N`, so it cannot see across a process/restore boundary. The watermark
//! records that boundary explicitly.
//!
//! The value is keyed by the CALLER under `(group_id, our_user_id)` and MUST be
//! persisted by the application independently of — and at least as durably as —
//! the session blob (the crate cannot persist across a process restart). It
//! carries NO secret bytes: only the public `(epoch, counter)` metadata that is
//! already present, in the clear, in the serialised session blob.
//!
//! Gated behind the same `session-serialization` feature as the rest of the
//! (de)serialisation surface (and, like [`crate::session`], `std`/`wasm`).

#[cfg(all(
    feature = "session-serialization",
    any(feature = "std", feature = "wasm")
))]
use trelis_error::{CryptoError, Result};

#[cfg(all(
    feature = "session-serialization",
    any(feature = "std", feature = "wasm")
))]
use crate::session::CocoaSession;

/// Cross-invocation monotonic high-water mark for a CoCoA session identity.
///
/// A 16-byte, secret-free `(epoch_number, message_counter)` value. Ordering is
/// lexicographic — a strictly-higher epoch always dominates (it lands in a
/// disjoint per-epoch key space regardless of counter); within one epoch the
/// counter decides. [`check`](Self::check) rejects a restore whose
/// `(epoch, counter)` is strictly below this watermark and accepts equal or
/// above (the honest reload of the newest blob); [`advanced`](Self::advanced)
/// is the lexicographic max the caller persists on every emit/serialise.
///
/// See the module docs for the persistence contract; carries no key material.
#[cfg(all(
    feature = "session-serialization",
    any(feature = "std", feature = "wasm")
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionWatermark {
    // Field order is load-bearing: `epoch_number` MUST be declared FIRST so the
    // derived `Ord` (and the tuple comparisons in `check`/`advanced`) is exactly
    // lexicographic `(epoch, counter)`. Swapping the two fields silently flips
    // the ordering; `wm_rejects_lower_epoch_any_counter` and
    // `wm_advanced_is_lexicographic_max` are the intended tripwires.
    epoch_number: u64,
    message_counter: u64,
}

#[cfg(all(
    feature = "session-serialization",
    any(feature = "std", feature = "wasm")
))]
impl SessionWatermark {
    /// Constructs a watermark at an explicit `(epoch_number, message_counter)`.
    #[must_use]
    pub const fn new(epoch_number: u64, message_counter: u64) -> Self {
        Self {
            epoch_number,
            message_counter,
        }
    }

    /// The highest state the caller has committed to for this identity — the
    /// session's current `(epoch_number, message_counter)`.
    #[must_use]
    pub fn of_session(s: &CocoaSession) -> Self {
        Self::new(s.epoch_number(), s.message_counter())
    }

    /// Returns the watermark's epoch number.
    #[must_use]
    pub const fn epoch_number(&self) -> u64 {
        self.epoch_number
    }

    /// Returns the watermark's message counter.
    #[must_use]
    pub const fn message_counter(&self) -> u64 {
        self.message_counter
    }

    /// Rejects a restore that would re-emit at-or-below an already-committed
    /// `(epoch, counter)`.
    ///
    /// Lexicographic: a strictly-lower epoch (any counter), or the same epoch
    /// with a strictly-lower counter, is the rollback and is rejected; EQUAL is
    /// accepted (the honest reload of the newest blob) and so is any higher
    /// `(epoch, counter)` (a strictly-higher epoch always dominates — its key
    /// space is disjoint). This composes with the 52-05 in-object guard
    /// [`Epoch::set_message_counter`](crate::epoch::Epoch): both reject
    /// strictly-below and allow equal, so the honest fresh-restore forward-set
    /// `0 -> N` and the honest newest-blob reload both still pass (RESEARCH §6).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MessageCounterTooOld`] if
    /// `(epoch_number, message_counter)` is strictly below this watermark.
    pub fn check(&self, epoch_number: u64, message_counter: u64) -> Result<()> {
        if (epoch_number, message_counter) < (self.epoch_number, self.message_counter) {
            return Err(CryptoError::MessageCounterTooOld);
        }
        Ok(())
    }

    /// Returns the lexicographic max of this watermark and
    /// `(epoch_number, message_counter)` — the value the caller persists on
    /// every emit/serialise so a later stale restore is caught.
    #[must_use]
    pub fn advanced(self, epoch_number: u64, message_counter: u64) -> Self {
        core::cmp::max(self, Self::new(epoch_number, message_counter))
    }

    /// Serialises to 16 little-endian bytes: `epoch_u64 || counter_u64`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.epoch_number.to_le_bytes());
        b[8..16].copy_from_slice(&self.message_counter.to_le_bytes());
        b
    }

    /// Parses a watermark from 16 little-endian bytes: `epoch_u64 || counter_u64`.
    ///
    /// The length guard mirrors
    /// [`EncryptedMessage::from_bytes`](crate::session::EncryptedMessage) —
    /// reject a short buffer before any slice index (V5 input validation).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedMessage`] if `bytes.len() < 16`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(CryptoError::MalformedMessage);
        }
        let epoch_number = u64::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let message_counter = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        Ok(Self {
            epoch_number,
            message_counter,
        })
    }
}

#[cfg(all(test, feature = "session-serialization"))]
mod session_watermark_tests {
    use super::SessionWatermark;
    use trelis_error::CryptoError;

    /// Same epoch, strictly-lower counter is the intra-epoch rollback → rejected.
    #[test]
    fn wm_rejects_lower_counter_same_epoch() {
        let wm = SessionWatermark::new(3, 100);
        assert!(matches!(
            wm.check(3, 99),
            Err(CryptoError::MessageCounterTooOld)
        ));
    }

    /// A strictly-lower epoch is a rollback regardless of counter — a higher
    /// epoch dominates lexicographically, so `(2, u64::MAX) < (3, 0)`.
    #[test]
    fn wm_rejects_lower_epoch_any_counter() {
        let wm = SessionWatermark::new(3, 0);
        assert!(matches!(
            wm.check(2, u64::MAX),
            Err(CryptoError::MessageCounterTooOld)
        ));
    }

    /// Equal (honest newest-blob reload), same-epoch-forward, and higher-epoch
    /// restores are all accepted.
    #[test]
    fn wm_accepts_equal_and_above() {
        let wm = SessionWatermark::new(3, 100);
        assert!(wm.check(3, 100).is_ok());
        assert!(wm.check(3, 101).is_ok());
        assert!(wm.check(4, 0).is_ok());
    }

    /// `advanced` is the lexicographic max: a lower operand is ignored, a higher
    /// epoch replaces, a higher same-epoch counter replaces.
    #[test]
    fn wm_advanced_is_lexicographic_max() {
        assert_eq!(
            SessionWatermark::new(3, 100).advanced(3, 90),
            SessionWatermark::new(3, 100)
        );
        assert_eq!(
            SessionWatermark::new(3, 100).advanced(4, 0),
            SessionWatermark::new(4, 0)
        );
        assert_eq!(
            SessionWatermark::new(3, 100).advanced(3, 250),
            SessionWatermark::new(3, 250)
        );
    }

    /// 16-byte LE round-trip.
    #[test]
    fn wm_bytes_round_trip() {
        let wm = SessionWatermark::new(7, 42);
        assert_eq!(SessionWatermark::from_bytes(&wm.to_bytes()).unwrap(), wm);
    }

    /// A buffer shorter than 16 bytes is rejected before any slice index.
    #[test]
    fn wm_from_bytes_too_short_rejected() {
        assert!(matches!(
            SessionWatermark::from_bytes(&[0u8; 15]),
            Err(CryptoError::MalformedMessage)
        ));
    }
}
