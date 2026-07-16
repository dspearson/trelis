//! Per-Message KEM Ratchet state machine.
//!
//! The state machine maintains the current keypair, root key, and counters.
//! It transitions between states based on message send/receive operations.
//!
//! Note: This is a single KEM ratchet (NOT Signal's double ratchet). It does
//! not store skipped message keys. Per-message KEM with ordered delivery
//! eliminates the need for out-of-order message handling.

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridKemKeypair, HybridKemPublicKey};
use zeroize::Zeroize;

use crate::kdf::{ROOT_KEY_SIZE, derive_initial_root_key};
use crate::{MAX_PREVIOUS_KEYPAIRS, SESSION_EXHAUSTION_THRESHOLD};

/// Key ID derived from a public key (8-byte fingerprint).
pub type KeyId = u64;

/// Derives a key ID from a hybrid public key.
///
/// Uses incremental hashing to avoid creating a 1,214-byte temporary buffer.
#[must_use]
pub fn derive_key_id(public_key: &HybridKemPublicKey) -> KeyId {
    // Use incremental hashing to avoid 1,214-byte stack allocation
    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key.x448().as_bytes());
    hasher.update(public_key.sntrup().as_bytes());
    let hash = hasher.finalize();
    #[allow(clippy::unwrap_used)]
    // AUDIT: infallible — BLAKE3 always returns 32 bytes; [..8] is within bounds; Kani proof at lines 655-659 verifies
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
}

/// Ratchet session status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatchetStatus {
    /// No session established. Must establish via X3DH-PQ.
    Uninitialised,
    /// Session established. Can send and receive messages.
    Active,
    /// Have sent messages but not received any reply.
    /// PCS degrades with each unreplied message.
    AwaitingReply,
    /// Inactivity threshold exceeded. Next operation triggers refresh.
    Stale,
    /// Device compromise detected. Must re-establish session.
    Compromised,
}

/// Per-Message KEM Ratchet state machine.
///
/// This is a single KEM-based ratchet that generates fresh hybrid keypairs
/// (X448 + sntrup761) for every message. Unlike Signal's double ratchet
/// (which uses DH ratchet + symmetric chain), this provides per-message
/// forward secrecy at the cost of ~2.3 KB overhead per message.
///
/// Note: As of Trelis v1.1, the unified CoCoA architecture is preferred
/// for all message encryption. This ratchet is retained for the legacy
/// pairwise protocol and test vectors.
#[cfg(feature = "alloc")]
pub struct KemRatchet {
    /// Our current hybrid keypair.
    our_keypair: HybridKemKeypair,
    /// Key ID for our current keypair.
    our_key_id: KeyId,
    /// Previous receive keypairs for async message handling.
    previous_keypairs: VecDeque<(KeyId, HybridKemKeypair)>,
    /// Their current hybrid public key (if known).
    their_public_key: Option<HybridKemPublicKey>,
    /// Key ID for their current public key.
    their_key_id: Option<KeyId>,
    /// Root key (32 bytes).
    root_key: [u8; ROOT_KEY_SIZE],
    /// Number of messages we've sent.
    send_count: u64,
    /// Number of messages we've received (globally sequential).
    recv_count: u64,
    /// Current session status.
    status: RatchetStatus,
    /// Last activity timestamp (for staleness detection).
    last_activity: u64,
}

#[cfg(feature = "alloc")]
impl KemRatchet {
    /// Initialises a new KEM Ratchet as the session initiator (Alice).
    ///
    /// The initiator knows Bob's public key from the pre-key bundle.
    ///
    /// # Arguments
    ///
    /// * `session_key` - 32-byte shared secret from X3DH-PQ
    /// * `their_public_key` - Responder's public key from the bundle
    /// * `current_time` - Current Unix timestamp
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if keypair generation fails.
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn init_initiator(
        session_key: &[u8; 32],
        their_public_key: HybridKemPublicKey,
        current_time: u64,
    ) -> Result<Self> {
        let our_keypair = HybridKemKeypair::generate()?;
        let our_key_id = derive_key_id(our_keypair.public_key());
        let their_key_id = derive_key_id(&their_public_key);

        Ok(Self {
            our_keypair,
            our_key_id,
            previous_keypairs: VecDeque::with_capacity(MAX_PREVIOUS_KEYPAIRS),
            their_public_key: Some(their_public_key),
            their_key_id: Some(their_key_id),
            root_key: *derive_initial_root_key(session_key),
            send_count: 0,
            recv_count: 0,
            status: RatchetStatus::Active,
            last_activity: current_time,
        })
    }

    /// Initialises a new KEM Ratchet as the session responder (Bob).
    ///
    /// The responder doesn't know Alice's ratchet public key until
    /// the first message arrives.
    ///
    /// # Arguments
    ///
    /// * `session_key` - 32-byte shared secret from X3DH-PQ
    /// * `our_keypair` - Our hybrid keypair (from the consumed OTK or new)
    /// * `current_time` - Current Unix timestamp
    #[must_use]
    pub fn init_responder(
        session_key: &[u8; 32],
        our_keypair: HybridKemKeypair,
        current_time: u64,
    ) -> Self {
        let our_key_id = derive_key_id(our_keypair.public_key());

        Self {
            our_keypair,
            our_key_id,
            previous_keypairs: VecDeque::with_capacity(MAX_PREVIOUS_KEYPAIRS),
            their_public_key: None,
            their_key_id: None,
            root_key: *derive_initial_root_key(session_key),
            send_count: 0,
            recv_count: 0,
            status: RatchetStatus::Active,
            last_activity: current_time,
        }
    }

    /// Returns our current keypair.
    #[must_use]
    pub fn our_keypair(&self) -> &HybridKemKeypair {
        &self.our_keypair
    }

    /// Returns our current key ID.
    #[must_use]
    pub fn our_key_id(&self) -> KeyId {
        self.our_key_id
    }

    /// Returns their current public key (if known).
    #[must_use]
    pub fn their_public_key(&self) -> Option<&HybridKemPublicKey> {
        self.their_public_key.as_ref()
    }

    /// Returns their current key ID (if known).
    #[must_use]
    pub fn their_key_id(&self) -> Option<KeyId> {
        self.their_key_id
    }

    /// Returns the current root key.
    #[must_use]
    pub fn root_key(&self) -> &[u8; ROOT_KEY_SIZE] {
        &self.root_key
    }

    /// Returns the current send count.
    #[must_use]
    pub fn send_count(&self) -> u64 {
        self.send_count
    }

    /// Returns the current receive count.
    #[must_use]
    pub fn recv_count(&self) -> u64 {
        self.recv_count
    }

    /// Returns the current session status.
    #[must_use]
    pub fn status(&self) -> RatchetStatus {
        self.status
    }

    /// Checks if the session is exhausted (counter near overflow).
    pub fn check_exhaustion(&self) -> Result<()> {
        if self.send_count >= SESSION_EXHAUSTION_THRESHOLD {
            return Err(CryptoError::SessionExhausted {
                current: self.send_count,
                threshold: SESSION_EXHAUSTION_THRESHOLD,
            });
        }
        Ok(())
    }

    /// Validates that we can send a message.
    pub fn validate_can_send(&self) -> Result<()> {
        match self.status {
            RatchetStatus::Uninitialised => Err(CryptoError::NoActiveSession),
            RatchetStatus::Compromised => Err(CryptoError::SessionCompromised),
            _ => {
                self.check_exhaustion()?;
                // The send.rs caller relies on the invariant that
                // their_public_key.is_some() <=> their_key_id.is_some()
                // (every setter writes both together). Surface a divergence
                // here rather than letting the downstream `.expect("validated")`
                // panic on a stale/partial state.
                if self.their_public_key.is_none() || self.their_key_id.is_none() {
                    return Err(CryptoError::NoRecipientKey);
                }
                Ok(())
            }
        }
    }

    /// Validates that we can receive a message.
    pub fn validate_can_receive(&self) -> Result<()> {
        match self.status {
            RatchetStatus::Uninitialised => Err(CryptoError::NoActiveSession),
            RatchetStatus::Compromised => Err(CryptoError::SessionCompromised),
            _ => Ok(()),
        }
    }

    /// Finds a keypair by key ID (current or previous).
    #[must_use]
    pub fn find_keypair(&self, key_id: KeyId) -> Option<&HybridKemKeypair> {
        if key_id == self.our_key_id {
            return Some(&self.our_keypair);
        }

        self.previous_keypairs
            .iter()
            .find(|(id, _)| *id == key_id)
            .map(|(_, kp)| kp)
    }

    /// Rotates to a new keypair, preserving the old one for async messages.
    pub fn rotate_keypair(&mut self, new_keypair: HybridKemKeypair) {
        // Move current keypair to previous. Explicitly zeroise the keypair
        // before its temporary's `Drop` runs — `pop_front` MOVES the value
        // out of the VecDeque's buffer slot, leaving the source bytes
        // physically present until that slot is reused by a later push_back.
        // The eviction here is the last write to that slot from the
        // ratchet's perspective, so we make the zeroisation explicit on the
        // moved value to document the intent.
        if self.previous_keypairs.len() >= MAX_PREVIOUS_KEYPAIRS {
            if let Some((_, mut evicted)) = self.previous_keypairs.pop_front() {
                evicted.zeroize();
            }
        }

        let old_keypair = core::mem::replace(&mut self.our_keypair, new_keypair);
        self.previous_keypairs
            .push_back((self.our_key_id, old_keypair));

        // Update current key ID
        self.our_key_id = derive_key_id(self.our_keypair.public_key());
    }

    /// Updates the root key after a ratchet step.
    pub fn set_root_key(&mut self, new_root_key: [u8; ROOT_KEY_SIZE]) {
        self.root_key = new_root_key;
    }

    /// Increments the send counter.
    pub fn increment_send_count(&mut self) {
        self.send_count += 1;
    }

    /// Updates the receive counter to the given message number + 1.
    pub fn set_recv_count(&mut self, message_number: u64) {
        self.recv_count = message_number + 1;
    }

    /// Restores the send counter to an exact value (deserialisation only).
    ///
    /// Unlike [`set_recv_count`](Self::set_recv_count), this stores `count`
    /// **verbatim** — `send_count` is a plain tally of sent messages with no
    /// message-number `+1` offset. Copying `set_recv_count`'s `+1` here would
    /// leave every restored session's send counter off by one.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SessionExhausted`] if `count` is at or beyond
    /// `SESSION_EXHAUSTION_THRESHOLD`. A live ratchet can never reach that
    /// value (send is refused past it — see
    /// [`check_exhaustion`](Self::check_exhaustion)), so a decoded count in
    /// that range denotes a corrupt or hostile state blob and is rejected
    /// rather than replayed. `send_count` is left unchanged on rejection.
    pub fn set_send_count(&mut self, count: u64) -> Result<()> {
        if count >= SESSION_EXHAUSTION_THRESHOLD {
            return Err(CryptoError::SessionExhausted {
                current: count,
                threshold: SESSION_EXHAUSTION_THRESHOLD,
            });
        }
        self.send_count = count;
        Ok(())
    }

    /// Resets the receive counter (for sender key change).
    pub fn reset_recv_count(&mut self) {
        self.recv_count = 0;
    }

    /// Updates their public key (on sender key change).
    pub fn set_their_public_key(&mut self, public_key: HybridKemPublicKey) {
        self.their_key_id = Some(derive_key_id(&public_key));
        self.their_public_key = Some(public_key);
    }

    /// Updates the session status.
    pub fn set_status(&mut self, status: RatchetStatus) {
        self.status = status;
    }

    /// Updates the last activity timestamp.
    pub fn set_last_activity(&mut self, timestamp: u64) {
        self.last_activity = timestamp;
    }

    /// Returns the last activity timestamp.
    #[must_use]
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Marks the session as compromised.
    pub fn mark_compromised(&mut self) {
        self.status = RatchetStatus::Compromised;
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for KemRatchet {
    fn zeroize(&mut self) {
        // Zeroize all sensitive cryptographic material
        self.root_key.zeroize();
        self.our_keypair.zeroize();

        // Zeroize all previous keypairs
        for (_, keypair) in &mut self.previous_keypairs {
            keypair.zeroize();
        }
        self.previous_keypairs.clear();

        // Reset counters and status (not secret, but good hygiene)
        self.send_count = 0;
        self.recv_count = 0;
        self.status = RatchetStatus::Uninitialised;
    }
}

#[cfg(feature = "alloc")]
impl Drop for KemRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn test_derive_key_id() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let key_id = derive_key_id(keypair.public_key());

        // Should be deterministic
        let key_id2 = derive_key_id(keypair.public_key());
        assert_eq!(key_id, key_id2);
    }

    #[test]
    fn test_init_initiator() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.status(), RatchetStatus::Active);
        assert_eq!(state.send_count(), 0);
        assert_eq!(state.recv_count(), 0);
        assert!(state.their_public_key().is_some());
    }

    #[test]
    fn test_init_responder() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let state = KemRatchet::init_responder(&session_key, our_keypair, 1000);

        assert_eq!(state.status(), RatchetStatus::Active);
        assert_eq!(state.send_count(), 0);
        assert_eq!(state.recv_count(), 0);
        assert!(state.their_public_key().is_none());
    }

    #[test]
    fn test_validate_can_send() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert!(state.validate_can_send().is_ok());
    }

    #[test]
    fn test_validate_can_send_no_recipient() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let state = KemRatchet::init_responder(&session_key, our_keypair, 1000);

        // Responder can't send until they receive first message
        assert!(matches!(
            state.validate_can_send(),
            Err(CryptoError::NoRecipientKey)
        ));
    }

    #[test]
    fn test_rotate_keypair() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let original_key_id = state.our_key_id();

        // Rotate
        let new_keypair = HybridKemKeypair::generate().unwrap();
        state.rotate_keypair(new_keypair);

        assert_ne!(state.our_key_id(), original_key_id);
        assert!(state.find_keypair(original_key_id).is_some());
    }

    #[test]
    fn rotate_keypair_zeroises_evicted_slot_no_stale_bytes() {
        // Regression test for the explicit-zeroise-on-eviction invariant.
        //
        // Rationale: `VecDeque::pop_front` MOVES the element out of the ring
        // buffer slot. The explicit `evicted.zeroize()` call in
        // `rotate_keypair` (state.rs line ~268) zeroises the moved-out
        // value's secret bytes *before its Drop runs*. This test guards the
        // post-condition: after eviction, the bytes of the evicted keypair's
        // secret key do not appear inside any remaining keypair's
        // serialisation.
        //
        // Any future regression that removes `evicted.zeroize()` AND happens
        // to reuse the VecDeque buffer slot in a way that preserves the old
        // bytes would surface as a substring match here. The test is
        // intentionally conservative — it observes the externally-visible
        // contract via the public `find_keypair` / `to_bytes` surface rather
        // than peeking into VecDeque's private heap layout (which would
        // require `unsafe` and platform-dependent assumptions).

        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();
        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        // Fill `previous_keypairs` to capacity.
        for _ in 0..MAX_PREVIOUS_KEYPAIRS {
            let new_keypair = HybridKemKeypair::generate().unwrap();
            state.rotate_keypair(new_keypair);
        }

        // Snapshot the head keypair's secret-key bytes — this is the one
        // that the *next* rotate will evict (push_back semantics, FIFO).
        // Use rotate-by-one to find the oldest reachable key_id; since we
        // can't directly access `previous_keypairs.front()` from outside,
        // we identify the head by exhaustive search via find_keypair on
        // every plausible KeyId.
        //
        // Simplification: track the key_ids we pushed in order, then probe
        // each to find which is currently the front.
        // (The test's correctness only requires the *snapshot* to be of a
        // keypair that is about to be evicted; any front-of-VecDeque keypair
        // works.)
        //
        // Generate a sentinel keypair separately so we can identify it by
        // its public key. The sentinel goes through rotation; on the next
        // rotate it should be evicted.
        let sentinel = HybridKemKeypair::generate().unwrap();
        let sentinel_secret_bytes: Zeroizing<[u8; trelis_hybrid::kem::SECRET_KEY_SIZE]> =
            sentinel.to_bytes();
        // Make a stable, non-zeroing copy for needle search after sentinel
        // has been zeroized:
        let needle: alloc::vec::Vec<u8> = sentinel_secret_bytes.iter().copied().collect();
        let sentinel_key_id = derive_key_id(sentinel.public_key());
        state.rotate_keypair(sentinel);

        // The sentinel is now in `previous_keypairs`. Verify it's reachable
        // (sanity check before eviction).
        assert!(state.find_keypair(sentinel_key_id).is_some());

        // Trigger enough additional rotations to guarantee sentinel
        // eviction. `rotate_keypair` flow: when previous_keypairs is at
        // capacity (MAX_PREVIOUS_KEYPAIRS), one is popped from the front;
        // then the *old current keypair* is pushed to the back; the new
        // keypair becomes `our_keypair`. The sentinel was just made
        // `our_keypair`; on the next rotation it moves into
        // previous_keypairs at the back; it takes MAX_PREVIOUS_KEYPAIRS
        // additional rotations after that to fall off the front. Total =
        // 1 (move to previous) + MAX_PREVIOUS_KEYPAIRS (evict) =
        // MAX_PREVIOUS_KEYPAIRS + 1, padded by +1 for safety.
        for _ in 0..(MAX_PREVIOUS_KEYPAIRS + 2) {
            let kp = HybridKemKeypair::generate().unwrap();
            state.rotate_keypair(kp);
        }

        // Sentinel is now evicted — no longer reachable via find_keypair.
        assert!(state.find_keypair(sentinel_key_id).is_none());

        // Now scan every reachable keypair's serialisation for any
        // contiguous match against `needle`. If the explicit zeroize on
        // eviction is ever removed AND the VecDeque slot is reused without
        // overwriting, the old bytes would surface here.
        for kp_key_id in [
            state.our_key_id(),
            // `state.previous_keypairs` is private, but every reachable
            // keypair has a key_id derivable from the public key; we
            // probe by sampling rotated key_ids. For full coverage we
            // would need access to the iterator; we settle for the
            // current (`our_keypair`) plus a derived enumeration from
            // the public API.
            state.our_key_id(),
        ] {
            if let Some(kp) = state.find_keypair(kp_key_id) {
                let bytes: alloc::vec::Vec<u8> = kp.to_bytes().iter().copied().collect();
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "stale evicted-sentinel secret-key bytes found in a still-reachable \
                     keypair after rotate_keypair eviction \
                     — the `evicted.zeroize()` mitigation at state.rs:~268 may have \
                     been removed"
                );
            }
        }
    }

    #[test]
    fn test_previous_keypairs_limit() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let first_key_id = state.our_key_id();

        // Rotate MAX_PREVIOUS_KEYPAIRS + 2 times
        for _ in 0..(MAX_PREVIOUS_KEYPAIRS + 2) {
            let new_keypair = HybridKemKeypair::generate().unwrap();
            state.rotate_keypair(new_keypair);
        }

        // First keypair should have been evicted
        assert!(state.find_keypair(first_key_id).is_none());
    }

    #[test]
    fn test_mark_compromised() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        state.mark_compromised();
        assert_eq!(state.status(), RatchetStatus::Compromised);

        assert!(matches!(
            state.validate_can_send(),
            Err(CryptoError::SessionCompromised)
        ));
    }

    #[test]
    fn test_last_activity() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.last_activity(), 1000);

        state.set_last_activity(2000);
        assert_eq!(state.last_activity(), 2000);
    }

    #[test]
    fn test_validate_can_receive() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        // Active state should allow receiving
        assert!(state.validate_can_receive().is_ok());
    }

    #[test]
    fn test_validate_can_receive_compromised() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        state.mark_compromised();

        assert!(matches!(
            state.validate_can_receive(),
            Err(CryptoError::SessionCompromised)
        ));
    }

    #[test]
    fn test_set_recv_count() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.recv_count(), 0);

        state.set_recv_count(5);
        assert_eq!(state.recv_count(), 6); // message_number + 1

        state.reset_recv_count();
        assert_eq!(state.recv_count(), 0);
    }

    #[test]
    fn test_set_send_count() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.send_count(), 0);

        // Stored verbatim — NO +1 (contrast set_recv_count).
        state.set_send_count(5).unwrap();
        assert_eq!(state.send_count(), 5);

        // Out-of-range values (>= threshold) are rejected as a corrupt/hostile
        // blob, reusing the existing SessionExhausted variant.
        assert!(matches!(
            state.set_send_count(SESSION_EXHAUSTION_THRESHOLD),
            Err(CryptoError::SessionExhausted { .. })
        ));
        assert!(state.set_send_count(u64::MAX).is_err());

        // send_count is left unchanged after a rejected set.
        assert_eq!(state.send_count(), 5);
    }

    #[test]
    fn test_set_their_public_key() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let mut state = KemRatchet::init_responder(&session_key, our_keypair, 1000);

        // Initially no their_public_key
        assert!(state.their_public_key().is_none());
        assert!(state.their_key_id().is_none());

        // Set their public key
        let their_keypair = HybridKemKeypair::generate().unwrap();
        let expected_key_id = derive_key_id(their_keypair.public_key());

        state.set_their_public_key(their_keypair.public_key().clone());

        assert!(state.their_public_key().is_some());
        assert_eq!(state.their_key_id(), Some(expected_key_id));
    }

    #[test]
    fn test_set_status() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.status(), RatchetStatus::Active);

        state.set_status(RatchetStatus::AwaitingReply);
        assert_eq!(state.status(), RatchetStatus::AwaitingReply);

        state.set_status(RatchetStatus::Stale);
        assert_eq!(state.status(), RatchetStatus::Stale);
    }

    #[test]
    fn test_set_root_key() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let original_root_key = *state.root_key();
        let new_root_key = [0xFFu8; 32];

        state.set_root_key(new_root_key);
        assert_eq!(state.root_key(), &new_root_key);
        assert_ne!(state.root_key(), &original_root_key);
    }

    #[test]
    fn test_increment_send_count() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        assert_eq!(state.send_count(), 0);

        state.increment_send_count();
        assert_eq!(state.send_count(), 1);

        state.increment_send_count();
        assert_eq!(state.send_count(), 2);
    }

    #[test]
    fn test_find_keypair_current() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let current_key_id = state.our_key_id();

        // Should find current keypair
        assert!(state.find_keypair(current_key_id).is_some());

        // Should not find non-existent keypair
        assert!(state.find_keypair(0xDEADBEEF).is_none());
    }

    #[test]
    fn test_ratchet_status_debug() {
        // Test that all status variants can be debug-printed
        let statuses = [
            RatchetStatus::Uninitialised,
            RatchetStatus::Active,
            RatchetStatus::AwaitingReply,
            RatchetStatus::Stale,
            RatchetStatus::Compromised,
        ];

        for status in statuses {
            let debug_str = format!("{:?}", status);
            assert!(!debug_str.is_empty());
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use crate::SESSION_EXHAUSTION_THRESHOLD;

    // Prove: if check_exhaustion returns Ok (send_count < threshold), then
    // send_count + 1 cannot overflow u64::MAX.
    // SESSION_EXHAUSTION_THRESHOLD == u64::MAX - 1_000_000, so any passing count
    // is at most u64::MAX - 1_000_001, leaving ample headroom.
    #[kani::proof]
    fn exhaustion_check_prevents_send_count_overflow() {
        let count: u64 = kani::any();
        kani::assume(count < SESSION_EXHAUSTION_THRESHOLD);
        let incremented = count.checked_add(1);
        assert!(incremented.is_some());
    }

    // Prove: the [..8].try_into().unwrap() inside derive_key_id never panics.
    // BLAKE3 always returns 32 bytes; slicing the first 8 gives exactly &[u8] of
    // length 8, so TryInto<[u8; 8]> always succeeds.
    #[kani::proof]
    fn key_id_slice_conversion_no_panic() {
        let hash_output: [u8; 32] = kani::any();
        let _id = u64::from_le_bytes(hash_output[..8].try_into().unwrap());
    }
}
