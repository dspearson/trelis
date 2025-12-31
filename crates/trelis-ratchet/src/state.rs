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
pub fn derive_key_id(public_key: &HybridKemPublicKey) -> KeyId {
    // Use incremental hashing to avoid 1,214-byte stack allocation
    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key.x448().as_bytes());
    hasher.update(public_key.sntrup().as_bytes());
    let hash = hasher.finalize();
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
            previous_keypairs: VecDeque::new(),
            their_public_key: Some(their_public_key),
            their_key_id: Some(their_key_id),
            root_key: derive_initial_root_key(session_key),
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
    pub fn init_responder(
        session_key: &[u8; 32],
        our_keypair: HybridKemKeypair,
        current_time: u64,
    ) -> Self {
        let our_key_id = derive_key_id(our_keypair.public_key());

        Self {
            our_keypair,
            our_key_id,
            previous_keypairs: VecDeque::new(),
            their_public_key: None,
            their_key_id: None,
            root_key: derive_initial_root_key(session_key),
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
                if self.their_public_key.is_none() {
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
        // Move current keypair to previous
        if self.previous_keypairs.len() >= MAX_PREVIOUS_KEYPAIRS {
            self.previous_keypairs.pop_front();
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
        self.root_key.zeroize();
        // Note: keypairs should implement Zeroize as well
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
}
