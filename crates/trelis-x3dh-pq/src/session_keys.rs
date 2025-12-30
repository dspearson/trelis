//! Session key derivation from X3DH-PQ shared secret.
//!
//! After the X3DH-PQ handshake completes, both parties have a shared secret.
//! This module derives the session keys used by the Double Ratchet:
//!
//! - **Root key**: Seeds the symmetric ratchet
//! - **Send chain key**: Initial sending chain (direction depends on role)
//! - **Receive chain key**: Initial receiving chain

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::transcript::HASH_SIZE;

/// Context for deriving the root key.
const ROOT_KEY_CONTEXT: &str = "trelis-root-key-v1";

/// Context for deriving the send chain key (for initiator).
const SEND_CHAIN_CONTEXT: &str = "trelis-send-chain-v1";

/// Context for deriving the receive chain key (for initiator).
const RECV_CHAIN_CONTEXT: &str = "trelis-recv-chain-v1";

/// Session keys derived from X3DH-PQ handshake.
///
/// These keys initialise the Double Ratchet state machine.
/// The root key seeds the symmetric ratchet, while the chain
/// keys provide the initial sending/receiving states.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Root key for the Double Ratchet (32 bytes).
    root_key: [u8; HASH_SIZE],
    /// Initial sending chain key (32 bytes).
    send_chain_key: [u8; HASH_SIZE],
    /// Initial receiving chain key (32 bytes).
    recv_chain_key: [u8; HASH_SIZE],
}

impl SessionKeys {
    /// Derives session keys from the shared secret.
    ///
    /// Uses BLAKE3 derive_key with different contexts for each key
    /// to ensure cryptographic separation.
    #[must_use]
    pub fn derive(shared_secret: &[u8; HASH_SIZE]) -> Self {
        Self {
            root_key: blake3::derive_key(ROOT_KEY_CONTEXT, shared_secret),
            send_chain_key: blake3::derive_key(SEND_CHAIN_CONTEXT, shared_secret),
            recv_chain_key: blake3::derive_key(RECV_CHAIN_CONTEXT, shared_secret),
        }
    }

    /// Returns the root key.
    #[must_use]
    pub fn root_key(&self) -> &[u8; HASH_SIZE] {
        &self.root_key
    }

    /// Returns the send chain key.
    ///
    /// For the initiator (Alice), this is the sending direction.
    /// For the responder (Bob), this becomes the receiving direction.
    #[must_use]
    pub fn send_chain_key(&self) -> &[u8; HASH_SIZE] {
        &self.send_chain_key
    }

    /// Returns the receive chain key.
    ///
    /// For the initiator (Alice), this is the receiving direction.
    /// For the responder (Bob), this becomes the sending direction.
    #[must_use]
    pub fn recv_chain_key(&self) -> &[u8; HASH_SIZE] {
        &self.recv_chain_key
    }

    /// Returns a copy of the session keys with swapped directions.
    ///
    /// Used by the responder to get keys in the correct orientation.
    #[must_use]
    pub fn swap_directions(&self) -> Self {
        Self {
            root_key: self.root_key,
            send_chain_key: self.recv_chain_key,
            recv_chain_key: self.send_chain_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = [0x42u8; 32];
        let keys = SessionKeys::derive(&shared_secret);

        // Keys should be 32 bytes
        assert_eq!(keys.root_key().len(), 32);
        assert_eq!(keys.send_chain_key().len(), 32);
        assert_eq!(keys.recv_chain_key().len(), 32);

        // All keys should be different
        assert_ne!(keys.root_key(), keys.send_chain_key());
        assert_ne!(keys.root_key(), keys.recv_chain_key());
        assert_ne!(keys.send_chain_key(), keys.recv_chain_key());
    }

    #[test]
    fn test_deterministic_derivation() {
        let shared_secret = [0xABu8; 32];

        let keys1 = SessionKeys::derive(&shared_secret);
        let keys2 = SessionKeys::derive(&shared_secret);

        assert_eq!(keys1.root_key(), keys2.root_key());
        assert_eq!(keys1.send_chain_key(), keys2.send_chain_key());
        assert_eq!(keys1.recv_chain_key(), keys2.recv_chain_key());
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let secret1 = [0x01u8; 32];
        let secret2 = [0x02u8; 32];

        let keys1 = SessionKeys::derive(&secret1);
        let keys2 = SessionKeys::derive(&secret2);

        assert_ne!(keys1.root_key(), keys2.root_key());
        assert_ne!(keys1.send_chain_key(), keys2.send_chain_key());
        assert_ne!(keys1.recv_chain_key(), keys2.recv_chain_key());
    }

    #[test]
    fn test_swap_directions() {
        let shared_secret = [0x55u8; 32];
        let keys = SessionKeys::derive(&shared_secret);
        let swapped = keys.swap_directions();

        // Root key stays the same
        assert_eq!(keys.root_key(), swapped.root_key());

        // Send and receive are swapped
        assert_eq!(keys.send_chain_key(), swapped.recv_chain_key());
        assert_eq!(keys.recv_chain_key(), swapped.send_chain_key());
    }
}
