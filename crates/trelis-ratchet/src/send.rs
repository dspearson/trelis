//! KEM Ratchet encryption (send) path.
//!
//! Encrypts plaintext by:
//! 1. Generating a fresh hybrid keypair
//! 2. Encapsulating to recipient's public key
//! 3. Deriving message key via KDF
//! 4. Encrypting with XChaCha20-Poly1305

use trelis_error::Result;
use trelis_hybrid::HybridKemKeypair;
use trelis_primitives::aead::{self, AeadKey, Nonce};
use zeroize::Zeroize;

use crate::header::{MessageHeader, RatchetMessage};
use crate::kdf::kdf_rk;
use crate::nonce::derive_hedged_nonce;
use crate::state::{KemRatchet, RatchetStatus};

/// Result of a send operation.
///
/// Contains the encrypted message to transmit and metadata about the
/// state update that occurred. The caller must send the message over
/// the network to complete the operation.
///
/// # Usage
///
/// ```ignore
/// let result = send_message(&mut ratchet_state, plaintext, timestamp)?;
///
/// // Send the encrypted message
/// network.send(result.message().to_bytes());
///
/// // Check if state was updated (always true for successful sends)
/// assert!(result.state_updated());
/// ```
///
/// # Per-Message Forward Secrecy
///
/// Each send operation generates a fresh hybrid keypair. The previous
/// keypair is retained temporarily for async message handling, but the
/// message key is deleted immediately after encryption.
#[cfg(feature = "alloc")]
pub struct SendResult {
    /// The encrypted message to send.
    pub message: RatchetMessage,
    /// Whether the ratchet state was updated.
    /// Always true for successful sends.
    state_updated: bool,
}

#[cfg(feature = "alloc")]
impl SendResult {
    /// Returns the encrypted message.
    #[must_use]
    pub fn message(&self) -> &RatchetMessage {
        &self.message
    }

    /// Checks if state was updated.
    #[must_use]
    pub fn state_updated(&self) -> bool {
        self.state_updated
    }
}

/// Encrypts plaintext and advances the ratchet state.
///
/// This is the main send function. It:
/// 1. Validates the session state
/// 2. Generates a fresh hybrid keypair
/// 3. Encapsulates to the recipient's public key
/// 4. Derives the message key via KDF
/// 5. Generates a hedged nonce
/// 6. Encrypts with XChaCha20-Poly1305
/// 7. Updates the ratchet state
///
/// # Arguments
///
/// * `state` - Mutable reference to the ratchet state
/// * `plaintext` - The message to encrypt
/// * `current_time` - Current Unix timestamp
///
/// # Returns
///
/// A `SendResult` containing the encrypted message.
///
/// # Errors
///
/// - `NoActiveSession` if the session is not active
/// - `SessionCompromised` if the session was compromised
/// - `NoRecipientKey` if recipient's public key is unknown
/// - `SessionExhausted` if the message counter is near overflow
/// - `RngFailure` if random number generation fails
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn send_message(
    state: &mut KemRatchet,
    plaintext: &[u8],
    current_time: u64,
) -> Result<SendResult> {
    // Step 1: Validate state
    state.validate_can_send()?;

    // Step 2: Generate fresh hybrid keypair
    let new_keypair = HybridKemKeypair::generate()?;

    // Step 3: Encapsulate to recipient's public key
    let their_pk = state
        .their_public_key()
        .expect("validated in validate_can_send");
    let (shared_secret, encapsulation) = their_pk.encapsulate()?;

    // Step 4: Derive keys via KDF
    let mut kdf_output = kdf_rk(state.root_key(), shared_secret.as_bytes());

    // Step 5: Build header
    let header = MessageHeader::new(
        state.their_key_id().expect("validated"),
        new_keypair.public_key().clone(),
        encapsulation,
        state.send_count(),
    );

    // Step 6: Generate hedged nonce
    let nonce = derive_hedged_nonce(state.send_count(), &kdf_output.message_key)?;

    // Step 7: Encrypt with header as AAD
    let aad = header.to_bytes();
    let aead_key = AeadKey::from_bytes(kdf_output.message_key);
    let aead_nonce = Nonce::from_bytes(nonce);
    let ciphertext = aead::encrypt(&aead_key, &aead_nonce, plaintext, &aad)?;

    // Step 8: Update state atomically
    state.rotate_keypair(new_keypair);
    state.set_root_key(kdf_output.new_root_key);
    state.increment_send_count();
    state.set_status(RatchetStatus::AwaitingReply);
    state.set_last_activity(current_time);

    // Step 9: Zeroize sensitive material
    kdf_output.zeroize();

    let message = RatchetMessage {
        header,
        nonce,
        ciphertext,
    };

    Ok(SendResult {
        message,
        state_updated: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_message() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let plaintext = b"Hello, World!";
        let result = send_message(&mut state, plaintext, 1001).unwrap();

        // Check message structure
        assert_eq!(result.message.header.message_number, 0);
        assert!(!result.message.ciphertext.is_empty());

        // Check state was updated
        assert_eq!(state.send_count(), 1);
        assert_eq!(state.status(), RatchetStatus::AwaitingReply);
    }

    #[test]
    fn test_send_multiple_messages() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        // Send multiple messages
        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            let result = send_message(&mut state, plaintext.as_bytes(), 1000 + i).unwrap();
            assert_eq!(result.message.header.message_number, i);
        }

        assert_eq!(state.send_count(), 5);
    }

    #[test]
    fn test_send_rotates_keypair() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let original_key_id = state.our_key_id();

        send_message(&mut state, b"test", 1001).unwrap();

        // Key should have rotated
        assert_ne!(state.our_key_id(), original_key_id);
        // Original should still be in previous keypairs
        assert!(state.find_keypair(original_key_id).is_some());
    }

    #[test]
    fn test_send_without_recipient_fails() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let mut state = KemRatchet::init_responder(&session_key, our_keypair, 1000);

        let result = send_message(&mut state, b"test", 1001);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_different_sender_key_each_message() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        let result1 = send_message(&mut state, b"message 1", 1001).unwrap();
        let result2 = send_message(&mut state, b"message 2", 1002).unwrap();

        // Each message should have a different sender public key
        assert_ne!(
            result1.message.header.sender_public_key.to_bytes(),
            result2.message.header.sender_public_key.to_bytes()
        );
    }
}
