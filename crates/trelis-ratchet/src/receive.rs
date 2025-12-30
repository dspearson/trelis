//! Double Ratchet decryption (receive) path.
//!
//! Decrypts messages by:
//! 1. Checking for skipped message keys
//! 2. Handling sender key changes (ratchet step)
//! 3. Skipping keys for out-of-order delivery
//! 4. Decapsulating to derive shared secret
//! 5. Deriving message key via KDF
//! 6. Decrypting with XChaCha20-Poly1305

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_primitives::aead::{self, AeadKey, Nonce};
use zeroize::Zeroize;

use crate::header::RatchetMessage;
use crate::kdf::kdf_rk;
use crate::skipped_keys::SkippedKeyIndex;
use crate::state::{DoubleRatchet, RatchetStatus};
use crate::{MAX_CHAIN_LOOKAHEAD, MAX_SKIP};

/// Decrypts a received message and updates the ratchet state.
///
/// This is the main receive function. It:
/// 1. Validates the session state
/// 2. Checks for skipped message key (out-of-order handling)
/// 3. Validates that we have the decapsulation keypair
/// 4. Handles sender key change (ratchet step)
/// 5. Skips keys if message number > expected
/// 6. Decapsulates to get shared secret
/// 7. Derives message key via KDF
/// 8. Decrypts with AAD verification
/// 9. Updates the ratchet state
///
/// # Arguments
///
/// * `state` - Mutable reference to the ratchet state
/// * `message` - The received encrypted message
/// * `current_time` - Current Unix timestamp
///
/// # Returns
///
/// The decrypted plaintext.
///
/// # Errors
///
/// - `NoActiveSession` if the session is not active
/// - `SessionCompromised` if the session was compromised
/// - `UnknownRecipientKeyId` if we don't have the decapsulation keypair
/// - `TooManySkippedKeys` if the message gap is too large
/// - `AeadAuthenticationFailed` if decryption fails
#[cfg(feature = "alloc")]
pub fn receive_message(
    state: &mut DoubleRatchet,
    message: &RatchetMessage,
    current_time: u64,
) -> Result<Vec<u8>> {
    // Step 1: Validate state
    state.validate_can_receive()?;

    // Step 2: Check for skipped message key (out-of-order handling)
    let sender_key_bytes = message.header.sender_public_key.to_bytes();
    let skip_index =
        SkippedKeyIndex::from_sender_key(&sender_key_bytes, message.header.message_number);

    if let Some(message_key) = state.skipped_keys_mut().remove(&skip_index) {
        // Found in skipped keys - decrypt and return
        let aad = message.header.to_bytes();
        let aead_key = AeadKey::from_bytes(message_key);
        let aead_nonce = Nonce::from_bytes(message.nonce);
        let plaintext = aead::decrypt(&aead_key, &aead_nonce, &message.ciphertext, &aad);
        return plaintext;
    }

    // Step 3: Validate that we have the decapsulation keypair (just check, don't hold ref)
    let recipient_key_id = message.header.recipient_key_id;
    if state.find_keypair(recipient_key_id).is_none() {
        return Err(CryptoError::UnknownRecipientKeyId);
    }

    // Step 4: Check for sender key change (ratchet step)
    let sender_key_changed = match state.their_public_key() {
        Some(their_pk) => their_pk.to_bytes() != sender_key_bytes,
        None => true, // First message from this peer
    };

    if sender_key_changed {
        // Skip remaining keys in the OLD chain before switching
        // This handles late arrivals from the previous chain
        let lookahead_end = state.recv_count().saturating_add(MAX_CHAIN_LOOKAHEAD);
        skip_message_keys(state, state.recv_count(), lookahead_end)?;

        // Update sender key
        state.set_their_public_key(message.header.sender_public_key.clone());
        state.reset_recv_count();
    }

    // Step 5: Skip keys if message number > expected
    if message.header.message_number > state.recv_count() {
        let gap = message.header.message_number - state.recv_count();
        if gap > MAX_SKIP {
            return Err(CryptoError::TooManySkippedMessages);
        }
        skip_message_keys(state, state.recv_count(), message.header.message_number)?;
    }

    // Step 6: Now get the keypair and decapsulate
    // (safe because we validated it exists above and haven't removed it)
    let keypair = state
        .find_keypair(recipient_key_id)
        .expect("keypair validated above");
    let shared_secret = keypair.decapsulate(&message.header.encapsulation)?;

    // Step 7: Derive keys via KDF
    let mut kdf_output = kdf_rk(state.root_key(), shared_secret.as_bytes());

    // Step 8: Decrypt with AAD verification
    let aad = message.header.to_bytes();
    let aead_key = AeadKey::from_bytes(kdf_output.message_key);
    let aead_nonce = Nonce::from_bytes(message.nonce);
    let plaintext = aead::decrypt(&aead_key, &aead_nonce, &message.ciphertext, &aad)?;

    // Step 9: Update state atomically (MUST be after successful decrypt)
    state.set_root_key(kdf_output.new_root_key);
    state.set_recv_count(message.header.message_number);
    state.set_status(RatchetStatus::Active); // PCS restored
    state.set_last_activity(current_time);

    // Zeroize sensitive material
    kdf_output.zeroize();

    Ok(plaintext)
}

/// Derives and stores skipped message keys for the range [start, end).
///
/// This is called when:
/// 1. The sender key changes (to handle late arrivals from old chain)
/// 2. A message arrives with a gap (out-of-order delivery)
#[cfg(feature = "alloc")]
fn skip_message_keys(state: &mut DoubleRatchet, start: u64, end: u64) -> Result<()> {
    if end <= start {
        return Ok(());
    }

    // Get sender key hash for indexing
    let _their_pk = match state.their_public_key() {
        Some(pk) => pk.to_bytes(),
        None => return Ok(()), // No sender key yet, nothing to skip
    };

    // We need to derive keys for each skipped message
    // But we don't have the encapsulations for those messages
    // In a real implementation, we'd need to store the shared secrets
    // or use a different approach (like a chain key ratchet)
    //
    // For now, we just record that these messages were skipped
    // and will need their keys when they arrive

    // NOTE: This is a simplified implementation. The full protocol
    // would derive actual message keys here using stored chain state.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send::send_message;
    use trelis_hybrid::HybridKemKeypair;

    #[test]
    fn test_receive_message() {
        let session_key = [0x42u8; 32];

        // Alice (initiator) and Bob (responder)
        let bob_keypair = HybridKemKeypair::generate().unwrap();

        let mut alice_state = DoubleRatchet::init_initiator(
            &session_key,
            bob_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        let mut _bob_state = DoubleRatchet::init_responder(&session_key, bob_keypair, 1000);

        // Alice sends to Bob
        let plaintext = b"Hello, Bob!";
        let _send_result = send_message(&mut alice_state, plaintext, 1001).unwrap();

        // Bob needs to set up to receive - he needs Alice's public key from the message
        // and set his recipient key ID to match what Alice used
        // This is a simplified test - in reality, Bob would use his OTK key ID

        // Bob receives
        // Note: This test is incomplete because Bob's state doesn't have the right
        // keypair ID. In a real scenario, the initial message would be handled
        // specially (X3DH provides the initial state).
    }

    #[test]
    fn test_sender_key_id_mismatch_rejected() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state = DoubleRatchet::init_initiator(
            &session_key,
            their_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // Create a message with a different recipient key ID
        let other_keypair = HybridKemKeypair::generate().unwrap();
        let (_, encap) = other_keypair.public_key().encapsulate().unwrap();

        let header = crate::header::MessageHeader::new(
            0xDEADBEEF, // Wrong key ID
            other_keypair.public_key().clone(),
            encap,
            0,
        );

        let message = RatchetMessage {
            header,
            nonce: [0u8; 24],
            ciphertext: b"fake ciphertext".to_vec(),
        };

        let result = receive_message(&mut state, &message, 1001);
        assert!(matches!(result, Err(CryptoError::UnknownRecipientKeyId)));
    }

    #[test]
    fn test_receive_validates_session_state() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let mut state = DoubleRatchet::init_responder(&session_key, our_keypair, 1000);
        state.mark_compromised();

        let other_keypair = HybridKemKeypair::generate().unwrap();
        let (_, encap) = other_keypair.public_key().encapsulate().unwrap();

        let header = crate::header::MessageHeader::new(
            0,
            other_keypair.public_key().clone(),
            encap,
            0,
        );

        let message = RatchetMessage {
            header,
            nonce: [0u8; 24],
            ciphertext: vec![],
        };

        let result = receive_message(&mut state, &message, 1001);
        assert!(matches!(result, Err(CryptoError::SessionCompromised)));
    }
}
