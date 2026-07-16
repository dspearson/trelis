//! Per-Message Ratchet decryption (receive) path.
//!
//! Decrypts messages by:
//! 1. Validating message order (ordered delivery required)
//! 2. Handling sender key changes (ratchet step)
//! 3. Decapsulating to derive shared secret
//! 4. Deriving message key via KDF
//! 5. Decrypting with XChaCha20-Poly1305
//!
//! # Transport Requirements
//!
//! This implementation requires ordered, reliable message delivery.
//! Out-of-order messages are rejected with `MessageOrderViolation`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_primitives::aead::{self, AeadKey, Nonce};
use zeroize::Zeroize;

use crate::header::RatchetMessage;
use crate::kdf::kdf_rk;
use crate::state::{KemRatchet, RatchetStatus};

/// Decrypts a received message and updates the ratchet state.
///
/// This is the main receive function. It:
/// 1. Validates the session state
/// 2. Validates message order (ordered delivery required)
/// 3. Validates that we have the decapsulation keypair
/// 4. Handles sender key change (ratchet step)
/// 5. Decapsulates to get shared secret
/// 6. Derives message key via KDF
/// 7. Decrypts with AAD verification
/// 8. Updates the ratchet state
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
/// - `MessageOrderViolation` if messages arrive out of order
/// - `UnknownRecipientKeyId` if we don't have the decapsulation keypair
/// - `AeadAuthenticationFailed` if decryption fails
#[cfg(feature = "alloc")]
pub fn receive_message(
    state: &mut KemRatchet,
    message: &RatchetMessage,
    current_time: u64,
) -> Result<Vec<u8>> {
    // Step 1: Validate state
    state.validate_can_receive()?;

    // Step 2: Validate message order (ordered delivery required)
    // Transport layer (NATS JetStream) guarantees in-order delivery.
    // If message_number != recv_count, this indicates transport failure
    // or session desync, requiring session re-establishment.
    if message.header.message_number != state.recv_count() {
        return Err(CryptoError::MessageOrderViolation {
            expected: state.recv_count(),
            received: message.header.message_number,
        });
    }

    // Step 3: Validate that we have the decapsulation keypair
    let recipient_key_id = message.header.recipient_key_id;
    if state.find_keypair(recipient_key_id).is_none() {
        return Err(CryptoError::UnknownRecipientKeyId);
    }

    // Step 4: Detect sender key change (ratchet step).
    //
    // Read-only: this compares the claimed sender key against stored state but
    // does NOT mutate `their_public_key`. The write is deferred to the Step-8
    // atomic block (below), so an unauthenticated, spoofed-sender message that
    // fails AEAD cannot overwrite ratchet state (RCH-01: authenticate before
    // mutate). The comparison uses `HybridKemPublicKey`'s alloc-free, field-wise
    // `PartialEq` (X448 + sntrup761, both byte-canonical) lifted over `Option<&_>`,
    // so no `to_bytes()` buffers are allocated. `None` (no stored key) ⇒
    // changed=true, matching the first message from this peer.
    let sender_key_changed = state.their_public_key() != Some(&message.header.sender_public_key);

    // Step 5: Decapsulate to get shared secret
    #[allow(clippy::expect_used)]
    // AUDIT: infallible — keypair presence validated by find_keypair contract above
    let keypair = state
        .find_keypair(recipient_key_id)
        .expect("keypair validated above");
    let shared_secret = keypair.decapsulate(&message.header.encapsulation)?;

    // Step 6: Derive keys via KDF
    let mut kdf_output = kdf_rk(state.root_key(), shared_secret.as_bytes());

    // Step 7: Decrypt with AAD verification
    let aad = message.header.to_bytes();
    let aead_key = AeadKey::from_bytes(kdf_output.message_key);
    let aead_nonce = Nonce::from_bytes(message.nonce);
    let plaintext = aead::decrypt(&aead_key, &aead_nonce, &message.ciphertext, &aad)?;

    // Step 8: Update state atomically (MUST be after successful decrypt)
    state.set_root_key(kdf_output.new_root_key);
    if sender_key_changed {
        // Deferred from Step 4: record the peer's new key only after
        // `aead::decrypt` (Step 7) has verified the AEAD tag — the sole
        // authenticity proof. A spoofed `sender_public_key` on a message that
        // fails decrypt returns via `?` above and leaves `their_public_key`
        // unchanged (RCH-01). recv_count is NOT reset — it is globally
        // sequential (spec §11).
        state.set_their_public_key(message.header.sender_public_key.clone());
    }
    state.set_recv_count(message.header.message_number);
    state.set_status(RatchetStatus::Active); // PCS restored
    state.set_last_activity(current_time);

    // Zeroize sensitive material
    kdf_output.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send::send_message;
    use trelis_hybrid::HybridKemKeypair;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_send_produces_valid_message() {
        // This test validates that send_message produces a well-formed message.
        // Full receive integration testing is done in trelis-integration-tests
        // where X3DH provides the initial shared state.
        let session_key = [0x42u8; 32];

        let bob_keypair = HybridKemKeypair::generate().unwrap();

        let mut alice_state =
            KemRatchet::init_initiator(&session_key, bob_keypair.public_key().clone(), 1000)
                .unwrap();

        let plaintext = b"Hello, Bob!";
        let result = send_message(&mut alice_state, plaintext, 1001).unwrap();

        // Verify message structure
        assert_eq!(result.message.header.message_number, 0);
        assert!(!result.message.ciphertext.is_empty());
        assert_ne!(result.message.nonce, [0u8; 24]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sender_key_id_mismatch_rejected() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
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

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_receive_validates_session_state() {
        let session_key = [0x42u8; 32];
        let our_keypair = HybridKemKeypair::generate().unwrap();

        let mut state = KemRatchet::init_responder(&session_key, our_keypair, 1000);
        state.mark_compromised();

        let other_keypair = HybridKemKeypair::generate().unwrap();
        let (_, encap) = other_keypair.public_key().encapsulate().unwrap();

        let header =
            crate::header::MessageHeader::new(0, other_keypair.public_key().clone(), encap, 0);

        let message = RatchetMessage {
            header,
            nonce: [0u8; 24],
            ciphertext: vec![],
        };

        let result = receive_message(&mut state, &message, 1001);
        assert!(matches!(result, Err(CryptoError::SessionCompromised)));
    }

    /// RCH-01 (SC1) — authenticate-before-mutate.
    ///
    /// A `receive_message` whose header carries a *different* (spoofed) valid
    /// `sender_public_key` but whose ciphertext fails AEAD authentication must
    /// return `Err` **and** leave `state.their_public_key()` byte-identical to
    /// before the call. The `set_their_public_key` write is deferred to the
    /// Step-8 post-decrypt block, so `decapsulate`/`aead::decrypt` fail (via
    /// `?`) before any mutation.
    ///
    /// Pitfall 2: assert the invariant (`is_err()` + unchanged key), not the
    /// exact error — the failure may land at `decapsulate` or `aead::decrypt`,
    /// both of which precede the deferred write.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_failed_decrypt_spoofed_sender_leaves_their_public_key_unchanged() {
        let session_key = [0x42u8; 32];
        let their_keypair = HybridKemKeypair::generate().unwrap();

        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .unwrap();

        // A valid encapsulation to OUR own current key so Step 5 (decapsulate)
        // succeeds; the AEAD tag over garbage ciphertext is what fails.
        let (_, encap) = state.our_keypair().public_key().encapsulate().unwrap();

        // A fresh, DIFFERENT sender key (a spoofed peer identity).
        let spoof = HybridKemKeypair::generate().unwrap();

        let header = crate::header::MessageHeader::new(
            state.our_key_id(),         // recipient_key_id = our key => find_keypair passes
            spoof.public_key().clone(), // spoofed sender_public_key (changed)
            encap,
            0, // message_number == recv_count
        );
        let message = RatchetMessage {
            header,
            nonce: [0u8; 24],
            ciphertext: b"not an authenticating ciphertext".to_vec(),
        };

        let before = state.their_public_key().unwrap().to_bytes();
        let result = receive_message(&mut state, &message, 1001);
        assert!(
            result.is_err(),
            "spoofed-sender garbage ciphertext must fail"
        );
        let after = state.their_public_key().unwrap().to_bytes();
        assert_eq!(
            before, after,
            "their_public_key must be byte-unchanged on a failed decrypt"
        );
    }

    /// RCH-01 (W1) — the deferred write still executes on a successful decrypt.
    ///
    /// Drives a genuine two-party ratchet step (Alice initiator, Bob responder
    /// share the same derived root key) where the peer's `sender_public_key`
    /// GENUINELY CHANGES between messages. After each successful receive,
    /// `their_public_key()` must reflect the NEW sender key — proving the
    /// Step-8 write runs on success (guards against a delete-not-defer
    /// regression and protects Phase-60 PRF-03, which rewrites this region).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_successful_receive_records_new_sender_key() {
        let session_key = [0x42u8; 32];
        let bob_keypair = HybridKemKeypair::generate().unwrap();
        let bob_pk = bob_keypair.public_key().clone();

        // Both peers derive the same initial root key from `session_key`.
        let mut alice = KemRatchet::init_initiator(&session_key, bob_pk, 1000).unwrap();
        let mut bob = KemRatchet::init_responder(&session_key, bob_keypair, 1000);

        // First ratchet step: Alice -> Bob.
        let msg1 = send_message(&mut alice, b"hello", 1001).unwrap();
        let sender_key_1 = msg1.message.header.sender_public_key.to_bytes();
        receive_message(&mut bob, &msg1.message, 1002).unwrap();
        assert_eq!(
            bob.their_public_key().unwrap().to_bytes(),
            sender_key_1,
            "first successful receive must record the peer's key"
        );

        // Second ratchet step: Alice's sender key GENUINELY CHANGES.
        let msg2 = send_message(&mut alice, b"world", 1003).unwrap();
        let sender_key_2 = msg2.message.header.sender_public_key.to_bytes();
        assert_ne!(
            sender_key_1, sender_key_2,
            "each send rotates the sender key"
        );

        receive_message(&mut bob, &msg2.message, 1004).unwrap();
        assert_eq!(
            bob.their_public_key().unwrap().to_bytes(),
            sender_key_2,
            "their_public_key must reflect the NEW sender key after a successful receive"
        );
    }
}
