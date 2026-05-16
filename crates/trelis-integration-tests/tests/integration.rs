//! Integration tests for the full Trelis protocol flow.
//!
//! Tests the complete X3DH-PQ → KEM Ratchet → Message Exchange flow.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::needless_borrow)]

use trelis_error::Result;
use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair, HybridSigningKeypair};
use trelis_ratchet::{KemRatchet, receive_message, send_message};
use trelis_x3dh_pq::{Initiator, PreKeyBundle, Responder};

/// Complete session establishment and message exchange between Alice and Bob.
#[cfg_attr(miri, ignore)]
#[test]
fn test_full_session_establishment() -> Result<()> {
    // =========================================================================
    // Setup: Generate identity keys for both parties
    // =========================================================================

    // Alice's identity
    let alice_identity = HybridIdentityKeypair::generate()?;

    // Bob's identity and bundle components
    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    // =========================================================================
    // Step 1: Bob creates and signs his pre-key bundle
    // =========================================================================

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,    // OTK key ID
        1000, // Timestamp
        2000, // Expiration
    );

    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    // =========================================================================
    // Step 2: Alice initiates session using Bob's bundle
    // =========================================================================

    let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500)?;

    // =========================================================================
    // Step 3: Bob receives initial message and derives session keys
    // =========================================================================

    let bob_session_keys = Responder::establish(
        &bob_identity,
        &bob_otk,
        alice_identity.signing().public_key(),
        alice_identity.kem().public_key().x448(),
        &signed_bundle,
        alice_result.initial_message(),
    )?;

    // =========================================================================
    // Verify: Both parties derived the same session keys
    // =========================================================================

    assert_eq!(
        alice_result.session_keys().root_key(),
        bob_session_keys.root_key(),
        "Root keys should match"
    );

    // Note: Send/recv chain keys are swapped between initiator and responder
    assert_eq!(
        alice_result.session_keys().send_chain_key(),
        bob_session_keys.recv_chain_key(),
        "Alice's send should match Bob's recv"
    );
    assert_eq!(
        alice_result.session_keys().recv_chain_key(),
        bob_session_keys.send_chain_key(),
        "Alice's recv should match Bob's send"
    );

    Ok(())
}

/// Test that invalid bundle signatures are rejected.
#[cfg_attr(miri, ignore)]
#[test]
fn test_invalid_bundle_signature() -> Result<()> {
    let alice_identity = HybridIdentityKeypair::generate()?;

    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    // Create bundle signed by a different identity
    let wrong_signer = HybridSigningKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );

    // Sign with wrong identity
    let mut signed_bundle = bob_bundle.sign(&wrong_signer)?;
    // Replace identity with original to create mismatch
    signed_bundle.bundle.identity_signing = bob_identity.signing().public_key().clone();

    // Alice tries to initiate with Bob's expected identity
    let result = Initiator::establish(&alice_identity, &signed_bundle, 1500);

    // Should fail due to signature mismatch
    assert!(result.is_err(), "Invalid signature should be rejected");

    Ok(())
}

/// Test expired bundle is rejected.
#[cfg_attr(miri, ignore)]
#[test]
fn test_expired_bundle_rejection() -> Result<()> {
    let alice_identity = HybridIdentityKeypair::generate()?;

    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000, // Expires at 2000
    );

    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    // Try to use bundle after expiration
    let result = Initiator::establish(&alice_identity, &signed_bundle, 3000);

    assert!(result.is_err(), "Expired bundle should be rejected");

    Ok(())
}

/// Test KEM Ratchet initialisation from session keys.
#[cfg_attr(miri, ignore)]
#[test]
fn test_ratchet_from_session_keys() -> Result<()> {
    // Establish session first
    let alice_identity = HybridIdentityKeypair::generate()?;

    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500)?;

    let bob_keys = Responder::establish(
        &bob_identity,
        &bob_otk,
        alice_identity.signing().public_key(),
        alice_identity.kem().public_key().x448(),
        &signed_bundle,
        alice_result.initial_message(),
    )?;

    // Initialise KEM Ratchet for both parties
    // Bob creates a new keypair for the ratchet
    let bob_ratchet_keypair = HybridKemKeypair::generate()?;

    let mut alice_ratchet = KemRatchet::init_initiator(
        alice_result.session_keys().root_key(),
        bob_ratchet_keypair.public_key().clone(),
        1500,
    )?;

    let mut bob_ratchet =
        KemRatchet::init_responder(bob_keys.root_key(), bob_ratchet_keypair, 1500);

    // Alice sends a message
    let plaintext = b"Hello, Bob!";
    let send_result = send_message(&mut alice_ratchet, plaintext, 1501)?;

    // Bob needs to set Alice's public key from the message header
    bob_ratchet.set_their_public_key(send_result.message.header.sender_public_key.clone());

    // Bob decrypts - but he needs the right keypair
    // The message is encrypted to Bob's ratchet keypair
    let decrypted = receive_message(&mut bob_ratchet, &send_result.message, 1502)?;
    assert_eq!(&decrypted, plaintext);

    Ok(())
}

/// Test multiple message exchange with ratcheting.
#[cfg_attr(miri, ignore)]
#[test]
fn test_multi_message_exchange() -> Result<()> {
    // Quick session setup
    let alice_identity = HybridIdentityKeypair::generate()?;
    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500)?;

    let bob_keys = Responder::establish(
        &bob_identity,
        &bob_otk,
        alice_identity.signing().public_key(),
        alice_identity.kem().public_key().x448(),
        &signed_bundle,
        alice_result.initial_message(),
    )?;

    // Create ratchets
    let bob_ratchet_keypair = HybridKemKeypair::generate()?;

    let mut alice = KemRatchet::init_initiator(
        alice_result.session_keys().root_key(),
        bob_ratchet_keypair.public_key().clone(),
        1500,
    )?;

    let mut bob = KemRatchet::init_responder(bob_keys.root_key(), bob_ratchet_keypair, 1500);

    // Alice sends multiple messages
    for i in 0..3 {
        let alice_msg = format!("Message {} from Alice", i);
        let send_result = send_message(&mut alice, alice_msg.as_bytes(), 1501 + i)?;

        // Bob needs to set Alice's public key from first message
        if i == 0 {
            bob.set_their_public_key(send_result.message.header.sender_public_key.clone());
        }

        let decrypted = receive_message(&mut bob, &send_result.message, 1502 + i)?;
        assert_eq!(decrypted, alice_msg.as_bytes());
    }

    Ok(())
}

/// Test that tampered messages are rejected.
#[cfg_attr(miri, ignore)]
#[test]
fn test_tampered_message_rejection() -> Result<()> {
    let alice_identity = HybridIdentityKeypair::generate()?;
    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500)?;

    let bob_keys = Responder::establish(
        &bob_identity,
        &bob_otk,
        alice_identity.signing().public_key(),
        alice_identity.kem().public_key().x448(),
        &signed_bundle,
        alice_result.initial_message(),
    )?;

    let bob_ratchet_keypair = HybridKemKeypair::generate()?;

    let mut alice = KemRatchet::init_initiator(
        alice_result.session_keys().root_key(),
        bob_ratchet_keypair.public_key().clone(),
        1500,
    )?;

    let mut bob = KemRatchet::init_responder(bob_keys.root_key(), bob_ratchet_keypair, 1500);

    // Alice sends a message
    let send_result = send_message(&mut alice, b"Secret message", 1501)?;

    // Set up Bob's state
    bob.set_their_public_key(send_result.message.header.sender_public_key.clone());

    // Attacker tampers with ciphertext
    let mut tampered_message = send_result.message.clone();
    if !tampered_message.ciphertext.is_empty() {
        tampered_message.ciphertext[0] ^= 0xFF;
    }

    // Bob should reject tampered message
    let result = receive_message(&mut bob, &tampered_message, 1502);
    assert!(result.is_err(), "Tampered message should be rejected");

    Ok(())
}

/// Test that different identities produce different session keys.
#[cfg_attr(miri, ignore)]
#[test]
fn test_identity_binding() -> Result<()> {
    let alice_identity = HybridIdentityKeypair::generate()?;
    let carol_identity = HybridIdentityKeypair::generate()?; // Different identity

    let bob_identity = HybridIdentityKeypair::generate()?;
    let bob_otk = HybridKemKeypair::generate()?;

    let bob_bundle = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle = bob_bundle.sign(bob_identity.signing())?;

    // Alice establishes session
    let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500)?;

    // Bob uses Carol's identity instead of Alice's (MITM attempt)
    let bob_keys_with_carol = Responder::establish(
        &bob_identity,
        &bob_otk,
        carol_identity.signing().public_key(), // Wrong identity!
        carol_identity.kem().public_key().x448(),
        &signed_bundle,
        alice_result.initial_message(),
    )?;

    // Keys should NOT match due to identity binding
    assert_ne!(
        alice_result.session_keys().root_key(),
        bob_keys_with_carol.root_key(),
        "Keys should differ with wrong identity"
    );

    Ok(())
}

/// Test multiple sessions with different OTKs produce different keys.
#[cfg_attr(miri, ignore)]
#[test]
fn test_otk_uniqueness() -> Result<()> {
    let alice_identity = HybridIdentityKeypair::generate()?;
    let bob_identity = HybridIdentityKeypair::generate()?;

    // First session with first OTK
    let bob_otk1 = HybridKemKeypair::generate()?;
    let bundle1 = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk1.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle1 = bundle1.sign(bob_identity.signing())?;
    let alice_result1 = Initiator::establish(&alice_identity, &signed_bundle1, 1500)?;

    // Second session with second OTK
    let bob_otk2 = HybridKemKeypair::generate()?;
    let bundle2 = PreKeyBundle::new(
        bob_identity.signing().public_key().clone(),
        bob_identity.kem().public_key().clone(),
        bob_otk2.public_key().clone(),
        2,
        1000,
        2000,
    );
    let signed_bundle2 = bundle2.sign(bob_identity.signing())?;
    let alice_result2 = Initiator::establish(&alice_identity, &signed_bundle2, 1500)?;

    // Keys should be different due to different OTKs and ephemeral keys
    assert_ne!(
        alice_result1.session_keys().root_key(),
        alice_result2.session_keys().root_key(),
        "Different sessions should have different keys"
    );

    Ok(())
}
