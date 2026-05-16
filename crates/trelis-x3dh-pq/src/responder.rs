//! X3DH-PQ responder (Bob) session establishment.
//!
//! The responder receives the initiator's initial message and uses
//! their own private keys to derive the same session keys.

use trelis_error::Result;
use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair, HybridSigningPublicKey};
use trelis_primitives::X448Public;

use crate::bundle::SignedPreKeyBundle;
use crate::initiator::InitialMessage;
use crate::session_keys::SessionKeys;
use crate::transcript::{DH_SIZE, PQ_SS_SIZE, Transcript};

/// X3DH-PQ responder (Bob).
///
/// The responder receives an initial message from the initiator and uses
/// their private keys (identity and one-time) to derive the same session keys.
///
/// # Protocol Role
///
/// 1. Receives [`InitialMessage`] from initiator
/// 2. Uses private keys to compute matching DH and decapsulate PQ ciphertext
/// 3. Returns [`SessionKeys`] with send/receive directions swapped
///
/// # Security
///
/// The responder MUST:
/// - Keep the one-time key private until the initial message is received
/// - Delete the one-time key after deriving session keys (one-time use)
/// - Verify the initiator's identity through the transcript binding
///
/// # Example
///
/// ```ignore
/// // Receive initial message from network
/// let initial_msg = InitialMessage::from_bytes(&network_data)?;
///
/// // Derive session keys using our private keys
/// let session_keys = Responder::establish(
///     &our_identity,
///     &our_otk,         // Must match the OTK in our published bundle
///     &their_identity_signing,
///     &their_identity_kem_x448,
///     &our_published_bundle,
///     &initial_msg,
/// )?;
///
/// // Initialise ratchet as responder (send/recv are already swapped)
/// let ratchet = KemRatchet::respond(session_keys);
/// ```
pub struct Responder;

impl Responder {
    /// Establishes a session from the initiator's message.
    ///
    /// # Arguments
    ///
    /// * `our_identity` - Our identity keypair
    /// * `our_otk` - The one-time keypair that was used in the bundle
    /// * `their_identity_signing` - Initiator's identity signing public key
    /// * `their_identity_kem_x448` - Initiator's identity KEM X448 public key
    /// * `our_bundle` - The bundle we published (for transcript binding)
    /// * `initial_message` - The initiator's initial message
    ///
    /// # Protocol Steps
    ///
    /// 1. Compute DH1: their identity KEM.X448 ↔ our OTK.X448
    /// 2. Compute DH2: their ephemeral ↔ our identity KEM.X448
    /// 3. Compute DH3: their ephemeral ↔ our OTK.X448
    /// 4. Decapsulate sntrup761 ciphertext
    /// 5. Build transcript and derive shared secret
    /// 6. Derive session keys (with swapped directions)
    ///
    /// # Errors
    ///
    /// - `DecapsulationFailed` if sntrup761 decapsulation fails
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn establish(
        our_identity: &HybridIdentityKeypair,
        our_otk: &HybridKemKeypair,
        their_identity_signing: &HybridSigningPublicKey,
        their_identity_kem_x448: &X448Public,
        our_bundle: &SignedPreKeyBundle,
        initial_message: &InitialMessage,
    ) -> Result<SessionKeys> {
        // Parse initiator's ephemeral public key
        let their_ephemeral = X448Public::from_bytes(initial_message.ephemeral_public())?;

        // Parse sntrup761 ciphertext
        let pq_ciphertext = initial_message.pq_ciphertext_typed()?;

        // Step 1: DH1 - their identity KEM.X448 ↔ our OTK.X448
        let dh1 = our_otk.x448_dh(their_identity_kem_x448)?;

        // Step 2: DH2 - their ephemeral ↔ our identity KEM.X448
        let dh2 = our_identity.kem().x448_dh(&their_ephemeral)?;

        // Step 3: DH3 - their ephemeral ↔ our OTK.X448
        let dh3 = our_otk.x448_dh(&their_ephemeral)?;

        // Step 4: Decapsulate sntrup761 ciphertext
        let pq_ss = our_otk.sntrup_decapsulate(&pq_ciphertext)?;

        // Convert to fixed-size arrays for transcript
        let dh1_bytes: [u8; DH_SIZE] = *dh1.as_bytes();
        let dh2_bytes: [u8; DH_SIZE] = *dh2.as_bytes();
        let dh3_bytes: [u8; DH_SIZE] = *dh3.as_bytes();
        let pq_ss_bytes: [u8; PQ_SS_SIZE] = *pq_ss.as_bytes();

        // Step 5: Build transcript and derive shared secret
        // Note: The transcript uses initiator's identity first, responder's second
        let transcript = Transcript::new(
            their_identity_signing,
            our_identity.signing().public_key(),
            our_bundle,
            &dh1_bytes,
            &dh2_bytes,
            &dh3_bytes,
            &pq_ss_bytes,
        );

        let shared_secret = transcript.derive_shared_secret();

        // Step 6: Derive session keys with swapped directions
        // The responder's send is the initiator's receive and vice versa
        let session_keys = SessionKeys::derive(&shared_secret).swap_directions();

        Ok(session_keys)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bundle::PreKeyBundle;
    use crate::initiator::Initiator;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_initiator_responder_derive_same_keys() {
        // Alice's identity
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        // Bob's identity and bundle
        let bob_identity = HybridIdentityKeypair::generate().unwrap();
        let bob_otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            bob_identity.signing().public_key().clone(),
            bob_identity.kem().public_key().clone(),
            bob_otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        let signed_bundle = bundle.sign(bob_identity.signing()).unwrap();

        // Alice establishes session
        let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500).unwrap();

        // Bob receives initial message and establishes session
        let bob_keys = Responder::establish(
            &bob_identity,
            &bob_otk,
            alice_identity.signing().public_key(),
            alice_identity.kem().public_key().x448(),
            &signed_bundle,
            alice_result.initial_message(),
        )
        .unwrap();

        // Both should derive the same root key
        assert_eq!(
            alice_result.session_keys().root_key(),
            bob_keys.root_key(),
            "Root keys should match"
        );

        // Alice's send should be Bob's receive
        assert_eq!(
            alice_result.session_keys().send_chain_key(),
            bob_keys.recv_chain_key(),
            "Alice's send should be Bob's receive"
        );

        // Alice's receive should be Bob's send
        assert_eq!(
            alice_result.session_keys().recv_chain_key(),
            bob_keys.send_chain_key(),
            "Alice's receive should be Bob's send"
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_different_identities_different_keys() {
        // Alice's identity
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        // Bob's identity and bundle
        let bob_identity = HybridIdentityKeypair::generate().unwrap();
        let bob_otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            bob_identity.signing().public_key().clone(),
            bob_identity.kem().public_key().clone(),
            bob_otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        let signed_bundle = bundle.sign(bob_identity.signing()).unwrap();

        // Alice establishes session
        let alice_result = Initiator::establish(&alice_identity, &signed_bundle, 1500).unwrap();

        // Carol pretends to be Alice but uses her own identity
        let carol_identity = HybridIdentityKeypair::generate().unwrap();

        // Bob uses Carol's identity instead of Alice's
        let bob_keys_with_carol = Responder::establish(
            &bob_identity,
            &bob_otk,
            carol_identity.signing().public_key(), // Wrong identity!
            carol_identity.kem().public_key().x448(),
            &signed_bundle,
            alice_result.initial_message(),
        )
        .unwrap();

        // Keys should NOT match due to identity binding
        assert_ne!(
            alice_result.session_keys().root_key(),
            bob_keys_with_carol.root_key(),
            "Keys should differ with wrong identity"
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_multiple_sessions_different_keys() {
        // Alice's identity
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        // Bob's identity
        let bob_identity = HybridIdentityKeypair::generate().unwrap();

        // First session with first OTK
        let bob_otk1 = HybridKemKeypair::generate().unwrap();
        let bundle1 = PreKeyBundle::new(
            bob_identity.signing().public_key().clone(),
            bob_identity.kem().public_key().clone(),
            bob_otk1.public_key().clone(),
            1,
            1000,
            2000,
        );
        let signed_bundle1 = bundle1.sign(bob_identity.signing()).unwrap();
        let alice_result1 = Initiator::establish(&alice_identity, &signed_bundle1, 1500).unwrap();

        // Second session with second OTK
        let bob_otk2 = HybridKemKeypair::generate().unwrap();
        let bundle2 = PreKeyBundle::new(
            bob_identity.signing().public_key().clone(),
            bob_identity.kem().public_key().clone(),
            bob_otk2.public_key().clone(),
            2,
            1000,
            2000,
        );
        let signed_bundle2 = bundle2.sign(bob_identity.signing()).unwrap();
        let alice_result2 = Initiator::establish(&alice_identity, &signed_bundle2, 1500).unwrap();

        // Keys should be different due to different OTKs and ephemeral keys
        assert_ne!(
            alice_result1.session_keys().root_key(),
            alice_result2.session_keys().root_key(),
            "Different sessions should have different keys"
        );
    }
}
