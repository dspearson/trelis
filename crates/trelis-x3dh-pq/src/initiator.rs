//! X3DH-PQ initiator (Alice) session establishment.
//!
//! The initiator fetches the responder's pre-key bundle, verifies its signature,
//! performs the DH and KEM operations, and derives session keys.

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair};
use trelis_primitives::Sntrup761Ciphertext;
use trelis_wire::constants::{SNTRUP761_CT_SIZE, X448_PK_SIZE};

use crate::bundle::SignedPreKeyBundle;
use crate::session_keys::SessionKeys;
use crate::transcript::{DH_SIZE, PQ_SS_SIZE, Transcript};

/// Initial message sent from Alice to Bob.
///
/// Contains Alice's ephemeral public key and the sntrup761 ciphertext.
#[derive(Clone)]
pub struct InitialMessage {
    /// Alice's ephemeral X448 public key.
    ephemeral_public: [u8; X448_PK_SIZE],
    /// sntrup761 ciphertext for post-quantum key exchange.
    pq_ciphertext: [u8; SNTRUP761_CT_SIZE],
}

impl InitialMessage {
    /// Returns the ephemeral X448 public key.
    #[must_use]
    pub fn ephemeral_public(&self) -> &[u8; X448_PK_SIZE] {
        &self.ephemeral_public
    }

    /// Returns the sntrup761 ciphertext.
    #[must_use]
    pub fn pq_ciphertext(&self) -> &[u8; SNTRUP761_CT_SIZE] {
        &self.pq_ciphertext
    }

    /// Serialises the initial message to bytes.
    ///
    /// Format: ephemeral_public (56 B) || pq_ciphertext (1039 B)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X448_PK_SIZE + SNTRUP761_CT_SIZE] {
        let mut output = [0u8; X448_PK_SIZE + SNTRUP761_CT_SIZE];
        output[..X448_PK_SIZE].copy_from_slice(&self.ephemeral_public);
        output[X448_PK_SIZE..].copy_from_slice(&self.pq_ciphertext);
        output
    }

    /// Deserialises an initial message from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the input is the wrong size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X448_PK_SIZE + SNTRUP761_CT_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut ephemeral_public = [0u8; X448_PK_SIZE];
        ephemeral_public.copy_from_slice(&bytes[..X448_PK_SIZE]);

        let mut pq_ciphertext = [0u8; SNTRUP761_CT_SIZE];
        pq_ciphertext.copy_from_slice(&bytes[X448_PK_SIZE..]);

        Ok(Self {
            ephemeral_public,
            pq_ciphertext,
        })
    }

    /// Returns the sntrup761 ciphertext as a structured type.
    pub fn pq_ciphertext_typed(&self) -> Result<Sntrup761Ciphertext> {
        Sntrup761Ciphertext::from_bytes(&self.pq_ciphertext)
    }
}

/// Result of initiator session establishment.
///
/// Contains both the derived session keys and the initial message that must
/// be sent to the responder to complete the handshake.
///
/// # Usage
///
/// After calling [`Initiator::establish()`], you should:
/// 1. Send [`initial_message()`](Self::initial_message) to the responder
/// 2. Use [`session_keys()`](Self::session_keys) to initialise the Double Ratchet
///
/// # Example
///
/// ```ignore
/// let result = Initiator::establish(&our_identity, &their_bundle, timestamp)?;
///
/// // Send initial message over the network
/// network.send(result.initial_message().to_bytes());
///
/// // Initialise ratchet with session keys
/// let ratchet = KemRatchet::initiate(result.into_session_keys());
/// ```
pub struct InitiatorResult {
    /// Session keys for the Double Ratchet.
    session_keys: SessionKeys,
    /// Initial message to send to responder.
    initial_message: InitialMessage,
}

impl InitiatorResult {
    /// Returns the derived session keys.
    #[must_use]
    pub fn session_keys(&self) -> &SessionKeys {
        &self.session_keys
    }

    /// Consumes self and returns the session keys.
    #[must_use]
    pub fn into_session_keys(self) -> SessionKeys {
        self.session_keys
    }

    /// Returns the initial message to send.
    #[must_use]
    pub fn initial_message(&self) -> &InitialMessage {
        &self.initial_message
    }
}

/// X3DH-PQ initiator (Alice).
///
/// Establishes a session with a responder using their pre-key bundle.
pub struct Initiator;

impl Initiator {
    /// Establishes a session with the responder.
    ///
    /// # Arguments
    ///
    /// * `our_identity` - Our identity keypair
    /// * `their_bundle` - Responder's signed pre-key bundle
    /// * `current_time` - Current Unix timestamp (for bundle validation)
    ///
    /// # Protocol Steps
    ///
    /// 1. Verify bundle signature
    /// 2. Validate bundle timestamps
    /// 3. Generate ephemeral X448 keypair
    /// 4. Compute DH1: our identity KEM ↔ their OTK
    /// 5. Compute DH2: our ephemeral ↔ their identity KEM
    /// 6. Compute DH3: our ephemeral ↔ their OTK
    /// 7. Encapsulate to their sntrup761 key
    /// 8. Build transcript and derive shared secret
    /// 9. Derive session keys
    ///
    /// # Errors
    ///
    /// - `BundleSignatureInvalid` if bundle signature verification fails
    /// - `BundleTimestampInFuture` if bundle was created in the future
    /// - `BundleExpired` if bundle has expired
    /// - `RngFailure` if random number generation fails
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn establish(
        our_identity: &HybridIdentityKeypair,
        their_bundle: &SignedPreKeyBundle,
        current_time: u64,
    ) -> Result<InitiatorResult> {
        // Step 1: Verify bundle signature (MANDATORY)
        their_bundle.verify()?;

        // Step 2: Validate timestamps
        their_bundle.validate_timestamps(current_time)?;

        // Step 3: Generate ephemeral X448 keypair
        let ephemeral = HybridKemKeypair::generate()?;

        // Step 4: DH1 - our identity KEM.X448 ↔ their OTK.X448
        let dh1 = our_identity
            .kem()
            .x448_dh(their_bundle.one_time_key().x448())?;

        // Step 5: DH2 - our ephemeral.X448 ↔ their identity KEM.X448
        let dh2 = ephemeral.x448_dh(their_bundle.identity_kem().x448())?;

        // Step 6: DH3 - our ephemeral.X448 ↔ their OTK.X448
        let dh3 = ephemeral.x448_dh(their_bundle.one_time_key().x448())?;

        // Step 7: Encapsulate to their sntrup761 key (in OTK)
        let (pq_ss, pq_ct) = their_bundle.one_time_key().sntrup_encapsulate()?;

        // Convert to fixed-size arrays for transcript
        let dh1_bytes: [u8; DH_SIZE] = *dh1.as_bytes();
        let dh2_bytes: [u8; DH_SIZE] = *dh2.as_bytes();
        let dh3_bytes: [u8; DH_SIZE] = *dh3.as_bytes();
        let pq_ss_bytes: [u8; PQ_SS_SIZE] = *pq_ss.as_bytes();

        // Step 8: Build transcript and derive shared secret
        let transcript = Transcript::new(
            our_identity.signing().public_key(),
            their_bundle.identity_signing(),
            their_bundle,
            &dh1_bytes,
            &dh2_bytes,
            &dh3_bytes,
            &pq_ss_bytes,
        );

        let shared_secret = transcript.derive_shared_secret();

        // Step 9: Derive session keys
        let session_keys = SessionKeys::derive(&shared_secret);

        // Build initial message
        let initial_message = InitialMessage {
            ephemeral_public: *ephemeral.x448_public().as_bytes(),
            pq_ciphertext: *pq_ct.as_bytes(),
        };

        Ok(InitiatorResult {
            session_keys,
            initial_message,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bundle::PreKeyBundle;
    use trelis_hybrid::HybridSigningKeypair;

    #[test]
    fn test_initial_message_serialisation() {
        let msg = InitialMessage {
            ephemeral_public: [0x42u8; X448_PK_SIZE],
            pq_ciphertext: [0xABu8; SNTRUP761_CT_SIZE],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), X448_PK_SIZE + SNTRUP761_CT_SIZE);
        assert_eq!(bytes.len(), 56 + 1039);

        let recovered = InitialMessage::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.ephemeral_public, msg.ephemeral_public);
        assert_eq!(recovered.pq_ciphertext, msg.pq_ciphertext);
    }

    #[test]
    fn test_initial_message_wrong_size() {
        let bytes = [0u8; 100];
        assert!(matches!(
            InitialMessage::from_bytes(&bytes),
            Err(CryptoError::MalformedMessage)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_initiator_establish() {
        // Alice's identity
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        // Bob's identity and bundle
        let bob_signing = HybridSigningKeypair::generate().unwrap();
        let bob_kem = HybridKemKeypair::generate().unwrap();
        let bob_otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            bob_signing.public_key().clone(),
            bob_kem.public_key().clone(),
            bob_otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        let signed_bundle = bundle.sign(&bob_signing).unwrap();

        // Establish session
        let result = Initiator::establish(&alice_identity, &signed_bundle, 1500).unwrap();

        // Should have valid session keys
        assert_eq!(result.session_keys().root_key().len(), 32);
        assert_eq!(result.session_keys().send_chain_key().len(), 32);
        assert_eq!(result.session_keys().recv_chain_key().len(), 32);

        // Should have valid initial message
        assert_eq!(result.initial_message().ephemeral_public().len(), 56);
        assert_eq!(result.initial_message().pq_ciphertext().len(), 1039);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_initiator_rejects_invalid_signature() {
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        // Create bundle signed by different key
        let bob_signing = HybridSigningKeypair::generate().unwrap();
        let bob_kem = HybridKemKeypair::generate().unwrap();
        let bob_otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            bob_signing.public_key().clone(),
            bob_kem.public_key().clone(),
            bob_otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        // Sign with wrong key
        let wrong_signer = HybridSigningKeypair::generate().unwrap();
        let mut signed_bundle = bundle.sign(&wrong_signer).unwrap();
        // Replace identity with original to create mismatch
        signed_bundle.bundle.identity_signing = bob_signing.public_key().clone();

        let result = Initiator::establish(&alice_identity, &signed_bundle, 1500);
        assert!(matches!(result, Err(CryptoError::BundleSignatureInvalid)));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_initiator_rejects_expired_bundle() {
        let alice_identity = HybridIdentityKeypair::generate().unwrap();

        let bob_signing = HybridSigningKeypair::generate().unwrap();
        let bob_kem = HybridKemKeypair::generate().unwrap();
        let bob_otk = HybridKemKeypair::generate().unwrap();

        let bundle = PreKeyBundle::new(
            bob_signing.public_key().clone(),
            bob_kem.public_key().clone(),
            bob_otk.public_key().clone(),
            1,
            1000,
            2000,
        );

        let signed_bundle = bundle.sign(&bob_signing).unwrap();

        // Current time is past expiration
        let result = Initiator::establish(&alice_identity, &signed_bundle, 3000);
        assert!(matches!(result, Err(CryptoError::BundleExpired)));
    }
}
