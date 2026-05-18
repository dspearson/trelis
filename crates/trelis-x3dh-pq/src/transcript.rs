//! Transcript binding for X3DH-PQ key derivation.
//!
//! The transcript ensures that all parties derive the same session keys
//! and prevents unknown-key-share (UKS) attacks by binding identities
//! and the pre-key bundle into the key derivation.

use trelis_hybrid::HybridSigningPublicKey;
use trelis_wire::constants::{SNTRUP761_SS_SIZE, X448_PK_SIZE};
use zeroize::{Zeroize, Zeroizing};

use crate::bundle::SignedPreKeyBundle;

/// Context string for X3DH-PQ session key derivation. Re-exported from
/// `trelis_primitives::blake3_kdf` registry (PROTO-07-NEW1).
pub use trelis_primitives::SESSION_CONTEXT;

/// Size of a BLAKE3 hash output.
pub const HASH_SIZE: usize = 32;

/// Size of X448 DH output.
pub const DH_SIZE: usize = X448_PK_SIZE;

/// Size of sntrup761 shared secret.
pub const PQ_SS_SIZE: usize = SNTRUP761_SS_SIZE;

/// Total size of the transcript input:
/// - 3 hashes (32 B each): H(I_a), H(I_b), H(bundle)
/// - 3 DH outputs (56 B each): DH1, DH2, DH3
/// - 1 PQ shared secret (32 B): PQ_ss
pub const TRANSCRIPT_SIZE: usize = 3 * HASH_SIZE + 3 * DH_SIZE + PQ_SS_SIZE;

/// Transcript for X3DH-PQ key derivation.
///
/// Contains all the values that are bound into the session key derivation:
/// - Identity hashes (prevents UKS attacks)
/// - Bundle hash (binds to specific OTK and timestamps)
/// - DH shared secrets
/// - Post-quantum shared secret
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Transcript {
    /// Hash of Alice's identity signing public key.
    alice_identity_hash: [u8; HASH_SIZE],
    /// Hash of Bob's identity signing public key.
    bob_identity_hash: [u8; HASH_SIZE],
    /// Hash of the pre-key bundle (including timestamps).
    bundle_hash: [u8; HASH_SIZE],
    /// DH1: Alice identity KEM ↔ Bob OTK.
    dh1: [u8; DH_SIZE],
    /// DH2: Alice ephemeral ↔ Bob identity KEM.
    dh2: [u8; DH_SIZE],
    /// DH3: Alice ephemeral ↔ Bob OTK.
    dh3: [u8; DH_SIZE],
    /// Post-quantum shared secret from sntrup761 encapsulation.
    pq_ss: [u8; PQ_SS_SIZE],
}

impl Transcript {
    /// Creates a new transcript from the protocol components.
    ///
    /// # Arguments
    ///
    /// * `alice_identity` - Alice's identity signing public key
    /// * `bob_identity` - Bob's identity signing public key
    /// * `bundle` - Bob's signed pre-key bundle
    /// * `dh1` - X448 DH result: Alice identity KEM ↔ Bob OTK
    /// * `dh2` - X448 DH result: Alice ephemeral ↔ Bob identity KEM
    /// * `dh3` - X448 DH result: Alice ephemeral ↔ Bob OTK
    /// * `pq_ss` - sntrup761 shared secret
    #[must_use]
    pub fn new(
        alice_identity: &HybridSigningPublicKey,
        bob_identity: &HybridSigningPublicKey,
        bundle: &SignedPreKeyBundle,
        dh1: &[u8; DH_SIZE],
        dh2: &[u8; DH_SIZE],
        dh3: &[u8; DH_SIZE],
        pq_ss: &[u8; PQ_SS_SIZE],
    ) -> Self {
        Self {
            alice_identity_hash: hash_identity(alice_identity),
            bob_identity_hash: hash_identity(bob_identity),
            bundle_hash: hash_bundle(bundle),
            dh1: *dh1,
            dh2: *dh2,
            dh3: *dh3,
            pq_ss: *pq_ss,
        }
    }

    /// Serialises the transcript to a fixed-size byte array for KDF input.
    ///
    /// The order is:
    /// 1. H(Alice identity) - 32 bytes
    /// 2. H(Bob identity) - 32 bytes
    /// 3. H(bundle) - 32 bytes
    /// 4. DH1 - 56 bytes
    /// 5. DH2 - 56 bytes
    /// 6. DH3 - 56 bytes
    /// 7. PQ_ss - 32 bytes
    ///
    /// Total: 296 bytes.
    ///
    /// The output contains DH and PQ shared-secret bytes, so it is wrapped
    /// in `Zeroizing<>` to ensure the intermediate KDF input is zeroized on
    /// drop (ERGO-02 / MEM-03-NEW1).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; TRANSCRIPT_SIZE]> {
        let mut output = Zeroizing::new([0u8; TRANSCRIPT_SIZE]);
        let mut offset = 0;

        // Identity hashes (prevents UKS attacks)
        output[offset..offset + HASH_SIZE].copy_from_slice(&self.alice_identity_hash);
        offset += HASH_SIZE;
        output[offset..offset + HASH_SIZE].copy_from_slice(&self.bob_identity_hash);
        offset += HASH_SIZE;

        // Bundle hash (binds to specific OTK and timestamps)
        output[offset..offset + HASH_SIZE].copy_from_slice(&self.bundle_hash);
        offset += HASH_SIZE;

        // DH shared secrets
        output[offset..offset + DH_SIZE].copy_from_slice(&self.dh1);
        offset += DH_SIZE;
        output[offset..offset + DH_SIZE].copy_from_slice(&self.dh2);
        offset += DH_SIZE;
        output[offset..offset + DH_SIZE].copy_from_slice(&self.dh3);
        offset += DH_SIZE;

        // Post-quantum shared secret
        output[offset..offset + PQ_SS_SIZE].copy_from_slice(&self.pq_ss);

        output
    }

    /// Derives the shared secret using BLAKE3 derive_key.
    ///
    /// This produces a 32-byte shared secret that is then used to derive
    /// the root key, send chain, and receive chain. Wrapped in `Zeroizing<>`
    /// (ERGO-02 / MEM-03-NEW1).
    #[must_use]
    pub fn derive_shared_secret(&self) -> Zeroizing<[u8; HASH_SIZE]> {
        let transcript_bytes = self.to_bytes();
        Zeroizing::new(blake3::derive_key(
            SESSION_CONTEXT,
            transcript_bytes.as_slice(),
        ))
    }
}

/// Hashes an identity signing public key for transcript binding.
///
/// This hash serves two security purposes:
///
/// 1. **Unknown Key Share (UKS) Prevention**: By including both Alice's and
///    Bob's identity hashes in the transcript, we prevent an attacker from
///    re-using a legitimate handshake between Alice and Bob to establish
///    a session where one party believes they're talking to someone else.
///
/// 2. **Compact Representation**: The full hybrid signing public key is 2,009
///    bytes. Hashing reduces this to 32 bytes for the transcript while
///    maintaining cryptographic binding.
///
/// # Arguments
///
/// * `identity` - The hybrid signing public key to hash
///
/// # Returns
///
/// A 32-byte BLAKE3 hash of the serialised public key.
fn hash_identity(identity: &HybridSigningPublicKey) -> [u8; HASH_SIZE] {
    let bytes = identity.to_bytes();
    *blake3::hash(&bytes).as_bytes()
}

/// Hashes the bundle signing data for transcript binding.
///
/// By including the bundle hash in the transcript, we bind the session keys to:
///
/// - **The specific one-time key**: Prevents replay attacks with different OTKs
/// - **Timestamps**: `created_at` and `expires_at` are part of signed data
/// - **Key IDs**: Helps detect bundle substitution attacks
///
/// This ensures that both parties derive the same session keys only when
/// using the exact same bundle, preventing various transcript manipulation attacks.
///
/// # Arguments
///
/// * `bundle` - The signed pre-key bundle to hash
///
/// # Returns
///
/// A 32-byte BLAKE3 hash of the bundle's signing data.
fn hash_bundle(bundle: &SignedPreKeyBundle) -> [u8; HASH_SIZE] {
    let signing_data = bundle.signing_data();
    *blake3::hash(&signing_data).as_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_size() {
        // 3 hashes + 3 DH + 1 PQ_ss = 3*32 + 3*56 + 32 = 96 + 168 + 32 = 296
        assert_eq!(TRANSCRIPT_SIZE, 296);
    }

    #[test]
    fn test_hash_size() {
        assert_eq!(HASH_SIZE, 32);
    }

    #[test]
    fn test_dh_size() {
        assert_eq!(DH_SIZE, 56);
    }

    #[test]
    fn test_pq_ss_size() {
        assert_eq!(PQ_SS_SIZE, 32);
    }
}
