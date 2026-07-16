//! Transcript binding for X3DH-PQ key derivation.
//!
//! The transcript ensures that all parties derive the same session keys
//! and prevents unknown-key-share (UKS) attacks by binding identities
//! and the pre-key bundle into the key derivation.

use trelis_hybrid::HybridSigningPublicKey;
use trelis_wire::constants::{CIPHER_SUITE, PROTOCOL_VERSION, SNTRUP761_SS_SIZE, X448_PK_SIZE};
use zeroize::{Zeroize, Zeroizing};

use crate::bundle::SignedPreKeyBundle;

/// Context strings for X3DH-PQ session key derivation, re-exported from the
/// `trelis_primitives::blake3_kdf` registry. `SESSION_CONTEXT` (v1) is retained
/// verbatim as registry history; [`Transcript::derive_shared_secret`] derives
/// under `SESSION_V2_CONTEXT`, which binds the additive
/// `{version ‖ suite-id ‖ SessionFlags}` framing block (299-byte transcript).
pub use trelis_primitives::{SESSION_CONTEXT, SESSION_V2_CONTEXT};

/// Size of a BLAKE3 hash output.
pub const HASH_SIZE: usize = 32;

/// Size of X448 DH output.
pub const DH_SIZE: usize = X448_PK_SIZE;

/// Size of sntrup761 shared secret.
pub const PQ_SS_SIZE: usize = SNTRUP761_SS_SIZE;

/// Size of the trailing `{version ‖ suite-id ‖ SessionFlags}` framing block
/// appended to the transcript: 1 B `PROTOCOL_VERSION` + 1 B `CIPHER_SUITE`
/// + 1 B `SessionFlags`.
pub const FRAMING_SIZE: usize = 3;

/// Total size of the transcript input:
/// - 3 hashes (32 B each): H(I_a), H(I_b), H(bundle)
/// - 3 DH outputs (56 B each): DH1, DH2, DH3
/// - 1 PQ shared secret (32 B): PQ_ss
/// - 1 framing block (3 B): `PROTOCOL_VERSION` ‖ `CIPHER_SUITE` ‖ `SessionFlags`
///
/// The framing block is appended after `pq_ss` at offsets 296/297/298, binding
/// the negotiated version + cipher-suite and the LI-capability bit into the KDF
/// input so a downgrade/strip or a toggled LI bit diverges the derived key.
pub const TRANSCRIPT_SIZE: usize = 3 * HASH_SIZE + 3 * DH_SIZE + PQ_SS_SIZE + FRAMING_SIZE;

/// Per-session capability flags bound into the X3DH-PQ transcript.
///
/// Mirrors crypto-spec §22 H.1 `SessionFlags`: bit 0 carries the
/// Lawful-Interception (LI) capability; bits 1..=7 are reserved and MUST
/// serialise as zero. Binding this byte into the transcript makes a toggled LI
/// bit diverge the derived key — the §22 H.1 transparency property (F18).
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct SessionFlags {
    /// Whether this session is Lawful-Interception-capable (transcript bit 0).
    pub li_capable: bool,
}

impl SessionFlags {
    /// Serialises the flags to the single transcript byte.
    ///
    /// Returns `[0x01]` when `li_capable`, else `[0x00]`. Bits 1..=7 (reserved)
    /// are always zero, so both handshake sides emit an identical byte.
    #[must_use]
    pub fn to_transcript_bytes(self) -> [u8; 1] {
        [u8::from(self.li_capable)]
    }
}

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
    /// Per-session capability flags (LI-capability bit); serialised into the
    /// trailing framing block. `version`/`suite-id` are protocol constants read
    /// from `trelis_wire` in `to_bytes()` and are not stored here.
    flags: SessionFlags,
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
    /// * `flags` - per-session capability flags (LI-capability bit); both
    ///   parties MUST pass the identical value or the derived key diverges
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alice_identity: &HybridSigningPublicKey,
        bob_identity: &HybridSigningPublicKey,
        bundle: &SignedPreKeyBundle,
        dh1: &[u8; DH_SIZE],
        dh2: &[u8; DH_SIZE],
        dh3: &[u8; DH_SIZE],
        pq_ss: &[u8; PQ_SS_SIZE],
        flags: SessionFlags,
    ) -> Self {
        Self {
            alice_identity_hash: hash_identity(alice_identity),
            bob_identity_hash: hash_identity(bob_identity),
            bundle_hash: hash_bundle(bundle),
            dh1: *dh1,
            dh2: *dh2,
            dh3: *dh3,
            pq_ss: *pq_ss,
            flags,
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
    /// 8. PROTOCOL_VERSION - 1 byte (offset 296)
    /// 9. CIPHER_SUITE - 1 byte (offset 297)
    /// 10. SessionFlags - 1 byte (offset 298)
    ///
    /// Total: 299 bytes (the 296-byte core plus the trailing 3-byte
    /// `{version ‖ suite-id ‖ SessionFlags}` framing block).
    ///
    /// The output contains DH and PQ shared-secret bytes, so it is wrapped
    /// in `Zeroizing<>` to ensure the intermediate KDF input is zeroized on
    /// drop.
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
        offset += PQ_SS_SIZE;

        // Trailing framing block: version ‖ suite-id ‖ SessionFlags (F08 + F18).
        // version/suite come from the wire constants (single source of truth);
        // the SessionFlags byte is the only per-session input. Any difference on
        // either side diverges the derived key (fail-closed).
        output[offset] = PROTOCOL_VERSION;
        output[offset + 1] = CIPHER_SUITE;
        output[offset + 2] = self.flags.to_transcript_bytes()[0];

        output
    }

    /// Derives the shared secret using BLAKE3 derive_key.
    ///
    /// This produces a 32-byte shared secret that is then used to derive
    /// the root key, send chain, and receive chain. Wrapped in `Zeroizing<>`.
    #[must_use]
    pub fn derive_shared_secret(&self) -> Zeroizing<[u8; HASH_SIZE]> {
        let transcript_bytes = self.to_bytes();
        Zeroizing::new(blake3::derive_key(
            SESSION_V2_CONTEXT,
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
        // 3 hashes + 3 DH + 1 PQ_ss + 3 framing
        //   = 3*32 + 3*56 + 32 + 3 = 96 + 168 + 32 + 3 = 299
        assert_eq!(TRANSCRIPT_SIZE, 299);
        assert_eq!(FRAMING_SIZE, 3);
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
