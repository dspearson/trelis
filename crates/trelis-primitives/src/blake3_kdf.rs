//! BLAKE3-based key derivation with domain separation.
//!
//! This module wraps BLAKE3's `derive_key` function to provide domain-separated
//! key derivation as specified by the Trelis protocol.
//!
//! # Domain Separation Contexts
//!
//! All contexts are immutable `&'static str` values that MUST NOT be changed
//! after protocol deployment. Per Spec Section 14, Table 14.1:
//!
//! ## Core Protocol Contexts
//! - `"trelis-hybrid-kem-v1"` - Hybrid KEM shared secret combination
//! - `"trelis-hybrid-kem-v2"` - Hybrid KEM v2 (binds ct_sntrup, x448_eph, pk_hybrid)
//! - `"trelis-session-v1"` - X3DH-PQ session key derivation
//! - `"trelis-session-v2"` - X3DH-PQ session key derivation (binds version/suite/SessionFlags)
//! - `"trelis-ratchet-init-v1"` - KEM ratchet initial root key derivation
//! - `"trelis-pq-ratchet-root-v1"` - KEM ratchet root key derivation
//! - `"trelis-pq-ratchet-message-v1"` - KEM ratchet message key derivation
//! - `"trelis-ratchet-nonce-v1"` - Hedged nonce derivation
//! - `"trelis-safety-number-v1"` - Safety number fingerprint
//! - `"trelis-aead-commit-v1"` - Committing-AEAD key-commitment subkey (CMT-4)
//!
//! ## Signature Contexts
//! - `"trelis-sig-prekey-bundle-v1"` - Pre-key bundle signature prehash
//! - `"trelis-sig-ratchet-message-v1"` - Per-message ratchet signatures
//! - `"trelis-sig-cocoa-update-v1"` - CoCoA tree update signatures
//! - `"trelis-sig-safety-number-v1"` - Safety number attestation
//! - `"trelis-sig-device-attest-v1"` - Device key attestation
//! - `"trelis-hybrid-sig-bop2-h1-v1"` - Bird-of-Prey-2 H1 (binds full hybrid vk)
//! - `"trelis-hybrid-sig-bop2-h2-v1"` - Bird-of-Prey-2 H2 (Ed448 challenge from sigma2)
//! - `"trelis-hybrid-sig-bop2-h1-ctx-v1"` - Bird-of-Prey-2 H1 (explicit-context signing path, WR-03)
//! - `"trelis-hybrid-sig-bop2-h1-prehash-v1"` - Bird-of-Prey-2 H1 (BLAKE3-prehash signing path, WR-03)
//!
//! ## Device Key Contexts
//! - `"trelis-device-seed-v1"` - Device seed from hardware entropy
//! - `"trelis-device-identity-key-v1"` - Device identity key derivation
//! - `"trelis-device-signing-key-v1"` - Device signing key derivation
//! - `"trelis-bundle-wrap-v1"` - Device key wrap
//!
//! ## Recovery Contexts
//! - `"trelis-recovery-ed448-v1"` - Recovery keypair Ed448 component
//! - `"trelis-recovery-mldsa-v1"` - Recovery keypair ML-DSA-65 component
//! - `"trelis-recovery-x448-v1"` - Recovery keypair X448 component
//! - `"trelis-recovery-sntrup-v1"` - Recovery keypair sntrup761 component
//! - `"trelis-recovery-key-attest-v1"` - Recovery key attestation
//! - `"trelis-recovery-notice-v1"` - Recovery notice signatures
//! - `"trelis-recovery-escrow-v1"` - Recovery key escrow
//!
//! ## Other Contexts
//! - `"trelis-compromise-notice-v1"` - Compromise notice signature
//! - `"trelis-mldsa-hedge-v1"` - Hedged ML-DSA-65 signing
//! - `"trelis-attachment-key-v1"` - Attachment encryption keys
//! - `"trelis-history-sync-v1"` - History sync threads
//! - `"trelis-safety-number-sync-v1"` - Safety number sync
//! - `"trelis-warrant-auth-v1"` - Lawful intercept warrant auth
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::blake3_kdf::{derive_key, hash};
//!
//! // Derive a key with domain separation
//! let input = b"some input material";
//! let key = derive_key("trelis-hybrid-kem-v1", input);
//! assert_eq!(key.len(), 32);
//!
//! // Hash without domain separation
//! let digest = hash(b"some data");
//! assert_eq!(digest.len(), 32);
//! ```

use zeroize::{Zeroize, Zeroizing};

/// Output size for BLAKE3 operations (32 bytes = 256 bits).
pub const OUTPUT_SIZE: usize = 32;

// ============================================================================
// Domain Separation Context Constants
// ============================================================================
//
// These context strings provide cryptographic domain separation for all
// key derivation operations. They MUST NOT be changed after protocol deployment.

/// Context for hybrid KEM shared secret combination.
pub const HYBRID_KEM_CONTEXT: &str = "trelis-hybrid-kem-v1";

/// Context for the v2 hybrid KEM shared secret combination.
///
/// Unlike [`HYBRID_KEM_CONTEXT`] (v1, which binds only `ss_x448 || ss_sntrup`),
/// the v2 combiner binds the full encapsulation into a fixed 184-byte KDF input:
/// `H(ct_sntrup) || H(x448_eph) || H(pk_hybrid) || ss_x448 || ss_sntrup`
/// (X-Wing-shaped; classical-first ordering preserved). This makes
/// MAL-BIND-K-CT / MAL-BIND-K-PK hold under BLAKE3 collision-resistance alone,
/// independent of the unproven sntrup761 C2PRI assumption (v1.5 finding F02).
/// v1 is retained verbatim and stays exercised by its KAT.
pub const HYBRID_KEM_V2_CONTEXT: &str = "trelis-hybrid-kem-v2";

/// Context for the Bird-of-Prey-2 hybrid signature `H1` hash.
///
/// `H1` binds the full hybrid verification key together with the message and
/// Schnorr commitment (`pkID || pkSig || m || com`), giving BUFF
/// exclusive-ownership: the whole hybrid vk is committed into the signed body,
/// so a mixed or forged vk cannot verify. Registered here as the single source
/// of truth; consumed by the BoP-2 signature combiner (phase 49 plan 03).
pub const SIG_BOP2_H1_CONTEXT: &str = "trelis-hybrid-sig-bop2-h1-v1";

/// Context for the Bird-of-Prey-2 hybrid signature `H2` hash.
///
/// `H2` derives the Ed448 Schnorr challenge from `sigma2` (the ML-DSA-65 half)
/// via a wide reduction into a scalar, tying the classical response to *this*
/// `sigma2` and lifting the combiner to strong unforgeability (SUF-CMA).
/// Registered here as the single source of truth; consumed by the BoP-2
/// signature combiner (phase 49 plan 03).
pub const SIG_BOP2_H2_CONTEXT: &str = "trelis-hybrid-sig-bop2-h2-v1";

/// Context for the Bird-of-Prey-2 hybrid signature `H1` hash on the
/// explicit-context signing path (`sign_with_context` / `verify_with_context`).
///
/// Domain-separates the context-signing path from the plain `sign()` path at the
/// `H1` root (WR-03): `sign_with_context(m, ctx)` derives `m'` under this
/// context, so it can no longer collide with `sign(ctx_len || ctx || m)` under
/// [`SIG_BOP2_H1_CONTEXT`]. The plain path ([`SIG_BOP2_H1_CONTEXT`]) is
/// unchanged. Registered here as the single source of truth; consumed by the
/// BoP-2 signature combiner (phase 56 plan 01).
pub const SIG_BOP2_H1_CTX_CONTEXT: &str = "trelis-hybrid-sig-bop2-h1-ctx-v1"; // 32 bytes

/// Context for the Bird-of-Prey-2 hybrid signature `H1` hash on the
/// BLAKE3-prehash signing path (`sign_prehashed` / `verify_prehashed`).
///
/// Domain-separates the prehash-signing path from the plain `sign()` path at the
/// `H1` root (WR-03): `sign_prehashed(ctx, m)` derives `m'` under this context,
/// so `sign(derive_key(ctx, m))` can no longer collide with it. The plain path
/// ([`SIG_BOP2_H1_CONTEXT`]) is unchanged. Registered here as the single source
/// of truth; consumed by the BoP-2 signature combiner (phase 56 plan 01).
pub const SIG_BOP2_H1_PREHASH_CONTEXT: &str = "trelis-hybrid-sig-bop2-h1-prehash-v1"; // 36 bytes

/// Context for X3DH-PQ session key derivation.
pub const SESSION_CONTEXT: &str = "trelis-session-v1";

/// Context for the v2 X3DH-PQ session key derivation.
///
/// Unlike [`SESSION_CONTEXT`] (v1, over the 296-byte 7-field transcript), the
/// v2 context derives over the 299-byte transcript that appends the additive
/// `{version || suite-id || SessionFlags}` framing block after `pq_ss`. This
/// closes the Ch17:236 #2 version/suite-binding MUST (F08) and the §22 H.1
/// LI-capability-bit gap (F18): a downgraded/stripped suite or a toggled LI
/// bit now diverges the derived key (fail-closed).
///
/// v1 is retained verbatim as registry history (additive rule). Unlike the KEM
/// combiner, there is NO live v1 code path — both X3DH-PQ call sites switch to
/// v2 (there are no deployed sessions to remain compatible with).
pub const SESSION_V2_CONTEXT: &str = "trelis-session-v2";

/// Context for double ratchet root key derivation.
pub const RATCHET_ROOT_CONTEXT: &str = "trelis-pq-ratchet-root-v1";

/// Context for double ratchet message key derivation.
pub const RATCHET_MESSAGE_CONTEXT: &str = "trelis-pq-ratchet-message-v1";

/// Context for hedged nonce derivation.
pub const RATCHET_NONCE_CONTEXT: &str = "trelis-ratchet-nonce-v1";

/// Context for the initial KEM-ratchet root key derivation
/// (`derive_initial_root_key` in `trelis-ratchet`).
///
/// Registry-completeness entry so the `trelis-ratchet-init-v1` string sits in
/// the central catalogue alongside its sibling ratchet contexts
/// ([`RATCHET_ROOT_CONTEXT`], [`RATCHET_MESSAGE_CONTEXT`],
/// [`RATCHET_NONCE_CONTEXT`]). `trelis-ratchet`'s `KDF_INIT` re-exports this
/// constant (single source of truth), so the two cannot drift; the value is
/// byte-unchanged.
pub const RATCHET_INIT_CONTEXT: &str = "trelis-ratchet-init-v1";

/// Context for safety number fingerprint.
pub const SAFETY_NUMBER_CONTEXT: &str = "trelis-safety-number-v1";

/// Context for pre-key bundle signature prehash.
pub const PREKEY_BUNDLE_SIG_CONTEXT: &str = "trelis-sig-prekey-bundle-v1";

/// Context for device key wrap.
pub const BUNDLE_WRAP_CONTEXT: &str = "trelis-bundle-wrap-v1";

/// Context for recovery keypair Ed448 component derivation.
///
/// Used when deriving the classical (Ed448) portion of a recovery identity
/// keypair from a recovery seed.
pub const RECOVERY_ED448_CONTEXT: &str = "trelis-recovery-ed448-v1";

/// Context for recovery keypair ML-DSA-65 component derivation.
///
/// Used when deriving the post-quantum (ML-DSA-65) portion of a recovery
/// identity keypair from a recovery seed.
pub const RECOVERY_MLDSA_CONTEXT: &str = "trelis-recovery-mldsa-v1";

/// Context for compromise notice signatures.
///
/// Used as the domain separator when signing a `CompromiseNotice` message
/// to announce that a key has been compromised.
pub const COMPROMISE_NOTICE_CONTEXT: &str = "trelis-compromise-notice-v1";

// ============================================================================
// Committing AEAD Context (Spec Section 4, Phase 54 AEAD-01)
// ============================================================================

/// Context for the committing-AEAD key-commitment subkey (Phase 54, AEAD-01).
///
/// `K_commit = derive_key(AEAD_COMMIT_CONTEXT, K)` keys the BLAKE3 commitment
/// that the committing AEAD wrapper (`aead::encrypt_committing`) appends over
/// the length-framed `(nonce, aad, ciphertext)`. This domain-separates the
/// commitment MAC from every other `derive_key` use, so a commitment can never
/// be confused with a wrap, session, or ratchet key. The wrapper gives the
/// multi-key ("one plaintext, N keys") wraps CMT-4 key commitment: a single
/// committing ciphertext cannot be opened under two different keys. Additive —
/// the base XChaCha20-Poly1305 `aead::encrypt`/`decrypt` are unchanged.
pub const AEAD_COMMIT_CONTEXT: &str = "trelis-aead-commit-v1"; // 21 bytes

// ============================================================================
// Signature Context Constants (Spec Section 14, Table 14.1)
// ============================================================================

/// Context for per-message ratchet signatures.
///
/// Used when signing individual ratchet messages for authentication.
pub const SIG_RATCHET_MESSAGE_CONTEXT: &str = "trelis-sig-ratchet-message-v1";

/// Context for CoCoA tree update signatures.
///
/// Used when signing CoCoA group key agreement update operations.
pub const SIG_COCOA_UPDATE_CONTEXT: &str = "trelis-sig-cocoa-update-v1";

/// Context for safety number attestation signatures.
///
/// Used when signing safety number verification attestations.
pub const SIG_SAFETY_NUMBER_CONTEXT: &str = "trelis-sig-safety-number-v1";

/// Context for device key attestation signatures.
///
/// Used when a device signs an attestation about its keys.
pub const SIG_DEVICE_ATTEST_CONTEXT: &str = "trelis-sig-device-attest-v1";

// ============================================================================
// Device Key Derivation Contexts (Spec Section 14.3)
// ============================================================================

/// Context for device seed derivation from hardware entropy.
///
/// Used by [`derive_device_seed`] to derive a device-specific seed from
/// hardware random sources (e.g. a secure enclave) before that seed is fed
/// into [`HybridIdentityKeypair::generate_from_seed`](../../trelis_hybrid/identity/struct.HybridIdentityKeypair.html).
pub const DEVICE_SEED_CONTEXT: &str = "trelis-device-seed-v1";

/// Context for device identity key derivation.
///
/// Used inside `HybridIdentityKeypair::generate_from_seed` to derive the
/// device's KEM-side identity seed from the device seed (`identity` in this
/// naming refers to "the keypair that *receives* messages addressed to the
/// device", i.e. the X448 + sntrup761 KEM keypair — see
/// [`DEVICE_SIGNING_KEY_CONTEXT`] for the signing side).
pub const DEVICE_IDENTITY_KEY_CONTEXT: &str = "trelis-device-identity-key-v1";

/// Context for device signing key derivation.
///
/// Used inside `HybridIdentityKeypair::generate_from_seed` to derive the
/// device's signing keypair seed from the device seed.
pub const DEVICE_SIGNING_KEY_CONTEXT: &str = "trelis-device-signing-key-v1";

/// Derive a canonical 32-byte device seed from raw hardware entropy.
///
/// This is the recommended pre-step before calling
/// `HybridIdentityKeypair::generate_from_seed`: take the raw hardware-entropy
/// bytes (any length), run them through BLAKE3 with [`DEVICE_SEED_CONTEXT`],
/// and feed the resulting 32-byte seed to the seeded identity-keypair
/// constructor. The same input always produces the same output, so the
/// derived identity is stable across reboots and reproducible from the
/// secure-enclave secret.
///
/// # Threat-model fit
///
/// The hardware entropy itself is the trust root; this function does NOT
/// add entropy, it just provides domain separation so that the same
/// hardware secret cannot be misused as a key in some other Trelis context
/// (the BLAKE3 derive_key construction prevents cross-context substitution).
///
/// # Example
///
/// ```ignore
/// use trelis_primitives::derive_device_seed;
/// // hardware_secret might come from a TPM, SecureEnclave, etc.
/// let hardware_secret = [0x42u8; 32];
/// let device_seed = derive_device_seed(&hardware_secret);
/// // device_seed is now ready for HybridIdentityKeypair::generate_from_seed
/// ```
#[must_use]
pub fn derive_device_seed(hardware_entropy: &[u8]) -> Zeroizing<[u8; OUTPUT_SIZE]> {
    Zeroizing::new(blake3::derive_key(DEVICE_SEED_CONTEXT, hardware_entropy))
}

// ============================================================================
// Additional Recovery Contexts (Spec Appendix C)
// ============================================================================

/// Context for recovery key attestation.
///
/// Used when attesting to the validity of a recovery key.
pub const RECOVERY_KEY_ATTEST_CONTEXT: &str = "trelis-recovery-key-attest-v1";

/// Context for recovery notice signatures.
///
/// Used when signing recovery notice messages.
pub const RECOVERY_NOTICE_CONTEXT: &str = "trelis-recovery-notice-v1";

/// Context for recovery keypair X448 component derivation.
///
/// Used when deriving the X448 KEM portion of recovery keys.
pub const RECOVERY_X448_CONTEXT: &str = "trelis-recovery-x448-v1";

/// Context for recovery keypair sntrup761 component derivation.
///
/// Used when deriving the sntrup761 KEM portion of recovery keys.
pub const RECOVERY_SNTRUP_CONTEXT: &str = "trelis-recovery-sntrup-v1";

/// Context for recovery key escrow.
///
/// Used when escrowing recovery keys with trusted parties.
pub const RECOVERY_ESCROW_CONTEXT: &str = "trelis-recovery-escrow-v1";

// ============================================================================
// Hedged Cryptography Contexts (Spec Section 5.3)
// ============================================================================

/// Context for hedged ML-DSA-65 signing.
///
/// Used to combine fresh entropy with message hash for defence against
/// RNG compromise when generating ML-DSA-65 signatures.
pub const MLDSA_HEDGE_CONTEXT: &str = "trelis-mldsa-hedge-v1";

// ============================================================================
// Sync Contexts (Spec Table 14.1)
// ============================================================================

/// Context for history sync threads.
///
/// Used in multi-device message history synchronisation.
pub const HISTORY_SYNC_CONTEXT: &str = "trelis-history-sync-v1";

/// Context for safety number sync.
///
/// Used when synchronising safety number verifications across devices.
pub const SAFETY_NUMBER_SYNC_CONTEXT: &str = "trelis-safety-number-sync-v1";

/// Context for device-set-bound safety numbers.
///
/// Used by `SafetyNumber::new_with_device_set` to derive a safety number
/// that incorporates each user's current device set. A distinct context
/// from `SAFETY_NUMBER_CONTEXT` so device-set-bound safety numbers cannot
/// be confused with identity-only ones — see spec §15.6.
pub const SAFETY_NUMBER_DEVICE_SET_CONTEXT: &str = "trelis-safety-number-device-set-v1";

/// Context for identity-certificate signatures.
///
/// Used by `IdentityCertificate` (spec §15.4) to bind an attester's
/// hybrid signature to a subject identity public key plus issued/expires
/// metadata. The library does not take a position on whether the issuer
/// is a CA, a relying party, or the subject themselves — it only
/// guarantees that the signature is over a domain-separated body that
/// cannot be confused with any other signed structure in the protocol.
pub const IDENTITY_CERT_CONTEXT: &str = "trelis-identity-cert-v1";

// ============================================================================
// Lawful Intercept Context (Spec Section 22)
// ============================================================================

/// Context for warrant authorisation signatures.
///
/// Used for cryptographic authorisation of lawful intercept warrants.
pub const WARRANT_AUTH_CONTEXT: &str = "trelis-warrant-auth-v1";

/// Derives a key using BLAKE3 with domain separation.
///
/// This is the primary KDF function for the Trelis protocol. The context string
/// provides domain separation to ensure keys derived for different purposes are
/// cryptographically independent.
///
/// # Arguments
///
/// * `context` - A static string identifying the derivation context. This MUST
///   be unique for each use case and MUST NOT change after protocol deployment.
/// * `input` - The input key material to derive from.
///
/// # Returns
///
/// A 32-byte derived key.
///
/// # Security
///
/// The context string is processed through BLAKE3's built-in context handling,
/// which provides proper domain separation without length-extension vulnerabilities.
///
/// The output is wrapped in `Zeroizing<>` so the secret-material bytes are
/// zeroed on drop. Most callers continue to compile
/// unchanged because `Zeroizing<T>: Deref<Target = T>`.
#[must_use]
pub fn derive_key(context: &str, input: &[u8]) -> Zeroizing<[u8; OUTPUT_SIZE]> {
    Zeroizing::new(blake3::derive_key(context, input))
}

/// Computes a BLAKE3 hash of the input.
///
/// This is used for hashing public data (e.g., identity keys for safety numbers).
/// For key derivation, use [`derive_key`] instead to ensure domain separation.
///
/// # Arguments
///
/// * `input` - The data to hash.
///
/// # Returns
///
/// A 32-byte hash digest.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; OUTPUT_SIZE] {
    *blake3::hash(input).as_bytes()
}

/// Computes a keyed BLAKE3 hash (MAC).
///
/// This provides a keyed hash function for message authentication.
///
/// # Arguments
///
/// * `key` - A 32-byte key.
/// * `input` - The data to authenticate.
///
/// # Returns
///
/// A 32-byte authentication tag, wrapped in `Zeroizing<>`.
#[must_use]
pub fn keyed_hash(key: &[u8; OUTPUT_SIZE], input: &[u8]) -> Zeroizing<[u8; OUTPUT_SIZE]> {
    Zeroizing::new(*blake3::keyed_hash(key, input).as_bytes())
}

/// Derives multiple keys from a single input using domain-separated derivation.
///
/// This is useful for protocols that need to derive multiple independent keys
/// from shared secret material (e.g., root key + chain key from X3DH output).
///
/// # Arguments
///
/// * `context_prefix` - Base context string.
/// * `input` - The input key material.
/// * `count` - Number of keys to derive.
///
/// # Returns
///
/// A vector of derived keys, each 32 bytes, each wrapped in `Zeroizing<>`
/// so they zero on drop.
#[cfg(feature = "alloc")]
#[must_use]
pub fn derive_multiple_keys(
    context_prefix: &str,
    input: &[u8],
    count: usize,
) -> alloc::vec::Vec<Zeroizing<[u8; OUTPUT_SIZE]>> {
    use alloc::format;
    use alloc::vec::Vec;

    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let context = format!("{context_prefix}-{i}");
        keys.push(derive_key(&context, input));
    }
    keys
}

/// A wrapper around a derived key that zeroizes on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; OUTPUT_SIZE]);

impl DerivedKey {
    /// Derives a new key with domain separation.
    #[must_use]
    pub fn derive(context: &str, input: &[u8]) -> Self {
        Self(*derive_key(context, input))
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; OUTPUT_SIZE] {
        &self.0
    }

    /// Consumes self and returns the key bytes, wrapped in `Zeroizing<>`
    /// so the consumed material is zeroed on caller drop.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<[u8; OUTPUT_SIZE]> {
        Zeroizing::new(self.0)
    }
}

impl AsRef<[u8]> for DerivedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from specification: context string validation.
    ///
    /// Context: "trelis-hybrid-kem-v1"
    /// Input: 32 zero bytes
    /// Expected output: specified in test-vectors.tex
    #[test]
    fn test_context_string_validation() {
        let context = "trelis-hybrid-kem-v1";
        let input = [0u8; 32];

        let output = derive_key(context, &input);

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);

        // Verify context string is exactly as expected
        assert_eq!(context.as_bytes().len(), 20);
        assert_eq!(
            hex::encode(context.as_bytes()),
            "7472656c69732d6879627269642d6b656d2d7631"
        );

        // v2 KEM context (phase 49 CMB-01) — pinned so an accidental edit to the
        // string fails loudly, exactly like the v1 assertion above.
        assert_eq!(HYBRID_KEM_V2_CONTEXT, "trelis-hybrid-kem-v2");
        assert_eq!(HYBRID_KEM_V2_CONTEXT.as_bytes().len(), 20);
        assert_eq!(
            hex::encode(HYBRID_KEM_V2_CONTEXT.as_bytes()),
            "7472656c69732d6879627269642d6b656d2d7632"
        );

        // BoP-2 signature contexts (single source of truth; consumed by plan 03).
        assert_eq!(SIG_BOP2_H1_CONTEXT, "trelis-hybrid-sig-bop2-h1-v1");
        assert_eq!(SIG_BOP2_H1_CONTEXT.as_bytes().len(), 28);
        assert_eq!(
            hex::encode(SIG_BOP2_H1_CONTEXT.as_bytes()),
            "7472656c69732d6879627269642d7369672d626f70322d68312d7631"
        );
        assert_eq!(SIG_BOP2_H2_CONTEXT, "trelis-hybrid-sig-bop2-h2-v1");
        assert_eq!(SIG_BOP2_H2_CONTEXT.as_bytes().len(), 28);
        assert_eq!(
            hex::encode(SIG_BOP2_H2_CONTEXT.as_bytes()),
            "7472656c69732d6879627269642d7369672d626f70322d68322d7631"
        );

        // WR-03 (phase 56) sibling H1 contexts — byte-pinned so an accidental
        // edit fails loudly, exactly like the base BoP-2 pins above. The plain
        // SIG_BOP2_H1_CONTEXT and its pin above stay byte-frozen (unchanged).
        assert_eq!(SIG_BOP2_H1_CTX_CONTEXT, "trelis-hybrid-sig-bop2-h1-ctx-v1");
        assert_eq!(SIG_BOP2_H1_CTX_CONTEXT.as_bytes().len(), 32);
        assert_eq!(
            hex::encode(SIG_BOP2_H1_CTX_CONTEXT.as_bytes()),
            "7472656c69732d6879627269642d7369672d626f70322d68312d6374782d7631"
        );
        assert_eq!(
            SIG_BOP2_H1_PREHASH_CONTEXT,
            "trelis-hybrid-sig-bop2-h1-prehash-v1"
        );
        assert_eq!(SIG_BOP2_H1_PREHASH_CONTEXT.as_bytes().len(), 36);
        assert_eq!(
            hex::encode(SIG_BOP2_H1_PREHASH_CONTEXT.as_bytes()),
            "7472656c69732d6879627269642d7369672d626f70322d68312d707265686173682d7631"
        );

        // v2 session context (phase 50 TXB-01) — byte-pinned so an accidental
        // edit to the string fails loudly, exactly like the KEM v2 pin above.
        assert_eq!(SESSION_V2_CONTEXT, "trelis-session-v2");
        assert_eq!(SESSION_V2_CONTEXT.as_bytes().len(), 17);
        assert_eq!(
            hex::encode(SESSION_V2_CONTEXT.as_bytes()),
            "7472656c69732d73657373696f6e2d7632"
        );

        // Committing-AEAD context (phase 54 AEAD-01) — byte-pinned so an
        // accidental edit to the string fails loudly, exactly like the KEM/
        // session v2 pins above.
        assert_eq!(AEAD_COMMIT_CONTEXT, "trelis-aead-commit-v1");
        assert_eq!(AEAD_COMMIT_CONTEXT.as_bytes().len(), 21);
        assert_eq!(
            hex::encode(AEAD_COMMIT_CONTEXT.as_bytes()),
            "7472656c69732d616561642d636f6d6d69742d7631"
        );

        // v1 context values are unchanged (additive invariant: v1 retained verbatim).
        assert_eq!(HYBRID_KEM_CONTEXT, "trelis-hybrid-kem-v1");
        assert_eq!(SESSION_CONTEXT, "trelis-session-v1");

        // Different context produces different output
        let other_output = derive_key("trelis-other-context", &input);
        assert_ne!(output, other_output);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let context = "test-context";
        let input = b"test input";

        let key1 = derive_key(context, input);
        let key2 = derive_key(context, input);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_context_sensitivity() {
        let input = b"same input";

        let key1 = derive_key("context-a", input);
        let key2 = derive_key("context-b", input);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_input_sensitivity() {
        let context = "same-context";

        let key1 = derive_key(context, b"input-a");
        let key2 = derive_key(context, b"input-b");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hash_deterministic() {
        let input = b"test data";

        let hash1 = hash(input);
        let hash2 = hash(input);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_sensitivity() {
        let hash1 = hash(b"data-a");
        let hash2 = hash(b"data-b");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0x42u8; 32];
        let input = b"test data";

        let tag1 = keyed_hash(&key, input);
        let tag2 = keyed_hash(&key, input);

        assert_eq!(tag1, tag2);

        // Different key produces different tag
        let other_key = [0x43u8; 32];
        let other_tag = keyed_hash(&other_key, input);
        assert_ne!(tag1, other_tag);
    }

    #[test]
    fn test_derived_key_wrapper() {
        let key = DerivedKey::derive("test", b"input");

        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_derive_multiple_keys() {
        let keys = derive_multiple_keys("test-prefix", b"input", 3);

        assert_eq!(keys.len(), 3);

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_empty_input() {
        // Should handle empty input without panicking
        let key = derive_key("context", b"");
        assert_eq!(key.len(), 32);

        let h = hash(b"");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_large_input() {
        // Should handle large input
        let large_input = [0xffu8; 10000];
        let key = derive_key("context", &large_input);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_device_seed_deterministic() {
        let hardware_entropy = b"hardware-attested-bytes-from-enclave";
        let s1 = derive_device_seed(hardware_entropy);
        let s2 = derive_device_seed(hardware_entropy);
        assert_eq!(
            *s1, *s2,
            "same hardware_entropy must produce identical seed"
        );
        assert_eq!(s1.len(), OUTPUT_SIZE);
    }

    #[test]
    fn test_derive_device_seed_input_sensitive() {
        let s_a = derive_device_seed(b"input-a");
        let s_b = derive_device_seed(b"input-b");
        assert_ne!(
            *s_a, *s_b,
            "distinct hardware_entropy must produce distinct seeds"
        );
    }

    #[test]
    fn test_derive_device_seed_context_domain_separated() {
        // derive_device_seed MUST be domain-separated from raw derive_key.
        // A caller who naively re-used the same input bytes against a generic
        // derive_key call with a different context must not collide.
        let input = b"shared-input";
        let device_seed = derive_device_seed(input);
        let raw = derive_key("trelis-some-other-context-v1", input);
        assert_ne!(
            *device_seed, *raw,
            "device_seed must not collide with raw derive_key under another context"
        );
    }

    #[test]
    fn test_derive_device_seed_accepts_variable_length() {
        // The function takes any-length input; BLAKE3 hashes it through.
        // Empty, short, long must all produce 32-byte outputs and not panic.
        let empty = derive_device_seed(b"");
        let short = derive_device_seed(b"x");
        let long = derive_device_seed(&[0xAAu8; 4096]);
        assert_eq!(empty.len(), OUTPUT_SIZE);
        assert_eq!(short.len(), OUTPUT_SIZE);
        assert_eq!(long.len(), OUTPUT_SIZE);
        // All three should be distinct (BLAKE3 collision probability is
        // negligible for these inputs).
        assert_ne!(*empty, *short);
        assert_ne!(*empty, *long);
        assert_ne!(*short, *long);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: BLAKE3 hash is deterministic - same input always produces same output.
        #[test]
        fn hash_is_deterministic(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let hash1 = hash(&input);
            let hash2 = hash(&input);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: BLAKE3 derive_key is deterministic with same context and input.
        #[test]
        fn derive_key_is_deterministic(
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let context = "test-context-for-proptest";
            let key1 = derive_key(context, &input);
            let key2 = derive_key(context, &input);
            prop_assert_eq!(key1, key2);
        }

        /// Property: Different contexts produce different outputs (with high probability).
        #[test]
        fn different_contexts_different_outputs(
            input in proptest::collection::vec(any::<u8>(), 1..256),
            context1 in "[a-z]{5,20}",
            context2 in "[a-z]{5,20}",
        ) {
            prop_assume!(context1 != context2);
            let key1 = derive_key(&context1, &input);
            let key2 = derive_key(&context2, &input);
            prop_assert_ne!(key1, key2);
        }

        /// Property: Different inputs produce different outputs (with high probability).
        #[test]
        fn different_inputs_different_outputs(
            input1 in proptest::collection::vec(any::<u8>(), 1..256),
            input2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(input1 != input2);
            let context = "same-context-for-both";
            let key1 = derive_key(context, &input1);
            let key2 = derive_key(context, &input2);
            prop_assert_ne!(key1, key2);
        }

        /// Property: Hash output is always OUTPUT_SIZE bytes.
        #[test]
        fn hash_output_size_constant(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let h = hash(&input);
            prop_assert_eq!(h.len(), OUTPUT_SIZE);
        }

        /// Property: derive_key output is always OUTPUT_SIZE bytes.
        #[test]
        fn derive_key_output_size_constant(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let context = "test-context";
            let key = derive_key(context, &input);
            prop_assert_eq!(key.len(), OUTPUT_SIZE);
        }

        /// Property: keyed_hash is deterministic.
        #[test]
        fn keyed_hash_is_deterministic(
            key in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tag1 = keyed_hash(&key, &input);
            let tag2 = keyed_hash(&key, &input);
            prop_assert_eq!(tag1, tag2);
        }

        /// Property: Different keys produce different keyed_hash outputs.
        #[test]
        fn different_keys_different_keyed_hash(
            key1 in proptest::array::uniform32(any::<u8>()),
            key2 in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(key1 != key2);
            let tag1 = keyed_hash(&key1, &input);
            let tag2 = keyed_hash(&key2, &input);
            prop_assert_ne!(tag1, tag2);
        }

        /// Property: keyed_hash output is always OUTPUT_SIZE bytes.
        #[test]
        fn keyed_hash_output_size_constant(
            key in proptest::array::uniform32(any::<u8>()),
            input in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let tag = keyed_hash(&key, &input);
            prop_assert_eq!(tag.len(), OUTPUT_SIZE);
        }

        /// Property: DerivedKey wrapper preserves key bytes.
        #[test]
        fn derived_key_wrapper_preserves_bytes(
            input in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let context = "wrapper-test";
            let key = DerivedKey::derive(context, &input);
            let raw = derive_key(context, &input);
            prop_assert_eq!(*key.as_bytes(), *raw);
        }

        /// Property: DerivedKey into_bytes returns same bytes as as_bytes.
        #[test]
        fn derived_key_into_bytes_consistent(
            input in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let context = "into-bytes-test";
            let key = DerivedKey::derive(context, &input);
            let expected = *key.as_bytes();
            let actual = key.into_bytes();
            prop_assert_eq!(*actual, expected);
        }

        /// Property: hash of different inputs produces different outputs.
        #[test]
        fn hash_different_inputs_different_outputs(
            input1 in proptest::collection::vec(any::<u8>(), 1..256),
            input2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(input1 != input2);
            let hash1 = hash(&input1);
            let hash2 = hash(&input2);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Empty input produces valid output.
        #[test]
        fn empty_input_valid_output(_dummy: u8) {
            // Empty input should not panic and should produce valid 32-byte output
            let h = hash(b"");
            prop_assert_eq!(h.len(), OUTPUT_SIZE);

            let key = derive_key("context", b"");
            prop_assert_eq!(key.len(), OUTPUT_SIZE);
        }

        /// Property: Context string affects output even with empty input.
        #[test]
        fn context_affects_empty_input(
            context1 in "[a-z]{5,20}",
            context2 in "[a-z]{5,20}",
        ) {
            prop_assume!(context1 != context2);
            let key1 = derive_key(&context1, b"");
            let key2 = derive_key(&context2, b"");
            prop_assert_ne!(key1, key2);
        }
    }
}
