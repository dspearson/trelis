//! Hybrid shared secret combination.
//!
//! This module provides the shared secret combiner used by hybrid KEM operations.
//! The combiner uses BLAKE3's key derivation with domain separation to combine
//! classical (X448) and post-quantum (sntrup761) shared secrets.
//!
//! # Combination Order
//!
//! The classical component (X448, 56 bytes) is concatenated first, followed by
//! the post-quantum component (sntrup761, 32 bytes). This ordering is normative
//! and MUST be followed by all implementations for interoperability.
//!
//! # v2 Combiner
//!
//! [`HybridSharedSecret::combine_v2`] additionally binds the full encapsulation
//! (sntrup761 ciphertext, X448 ephemeral, recipient hybrid public key) into the
//! KDF, making key/ciphertext and key/public-key binding hold under BLAKE3
//! collision-resistance alone — independent of the sntrup761 C2PRI assumption
//! (v1.5 finding F02). v1 [`HybridSharedSecret::combine`] is retained verbatim.
//!
//! # Example
//!
//! ```
//! use trelis_hybrid::combiner::HybridSharedSecret;
//!
//! let x448_ss = [0x11u8; 56];   // X448 shared secret
//! let sntrup_ss = [0x22u8; 32]; // sntrup761 shared secret
//!
//! let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
//! assert_eq!(combined.as_bytes().len(), 32);
//! ```

use subtle::ConstantTimeEq;
use trelis_primitives::blake3_kdf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of X448 shared secret in bytes.
pub const X448_SS_SIZE: usize = 56;

/// Size of sntrup761 shared secret in bytes.
pub const SNTRUP_SS_SIZE: usize = 32;

/// Size of combined input to the v1 KDF.
pub const COMBINED_INPUT_SIZE: usize = X448_SS_SIZE + SNTRUP_SS_SIZE;

/// Size of the fixed v2 combiner KDF input.
///
/// Layout: `H(ct_sntrup)[32] || H(x448_eph)[32] || H(pk_hybrid)[32] ||
/// ss_x448[56] || ss_sntrup[32]` = 184 bytes (X-Wing-shaped, classical-first).
pub const V2_COMBINED_INPUT_SIZE: usize = 184;

/// Size of derived hybrid shared secret.
pub const SHARED_SECRET_SIZE: usize = 32;

/// Combined hybrid shared secret.
///
/// This is the result of combining X448 and sntrup761 shared secrets using
/// BLAKE3 key derivation. The combined secret is suitable for use as input
/// to further key derivation or directly as a symmetric key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl HybridSharedSecret {
    /// Combines X448 and sntrup761 shared secrets into a hybrid shared secret.
    ///
    /// # Arguments
    ///
    /// * `x448_ss` - The X448 (classical) shared secret (56 bytes)
    /// * `sntrup_ss` - The sntrup761 (post-quantum) shared secret (32 bytes)
    ///
    /// # Returns
    ///
    /// A 32-byte hybrid shared secret derived using BLAKE3.
    ///
    /// # Security
    ///
    /// The combination order is normative: X448 first, then sntrup761.
    /// The intermediate concatenation buffer is zeroized after use.
    #[must_use]
    pub fn combine(x448_ss: &[u8; X448_SS_SIZE], sntrup_ss: &[u8; SNTRUP_SS_SIZE]) -> Self {
        let mut input = [0u8; COMBINED_INPUT_SIZE];
        input[..X448_SS_SIZE].copy_from_slice(x448_ss);
        input[X448_SS_SIZE..].copy_from_slice(sntrup_ss);

        let combined = blake3_kdf::derive_key(blake3_kdf::HYBRID_KEM_CONTEXT, &input);
        input.zeroize();

        Self { bytes: *combined }
    }

    /// Combines the two shared secrets **and** the full encapsulation into a
    /// hybrid shared secret (v2, X-Wing-shaped).
    ///
    /// Beyond the v1 inputs, v2 binds the sntrup761 ciphertext, the X448
    /// ephemeral public key, and the recipient's static hybrid public key into
    /// the KDF. This makes MAL-BIND-K-CT / MAL-BIND-K-PK hold under BLAKE3
    /// collision-resistance alone, independent of the unproven sntrup761 C2PRI
    /// assumption (v1.5 finding F02). Every downstream KEM consumer inherits the
    /// property because the fix is at the combiner root.
    ///
    /// # Arguments
    ///
    /// * `x448_ss` - The X448 (classical) shared secret (56 bytes)
    /// * `sntrup_ss` - The sntrup761 (post-quantum) shared secret (32 bytes)
    /// * `ct_sntrup` - The transmitted sntrup761 ciphertext (any length; hashed to 32 bytes)
    /// * `x448_eph` - The transmitted X448 ephemeral public key (any length; hashed to 32 bytes)
    /// * `pk_hybrid` - The recipient's static hybrid public key (any length; hashed to 32 bytes)
    ///
    /// # Returns
    ///
    /// A 32-byte hybrid shared secret derived using BLAKE3.
    ///
    /// # Security
    ///
    /// Each variable-length component is hashed to 32 bytes so the KDF input is a
    /// fixed 184 bytes, foreclosing any length / canonical-encoding ambiguity.
    /// The X448 ephemeral is bound by its **transmitted encoding** (matching the
    /// peer's view, exactly as X-Wing hashes the wire ciphertext), not a
    /// re-canonicalised point. The classical-first ordering (`ss_x448` before
    /// `ss_sntrup`) is preserved. The intermediate buffer is zeroized after use.
    #[must_use]
    pub fn combine_v2(
        x448_ss: &[u8; X448_SS_SIZE],
        sntrup_ss: &[u8; SNTRUP_SS_SIZE],
        ct_sntrup: &[u8],
        x448_eph: &[u8],
        pk_hybrid: &[u8],
    ) -> Self {
        let mut input = [0u8; V2_COMBINED_INPUT_SIZE];
        // Fixed 32-byte digests of the three variable-length wire components.
        input[0..32].copy_from_slice(&blake3_kdf::hash(ct_sntrup));
        input[32..64].copy_from_slice(&blake3_kdf::hash(x448_eph));
        input[64..96].copy_from_slice(&blake3_kdf::hash(pk_hybrid));
        // Classical-first ordering (normative): ss_x448 [96..152], ss_sntrup [152..184].
        input[96..96 + X448_SS_SIZE].copy_from_slice(x448_ss);
        input[96 + X448_SS_SIZE..].copy_from_slice(sntrup_ss);

        let combined = blake3_kdf::derive_key(blake3_kdf::HYBRID_KEM_V2_CONTEXT, &input);
        input.zeroize();

        Self { bytes: *combined }
    }

    /// Returns the shared secret as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }

    /// Returns the shared secret as a byte array, consuming self.
    ///
    /// The bytes are wrapped in `Zeroizing<...>` so the caller's storage is
    /// automatically zeroised on drop. Returning a raw `[u8; N]` would defeat
    /// the type's `ZeroizeOnDrop` guarantee for the consumed value.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<[u8; SHARED_SECRET_SIZE]> {
        Zeroizing::new(self.bytes)
    }

    /// Creates a shared secret from raw bytes.
    ///
    /// This is primarily for testing or when receiving a pre-computed secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self { bytes }
    }
}

impl ConstantTimeEq for HybridSharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for HybridSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for HybridSharedSecret {}

impl core::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSharedSecret")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    // `format!` requires alloc; gated so the rest of the test module still
    // compiles under `--no-default-features` for MIRI.
    #[cfg(feature = "alloc")]
    use alloc::format;

    #[test]
    fn test_combine_produces_32_bytes() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        assert_eq!(combined.as_bytes().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_combine_is_deterministic() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);

        assert_eq!(combined1, combined2);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let x448_ss1 = [0x11u8; X448_SS_SIZE];
        let x448_ss2 = [0x22u8; X448_SS_SIZE];
        let sntrup_ss = [0x33u8; SNTRUP_SS_SIZE];

        let combined1 = HybridSharedSecret::combine(&x448_ss1, &sntrup_ss);
        let combined2 = HybridSharedSecret::combine(&x448_ss2, &sntrup_ss);

        assert_ne!(combined1, combined2);
    }

    #[test]
    fn test_order_matters() {
        // Verify that swapping components produces different output
        // (even though we can't actually swap types, we can verify
        // that the combination is not symmetric)
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);

        // Create a "reversed" version by using different input pattern
        let mut reversed_input = [0u8; COMBINED_INPUT_SIZE];
        reversed_input[..SNTRUP_SS_SIZE].copy_from_slice(&sntrup_ss);
        reversed_input[SNTRUP_SS_SIZE..SNTRUP_SS_SIZE + X448_SS_SIZE].copy_from_slice(&x448_ss);

        let reversed = blake3_kdf::derive_key(blake3_kdf::HYBRID_KEM_CONTEXT, &reversed_input);
        assert_ne!(combined.as_bytes(), &*reversed);
    }

    // --- v2 combiner (X-Wing-shaped, binds the full encapsulation) ---
    //
    // Fixed, deterministic sample inputs. Sizes match the real encapsulation
    // fields (ct_sntrup 1039 B, x448_eph 56 B, pk_hybrid 1214 B); the exact
    // contents are arbitrary. Declared as `const` so the test module still
    // compiles under `--no-default-features` (no alloc / Vec) for MIRI.
    const V2_SS_X448: [u8; X448_SS_SIZE] = [0x11u8; X448_SS_SIZE];
    const V2_SS_SNTRUP: [u8; SNTRUP_SS_SIZE] = [0x22u8; SNTRUP_SS_SIZE];
    const V2_CT_SNTRUP: [u8; 1039] = [0x33u8; 1039];
    const V2_X448_EPH: [u8; 56] = [0x44u8; 56];
    const V2_PK_HYBRID: [u8; 1214] = [0x55u8; 1214];

    /// 56-byte little-endian add, wrapping mod 2^448. Used to build the
    /// non-canonical X448 sibling `u + p` for the MAL-BIND-K-CT DH-half witness.
    /// Pure `u8` arithmetic (no casts) so it stays clippy-pedantic clean.
    fn le_add_56(a: &[u8; 56], b: &[u8; 56]) -> [u8; 56] {
        let mut out = [0u8; 56];
        let mut carry = false;
        let mut i = 0;
        while i < 56 {
            let (s1, o1) = a[i].overflowing_add(b[i]);
            let (s2, o2) = s1.overflowing_add(u8::from(carry));
            out[i] = s2;
            carry = o1 || o2;
            i += 1;
        }
        out
    }

    #[test]
    fn test_combine_v2_produces_32_bytes() {
        let out = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_eq!(out.as_bytes().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_combine_v2_deterministic() {
        let out1 = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let out2 = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_combine_v2_binds_ct_sntrup() {
        let base = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let mut ct2 = V2_CT_SNTRUP;
        ct2[0] ^= 0x01;
        let flipped = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &ct2,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_ne!(base, flipped, "flipping ct_sntrup must change the v2 key");
    }

    #[test]
    fn test_combine_v2_binds_x448_eph() {
        let base = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let mut eph2 = V2_X448_EPH;
        eph2[0] ^= 0x01;
        let flipped = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &eph2,
            &V2_PK_HYBRID,
        );
        assert_ne!(base, flipped, "flipping x448_eph must change the v2 key");
    }

    #[test]
    fn test_combine_v2_binds_pk_hybrid() {
        let base = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let mut pk2 = V2_PK_HYBRID;
        pk2[0] ^= 0x01;
        let flipped = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &pk2,
        );
        assert_ne!(base, flipped, "flipping pk_hybrid must change the v2 key");
    }

    #[test]
    fn test_combine_v2_classical_first_layout() {
        // Prove the exact 184-byte input layout, including classical-first
        // ordering: ss_x448 occupies input[96..152], ss_sntrup input[152..184].
        let out = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );

        let mut expected_input = [0u8; V2_COMBINED_INPUT_SIZE];
        expected_input[0..32].copy_from_slice(&blake3_kdf::hash(&V2_CT_SNTRUP));
        expected_input[32..64].copy_from_slice(&blake3_kdf::hash(&V2_X448_EPH));
        expected_input[64..96].copy_from_slice(&blake3_kdf::hash(&V2_PK_HYBRID));
        expected_input[96..152].copy_from_slice(&V2_SS_X448); // classical first
        expected_input[152..184].copy_from_slice(&V2_SS_SNTRUP);
        let expected = blake3_kdf::derive_key(blake3_kdf::HYBRID_KEM_V2_CONTEXT, &expected_input);
        assert_eq!(out.as_bytes(), &*expected);

        // Swapping the two shared-secret regions must change the key (ordering
        // is normative, not symmetric).
        let mut swapped = [0u8; V2_COMBINED_INPUT_SIZE];
        swapped[0..96].copy_from_slice(&expected_input[0..96]);
        swapped[96..128].copy_from_slice(&V2_SS_SNTRUP); // sntrup where x448 belongs
        swapped[128..184].copy_from_slice(&V2_SS_X448);
        let swapped_key = blake3_kdf::derive_key(blake3_kdf::HYBRID_KEM_V2_CONTEXT, &swapped);
        assert_ne!(out.as_bytes(), &*swapped_key);
    }

    #[test]
    fn test_combine_v2_differs_from_v1() {
        // v2 must not collide with v1 on the same shared secrets (distinct
        // context + distinct input shape).
        let v1 = HybridSharedSecret::combine(&V2_SS_X448, &V2_SS_SNTRUP);
        let v2 = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let bytes = *combined.as_bytes();

        let recovered = HybridSharedSecret::from_bytes(bytes);
        assert_eq!(combined, recovered);
    }

    #[test]
    fn test_into_bytes() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let expected = *combined.as_bytes();

        let bytes = combined.into_bytes();
        assert_eq!(*bytes, expected);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_debug_redacts_secret() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let debug_str = format!("{:?}", combined);

        // Debug should NOT contain the actual bytes
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("0x11"));
    }

    // --- MAL-BIND (CMB-01, v1.5 F02): non-tautological v1-vs-v2 contrast ---

    #[cfg_attr(miri, ignore)]
    #[test]
    fn mal_bind_k_ct_dh_half() {
        // The genuine MAL-BIND-K-CT witness on the DH half: two DISTINCT 56-byte
        // X448 ephemeral encodings that diffie_hellman maps to the SAME ss_x448 —
        // the canonical base point u = 5 and its non-canonical sibling u + p
        // (p = 2^448 - 2^224 - 1). X448 from_bytes performs no canonicality check
        // and the Montgomery ladder reduces mod p, so both yield one shared
        // secret. Under v1 (no ephemeral binding) the hybrid key is IDENTICAL
        // (the gap); under v2 it DIFFERS because H(x448_eph) differs.
        use trelis_primitives::x448::{X448Public, X448Secret};

        // Curve448 field prime p, little-endian: 0xFF x28, 0xFE, 0xFF x27.
        let mut p448 = [0xFFu8; 56];
        p448[28] = 0xFE;

        // Canonical encoding: base point u = 5.
        let mut u_canonical = [0u8; 56];
        u_canonical[0] = 5;
        // Non-canonical sibling u + p (a distinct wire encoding reducing to u=5).
        let u_sibling = le_add_56(&u_canonical, &p448);
        assert_ne!(
            u_canonical, u_sibling,
            "the two ephemeral encodings must be distinct on the wire"
        );

        // Deterministic recipient X448 secret (from_bytes clamps; no RNG needed).
        let secret = X448Secret::from_bytes([0x07u8; 56]);
        let eph_canonical = X448Public::from_array(u_canonical);
        let eph_sibling = X448Public::from_array(u_sibling);

        // Witness validity: both encodings decapsulate to the SAME ss_x448.
        let ss_canonical = secret
            .diffie_hellman(&eph_canonical)
            .expect("canonical u=5 is a valid, non-low-order point");
        let ss_sibling = secret
            .diffie_hellman(&eph_sibling)
            .expect("sibling u+p reduces to u=5, also valid");
        assert_eq!(
            ss_canonical.as_bytes(),
            ss_sibling.as_bytes(),
            "witness invalid: the sibling encoding must yield the same ss_x448"
        );

        let sntrup_ss = V2_SS_SNTRUP;

        // v1 arm: combine() ignores the ephemeral, so the two distinct wire
        // ciphertexts give the SAME key — MAL-BIND-K-CT VIOLATED under v1.
        let v1_canonical = HybridSharedSecret::combine(ss_canonical.as_bytes(), &sntrup_ss);
        let v1_sibling = HybridSharedSecret::combine(ss_sibling.as_bytes(), &sntrup_ss);
        let v1_key_same = v1_canonical == v1_sibling;
        assert!(v1_key_same, "v1 gap must exist: same ss => same v1 key");

        // v2 arm: combine_v2 binds H(x448_eph), so the distinct encodings give
        // DIFFERENT keys — MAL-BIND-K-CT CLOSED under v2.
        let v2_canonical = HybridSharedSecret::combine_v2(
            ss_canonical.as_bytes(),
            &sntrup_ss,
            &V2_CT_SNTRUP,
            &u_canonical,
            &V2_PK_HYBRID,
        );
        let v2_sibling = HybridSharedSecret::combine_v2(
            ss_sibling.as_bytes(),
            &sntrup_ss,
            &V2_CT_SNTRUP,
            &u_sibling,
            &V2_PK_HYBRID,
        );
        let v2_key_differs = v2_canonical != v2_sibling;
        assert!(
            v2_key_differs,
            "v2 must close the gap: distinct x448_eph => distinct v2 key"
        );
    }

    #[test]
    fn mal_bind_k_ct_pq_half() {
        // PQ half: flip one byte of ct_sntrup with ss_sntrup (and all else) held
        // fixed. The combiner ITSELF must bind the PQ ciphertext, regardless of
        // sntrup761's internal (unproven) C2PRI status — the F02 guarantee.
        let base = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let mut ct2 = V2_CT_SNTRUP;
        ct2[0] ^= 0x01;
        let flipped = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &ct2,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_ne!(
            base, flipped,
            "v2 must bind ct_sntrup even with ss_sntrup fixed"
        );
    }

    #[test]
    fn mal_bind_k_pk() {
        // Same (ss_x448, ss_sntrup, ct_sntrup, x448_eph); two different pk_hybrid.
        let pk_a = V2_PK_HYBRID;
        let mut pk_b = V2_PK_HYBRID;
        pk_b[0] ^= 0x01;

        // v2 binds H(pk_hybrid): distinct recipient pk => distinct key (closed).
        let v2_a = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &pk_a,
        );
        let v2_b = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &pk_b,
        );
        assert_ne!(v2_a, v2_b, "v2 must bind pk_hybrid (MAL-BIND-K-PK closed)");

        // v1 ignores pk entirely: identical keys (the gap v2 closes).
        let v1_a = HybridSharedSecret::combine(&V2_SS_X448, &V2_SS_SNTRUP);
        let v1_b = HybridSharedSecret::combine(&V2_SS_X448, &V2_SS_SNTRUP);
        assert_eq!(v1_a, v1_b, "v1 gap: pk not bound => identical v1 keys");
    }

    #[test]
    fn mal_bind_negative_control() {
        // Anti-tautology guard: identical inputs across both calls MUST still
        // yield identical keys (proves the harness isn't trivially always-different).
        let k1 = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        let k2 = HybridSharedSecret::combine_v2(
            &V2_SS_X448,
            &V2_SS_SNTRUP,
            &V2_CT_SNTRUP,
            &V2_X448_EPH,
            &V2_PK_HYBRID,
        );
        assert_eq!(k1, k2, "identical inputs must yield identical v2 keys");
    }
}

// proptest uses alloc internally, so gate the proptests module behind
// `alloc` to allow `cargo {check,miri test} --no-default-features` to
// reach the rest of the crate.
#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate a 56-byte X448 shared secret.
    fn x448_strategy() -> impl Strategy<Value = [u8; X448_SS_SIZE]> {
        proptest::collection::vec(any::<u8>(), X448_SS_SIZE..=X448_SS_SIZE).prop_map(|v| {
            let mut arr = [0u8; X448_SS_SIZE];
            arr.copy_from_slice(&v);
            arr
        })
    }

    proptest! {
        /// Property: HybridSharedSecret::combine is deterministic.
        /// The same inputs always produce the same output.
        #[cfg_attr(miri, ignore)]
        #[test]
        fn combine_is_deterministic(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined1, combined2);
        }

        /// Property: Equality is reflexive (a == a).
        #[cfg_attr(miri, ignore)]
        #[test]
        fn equality_reflexive(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert!(combined == combined);
        }

        /// Property: Equality is symmetric (a == b implies b == a).
        #[cfg_attr(miri, ignore)]
        #[test]
        fn equality_symmetric(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined1 == combined2, combined2 == combined1);
        }

        /// Property: Equality is transitive (a == b && b == c implies a == c).
        #[cfg_attr(miri, ignore)]
        #[test]
        fn equality_transitive(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let a = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let b = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let c = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            // If a == b and b == c, then a == c
            prop_assert!((a == b && b == c) == (a == c));
        }

        /// Property: Different X448 inputs produce different outputs (with high probability).
        #[cfg_attr(miri, ignore)]
        #[test]
        fn different_x448_different_output(
            x448_ss1 in x448_strategy(),
            x448_ss2 in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(x448_ss1 != x448_ss2);
            let combined1 = HybridSharedSecret::combine(&x448_ss1, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss2, &sntrup_ss);
            prop_assert_ne!(combined1, combined2);
        }

        /// Property: Different sntrup inputs produce different outputs (with high probability).
        #[cfg_attr(miri, ignore)]
        #[test]
        fn different_sntrup_different_output(
            x448_ss in x448_strategy(),
            sntrup_ss1 in proptest::array::uniform32(any::<u8>()),
            sntrup_ss2 in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(sntrup_ss1 != sntrup_ss2);
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss1);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss2);
            prop_assert_ne!(combined1, combined2);
        }

        /// Property: from_bytes roundtrip preserves the secret.
        #[cfg_attr(miri, ignore)]
        #[test]
        fn from_bytes_roundtrip(bytes in proptest::array::uniform32(any::<u8>())) {
            let secret = HybridSharedSecret::from_bytes(bytes);
            prop_assert_eq!(*secret.as_bytes(), bytes);
        }

        /// Property: into_bytes preserves the secret.
        #[cfg_attr(miri, ignore)]
        #[test]
        fn into_bytes_preserves(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let expected = *combined.as_bytes();
            let actual = combined.into_bytes();
            prop_assert_eq!(*actual, expected);
        }

        /// Property: Output is always SHARED_SECRET_SIZE bytes.
        #[cfg_attr(miri, ignore)]
        #[test]
        fn output_size_constant(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined.as_bytes().len(), SHARED_SECRET_SIZE);
        }
    }
}
