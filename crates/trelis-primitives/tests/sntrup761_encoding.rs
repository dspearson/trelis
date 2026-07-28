// Test corpus mirrors the source's representation. Pedantic warnings are
// silenced wholesale.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_borrow,
    clippy::needless_range_loop,
    clippy::manual_clamp,
    clippy::manual_range_contains,
    clippy::useless_asref,
    clippy::clone_on_copy,
    clippy::cast_possible_truncation,
    clippy::unnecessary_cast,
    clippy::pedantic
)]
//! Wire-format encoding and KEM property tests for sntrup761.
//!
//! These tests cover the encoding layer (`small`/`rq`/`rounded` codecs) and
//! end-to-end KEM behaviour of the sntrup761 implementation.
//!
//! # Relationship to the frozen KAT corpus
//!
//! This file was formerly `sntrup761_cross_validation.rs` and ran the C FFI
//! backend against the pure Rust one to prove they agreed. The C backend was
//! removed when PQClean was archived (RUSTSEC-2026-0162, RUSTSEC-2026-0163).
//! Equivalence with the canonical C reference is now enforced by frozen
//! known-answer vectors in `sntrup761_kat.rs`; what remains here are the
//! implementation-independent properties: codec round-trips, size invariants,
//! boundary conditions and KEM self-consistency.
//!
//! Run with: cargo test -p trelis-primitives --test sntrup761_encoding

#![cfg(feature = "std")]

use rayon::prelude::*;
use trelis_primitives::sntrup761::encoding::{
    P, Q, Q12, ROUNDED_BYTES, RQ_BYTES, SMALL_BYTES, rounded_decode, rounded_encode, rq_decode,
    rq_encode, small_decode, small_encode,
};
use trelis_primitives::sntrup761::{
    CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE, Sntrup761Ciphertext,
    Sntrup761PublicKey, Sntrup761SecretKey,
};

// ============================================================================
// Encoding Roundtrip Tests
// ============================================================================

#[test]
fn test_small_encode_decode_roundtrip_all_patterns() {
    // Test all possible 3-value patterns at each position
    for pattern in 0..27 {
        // 3^3 = 27 patterns for first 3 coefficients
        let mut coeffs = [0i8; P];
        coeffs[0] = ((pattern % 3) as i8) - 1;
        coeffs[1] = (((pattern / 3) % 3) as i8) - 1;
        coeffs[2] = (((pattern / 9) % 3) as i8) - 1;

        let encoded = small_encode(&coeffs);
        let decoded = small_decode(&encoded);

        assert_eq!(
            coeffs,
            decoded,
            "Small roundtrip failed for pattern {}: {:?} -> {:?}",
            pattern,
            &coeffs[..3],
            &decoded[..3]
        );
    }
}

#[test]
fn test_small_encode_decode_alternating() {
    // Test alternating -1, 0, 1 pattern
    let mut coeffs = [0i8; P];
    for i in 0..P {
        coeffs[i] = ((i % 3) as i8) - 1;
    }

    let encoded = small_encode(&coeffs);
    let decoded = small_decode(&encoded);

    assert_eq!(coeffs, decoded, "Alternating pattern roundtrip failed");
}

#[test]
fn test_small_encode_decode_all_minus_one() {
    let coeffs = [-1i8; P];
    let encoded = small_encode(&coeffs);
    let decoded = small_decode(&encoded);
    assert_eq!(coeffs, decoded);
}

#[test]
fn test_small_encode_decode_all_zero() {
    let coeffs = [0i8; P];
    let encoded = small_encode(&coeffs);
    let decoded = small_decode(&encoded);
    assert_eq!(coeffs, decoded);
}

#[test]
fn test_small_encode_decode_all_one() {
    let coeffs = [1i8; P];
    let encoded = small_encode(&coeffs);
    let decoded = small_decode(&encoded);
    assert_eq!(coeffs, decoded);
}

#[test]
fn test_rq_encode_decode_zero_polynomial() {
    let coeffs = [0i16; P];
    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);
    assert_eq!(coeffs, decoded, "Zero polynomial roundtrip failed");
}

#[test]
fn test_rq_encode_decode_max_values() {
    // Test with maximum positive values
    let coeffs = [Q12; P];
    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);
    assert_eq!(coeffs, decoded, "Max positive roundtrip failed");
}

#[test]
fn test_rq_encode_decode_min_values() {
    // Test with maximum negative values
    let coeffs = [-Q12; P];
    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);
    assert_eq!(coeffs, decoded, "Max negative roundtrip failed");
}

#[test]
fn test_rq_encode_decode_alternating_extremes() {
    let mut coeffs = [0i16; P];
    for i in 0..P {
        coeffs[i] = if i % 2 == 0 { Q12 } else { -Q12 };
    }
    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);
    assert_eq!(coeffs, decoded, "Alternating extremes roundtrip failed");
}

#[test]
fn test_rq_encode_decode_sequential_values() {
    let mut coeffs = [0i16; P];
    for i in 0..P {
        // Values spanning the full range
        coeffs[i] = ((i as i32 * 6 - (P as i32 * 3)) % (Q as i32)) as i16;
        // Clamp to valid range
        if coeffs[i] > Q12 {
            coeffs[i] = Q12;
        }
        if coeffs[i] < -Q12 {
            coeffs[i] = -Q12;
        }
    }
    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);
    assert_eq!(coeffs, decoded, "Sequential values roundtrip failed");
}

#[test]
fn test_rounded_encode_decode_zero() {
    let coeffs = [0i16; P];
    let encoded = rounded_encode(&coeffs);
    let decoded = rounded_decode(&encoded);

    // Rounded encoding divides by 3 then multiplies back, so small values should stay small
    for (i, (&orig, &dec)) in coeffs.iter().zip(decoded.iter()).enumerate() {
        assert!(
            (orig - dec).abs() <= 3,
            "Rounded zero mismatch at {}: expected ~{}, got {}",
            i,
            orig,
            dec
        );
    }
}

#[test]
fn test_rounded_encode_decode_multiples_of_three() {
    // Values that are multiples of 3 should roundtrip exactly
    let mut coeffs = [0i16; P];
    for i in 0..P {
        coeffs[i] = (((i as i32 * 9) % 2100) - 1050) as i16;
        // Ensure multiple of 3
        coeffs[i] = (coeffs[i] / 3) * 3;
    }

    let encoded = rounded_encode(&coeffs);
    let decoded = rounded_decode(&encoded);

    for (i, (&orig, &dec)) in coeffs.iter().zip(decoded.iter()).enumerate() {
        assert_eq!(
            orig, dec,
            "Rounded multiple-of-3 mismatch at {}: expected {}, got {}",
            i, orig, dec
        );
    }
}

// ============================================================================
// Encoding of Real Generated Keys
// ============================================================================

#[test]
fn test_generated_public_key_decode_reencode() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let pk = sk.public_key();
    let pk_bytes = pk.as_bytes();

    let coeffs = rq_decode(pk_bytes);

    // Verify all coefficients are in valid range
    for (i, &c) in coeffs.iter().enumerate() {
        assert!(
            c >= -Q12 && c <= Q12,
            "Public key coefficient {} out of range: {} (valid: [{}, {}])",
            i,
            c,
            -Q12,
            Q12
        );
    }

    let reencoded = rq_encode(&coeffs);

    assert_eq!(
        pk_bytes, &reencoded,
        "public key -> decode -> encode mismatch"
    );
}

#[test]
fn test_generated_secret_key_components() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let sk_bytes = sk.as_bytes();

    // Parse secret key structure: f(191) || ginv(191) || pk(1158) || rho(191) || hash(32)
    let f_bytes: &[u8; SMALL_BYTES] = sk_bytes[0..SMALL_BYTES].try_into().unwrap();
    let ginv_bytes: &[u8; SMALL_BYTES] = sk_bytes[SMALL_BYTES..2 * SMALL_BYTES].try_into().unwrap();
    let pk_bytes: &[u8; RQ_BYTES] = sk_bytes[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES]
        .try_into()
        .unwrap();

    // Decode f and ginv
    let f_coeffs = small_decode(f_bytes);
    let ginv_coeffs = small_decode(ginv_bytes);

    // Verify f coefficients are in {-1, 0, 1}
    for (i, &c) in f_coeffs.iter().enumerate() {
        assert!(c >= -1 && c <= 1, "f coefficient {} out of range: {}", i, c);
    }

    // Verify ginv coefficients are in {-1, 0, 1}
    for (i, &c) in ginv_coeffs.iter().enumerate() {
        assert!(
            c >= -1 && c <= 1,
            "ginv coefficient {} out of range: {}",
            i,
            c
        );
    }

    // Re-encode and verify
    let f_reencoded = small_encode(&f_coeffs);
    let ginv_reencoded = small_encode(&ginv_coeffs);

    assert_eq!(f_bytes, &f_reencoded, "f encoding mismatch");
    assert_eq!(ginv_bytes, &ginv_reencoded, "ginv encoding mismatch");

    // Verify embedded public key
    let pk_coeffs = rq_decode(pk_bytes);
    let pk_reencoded = rq_encode(&pk_coeffs);
    assert_eq!(pk_bytes, &pk_reencoded, "Embedded pk encoding mismatch");
}

#[test]
fn test_ciphertext_decode_reencode() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let pk = sk.public_key();
    let (_ss, ct) = pk.encapsulate().unwrap();
    let ct_bytes = ct.as_bytes();

    // Parse ciphertext: rounded_body(1007) || confirm(32)
    let body_bytes: &[u8; ROUNDED_BYTES] = ct_bytes[0..ROUNDED_BYTES].try_into().unwrap();

    // Decode rounded body
    let body_coeffs = rounded_decode(body_bytes);

    // Verify all coefficients are in valid range (multiples of 3)
    for (i, &c) in body_coeffs.iter().enumerate() {
        // Rounded values should be multiples of 3 in approximately [-2295, 2295]
        assert!(
            c >= -2400 && c <= 2400,
            "Ciphertext coefficient {} out of range: {}",
            i,
            c
        );
    }

    // Re-encode - note: this tests the encode path, not exact roundtrip
    // since rounded encoding involves quantisation
    let body_reencoded = rounded_encode(&body_coeffs);
    assert_eq!(body_reencoded.len(), ROUNDED_BYTES);
}

// ============================================================================
// KEM Self-Consistency
// ============================================================================

#[test]
fn test_kem_roundtrip() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let pk = sk.public_key();

    let (ss_encap, ct) = pk.encapsulate().unwrap();
    let ss_decap = sk.decapsulate(&ct).expect("decapsulation failed");

    assert_eq!(
        ss_encap.as_bytes(),
        ss_decap.as_bytes(),
        "KEM shared secret mismatch"
    );
}

#[test]
fn test_kem_multiple_sessions() {
    for i in 0..10 {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        let (ss_encap, ct) = pk.encapsulate().unwrap();

        // Round-trip the ciphertext through the wire format
        let ct = Sntrup761Ciphertext::from_bytes(ct.as_bytes()).unwrap();
        let ss_decap = sk.decapsulate(&ct).unwrap();

        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "Session {} failed",
            i
        );
    }
}

#[test]
fn test_secret_key_serialisation_roundtrip() {
    let sk = Sntrup761SecretKey::generate().unwrap();

    let restored =
        Sntrup761SecretKey::from_bytes(sk.as_bytes()).expect("Failed to deserialise secret key");

    assert_eq!(
        sk.public_key().as_bytes(),
        restored.public_key().as_bytes(),
        "Public keys derived from same secret key differ"
    );

    // The deserialised key must still decapsulate correctly
    let (ss_encap, ct) = sk.public_key().encapsulate().unwrap();
    let ss_decap = restored.decapsulate(&ct).unwrap();
    assert_eq!(ss_encap.as_bytes(), ss_decap.as_bytes());
}

// ============================================================================
// Size Invariants
// ============================================================================

#[test]
fn test_public_key_size_matches_encoding() {
    assert_eq!(PUBLIC_KEY_SIZE, RQ_BYTES);
}

#[test]
fn test_secret_key_size() {
    assert_eq!(SECRET_KEY_SIZE, 1763);
    // f || ginv || pk || rho || hash
    assert_eq!(
        SECRET_KEY_SIZE,
        2 * SMALL_BYTES + RQ_BYTES + SMALL_BYTES + 32
    );
}

#[test]
fn test_ciphertext_size_matches_encoding() {
    assert_eq!(CIPHERTEXT_SIZE, ROUNDED_BYTES + 32);
}

#[test]
fn test_shared_secret_size() {
    assert_eq!(SHARED_SECRET_SIZE, 32);
}

// ============================================================================
// Edge Cases and Boundary Conditions
// ============================================================================

#[test]
fn test_rq_boundary_values() {
    // Test boundary values at Q12
    let mut coeffs = [0i16; P];
    coeffs[0] = Q12;
    coeffs[1] = -Q12;
    coeffs[P - 1] = Q12;

    let encoded = rq_encode(&coeffs);
    let decoded = rq_decode(&encoded);

    assert_eq!(coeffs, decoded, "Boundary values roundtrip failed");
}

#[test]
fn test_single_nonzero_coefficient() {
    for pos in [0, 1, P / 2, P - 2, P - 1] {
        let mut coeffs = [0i16; P];
        coeffs[pos] = 1000;

        let encoded = rq_encode(&coeffs);
        let decoded = rq_decode(&encoded);

        assert_eq!(coeffs, decoded, "Single nonzero at position {} failed", pos);
    }
}

#[test]
fn test_small_single_nonzero() {
    for pos in [0, 1, P / 2, P - 2, P - 1] {
        for val in [-1i8, 1i8] {
            let mut coeffs = [0i8; P];
            coeffs[pos] = val;

            let encoded = small_encode(&coeffs);
            let decoded = small_decode(&encoded);

            assert_eq!(
                coeffs, decoded,
                "Small single nonzero at position {} with value {} failed",
                pos, val
            );
        }
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_many_keys_encoding_roundtrip() {
    for _ in 0..50 {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        // Decode and re-encode public key
        let coeffs = rq_decode(pk.as_bytes());
        let reencoded = rq_encode(&coeffs);

        assert_eq!(pk.as_bytes(), &reencoded, "Public key roundtrip mismatch");
    }
}

#[test]
fn test_many_encapsulations() {
    for _ in 0..20 {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let pk = Sntrup761PublicKey::from_bytes(sk.public_key().as_bytes()).unwrap();

        let (ss_encap, ct) = pk.encapsulate().unwrap();
        let ss_decap = sk.decapsulate(&ct).unwrap();

        assert_eq!(ss_encap.as_bytes(), ss_decap.as_bytes());
    }
}

// ============================================================================
// Coefficient Distribution Tests
// ============================================================================

#[test]
fn test_public_key_coefficient_distribution() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let pk = sk.public_key();
    let coeffs = rq_decode(pk.as_bytes());

    let mut positive = 0;
    let mut negative = 0;

    for &c in &coeffs {
        match c.cmp(&0) {
            std::cmp::Ordering::Greater => positive += 1,
            std::cmp::Ordering::Less => negative += 1,
            std::cmp::Ordering::Equal => {}
        }
    }

    // Public key coefficients should be roughly evenly distributed
    // (this is a sanity check, not a statistical test)
    assert!(
        positive > 100 && negative > 100,
        "Unexpected coefficient distribution: +{}, -{}",
        positive,
        negative
    );
}

#[test]
fn test_confirmation_hash_format() {
    let sk = Sntrup761SecretKey::generate().unwrap();
    let pk = sk.public_key();
    let (_, ct) = pk.encapsulate().unwrap();

    // Confirmation is last 32 bytes
    let confirm = &ct.as_bytes()[ROUNDED_BYTES..];
    assert_eq!(confirm.len(), 32, "confirmation hash wrong size");
}

// ============================================================================
// Property-Based Tests (proptest)
// ============================================================================

mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for generating valid small polynomial coefficients (-1, 0, 1)
    fn small_coeff_strategy() -> impl Strategy<Value = i8> {
        prop_oneof![Just(-1i8), Just(0i8), Just(1i8)]
    }

    /// Strategy for generating valid Rq polynomial coefficients
    fn rq_coeff_strategy() -> impl Strategy<Value = i16> {
        (-Q12..=Q12).prop_map(|x| x as i16)
    }

    /// Strategy for generating small polynomials
    fn small_poly_strategy() -> impl Strategy<Value = [i8; P]> {
        proptest::collection::vec(small_coeff_strategy(), P..=P).prop_map(|v| {
            let mut arr = [0i8; P];
            arr.copy_from_slice(&v);
            arr
        })
    }

    /// Strategy for generating Rq polynomials
    fn rq_poly_strategy() -> impl Strategy<Value = [i16; P]> {
        proptest::collection::vec(rq_coeff_strategy(), P..=P).prop_map(|v| {
            let mut arr = [0i16; P];
            arr.copy_from_slice(&v);
            arr
        })
    }

    /// Strategy for generating rounded polynomials (multiples of 3)
    fn rounded_poly_strategy() -> impl Strategy<Value = [i16; P]> {
        proptest::collection::vec(-765i16..=765i16, P..=P).prop_map(|v| {
            let mut arr = [0i16; P];
            for (i, &x) in v.iter().enumerate() {
                arr[i] = x * 3; // Ensure multiple of 3
            }
            arr
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property: small polynomial encode-decode is identity
        #[test]
        fn prop_small_encode_decode_roundtrip(coeffs in small_poly_strategy()) {
            let encoded = small_encode(&coeffs);
            let decoded = small_decode(&encoded);
            prop_assert_eq!(coeffs, decoded, "Small roundtrip failed");
        }

        /// Property: Rq polynomial encode-decode is identity
        #[test]
        fn prop_rq_encode_decode_roundtrip(coeffs in rq_poly_strategy()) {
            let encoded = rq_encode(&coeffs);
            let decoded = rq_decode(&encoded);
            prop_assert_eq!(coeffs, decoded, "Rq roundtrip failed");
        }

        /// Property: rounded polynomial encode-decode preserves multiples of 3
        #[test]
        fn prop_rounded_encode_decode_roundtrip(coeffs in rounded_poly_strategy()) {
            let encoded = rounded_encode(&coeffs);
            let decoded = rounded_decode(&encoded);
            // Rounded encoding should be exact for multiples of 3
            prop_assert_eq!(coeffs, decoded, "Rounded roundtrip failed");
        }

        /// Property: small encoding produces exactly SMALL_BYTES bytes
        #[test]
        fn prop_small_encode_size(coeffs in small_poly_strategy()) {
            let encoded = small_encode(&coeffs);
            prop_assert_eq!(encoded.len(), SMALL_BYTES, "Wrong small encoding size");
        }

        /// Property: Rq encoding produces exactly RQ_BYTES bytes
        #[test]
        fn prop_rq_encode_size(coeffs in rq_poly_strategy()) {
            let encoded = rq_encode(&coeffs);
            prop_assert_eq!(encoded.len(), RQ_BYTES, "Wrong Rq encoding size");
        }

        /// Property: rounded encoding produces exactly ROUNDED_BYTES bytes
        #[test]
        fn prop_rounded_encode_size(coeffs in rounded_poly_strategy()) {
            let encoded = rounded_encode(&coeffs);
            prop_assert_eq!(encoded.len(), ROUNDED_BYTES, "Wrong rounded encoding size");
        }

        // Note: We don't test arbitrary byte decoding because the sntrup761
        // encoding format doesn't bijectively map to all possible byte strings.
        // Arbitrary bytes may decode to out-of-range coefficients, which is
        // expected. The important property is that valid encode-decode roundtrips
        // work correctly, which is tested by prop_*_encode_decode_roundtrip tests.
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: generated public keys always survive a wire-format roundtrip
        #[test]
        fn prop_generated_key_wire_roundtrip(_seed in any::<u64>()) {
            let sk = Sntrup761SecretKey::generate().unwrap();
            let pk = sk.public_key();

            let parsed = Sntrup761PublicKey::from_bytes(pk.as_bytes());
            prop_assert!(parsed.is_ok(), "Failed to parse generated public key");
            let parsed = parsed.unwrap();
            prop_assert_eq!(parsed.as_bytes(), pk.as_bytes());
        }

        /// Property: KEM always produces matching secrets across a wire roundtrip
        #[test]
        fn prop_kem_wire_roundtrip(_seed in any::<u64>()) {
            let sk = Sntrup761SecretKey::generate().unwrap();
            let pk = Sntrup761PublicKey::from_bytes(sk.public_key().as_bytes()).unwrap();

            let (ss_encap, ct) = pk.encapsulate().unwrap();
            let ct = Sntrup761Ciphertext::from_bytes(ct.as_bytes()).unwrap();
            let ss_decap = sk.decapsulate(&ct).unwrap();

            prop_assert_eq!(ss_encap.as_bytes(), ss_decap.as_bytes(), "KEM shared secret mismatch");
        }
    }
}

// ============================================================================
// Extended Stress Tests
// ============================================================================

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_1000_key_encoding_roundtrips() {
    (0..1000).into_par_iter().for_each(|i| {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        // Decode and re-encode should be identity
        let coeffs = rq_decode(pk.as_bytes());
        let reencoded = rq_encode(&coeffs);

        assert_eq!(pk.as_bytes(), &reencoded, "Key roundtrip {} failed", i);
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_1000_kem() {
    (0..1000).into_par_iter().for_each(|i| {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        let (ss_encap, ct) = pk.encapsulate().unwrap();
        let ss_decap = sk.decapsulate(&ct).expect("decapsulation failed");

        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "KEM iteration {} failed",
            i
        );
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_secret_key_serialisation() {
    (0..200).into_par_iter().for_each(|i| {
        let sk = Sntrup761SecretKey::generate().unwrap();
        let restored = Sntrup761SecretKey::from_bytes(sk.as_bytes())
            .expect("Failed to deserialise secret key");

        // Public keys must match
        assert_eq!(
            sk.public_key().as_bytes(),
            restored.public_key().as_bytes(),
            "Public key mismatch at iteration {}",
            i
        );

        // KEM must work with the deserialised key
        let (ss_encap, ct) = sk.public_key().encapsulate().unwrap();
        let ss_decap = restored.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "KEM failed with deserialised key at iteration {}",
            i
        );
    });
}
