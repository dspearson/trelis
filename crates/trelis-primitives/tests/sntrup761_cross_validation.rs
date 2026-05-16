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
    clippy::unnecessary_cast
)]
//! Cross-validation tests for sntrup761 implementations.
//!
//! These tests verify that:
//! 1. Wire format encoding is compatible between C and Rust implementations
//! 2. The pure Rust (WASM) implementation produces byte-for-byte identical
//!    outputs to the C reference implementation
//! 3. Cross-implementation KEM operations work correctly
//!
//! # Implementation Compatibility
//!
//! Both the C FFI (pqcrypto-ntruprime) and the pure Rust (WASM) implementation
//! use SHA-512 for internal hashing, matching the sntrup761 reference implementation.
//! This ensures:
//!
//! - **Wire format (public keys, ciphertexts)**: COMPATIBLE
//! - **KEM shared secrets**: COMPATIBLE (byte-for-byte identical)
//!
//! Run with: cargo test --features "std,wasm" --test sntrup761_cross_validation

// Only run on platforms with both C FFI and Rust implementations (native Unix/Linux)
#![cfg(all(
    feature = "std",
    feature = "wasm",
    not(target_os = "windows"),
    not(target_arch = "wasm32")
))]

use rayon::prelude::*;
use trelis_primitives::sntrup761::encoding::{
    P, Q, Q12, ROUNDED_BYTES, RQ_BYTES, SMALL_BYTES, rounded_decode, rounded_encode, rq_decode,
    rq_encode, small_decode, small_encode,
};
use trelis_primitives::sntrup761::ffi as c_impl;
use trelis_primitives::sntrup761::pure_rust as rust_impl;

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
// C FFI vs Rust Encoding Comparison
// ============================================================================

#[test]
fn test_c_generated_public_key_rust_decode_reencode() {
    // Generate key with C implementation
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let c_pk_bytes = c_pk.as_bytes();

    // Decode with Rust decoder
    let coeffs = rq_decode(c_pk_bytes);

    // Verify all coefficients are in valid range
    for (i, &c) in coeffs.iter().enumerate() {
        assert!(
            c >= -Q12 && c <= Q12,
            "C public key coefficient {} out of range: {} (valid: [{}, {}])",
            i,
            c,
            -Q12,
            Q12
        );
    }

    // Re-encode with Rust encoder
    let rust_encoded = rq_encode(&coeffs);

    // Should match exactly
    assert_eq!(
        c_pk_bytes, &rust_encoded,
        "C public key -> Rust decode -> Rust encode mismatch"
    );
}

#[test]
fn test_c_generated_secret_key_components() {
    // Generate key with C implementation
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let sk_bytes = c_sk.as_bytes();

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
fn test_c_ciphertext_rust_decode_reencode() {
    // Generate key and encapsulate with C implementation
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let (_ss, ct) = c_pk.encapsulate().unwrap();
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
// Cross-Implementation KEM Tests
// ============================================================================

#[test]
fn test_rust_key_used_with_c_encapsulation() {
    // Generate keypair with Rust implementation
    let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();

    // Create C public key from Rust bytes
    let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes())
        .expect("Failed to create C public key from Rust bytes");

    // Encapsulate with C implementation
    let (c_ss, c_ct) = c_pk.encapsulate().unwrap();

    // Create Rust ciphertext from C bytes
    let rust_ct = rust_impl::Sntrup761Ciphertext::from_bytes(c_ct.as_bytes())
        .expect("Failed to create Rust ciphertext from C bytes");

    // Decapsulate with Rust implementation
    let rust_ss = rust_sk
        .decapsulate(&rust_ct)
        .expect("Rust decapsulation failed");

    // Shared secrets should match
    assert_eq!(
        c_ss.as_bytes(),
        rust_ss.as_bytes(),
        "Cross-implementation shared secret mismatch: C encap -> Rust decap"
    );
}

#[test]
fn test_c_key_used_with_rust_encapsulation() {
    // Generate keypair with C implementation
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();

    // Create Rust public key from C bytes
    let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes())
        .expect("Failed to create Rust public key from C bytes");

    // Encapsulate with Rust implementation
    let (rust_ss, rust_ct) = rust_pk.encapsulate().unwrap();

    // Create C ciphertext from Rust bytes
    let c_ct = c_impl::Sntrup761Ciphertext::from_bytes(rust_ct.as_bytes())
        .expect("Failed to create C ciphertext from Rust bytes");

    // Decapsulate with C implementation
    let c_ss = c_sk.decapsulate(&c_ct).expect("C decapsulation failed");

    // Shared secrets should match
    assert_eq!(
        rust_ss.as_bytes(),
        c_ss.as_bytes(),
        "Cross-implementation shared secret mismatch: Rust encap -> C decap"
    );
}

#[test]
fn test_cross_implementation_multiple_sessions() {
    // Test multiple sessions to ensure consistency
    for i in 0..10 {
        // Alternate between implementations for key generation
        if i % 2 == 0 {
            // Rust key, C encapsulation
            let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
            let rust_pk = rust_sk.public_key();

            let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes()).unwrap();
            let (c_ss, c_ct) = c_pk.encapsulate().unwrap();

            let rust_ct = rust_impl::Sntrup761Ciphertext::from_bytes(c_ct.as_bytes()).unwrap();
            let rust_ss = rust_sk.decapsulate(&rust_ct).unwrap();

            assert_eq!(
                c_ss.as_bytes(),
                rust_ss.as_bytes(),
                "Session {} failed: Rust key, C encap",
                i
            );
        } else {
            // C key, Rust encapsulation
            let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
            let c_pk = c_sk.public_key();

            let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes()).unwrap();
            let (rust_ss, rust_ct) = rust_pk.encapsulate().unwrap();

            let c_ct = c_impl::Sntrup761Ciphertext::from_bytes(rust_ct.as_bytes()).unwrap();
            let c_ss = c_sk.decapsulate(&c_ct).unwrap();

            assert_eq!(
                rust_ss.as_bytes(),
                c_ss.as_bytes(),
                "Session {} failed: C key, Rust encap",
                i
            );
        }
    }
}

// ============================================================================
// Key Serialisation Cross-Validation
// ============================================================================

#[test]
fn test_secret_key_serialisation_cross_compatible() {
    // Generate with C
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();

    // Serialise from C, deserialise to Rust
    let rust_sk = rust_impl::Sntrup761SecretKey::from_bytes(c_sk.as_bytes())
        .expect("Failed to deserialise C secret key to Rust");

    // Public keys should match
    let c_pk = c_sk.public_key();
    let rust_pk = rust_sk.public_key();

    assert_eq!(
        c_pk.as_bytes(),
        rust_pk.as_bytes(),
        "Public keys derived from same secret key differ"
    );
}

#[test]
fn test_public_key_sizes_match() {
    assert_eq!(
        c_impl::PUBLIC_KEY_SIZE,
        rust_impl::PUBLIC_KEY_SIZE,
        "Public key sizes differ"
    );
    assert_eq!(c_impl::PUBLIC_KEY_SIZE, RQ_BYTES);
}

#[test]
fn test_secret_key_sizes_match() {
    assert_eq!(
        c_impl::SECRET_KEY_SIZE,
        rust_impl::SECRET_KEY_SIZE,
        "Secret key sizes differ"
    );
}

#[test]
fn test_ciphertext_sizes_match() {
    assert_eq!(
        c_impl::CIPHERTEXT_SIZE,
        rust_impl::CIPHERTEXT_SIZE,
        "Ciphertext sizes differ"
    );
    assert_eq!(c_impl::CIPHERTEXT_SIZE, ROUNDED_BYTES + 32);
}

#[test]
fn test_shared_secret_sizes_match() {
    assert_eq!(
        c_impl::SHARED_SECRET_SIZE,
        rust_impl::SHARED_SECRET_SIZE,
        "Shared secret sizes differ"
    );
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
fn test_many_c_keys_rust_roundtrip() {
    for _ in 0..50 {
        let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let c_pk = c_sk.public_key();

        // Decode and re-encode public key
        let coeffs = rq_decode(c_pk.as_bytes());
        let reencoded = rq_encode(&coeffs);

        assert_eq!(c_pk.as_bytes(), &reencoded, "Public key roundtrip mismatch");
    }
}

#[test]
fn test_many_rust_keys_c_roundtrip() {
    for _ in 0..50 {
        let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
        let rust_pk = rust_sk.public_key();

        // Verify C can parse the Rust-generated key
        let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes())
            .expect("C failed to parse Rust public key");

        assert_eq!(rust_pk.as_bytes(), c_pk.as_bytes());
    }
}

#[test]
fn test_many_cross_encapsulations() {
    for _ in 0..20 {
        // C key, Rust encap, C decap
        let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let c_pk = c_sk.public_key();

        let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes()).unwrap();
        let (rust_ss, rust_ct) = rust_pk.encapsulate().unwrap();

        let c_ct = c_impl::Sntrup761Ciphertext::from_bytes(rust_ct.as_bytes()).unwrap();
        let c_ss = c_sk.decapsulate(&c_ct).unwrap();

        assert_eq!(rust_ss.as_bytes(), c_ss.as_bytes());
    }
}

// ============================================================================
// Coefficient Distribution Tests
// ============================================================================

#[test]
fn test_c_public_key_coefficient_distribution() {
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let coeffs = rq_decode(c_pk.as_bytes());

    // Count coefficient distribution
    let mut positive = 0;
    let mut negative = 0;
    let mut zero = 0;

    for &c in &coeffs {
        match c.cmp(&0) {
            std::cmp::Ordering::Greater => positive += 1,
            std::cmp::Ordering::Less => negative += 1,
            std::cmp::Ordering::Equal => zero += 1,
        }
    }

    // Public key coefficients should be roughly evenly distributed
    // (this is a sanity check, not a statistical test)
    assert!(
        positive > 100 && negative > 100,
        "Unexpected coefficient distribution: +{}, -{}, 0:{}",
        positive,
        negative,
        zero
    );
}

#[test]
fn test_rust_public_key_coefficient_distribution() {
    let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();
    let coeffs = rq_decode(rust_pk.as_bytes());

    let mut positive = 0;
    let mut negative = 0;

    for &c in &coeffs {
        match c.cmp(&0) {
            std::cmp::Ordering::Greater => positive += 1,
            std::cmp::Ordering::Less => negative += 1,
            std::cmp::Ordering::Equal => {}
        }
    }

    assert!(
        positive > 100 && negative > 100,
        "Rust key has unexpected coefficient distribution"
    );
}

// ============================================================================
// Hash Function Consistency (if exposed)
// ============================================================================

#[test]
fn test_confirmation_hash_format() {
    // Generate ciphertext with both implementations
    let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let (_, c_ct) = c_pk.encapsulate().unwrap();

    // Confirmation is last 32 bytes
    let c_confirm = &c_ct.as_bytes()[ROUNDED_BYTES..];
    assert_eq!(c_confirm.len(), 32, "C confirmation hash wrong size");

    let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes()).unwrap();
    let (_, rust_ct) = rust_pk.encapsulate().unwrap();

    let rust_confirm = &rust_ct.as_bytes()[ROUNDED_BYTES..];
    assert_eq!(rust_confirm.len(), 32, "Rust confirmation hash wrong size");

    // Note: confirmations will differ because random r differs
    // This just checks the format is correct
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

        /// Property: C-generated keys can always be parsed by Rust encoder
        #[test]
        fn prop_c_key_rust_compatible(_seed in any::<u64>()) {
            let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
            let c_pk = c_sk.public_key();

            // Rust should be able to parse the key
            let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes());
            prop_assert!(rust_pk.is_ok(), "Failed to parse C public key");

            // And the parsed key should match
            let rust_pk_unwrapped = rust_pk.unwrap();
            prop_assert_eq!(rust_pk_unwrapped.as_bytes(), c_pk.as_bytes());
        }

        /// Property: Rust-generated keys can always be parsed by C encoder
        #[test]
        fn prop_rust_key_c_compatible(_seed in any::<u64>()) {
            let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
            let rust_pk = rust_sk.public_key();

            // C should be able to parse the key
            let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes());
            prop_assert!(c_pk.is_ok(), "Failed to parse Rust public key");

            // And the parsed key should match
            let c_pk_unwrapped = c_pk.unwrap();
            prop_assert_eq!(c_pk_unwrapped.as_bytes(), rust_pk.as_bytes());
        }

        /// Property: Cross-implementation KEM always produces matching secrets (C key, Rust encap)
        #[test]
        fn prop_cross_kem_c_key_rust_encap(_seed in any::<u64>()) {
            let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
            let c_pk = c_sk.public_key();

            let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes()).unwrap();
            let (rust_ss, rust_ct) = rust_pk.encapsulate().unwrap();

            let c_ct = c_impl::Sntrup761Ciphertext::from_bytes(rust_ct.as_bytes()).unwrap();
            let c_ss = c_sk.decapsulate(&c_ct).unwrap();

            prop_assert_eq!(rust_ss.as_bytes(), c_ss.as_bytes(), "KEM shared secret mismatch");
        }

        /// Property: Cross-implementation KEM always produces matching secrets (Rust key, C encap)
        #[test]
        fn prop_cross_kem_rust_key_c_encap(_seed in any::<u64>()) {
            let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
            let rust_pk = rust_sk.public_key();

            let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes()).unwrap();
            let (c_ss, c_ct) = c_pk.encapsulate().unwrap();

            let rust_ct = rust_impl::Sntrup761Ciphertext::from_bytes(c_ct.as_bytes()).unwrap();
            let rust_ss = rust_sk.decapsulate(&rust_ct).unwrap();

            prop_assert_eq!(c_ss.as_bytes(), rust_ss.as_bytes(), "KEM shared secret mismatch");
        }
    }
}

// ============================================================================
// Extended Stress Tests
// ============================================================================

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_1000_c_rust_roundtrips() {
    (0..1000).into_par_iter().for_each(|i| {
        let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let c_pk = c_sk.public_key();

        // Decode and re-encode should be identity
        let coeffs = rq_decode(c_pk.as_bytes());
        let reencoded = rq_encode(&coeffs);

        assert_eq!(c_pk.as_bytes(), &reencoded, "C key roundtrip {} failed", i);
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_500_cross_kem_c_key_rust_encap() {
    (0..500).into_par_iter().for_each(|i| {
        let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let c_pk = c_sk.public_key();

        let rust_pk = rust_impl::Sntrup761PublicKey::from_bytes(c_pk.as_bytes())
            .expect("Failed to parse C public key");
        let (rust_ss, rust_ct) = rust_pk.encapsulate().unwrap();

        let c_ct = c_impl::Sntrup761Ciphertext::from_bytes(rust_ct.as_bytes())
            .expect("Failed to parse Rust ciphertext");
        let c_ss = c_sk.decapsulate(&c_ct).expect("C decapsulation failed");

        assert_eq!(
            rust_ss.as_bytes(),
            c_ss.as_bytes(),
            "Cross-KEM iteration {} failed (C key, Rust encap)",
            i
        );
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_500_cross_kem_rust_key_c_encap() {
    (0..500).into_par_iter().for_each(|i| {
        let rust_sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
        let rust_pk = rust_sk.public_key();

        let c_pk = c_impl::Sntrup761PublicKey::from_bytes(rust_pk.as_bytes())
            .expect("Failed to parse Rust public key");
        let (c_ss, c_ct) = c_pk.encapsulate().unwrap();

        let rust_ct = rust_impl::Sntrup761Ciphertext::from_bytes(c_ct.as_bytes())
            .expect("Failed to parse C ciphertext");
        let rust_ss = rust_sk
            .decapsulate(&rust_ct)
            .expect("Rust decapsulation failed");

        assert_eq!(
            c_ss.as_bytes(),
            rust_ss.as_bytes(),
            "Cross-KEM iteration {} failed (Rust key, C encap)",
            i
        );
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_1000_rust_only_kem() {
    (0..1000).into_par_iter().for_each(|i| {
        let sk = rust_impl::Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        let (ss_encap, ct) = pk.encapsulate().unwrap();
        let ss_decap = sk.decapsulate(&ct).expect("Rust decapsulation failed");

        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "Rust-only KEM iteration {} failed",
            i
        );
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_1000_c_only_kem() {
    (0..1000).into_par_iter().for_each(|i| {
        let sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let pk = sk.public_key();

        let (ss_encap, ct) = pk.encapsulate().unwrap();
        let ss_decap = sk.decapsulate(&ct).expect("C decapsulation failed");

        assert_eq!(
            ss_encap.as_bytes(),
            ss_decap.as_bytes(),
            "C-only KEM iteration {} failed",
            i
        );
    });
}

#[test]
#[ignore] // Long-running: run with `cargo test -- --ignored`
fn stress_test_secret_key_serialisation() {
    (0..200).into_par_iter().for_each(|i| {
        // Generate with C, use with Rust
        let c_sk = c_impl::Sntrup761SecretKey::generate().unwrap();
        let rust_sk = rust_impl::Sntrup761SecretKey::from_bytes(c_sk.as_bytes())
            .expect("Failed to deserialise C secret key");

        // Public keys must match
        let c_pk = c_sk.public_key();
        let rust_pk = rust_sk.public_key();
        assert_eq!(
            c_pk.as_bytes(),
            rust_pk.as_bytes(),
            "Public key mismatch at iteration {}",
            i
        );

        // KEM must work with the deserialised key
        let (c_ss, c_ct) = c_pk.encapsulate().unwrap();
        let rust_ct = rust_impl::Sntrup761Ciphertext::from_bytes(c_ct.as_bytes()).unwrap();
        let rust_ss = rust_sk.decapsulate(&rust_ct).unwrap();
        assert_eq!(
            c_ss.as_bytes(),
            rust_ss.as_bytes(),
            "KEM failed with deserialised key at iteration {}",
            i
        );
    });
}
