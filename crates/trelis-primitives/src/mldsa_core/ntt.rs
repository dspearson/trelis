use super::module_lattice::algebra::Field;
use super::module_lattice::encode::ArraySize;
use core::ops::Mul;

use super::algebra::{BaseField, Elem, NttPolynomial, NttVector, Polynomial, Vector};

// Since the powers of zeta used in the NTT and MultiplyNTTs are fixed, we use pre-computed tables
// to avoid the need to compute the exponetiations at runtime.
//
//   ZETA_POW_BITREV[i] = zeta^{BitRev_8(i)}
//
// Note that the const environment here imposes some annoying conditions.  Because operator
// overloading can't be const, we have to do all the reductions here manually.  Because `for` loops
// are forbidden in `const` functions, we do them manually with `while` loops.
//
// The values computed here match those provided in Appendix B of FIPS 204.
//
// API-03: the three allow-attributes below are scoped to this single const initialiser
// (`ZETA_POW_BITREV`), not file-level. Justification:
// - `cast_possible_truncation` / `as_conversions`: the `(curr as u32)` cast on line 31 and
//   the `(x as u8).reverse_bits() as usize` chain inside `bitrev8` are mandated by the
//   FIPS 204 reference algorithm — `curr` is constrained to `< BaseField::QL` (the modulus,
//   a u32), so truncation cannot occur in practice, and the bitrev computation is defined
//   over `u8`.
// - `integer_division_remainder_used`: the `% BaseField::QL` reduction is the modular
//   arithmetic specified by FIPS 204 §B; flagging it would just produce noise.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::as_conversions)]
#[allow(clippy::integer_division_remainder_used)]
const ZETA_POW_BITREV: [Elem; 256] = {
    const ZETA: u64 = 1753;
    const fn bitrev8(x: usize) -> usize {
        (x as u8).reverse_bits() as usize
    }

    // Compute the powers of zeta
    let mut pow = [Elem::new(0); 256];
    let mut i = 0;
    let mut curr = 1u64;
    while i < 256 {
        pow[i] = Elem::new(curr as u32);
        i += 1;
        curr = (curr * ZETA) % BaseField::QL;
    }

    // Reorder the powers according to bitrev8
    // Note that entry 0 is left as zero, in order to match the `zetas` array in the
    // specification.
    let mut pow_bitrev = [Elem::new(0); 256];
    let mut i = 1;
    while i < 256 {
        pow_bitrev[i] = pow[bitrev8(i)];
        i += 1;
    }
    pow_bitrev
};

pub trait Ntt {
    type Output;
    fn ntt(&self) -> Self::Output;
}

impl Ntt for Polynomial {
    type Output = NttPolynomial;

    // Algorithm 41 NTT
    fn ntt(&self) -> Self::Output {
        let mut w = self.0;

        let mut m = 0;
        for len in [128, 64, 32, 16, 8, 4, 2, 1] {
            for start in (0..256).step_by(2 * len) {
                m += 1;
                let z = ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = z * w[j + len];
                    w[j + len] = w[j] - t;
                    w[j] = w[j] + t;
                }
            }
        }

        NttPolynomial::new(w)
    }
}

impl<K: ArraySize> Ntt for Vector<K> {
    type Output = NttVector<K>;

    fn ntt(&self) -> Self::Output {
        NttVector::new(self.0.iter().map(Polynomial::ntt).collect())
    }
}

#[allow(clippy::module_name_repetitions)]
pub trait NttInverse {
    type Output;
    fn ntt_inverse(&self) -> Self::Output;
}

impl NttInverse for NttPolynomial {
    type Output = Polynomial;

    // Algorithm 42 NTT^{−1}
    fn ntt_inverse(&self) -> Self::Output {
        const INVERSE_256: Elem = Elem::new(8_347_681);

        let mut w = self.0;

        let mut m = 256;
        for len in [1, 2, 4, 8, 16, 32, 64, 128] {
            for start in (0..256).step_by(2 * len) {
                m -= 1;
                let z = -ZETA_POW_BITREV[m];

                for j in start..(start + len) {
                    let t = w[j];
                    w[j] = t + w[j + len];
                    w[j + len] = z * (t - w[j + len]);
                }
            }
        }

        INVERSE_256 * &Polynomial::new(w)
    }
}

impl<K: ArraySize> NttInverse for NttVector<K> {
    type Output = Vector<K>;

    fn ntt_inverse(&self) -> Self::Output {
        Vector::new(self.0.iter().map(NttPolynomial::ntt_inverse).collect())
    }
}

impl Mul<&NttPolynomial> for &NttPolynomial {
    type Output = NttPolynomial;

    // Algorithm 45 MultiplyNTT
    fn mul(self, rhs: &NttPolynomial) -> NttPolynomial {
        NttPolynomial::new(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&x, &y)| x * y)
                .collect(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::as_conversions)]
#[allow(clippy::cast_possible_truncation)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use hybrid_array::{
        Array,
        typenum::{U2, U3},
    };

    use crate::mldsa_core::algebra::*;

    // Multiplication in R_q, modulo X^256 + 1
    impl Mul<&Polynomial> for &Polynomial {
        type Output = Polynomial;

        fn mul(self, rhs: &Polynomial) -> Self::Output {
            let mut out = Self::Output::default();
            for (i, x) in self.0.iter().enumerate() {
                for (j, y) in rhs.0.iter().enumerate() {
                    let (sign, index) = if i + j < 256 {
                        (Elem::new(1), i + j)
                    } else {
                        (Elem::new(BaseField::Q - 1), i + j - 256)
                    };

                    out.0[index] = out.0[index] + (sign * *x * *y);
                }
            }
            out
        }
    }

    // A polynomial with only a scalar component, to make simple test cases
    fn const_ntt(x: Int) -> NttPolynomial {
        let mut p = Polynomial::default();
        p.0[0] = Elem::new(x);
        p.ntt()
    }

    #[test]
    fn ntt() {
        let f = Polynomial::new(Array::from_fn(|i| Elem::new(i as Int)));
        let g = Polynomial::new(Array::from_fn(|i| Elem::new((2 * i) as Int)));
        let f_hat = f.ntt();
        let g_hat = g.ntt();

        // Verify that NTT and NTT^-1 are actually inverses
        let f_unhat = f_hat.ntt_inverse();
        assert_eq!(f, f_unhat);

        // Verify that NTT is a homomorphism with regard to addition
        let fg = &f + &g;
        let f_hat_g_hat = &f_hat + &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);

        // Verify that NTT is a homomorphism with regard to multiplication
        let fg = &f * &g;
        let f_hat_g_hat = &f_hat * &g_hat;
        let fg_unhat = f_hat_g_hat.ntt_inverse();
        assert_eq!(fg, fg_unhat);
    }

    #[test]
    fn ntt_vector() {
        // Verify vector addition
        let v1: NttVector<U3> = NttVector::new(Array([const_ntt(1), const_ntt(1), const_ntt(1)]));
        let v2: NttVector<U3> = NttVector::new(Array([const_ntt(2), const_ntt(2), const_ntt(2)]));
        let v3: NttVector<U3> = NttVector::new(Array([const_ntt(3), const_ntt(3), const_ntt(3)]));
        assert_eq!((&v1 + &v2), v3);

        // Verify dot product
        assert_eq!((&v1 * &v2), const_ntt(6));
        assert_eq!((&v1 * &v3), const_ntt(9));
        assert_eq!((&v2 * &v3), const_ntt(18));
    }

    #[test]
    fn ntt_matrix() {
        // Verify matrix multiplication by a vector
        let a: NttMatrix<U3, U2> = NttMatrix::new(Array([
            NttVector::new(Array([const_ntt(1), const_ntt(2)])),
            NttVector::new(Array([const_ntt(3), const_ntt(4)])),
            NttVector::new(Array([const_ntt(5), const_ntt(6)])),
        ]));
        let v_in: NttVector<U2> = NttVector::new(Array([const_ntt(1), const_ntt(2)]));
        let v_out: NttVector<U3> =
            NttVector::new(Array([const_ntt(5), const_ntt(11), const_ntt(17)]));
        assert_eq!(&a * &v_in, v_out);
    }

    // =========================================================================
    // Edge Case Tests for Dot Product Accumulator Optimisation
    // =========================================================================
    //
    // These tests verify the optimised dot product implementation handles
    // boundary conditions correctly, particularly around:
    // - Zero vectors
    // - Large coefficient values near the field modulus
    // - Accumulation patterns that could overflow without proper reduction

    use hybrid_array::typenum::U1;

    /// Test dot product with zero vectors - result should be zero polynomial
    #[test]
    fn dot_product_zero_vectors() {
        let zero: NttVector<U3> = NttVector::default();
        let v: NttVector<U3> = NttVector::new(Array([const_ntt(1), const_ntt(2), const_ntt(3)]));

        // 0 · v = 0
        let result = &zero * &v;
        let expected = NttPolynomial::default();
        assert_eq!(result, expected, "Zero dot any should be zero");

        // v · 0 = 0
        let result = &v * &zero;
        assert_eq!(result, expected, "Any dot zero should be zero");

        // 0 · 0 = 0
        let result = &zero * &zero;
        assert_eq!(result, expected, "Zero dot zero should be zero");
    }

    /// Test dot product with single-element vectors (U1)
    #[test]
    fn dot_product_single_element() {
        let v1: NttVector<U1> = NttVector::new(Array([const_ntt(7)]));
        let v2: NttVector<U1> = NttVector::new(Array([const_ntt(11)]));

        let result = &v1 * &v2;
        let expected = const_ntt(77);
        assert_eq!(result, expected, "Single element dot product failed");
    }

    /// Test dot product with coefficients near Q (field modulus)
    /// This verifies Barrett reduction works correctly at boundaries
    #[test]
    fn dot_product_large_coefficients() {
        // Q = 8380417, use values near Q-1
        let large_val = BaseField::Q - 1; // Maximum valid coefficient

        // Create polynomials with large coefficients
        let mut p1 = Polynomial::default();
        let mut p2 = Polynomial::default();
        p1.0[0] = Elem::new(large_val);
        p2.0[0] = Elem::new(large_val);

        let ntt1 = p1.ntt();
        let ntt2 = p2.ntt();

        let v1: NttVector<U2> = NttVector::new(Array([ntt1.clone(), ntt1.clone()]));
        let v2: NttVector<U2> = NttVector::new(Array([ntt2.clone(), ntt2.clone()]));

        // This should not overflow - result should be properly reduced
        let result = &v1 * &v2;

        // Verify result is in valid range (all coefficients < Q)
        for elem in result.0.iter() {
            assert!(
                elem.0 < BaseField::Q,
                "Coefficient {} exceeds Q={}",
                elem.0,
                BaseField::Q
            );
        }
    }

    /// Test dot product accumulation doesn't overflow
    /// Uses values that when squared and summed could overflow u32
    #[test]
    fn dot_product_accumulation_stress() {
        // Create vectors where accumulation could be problematic
        // Each element contributes (val * val) to the sum
        let val = 2000u32; // Chosen so val^2 * K doesn't overflow intermediates

        let mut p = Polynomial::default();
        p.0[0] = Elem::new(val);
        let ntt_p = p.ntt();

        // Vector of 4 identical polynomials
        use hybrid_array::typenum::U4;
        let v: NttVector<U4> = NttVector::new(Array([
            ntt_p.clone(),
            ntt_p.clone(),
            ntt_p.clone(),
            ntt_p.clone(),
        ]));

        // v · v should equal 4 * (val^2) for the constant coefficient
        let result = &v * &v;
        let result_poly = result.ntt_inverse();

        // 4 * 2000^2 = 16,000,000 which is > Q, so it wraps
        // Expected: 16000000 mod 8380417 = 7619583
        let expected = (4u64 * val as u64 * val as u64) % (BaseField::Q as u64);
        assert_eq!(
            result_poly.0[0].0, expected as u32,
            "Accumulation gave wrong result"
        );
    }

    /// Test that dot product is commutative: a · b = b · a
    #[test]
    fn dot_product_commutativity() {
        let v1: NttVector<U3> = NttVector::new(Array([const_ntt(3), const_ntt(7), const_ntt(11)]));
        let v2: NttVector<U3> = NttVector::new(Array([const_ntt(2), const_ntt(5), const_ntt(13)]));

        let ab = &v1 * &v2;
        let ba = &v2 * &v1;

        assert_eq!(ab, ba, "Dot product should be commutative");
    }

    /// Test dot product with mixed positive values (in centred representation)
    /// Verifies handling of "negative" values (stored as Q - x)
    #[test]
    fn dot_product_centred_representation() {
        // In centred representation, -1 is stored as Q-1
        let neg_one = BaseField::Q - 1;

        let mut p_pos = Polynomial::default();
        let mut p_neg = Polynomial::default();
        p_pos.0[0] = Elem::new(1);
        p_neg.0[0] = Elem::new(neg_one); // This represents -1

        let ntt_pos = p_pos.ntt();
        let ntt_neg = p_neg.ntt();

        let v1: NttVector<U2> = NttVector::new(Array([ntt_pos.clone(), ntt_neg.clone()]));
        let v2: NttVector<U2> = NttVector::new(Array([ntt_pos.clone(), ntt_pos.clone()]));

        // (1, -1) · (1, 1) = 1*1 + (-1)*1 = 0
        let result = &v1 * &v2;
        let result_poly = result.ntt_inverse();

        assert_eq!(result_poly.0[0].0, 0, "1 + (-1) should equal 0");
    }

    /// Regression test: verify optimised dot product matches fold-based reference
    #[test]
    fn dot_product_reference_comparison() {
        // Create test vectors with varied coefficients
        let polys: Vec<NttPolynomial> = (0..4)
            .map(|i| {
                let mut p = Polynomial::default();
                for j in 0..256 {
                    p.0[j] = Elem::new(((i * 256 + j) % 1000) as u32);
                }
                p.ntt()
            })
            .collect();

        use hybrid_array::typenum::U4;
        let v1: NttVector<U4> = NttVector::new(Array([
            polys[0].clone(),
            polys[1].clone(),
            polys[2].clone(),
            polys[3].clone(),
        ]));
        let v2: NttVector<U4> = NttVector::new(Array([
            polys[3].clone(),
            polys[2].clone(),
            polys[1].clone(),
            polys[0].clone(),
        ]));

        // Compute using optimised implementation
        let result = &v1 * &v2;

        // Compute reference using explicit fold (the old algorithm)
        let reference: NttPolynomial =
            v1.0.iter()
                .zip(v2.0.iter())
                .map(|(x, y)| x * y)
                .fold(NttPolynomial::default(), |acc, prod| &acc + &prod);

        assert_eq!(result, reference, "Optimised should match reference");
    }
}
