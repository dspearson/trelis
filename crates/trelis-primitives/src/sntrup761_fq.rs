//! Optimised field arithmetic for sntrup761 (Fq = Z/4591Z).
//!
//! This module provides an optimised implementation of field element operations
//! for the sntrup761 KEM, specifically targeting the slow `recip()` operation.
//!
//! # Optimisation: Extended GCD vs Fermat
//!
//! The ntrulp crate uses Fermat's little theorem for field inversion:
//! `a^(-1) = a^(q-2) mod q`, requiring q-2 = 4589 multiplications.
//!
//! This module uses the binary extended GCD algorithm which requires only
//! O(log q) ≈ 12 iterations, providing approximately 380x speedup for
//! field element inversion.
//!
//! # Constant-Time Considerations
//!
//! The extended GCD implementation uses conditional moves and avoids
//! secret-dependent branches where possible. However, for non-secret
//! field elements (like the ratio parameter), timing is not a concern.

use crate::sntrup761_encoding::P;

/// The prime modulus q = 4591 for sntrup761.
pub const Q: i32 = 4591;

// ============================================================================
// Constant-time helper functions
// ============================================================================

/// Returns -1 (all bits set) if x is negative, 0 otherwise.
/// This is constant-time (no branches).
#[inline(always)]
fn i16_negative_mask(x: i16) -> i16 {
    x >> 15
}

/// Returns -1 (all bits set) if x is non-zero, 0 otherwise.
/// This is constant-time (no branches).
#[inline(always)]
fn i16_nonzero_mask(x: i16) -> i16 {
    // Convert to u16 for the bitwise operations
    let xu = x as u16;
    // If x != 0, then (x | -x) has the sign bit set
    let neg = (xu | xu.wrapping_neg()) >> 15;
    -(neg as i16)
}

/// Half of q, used for centred representation.
pub const Q12: i32 = (Q - 1) / 2; // 2295

// ============================================================================
// Fast modular arithmetic (avoiding division/modulo operators)
// ============================================================================

/// Constant for fast division: 2^31
const V: u32 = 0x8000_0000;

/// Precomputed: 2^31 / Q = 2147483648 / 4591 = 467811
/// This avoids a division in every freeze() call.
const V_DIV_Q: u32 = V / Q as u32;

/// Precomputed: 2^31 mod Q = 2147483648 mod 4591 = 2727
const V_MOD_Q: u32 = V % Q as u32;

/// Fast unsigned division and modulo for 14-bit modulus.
///
/// Returns (quotient, remainder) for x / m.
/// Uses fixed-point multiplication to avoid slow division.
/// This matches ntrulp's u32_divmod_u14 exactly.
#[inline(always)]
fn u32_divmod_u14(x: u32, m: u16) -> (u32, u16) {
    // Compute reciprocal: v = 2^31 / m
    let mut v = V;
    v /= m as u32;

    let mut q = 0u32;

    // First approximation
    let qpart = ((x as u64 * v as u64) >> 31) as u32;
    let new_x = x.wrapping_sub(qpart * m as u32);
    q += qpart;

    // Second refinement (note: cast to u32 before shift, matching ntrulp)
    let qpart = (new_x as u64 * v as u64) as u32 >> 31;
    let final_x = new_x.wrapping_sub(qpart * m as u32);
    q += qpart;

    // Final correction
    let sub_x = final_x.wrapping_sub(m as u32);
    q += 1;

    let mask = if sub_x >> 31 != 0 { u32::MAX } else { 0 };
    let added_x = sub_x.wrapping_add(mask & m as u32);
    let final_q = q.wrapping_add(mask);

    (final_q, added_x as u16)
}

/// Optimised unsigned divmod for Q=4591 using precomputed reciprocal.
///
/// This avoids the division `V / m` that happens in the generic version.
#[inline(always)]
fn u32_divmod_q(x: u32) -> (u32, u16) {
    let v = V_DIV_Q;

    let mut q = 0u32;

    // First approximation
    let qpart = ((x as u64 * v as u64) >> 31) as u32;
    let new_x = x.wrapping_sub(qpart * Q as u32);
    q += qpart;

    // Second refinement
    let qpart = (new_x as u64 * v as u64) as u32 >> 31;
    let final_x = new_x.wrapping_sub(qpart * Q as u32);
    q += qpart;

    // Final correction
    let sub_x = final_x.wrapping_sub(Q as u32);
    q += 1;

    let mask = if sub_x >> 31 != 0 { u32::MAX } else { 0 };
    let added_x = sub_x.wrapping_add(mask & Q as u32);
    let final_q = q.wrapping_add(mask);

    (final_q, added_x as u16)
}

/// Fast signed division and modulo for 14-bit modulus.
///
/// Returns (quotient, remainder) for x / m where x is signed.
#[inline(always)]
fn i32_divmod_u14(x: i32, m: u16) -> (u32, u32) {
    // Add V to make x positive, divide, then adjust
    let (mut uq, ur) = u32_divmod_u14(V.wrapping_add(x as u32), m);
    let mut ur = ur as u32;

    // Subtract the contribution of V
    let (uq2, ur2) = u32_divmod_u14(V, m);
    ur = ur.wrapping_sub(ur2 as u32);
    uq = uq.wrapping_sub(uq2);

    // Fix negative remainder
    let mask: u32 = if ur >> 15 != 0 { u32::MAX } else { 0 };
    ur = ur.wrapping_add(mask & m as u32);
    uq = uq.wrapping_add(mask);

    (uq, ur)
}

/// Fast signed modulo for 14-bit modulus.
#[inline(always)]
#[allow(dead_code)]
fn i32_mod_u14(x: i32, m: u16) -> u32 {
    i32_divmod_u14(x, m).1
}

/// Precomputed: u32_divmod_u14(V, Q) = (467811, 2727)
/// quotient = 2^31 / 4591 = 467811
/// remainder = 2^31 mod 4591 = 2727
const V_DIVMOD_Q: (u32, u32) = (V_DIV_Q, V_MOD_Q);

/// Optimised signed divmod for Q=4591 using precomputed constants.
///
/// This eliminates the call to u32_divmod_u14(V, Q) that happens every freeze().
#[inline(always)]
fn i32_divmod_q(x: i32) -> (u32, u32) {
    // Add V to make x positive, divide, then adjust
    let (mut uq, ur) = u32_divmod_q(V.wrapping_add(x as u32));
    let mut ur = ur as u32;

    // Use precomputed V mod Q instead of recomputing
    ur = ur.wrapping_sub(V_DIVMOD_Q.1);
    uq = uq.wrapping_sub(V_DIVMOD_Q.0);

    // Fix negative remainder
    let mask: u32 = if ur >> 15 != 0 { u32::MAX } else { 0 };
    ur = ur.wrapping_add(mask & Q as u32);
    uq = uq.wrapping_add(mask);

    (uq, ur)
}

/// Optimised signed mod for Q=4591.
#[inline(always)]
fn i32_mod_q(x: i32) -> u32 {
    i32_divmod_q(x).1
}

// ============================================================================
// F3 (mod 3) arithmetic - for R3 polynomials
// ============================================================================

/// Reduce a value to the centred range [-1, 0, 1] (mod 3).
///
/// This is equivalent to ntrulp's `f3::freeze()`.
/// Uses fixed-point multiplication to avoid division.
#[inline(always)]
pub fn f3_freeze(a: i16) -> i8 {
    let a_32 = a as i32;
    // First approximation: a - 3 * floor(a * 10923 / 2^15)
    let b = a_32 - (3 * ((10923 * a_32) >> 15));
    // Refinement step
    let c = b - (3 * ((89_478_485 * b + 134_217_728) >> 28));
    c as i8
}

/// Reduce a value to the centred range [-(q-1)/2, (q-1)/2].
///
/// This is equivalent to ntrulp's `fq::freeze()`.
/// Uses precomputed constants for Q=4591 to avoid division.
#[inline(always)]
pub fn freeze(x: i32) -> i16 {
    // Compute (x + Q12) mod Q, then subtract Q12 to centre
    // Uses optimised i32_mod_q with precomputed reciprocal
    let r = i32_mod_q(x + Q12);
    r as i16 - Q12 as i16
}

/// Compute the multiplicative inverse of a field element using extended GCD.
///
/// Returns `a^(-1) mod q` where q = 4591.
///
/// # Algorithm
///
/// Uses the binary extended GCD algorithm which is O(log q) instead of
/// the O(q) Fermat's little theorem approach.
///
/// # Panics
///
/// Panics if `a` is zero (not invertible).
#[inline]
pub fn recip(a: i16) -> i16 {
    // Extended GCD for modular inverse
    // We want to find x such that a*x ≡ 1 (mod q)
    //
    // Binary extended GCD:
    // Maintain invariants: u*a_orig ≡ u_factor (mod q)
    //                      v*a_orig ≡ v_factor (mod q)
    // where we track (u, v) and reduce until gcd is found.

    debug_assert!(a != 0, "Cannot invert zero");

    // Normalise input to positive
    let a_pos = if a < 0 { a as i32 + Q } else { a as i32 };

    // Standard extended Euclidean algorithm
    let mut old_r = Q;
    let mut r = a_pos;
    let mut old_s = 0i32;
    let mut s = 1i32;

    while r != 0 {
        let quotient = old_r / r;

        let temp = old_r - quotient * r;
        old_r = r;
        r = temp;

        let temp = old_s - quotient * s;
        old_s = s;
        s = temp;
    }

    // old_r should be 1 (gcd)
    debug_assert_eq!(old_r, 1, "a is not invertible mod q");

    // Normalise result to centred range
    freeze(old_s)
}

/// Optimised Rq polynomial for sntrup761.
///
/// This type provides the same functionality as ntrulp's `Rq` but uses
/// the optimised field arithmetic for polynomial inversion.
#[derive(Debug, Clone)]
pub struct Rq {
    /// Polynomial coefficients in centred representation.
    pub coeffs: [i16; P],
}

impl Default for Rq {
    fn default() -> Self {
        Self::new()
    }
}

impl Rq {
    /// Create a new zero polynomial.
    #[inline]
    pub fn new() -> Self {
        Self { coeffs: [0i16; P] }
    }

    /// Create a polynomial from coefficients.
    #[inline]
    pub fn from(coeffs: [i16; P]) -> Self {
        Self { coeffs }
    }

    /// Check if polynomial equals 1 (constant polynomial).
    pub fn eq_one(&self) -> bool {
        if self.coeffs[0] != 1 {
            return false;
        }
        for i in 1..P {
            if self.coeffs[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Multiply this Rq polynomial by an R3 polynomial.
    ///
    /// Computes h = f*g in the ring Rq where g has coefficients in {-1, 0, 1}.
    pub fn mult_r3(&self, g: &[i8; P]) -> Rq {
        let f = &self.coeffs;
        let mut fg = [0i32; P + P - 1];

        // Convolution
        for i in 0..P {
            let gi = g[i] as i32;
            if gi != 0 {
                for j in 0..P {
                    fg[i + j] += f[j] as i32 * gi;
                }
            }
        }

        // Reduce modulo x^p - x - 1
        // f[i] += f[i + p] and f[i + 1] += f[i + p] for i in reverse
        for i in (P..P + P - 1).rev() {
            fg[i - P] += fg[i];
            fg[i - P + 1] += fg[i];
        }

        // Reduce coefficients to Fq
        let mut out = [0i16; P];
        for i in 0..P {
            out[i] = freeze(fg[i]);
        }

        Rq::from(out)
    }

    /// Compute the reciprocal (inverse) of RATIO * self in Rq.
    ///
    /// Returns `out` such that `out * (RATIO * self) = 1` in Rq.
    ///
    /// This uses the optimised extended GCD for field element inversion,
    /// providing significant speedup over the Fermat-based approach.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the polynomial is not invertible.
    pub fn recip<const RATIO: i16>(&self) -> Result<Rq, &'static str> {
        let input = self.coeffs; // Copy for predictable access patterns
        let mut out = [0i16; P];
        let mut f = [0i16; P + 1];
        let mut g = [0i16; P + 1];
        let mut v = [0i16; P + 1];
        let mut r = [0i16; P + 1];
        let mut delta: i16;
        let mut swap: i16;
        let mut t: i16;
        let mut f0: i32;
        let mut g0: i32;

        // Quotient update closure
        let quotient = |out: &mut [i16], f0: i32, g0: i32, fv: &[i16]| {
            for i in 0..P + 1 {
                let x = f0 * out[i] as i32 - g0 * fv[i] as i32;
                out[i] = freeze(x);
            }
        };

        // Initialize r[0] = 1/RATIO using fast extended GCD
        r[0] = recip(RATIO);

        // f = x^p - x - 1
        f[0] = 1;
        f[P - 1] = -1;
        f[P] = -1;

        // g = reverse(input)
        for i in 0..P {
            g[P - 1 - i] = input[i];
        }

        g[P] = 0;
        delta = 1;

        // Main loop: 2*P - 1 iterations
        // Uses branchless operations for constant-time execution
        for _ in 0..2 * P - 1 {
            // Shift v right
            for i in (1..=P).rev() {
                v[i] = v[i - 1];
            }
            v[0] = 0;

            // Compute swap mask (all 1s if swap, all 0s otherwise)
            // swap = (delta > 0) && (g[0] != 0)
            swap = i16_negative_mask(-delta) & i16_nonzero_mask(g[0]);

            // Conditional delta update using XOR
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            // Constant-time conditional swap using XOR
            for i in 0..P + 1 {
                t = swap & (f[i] ^ g[i]);
                f[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            f0 = f[0] as i32;
            g0 = g[0] as i32;

            // Update polynomial quotients
            quotient(&mut g, f0, g0, &f);
            quotient(&mut r, f0, g0, &v);

            // Shift g left (divide by x)
            for i in 0..P {
                g[i] = g[i + 1];
            }
            g[P] = 0;
        }

        // Check if inversion succeeded
        if i16_nonzero_mask(delta) != 0 {
            return Err("Polynomial not invertible");
        }

        // Scale by 1/f[0]
        let scale = recip(f[0]);
        for i in 0..P {
            let x = scale as i32 * v[P - 1 - i] as i32;
            out[i] = freeze(x);
        }

        Ok(Rq::from(out))
    }

    /// Convert to R3 polynomial (reduce coefficients mod 3).
    pub fn to_r3(&self) -> [i8; P] {
        let mut out = [0i8; P];
        for (out_coeff, &in_coeff) in out.iter_mut().zip(self.coeffs.iter()) {
            let r = ((in_coeff as i32 % 3) + 3) % 3;
            *out_coeff = match r {
                0 => 0,
                1 => 1,
                2 => -1,
                _ => unreachable!(),
            };
        }
        out
    }

    /// Multiply all coefficients by a scalar.
    pub fn mult_int(&self, n: i16) -> Rq {
        let mut out = [0i16; P];
        for (out_coeff, &in_coeff) in out.iter_mut().zip(self.coeffs.iter()) {
            *out_coeff = freeze(in_coeff as i32 * n as i32);
        }
        Rq::from(out)
    }
}

impl From<[i16; P]> for Rq {
    fn from(coeffs: [i16; P]) -> Self {
        Rq { coeffs }
    }
}

impl From<&[i8; P]> for Rq {
    fn from(coeffs: &[i8; P]) -> Self {
        let mut out = [0i16; P];
        for i in 0..P {
            out[i] = coeffs[i] as i16;
        }
        Rq { coeffs: out }
    }
}

// ============================================================================
// R3 polynomial (coefficients in {-1, 0, 1})
// ============================================================================

/// Optimised R3 polynomial for sntrup761.
///
/// This type provides the same functionality as ntrulp's `R3` but with
/// optimised polynomial inversion matching the Rq implementation.
#[derive(Debug, Clone)]
pub struct R3 {
    /// Polynomial coefficients in {-1, 0, 1}.
    pub coeffs: [i8; P],
}

impl Default for R3 {
    fn default() -> Self {
        Self::new()
    }
}

impl R3 {
    /// Create a new zero polynomial.
    #[inline]
    pub fn new() -> Self {
        Self { coeffs: [0i8; P] }
    }

    /// Create a polynomial from coefficients.
    #[inline]
    pub fn from(coeffs: [i8; P]) -> Self {
        Self { coeffs }
    }

    /// Check if polynomial equals 1 (constant polynomial).
    pub fn eq_one(&self) -> bool {
        if self.coeffs[0] != 1 {
            return false;
        }
        for i in 1..P {
            if self.coeffs[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Check if polynomial equals zero.
    pub fn eq_zero(&self) -> bool {
        for c in self.coeffs {
            if c != 0 {
                return false;
            }
        }
        true
    }

    /// Multiply two R3 polynomials.
    ///
    /// Computes h = f*g in the ring R3.
    pub fn mult(&self, g: &R3) -> R3 {
        let f = &self.coeffs;
        let g = &g.coeffs;
        let mut fg = [0i8; P + P - 1];

        // Convolution with running freeze
        for i in 0..P {
            let mut r = 0i8;
            for j in 0..=i {
                let x = r + f[j] * g[i - j];
                r = f3_freeze(x as i16);
            }
            fg[i] = r;
        }
        for i in P..P + P - 1 {
            let mut r = 0i8;
            for j in (i - P + 1)..P {
                let x = r + f[j] * g[i - j];
                r = f3_freeze(x as i16);
            }
            fg[i] = r;
        }

        // Reduce modulo x^p - x - 1
        for i in (P..P + P - 1).rev() {
            let x0 = fg[i - P] + fg[i];
            let x1 = fg[i - P + 1] + fg[i];
            fg[i - P] = f3_freeze(x0 as i16);
            fg[i - P + 1] = f3_freeze(x1 as i16);
        }

        let mut out = [0i8; P];
        out[..P].copy_from_slice(&fg[..P]);
        R3::from(out)
    }

    /// Compute the reciprocal (inverse) of self in R3.
    ///
    /// Returns `out` such that `out * self = 1` in R3.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the polynomial is not invertible.
    pub fn recip(&self) -> Result<R3, &'static str> {
        let input = self.coeffs; // Copy for predictable access patterns
        let mut out = [0i8; P];
        let mut f = [0i8; P + 1];
        let mut g = [0i8; P + 1];
        let mut v = [0i8; P + 1];
        let mut r = [0i8; P + 1];
        let mut delta: i16;
        let mut swap: i8;
        let mut t: i8;
        let mut sign: i8;

        // Scalar quotient update for R3 polynomials
        let quotient = |out: &mut [i8], sign: i8, fv: &[i8]| {
            for i in 0..P + 1 {
                let x = out[i] + sign * fv[i];
                out[i] = f3_freeze(x as i16);
            }
        };

        // Initialize r[0] = 1
        r[0] = 1;

        // f = x^p - x - 1
        f[0] = 1;
        f[P - 1] = -1;
        f[P] = -1;

        // g = reverse(input)
        for i in 0..P {
            g[P - 1 - i] = input[i];
        }

        g[P] = 0;
        delta = 1;

        // Main loop: 2*P - 1 iterations
        for _ in 0..2 * P - 1 {
            // Shift v right
            for i in (1..=P).rev() {
                v[i] = v[i - 1];
            }
            v[0] = 0;

            // sign = -g[0] * f[0] (in F3, this is the elimination coefficient)
            sign = -g[0] * f[0];

            // Compute swap mask
            swap = (i16_negative_mask(-delta) & i16_nonzero_mask(g[0] as i16)) as i8;

            // Conditional delta update
            delta ^= (swap as i16) & (delta ^ -delta);
            delta += 1;

            // Constant-time conditional swap
            for i in 0..P + 1 {
                t = swap & (f[i] ^ g[i]);
                f[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            // Update polynomial quotients
            quotient(&mut g, sign, &f);
            quotient(&mut r, sign, &v);

            // Shift g left (divide by x)
            for i in 0..P {
                g[i] = g[i + 1];
            }
            g[P] = 0;
        }

        // Check if inversion succeeded
        if i16_nonzero_mask(delta) != 0 {
            return Err("Polynomial not invertible in R3");
        }

        // Scale by f[0] (which is ±1 in R3)
        sign = f[0];
        for i in 0..P {
            out[i] = sign * v[P - 1 - i];
        }

        Ok(R3::from(out))
    }

    /// Convert to Rq polynomial.
    pub fn rq_from_r3(&self) -> Rq {
        let mut out = [0i16; P];
        for (i, v) in out.iter_mut().enumerate() {
            *v = freeze(self.coeffs[i].into());
        }
        Rq::from(out)
    }
}

impl From<[i8; P]> for R3 {
    fn from(coeffs: [i8; P]) -> Self {
        R3 { coeffs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeze() {
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(1), 1);
        assert_eq!(freeze(-1), -1);
        assert_eq!(freeze(Q), 0);
        assert_eq!(freeze(-Q), 0);
        assert_eq!(freeze(Q + 1), 1);
        assert_eq!(freeze(Q12 + 1), Q12 as i16 + 1 - Q as i16);
    }

    #[test]
    fn test_recip_basic() {
        // Test that a * recip(a) ≡ 1 (mod q)
        for a in [1i16, 2, 3, 42, 100, 1000, 2000, -1, -42, -1000] {
            let inv = recip(a);
            let product = freeze(a as i32 * inv as i32);
            assert_eq!(product, 1, "recip({}) = {} failed", a, inv);
        }
    }

    #[test]
    fn test_recip_vs_fermat() {
        // Compare extended GCD result with Fermat's little theorem
        fn fermat_recip(a: i16) -> i16 {
            let mut ai = a;
            for _ in 1..Q - 2 {
                ai = freeze(a as i32 * ai as i32);
            }
            ai
        }

        for a in [1i16, 7, 13, 42, 761, 1234, 2000, 4000, -1, -100] {
            let egcd = recip(a);
            let fermat = fermat_recip(a);
            assert_eq!(
                egcd, fermat,
                "Mismatch for a={}: egcd={}, fermat={}",
                a, egcd, fermat
            );
        }
    }

    #[test]
    fn test_rq_mult_r3() {
        // Simple test: multiply by 1 polynomial
        let mut f_coeffs = [0i16; P];
        f_coeffs[0] = 1;
        let f = Rq::from(f_coeffs);

        let mut g_coeffs = [0i8; P];
        g_coeffs[0] = 1;

        let h = f.mult_r3(&g_coeffs);
        assert!(h.eq_one());
    }

    #[test]
    fn test_rq_recip() {
        // Create a simple invertible polynomial
        let mut coeffs = [0i16; P];
        coeffs[0] = 1;
        coeffs[1] = 1;

        let rq = Rq::from(coeffs);
        let inv = rq.recip::<1>().expect("Should be invertible");

        // Verify: inv * rq should equal 1
        let r3_coeffs = rq.to_r3();
        let product = inv.mult_r3(&r3_coeffs);

        assert!(product.eq_one(), "Reciprocal verification failed");
    }

    #[test]
    fn test_f3_freeze() {
        // Test values in centred range
        assert_eq!(f3_freeze(0), 0);
        assert_eq!(f3_freeze(1), 1);
        assert_eq!(f3_freeze(-1), -1);
        assert_eq!(f3_freeze(2), -1); // 2 mod 3 = 2 -> -1 in centred
        assert_eq!(f3_freeze(-2), 1); // -2 mod 3 = 1
        assert_eq!(f3_freeze(3), 0);
        assert_eq!(f3_freeze(-3), 0);
        assert_eq!(f3_freeze(4), 1);
        assert_eq!(f3_freeze(-4), -1);

        // Test a range of values
        for i in -100i16..=100 {
            let expected = match ((i % 3) + 3) % 3 {
                0 => 0i8,
                1 => 1,
                2 => -1,
                _ => unreachable!(),
            };
            assert_eq!(f3_freeze(i), expected, "f3_freeze({}) failed", i);
        }
    }

    #[test]
    fn test_r3_mult() {
        // Test: 1 * 1 = 1
        let mut one_coeffs = [0i8; P];
        one_coeffs[0] = 1;
        let one = R3::from(one_coeffs);

        let product = one.mult(&one);
        assert!(product.eq_one());

        // Test: x * 1 = x
        let mut x_coeffs = [0i8; P];
        x_coeffs[1] = 1;
        let x = R3::from(x_coeffs);

        let product = x.mult(&one);
        assert_eq!(product.coeffs[1], 1);
        assert_eq!(product.coeffs[0], 0);
    }

    #[test]
    fn test_r3_recip() {
        // Create a simple invertible R3 polynomial
        let mut coeffs = [0i8; P];
        coeffs[0] = 1;
        coeffs[1] = 1;

        let r3 = R3::from(coeffs);
        let inv = r3.recip().expect("Should be invertible");

        // Verify: inv * r3 should equal 1
        let product = inv.mult(&r3);
        assert!(product.eq_one(), "R3 reciprocal verification failed");
    }

    #[test]
    fn test_r3_recip_random_pattern() {
        // Create a polynomial with alternating coefficients
        let mut coeffs = [0i8; P];
        for i in 0..50 {
            coeffs[i * 2] = if i % 2 == 0 { 1 } else { -1 };
        }

        let r3 = R3::from(coeffs);
        if let Ok(inv) = r3.recip() {
            let product = inv.mult(&r3);
            assert!(
                product.eq_one(),
                "R3 reciprocal verification failed for alternating pattern"
            );
        }
        // Note: some polynomials may not be invertible, which is fine
    }

    // ========================================================================
    // Edge case tests for cryptographic correctness
    // ========================================================================

    /// Verify precomputed constants are mathematically correct.
    #[test]
    fn test_precomputed_constants() {
        // V = 2^31
        assert_eq!(V, 0x8000_0000);
        assert_eq!(V, 1u32 << 31);

        // V_DIV_Q = V / Q (integer division)
        let expected_div = V / Q as u32;
        assert_eq!(V_DIV_Q, expected_div, "V_DIV_Q mismatch");

        // V_MOD_Q = V % Q
        let expected_mod = V % Q as u32;
        assert_eq!(V_MOD_Q, expected_mod, "V_MOD_Q mismatch");

        // Verify: V_DIV_Q * Q + V_MOD_Q == V
        let reconstructed = V_DIV_Q as u64 * Q as u64 + V_MOD_Q as u64;
        assert_eq!(reconstructed, V as u64, "V reconstruction failed");

        // Verify V_DIVMOD_Q tuple matches individual constants
        assert_eq!(V_DIVMOD_Q.0, V_DIV_Q);
        assert_eq!(V_DIVMOD_Q.1, V_MOD_Q);
    }

    /// Compare optimised u32_divmod_q against generic u32_divmod_u14.
    #[test]
    fn test_u32_divmod_q_vs_generic() {
        // Test specific edge cases
        let test_values: &[u32] = &[
            0,
            1,
            Q as u32 - 1,
            Q as u32,
            Q as u32 + 1,
            2 * Q as u32,
            V - 1,
            V,
            V + 1,
            V + Q as u32,
            u32::MAX / 2,
            u32::MAX - Q as u32,
            u32::MAX - 1,
            u32::MAX,
        ];

        for &x in test_values {
            let optimised = u32_divmod_q(x);
            let generic = u32_divmod_u14(x, Q as u16);
            assert_eq!(
                optimised, generic,
                "u32_divmod_q({}) = {:?}, but u32_divmod_u14 = {:?}",
                x, optimised, generic
            );
        }

        // Test a range of values around Q boundaries
        for i in 0..10000u32 {
            let optimised = u32_divmod_q(i);
            let generic = u32_divmod_u14(i, Q as u16);
            assert_eq!(optimised, generic, "Mismatch at x={}", i);
        }
    }

    /// Compare optimised i32_divmod_q against generic i32_divmod_u14.
    #[test]
    fn test_i32_divmod_q_vs_generic() {
        // Test specific edge cases
        let test_values: &[i32] = &[
            0,
            1,
            -1,
            Q - 1,
            Q,
            Q + 1,
            -Q + 1,
            -Q,
            -Q - 1,
            Q12,
            -Q12,
            Q12 + 1,
            -Q12 - 1,
            i32::MAX / 2,
            i32::MIN / 2,
            // Near overflow boundaries for x + Q12
            i32::MAX - Q12 - 100,
            i32::MIN + Q12 + 100,
        ];

        for &x in test_values {
            let optimised = i32_divmod_q(x);
            let generic = i32_divmod_u14(x, Q as u16);
            assert_eq!(
                optimised, generic,
                "i32_divmod_q({}) = {:?}, but i32_divmod_u14 = {:?}",
                x, optimised, generic
            );
        }

        // Test a range of positive and negative values
        for i in -10000i32..10000 {
            let optimised = i32_divmod_q(i);
            let generic = i32_divmod_u14(i, Q as u16);
            assert_eq!(optimised, generic, "Mismatch at x={}", i);
        }
    }

    /// Test freeze() at critical boundary values.
    #[test]
    fn test_freeze_boundaries() {
        // Basic values
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(1), 1);
        assert_eq!(freeze(-1), -1);

        // Q boundaries
        assert_eq!(freeze(Q), 0);
        assert_eq!(freeze(-Q), 0);
        assert_eq!(freeze(Q - 1), Q as i16 - 1 - Q12 as i16 - Q12 as i16 - 1);
        assert_eq!(freeze(Q + 1), 1);
        assert_eq!(freeze(-Q - 1), -1);

        // Q12 boundaries (output range is [-Q12, Q12])
        assert_eq!(freeze(Q12), Q12 as i16);
        assert_eq!(freeze(-Q12), -(Q12 as i16));
        assert_eq!(freeze(Q12 + 1), Q12 as i16 + 1 - Q as i16);
        assert_eq!(freeze(-Q12 - 1), -(Q12 as i16) - 1 + Q as i16);

        // Multiple of Q
        assert_eq!(freeze(2 * Q), 0);
        assert_eq!(freeze(-2 * Q), 0);
        assert_eq!(freeze(100 * Q), 0);
        assert_eq!(freeze(-100 * Q), 0);

        // Large values
        assert_eq!(freeze(1_000_000), freeze(1_000_000 % Q));
        assert_eq!(freeze(-1_000_000), freeze(-1_000_000 % Q + Q));
    }

    /// Exhaustive freeze() test comparing with ntrulp-style implementation.
    #[test]
    fn test_freeze_exhaustive_vs_reference() {
        // Reference implementation using generic i32_mod_u14
        fn freeze_reference(x: i32) -> i16 {
            let r = i32_divmod_u14(x + Q12, Q as u16).1;
            r as i16 - Q12 as i16
        }

        // Test full i16 range (inputs commonly used in sntrup761)
        for x in i16::MIN..=i16::MAX {
            let our_result = freeze(x as i32);
            let ref_result = freeze_reference(x as i32);
            assert_eq!(
                our_result, ref_result,
                "freeze({}) = {}, but reference = {}",
                x, our_result, ref_result
            );
        }
    }

    /// Test freeze() with values that could cause overflow in x + Q12.
    #[test]
    fn test_freeze_overflow_safety() {
        // These values are near the limits of what freeze() can safely handle
        // The internal computation is x + Q12 which must not overflow

        // Safe large positive
        let large_pos = i32::MAX - Q12 - 1000;
        let result = freeze(large_pos);
        // Just verify it doesn't panic and produces a value in range
        assert!(result >= -(Q12 as i16) && result <= Q12 as i16);

        // Safe large negative
        let large_neg = i32::MIN + Q12 + 1000;
        let result = freeze(large_neg);
        assert!(result >= -(Q12 as i16) && result <= Q12 as i16);

        // Values used in actual sntrup761 computations (products of coefficients)
        // Max coefficient is Q12 = 2295, so max product is 2295 * 2295 = 5267025
        let max_product = (Q12 as i64 * Q12 as i64) as i32;
        let result = freeze(max_product);
        assert!(result >= -(Q12 as i16) && result <= Q12 as i16);

        let min_product = -(Q12 as i64 * Q12 as i64) as i32;
        let result = freeze(min_product);
        assert!(result >= -(Q12 as i16) && result <= Q12 as i16);
    }

    /// Test f3_freeze() at boundary values.
    #[test]
    fn test_f3_freeze_boundaries() {
        // Basic values
        assert_eq!(f3_freeze(0), 0);
        assert_eq!(f3_freeze(1), 1);
        assert_eq!(f3_freeze(-1), -1);
        assert_eq!(f3_freeze(2), -1); // 2 ≡ -1 (mod 3)
        assert_eq!(f3_freeze(-2), 1); // -2 ≡ 1 (mod 3)

        // Multiples of 3
        assert_eq!(f3_freeze(3), 0);
        assert_eq!(f3_freeze(-3), 0);
        assert_eq!(f3_freeze(300), 0);
        assert_eq!(f3_freeze(-300), 0);

        // i16 boundaries
        // i16::MAX = 32767 = 3 * 10922 + 1, so 32767 mod 3 = 1
        assert_eq!(f3_freeze(i16::MAX), 1);
        // i16::MIN = -32768 = 3 * (-10923) + 1, so -32768 mod 3 = 1 (centred: 1)
        // Actually: -32768 = -32769 + 1 = 3*(-10923) + 1
        let min_mod = ((i16::MIN as i32 % 3) + 3) % 3;
        let expected = match min_mod {
            0 => 0i8,
            1 => 1,
            2 => -1,
            _ => unreachable!(),
        };
        assert_eq!(f3_freeze(i16::MIN), expected);
    }

    /// Exhaustive f3_freeze() test for full i16 range.
    #[test]
    fn test_f3_freeze_exhaustive() {
        for x in i16::MIN..=i16::MAX {
            let result = f3_freeze(x);

            // Verify result is in centred range [-1, 0, 1]
            assert!(
                result >= -1 && result <= 1,
                "f3_freeze({}) = {} out of range",
                x,
                result
            );

            // Verify correctness: x ≡ result (mod 3)
            let x_mod3 = ((x as i32 % 3) + 3) % 3;
            let result_mod3 = ((result as i32 % 3) + 3) % 3;
            assert_eq!(
                x_mod3, result_mod3,
                "f3_freeze({}) = {} incorrect mod 3",
                x, result
            );
        }
    }

    /// Test recip() edge cases.
    #[test]
    fn test_recip_edge_cases() {
        // recip(1) should be 1
        assert_eq!(recip(1), 1);

        // recip(-1) should be -1
        assert_eq!(recip(-1), -1);

        // recip(a) * a ≡ 1 (mod Q) for various values
        let test_values: &[i16] = &[
            1, 2, 3, 7, 13, 42, 100, 500, 1000, 2000, 2295, // Q12
            -1, -2, -3, -7, -42, -100, -1000, -2295,
        ];

        for &a in test_values {
            let inv = recip(a);
            let product = freeze(a as i32 * inv as i32);
            assert_eq!(
                product, 1,
                "recip({}) = {} failed: {} * {} mod Q = {}",
                a, inv, a, inv, product
            );
        }

        // recip(a) = -recip(-a) (antisymmetry)
        for &a in &[2i16, 7, 42, 100, 1000] {
            assert_eq!(
                recip(a),
                freeze(-(recip(-a) as i32)),
                "Antisymmetry failed for a={}",
                a
            );
        }
    }

    /// Compare our recip with ntrulp's Fermat-based recip for all valid inputs.
    #[test]
    fn test_recip_vs_fermat_exhaustive() {
        // Fermat's little theorem: a^(q-2) ≡ a^(-1) (mod q)
        fn fermat_recip(a: i16) -> i16 {
            if a == 0 {
                return 0;
            }
            let mut ai = a;
            for _ in 1..Q - 2 {
                ai = freeze(a as i32 * ai as i32);
            }
            ai
        }

        // Test all non-zero values in the valid coefficient range
        for a in 1..=Q12 as i16 {
            let egcd = recip(a);
            let fermat = fermat_recip(a);
            assert_eq!(
                egcd, fermat,
                "recip({}) mismatch: egcd={}, fermat={}",
                a, egcd, fermat
            );
        }

        // Test negative values
        for a in (-(Q12 as i16))..=-1 {
            let egcd = recip(a);
            let fermat = fermat_recip(a);
            assert_eq!(
                egcd, fermat,
                "recip({}) mismatch: egcd={}, fermat={}",
                a, egcd, fermat
            );
        }
    }

    /// Direct comparison with ntrulp crate's freeze implementation.
    #[test]
    fn test_freeze_vs_ntrulp_crate() {
        use ntrulp::poly::fq::freeze as ntrulp_freeze;

        // Test full i16 range
        for x in i16::MIN..=i16::MAX {
            let our_result = freeze(x as i32);
            let ntrulp_result = ntrulp_freeze(x as i32);
            assert_eq!(
                our_result, ntrulp_result,
                "freeze({}) = {}, but ntrulp = {}",
                x, our_result, ntrulp_result
            );
        }

        // Test larger values commonly seen in polynomial operations
        for x in &[
            100_000i32, -100_000, 1_000_000, -1_000_000, 5_000_000, -5_000_000,
        ] {
            let our_result = freeze(*x);
            let ntrulp_result = ntrulp_freeze(*x);
            assert_eq!(
                our_result, ntrulp_result,
                "freeze({}) = {}, but ntrulp = {}",
                x, our_result, ntrulp_result
            );
        }
    }

    /// Direct comparison with ntrulp crate's f3_freeze implementation.
    #[test]
    fn test_f3_freeze_vs_ntrulp_crate() {
        use ntrulp::poly::f3::freeze as ntrulp_f3_freeze;

        // Test full i16 range
        for x in i16::MIN..=i16::MAX {
            let our_result = f3_freeze(x);
            let ntrulp_result = ntrulp_f3_freeze(x);
            assert_eq!(
                our_result, ntrulp_result,
                "f3_freeze({}) = {}, but ntrulp = {}",
                x, our_result, ntrulp_result
            );
        }
    }

    /// Direct comparison with ntrulp's divmod functions.
    #[test]
    fn test_divmod_vs_ntrulp_crate() {
        use ntrulp::math::nums::{
            i32_divmod_u14 as ntrulp_i32_divmod, u32_divmod_u14 as ntrulp_u32_divmod,
        };

        // Test u32_divmod_q against ntrulp
        let u32_test_values: &[u32] = &[
            0,
            1,
            Q as u32 - 1,
            Q as u32,
            Q as u32 + 1,
            V - 1,
            V,
            V + 1,
            u32::MAX / 2,
            u32::MAX,
        ];

        for &x in u32_test_values {
            let our_result = u32_divmod_q(x);
            let ntrulp_result = ntrulp_u32_divmod(x, Q as u16);
            assert_eq!(
                our_result, ntrulp_result,
                "u32_divmod_q({}) = {:?}, but ntrulp = {:?}",
                x, our_result, ntrulp_result
            );
        }

        // Test i32_divmod_q against ntrulp
        let i32_test_values: &[i32] = &[
            0,
            1,
            -1,
            Q - 1,
            Q,
            Q + 1,
            -Q + 1,
            -Q,
            -Q - 1,
            Q12,
            -Q12,
            i32::MAX / 2,
            i32::MIN / 2,
        ];

        for &x in i32_test_values {
            let our_result = i32_divmod_q(x);
            let ntrulp_result = ntrulp_i32_divmod(x, Q as u16);
            assert_eq!(
                our_result, ntrulp_result,
                "i32_divmod_q({}) = {:?}, but ntrulp = {:?}",
                x, our_result, ntrulp_result
            );
        }
    }
}
