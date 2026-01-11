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
//! This module provides two inversion functions:
//! - `recip()` - Fast extended GCD (~12 iterations, ~380x speedup), variable-time
//! - `recip_ct()` - Constant-time Fermat with binary exponentiation (~26 ops)
//!
//! # Constant-Time Guarantees
//!
//! This module is designed to prevent timing side-channel attacks:
//!
//! - **`recip_ct()`**: Fully constant-time field inversion using Fermat's little
//!   theorem with binary exponentiation. Always performs exactly 13 squarings and
//!   13 conditional multiplications via constant-time select.
//!
//! - **`recip()`**: Fast but variable-time. Only use for public values (e.g., RATIO).
//!
//! - **`freeze()`, `u32_divmod_q()`**: Constant-time via arithmetic masking.
//!
//! - **`mult_r3()`**: Constant-time - always performs all P*P iterations regardless
//!   of zero coefficients, preventing sparsity pattern leakage.
//!
//! - **Polynomial reciprocal (`Rq::recip`)**: Uses constant-time `recip_ct()` for
//!   the final scaling step where the input may be secret-dependent.

use crate::sntrup761_encoding::P;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Constant-time conditional select: returns a if mask is all-ones, b if mask is zero.
/// mask must be either 0 or -1 (all bits set).
#[inline(always)]
fn i16_select(mask: i16, a: i16, b: i16) -> i16 {
    b ^ (mask & (a ^ b))
}

/// Constant-time conditional select for i32.
#[inline(always)]
#[allow(dead_code)]
fn i32_select(mask: i32, a: i32, b: i32) -> i32 {
    b ^ (mask & (a ^ b))
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

    // Final correction (constant-time via arithmetic masking)
    let sub_x = final_x.wrapping_sub(m as u32);
    q += 1;

    // Constant-time mask: 0xFFFFFFFF if sub_x has high bit set, 0 otherwise
    // (sub_x >> 31) is 1 if negative (underflow), 0 otherwise
    // 0 - 1 = 0xFFFFFFFF, 0 - 0 = 0
    let mask = 0u32.wrapping_sub(sub_x >> 31);
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

    // Final correction (constant-time via arithmetic masking)
    let sub_x = final_x.wrapping_sub(Q as u32);
    q += 1;

    // Constant-time mask: 0xFFFFFFFF if sub_x has high bit set, 0 otherwise
    let mask = 0u32.wrapping_sub(sub_x >> 31);
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

/// Constant-time modular inverse using Fermat's little theorem.
///
/// Computes a^(-1) = a^(q-2) mod q using binary exponentiation.
/// This is slower than the extended GCD (~21 operations vs ~12), but is
/// fully constant-time with no secret-dependent branches or memory accesses.
///
/// # Constant-Time Guarantee
///
/// This function:
/// - Always performs exactly 13 squarings
/// - Always performs exactly 13 conditional multiplications (via constant-time select)
/// - Has no secret-dependent branches or memory accesses
///
/// Use this for operations on secret data (e.g., secret key coefficients).
/// For public data, use `recip()` which is faster.
///
/// # Panics
///
/// Panics in debug mode if `a` is zero.
#[inline]
pub fn recip_ct(a: i16) -> i16 {
    debug_assert!(a != 0, "Cannot invert zero");

    // Normalise input to positive in range [1, Q-1] using constant-time arithmetic
    // If a < 0, we want a + Q, otherwise a
    // mask = -1 if a < 0, else 0
    let neg_mask = (a >> 15) as i32; // -1 if negative, 0 otherwise
    let a_pos = (a as i32) + (neg_mask & Q);

    // Fermat's little theorem: a^(-1) = a^(q-2) mod q
    // q - 2 = 4589 = 0b1000111101101
    //
    // Binary representation (13 bits):
    // bit 12: 1 (4096)
    // bit 11: 0
    // bit 10: 0
    // bit 9:  0
    // bit 8:  1 (256)
    // bit 7:  1 (128)
    // bit 6:  1 (64)
    // bit 5:  1 (32)
    // bit 4:  0
    // bit 3:  1 (8)
    // bit 2:  1 (4)
    // bit 1:  0
    // bit 0:  1 (1)

    let mut result = 1i32;
    let mut base = a_pos;

    // Q - 2 = 4589 = 0x11ED
    const EXP: u32 = 4589;

    // Unrolled loop for constant-time (13 iterations for 13-bit exponent)
    // Each iteration: conditionally multiply by base, then square base
    // We use i16_select on the frozen (reduced) values

    // Bit 0 (value 1)
    let bit_mask = -((EXP & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 1 (value 0)
    let bit_mask = -(((EXP >> 1) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 2 (value 1)
    let bit_mask = -(((EXP >> 2) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 3 (value 1)
    let bit_mask = -(((EXP >> 3) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 4 (value 0)
    let bit_mask = -(((EXP >> 4) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 5 (value 1)
    let bit_mask = -(((EXP >> 5) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 6 (value 1)
    let bit_mask = -(((EXP >> 6) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 7 (value 1)
    let bit_mask = -(((EXP >> 7) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 8 (value 1)
    let bit_mask = -(((EXP >> 8) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 9 (value 0)
    let bit_mask = -(((EXP >> 9) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 10 (value 0)
    let bit_mask = -(((EXP >> 10) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 11 (value 0)
    let bit_mask = -(((EXP >> 11) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;
    base = freeze(base * base) as i32;

    // Bit 12 (value 1) - MSB, no need to square after
    let bit_mask = -(((EXP >> 12) & 1) as i16);
    let prod = freeze(result * base);
    let same = freeze(result);
    result = i16_select(bit_mask, prod, same) as i32;

    result as i16
}

/// Optimised Rq polynomial for sntrup761.
///
/// This type provides the same functionality as ntrulp's `Rq` but uses
/// the optimised field arithmetic for polynomial inversion.
///
/// # Security
///
/// This type implements `Zeroize` and `ZeroizeOnDrop` to securely clear
/// polynomial coefficients when dropped, as they may contain secret key material.
///
/// Cache-line aligned (64 bytes) for optimal memory access patterns.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(64))]
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
    ///
    /// # Constant-Time Guarantee
    ///
    /// This function performs all P*P iterations regardless of the values in g,
    /// ensuring no timing side-channel leaks the sparsity pattern of g.
    pub fn mult_r3(&self, g: &[i8; P]) -> Rq {
        let f = &self.coeffs;
        let mut fg = [0i32; P + P - 1];

        // Convolution - constant-time (always perform all iterations)
        // When gi == 0, the addition is 0 which doesn't change the result
        for i in 0..P {
            let gi = g[i] as i32;
            for j in 0..P {
                fg[i + j] += f[j] as i32 * gi;
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

        // Inline function for quotient update (called 3042 times per recip)
        #[inline(always)]
        fn quotient_update(out: &mut [i16; P + 1], f0: i32, g0: i32, fv: &[i16; P + 1]) {
            for i in 0..P + 1 {
                let x = f0 * out[i] as i32 - g0 * fv[i] as i32;
                out[i] = freeze(x);
            }
        }

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
            quotient_update(&mut g, f0, g0, &f);
            quotient_update(&mut r, f0, g0, &v);

            // Shift g left (divide by x)
            for i in 0..P {
                g[i] = g[i + 1];
            }
            g[P] = 0;
        }

        // Check if inversion succeeded
        if i16_nonzero_mask(delta) != 0 {
            // Zeroize intermediate arrays before returning error
            f.zeroize();
            g.zeroize();
            v.zeroize();
            r.zeroize();
            return Err("Polynomial not invertible");
        }

        // Scale by 1/f[0] using constant-time reciprocal
        // (f[0] may be secret-dependent during key generation/decapsulation)
        let scale = recip_ct(f[0]);
        for i in 0..P {
            let x = scale as i32 * v[P - 1 - i] as i32;
            out[i] = freeze(x);
        }

        // Zeroize intermediate arrays containing secret-derived data
        f.zeroize();
        g.zeroize();
        v.zeroize();
        r.zeroize();

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

impl ConstantTimeEq for Rq {
    /// Constant-time equality comparison for polynomials.
    ///
    /// Returns `Choice(1)` if self == other, `Choice(0)` otherwise.
    /// Executes in constant time regardless of coefficient values.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.coeffs.ct_eq(&other.coeffs)
    }
}

// ============================================================================
// R3 polynomial (coefficients in {-1, 0, 1})
// ============================================================================

/// Optimised R3 polynomial for sntrup761.
///
/// This type provides the same functionality as ntrulp's `R3` but with
/// optimised polynomial inversion matching the Rq implementation.
///
/// # Security
///
/// This type implements `Zeroize` and `ZeroizeOnDrop` to securely clear
/// polynomial coefficients when dropped, as they may contain secret key material.
///
/// Cache-line aligned (64 bytes) for optimal memory access patterns.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(64))]
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

        // Inline function for R3 quotient update (called 3042 times per recip)
        #[inline(always)]
        fn quotient_update_r3(out: &mut [i8; P + 1], sign: i8, fv: &[i8; P + 1]) {
            for i in 0..P + 1 {
                let x = out[i] + sign * fv[i];
                out[i] = f3_freeze(x as i16);
            }
        }

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
            quotient_update_r3(&mut g, sign, &f);
            quotient_update_r3(&mut r, sign, &v);

            // Shift g left (divide by x)
            for i in 0..P {
                g[i] = g[i + 1];
            }
            g[P] = 0;
        }

        // Check if inversion succeeded
        if i16_nonzero_mask(delta) != 0 {
            // Zeroize intermediate arrays before returning error
            f.zeroize();
            g.zeroize();
            v.zeroize();
            r.zeroize();
            return Err("Polynomial not invertible in R3");
        }

        // Scale by f[0] (which is ±1 in R3)
        sign = f[0];
        for i in 0..P {
            out[i] = sign * v[P - 1 - i];
        }

        // Zeroize intermediate arrays containing secret-derived data
        f.zeroize();
        g.zeroize();
        v.zeroize();
        r.zeroize();

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

impl ConstantTimeEq for R3 {
    /// Constant-time equality comparison for R3 polynomials.
    ///
    /// Returns `Choice(1)` if self == other, `Choice(0)` otherwise.
    /// Executes in constant time regardless of coefficient values.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.coeffs.ct_eq(&other.coeffs)
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

    /// Verify recip(0) panics in debug mode.
    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_recip_zero_panics() {
        // Zero is not invertible in any field
        let _ = recip(0);
    }

    /// Verify recip_ct(0) panics in debug mode.
    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_recip_ct_zero_panics() {
        // Zero is not invertible in any field
        let _ = recip_ct(0);
    }

    /// Test freeze() with values at the edges of its safe input range.
    ///
    /// Note: freeze() is designed for polynomial arithmetic where values are
    /// bounded by products of coefficients (max ~5.3 million for Q12*Q12).
    /// It uses `x + Q12` internally, so the safe input range is approximately
    /// [i32::MIN + Q12, i32::MAX - Q12] to avoid overflow.
    ///
    /// For sntrup761, actual inputs never exceed ±(Q12 * Q12) ≈ ±5,267,025.
    #[test]
    fn test_freeze_with_i32_extremes() {
        // Test the actual maximum values used in sntrup761 polynomial arithmetic
        // Max coefficient is Q12 = 2295, so max product is 2295 * 2295 = 5267025
        let max_product = (Q12 as i64 * Q12 as i64) as i32;
        let result = freeze(max_product);
        assert!(
            result >= -(Q12 as i16) && result <= Q12 as i16,
            "freeze(Q12*Q12) = {} out of valid range",
            result
        );

        let min_product = -(Q12 as i64 * Q12 as i64) as i32;
        let result = freeze(min_product);
        assert!(
            result >= -(Q12 as i16) && result <= Q12 as i16,
            "freeze(-Q12*Q12) = {} out of valid range",
            result
        );

        // Test values at the safe boundary (just below overflow threshold)
        // freeze() computes x + Q12 internally, so max safe input is i32::MAX - Q12
        let safe_max = i32::MAX - Q12 - 1;
        let safe_result = freeze(safe_max);
        assert!(
            safe_result >= -(Q12 as i16) && safe_result <= Q12 as i16,
            "freeze({}) = {} out of valid range",
            safe_max,
            safe_result
        );

        // Min safe input: i32::MIN would need adjustment for the internal arithmetic
        // But for sntrup761, we never get close to i32::MIN either
        let safe_min = i32::MIN + Q12 + 1;
        let safe_result = freeze(safe_min);
        assert!(
            safe_result >= -(Q12 as i16) && safe_result <= Q12 as i16,
            "freeze({}) = {} out of valid range",
            safe_min,
            safe_result
        );

        // Test some intermediate large values that might occur in polynomial ops
        for &x in &[
            100_000i32,
            -100_000,
            1_000_000,
            -1_000_000,
            5_000_000,
            -5_000_000,
            max_product / 2,
            min_product / 2,
        ] {
            let result = freeze(x);
            assert!(
                result >= -(Q12 as i16) && result <= Q12 as i16,
                "freeze({}) = {} out of valid range",
                x,
                result
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

    /// Verify recip_ct (constant-time) matches recip (fast) for all valid inputs.
    #[test]
    fn test_recip_ct_vs_recip_exhaustive() {
        // Test all non-zero values in the valid coefficient range
        for a in 1..=Q12 as i16 {
            let fast = recip(a);
            let ct = recip_ct(a);
            assert_eq!(
                fast, ct,
                "recip_ct({}) = {} but recip({}) = {}",
                a, ct, a, fast
            );
        }

        // Test negative values
        for a in (-(Q12 as i16))..=-1 {
            let fast = recip(a);
            let ct = recip_ct(a);
            assert_eq!(
                fast, ct,
                "recip_ct({}) = {} but recip({}) = {}",
                a, ct, a, fast
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
