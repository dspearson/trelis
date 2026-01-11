//! Polynomial arithmetic for sntrup761.
//!
//! This module provides polynomial multiplication using:
//! - **Karatsuba**: O(n^1.58) - default, faster for n=761 in pure Rust
//! - **NTT**: O(n log n) with Barrett reduction - available for comparison
//!
//! # Ring Structure
//!
//! sntrup761 operates in the ring Z_q\[x\]/(x^p - x - 1) where:
//! - p = 761 (polynomial degree)
//! - q = 4591 (coefficient modulus for Rq)
//!
//! For R3, coefficients are in {-1, 0, 1}.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// Polynomial degree for sntrup761.
pub const P: usize = 761;

/// Modulus for Rq polynomials.
pub const Q: i32 = 4591;

/// Half of Q, used for centred representation.
pub const Q_HALF: i32 = Q / 2;

// ============================================================================
// Karatsuba Multiplication
// ============================================================================
//
// Karatsuba reduces multiplication from O(n²) to O(n^1.58).
// For n=761, this is ~580,000 → ~25,000 operations (~23x reduction).
//
// Algorithm:
// For polynomials A = A_low + x^m * A_high, B = B_low + x^m * B_high:
// A * B = A_low*B_low + x^m * ((A_low+A_high)*(B_low+B_high) - A_low*B_low - A_high*B_high) + x^2m * A_high*B_high
//
// This uses 3 multiplications instead of 4.

/// Karatsuba threshold - below this, use schoolbook multiplication.
/// Tuned for sntrup761's coefficient sizes.
const KARATSUBA_THRESHOLD: usize = 32;

/// NTT size (must be power of 2, ≥ 2*P-1 = 1521)
const NTT_SIZE: usize = 2048;

/// NTT-friendly prime: 998244353 = 119 * 2^23 + 1
/// Supports NTT sizes up to 2^23.
const NTT_PRIME: u64 = 998244353;

/// Primitive root of unity for NTT_PRIME.
const NTT_PRIMITIVE_ROOT: u64 = 3;

/// Schoolbook polynomial multiplication (for small polynomials).
/// Result has length a.len() + b.len() - 1.
fn schoolbook_mult(a: &[i32], b: &[i32]) -> Vec<i32> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut result = vec![0i32; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 {
            continue;
        }
        for (j, &bj) in b.iter().enumerate() {
            result[i + j] += ai * bj;
        }
    }
    result
}

/// Karatsuba polynomial multiplication.
/// Returns a polynomial of degree len(a) + len(b) - 2.
///
/// Optimised to use `with_capacity` for pre-allocation where possible.
fn karatsuba_mult(a: &[i32], b: &[i32]) -> Vec<i32> {
    let n = a.len().max(b.len());

    // Base case: use schoolbook for small polynomials
    if n <= KARATSUBA_THRESHOLD {
        return schoolbook_mult(a, b);
    }

    // Pad to same length (required for correct splitting)
    let mut a_padded = Vec::with_capacity(n);
    let mut b_padded = Vec::with_capacity(n);
    a_padded.extend_from_slice(a);
    a_padded.resize(n, 0);
    b_padded.extend_from_slice(b);
    b_padded.resize(n, 0);

    let m = n / 2;

    // Split: A = A_low + x^m * A_high
    let a_low = &a_padded[..m];
    let a_high = &a_padded[m..];
    let b_low = &b_padded[..m];
    let b_high = &b_padded[m..];

    // Three recursive multiplications
    let z0 = karatsuba_mult(a_low, b_low);
    let z2 = karatsuba_mult(a_high, b_high);

    // z1 = (A_low + A_high) * (B_low + B_high) - z0 - z2
    // Pre-allocate sum vectors
    let sum_len = a_low.len().max(a_high.len());
    let mut a_sum = Vec::with_capacity(sum_len);
    let mut b_sum = Vec::with_capacity(sum_len);

    // Build sums: for overlapping indices, add; for non-overlapping, copy
    let overlap = a_low.len().min(a_high.len());
    for i in 0..overlap {
        a_sum.push(a_low[i] + a_high[i]);
    }
    // Extend with remaining elements (only one of these will be non-empty)
    if a_low.len() > a_high.len() {
        a_sum.extend_from_slice(&a_low[overlap..]);
    } else if a_high.len() > a_low.len() {
        a_sum.extend_from_slice(&a_high[overlap..]);
    }

    let overlap = b_low.len().min(b_high.len());
    for i in 0..overlap {
        b_sum.push(b_low[i] + b_high[i]);
    }
    if b_low.len() > b_high.len() {
        b_sum.extend_from_slice(&b_low[overlap..]);
    } else if b_high.len() > b_low.len() {
        b_sum.extend_from_slice(&b_high[overlap..]);
    }

    let z1_full = karatsuba_mult(&a_sum, &b_sum);

    // Combine: result = z0 + x^m * z1 + x^2m * z2
    let result_len = 2 * n - 1;
    let mut result = vec![0i32; result_len];

    // Add z0 at position 0
    for (i, &v) in z0.iter().enumerate() {
        result[i] += v;
    }

    // Add z2 at position 2m
    for (i, &v) in z2.iter().enumerate() {
        if i + 2 * m < result_len {
            result[i + 2 * m] += v;
        }
    }

    // Add z1 - z0 - z2 at position m
    for (i, &v) in z1_full.iter().enumerate() {
        if i + m < result_len {
            result[i + m] += v;
        }
    }
    for (i, &v) in z0.iter().enumerate() {
        if i + m < result_len {
            result[i + m] -= v;
        }
    }
    for (i, &v) in z2.iter().enumerate() {
        if i + m < result_len {
            result[i + m] -= v;
        }
    }

    result
}

// ============================================================================
// Number-Theoretic Transform (NTT)
// ============================================================================
//
// NTT provides O(n log n) polynomial multiplication using the convolution theorem.
// We use prime 998244353 = 119 * 2^23 + 1 which supports NTT sizes up to 2^23.

/// Barrett reduction constant: floor(2^64 / NTT_PRIME).
/// Used to approximate division by NTT_PRIME without 128-bit division.
const BARRETT_MU: u64 = ((1u128 << 64) / NTT_PRIME as u128) as u64;

/// Modular exponentiation: base^exp mod modulus
#[inline]
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

/// Modular multiplication using Barrett reduction.
/// Computes (a * b) mod NTT_PRIME without 128-bit division.
/// Assumes inputs are in [0, NTT_PRIME-1].
#[inline(always)]
fn mod_mul(a: u64, b: u64) -> u64 {
    let prod = a as u128 * b as u128;
    // Barrett reduction: q ≈ floor(prod / NTT_PRIME)
    // q = floor(prod * BARRETT_MU / 2^64)
    let q = ((prod * BARRETT_MU as u128) >> 64) as u64;
    // r = prod - q * NTT_PRIME (may be off by one NTT_PRIME)
    let mut r = (prod - q as u128 * NTT_PRIME as u128) as u64;
    // Single correction if needed
    if r >= NTT_PRIME {
        r -= NTT_PRIME;
    }
    r
}

/// Modular addition: (a + b) mod NTT_PRIME
#[inline(always)]
fn mod_add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= NTT_PRIME {
        sum - NTT_PRIME
    } else {
        sum
    }
}

/// Modular subtraction: (a - b) mod NTT_PRIME
#[inline(always)]
fn mod_sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { NTT_PRIME - b + a }
}

/// Compute twiddle factors for a specific butterfly stage.
/// Returns the primitive root of unity for this stage.
#[inline]
fn compute_stage_root(len: usize, inverse: bool) -> u64 {
    let order = NTT_PRIME - 1;
    let mut root = mod_pow(NTT_PRIMITIVE_ROOT, order / len as u64, NTT_PRIME);
    if inverse {
        root = mod_pow(root, NTT_PRIME - 2, NTT_PRIME);
    }
    root
}

/// Bit-reverse permutation for NTT.
#[inline]
fn bit_reverse(x: usize, log_n: usize) -> usize {
    x.reverse_bits() >> (usize::BITS as usize - log_n)
}

/// In-place forward NTT (Cooley-Tukey).
fn ntt_forward(a: &mut [u64]) {
    let n = a.len();
    let log_n = n.trailing_zeros() as usize;

    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }

    // Cooley-Tukey butterfly with on-the-fly twiddle computation
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let root = compute_stage_root(len, false);

        for start in (0..n).step_by(len) {
            let mut w = 1u64;
            for j in 0..half {
                let u = a[start + j];
                let v = mod_mul(a[start + j + half], w);
                a[start + j] = mod_add(u, v);
                a[start + j + half] = mod_sub(u, v);
                w = mod_mul(w, root);
            }
        }
        len *= 2;
    }
}

/// In-place inverse NTT (Cooley-Tukey).
fn ntt_inverse(a: &mut [u64]) {
    let n = a.len();
    let log_n = n.trailing_zeros() as usize;

    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }

    // Inverse butterfly with on-the-fly twiddle computation
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let root = compute_stage_root(len, true);

        for start in (0..n).step_by(len) {
            let mut w = 1u64;
            for j in 0..half {
                let u = a[start + j];
                let v = mod_mul(a[start + j + half], w);
                a[start + j] = mod_add(u, v);
                a[start + j + half] = mod_sub(u, v);
                w = mod_mul(w, root);
            }
        }
        len *= 2;
    }

    // Multiply by 1/n
    let n_inv = mod_pow(n as u64, NTT_PRIME - 2, NTT_PRIME);
    for x in a.iter_mut() {
        *x = mod_mul(*x, n_inv);
    }
}

/// NTT-based polynomial multiplication.
fn ntt_mult(a: &[i32], b: &[i32]) -> Vec<i32> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }

    let result_len = a.len() + b.len() - 1;

    // Convert to NTT domain (handling negative values)
    let mut a_ntt = vec![0u64; NTT_SIZE];
    let mut b_ntt = vec![0u64; NTT_SIZE];

    for (i, &coeff) in a.iter().enumerate() {
        a_ntt[i] = if coeff >= 0 {
            coeff as u64 % NTT_PRIME
        } else {
            (NTT_PRIME as i64 + (coeff as i64 % NTT_PRIME as i64)) as u64 % NTT_PRIME
        };
    }

    for (i, &coeff) in b.iter().enumerate() {
        b_ntt[i] = if coeff >= 0 {
            coeff as u64 % NTT_PRIME
        } else {
            (NTT_PRIME as i64 + (coeff as i64 % NTT_PRIME as i64)) as u64 % NTT_PRIME
        };
    }

    // Forward NTT
    ntt_forward(&mut a_ntt);
    ntt_forward(&mut b_ntt);

    // Pointwise multiplication with Barrett reduction
    for i in 0..NTT_SIZE {
        a_ntt[i] = mod_mul(a_ntt[i], b_ntt[i]);
    }

    // Inverse NTT
    ntt_inverse(&mut a_ntt);

    // Convert back to signed integers
    let mut result = vec![0i32; result_len];
    for (i, &v) in a_ntt.iter().enumerate().take(result_len) {
        result[i] = if v > NTT_PRIME / 2 {
            (v as i64 - NTT_PRIME as i64) as i32
        } else {
            v as i32
        };
    }

    result
}

// ============================================================================
// Modular Reduction
// ============================================================================

/// Reduce coefficient modulo q to centred range [-(q-1)/2, (q-1)/2].
#[inline(always)]
fn reduce_mod_q(x: i32) -> i16 {
    let mut r = x % Q;
    if r > Q_HALF {
        r -= Q;
    } else if r < -Q_HALF {
        r += Q;
    }
    r as i16
}

/// Reduce coefficient modulo 3 to range {-1, 0, 1}.
#[inline(always)]
fn reduce_mod_3(x: i32) -> i8 {
    match x.rem_euclid(3) {
        0 => 0,
        1 => 1,
        _ => -1,
    }
}

// ============================================================================
// Ring Reduction: x^P - x - 1
// ============================================================================
//
// After multiplication, we have a polynomial of degree up to 2P-2.
// We need to reduce modulo (x^P - x - 1).
//
// Since x^P ≡ x + 1 (mod x^P - x - 1), we substitute:
// - Coefficient at x^P adds to coefficients at x^1 and x^0
// - Coefficient at x^(P+1) adds to coefficients at x^2 and x^1
// - etc.

/// Reduce polynomial modulo (x^P - x - 1) with coefficients in Rq.
///
/// After multiplication, we have a polynomial of degree up to 2P-2.
/// Since x^P ≡ x + 1 (mod x^P - x - 1), each coefficient at x^(P+k)
/// contributes to both x^k and x^(k+1).
fn reduce_ring_rq(poly: &[i32]) -> [i16; P] {
    let mut result = [0i32; P];

    // Copy lower coefficients directly using slice copy
    let low_len = P.min(poly.len());
    result[..low_len].copy_from_slice(&poly[..low_len]);

    // Reduce higher coefficients: x^(P+k) ≡ x^(k+1) + x^k
    // For standard polynomial multiplication (degree 2P-2), k ranges 0 to P-2
    // so k+1 never reaches P and the wrap-around case doesn't trigger.
    if poly.len() > P {
        for (k, &v) in poly[P..].iter().enumerate() {
            result[k] += v;
            if k + 1 < P {
                result[k + 1] += v;
            } else {
                // Wrap-around: x^P = x + 1, so x^(k+1) where k+1 >= P
                // contributes to x^0, x^1, and x^(k+1-P)
                result[0] += v;
                result[1] += v;
                result[k + 1 - P] += v;
            }
        }
    }

    // Final reduction modulo q - use array::map for cleaner code
    let mut final_result = [0i16; P];
    for i in 0..P {
        final_result[i] = reduce_mod_q(result[i]);
    }
    final_result
}

/// Reduce polynomial modulo (x^P - x - 1) with coefficients in R3.
fn reduce_ring_r3(poly: &[i32]) -> [i8; P] {
    let mut result = [0i32; P];

    // Copy lower coefficients directly using slice copy
    let low_len = P.min(poly.len());
    result[..low_len].copy_from_slice(&poly[..low_len]);

    // Reduce higher coefficients: x^(P+k) ≡ x^(k+1) + x^k
    if poly.len() > P {
        for (k, &v) in poly[P..].iter().enumerate() {
            result[k] += v;
            if k + 1 < P {
                result[k + 1] += v;
            } else {
                result[0] += v;
                result[1] += v;
                result[k + 1 - P] += v;
            }
        }
    }

    // Final reduction modulo 3
    let mut final_result = [0i8; P];
    for i in 0..P {
        final_result[i] = reduce_mod_3(result[i]);
    }
    final_result
}

// ============================================================================
// Public API
// ============================================================================

/// Multiply two Rq polynomials using Karatsuba (O(n^1.58)).
///
/// Both inputs are in centred representation: coefficients in [-(q-1)/2, (q-1)/2].
/// Output is reduced modulo (x^P - x - 1) and modulo q.
///
/// Note: Karatsuba outperforms NTT for n=761 due to NTT's higher constant factors
/// (zero-padding to 2048, 128-bit modular arithmetic).
pub fn rq_mult_rq(a: &[i16; P], b: &[i16; P]) -> [i16; P] {
    // Convert to i32 for intermediate calculations
    let a_i32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b_i32: Vec<i32> = b.iter().map(|&x| x as i32).collect();

    // Karatsuba multiplication (faster than NTT for this size in pure Rust)
    let product = karatsuba_mult(&a_i32, &b_i32);

    // Reduce modulo ring and modulo q
    reduce_ring_rq(&product)
}

/// Multiply Rq polynomial by R3 polynomial using Karatsuba (O(n^1.58)).
///
/// This is the common case in sntrup761: h * r where h ∈ Rq, r ∈ R3.
/// Since R3 coefficients are small (-1, 0, 1), this is efficient.
pub fn rq_mult_r3(a: &[i16; P], b: &[i8; P]) -> [i16; P] {
    let a_i32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b_i32: Vec<i32> = b.iter().map(|&x| x as i32).collect();

    // Karatsuba multiplication
    let product = karatsuba_mult(&a_i32, &b_i32);
    reduce_ring_rq(&product)
}

/// Multiply two R3 polynomials using Karatsuba (O(n^1.58)).
///
/// Both inputs have coefficients in {-1, 0, 1}.
/// Output is reduced modulo (x^P - x - 1) and modulo 3.
pub fn r3_mult_r3(a: &[i8; P], b: &[i8; P]) -> [i8; P] {
    let a_i32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b_i32: Vec<i32> = b.iter().map(|&x| x as i32).collect();

    // Karatsuba multiplication
    let product = karatsuba_mult(&a_i32, &b_i32);
    reduce_ring_r3(&product)
}

/// Multiply Rq by R3 using NTT (for benchmarking comparison).
#[allow(dead_code)]
pub fn rq_mult_r3_ntt(a: &[i16; P], b: &[i8; P]) -> [i16; P] {
    let a_i32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b_i32: Vec<i32> = b.iter().map(|&x| x as i32).collect();
    let product = ntt_mult(&a_i32, &b_i32);
    reduce_ring_rq(&product)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schoolbook_mult() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5];
        let result = schoolbook_mult(&a, &b);
        // (1 + 2x + 3x²)(4 + 5x) = 4 + 5x + 8x + 10x² + 12x² + 15x³
        //                        = 4 + 13x + 22x² + 15x³
        assert_eq!(result, vec![4, 13, 22, 15]);
    }

    #[test]
    fn test_karatsuba_matches_schoolbook() {
        // Test with polynomial sizes around the threshold
        for size in [16, 32, 64, 128] {
            let a: Vec<i32> = (0..size).map(|i| (i % 7) as i32 - 3).collect();
            let b: Vec<i32> = (0..size).map(|i| ((i * 3) % 11) as i32 - 5).collect();

            let schoolbook = schoolbook_mult(&a, &b);
            let karatsuba = karatsuba_mult(&a, &b);

            assert_eq!(schoolbook, karatsuba, "Mismatch at size {}", size);
        }
    }

    #[test]
    fn test_reduce_mod_q() {
        assert_eq!(reduce_mod_q(0), 0);
        assert_eq!(reduce_mod_q(100), 100);
        assert_eq!(reduce_mod_q(-100), -100);
        assert_eq!(reduce_mod_q(Q), 0);
        assert_eq!(reduce_mod_q(Q + 1), 1);
        assert_eq!(reduce_mod_q(-Q), 0);
        assert_eq!(reduce_mod_q(Q_HALF + 1), (Q_HALF + 1 - Q) as i16);
    }

    #[test]
    fn test_reduce_mod_3() {
        assert_eq!(reduce_mod_3(0), 0);
        assert_eq!(reduce_mod_3(1), 1);
        assert_eq!(reduce_mod_3(2), -1);
        assert_eq!(reduce_mod_3(3), 0);
        assert_eq!(reduce_mod_3(-1), -1);
        assert_eq!(reduce_mod_3(-2), 1);
    }

    #[test]
    fn test_rq_mult_r3_basic() {
        // Simple test: multiply by 1 (identity in R3)
        let mut a = [0i16; P];
        a[0] = 1; // a = 1

        let mut b = [0i8; P];
        b[0] = 1; // b = 1

        let result = rq_mult_r3(&a, &b);
        assert_eq!(result[0], 1);
        for &c in &result[1..] {
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn test_r3_mult_identity() {
        // Multiply by identity (1)
        let mut a = [0i8; P];
        a[0] = 1;
        a[1] = -1;
        a[2] = 1;

        let mut identity = [0i8; P];
        identity[0] = 1;

        let result = r3_mult_r3(&a, &identity);
        assert_eq!(result[0], 1);
        assert_eq!(result[1], -1);
        assert_eq!(result[2], 1);
    }

    #[test]
    fn test_ntt_matches_schoolbook() {
        // Small test to verify NTT correctness
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7];

        let schoolbook = schoolbook_mult(&a, &b);
        let ntt = ntt_mult(&a, &b);

        assert_eq!(schoolbook.len(), ntt.len());
        for (s, n) in schoolbook.iter().zip(ntt.iter()) {
            assert_eq!(*s, *n, "Mismatch: schoolbook={}, ntt={}", s, n);
        }
    }

    #[test]
    fn test_ntt_matches_karatsuba_larger() {
        // Larger test with random-ish values
        let a: Vec<i32> = (0..100).map(|i| (i % 17) as i32 - 8).collect();
        let b: Vec<i32> = (0..100).map(|i| ((i * 3) % 13) as i32 - 6).collect();

        let karatsuba = karatsuba_mult(&a, &b);
        let ntt = ntt_mult(&a, &b);

        assert_eq!(karatsuba.len(), ntt.len());
        for (k, n) in karatsuba.iter().zip(ntt.iter()) {
            assert_eq!(*k, *n, "Mismatch: karatsuba={}, ntt={}", k, n);
        }
    }

    #[test]
    fn test_ntt_full_size() {
        // Test with actual sntrup761 polynomial sizes
        let mut a = [0i32; P];
        let mut b = [0i32; P];

        // Fill with small values
        for i in 0..P {
            a[i] = (i % 5) as i32 - 2;
            b[i] = ((i * 7) % 5) as i32 - 2;
        }

        let karatsuba = karatsuba_mult(&a, &b);
        let ntt = ntt_mult(&a, &b);

        assert_eq!(karatsuba.len(), ntt.len());
        for (k, n) in karatsuba.iter().zip(ntt.iter()) {
            assert_eq!(*k, *n);
        }
    }

    #[test]
    fn test_ntt_rq_mult_r3_matches_karatsuba() {
        // Verify NTT-based rq_mult_r3 matches Karatsuba version
        let mut a = [0i16; P];
        let mut b = [0i8; P];

        // Fill with representative values
        for i in 0..P {
            a[i] = ((i as i32 * 17) % 1000 - 500) as i16;
            b[i] = (i % 3) as i8 - 1; // -1, 0, or 1
        }

        let karatsuba_result = rq_mult_r3(&a, &b);
        let ntt_result = rq_mult_r3_ntt(&a, &b);

        for i in 0..P {
            assert_eq!(
                ntt_result[i], karatsuba_result[i],
                "Mismatch at index {}: ntt={}, karatsuba={}",
                i, ntt_result[i], karatsuba_result[i]
            );
        }
    }

    // =========================================================================
    // Edge Case Tests for Karatsuba Optimisation
    // =========================================================================
    //
    // These tests verify the optimised Karatsuba implementation handles
    // boundary conditions correctly, particularly around:
    // - Empty and single-element polynomials
    // - Threshold boundary (KARATSUBA_THRESHOLD = 32)
    // - Odd vs even length polynomials
    // - Unequal length operands
    // - Coefficient overflow scenarios

    /// Test multiplication with empty polynomials
    #[test]
    fn karatsuba_empty_polynomials() {
        let empty: Vec<i32> = vec![];
        let non_empty = vec![1, 2, 3];

        let expected_empty: Vec<i32> = vec![];
        assert_eq!(karatsuba_mult(&empty, &non_empty), expected_empty);
        assert_eq!(karatsuba_mult(&non_empty, &empty), expected_empty);
        assert_eq!(karatsuba_mult(&empty, &empty), expected_empty);
    }

    /// Test multiplication with single coefficient
    #[test]
    fn karatsuba_single_coefficient() {
        let a = vec![7];
        let b = vec![11];
        assert_eq!(karatsuba_mult(&a, &b), vec![77]);

        // Single times multi
        let c = vec![2, 3, 4];
        assert_eq!(karatsuba_mult(&a, &c), vec![14, 21, 28]);
    }

    /// Test at the Karatsuba threshold boundary (32)
    /// This is where the algorithm switches between schoolbook and Karatsuba
    #[test]
    fn karatsuba_threshold_boundary() {
        // Just below threshold - uses schoolbook
        let a31: Vec<i32> = (0..31).map(|i| (i % 5) as i32 - 2).collect();
        let b31: Vec<i32> = (0..31).map(|i| ((i * 3) % 7) as i32 - 3).collect();

        // At threshold - first Karatsuba level
        let a32: Vec<i32> = (0..32).map(|i| (i % 5) as i32 - 2).collect();
        let b32: Vec<i32> = (0..32).map(|i| ((i * 3) % 7) as i32 - 3).collect();

        // Just above threshold
        let a33: Vec<i32> = (0..33).map(|i| (i % 5) as i32 - 2).collect();
        let b33: Vec<i32> = (0..33).map(|i| ((i * 3) % 7) as i32 - 3).collect();

        // All should match schoolbook
        assert_eq!(
            karatsuba_mult(&a31, &b31),
            schoolbook_mult(&a31, &b31),
            "Failed at size 31"
        );
        assert_eq!(
            karatsuba_mult(&a32, &b32),
            schoolbook_mult(&a32, &b32),
            "Failed at size 32"
        );
        assert_eq!(
            karatsuba_mult(&a33, &b33),
            schoolbook_mult(&a33, &b33),
            "Failed at size 33"
        );
    }

    /// Test with odd-length polynomials (exercises unequal split handling)
    #[test]
    fn karatsuba_odd_lengths() {
        for size in [33, 47, 63, 65, 127, 255, 513] {
            let a: Vec<i32> = (0..size).map(|i| (i % 11) as i32 - 5).collect();
            let b: Vec<i32> = (0..size).map(|i| ((i * 7) % 13) as i32 - 6).collect();

            let karatsuba = karatsuba_mult(&a, &b);
            let schoolbook = schoolbook_mult(&a, &b);

            assert_eq!(karatsuba, schoolbook, "Mismatch at odd size {}", size);
        }
    }

    /// Test with unequal length operands
    #[test]
    fn karatsuba_unequal_lengths() {
        // Helper to trim trailing zeros for comparison
        // (Karatsuba may pad results due to power-of-2 sizing)
        fn trim_trailing_zeros(v: &[i32]) -> &[i32] {
            let len = v.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
            &v[..len]
        }

        let test_cases = [
            (16, 64),   // Small vs large
            (33, 47),   // Both odd
            (32, 33),   // Threshold boundary
            (100, 761), // Realistic sntrup761 case
            (1, 100),   // Single vs many
        ];

        for (len_a, len_b) in test_cases {
            let a: Vec<i32> = (0..len_a).map(|i| (i % 7) as i32 - 3).collect();
            let b: Vec<i32> = (0..len_b).map(|i| ((i * 5) % 9) as i32 - 4).collect();

            let karatsuba = karatsuba_mult(&a, &b);
            let schoolbook = schoolbook_mult(&a, &b);

            // Karatsuba may have trailing zeros due to padding; compare meaningful parts
            assert_eq!(
                trim_trailing_zeros(&karatsuba),
                trim_trailing_zeros(&schoolbook),
                "Mismatch for lengths {} x {}",
                len_a,
                len_b
            );

            // Also test reversed order
            let karatsuba_rev = karatsuba_mult(&b, &a);
            let schoolbook_rev = schoolbook_mult(&b, &a);

            assert_eq!(
                trim_trailing_zeros(&karatsuba_rev),
                trim_trailing_zeros(&schoolbook_rev),
                "Mismatch for reversed lengths {} x {}",
                len_b,
                len_a
            );
        }
    }

    /// Test with all-zero polynomials
    #[test]
    fn karatsuba_zero_polynomial() {
        let zero = vec![0i32; 100];
        let nonzero: Vec<i32> = (0..100).map(|i| i as i32).collect();

        let result = karatsuba_mult(&zero, &nonzero);
        assert!(
            result.iter().all(|&x| x == 0),
            "Zero times anything should be zero"
        );
    }

    /// Test with larger coefficient values (within sntrup761 range)
    /// sntrup761 uses q = 4591, so coefficients are in [-2295, 2295]
    #[test]
    fn karatsuba_large_coefficients() {
        // Use values near sntrup761 bounds: q/2 ~ 2295
        // For 64 terms: max accumulation = 2295^2 * 64 ~ 337M << i32::MAX (2.1B)
        let max_coeff = 2000i32;

        let a: Vec<i32> = (0..64)
            .map(|i| if i % 2 == 0 { max_coeff } else { -max_coeff })
            .collect();
        let b: Vec<i32> = (0..64)
            .map(|i| {
                if i % 3 == 0 {
                    max_coeff
                } else {
                    -max_coeff / 2
                }
            })
            .collect();

        let karatsuba = karatsuba_mult(&a, &b);
        let schoolbook = schoolbook_mult(&a, &b);

        assert_eq!(karatsuba, schoolbook, "Large coefficient mismatch");

        // Verify no unexpected zeros (sanity check)
        assert!(
            karatsuba.iter().any(|&x| x != 0),
            "Result should be non-zero"
        );
    }

    // =========================================================================
    // Edge Case Tests for Ring Reduction Optimisation
    // =========================================================================
    //
    // These tests verify the optimised ring reduction handles:
    // - Short inputs (< P)
    // - Exactly P length inputs
    // - Standard 2P-1 length inputs
    // - Coefficient accumulation edge cases

    /// Test ring reduction with short input (< P)
    #[test]
    fn ring_reduce_short_input() {
        let short = vec![1, 2, 3, 4, 5];
        let result = reduce_ring_rq(&short);

        // Should just copy with zeros
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 2);
        assert_eq!(result[4], 5);
        for i in 5..P {
            assert_eq!(result[i], 0, "Position {} should be zero", i);
        }
    }

    /// Test ring reduction with exactly P coefficients
    #[test]
    fn ring_reduce_exact_p() {
        let mut input = vec![0i32; P];
        for i in 0..P {
            input[i] = (i % 100) as i32;
        }

        let result = reduce_ring_rq(&input);

        // Should be identity (just mod q reduction)
        for i in 0..P {
            assert_eq!(result[i], (i % 100) as i16, "Mismatch at {}", i);
        }
    }

    /// Test ring reduction with standard 2P-1 length (normal multiplication result)
    #[test]
    fn ring_reduce_standard_length() {
        // Create input where we know the expected output
        // Use x^P which should reduce to x + 1
        let mut input = vec![0i32; 2 * P - 1];
        input[P] = 1; // x^P term

        let result = reduce_ring_rq(&input);

        // x^P ≡ x + 1 (mod x^P - x - 1)
        assert_eq!(result[0], 1, "Constant term should be 1");
        assert_eq!(result[1], 1, "Linear term should be 1");
        for i in 2..P {
            assert_eq!(result[i], 0, "Higher terms should be 0");
        }
    }

    /// Test ring reduction: x^(P+k) ≡ x^(k+1) + x^k
    #[test]
    fn ring_reduce_higher_powers() {
        for k in [0, 1, 10, 100, P / 2, P - 2] {
            let mut input = vec![0i32; P + k + 1];
            input[P + k] = 1; // x^(P+k) term

            let result = reduce_ring_rq(&input);

            // x^(P+k) ≡ x^(k+1) + x^k
            assert_eq!(result[k], 1, "x^{} coefficient wrong for k={}", k, k);
            if k + 1 < P {
                assert_eq!(
                    result[k + 1],
                    1,
                    "x^{} coefficient wrong for k={}",
                    k + 1,
                    k
                );
            }
        }
    }

    /// Test ring reduction with coefficients that need mod q reduction
    #[test]
    fn ring_reduce_needs_mod_q() {
        let mut input = vec![0i32; P];
        input[0] = Q + 100; // Should reduce to 100
        input[1] = -Q + 50; // Should reduce to 50
        input[2] = 2 * Q; // Should reduce to 0
        input[3] = Q_HALF + 100; // Should reduce to centred representation

        let result = reduce_ring_rq(&input);

        assert_eq!(result[0], 100);
        assert_eq!(result[1], 50);
        assert_eq!(result[2], 0);
        // Q_HALF + 100 > Q_HALF, so it becomes (Q_HALF + 100 - Q)
        let expected = (Q_HALF + 100 - Q) as i16;
        assert_eq!(result[3], expected);
    }

    /// Test R3 ring reduction
    #[test]
    fn ring_reduce_r3_basic() {
        let mut input = vec![0i32; P];
        input[0] = 4; // Should reduce to 1 (mod 3)
        input[1] = 5; // Should reduce to -1 (mod 3)
        input[2] = 6; // Should reduce to 0 (mod 3)
        input[3] = -1; // Should stay -1

        let result = reduce_ring_r3(&input);

        assert_eq!(result[0], 1);
        assert_eq!(result[1], -1);
        assert_eq!(result[2], 0);
        assert_eq!(result[3], -1);
    }

    /// Regression test: verify Karatsuba + reduction matches reference
    #[test]
    fn karatsuba_reduction_end_to_end() {
        // Use the public API functions
        let mut a = [0i16; P];
        let mut b = [0i8; P];

        // Create polynomials with known structure
        a[0] = 1;
        a[1] = 2;
        a[P - 1] = 3;

        b[0] = 1;
        b[1] = -1;
        b[P - 1] = 1;

        let result = rq_mult_r3(&a, &b);

        // Verify using NTT reference
        let ntt_result = rq_mult_r3_ntt(&a, &b);

        for i in 0..P {
            assert_eq!(
                result[i], ntt_result[i],
                "Karatsuba/NTT mismatch at index {}",
                i
            );
        }
    }

    /// Test full-size P=761 polynomial multiplication (the actual sntrup761 size)
    #[test]
    fn karatsuba_full_sntrup761_size() {
        let mut a = [0i16; P];
        let mut b = [0i8; P];

        // Fill with varied values
        for i in 0..P {
            a[i] = ((i * 17 + 31) % 2000) as i16 - 1000;
            b[i] = ((i * 7 + 13) % 3) as i8 - 1;
        }

        // This should complete without panic
        let result = rq_mult_r3(&a, &b);

        // Verify all coefficients are in valid range
        for (i, &c) in result.iter().enumerate() {
            assert!(
                c >= -Q_HALF as i16 && c <= Q_HALF as i16,
                "Coefficient {} at index {} out of range",
                c,
                i
            );
        }
    }
}
