//! sntrup761 wire format encoding/decoding.
//!
//! This module implements the standard sntrup761 encoding as specified
//! in the NTRU Prime submission and used by PQClean. The encoding uses
//! a hierarchical base conversion scheme to achieve compact representation.
//!
//! # Wire Format Sizes
//!
//! - Public key (Rq): 1,158 bytes
//! - Secret key: 1,763 bytes (f + ginv + pk + rho + hash)
//! - Ciphertext (Rounded): 1,007 bytes + 32 bytes confirmation = 1,039 bytes
//! - Small polynomial (R3): 191 bytes
//!
//! # Parameters
//!
//! - p = 761 (polynomial degree)
//! - q = 4591 (modulus for Rq)
//! - w = 286 (weight for short polynomials)

/// Polynomial degree for sntrup761.
pub const P: usize = 761;

/// Modulus for Rq polynomials.
pub const Q: i16 = 4591;

/// Half of Q, used for centering.
pub const Q12: i16 = (Q - 1) / 2; // 2295

/// Encoded size of a Small (R3) polynomial.
pub const SMALL_BYTES: usize = 191; // ceil(761/4)

/// Encoded size of an Rq polynomial (public key).
pub const RQ_BYTES: usize = 1158;

/// Encoded size of a Rounded polynomial (ciphertext body).
pub const ROUNDED_BYTES: usize = 1007;

/// Confirmation hash size.
pub const CONFIRM_BYTES: usize = 32;

/// Total ciphertext size.
pub const CIPHERTEXT_BYTES: usize = ROUNDED_BYTES + CONFIRM_BYTES; // 1039

/// Encoded size of secret key.
pub const SECRET_KEY_BYTES: usize = 2 * SMALL_BYTES + RQ_BYTES + SMALL_BYTES + 32; // 1763

// ============================================================================
// R3 / Small Polynomial Encoding (191 bytes)
// ============================================================================

/// Encodes a Small polynomial (761 coefficients in {-1, 0, 1}) to 191 bytes.
///
/// Each coefficient is mapped: -1 → 0, 0 → 1, 1 → 2, then packed 4 per byte.
pub fn small_encode(coeffs: &[i8; P]) -> [u8; SMALL_BYTES] {
    let mut out = [0u8; SMALL_BYTES];

    // Pack 4 coefficients per byte for the first 760 coefficients
    for i in 0..(P / 4) {
        let mut x = (coeffs[4 * i] + 1) as u8;
        x += ((coeffs[4 * i + 1] + 1) as u8) << 2;
        x += ((coeffs[4 * i + 2] + 1) as u8) << 4;
        x += ((coeffs[4 * i + 3] + 1) as u8) << 6;
        out[i] = x;
    }

    // Handle the last coefficient (761st)
    out[P / 4] = (coeffs[P - 1] + 1) as u8;

    out
}

/// Decodes 191 bytes to a Small polynomial (761 coefficients in {-1, 0, 1}).
pub fn small_decode(bytes: &[u8; SMALL_BYTES]) -> [i8; P] {
    let mut coeffs = [0i8; P];

    // Unpack 4 coefficients per byte for the first 760 coefficients
    for i in 0..(P / 4) {
        let x = bytes[i];
        coeffs[4 * i] = ((x & 3) as i8) - 1;
        coeffs[4 * i + 1] = (((x >> 2) & 3) as i8) - 1;
        coeffs[4 * i + 2] = (((x >> 4) & 3) as i8) - 1;
        coeffs[4 * i + 3] = (((x >> 6) & 3) as i8) - 1;
    }

    // Handle the last coefficient (761st)
    coeffs[P - 1] = ((bytes[P / 4] & 3) as i8) - 1;

    coeffs
}

// ============================================================================
// Rq Polynomial Encoding (1158 bytes) - Public Key
// ============================================================================

/// Constant-time division for encoding.
///
/// Returns (quotient, remainder) of x / m where m < 16384.
///
/// # Constant-Time Properties
///
/// This function is designed to execute in constant time regardless of input values:
/// - Uses a fixed number of arithmetic operations (no branches on secret data)
/// - Uses arithmetic masking instead of conditional branches for the final correction
/// - The mask computation `(x_minus_m >> 31).wrapping_neg()` produces all-1s if x < m,
///   all-0s otherwise, avoiding timing leaks
///
/// # Constraints
///
/// - Divisor `m` must be less than 16384 (14 bits) for the approximation to work correctly
/// - Dividend `x` must fit in u32
///
/// # Algorithm
///
/// Uses Newton-Raphson style iterative approximation:
/// 1. Compute v = floor(2^31 / m) as the reciprocal approximation
/// 2. First approximation: q ≈ (x * v) >> 31
/// 3. Refine with a second iteration
/// 4. Apply constant-time correction if remainder >= m
#[inline]
fn divmod_u14(x: u32, m: u16) -> (u32, u16) {
    // v = floor(2^31 / m) - reciprocal approximation
    let v: u32 = 0x8000_0000 / (m as u32);

    let mut q: u32 = 0;

    // First approximation: q ≈ (x * v) >> 31
    let qpart = ((x as u64 * v as u64) >> 31) as u32;
    let mut x = x - qpart * (m as u32);
    q += qpart;

    // Second approximation (refine for better precision)
    let qpart = ((x as u64 * v as u64) >> 31) as u32;
    x -= qpart * (m as u32);
    q += qpart;

    // Final correction: if x >= m, subtract m and increment q
    // Done with arithmetic masking to avoid branches
    let x_minus_m = x.wrapping_sub(m as u32);
    q += 1;

    // Constant-time selection: mask is all-1s if x < m (correction needed), all-0s otherwise
    let mask = (x_minus_m >> 31).wrapping_neg();
    let x = x_minus_m.wrapping_add(mask & (m as u32));
    let q = q.wrapping_add(mask);

    (q, x as u16)
}

/// Encodes an Rq polynomial (761 coefficients in [-2295, 2295]) to 1158 bytes.
///
/// Uses hierarchical base conversion to pack coefficients efficiently.
///
/// # Encoding Structure
///
/// The sntrup761 encoding uses a multi-stage hierarchical base conversion scheme.
/// At each stage, pairs of values are combined and partially written to output.
/// The moduli at each stage are chosen to minimise output size while maintaining
/// bijectivity.
///
/// ## Stage Moduli (from NTRU Prime specification)
///
/// | Stage | Input Values | Output Values | Modulus | Bytes Written |
/// |-------|--------------|---------------|---------|---------------|
/// | 1     | 761 coeffs   | 381 values    | Q=4591  | 760 bytes     |
/// | 2     | 381 values   | 191 values    | 322     | 190 bytes     |
/// | 3     | 191 values   | 96 values     | 406     | 95 bytes      |
/// | 4     | 96 values    | 48 values     | 644     | 48 bytes      |
/// | 5     | 48 values    | 24 values     | 1621    | 24 bytes      |
/// | 6     | 24 values    | 12 values     | 10265   | 23 bytes      |
/// | 7     | 12 values    | 6 values      | 1608    | 6 bytes       |
/// | 8     | 6 values     | 3 values      | 10101   | 5 bytes       |
/// | 9     | 3 values     | 2 values      | 1557    | 1 byte        |
/// | 10    | 2 values     | 1 value       | 9470    | 4 bytes       |
///
/// Total: 1158 bytes
///
/// The moduli satisfy M\[i+1\] ≈ ceil(sqrt(M\[i\]^2)) to achieve near-optimal compression.
pub fn rq_encode(coeffs: &[i16; P]) -> [u8; RQ_BYTES] {
    let mut out = [0u8; RQ_BYTES];
    let mut out_idx = 0;
    let mut r = [0u16; 381];

    // Stage 1: Process pairs of coefficients (760 coefficients → 380 pairs + 1)
    for i in 0..380 {
        let r0 = ((coeffs[2 * i] + Q12) & 16383) as u16;
        let r1 = ((coeffs[2 * i + 1] + Q12) & 16383) as u16;
        let r2 = r0 as u32 + r1 as u32 * Q as u32;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }
    r[380] = ((coeffs[760] + Q12) & 16383) as u16;

    // Stage 2: 381 values → 191 values (mod 322)
    for i in 0..190 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 322;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    r[190] = r[380];

    // Stage 3: 191 values → 96 values (mod 406)
    for i in 0..95 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 406;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    r[95] = r[190];

    // Stage 4: 96 values → 48 values (mod 644)
    for i in 0..48 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 644;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }

    // Stage 5: 48 values → 24 values (mod 1621)
    for i in 0..23 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 1621;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    // Special handling for last pair
    let r2 = r[46] as u32 + r[47] as u32 * 1621;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    out[out_idx] = (r2 >> 8) as u8;
    out_idx += 1;
    r[23] = (r2 >> 16) as u16;

    // Stage 6: 24 values → 12 values (mod 10265)
    for i in 0..11 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 10265;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }
    let r2 = r[22] as u32 + r[23] as u32 * 10265;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    r[11] = (r2 >> 8) as u16;

    // Stage 7: 12 values → 6 values (mod 1608)
    for i in 0..5 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 1608;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    let r2 = r[10] as u32 + r[11] as u32 * 1608;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    out[out_idx] = (r2 >> 8) as u8;
    out_idx += 1;
    r[5] = (r2 >> 16) as u16;

    // Stage 8: 6 values → 3 values (mod 10101)
    for i in 0..2 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 10101;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }
    let r2 = r[4] as u32 + r[5] as u32 * 10101;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    r[2] = (r2 >> 8) as u16;

    // Stage 9: 3 values → 2 values (mod 1557)
    let r2 = r[0] as u32 + r[1] as u32 * 1557;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    r[0] = (r2 >> 8) as u16;
    r[1] = r[2];

    // Stage 10: 2 values → 1 value (mod 9470)
    let r2 = r[0] as u32 + r[1] as u32 * 9470;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    out[out_idx] = (r2 >> 8) as u8;
    out_idx += 1;
    r[0] = (r2 >> 16) as u16;

    // Final: output remaining
    out[out_idx] = r[0] as u8;
    out_idx += 1;
    out[out_idx] = (r[0] >> 8) as u8;

    out
}

/// Decodes 1158 bytes to an Rq polynomial (761 coefficients in [-2295, 2295]).
///
/// This reverses the hierarchical base conversion used in [`rq_encode`].
/// See that function's documentation for details on the encoding structure.
pub fn rq_decode(bytes: &[u8; RQ_BYTES]) -> [i16; P] {
    let mut coeffs = [0i16; P];
    let mut s_idx = RQ_BYTES;

    // Working arrays for each stage
    let mut r10 = [0u16; 1];
    let mut r9 = [0u16; 2];
    let mut r8 = [0u16; 3];
    let mut r7 = [0u16; 6];
    let mut r6 = [0u16; 12];
    let mut r5 = [0u16; 24];
    let mut r4 = [0u16; 48];
    let mut r3 = [0u16; 96];
    let mut r2 = [0u16; 191];
    let mut r1 = [0u16; 381];

    // Stage 10 → 9: Read final 2 bytes
    s_idx -= 1;
    let mut r = bytes[s_idx] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    r10[0] = (r % 1608) as u16; // Clamp for invalid inputs

    // Stage 9 → 8
    let mut r = r10[0] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 9470);
    r9[0] = rem;
    r9[1] = (q % 11127) as u16;

    // Stage 8 → 7
    r8[2] = r9[1];
    let mut r = r9[0] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 1557);
    r8[0] = rem;
    r8[1] = (q % 1557) as u16;

    // Stage 7 → 6
    let mut r = r8[2] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 10101);
    r7[4] = rem;
    r7[5] = (q % 282) as u16;
    for i in (0..=1).rev() {
        let mut r = r8[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 10101);
        r7[2 * i] = rem;
        r7[2 * i + 1] = (q % 10101) as u16;
    }

    // Stage 6 → 5
    let mut r = r7[5] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 1608);
    r6[10] = rem;
    r6[11] = (q % 11468) as u16;
    for i in (0..=4).rev() {
        let mut r = r7[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 1608);
        r6[2 * i] = rem;
        r6[2 * i + 1] = (q % 1608) as u16;
    }

    // Stage 5 → 4
    let mut r = r6[11] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 10265);
    r5[22] = rem;
    r5[23] = (q % 286) as u16;
    for i in (0..=10).rev() {
        let mut r = r6[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 10265);
        r5[2 * i] = rem;
        r5[2 * i + 1] = (q % 10265) as u16;
    }

    // Stage 4 → 3
    let mut r = r5[23] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 1621);
    r4[46] = rem;
    r4[47] = (q % 11550) as u16;
    for i in (0..=22).rev() {
        let mut r = r5[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 1621);
        r4[2 * i] = rem;
        r4[2 * i + 1] = (q % 1621) as u16;
    }

    // Stage 3 → 2
    let mut r = r4[47] as u32;
    s_idx -= 1;
    r = (r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(r, 644);
    r3[94] = rem;
    r3[95] = (q % Q as u32) as u16;
    for i in (0..=46).rev() {
        let mut r = r4[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 644);
        r3[2 * i] = rem;
        r3[2 * i + 1] = (q % 644) as u16;
    }

    // Stage 2 → 1
    r2[190] = r3[95];
    for i in (0..=94).rev() {
        let mut r = r3[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 406);
        r2[2 * i] = rem;
        r2[2 * i + 1] = (q % 406) as u16;
    }

    // Stage 1 → coefficients
    r1[380] = r2[190];
    for i in (0..=189).rev() {
        let mut r = r2[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, 322);
        r1[2 * i] = rem;
        r1[2 * i + 1] = (q % 322) as u16;
    }

    // Final: unpack to coefficients
    coeffs[760] = r1[380] as i16 - Q12;
    for i in (0..=379).rev() {
        let mut r = r1[i] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        r = (r << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(r, Q as u16);
        coeffs[2 * i] = rem as i16 - Q12;
        coeffs[2 * i + 1] = (q % Q as u32) as i16 - Q12;
    }

    coeffs
}

// ============================================================================
// Rounded Polynomial Encoding (1007 bytes) - Ciphertext
// ============================================================================

/// Encodes a Rounded polynomial for ciphertext (1007 bytes).
///
/// First rounds each coefficient by dividing by 3, then encodes mod 1531.
///
/// # Encoding Structure
///
/// Similar to Rq encoding but uses different moduli optimised for the
/// reduced range after rounding (values in [0, 1530] instead of [0, 4590]).
///
/// ## Stage Moduli (Rounded variant)
///
/// | Stage | Input Values | Output Values | Modulus | Bytes Written |
/// |-------|--------------|---------------|---------|---------------|
/// | 1     | 761 coeffs   | 381 values    | 1531    | 380 bytes     |
/// | 2     | 381 values   | 191 values    | 9157    | 380 bytes     |
/// | 3     | 191 values   | 96 values     | 1280    | 95 bytes      |
/// | 4     | 96 values    | 48 values     | 6400    | 96 bytes      |
/// | 5     | 48 values    | 24 values     | 625     | 24 bytes      |
/// | 6     | 24 values    | 12 values     | 1526    | 12 bytes      |
/// | 7     | 12 values    | 6 values      | 9097    | 12 bytes      |
/// | 8     | 6 values     | 3 values      | 1263    | 3 bytes       |
/// | 9     | 3 values     | 2 values      | 6232    | 3 bytes       |
/// | 10    | 2 values     | 1 value       | 593     | 2 bytes       |
///
/// Total: 1007 bytes
pub fn rounded_encode(coeffs: &[i16; P]) -> [u8; ROUNDED_BYTES] {
    // First, round the coefficients (divide by 3)
    let mut rounded = [0i16; P];
    for i in 0..P {
        // Round: 3 * ((10923 * a + 16384) >> 15)
        // This computes approximately round(a / 3) * 3
        let a = coeffs[i] as i32;
        rounded[i] = (3 * ((10923 * a + 16384) >> 15)) as i16;
    }

    // Now encode using the 761x1531 encoding
    rounded_encode_raw(&rounded)
}

/// Encodes pre-rounded coefficients (internal, 1007 bytes).
fn rounded_encode_raw(coeffs: &[i16; P]) -> [u8; ROUNDED_BYTES] {
    let mut out = [0u8; ROUNDED_BYTES];
    let mut out_idx = 0;
    let mut r = [0u16; 381];

    // Stage 1: Process pairs, scaling by 10923/2^15 ≈ 1/3
    for i in 0..380 {
        let r0 = ((((coeffs[2 * i] as i32 + Q12 as i32) & 16383) * 10923) >> 15) as u16;
        let r1 = ((((coeffs[2 * i + 1] as i32 + Q12 as i32) & 16383) * 10923) >> 15) as u16;
        let r2 = r0 as u32 + r1 as u32 * 1531;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    r[380] = ((((coeffs[760] as i32 + Q12 as i32) & 16383) * 10923) >> 15) as u16;

    // Stage 2: 381 values → 191 values (mod 9157)
    for i in 0..190 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 9157;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }
    r[190] = r[380];

    // Stage 3: 191 values → 96 values (mod 1280)
    for i in 0..95 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 1280;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }
    r[95] = r[190];

    // Stage 4: 96 values → 48 values (mod 6400)
    for i in 0..48 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 6400;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }

    // Stage 5: 48 values → 24 values (mod 625)
    for i in 0..24 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 625;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }

    // Stage 6: 24 values → 12 values (mod 1526)
    for i in 0..12 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 1526;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }

    // Stage 7: 12 values → 6 values (mod 9097)
    for i in 0..6 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 9097;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        out[out_idx] = (r2 >> 8) as u8;
        out_idx += 1;
        r[i] = (r2 >> 16) as u16;
    }

    // Stage 8: 6 values → 3 values (mod 1263)
    for i in 0..3 {
        let r2 = r[2 * i] as u32 + r[2 * i + 1] as u32 * 1263;
        out[out_idx] = r2 as u8;
        out_idx += 1;
        r[i] = (r2 >> 8) as u16;
    }

    // Stage 9: 3 values → 2 values (mod 6232)
    let r2 = r[0] as u32 + r[1] as u32 * 6232;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    out[out_idx] = (r2 >> 8) as u8;
    out_idx += 1;
    r[0] = (r2 >> 16) as u16;
    r[1] = r[2];

    // Stage 10: 2 values → 1 value (mod 593)
    let r2 = r[0] as u32 + r[1] as u32 * 593;
    out[out_idx] = r2 as u8;
    out_idx += 1;
    r[0] = (r2 >> 8) as u16;

    // Final: output remaining 2 bytes
    out[out_idx] = r[0] as u8;
    out_idx += 1;
    out[out_idx] = (r[0] >> 8) as u8;

    out
}

/// Decodes 1007 bytes to a Rounded polynomial.
///
/// The output values are scaled up by 3 to recover approximate original values.
///
/// This reverses the hierarchical base conversion used in [`rounded_encode`].
/// See that function's documentation for details on the encoding structure.
pub fn rounded_decode(bytes: &[u8; ROUNDED_BYTES]) -> [i16; P] {
    let mut coeffs = [0i16; P];
    let mut s_idx = ROUNDED_BYTES;

    // Working arrays for each stage
    let mut r = [0u16; 381];

    // Decode stages in reverse order (10 → 1)

    // Final: Read last 2 bytes to get r[0] carry
    s_idx -= 1;
    let mut final_r = bytes[s_idx] as u32;
    s_idx -= 1;
    final_r = (final_r << 8) | bytes[s_idx] as u32;

    // Stage 10: Combine final_r with next byte to split into r[0], r[1]
    s_idx -= 1;
    let v = (final_r << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(v, 593);
    r[0] = rem;
    r[1] = q as u16;

    // Stage 9: Expand 2 → 3 (mod 6232)
    let r_2 = r[1];
    let mut v = r[0] as u32;
    s_idx -= 1;
    v = (v << 8) | bytes[s_idx] as u32;
    s_idx -= 1;
    v = (v << 8) | bytes[s_idx] as u32;
    let (q, rem) = divmod_u14(v, 6232);
    r[0] = rem;
    r[1] = q as u16;
    r[2] = r_2;

    // Stage 8: Expand 3 → 6 (mod 1263)
    for i in (0..3).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 1263);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }

    // Stage 7: Expand 6 → 12 (mod 9097)
    for i in (0..6).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 9097);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }

    // Stage 6: Expand 12 → 24 (mod 1526)
    for i in (0..12).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 1526);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }

    // Stage 5: Expand 24 → 48 (mod 625)
    for i in (0..24).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 625);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }

    // Stage 4: Expand 48 → 96 (mod 6400)
    for i in (0..48).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 6400);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }

    // Stage 3: Expand 96 → 191 (mod 1280)
    // Special: r[95] from encode becomes r[190] in decode
    let r95 = r[95];
    for i in (0..95).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 1280);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }
    r[190] = r95;

    // Stage 2: Expand 191 → 381 (mod 9157)
    // Special: r[190] from stage 3 becomes r[380]
    let r190 = r[190];
    for i in (0..190).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 9157);
        r[2 * i] = rem;
        r[2 * i + 1] = q as u16;
    }
    r[380] = r190;

    // Stage 1: Expand 381 → 761 coefficients (mod 1531)
    coeffs[760] = scale_up(r[380]);
    for i in (0..380).rev() {
        let mut v = r[i] as u32;
        s_idx -= 1;
        v = (v << 8) | bytes[s_idx] as u32;
        let (q, rem) = divmod_u14(v, 1531);
        coeffs[2 * i] = scale_up(rem);
        coeffs[2 * i + 1] = scale_up(q as u16);
    }

    coeffs
}

/// Scale decoded rounded value back up by factor of 3.
/// The value v is in [0, 1530], we compute 3*v - Q12 to get back to centred form.
#[inline]
fn scale_up(v: u16) -> i16 {
    // v represents (original + Q12) / 3
    // original = 3*v - Q12
    (3 * (v as i32) - Q12 as i32) as i16
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_roundtrip() {
        let mut coeffs = [0i8; P];
        for i in 0..P {
            coeffs[i] = ((i % 3) as i8) - 1; // -1, 0, 1 pattern
        }

        let encoded = small_encode(&coeffs);
        let decoded = small_decode(&encoded);

        assert_eq!(coeffs, decoded);
    }

    #[test]
    fn test_small_encode_size() {
        let coeffs = [0i8; P];
        let encoded = small_encode(&coeffs);
        assert_eq!(encoded.len(), SMALL_BYTES);
    }

    #[test]
    fn test_rq_roundtrip() {
        let mut coeffs = [0i16; P];
        for i in 0..P {
            // Values in valid range [-2295, 2295]
            coeffs[i] = ((i as i16 * 7) % (Q - 1)) - Q12;
        }

        let encoded = rq_encode(&coeffs);
        let decoded = rq_decode(&encoded);

        assert_eq!(coeffs, decoded);
    }

    #[test]
    fn test_rq_encode_size() {
        let coeffs = [0i16; P];
        let encoded = rq_encode(&coeffs);
        assert_eq!(encoded.len(), RQ_BYTES);
    }

    #[test]
    fn test_rounded_encode_size() {
        let coeffs = [0i16; P];
        let encoded = rounded_encode(&coeffs);
        assert_eq!(encoded.len(), ROUNDED_BYTES);
    }

    #[test]
    fn test_constants() {
        assert_eq!(P, 761);
        assert_eq!(Q, 4591);
        assert_eq!(Q12, 2295);
        assert_eq!(SMALL_BYTES, 191);
        assert_eq!(RQ_BYTES, 1158);
        assert_eq!(ROUNDED_BYTES, 1007);
        assert_eq!(CIPHERTEXT_BYTES, 1039);
        assert_eq!(SECRET_KEY_BYTES, 1763);
    }

    #[test]
    fn test_rounded_encode_zeros() {
        // Test with zero coefficients - should give consistent roundtrip
        let coeffs = [0i16; P];
        let encoded = rounded_encode(&coeffs);
        let decoded = rounded_decode(&encoded);

        // After rounding and scaling, values should be close to zero
        for i in 0..P {
            assert!(
                decoded[i].abs() <= 3,
                "Coefficient {} should be near zero, got {}",
                i,
                decoded[i]
            );
        }
    }

    #[test]
    fn test_rounded_raw_roundtrip_simple() {
        // Test with values that are already multiples of 3 (no rounding loss)
        let mut coeffs = [0i16; P];
        for i in 0..P {
            // Generate values in range [-750, 749], rounded to nearest multiple of 3
            let raw = ((i as i16 * 7) % 1500) - 750;
            coeffs[i] = (raw / 3) * 3;
        }

        let encoded = rounded_encode_raw(&coeffs);
        let decoded = rounded_decode(&encoded);

        // Check first few coefficients for debugging
        for i in 0..10 {
            if coeffs[i] != decoded[i] {
                panic!(
                    "Mismatch at index {}: expected {}, got {}",
                    i, coeffs[i], decoded[i]
                );
            }
        }
    }
}

// C FFI comparison tests - only on platforms with C implementation
#[cfg(all(
    test,
    feature = "std",
    not(target_os = "windows"),
    not(target_arch = "wasm32")
))]
mod c_comparison_tests {
    use super::*;
    use crate::sntrup761::Sntrup761SecretKey;

    #[test]
    fn test_rq_encode_matches_c() {
        // Generate a keypair using C FFI
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.as_bytes();

        // Decode using our Rust decoder
        let coeffs = rq_decode(pk_bytes);

        // Re-encode using our Rust encoder
        let re_encoded = rq_encode(&coeffs);

        // Should match the original
        assert_eq!(pk_bytes, &re_encoded);
    }

    #[test]
    fn test_rq_decode_produces_valid_range() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();
        let coeffs = rq_decode(pk.as_bytes());

        // All coefficients should be in valid range
        for (i, &c) in coeffs.iter().enumerate() {
            assert!(
                c >= -Q12 && c <= Q12,
                "Coefficient {} out of range: {} (should be in [{}, {}])",
                i,
                c,
                -Q12,
                Q12
            );
        }
    }

    /// Test that malformed/arbitrary byte sequences are handled gracefully by decoders.
    ///
    /// The decoders should not panic or produce undefined behavior when given
    /// arbitrary byte sequences. They may produce invalid polynomial coefficients
    /// (e.g., small_decode may return values outside {-1, 0, 1}), but the
    /// subsequent KEM operations will detect this via implicit rejection.
    ///
    /// Note: These decoders do NOT validate input - they just decode bytes.
    /// Validation happens at a higher level (KEM re-encapsulation check).
    #[test]
    fn test_malformed_encoding_handling() {
        // Test rq_decode with all-zero bytes
        let zero_bytes = [0u8; RQ_BYTES];
        let coeffs = rq_decode(&zero_bytes);
        // Should not panic, produces P coefficients
        assert_eq!(coeffs.len(), P);

        // Test rq_decode with all-0xFF bytes
        let max_bytes = [0xFFu8; RQ_BYTES];
        let coeffs = rq_decode(&max_bytes);
        assert_eq!(coeffs.len(), P);

        // Test rq_decode with alternating pattern
        let mut alt_bytes = [0u8; RQ_BYTES];
        for (i, b) in alt_bytes.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xAA } else { 0x55 };
        }
        let coeffs = rq_decode(&alt_bytes);
        assert_eq!(coeffs.len(), P);

        // Test small_decode with all zeros - should produce valid {-1, 0, 1} coefficients
        let zero_small = [0u8; SMALL_BYTES];
        let small_coeffs = small_decode(&zero_small);
        assert_eq!(small_coeffs.len(), P);
        // All-zeros is a valid encoding, should produce valid coefficients
        for &c in &small_coeffs {
            assert!(
                c >= -1 && c <= 1,
                "small coefficient {} out of range for zero input",
                c
            );
        }

        // Test small_decode with arbitrary data - may produce invalid coefficients
        // (this is expected - the decoder doesn't validate, KEM implicit rejection handles it)
        let max_small = [0xFFu8; SMALL_BYTES];
        let small_coeffs = small_decode(&max_small);
        assert_eq!(small_coeffs.len(), P);
        // Note: Coefficients may be outside {-1, 0, 1} for malformed input
        // The test just verifies the decoder doesn't panic

        // Test rounded_decode with random-ish data
        let mut rounded_bytes = [0u8; ROUNDED_BYTES];
        for (i, b) in rounded_bytes.iter_mut().enumerate() {
            *b = ((i * 37) % 256) as u8;
        }
        let rounded_coeffs = rounded_decode(&rounded_bytes);
        assert_eq!(rounded_coeffs.len(), P);
        // The test just verifies no panic

        // Verify encode(decode(x)) produces valid output (not necessarily x)
        // This is a sanity check that the roundtrip doesn't panic
        let random_bytes = {
            let mut b = [0u8; RQ_BYTES];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = ((i * 127 + 31) % 256) as u8;
            }
            b
        };
        let decoded = rq_decode(&random_bytes);
        let re_encoded = rq_encode(&decoded);
        assert_eq!(re_encoded.len(), RQ_BYTES);

        // Verify small_encode(small_decode(valid)) roundtrips correctly
        // First create a valid small polynomial encoding
        let valid_small: [i8; P] = [0i8; P]; // All zeros is valid
        let encoded = small_encode(&valid_small);
        let decoded = small_decode(&encoded);
        assert_eq!(valid_small, decoded);
    }
}
