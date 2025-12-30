//! Pure Rust sntrup761 KEM implementation for WASM.
//!
//! This module implements the sntrup761 Key Encapsulation Mechanism using
//! ntrulp for polynomial arithmetic and custom encoding for wire format
//! compatibility with the standard (PQClean/reference) implementation.
//!
//! # Compatibility
//!
//! This implementation is intended to be **fully compatible** with the C
//! reference implementation:
//! - Wire format encoding matches exactly
//! - Hash functions use SHA-512 (same as reference)
//! - Shared secrets are byte-for-byte identical
//!
//! # Wire Format
//!
//! Key sizes match the standard format:
//! - Public key: 1,158 bytes
//! - Secret key: 1,763 bytes
//! - Ciphertext: 1,039 bytes (1,007 + 32 confirmation)
//! - Shared secret: 32 bytes

extern crate alloc;

use sha2::{Digest, Sha512};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sntrup761_encoding::{
    P, ROUNDED_BYTES, RQ_BYTES, SECRET_KEY_BYTES, SMALL_BYTES, rounded_encode, rq_decode,
    rq_encode, small_decode, small_encode,
};
use crate::sntrup761_poly;
use trelis_error::{CryptoError, Result};

use ntrulp::poly::r3::R3;
use ntrulp::rng::{random_small, short_random};
use rand_core::RngCore;

// Use OsRng from our random module for cryptographic random generation
use crate::random::OsRng;

/// Size of sntrup761 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = RQ_BYTES; // 1158

/// Size of sntrup761 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = SECRET_KEY_BYTES; // 1763

/// Size of sntrup761 ciphertext in bytes.
pub const CIPHERTEXT_SIZE: usize = ROUNDED_BYTES + 32; // 1039

/// Size of sntrup761 shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// Weight parameter (number of ±1 coefficients in short polynomials).
const W: usize = 286;

/// Maximum attempts for key generation before failing.
/// This prevents infinite loops if the RNG is broken.
const MAX_KEYGEN_ATTEMPTS: usize = 10_000;

// ============================================================================
// Hash Functions (SHA-512, matching reference implementation)
// ============================================================================
//
// The sntrup761 reference implementation uses SHA-512 with byte prefixes.
// The Hash function is: Hash(b, data) = SHA-512(b || data)[0:32]
//
// Structure (non-LPR variant which sntrup761 uses):
// 1. r_hash = Hash(3, r_enc) = SHA-512(3 || r_enc)[0:32]
// 2. cache = Hash(4, pk) = SHA-512(4 || pk)[0:32]
// 3. confirm = Hash(2, r_hash || cache) = SHA-512(2 || r_hash || cache)[0:32]
// 4. session = Hash(b, r_hash || ciphertext) = SHA-512(b || r_hash || ct)[0:32]

/// Core hash function: Hash(prefix, data) = SHA-512(prefix || data)[0:32]
fn hash_with_prefix(prefix: u8, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([prefix]);
    hasher.update(data);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// Hash the r encoding: r_hash = SHA-512(3 || r_enc)[0:32]
fn hash_r_encoding(r_enc: &[u8]) -> [u8; 32] {
    hash_with_prefix(3, r_enc)
}

/// Compute public key cache: cache = SHA-512(4 || pk)[0:32]
fn hash_pk_cache(pk: &[u8]) -> [u8; 32] {
    hash_with_prefix(4, pk)
}

/// Compute HashConfirm: SHA-512(2 || r_hash || cache)[0:32]
fn hash_confirm(r_hash: &[u8; 32], cache: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(r_hash);
    data[32..].copy_from_slice(cache);
    hash_with_prefix(2, &data)
}

/// Compute HashSession: SHA-512(prefix || r_hash || ciphertext)[0:32]
fn hash_session(prefix: u8, r_hash: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([prefix]);
    hasher.update(r_hash);
    hasher.update(ciphertext);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

// ============================================================================
// Polynomial Arithmetic (Optimised with Karatsuba)
// ============================================================================

/// Round Rq polynomial coefficients to nearest multiple of 3.
fn round_rq(coeffs: &[i16; P]) -> [i16; P] {
    let mut rounded = [0i16; P];
    for i in 0..P {
        // Round to nearest multiple of 3
        // This is: round(c / 3) * 3
        let c = coeffs[i] as i32;
        rounded[i] = (3 * ((c * 10923 + 16384) >> 15)) as i16;
    }
    rounded
}

/// Optimised Rq × R3 multiplication using Karatsuba.
/// This is the main performance bottleneck in sntrup761.
fn rq_mult_r3_karatsuba(rq_coeffs: &[i16; P], r3_coeffs: &[i8; P]) -> [i16; P] {
    sntrup761_poly::rq_mult_r3(rq_coeffs, r3_coeffs)
}

/// Optimised R3 × R3 multiplication using Karatsuba.
fn r3_mult_r3_karatsuba(a_coeffs: &[i8; P], b_coeffs: &[i8; P]) -> [i8; P] {
    sntrup761_poly::r3_mult_r3(a_coeffs, b_coeffs)
}

// ============================================================================
// Key Types
// ============================================================================

/// sntrup761 secret key (WASM backend).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sntrup761SecretKey {
    /// Serialised secret key in standard format.
    bytes: [u8; SECRET_KEY_SIZE],
}

impl Sntrup761SecretKey {
    /// Generates a new random keypair and returns the secret key.
    ///
    /// # Panics
    ///
    /// Panics if key generation fails after `MAX_KEYGEN_ATTEMPTS` attempts,
    /// which indicates a broken RNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut attempts = 0usize;

        // Generate small g and compute ginv
        let (g_coeffs, ginv_coeffs) = loop {
            attempts += 1;
            if attempts > MAX_KEYGEN_ATTEMPTS {
                panic!(
                    "sntrup761: g generation failed after {} attempts - RNG may be broken",
                    MAX_KEYGEN_ATTEMPTS
                );
            }
            let g_coeffs = random_small(&mut rng);
            let g = R3::from(g_coeffs);
            if let Ok(ginv) = g.recip() {
                break (g_coeffs, ginv.coeffs);
            }
            // g not invertible, retry
        };

        // Generate short f with weight W
        attempts = 0;
        let f_coeffs = loop {
            attempts += 1;
            if attempts > MAX_KEYGEN_ATTEMPTS {
                panic!(
                    "sntrup761: f generation failed after {} attempts - RNG may be broken",
                    MAX_KEYGEN_ATTEMPTS
                );
            }
            if let Ok(short) = short_random(&mut rng) {
                // Verify it has correct weight
                let mut f_i8 = [0i8; P];
                let mut weight = 0usize;
                for i in 0..P {
                    f_i8[i] = short[i] as i8;
                    if f_i8[i] != 0 {
                        weight += 1;
                    }
                }
                if weight == W {
                    break f_i8;
                }
            }
        };

        // Compute public key: h = (1/3f) * g in Rq
        let f_rq = R3::from(f_coeffs).rq_from_r3();

        // Compute 1/(3f) in Rq
        // If f is not invertible mod 3, regenerate the entire keypair.
        // This is extremely rare with properly generated f.
        let finv = match f_rq.recip::<3>() {
            Ok(inv) => inv,
            Err(_) => {
                // f not invertible mod 3, regenerate entire keypair
                return Self::generate();
            }
        };

        // h = finv * g using Karatsuba (major speedup)
        let h_coeffs = rq_mult_r3_karatsuba(&finv.coeffs, &g_coeffs);

        // Encode public key
        let pk_bytes = rq_encode(&h_coeffs);

        // Generate random rho for implicit rejection
        let mut rho = [0u8; SMALL_BYTES];
        rng.fill_bytes(&mut rho);

        // Compute pk cache = SHA-512(4 || pk)[0:32]
        let pk_cache = hash_pk_cache(&pk_bytes);

        // Assemble secret key: f || ginv || pk || rho || cache
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        let f_enc = small_encode(&f_coeffs);
        let ginv_enc = small_encode(&ginv_coeffs);

        bytes[0..SMALL_BYTES].copy_from_slice(&f_enc);
        bytes[SMALL_BYTES..2 * SMALL_BYTES].copy_from_slice(&ginv_enc);
        bytes[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES].copy_from_slice(&pk_bytes);
        bytes[2 * SMALL_BYTES + RQ_BYTES..2 * SMALL_BYTES + RQ_BYTES + SMALL_BYTES]
            .copy_from_slice(&rho);
        bytes[SECRET_KEY_SIZE - 32..].copy_from_slice(&pk_cache);

        Self { bytes }
    }

    /// Creates a secret key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: key_bytes })
    }

    /// Returns the secret key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derives the public key from this secret key.
    #[must_use]
    pub fn public_key(&self) -> Sntrup761PublicKey {
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];
        pk_bytes.copy_from_slice(&self.bytes[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES]);
        Sntrup761PublicKey { bytes: pk_bytes }
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &Sntrup761Ciphertext) -> Result<Sntrup761SharedSecret> {
        // Parse secret key components
        let f_coeffs = small_decode(
            self.bytes[0..SMALL_BYTES]
                .try_into()
                .map_err(|_| CryptoError::DecapsulationFailed)?,
        );
        let ginv_coeffs = small_decode(
            self.bytes[SMALL_BYTES..2 * SMALL_BYTES]
                .try_into()
                .map_err(|_| CryptoError::DecapsulationFailed)?,
        );
        let pk_bytes: &[u8; RQ_BYTES] = self.bytes[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES]
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed)?;
        let rho: &[u8; SMALL_BYTES] = self.bytes
            [2 * SMALL_BYTES + RQ_BYTES..2 * SMALL_BYTES + RQ_BYTES + SMALL_BYTES]
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed)?;
        let cache: &[u8; 32] = self.bytes[SECRET_KEY_SIZE - 32..]
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed)?;

        // Parse ciphertext
        let ct_body: &[u8; ROUNDED_BYTES] = ciphertext.bytes[0..ROUNDED_BYTES]
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed)?;
        let confirm: &[u8; 32] = ciphertext.bytes[ROUNDED_BYTES..]
            .try_into()
            .map_err(|_| CryptoError::DecapsulationFailed)?;

        // Decode ciphertext to Rq coefficients
        // For rounded ciphertext, we need to decode and scale by 3
        let c_coeffs = decode_rounded(ct_body);

        // Compute e = 3 * (c * f) in Rq using Karatsuba (major speedup)
        let cf_coeffs = rq_mult_r3_karatsuba(&c_coeffs, &f_coeffs);
        // Scale by 3
        let mut e_coeffs = [0i16; P];
        for i in 0..P {
            e_coeffs[i] = cf_coeffs[i].wrapping_mul(3);
            // Reduce modulo q if needed
            let mut v = e_coeffs[i] as i32;
            const Q: i32 = 4591;
            const Q_HALF: i32 = Q / 2;
            if v > Q_HALF {
                v -= Q;
            } else if v < -Q_HALF {
                v += Q;
            }
            e_coeffs[i] = v as i16;
        }

        // Compute r' = Round(e) * ginv in R3
        // First reduce e to R3 (mod 3)
        let mut e_r3_coeffs = [0i8; P];
        for i in 0..P {
            let r = ((e_coeffs[i] as i32 % 3) + 3) % 3;
            e_r3_coeffs[i] = match r {
                0 => 0,
                1 => 1,
                2 => -1,
                _ => unreachable!(),
            };
        }

        // Multiply in R3 using Karatsuba (major speedup)
        let r_prime_coeffs = r3_mult_r3_karatsuba(&e_r3_coeffs, &ginv_coeffs);

        // Encode r' (small polynomial)
        let r_enc = small_encode(&r_prime_coeffs);

        // Hash r encoding: r_hash = SHA-512(3 || r_enc)[0:32]
        let r_hash = hash_r_encoding(&r_enc);

        // Re-encapsulate with r' to verify using Karatsuba
        let h_coeffs = rq_decode(pk_bytes);
        let hr_coeffs = rq_mult_r3_karatsuba(&h_coeffs, &r_prime_coeffs);
        let c_prime_coeffs = round_rq(&hr_coeffs);
        let c_prime_bytes = rounded_encode(&c_prime_coeffs);

        // Compute expected confirmation = SHA-512(2 || r_hash || cache)[0:32]
        let confirm_prime = hash_confirm(&r_hash, cache);

        // Compare ciphertext and confirmation (constant-time)
        let ct_match = ct_body.ct_eq(&c_prime_bytes);
        let confirm_match = confirm.ct_eq(&confirm_prime);
        let valid = ct_match & confirm_match;

        // Compute success shared secret = SHA-512(1 || r_hash || ciphertext)[0:32]
        let ss_success = hash_session(1, &r_hash, &ciphertext.bytes);

        // Compute rejection shared secret using rho instead of r
        // In the reference, rejection uses rho as the input (not r):
        // rho_hash = SHA-512(3 || rho)[0:32]
        // ss_reject = SHA-512(0 || rho_hash || ciphertext)[0:32]
        let rho_hash = hash_r_encoding(rho);
        let ss_reject = hash_session(0, &rho_hash, &ciphertext.bytes);

        // Select based on validity (constant-time)
        let mut ss_bytes = [0u8; SHARED_SECRET_SIZE];
        for i in 0..SHARED_SECRET_SIZE {
            ss_bytes[i] = u8::conditional_select(&ss_reject[i], &ss_success[i], valid);
        }

        Ok(Sntrup761SharedSecret { bytes: ss_bytes })
    }
}

impl core::fmt::Debug for Sntrup761SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// sntrup761 public key (WASM backend).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sntrup761PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl Sntrup761PublicKey {
    /// Creates a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: key_bytes })
    }

    /// Creates a public key from a fixed-size array.
    #[must_use]
    pub const fn from_array(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Encapsulates to this public key, producing a shared secret and ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if random polynomial generation fails after `MAX_KEYGEN_ATTEMPTS`
    /// attempts, which indicates a broken RNG.
    #[must_use]
    pub fn encapsulate(&self) -> (Sntrup761SharedSecret, Sntrup761Ciphertext) {
        let mut rng = OsRng;
        let mut attempts = 0usize;

        // Generate short random r with weight W
        let r_coeffs = loop {
            attempts += 1;
            if attempts > MAX_KEYGEN_ATTEMPTS {
                panic!(
                    "sntrup761: r generation failed after {} attempts - RNG may be broken",
                    MAX_KEYGEN_ATTEMPTS
                );
            }
            if let Ok(short) = short_random(&mut rng) {
                let mut r_i8 = [0i8; P];
                let mut weight = 0usize;
                for i in 0..P {
                    r_i8[i] = short[i] as i8;
                    if r_i8[i] != 0 {
                        weight += 1;
                    }
                }
                if weight == W {
                    break r_i8;
                }
            }
        };

        // Decode public key
        let h_coeffs = rq_decode(&self.bytes);

        // Compute c = Round(h * r) using Karatsuba (major speedup)
        let hr_coeffs = rq_mult_r3_karatsuba(&h_coeffs, &r_coeffs);
        let c_coeffs = round_rq(&hr_coeffs);

        // Encode ciphertext body (rounded polynomial)
        let c_bytes = rounded_encode(&c_coeffs);

        // Encode r (small polynomial)
        let r_enc = small_encode(&r_coeffs);

        // Hash r encoding: r_hash = SHA-512(3 || r_enc)[0:32]
        let r_hash = hash_r_encoding(&r_enc);

        // Compute pk cache = SHA-512(4 || pk)[0:32]
        let cache = hash_pk_cache(&self.bytes);

        // Compute confirmation = SHA-512(2 || r_hash || cache)[0:32]
        let confirm = hash_confirm(&r_hash, &cache);

        // Assemble full ciphertext (body + confirmation)
        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes[0..ROUNDED_BYTES].copy_from_slice(&c_bytes);
        ct_bytes[ROUNDED_BYTES..].copy_from_slice(&confirm);

        // Compute shared secret = SHA-512(1 || r_hash || ciphertext)[0:32]
        let ss = hash_session(1, &r_hash, &ct_bytes);

        (
            Sntrup761SharedSecret { bytes: ss },
            Sntrup761Ciphertext { bytes: ct_bytes },
        )
    }
}

impl core::fmt::Debug for Sntrup761PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761PublicKey")
            .field("bytes", &"[1158 bytes]")
            .finish()
    }
}

/// sntrup761 ciphertext.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sntrup761Ciphertext {
    bytes: [u8; CIPHERTEXT_SIZE],
}

impl Sntrup761Ciphertext {
    /// Creates a ciphertext from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CIPHERTEXT_SIZE {
            return Err(CryptoError::InvalidCiphertextLength {
                expected: CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }

        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: ct_bytes })
    }

    /// Creates a ciphertext from a fixed-size array.
    #[must_use]
    pub const fn from_array(bytes: [u8; CIPHERTEXT_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the ciphertext as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_SIZE] {
        &self.bytes
    }

    /// Returns the ciphertext as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        self.bytes
    }
}

impl core::fmt::Debug for Sntrup761Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761Ciphertext")
            .field("bytes", &"[1039 bytes]")
            .finish()
    }
}

/// sntrup761 shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sntrup761SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl Sntrup761SharedSecret {
    /// Returns the shared secret as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }

    /// Returns the shared secret as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SHARED_SECRET_SIZE] {
        self.bytes
    }
}

impl ConstantTimeEq for Sntrup761SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl core::fmt::Debug for Sntrup761SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761SharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Decode rounded ciphertext bytes to Rq coefficients.
/// This scales the decoded values by 3 to recover approximate original values.
fn decode_rounded(bytes: &[u8; ROUNDED_BYTES]) -> [i16; P] {
    // Use the rounded decoder from encoding module
    // The rounded encoding divides by 3, so we need to multiply back
    crate::sntrup761_encoding::rounded_decode(bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        // Verify sizes
        assert_eq!(sk.as_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(pk.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_key_serialisation_roundtrip() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        // Secret key roundtrip
        let sk_bytes = sk.as_bytes().to_vec();
        let sk2 = Sntrup761SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.as_bytes(), sk2.as_bytes());

        // Public key roundtrip
        let pk_bytes = pk.as_bytes().to_vec();
        let pk2 = Sntrup761PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        // Encapsulate
        let (ss_enc, ct) = pk.encapsulate();

        // Decapsulate
        let ss_dec = sk.decapsulate(&ct).unwrap();

        // Shared secrets should match
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_multiple_encapsulations_different() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (ss1, ct1) = pk.encapsulate();
        let (ss2, ct2) = pk.encapsulate();

        // Different encapsulations should produce different ciphertexts and secrets
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // But both should decapsulate correctly
        let ss1_dec = sk.decapsulate(&ct1).unwrap();
        let ss2_dec = sk.decapsulate(&ct2).unwrap();

        assert_eq!(ss1.as_bytes(), ss1_dec.as_bytes());
        assert_eq!(ss2.as_bytes(), ss2_dec.as_bytes());
    }

    #[test]
    fn test_ciphertext_serialisation() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (ss, ct) = pk.encapsulate();

        // Serialise and deserialise ciphertext
        let ct_bytes = ct.as_bytes().to_vec();
        let ct2 = Sntrup761Ciphertext::from_bytes(&ct_bytes).unwrap();

        // Decapsulate with deserialised ciphertext
        let ss2 = sk.decapsulate(&ct2).unwrap();

        assert_eq!(ss.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_constants() {
        assert_eq!(PUBLIC_KEY_SIZE, 1158);
        assert_eq!(SECRET_KEY_SIZE, 1763);
        assert_eq!(CIPHERTEXT_SIZE, 1039);
        assert_eq!(SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Sntrup761SecretKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());

        let result = Sntrup761PublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let result = Sntrup761Ciphertext::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }
}
