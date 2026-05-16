//! Cryptographically secure random number generation.
//!
//! This module provides a safe wrapper around the system's CSPRNG for
//! generating random bytes used in key generation, nonce creation, and
//! other cryptographic operations.
//!
//! # Security
//!
//! All random generation uses the operating system's CSPRNG via `getrandom`.
//! On failure, operations return an error rather than falling back to
//! less secure sources.
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::random::{generate_bytes, fill_bytes};
//!
//! // Generate a fixed-size array
//! let key: [u8; 32] = generate_bytes().unwrap();
//!
//! // Fill an existing buffer
//! let mut buffer = [0u8; 16];
//! fill_bytes(&mut buffer).unwrap();
//! ```

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use trelis_error::{CryptoError, Result};

/// Fills a buffer with cryptographically secure random bytes.
///
/// # Arguments
///
/// * `dest` - The buffer to fill with random bytes.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails. This is a fatal error
/// that should not be silently ignored.
///
/// # Security
///
/// This function blocks until sufficient entropy is available. It will not
/// return until the buffer is filled with high-quality random bytes.
pub fn fill_bytes(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest).map_err(|_| CryptoError::RngFailure)
}

/// Generates a fixed-size array of cryptographically secure random bytes.
///
/// # Type Parameters
///
/// * `N` - The size of the array to generate.
///
/// # Returns
///
/// An array of `N` random bytes.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails.
///
/// # Examples
///
/// ```
/// use trelis_primitives::random::generate_bytes;
///
/// let key: [u8; 32] = generate_bytes().unwrap();
/// let nonce: [u8; 24] = generate_bytes().unwrap();
/// ```
pub fn generate_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fill_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Generates a vector of cryptographically secure random bytes.
///
/// # Arguments
///
/// * `len` - The number of random bytes to generate.
///
/// # Returns
///
/// A vector containing `len` random bytes.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails.
#[cfg(feature = "alloc")]
pub fn generate_vec(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    fill_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Generates a random u64 value.
///
/// # Returns
///
/// A random 64-bit unsigned integer.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails.
pub fn generate_u64() -> Result<u64> {
    let bytes: [u8; 8] = generate_bytes()?;
    Ok(u64::from_le_bytes(bytes))
}

/// Generates a random u32 value.
///
/// # Returns
///
/// A random 32-bit unsigned integer.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails.
pub fn generate_u32() -> Result<u32> {
    let bytes: [u8; 4] = generate_bytes()?;
    Ok(u32::from_le_bytes(bytes))
}

/// A wrapper around `rand_core::CryptoRngCore` using `getrandom`.
///
/// This type implements the `RngCore` and `CryptoRng` traits, making it
/// compatible with cryptographic libraries that expect those interfaces.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl rand_core::RngCore for OsRng {
    // The RngCore v0.6 trait's next_u32/next_u64/fill_bytes are infallible by
    // contract; on the rare CSPRNG failure we have no choice but to panic.
    // The fallible variant is exposed via `try_fill_bytes`.
    #[allow(clippy::expect_used)]
    fn next_u32(&mut self) -> u32 {
        generate_u32().expect("RNG failure")
    }

    #[allow(clippy::expect_used)]
    fn next_u64(&mut self) -> u64 {
        generate_u64().expect("RNG failure")
    }

    #[allow(clippy::expect_used)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes(dest).expect("RNG failure");
    }

    #[allow(clippy::unwrap_used)] // NonZeroU32::new(1) is provably Some
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        fill_bytes(dest).map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
    }
}

impl rand_core::CryptoRng for OsRng {}

// Additionally implement `rand_core 0.10`'s `TryRng` (which auto-implements `Rng`
// via the blanket `R: TryRng<Error = Infallible>` impl) so this type works
// with crates that have migrated past the v0.6 traits — notably `ntrulp 0.2.5`,
// whose `short_random<R: Rng>` requires `rand::Rng` from `rand 0.10`, which is
// itself blanket-implemented for any `rand_core::Rng` 0.10. `OsRng` is
// infallible (it expects the system CSPRNG to succeed), so `Error = Infallible`
// is correct.
impl rand_core_v10::TryRng for OsRng {
    type Error = rand_core_v10::Infallible;

    // Infallible error type by design — we wrap the v0.6 RngCore semantics
    // and panic on the rare CSPRNG failure since `Error = Infallible` permits
    // no failure reporting.
    #[allow(clippy::expect_used)]
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(generate_u32().expect("RNG failure"))
    }

    #[allow(clippy::expect_used)]
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        Ok(generate_u64().expect("RNG failure"))
    }

    #[allow(clippy::expect_used)]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        fill_bytes(dst).expect("RNG failure");
        Ok(())
    }
}

impl rand_core_v10::TryCryptoRng for OsRng {}

/// A deterministic RNG seeded with BLAKE3.
///
/// This RNG uses BLAKE3 in XOF (extendable output function) mode to generate
/// deterministic random bytes from a 32-byte seed. The same seed always
/// produces the same sequence of bytes.
///
/// # Security
///
/// This is intended for deterministic key derivation, NOT for general-purpose
/// random number generation. For cryptographic randomness, use [`OsRng`].
///
/// `SeededRng` deliberately does **not** implement `rand_core::CryptoRng`: it is
/// a deterministic PRNG, not a DRBG drawing from an approved entropy source
/// (NIST SP 800-133). Implementing `CryptoRng` would let callers pass it to any
/// API expecting cryptographic randomness and silently receive deterministic
/// output (finding API-01). Internal deterministic use only requires `RngCore`.
///
/// # Example
///
/// ```
/// use trelis_primitives::random::SeededRng;
/// use rand_core::RngCore;
///
/// let seed = [0x42u8; 32];
/// let mut rng1 = SeededRng::new(&seed, "my-context");
/// let mut rng2 = SeededRng::new(&seed, "my-context");
///
/// let mut buf1 = [0u8; 32];
/// let mut buf2 = [0u8; 32];
/// rng1.fill_bytes(&mut buf1);
/// rng2.fill_bytes(&mut buf2);
///
/// // Same seed + context = same output
/// assert_eq!(buf1, buf2);
/// ```
pub struct SeededRng {
    reader: blake3::OutputReader,
}

impl SeededRng {
    /// Creates a new deterministic RNG from a seed and context.
    ///
    /// The context string provides domain separation, ensuring that the same
    /// seed used in different contexts produces different output.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed value
    /// * `context` - A context string for domain separation
    #[must_use]
    pub fn new(seed: &[u8; 32], context: &str) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }
}

impl rand_core::RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.reader.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.reader.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.reader.fill(dest);
        Ok(())
    }
}

// Mirror the `rand_core 0.6` impl on `rand_core 0.10`'s `TryRng` (which auto-
// implements `Rng` for callers needing the new-style trait, e.g. ntrulp 0.2.5).
// `SeededRng` deliberately does NOT implement `TryCryptoRng` / `CryptoRng`,
// for the same reason it does not implement v0.6 `CryptoRng` (finding API-01).
impl rand_core_v10::TryRng for SeededRng {
    type Error = rand_core_v10::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.reader.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.reader.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.reader.fill(dst);
        Ok(())
    }
}

// NOTE: `SeededRng` intentionally does NOT implement `rand_core::CryptoRng`.
// It is a deterministic PRNG; advertising it as a CSPRNG is a misuse hazard
// (finding API-01). Internal deterministic key derivation only needs `RngCore`.

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_fill_bytes() {
        let mut buffer = [0u8; 32];
        fill_bytes(&mut buffer).unwrap();

        // Extremely unlikely that 32 random bytes are all zeros
        assert_ne!(buffer, [0u8; 32]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_bytes() {
        let bytes: [u8; 32] = generate_bytes().unwrap();

        // Extremely unlikely that 32 random bytes are all zeros
        assert_ne!(bytes, [0u8; 32]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_bytes_different_each_time() {
        let bytes1: [u8; 32] = generate_bytes().unwrap();
        let bytes2: [u8; 32] = generate_bytes().unwrap();

        // Two random generations should be different
        assert_ne!(bytes1, bytes2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    #[cfg(feature = "alloc")]
    fn test_generate_vec() {
        let vec = generate_vec(64).unwrap();
        assert_eq!(vec.len(), 64);

        // Check it's not all zeros
        assert!(vec.iter().any(|&b| b != 0));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    #[cfg(feature = "alloc")]
    fn test_generate_vec_empty() {
        let vec = generate_vec(0).unwrap();
        assert!(vec.is_empty());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_u64() {
        let val1 = generate_u64().unwrap();
        let val2 = generate_u64().unwrap();

        // Two random u64s should be different (probability of collision ~2^-64)
        assert_ne!(val1, val2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_u32() {
        let val1 = generate_u32().unwrap();
        let val2 = generate_u32().unwrap();

        // Two random u32s should be different
        assert_ne!(val1, val2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_os_rng_trait() {
        use rand_core::RngCore;

        let mut rng = OsRng;

        let val1 = rng.next_u64();
        let val2 = rng.next_u64();
        assert_ne!(val1, val2);

        let mut buffer = [0u8; 16];
        rng.fill_bytes(&mut buffer);
        assert_ne!(buffer, [0u8; 16]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_os_rng_try_fill() {
        use rand_core::RngCore;

        let mut rng = OsRng;
        let mut buffer = [0u8; 32];

        assert!(rng.try_fill_bytes(&mut buffer).is_ok());
        assert_ne!(buffer, [0u8; 32]);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_various_sizes() {
        // Test generation of various sizes
        let _: [u8; 1] = generate_bytes().unwrap();
        let _: [u8; 16] = generate_bytes().unwrap();
        let _: [u8; 24] = generate_bytes().unwrap();
        let _: [u8; 32] = generate_bytes().unwrap();
        let _: [u8; 64] = generate_bytes().unwrap();
        let _: [u8; 128] = generate_bytes().unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_empty_fill() {
        // Should succeed with empty buffer
        let mut buffer: [u8; 0] = [];
        fill_bytes(&mut buffer).unwrap();
    }

    #[test]
    fn test_seeded_rng_deterministic() {
        use rand_core::RngCore;

        let seed = [0x42u8; 32];
        let mut rng1 = SeededRng::new(&seed, "test-context");
        let mut rng2 = SeededRng::new(&seed, "test-context");

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        // Same seed + context = same output
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_seeded_rng_different_seeds() {
        use rand_core::RngCore;

        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];
        let mut rng1 = SeededRng::new(&seed1, "test-context");
        let mut rng2 = SeededRng::new(&seed2, "test-context");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        // Different seeds = different output
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_seeded_rng_different_contexts() {
        use rand_core::RngCore;

        let seed = [0x42u8; 32];
        let mut rng1 = SeededRng::new(&seed, "context-a");
        let mut rng2 = SeededRng::new(&seed, "context-b");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        // Same seed, different context = different output
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_seeded_rng_next_u32_u64() {
        use rand_core::RngCore;

        let seed = [0x42u8; 32];
        let mut rng1 = SeededRng::new(&seed, "test");
        let mut rng2 = SeededRng::new(&seed, "test");

        // Should produce same sequence
        assert_eq!(rng1.next_u32(), rng2.next_u32());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u32(), rng2.next_u32());
    }
}
