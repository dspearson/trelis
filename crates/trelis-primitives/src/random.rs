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
    fn next_u32(&mut self) -> u32 {
        generate_u32().expect("RNG failure")
    }

    fn next_u64(&mut self) -> u64 {
        generate_u64().expect("RNG failure")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes(dest).expect("RNG failure");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        fill_bytes(dest).map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))
    }
}

impl rand_core::CryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_bytes() {
        let mut buffer = [0u8; 32];
        fill_bytes(&mut buffer).unwrap();

        // Extremely unlikely that 32 random bytes are all zeros
        assert_ne!(buffer, [0u8; 32]);
    }

    #[test]
    fn test_generate_bytes() {
        let bytes: [u8; 32] = generate_bytes().unwrap();

        // Extremely unlikely that 32 random bytes are all zeros
        assert_ne!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_generate_bytes_different_each_time() {
        let bytes1: [u8; 32] = generate_bytes().unwrap();
        let bytes2: [u8; 32] = generate_bytes().unwrap();

        // Two random generations should be different
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_generate_vec() {
        let vec = generate_vec(64).unwrap();
        assert_eq!(vec.len(), 64);

        // Check it's not all zeros
        assert!(vec.iter().any(|&b| b != 0));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_generate_vec_empty() {
        let vec = generate_vec(0).unwrap();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_generate_u64() {
        let val1 = generate_u64().unwrap();
        let val2 = generate_u64().unwrap();

        // Two random u64s should be different (probability of collision ~2^-64)
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_generate_u32() {
        let val1 = generate_u32().unwrap();
        let val2 = generate_u32().unwrap();

        // Two random u32s should be different
        assert_ne!(val1, val2);
    }

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

    #[test]
    fn test_os_rng_try_fill() {
        use rand_core::RngCore;

        let mut rng = OsRng;
        let mut buffer = [0u8; 32];

        assert!(rng.try_fill_bytes(&mut buffer).is_ok());
        assert_ne!(buffer, [0u8; 32]);
    }

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

    #[test]
    fn test_empty_fill() {
        // Should succeed with empty buffer
        let mut buffer: [u8; 0] = [];
        fill_bytes(&mut buffer).unwrap();
    }
}
