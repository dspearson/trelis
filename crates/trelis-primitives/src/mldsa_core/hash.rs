//! Hash function abstraction for ML-DSA
//!
//! This module defines traits that abstract over hash functions (SHAKE vs BLAKE3),
//! allowing both implementations to coexist in the same binary and be selected at
//! compile time via type parameters rather than feature flags.

use super::module_lattice::encode::ArraySize;
use hybrid_array::Array;

/// Trait for hash state objects (G and H functions in ML-DSA)
///
/// This provides the common interface for both SHAKE and BLAKE3 hash implementations.
pub trait HashState: Default {
    /// Absorb input bytes into the hash state
    fn absorb(self, input: &[u8]) -> Self;

    /// Squeeze output bytes from the hash state
    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self;

    /// Squeeze a fixed-size array from the hash state
    fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

/// Trait for a hash suite (G and H function pair) used by ML-DSA
///
/// Different implementations (SHAKE, BLAKE3) provide different G and H types.
pub trait HashSuite: 'static {
    /// The G hash function type (SHAKE128 or BLAKE3 with "ML-DSA-B-G" context)
    type G: HashState;

    /// The H hash function type (SHAKE256 or BLAKE3 with "ML-DSA-B-H" context)
    type H: HashState;
}
