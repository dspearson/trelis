use super::hash::{HashState, HashSuite};
use super::module_lattice::encode::ArraySize;
use blake3::{Hasher, OutputReader};
use hybrid_array::Array;

// Threshold for tiny squeeze caching (fits in L1 cache)
const TINY_SQUEEZE_MAX: usize = 128;
const TINY_PREFETCH: usize = 1024;
// Threshold for parallel hashing (rayon) - must match upstream
const PAR_RAYON_BYTES: usize = 128 * 1024;

#[derive(Debug)]
/// BLAKE3 hash state - optimised for ML-DSA's access patterns.
///
/// Unlike the previous implementation, this version:
/// 1. Does NOT buffer input - updates the hasher directly
/// 2. Only allocates for squeeze caching after seeing multiple tiny squeezes
/// 3. Uses rayon parallel hashing for large inputs (>= 128KB)
#[allow(clippy::large_enum_variant)]
pub enum Blake3State {
    /// Absorbing state - hasher only, no buffer
    Absorbing(Hasher),
    /// Squeezing state with optional tiny-squeeze cache
    Squeezing {
        /// XOF reader for output
        reader: OutputReader,
        /// Count of tiny squeezes (enables caching after first)
        tiny_hits: u32,
        /// Inline cache for repeated tiny squeezes (stack allocated)
        cache: [u8; TINY_PREFETCH],
        /// Read offset into cache
        cache_off: usize,
        /// Valid bytes in cache
        cache_len: usize,
    },
}

impl Default for Blake3State {
    #[inline]
    fn default() -> Self {
        Blake3State::Absorbing(Hasher::new())
    }
}

impl Blake3State {
    /// Create a new hash state with a derive key context.
    #[inline]
    pub fn new_derive_key(context: &str) -> Self {
        Blake3State::Absorbing(Hasher::new_derive_key(context))
    }

    /// Absorb input into the hash state.
    ///
    /// Updates the hasher directly. Uses rayon for large inputs when std feature is enabled.
    #[must_use]
    #[inline]
    pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Blake3State::Absorbing(hasher) => {
                #[cfg(feature = "std")]
                if input.len() >= PAR_RAYON_BYTES {
                    hasher.update_rayon(input);
                } else {
                    hasher.update(input);
                }
                #[cfg(not(feature = "std"))]
                hasher.update(input);
            }
            Blake3State::Squeezing { .. } => unreachable!("absorb after squeeze"),
        }
        self
    }

    #[inline]
    fn ensure_reader(&mut self) {
        if let Blake3State::Absorbing(hasher) = self {
            let reader = hasher.finalize_xof();
            *self = Blake3State::Squeezing {
                reader,
                tiny_hits: 0,
                cache: [0u8; TINY_PREFETCH],
                cache_off: 0,
                cache_len: 0,
            };
        }
    }

    /// Squeeze output from the hash state.
    #[inline]
    pub fn squeeze(&mut self, out: &mut [u8]) -> &mut Self {
        self.ensure_reader();

        if let Blake3State::Squeezing {
            reader,
            tiny_hits,
            cache,
            cache_off,
            cache_len,
        } = self
        {
            if out.len() <= TINY_SQUEEZE_MAX {
                // Tiny squeeze path - use caching after first tiny squeeze
                if *tiny_hits > 0 {
                    // Refill cache if needed
                    if *cache_off + out.len() > *cache_len {
                        reader.fill(cache);
                        *cache_off = 0;
                        *cache_len = TINY_PREFETCH;
                    }
                    // Serve from cache
                    out.copy_from_slice(&cache[*cache_off..*cache_off + out.len()]);
                    *cache_off += out.len();
                } else {
                    // First tiny squeeze - fill directly, enable caching for next
                    reader.fill(out);
                    *tiny_hits = 1;
                }
            } else {
                // Large squeeze - fill directly
                reader.fill(out);
                // Reset tiny tracking
                *tiny_hits = 0;
                *cache_off = 0;
                *cache_len = 0;
            }
        }
        self
    }

    /// Squeeze output into a new array.
    #[allow(dead_code)]
    #[inline]
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

/// BLAKE3 hash state for G function (uses "ML-DSA-B-G" context).
pub struct Blake3StateG(Blake3State);
/// BLAKE3 hash state for H function (uses "ML-DSA-B-H" context).
pub struct Blake3StateH(Blake3State);

impl Default for Blake3StateG {
    #[inline]
    fn default() -> Self {
        Blake3StateG(Blake3State::new_derive_key("ML-DSA-B-G"))
    }
}

impl Blake3StateG {
    /// Absorb input data into the hash state.
    #[allow(dead_code)]
    pub fn absorb(mut self, input: &[u8]) -> Self {
        self.0 = self.0.absorb(input);
        self
    }

    /// Squeeze output data from the hash state.
    #[allow(dead_code)]
    pub fn squeeze(&mut self, out: &mut [u8]) -> &mut Self {
        self.0.squeeze(out);
        self
    }

    /// Squeeze output data into a new array.
    #[allow(dead_code)]
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        self.0.squeeze_new()
    }
}

impl Default for Blake3StateH {
    #[inline]
    fn default() -> Self {
        Blake3StateH(Blake3State::new_derive_key("ML-DSA-B-H"))
    }
}

impl Blake3StateH {
    /// Absorb input data into the hash state.
    #[allow(dead_code)]
    pub fn absorb(mut self, input: &[u8]) -> Self {
        self.0 = self.0.absorb(input);
        self
    }

    /// Squeeze output data from the hash state.
    #[allow(dead_code)]
    pub fn squeeze(&mut self, out: &mut [u8]) -> &mut Self {
        self.0.squeeze(out);
        self
    }

    /// Squeeze output data into a new array.
    #[allow(dead_code)]
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        self.0.squeeze_new()
    }
}

#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for G function
pub type G = Blake3StateG;
#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for H function
pub type H = Blake3StateH;

// Implement HashState for Blake3StateG
impl HashState for Blake3StateG {
    fn absorb(self, input: &[u8]) -> Self {
        Blake3StateG::absorb(self, input)
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        Blake3StateG::squeeze(self, output)
    }
}

// Implement HashState for Blake3StateH
impl HashState for Blake3StateH {
    fn absorb(self, input: &[u8]) -> Self {
        Blake3StateH::absorb(self, input)
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        Blake3StateH::squeeze(self, output)
    }
}

/// BLAKE3-based hash suite (experimental variant)
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3Suite;

impl HashSuite for Blake3Suite {
    type G = Blake3StateG;
    type H = Blake3StateH;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mldsa_core::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("7b81750d951e3c66085d459b69db12076db380eaf1e8b484d1f20139a7043ef8");
        let expected2 = hex!("75369b21aa54f22c9497bc233ef94138f372f94e8bb6f7eca4a9c0b36e111fa7");

        let mut g = G::default().absorb(input);

        let mut actual = [0u8; 32];
        g.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = g.squeeze_new();
        assert_eq!(actual, expected2);
    }

    #[test]
    fn h() {
        let input = b"hello world";
        let expected1 = hex!("064033d1d12df7bd1ff05aa000185f0c6aab84d36996d1dcdf1bc5aa13e76d48");
        let expected2 = hex!("32ebb1ba0ff31dc7cdc238ff123637ee875075a4cc09aa362c8da112cdb8299c");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
