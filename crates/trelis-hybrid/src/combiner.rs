//! Hybrid shared secret combination.
//!
//! This module provides the shared secret combiner used by hybrid KEM operations.
//! The combiner uses BLAKE3's key derivation with domain separation to combine
//! classical (X448) and post-quantum (sntrup761) shared secrets.
//!
//! # Combination Order
//!
//! The classical component (X448, 56 bytes) is concatenated first, followed by
//! the post-quantum component (sntrup761, 32 bytes). This ordering is normative
//! and MUST be followed by all implementations for interoperability.
//!
//! # Example
//!
//! ```
//! use trelis_hybrid::combiner::HybridSharedSecret;
//!
//! let x448_ss = [0x11u8; 56];   // X448 shared secret
//! let sntrup_ss = [0x22u8; 32]; // sntrup761 shared secret
//!
//! let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
//! assert_eq!(combined.as_bytes().len(), 32);
//! ```

use subtle::ConstantTimeEq;
use trelis_primitives::blake3_kdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of X448 shared secret in bytes.
pub const X448_SS_SIZE: usize = 56;

/// Size of sntrup761 shared secret in bytes.
pub const SNTRUP_SS_SIZE: usize = 32;

/// Size of combined input to KDF.
pub const COMBINED_INPUT_SIZE: usize = X448_SS_SIZE + SNTRUP_SS_SIZE;

/// Size of derived hybrid shared secret.
pub const SHARED_SECRET_SIZE: usize = 32;

/// Domain separation context for hybrid KEM combination.
const CONTEXT: &str = "trelis-hybrid-kem-v1";

/// Combined hybrid shared secret.
///
/// This is the result of combining X448 and sntrup761 shared secrets using
/// BLAKE3 key derivation. The combined secret is suitable for use as input
/// to further key derivation or directly as a symmetric key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl HybridSharedSecret {
    /// Combines X448 and sntrup761 shared secrets into a hybrid shared secret.
    ///
    /// # Arguments
    ///
    /// * `x448_ss` - The X448 (classical) shared secret (56 bytes)
    /// * `sntrup_ss` - The sntrup761 (post-quantum) shared secret (32 bytes)
    ///
    /// # Returns
    ///
    /// A 32-byte hybrid shared secret derived using BLAKE3.
    ///
    /// # Security
    ///
    /// The combination order is normative: X448 first, then sntrup761.
    /// The intermediate concatenation buffer is zeroized after use.
    #[must_use]
    pub fn combine(x448_ss: &[u8; X448_SS_SIZE], sntrup_ss: &[u8; SNTRUP_SS_SIZE]) -> Self {
        let mut input = [0u8; COMBINED_INPUT_SIZE];
        input[..X448_SS_SIZE].copy_from_slice(x448_ss);
        input[X448_SS_SIZE..].copy_from_slice(sntrup_ss);

        let combined = blake3_kdf::derive_key(CONTEXT, &input);
        input.zeroize();

        Self { bytes: combined }
    }

    /// Returns the shared secret as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }

    /// Returns the shared secret as a byte array, consuming self.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SHARED_SECRET_SIZE] {
        self.bytes
    }

    /// Creates a shared secret from raw bytes.
    ///
    /// This is primarily for testing or when receiving a pre-computed secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self { bytes }
    }
}

impl ConstantTimeEq for HybridSharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for HybridSharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for HybridSharedSecret {}

impl core::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSharedSecret")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::clone_on_copy)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_combine_produces_32_bytes() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        assert_eq!(combined.as_bytes().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_combine_is_deterministic() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);

        assert_eq!(combined1, combined2);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let x448_ss1 = [0x11u8; X448_SS_SIZE];
        let x448_ss2 = [0x22u8; X448_SS_SIZE];
        let sntrup_ss = [0x33u8; SNTRUP_SS_SIZE];

        let combined1 = HybridSharedSecret::combine(&x448_ss1, &sntrup_ss);
        let combined2 = HybridSharedSecret::combine(&x448_ss2, &sntrup_ss);

        assert_ne!(combined1, combined2);
    }

    #[test]
    fn test_order_matters() {
        // Verify that swapping components produces different output
        // (even though we can't actually swap types, we can verify
        // that the combination is not symmetric)
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);

        // Create a "reversed" version by using different input pattern
        let mut reversed_input = [0u8; COMBINED_INPUT_SIZE];
        reversed_input[..SNTRUP_SS_SIZE].copy_from_slice(&sntrup_ss);
        reversed_input[SNTRUP_SS_SIZE..SNTRUP_SS_SIZE + X448_SS_SIZE].copy_from_slice(&x448_ss);

        let reversed = blake3_kdf::derive_key(CONTEXT, &reversed_input);
        assert_ne!(combined.as_bytes(), &reversed);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let bytes = combined.as_bytes().clone();

        let recovered = HybridSharedSecret::from_bytes(bytes);
        assert_eq!(combined, recovered);
    }

    #[test]
    fn test_into_bytes() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let expected = combined.as_bytes().clone();

        let bytes = combined.into_bytes();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_debug_redacts_secret() {
        let x448_ss = [0x11u8; X448_SS_SIZE];
        let sntrup_ss = [0x22u8; SNTRUP_SS_SIZE];

        let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
        let debug_str = format!("{:?}", combined);

        // Debug should NOT contain the actual bytes
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("0x11"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate a 56-byte X448 shared secret.
    fn x448_strategy() -> impl Strategy<Value = [u8; X448_SS_SIZE]> {
        proptest::collection::vec(any::<u8>(), X448_SS_SIZE..=X448_SS_SIZE).prop_map(|v| {
            let mut arr = [0u8; X448_SS_SIZE];
            arr.copy_from_slice(&v);
            arr
        })
    }

    proptest! {
        /// Property: HybridSharedSecret::combine is deterministic.
        /// The same inputs always produce the same output.
        #[test]
        fn combine_is_deterministic(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined1, combined2);
        }

        /// Property: Equality is reflexive (a == a).
        #[test]
        fn equality_reflexive(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert!(combined == combined);
        }

        /// Property: Equality is symmetric (a == b implies b == a).
        #[test]
        fn equality_symmetric(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined1 == combined2, combined2 == combined1);
        }

        /// Property: Equality is transitive (a == b && b == c implies a == c).
        #[test]
        fn equality_transitive(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let a = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let b = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let c = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            // If a == b and b == c, then a == c
            prop_assert!((a == b && b == c) == (a == c));
        }

        /// Property: Different X448 inputs produce different outputs (with high probability).
        #[test]
        fn different_x448_different_output(
            x448_ss1 in x448_strategy(),
            x448_ss2 in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(x448_ss1 != x448_ss2);
            let combined1 = HybridSharedSecret::combine(&x448_ss1, &sntrup_ss);
            let combined2 = HybridSharedSecret::combine(&x448_ss2, &sntrup_ss);
            prop_assert_ne!(combined1, combined2);
        }

        /// Property: Different sntrup inputs produce different outputs (with high probability).
        #[test]
        fn different_sntrup_different_output(
            x448_ss in x448_strategy(),
            sntrup_ss1 in proptest::array::uniform32(any::<u8>()),
            sntrup_ss2 in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(sntrup_ss1 != sntrup_ss2);
            let combined1 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss1);
            let combined2 = HybridSharedSecret::combine(&x448_ss, &sntrup_ss2);
            prop_assert_ne!(combined1, combined2);
        }

        /// Property: from_bytes roundtrip preserves the secret.
        #[test]
        fn from_bytes_roundtrip(bytes in proptest::array::uniform32(any::<u8>())) {
            let secret = HybridSharedSecret::from_bytes(bytes);
            prop_assert_eq!(*secret.as_bytes(), bytes);
        }

        /// Property: into_bytes preserves the secret.
        #[test]
        fn into_bytes_preserves(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            let expected = *combined.as_bytes();
            let actual = combined.into_bytes();
            prop_assert_eq!(actual, expected);
        }

        /// Property: Output is always SHARED_SECRET_SIZE bytes.
        #[test]
        fn output_size_constant(
            x448_ss in x448_strategy(),
            sntrup_ss in proptest::array::uniform32(any::<u8>()),
        ) {
            let combined = HybridSharedSecret::combine(&x448_ss, &sntrup_ss);
            prop_assert_eq!(combined.as_bytes().len(), SHARED_SECRET_SIZE);
        }
    }
}
