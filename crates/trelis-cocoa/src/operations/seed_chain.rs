//! Seed chain derivation for CoCoA path updates.
//!
//! This module provides the core seed management functionality for CoCoA-SA:
//!
//! - **Leaf seed generation**: Random 32-byte seeds for path updates
//! - **Path seed derivation**: H1-based chain from leaf to root
//! - **Keypair derivation**: H2-based deterministic KEM keypairs
//!
//! # Seed Flow
//!
//! In CoCoA, when a member performs an operation (add, remove, update),
//! they generate a fresh leaf seed and derive all path seeds:
//!
//! ```text
//! leaf_seed (random) → H1 → parent_seed → H1 → grandparent_seed → ... → root_seed
//!                      ↓                  ↓                             ↓
//!                     H2                 H2                            H2
//!                      ↓                  ↓                             ↓
//!                  keypair            keypair                      keypair
//! ```
//!
//! Each path node's seed is encrypted to the resolution of its sibling subtree.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::Result;
use trelis_hybrid::HybridKemKeypair;
use trelis_primitives::fill_bytes;

use crate::key_schedule::{advance_seed_chain, h1_seed_derive};

/// Size of a seed in bytes.
pub const SEED_SIZE: usize = 32;

/// A 32-byte seed used in the CoCoA seed chain.
pub type Seed = [u8; SEED_SIZE];

/// Generates a fresh random leaf seed.
///
/// This seed is the starting point for path derivation. It is generated
/// using the system CSPRNG.
///
/// # Errors
///
/// Returns `RngFailure` if the system CSPRNG fails.
pub fn generate_leaf_seed() -> Result<Seed> {
    let mut seed = [0u8; SEED_SIZE];
    fill_bytes(&mut seed)?;
    Ok(seed)
}

/// Derives path seeds from leaf to root.
///
/// Given a leaf seed and the path length (number of nodes from leaf to root),
/// returns the seeds for each node in the path. The first element is the
/// leaf seed, the last is the root seed.
///
/// # Arguments
///
/// * `leaf_seed` - The starting seed at the leaf level
/// * `path_length` - Number of nodes in the path (1 = just leaf, tree_depth + 1 = full path)
///
/// # Returns
///
/// A vector of seeds, ordered from leaf to root.
///
/// # Example
///
/// ```ignore
/// use trelis_cocoa::operations::seed_chain::{generate_leaf_seed, derive_path_seeds};
///
/// let leaf_seed = generate_leaf_seed().unwrap();
/// let path_seeds = derive_path_seeds(&leaf_seed, 4);
///
/// assert_eq!(path_seeds.len(), 4);
/// assert_eq!(path_seeds[0], leaf_seed);
/// ```
#[cfg(feature = "alloc")]
#[must_use]
pub fn derive_path_seeds(leaf_seed: &Seed, path_length: usize) -> Vec<Seed> {
    if path_length == 0 {
        return Vec::new();
    }

    let mut seeds = Vec::with_capacity(path_length);
    seeds.push(*leaf_seed);

    let mut current = *leaf_seed;
    for _ in 1..path_length {
        current = h1_seed_derive(&current);
        seeds.push(current);
    }

    seeds
}

/// Gets the seed at a specific level in the path.
///
/// This is equivalent to `advance_seed_chain` but with a clearer name
/// for the CoCoA context.
///
/// # Arguments
///
/// * `leaf_seed` - The starting seed at the leaf level
/// * `levels_up` - Number of levels to advance (0 = leaf, tree_depth = root)
#[must_use]
pub fn get_seed_at_level(leaf_seed: &Seed, levels_up: u32) -> Seed {
    advance_seed_chain(leaf_seed, levels_up)
}

/// Derives a KEM keypair from a node seed using H2.
///
/// This is the core function for deterministic keypair generation in CoCoA.
/// The same seed always produces the same keypair.
///
/// # Arguments
///
/// * `seed` - A 32-byte seed (typically from the seed chain)
///
/// # Returns
///
/// A hybrid KEM keypair deterministically derived from the seed.
///
/// # Errors
///
/// Returns `KeyGenerationFailed` if the underlying sntrup761 deterministic
/// keygen exhausts its retry budget (RNG-broken indicator).
pub fn derive_node_keypair(seed: &Seed) -> Result<HybridKemKeypair> {
    HybridKemKeypair::generate_from_seed(seed)
}

/// Derives the delta root from the root seed.
///
/// The delta root is used in the epoch key schedule to derive
/// the new epoch secret.
///
/// # Arguments
///
/// * `root_seed` - The seed at the root of the path
#[must_use]
pub fn derive_delta_root(root_seed: &Seed) -> Seed {
    // The delta_root is simply the root seed in CoCoA-SA.
    // The epoch key schedule (H5) combines this with init_secret and transcript.
    *root_seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_generate_leaf_seed() {
        let seed1 = generate_leaf_seed().unwrap();
        let seed2 = generate_leaf_seed().unwrap();

        // Seeds should be different (with overwhelming probability)
        assert_ne!(seed1, seed2);

        // Seeds should be the correct size
        assert_eq!(seed1.len(), SEED_SIZE);
    }

    #[test]
    fn test_derive_path_seeds_length() {
        let leaf_seed = [0x42u8; 32];

        // Empty path
        let empty = derive_path_seeds(&leaf_seed, 0);
        assert!(empty.is_empty());

        // Single node (just leaf)
        let single = derive_path_seeds(&leaf_seed, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], leaf_seed);

        // Full path (4 levels)
        let full = derive_path_seeds(&leaf_seed, 4);
        assert_eq!(full.len(), 4);
    }

    #[test]
    fn test_derive_path_seeds_deterministic() {
        let leaf_seed = [0x42u8; 32];

        let path1 = derive_path_seeds(&leaf_seed, 4);
        let path2 = derive_path_seeds(&leaf_seed, 4);

        assert_eq!(path1, path2);
    }

    #[test]
    fn test_derive_path_seeds_chain() {
        let leaf_seed = [0x42u8; 32];
        let path = derive_path_seeds(&leaf_seed, 4);

        // First should be leaf seed
        assert_eq!(path[0], leaf_seed);

        // Each subsequent should be H1 of the previous
        for i in 1..path.len() {
            assert_eq!(path[i], h1_seed_derive(&path[i - 1]));
        }
    }

    #[test]
    fn test_get_seed_at_level() {
        let leaf_seed = [0x42u8; 32];

        // Level 0 should be leaf seed
        assert_eq!(get_seed_at_level(&leaf_seed, 0), leaf_seed);

        // Level 1 should be H1(leaf_seed)
        assert_eq!(get_seed_at_level(&leaf_seed, 1), h1_seed_derive(&leaf_seed));

        // Consistency with derive_path_seeds
        let path = derive_path_seeds(&leaf_seed, 4);
        for (i, seed) in path.iter().enumerate() {
            assert_eq!(get_seed_at_level(&leaf_seed, i as u32), *seed);
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_derive_node_keypair_deterministic() {
        let seed = [0x42u8; 32];

        let keypair1 = derive_node_keypair(&seed).unwrap();
        let keypair2 = derive_node_keypair(&seed).unwrap();

        // Same seed should produce same keypair
        assert_eq!(
            keypair1.public_key().to_bytes(),
            keypair2.public_key().to_bytes()
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_derive_node_keypair_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let keypair1 = derive_node_keypair(&seed1).unwrap();
        let keypair2 = derive_node_keypair(&seed2).unwrap();

        // Different seeds should produce different keypairs
        assert_ne!(
            keypair1.public_key().to_bytes(),
            keypair2.public_key().to_bytes()
        );
    }

    #[test]
    fn test_derive_delta_root() {
        let root_seed = [0x42u8; 32];
        let delta = derive_delta_root(&root_seed);

        // Delta root should be the root seed
        assert_eq!(delta, root_seed);
    }
}
