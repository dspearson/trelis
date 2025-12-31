//! Hedged nonce derivation for XChaCha20-Poly1305.
//!
//! This module implements defence-in-depth nonce derivation that combines
//! a deterministic counter with fresh randomness. This ensures unique nonces
//! even if the RNG is compromised or produces repeated values.

use trelis_error::Result;
use zeroize::Zeroize;

#[cfg(any(feature = "std", feature = "wasm"))]
use trelis_primitives::random::generate_bytes;

/// Context string for hedged nonce derivation.
pub const NONCE_CONTEXT: &str = "trelis-ratchet-nonce-v1";

/// Size of XChaCha20 nonce (192 bits = 24 bytes).
pub const NONCE_SIZE: usize = 24;

/// Size of the random component in hedged nonce derivation.
pub const RANDOM_COMPONENT_SIZE: usize = 16;

/// Derives a hedged nonce combining counter, message key, and randomness.
///
/// This provides defence-in-depth against:
/// 1. RNG failure/compromise (counter ensures uniqueness)
/// 2. Counter bugs (random component adds entropy)
///
/// # Arguments
///
/// * `counter` - Message counter (send_count or recv_count)
/// * `message_key` - The 32-byte message key for this message
///
/// # Returns
///
/// A 24-byte nonce suitable for XChaCha20-Poly1305.
///
/// # Security
///
/// As long as either (a) the RNG produces fresh values OR (b) the message
/// counter advances, nonces will not repeat. This is the "hedging" property.
#[cfg(any(feature = "std", feature = "wasm"))]
pub fn derive_hedged_nonce(counter: u64, message_key: &[u8; 32]) -> Result<[u8; NONCE_SIZE]> {
    // Generate random component
    let random_component: [u8; RANDOM_COMPONENT_SIZE] = generate_bytes()?;

    derive_nonce_with_random(counter, message_key, &random_component)
}

/// Derives a nonce with explicit random component (for testing).
///
/// This is the core derivation function that allows testing with
/// deterministic random values.
pub fn derive_nonce_with_random(
    counter: u64,
    message_key: &[u8; 32],
    random_component: &[u8; RANDOM_COMPONENT_SIZE],
) -> Result<[u8; NONCE_SIZE]> {
    // Combine counter + message_key + random
    // 8 + 32 + 16 = 56 bytes
    let mut input = [0u8; 56];
    input[0..8].copy_from_slice(&counter.to_be_bytes());
    input[8..40].copy_from_slice(message_key);
    input[40..56].copy_from_slice(random_component);

    // Derive 32-byte output via BLAKE3
    let derived = blake3::derive_key(NONCE_CONTEXT, &input);

    // Take first 24 bytes for XChaCha20
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&derived[..NONCE_SIZE]);

    // Zeroize input
    let mut input_vec = input;
    input_vec.zeroize();

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_context() {
        assert_eq!(NONCE_CONTEXT, "trelis-ratchet-nonce-v1");
    }

    #[test]
    fn test_nonce_size() {
        assert_eq!(NONCE_SIZE, 24);
    }

    #[test]
    fn test_derive_nonce_with_random() {
        let counter = 42u64;
        let message_key = [0x42u8; 32];
        let random = [0xABu8; RANDOM_COMPONENT_SIZE];

        let nonce = derive_nonce_with_random(counter, &message_key, &random).unwrap();

        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_nonce_deterministic_with_same_inputs() {
        let counter = 42u64;
        let message_key = [0x42u8; 32];
        let random = [0xABu8; RANDOM_COMPONENT_SIZE];

        let nonce1 = derive_nonce_with_random(counter, &message_key, &random).unwrap();
        let nonce2 = derive_nonce_with_random(counter, &message_key, &random).unwrap();

        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_different_with_different_counter() {
        let message_key = [0x42u8; 32];
        let random = [0xABu8; RANDOM_COMPONENT_SIZE];

        let nonce1 = derive_nonce_with_random(0, &message_key, &random).unwrap();
        let nonce2 = derive_nonce_with_random(1, &message_key, &random).unwrap();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_different_with_different_random() {
        let counter = 42u64;
        let message_key = [0x42u8; 32];
        let random1 = [0xABu8; RANDOM_COMPONENT_SIZE];
        let random2 = [0xCDu8; RANDOM_COMPONENT_SIZE];

        let nonce1 = derive_nonce_with_random(counter, &message_key, &random1).unwrap();
        let nonce2 = derive_nonce_with_random(counter, &message_key, &random2).unwrap();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_different_with_different_message_key() {
        let counter = 42u64;
        let message_key1 = [0x42u8; 32];
        let message_key2 = [0x43u8; 32];
        let random = [0xABu8; RANDOM_COMPONENT_SIZE];

        let nonce1 = derive_nonce_with_random(counter, &message_key1, &random).unwrap();
        let nonce2 = derive_nonce_with_random(counter, &message_key2, &random).unwrap();

        assert_ne!(nonce1, nonce2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_derive_hedged_nonce() {
        let counter = 42u64;
        let message_key = [0x42u8; 32];

        let nonce = derive_hedged_nonce(counter, &message_key).unwrap();
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hedged_nonce_different_each_call() {
        let counter = 42u64;
        let message_key = [0x42u8; 32];

        let nonce1 = derive_hedged_nonce(counter, &message_key).unwrap();
        let nonce2 = derive_hedged_nonce(counter, &message_key).unwrap();

        // Should be different due to random component
        assert_ne!(nonce1, nonce2);
    }
}
