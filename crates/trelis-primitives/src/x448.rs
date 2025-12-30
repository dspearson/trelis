//! X448 Diffie-Hellman key exchange.
//!
//! This module provides X448 elliptic curve Diffie-Hellman as specified in
//! RFC 7748. X448 uses Curve448 (Goldilocks) and provides approximately
//! 224-bit security (NIST Level 4).
//!
//! # Key Sizes
//!
//! - Public key: 56 bytes
//! - Secret key: 56 bytes
//! - Shared secret: 56 bytes
//!
//! # Security Properties
//!
//! - Contributory key agreement
//! - Forward secrecy (when ephemeral keys are used)
//! - Resistance to timing attacks (constant-time implementation)
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::x448::{X448Secret, X448Public};
//!
//! // Alice generates her keypair
//! let alice_secret = X448Secret::generate().unwrap();
//! let alice_public = alice_secret.public_key();
//!
//! // Bob generates his keypair
//! let bob_secret = X448Secret::generate().unwrap();
//! let bob_public = bob_secret.public_key();
//!
//! // Both compute the same shared secret
//! let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
//! let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
//!
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use ed448_goldilocks_plus::{MontgomeryPoint, Scalar};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of X448 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 56;

/// Size of X448 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 56;

/// Size of X448 shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 56;

/// X448 secret key.
///
/// This key is used for Diffie-Hellman key agreement. It is zeroized
/// on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X448Secret {
    bytes: [u8; SECRET_KEY_SIZE],
}

impl X448Secret {
    /// Generates a new random secret key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        fill_bytes(&mut bytes)?;
        // Apply clamping as per RFC 7748
        bytes[0] &= 0xFC;
        bytes[55] |= 0x80;
        Ok(Self { bytes })
    }

    /// Creates a secret key from raw bytes.
    ///
    /// Note: The bytes are clamped as per RFC 7748.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; SECRET_KEY_SIZE]) -> Self {
        // Apply clamping
        bytes[0] &= 0xFC;
        bytes[55] |= 0x80;
        Self { bytes }
    }

    /// Returns the secret key bytes (clamped).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derives the public key from this secret key.
    #[must_use]
    pub fn public_key(&self) -> X448Public {
        let scalar = Scalar::from_bytes(&self.bytes);
        let public_point = &MontgomeryPoint::GENERATOR * &scalar;
        X448Public {
            bytes: *public_point.as_bytes(),
        }
    }

    /// Performs X448 Diffie-Hellman key agreement.
    ///
    /// # Arguments
    ///
    /// * `their_public` - The other party's public key.
    ///
    /// # Returns
    ///
    /// The shared secret (56 bytes).
    ///
    /// # Errors
    ///
    /// Returns `DecapsulationFailed` if the public key is invalid or
    /// the result is the all-zeros point (which would indicate a
    /// small-subgroup attack).
    pub fn diffie_hellman(&self, their_public: &X448Public) -> Result<X448SharedSecret> {
        let their_point = MontgomeryPoint(their_public.bytes);
        let scalar = Scalar::from_bytes(&self.bytes);
        let shared_point = &their_point * &scalar;

        // Check for all-zeros result (invalid)
        let zero = [0u8; SHARED_SECRET_SIZE];
        if bool::from(shared_point.as_bytes().ct_eq(&zero)) {
            return Err(CryptoError::DecapsulationFailed);
        }

        Ok(X448SharedSecret {
            bytes: *shared_point.as_bytes(),
        })
    }
}

impl ConstantTimeEq for X448Secret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// X448 public key.
///
/// This key is shared with the other party for Diffie-Hellman key agreement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X448Public {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl X448Public {
    /// Creates a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 56 bytes.
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
}

impl core::fmt::Debug for X448Public {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X448Public")
            .field("bytes", &"[56 bytes]")
            .finish()
    }
}

/// X448 shared secret.
///
/// The result of a Diffie-Hellman key agreement. This should typically
/// be fed into a KDF (like BLAKE3) before use as a key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X448SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl X448SharedSecret {
    /// Returns the shared secret as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }

    /// Returns the shared secret as a byte array.
    ///
    /// Note: This consumes the secret to transfer ownership.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SHARED_SECRET_SIZE] {
        self.bytes
    }
}

impl ConstantTimeEq for X448SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for X448SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for X448SharedSecret {}

impl core::fmt::Debug for X448SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X448SharedSecret")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let secret = X448Secret::generate().unwrap();
        let public = secret.public_key();

        assert_eq!(public.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_diffie_hellman_agreement() {
        // Alice
        let alice_secret = X448Secret::generate().unwrap();
        let alice_public = alice_secret.public_key();

        // Bob
        let bob_secret = X448Secret::generate().unwrap();
        let bob_public = bob_secret.public_key();

        // Both compute shared secret
        let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
        let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();

        // Shared secrets should be equal
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let alice_secret = X448Secret::generate().unwrap();
        let bob_secret = X448Secret::generate().unwrap();
        let charlie_secret = X448Secret::generate().unwrap();

        let bob_public = bob_secret.public_key();
        let charlie_public = charlie_secret.public_key();

        let shared_with_bob = alice_secret.diffie_hellman(&bob_public).unwrap();
        let shared_with_charlie = alice_secret.diffie_hellman(&charlie_public).unwrap();

        // Different parties should produce different shared secrets
        assert_ne!(shared_with_bob, shared_with_charlie);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let secret = X448Secret::generate().unwrap();
        let public = secret.public_key();

        let bytes = public.to_bytes();
        let recovered = X448Public::from_bytes(&bytes).unwrap();

        assert_eq!(public, recovered);
    }

    #[test]
    fn test_invalid_public_key_length() {
        let result = X448Public::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength { expected: 56, actual: 50 })
        ));
    }

    #[test]
    fn test_secret_key_clamping() {
        // Create a key with specific bytes that would be affected by clamping
        let bytes = [0xffu8; SECRET_KEY_SIZE];
        let secret = X448Secret::from_bytes(bytes);

        // Clamping should clear lowest 2 bits of first byte
        assert_eq!(secret.as_bytes()[0] & 0x03, 0x00);

        // Clamping should set highest bit of last byte
        assert_eq!(secret.as_bytes()[55] & 0x80, 0x80);
    }

    #[test]
    fn test_shared_secret_constant_time_eq() {
        let alice = X448Secret::generate().unwrap();
        let bob = X448Secret::generate().unwrap();

        let shared1 = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared2 = alice.diffie_hellman(&bob.public_key()).unwrap();

        // Same computation should produce same result
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_zero_public_key_rejected() {
        let secret = X448Secret::generate().unwrap();
        let zero_public = X448Public::from_array([0u8; PUBLIC_KEY_SIZE]);

        // DH with zero point should fail
        let result = secret.diffie_hellman(&zero_public);
        assert!(matches!(result, Err(CryptoError::DecapsulationFailed)));
    }

    // RFC 7748 Test Vector
    // Note: RFC 7748 test vectors show raw (unclamped) private keys.
    // The X448 function internally applies clamping (decodeScalar448).
    // Our from_bytes method applies clamping, so the test vectors work correctly.
    #[test]
    fn test_rfc7748_vector() {
        // From RFC 7748 Section 6.2
        let alice_private = hex::decode(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        ).unwrap();

        let alice_public_expected = hex::decode(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        ).unwrap();

        let bob_private = hex::decode(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        ).unwrap();

        let bob_public_expected = hex::decode(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        ).unwrap();

        let shared_expected = hex::decode(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        ).unwrap();

        // Create keys from test vectors using from_bytes (which applies clamping)
        let mut alice_bytes = [0u8; 56];
        alice_bytes.copy_from_slice(&alice_private);
        let alice_secret = X448Secret::from_bytes(alice_bytes);

        let mut bob_bytes = [0u8; 56];
        bob_bytes.copy_from_slice(&bob_private);
        let bob_secret = X448Secret::from_bytes(bob_bytes);

        // Verify public keys
        let alice_public = alice_secret.public_key();
        let bob_public = bob_secret.public_key();

        assert_eq!(alice_public.as_bytes().as_slice(), alice_public_expected.as_slice());
        assert_eq!(bob_public.as_bytes().as_slice(), bob_public_expected.as_slice());

        // Verify shared secret
        let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
        let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();

        assert_eq!(alice_shared.as_bytes().as_slice(), shared_expected.as_slice());
        assert_eq!(bob_shared.as_bytes().as_slice(), shared_expected.as_slice());
    }
}
