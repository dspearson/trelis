//! sntrup761 Key Encapsulation Mechanism.
//!
//! This module provides sntrup761 post-quantum KEM as specified by NTRU Prime.
//! sntrup761 is a lattice-based key encapsulation mechanism providing
//! approximately 128-bit security against quantum attacks (NIST Level 3).
//!
//! # Key Sizes
//!
//! - Public key: 1,158 bytes
//! - Secret key: 1,763 bytes
//! - Ciphertext: 1,039 bytes
//! - Shared secret: 32 bytes
//!
//! # Security Properties
//!
//! - Post-quantum security (lattice-based)
//! - IND-CCA2 security
//! - Implicit rejection (decapsulation always outputs a valid-looking shared secret)
//!
//! # Platform Support
//!
//! This module provides the C FFI backend using `pqcrypto-ntruprime`.
//! It requires the `std` feature and native compilation.
//!
//! For WASM/browser builds, use the `wasm` feature which provides a pure
//! Rust implementation (`pure_rust`) with identical wire format encoding.
//! Both backends produce **byte-for-byte identical outputs** and are fully
//! interoperable.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "std")]
//! # fn main() {
//! use trelis_primitives::sntrup761::{Sntrup761SecretKey, Sntrup761PublicKey};
//!
//! // Generate a keypair
//! let secret_key = Sntrup761SecretKey::generate();
//! let public_key = secret_key.public_key();
//!
//! // Encapsulate: sender creates shared secret and ciphertext
//! let (shared_secret, ciphertext) = public_key.encapsulate();
//!
//! // Decapsulate: receiver recovers shared secret from ciphertext
//! let recovered_secret = secret_key.decapsulate(&ciphertext).unwrap();
//!
//! assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

#[cfg(feature = "std")]
use pqcrypto_ntruprime::sntrup761;
#[cfg(feature = "std")]
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PkTrait, SecretKey as SkTrait,
    SharedSecret as SsTrait,
};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use trelis_error::{CryptoError, Result};

/// Size of sntrup761 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1158;

/// Size of sntrup761 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 1763;

/// Size of sntrup761 ciphertext in bytes.
pub const CIPHERTEXT_SIZE: usize = 1039;

/// Size of sntrup761 shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

// ============================================================================
// Implementation (std feature only)
// ============================================================================

/// sntrup761 secret key.
///
/// Used for decapsulating ciphertexts to recover shared secrets.
/// Contains both the secret key material and a cached copy of the public key.
#[cfg(feature = "std")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sntrup761SecretKey {
    bytes: [u8; SECRET_KEY_SIZE],
    #[zeroize(skip)]
    public_key_bytes: [u8; PUBLIC_KEY_SIZE],
}

#[cfg(feature = "std")]
impl Sntrup761SecretKey {
    /// Generates a new random keypair and returns the secret key.
    #[must_use]
    pub fn generate() -> Self {
        let (pk, sk) = sntrup761::keypair();

        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes.copy_from_slice(sk.as_bytes());

        let mut public_key_bytes = [0u8; PUBLIC_KEY_SIZE];
        public_key_bytes.copy_from_slice(pk.as_bytes());

        Self {
            bytes,
            public_key_bytes,
        }
    }

    /// Generates a keypair deterministically from a 32-byte seed.
    ///
    /// Uses the pure Rust sntrup761 implementation with a BLAKE3-seeded RNG
    /// to generate deterministic keypairs. The same seed always produces
    /// the same keypair.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed value
    ///
    /// # Note
    ///
    /// This uses the pure Rust implementation (same as WASM backend) rather
    /// than the C FFI, since the C implementation doesn't support seeded
    /// key generation.
    #[must_use]
    pub fn generate_from_seed(seed: &[u8; 32]) -> Self {
        // Use the pure Rust implementation for deterministic keygen
        let wasm_sk = super::pure_rust::Sntrup761SecretKey::generate_from_seed(seed);

        // Convert to std format
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes.copy_from_slice(wasm_sk.as_bytes());

        // Extract public key from secret key structure
        let pk_start = 2 * 191;
        let mut public_key_bytes = [0u8; PUBLIC_KEY_SIZE];
        public_key_bytes.copy_from_slice(&bytes[pk_start..pk_start + PUBLIC_KEY_SIZE]);

        Self {
            bytes,
            public_key_bytes,
        }
    }

    /// Creates a secret key from raw bytes.
    ///
    /// # Note
    ///
    /// This reconstructs the secret key from its serialised form. The public
    /// key is derived from the last portion of the secret key bytes as per
    /// the sntrup761 key format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        // The public key is embedded in the secret key structure
        // In sntrup761, the secret key contains: (f, ginv, pk, rho)
        // where pk starts at offset 2*191 = 382 and is 1158 bytes
        let pk_start = 2 * 191; // f and ginv each take 191 bytes in packed form
        let mut public_key_bytes = [0u8; PUBLIC_KEY_SIZE];
        public_key_bytes.copy_from_slice(&bytes[pk_start..pk_start + PUBLIC_KEY_SIZE]);

        Ok(Self {
            bytes: key_bytes,
            public_key_bytes,
        })
    }

    /// Returns the secret key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derives the public key from this secret key.
    #[must_use]
    pub fn public_key(&self) -> Sntrup761PublicKey {
        Sntrup761PublicKey {
            bytes: self.public_key_bytes,
        }
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    ///
    /// # Security
    ///
    /// sntrup761 provides implicit rejection: if decapsulation fails,
    /// a pseudorandom value derived from the ciphertext and secret key
    /// is returned instead of an error. This prevents timing attacks.
    pub fn decapsulate(&self, ciphertext: &Sntrup761Ciphertext) -> Result<Sntrup761SharedSecret> {
        let sk = sntrup761::SecretKey::from_bytes(&self.bytes)
            .map_err(|_| CryptoError::DecapsulationFailed)?;

        let ct = sntrup761::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|_| CryptoError::DecapsulationFailed)?;

        let ss = sntrup761::decapsulate(&ct, &sk);

        let mut ss_bytes = [0u8; SHARED_SECRET_SIZE];
        ss_bytes.copy_from_slice(ss.as_bytes());

        Ok(Sntrup761SharedSecret { bytes: ss_bytes })
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for Sntrup761SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// sntrup761 public key.
///
/// Used for encapsulating shared secrets. Can be freely shared.
#[cfg(feature = "std")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sntrup761PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

#[cfg(feature = "std")]
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
    /// The shared secret should be used as input to a KDF before use as a key.
    /// The ciphertext should be sent to the key owner for decapsulation.
    #[must_use]
    pub fn encapsulate(&self) -> (Sntrup761SharedSecret, Sntrup761Ciphertext) {
        let pk = sntrup761::PublicKey::from_bytes(&self.bytes)
            .expect("valid public key bytes should parse");

        let (ss, ct) = sntrup761::encapsulate(&pk);

        let mut ss_bytes = [0u8; SHARED_SECRET_SIZE];
        ss_bytes.copy_from_slice(ss.as_bytes());

        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(ct.as_bytes());

        (
            Sntrup761SharedSecret { bytes: ss_bytes },
            Sntrup761Ciphertext { bytes: ct_bytes },
        )
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for Sntrup761PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sntrup761PublicKey")
            .field("bytes", &"[1158 bytes]")
            .finish()
    }
}

/// sntrup761 ciphertext.
///
/// The result of encapsulation, sent to the key owner for decapsulation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sntrup761Ciphertext {
    bytes: [u8; CIPHERTEXT_SIZE],
}

impl Sntrup761Ciphertext {
    /// Creates a ciphertext from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CIPHERTEXT_SIZE {
            return Err(CryptoError::DecapsulationFailed);
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
///
/// The result of encapsulation or decapsulation. This should be used as
/// input to a KDF before use as a key.
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
// Tests
// ============================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        assert_eq!(sk.as_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(pk.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (ss1, ct) = pk.encapsulate();
        let ss2 = sk.decapsulate(&ct).expect("decapsulation should succeed");

        assert!(bool::from(ss1.ct_eq(&ss2)));
    }

    #[test]
    fn test_multiple_encapsulations() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        // Multiple encapsulations should produce different ciphertexts
        let (ss1, ct1) = pk.encapsulate();
        let (ss2, ct2) = pk.encapsulate();

        // Shared secrets and ciphertexts should differ
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert!(!bool::from(ss1.ct_eq(&ss2)));

        // But both should decapsulate correctly
        let recovered1 = sk.decapsulate(&ct1).unwrap();
        let recovered2 = sk.decapsulate(&ct2).unwrap();

        assert!(bool::from(ss1.ct_eq(&recovered1)));
        assert!(bool::from(ss2.ct_eq(&recovered2)));
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let sk1 = Sntrup761SecretKey::generate();
        let pk1 = sk1.public_key();

        let sk2 = Sntrup761SecretKey::generate();
        let pk2 = sk2.public_key();

        let (ss1, _) = pk1.encapsulate();
        let (ss2, _) = pk2.encapsulate();

        assert!(!bool::from(ss1.ct_eq(&ss2)));
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(PUBLIC_KEY_SIZE, 1158);
        assert_eq!(SECRET_KEY_SIZE, 1763);
        assert_eq!(CIPHERTEXT_SIZE, 1039);
        assert_eq!(SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let sk = Sntrup761SecretKey::generate();
        let pk1 = sk.public_key();

        let pk2 = Sntrup761PublicKey::from_bytes(pk1.as_bytes()).unwrap();

        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_secret_key_from_bytes_roundtrip() {
        let sk1 = Sntrup761SecretKey::generate();
        let pk1 = sk1.public_key();

        let sk2 = Sntrup761SecretKey::from_bytes(sk1.as_bytes()).unwrap();
        let pk2 = sk2.public_key();

        // Public keys should match
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());

        // Both should decapsulate correctly
        let (ss, ct) = pk1.encapsulate();
        let recovered = sk2.decapsulate(&ct).unwrap();

        assert!(bool::from(ss.ct_eq(&recovered)));
    }

    #[test]
    fn test_ciphertext_from_bytes() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (ss1, ct1) = pk.encapsulate();

        let ct2 = Sntrup761Ciphertext::from_bytes(ct1.as_bytes()).unwrap();
        let ss2 = sk.decapsulate(&ct2).unwrap();

        assert!(bool::from(ss1.ct_eq(&ss2)));
    }

    #[test]
    fn test_ciphertext_sizes() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (_, ct) = pk.encapsulate();

        assert_eq!(ct.as_bytes().len(), CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_shared_secret_constant_time_eq() {
        let sk = Sntrup761SecretKey::generate();
        let pk = sk.public_key();

        let (ss1, ct) = pk.encapsulate();
        let ss2 = sk.decapsulate(&ct).unwrap();

        // Same secrets should be equal
        assert!(bool::from(ss1.ct_eq(&ss2)));

        // Different encapsulations should produce different secrets
        let (ss3, _) = pk.encapsulate();
        assert!(!bool::from(ss1.ct_eq(&ss3)));
    }

    #[test]
    fn test_invalid_public_key_length() {
        let result = Sntrup761PublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let result = Sntrup761Ciphertext::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }
}
