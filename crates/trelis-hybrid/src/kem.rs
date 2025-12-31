//! Hybrid Key Encapsulation Mechanism (X448 + sntrup761).
//!
//! This module provides hybrid KEM that combines classical X448 Diffie-Hellman
//! with post-quantum sntrup761 KEM. Both components contribute to the final
//! shared secret via BLAKE3 key derivation.
//!
//! # Key Sizes
//!
//! - Public key: 1,214 bytes (X448 56B + sntrup761 1,158B)
//! - Encapsulation: 1,095 bytes (X448 ephemeral 56B + sntrup761 ciphertext 1,039B)
//! - Shared secret: 32 bytes (BLAKE3 combined)
//!
//! # Example
//!
//! ```
//! use trelis_hybrid::kem::HybridKemKeypair;
//!
//! // Recipient generates keypair
//! let keypair = HybridKemKeypair::generate().unwrap();
//! let public_key = keypair.public_key().clone();
//!
//! // Sender encapsulates
//! let (shared_secret_sender, encapsulation) = public_key.encapsulate().unwrap();
//!
//! // Recipient decapsulates
//! let shared_secret_recipient = keypair.decapsulate(&encapsulation).unwrap();
//!
//! assert_eq!(shared_secret_sender.as_bytes(), shared_secret_recipient.as_bytes());
//! ```

use trelis_primitives::{
    Sntrup761Ciphertext, Sntrup761PublicKey, Sntrup761SecretKey, X448Public, X448Secret,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::combiner::HybridSharedSecret;
use trelis_error::{CryptoError, Result};

/// Size of X448 public key in bytes.
pub const X448_PK_SIZE: usize = 56;

/// Size of sntrup761 public key in bytes.
pub const SNTRUP_PK_SIZE: usize = 1158;

/// Size of hybrid KEM public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = X448_PK_SIZE + SNTRUP_PK_SIZE;

/// Size of X448 ephemeral public key in bytes.
pub const X448_EPH_SIZE: usize = 56;

/// Size of sntrup761 ciphertext in bytes.
pub const SNTRUP_CT_SIZE: usize = 1039;

/// Size of hybrid encapsulation in bytes.
pub const ENCAPSULATION_SIZE: usize = X448_EPH_SIZE + SNTRUP_CT_SIZE;

/// Size of X448 secret key in bytes.
pub const X448_SK_SIZE: usize = 56;

/// Size of sntrup761 secret key in bytes.
pub const SNTRUP_SK_SIZE: usize = 1763;

/// Size of hybrid KEM secret key in bytes.
pub const SECRET_KEY_SIZE: usize = X448_SK_SIZE + SNTRUP_SK_SIZE;

/// Hybrid KEM keypair (X448 + sntrup761).
///
/// This keypair contains both classical and post-quantum KEM keys.
/// The combined shared secret provides security as long as either
/// algorithm remains secure.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemKeypair {
    #[zeroize(skip)]
    public_key: HybridKemPublicKey,
    x448_secret: X448Secret,
    sntrup_secret: Sntrup761SecretKey,
}

impl HybridKemKeypair {
    /// Generates a new random hybrid KEM keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    pub fn generate() -> Result<Self> {
        let x448_secret = X448Secret::generate()?;
        let sntrup_secret = Sntrup761SecretKey::generate();

        let public_key = HybridKemPublicKey {
            x448: x448_secret.public_key(),
            sntrup: sntrup_secret.public_key(),
        };

        Ok(Self {
            public_key,
            x448_secret,
            sntrup_secret,
        })
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &HybridKemPublicKey {
        &self.public_key
    }

    /// Serialises the secret key to bytes.
    ///
    /// Format: X448 secret (56 bytes) || sntrup761 secret (1,763 bytes)
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material and should be
    /// handled securely (encrypted storage, zeroization after use).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        bytes[..X448_SK_SIZE].copy_from_slice(self.x448_secret.as_bytes());
        bytes[X448_SK_SIZE..].copy_from_slice(self.sntrup_secret.as_bytes());
        bytes
    }

    /// Deserialises a keypair from secret key bytes.
    ///
    /// The public key is derived from the secret key components.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 1,819 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut x448_bytes = [0u8; X448_SK_SIZE];
        x448_bytes.copy_from_slice(&bytes[..X448_SK_SIZE]);
        let x448_secret = X448Secret::from_bytes(x448_bytes);

        let sntrup_secret = Sntrup761SecretKey::from_bytes(&bytes[X448_SK_SIZE..])?;

        let public_key = HybridKemPublicKey {
            x448: x448_secret.public_key(),
            sntrup: sntrup_secret.public_key(),
        };

        Ok(Self {
            public_key,
            x448_secret,
            sntrup_secret,
        })
    }

    /// Decapsulates a hybrid encapsulation to recover the shared secret.
    ///
    /// # Arguments
    ///
    /// * `encapsulation` - The hybrid encapsulation from the sender.
    ///
    /// # Returns
    ///
    /// The combined shared secret (32 bytes).
    ///
    /// # Errors
    ///
    /// Returns `DecapsulationFailed` if decapsulation fails.
    pub fn decapsulate(&self, encapsulation: &HybridEncapsulation) -> Result<HybridSharedSecret> {
        // X448 DH with ephemeral public key
        let x448_ss = self
            .x448_secret
            .diffie_hellman(&encapsulation.x448_ephemeral)?;

        // sntrup761 decapsulation
        let sntrup_ss = self
            .sntrup_secret
            .decapsulate(&encapsulation.sntrup_ciphertext)?;

        // Combine shared secrets
        Ok(HybridSharedSecret::combine(
            x448_ss.as_bytes(),
            sntrup_ss.as_bytes(),
        ))
    }

    /// Returns the X448 secret key reference (for internal use).
    #[cfg(feature = "expose-internals")]
    #[must_use]
    pub fn x448_secret(&self) -> &X448Secret {
        &self.x448_secret
    }

    /// Returns the sntrup761 secret key reference (for internal use).
    #[cfg(feature = "expose-internals")]
    #[must_use]
    pub fn sntrup_secret(&self) -> &Sntrup761SecretKey {
        &self.sntrup_secret
    }

    /// Returns the X448 public key (for internal use in X3DH-PQ).
    #[cfg(feature = "expose-internals")]
    #[must_use]
    pub fn x448_public(&self) -> &X448Public {
        &self.public_key.x448
    }

    /// Performs X448 DH with the secret key (for X3DH-PQ).
    #[cfg(feature = "expose-internals")]
    pub fn x448_dh(
        &self,
        their_public: &X448Public,
    ) -> Result<trelis_primitives::X448SharedSecret> {
        self.x448_secret.diffie_hellman(their_public)
    }

    /// Decapsulates a sntrup761 ciphertext only (for X3DH-PQ).
    #[cfg(feature = "expose-internals")]
    pub fn sntrup_decapsulate(
        &self,
        ciphertext: &Sntrup761Ciphertext,
    ) -> Result<trelis_primitives::Sntrup761SharedSecret> {
        self.sntrup_secret.decapsulate(ciphertext)
    }
}

impl core::fmt::Debug for HybridKemKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridKemKeypair")
            .field("public_key", &self.public_key)
            .field("x448_secret", &"[redacted]")
            .field("sntrup_secret", &"[redacted]")
            .finish()
    }
}

/// Hybrid KEM public key (X448 + sntrup761).
///
/// This public key is used for encapsulation to create a hybrid shared secret.
#[derive(Clone)]
pub struct HybridKemPublicKey {
    /// X448 public key (56 bytes)
    pub x448: X448Public,
    /// sntrup761 public key (1,158 bytes)
    pub sntrup: Sntrup761PublicKey,
}

impl HybridKemPublicKey {
    /// Serialises the public key to bytes.
    ///
    /// Format: X448 (56 bytes) || sntrup761 (1,158 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes[..X448_PK_SIZE].copy_from_slice(self.x448.as_bytes());
        bytes[X448_PK_SIZE..].copy_from_slice(self.sntrup.as_bytes());
        bytes
    }

    /// Deserialises a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 1,214 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let x448 = X448Public::from_bytes(&bytes[..X448_PK_SIZE])?;
        let sntrup = Sntrup761PublicKey::from_bytes(&bytes[X448_PK_SIZE..])?;

        Ok(Self { x448, sntrup })
    }

    /// Returns the X448 public key (for internal use in X3DH-PQ).
    #[cfg(feature = "expose-internals")]
    #[must_use]
    pub fn x448(&self) -> &X448Public {
        &self.x448
    }

    /// Returns the sntrup761 public key (for internal use in X3DH-PQ).
    #[cfg(feature = "expose-internals")]
    #[must_use]
    pub fn sntrup(&self) -> &Sntrup761PublicKey {
        &self.sntrup
    }

    /// Encapsulates to the sntrup761 public key only (for X3DH-PQ).
    ///
    /// Returns (shared_secret, ciphertext).
    #[cfg(feature = "expose-internals")]
    pub fn sntrup_encapsulate(
        &self,
    ) -> (
        trelis_primitives::Sntrup761SharedSecret,
        Sntrup761Ciphertext,
    ) {
        self.sntrup.encapsulate()
    }

    /// Encapsulates to this public key, producing a shared secret and encapsulation.
    ///
    /// # Returns
    ///
    /// A tuple of (shared_secret, encapsulation). The encapsulation should be sent
    /// to the key owner for decapsulation.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if random number generation fails.
    pub fn encapsulate(&self) -> Result<(HybridSharedSecret, HybridEncapsulation)> {
        // Generate ephemeral X448 keypair
        let x448_ephemeral_secret = X448Secret::generate()?;
        let x448_ephemeral = x448_ephemeral_secret.public_key();

        // X448 DH with recipient
        let x448_ss = x448_ephemeral_secret.diffie_hellman(&self.x448)?;

        // sntrup761 encapsulation
        let (sntrup_ss, sntrup_ciphertext) = self.sntrup.encapsulate();

        // Combine shared secrets
        let shared_secret = HybridSharedSecret::combine(x448_ss.as_bytes(), sntrup_ss.as_bytes());

        let encapsulation = HybridEncapsulation {
            x448_ephemeral,
            sntrup_ciphertext,
        };

        Ok((shared_secret, encapsulation))
    }
}

impl PartialEq for HybridKemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.x448 == other.x448 && self.sntrup == other.sntrup
    }
}

impl Eq for HybridKemPublicKey {}

impl core::fmt::Debug for HybridKemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridKemPublicKey")
            .field("x448", &self.x448)
            .field("sntrup", &"[1158 bytes]")
            .finish()
    }
}

/// Hybrid encapsulation (X448 ephemeral + sntrup761 ciphertext).
///
/// This is sent from the encapsulating party (sender) to the key owner
/// (recipient) for decapsulation.
#[derive(Clone)]
pub struct HybridEncapsulation {
    /// X448 ephemeral public key (56 bytes)
    pub x448_ephemeral: X448Public,
    /// sntrup761 ciphertext (1,039 bytes)
    pub sntrup_ciphertext: Sntrup761Ciphertext,
}

impl HybridEncapsulation {
    /// Serialises the encapsulation to bytes.
    ///
    /// Format: X448 ephemeral (56 bytes) || sntrup761 ciphertext (1,039 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENCAPSULATION_SIZE] {
        let mut bytes = [0u8; ENCAPSULATION_SIZE];
        bytes[..X448_EPH_SIZE].copy_from_slice(self.x448_ephemeral.as_bytes());
        bytes[X448_EPH_SIZE..].copy_from_slice(self.sntrup_ciphertext.as_bytes());
        bytes
    }

    /// Deserialises an encapsulation from bytes.
    ///
    /// # Errors
    ///
    /// Returns `DecapsulationFailed` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCAPSULATION_SIZE {
            return Err(CryptoError::DecapsulationFailed);
        }

        let x448_ephemeral = X448Public::from_bytes(&bytes[..X448_EPH_SIZE])?;
        let sntrup_ciphertext = Sntrup761Ciphertext::from_bytes(&bytes[X448_EPH_SIZE..])?;

        Ok(Self {
            x448_ephemeral,
            sntrup_ciphertext,
        })
    }
}

impl core::fmt::Debug for HybridEncapsulation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridEncapsulation")
            .field("x448_ephemeral", &self.x448_ephemeral)
            .field("sntrup_ciphertext", &"[1039 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(PUBLIC_KEY_SIZE, 1214);
    }

    #[test]
    fn test_encapsulation_size() {
        assert_eq!(ENCAPSULATION_SIZE, 1095);
    }

    #[test]
    fn test_key_generation() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let pk_bytes = keypair.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let public_key = keypair.public_key().clone();

        // Sender encapsulates
        let (shared_secret_sender, encapsulation) = public_key.encapsulate().unwrap();

        // Recipient decapsulates
        let shared_secret_recipient = keypair.decapsulate(&encapsulation).unwrap();

        assert_eq!(
            shared_secret_sender.as_bytes(),
            shared_secret_recipient.as_bytes()
        );
    }

    #[test]
    fn test_encapsulation_serialisation() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let (_, encapsulation) = keypair.public_key().encapsulate().unwrap();

        let bytes = encapsulation.to_bytes();
        assert_eq!(bytes.len(), ENCAPSULATION_SIZE);

        let recovered = HybridEncapsulation::from_bytes(&bytes).unwrap();

        // Decapsulate with recovered encapsulation
        let ss1 = keypair.decapsulate(&encapsulation).unwrap();
        let ss2 = keypair.decapsulate(&recovered).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_public_key_serialisation() {
        let keypair = HybridKemKeypair::generate().unwrap();
        let pk = keypair.public_key();

        let bytes = pk.to_bytes();
        let recovered = HybridKemPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, &recovered);
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let keypair1 = HybridKemKeypair::generate().unwrap();
        let keypair2 = HybridKemKeypair::generate().unwrap();

        let (ss1, _) = keypair1.public_key().encapsulate().unwrap();
        let (ss2, _) = keypair2.public_key().encapsulate().unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = HybridKemKeypair::generate().unwrap();
        let keypair2 = HybridKemKeypair::generate().unwrap();

        let (shared_secret_sender, encapsulation) = keypair1.public_key().encapsulate().unwrap();

        // Decapsulate with wrong key produces different secret
        let shared_secret_wrong = keypair2.decapsulate(&encapsulation).unwrap();
        assert_ne!(
            shared_secret_sender.as_bytes(),
            shared_secret_wrong.as_bytes()
        );
    }

    #[test]
    fn test_multiple_encapsulations() {
        let keypair = HybridKemKeypair::generate().unwrap();

        let (ss1, enc1) = keypair.public_key().encapsulate().unwrap();
        let (ss2, enc2) = keypair.public_key().encapsulate().unwrap();

        // Different random values produce different results
        assert_ne!(ss1, ss2);
        assert_ne!(enc1.to_bytes(), enc2.to_bytes());

        // But both should decapsulate correctly
        let ss1_dec = keypair.decapsulate(&enc1).unwrap();
        let ss2_dec = keypair.decapsulate(&enc2).unwrap();

        assert_eq!(ss1, ss1_dec);
        assert_eq!(ss2, ss2_dec);
    }
}
