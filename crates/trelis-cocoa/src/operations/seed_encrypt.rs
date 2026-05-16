//! Seed encryption for CoCoA path updates.
//!
//! This module handles the encryption and decryption of path seeds
//! in CoCoA-SA. Each path node's seed is encrypted to members who
//! need it to derive the shared state.
//!
//! # Encryption Scheme
//!
//! Seeds are encrypted using:
//! 1. Hybrid KEM (X448 + sntrup761) encapsulation to the recipient's public key
//! 2. AEAD (XChaCha20-Poly1305) encryption of the seed using the KEM shared secret
//!
//! The AAD (additional authenticated data) includes the tree position
//! to bind the ciphertext to its intended location.
//!
//! # Wire Format
//!
//! ```text
//! EncryptedSeed {
//!     encapsulation: [u8; 1095]  // Hybrid KEM encapsulation
//!     ciphertext: [u8; 48]       // AEAD encrypted seed (32 bytes + 16 byte tag)
//! }
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::kem::ENCAPSULATION_SIZE as HYBRID_ENCAPSULATION_SIZE;
use trelis_hybrid::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};
use trelis_primitives::aead::{self, AeadKey, Nonce, TAG_SIZE as AEAD_TAG_SIZE};

use crate::operations::seed_chain::{SEED_SIZE, Seed};
use crate::tree::NodeIndex;

/// Size of the AEAD-encrypted seed including the authentication tag.
pub const ENCRYPTED_SEED_CIPHERTEXT_SIZE: usize = SEED_SIZE + AEAD_TAG_SIZE;

/// Size of an encrypted seed in bytes (hybrid encapsulation || AEAD ciphertext).
pub const ENCRYPTED_SEED_SIZE: usize = HYBRID_ENCAPSULATION_SIZE + ENCRYPTED_SEED_CIPHERTEXT_SIZE;

/// AEAD nonce for seed encryption (all zeros - single-use key).
///
/// Since each KEM encapsulation produces a unique key, we can use
/// a fixed nonce. The key is only used once per encapsulation.
const SEED_ENCRYPTION_NONCE: [u8; 24] = [0u8; 24];

/// An encrypted seed ready for transmission.
#[derive(Clone)]
pub struct EncryptedNodeSeed {
    /// The KEM encapsulation (ephemeral key + sntrup ciphertext).
    pub encapsulation: HybridEncapsulation,
    /// The AEAD-encrypted seed (seed bytes + AEAD tag).
    pub ciphertext: [u8; ENCRYPTED_SEED_CIPHERTEXT_SIZE],
}

impl EncryptedNodeSeed {
    /// Returns the size of an encrypted seed in bytes.
    #[must_use]
    pub const fn size() -> usize {
        ENCRYPTED_SEED_SIZE
    }

    /// Serialises the encrypted seed to bytes.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCRYPTED_SEED_SIZE);
        bytes.extend_from_slice(&self.encapsulation.to_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialises an encrypted seed from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCRYPTED_SEED_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let encapsulation = HybridEncapsulation::from_bytes(&bytes[..HYBRID_ENCAPSULATION_SIZE])?;
        let mut ciphertext = [0u8; ENCRYPTED_SEED_CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&bytes[HYBRID_ENCAPSULATION_SIZE..]);

        Ok(Self {
            encapsulation,
            ciphertext,
        })
    }
}

/// Encrypts a seed to a single recipient.
///
/// Uses hybrid KEM encapsulation followed by AEAD encryption.
/// The tree position is included in the AAD to prevent cross-position attacks.
///
/// # Arguments
///
/// * `seed` - The 32-byte seed to encrypt
/// * `recipient_public_key` - The recipient's hybrid KEM public key
/// * `tree_position` - The node index in the tree (for AAD binding)
///
/// # Returns
///
/// An `EncryptedNodeSeed` containing the encapsulation and ciphertext.
///
/// # Errors
///
/// Returns an error if KEM encapsulation or AEAD encryption fails.
pub fn encrypt_seed_to_recipient(
    seed: &Seed,
    recipient_public_key: &HybridKemPublicKey,
    tree_position: &NodeIndex,
) -> Result<EncryptedNodeSeed> {
    // Encapsulate to get shared secret and encapsulation
    let (shared_secret, encapsulation) = recipient_public_key.encapsulate()?;

    // Derive AEAD key from shared secret
    let aead_key = AeadKey::from_bytes(*shared_secret.as_bytes());
    let nonce = Nonce::from_bytes(SEED_ENCRYPTION_NONCE);

    // Build AAD: tree_position || "cocoa-seed-encrypt"
    let aad = build_seed_aad(tree_position);

    // Encrypt the seed
    let ciphertext_vec = aead::encrypt(&aead_key, &nonce, seed, &aad)?;

    // Convert to fixed-size array
    // AEAD should always produce SEED_SIZE bytes plaintext + AEAD_TAG_SIZE bytes tag.
    if ciphertext_vec.len() != ENCRYPTED_SEED_CIPHERTEXT_SIZE {
        return Err(CryptoError::AeadAuthenticationFailed);
    }
    let mut ciphertext = [0u8; ENCRYPTED_SEED_CIPHERTEXT_SIZE];
    ciphertext.copy_from_slice(&ciphertext_vec);

    Ok(EncryptedNodeSeed {
        encapsulation,
        ciphertext,
    })
}

/// Decrypts a seed using our keypair.
///
/// # Arguments
///
/// * `encrypted` - The encrypted seed to decrypt
/// * `our_keypair` - Our hybrid KEM keypair
/// * `tree_position` - The node index in the tree (for AAD verification)
///
/// # Returns
///
/// The decrypted 32-byte seed.
///
/// # Errors
///
/// Returns an error if decapsulation or AEAD decryption fails.
pub fn decrypt_seed(
    encrypted: &EncryptedNodeSeed,
    our_keypair: &HybridKemKeypair,
    tree_position: &NodeIndex,
) -> Result<Seed> {
    // Decapsulate to get shared secret
    let shared_secret = our_keypair.decapsulate(&encrypted.encapsulation)?;

    // Derive AEAD key
    let aead_key = AeadKey::from_bytes(*shared_secret.as_bytes());
    let nonce = Nonce::from_bytes(SEED_ENCRYPTION_NONCE);

    // Build AAD (must match encryption)
    let aad = build_seed_aad(tree_position);

    // Decrypt the seed
    let plaintext = aead::decrypt(&aead_key, &nonce, &encrypted.ciphertext, &aad)?;

    // Convert to fixed-size array
    if plaintext.len() != 32 {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);

    Ok(seed)
}

/// Encrypts a seed to multiple recipients in a resolution set.
///
/// This is used when a path node's seed needs to be distributed to
/// all members in the resolution of the sibling subtree.
///
/// # Arguments
///
/// * `seed` - The 32-byte seed to encrypt
/// * `resolution` - The node indices in the resolution set
/// * `public_keys` - The public keys corresponding to each resolution node
/// * `tree_position` - The tree position for AAD binding
///
/// # Returns
///
/// A vector of encrypted seeds, one for each recipient.
///
/// # Errors
///
/// Returns an error if encryption to any recipient fails.
#[cfg(feature = "alloc")]
pub fn encrypt_seed_to_resolution(
    seed: &Seed,
    resolution: &[NodeIndex],
    public_keys: &[&HybridKemPublicKey],
    tree_position: &NodeIndex,
) -> Result<Vec<EncryptedNodeSeed>> {
    if resolution.len() != public_keys.len() {
        return Err(CryptoError::MalformedMessage);
    }

    let mut encrypted_seeds = Vec::with_capacity(resolution.len());

    for pk in public_keys {
        let encrypted = encrypt_seed_to_recipient(seed, pk, tree_position)?;
        encrypted_seeds.push(encrypted);
    }

    Ok(encrypted_seeds)
}

/// Protocol version for seed encryption AAD format.
/// Increment when making breaking changes to the AAD structure.
const SEED_AAD_VERSION: u16 = 1;

/// Size of the canonical seed AAD format in bytes.
///
/// Layout:
/// - 2 bytes: protocol version (u16 LE)
/// - 4 bytes: tree depth (u32 LE)
/// - 4 bytes: tree position (u32 LE)
/// - 18 bytes: domain separator "cocoa-seed-encrypt"
pub const SEED_AAD_SIZE: usize = 28;

/// Builds the AAD (Additional Authenticated Data) for seed encryption.
///
/// The AAD uses a canonical format to bind the ciphertext to:
/// - Protocol version (for forward compatibility)
/// - Tree position (depth + position)
/// - Domain separator string
///
/// # Format
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 2 | Protocol version (u16 LE) |
/// | 2 | 4 | Tree depth (u32 LE) |
/// | 6 | 4 | Tree position (u32 LE) |
/// | 10 | 18 | Domain separator "cocoa-seed-encrypt" |
fn build_seed_aad(tree_position: &NodeIndex) -> [u8; SEED_AAD_SIZE] {
    let mut aad = [0u8; SEED_AAD_SIZE];

    // Protocol version (2 bytes)
    aad[0..2].copy_from_slice(&SEED_AAD_VERSION.to_le_bytes());

    // Tree depth (4 bytes)
    aad[2..6].copy_from_slice(&tree_position.depth.to_le_bytes());

    // Tree position (4 bytes)
    aad[6..10].copy_from_slice(&tree_position.position.to_le_bytes());

    // Domain separator (18 bytes)
    aad[10..].copy_from_slice(b"cocoa-seed-encrypt");

    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> HybridKemKeypair {
        HybridKemKeypair::generate().unwrap()
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed = [0x42u8; 32];
        let keypair = test_keypair();
        let position = NodeIndex::new(2, 3);

        let encrypted = encrypt_seed_to_recipient(&seed, keypair.public_key(), &position).unwrap();
        let decrypted = decrypt_seed(&encrypted, &keypair, &position).unwrap();

        assert_eq!(decrypted, seed);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypted_seed_serialisation() {
        let seed = [0x42u8; 32];
        let keypair = test_keypair();
        let position = NodeIndex::new(2, 3);

        let encrypted = encrypt_seed_to_recipient(&seed, keypair.public_key(), &position).unwrap();
        let bytes = encrypted.to_bytes();
        let recovered = EncryptedNodeSeed::from_bytes(&bytes).unwrap();

        // Verify we can still decrypt
        let decrypted = decrypt_seed(&recovered, &keypair, &position).unwrap();
        assert_eq!(decrypted, seed);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_wrong_position_fails() {
        let seed = [0x42u8; 32];
        let keypair = test_keypair();
        let position1 = NodeIndex::new(2, 3);
        let position2 = NodeIndex::new(2, 4);

        let encrypted = encrypt_seed_to_recipient(&seed, keypair.public_key(), &position1).unwrap();

        // Decrypting with wrong position should fail
        let result = decrypt_seed(&encrypted, &keypair, &position2);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_wrong_keypair_fails() {
        let seed = [0x42u8; 32];
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();
        let position = NodeIndex::new(2, 3);

        let encrypted = encrypt_seed_to_recipient(&seed, keypair1.public_key(), &position).unwrap();

        // Decrypting with wrong keypair should fail
        let result = decrypt_seed(&encrypted, &keypair2, &position);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypted_seed_size() {
        let seed = [0x42u8; 32];
        let keypair = test_keypair();
        let position = NodeIndex::new(2, 3);

        let encrypted = encrypt_seed_to_recipient(&seed, keypair.public_key(), &position).unwrap();
        let bytes = encrypted.to_bytes();

        assert_eq!(bytes.len(), ENCRYPTED_SEED_SIZE);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypt_to_resolution() {
        let seed = [0x42u8; 32];
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();
        let keypair3 = test_keypair();

        let resolution = [
            NodeIndex::new(3, 0),
            NodeIndex::new(3, 1),
            NodeIndex::new(3, 2),
        ];
        let public_keys = [
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];
        let position = NodeIndex::new(2, 1);

        let encrypted_seeds =
            encrypt_seed_to_resolution(&seed, &resolution, &public_keys, &position).unwrap();

        assert_eq!(encrypted_seeds.len(), 3);

        // Each recipient should be able to decrypt
        let decrypted1 = decrypt_seed(&encrypted_seeds[0], &keypair1, &position).unwrap();
        let decrypted2 = decrypt_seed(&encrypted_seeds[1], &keypair2, &position).unwrap();
        let decrypted3 = decrypt_seed(&encrypted_seeds[2], &keypair3, &position).unwrap();

        assert_eq!(decrypted1, seed);
        assert_eq!(decrypted2, seed);
        assert_eq!(decrypted3, seed);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_encrypt_to_resolution_mismatched_lengths() {
        let seed = [0x42u8; 32];
        let keypair = test_keypair();

        let resolution = [NodeIndex::new(3, 0), NodeIndex::new(3, 1)];
        let public_keys = [keypair.public_key()]; // Only one key
        let position = NodeIndex::new(2, 1);

        let result = encrypt_seed_to_resolution(&seed, &resolution, &public_keys, &position);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_build_seed_aad() {
        let position = NodeIndex::new(2, 3);
        let aad = build_seed_aad(&position);

        // Check total size
        assert_eq!(aad.len(), SEED_AAD_SIZE);

        // Check protocol version (2 bytes)
        let version = u16::from_le_bytes([aad[0], aad[1]]);
        assert_eq!(version, SEED_AAD_VERSION);

        // Check tree depth (4 bytes)
        let depth = u32::from_le_bytes([aad[2], aad[3], aad[4], aad[5]]);
        assert_eq!(depth, 2);

        // Check tree position (4 bytes)
        let pos = u32::from_le_bytes([aad[6], aad[7], aad[8], aad[9]]);
        assert_eq!(pos, 3);

        // Check domain separator (18 bytes)
        assert_eq!(&aad[10..], b"cocoa-seed-encrypt");
    }
}
