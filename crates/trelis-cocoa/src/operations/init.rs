//! Group initialisation (CGKA.Init).
//!
//! Creates a new CoCoA group with the creator as the first member.
//!
//! # Welcome Message Encryption
//!
//! When adding members to a group, the creator sends encrypted welcome messages
//! containing the epoch secret and transcript hash. The encryption uses:
//!
//! 1. Hybrid KEM (X448 + sntrup761) to encapsulate to each member's identity key
//! 2. XChaCha20-Poly1305 AEAD for symmetric encryption
//!
//! This provides both classical and post-quantum security for the welcome data.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{
    HybridEncapsulation, HybridIdentityKeypair, HybridKemKeypair, HybridPreKeyBundle,
};
use trelis_primitives::aead::{self, AeadKey, Nonce};
use trelis_primitives::random::generate_bytes;

use crate::session::CocoaSession;
use crate::{GroupId, UserId};

/// Size of welcome info plaintext: epoch_secret (32) + transcript_hash (32).
const WELCOME_INFO_PLAINTEXT_SIZE: usize = 64;

/// Context for deriving welcome encryption key from shared secret.
const WELCOME_KEY_CONTEXT: &str = "cocoa-sa-welcome-key-v1";

/// Welcome message sent to new members when joining a group.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Welcome {
    /// Group identifier.
    pub group_id: GroupId,
    /// Epoch number at time of welcome.
    pub epoch: u64,
    /// Recipient's assigned leaf position.
    pub leaf_position: u32,
    /// Tree depth.
    pub tree_depth: u32,
    /// Current member count.
    pub member_count: u32,
    /// Encrypted group info (epoch secret, tree state, transcript).
    /// Encrypted to the recipient's KEM key.
    pub encrypted_info: Vec<u8>,
    /// Encapsulation for decrypting the info.
    pub encapsulation: Vec<u8>,
}

/// Creates a new CoCoA group.
///
/// # Arguments
///
/// * `creator_identity` - Creator's identity keypair (for signing)
/// * `creator_kem` - Creator's KEM keypair (for encryption)
/// * `creator_user_id` - Creator's user identifier
/// * `member_bundles` - Pre-key bundles of initial members (excluding creator)
///
/// # Returns
///
/// A tuple of (creator's session, welcome messages for other members).
///
/// # Security
///
/// Each welcome message is encrypted to the recipient's identity KEM key using
/// hybrid encryption (X448 + sntrup761). This ensures only the intended recipient
/// can decrypt the epoch secret.
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn create_group(
    _creator_identity: &HybridIdentityKeypair,
    creator_kem: HybridKemKeypair,
    creator_user_id: UserId,
    member_bundles: &[&HybridPreKeyBundle],
) -> Result<(CocoaSession, Vec<Welcome>)> {
    // Generate group ID
    let group_id: GroupId = generate_bytes()?;

    // Total members = creator + others
    let total_members = 1 + member_bundles.len() as u32;

    // Generate initial epoch secret
    let epoch_secret: [u8; 32] = generate_bytes()?;

    // Initial transcript hash (empty for new group)
    let transcript_hash = [0u8; 32];

    // Create creator's session
    let session = CocoaSession::create_group(
        group_id,
        creator_user_id,
        creator_kem,
        total_members,
        &epoch_secret,
    )?;

    // Generate welcome messages for other members
    let mut welcomes = Vec::with_capacity(member_bundles.len());

    for (i, bundle) in member_bundles.iter().enumerate() {
        let leaf_position = (i + 1) as u32; // Creator is at position 0

        // Encapsulate to the member's identity KEM key
        let (shared_secret, encap) = bundle.identity_kem().encapsulate()?;

        // Derive AEAD key from shared secret
        let aead_key = derive_welcome_key(shared_secret.as_bytes());

        // Build welcome info plaintext: epoch_secret || transcript_hash
        let mut plaintext = [0u8; WELCOME_INFO_PLAINTEXT_SIZE];
        plaintext[..32].copy_from_slice(&epoch_secret);
        plaintext[32..].copy_from_slice(&transcript_hash);

        // Generate random nonce for AEAD
        let nonce_bytes: [u8; 24] = generate_bytes()?;
        let nonce = Nonce::from_bytes(nonce_bytes);

        // Encrypt with group_id as AAD to bind welcome to this group
        let ciphertext = aead::encrypt(&aead_key, &nonce, &plaintext, &group_id)?;

        // encrypted_info = nonce (24) || ciphertext (plaintext + 16 tag)
        let mut encrypted_info = Vec::with_capacity(24 + ciphertext.len());
        encrypted_info.extend_from_slice(&nonce_bytes);
        encrypted_info.extend_from_slice(&ciphertext);

        let welcome = Welcome {
            group_id,
            epoch: 0,
            leaf_position,
            tree_depth: session.tree().tree_depth(),
            member_count: total_members,
            encrypted_info,
            encapsulation: encap.to_bytes().to_vec(),
        };

        welcomes.push(welcome);
    }

    Ok((session, welcomes))
}

/// Derives the AEAD key for welcome message encryption.
fn derive_welcome_key(shared_secret: &[u8; 32]) -> AeadKey {
    let key_bytes = blake3::derive_key(WELCOME_KEY_CONTEXT, shared_secret);
    AeadKey::from_bytes(key_bytes)
}

/// Encrypts welcome information to a recipient's KEM key.
///
/// This is used when adding members to encrypt the group state.
///
/// # Arguments
///
/// * `info` - The information to encrypt (must implement `to_bytes()`)
/// * `recipient_key` - The recipient's KEM public key
///
/// # Returns
///
/// A tuple of (encrypted_info, encapsulation bytes).
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn encrypt_welcome_info<T: WelcomeInfoSerialise>(
    info: &T,
    recipient_key: &trelis_hybrid::HybridKemPublicKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Encapsulate to get shared secret
    let (shared_secret, encap) = recipient_key.encapsulate()?;

    // Derive AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Generate random nonce
    let nonce_bytes: [u8; 24] = generate_bytes()?;
    let nonce = Nonce::from_bytes(nonce_bytes);

    // Serialise and encrypt the info
    let plaintext = info.to_bytes();
    let ciphertext = aead::encrypt(&aead_key, &nonce, &plaintext, b"cocoa-welcome-add")?;

    // encrypted_info = nonce (24) || ciphertext
    let mut encrypted_info = Vec::with_capacity(24 + ciphertext.len());
    encrypted_info.extend_from_slice(&nonce_bytes);
    encrypted_info.extend_from_slice(&ciphertext);

    Ok((encrypted_info, encap.to_bytes().to_vec()))
}

/// Trait for types that can be serialised for welcome encryption.
#[cfg(feature = "alloc")]
pub trait WelcomeInfoSerialise {
    /// Serialises the info to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Decrypts welcome information using the recipient's KEM keypair.
///
/// This is the inverse of [`encrypt_welcome_info`]. It decapsulates the shared
/// secret from the encapsulation bytes and decrypts the encrypted info.
///
/// # Arguments
///
/// * `encrypted_info` - Encrypted bytes in format: nonce (24 bytes) || ciphertext
/// * `encapsulation_bytes` - KEM encapsulation bytes from the sender
/// * `our_kem` - The recipient's KEM keypair for decapsulation
///
/// # Returns
///
/// The decrypted plaintext bytes.
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
#[must_use = "the decrypted plaintext must be checked or used"]
pub fn decrypt_welcome_info(
    encrypted_info: &[u8],
    encapsulation_bytes: &[u8],
    our_kem: &HybridKemKeypair,
) -> Result<Vec<u8>> {
    if encrypted_info.len() < 24 {
        return Err(CryptoError::MalformedMessage);
    }

    // Parse the encapsulation
    let encapsulation = HybridEncapsulation::from_bytes(encapsulation_bytes)?;

    // Decapsulate to recover the shared secret
    let shared_secret = our_kem.decapsulate(&encapsulation)?;

    // Derive the AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Parse encrypted_info: nonce (24 bytes) || ciphertext
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&encrypted_info[..24]);
    let nonce = Nonce::from_bytes(nonce_bytes);
    let ciphertext = &encrypted_info[24..];

    // Decrypt using the same AAD as encrypt_welcome_info
    let plaintext = aead::decrypt(&aead_key, &nonce, ciphertext, b"cocoa-welcome-add")?;

    Ok(plaintext)
}

/// Processes a welcome message to join a group.
///
/// # Arguments
///
/// * `our_user_id` - Our user identifier
/// * `our_kem` - Our KEM keypair (matching the one in our pre-key bundle)
/// * `welcome` - The welcome message
///
/// # Returns
///
/// A session for participating in the group.
///
/// # Errors
///
/// Returns an error if:
/// - The encapsulation cannot be parsed
/// - Decapsulation fails (wrong key or corrupted data)
/// - Decryption fails (tampered ciphertext or wrong AAD)
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn process_welcome(
    our_user_id: UserId,
    our_kem: HybridKemKeypair,
    welcome: &Welcome,
) -> Result<CocoaSession> {
    // Parse the encapsulation from bytes
    let encapsulation = HybridEncapsulation::from_bytes(&welcome.encapsulation)?;

    // Decapsulate to recover the shared secret
    let shared_secret = our_kem.decapsulate(&encapsulation)?;

    // Derive the same AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Parse encrypted_info: nonce (24) || ciphertext
    if welcome.encrypted_info.len() < 24 {
        return Err(CryptoError::MalformedMessage);
    }
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&welcome.encrypted_info[..24]);
    let nonce = Nonce::from_bytes(nonce_bytes);
    let ciphertext = &welcome.encrypted_info[24..];

    // Decrypt with group_id as AAD
    let plaintext = aead::decrypt(&aead_key, &nonce, ciphertext, &welcome.group_id)?;

    // Validate plaintext size
    if plaintext.len() != WELCOME_INFO_PLAINTEXT_SIZE {
        return Err(CryptoError::MalformedMessage);
    }

    // Extract epoch_secret and transcript_hash
    let mut epoch_secret = [0u8; 32];
    let mut transcript_hash = [0u8; 32];
    epoch_secret.copy_from_slice(&plaintext[..32]);
    transcript_hash.copy_from_slice(&plaintext[32..]);

    let mut session = CocoaSession::join_group(
        welcome.group_id,
        our_user_id,
        our_kem,
        welcome.leaf_position,
        welcome.tree_depth,
        welcome.member_count,
        &epoch_secret,
        transcript_hash,
    );

    // Advance to the correct epoch if joining mid-session
    for _ in 0..welcome.epoch {
        session.advance_epoch(&[0u8; 32], transcript_hash);
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::HybridOneTimeKeyPair;

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_single_member() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let (session, welcomes) = create_group(&identity, kem, user_id, &[]).unwrap();

        assert_eq!(session.our_leaf_position(), 0);
        assert_eq!(session.member_count(), 1);
        assert!(welcomes.is_empty());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_multiple_members() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        // Create member bundles
        let member1_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle1 = create_test_bundle(&member1_identity);

        let member2_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle2 = create_test_bundle(&member2_identity);

        let bundles: Vec<&HybridPreKeyBundle> = vec![&bundle1, &bundle2];

        let (session, welcomes) = create_group(&identity, kem, user_id, &bundles).unwrap();

        assert_eq!(session.member_count(), 3);
        assert_eq!(welcomes.len(), 2);
        assert_eq!(welcomes[0].leaf_position, 1);
        assert_eq!(welcomes[1].leaf_position, 2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_has_correct_group_id() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        let (session, welcomes) = create_group(&identity, kem, user_id, &[&bundle]).unwrap();

        assert_eq!(welcomes[0].group_id, *session.group_id());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_encryption_round_trip() {
        // Creator sets up the group
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        // Member's identity key - the bundle is created with this, and the member
        // keeps the keypair to decrypt the welcome
        let member_identity = HybridIdentityKeypair::generate().unwrap();
        // HybridKemKeypair is no longer Clone; reconstruct an owned copy
        // from the identity's KEM keypair bytes for process_welcome (which consumes it).
        let member_kem =
            HybridKemKeypair::from_bytes(&member_identity.kem().to_bytes()[..]).unwrap();
        let member_user_id = [0x02u8; 32];
        let bundle = create_test_bundle(&member_identity);

        // Create group with member
        let (creator_session, welcomes) =
            create_group(&creator_identity, creator_kem, creator_user_id, &[&bundle]).unwrap();

        assert_eq!(welcomes.len(), 1);
        let welcome = &welcomes[0];

        // Verify welcome has encrypted data
        assert!(!welcome.encrypted_info.is_empty());
        assert!(!welcome.encapsulation.is_empty());

        // Member processes the welcome using their identity KEM keypair
        let member_session = process_welcome(member_user_id, member_kem, welcome).unwrap();

        // Verify both sessions are for the same group
        assert_eq!(member_session.group_id(), creator_session.group_id());

        // Verify member is at the correct position
        assert_eq!(member_session.our_leaf_position(), 1);
        assert_eq!(creator_session.our_leaf_position(), 0);

        // Both should be at epoch 0
        assert_eq!(member_session.epoch_number(), 0);
        assert_eq!(creator_session.epoch_number(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_decryption_fails_with_wrong_key() {
        // Creator sets up the group
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        // Create group
        let (_, welcomes) =
            create_group(&creator_identity, creator_kem, creator_user_id, &[&bundle]).unwrap();

        let welcome = &welcomes[0];

        // Try to process with a different KEM keypair (attacker scenario)
        let wrong_identity = HybridIdentityKeypair::generate().unwrap();
        // HybridKemKeypair is no longer Clone; reconstruct an owned copy.
        let wrong_kem = HybridKemKeypair::from_bytes(&wrong_identity.kem().to_bytes()[..]).unwrap();

        // This should fail because the wrong key can't decrypt
        let result = process_welcome([0x03u8; 32], wrong_kem, welcome);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_encryption_unique_per_member() {
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        let member1_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle1 = create_test_bundle(&member1_identity);

        let member2_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle2 = create_test_bundle(&member2_identity);

        let (_, welcomes) = create_group(
            &creator_identity,
            creator_kem,
            creator_user_id,
            &[&bundle1, &bundle2],
        )
        .unwrap();

        assert_eq!(welcomes.len(), 2);

        // Each welcome should have different encrypted data (different nonces, different encapsulations)
        assert_ne!(welcomes[0].encrypted_info, welcomes[1].encrypted_info);
        assert_ne!(welcomes[0].encapsulation, welcomes[1].encapsulation);

        // But same group parameters
        assert_eq!(welcomes[0].group_id, welcomes[1].group_id);
        assert_eq!(welcomes[0].epoch, welcomes[1].epoch);
    }
}
