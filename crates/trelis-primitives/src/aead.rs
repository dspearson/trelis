//! XChaCha20-Poly1305 authenticated encryption.
//!
//! This module provides the AEAD primitive for the Trelis protocol using
//! XChaCha20-Poly1305 with 256-bit keys, 192-bit nonces, and 128-bit tags.
//!
//! # Wire Format
//!
//! Encrypted messages are encoded as: `ciphertext || tag` (tag appended).
//! The nonce is NOT included in the output and must be transmitted separately
//! or derived deterministically.
//!
//! The committing variant (`encrypt_committing`) additionally appends a 32-byte
//! BLAKE3 key-commitment, so its output is `ciphertext || tag || commitment`
//! (commitment = [`COMMITMENT_SIZE`] bytes). See the "Committing AEAD" section
//! below for the CMT-4 construction.
//!
//! # Security Properties
//!
//! - **Confidentiality**: XChaCha20 stream cipher
//! - **Integrity**: Poly1305 authentication tag
//! - **Authenticity**: AAD is authenticated but not encrypted
//!
//! # Nonce Requirements
//!
//! XChaCha20 uses 192-bit (24-byte) nonces, providing sufficient space for
//! random nonce generation without practical collision risk. However, the
//! Trelis protocol uses hedged nonces combining counters and randomness
//! for defence-in-depth.
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::aead::{AeadKey, Nonce, encrypt, decrypt};
//!
//! let key = AeadKey::from_bytes([0x42; 32]);
//! let nonce = Nonce::from_bytes([0x00; 24]);
//! let plaintext = b"Hello, world!";
//! let aad = b"associated data";
//!
//! let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
//! let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use trelis_error::{CryptoError, Result};

// The committing-AEAD wrapper (`encrypt_committing`/`decrypt_committing`)
// derives its key-commitment subkey via `blake3_kdf`. Only the allocating path
// needs it, so the import is gated on `alloc` to avoid an unused-import warning
// under `--no-default-features`.
#[cfg(feature = "alloc")]
use crate::blake3_kdf::{self, AEAD_COMMIT_CONTEXT};

/// Size of the AEAD key in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes (192 bits).
pub const NONCE_SIZE: usize = 24;

/// Size of the authentication tag in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// XChaCha20-Poly1305 key.
///
/// The key is zeroized when dropped to prevent leakage of secret material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_SIZE]);

impl AeadKey {
    /// Creates a new key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the key as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Attempts to create a key from a slice.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl ConstantTimeEq for AeadKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// XChaCha20-Poly1305 nonce (192 bits).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Creates a new nonce from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Attempts to create a nonce from a slice.
    ///
    /// # Errors
    ///
    /// Returns `InvalidNonceLength` if the slice is not exactly 24 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self([0u8; NONCE_SIZE])
    }
}

/// Poly1305 authentication tag (128 bits).
#[derive(Clone, Copy, Debug)]
pub struct Tag([u8; TAG_SIZE]);

impl Tag {
    /// Creates a new tag from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TAG_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the tag as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }

    /// Attempts to create a tag from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 16 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }
        let mut bytes = [0u8; TAG_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl ConstantTimeEq for Tag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Tag {}

/// Encrypts plaintext with XChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - The 256-bit encryption key.
/// * `nonce` - The 192-bit nonce (MUST be unique per key).
/// * `plaintext` - The data to encrypt.
/// * `aad` - Associated authenticated data (authenticated but not encrypted).
///
/// # Returns
///
/// The ciphertext with appended authentication tag (length = plaintext.len() + 16).
///
/// # Errors
///
/// Returns an error if encryption fails (should not happen with valid inputs).
///
/// # Security
///
/// - The nonce MUST be unique for each encryption with the same key.
/// - The AAD is authenticated but not encrypted.
/// - Empty plaintext is valid and produces a 16-byte output (tag only).
#[cfg(feature = "alloc")]
pub fn encrypt(key: &AeadKey, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.0.len(),
        })?;

    let xnonce = XNonce::from_slice(&nonce.0);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Decrypts ciphertext with XChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - The 256-bit decryption key.
/// * `nonce` - The 192-bit nonce used during encryption.
/// * `ciphertext` - The ciphertext with appended authentication tag.
/// * `aad` - Associated authenticated data (must match encryption AAD).
///
/// # Returns
///
/// The decrypted plaintext.
///
/// # Errors
///
/// Returns `DecryptionFailed` if:
/// - The ciphertext is too short (less than 16 bytes for the tag)
/// - The authentication tag is invalid (wrong key, corrupted data, or wrong AAD)
///
/// # Security
///
/// This function provides constant-time tag verification to prevent timing attacks.
/// The error returned does not distinguish between authentication failure modes.
#[cfg(feature = "alloc")]
#[must_use = "the decrypted plaintext must be checked or used"]
pub fn decrypt(key: &AeadKey, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_SIZE {
        return Err(CryptoError::InvalidCiphertext);
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.0.len(),
        })?;

    let xnonce = XNonce::from_slice(&nonce.0);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::AeadAuthenticationFailed)
}

/// Encrypts plaintext in place, returning the authentication tag.
///
/// `buffer[..plaintext_len]` contains the plaintext on entry. On success,
/// `buffer[..plaintext_len]` is replaced with ciphertext of the same length.
/// The returned [`Tag`] (16 bytes) must be appended or stored separately by
/// the caller.
///
/// This avoids all heap allocation — the underlying `AeadInPlace` trait
/// encrypts directly in the provided buffer.
///
/// # Errors
///
/// Returns an error if encryption fails (should not happen with valid inputs).
pub fn encrypt_in_place(
    key: &AeadKey,
    nonce: &Nonce,
    buffer: &mut [u8],
    plaintext_len: usize,
    aad: &[u8],
) -> Result<Tag> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.0.len(),
        })?;

    let xnonce = XNonce::from_slice(&nonce.0);
    let tag = cipher
        .encrypt_in_place_detached(xnonce, aad, &mut buffer[..plaintext_len])
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut tag_bytes = [0u8; TAG_SIZE];
    tag_bytes.copy_from_slice(&tag);
    Ok(Tag(tag_bytes))
}

/// Decrypts ciphertext in place using a detached authentication tag.
///
/// `buffer[..ciphertext_len]` contains the ciphertext on entry. The `tag`
/// is verified and, on success, `buffer[..ciphertext_len]` is replaced with
/// the plaintext (same length, since XChaCha20 is a stream cipher).
///
/// This avoids all heap allocation — the underlying `AeadInPlace` trait
/// decrypts directly in the provided buffer.
///
/// # Errors
///
/// Returns `AeadAuthenticationFailed` if the tag is invalid.
#[must_use = "the decrypt outcome must be checked"]
pub fn decrypt_in_place(
    key: &AeadKey,
    nonce: &Nonce,
    buffer: &mut [u8],
    ciphertext_len: usize,
    tag: &Tag,
    aad: &[u8],
) -> Result<()> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.0.len(),
        })?;

    let xnonce = XNonce::from_slice(&nonce.0);
    let aead_tag = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&tag.0);
    cipher
        .decrypt_in_place_detached(xnonce, aad, &mut buffer[..ciphertext_len], aead_tag)
        .map_err(|_| CryptoError::AeadAuthenticationFailed)
}

// ============================================================================
// Committing AEAD (CMT-4) — additive wrapper over the multi-key wraps
// ============================================================================
//
// The base `encrypt`/`decrypt` above are XChaCha20-Poly1305, which is NOT
// key-committing: one ciphertext can in principle open under two different keys
// to two different plaintexts. The multi-key wraps ("one plaintext, N keys" —
// group path seeds, Welcome epoch secrets, device-key wraps) need that to be a
// *designed* property, not incidental. The functions below layer an
// Encrypt-then-BLAKE3-commit (CMT-4) commitment on top of the base cipher: the
// cipher and its Poly1305 tag are unchanged, and a 32-byte BLAKE3
// key-commitment is appended. See `blake3_kdf::AEAD_COMMIT_CONTEXT`
// (Phase 54, AEAD-01/F01).

/// Size of the appended key-commitment tag in bytes.
///
/// This is the full 256-bit BLAKE3 output, giving 128-bit collision
/// resistance. It MUST NOT be truncated: a 16-byte commitment would fall to
/// 2^64 birthday resistance, too weak to bind the key.
pub const COMMITMENT_SIZE: usize = 32;

/// Computes the length-framed, domain-separated BLAKE3 key-commitment.
///
/// `C = BLAKE3_keyed(K_commit, LE64(|nonce|)‖nonce ‖ LE64(|aad|)‖aad ‖ LE64(|ct|)‖ct)`
/// where `K_commit = derive_key(AEAD_COMMIT_CONTEXT, key)`. The `LE64(len)‖field`
/// framing on each of nonce/aad/ct is mandatory: without it `nonce‖aad‖ct` is
/// parse-ambiguous and a byte could be shifted across the aad|ct boundary for
/// the same MAC input (a canonicalisation collision). The prefixes are LE64
/// (not LE32) so a field length can never truncate modulo 2^32 and alias two
/// distinct triples onto one MAC input (WR-01) — u64 covers any `usize` length;
/// the commitment output stays 32 bytes regardless. Centralised here so
/// `encrypt_committing` and `decrypt_committing` cannot drift.
///
/// `K_commit` stays inside the `Zeroizing` that `derive_key` returns, so it is
/// zeroed on drop; it is never copied into a bare array. The returned
/// commitment is public (it is appended to the ciphertext on the wire).
#[cfg(feature = "alloc")]
fn aead_commitment(key: &AeadKey, nonce: &Nonce, aad: &[u8], ct: &[u8]) -> [u8; COMMITMENT_SIZE] {
    let k_commit = blake3_kdf::derive_key(AEAD_COMMIT_CONTEXT, key.as_bytes());
    let mut input = Vec::with_capacity(8 + NONCE_SIZE + 8 + aad.len() + 8 + ct.len());
    input.extend_from_slice(&(NONCE_SIZE as u64).to_le_bytes());
    input.extend_from_slice(nonce.as_bytes());
    input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    input.extend_from_slice(ct);
    *blake3_kdf::keyed_hash(&k_commit, &input)
}

/// Committing AEAD: XChaCha20-Poly1305 then an appended 32-byte BLAKE3
/// key-commitment (CMT-4).
///
/// The output is `encrypt(key, nonce, plaintext, aad) ‖ commitment(32)`, so
/// `out.len() == plaintext.len() + TAG_SIZE + COMMITMENT_SIZE`. The commitment
/// binds the length-framed `(nonce, aad, full-ciphertext)` — where the
/// ciphertext includes the Poly1305 tag — under a domain-separated subkey. This
/// gives key commitment: a single committing ciphertext cannot be opened under
/// two different keys. The base [`encrypt`] is called unchanged and retained —
/// this is an additive wrapper for the multi-key ("one plaintext, N keys")
/// wraps.
///
/// # Errors
///
/// Propagates any error from the underlying [`encrypt`].
#[cfg(feature = "alloc")]
pub fn encrypt_committing(
    key: &AeadKey,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let mut out = encrypt(key, nonce, plaintext, aad)?; // body ‖ poly1305 tag
    let commitment = aead_commitment(key, nonce, aad, &out);
    out.extend_from_slice(&commitment); // ‖ commitment(32)
    Ok(out)
}

/// Inverse of [`encrypt_committing`]: constant-time-verify the 32-byte
/// commitment, then the Poly1305 tag.
///
/// Returns the recovered plaintext iff BOTH the recomputed commitment matches
/// (in constant time) AND the Poly1305 tag verifies. On either failure the
/// uniform [`CryptoError::AeadAuthenticationFailed`] is returned, so a caller
/// cannot distinguish a commitment mismatch from a Poly1305 failure. The
/// commitment is verified BEFORE the Poly1305 open (Encrypt-then-MAC), so the
/// key-commitment property holds independently of Poly1305.
///
/// # Errors
///
/// - [`CryptoError::InvalidCiphertext`] if `committing_ct` is shorter than
///   `TAG_SIZE + COMMITMENT_SIZE` (checked before any slicing).
/// - [`CryptoError::AeadAuthenticationFailed`] on a commitment mismatch, a
///   wrong key, tampered ciphertext/commitment, or a wrong AAD.
#[cfg(feature = "alloc")]
#[must_use = "the decrypted plaintext must be checked or used"]
pub fn decrypt_committing(
    key: &AeadKey,
    nonce: &Nonce,
    committing_ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if committing_ct.len() < TAG_SIZE + COMMITMENT_SIZE {
        return Err(CryptoError::InvalidCiphertext);
    }
    let split = committing_ct.len() - COMMITMENT_SIZE;
    let (ct, commitment) = committing_ct.split_at(split);
    let expected = aead_commitment(key, nonce, aad, ct);
    // Constant-time compare; the uniform error is identical to a Poly1305
    // failure, so no oracle distinguishes the two paths.
    if expected[..].ct_eq(commitment).unwrap_u8() != 1 {
        return Err(CryptoError::AeadAuthenticationFailed);
    }
    decrypt(key, nonce, ct, aad) // Poly1305 verify + open
}

// Gated on `alloc` because the tests below use the allocating
// `encrypt`/`decrypt` helpers and `alloc::vec` macros. Without this gate,
// `cargo {check,miri test} --no-default-features` fails to compile the
// test module, preventing MIRI from reaching the rest of this crate.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"Hello, Trelis!";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"";
        let aad = b"some aad";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        // Empty plaintext produces tag only
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_aad() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"test data";
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let key2 = AeadKey::from_bytes([0x43; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = encrypt(&key1, &nonce, plaintext, aad).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, aad);

        assert!(matches!(result, Err(CryptoError::AeadAuthenticationFailed)));
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce1 = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let nonce2 = Nonce::from_bytes([0x01; NONCE_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let result = decrypt(&key, &nonce2, &ciphertext, aad);

        assert!(matches!(result, Err(CryptoError::AeadAuthenticationFailed)));
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"secret message";

        let ciphertext = encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");

        assert!(matches!(result, Err(CryptoError::AeadAuthenticationFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AeadAuthenticationFailed)));
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        // Tamper with tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AeadAuthenticationFailed)));
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);

        // Ciphertext shorter than tag size
        let short_ciphertext = [0u8; TAG_SIZE - 1];
        let result = decrypt(&key, &nonce, &short_ciphertext, b"");

        assert!(matches!(result, Err(CryptoError::InvalidCiphertext)));
    }

    #[test]
    fn test_key_try_from_slice() {
        let valid_slice = [0x42u8; KEY_SIZE];
        assert!(AeadKey::try_from_slice(&valid_slice).is_ok());

        let short_slice = [0x42u8; KEY_SIZE - 1];
        assert!(matches!(
            AeadKey::try_from_slice(&short_slice),
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn test_nonce_try_from_slice() {
        let valid_slice = [0x00u8; NONCE_SIZE];
        assert!(Nonce::try_from_slice(&valid_slice).is_ok());

        let short_slice = [0x00u8; NONCE_SIZE - 1];
        assert!(matches!(
            Nonce::try_from_slice(&short_slice),
            Err(CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 23
            })
        ));
    }

    #[test]
    fn test_tag_constant_time_eq() {
        let tag1 = Tag::from_bytes([0x42; TAG_SIZE]);
        let tag2 = Tag::from_bytes([0x42; TAG_SIZE]);
        let tag3 = Tag::from_bytes([0x43; TAG_SIZE]);

        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_block_boundary_sizes() {
        // Test at XChaCha20 block boundaries (64 bytes)
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);

        for size in [63, 64, 65, 127, 128, 129] {
            let plaintext = vec![0xabu8; size];
            let ciphertext = encrypt(&key, &nonce, &plaintext, b"").unwrap();

            // Ciphertext should be plaintext + tag
            assert_eq!(ciphertext.len(), size + TAG_SIZE);

            let decrypted = decrypt(&key, &nonce, &ciphertext, b"").unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_large_message() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = vec![0xffu8; 1_000_000]; // 1 MB

        let ciphertext = encrypt(&key, &nonce, &plaintext, b"").unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_in_place_roundtrip() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"Hello, in-place!";
        let aad = b"aad";

        // Encrypt in place
        let mut buf = plaintext.to_vec();
        let tag = encrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), aad).unwrap();

        // Ciphertext should differ from plaintext
        assert_ne!(&buf[..plaintext.len()], plaintext.as_slice());

        // Decrypt in place
        decrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), &tag, aad).unwrap();
        assert_eq!(&buf[..plaintext.len()], plaintext.as_slice());
    }

    #[test]
    fn test_in_place_matches_allocating() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"consistency check";
        let aad = b"";

        // Allocating path
        let ct_alloc = encrypt(&key, &nonce, plaintext, aad).unwrap();

        // In-place path
        let mut buf = plaintext.to_vec();
        let tag = encrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), aad).unwrap();

        // Ciphertext should match (without tag)
        assert_eq!(&buf[..plaintext.len()], &ct_alloc[..plaintext.len()]);
        // Tag should match
        assert_eq!(tag.as_bytes(), &ct_alloc[plaintext.len()..]);
    }

    #[test]
    fn test_decrypt_in_place_wrong_tag_fails() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"test data";

        let mut buf = plaintext.to_vec();
        let _tag = encrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), b"").unwrap();

        // Wrong tag
        let bad_tag = Tag::from_bytes([0xff; TAG_SIZE]);
        let result = decrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), &bad_tag, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_in_place_empty() {
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);

        let mut buf = vec![];
        let tag = encrypt_in_place(&key, &nonce, &mut buf, 0, b"").unwrap();

        // Decrypt empty
        decrypt_in_place(&key, &nonce, &mut buf, 0, &tag, b"").unwrap();
    }

    #[test]
    fn committing_aead_is_key_committing() {
        // Positive round-trip: encrypt then decrypt under the same key recovers
        // the exact plaintext (the commitment is stripped on the way out).
        let k1 = AeadKey::from_bytes([0x11; KEY_SIZE]);
        let n = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"epoch-secret-material";
        let aad = b"aad";

        let ct = encrypt_committing(&k1, &n, plaintext, aad).unwrap();
        // out = body ‖ poly1305 tag(16) ‖ commitment(32).
        assert_eq!(ct.len(), plaintext.len() + TAG_SIZE + COMMITMENT_SIZE);
        let recovered = decrypt_committing(&k1, &n, &ct, aad).unwrap();
        assert_eq!(recovered, plaintext);

        // Key commitment (the direct F01 / AEAD-01 guarantee): the SAME
        // committing ciphertext MUST NOT open under a different key.
        let k2 = AeadKey::from_bytes([0x22; KEY_SIZE]);
        assert!(matches!(
            decrypt_committing(&k2, &n, &ct, aad),
            Err(CryptoError::AeadAuthenticationFailed)
        ));

        // Tampered commitment (flip the last byte) is rejected with the uniform
        // error — the constant-time compare fails before the Poly1305 open.
        let mut bad_commit = ct.clone();
        let last = bad_commit.len() - 1;
        bad_commit[last] ^= 0xff;
        assert!(matches!(
            decrypt_committing(&k1, &n, &bad_commit, aad),
            Err(CryptoError::AeadAuthenticationFailed)
        ));

        // Tampered ciphertext body is rejected (uniform error): the recomputed
        // commitment no longer matches the stored one.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xff;
        assert!(matches!(
            decrypt_committing(&k1, &n, &bad_ct, aad),
            Err(CryptoError::AeadAuthenticationFailed)
        ));

        // Wrong AAD is rejected (the commitment binds the AAD).
        assert!(matches!(
            decrypt_committing(&k1, &n, &ct, b"wrong aad"),
            Err(CryptoError::AeadAuthenticationFailed)
        ));

        // Truncated input (shorter than TAG_SIZE + COMMITMENT_SIZE) is rejected
        // with InvalidCiphertext, returned before any slicing.
        let short = [0u8; TAG_SIZE + COMMITMENT_SIZE - 1];
        assert!(matches!(
            decrypt_committing(&k1, &n, &short, aad),
            Err(CryptoError::InvalidCiphertext)
        ));
    }

    #[test]
    fn base_aead_still_present() {
        // SC2: the base XChaCha20-Poly1305 encrypt/decrypt remain usable and
        // unchanged — the per-message channel relies on them and they carry no
        // deprecation marker. The base output carries only the Poly1305 tag; the
        // committing wrapper appends exactly COMMITMENT_SIZE more bytes.
        let key = AeadKey::from_bytes([0x42; KEY_SIZE]);
        let nonce = Nonce::from_bytes([0x00; NONCE_SIZE]);
        let plaintext = b"per-message channel payload";
        let aad = b"channel-aad";

        let base = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(base.len(), plaintext.len() + TAG_SIZE);
        let decrypted = decrypt(&key, &nonce, &base, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        let committing = encrypt_committing(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(committing.len(), base.len() + COMMITMENT_SIZE);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Partitioning-resistance (the direct F01 / AEAD-01 guarantee): no
        /// single committing ciphertext produced under `k1` can be opened under
        /// any distinct key `k2`. This is the non-inferable backstop named in
        /// 54-VALIDATION — the commitment binds the key, so one ciphertext
        /// cannot open under two keys.
        #[test]
        fn no_committing_ct_opens_under_two_keys(
            k1 in proptest::array::uniform32(any::<u8>()),
            k2 in proptest::array::uniform32(any::<u8>()),
            msg in proptest::collection::vec(any::<u8>(), 0..128),
            aad in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            prop_assume!(k1 != k2);
            let n = Nonce::from_bytes([0x00; NONCE_SIZE]);
            let ct = encrypt_committing(&AeadKey::from_bytes(k1), &n, &msg, &aad).unwrap();
            // Under any different key, decrypt_committing must fail (commitment
            // mismatch or Poly1305 failure — the uniform error).
            prop_assert!(decrypt_committing(&AeadKey::from_bytes(k2), &n, &ct, &aad).is_err());
        }
    }
}
