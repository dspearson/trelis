//! Account recovery and compromise notification.
//!
//! This module provides types for handling key compromise scenarios:
//!
//! - [`CompromiseNotice`]: A signed notice announcing that a key has been compromised
//! - [`derive_recovery_keypair`]: Derives a deterministic recovery keypair from a seed
//!
//! # Security Model
//!
//! When a user suspects their identity key has been compromised, they can publish
//! a `CompromiseNotice` signed by:
//! 1. The compromised key itself (if still accessible), or
//! 2. A pre-registered recovery key
//!
//! Recipients should treat any messages signed by the compromised key after the
//! `compromised_at` timestamp with suspicion.
//!
//! # Recovery Keypair Derivation
//!
//! A recovery keypair can be deterministically derived from a 32-byte seed using
//! domain-separated BLAKE3 key derivation. This allows users to regenerate their
//! recovery key from a memorised or backed-up seed phrase.
//!
//! ```no_run
//! # // no_run: Windows doctest threads have 1MB stack which may overflow
//! # // with ML-DSA-65 key derivation. Unit tests cover this functionality.
//! use trelis_hybrid::recovery::{derive_recovery_keypair, CompromiseNotice, CompromiseReason};
//! use trelis_primitives::MlDsa65Fips204;
//!
//! // Derive recovery keypair from seed (e.g., from mnemonic phrase)
//! let seed = [0x42u8; 32];
//! let recovery_keypair = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();
//!
//! // Use recovery keypair to sign a CompromiseNotice
//! let compromised_fingerprint = [0xAAu8; 32];
//! let notice = CompromiseNotice::new(
//!     compromised_fingerprint,
//!     CompromiseReason::KeyExfiltration,
//!     1704067200,
//!     &recovery_keypair,
//! ).unwrap();
//! ```
//!
//! # Example
//!
//! ```no_run
//! # // no_run: Windows doctest threads have 1MB stack which may overflow
//! # // with ML-DSA-65 key generation. Unit tests cover this functionality.
//! use trelis_hybrid::recovery::{CompromiseNotice, CompromiseReason};
//! use trelis_hybrid::signature::HybridSigningKeypair;
//! use trelis_primitives::MlDsa65Fips204;
//!
//! // User creates a compromise notice
//! let signing_key = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
//! let compromised_fingerprint = [0xAA; 32]; // Fingerprint of compromised key
//!
//! let notice = CompromiseNotice::new(
//!     compromised_fingerprint,
//!     CompromiseReason::KeyExfiltration,
//!     1704067200, // Unix timestamp
//!     &signing_key,
//! ).unwrap();
//!
//! // Recipients verify the notice
//! assert!(notice.verify(&signing_key.public_key()).is_ok());
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_primitives::{
    DefaultMlDsaScheme, Ed448SigningKey, MlDsaScheme, RECOVERY_ED448_CONTEXT,
    RECOVERY_MLDSA_CONTEXT, derive_key,
};

use crate::signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

/// Context string for compromise notice signatures.
const COMPROMISE_NOTICE_CONTEXT: &str = "trelis-compromise-notice-v1";

/// Size of a key fingerprint (BLAKE3 hash of public key).
pub const FINGERPRINT_SIZE: usize = 32;

/// Reason for key compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompromiseReason {
    /// Key material was exfiltrated (stolen, copied).
    KeyExfiltration = 0,

    /// Device containing key was stolen/lost.
    DeviceTheft = 1,

    /// Key may have been exposed through malware.
    MalwareExposure = 2,

    /// Backup containing key was compromised.
    BackupCompromise = 3,

    /// Server-side breach affecting key storage.
    ServerBreach = 4,

    /// Unspecified or unknown compromise.
    Unknown = 255,
}

impl CompromiseReason {
    /// Converts from a byte representation.
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::KeyExfiltration,
            1 => Self::DeviceTheft,
            2 => Self::MalwareExposure,
            3 => Self::BackupCompromise,
            4 => Self::ServerBreach,
            _ => Self::Unknown,
        }
    }

    /// Converts to a byte representation.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns a human-readable description of the reason.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::KeyExfiltration => "Key material exfiltrated",
            Self::DeviceTheft => "Device containing key stolen or lost",
            Self::MalwareExposure => "Potential malware exposure",
            Self::BackupCompromise => "Backup compromise",
            Self::ServerBreach => "Server-side breach",
            Self::Unknown => "Unknown compromise reason",
        }
    }
}

/// A signed notice announcing that a cryptographic key has been compromised.
///
/// This notice is published to inform other parties that:
/// 1. The specified key should no longer be trusted
/// 2. Messages from this key after `compromised_at` should be treated with suspicion
/// 3. New sessions should not be established with this key
///
/// # Signing Authority
///
/// The notice MUST be signed by either:
/// - The compromised key itself (if the user still has access)
/// - A pre-registered recovery key (if the compromised key is inaccessible)
///
/// # Wire Format
///
/// ```text
/// +----------------------+-------+
/// | compromised_fp       | 32    | BLAKE3 fingerprint of compromised key
/// | compromised_at       | 8     | Unix timestamp (LE)
/// | reason               | 1     | CompromiseReason byte
/// | signer_fp            | 32    | BLAKE3 fingerprint of signing key
/// | signature            | 3423  | HybridSignature
/// +----------------------+-------+
/// Total: 3496 bytes
/// ```
#[derive(Clone)]
pub struct CompromiseNotice<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// BLAKE3 fingerprint of the compromised key.
    pub compromised_fingerprint: [u8; FINGERPRINT_SIZE],

    /// Unix timestamp when the compromise is believed to have occurred.
    ///
    /// Messages signed by the compromised key before this time may still be
    /// trustworthy; messages after should be treated with suspicion.
    pub compromised_at: u64,

    /// Reason for the compromise (informational).
    pub reason: CompromiseReason,

    /// BLAKE3 fingerprint of the key that signed this notice.
    ///
    /// This is either the compromised key itself or a recovery key.
    pub signer_fingerprint: [u8; FINGERPRINT_SIZE],

    /// Signature over the notice data.
    pub signature: HybridSignature<S>,
}

impl<S: MlDsaScheme> CompromiseNotice<S> {
    /// Size of the fixed portion (before signature).
    const FIXED_SIZE: usize = FINGERPRINT_SIZE + 8 + 1 + FINGERPRINT_SIZE; // 73 bytes

    /// Creates a new compromise notice.
    ///
    /// # Arguments
    ///
    /// * `compromised_fingerprint` - BLAKE3 hash of the compromised key
    /// * `reason` - Reason for the compromise
    /// * `compromised_at` - Unix timestamp of suspected compromise
    /// * `signing_key` - Key to sign the notice (compromised key or recovery key)
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if signing fails.
    pub fn new(
        compromised_fingerprint: [u8; FINGERPRINT_SIZE],
        reason: CompromiseReason,
        compromised_at: u64,
        signing_key: &HybridSigningKeypair<S>,
    ) -> Result<Self> {
        let signer_fingerprint = key_fingerprint(signing_key.public_key());

        let sig_data = Self::signing_data(
            &compromised_fingerprint,
            compromised_at,
            reason,
            &signer_fingerprint,
        );
        let signature = signing_key.sign(&sig_data)?;

        Ok(Self {
            compromised_fingerprint,
            compromised_at,
            reason,
            signer_fingerprint,
            signature,
        })
    }

    /// Verifies the notice signature.
    ///
    /// # Arguments
    ///
    /// * `signer_key` - Public key of the party that signed the notice
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if verification fails.
    pub fn verify(&self, signer_key: &HybridSigningPublicKey<S>) -> Result<()> {
        // Verify the signer fingerprint matches
        let expected_fingerprint = key_fingerprint(signer_key);
        if expected_fingerprint != self.signer_fingerprint {
            return Err(CryptoError::SignatureVerificationFailed);
        }

        let sig_data = Self::signing_data(
            &self.compromised_fingerprint,
            self.compromised_at,
            self.reason,
            &self.signer_fingerprint,
        );

        signer_key.verify(&sig_data, &self.signature)
    }

    /// Returns true if this is a self-signed notice (compromised key signed it).
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.compromised_fingerprint == self.signer_fingerprint
    }

    /// Creates the data to be signed.
    ///
    /// Format: context || compromised_fp || compromised_at || reason || signer_fp
    #[cfg(feature = "alloc")]
    fn signing_data(
        compromised_fingerprint: &[u8; FINGERPRINT_SIZE],
        compromised_at: u64,
        reason: CompromiseReason,
        signer_fingerprint: &[u8; FINGERPRINT_SIZE],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(COMPROMISE_NOTICE_CONTEXT.len() + Self::FIXED_SIZE);

        data.extend_from_slice(COMPROMISE_NOTICE_CONTEXT.as_bytes());
        data.extend_from_slice(compromised_fingerprint);
        data.extend_from_slice(&compromised_at.to_le_bytes());
        data.push(reason.to_byte());
        data.extend_from_slice(signer_fingerprint);

        data
    }

    /// Serialises the notice to bytes.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let total_size = Self::FIXED_SIZE + sig_bytes.len();

        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.compromised_fingerprint);
        bytes.extend_from_slice(&self.compromised_at.to_le_bytes());
        bytes.push(self.reason.to_byte());
        bytes.extend_from_slice(&self.signer_fingerprint);
        bytes.extend_from_slice(&sig_bytes);

        bytes
    }

    /// Deserialises a notice from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::FIXED_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        // Compromised fingerprint
        let mut compromised_fingerprint = [0u8; FINGERPRINT_SIZE];
        compromised_fingerprint.copy_from_slice(&bytes[offset..offset + FINGERPRINT_SIZE]);
        offset += FINGERPRINT_SIZE;

        // Compromised at
        let compromised_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        // Reason
        let reason = CompromiseReason::from_byte(bytes[offset]);
        offset += 1;

        // Signer fingerprint
        let mut signer_fingerprint = [0u8; FINGERPRINT_SIZE];
        signer_fingerprint.copy_from_slice(&bytes[offset..offset + FINGERPRINT_SIZE]);
        offset += FINGERPRINT_SIZE;

        // Signature
        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            compromised_fingerprint,
            compromised_at,
            reason,
            signer_fingerprint,
            signature,
        })
    }
}

impl core::fmt::Debug for CompromiseNotice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompromiseNotice")
            .field("compromised_fingerprint", &"[32 bytes]")
            .field("compromised_at", &self.compromised_at)
            .field("reason", &self.reason)
            .field("signer_fingerprint", &"[32 bytes]")
            .field("is_self_signed", &self.is_self_signed())
            .field("signature", &"[3423 bytes]")
            .finish()
    }
}

/// Calculates the fingerprint of a hybrid signing public key.
///
/// Uses BLAKE3 hash of the serialised public key.
#[cfg(feature = "alloc")]
pub fn key_fingerprint<S: MlDsaScheme>(
    public_key: &HybridSigningPublicKey<S>,
) -> [u8; FINGERPRINT_SIZE] {
    let pk_bytes = public_key.to_bytes();
    blake3::hash(&pk_bytes).into()
}

/// Size of the recovery seed in bytes.
pub const RECOVERY_SEED_SIZE: usize = 32;

/// Derives a deterministic recovery keypair from a seed.
///
/// This function uses domain-separated BLAKE3 key derivation to produce
/// a hybrid signing keypair that can be regenerated from the same seed.
///
/// The type parameter `S` selects the ML-DSA variant:
/// - `MlDsa65Fips204`: Standard FIPS 204 (default if not specified)
/// - `MlDsa65SuiteB`: PQC-Suite-B with BLAKE3
///
/// # Arguments
///
/// * `seed` - A 32-byte seed (e.g., derived from a mnemonic phrase)
///
/// # Returns
///
/// A `HybridSigningKeypair` that can be used to sign `CompromiseNotice` messages
/// or other recovery-related operations.
///
/// # Security
///
/// - The seed MUST be generated from a cryptographically secure source
/// - The seed SHOULD be backed up securely (e.g., as a mnemonic phrase)
/// - The derived keypair is deterministic: same seed always produces same keys
/// - Domain separation ensures recovery keys are distinct from identity keys
///
/// # Example
///
/// ```no_run
/// # // no_run: Windows doctest threads have 1MB stack which may overflow
/// # // with ML-DSA-65 key derivation. Unit tests cover this functionality.
/// use trelis_hybrid::recovery::derive_recovery_keypair;
/// use trelis_primitives::MlDsa65Fips204;
///
/// let seed = [0x42u8; 32]; // In practice, derive from mnemonic
/// let recovery_key = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();
///
/// // Same seed always produces the same keypair
/// let recovery_key2 = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();
/// assert_eq!(
///     recovery_key.public_key().to_bytes(),
///     recovery_key2.public_key().to_bytes()
/// );
/// ```
///
/// # Errors
///
/// Returns `KeyGenerationFailed` if key generation fails internally.
#[cfg(any(feature = "std", feature = "wasm"))]
pub fn derive_recovery_keypair<S: MlDsaScheme>(
    seed: &[u8; RECOVERY_SEED_SIZE],
) -> Result<HybridSigningKeypair<S>> {
    // Derive Ed448 seed (57 bytes) using domain separation
    // We derive two 32-byte blocks and combine them
    // Using a fixed suffix for the second derivation to avoid format! dependency
    const ED448_CONTEXT_2: &str = "trelis-recovery-ed448-v1-2";

    let ed448_seed_part1 = derive_key(RECOVERY_ED448_CONTEXT, seed);
    let ed448_seed_part2 = derive_key(ED448_CONTEXT_2, seed);

    let mut ed448_seed = [0u8; 57];
    ed448_seed[..32].copy_from_slice(&ed448_seed_part1);
    ed448_seed[32..57].copy_from_slice(&ed448_seed_part2[..25]);

    let ed448_secret = Ed448SigningKey::from_seed(ed448_seed);

    // Derive ML-DSA key using the trait's generate_from_seed method
    let mldsa_rng_seed = derive_key(RECOVERY_MLDSA_CONTEXT, seed);
    let mldsa_secret = S::generate_from_seed(&mldsa_rng_seed)?;

    // Construct the hybrid keypair
    Ok(HybridSigningKeypair::from_components(
        ed448_secret,
        mldsa_secret,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;
    use trelis_primitives::MlDsa65Fips204;

    // Type aliases for tests - use FIPS 204 (standard) for consistent testing
    type TestKeypair = HybridSigningKeypair<MlDsa65Fips204>;
    type TestNotice = CompromiseNotice<MlDsa65Fips204>;

    #[test]
    fn test_compromise_reason_roundtrip() {
        for reason in [
            CompromiseReason::KeyExfiltration,
            CompromiseReason::DeviceTheft,
            CompromiseReason::MalwareExposure,
            CompromiseReason::BackupCompromise,
            CompromiseReason::ServerBreach,
        ] {
            let byte = reason.to_byte();
            let recovered = CompromiseReason::from_byte(byte);
            assert_eq!(recovered, reason);
        }
    }

    #[test]
    fn test_compromise_reason_unknown() {
        // Unknown byte values should map to Unknown
        assert_eq!(CompromiseReason::from_byte(99), CompromiseReason::Unknown);
        assert_eq!(CompromiseReason::from_byte(200), CompromiseReason::Unknown);
    }

    #[test]
    fn test_compromise_reason_descriptions() {
        assert!(!CompromiseReason::KeyExfiltration.description().is_empty());
        assert!(!CompromiseReason::DeviceTheft.description().is_empty());
        assert!(!CompromiseReason::MalwareExposure.description().is_empty());
        assert!(!CompromiseReason::BackupCompromise.description().is_empty());
        assert!(!CompromiseReason::ServerBreach.description().is_empty());
        assert!(!CompromiseReason::Unknown.description().is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compromise_notice_create() {
        let signing_key = TestKeypair::generate().unwrap();
        let compromised_fp = [0xAAu8; 32];

        let notice = TestNotice::new(
            compromised_fp,
            CompromiseReason::DeviceTheft,
            1704067200,
            &signing_key,
        )
        .unwrap();

        assert_eq!(notice.compromised_fingerprint, compromised_fp);
        assert_eq!(notice.compromised_at, 1704067200);
        assert_eq!(notice.reason, CompromiseReason::DeviceTheft);
        assert!(!notice.is_self_signed()); // Different fingerprint
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compromise_notice_self_signed() {
        let signing_key = TestKeypair::generate().unwrap();
        let self_fingerprint = key_fingerprint(&signing_key.public_key());

        let notice = TestNotice::new(
            self_fingerprint,
            CompromiseReason::KeyExfiltration,
            1704067200,
            &signing_key,
        )
        .unwrap();

        assert!(notice.is_self_signed());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compromise_notice_verify() {
        let signing_key = TestKeypair::generate().unwrap();

        let notice = TestNotice::new(
            [0xAAu8; 32],
            CompromiseReason::MalwareExposure,
            1704067200,
            &signing_key,
        )
        .unwrap();

        // Verify with correct key
        assert!(notice.verify(&signing_key.public_key()).is_ok());

        // Verify with wrong key should fail
        let other_key = TestKeypair::generate().unwrap();
        assert!(notice.verify(&other_key.public_key()).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_compromise_notice_serialisation() {
        let signing_key = TestKeypair::generate().unwrap();

        let notice = TestNotice::new(
            [0xBBu8; 32],
            CompromiseReason::ServerBreach,
            1704067200,
            &signing_key,
        )
        .unwrap();

        let bytes = notice.to_bytes();
        let recovered = CompromiseNotice::from_bytes(&bytes).unwrap();

        assert_eq!(
            recovered.compromised_fingerprint,
            notice.compromised_fingerprint
        );
        assert_eq!(recovered.compromised_at, notice.compromised_at);
        assert_eq!(recovered.reason, notice.reason);
        assert_eq!(recovered.signer_fingerprint, notice.signer_fingerprint);

        // Signature should still verify
        assert!(recovered.verify(&signing_key.public_key()).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_fingerprint_deterministic() {
        let keypair = TestKeypair::generate().unwrap();
        let fp1 = key_fingerprint(&keypair.public_key());
        let fp2 = key_fingerprint(&keypair.public_key());

        assert_eq!(fp1, fp2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_fingerprint_unique() {
        let keypair1 = TestKeypair::generate().unwrap();
        let keypair2 = TestKeypair::generate().unwrap();

        let fp1 = key_fingerprint(&keypair1.public_key());
        let fp2 = key_fingerprint(&keypair2.public_key());

        assert_ne!(fp1, fp2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_derive_recovery_keypair_deterministic() {
        let seed = [0x42u8; 32];

        let keypair1 = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();
        let keypair2 = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();

        // Same seed should produce identical public keys
        assert_eq!(
            keypair1.public_key().to_bytes(),
            keypair2.public_key().to_bytes()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_derive_recovery_keypair_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let keypair1 = derive_recovery_keypair::<MlDsa65Fips204>(&seed1).unwrap();
        let keypair2 = derive_recovery_keypair::<MlDsa65Fips204>(&seed2).unwrap();

        // Different seeds should produce different public keys
        assert_ne!(
            keypair1.public_key().to_bytes(),
            keypair2.public_key().to_bytes()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_derive_recovery_keypair_sign_verify() {
        let seed = [0xAAu8; 32];
        let keypair = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();

        let message = b"test message for recovery key";
        let signature = keypair.sign(message).unwrap();

        // Signature should verify with derived public key
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_derive_recovery_keypair_compromise_notice() {
        let seed = [0xBBu8; 32];
        let recovery_keypair = derive_recovery_keypair::<MlDsa65Fips204>(&seed).unwrap();
        let compromised_fingerprint = [0xCCu8; 32];

        // Create a compromise notice signed by recovery key
        let notice = TestNotice::new(
            compromised_fingerprint,
            CompromiseReason::KeyExfiltration,
            1704067200,
            &recovery_keypair,
        )
        .unwrap();

        // Verify the notice
        assert!(notice.verify(&recovery_keypair.public_key()).is_ok());
        assert!(!notice.is_self_signed()); // Recovery key != compromised key
    }
}
