//! Account recovery and compromise notification.
//!
//! This module provides types for handling key compromise scenarios:
//!
//! - [`CompromiseNotice`]: A signed notice announcing that a key has been compromised
//! - [`RecoveryKeyAttestation`]: A double-signed old→new identity-rotation attestation
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
use trelis_primitives::{DefaultMlDsaScheme, MlDsaScheme};
#[cfg(any(feature = "std", feature = "wasm"))]
use trelis_primitives::{
    Ed448SigningKey, RECOVERY_ED448_CONTEXT, RECOVERY_MLDSA_CONTEXT, derive_key,
};

use crate::signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

// Context strings imported from the central BLAKE3 derive-key registry
// in `trelis_primitives::blake3_kdf`.
use trelis_primitives::{COMPROMISE_NOTICE_CONTEXT, RECOVERY_KEY_ATTEST_CONTEXT};

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
/// | signature            | 3366  | HybridSignature
/// +----------------------+-------+
/// Total: 3439 bytes
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
    #[must_use = "the verify outcome must be checked"]
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
            .field("signature", &"[3366 bytes]")
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
    ed448_seed[..32].copy_from_slice(ed448_seed_part1.as_slice());
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

/// Size of the stable account identifier bound into a recovery attestation.
pub const USER_ID_SIZE: usize = 32;

/// Double-signed old→new identity-rotation attestation.
///
/// Issued when a user rotates their identity keypair (compromise recovery or
/// key hygiene). The attestation is **cross-signed by BOTH the old and the new
/// identity keys** over the same domain-separated body, binding both identity
/// public keys and the stable `user_id`. This proves, in one object:
///
/// - possession of the NEW identity secret key (`sig_new`),
/// - old→new rotation continuity endorsed by the OLD key (`sig_old`), and
/// - exclusive ownership for THIS account — neither signature can be lifted to
///   a different rotation or re-homed to another account, because both public
///   keys and the `user_id` are inside the signed body and BoP-2 additionally
///   binds each signer's verification key into `m'`.
///
/// A verifier MUST accept only an attestation for which BOTH signatures verify
/// (see [`Self::verify`]); the type has no single-signature construction path,
/// and a legacy single-sig attestation blob is rejected by the exact-length
/// wire gate in [`Self::from_bytes`].
///
/// # Wire format
///
/// ```text
/// +----------------------+-------+
/// | old_identity_pk      | 2009  | HybridSigningPublicKey (Ed448 + ML-DSA)
/// | new_identity_pk      | 2009  | HybridSigningPublicKey (Ed448 + ML-DSA)
/// | user_id              | 32    | Stable account identifier
/// | registered_at        | 8     | Unix timestamp (LE)
/// | sig_old              | 3366  | HybridSignature by the OLD identity key
/// | sig_new              | 3366  | HybridSignature by the NEW identity key
/// +----------------------+-------+
/// Total: 10,790 bytes
/// ```
///
/// Serialise with [`Self::to_bytes`]; parse with [`Self::from_bytes`].
///
/// # Domain separation
///
/// Signing body: `RECOVERY_KEY_ATTEST_CONTEXT || old_identity_pk_bytes ||
/// new_identity_pk_bytes || user_id || registered_at(LE)`. The context string
/// `trelis-recovery-key-attest-v1` ensures the signatures cannot be replayed as
/// any other protocol signature.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct RecoveryKeyAttestation<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// The OLD identity key being rotated away from.
    pub old_identity_pk: HybridSigningPublicKey<S>,
    /// The NEW identity key being rotated to.
    pub new_identity_pk: HybridSigningPublicKey<S>,
    /// Stable 32-byte account identifier (constant across identity rotations).
    pub user_id: [u8; USER_ID_SIZE],
    /// Unix timestamp (seconds) when the rotation was registered.
    pub registered_at: u64,
    /// `sig_old` — signature by the OLD identity key over the body.
    pub sig_old: HybridSignature<S>,
    /// `sig_new` — signature by the NEW identity key over the body.
    pub sig_new: HybridSignature<S>,
}

#[cfg(feature = "alloc")]
impl<S: MlDsaScheme> RecoveryKeyAttestation<S> {
    /// Total wire size in bytes (`old_identity_pk + new_identity_pk + user_id +
    /// registered_at + sig_old + sig_new`).
    pub const WIRE_SIZE: usize = SIGNING_PK_WIRE_SIZE
        + SIGNING_PK_WIRE_SIZE
        + USER_ID_SIZE
        + 8
        + SIGNATURE_WIRE_SIZE
        + SIGNATURE_WIRE_SIZE;

    /// Cross-signs an old→new identity rotation.
    ///
    /// `sig_old` is produced by the OLD identity keypair and `sig_new` by the
    /// NEW identity keypair, both over the same domain-separated body binding
    /// both public keys, `user_id`, and `registered_at`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MalformedMessage`] if the old and new identity
    /// public keys are equal — a no-op "rotate X→X" self-attestation proves no
    /// key change and is rejected as misuse. Returns a signature error if
    /// either identity keypair fails to sign.
    pub fn create(
        old_identity_keypair: &HybridSigningKeypair<S>,
        new_identity_keypair: &HybridSigningKeypair<S>,
        user_id: [u8; USER_ID_SIZE],
        registered_at: u64,
    ) -> Result<Self> {
        let old_identity_pk = old_identity_keypair.public_key().clone();
        let new_identity_pk = new_identity_keypair.public_key().clone();
        // Misuse resistance: reject a no-op rotation. An attestation whose old
        // and new identity keys are equal proves nothing about a key change and
        // could mislead a consumer that reads "valid attestation ⇒ identity
        // rotated". `HybridSigningPublicKey: Eq`.
        if old_identity_pk == new_identity_pk {
            return Err(CryptoError::MalformedMessage);
        }
        let body = Self::signing_data(&old_identity_pk, &new_identity_pk, &user_id, registered_at);
        let sig_old = old_identity_keypair.sign(&body)?;
        let sig_new = new_identity_keypair.sign(&body)?;
        Ok(Self {
            old_identity_pk,
            new_identity_pk,
            user_id,
            registered_at,
            sig_old,
            sig_new,
        })
    }

    /// Verifies the attestation, requiring BOTH signatures.
    ///
    /// Recomputes the signed body and checks `sig_old` under `old_identity_pk`
    /// AND `sig_new` under `new_identity_pk`. The sequential `?` makes this an
    /// AND, not an OR: verification fails if EITHER signature is invalid.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if either signature does not
    /// verify.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self) -> Result<()> {
        let body = Self::signing_data(
            &self.old_identity_pk,
            &self.new_identity_pk,
            &self.user_id,
            self.registered_at,
        );
        self.old_identity_pk.verify(&body, &self.sig_old)?;
        self.new_identity_pk.verify(&body, &self.sig_new)?;
        Ok(())
    }

    /// Returns the domain-separated body that BOTH identity keys sign.
    ///
    /// Format: `RECOVERY_KEY_ATTEST_CONTEXT || old_pk || new_pk || user_id ||
    /// registered_at(LE)`. All fields after the context are fixed-length.
    fn signing_data(
        old_pk: &HybridSigningPublicKey<S>,
        new_pk: &HybridSigningPublicKey<S>,
        user_id: &[u8; USER_ID_SIZE],
        registered_at: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            RECOVERY_KEY_ATTEST_CONTEXT.len() + 2 * SIGNING_PK_WIRE_SIZE + USER_ID_SIZE + 8,
        );
        data.extend_from_slice(RECOVERY_KEY_ATTEST_CONTEXT.as_bytes());
        data.extend_from_slice(&old_pk.to_bytes());
        data.extend_from_slice(&new_pk.to_bytes());
        data.extend_from_slice(user_id);
        data.extend_from_slice(&registered_at.to_le_bytes());
        data
    }

    /// Serialises the attestation to its canonical wire form.
    ///
    /// Layout: `old_identity_pk (2,009) || new_identity_pk (2,009) ||
    /// user_id (32) || registered_at (8 LE) || sig_old (3,366) ||
    /// sig_new (3,366)` = 10,790 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::WIRE_SIZE);
        bytes.extend_from_slice(&self.old_identity_pk.to_bytes());
        bytes.extend_from_slice(&self.new_identity_pk.to_bytes());
        bytes.extend_from_slice(&self.user_id);
        bytes.extend_from_slice(&self.registered_at.to_le_bytes());
        bytes.extend_from_slice(&self.sig_old.to_bytes());
        bytes.extend_from_slice(&self.sig_new.to_bytes());
        bytes
    }

    /// Parses an attestation from its canonical wire form.
    ///
    /// Does NOT call [`Self::verify`]; the caller must do so before trusting
    /// the parsed attestation. The exact-length gate rejects any input whose
    /// length is not exactly [`Self::WIRE_SIZE`] (10,790) — this is how a
    /// legacy single-signature attestation blob is rejected.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the slice has the wrong size or any
    /// sub-component fails to decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;
        let old_identity_pk =
            HybridSigningPublicKey::<S>::from_bytes(&bytes[offset..offset + SIGNING_PK_WIRE_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += SIGNING_PK_WIRE_SIZE;

        let new_identity_pk =
            HybridSigningPublicKey::<S>::from_bytes(&bytes[offset..offset + SIGNING_PK_WIRE_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += SIGNING_PK_WIRE_SIZE;

        let mut user_id = [0u8; USER_ID_SIZE];
        user_id.copy_from_slice(&bytes[offset..offset + USER_ID_SIZE]);
        offset += USER_ID_SIZE;

        let registered_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        let sig_old =
            HybridSignature::<S>::from_bytes(&bytes[offset..offset + SIGNATURE_WIRE_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += SIGNATURE_WIRE_SIZE;

        let sig_new =
            HybridSignature::<S>::from_bytes(&bytes[offset..offset + SIGNATURE_WIRE_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            old_identity_pk,
            new_identity_pk,
            user_id,
            registered_at,
            sig_old,
            sig_new,
        })
    }
}

/// Size of `HybridSigningPublicKey` on the wire (Ed448 57 + ML-DSA-65 1,952).
///
/// Single-sourced from [`crate::signature::PUBLIC_KEY_SIZE`] (the crate
/// convention, cf. `prekey_bundle.rs` / `one_time_key.rs`) so the attestation
/// wire layout tracks the signing-key encoding instead of desyncing from a
/// hand-written literal if the key size ever changes.
const SIGNING_PK_WIRE_SIZE: usize = crate::signature::PUBLIC_KEY_SIZE;
/// Size of `HybridSignature` on the wire (BoP-2 response 57 + ML-DSA-65 3,309).
///
/// Single-sourced from [`crate::signature::SIGNATURE_SIZE`] so the attestation
/// wire layout tracks the combiner (now the 3,366-byte BoP-2 signature).
const SIGNATURE_WIRE_SIZE: usize = crate::signature::SIGNATURE_SIZE;

#[cfg(feature = "alloc")]
impl<S: MlDsaScheme> core::fmt::Debug for RecoveryKeyAttestation<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryKeyAttestation")
            .field("old_identity_pk", &"[hybrid signing pk]")
            .field("new_identity_pk", &"[hybrid signing pk]")
            .field("user_id", &"[32 bytes]")
            .field("registered_at", &self.registered_at)
            .field("sig_old", &"[3366 bytes]")
            .field("sig_new", &"[3366 bytes]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;
    use alloc::vec;
    use trelis_primitives::MlDsa65Fips204;

    // Type aliases for tests - use FIPS 204 (standard) for consistent testing
    type TestKeypair = HybridSigningKeypair<MlDsa65Fips204>;
    type TestNotice = CompromiseNotice<MlDsa65Fips204>;
    type TestAttestation = RecoveryKeyAttestation<MlDsa65Fips204>;

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

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_happy_path() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();
        let user_id = [0x11u8; USER_ID_SIZE];

        let attestation =
            TestAttestation::create(&old_identity, &new_identity, user_id, 1_704_067_200).unwrap();

        assert!(attestation.verify().is_ok());
        assert_eq!(
            attestation.old_identity_pk.to_bytes(),
            old_identity.public_key().to_bytes()
        );
        assert_eq!(
            attestation.new_identity_pk.to_bytes(),
            new_identity.public_key().to_bytes()
        );
        assert_eq!(attestation.user_id, user_id);
        assert_eq!(attestation.registered_at, 1_704_067_200);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_tamper_detection() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();

        let mut attestation = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0x22u8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap();

        // Tamper with the timestamp — neither signature still covers the new
        // value, so verification must fail.
        attestation.registered_at = 1_704_067_201;

        assert!(attestation.verify().is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_cross_identity_rejected() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();
        let other_identity = TestKeypair::generate().unwrap();

        let mut attestation = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0x33u8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap();

        // Swap the new identity pk for an unrelated key. `sig_new` was produced
        // over a body binding the genuine `new_identity_pk` (and BoP-2 binds the
        // signer vk into m'), so verification must now fail.
        attestation.new_identity_pk = other_identity.public_key().clone();

        assert!(attestation.verify().is_err());
    }

    #[test]
    fn test_recovery_key_attestation_wire_size_constant() {
        // old_identity_pk (2,009) + new_identity_pk (2,009) + user_id (32)
        // + registered_at (8) + sig_old (3,366) + sig_new (3,366) = 10,790
        assert_eq!(
            TestAttestation::WIRE_SIZE,
            2_009 + 2_009 + 32 + 8 + 3_366 + 3_366
        );
        assert_eq!(TestAttestation::WIRE_SIZE, 10_790);
        // WR-01: the public-key wire size is single-sourced from the signature
        // crate, so a future key-size change flows through to the attestation
        // layout instead of silently desyncing from a hand-written literal.
        assert_eq!(SIGNING_PK_WIRE_SIZE, crate::signature::PUBLIC_KEY_SIZE);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_serialisation_roundtrip() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();
        let user_id = [0x44u8; USER_ID_SIZE];

        let attestation =
            TestAttestation::create(&old_identity, &new_identity, user_id, 1_704_067_200).unwrap();

        let bytes = attestation.to_bytes();
        assert_eq!(bytes.len(), TestAttestation::WIRE_SIZE);

        let parsed = TestAttestation::from_bytes(&bytes).unwrap();
        assert!(parsed.verify().is_ok());
        assert_eq!(parsed.registered_at, 1_704_067_200);
        assert_eq!(parsed.user_id, user_id);
        assert_eq!(
            parsed.old_identity_pk.to_bytes(),
            old_identity.public_key().to_bytes()
        );
        assert_eq!(
            parsed.new_identity_pk.to_bytes(),
            new_identity.public_key().to_bytes()
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_from_bytes_wrong_length() {
        // Too short
        let too_short = vec![0u8; TestAttestation::WIRE_SIZE - 1];
        assert!(matches!(
            TestAttestation::from_bytes(&too_short),
            Err(CryptoError::MalformedMessage)
        ));

        // Too long
        let too_long = vec![0u8; TestAttestation::WIRE_SIZE + 1];
        assert!(matches!(
            TestAttestation::from_bytes(&too_long),
            Err(CryptoError::MalformedMessage)
        ));

        // Empty
        assert!(matches!(
            TestAttestation::from_bytes(&[]),
            Err(CryptoError::MalformedMessage)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_from_bytes_corrupt_body() {
        // Right length, but the bytes don't decode as valid public keys.
        // The Ed448 verifying-key parser rejects most random byte patterns,
        // so an all-zeros buffer of the right length still fails sub-component
        // decoding rather than silently producing a malformed attestation.
        let all_zeros = vec![0u8; TestAttestation::WIRE_SIZE];
        assert!(matches!(
            TestAttestation::from_bytes(&all_zeros),
            Err(CryptoError::MalformedMessage)
        ));
    }

    /// IN-01: exercise the *later* sub-component decode arms of `from_bytes`.
    ///
    /// The all-zeros `corrupt_body` test above fails at the FIRST field
    /// (`old_identity_pk` at offset 0) and returns early, so the decode-failure
    /// arms for `new_identity_pk`, `sig_old`, and `sig_new` — including the
    /// BoP-2 response UR-guard — were never independently exercised. Here we
    /// take a genuine 10,790-byte attestation, keep the leading fields valid,
    /// and corrupt exactly one later region at a time to `0xFF`. Each buffer
    /// stays length-valid (passes the exact-length gate) yet must still
    /// parse-fail with `MalformedMessage`, reaching the later `map_err` arms.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_key_attestation_from_bytes_corrupt_later_fields() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();

        let good = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0xAAu8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap()
        .to_bytes();
        assert_eq!(good.len(), TestAttestation::WIRE_SIZE);

        // Field offsets within the 10,790-byte wire form:
        //   old_identity_pk [0..2009], new_identity_pk [2009..4018],
        //   user_id [4018..4050], registered_at [4050..4058],
        //   sig_old [4058..7424], sig_new [7424..10790].
        // Corrupting a later region to 0xFF forces the matching sub-component
        // decode to fail: the pk parser rejects the non-canonical Ed448 key
        // bytes, and the BoP-2 response UR-guard rejects rsp byte 56 = 0xFF.
        for (start, end) in [(2009usize, 4018usize), (4058, 7424), (7424, 10790)] {
            let mut corrupt = good.clone();
            corrupt[start..end].fill(0xFF);
            assert_eq!(corrupt.len(), TestAttestation::WIRE_SIZE);
            assert!(
                matches!(
                    TestAttestation::from_bytes(&corrupt),
                    Err(CryptoError::MalformedMessage)
                ),
                "corrupting bytes [{start}..{end}] must fail sub-component decode"
            );
        }
    }

    // ------------------------------------------------------------------
    // REC-01 SC1/SC2 negative + AND-not-OR backstop tests
    // ------------------------------------------------------------------

    /// SC1 backstop: verify() is an AND, not an OR. A genuine σ_old paired with
    /// a σ_new made by an UNRELATED key (new_identity_pk left genuine) must be
    /// rejected — and the symmetric case too.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_requires_both_sigs() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();
        let unrelated = TestKeypair::generate().unwrap();

        let genuine = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0x55u8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap();

        // The exact body both genuine keys signed.
        let body = TestAttestation::signing_data(
            &genuine.old_identity_pk,
            &genuine.new_identity_pk,
            &genuine.user_id,
            genuine.registered_at,
        );

        // Case A: genuine sig_old, but sig_new made by an unrelated key over the
        // same body. `new_identity_pk` stays genuine, so acceptance here would
        // mean verify only checks one signature. It must reject.
        let mut forged_new = genuine.clone();
        forged_new.sig_new = unrelated.sign(&body).unwrap();
        assert!(forged_new.verify().is_err());

        // Case B: the symmetric case — genuine sig_new, sig_old by the unrelated key.
        let mut forged_old = genuine.clone();
        forged_old.sig_old = unrelated.sign(&body).unwrap();
        assert!(forged_old.verify().is_err());
    }

    /// SC1: a legacy single-signature attestation blob is rejected. The two
    /// historical wire lengths — 7,392 (previous code constant) and 7,449 (old
    /// spec figure) — are both != 10,790, so the exact-length gate rejects them.
    /// These are the ONLY place the legacy sizes appear, as deliberate inputs.
    #[test]
    fn test_recovery_attestation_rejects_legacy_single_sig() {
        let legacy_code_len = vec![0u8; 7_392];
        let legacy_spec_len = vec![0u8; 7_449];

        assert!(matches!(
            TestAttestation::from_bytes(&legacy_code_len),
            Err(CryptoError::MalformedMessage)
        ));
        assert!(matches!(
            TestAttestation::from_bytes(&legacy_spec_len),
            Err(CryptoError::MalformedMessage)
        ));
    }

    /// SC2: user_id is bound into the signed body. Mutating it after signing —
    /// e.g. re-homing the rotation to another account — must fail verification.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_user_id_binding() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();

        let mut attestation = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0x66u8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap();

        // Flip a byte of user_id post-sign: the recomputed body differs from the
        // one both keys signed, so verification must fail (cross-user binding).
        attestation.user_id[0] ^= 0x01;

        assert!(attestation.verify().is_err());
    }

    /// SC2: a signature cannot be grafted from a different attestation. Both
    /// public keys and user_id are in the body each key signs, and BoP-2 binds
    /// each signer's vk into m', so B's σ cannot be lifted into A.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_sig_graft_rejected() {
        let old_a = TestKeypair::generate().unwrap();
        let new_a = TestKeypair::generate().unwrap();
        let old_b = TestKeypair::generate().unwrap();
        let new_b = TestKeypair::generate().unwrap();

        let att_a =
            TestAttestation::create(&old_a, &new_a, [0x77u8; USER_ID_SIZE], 1_704_067_200).unwrap();
        let att_b =
            TestAttestation::create(&old_b, &new_b, [0x88u8; USER_ID_SIZE], 1_704_067_200).unwrap();

        // Graft B's sig_new into A ⇒ A's body binds new_a's pk (and user_id 0x77),
        // not B's, so verification fails.
        let mut grafted_new = att_a.clone();
        grafted_new.sig_new = att_b.sig_new.clone();
        assert!(grafted_new.verify().is_err());

        // Graft B's sig_old into A ⇒ likewise rejected.
        let mut grafted_old = att_a.clone();
        grafted_old.sig_old = att_b.sig_old.clone();
        assert!(grafted_old.verify().is_err());
    }

    /// SC2 (directional): σ_old verifies under old_identity_pk and NOT under
    /// new_identity_pk — BoP-2 binds each signer's vk into m', proving the two
    /// signatures are bound to their respective keys.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_signing_direction() {
        let old_identity = TestKeypair::generate().unwrap();
        let new_identity = TestKeypair::generate().unwrap();

        let attestation = TestAttestation::create(
            &old_identity,
            &new_identity,
            [0x99u8; USER_ID_SIZE],
            1_704_067_200,
        )
        .unwrap();

        let body = TestAttestation::signing_data(
            &attestation.old_identity_pk,
            &attestation.new_identity_pk,
            &attestation.user_id,
            attestation.registered_at,
        );

        // σ_old verifies under the OLD identity pk...
        assert!(
            attestation
                .old_identity_pk
                .verify(&body, &attestation.sig_old)
                .is_ok()
        );
        // ...but NOT under the NEW identity pk.
        assert!(
            attestation
                .new_identity_pk
                .verify(&body, &attestation.sig_old)
                .is_err()
        );
    }

    /// IN-04 (misuse resistance): `create` rejects a no-op rotation where the
    /// old and new identity keys are identical. Such a "rotate X→X"
    /// self-attestation is semantically meaningless and could mislead a
    /// consumer that treats a valid attestation as proof the identity changed.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_recovery_attestation_rejects_noop_rotation() {
        let identity = TestKeypair::generate().unwrap();

        // Same keypair for old and new ⇒ old_identity_pk == new_identity_pk.
        let result =
            TestAttestation::create(&identity, &identity, [0xABu8; USER_ID_SIZE], 1_704_067_200);

        assert!(matches!(result, Err(CryptoError::MalformedMessage)));
    }
}
