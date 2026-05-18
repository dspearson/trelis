//! Device approval certificates for new device onboarding.
//!
//! When a user adds a new device, an existing device signs an approval
//! certificate to authorise the new device. This provides:
//!
//! - **Audit trail**: Who approved which device and when
//! - **Verification**: Any relying party can verify the approval without
//!   out-of-band public-key lookup — the approving device's public key is
//!   embedded in the cert (MD-01).
//! - **Replay resistance**: A server-issued `server_nonce` binds the cert to
//!   a single approval flow within a caller-policed validity window (MD-01).
//! - **Account binding**: An explicit `user_id` binds the approval to a user
//!   account, preventing cross-account misuse (MD-01).
//! - **Non-repudiation**: Approving device cannot deny the approval.
//!
//! # Caller-Boundary Contract (Server Nonce)
//!
//! The library does **not** maintain a server-nonce store. The caller is
//! responsible for the issue / consume cycle:
//!
//! ```text
//!   Server                  Approving Device              Verifier
//!     │                            │                          │
//!     │── IssueApprovalNonce ─────▶│                          │
//!     │   nonce = random[u8;32]    │                          │
//!     │── nonce ───────────────────▶                          │
//!     │                            │                          │
//!     │                            ├── DeviceApprovalCertificate
//!     │                            │   ::new(..., nonce, ...) │
//!     │                            │                          │
//!     │                            ├──── cert ───────────────▶│
//!     │                            │                          │
//!     │                            │                  ┌───────┤
//!     │                            │                  │ caller-side
//!     │                            │                  │ ConsumeApprovalNonce
//!     │◀── ConsumeApprovalNonce ───┼──────────────────┤  →  NonceReplayed
//!     │   single-use check         │                  │      if already consumed
//!     │                            │                  └───────┤
//!     │                            │                          │
//!     │                            │                  cert.verify(now, window)
//!     │                            │                          │
//! ```
//!
//! Single-use semantics, the validity window (`NonceWindow`), and the storage
//! backend (in-memory, sqlite, distributed cache, etc.) are entirely the
//! caller's responsibility. The library only:
//! - Carries the nonce as opaque 32 bytes inside the signed cert.
//! - Provides typed `CryptoError` variants (`NonceExpired`, `NonceReplayed`,
//!   `NonceMismatch`) so callers can surface specific failure modes.
//! - Provides a sensible default window (`DEFAULT_NONCE_WINDOW = 5 minutes`)
//!   the caller MUST pass explicitly to `verify` — there is no silent default.
//!
//! # Example
//!
//! ```ignore
//! use trelis_multidevice::{DeviceApprovalCertificate, NonceWindow};
//! use trelis_hybrid::HybridSigningKeypair;
//!
//! // Existing device approves new device
//! let existing_device = HybridSigningKeypair::generate().unwrap();
//! let new_device_fingerprint = [0u8; 32]; // BLAKE3 hash of new device's public key
//! let user_id = [0x01u8; 32];             // Account identifier
//! let server_nonce = [0x02u8; 32];        // Caller obtained this from the server
//!
//! let cert = DeviceApprovalCertificate::new(
//!     [0x42u8; 16],               // approving device ID
//!     user_id,
//!     new_device_fingerprint,
//!     server_nonce,
//!     1234567890,                 // approved_at (Unix seconds)
//!     &existing_device,
//! ).unwrap();
//!
//! // Relying party verifies — no public key argument; pk is embedded.
//! let now = 1234567920u64;       // 30 seconds later
//! assert!(cert.verify(now, NonceWindow::DEFAULT).is_ok());
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use trelis_error::{CryptoError, Result};
use trelis_hybrid::HybridSignature;
#[cfg(feature = "alloc")]
use trelis_hybrid::{HybridSigningKeypair, HybridSigningPublicKey, signature::PUBLIC_KEY_SIZE};

use crate::DeviceId;

/// Context string for device approval signatures.
#[cfg(feature = "alloc")]
const APPROVAL_CONTEXT: &str = "trelis-device-approval-v1";

/// Size of a device fingerprint (BLAKE3 hash of public key).
pub const FINGERPRINT_SIZE: usize = 32;

/// Size of a user-account identifier (32 bytes, typically a hash of the user's
/// identity public key or a server-issued account-scoped value).
pub const USER_ID_SIZE: usize = 32;

/// Size of the server-issued single-use nonce.
pub const SERVER_NONCE_SIZE: usize = 32;

/// A validity window for server-issued approval nonces.
///
/// The verifier supplies this to [`DeviceApprovalCertificate::verify`]; an
/// approval whose `approved_at` differs from the verifier's `now` by more than
/// the window fails with [`CryptoError::NonceExpired`].
///
/// Callers MUST pass the window explicitly at every verify site so the policy
/// decision is visible at the call. [`NonceWindow::DEFAULT`] is provided as a
/// sensible 5-minute starting point but is never silently applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceWindow {
    seconds: u64,
}

impl NonceWindow {
    /// Default 5-minute (300 second) window.
    pub const DEFAULT: NonceWindow = NonceWindow { seconds: 300 };

    /// Construct a window from a number of seconds.
    #[must_use]
    pub const fn seconds(seconds: u64) -> Self {
        Self { seconds }
    }

    /// Returns the window in seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.seconds
    }
}

/// A signed certificate approving a new device.
///
/// Created by an existing device to authorise a new device to join
/// the user's device set. The certificate is self-verifying: it carries the
/// approving device's public key, an account identifier, and a server-issued
/// single-use nonce, so any relying party can verify it without an out-of-band
/// public-key lookup.
///
/// **Wire layout** (5552 bytes total before signature padding):
/// ```text
/// device_id (16) || user_id (32) || new_device_fingerprint (32)
///                || server_nonce (32) || approving_device_pk (2009)
///                || approved_at (8) || signature (3423)
/// ```
#[derive(Clone)]
pub struct DeviceApprovalCertificate {
    /// ID of the device that created this approval.
    pub approving_device_id: DeviceId,

    /// User account this approval is bound to.
    pub user_id: [u8; USER_ID_SIZE],

    /// Fingerprint (BLAKE3 hash) of the new device's public key.
    pub new_device_fingerprint: [u8; FINGERPRINT_SIZE],

    /// Server-issued single-use nonce binding this approval to one flow.
    pub server_nonce: [u8; SERVER_NONCE_SIZE],

    /// Embedded public key of the approving device — makes the cert
    /// self-verifying without out-of-band pk lookup.
    pub approving_device_pk: HybridSigningPublicKey,

    /// Unix timestamp when approval was granted.
    pub approved_at: u64,

    /// Signature from the approving device.
    pub signature: HybridSignature,
}

impl DeviceApprovalCertificate {
    /// Wire-format body size (before the signature).
    #[cfg(feature = "alloc")]
    const BODY_SIZE: usize =
        16 + USER_ID_SIZE + FINGERPRINT_SIZE + SERVER_NONCE_SIZE + PUBLIC_KEY_SIZE + 8;

    /// Creates a new device approval certificate.
    ///
    /// The certificate is signed by the approving device's signing key. The
    /// embedded `approving_device_pk` is taken from the keypair so the cert
    /// is self-verifying.
    ///
    /// # Arguments
    ///
    /// * `approving_device_id` - ID of the device granting approval.
    /// * `user_id` - User account this approval is bound to.
    /// * `new_device_fingerprint` - BLAKE3 hash of the new device's public key.
    /// * `server_nonce` - Single-use nonce issued by the server for this approval flow.
    /// * `approved_at` - Unix timestamp for the approval (seconds).
    /// * `signing_key` - Approving device's signing keypair.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if signing fails.
    #[cfg(feature = "alloc")]
    pub fn new(
        approving_device_id: DeviceId,
        user_id: [u8; USER_ID_SIZE],
        new_device_fingerprint: [u8; FINGERPRINT_SIZE],
        server_nonce: [u8; SERVER_NONCE_SIZE],
        approved_at: u64,
        signing_key: &HybridSigningKeypair,
    ) -> Result<Self> {
        let approving_device_pk_ref = signing_key.public_key();
        let sig_data = Self::signing_data(
            &approving_device_id,
            &user_id,
            &new_device_fingerprint,
            &server_nonce,
            approving_device_pk_ref,
            approved_at,
        );

        let signature = signing_key.sign(&sig_data)?;

        Ok(Self {
            approving_device_id,
            user_id,
            new_device_fingerprint,
            server_nonce,
            approving_device_pk: approving_device_pk_ref.clone(),
            approved_at,
            signature,
        })
    }

    /// Verifies the approval certificate.
    ///
    /// Checks both freshness (against the caller-supplied window) and the
    /// embedded signature in that order. The signature path uses the
    /// `approving_device_pk` field — no out-of-band public key argument is
    /// required.
    ///
    /// `now` is caller-supplied (the library never calls `SystemTime::now()`)
    /// so callers stay testable and `no_std`-friendly. `window` is the
    /// validity window the caller wants to enforce — pass
    /// [`NonceWindow::DEFAULT`] for the 5-minute default, or
    /// [`NonceWindow::seconds`] for a custom value.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::NonceExpired`] if `|now - approved_at|` exceeds the window
    ///   (covers both stale certs and future-dated certs from clock skew).
    /// - [`CryptoError::SignatureVerificationFailed`] if the embedded signature
    ///   does not verify under the embedded public key.
    ///
    /// `NonceReplayed` and `NonceMismatch` are NOT returned here — those are
    /// caller-boundary concerns. Callers invoke their `ConsumeApprovalNonce`
    /// store BEFORE calling `verify` and map their store's outcomes to those
    /// variants themselves.
    #[cfg(feature = "alloc")]
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self, now: u64, window: NonceWindow) -> Result<()> {
        // Cheap freshness check first — abs(now - approved_at) <= window.
        // Reject both stale certs (now > approved_at + window) and
        // implausibly future-dated certs (approved_at > now + window).
        let elapsed = now.abs_diff(self.approved_at);
        if elapsed > window.as_secs() {
            return Err(CryptoError::NonceExpired);
        }

        let sig_data = Self::signing_data(
            &self.approving_device_id,
            &self.user_id,
            &self.new_device_fingerprint,
            &self.server_nonce,
            &self.approving_device_pk,
            self.approved_at,
        );

        self.approving_device_pk.verify(&sig_data, &self.signature)
    }

    /// Creates the data to be signed.
    ///
    /// Format: `context || approving_device_id || user_id ||
    /// new_device_fingerprint || server_nonce || approving_device_pk_bytes ||
    /// approved_at_le_u64`.
    #[cfg(feature = "alloc")]
    fn signing_data(
        approving_device_id: &DeviceId,
        user_id: &[u8; USER_ID_SIZE],
        new_device_fingerprint: &[u8; FINGERPRINT_SIZE],
        server_nonce: &[u8; SERVER_NONCE_SIZE],
        approving_device_pk: &HybridSigningPublicKey,
        approved_at: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(APPROVAL_CONTEXT.len() + Self::BODY_SIZE);

        data.extend_from_slice(APPROVAL_CONTEXT.as_bytes());
        data.extend_from_slice(approving_device_id);
        data.extend_from_slice(user_id);
        data.extend_from_slice(new_device_fingerprint);
        data.extend_from_slice(server_nonce);
        data.extend_from_slice(&approving_device_pk.to_bytes());
        data.extend_from_slice(&approved_at.to_le_bytes());

        data
    }

    /// Serialises the certificate to bytes.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.signature.to_bytes();
        let total_size = Self::BODY_SIZE + sig_bytes.len();

        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.approving_device_id);
        bytes.extend_from_slice(&self.user_id);
        bytes.extend_from_slice(&self.new_device_fingerprint);
        bytes.extend_from_slice(&self.server_nonce);
        bytes.extend_from_slice(&self.approving_device_pk.to_bytes());
        bytes.extend_from_slice(&self.approved_at.to_le_bytes());
        bytes.extend_from_slice(&sig_bytes);

        bytes
    }

    /// Deserialises a certificate from bytes.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the data is invalid.
    #[cfg(feature = "alloc")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::BODY_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;

        let mut approving_device_id = [0u8; 16];
        approving_device_id.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;

        let mut user_id = [0u8; USER_ID_SIZE];
        user_id.copy_from_slice(&bytes[offset..offset + USER_ID_SIZE]);
        offset += USER_ID_SIZE;

        let mut new_device_fingerprint = [0u8; FINGERPRINT_SIZE];
        new_device_fingerprint.copy_from_slice(&bytes[offset..offset + FINGERPRINT_SIZE]);
        offset += FINGERPRINT_SIZE;

        let mut server_nonce = [0u8; SERVER_NONCE_SIZE];
        server_nonce.copy_from_slice(&bytes[offset..offset + SERVER_NONCE_SIZE]);
        offset += SERVER_NONCE_SIZE;

        let approving_device_pk =
            HybridSigningPublicKey::from_bytes(&bytes[offset..offset + PUBLIC_KEY_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += PUBLIC_KEY_SIZE;

        let approved_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            approving_device_id,
            user_id,
            new_device_fingerprint,
            server_nonce,
            approving_device_pk,
            approved_at,
            signature,
        })
    }
}

impl core::fmt::Debug for DeviceApprovalCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceApprovalCertificate")
            .field(
                "approving_device_id",
                &hex::encode(self.approving_device_id),
            )
            .field("user_id", &hex::encode(self.user_id))
            .field(
                "new_device_fingerprint",
                &hex::encode(self.new_device_fingerprint),
            )
            .field("server_nonce", &hex::encode(self.server_nonce))
            .field("approving_device_pk", &"[2009 bytes]")
            .field("approved_at", &self.approved_at)
            .field("signature", &"[3423 bytes]")
            .finish()
    }
}

/// Calculates the fingerprint of a device's public key.
///
/// Uses BLAKE3 hash of the serialised hybrid signing public key.
#[cfg(feature = "alloc")]
#[must_use]
pub fn device_fingerprint(public_key: &HybridSigningPublicKey) -> [u8; FINGERPRINT_SIZE] {
    let pk_bytes = public_key.to_bytes();
    blake3::hash(&pk_bytes).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrow)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    fn test_cert(approved_at: u64) -> (DeviceApprovalCertificate, HybridSigningKeypair) {
        let signing_key = HybridSigningKeypair::generate().unwrap();
        let cert = DeviceApprovalCertificate::new(
            [0x42u8; 16],
            [0x01u8; 32],
            [0xAAu8; 32],
            [0x02u8; 32],
            approved_at,
            &signing_key,
        )
        .unwrap();
        (cert, signing_key)
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_create() {
        let (cert, signing_key) = test_cert(1000);

        assert_eq!(cert.approving_device_id, [0x42u8; 16]);
        assert_eq!(cert.user_id, [0x01u8; 32]);
        assert_eq!(cert.new_device_fingerprint, [0xAAu8; 32]);
        assert_eq!(cert.server_nonce, [0x02u8; 32]);
        assert_eq!(cert.approved_at, 1000);
        // Embedded pk matches the signing keypair's public key
        assert_eq!(
            cert.approving_device_pk.to_bytes(),
            signing_key.public_key().to_bytes()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_verify_within_window() {
        let (cert, _) = test_cert(1000);
        // 30 seconds later — well within the default 5-minute window
        assert!(cert.verify(1030, NonceWindow::DEFAULT).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_verify_self_contained() {
        // Round-trip the cert to bytes and back to prove the verifier needs
        // nothing besides the deserialised cert + a clock.
        let (cert, _) = test_cert(1000);
        let bytes = cert.to_bytes();
        let recovered = DeviceApprovalCertificate::from_bytes(&bytes).unwrap();
        assert!(recovered.verify(1030, NonceWindow::DEFAULT).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_cert_expired_nonce_rejected() {
        let (cert, _) = test_cert(1000);
        // 5 minutes + 1 second later — outside the default window
        let result = cert.verify(1000 + 301, NonceWindow::DEFAULT);
        assert!(matches!(result, Err(CryptoError::NonceExpired)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_cert_future_dated_rejected() {
        let (cert, _) = test_cert(1000);
        // Verifier's clock reads BEFORE the approval was signed — implausibly
        // future-dated cert. With the default 5-minute window, 999 should pass
        // (1 second skew) but 600 (400 seconds in the past) should fail.
        assert!(cert.verify(999, NonceWindow::DEFAULT).is_ok());
        let result = cert.verify(600, NonceWindow::DEFAULT);
        assert!(matches!(result, Err(CryptoError::NonceExpired)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_cert_custom_window() {
        let (cert, _) = test_cert(1000);
        // 10-second window — 5 seconds elapsed is fine, 11 seconds is not.
        let w = NonceWindow::seconds(10);
        assert!(cert.verify(1005, w).is_ok());
        let result = cert.verify(1011, w);
        assert!(matches!(result, Err(CryptoError::NonceExpired)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_cert_tamper_rejects() {
        let (mut cert, _) = test_cert(1000);
        // Tamper the user_id (post-signing); signature should now fail.
        cert.user_id = [0xFFu8; 32];
        let result = cert.verify(1030, NonceWindow::DEFAULT);
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_cert_nonce_tamper_rejects() {
        let (mut cert, _) = test_cert(1000);
        // Tamper the server_nonce (post-signing); signature should now fail.
        cert.server_nonce = [0xFFu8; 32];
        let result = cert.verify(1030, NonceWindow::DEFAULT);
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_serialisation_roundtrip() {
        let (cert, _) = test_cert(5000);
        let bytes = cert.to_bytes();
        let recovered = DeviceApprovalCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.approving_device_id, cert.approving_device_id);
        assert_eq!(recovered.user_id, cert.user_id);
        assert_eq!(
            recovered.new_device_fingerprint,
            cert.new_device_fingerprint
        );
        assert_eq!(recovered.server_nonce, cert.server_nonce);
        assert_eq!(recovered.approved_at, cert.approved_at);
        assert_eq!(
            recovered.approving_device_pk.to_bytes(),
            cert.approving_device_pk.to_bytes()
        );
        assert!(recovered.verify(5030, NonceWindow::DEFAULT).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_wire_size() {
        let (cert, _) = test_cert(1000);
        let bytes = cert.to_bytes();
        // 16 + 32 + 32 + 32 + 2009 + 8 = 2129 body + 3423 signature = 5552.
        assert_eq!(bytes.len(), 2129 + 3423);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_device_fingerprint() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let fp1 = device_fingerprint(&keypair.public_key());
        let fp2 = device_fingerprint(&keypair.public_key());

        // Same key should produce same fingerprint
        assert_eq!(fp1, fp2);

        // Different key should produce different fingerprint
        let other = HybridSigningKeypair::generate().unwrap();
        let fp3 = device_fingerprint(&other.public_key());
        assert_ne!(fp1, fp3);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_from_bytes_too_short() {
        // Less than minimum body size
        let bytes = [0u8; 20];
        assert!(DeviceApprovalCertificate::from_bytes(&bytes).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_approval_certificate_debug_redacts_pk_and_sig() {
        let (cert, _) = test_cert(1000);

        let debug_str = format!("{:?}", cert);
        assert!(debug_str.contains("DeviceApprovalCertificate"));
        assert!(debug_str.contains("approved_at"));
        assert!(debug_str.contains("1000"));
        // pk and signature are bulk-elided in Debug.
        assert!(debug_str.contains("[2009 bytes]"));
        assert!(debug_str.contains("[3423 bytes]"));
    }

    #[test]
    fn test_fingerprint_size() {
        assert_eq!(FINGERPRINT_SIZE, 32);
        assert_eq!(USER_ID_SIZE, 32);
        assert_eq!(SERVER_NONCE_SIZE, 32);
    }

    #[test]
    fn test_nonce_window_default() {
        assert_eq!(NonceWindow::DEFAULT.as_secs(), 300);
        assert_eq!(NonceWindow::seconds(42).as_secs(), 42);
    }
}
