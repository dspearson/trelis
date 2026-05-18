//! Identity certificates and certified safety numbers (spec §15.4).
//!
//! An [`IdentityCertificate`] binds an attester's hybrid signature to a
//! subject's identity public key plus issued / expires metadata. The library
//! does NOT take a position on whether the issuer is a public CA, a relying
//! party, or the subject themselves — it only guarantees that the signature
//! is over a domain-separated body so it cannot be confused with any other
//! signed structure in the Trelis protocol.
//!
//! A [`CertifiedSafetyNumber`] wraps a [`SafetyNumber`] with one or two
//! identity certificates plus the parties' hybrid signatures over the safety
//! number itself. This is the spec §15.4 "for automated verification with
//! PKI" construction; the chain-validation step that traditional PKI deploys
//! is intentionally application-tier and lives outside this crate.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_primitives::IDENTITY_CERT_CONTEXT;

use crate::identity::HybridIdentityPublicKey;
use crate::safety_number::SafetyNumber;
use crate::signature::{HybridSignature, HybridSigningKeypair, HybridSigningPublicKey};

/// Domain separator for the safety-number portion of
/// [`CertifiedSafetyNumber`]. Bound to v1 so a future construction that
/// signs additional bytes alongside the safety number can be distinguished
/// from this one.
pub const CERTIFIED_SAFETY_NUMBER_CONTEXT: &str = "trelis-certified-safety-number-v1";

/// A signed leaf-tier identity certificate.
///
/// `IdentityCertificate` is the smallest unit a PKI deployment can build
/// on: one issuer attests, with a hybrid signature, that the named subject
/// identity key is theirs over a stated validity window. PKI chain logic
/// (issuer-of-issuer-of-subject, root anchors, CRLs) is intentionally
/// not modelled in this crate — it is application-tier.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct IdentityCertificate {
    /// The subject's hybrid identity public key (signing + KEM).
    pub subject_identity: HybridIdentityPublicKey,
    /// The issuer's hybrid signing public key (whichever party attested).
    pub issuer_signing_pk: HybridSigningPublicKey,
    /// Unix timestamp (seconds) when the certificate was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the certificate expires.
    pub expires_at: u64,
    /// Hybrid signature by `issuer_signing_pk` over the certificate body.
    pub signature: HybridSignature,
}

#[cfg(feature = "alloc")]
impl IdentityCertificate {
    /// Issues a new certificate signed by the issuer keypair.
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if the issuer keypair fails to sign.
    pub fn issue(
        issuer_keypair: &HybridSigningKeypair,
        subject_identity: HybridIdentityPublicKey,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let body = Self::signing_data(&subject_identity, issued_at, expires_at);
        let signature = issuer_keypair.sign(&body)?;
        Ok(Self {
            subject_identity,
            issuer_signing_pk: issuer_keypair.public_key().clone(),
            issued_at,
            expires_at,
            signature,
        })
    }

    /// Verifies that the certificate body was signed by `issuer_signing_pk`.
    ///
    /// Note: this does NOT check chain-of-trust or expiry — call
    /// [`Self::validate_validity_window`] separately for time-bound checks.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature does not verify.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self) -> Result<()> {
        let body = Self::signing_data(&self.subject_identity, self.issued_at, self.expires_at);
        self.issuer_signing_pk.verify(&body, &self.signature)
    }

    /// Returns `Ok` if `now` is within `[issued_at, expires_at]`.
    ///
    /// # Errors
    ///
    /// Returns `BundleTimestampInFuture` if the certificate was issued in
    /// the future; `BundleExpired` if it has expired. (The pre-existing
    /// `Bundle*` variants are reused — the audit reading is the same:
    /// timestamp-bound credential failed its window check.)
    pub fn validate_validity_window(&self, now: u64) -> Result<()> {
        if self.issued_at > now {
            return Err(CryptoError::BundleTimestampInFuture);
        }
        if self.expires_at < now {
            return Err(CryptoError::BundleExpired);
        }
        Ok(())
    }

    /// Serialises the certificate to its canonical wire form.
    ///
    /// Layout: `subject_identity (3,223) || issuer_signing_pk (2,009) ||
    /// issued_at (8) || expires_at (8) || signature (3,423)` = 8,671 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CERTIFICATE_WIRE_SIZE);
        bytes.extend_from_slice(&self.subject_identity.to_bytes());
        bytes.extend_from_slice(&self.issuer_signing_pk.to_bytes());
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Parses a certificate from its canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the slice has the wrong size or any
    /// sub-component fails to decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CERTIFICATE_WIRE_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut offset = 0;
        let subject_identity =
            HybridIdentityPublicKey::from_bytes(&bytes[offset..offset + IDENTITY_PK_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += IDENTITY_PK_SIZE;

        let issuer_signing_pk =
            HybridSigningPublicKey::from_bytes(&bytes[offset..offset + SIGNING_PK_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += SIGNING_PK_SIZE;

        let issued_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;
        let expires_at = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        offset += 8;

        let signature = HybridSignature::from_bytes(&bytes[offset..])
            .map_err(|_| CryptoError::MalformedMessage)?;

        Ok(Self {
            subject_identity,
            issuer_signing_pk,
            issued_at,
            expires_at,
            signature,
        })
    }

    /// Returns the bytes that should be signed for this certificate.
    fn signing_data(
        subject_identity: &HybridIdentityPublicKey,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let subject_bytes = subject_identity.to_bytes();
        let mut data = Vec::with_capacity(IDENTITY_CERT_CONTEXT.len() + subject_bytes.len() + 16);
        data.extend_from_slice(IDENTITY_CERT_CONTEXT.as_bytes());
        data.extend_from_slice(&subject_bytes);
        data.extend_from_slice(&issued_at.to_le_bytes());
        data.extend_from_slice(&expires_at.to_le_bytes());
        data
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for IdentityCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityCertificate")
            .field("subject_identity", &"[hybrid identity pk]")
            .field("issuer_signing_pk", &"[hybrid signing pk]")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"[3423 bytes]")
            .finish()
    }
}

/// A safety number wrapped with one or two identity certificates plus the
/// parties' hybrid signatures over the safety number itself.
///
/// Per the spec §15.4 construction, the local party always provides
/// `our_certificate` and `our_signature`. The remote party's certificate
/// and signature are optional: in flows where only one side has been
/// certified (e.g., introducer-side verification before the other party
/// has been certified), the remote pair is `None`.
///
/// Calling [`Self::verify`] checks that the local-side certificate is
/// self-consistent (issuer signed subject) and that `our_signature` is
/// over the safety number under the certified subject identity key.
/// When the remote pair is `Some`, the same check is performed on the
/// remote side.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct CertifiedSafetyNumber {
    /// The safety number being certified.
    pub safety_number: SafetyNumber,
    /// Our identity certificate (issued by some attester).
    pub our_certificate: IdentityCertificate,
    /// Our hybrid signature over the safety number.
    pub our_signature: HybridSignature,
    /// The other party's identity certificate, when available.
    pub their_certificate: Option<IdentityCertificate>,
    /// The other party's hybrid signature over the safety number, when
    /// available.
    pub their_signature: Option<HybridSignature>,
}

#[cfg(feature = "alloc")]
impl CertifiedSafetyNumber {
    /// Creates a one-sided certified safety number (our side only).
    ///
    /// # Errors
    ///
    /// Returns `SignatureError` if our keypair fails to sign.
    pub fn create_one_sided(
        safety_number: SafetyNumber,
        our_keypair: &HybridSigningKeypair,
        our_certificate: IdentityCertificate,
    ) -> Result<Self> {
        let body = Self::signing_data(&safety_number);
        let our_signature = our_keypair.sign(&body)?;
        Ok(Self {
            safety_number,
            our_certificate,
            our_signature,
            their_certificate: None,
            their_signature: None,
        })
    }

    /// Attaches the other party's certified signature to a previously
    /// one-sided certified safety number.
    pub fn attach_their_side(
        &mut self,
        their_certificate: IdentityCertificate,
        their_signature: HybridSignature,
    ) {
        self.their_certificate = Some(their_certificate);
        self.their_signature = Some(their_signature);
    }

    /// Verifies the certified safety number end-to-end.
    ///
    /// Walks:
    /// 1. `our_certificate` self-verifies (issuer signed subject).
    /// 2. `our_signature` is by `our_certificate.subject_identity` over
    ///    the safety number.
    /// 3. If `their_certificate` and `their_signature` are present, the
    ///    same two checks are performed on the remote pair.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` at the first failed check.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self) -> Result<()> {
        let body = Self::signing_data(&self.safety_number);

        self.our_certificate.verify()?;
        self.our_certificate
            .subject_identity
            .signing
            .verify(&body, &self.our_signature)?;

        if let (Some(their_cert), Some(their_sig)) =
            (&self.their_certificate, &self.their_signature)
        {
            their_cert.verify()?;
            their_cert
                .subject_identity
                .signing
                .verify(&body, their_sig)?;
        }

        Ok(())
    }

    /// Serialises to the canonical wire form.
    ///
    /// Layout: `safety_number (32) || presence_byte (1) ||
    /// our_certificate (8,671) || our_signature (3,423) ||
    /// [their_certificate (8,671) || their_signature (3,423)]`. The
    /// presence byte is `0x00` for one-sided, `0x01` for two-sided.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * (CERTIFICATE_WIRE_SIZE + SIGNATURE_WIRE_SIZE) + 33);
        bytes.extend_from_slice(self.safety_number.fingerprint());
        match (&self.their_certificate, &self.their_signature) {
            (Some(their_cert), Some(their_sig)) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&self.our_certificate.to_bytes());
                bytes.extend_from_slice(&self.our_signature.to_bytes());
                bytes.extend_from_slice(&their_cert.to_bytes());
                bytes.extend_from_slice(&their_sig.to_bytes());
            }
            _ => {
                bytes.push(0x00);
                bytes.extend_from_slice(&self.our_certificate.to_bytes());
                bytes.extend_from_slice(&self.our_signature.to_bytes());
            }
        }
        bytes
    }

    /// Parses from the canonical wire form.
    ///
    /// # Errors
    ///
    /// Returns `MalformedMessage` if the slice has the wrong size, an
    /// unrecognised presence byte, or if any sub-component fails to decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const HEADER: usize = 32 + 1;
        const ONE_SIDED_SIZE: usize = HEADER + CERTIFICATE_WIRE_SIZE + SIGNATURE_WIRE_SIZE;
        const TWO_SIDED_SIZE: usize = HEADER + 2 * (CERTIFICATE_WIRE_SIZE + SIGNATURE_WIRE_SIZE);

        if bytes.len() != ONE_SIDED_SIZE && bytes.len() != TWO_SIDED_SIZE {
            return Err(CryptoError::MalformedMessage);
        }

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&bytes[..32]);
        let safety_number = SafetyNumber::from_fingerprint_bytes(fingerprint);

        let presence = bytes[32];
        let mut offset = HEADER;

        let our_certificate =
            IdentityCertificate::from_bytes(&bytes[offset..offset + CERTIFICATE_WIRE_SIZE])?;
        offset += CERTIFICATE_WIRE_SIZE;

        let our_signature =
            HybridSignature::from_bytes(&bytes[offset..offset + SIGNATURE_WIRE_SIZE])
                .map_err(|_| CryptoError::MalformedMessage)?;
        offset += SIGNATURE_WIRE_SIZE;

        let (their_certificate, their_signature) = match presence {
            0x00 => {
                if bytes.len() != ONE_SIDED_SIZE {
                    return Err(CryptoError::MalformedMessage);
                }
                (None, None)
            }
            0x01 => {
                if bytes.len() != TWO_SIDED_SIZE {
                    return Err(CryptoError::MalformedMessage);
                }
                let their_cert = IdentityCertificate::from_bytes(
                    &bytes[offset..offset + CERTIFICATE_WIRE_SIZE],
                )?;
                offset += CERTIFICATE_WIRE_SIZE;
                let their_sig =
                    HybridSignature::from_bytes(&bytes[offset..offset + SIGNATURE_WIRE_SIZE])
                        .map_err(|_| CryptoError::MalformedMessage)?;
                (Some(their_cert), Some(their_sig))
            }
            _ => return Err(CryptoError::MalformedMessage),
        };

        Ok(Self {
            safety_number,
            our_certificate,
            our_signature,
            their_certificate,
            their_signature,
        })
    }

    /// Returns the bytes signed by each party to attest to the safety number.
    fn signing_data(safety_number: &SafetyNumber) -> Vec<u8> {
        let mut data = Vec::with_capacity(CERTIFIED_SAFETY_NUMBER_CONTEXT.len() + 32);
        data.extend_from_slice(CERTIFIED_SAFETY_NUMBER_CONTEXT.as_bytes());
        data.extend_from_slice(safety_number.fingerprint());
        data
    }
}

/// Size of `HybridIdentityPublicKey` on the wire (signing 2,009 + KEM 1,214).
const IDENTITY_PK_SIZE: usize = 3_223;
/// Size of `HybridSigningPublicKey` on the wire (Ed448 57 + ML-DSA 1,952).
const SIGNING_PK_SIZE: usize = 2_009;
/// Size of `HybridSignature` on the wire (Ed448 114 + ML-DSA 3,309).
const SIGNATURE_WIRE_SIZE: usize = 3_423;
/// Total wire size of one [`IdentityCertificate`].
pub const CERTIFICATE_WIRE_SIZE: usize =
    IDENTITY_PK_SIZE + SIGNING_PK_SIZE + 8 + 8 + SIGNATURE_WIRE_SIZE;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::HybridIdentityKeypair;

    fn fresh_identity_kp() -> HybridIdentityKeypair {
        HybridIdentityKeypair::generate().unwrap()
    }

    fn fresh_signing_kp() -> HybridSigningKeypair {
        HybridSigningKeypair::generate().unwrap()
    }

    #[test]
    fn test_certificate_wire_size_constant() {
        assert_eq!(CERTIFICATE_WIRE_SIZE, 3_223 + 2_009 + 8 + 8 + 3_423);
        assert_eq!(CERTIFICATE_WIRE_SIZE, 8_671);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_identity_certificate_issue_verify_roundtrip() {
        let issuer = fresh_signing_kp();
        let subject = fresh_identity_kp();

        let cert = IdentityCertificate::issue(&issuer, subject.public_key().clone(), 1_000, 2_000)
            .unwrap();
        assert!(cert.verify().is_ok());

        let bytes = cert.to_bytes();
        assert_eq!(bytes.len(), CERTIFICATE_WIRE_SIZE);
        let parsed = IdentityCertificate::from_bytes(&bytes).unwrap();
        assert!(parsed.verify().is_ok());
        assert_eq!(parsed.issued_at, 1_000);
        assert_eq!(parsed.expires_at, 2_000);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_identity_certificate_validity_window() {
        let issuer = fresh_signing_kp();
        let subject = fresh_identity_kp();
        let cert = IdentityCertificate::issue(&issuer, subject.public_key().clone(), 1_000, 2_000)
            .unwrap();

        assert!(cert.validate_validity_window(1_500).is_ok());
        assert!(matches!(
            cert.validate_validity_window(500),
            Err(CryptoError::BundleTimestampInFuture)
        ));
        assert!(matches!(
            cert.validate_validity_window(2_500),
            Err(CryptoError::BundleExpired)
        ));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_identity_certificate_tamper_detection() {
        let issuer = fresh_signing_kp();
        let subject = fresh_identity_kp();
        let mut cert =
            IdentityCertificate::issue(&issuer, subject.public_key().clone(), 1_000, 2_000)
                .unwrap();
        cert.issued_at = 999;
        assert!(cert.verify().is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_certified_safety_number_one_sided_roundtrip() {
        let alice_signing = fresh_signing_kp();
        let alice_identity = fresh_identity_kp();
        let bob_identity = fresh_identity_kp();

        let alice_cert = IdentityCertificate::issue(
            &alice_signing,
            alice_identity.public_key().clone(),
            1_000,
            2_000,
        )
        .unwrap();

        let sn = SafetyNumber::new(alice_identity.public_key(), bob_identity.public_key());
        let certified =
            CertifiedSafetyNumber::create_one_sided(sn, alice_identity.signing(), alice_cert)
                .unwrap();

        assert!(certified.verify().is_ok());

        let bytes = certified.to_bytes();
        let parsed = CertifiedSafetyNumber::from_bytes(&bytes).unwrap();
        assert!(parsed.verify().is_ok());
        assert!(parsed.their_certificate.is_none());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_certified_safety_number_two_sided_roundtrip() {
        let alice_signing = fresh_signing_kp();
        let bob_signing = fresh_signing_kp();
        let alice_identity = fresh_identity_kp();
        let bob_identity = fresh_identity_kp();

        let alice_cert = IdentityCertificate::issue(
            &alice_signing,
            alice_identity.public_key().clone(),
            1_000,
            2_000,
        )
        .unwrap();
        let bob_cert = IdentityCertificate::issue(
            &bob_signing,
            bob_identity.public_key().clone(),
            1_000,
            2_000,
        )
        .unwrap();

        let sn = SafetyNumber::new(alice_identity.public_key(), bob_identity.public_key());
        let mut certified = CertifiedSafetyNumber::create_one_sided(
            sn.clone(),
            alice_identity.signing(),
            alice_cert,
        )
        .unwrap();

        // Bob signs the same safety number.
        let bob_body = [CERTIFIED_SAFETY_NUMBER_CONTEXT.as_bytes(), sn.fingerprint()].concat();
        let bob_signature = bob_identity.signing().sign(&bob_body).unwrap();
        certified.attach_their_side(bob_cert, bob_signature);

        assert!(certified.verify().is_ok());

        let bytes = certified.to_bytes();
        let parsed = CertifiedSafetyNumber::from_bytes(&bytes).unwrap();
        assert!(parsed.verify().is_ok());
        assert!(parsed.their_certificate.is_some());
        assert!(parsed.their_signature.is_some());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_certified_safety_number_tampered_safety_number_rejected() {
        let alice_signing = fresh_signing_kp();
        let alice_identity = fresh_identity_kp();
        let bob_identity = fresh_identity_kp();

        let alice_cert = IdentityCertificate::issue(
            &alice_signing,
            alice_identity.public_key().clone(),
            1_000,
            2_000,
        )
        .unwrap();

        let sn = SafetyNumber::new(alice_identity.public_key(), bob_identity.public_key());
        let mut certified =
            CertifiedSafetyNumber::create_one_sided(sn, alice_identity.signing(), alice_cert)
                .unwrap();

        // Substitute a different safety number — Alice's signature no
        // longer covers it.
        let other_identity = fresh_identity_kp();
        certified.safety_number =
            SafetyNumber::new(alice_identity.public_key(), other_identity.public_key());

        assert!(certified.verify().is_err());
    }
}
