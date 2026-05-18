//! Error types for the Trelis cryptographic library.
//!
//! # Purpose
//!
//! This crate provides [`CryptoError`], the comprehensive error type used
//! across every crate of the Trelis hybrid post-quantum protocol library,
//! along with [`Result<T>`] (the crate-wide result alias) and
//! [`ErrorCategory`] (the classification surface used for handling
//! decisions).
//!
//! # Scope
//!
//! - One enumerated error type covering every failure mode in the protocol
//!   stack: key handling, signatures, AEAD encryption, KEM, protocol logic,
//!   wire-format parsing, bundle validation, device wraps, RNG, tree/group
//!   operations, rate limiting, sessions, and serialisation.
//! - One [`ErrorCategory`] enum (Fatal / Transient / Protocol / Security)
//!   for caller-facing classification.
//! - `Display` impls deliberately scrubbed of sensitive information.
//!
//! Out of scope: caller-specific error wrapping, anyhow / eyre integration,
//! backtrace capture (this crate is `no_std`).
//!
//! # Threat model fit
//!
//! Error variants are designed for the **co-located-process timing
//! adversary** model (see `FINDINGS-v1.1.md` Phase 2). The relevant choices:
//!
//! - Decryption failures collapse to either
//!   [`CryptoError::DecryptionFailed`] (oracle-safe; for attacker-facing
//!   paths) or [`CryptoError::AeadAuthenticationFailed`] (narrower; for
//!   internal symmetric-only paths where oracle safety is not a concern).
//! - Signature failures collapse to [`CryptoError::SignatureVerificationFailed`]
//!   regardless of whether Ed448 or ML-DSA-65 failed — distinguishing would
//!   leak protocol-internal state.
//! - Variants carry only public diagnostic data (lengths, counters, version
//!   bytes). No variant carries secret bytes or key material.
//!
//! # Public-API entry points
//!
//! - [`CryptoError`] — the error enum itself.
//! - [`Result<T>`] — the `core::result::Result<T, CryptoError>` alias used
//!   throughout the workspace.
//! - [`ErrorCategory`] and [`CryptoError::category`] / [`CryptoError::is_fatal`] /
//!   [`CryptoError::is_security_error`] — classification helpers for callers
//!   building retry / rejection policy.
//!
//! # Feature flags
//!
//! - `alloc` — Enables `extern crate alloc`. The crate is `no_std`; `alloc`
//!   is required only by callers that already use it.
//! - `std` — Enables `extern crate std` and implements [`std::error::Error`]
//!   for [`CryptoError`] so the type integrates with `std`-based error
//!   pipelines.
//!
//! Default features: none. The base build is `no_std` with no allocator.
//!
//! # Security caveats
//!
//! - `Display` strings are stable, public, and side-channel-safe. They do
//!   not differ based on which internal branch produced the error, so
//!   logging the `Display` output of a `CryptoError` is safe even on
//!   attacker-facing paths.
//! - The enum is `#[non_exhaustive]`. Downstream callers MUST NOT pattern-
//!   match without a wildcard arm; adding a variant is not a breaking
//!   change.
//! - Several variants are reserved for code paths that exist in the
//!   protocol but are not yet exercised at HEAD — they are documented as
//!   "Reserved for …" and Phase 13 TEST-04 will close the coverage gap.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Pedantic-lint policy:
// - `too_many_lines` on `CryptoError::fmt` is intentional: the Display
//   match is exhaustive over CryptoError variants. Splitting would lose
//   the single-place enum-coverage assertion that Phase 13 TEST-04 relies
//   on.
// See Phase 10 disposition in `10-PEDANTIC-DRAFT.md`.
#![allow(clippy::too_many_lines)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

/// Result type alias using [`CryptoError`].
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Comprehensive error type for all cryptographic operations.
///
/// All variants are designed to avoid leaking sensitive information through
/// error messages. Timing-sensitive operations should return the same error
/// variant regardless of which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    // ─── Key Errors ─────────────────────────────────────────────────────────
    /// Key length does not match expected size.
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// Key generation failed (e.g., RNG failure).
    KeyGenerationFailed,

    /// Key derivation function failed.
    ///
    /// Reserved for KDF code paths. Caller can retry with different inputs
    /// if the derivation is non-deterministic, or surface the failure to
    /// the operator if the inputs are well-formed.
    KeyDerivationFailed,

    // ─── Signature Errors ───────────────────────────────────────────────────
    /// Signature verification failed.
    ///
    /// This error is intentionally vague to prevent timing attacks.
    /// It does not distinguish between Ed448 and ML-DSA-65 failures,
    /// and (after Phase 11's CLEAN-06 merge) it covers hybrid-signature
    /// failures where either or both component algorithms failed —
    /// callers receive the same external signal regardless.
    SignatureVerificationFailed,

    /// Invalid signature format or length.
    InvalidSignature,

    /// Context string exceeds maximum allowed length (255 bytes).
    InvalidContextLength {
        /// Actual length in bytes.
        actual: usize,
        /// Maximum allowed length (255).
        max: usize,
    },

    // ─── Encryption Errors ──────────────────────────────────────────────────
    /// Decryption failed due to invalid ciphertext, wrong key, or any other
    /// failure of a high-level decrypt path.
    ///
    /// **Intentionally vague.** This variant is used when a higher-level
    /// decrypt path cannot or should not reveal whether the failure is at
    /// the AEAD-tag check, the key derivation, or the post-decrypt
    /// validation. Returning the same external signal for every internal
    /// branch is the standard oracle-attack defence — distinguishing causes
    /// would let an attacker learn which step rejected the ciphertext.
    ///
    /// Use [`AeadAuthenticationFailed`](Self::AeadAuthenticationFailed)
    /// only when the caller has already narrowed the failure to the AEAD
    /// layer specifically AND oracle safety is not a concern (e.g.,
    /// internal symmetric-only paths that never see attacker-controlled
    /// ciphertexts).
    DecryptionFailed,

    /// AEAD authentication tag verification failed.
    ///
    /// **Specifically the AEAD tag check failed.** Use this variant when
    /// the caller has already narrowed the failure to the AEAD layer and
    /// oracle safety is NOT a concern (e.g., internal symmetric-only
    /// paths where the ciphertext is not attacker-controlled).
    ///
    /// For attacker-facing decrypt paths (anything that processes a
    /// message from the wire), prefer
    /// [`DecryptionFailed`](Self::DecryptionFailed) — the uniform external
    /// signal prevents oracle attacks.
    AeadAuthenticationFailed,

    /// Nonce has invalid length.
    InvalidNonceLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    // ─── KEM Errors ─────────────────────────────────────────────────────────
    /// KEM encapsulation failed.
    EncapsulationFailed,

    /// KEM decapsulation failed.
    DecapsulationFailed,

    /// Invalid ciphertext format.
    InvalidCiphertext,

    /// Ciphertext length does not match expected size.
    InvalidCiphertextLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    // ─── Protocol Errors ────────────────────────────────────────────────────
    /// Unknown sender public key (not in known keys).
    ///
    /// Reserved for sender-side known-keys validation. Caller can request a
    /// key-transparency update for the sender or reject the message.
    UnknownSenderKey,

    /// Message counter is too old (possible replay or lost sync).
    ///
    /// Reserved for replay-protection logic. Caller logs the anomaly and
    /// rejects the message (Security category).
    MessageCounterTooOld,

    /// Message counter is too far ahead (exceeds `MAX_SKIP`).
    ///
    /// Reserved for sync-loss detection. Caller logs the gap and either
    /// re-establishes the session or drops the message.
    MessageCounterTooFarAhead {
        /// Maximum allowed skip.
        max_skip: u64,
        /// Actual gap encountered.
        gap: u64,
    },

    /// Too many skipped keys stored (exceeds limit).
    ///
    /// Reserved for skipped-keys cache bounds. Caller can clean the cache
    /// or refuse to accept further out-of-order messages.
    TooManySkippedKeys {
        /// Maximum allowed skipped keys.
        limit: usize,
    },

    /// Skipped key has expired (exceeded `MAX_AGE`).
    ///
    /// Reserved for skipped-keys age-based expiry. Caller logs and rejects
    /// the message — the original key is no longer reachable.
    SkippedKeyExpired,

    /// Duplicate message detected (replay attack).
    ///
    /// Caller rejects the message (Security category). The current code
    /// path uses this only in the replay-defence test; protocol callers
    /// surface this when the same wire-counter is observed twice.
    DuplicateMessage,

    /// Epoch is too old for processing.
    ///
    /// Reserved for replay-candidate detection at the epoch boundary.
    /// Caller logs and rejects (Security category).
    EpochTooOld {
        /// Minimum accepted epoch.
        minimum: u64,
        /// Received epoch.
        received: u64,
    },

    /// Unknown recipient key ID.
    UnknownRecipientKeyId,

    /// Session has been exhausted (counter overflow imminent).
    SessionExhausted {
        /// Current counter value.
        current: u64,
        /// Threshold at which session should rotate.
        threshold: u64,
    },

    // ─── Wire Format Errors ─────────────────────────────────────────────────
    /// Unsupported protocol version.
    UnsupportedProtocolVersion {
        /// Received version byte.
        received: u8,
        /// Supported version byte.
        supported: u8,
    },

    /// Unsupported cipher suite.
    UnsupportedCipherSuite {
        /// Received cipher suite byte.
        received: u8,
        /// Supported cipher suite byte.
        supported: u8,
    },

    /// Message is malformed or truncated.
    MalformedMessage,

    /// Invalid header format.
    ///
    /// Reserved for wire-format header parsing failures distinct from
    /// `MalformedMessage` (which is the more general parse-failed variant).
    /// Caller rejects the message and may log the malformed header.
    InvalidHeader,

    /// Unexpected end of input during parsing.
    ///
    /// Reserved for truncation detection in wire-format parsers. Carries
    /// the expected/available byte counts as a diagnostic. Caller rejects
    /// the message and may log the truncation.
    UnexpectedEndOfInput {
        /// Expected minimum bytes.
        expected: usize,
        /// Actual bytes available.
        available: usize,
    },

    // ─── Bundle Errors ──────────────────────────────────────────────────────
    /// Pre-key bundle signature verification failed.
    InvalidBundleSignature,

    /// Pre-key bundle has expired.
    BundleExpired,

    /// Bundle timestamp is in the future.
    BundleTimestampInFuture,

    // ─── Device Wrap Errors ─────────────────────────────────────────────────
    /// Device key wrap is for wrong recipient.
    ///
    /// Reserved for the device-wrap addressing logic. Caller drops the
    /// message and may log the misaddress.
    WrongRecipient,

    /// Context mismatch in device key wrap.
    ///
    /// Reserved for device-wrap context-string validation. Caller logs
    /// and rejects.
    ContextMismatch,

    // ─── Random Number Generation ───────────────────────────────────────────
    /// Cryptographically secure RNG failure.
    RngFailure,

    // ─── Tree/Group Errors ──────────────────────────────────────────────────
    /// Invalid tree node index.
    ///
    /// Reserved for tree-data-structure invariant violation. Indicates an
    /// internal logic bug or an attack on the tree integrity (Protocol
    /// category — caller may need to resync session state).
    InvalidNodeIndex,

    /// Member not found in group.
    ///
    /// Reserved for group-membership lookup. Caller refreshes the group
    /// state and retries.
    MemberNotFound,

    /// Group is full (maximum members reached).
    ///
    /// Reserved for the capacity-bound check at member add. Fatal category
    /// — caller surrenders the operation.
    GroupFull,

    /// Invalid tree state.
    ///
    /// Reserved for general tree-integrity invariant violation (distinct
    /// from `InvalidNodeIndex` which is index-specific). Fatal category —
    /// caller surrenders the operation.
    InvalidTreeState,

    /// Invalid group size (e.g., zero members).
    InvalidGroupSize,

    /// Group ID mismatch between commit and session.
    GroupIdMismatch,

    /// Cannot remove yourself from the group.
    SelfRemovalForbidden,

    /// Invalid leaf position in tree.
    InvalidLeafPosition,

    /// You have been removed from the group.
    RemovedFromGroup,

    /// Epoch mismatch between message and session.
    EpochMismatch {
        /// Expected epoch.
        expected: u64,
        /// Received epoch.
        received: u64,
    },

    // ─── Rate Limiting ──────────────────────────────────────────────────────
    /// Rate limit exceeded.
    RateLimitExceeded,

    // ─── Session Errors ─────────────────────────────────────────────────────
    /// No active session — either before initialisation or after teardown.
    ///
    /// Phase 11 CLEAN-06 merged the previously-separate `SessionNotInitialised`
    /// variant into this one: no in-tree match site distinguished the two,
    /// and the merge keeps the surface smaller. Callers respond to this
    /// variant by establishing (or re-establishing) a session — typically
    /// via the X3DH-PQ initiator/responder flow.
    NoActiveSession,

    /// Session has been marked as compromised.
    SessionCompromised,

    /// No recipient public key available.
    NoRecipientKey,

    /// Message arrived out of order (ordered delivery required).
    ///
    /// Per-message KEM ratchet requires ordered, reliable delivery.
    /// This error indicates transport failure or session desync. Reserved
    /// for the per-message-KEM-ratchet ordering checks. Caller logs and
    /// may re-establish session.
    MessageOrderViolation {
        /// Expected message number.
        expected: u64,
        /// Received message number.
        received: u64,
    },

    // ─── Serialisation Errors ───────────────────────────────────────────────
    /// Invalid magic bytes in serialised data.
    InvalidMagic,

    /// Unsupported state serialisation version.
    UnsupportedStateVersion,

    // ─── Multi-Device Approval / Nonce Errors (Phase 16) ────────────────────
    /// Server-issued nonce window has elapsed.
    ///
    /// Returned by `DeviceApprovalCertificate::verify` when the elapsed time
    /// since `approved_at` exceeds the caller-supplied `NonceWindow`. Distinct
    /// from `SignatureVerificationFailed` so callers can route on the specific
    /// freshness failure (e.g. surface "approval link expired" to the user).
    NonceExpired,

    /// Caller's replay-cache reports the approval nonce was already consumed.
    ///
    /// The library never maintains a nonce store; this variant is what
    /// callers map their `ConsumeApprovalNonce` "already consumed" outcome to
    /// when wrapping the approval-verify call. Security category — indicates a
    /// genuine replay attempt or a buggy caller.
    NonceReplayed,

    /// Approval nonce in the cert does not match the nonce the verifier expected.
    ///
    /// The verifier remembers the nonce it issued for the in-flight approval
    /// flow; if the cert carries a different `server_nonce`, this variant
    /// fires. Security category — indicates a man-in-the-middle swap or
    /// approval-cert reuse from a different flow.
    NonceMismatch,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Key errors
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            Self::KeyGenerationFailed => write!(f, "key generation failed"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),

            // Signature errors
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::InvalidSignature => write!(f, "invalid signature format"),
            Self::InvalidContextLength { actual, max } => {
                write!(
                    f,
                    "context string too long: {actual} bytes exceeds maximum {max}"
                )
            }

            // Encryption errors
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::AeadAuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::InvalidNonceLength { expected, actual } => {
                write!(f, "invalid nonce length: expected {expected}, got {actual}")
            }

            // KEM errors
            Self::EncapsulationFailed => write!(f, "KEM encapsulation failed"),
            Self::DecapsulationFailed => write!(f, "KEM decapsulation failed"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext format"),
            Self::InvalidCiphertextLength { expected, actual } => {
                write!(
                    f,
                    "invalid ciphertext length: expected {expected}, got {actual}"
                )
            }

            // Protocol errors
            Self::UnknownSenderKey => write!(f, "unknown sender public key"),
            Self::MessageCounterTooOld => write!(f, "message counter too old"),
            Self::MessageCounterTooFarAhead { max_skip, gap } => {
                write!(
                    f,
                    "message counter too far ahead (max skip: {max_skip}, gap: {gap})"
                )
            }
            Self::TooManySkippedKeys { limit } => {
                write!(f, "too many skipped keys (limit: {limit})")
            }
            Self::SkippedKeyExpired => write!(f, "skipped key has expired"),
            Self::DuplicateMessage => write!(f, "duplicate message detected"),
            Self::EpochTooOld { minimum, received } => {
                write!(
                    f,
                    "epoch too old (minimum: {minimum}, received: {received})"
                )
            }
            Self::UnknownRecipientKeyId => write!(f, "unknown recipient key ID"),
            Self::SessionExhausted { current, threshold } => {
                write!(
                    f,
                    "session exhausted (current: {current}, threshold: {threshold})"
                )
            }

            // Multi-device approval / nonce errors
            Self::NonceExpired => write!(f, "approval nonce window has elapsed"),
            Self::NonceReplayed => write!(f, "approval nonce already consumed"),
            Self::NonceMismatch => write!(f, "approval nonce does not match issued value"),

            // Wire format errors
            Self::UnsupportedProtocolVersion {
                received,
                supported,
            } => {
                write!(
                    f,
                    "unsupported protocol version: received 0x{received:02x}, supported 0x{supported:02x}"
                )
            }
            Self::UnsupportedCipherSuite {
                received,
                supported,
            } => {
                write!(
                    f,
                    "unsupported cipher suite: received 0x{received:02x}, supported 0x{supported:02x}"
                )
            }
            Self::MalformedMessage => write!(f, "malformed message"),
            Self::InvalidHeader => write!(f, "invalid header format"),
            Self::UnexpectedEndOfInput {
                expected,
                available,
            } => {
                write!(
                    f,
                    "unexpected end of input: expected {expected}, available {available}"
                )
            }

            // Bundle errors
            Self::InvalidBundleSignature => write!(f, "invalid bundle signature"),
            Self::BundleExpired => write!(f, "bundle has expired"),
            Self::BundleTimestampInFuture => write!(f, "bundle timestamp is in the future"),

            // Device wrap errors
            Self::WrongRecipient => write!(f, "wrong recipient for device key wrap"),
            Self::ContextMismatch => write!(f, "context mismatch in device key wrap"),

            // RNG errors
            Self::RngFailure => write!(f, "RNG failure"),

            // Tree/group errors
            Self::InvalidNodeIndex => write!(f, "invalid tree node index"),
            Self::MemberNotFound => write!(f, "member not found in group"),
            Self::GroupFull => write!(f, "group is full"),
            Self::InvalidTreeState => write!(f, "invalid tree state"),
            Self::InvalidGroupSize => write!(f, "invalid group size"),
            Self::GroupIdMismatch => write!(f, "group ID mismatch"),
            Self::SelfRemovalForbidden => write!(f, "cannot remove yourself from group"),
            Self::InvalidLeafPosition => write!(f, "invalid leaf position"),
            Self::RemovedFromGroup => write!(f, "you have been removed from the group"),
            Self::EpochMismatch { expected, received } => {
                write!(
                    f,
                    "epoch mismatch: expected {expected}, received {received}"
                )
            }

            // Rate limiting
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),

            // Session errors
            Self::NoActiveSession => write!(f, "no active session"),
            Self::SessionCompromised => write!(f, "session compromised"),
            Self::NoRecipientKey => write!(f, "no recipient public key"),
            Self::MessageOrderViolation { expected, received } => {
                write!(
                    f,
                    "message order violation: expected {expected}, received {received}"
                )
            }

            // Serialisation errors
            Self::InvalidMagic => write!(f, "invalid magic bytes"),
            Self::UnsupportedStateVersion => write!(f, "unsupported state version"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Error category for classification and handling decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Fatal errors that cannot be recovered from.
    Fatal,
    /// Transient errors that may succeed on retry.
    Transient,
    /// Protocol-level errors requiring session reset.
    Protocol,
    /// Security-related errors (potential attacks).
    Security,
}

impl CryptoError {
    /// Returns the category of this error for handling decisions.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            // Fatal errors
            Self::KeyGenerationFailed
            | Self::RngFailure
            | Self::InvalidTreeState
            | Self::GroupFull
            | Self::InvalidGroupSize => ErrorCategory::Fatal,

            // Transient errors
            Self::RateLimitExceeded => ErrorCategory::Transient,

            // Protocol errors requiring session reset
            Self::SessionExhausted { .. }
            | Self::EpochTooOld { .. }
            | Self::UnknownSenderKey
            | Self::UnknownRecipientKeyId
            | Self::MemberNotFound
            | Self::InvalidNodeIndex
            | Self::NoActiveSession
            | Self::SessionCompromised
            | Self::NoRecipientKey
            | Self::GroupIdMismatch
            | Self::SelfRemovalForbidden
            | Self::InvalidLeafPosition
            | Self::RemovedFromGroup
            | Self::EpochMismatch { .. }
            | Self::MessageOrderViolation { .. } => ErrorCategory::Protocol,

            // Security errors (potential attacks)
            Self::SignatureVerificationFailed
            | Self::InvalidSignature
            | Self::DecryptionFailed
            | Self::AeadAuthenticationFailed
            | Self::DecapsulationFailed
            | Self::MessageCounterTooOld
            | Self::MessageCounterTooFarAhead { .. }
            | Self::TooManySkippedKeys { .. }
            | Self::SkippedKeyExpired
            | Self::DuplicateMessage
            | Self::InvalidBundleSignature
            | Self::BundleExpired
            | Self::BundleTimestampInFuture
            | Self::WrongRecipient
            | Self::ContextMismatch
            | Self::UnsupportedProtocolVersion { .. }
            | Self::UnsupportedCipherSuite { .. }
            | Self::MalformedMessage
            | Self::InvalidHeader
            | Self::UnexpectedEndOfInput { .. }
            | Self::InvalidKeyLength { .. }
            | Self::InvalidNonceLength { .. }
            | Self::InvalidContextLength { .. }
            | Self::InvalidCiphertext
            | Self::InvalidCiphertextLength { .. }
            | Self::EncapsulationFailed
            | Self::KeyDerivationFailed
            | Self::InvalidMagic
            | Self::UnsupportedStateVersion
            | Self::NonceExpired
            | Self::NonceReplayed
            | Self::NonceMismatch => ErrorCategory::Security,
        }
    }

    /// Returns `true` if this is a fatal error that cannot be recovered from.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self.category(), ErrorCategory::Fatal)
    }

    /// Returns `true` if this is a security-related error.
    #[must_use]
    pub const fn is_security_error(&self) -> bool {
        matches!(self.category(), ErrorCategory::Security)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 32, got 16");
    }

    #[test]
    fn test_error_category() {
        assert_eq!(CryptoError::RngFailure.category(), ErrorCategory::Fatal);
        assert_eq!(
            CryptoError::RateLimitExceeded.category(),
            ErrorCategory::Transient
        );
        assert_eq!(
            CryptoError::NoActiveSession.category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            CryptoError::DuplicateMessage.category(),
            ErrorCategory::Security
        );
    }

    #[test]
    fn test_is_fatal() {
        assert!(CryptoError::RngFailure.is_fatal());
        assert!(!CryptoError::DecryptionFailed.is_fatal());
    }

    #[test]
    fn test_is_security_error() {
        assert!(CryptoError::DuplicateMessage.is_security_error());
        assert!(CryptoError::SignatureVerificationFailed.is_security_error());
        assert!(!CryptoError::RateLimitExceeded.is_security_error());
    }
}
