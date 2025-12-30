//! Error types for the Trelis cryptographic library.
//!
//! This crate provides a comprehensive error type covering all failure modes
//! in the Trelis hybrid post-quantum protocol.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
    KeyDerivationFailed,

    // ─── Signature Errors ───────────────────────────────────────────────────

    /// Signature verification failed.
    ///
    /// This error is intentionally vague to prevent timing attacks.
    /// It does not distinguish between Ed448 and ML-DSA-65 failures.
    SignatureVerificationFailed,

    /// Hybrid signature verification failed.
    ///
    /// Both Ed448 and ML-DSA-65 signatures must verify.
    /// This error is returned if either or both fail.
    HybridSignatureVerificationFailed,

    /// Invalid signature format or length.
    InvalidSignature,

    // ─── Encryption Errors ──────────────────────────────────────────────────

    /// Decryption failed due to invalid ciphertext or wrong key.
    ///
    /// This error is intentionally vague to prevent oracle attacks.
    DecryptionFailed,

    /// AEAD authentication tag verification failed.
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

    /// Session has not been initialised.
    SessionNotInitialised,

    /// Unknown sender public key (not in known keys).
    UnknownSenderKey,

    /// Message counter is too old (possible replay or lost sync).
    MessageCounterTooOld,

    /// Message counter is too far ahead (exceeds MAX_SKIP).
    MessageCounterTooFarAhead {
        /// Maximum allowed skip.
        max_skip: u64,
        /// Actual gap encountered.
        gap: u64,
    },

    /// Too many skipped keys stored (exceeds limit).
    TooManySkippedKeys {
        /// Maximum allowed skipped keys.
        limit: usize,
    },

    /// Skipped key has expired (exceeded MAX_AGE).
    SkippedKeyExpired,

    /// Duplicate message detected (replay attack).
    DuplicateMessage,

    /// Epoch is too old for processing.
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
    InvalidHeader,

    /// Unexpected end of input during parsing.
    UnexpectedEndOfInput {
        /// Expected minimum bytes.
        expected: usize,
        /// Actual bytes available.
        available: usize,
    },

    // ─── Bundle Errors ──────────────────────────────────────────────────────

    /// Pre-key bundle signature verification failed.
    BundleSignatureInvalid,

    /// Pre-key bundle has expired.
    BundleExpired,

    /// Bundle timestamp is in the future.
    BundleTimestampInFuture,

    // ─── Device Wrap Errors ─────────────────────────────────────────────────

    /// Device key wrap is for wrong recipient.
    WrongRecipient,

    /// Context mismatch in device key wrap.
    ContextMismatch,

    // ─── Random Number Generation ───────────────────────────────────────────

    /// Cryptographically secure RNG failure.
    RngFailure,

    // ─── Tree/Group Errors ──────────────────────────────────────────────────

    /// Invalid tree node index.
    InvalidNodeIndex,

    /// Member not found in group.
    MemberNotFound,

    /// Group is full (maximum members reached).
    GroupFull,

    /// Invalid tree state.
    InvalidTreeState,

    /// Invalid group size (e.g., zero members).
    InvalidGroupSize,

    /// Group ID mismatch between commit and session.
    GroupIdMismatch,

    /// Cannot remove yourself from the group.
    CannotRemoveSelf,

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

    /// No active session established.
    NoActiveSession,

    /// Session has been marked as compromised.
    SessionCompromised,

    /// No recipient public key available.
    NoRecipientKey,

    /// Too many messages skipped (exceeds MAX_SKIP).
    TooManySkippedMessages,

    // ─── Serialisation Errors ───────────────────────────────────────────────

    /// Invalid magic bytes in serialised data.
    InvalidMagic,

    /// Unsupported state serialisation version.
    UnsupportedStateVersion,
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
            Self::HybridSignatureVerificationFailed => {
                write!(f, "hybrid signature verification failed")
            }
            Self::InvalidSignature => write!(f, "invalid signature format"),

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
                write!(f, "invalid ciphertext length: expected {expected}, got {actual}")
            }

            // Protocol errors
            Self::SessionNotInitialised => write!(f, "session not initialised"),
            Self::UnknownSenderKey => write!(f, "unknown sender public key"),
            Self::MessageCounterTooOld => write!(f, "message counter too old"),
            Self::MessageCounterTooFarAhead { max_skip, gap } => {
                write!(f, "message counter too far ahead (max skip: {max_skip}, gap: {gap})")
            }
            Self::TooManySkippedKeys { limit } => {
                write!(f, "too many skipped keys (limit: {limit})")
            }
            Self::SkippedKeyExpired => write!(f, "skipped key has expired"),
            Self::DuplicateMessage => write!(f, "duplicate message detected"),
            Self::EpochTooOld { minimum, received } => {
                write!(f, "epoch too old (minimum: {minimum}, received: {received})")
            }
            Self::UnknownRecipientKeyId => write!(f, "unknown recipient key ID"),
            Self::SessionExhausted { current, threshold } => {
                write!(f, "session exhausted (current: {current}, threshold: {threshold})")
            }

            // Wire format errors
            Self::UnsupportedProtocolVersion { received, supported } => {
                write!(
                    f,
                    "unsupported protocol version: received 0x{received:02x}, supported 0x{supported:02x}"
                )
            }
            Self::UnsupportedCipherSuite { received, supported } => {
                write!(
                    f,
                    "unsupported cipher suite: received 0x{received:02x}, supported 0x{supported:02x}"
                )
            }
            Self::MalformedMessage => write!(f, "malformed message"),
            Self::InvalidHeader => write!(f, "invalid header format"),
            Self::UnexpectedEndOfInput { expected, available } => {
                write!(f, "unexpected end of input: expected {expected}, available {available}")
            }

            // Bundle errors
            Self::BundleSignatureInvalid => write!(f, "bundle signature invalid"),
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
            Self::CannotRemoveSelf => write!(f, "cannot remove yourself from group"),
            Self::InvalidLeafPosition => write!(f, "invalid leaf position"),
            Self::RemovedFromGroup => write!(f, "you have been removed from the group"),
            Self::EpochMismatch { expected, received } => {
                write!(f, "epoch mismatch: expected {expected}, received {received}")
            }

            // Rate limiting
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),

            // Session errors
            Self::NoActiveSession => write!(f, "no active session"),
            Self::SessionCompromised => write!(f, "session compromised"),
            Self::NoRecipientKey => write!(f, "no recipient public key"),
            Self::TooManySkippedMessages => write!(f, "too many skipped messages"),

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
            Self::SessionNotInitialised
            | Self::SessionExhausted { .. }
            | Self::EpochTooOld { .. }
            | Self::UnknownSenderKey
            | Self::UnknownRecipientKeyId
            | Self::MemberNotFound
            | Self::InvalidNodeIndex
            | Self::NoActiveSession
            | Self::SessionCompromised
            | Self::NoRecipientKey
            | Self::GroupIdMismatch
            | Self::CannotRemoveSelf
            | Self::InvalidLeafPosition
            | Self::RemovedFromGroup
            | Self::EpochMismatch { .. } => ErrorCategory::Protocol,

            // Security errors (potential attacks)
            Self::SignatureVerificationFailed
            | Self::HybridSignatureVerificationFailed
            | Self::InvalidSignature
            | Self::DecryptionFailed
            | Self::AeadAuthenticationFailed
            | Self::DecapsulationFailed
            | Self::MessageCounterTooOld
            | Self::MessageCounterTooFarAhead { .. }
            | Self::TooManySkippedKeys { .. }
            | Self::SkippedKeyExpired
            | Self::DuplicateMessage
            | Self::BundleSignatureInvalid
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
            | Self::InvalidCiphertext
            | Self::InvalidCiphertextLength { .. }
            | Self::EncapsulationFailed
            | Self::KeyDerivationFailed
            | Self::TooManySkippedMessages
            | Self::InvalidMagic
            | Self::UnsupportedStateVersion => ErrorCategory::Security,
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
            CryptoError::SessionNotInitialised.category(),
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
