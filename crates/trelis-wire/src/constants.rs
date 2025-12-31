//! Protocol constants and size definitions.
//!
//! This module defines all normative constants for the Trelis wire format.

// =============================================================================
// Protocol Header
// =============================================================================

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Current cipher suite (TRELIS_HYBRID_V1).
pub const CIPHER_SUITE: u8 = 0x01;

/// Size of the protocol header in bytes.
pub const HEADER_SIZE: usize = 2;

// =============================================================================
// Symmetric Cryptography
// =============================================================================

/// Size of XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of AEAD key in bytes.
pub const AEAD_KEY_SIZE: usize = 32;

// =============================================================================
// Classical Keys
// =============================================================================

/// Size of Ed448 public key in bytes.
pub const ED448_PK_SIZE: usize = 57;

/// Size of Ed448 signature in bytes.
pub const ED448_SIG_SIZE: usize = 114;

/// Size of X448 public key in bytes.
pub const X448_PK_SIZE: usize = 56;

// =============================================================================
// Post-Quantum Keys
// =============================================================================

/// Size of ML-DSA-65 public key in bytes.
pub const MLDSA65_PK_SIZE: usize = 1952;

/// Size of ML-DSA-65 signature in bytes.
pub const MLDSA65_SIG_SIZE: usize = 3309;

/// Size of sntrup761 public key in bytes.
pub const SNTRUP761_PK_SIZE: usize = 1158;

/// Size of sntrup761 ciphertext in bytes.
pub const SNTRUP761_CT_SIZE: usize = 1039;

/// Size of sntrup761 shared secret in bytes.
pub const SNTRUP761_SS_SIZE: usize = 32;

// =============================================================================
// Hybrid Keys
// =============================================================================

/// Size of hybrid signing public key in bytes (Ed448 + ML-DSA-65).
pub const HYBRID_SIGNING_PK_SIZE: usize = ED448_PK_SIZE + MLDSA65_PK_SIZE;

/// Size of hybrid signature in bytes (Ed448 + ML-DSA-65).
pub const HYBRID_SIG_SIZE: usize = ED448_SIG_SIZE + MLDSA65_SIG_SIZE;

/// Size of hybrid KEM public key in bytes (X448 + sntrup761).
pub const HYBRID_KEM_PK_SIZE: usize = X448_PK_SIZE + SNTRUP761_PK_SIZE;

/// Size of hybrid encapsulation in bytes (X448 ephemeral + sntrup761 ciphertext).
pub const HYBRID_ENCAP_SIZE: usize = X448_PK_SIZE + SNTRUP761_CT_SIZE;

/// Size of hybrid identity public key in bytes (signing + KEM).
pub const HYBRID_IDENTITY_PK_SIZE: usize = HYBRID_SIGNING_PK_SIZE + HYBRID_KEM_PK_SIZE;

// =============================================================================
// Protocol Messages
// =============================================================================

/// Size of key ID in bytes.
pub const KEY_ID_SIZE: usize = 8;

/// Size of one-time key (key_id + KEM public key).
pub const OTK_SIZE: usize = KEY_ID_SIZE + HYBRID_KEM_PK_SIZE;

/// Size of pre-key bundle in bytes.
pub const PREKEY_BUNDLE_SIZE: usize = HYBRID_SIGNING_PK_SIZE + HYBRID_KEM_PK_SIZE + OTK_SIZE;

/// Size of device key wrap in bytes.
pub const DEVICE_KEY_WRAP_SIZE: usize =
    KEY_ID_SIZE + X448_PK_SIZE + SNTRUP761_CT_SIZE + NONCE_SIZE + 48;

// =============================================================================
// Double Ratchet
// =============================================================================

/// Maximum number of skipped message keys to store.
pub const MAX_SKIPPED_KEYS: usize = 2000;

/// Maximum messages to skip within a single chain.
pub const MAX_SKIP: u64 = 1000;

/// Maximum chain lookahead for out-of-order messages.
pub const MAX_CHAIN_LOOKAHEAD: u64 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signing_pk_size() {
        assert_eq!(HYBRID_SIGNING_PK_SIZE, 57 + 1952);
        assert_eq!(HYBRID_SIGNING_PK_SIZE, 2009);
    }

    #[test]
    fn test_hybrid_sig_size() {
        assert_eq!(HYBRID_SIG_SIZE, 114 + 3309);
        assert_eq!(HYBRID_SIG_SIZE, 3423);
    }

    #[test]
    fn test_hybrid_kem_pk_size() {
        assert_eq!(HYBRID_KEM_PK_SIZE, 56 + 1158);
        assert_eq!(HYBRID_KEM_PK_SIZE, 1214);
    }

    #[test]
    fn test_hybrid_encap_size() {
        assert_eq!(HYBRID_ENCAP_SIZE, 56 + 1039);
        assert_eq!(HYBRID_ENCAP_SIZE, 1095);
    }

    #[test]
    fn test_hybrid_identity_pk_size() {
        assert_eq!(HYBRID_IDENTITY_PK_SIZE, 2009 + 1214);
        assert_eq!(HYBRID_IDENTITY_PK_SIZE, 3223);
    }

    #[test]
    fn test_prekey_bundle_size() {
        // signing (2009) + kem (1214) + otk (8 + 1214)
        assert_eq!(PREKEY_BUNDLE_SIZE, 2009 + 1214 + 8 + 1214);
        assert_eq!(PREKEY_BUNDLE_SIZE, 4445);
    }

    #[test]
    fn test_device_key_wrap_size() {
        // key_id (8) + x448_eph (56) + sntrup_ct (1039) + nonce (24) + encrypted (48)
        assert_eq!(DEVICE_KEY_WRAP_SIZE, 8 + 56 + 1039 + 24 + 48);
        assert_eq!(DEVICE_KEY_WRAP_SIZE, 1175);
    }
}
