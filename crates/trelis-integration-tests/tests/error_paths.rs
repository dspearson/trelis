//! Comprehensive error path and edge case tests for the Trelis cryptographic library.
//!
//! These tests verify that all error conditions are properly detected and reported,
//! ensuring the library fails safely and securely.

// Test code; pedantic warnings have no value here and are silenced wholesale.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_borrow,
    clippy::clone_on_copy,
    clippy::assertions_on_constants,
    clippy::needless_range_loop
)]

use trelis_cocoa::CocoaSession;
use trelis_error::{CryptoError, ErrorCategory};
use trelis_hybrid::HybridKemKeypair;
use trelis_primitives::mldsa::DefaultMlDsaScheme;
use trelis_primitives::{
    AeadKey, Ed448Signature, Ed448SigningKey, MlDsa65Signature, MlDsa65SigningKey, Nonce,
    Sntrup761Ciphertext, Sntrup761SecretKey, X448Public, X448Secret, decrypt, encrypt,
};
use trelis_wire::{
    decode::{Decoder, DecoderError},
    encode::Encoder,
};

// Type aliases that explicitly use the default ML-DSA scheme to help type inference
type HybridSigningKeypair = trelis_hybrid::HybridSigningKeypair<DefaultMlDsaScheme>;
type HybridSignature = trelis_hybrid::HybridSignature<DefaultMlDsaScheme>;

// ═══════════════════════════════════════════════════════════════════════════════
// AEAD Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod aead_errors {
    use super::*;

    #[test]
    fn test_aead_decrypt_wrong_key() {
        let key1 = AeadKey::from_bytes([0u8; 32]);
        let key2 = AeadKey::from_bytes([1u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message";
        let aad = b"associated data";

        // Encrypt with key1 (ciphertext includes tag)
        let ciphertext = encrypt(&key1, &nonce, plaintext, aad).unwrap();

        // Decrypt with key2 should fail
        let result = decrypt(&key2, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_decrypt_wrong_nonce() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce1 = Nonce::from_bytes([0u8; 24]);
        let nonce2 = Nonce::from_bytes([1u8; 24]);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, &nonce1, plaintext, aad).unwrap();

        // Decrypt with wrong nonce should fail
        let result = decrypt(&key, &nonce2, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_decrypt_wrong_aad() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message";
        let aad1 = b"associated data 1";
        let aad2 = b"associated data 2";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad1).unwrap();

        // Decrypt with wrong AAD should fail
        let result = decrypt(&key, &nonce, &ciphertext, aad2);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_decrypt_modified_ciphertext() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Flip a bit in ciphertext (not the tag portion)
        if ciphertext.len() > 16 {
            ciphertext[0] ^= 0x01;
        }

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_decrypt_modified_tag() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Flip a bit in the tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_decrypt_truncated_ciphertext() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message that is long enough";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Truncate ciphertext (lose some of the tag)
        let truncated = &ciphertext[..ciphertext.len() / 2];

        let result = decrypt(&key, &nonce, truncated, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_empty_plaintext() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"";
        let aad = b"associated data";

        // Empty plaintext should work (produces 16-byte tag only)
        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), 16); // Just the tag

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_aead_empty_aad() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = b"secret message";
        let aad = b"";

        // Empty AAD should work
        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = AeadKey::from_bytes([0x42u8; 32]);
        let nonce = Nonce::from_bytes([0x00u8; 24]);
        let plaintext = b"Hello, Trelis!";
        let aad = b"associated data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_ciphertext_too_short() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let aad = b"aad";

        // Ciphertext must be at least 16 bytes (the tag)
        let short = [0u8; 8];
        let result = decrypt(&key, &nonce, &short, aad);
        assert!(result.is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ed448 Signature Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ed448_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ed448_verify_wrong_key() {
        let keypair1 = Ed448SigningKey::generate().unwrap();
        let keypair2 = Ed448SigningKey::generate().unwrap();
        let message = b"test message";

        let signature = keypair1.sign(message);

        // Verify with wrong public key should fail
        let result = keypair2.verifying_key().verify(message, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ed448_verify_wrong_message() {
        let keypair = Ed448SigningKey::generate().unwrap();
        let message1 = b"original message";
        let message2 = b"modified message";

        let signature = keypair.sign(message1);

        // Verify with wrong message should fail
        let result = keypair.verifying_key().verify(message2, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ed448_verify_modified_signature() {
        let keypair = Ed448SigningKey::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);
        let mut sig_bytes = signature.to_bytes();

        // Flip a bit in signature
        sig_bytes[0] ^= 0x01;

        // from_bytes may reject invalid signature bytes (which is valid behavior)
        // If it accepts them, verify should reject the modified signature
        match Ed448Signature::from_bytes(&sig_bytes) {
            Ok(modified_sig) => {
                let result = keypair.verifying_key().verify(message, &modified_sig);
                assert!(
                    result.is_err(),
                    "Modified signature should fail verification"
                );
            }
            Err(_) => {
                // from_bytes rejecting invalid signature bytes is acceptable
            }
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ed448_verify_empty_message() {
        let keypair = Ed448SigningKey::generate().unwrap();
        let message = b"";

        // Empty message should still work
        let signature = keypair.sign(message);
        let result = keypair.verifying_key().verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed448_signature_from_wrong_length() {
        // Wrong length should fail to parse
        let short_bytes = [0u8; 50]; // Ed448 signature is 114 bytes
        let sig_result = Ed448Signature::from_bytes(&short_bytes);

        // Should fail to parse due to wrong length
        assert!(sig_result.is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 Signature Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod mldsa65_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_mldsa65_verify_wrong_key() {
        let keypair1 = MlDsa65SigningKey::generate().unwrap();
        let keypair2 = MlDsa65SigningKey::generate().unwrap();
        let message = b"test message";

        let signature = keypair1.sign(message).unwrap();

        // Verify with wrong public key should fail
        let result = keypair2.verifying_key().verify(message, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_mldsa65_verify_wrong_message() {
        let keypair = MlDsa65SigningKey::generate().unwrap();
        let message1 = b"original message";
        let message2 = b"modified message";

        let signature = keypair.sign(message1).unwrap();

        // Verify with wrong message should fail
        let result = keypair.verifying_key().verify(message2, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_mldsa65_verify_modified_signature() {
        let keypair = MlDsa65SigningKey::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message).unwrap();
        let mut sig_bytes = signature.to_bytes().to_vec();

        // Flip a bit in signature
        sig_bytes[0] ^= 0x01;

        // from_bytes returns Result
        let modified_sig = MlDsa65Signature::from_bytes(&sig_bytes).unwrap();
        let result = keypair.verifying_key().verify(message, &modified_sig);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_mldsa65_verify_empty_message() {
        let keypair = MlDsa65SigningKey::generate().unwrap();
        let message = b"";

        // Empty message should work
        let signature = keypair.sign(message).unwrap();
        let result = keypair.verifying_key().verify(message, &signature);
        assert!(result.is_ok());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid Signature Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod hybrid_signature_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_verify_wrong_key() {
        let keypair1 = HybridSigningKeypair::generate().unwrap();
        let keypair2 = HybridSigningKeypair::generate().unwrap();
        let message = b"test message";

        let signature = keypair1.sign(message).unwrap();

        // Verify with wrong public key should fail
        let result = keypair2.public_key().verify(message, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_verify_wrong_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message1 = b"original message";
        let message2 = b"modified message";

        let signature = keypair.sign(message1).unwrap();

        // Verify with wrong message should fail
        let result = keypair.public_key().verify(message2, &signature);
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_verify_with_empty_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"";

        // Empty message should work
        let signature = keypair.sign(message).unwrap();
        let result = keypair.public_key().verify(message, &signature);
        assert!(result.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_verify_large_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = vec![0xABu8; 1_000_000]; // 1MB message

        let signature = keypair.sign(&message).unwrap();
        let result = keypair.public_key().verify(&message, &signature);
        assert!(result.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_signature_serialization_roundtrip() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message).unwrap();
        let bytes = signature.to_bytes();
        let restored = HybridSignature::from_bytes(&bytes).unwrap();

        // Should still verify
        assert!(keypair.public_key().verify(message, &restored).is_ok());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// X448 Key Exchange Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod x448_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_x448_dh_produces_different_secrets() {
        let alice = X448Secret::generate().unwrap();
        let bob = X448Secret::generate().unwrap();
        let carol = X448Secret::generate().unwrap();

        // Alice-Bob shared secret
        let ab_secret = alice.diffie_hellman(&bob.public_key()).unwrap();

        // Alice-Carol shared secret
        let ac_secret = alice.diffie_hellman(&carol.public_key()).unwrap();

        // Should be different
        assert_ne!(ab_secret.as_bytes(), ac_secret.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_x448_dh_symmetric() {
        let alice = X448Secret::generate().unwrap();
        let bob = X448Secret::generate().unwrap();

        // DH should be symmetric
        let ab_secret = alice.diffie_hellman(&bob.public_key()).unwrap();
        let ba_secret = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(ab_secret.as_bytes(), ba_secret.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_x448_public_key_serialization() {
        let secret = X448Secret::generate().unwrap();
        let public = secret.public_key();

        let bytes = public.as_bytes();
        // from_bytes returns Result
        let restored = X448Public::from_bytes(bytes).unwrap();

        assert_eq!(public.as_bytes(), restored.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// sntrup761 KEM Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod sntrup761_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sntrup761_decapsulate_wrong_key() {
        let keypair1 = Sntrup761SecretKey::generate().unwrap();
        let keypair2 = Sntrup761SecretKey::generate().unwrap();

        // Encapsulate to keypair1's public key
        let (shared_secret1, ciphertext) = keypair1.public_key().encapsulate().unwrap();

        // Try to decapsulate with keypair2's secret key (should produce different secret)
        let shared_secret2 = keypair2.decapsulate(&ciphertext).unwrap();

        // Shared secrets should NOT match
        assert_ne!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sntrup761_decapsulate_modified_ciphertext() {
        let keypair = Sntrup761SecretKey::generate().unwrap();

        let (shared_secret1, ciphertext) = keypair.public_key().encapsulate().unwrap();

        // Modify the ciphertext
        let mut ct_bytes = ciphertext.to_bytes().to_vec();
        ct_bytes[0] ^= 0x01;
        // from_bytes returns Result
        let modified_ct = Sntrup761Ciphertext::from_bytes(&ct_bytes).unwrap();

        // Decapsulation should produce a different (pseudo-random) secret
        let shared_secret2 = keypair.decapsulate(&modified_ct).unwrap();
        assert_ne!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sntrup761_encapsulation_produces_unique_secrets() {
        let keypair = Sntrup761SecretKey::generate().unwrap();

        let (secret1, _ct1) = keypair.public_key().encapsulate().unwrap();
        let (secret2, _ct2) = keypair.public_key().encapsulate().unwrap();

        // Each encapsulation should produce a unique secret
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_sntrup761_roundtrip() {
        let keypair = Sntrup761SecretKey::generate().unwrap();

        let (encap_secret, ciphertext) = keypair.public_key().encapsulate().unwrap();
        let decap_secret = keypair.decapsulate(&ciphertext).unwrap();

        assert_eq!(encap_secret.as_bytes(), decap_secret.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid KEM Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod hybrid_kem_errors {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_kem_decapsulate_wrong_key() {
        let keypair1 = HybridKemKeypair::generate().unwrap();
        let keypair2 = HybridKemKeypair::generate().unwrap();

        let (shared_secret1, encapsulation) = keypair1.public_key().encapsulate().unwrap();

        // Decapsulate with wrong key should fail or produce different secret
        let result = keypair2.decapsulate(&encapsulation);

        match result {
            Ok(shared_secret2) => {
                assert_ne!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
            }
            Err(_) => {
                // Expected
            }
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_kem_encapsulation_unique() {
        let keypair = HybridKemKeypair::generate().unwrap();

        let (secret1, enc1) = keypair.public_key().encapsulate().unwrap();
        let (secret2, enc2) = keypair.public_key().encapsulate().unwrap();

        // Each encapsulation should be unique
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
        assert_ne!(enc1.to_bytes(), enc2.to_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_kem_roundtrip() {
        let keypair = HybridKemKeypair::generate().unwrap();

        let (encap_secret, encapsulation) = keypair.public_key().encapsulate().unwrap();
        let decap_secret = keypair
            .decapsulate(&encapsulation)
            .expect("decapsulation failed");

        assert_eq!(encap_secret.as_bytes(), decap_secret.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_kem_serialization_roundtrip() {
        let keypair = HybridKemKeypair::generate().unwrap();

        // Serialize and deserialize keypair
        let bytes = keypair.to_bytes();
        let restored = HybridKemKeypair::from_bytes(&bytes[..]).unwrap();

        // Encapsulate with original, decapsulate with restored
        let (secret1, enc) = keypair.public_key().encapsulate().unwrap();
        let secret2 = restored.decapsulate(&enc).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wire Format Error Path Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod wire_format_errors {
    use super::*;

    #[test]
    fn test_decoder_underflow_u8() {
        let buf: [u8; 0] = [];
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.read_u8(), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_underflow_u16() {
        let buf = [0x01]; // Only 1 byte, need 2
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.read_u16(), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_underflow_u32() {
        let buf = [0x01, 0x02, 0x03]; // Only 3 bytes, need 4
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.read_u32(), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_underflow_u64() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]; // Only 7 bytes, need 8
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.read_u64(), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_underflow_bytes() {
        let buf = [0x01, 0x02, 0x03];
        let mut dec = Decoder::new(&buf);

        // Try to read 10 bytes from 3-byte buffer
        assert!(matches!(
            dec.read_bytes(10),
            Err(DecoderError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_decoder_underflow_array() {
        let buf = [0x01, 0x02];
        let mut dec = Decoder::new(&buf);

        // Try to read 32-byte array from 2-byte buffer
        let result: Result<[u8; 32], _> = dec.read_array();
        assert!(matches!(result, Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_decoder_invalid_protocol_version() {
        let buf = [0x99, 0x01]; // Invalid version 0x99
        let mut dec = Decoder::new(&buf);

        assert!(matches!(
            dec.read_header(),
            Err(DecoderError::UnsupportedProtocolVersion(0x99))
        ));
    }

    #[test]
    fn test_decoder_invalid_cipher_suite() {
        let buf = [0x01, 0x99]; // Valid version, invalid cipher suite
        let mut dec = Decoder::new(&buf);

        assert!(matches!(
            dec.read_header(),
            Err(DecoderError::UnsupportedCipherSuite(0x99))
        ));
    }

    #[test]
    fn test_decoder_length_prefixed_overflow() {
        // Length prefix claims 1000 bytes but only 3 bytes available
        let buf = [0xE8, 0x03, 0x00, 0x00, 0xAA, 0xBB, 0xCC]; // Length = 1000
        let mut dec = Decoder::new(&buf);

        assert!(matches!(
            dec.read_length_prefixed(),
            Err(DecoderError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_decoder_skip_overflow() {
        let buf = [0x01, 0x02, 0x03];
        let mut dec = Decoder::new(&buf);

        assert!(matches!(dec.skip(100), Err(DecoderError::UnexpectedEof)));
    }

    #[test]
    fn test_encoder_overflow() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);

        // Try to write 8 bytes into 4-byte buffer
        assert!(enc.write_u64(0x0102030405060708).is_none());
    }

    #[test]
    fn test_decoder_position_tracking() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut dec = Decoder::new(&buf);

        assert_eq!(dec.position(), 0);
        assert_eq!(dec.remaining(), 8);

        dec.read_u16().unwrap();
        assert_eq!(dec.position(), 2);
        assert_eq!(dec.remaining(), 6);

        dec.read_u32().unwrap();
        assert_eq!(dec.position(), 6);
        assert_eq!(dec.remaining(), 2);
    }

    #[test]
    fn test_decoder_is_empty() {
        let buf = [0x01, 0x02];
        let mut dec = Decoder::new(&buf);

        assert!(!dec.is_empty());
        dec.read_u16().unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_decoder_has_remaining() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        let dec = Decoder::new(&buf);

        assert!(dec.has_remaining(4));
        assert!(dec.has_remaining(3));
        assert!(!dec.has_remaining(5));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error Type Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod crypto_error_tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        // Fatal errors
        assert_eq!(CryptoError::RngFailure.category(), ErrorCategory::Fatal);
        assert_eq!(
            CryptoError::KeyGenerationFailed.category(),
            ErrorCategory::Fatal
        );
        assert_eq!(
            CryptoError::InvalidTreeState.category(),
            ErrorCategory::Fatal
        );
        assert_eq!(CryptoError::GroupFull.category(), ErrorCategory::Fatal);

        // Transient errors
        assert_eq!(
            CryptoError::RateLimitExceeded.category(),
            ErrorCategory::Transient
        );

        // Protocol errors
        assert_eq!(
            CryptoError::NoActiveSession.category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            CryptoError::MemberNotFound.category(),
            ErrorCategory::Protocol
        );

        // Security errors
        assert_eq!(
            CryptoError::SignatureVerificationFailed.category(),
            ErrorCategory::Security
        );
        assert_eq!(
            CryptoError::DecryptionFailed.category(),
            ErrorCategory::Security
        );
        assert_eq!(
            CryptoError::DuplicateMessage.category(),
            ErrorCategory::Security
        );
    }

    #[test]
    fn test_is_fatal() {
        assert!(CryptoError::RngFailure.is_fatal());
        assert!(CryptoError::KeyGenerationFailed.is_fatal());
        assert!(!CryptoError::DecryptionFailed.is_fatal());
        assert!(!CryptoError::RateLimitExceeded.is_fatal());
    }

    #[test]
    fn test_is_security_error() {
        assert!(CryptoError::SignatureVerificationFailed.is_security_error());
        assert!(CryptoError::DecryptionFailed.is_security_error());
        assert!(CryptoError::DuplicateMessage.is_security_error());
        assert!(CryptoError::MalformedMessage.is_security_error());
        assert!(!CryptoError::RateLimitExceeded.is_security_error());
        assert!(!CryptoError::RngFailure.is_security_error()); // Fatal, not security
    }

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));

        let err = CryptoError::EpochMismatch {
            expected: 5,
            received: 3,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = CryptoError::DecryptionFailed;
        let err2 = CryptoError::DecryptionFailed;
        let err3 = CryptoError::EncapsulationFailed;

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_error_clone() {
        let err1 = CryptoError::SessionExhausted {
            current: 100,
            threshold: 90,
        };
        let err2 = err1.clone();

        assert_eq!(err1, err2);
    }

    #[test]
    fn test_error_copy() {
        let err1 = CryptoError::DecryptionFailed;
        let err2 = err1; // Copy
        let err3 = err1; // Still valid because Copy

        assert_eq!(err2, err3);
    }

    #[test]
    fn test_all_error_variants_have_display() {
        // Ensure all error variants can be displayed without panic
        let errors = [
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            },
            CryptoError::KeyGenerationFailed,
            CryptoError::KeyDerivationFailed,
            CryptoError::SignatureVerificationFailed,
            CryptoError::InvalidSignature,
            CryptoError::DecryptionFailed,
            CryptoError::AeadAuthenticationFailed,
            CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 12,
            },
            CryptoError::EncapsulationFailed,
            CryptoError::DecapsulationFailed,
            CryptoError::InvalidCiphertext,
            CryptoError::InvalidCiphertextLength {
                expected: 1039,
                actual: 100,
            },
            CryptoError::UnknownSenderKey,
            CryptoError::MessageCounterTooOld,
            CryptoError::MessageCounterTooFarAhead {
                max_skip: 100,
                gap: 200,
            },
            CryptoError::TooManySkippedKeys { limit: 1000 },
            CryptoError::SkippedKeyExpired,
            CryptoError::DuplicateMessage,
            CryptoError::EpochTooOld {
                minimum: 5,
                received: 3,
            },
            CryptoError::UnknownRecipientKeyId,
            CryptoError::SessionExhausted {
                current: 1000,
                threshold: 900,
            },
            CryptoError::UnsupportedProtocolVersion {
                received: 2,
                supported: 1,
            },
            CryptoError::UnsupportedCipherSuite {
                received: 2,
                supported: 1,
            },
            CryptoError::MalformedMessage,
            CryptoError::InvalidHeader,
            CryptoError::UnexpectedEndOfInput {
                expected: 100,
                available: 50,
            },
            CryptoError::InvalidBundleSignature,
            CryptoError::BundleExpired,
            CryptoError::BundleTimestampInFuture,
            CryptoError::WrongRecipient,
            CryptoError::ContextMismatch,
            CryptoError::RngFailure,
            CryptoError::InvalidNodeIndex,
            CryptoError::MemberNotFound,
            CryptoError::GroupFull,
            CryptoError::InvalidTreeState,
            CryptoError::InvalidGroupSize,
            CryptoError::GroupIdMismatch,
            CryptoError::SelfRemovalForbidden,
            CryptoError::InvalidLeafPosition,
            CryptoError::RemovedFromGroup,
            CryptoError::EpochMismatch {
                expected: 5,
                received: 3,
            },
            CryptoError::RateLimitExceeded,
            CryptoError::NoActiveSession,
            CryptoError::SessionCompromised,
            CryptoError::NoRecipientKey,
            CryptoError::MessageOrderViolation {
                expected: 5,
                received: 7,
            },
            CryptoError::InvalidMagic,
            CryptoError::UnsupportedStateVersion,
        ];

        for err in errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty(), "Error {:?} has empty display", err);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CoCoA Tree Edge Case Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod cocoa_edge_cases {
    use super::*;

    fn make_group_id(name: &str) -> [u8; 32] {
        let mut id = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        id[..len].copy_from_slice(&bytes[..len]);
        id
    }

    fn make_user_id(name: &str) -> [u8; 32] {
        make_group_id(name)
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cocoa_single_member_group() {
        let my_kem = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0u8; 32];

        // Single member group
        let session = CocoaSession::create_group(
            make_group_id("group-1"),
            make_user_id("alice"),
            my_kem,
            1, // Just ourselves
            &epoch_secret,
        );

        assert!(session.is_ok());
        let session = session.unwrap();
        assert_eq!(session.epoch_number(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cocoa_zero_members_rejected() {
        let my_kem = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0u8; 32];

        // Zero members should fail
        let result = CocoaSession::create_group(
            make_group_id("group-1"),
            make_user_id("alice"),
            my_kem,
            0,
            &epoch_secret,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidGroupSize)));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cocoa_group_id_preserved() {
        let my_kem = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0u8; 32];
        let group_id = make_group_id("my-unique-group-id");

        let session =
            CocoaSession::create_group(group_id, make_user_id("alice"), my_kem, 1, &epoch_secret)
                .unwrap();

        assert_eq!(session.group_id(), &group_id);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cocoa_user_id_preserved() {
        let my_kem = HybridKemKeypair::generate().unwrap();
        let epoch_secret = [0u8; 32];
        let user_id = make_user_id("alice@example.com");

        let session =
            CocoaSession::create_group(make_group_id("group-1"), user_id, my_kem, 1, &epoch_secret)
                .unwrap();

        assert_eq!(session.our_user_id(), &user_id);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge Case Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_large_message_signature() {
        let keypair = HybridSigningKeypair::generate().unwrap();

        // 10MB message
        let large_message = vec![0xABu8; 10 * 1024 * 1024];

        let signature = keypair.sign(&large_message).unwrap();
        let result = keypair.public_key().verify(&large_message, &signature);
        assert!(result.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_all_zeros_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = vec![0u8; 1000];

        let signature = keypair.sign(&message).unwrap();
        let result = keypair.public_key().verify(&message, &signature);
        assert!(result.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_all_ones_message() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = vec![0xFFu8; 1000];

        let signature = keypair.sign(&message).unwrap();
        let result = keypair.public_key().verify(&message, &signature);
        assert!(result.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_repeated_operations() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"test message";

        // Sign and verify many times
        for _ in 0..100 {
            let signature = keypair.sign(message).unwrap();
            assert!(keypair.public_key().verify(message, &signature).is_ok());
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_multiple_keypairs() {
        let keypairs: Vec<_> = (0..10)
            .map(|_| HybridSigningKeypair::generate().unwrap())
            .collect();

        let message = b"shared message";

        // All keypairs should produce valid signatures
        for kp in &keypairs {
            let sig = kp.sign(message).unwrap();
            assert!(kp.public_key().verify(message, &sig).is_ok());
        }

        // Cross-verification should fail
        for i in 0..keypairs.len() {
            let sig = keypairs[i].sign(message).unwrap();
            for j in 0..keypairs.len() {
                if i != j {
                    assert!(keypairs[j].public_key().verify(message, &sig).is_err());
                }
            }
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_binary_patterns() {
        let keypair = HybridSigningKeypair::generate().unwrap();

        // Test various binary patterns
        let patterns = [
            vec![0x00, 0xFF, 0x00, 0xFF],
            vec![0xAA, 0x55, 0xAA, 0x55],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0x01, 0x02, 0x04, 0x08],
        ];

        for pattern in patterns {
            let sig = keypair.sign(&pattern).unwrap();
            assert!(keypair.public_key().verify(&pattern, &sig).is_ok());
        }
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let plaintext = b"test";
        let aad = b"aad";

        let mut nonces = std::collections::HashSet::new();

        // Generate many nonces and ensure they're unique
        for i in 0..1000u64 {
            let mut nonce_bytes = [0u8; 24];
            nonce_bytes[..8].copy_from_slice(&i.to_le_bytes());
            let nonce = Nonce::from_bytes(nonce_bytes);
            nonces.insert(nonce_bytes);

            // Each encryption with unique nonce should work
            let _ct = encrypt(&key, &nonce, plaintext, aad).unwrap();
        }

        assert_eq!(nonces.len(), 1000);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_keypair_generation_produces_unique_keys() {
        let mut public_keys = std::collections::HashSet::new();

        for _ in 0..100 {
            let keypair = HybridSigningKeypair::generate().unwrap();
            let pk_bytes = keypair.public_key().to_bytes();
            assert!(
                public_keys.insert(pk_bytes),
                "Duplicate public key generated!"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Serialization Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod key_serialization {
    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_signing_keypair_roundtrip() {
        let original = HybridSigningKeypair::generate().unwrap();
        let bytes = original.to_bytes();
        let restored = HybridSigningKeypair::from_bytes(&bytes[..]).unwrap();

        let message = b"test";
        let sig = original.sign(message).unwrap();

        // Both should verify
        assert!(original.public_key().verify(message, &sig).is_ok());
        assert!(restored.public_key().verify(message, &sig).is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_kem_keypair_roundtrip() {
        let original = HybridKemKeypair::generate().unwrap();
        let bytes = original.to_bytes();
        let restored = HybridKemKeypair::from_bytes(&bytes[..]).unwrap();

        // Encapsulate with original, decapsulate with restored
        let (secret1, enc) = original.public_key().encapsulate().unwrap();
        let secret2 = restored.decapsulate(&enc).unwrap();

        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_hybrid_signature_roundtrip() {
        let keypair = HybridSigningKeypair::generate().unwrap();
        let message = b"test message";

        let sig = keypair.sign(message).unwrap();
        let bytes = sig.to_bytes();
        let restored = HybridSignature::from_bytes(&bytes).unwrap();

        // Both should verify
        assert!(keypair.public_key().verify(message, &sig).is_ok());
        assert!(keypair.public_key().verify(message, &restored).is_ok());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod boundary_tests {
    use super::*;

    #[test]
    fn test_aead_max_message_size() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let aad = b"aad";

        // Test with 64KB message
        let large = vec![0xABu8; 64 * 1024];
        let ciphertext = encrypt(&key, &nonce, &large, aad).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), large);
    }

    #[test]
    fn test_single_byte_message() {
        let key = AeadKey::from_bytes([0u8; 32]);
        let nonce = Nonce::from_bytes([0u8; 24]);
        let plaintext = &[0xAB];
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_encoder_exact_fit() {
        let mut buf = [0u8; 4];
        let mut enc = Encoder::new(&mut buf);

        // Should fit exactly (returns Some for success)
        assert!(enc.write_u32(0x12345678).is_some());
        assert_eq!(enc.position(), 4);
    }

    #[test]
    fn test_encoder_one_byte_short() {
        let mut buf = [0u8; 3];
        let mut enc = Encoder::new(&mut buf);

        // Should fail - needs 4 bytes, have 3 (returns None)
        assert!(enc.write_u32(0x12345678).is_none());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_signature_different_for_different_messages() {
        let keypair = HybridSigningKeypair::generate().unwrap();

        let sig1 = keypair.sign(b"message1").unwrap();
        let sig2 = keypair.sign(b"message2").unwrap();

        // Signatures should be different (at least one component)
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}
