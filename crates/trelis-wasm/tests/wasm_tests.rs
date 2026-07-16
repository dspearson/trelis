//! WASM binding tests using wasm-bindgen-test.
//!
//! Run with: `wasm-pack test --headless --chrome crates/trelis-wasm`

#![cfg(target_arch = "wasm32")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::useless_vec,
    clippy::len_zero,
    clippy::needless_borrow
)]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Import all the WASM bindings
use trelis_wasm::*;

// Helper to extract bytes from JsValue object field
fn get_bytes_field(obj: &JsValue, field: &str) -> Vec<u8> {
    let field_val = js_sys::Reflect::get(obj, &JsValue::from_str(field)).unwrap();
    js_sys::Uint8Array::new(&field_val).to_vec()
}

fn get_bool_field(obj: &JsValue, field: &str) -> bool {
    let field_val = js_sys::Reflect::get(obj, &JsValue::from_str(field)).unwrap();
    field_val.as_bool().unwrap()
}

fn get_string_field(obj: &JsValue, field: &str) -> String {
    let field_val = js_sys::Reflect::get(obj, &JsValue::from_str(field)).unwrap();
    field_val.as_string().unwrap()
}

fn get_number_field(obj: &JsValue, field: &str) -> f64 {
    let field_val = js_sys::Reflect::get(obj, &JsValue::from_str(field)).unwrap();
    field_val.as_f64().unwrap()
}

// ============================================================================
// AEAD Tests
// ============================================================================

mod aead_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let key = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"Hello, WASM world!";
        let aad = b"additional data";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // Includes tag

        let decrypted = aead_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn test_aead_empty_plaintext() {
        let key = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"";
        let aad = b"";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn test_aead_wrong_key_fails() {
        let key1 = random_bytes_32().unwrap();
        let key2 = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = aead_encrypt(&key1, &nonce, plaintext, aad).unwrap();
        let result = aead_decrypt(&key2, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_aead_wrong_nonce_fails() {
        let key = random_bytes_32().unwrap();
        let nonce1 = random_bytes_24().unwrap();
        let nonce2 = random_bytes_24().unwrap();
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = aead_encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let result = aead_decrypt(&key, &nonce2, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_aead_wrong_aad_fails() {
        let key = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"secret message";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, b"aad1").unwrap();
        let result = aead_decrypt(&key, &nonce, &ciphertext, b"aad2");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_aead_tampered_ciphertext_fails() {
        let key = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = aead_encrypt(&key, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xFF; // Tamper with ciphertext

        let result = aead_decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_aead_invalid_key_length() {
        let key = vec![0u8; 16]; // Wrong size
        let nonce = random_bytes_24().unwrap();

        let result = aead_encrypt(&key, &nonce, b"test", b"");
        assert!(result.is_err());

        let result = aead_decrypt(&key, &nonce, b"test", b"");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_aead_invalid_nonce_length() {
        let key = random_bytes_32().unwrap();
        let nonce = vec![0u8; 12]; // Wrong size

        let result = aead_encrypt(&key, &nonce, b"test", b"");
        assert!(result.is_err());

        let result = aead_decrypt(&key, &nonce, b"test", b"");
        assert!(result.is_err());
    }
}

// ============================================================================
// KDF and Hash Tests
// ============================================================================

mod kdf_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_derive_key_deterministic() {
        let context = "trelis-test-context-v1";
        let input = random_bytes_32().unwrap();

        let key1 = derive_key(context, &input);
        let key2 = derive_key(context, &input);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_derive_key_different_contexts() {
        let input = random_bytes_32().unwrap();

        let key1 = derive_key("context-1", &input);
        let key2 = derive_key("context-2", &input);

        assert_ne!(key1, key2);
    }

    #[wasm_bindgen_test]
    fn test_derive_key_different_inputs() {
        let context = "same-context";
        let input1 = random_bytes_32().unwrap();
        let input2 = random_bytes_32().unwrap();

        let key1 = derive_key(context, &input1);
        let key2 = derive_key(context, &input2);

        assert_ne!(key1, key2);
    }

    #[wasm_bindgen_test]
    fn test_blake3_hash_deterministic() {
        let data = b"test data for hashing";

        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_blake3_hash_different_inputs() {
        let hash1 = blake3_hash(b"input 1");
        let hash2 = blake3_hash(b"input 2");

        assert_ne!(hash1, hash2);
    }

    #[wasm_bindgen_test]
    fn test_blake3_hash_empty_input() {
        let hash = blake3_hash(b"");
        assert_eq!(hash.len(), 32);
    }
}

// ============================================================================
// Random Number Generation Tests
// ============================================================================

mod random_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_random_bytes_32_length() {
        let bytes = random_bytes_32().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_random_bytes_24_length() {
        let bytes = random_bytes_24().unwrap();
        assert_eq!(bytes.len(), 24);
    }

    #[wasm_bindgen_test]
    fn test_random_bytes_different_each_call() {
        let bytes1 = random_bytes_32().unwrap();
        let bytes2 = random_bytes_32().unwrap();
        assert_ne!(bytes1, bytes2);
    }
}

// ============================================================================
// Ed448 Signature Tests
// ============================================================================

mod ed448_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_ed448_generate_keypair() {
        let result = ed448_generate().unwrap();

        let secret_key = get_bytes_field(&result, "secret_key");
        let public_key = get_bytes_field(&result, "public_key");

        assert_eq!(secret_key.len(), 57);
        assert_eq!(public_key.len(), 57);
    }

    #[wasm_bindgen_test]
    fn test_ed448_sign_verify_roundtrip() {
        let keypair = ed448_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let message = b"Test message for Ed448 signing";
        let signature = ed448_sign(&secret_key, message).unwrap();

        assert_eq!(signature.len(), 114);

        let valid = ed448_verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[wasm_bindgen_test]
    fn test_ed448_verify_wrong_message_fails() {
        let keypair = ed448_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let signature = ed448_sign(&secret_key, b"message 1").unwrap();
        let valid = ed448_verify(&public_key, b"message 2", &signature).unwrap();

        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_ed448_verify_wrong_key_fails() {
        let keypair1 = ed448_generate().unwrap();
        let keypair2 = ed448_generate().unwrap();
        let secret_key = get_bytes_field(&keypair1, "secret_key");
        let public_key = get_bytes_field(&keypair2, "public_key");

        let message = b"test message";
        let signature = ed448_sign(&secret_key, message).unwrap();
        let valid = ed448_verify(&public_key, message, &signature).unwrap();

        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_ed448_invalid_secret_key_length() {
        let result = ed448_sign(&[0u8; 32], b"message");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_ed448_invalid_public_key_length() {
        let result = ed448_verify(&[0u8; 32], b"message", &[0u8; 114]);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_ed448_invalid_signature_length() {
        let keypair = ed448_generate().unwrap();
        let public_key = get_bytes_field(&keypair, "public_key");

        let result = ed448_verify(&public_key, b"message", &[0u8; 64]);
        assert!(result.is_err());
    }
}

// ============================================================================
// ML-DSA-65 Signature Tests
// ============================================================================

mod mldsa65_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_mldsa65_generate_keypair() {
        let result = mldsa65_generate().unwrap();

        let secret_key = get_bytes_field(&result, "secret_key");
        let public_key = get_bytes_field(&result, "public_key");

        // ML-DSA-65 key sizes
        assert!(secret_key.len() > 0);
        assert_eq!(public_key.len(), 1952);
    }

    #[wasm_bindgen_test]
    fn test_mldsa65_sign_verify_roundtrip() {
        let keypair = mldsa65_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let message = b"Test message for ML-DSA-65 signing";
        let signature = mldsa65_sign(&secret_key, message).unwrap();

        assert_eq!(signature.len(), 3309);

        let valid = mldsa65_verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[wasm_bindgen_test]
    fn test_mldsa65_verify_wrong_message_fails() {
        let keypair = mldsa65_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let signature = mldsa65_sign(&secret_key, b"message 1").unwrap();
        let valid = mldsa65_verify(&public_key, b"message 2", &signature).unwrap();

        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_mldsa65_invalid_key_fails() {
        let result = mldsa65_sign(&[0u8; 100], b"message");
        assert!(result.is_err());
    }
}

// ============================================================================
// X448 Key Exchange Tests
// ============================================================================

mod x448_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_x448_generate_keypair() {
        let result = x448_generate().unwrap();

        let secret_key = get_bytes_field(&result, "secret_key");
        let public_key = get_bytes_field(&result, "public_key");

        assert_eq!(secret_key.len(), 56);
        assert_eq!(public_key.len(), 56);
    }

    #[wasm_bindgen_test]
    fn test_x448_dh_shared_secret_agreement() {
        let alice = x448_generate().unwrap();
        let bob = x448_generate().unwrap();

        let alice_secret = get_bytes_field(&alice, "secret_key");
        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_secret = get_bytes_field(&bob, "secret_key");
        let bob_public = get_bytes_field(&bob, "public_key");

        let shared_alice = x448_dh(&alice_secret, &bob_public).unwrap();
        let shared_bob = x448_dh(&bob_secret, &alice_public).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert_eq!(shared_alice.len(), 56);
    }

    #[wasm_bindgen_test]
    fn test_x448_different_keys_different_secrets() {
        let alice = x448_generate().unwrap();
        let bob = x448_generate().unwrap();
        let charlie = x448_generate().unwrap();

        let alice_secret = get_bytes_field(&alice, "secret_key");
        let bob_public = get_bytes_field(&bob, "public_key");
        let charlie_public = get_bytes_field(&charlie, "public_key");

        let shared_ab = x448_dh(&alice_secret, &bob_public).unwrap();
        let shared_ac = x448_dh(&alice_secret, &charlie_public).unwrap();

        assert_ne!(shared_ab, shared_ac);
    }

    #[wasm_bindgen_test]
    fn test_x448_invalid_secret_key_length() {
        let result = x448_dh(&[0u8; 32], &[0u8; 56]);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_x448_invalid_public_key_length() {
        let keypair = x448_generate().unwrap();
        let secret = get_bytes_field(&keypair, "secret_key");

        let result = x448_dh(&secret, &[0u8; 32]);
        assert!(result.is_err());
    }
}

// ============================================================================
// Hybrid Signature Tests
// ============================================================================

mod hybrid_signature_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_hybrid_sign_generate() {
        let result = hybrid_sign_generate().unwrap();
        let public_key = get_bytes_field(&result, "public_key");

        // 57 (Ed448) + 1952 (ML-DSA-65) = 2009
        assert_eq!(public_key.len(), 2009);
    }
}

// ============================================================================
// Hybrid KEM Tests
// ============================================================================

mod hybrid_kem_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_hybrid_kem_generate() {
        let result = hybrid_kem_generate().unwrap();

        let secret_key = get_bytes_field(&result, "secret_key");
        let public_key = get_bytes_field(&result, "public_key");

        assert_eq!(secret_key.len(), 1819);
        assert_eq!(public_key.len(), 1214);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_kem_encapsulate_decapsulate_roundtrip() {
        let keypair = hybrid_kem_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let enc_result = hybrid_kem_encapsulate(&public_key).unwrap();
        let shared_secret_enc = get_bytes_field(&enc_result, "shared_secret");
        let encapsulation = get_bytes_field(&enc_result, "encapsulation");

        assert_eq!(shared_secret_enc.len(), 32);
        assert_eq!(encapsulation.len(), 1095);

        let shared_secret_dec = hybrid_kem_decapsulate(&secret_key, &encapsulation).unwrap();
        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_kem_wrong_key_different_secret() {
        let keypair1 = hybrid_kem_generate().unwrap();
        let keypair2 = hybrid_kem_generate().unwrap();

        let public_key1 = get_bytes_field(&keypair1, "public_key");
        let secret_key2 = get_bytes_field(&keypair2, "secret_key");

        let enc_result = hybrid_kem_encapsulate(&public_key1).unwrap();
        let shared_secret_enc = get_bytes_field(&enc_result, "shared_secret");
        let encapsulation = get_bytes_field(&enc_result, "encapsulation");

        // Decapsulating with wrong key gives different secret (implicit rejection)
        let shared_secret_dec = hybrid_kem_decapsulate(&secret_key2, &encapsulation).unwrap();
        assert_ne!(shared_secret_enc, shared_secret_dec);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_kem_invalid_public_key() {
        let result = hybrid_kem_encapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_hybrid_kem_invalid_secret_key() {
        let keypair = hybrid_kem_generate().unwrap();
        let public_key = get_bytes_field(&keypair, "public_key");

        let enc_result = hybrid_kem_encapsulate(&public_key).unwrap();
        let encapsulation = get_bytes_field(&enc_result, "encapsulation");

        let result = hybrid_kem_decapsulate(&[0u8; 100], &encapsulation);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_hybrid_kem_invalid_encapsulation() {
        let keypair = hybrid_kem_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");

        let result = hybrid_kem_decapsulate(&secret_key, &[0u8; 100]);
        assert!(result.is_err());
    }
}

// ============================================================================
// Hybrid Identity Tests
// ============================================================================

mod hybrid_identity_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_hybrid_identity_generate() {
        let result = hybrid_identity_generate().unwrap();

        let secret_key = get_bytes_field(&result, "secret_key");
        let public_key = get_bytes_field(&result, "public_key");

        assert_eq!(secret_key.len(), 5908);
        assert_eq!(public_key.len(), 3223);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_identity_sign_verify_roundtrip() {
        let keypair = hybrid_identity_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let message = b"Test message for hybrid identity signing";
        let signature = hybrid_identity_sign(&secret_key, message).unwrap();

        assert_eq!(signature.len(), 3366);

        let valid = hybrid_identity_verify(&public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_identity_verify_wrong_message_fails() {
        let keypair = hybrid_identity_generate().unwrap();
        let secret_key = get_bytes_field(&keypair, "secret_key");
        let public_key = get_bytes_field(&keypair, "public_key");

        let signature = hybrid_identity_sign(&secret_key, b"message 1").unwrap();
        let valid = hybrid_identity_verify(&public_key, b"message 2", &signature).unwrap();

        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_hybrid_identity_decapsulate() {
        let identity = hybrid_identity_generate().unwrap();
        let secret_key = get_bytes_field(&identity, "secret_key");
        let public_key = get_bytes_field(&identity, "public_key");

        // Extract KEM public key from identity public key (it's at offset 2009)
        // Identity public key = signing (2009) + KEM (1214) = 3223
        let kem_public = &public_key[2009..];

        let enc_result = hybrid_kem_encapsulate(kem_public).unwrap();
        let shared_secret_enc = get_bytes_field(&enc_result, "shared_secret");
        let encapsulation = get_bytes_field(&enc_result, "encapsulation");

        let shared_secret_dec = hybrid_identity_decapsulate(&secret_key, &encapsulation).unwrap();
        assert_eq!(shared_secret_enc, shared_secret_dec);
    }
}

// ============================================================================
// Safety Number Tests
// ============================================================================

mod safety_number_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_safety_number_derive() {
        let alice = hybrid_identity_generate().unwrap();
        let bob = hybrid_identity_generate().unwrap();

        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_public = get_bytes_field(&bob, "public_key");

        let result = safety_number_derive(&alice_public, &bob_public).unwrap();

        let fingerprint = get_bytes_field(&result, "fingerprint");
        let display = get_string_field(&result, "display");

        assert_eq!(fingerprint.len(), 32);
        // display is a formatted two-line block (six groups of five digits
        // per line, single-space separators, newline between rows). Count
        // just the digits to verify the documented 60-digit safety number.
        let digit_count = display.chars().filter(|c| c.is_ascii_digit()).count();
        assert_eq!(digit_count, 60);
    }

    #[wasm_bindgen_test]
    fn test_safety_number_commutativity() {
        let alice = hybrid_identity_generate().unwrap();
        let bob = hybrid_identity_generate().unwrap();

        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_public = get_bytes_field(&bob, "public_key");

        let result_ab = safety_number_derive(&alice_public, &bob_public).unwrap();
        let result_ba = safety_number_derive(&bob_public, &alice_public).unwrap();

        let fingerprint_ab = get_bytes_field(&result_ab, "fingerprint");
        let fingerprint_ba = get_bytes_field(&result_ba, "fingerprint");

        assert_eq!(fingerprint_ab, fingerprint_ba);
    }

    #[wasm_bindgen_test]
    fn test_safety_number_to_qr_roundtrip() {
        let alice = hybrid_identity_generate().unwrap();
        let bob = hybrid_identity_generate().unwrap();

        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_public = get_bytes_field(&bob, "public_key");

        let qr_string = safety_number_to_qr(&alice_public, &bob_public).unwrap();
        assert_eq!(qr_string.len(), 44);

        let valid = safety_number_verify_qr(&qr_string, &alice_public, &bob_public).unwrap();
        assert!(valid);
    }

    #[wasm_bindgen_test]
    fn test_safety_number_verify_qr_invalid() {
        let alice = hybrid_identity_generate().unwrap();
        let bob = hybrid_identity_generate().unwrap();
        let charlie = hybrid_identity_generate().unwrap();

        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_public = get_bytes_field(&bob, "public_key");
        let charlie_public = get_bytes_field(&charlie, "public_key");

        let qr_string = safety_number_to_qr(&alice_public, &bob_public).unwrap();

        // QR from alice-bob should not match alice-charlie
        let valid = safety_number_verify_qr(&qr_string, &alice_public, &charlie_public).unwrap();
        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_safety_number_verify_qr_invalid_string() {
        let alice = hybrid_identity_generate().unwrap();
        let bob = hybrid_identity_generate().unwrap();

        let alice_public = get_bytes_field(&alice, "public_key");
        let bob_public = get_bytes_field(&bob, "public_key");

        let valid =
            safety_number_verify_qr("invalid_qr_string", &alice_public, &bob_public).unwrap();
        assert!(!valid);
    }
}

// ============================================================================
// Recovery Key Tests
// ============================================================================

mod recovery_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_derive_recovery_keypair_deterministic() {
        let seed = random_bytes_32().unwrap();

        let result1 = derive_recovery_keypair(&seed).unwrap();
        let result2 = derive_recovery_keypair(&seed).unwrap();

        let public_key1 = get_bytes_field(&result1, "public_key");
        let public_key2 = get_bytes_field(&result2, "public_key");

        assert_eq!(public_key1, public_key2);
    }

    #[wasm_bindgen_test]
    fn test_derive_recovery_keypair_different_seeds() {
        let seed1 = random_bytes_32().unwrap();
        let seed2 = random_bytes_32().unwrap();

        let result1 = derive_recovery_keypair(&seed1).unwrap();
        let result2 = derive_recovery_keypair(&seed2).unwrap();

        let public_key1 = get_bytes_field(&result1, "public_key");
        let public_key2 = get_bytes_field(&result2, "public_key");

        assert_ne!(public_key1, public_key2);
    }

    #[wasm_bindgen_test]
    fn test_derive_recovery_keypair_sizes() {
        let seed = random_bytes_32().unwrap();
        let result = derive_recovery_keypair(&seed).unwrap();

        let public_key = get_bytes_field(&result, "public_key");
        let secret_key = get_bytes_field(&result, "secret_key");

        assert_eq!(public_key.len(), 2009);
        assert_eq!(secret_key.len(), 4089);
    }

    #[wasm_bindgen_test]
    fn test_derive_recovery_keypair_invalid_seed_length() {
        let result = derive_recovery_keypair(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_key_fingerprint() {
        let recovery = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();
        let public_key = get_bytes_field(&recovery, "public_key");

        let fingerprint = key_fingerprint(&public_key).unwrap();
        assert_eq!(fingerprint.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_key_fingerprint_deterministic() {
        let recovery = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();
        let public_key = get_bytes_field(&recovery, "public_key");

        let fp1 = key_fingerprint(&public_key).unwrap();
        let fp2 = key_fingerprint(&public_key).unwrap();

        assert_eq!(fp1, fp2);
    }
}

// ============================================================================
// Compromise Notice Tests
// ============================================================================

mod compromise_notice_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_compromise_notice_create_verify() {
        let recovery = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();
        let public_key = get_bytes_field(&recovery, "public_key");
        let secret_key = get_bytes_field(&recovery, "secret_key");

        let fingerprint = key_fingerprint(&public_key).unwrap();

        let notice = compromise_notice_create(
            &fingerprint,
            0, // KeyExfiltration
            1234567890,
            &secret_key,
        )
        .unwrap();

        assert_eq!(notice.len(), 3439); // 73-byte body + 3366-byte BoP-2 signature

        let result = compromise_notice_verify(&notice, &public_key).unwrap();
        let valid = get_bool_field(&result, "valid");
        let reason = get_number_field(&result, "reason") as u8;
        let compromised_at = get_number_field(&result, "compromised_at") as u64;

        assert!(valid);
        assert_eq!(reason, 0);
        assert_eq!(compromised_at, 1234567890);
    }

    #[wasm_bindgen_test]
    fn test_compromise_notice_wrong_signer_fails() {
        let recovery1 = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();
        let recovery2 = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();

        let public_key1 = get_bytes_field(&recovery1, "public_key");
        let secret_key1 = get_bytes_field(&recovery1, "secret_key");
        let public_key2 = get_bytes_field(&recovery2, "public_key");

        let fingerprint = key_fingerprint(&public_key1).unwrap();

        let notice = compromise_notice_create(&fingerprint, 1, 1234567890, &secret_key1).unwrap();

        let result = compromise_notice_verify(&notice, &public_key2).unwrap();
        let valid = get_bool_field(&result, "valid");

        assert!(!valid);
    }

    #[wasm_bindgen_test]
    fn test_compromise_notice_is_self_signed() {
        let recovery = derive_recovery_keypair(&random_bytes_32().unwrap()).unwrap();
        let public_key = get_bytes_field(&recovery, "public_key");
        let secret_key = get_bytes_field(&recovery, "secret_key");

        let fingerprint = key_fingerprint(&public_key).unwrap();

        let notice = compromise_notice_create(&fingerprint, 0, 1234567890, &secret_key).unwrap();

        let result = compromise_notice_verify(&notice, &public_key).unwrap();
        let is_self_signed = get_bool_field(&result, "is_self_signed");

        assert!(is_self_signed);
    }
}

// ============================================================================
// X3DH-PQ Bundle Tests
// ============================================================================

mod x3dh_bundle_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_x3dh_create_bundle() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_public = get_bytes_field(&identity, "public_key");

        // Extract signing and KEM public keys
        let signing_public = &identity_public[..2009];
        let kem_public = &identity_public[2009..];

        let otk = hybrid_kem_generate().unwrap();
        let otk_public = get_bytes_field(&otk, "public_key");

        let bundle = x3dh_create_bundle(
            signing_public,
            kem_public,
            &otk_public,
            12345, // otk_key_id
            1000,  // timestamp
            2000,  // expiration
        )
        .unwrap();

        assert_eq!(bundle.len(), 4461);
    }

    #[wasm_bindgen_test]
    fn test_x3dh_sign_verify_bundle() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let identity_public = get_bytes_field(&identity, "public_key");

        // Extract signing keys
        let signing_public = &identity_public[..2009];
        let kem_public = &identity_public[2009..];

        // Need the signing secret key - extract from identity
        // Identity secret = signing (4089) + KEM (1819) = 5908
        let signing_secret = &identity_secret[..4089];

        let otk = hybrid_kem_generate().unwrap();
        let otk_public = get_bytes_field(&otk, "public_key");

        let bundle =
            x3dh_create_bundle(signing_public, kem_public, &otk_public, 12345, 1000, 2000).unwrap();

        let signed_bundle = x3dh_sign_bundle(&bundle, signing_secret).unwrap();
        assert_eq!(signed_bundle.len(), 7827);

        let result = x3dh_verify_bundle(&signed_bundle).unwrap();

        let parsed_signing = get_bytes_field(&result, "identity_signing");
        let parsed_kem = get_bytes_field(&result, "identity_kem");
        let parsed_otk = get_bytes_field(&result, "one_time_key");
        let parsed_otk_id = get_number_field(&result, "otk_key_id") as u64;
        let parsed_timestamp = get_number_field(&result, "timestamp") as u64;
        let parsed_expiration = get_number_field(&result, "expiration") as u64;

        assert_eq!(parsed_signing, signing_public);
        assert_eq!(parsed_kem, kem_public);
        assert_eq!(parsed_otk, otk_public);
        assert_eq!(parsed_otk_id, 12345);
        assert_eq!(parsed_timestamp, 1000);
        assert_eq!(parsed_expiration, 2000);
    }

    #[wasm_bindgen_test]
    fn test_x3dh_verify_bundle_invalid_size() {
        let result = x3dh_verify_bundle(&[0u8; 100]);
        assert!(result.is_err());
    }
}

// ============================================================================
// X3DH-PQ Session Establishment Tests
// ============================================================================

mod x3dh_session_tests {
    use super::*;

    fn create_signed_bundle() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Returns: (signed_bundle, bob_identity_secret, bob_otk_secret)
        let bob_identity = hybrid_identity_generate().unwrap();
        let bob_identity_secret = get_bytes_field(&bob_identity, "secret_key");
        let bob_identity_public = get_bytes_field(&bob_identity, "public_key");

        let bob_signing_public = &bob_identity_public[..2009];
        let bob_kem_public = &bob_identity_public[2009..];
        let bob_signing_secret = &bob_identity_secret[..4089];

        let bob_otk = hybrid_kem_generate().unwrap();
        let bob_otk_public = get_bytes_field(&bob_otk, "public_key");
        let bob_otk_secret = get_bytes_field(&bob_otk, "secret_key");

        let bundle = x3dh_create_bundle(
            bob_signing_public,
            bob_kem_public,
            &bob_otk_public,
            1,
            1000,
            5000,
        )
        .unwrap();

        let signed_bundle = x3dh_sign_bundle(&bundle, bob_signing_secret).unwrap();

        (signed_bundle, bob_identity_secret, bob_otk_secret)
    }

    #[wasm_bindgen_test]
    fn test_x3dh_initiator_establish() {
        let alice = hybrid_identity_generate().unwrap();
        let alice_secret = get_bytes_field(&alice, "secret_key");

        let (signed_bundle, _, _) = create_signed_bundle();

        let result = x3dh_initiator_establish(&alice_secret, &signed_bundle, 2000, false).unwrap();

        let root_key = get_bytes_field(&result, "root_key");
        let send_chain = get_bytes_field(&result, "send_chain_key");
        let recv_chain = get_bytes_field(&result, "recv_chain_key");
        let initial_message = get_bytes_field(&result, "initial_message");

        assert_eq!(root_key.len(), 32);
        assert_eq!(send_chain.len(), 32);
        assert_eq!(recv_chain.len(), 32);
        assert_eq!(initial_message.len(), 1095);
    }

    #[wasm_bindgen_test]
    fn test_x3dh_responder_establish() {
        let alice = hybrid_identity_generate().unwrap();
        let alice_secret = get_bytes_field(&alice, "secret_key");
        let alice_public = get_bytes_field(&alice, "public_key");

        // Split Alice's identity public into the signing half (Ed448+ML-DSA,
        // 2,009 bytes) and the X448 portion of her KEM half (first 56 bytes
        // of the 1,214-byte KEM key). The responder binding takes these as
        // separate arguments because session establishment only consumes the
        // X448 portion of Alice's identity KEM.
        let alice_signing_public = &alice_public[..2009];
        let alice_x448_public = &alice_public[2009..2009 + 56];

        let (signed_bundle, bob_identity_secret, bob_otk_secret) = create_signed_bundle();

        // Alice initiates
        let alice_result =
            x3dh_initiator_establish(&alice_secret, &signed_bundle, 2000, false).unwrap();
        let initial_message = get_bytes_field(&alice_result, "initial_message");

        // Bob responds (needs his own signed bundle to verify the OTK identity
        // that Alice's initial message references)
        let bob_result = x3dh_responder_establish(
            &bob_identity_secret,
            &bob_otk_secret,
            alice_signing_public,
            alice_x448_public,
            &signed_bundle,
            &initial_message,
            false,
        )
        .unwrap();

        let bob_root_key = get_bytes_field(&bob_result, "root_key");
        let alice_root_key = get_bytes_field(&alice_result, "root_key");

        // Both should derive the same root key
        assert_eq!(alice_root_key, bob_root_key);
    }

    /// End-to-end regression net for F18 through the WASM establish() wrappers:
    /// the `li_capable` bool passed to `x3dh_initiator_establish` /
    /// `x3dh_responder_establish` must thread into the transcript on both sides.
    /// (a) matching `true` still agrees; (b) a `true` / `false` mismatch diverges
    /// the derived key (fail-closed). Every other WASM session test uses `false`,
    /// so this is the only guard that a WASM binding actually honours the flag —
    /// if a binding ignored `li_capable` or hardcoded it, assertion (b) fails.
    #[wasm_bindgen_test]
    fn test_x3dh_li_capability_binding_through_establish() {
        let alice = hybrid_identity_generate().unwrap();
        let alice_secret = get_bytes_field(&alice, "secret_key");
        let alice_public = get_bytes_field(&alice, "public_key");
        let alice_signing_public = &alice_public[..2009];
        let alice_x448_public = &alice_public[2009..2009 + 56];

        let (signed_bundle, bob_identity_secret, bob_otk_secret) = create_signed_bundle();

        // Alice initiates as LI-capable = true.
        let alice_result =
            x3dh_initiator_establish(&alice_secret, &signed_bundle, 2000, true).unwrap();
        let initial_message = get_bytes_field(&alice_result, "initial_message");
        let alice_root_key = get_bytes_field(&alice_result, "root_key");

        // (a) Bob responds with the SAME flag → keys agree.
        let bob_match = x3dh_responder_establish(
            &bob_identity_secret,
            &bob_otk_secret,
            alice_signing_public,
            alice_x448_public,
            &signed_bundle,
            &initial_message,
            true,
        )
        .unwrap();
        let bob_match_root_key = get_bytes_field(&bob_match, "root_key");
        assert_eq!(
            alice_root_key, bob_match_root_key,
            "matching li_capable=true through wasm establish() must agree"
        );

        // (b) Bob responds with the MISMATCHED flag → keys diverge (fail-closed).
        let bob_mismatch = x3dh_responder_establish(
            &bob_identity_secret,
            &bob_otk_secret,
            alice_signing_public,
            alice_x448_public,
            &signed_bundle,
            &initial_message,
            false,
        )
        .unwrap();
        let bob_mismatch_root_key = get_bytes_field(&bob_mismatch, "root_key");
        assert_ne!(
            alice_root_key, bob_mismatch_root_key,
            "li_capable mismatch through wasm establish() must diverge (F18)"
        );
    }
}

// ============================================================================
// Ratchet Tests
// ============================================================================

mod ratchet_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_ratchet_init_initiator() {
        let session_key = random_bytes_32().unwrap();
        let their_kem = hybrid_kem_generate().unwrap();
        let their_public = get_bytes_field(&their_kem, "public_key");

        let init = ratchet_init_initiator(&session_key, &their_public, 1000).unwrap();
        let state = get_bytes_field(&init, "state");
        let our_public_key = get_bytes_field(&init, "our_public_key");
        assert!(!state.is_empty());
        assert_eq!(our_public_key.len(), 1214);
    }

    #[wasm_bindgen_test]
    fn test_ratchet_init_responder() {
        let session_key = random_bytes_32().unwrap();
        let our_kem = hybrid_kem_generate().unwrap();
        let our_secret = get_bytes_field(&our_kem, "secret_key");

        let init = ratchet_init_responder(&session_key, &our_secret, 1000).unwrap();
        let state = get_bytes_field(&init, "state");
        let our_public_key = get_bytes_field(&init, "our_public_key");
        assert!(!state.is_empty());
        assert_eq!(our_public_key.len(), 1214);
    }

    #[wasm_bindgen_test]
    fn test_ratchet_send_receive_roundtrip() {
        // Setup: Alice and Bob establish ratchets.
        let session_key = random_bytes_32().unwrap();

        let bob_kem = hybrid_kem_generate().unwrap();
        let bob_secret = get_bytes_field(&bob_kem, "secret_key");
        let bob_public = get_bytes_field(&bob_kem, "public_key");

        // Alice initialises as initiator with Bob's public key.
        let alice_init = ratchet_init_initiator(&session_key, &bob_public, 1000).unwrap();
        let alice_state = get_bytes_field(&alice_init, "state");

        // Bob initialises as responder with his own keypair.
        let bob_init = ratchet_init_responder(&session_key, &bob_secret, 1000).unwrap();
        let bob_state = get_bytes_field(&bob_init, "state");

        // Alice sends a message.
        let plaintext = b"Hello, Bob!";
        let send_result = ratchet_send(&alice_state, plaintext, 1001).unwrap();

        let alice_state_new = get_bytes_field(&send_result, "state");
        let header = get_bytes_field(&send_result, "header");
        let nonce = get_bytes_field(&send_result, "nonce");
        let ciphertext = get_bytes_field(&send_result, "ciphertext");

        assert!(!alice_state_new.is_empty());
        assert_eq!(nonce.len(), 24);
        assert!(!ciphertext.is_empty());

        // Bob receives the message via the wire-decomposed shape.
        let recv_result = ratchet_receive(&bob_state, &header, &nonce, &ciphertext, 1001).unwrap();

        let decrypted = get_bytes_field(&recv_result, "plaintext");
        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn test_ratchet_multiple_messages() {
        let session_key = random_bytes_32().unwrap();

        let bob_kem = hybrid_kem_generate().unwrap();
        let bob_secret = get_bytes_field(&bob_kem, "secret_key");
        let bob_public = get_bytes_field(&bob_kem, "public_key");

        let alice_init = ratchet_init_initiator(&session_key, &bob_public, 1000).unwrap();
        let mut alice_state = get_bytes_field(&alice_init, "state");

        let bob_init = ratchet_init_responder(&session_key, &bob_secret, 1000).unwrap();
        let mut bob_state = get_bytes_field(&bob_init, "state");

        for i in 0..3 {
            let plaintext = format!("Message {}", i);

            let send_result = ratchet_send(&alice_state, plaintext.as_bytes(), 1001 + i).unwrap();
            alice_state = get_bytes_field(&send_result, "state");
            let header = get_bytes_field(&send_result, "header");
            let nonce = get_bytes_field(&send_result, "nonce");
            let ciphertext = get_bytes_field(&send_result, "ciphertext");

            let recv_result =
                ratchet_receive(&bob_state, &header, &nonce, &ciphertext, 1001 + i).unwrap();
            bob_state = get_bytes_field(&recv_result, "state");
            let decrypted = get_bytes_field(&recv_result, "plaintext");

            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}

// ============================================================================
// CoCoA Session Tests
// ============================================================================

mod cocoa_tests {
    use super::*;

    /// Build the inputs every cocoa_create_group test needs: a fresh identity
    /// keypair, a fresh KEM keypair, and a random user id.
    fn fresh_creator_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let kem = hybrid_kem_generate().unwrap();
        let kem_secret = get_bytes_field(&kem, "secret_key");
        let user_id = random_bytes_32().unwrap();
        (identity_secret, kem_secret, user_id)
    }

    #[wasm_bindgen_test]
    fn test_cocoa_create_group() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();

        let result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();

        let session = get_bytes_field(&result, "session");
        assert!(!session.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_cocoa_encrypt_decrypt() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();
        let create_result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();
        let session = get_bytes_field(&create_result, "session");

        // Encrypt a message
        let plaintext = b"Hello, CoCoA group!";
        let encrypt_result = cocoa_encrypt(&session, plaintext).unwrap();

        let session_after = get_bytes_field(&encrypt_result, "session");
        let encrypted_message = get_bytes_field(&encrypt_result, "encrypted_message");
        assert!(!encrypted_message.is_empty());

        // Decrypt the message
        let decrypt_result = cocoa_decrypt(&session_after, &encrypted_message).unwrap();
        let decrypted = get_bytes_field(&decrypt_result, "plaintext");
        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn test_cocoa_session_info() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();
        let create_result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();
        let session = get_bytes_field(&create_result, "session");

        let info = cocoa_session_info(&session).unwrap();

        let epoch = get_number_field(&info, "epoch") as u32;
        let member_count = get_number_field(&info, "member_count") as u32;
        let our_leaf_position = get_number_field(&info, "our_leaf_position") as u32;

        assert_eq!(epoch, 0);
        assert_eq!(member_count, 1);
        assert_eq!(our_leaf_position, 0);
    }

    #[wasm_bindgen_test]
    fn test_cocoa_multiple_encryptions() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();
        let create_result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();
        let mut session = get_bytes_field(&create_result, "session");

        for i in 0..5 {
            let plaintext = format!("Group message {}", i);

            let encrypt_result = cocoa_encrypt(&session, plaintext.as_bytes()).unwrap();
            session = get_bytes_field(&encrypt_result, "session");
            let encrypted_message = get_bytes_field(&encrypt_result, "encrypted_message");

            // cocoa_decrypt is read-only — it returns {plaintext} only, no
            // updated session — so we keep the post-encrypt session for the
            // next loop iteration.
            let decrypt_result = cocoa_decrypt(&session, &encrypted_message).unwrap();
            let decrypted = get_bytes_field(&decrypt_result, "plaintext");

            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[wasm_bindgen_test]
    fn test_cocoa_rotate_keypair() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();
        let create_result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();
        let session = get_bytes_field(&create_result, "session");

        let rotate_result = cocoa_rotate_keypair(&session).unwrap();

        let session_after = get_bytes_field(&rotate_result, "session");
        let new_public_key = get_bytes_field(&rotate_result, "public_key");

        assert!(!session_after.is_empty());
        assert_eq!(new_public_key.len(), 1214);
    }

    #[wasm_bindgen_test]
    fn test_cocoa_create_update() {
        let (identity_secret, kem_secret, user_id) = fresh_creator_inputs();
        let create_result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();
        let session = get_bytes_field(&create_result, "session");

        // cocoa_create_update takes (session, identity_secret) — the second
        // argument is the signing keypair that signs the update commit.
        let update_result = cocoa_create_update(&session, &identity_secret).unwrap();

        let session_after = get_bytes_field(&update_result, "session");
        let commit = get_bytes_field(&update_result, "commit");

        assert!(!session_after.is_empty());
        assert!(!commit.is_empty());
    }
}

// ============================================================================
// Multidevice Tests
// ============================================================================

mod multidevice_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_device_fingerprint() {
        // device_fingerprint takes a 2,009-byte hybrid signing public key,
        // which is the first half of the full hybrid identity public key.
        let identity = hybrid_identity_generate().unwrap();
        let identity_public = get_bytes_field(&identity, "public_key");
        let signing_public = &identity_public[..2009];

        let fingerprint = device_fingerprint(signing_public).unwrap();
        assert_eq!(fingerprint.len(), 32);
    }

    #[wasm_bindgen_test]
    fn test_device_fingerprint_deterministic() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_public = get_bytes_field(&identity, "public_key");
        let signing_public = &identity_public[..2009];

        let fp1 = device_fingerprint(signing_public).unwrap();
        let fp2 = device_fingerprint(signing_public).unwrap();

        assert_eq!(fp1, fp2);
    }

    #[wasm_bindgen_test]
    fn test_device_approval_create_verify() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let signing_secret = &identity_secret[..4089];

        // A dedicated account identity keypair roots the device graph. Its
        // 2,009-byte signing public key (the first half of the hybrid identity
        // public key) is bound into the approval and passed as the trusted
        // anchor at verify (v0.7 identity-rooted layout).
        let account_identity = hybrid_identity_generate().unwrap();
        let account_identity_public = get_bytes_field(&account_identity, "public_key");
        let account_identity_pk = account_identity_public[..2009].to_vec();

        // v0.7 layout: 16-byte device id + 32-byte user id + 32-byte
        // server-issued nonce + 2,009-byte account identity pk, all bound into
        // the signed body.
        let approving_device_id = vec![0x01u8; 16];
        let user_id = vec![0x02u8; 32];
        let new_device_fingerprint = vec![0x03u8; 32];
        let server_nonce = vec![0x04u8; 32];
        let approved_at = 1234567890u64;

        let approval = device_approval_create(
            &approving_device_id,
            &user_id,
            &new_device_fingerprint,
            &server_nonce,
            &account_identity_pk,
            approved_at,
            signing_secret,
        )
        .unwrap();
        assert!(!approval.is_empty());

        // Verify within the default 300-second window. The signature is
        // self-verifying (embedded approving_device_pk); identity rooting
        // requires the trusted account identity anchor.
        let result =
            device_approval_verify(&approval, &account_identity_pk, approved_at + 30, 300).unwrap();
        assert!(get_bool_field(&result, "valid"));

        // Every body field round-trips through the verify result.
        assert_eq!(
            get_bytes_field(&result, "approving_device_id"),
            approving_device_id
        );
        assert_eq!(get_bytes_field(&result, "user_id"), user_id);
        assert_eq!(
            get_bytes_field(&result, "new_device_fingerprint"),
            new_device_fingerprint
        );
        assert_eq!(get_bytes_field(&result, "server_nonce"), server_nonce);
        assert_eq!(
            get_bytes_field(&result, "account_identity_pk"),
            account_identity_pk
        );
    }

    #[wasm_bindgen_test]
    fn test_device_approval_verify_expired() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let signing_secret = &identity_secret[..4089];

        let account_identity = hybrid_identity_generate().unwrap();
        let account_identity_public = get_bytes_field(&account_identity, "public_key");
        let account_identity_pk = account_identity_public[..2009].to_vec();

        let approval = device_approval_create(
            &vec![0x01u8; 16],
            &vec![0x02u8; 32],
            &vec![0x03u8; 32],
            &vec![0x04u8; 32],
            &account_identity_pk,
            1000,
            signing_secret,
        )
        .unwrap();

        // now is 400 seconds after approved_at, window is 300 — must reject on
        // freshness (checked before the identity anchor).
        let result = device_approval_verify(&approval, &account_identity_pk, 1400, 300).unwrap();
        assert!(!get_bool_field(&result, "valid"));
    }

    #[wasm_bindgen_test]
    fn test_device_approval_verify_future_dated() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let signing_secret = &identity_secret[..4089];

        let account_identity = hybrid_identity_generate().unwrap();
        let account_identity_public = get_bytes_field(&account_identity, "public_key");
        let account_identity_pk = account_identity_public[..2009].to_vec();

        let approval = device_approval_create(
            &vec![0x01u8; 16],
            &vec![0x02u8; 32],
            &vec![0x03u8; 32],
            &vec![0x04u8; 32],
            &account_identity_pk,
            5000,
            signing_secret,
        )
        .unwrap();

        // now is 400 seconds BEFORE approved_at, window is 300 — must reject.
        // The verify path uses abs_diff so both stale and future-dated certs
        // fall outside the window.
        let result = device_approval_verify(&approval, &account_identity_pk, 4600, 300).unwrap();
        assert!(!get_bool_field(&result, "valid"));
    }

    /// F10 regression net at the JS consumer boundary: `device_approval_verify`
    /// must reject a well-formed, in-window cert when the caller supplies a
    /// DIFFERENT account identity anchor than the one bound into the cert. The
    /// three other WASM device-approval tests all pass the CORRECT anchor, and
    /// the two negatives reject on freshness (checked before the identity anchor
    /// in `verify`), so each of those would still pass even if the binding
    /// dropped, hard-coded, or self-anchored the argument. This is therefore the
    /// only WASM guard that the identity-rooting anchor is actually honoured at
    /// the JS surface. `now = approved_at + 30` keeps the cert inside the
    /// 300-second window so the rejection is driven by the identity anchor, not
    /// freshness — the `valid == false` / `IdentityKeyMismatch` assertions below
    /// fail if a future edit drops the anchor comparison in the wrapper.
    #[wasm_bindgen_test]
    fn test_device_approval_verify_identity_mismatch() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let signing_secret = &identity_secret[..4089];

        // The account identity the cert is actually bound to.
        let account_identity = hybrid_identity_generate().unwrap();
        let account_identity_public = get_bytes_field(&account_identity, "public_key");
        let account_identity_pk = account_identity_public[..2009].to_vec();

        let approved_at = 1234567890u64;
        let approval = device_approval_create(
            &vec![0x01u8; 16],
            &vec![0x02u8; 32],
            &vec![0x03u8; 32],
            &vec![0x04u8; 32],
            &account_identity_pk,
            approved_at,
            signing_secret,
        )
        .unwrap();

        // A DIFFERENT but well-formed account identity signing key — a valid
        // 2,009-byte anchor that is not the one bound into the cert, so
        // `from_bytes` accepts it and the mismatch is decided by the anchor
        // comparison rather than a parse failure.
        let wrong_identity = hybrid_identity_generate().unwrap();
        let wrong_identity_public = get_bytes_field(&wrong_identity, "public_key");
        let wrong_account_identity_pk = wrong_identity_public[..2009].to_vec();

        // In-window (|now - approved_at| = 30 <= 300) so freshness passes and the
        // identity anchor is what rejects.
        let result =
            device_approval_verify(&approval, &wrong_account_identity_pk, approved_at + 30, 300)
                .unwrap();

        assert!(
            !get_bool_field(&result, "valid"),
            "a mismatched account identity anchor must reject"
        );
        // The binding surfaces the CryptoError via `{:?}`, so the anchor-rejection
        // path is `IdentityKeyMismatch` (distinct from the freshness path's
        // `NonceExpired` and the signature path's `SignatureVerificationFailed`).
        let err = get_string_field(&result, "error");
        assert!(
            err.contains("IdentityKeyMismatch"),
            "must reject on the identity anchor, got {err}"
        );
    }

    #[wasm_bindgen_test]
    fn test_device_revocation_create_verify() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let identity_public = get_bytes_field(&identity, "public_key");

        let signing_secret = &identity_secret[..4089];
        let signing_public = &identity_public[..2009];

        // device_revocation_create takes a 16-byte device ID (NOT a 32-byte
        // device fingerprint).
        let device_id = vec![0x01u8; 16];

        let revocation = device_revocation_create(
            &device_id,
            1, // reason: DeviceLost (RevocationReason::from_byte(1))
            1234567890,
            signing_secret,
        )
        .unwrap();

        assert!(revocation.len() > 0);

        let result = device_revocation_verify(&revocation, signing_public).unwrap();

        let valid = get_bool_field(&result, "valid");
        let reason = get_number_field(&result, "reason") as u8;

        assert!(valid);
        assert_eq!(reason, 1);
    }

    #[wasm_bindgen_test]
    fn test_device_key_wrap_unwrap() {
        // Build the AAD-binding fields used by both create and unwrap.
        // The wrap binds to: recipient_key_id || purpose || thread_id ||
        // bundle_id || epoch — these MUST match between create and unwrap or
        // the AEAD verification at unwrap fails.
        let secret = random_bytes_32().unwrap();
        let recipient_kem = hybrid_kem_generate().unwrap();
        let recipient_kem_public = get_bytes_field(&recipient_kem, "public_key");
        let recipient_kem_secret = get_bytes_field(&recipient_kem, "secret_key");
        let recipient_key_id = vec![0x01u8; 8];
        let purpose: u8 = 1;
        let thread_id = vec![0x02u8; 32];
        let bundle_id = vec![0x03u8; 32];
        let epoch = 1234567890u64;

        // device_key_wrap_create returns the canonical wrap byte string
        // directly (NOT a JsValue object); device_key_wrap_unwrap returns
        // the unwrapped 32-byte secret directly.
        let wrap_bytes = device_key_wrap_create(
            &secret,
            &recipient_kem_public,
            &recipient_key_id,
            purpose,
            &thread_id,
            &bundle_id,
            epoch,
        )
        .unwrap();
        assert!(!wrap_bytes.is_empty());

        let unwrapped = device_key_wrap_unwrap(
            &wrap_bytes,
            &recipient_kem_secret,
            &recipient_key_id,
            purpose,
            &thread_id,
            &bundle_id,
            epoch,
        )
        .unwrap();
        assert_eq!(unwrapped, secret);
    }

    #[wasm_bindgen_test]
    fn test_device_key_wrap_unwrap_aad_tamper_rejected() {
        let secret = random_bytes_32().unwrap();
        let recipient_kem = hybrid_kem_generate().unwrap();
        let recipient_kem_public = get_bytes_field(&recipient_kem, "public_key");
        let recipient_kem_secret = get_bytes_field(&recipient_kem, "secret_key");
        let recipient_key_id = vec![0x01u8; 8];
        let purpose: u8 = 1;
        let thread_id = vec![0x02u8; 32];
        let bundle_id = vec![0x03u8; 32];
        let epoch = 1234567890u64;

        let wrap_bytes = device_key_wrap_create(
            &secret,
            &recipient_kem_public,
            &recipient_key_id,
            purpose,
            &thread_id,
            &bundle_id,
            epoch,
        )
        .unwrap();

        // Tamper with the thread_id at unwrap time — AAD differs, so the
        // AEAD verification MUST fail rather than silently returning the
        // wrong plaintext.
        let mut wrong_thread_id = thread_id.clone();
        wrong_thread_id[0] ^= 0xFF;
        let unwrap_result = device_key_wrap_unwrap(
            &wrap_bytes,
            &recipient_kem_secret,
            &recipient_key_id,
            purpose,
            &wrong_thread_id,
            &bundle_id,
            epoch,
        );
        assert!(unwrap_result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_thread_settings_create() {
        let thread_id = random_bytes_32().unwrap();
        let settings = thread_settings_create(
            &thread_id, false, // ephemeral=false => history sync ON
            1234567890,
        )
        .unwrap();

        // The binding exposes the underlying boolean flag rather than the
        // `ephemeral` argument name. With ephemeral=false the new settings
        // have history_sync_enabled=true.
        let history_sync_enabled = get_bool_field(&settings, "history_sync_enabled");
        assert!(history_sync_enabled);
    }

    #[wasm_bindgen_test]
    fn test_retained_key_create_parse() {
        let message_id = random_bytes_32().unwrap();
        let message_key = random_bytes_32().unwrap();
        let timestamp = 1234567890u64;

        let retained = retained_key_create(&message_id, &message_key, 0, timestamp).unwrap();
        assert!(retained.len() > 0);

        let parsed = retained_key_parse(&retained).unwrap();

        // retained_key_parse intentionally does NOT return the message_key —
        // the comment in lib.rs says "message_key is protected". Round-trip
        // the visible fields (message_id, sequence, timestamp) instead.
        let parsed_message_id = get_bytes_field(&parsed, "message_id");
        let parsed_sequence = get_number_field(&parsed, "sequence") as u64;
        let parsed_timestamp = get_number_field(&parsed, "timestamp") as u64;

        assert_eq!(parsed_message_id, message_id);
        assert_eq!(parsed_sequence, 0);
        assert_eq!(parsed_timestamp, timestamp);
    }

    #[wasm_bindgen_test]
    fn test_thread_key_store_operations() {
        let thread_id = random_bytes_32().unwrap();

        let store = thread_key_store_create(&thread_id).unwrap();
        assert!(store.len() > 0);

        // Create and retain a key
        let message_id = random_bytes_32().unwrap();
        let message_key = random_bytes_32().unwrap();
        let retained_key = retained_key_create(&message_id, &message_key, 0, 1234567890).unwrap();
        let store = thread_key_store_retain(&store, &retained_key).unwrap();

        // Get info
        let info = thread_key_store_info(&store).unwrap();
        let key_count = get_number_field(&info, "key_count") as u32;
        assert_eq!(key_count, 1);

        // Get all keys
        let keys = thread_key_store_get_all_keys(&store).unwrap();
        assert!(keys.len() > 0);
    }
}

// ============================================================================
// History Key Share Tests
// ============================================================================

mod history_tests {
    use super::*;

    #[wasm_bindgen_test]
    fn test_history_key_share_create_verify() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");
        let identity_public = get_bytes_field(&identity, "public_key");

        let signing_secret = &identity_secret[..4089];
        let signing_public = &identity_public[..2009];

        let thread_id = random_bytes_32().unwrap();

        // Create key store with a key
        let store = thread_key_store_create(&thread_id).unwrap();
        let message_id = random_bytes_32().unwrap();
        let message_key = random_bytes_32().unwrap();
        let retained_key = retained_key_create(&message_id, &message_key, 0, 1234567890).unwrap();
        let store = thread_key_store_retain(&store, &retained_key).unwrap();

        let keys = thread_key_store_get_all_keys(&store).unwrap();

        // Create history share (thread_id, retained_keys, signing_secret, shared_at)
        let share =
            history_key_share_create(&thread_id, &keys, signing_secret, 1234567890).unwrap();

        assert!(share.len() > 0);

        // Verify
        let result = history_key_share_verify(&share, signing_public).unwrap();

        let valid = get_bool_field(&result, "valid");
        let returned_thread_id = get_bytes_field(&result, "thread_id");

        assert!(valid);
        assert_eq!(returned_thread_id, thread_id);
    }

    #[wasm_bindgen_test]
    fn test_history_key_share_extract_keys() {
        let identity = hybrid_identity_generate().unwrap();
        let identity_secret = get_bytes_field(&identity, "secret_key");

        let signing_secret = &identity_secret[..4089];

        let thread_id = random_bytes_32().unwrap();

        let store = thread_key_store_create(&thread_id).unwrap();
        let message_id = random_bytes_32().unwrap();
        let message_key = random_bytes_32().unwrap();
        let retained_key = retained_key_create(&message_id, &message_key, 0, 1234567890).unwrap();
        let store = thread_key_store_retain(&store, &retained_key).unwrap();

        let keys = thread_key_store_get_all_keys(&store).unwrap();

        let share =
            history_key_share_create(&thread_id, &keys, signing_secret, 1234567890).unwrap();

        let extracted = history_key_share_extract_keys(&share).unwrap();
        assert!(extracted.len() > 0);
    }
}
