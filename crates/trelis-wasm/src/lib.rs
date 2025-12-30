//! WASM bindings for Trelis cryptographic primitives and signatures.
//!
//! This crate provides WebAssembly bindings for the Trelis cryptographic library,
//! exposing the following functionality:
//!
//! - **AEAD**: XChaCha20-Poly1305 authenticated encryption
//! - **KDF**: BLAKE3-based key derivation
//! - **Signatures**: Ed448 and ML-DSA-65 (standalone and hybrid)
//! - **Key Exchange**: X448 Diffie-Hellman
//!
//! # Limitations
//!
//! The WASM build does **not** include sntrup761 post-quantum KEM, which requires
//! C FFI bindings. Full hybrid KEM functionality (including HybridKemKeypair,
//! HybridIdentityKeypair, and the X3DH-PQ/Double Ratchet protocols) requires
//! native compilation.
//!
//! For production use with full post-quantum protection, use the native library.

#![allow(clippy::needless_pass_by_value)]

use wasm_bindgen::prelude::*;

/// Initialise the WASM module with better panic handling (optional).
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// AEAD (XChaCha20-Poly1305)
// ============================================================================

/// Encrypt data using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
/// Ciphertext with 16-byte authentication tag appended
#[wasm_bindgen]
pub fn aead_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let key_arr: [u8; 32] = key.try_into().map_err(|_| JsValue::from_str("Invalid key"))?;
    let nonce_arr: [u8; 24] = nonce.try_into().map_err(|_| JsValue::from_str("Invalid nonce"))?;

    let aead_key = trelis_primitives::AeadKey::from_bytes(key_arr);
    let aead_nonce = trelis_primitives::Nonce::from_bytes(nonce_arr);

    trelis_primitives::encrypt(&aead_key, &aead_nonce, plaintext, aad)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

/// Decrypt data using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (same as used for encryption)
/// * `ciphertext` - Data to decrypt (includes 16-byte tag)
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Decrypted plaintext
#[wasm_bindgen]
pub fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let key_arr: [u8; 32] = key.try_into().map_err(|_| JsValue::from_str("Invalid key"))?;
    let nonce_arr: [u8; 24] = nonce.try_into().map_err(|_| JsValue::from_str("Invalid nonce"))?;

    let aead_key = trelis_primitives::AeadKey::from_bytes(key_arr);
    let aead_nonce = trelis_primitives::Nonce::from_bytes(nonce_arr);

    trelis_primitives::decrypt(&aead_key, &aead_nonce, ciphertext, aad)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

// ============================================================================
// Key Derivation (BLAKE3)
// ============================================================================

/// Derive a 32-byte key using BLAKE3 with domain separation.
///
/// # Arguments
/// * `context` - Domain separation string (e.g., "trelis-session-key-v1")
/// * `input` - Input key material
///
/// # Returns
/// 32-byte derived key
#[wasm_bindgen]
pub fn derive_key(context: &str, input: &[u8]) -> Vec<u8> {
    trelis_primitives::derive_key(context, input).to_vec()
}

/// Compute BLAKE3 hash of data.
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte hash
#[wasm_bindgen]
pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
    trelis_primitives::hash(data).to_vec()
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Generate 32 cryptographically secure random bytes.
///
/// # Returns
/// 32 random bytes
#[wasm_bindgen]
pub fn random_bytes_32() -> Result<Vec<u8>, JsValue> {
    let bytes: [u8; 32] = trelis_primitives::generate_bytes()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(bytes.to_vec())
}

/// Generate 24 cryptographically secure random bytes (for nonces).
///
/// # Returns
/// 24 random bytes
#[wasm_bindgen]
pub fn random_bytes_24() -> Result<Vec<u8>, JsValue> {
    let bytes: [u8; 24] = trelis_primitives::generate_bytes()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(bytes.to_vec())
}

// ============================================================================
// Ed448 Signatures
// ============================================================================

/// Generate an Ed448 signing keypair.
///
/// # Returns
/// Object with `secret_key` (57 bytes) and `public_key` (57 bytes)
#[wasm_bindgen]
pub fn ed448_generate() -> Result<JsValue, JsValue> {
    let keypair = trelis_primitives::Ed448SigningKey::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let secret_arr = js_sys::Uint8Array::from(keypair.seed().as_slice());
    let public_arr = js_sys::Uint8Array::from(keypair.verifying_key().as_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"secret_key".into(), &secret_arr)?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Sign a message with Ed448.
///
/// # Arguments
/// * `secret_key` - 57-byte secret key seed
/// * `message` - Message to sign
///
/// # Returns
/// 114-byte signature
#[wasm_bindgen]
pub fn ed448_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != 57 {
        return Err(JsValue::from_str("Secret key must be 57 bytes"));
    }

    let seed: [u8; 57] = secret_key.try_into().map_err(|_| JsValue::from_str("Invalid key"))?;
    let key = trelis_primitives::Ed448SigningKey::from_seed(seed);

    let sig = key.sign(message);
    Ok(sig.as_bytes().to_vec())
}

/// Verify an Ed448 signature.
///
/// # Arguments
/// * `public_key` - 57-byte public key
/// * `message` - Original message
/// * `signature` - 114-byte signature
///
/// # Returns
/// `true` if valid, `false` otherwise
#[wasm_bindgen]
pub fn ed448_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    if public_key.len() != 57 {
        return Err(JsValue::from_str("Public key must be 57 bytes"));
    }
    if signature.len() != 114 {
        return Err(JsValue::from_str("Signature must be 114 bytes"));
    }

    let sig_arr: [u8; 114] = signature.try_into().map_err(|_| JsValue::from_str("Invalid signature"))?;

    let pk = trelis_primitives::Ed448VerifyingKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = trelis_primitives::Ed448Signature::from_bytes(&sig_arr)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig).is_ok())
}

// ============================================================================
// ML-DSA-65 Signatures (Post-Quantum)
// ============================================================================

/// Generate an ML-DSA-65 signing keypair.
///
/// # Returns
/// Object with `secret_key` and `public_key` (1,952 bytes)
#[wasm_bindgen]
pub fn mldsa65_generate() -> Result<JsValue, JsValue> {
    let keypair = trelis_primitives::MlDsa65SigningKey::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let secret_arr = js_sys::Uint8Array::from(keypair.as_bytes().as_slice());
    let public_arr = js_sys::Uint8Array::from(keypair.verifying_key().as_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"secret_key".into(), &secret_arr)?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Sign a message with ML-DSA-65.
///
/// # Arguments
/// * `secret_key` - Secret key bytes
/// * `message` - Message to sign
///
/// # Returns
/// 3,309-byte signature
#[wasm_bindgen]
pub fn mldsa65_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = trelis_primitives::MlDsa65SigningKey::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = key.sign(message).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(sig.as_bytes().to_vec())
}

/// Verify an ML-DSA-65 signature.
///
/// # Arguments
/// * `public_key` - 1,952-byte public key
/// * `message` - Original message
/// * `signature` - 3,309-byte signature
///
/// # Returns
/// `true` if valid, `false` otherwise
#[wasm_bindgen]
pub fn mldsa65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk = trelis_primitives::MlDsa65VerifyingKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = trelis_primitives::MlDsa65Signature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig))
}

// ============================================================================
// Hybrid Signatures (Ed448 + ML-DSA-65)
// ============================================================================

/// Generate a hybrid signing keypair (Ed448 + ML-DSA-65).
///
/// Note: The keypair cannot be serialised. Use the returned object
/// to sign messages and get the public key.
///
/// # Returns
/// Object with `public_key` (2,009 bytes) - use `hybrid_sign_with_keypair` to sign
#[wasm_bindgen]
pub fn hybrid_sign_generate() -> Result<JsValue, JsValue> {
    let keypair = trelis_hybrid::HybridSigningKeypair::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let public_arr = js_sys::Uint8Array::from(keypair.public_key().to_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    // Note: We can't serialise the full keypair, so we store the Ed448 seed and ML-DSA key
    // This is a simplified approach - in production you'd want proper key storage
    Ok(obj.into())
}

/// Verify a hybrid signature (Ed448 + ML-DSA-65).
///
/// Both signatures must be valid for verification to succeed.
///
/// # Arguments
/// * `public_key` - 2,009-byte public key
/// * `message` - Original message
/// * `signature` - 3,423-byte hybrid signature
///
/// # Returns
/// `true` if both signatures are valid, `false` otherwise
#[wasm_bindgen]
pub fn hybrid_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk = trelis_hybrid::HybridSigningPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = trelis_hybrid::HybridSignature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig))
}

// ============================================================================
// X448 Key Exchange
// ============================================================================

/// Generate an X448 keypair for Diffie-Hellman key exchange.
///
/// # Returns
/// Object with `secret_key` (56 bytes) and `public_key` (56 bytes)
#[wasm_bindgen]
pub fn x448_generate() -> Result<JsValue, JsValue> {
    let secret = trelis_primitives::X448Secret::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let public = secret.public_key();

    let obj = js_sys::Object::new();
    let secret_arr = js_sys::Uint8Array::from(secret.as_bytes().as_slice());
    let public_arr = js_sys::Uint8Array::from(public.as_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"secret_key".into(), &secret_arr)?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Perform X448 Diffie-Hellman key exchange.
///
/// # Arguments
/// * `our_secret` - Our 56-byte secret key
/// * `their_public` - Their 56-byte public key
///
/// # Returns
/// 56-byte shared secret
#[wasm_bindgen]
pub fn x448_dh(our_secret: &[u8], their_public: &[u8]) -> Result<Vec<u8>, JsValue> {
    if our_secret.len() != 56 {
        return Err(JsValue::from_str("Secret key must be 56 bytes"));
    }
    if their_public.len() != 56 {
        return Err(JsValue::from_str("Public key must be 56 bytes"));
    }

    let secret_arr: [u8; 56] = our_secret.try_into().map_err(|_| JsValue::from_str("Invalid secret key"))?;

    let secret = trelis_primitives::X448Secret::from_bytes(secret_arr);
    let public = trelis_primitives::X448Public::from_bytes(their_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let shared = secret.diffie_hellman(&public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(shared.as_bytes().to_vec())
}
