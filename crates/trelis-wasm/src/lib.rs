//! WASM bindings for Trelis cryptographic primitives and protocols.
//!
//! This crate provides WebAssembly bindings for the Trelis cryptographic library,
//! exposing full post-quantum secure messaging functionality:
//!
//! - **AEAD**: XChaCha20-Poly1305 authenticated encryption
//! - **KDF**: BLAKE3-based key derivation (with WASM SIMD support)
//! - **Signatures**: Ed448 and ML-DSA-65 (standalone and hybrid)
//! - **Key Exchange**: X448 Diffie-Hellman
//! - **Hybrid KEM**: X448 + sntrup761 post-quantum key encapsulation
//! - **Hybrid Identity**: Combined signing + KEM identity keys
//! - **Safety Numbers**: Signal-style identity verification
//! - **X3DH-PQ**: Post-quantum extended triple Diffie-Hellman key agreement
//! - **KEM Ratchet**: Per-message forward secrecy with hybrid keys
//! - **CoCoA**: Concurrent group key agreement
//!
//! All keys are exportable as byte arrays for JavaScript storage (IndexedDB, etc.).

// trelis-wasm is the wasm-bindgen wrapper surface to JavaScript. The
// `cast_possible_truncation` / `cast_precision_loss` (u64/u8 → f64) allows
// reflect the wasm-bindgen → JS Number bridge: JS Number is f64, so the
// truncation is an API contract, not a bug. The `uninlined_format_args`
// allow covers the wholesale `format!("{:?}", e)` pattern used for
// JsValue error bridging.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::uninlined_format_args,
    clippy::unwrap_used,
    // WASM bindings commonly use unwrap after explicit checks
)]

use wasm_bindgen::prelude::*;

// Type aliases using the compile-time selected default ML-DSA scheme
// With `mldsa-blake3-default` feature: uses MlDsa65Blake3 (BLAKE3)
// Without that feature (default): uses MlDsa65Fips204 (SHA-3/SHAKE)
type HybridSigningPublicKey =
    trelis_hybrid::HybridSigningPublicKey<trelis_primitives::mldsa::DefaultMlDsaScheme>;
type HybridSigningKeypair =
    trelis_hybrid::HybridSigningKeypair<trelis_primitives::mldsa::DefaultMlDsaScheme>;
type HybridSignature = trelis_hybrid::HybridSignature<trelis_primitives::mldsa::DefaultMlDsaScheme>;

/// BLAKE3 `derive_key` context for reconstructing a CoCoA group session's
/// `init_secret` when deserialising a legacy (pre-`init_secret`-field) session
/// blob in `deserialize_cocoa_session`.
///
/// Deliberately distinct from `trelis_primitives::SESSION_CONTEXT`
/// (`"trelis-session-v1"`): that context (v1) derives an X3DH-PQ *pairwise*
/// session secret from a 296-byte transcript — the v2 context
/// (`"trelis-session-v2"`) derives over the 299-byte transcript that appends
/// the additive `{version || suite-id || SessionFlags}` framing block —
/// whereas this reconstructs a CoCoA *group* `init_secret` from a 32-byte
/// transcript hash. Different protocols, different operations — sharing a
/// context string would be a domain-separation violation, not an
/// interoperability fix.
const COCOA_WASM_LEGACY_SESSION_CONTEXT: &str = "trelis-cocoa-wasm-session-v1";

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
pub fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid key"))?;
    let nonce_arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid nonce"))?;

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
pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(JsValue::from_str("Nonce must be 24 bytes"));
    }

    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid key"))?;
    let nonce_arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid nonce"))?;

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
#[must_use]
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
#[must_use]
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
    let bytes: [u8; 32] =
        trelis_primitives::generate_bytes().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(bytes.to_vec())
}

/// Generate 24 cryptographically secure random bytes (for nonces).
///
/// # Returns
/// 24 random bytes
#[wasm_bindgen]
pub fn random_bytes_24() -> Result<Vec<u8>, JsValue> {
    let bytes: [u8; 24] =
        trelis_primitives::generate_bytes().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
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

    let seed: [u8; 57] = secret_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid key"))?;
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

    let sig_arr: [u8; 114] = signature
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid signature"))?;

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

    let sig = key
        .sign(message)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
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
pub fn mldsa65_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let pk = trelis_primitives::MlDsa65VerifyingKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = trelis_primitives::MlDsa65Signature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig).is_ok())
}

// ============================================================================
// Hybrid Signatures (Ed448 + ML-DSA-65)
// ============================================================================

/// Generate a hybrid signing keypair (Ed448 + ML-DSA-65).
///
/// # Limitations
///
/// This function only returns the public key. The secret key cannot be
/// exported due to WASM serialisation constraints. For signing operations,
/// use the individual `ed448_sign` and `mldsa65_sign` functions with
/// separately managed keys.
///
/// # Returns
/// Object with `public_key` (2,009 bytes)
#[wasm_bindgen]
pub fn hybrid_sign_generate() -> Result<JsValue, JsValue> {
    let keypair =
        HybridSigningKeypair::generate().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let public_arr = js_sys::Uint8Array::from(keypair.public_key().to_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Verify a hybrid signature (Ed448 + ML-DSA-65).
///
/// Both signatures must be valid for verification to succeed.
///
/// # Arguments
/// * `public_key` - 2,009-byte public key
/// * `message` - Original message
/// * `signature` - 3,366-byte hybrid signature
///
/// # Returns
/// `true` if both signatures are valid, `false` otherwise
#[wasm_bindgen]
pub fn hybrid_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk = HybridSigningPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = HybridSignature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig).is_ok())
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

    let secret_arr: [u8; 56] = our_secret
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid secret key"))?;

    let secret = trelis_primitives::X448Secret::from_bytes(secret_arr);
    let public = trelis_primitives::X448Public::from_bytes(their_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let shared = secret
        .diffie_hellman(&public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(shared.as_bytes().to_vec())
}

// ============================================================================
// Hybrid KEM (X448 + sntrup761)
// ============================================================================

/// Generate a hybrid KEM keypair (X448 + sntrup761).
///
/// # Returns
/// Object with `secret_key` (1,819 bytes) and `public_key` (1,214 bytes)
#[wasm_bindgen]
pub fn hybrid_kem_generate() -> Result<JsValue, JsValue> {
    let keypair = trelis_hybrid::HybridKemKeypair::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let secret_arr = js_sys::Uint8Array::from(keypair.to_bytes().as_slice());
    let public_arr = js_sys::Uint8Array::from(keypair.public_key().to_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"secret_key".into(), &secret_arr)?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Encapsulate to a hybrid KEM public key.
///
/// # Arguments
/// * `public_key` - 1,214-byte hybrid KEM public key
///
/// # Returns
/// Object with `shared_secret` (32 bytes) and `encapsulation` (1,095 bytes)
#[wasm_bindgen]
pub fn hybrid_kem_encapsulate(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let pk = trelis_hybrid::HybridKemPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let (shared_secret, encapsulation) = pk
        .encapsulate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let ss_arr = js_sys::Uint8Array::from(shared_secret.as_bytes().as_slice());
    let enc_arr = js_sys::Uint8Array::from(encapsulation.to_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"shared_secret".into(), &ss_arr)?;
    js_sys::Reflect::set(&obj, &"encapsulation".into(), &enc_arr)?;

    Ok(obj.into())
}

/// Decapsulate a hybrid KEM encapsulation.
///
/// # Arguments
/// * `secret_key` - 1,819-byte hybrid KEM secret key
/// * `encapsulation` - 1,095-byte encapsulation
///
/// # Returns
/// 32-byte shared secret
#[wasm_bindgen]
pub fn hybrid_kem_decapsulate(secret_key: &[u8], encapsulation: &[u8]) -> Result<Vec<u8>, JsValue> {
    let keypair = trelis_hybrid::HybridKemKeypair::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let enc = trelis_hybrid::HybridEncapsulation::from_bytes(encapsulation)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let shared_secret = keypair
        .decapsulate(&enc)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(shared_secret.as_bytes().to_vec())
}

// ============================================================================
// Hybrid Identity (Signing + KEM)
// ============================================================================

/// Generate a hybrid identity keypair (Ed448 + ML-DSA-65 + X448 + sntrup761).
///
/// # Returns
/// Object with `secret_key` (5,908 bytes) and `public_key` (3,223 bytes)
#[wasm_bindgen]
pub fn hybrid_identity_generate() -> Result<JsValue, JsValue> {
    let keypair = trelis_hybrid::HybridIdentityKeypair::generate()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    let secret_arr = js_sys::Uint8Array::from(keypair.to_bytes().as_slice());
    let public_arr = js_sys::Uint8Array::from(keypair.public_key().to_bytes().as_slice());

    js_sys::Reflect::set(&obj, &"secret_key".into(), &secret_arr)?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &public_arr)?;

    Ok(obj.into())
}

/// Sign a message with a hybrid identity key.
///
/// # Arguments
/// * `secret_key` - 5,908-byte hybrid identity secret key
/// * `message` - Message to sign
///
/// # Returns
/// 3,366-byte hybrid signature
#[wasm_bindgen]
pub fn hybrid_identity_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let keypair = trelis_hybrid::HybridIdentityKeypair::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let signature = keypair
        .sign(message)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(signature.to_bytes().to_vec())
}

/// Verify a hybrid identity signature.
///
/// # Arguments
/// * `public_key` - 3,223-byte hybrid identity public key
/// * `message` - Original message
/// * `signature` - 3,366-byte hybrid signature
///
/// # Returns
/// `true` if valid, `false` otherwise
#[wasm_bindgen]
pub fn hybrid_identity_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sig = trelis_hybrid::HybridSignature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(pk.verify(message, &sig).is_ok())
}

/// Decapsulate using a hybrid identity key.
///
/// # Arguments
/// * `secret_key` - 5,908-byte hybrid identity secret key
/// * `encapsulation` - 1,095-byte hybrid KEM encapsulation
///
/// # Returns
/// 32-byte shared secret
#[wasm_bindgen]
pub fn hybrid_identity_decapsulate(
    secret_key: &[u8],
    encapsulation: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let keypair = trelis_hybrid::HybridIdentityKeypair::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let enc = trelis_hybrid::HybridEncapsulation::from_bytes(encapsulation)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let shared_secret = keypair
        .decapsulate(&enc)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(shared_secret.as_bytes().to_vec())
}

// ============================================================================
// Safety Numbers
// ============================================================================

/// Derive a safety number from two hybrid identity public keys.
///
/// # Arguments
/// * `our_public_key` - Our 3,223-byte hybrid identity public key
/// * `their_public_key` - Their 3,223-byte hybrid identity public key
///
/// # Returns
/// Object with `fingerprint` (32 bytes) and `display` (60 decimal digits)
#[wasm_bindgen]
pub fn safety_number_derive(
    our_public_key: &[u8],
    their_public_key: &[u8],
) -> Result<JsValue, JsValue> {
    let our_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(our_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let their_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(their_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let safety_number = trelis_hybrid::SafetyNumber::new(&our_pk, &their_pk);

    let obj = js_sys::Object::new();
    let fingerprint_arr = js_sys::Uint8Array::from(safety_number.fingerprint().as_slice());
    let display_str = JsValue::from_str(&safety_number.display());

    js_sys::Reflect::set(&obj, &"fingerprint".into(), &fingerprint_arr)?;
    js_sys::Reflect::set(&obj, &"display".into(), &display_str)?;

    Ok(obj.into())
}

/// Generate a QR code string for a safety number.
///
/// # Arguments
/// * `our_public_key` - Our 3,223-byte hybrid identity public key
/// * `their_public_key` - Their 3,223-byte hybrid identity public key
///
/// # Returns
/// 44-character Base64-URL encoded string for QR code
#[wasm_bindgen]
pub fn safety_number_to_qr(
    our_public_key: &[u8],
    their_public_key: &[u8],
) -> Result<String, JsValue> {
    let our_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(our_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let their_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(their_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let safety_number = trelis_hybrid::SafetyNumber::new(&our_pk, &their_pk);

    Ok(safety_number.to_qr_string())
}

/// Verify a safety number QR code matches expected keys.
///
/// # Arguments
/// * `qr_string` - 44-character Base64-URL encoded QR string
/// * `our_public_key` - Our 3,223-byte hybrid identity public key
/// * `their_public_key` - Their 3,223-byte hybrid identity public key
///
/// # Returns
/// `true` if the QR code matches, `false` otherwise
#[wasm_bindgen]
pub fn safety_number_verify_qr(
    qr_string: &str,
    our_public_key: &[u8],
    their_public_key: &[u8],
) -> Result<bool, JsValue> {
    let parsed = trelis_hybrid::SafetyNumber::from_qr_string(qr_string);
    if parsed.is_none() {
        return Ok(false);
    }
    let parsed = parsed.unwrap();

    let our_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(our_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let their_pk = trelis_hybrid::HybridIdentityPublicKey::from_bytes(their_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let expected = trelis_hybrid::SafetyNumber::new(&our_pk, &their_pk);

    Ok(parsed.fingerprint() == expected.fingerprint())
}

// ============================================================================
// Key Recovery and Compromise Notices
// ============================================================================

/// Derive a deterministic recovery keypair from a seed.
///
/// This allows users to regenerate their recovery key from a backed-up seed
/// (e.g., derived from a mnemonic phrase).
///
/// # Arguments
/// * `seed` - 32-byte seed
///
/// # Returns
/// Object with:
/// - `public_key` - 2,009-byte hybrid signing public key
/// - `secret_key` - 4,089-byte hybrid signing secret key
#[wasm_bindgen]
pub fn derive_recovery_keypair(seed: &[u8]) -> Result<JsValue, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Seed must be 32 bytes"));
    }

    let seed_arr: [u8; 32] = seed
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid seed"))?;

    let keypair: HybridSigningKeypair = trelis_hybrid::recovery::derive_recovery_keypair(&seed_arr)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"public_key".into(),
        &js_sys::Uint8Array::from(keypair.public_key().to_bytes().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"secret_key".into(),
        &js_sys::Uint8Array::from(keypair.to_bytes().as_slice()),
    )?;

    Ok(obj.into())
}

/// Calculate the fingerprint of a hybrid signing public key.
///
/// # Arguments
/// * `public_key` - 2,009-byte hybrid signing public key
///
/// # Returns
/// 32-byte BLAKE3 fingerprint
#[wasm_bindgen]
pub fn key_fingerprint(public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pk = HybridSigningPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let fingerprint = trelis_hybrid::recovery::key_fingerprint(&pk);
    Ok(fingerprint.to_vec())
}

/// Create a compromise notice announcing that a key has been compromised.
///
/// # Arguments
/// * `compromised_fingerprint` - 32-byte fingerprint of the compromised key
/// * `reason` - Compromise reason (0=KeyExfiltration, 1=DeviceTheft, 2=MalwareExposure,
///              3=BackupCompromise, 4=ServerBreach, 255=Unknown)
/// * `compromised_at` - Unix timestamp when compromise is believed to have occurred
/// * `signing_secret` - 4,089-byte signing secret key (compromised key or recovery key)
///
/// # Returns
/// Serialised compromise notice (3,439 bytes: 73-byte body + 3,366-byte BoP-2 signature)
#[wasm_bindgen]
pub fn compromise_notice_create(
    compromised_fingerprint: &[u8],
    reason: u8,
    compromised_at: u64,
    signing_secret: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if compromised_fingerprint.len() != 32 {
        return Err(JsValue::from_str("Fingerprint must be 32 bytes"));
    }

    let mut fp = [0u8; 32];
    fp.copy_from_slice(compromised_fingerprint);

    let reason = trelis_hybrid::recovery::CompromiseReason::from_byte(reason);

    let keypair = HybridSigningKeypair::from_bytes(signing_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let notice = trelis_hybrid::recovery::CompromiseNotice::<
        trelis_primitives::mldsa::DefaultMlDsaScheme,
    >::new(fp, reason, compromised_at, &keypair)
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(notice.to_bytes())
}

/// Verify a compromise notice.
///
/// # Arguments
/// * `notice_bytes` - Serialised compromise notice
/// * `signer_public` - 2,009-byte public key of the expected signer
///
/// # Returns
/// Object with:
/// - `valid` - boolean indicating if signature is valid
/// - `compromised_fingerprint` - 32-byte fingerprint of compromised key
/// - `reason` - Compromise reason code
/// - `compromised_at` - Unix timestamp
/// - `is_self_signed` - boolean if signer is the compromised key
#[wasm_bindgen]
pub fn compromise_notice_verify(
    notice_bytes: &[u8],
    signer_public: &[u8],
) -> Result<JsValue, JsValue> {
    let notice = trelis_hybrid::recovery::CompromiseNotice::<
        trelis_primitives::mldsa::DefaultMlDsaScheme,
    >::from_bytes(notice_bytes)
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let signer_pk = HybridSigningPublicKey::from_bytes(signer_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let valid = notice.verify(&signer_pk).is_ok();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"valid".into(), &JsValue::from_bool(valid))?;
    js_sys::Reflect::set(
        &obj,
        &"compromised_fingerprint".into(),
        &js_sys::Uint8Array::from(notice.compromised_fingerprint.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"reason".into(),
        &JsValue::from_f64(notice.reason.to_byte() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"compromised_at".into(),
        &JsValue::from_f64(notice.compromised_at as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"is_self_signed".into(),
        &JsValue::from_bool(notice.is_self_signed()),
    )?;

    Ok(obj.into())
}

// ============================================================================
// X3DH-PQ Pre-Key Bundles
// ============================================================================

/// Create a pre-key bundle for X3DH-PQ session establishment.
///
/// # Arguments
/// * `identity_signing_public` - 2,009-byte hybrid signing public key
/// * `identity_kem_public` - 1,214-byte hybrid KEM public key
/// * `one_time_key_public` - 1,214-byte hybrid KEM public key (one-time)
/// * `otk_key_id` - Key ID for the one-time key
/// * `timestamp` - Unix timestamp when bundle was created
/// * `expiration` - Unix timestamp when bundle expires
///
/// # Returns
/// Serialised pre-key bundle (4,461 bytes)
#[wasm_bindgen]
pub fn x3dh_create_bundle(
    identity_signing_public: &[u8],
    identity_kem_public: &[u8],
    one_time_key_public: &[u8],
    otk_key_id: u64,
    timestamp: u64,
    expiration: u64,
) -> Result<Vec<u8>, JsValue> {
    let id_sign = HybridSigningPublicKey::from_bytes(identity_signing_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let id_kem = trelis_hybrid::HybridKemPublicKey::from_bytes(identity_kem_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let otk = trelis_hybrid::HybridKemPublicKey::from_bytes(one_time_key_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Build bundle bytes: all public keys + metadata
    let mut bundle = Vec::with_capacity(
        identity_signing_public.len() + identity_kem_public.len() + one_time_key_public.len() + 24,
    );
    bundle.extend_from_slice(&id_sign.to_bytes());
    bundle.extend_from_slice(&id_kem.to_bytes());
    bundle.extend_from_slice(&otk.to_bytes());
    bundle.extend_from_slice(&otk_key_id.to_le_bytes());
    bundle.extend_from_slice(&timestamp.to_le_bytes());
    bundle.extend_from_slice(&expiration.to_le_bytes());

    Ok(bundle)
}

/// Sign a pre-key bundle.
///
/// # Arguments
/// * `bundle` - 4,461-byte unsigned bundle from `x3dh_create_bundle`
/// * `signing_secret` - 4,089-byte hybrid signing secret key
///
/// # Returns
/// Signed bundle (7,827 bytes = bundle + 3,366-byte signature)
#[wasm_bindgen]
pub fn x3dh_sign_bundle(bundle: &[u8], signing_secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let keypair = HybridSigningKeypair::from_bytes(signing_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Domain-separated signing data
    let mut signing_data = Vec::with_capacity(23 + bundle.len());
    signing_data.extend_from_slice(b"trelis-prekey-bundle-v1");
    signing_data.extend_from_slice(bundle);

    let signature = keypair
        .sign(&signing_data)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Return bundle + signature
    let mut signed = Vec::with_capacity(bundle.len() + signature.to_bytes().len());
    signed.extend_from_slice(bundle);
    signed.extend_from_slice(&signature.to_bytes());

    Ok(signed)
}

/// Verify a signed pre-key bundle.
///
/// # Arguments
/// * `signed_bundle` - 7,827-byte signed bundle
///
/// # Returns
/// Object with bundle fields if valid, error if invalid
#[wasm_bindgen]
pub fn x3dh_verify_bundle(signed_bundle: &[u8]) -> Result<JsValue, JsValue> {
    // Bundle is 4,461 bytes, signature is 3,366 bytes
    const BUNDLE_SIZE: usize = 4461;
    const SIG_SIZE: usize = 3366;

    if signed_bundle.len() != BUNDLE_SIZE + SIG_SIZE {
        return Err(JsValue::from_str("Invalid signed bundle size"));
    }

    let bundle_bytes = &signed_bundle[..BUNDLE_SIZE];
    let sig_bytes = &signed_bundle[BUNDLE_SIZE..];

    // Parse identity signing key (first 2,009 bytes)
    let id_sign = HybridSigningPublicKey::from_bytes(&bundle_bytes[..2009])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Domain-separated signing data
    let mut signing_data = Vec::with_capacity(23 + bundle_bytes.len());
    signing_data.extend_from_slice(b"trelis-prekey-bundle-v1");
    signing_data.extend_from_slice(bundle_bytes);

    let signature = HybridSignature::from_bytes(sig_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    if id_sign.verify(&signing_data, &signature).is_err() {
        return Err(JsValue::from_str("Bundle signature invalid"));
    }

    // Parse remaining fields
    let id_kem = &bundle_bytes[2009..2009 + 1214];
    let otk = &bundle_bytes[2009 + 1214..2009 + 1214 + 1214];
    let otk_key_id = u64::from_le_bytes(bundle_bytes[4437..4445].try_into().unwrap());
    let timestamp = u64::from_le_bytes(bundle_bytes[4445..4453].try_into().unwrap());
    let expiration = u64::from_le_bytes(bundle_bytes[4453..4461].try_into().unwrap());

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"identity_signing".into(),
        &js_sys::Uint8Array::from(&bundle_bytes[..2009]),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"identity_kem".into(),
        &js_sys::Uint8Array::from(id_kem),
    )?;
    js_sys::Reflect::set(&obj, &"one_time_key".into(), &js_sys::Uint8Array::from(otk))?;
    js_sys::Reflect::set(
        &obj,
        &"otk_key_id".into(),
        &JsValue::from_f64(otk_key_id as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"timestamp".into(),
        &JsValue::from_f64(timestamp as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"expiration".into(),
        &JsValue::from_f64(expiration as f64),
    )?;

    Ok(obj.into())
}

/// Establish an X3DH-PQ session as the initiator (Alice).
///
/// # Arguments
/// * `our_identity_secret` - 5,908-byte our identity secret key
/// * `their_signed_bundle` - 7,827-byte signed pre-key bundle from responder
/// * `current_time` - Current Unix timestamp for bundle validation
/// * `li_capable` - whether this session is Lawful-Interception-capable
///   (SessionFlags bit 0, bound into the transcript); MUST match the value the
///   responder passes to `x3dh_responder_establish`
///
/// # Returns
/// Object with:
/// - `root_key` - 32-byte session root key
/// - `send_chain_key` - 32-byte sending chain key
/// - `recv_chain_key` - 32-byte receiving chain key
/// - `initial_message` - 1,095-byte message to send to responder
#[wasm_bindgen]
pub fn x3dh_initiator_establish(
    our_identity_secret: &[u8],
    their_signed_bundle: &[u8],
    current_time: u64,
    li_capable: bool,
) -> Result<JsValue, JsValue> {
    // Parse our identity keypair
    let our_identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(our_identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse the signed bundle
    let signed_bundle = parse_signed_bundle(their_signed_bundle)?;

    // Establish session
    let result = trelis_x3dh_pq::Initiator::establish(
        &our_identity,
        &signed_bundle,
        current_time,
        trelis_x3dh_pq::SessionFlags { li_capable },
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let session_keys = result.session_keys();
    let initial_message = result.initial_message();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"root_key".into(),
        &js_sys::Uint8Array::from(session_keys.root_key().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"send_chain_key".into(),
        &js_sys::Uint8Array::from(session_keys.send_chain_key().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"recv_chain_key".into(),
        &js_sys::Uint8Array::from(session_keys.recv_chain_key().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"initial_message".into(),
        &js_sys::Uint8Array::from(initial_message.to_bytes().as_slice()),
    )?;

    Ok(obj.into())
}

/// Establish an X3DH-PQ session as the responder (Bob).
///
/// # Arguments
/// * `our_identity_secret` - 5,908-byte our identity secret key
/// * `our_otk_secret` - 1,819-byte our one-time key secret (matching bundle)
/// * `their_identity_signing` - 2,009-byte initiator's identity signing public key
/// * `their_identity_kem_x448` - 56-byte initiator's X448 KEM public key
/// * `our_signed_bundle` - 7,827-byte the bundle we published
/// * `initial_message` - 1,095-byte initial message from initiator
/// * `li_capable` - whether this session is Lawful-Interception-capable
///   (SessionFlags bit 0, bound into the transcript); MUST match the value the
///   initiator passed to `x3dh_initiator_establish`, else the derived keys diverge
///
/// # Returns
/// Object with:
/// - `root_key` - 32-byte session root key
/// - `send_chain_key` - 32-byte sending chain key (responder's send = initiator's recv)
/// - `recv_chain_key` - 32-byte receiving chain key
#[wasm_bindgen]
pub fn x3dh_responder_establish(
    our_identity_secret: &[u8],
    our_otk_secret: &[u8],
    their_identity_signing: &[u8],
    their_identity_kem_x448: &[u8],
    our_signed_bundle: &[u8],
    initial_message: &[u8],
    li_capable: bool,
) -> Result<JsValue, JsValue> {
    // Parse our identity keypair
    let our_identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(our_identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse our OTK keypair
    let our_otk = trelis_hybrid::HybridKemKeypair::from_bytes(our_otk_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse their identity signing public key
    let their_id_signing =
        trelis_hybrid::HybridSigningPublicKey::from_bytes(their_identity_signing)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse their X448 public key
    if their_identity_kem_x448.len() != 56 {
        return Err(JsValue::from_str("X448 public key must be 56 bytes"));
    }
    let their_x448 = trelis_primitives::X448Public::from_bytes(their_identity_kem_x448)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse our signed bundle
    let our_bundle = parse_signed_bundle(our_signed_bundle)?;

    // Parse initial message
    let init_msg = trelis_x3dh_pq::InitialMessage::from_bytes(initial_message)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Establish session
    let session_keys = trelis_x3dh_pq::Responder::establish(
        &our_identity,
        &our_otk,
        &their_id_signing,
        &their_x448,
        &our_bundle,
        &init_msg,
        trelis_x3dh_pq::SessionFlags { li_capable },
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"root_key".into(),
        &js_sys::Uint8Array::from(session_keys.root_key().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"send_chain_key".into(),
        &js_sys::Uint8Array::from(session_keys.send_chain_key().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"recv_chain_key".into(),
        &js_sys::Uint8Array::from(session_keys.recv_chain_key().as_slice()),
    )?;

    Ok(obj.into())
}

/// Internal helper to parse a signed bundle from bytes.
fn parse_signed_bundle(bytes: &[u8]) -> Result<trelis_x3dh_pq::SignedPreKeyBundle, JsValue> {
    const BUNDLE_SIZE: usize = 4461;
    const SIG_SIZE: usize = 3366;

    if bytes.len() != BUNDLE_SIZE + SIG_SIZE {
        return Err(JsValue::from_str("Invalid signed bundle size"));
    }

    let bundle_bytes = &bytes[..BUNDLE_SIZE];
    let sig_bytes = &bytes[BUNDLE_SIZE..];

    // Parse identity signing key (first 2,009 bytes)
    let id_sign = trelis_hybrid::HybridSigningPublicKey::from_bytes(&bundle_bytes[..2009])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse identity KEM key (next 1,214 bytes)
    let id_kem = trelis_hybrid::HybridKemPublicKey::from_bytes(&bundle_bytes[2009..2009 + 1214])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse OTK (next 1,214 bytes)
    let otk = trelis_hybrid::HybridKemPublicKey::from_bytes(
        &bundle_bytes[2009 + 1214..2009 + 1214 + 1214],
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse metadata
    let otk_key_id = u64::from_le_bytes(bundle_bytes[4437..4445].try_into().unwrap());
    let timestamp = u64::from_le_bytes(bundle_bytes[4445..4453].try_into().unwrap());
    let expiration = u64::from_le_bytes(bundle_bytes[4453..4461].try_into().unwrap());

    // Parse signature
    let signature = trelis_hybrid::HybridSignature::from_bytes(sig_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let bundle =
        trelis_x3dh_pq::PreKeyBundle::new(id_sign, id_kem, otk, otk_key_id, timestamp, expiration);

    Ok(trelis_x3dh_pq::SignedPreKeyBundle { bundle, signature })
}

// ============================================================================
// KEM Ratchet (Per-Message Forward Secrecy)
// ============================================================================

/// Initialise a KEM ratchet as the session initiator (Alice).
///
/// Call this after X3DH-PQ completes with the derived session key.
///
/// # Arguments
/// * `session_key` - 32-byte shared secret from X3DH-PQ
/// * `their_public_key` - 1,214-byte recipient's KEM public key
/// * `current_time` - Current Unix timestamp
///
/// # Returns
/// Object with `state` (serialised ratchet state) and `our_public_key`
#[wasm_bindgen]
pub fn ratchet_init_initiator(
    session_key: &[u8],
    their_public_key: &[u8],
    current_time: u64,
) -> Result<JsValue, JsValue> {
    if session_key.len() != 32 {
        return Err(JsValue::from_str("Session key must be 32 bytes"));
    }

    let session_key_arr: [u8; 32] = session_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid session key"))?;

    let their_pk = trelis_hybrid::HybridKemPublicKey::from_bytes(their_public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let state =
        trelis_ratchet::KemRatchet::init_initiator(&session_key_arr, their_pk, current_time)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Serialise state for JavaScript storage
    let state_bytes = serialize_ratchet_state(&state);
    let our_pk = state.our_keypair().public_key().to_bytes();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(state_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"our_public_key".into(),
        &js_sys::Uint8Array::from(our_pk.as_slice()),
    )?;

    Ok(obj.into())
}

/// Initialise a KEM ratchet as the session responder (Bob).
///
/// Call this after receiving and processing an X3DH-PQ initial message.
///
/// # Arguments
/// * `session_key` - 32-byte shared secret from X3DH-PQ
/// * `our_kem_secret` - 1,819-byte our KEM secret key
/// * `current_time` - Current Unix timestamp
///
/// # Returns
/// Object with `state` (serialised ratchet state) and `our_public_key`
#[wasm_bindgen]
pub fn ratchet_init_responder(
    session_key: &[u8],
    our_kem_secret: &[u8],
    current_time: u64,
) -> Result<JsValue, JsValue> {
    if session_key.len() != 32 {
        return Err(JsValue::from_str("Session key must be 32 bytes"));
    }

    let session_key_arr: [u8; 32] = session_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid session key"))?;

    let our_keypair = trelis_hybrid::HybridKemKeypair::from_bytes(our_kem_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let state =
        trelis_ratchet::KemRatchet::init_responder(&session_key_arr, our_keypair, current_time);

    let state_bytes = serialize_ratchet_state(&state);
    let our_pk = state.our_keypair().public_key().to_bytes();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(state_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"our_public_key".into(),
        &js_sys::Uint8Array::from(our_pk.as_slice()),
    )?;

    Ok(obj.into())
}

/// Encrypt a message using the KEM ratchet.
///
/// # Arguments
/// * `state` - Serialised ratchet state
/// * `plaintext` - Message to encrypt
/// * `current_time` - Current Unix timestamp
///
/// # Returns
/// Object with `state` (updated), `message` (encrypted), `header` (for recipient)
#[wasm_bindgen]
pub fn ratchet_send(state: &[u8], plaintext: &[u8], current_time: u64) -> Result<JsValue, JsValue> {
    let mut ratchet =
        deserialize_ratchet_state(state).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let result = trelis_ratchet::send_message(&mut ratchet, plaintext, current_time)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_state = serialize_ratchet_state(&ratchet);
    let message = &result.message;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(new_state.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"header".into(),
        &js_sys::Uint8Array::from(message.header.to_bytes().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"nonce".into(),
        &js_sys::Uint8Array::from(message.nonce.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(message.ciphertext.as_slice()),
    )?;

    Ok(obj.into())
}

/// Decrypt a message using the KEM ratchet.
///
/// # Arguments
/// * `state` - Serialised ratchet state
/// * `header` - Message header bytes
/// * `nonce` - 24-byte nonce
/// * `ciphertext` - Encrypted message
/// * `current_time` - Current Unix timestamp
///
/// # Returns
/// Object with `state` (updated) and `plaintext`
#[wasm_bindgen]
pub fn ratchet_receive(
    state: &[u8],
    header: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    current_time: u64,
) -> Result<JsValue, JsValue> {
    let mut ratchet =
        deserialize_ratchet_state(state).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let msg_header = trelis_ratchet::MessageHeader::from_bytes(header)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let nonce_arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("Nonce must be 24 bytes"))?;

    let message = trelis_ratchet::RatchetMessage {
        header: msg_header,
        nonce: nonce_arr,
        ciphertext: ciphertext.to_vec(),
    };

    let plaintext = trelis_ratchet::receive_message(&mut ratchet, &message, current_time)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_state = serialize_ratchet_state(&ratchet);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(new_state.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"plaintext".into(),
        &js_sys::Uint8Array::from(plaintext.as_slice()),
    )?;

    Ok(obj.into())
}

// Internal helper to serialise KemRatchet state
fn serialize_ratchet_state(state: &trelis_ratchet::KemRatchet) -> Vec<u8> {
    // Format: our_keypair (1819) + root_key (32) + their_pk (1214 or 0) + counters (16) + status (1)
    let their_pk = state.their_public_key();
    let has_their_pk = their_pk.is_some();

    let size = 1819 + 32 + if has_their_pk { 1214 } else { 0 } + 16 + 1 + 8 + 1;
    let mut buf = Vec::with_capacity(size);

    buf.extend_from_slice(&state.our_keypair().to_bytes()[..]);
    buf.extend_from_slice(state.root_key());
    buf.push(u8::from(has_their_pk));
    if let Some(pk) = their_pk {
        buf.extend_from_slice(&pk.to_bytes());
    }
    buf.extend_from_slice(&state.send_count().to_le_bytes());
    buf.extend_from_slice(&state.recv_count().to_le_bytes());
    buf.push(match state.status() {
        trelis_ratchet::RatchetStatus::Uninitialised => 0,
        trelis_ratchet::RatchetStatus::Active => 1,
        trelis_ratchet::RatchetStatus::AwaitingReply => 2,
        trelis_ratchet::RatchetStatus::Stale => 3,
        trelis_ratchet::RatchetStatus::Compromised => 4,
    });
    buf.extend_from_slice(&state.last_activity().to_le_bytes());

    buf
}

// Internal helper to deserialize KemRatchet state
fn deserialize_ratchet_state(bytes: &[u8]) -> trelis_error::Result<trelis_ratchet::KemRatchet> {
    if bytes.len() < 1819 + 32 + 1 + 16 + 1 + 8 {
        return Err(trelis_error::CryptoError::MalformedMessage);
    }

    let our_keypair = trelis_hybrid::HybridKemKeypair::from_bytes(&bytes[..1819])?;
    let mut root_key = [0u8; 32];
    root_key.copy_from_slice(&bytes[1819..1851]);

    let has_their_pk = bytes[1851] == 1;
    let mut offset = 1852;

    // The entry guard above only covers the minimum (no their_public_key) layout.
    // Now that has_their_pk is known, validate the full required length before any
    // further offset-based indexing — this prevents a trap on a crafted short input.
    let required = offset
        + if has_their_pk { 1214 } else { 0 }
        + 8  // send_count
        + 8  // recv_count
        + 1  // status
        + 8; // last_activity
    if bytes.len() < required {
        return Err(trelis_error::CryptoError::MalformedMessage);
    }

    let their_pk = if has_their_pk {
        let pk = trelis_hybrid::HybridKemPublicKey::from_bytes(&bytes[offset..offset + 1214])?;
        offset += 1214;
        Some(pk)
    } else {
        None
    };

    let send_count = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let recv_count = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let status_byte = bytes[offset];
    offset += 1;
    let last_activity = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());

    // Reconstruct state - use init_responder as base then set fields
    let mut state =
        trelis_ratchet::KemRatchet::init_responder(&root_key, our_keypair, last_activity);

    if let Some(pk) = their_pk {
        state.set_their_public_key(pk);
    }

    // Restore send_count directly (bounded, O(1)) — replaces the
    // `0..send_count` replay that hung the WASM thread on a near-u64::MAX
    // state blob (RCH-02). set_send_count rejects a decoded count at/above
    // SESSION_EXHAUSTION_THRESHOLD via the existing SessionExhausted variant,
    // so a hostile blob errors here instead of looping.
    state.set_send_count(send_count)?;
    // set_recv_count(n) stores n+1, so we have to call it with recv_count-1
    // to restore the exact value. For recv_count==0 the responder default is
    // already 0; calling set_recv_count(0) would bump it to 1.
    if recv_count > 0 {
        state.set_recv_count(recv_count - 1);
    }

    state.set_status(match status_byte {
        0 => trelis_ratchet::RatchetStatus::Uninitialised,
        1 => trelis_ratchet::RatchetStatus::Active,
        2 => trelis_ratchet::RatchetStatus::AwaitingReply,
        3 => trelis_ratchet::RatchetStatus::Stale,
        _ => trelis_ratchet::RatchetStatus::Compromised,
    });

    Ok(state)
}

// ============================================================================
// CoCoA Group Encryption
// ============================================================================

/// Create a new CoCoA group.
///
/// # Arguments
/// * `creator_identity_secret` - 5,908-byte creator's identity secret key
/// * `creator_kem_secret` - 1,819-byte creator's KEM secret key
/// * `creator_user_id` - 32-byte user identifier
///
/// # Returns
/// Object with `session` (serialised), `group_id`, and `welcomes` array
#[wasm_bindgen]
pub fn cocoa_create_group(
    creator_identity_secret: &[u8],
    creator_kem_secret: &[u8],
    creator_user_id: &[u8],
) -> Result<JsValue, JsValue> {
    if creator_user_id.len() != 32 {
        return Err(JsValue::from_str("User ID must be 32 bytes"));
    }

    let identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(creator_identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let kem = trelis_hybrid::HybridKemKeypair::from_bytes(creator_kem_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(creator_user_id);

    // Create group with just the creator (no other members)
    let (session, welcomes) = trelis_cocoa::operations::create_group(&identity, kem, user_id, &[])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let session_bytes = serialize_cocoa_session(&session);
    let group_id = session.group_id();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(session_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"group_id".into(),
        &js_sys::Uint8Array::from(group_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(session.epoch_number() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"member_count".into(),
        &JsValue::from_f64(session.member_count() as f64),
    )?;

    // Welcomes array (empty for creator-only group)
    let welcomes_arr = js_sys::Array::new();
    for welcome in welcomes {
        let w = js_sys::Object::new();
        js_sys::Reflect::set(
            &w,
            &"group_id".into(),
            &js_sys::Uint8Array::from(welcome.group_id.as_slice()),
        )?;
        js_sys::Reflect::set(
            &w,
            &"epoch".into(),
            &JsValue::from_f64(welcome.epoch as f64),
        )?;
        js_sys::Reflect::set(
            &w,
            &"leaf_position".into(),
            &JsValue::from_f64(welcome.leaf_position as f64),
        )?;
        welcomes_arr.push(&w);
    }
    js_sys::Reflect::set(&obj, &"welcomes".into(), &welcomes_arr)?;

    Ok(obj.into())
}

/// Encrypt a message for the CoCoA group.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `plaintext` - Message to encrypt
///
/// # Returns
/// Object with updated `session` and `encrypted_message` (serialised EncryptedMessage)
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_encrypt(session: &[u8], plaintext: &[u8]) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let encrypted = cocoa_session
        .encrypt(plaintext)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"encrypted_message".into(),
        &js_sys::Uint8Array::from(encrypted.to_bytes().as_slice()),
    )?;

    Ok(obj.into())
}

/// Decrypt a CoCoA group message.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `encrypted_message` - Serialised EncryptedMessage
///
/// # Returns
/// Object with `plaintext`
#[wasm_bindgen]
pub fn cocoa_decrypt(session: &[u8], encrypted_message: &[u8]) -> Result<JsValue, JsValue> {
    let cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let message = trelis_cocoa::session::EncryptedMessage::from_bytes(encrypted_message)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let plaintext = cocoa_session
        .decrypt(&message)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"plaintext".into(),
        &js_sys::Uint8Array::from(plaintext.as_slice()),
    )?;

    Ok(obj.into())
}

/// Get CoCoA session information.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
///
/// # Returns
/// Object with session metadata
#[wasm_bindgen]
pub fn cocoa_session_info(session: &[u8]) -> Result<JsValue, JsValue> {
    let cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"group_id".into(),
        &js_sys::Uint8Array::from(cocoa_session.group_id().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"member_count".into(),
        &JsValue::from_f64(cocoa_session.member_count() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"our_leaf_position".into(),
        &JsValue::from_f64(cocoa_session.our_leaf_position() as f64),
    )?;

    Ok(obj.into())
}

/// Process a welcome message to join an existing CoCoA group.
///
/// # Arguments
/// * `our_user_id` - 32-byte user identifier
/// * `our_kem_secret` - 1,819-byte KEM secret key (matching bundle used)
/// * `welcome_bytes` - Serialised welcome message
/// * `committer_identity_public` - The expected group-creator/adder identity
///   public key (supplied out-of-band). GAP-01: the welcome's committer
///   signature is verified against this before joining; an unsigned/forged
///   welcome is rejected.
///
/// # Returns
/// Object with `session` (serialised CoCoA session)
#[wasm_bindgen]
pub fn cocoa_process_welcome(
    our_user_id: &[u8],
    our_kem_secret: &[u8],
    welcome_bytes: &[u8],
    committer_identity_public: &[u8],
) -> Result<JsValue, JsValue> {
    if our_user_id.len() != 32 {
        return Err(JsValue::from_str("User ID must be 32 bytes"));
    }

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(our_user_id);

    let our_kem = trelis_hybrid::HybridKemKeypair::from_bytes(our_kem_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // GAP-01: the caller supplies the expected committer identity out-of-band.
    let committer_identity =
        trelis_hybrid::HybridIdentityPublicKey::from_bytes(committer_identity_public)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let welcome = deserialize_welcome(welcome_bytes)?;

    let session =
        trelis_cocoa::operations::process_welcome(user_id, our_kem, &welcome, &committer_identity)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let session_bytes = serialize_cocoa_session(&session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(session_bytes.as_slice()),
    )?;

    Ok(obj.into())
}

/// Advance a CoCoA session to the next epoch.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `delta_root` - 32-byte delta root from commit
/// * `transcript_hash` - 32-byte new transcript hash
///
/// # Returns
/// Object with updated `session`
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_advance_epoch(
    session: &[u8],
    delta_root: &[u8],
    transcript_hash: &[u8],
) -> Result<JsValue, JsValue> {
    if delta_root.len() != 32 {
        return Err(JsValue::from_str("Delta root must be 32 bytes"));
    }
    if transcript_hash.len() != 32 {
        return Err(JsValue::from_str("Transcript hash must be 32 bytes"));
    }

    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut delta = [0u8; 32];
    delta.copy_from_slice(delta_root);

    let mut transcript = [0u8; 32];
    transcript.copy_from_slice(transcript_hash);

    cocoa_session.advance_epoch(&delta, transcript);

    let new_session = serialize_cocoa_session(&cocoa_session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

/// Rotate the KEM keypair for a CoCoA session.
///
/// This should be called periodically to maintain forward secrecy.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
///
/// # Returns
/// Object with updated `session` and new `public_key`
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_rotate_keypair(session: &[u8]) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    cocoa_session
        .rotate_keypair()
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);
    let new_pk = cocoa_session.our_keypair().public_key().to_bytes();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"public_key".into(),
        &js_sys::Uint8Array::from(new_pk.as_slice()),
    )?;

    Ok(obj.into())
}

// Internal helper to serialise a Welcome message
fn serialize_welcome(welcome: &trelis_cocoa::operations::Welcome) -> Vec<u8> {
    // Format: group_id (32) + epoch (8) + leaf_position (4) + tree_depth (4) +
    // member_count (4) + encrypted_info_len (4) + encrypted_info + encapsulation_len (4) + encapsulation
    //   + signature (SIGNATURE_SIZE) — GAP-01 committer signature, single-sourced size.
    let mut buf = Vec::with_capacity(
        32 + 8
            + 4
            + 4
            + 4
            + 4
            + welcome.encrypted_info.len()
            + 4
            + welcome.encapsulation.len()
            + trelis_hybrid::signature::SIGNATURE_SIZE,
    );

    buf.extend_from_slice(&welcome.group_id);
    buf.extend_from_slice(&welcome.epoch.to_le_bytes());
    buf.extend_from_slice(&welcome.leaf_position.to_le_bytes());
    buf.extend_from_slice(&welcome.tree_depth.to_le_bytes());
    buf.extend_from_slice(&welcome.member_count.to_le_bytes());
    buf.extend_from_slice(&(welcome.encrypted_info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&welcome.encrypted_info);
    buf.extend_from_slice(&(welcome.encapsulation.len() as u32).to_le_bytes());
    buf.extend_from_slice(&welcome.encapsulation);
    // GAP-01: marshal the committer signature bytes (fixed SIGNATURE_SIZE).
    buf.extend_from_slice(&welcome.signature.to_bytes());

    buf
}

// Internal helper to deserialize a Welcome message
fn deserialize_welcome(bytes: &[u8]) -> Result<trelis_cocoa::operations::Welcome, JsValue> {
    // minimum without variable parts, grown by the fixed GAP-01 signature.
    const MIN_SIZE: usize = 32 + 8 + 4 + 4 + 4 + 4 + 4 + trelis_hybrid::signature::SIGNATURE_SIZE;

    if bytes.len() < MIN_SIZE {
        return Err(JsValue::from_str("Welcome message too short"));
    }

    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&bytes[0..32]);

    let epoch = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let leaf_position = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
    let tree_depth = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
    let member_count = u32::from_le_bytes(bytes[48..52].try_into().unwrap());

    let encrypted_info_len = u32::from_le_bytes(bytes[52..56].try_into().unwrap()) as usize;

    // Use checked arithmetic throughout — wasm32 has 32-bit usize, so a
    // maximal length field plus a small offset wraps and causes a slice
    // panic on malformed input.
    let encrypted_info_end = 56usize
        .checked_add(encrypted_info_len)
        .ok_or_else(|| JsValue::from_str("Welcome message length overflow"))?;
    let after_encrypted_info = encrypted_info_end
        .checked_add(4)
        .ok_or_else(|| JsValue::from_str("Welcome message length overflow"))?;

    if bytes.len() < after_encrypted_info {
        return Err(JsValue::from_str("Welcome message truncated"));
    }

    let encrypted_info = bytes[56..encrypted_info_end].to_vec();

    let encapsulation_len = u32::from_le_bytes(
        bytes[encrypted_info_end..after_encrypted_info]
            .try_into()
            .unwrap(),
    ) as usize;

    let encapsulation_start = after_encrypted_info;
    let encapsulation_end = encapsulation_start
        .checked_add(encapsulation_len)
        .ok_or_else(|| JsValue::from_str("Welcome message length overflow"))?;
    if bytes.len() < encapsulation_end {
        return Err(JsValue::from_str("Welcome message truncated"));
    }

    let encapsulation = bytes[encapsulation_start..encapsulation_end].to_vec();

    // GAP-01: the committer signature occupies the trailing fixed SIGNATURE_SIZE
    // bytes. Use checked arithmetic (wasm32 usize is 32-bit) like the length
    // handling above.
    let signature_end = encapsulation_end
        .checked_add(trelis_hybrid::signature::SIGNATURE_SIZE)
        .ok_or_else(|| JsValue::from_str("Welcome message length overflow"))?;
    if bytes.len() < signature_end {
        return Err(JsValue::from_str("Welcome message truncated"));
    }
    let signature = HybridSignature::from_bytes(&bytes[encapsulation_end..signature_end])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(trelis_cocoa::operations::Welcome {
        group_id,
        epoch,
        leaf_position,
        tree_depth,
        member_count,
        encrypted_info,
        encapsulation,
        signature,
    })
}

// Internal helper to serialise CocoaSession
fn serialize_cocoa_session(session: &trelis_cocoa::CocoaSession) -> Vec<u8> {
    // Format v2: group_id (32) + user_id (32) + epoch_number (8) + leaf_pos (4) +
    // member_count (4) + tree_depth (4) + transcript_hash (32) + epoch_secret (32) +
    // message_counter (8) + our_keypair (1819)
    //
    // We persist the current epoch_secret (the input to EpochSecrets::derive)
    // rather than the init_secret (one of its derived outputs). join_group on
    // the receiving side wants the epoch_secret so that the reconstructed
    // EpochSecrets::derive produces the same app_secret as the original; if
    // we wrote init_secret here, the rebuilt session would compute
    // derive_app_secret(init_secret) instead of derive_app_secret(epoch_secret)
    // and self-decrypt of any encrypted message after a round-trip would fail
    // with AeadAuthenticationFailed.
    const SIZE: usize = 32 + 32 + 8 + 4 + 4 + 4 + 32 + 32 + 8 + 1819;
    let mut buf = Vec::with_capacity(SIZE);

    buf.extend_from_slice(session.group_id());
    buf.extend_from_slice(session.our_user_id());
    buf.extend_from_slice(&session.epoch_number().to_le_bytes());
    buf.extend_from_slice(&session.our_leaf_position().to_le_bytes());
    buf.extend_from_slice(&session.member_count().to_le_bytes());
    buf.extend_from_slice(&session.tree().tree_depth().to_le_bytes());
    buf.extend_from_slice(session.transcript_hash());
    buf.extend_from_slice(session.current_epoch_secret());
    buf.extend_from_slice(&session.message_counter().to_le_bytes());
    buf.extend_from_slice(&session.our_keypair().to_bytes()[..]);

    buf
}

// Parsed fields of a v2 CoCoA session blob — the single-sourced offset parse
// shared by `deserialize_cocoa_session` (the shipped restore driver) and the
// checked restore path, so the two cannot drift. Holds only the decoded fields;
// the restore POLICY (unchecked vs watermark-checked) is the caller's choice.
struct ParsedCocoaSessionV2 {
    group_id: [u8; 32],
    user_id: [u8; 32],
    epoch_number: u64,
    leaf_position: u32,
    member_count: u32,
    tree_depth: u32,
    transcript_hash: [u8; 32],
    epoch_secret: [u8; 32],
    message_counter: u64,
    our_keypair: trelis_hybrid::HybridKemKeypair,
}

// Single-sources the v2 blob parse. This is the EXACT offset logic that was
// inline in `deserialize_cocoa_session`: it supports both the old (1935-byte)
// format (epoch_secret derived from the transcript hash via the legacy context,
// counter 0) and the new (1975-byte) v2 format (raw epoch_secret +
// message_counter at offsets 116..148 / 148..156). The blob format, offsets, and
// `NEW_SIZE` (= 1975) are UNCHANGED — this is a signature-preserving extraction
// so the additive checked path cannot drift from the shipped driver.
fn parse_cocoa_session_v2(bytes: &[u8]) -> trelis_error::Result<ParsedCocoaSessionV2> {
    // Support both old format (1935 bytes) and new format (1975 bytes)
    const OLD_SIZE: usize = 32 + 32 + 8 + 4 + 4 + 4 + 32 + 1819; // 1935
    const NEW_SIZE: usize = 32 + 32 + 8 + 4 + 4 + 4 + 32 + 32 + 8 + 1819; // 1975

    if bytes.len() < OLD_SIZE {
        return Err(trelis_error::CryptoError::MalformedMessage);
    }

    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&bytes[0..32]);

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(&bytes[32..64]);

    let epoch_number = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
    let leaf_position = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
    let member_count = u32::from_le_bytes(bytes[76..80].try_into().unwrap());
    let tree_depth = u32::from_le_bytes(bytes[80..84].try_into().unwrap());

    let mut transcript_hash = [0u8; 32];
    transcript_hash.copy_from_slice(&bytes[84..116]);

    // Check if this is new format with epoch_secret and message_counter
    let (epoch_secret, message_counter, keypair_offset) = if bytes.len() >= NEW_SIZE {
        // New format: has the raw epoch_secret and message_counter
        let mut epoch_secret = [0u8; 32];
        epoch_secret.copy_from_slice(&bytes[116..148]);
        let message_counter = u64::from_le_bytes(bytes[148..156].try_into().unwrap());
        (epoch_secret, message_counter, 156)
    } else {
        // Old format: derive from transcript_hash (backwards compatible but less accurate)
        let epoch_secret =
            *trelis_primitives::derive_key(COCOA_WASM_LEGACY_SESSION_CONTEXT, &transcript_hash);
        (epoch_secret, 0u64, 116)
    };

    let our_keypair =
        trelis_hybrid::HybridKemKeypair::from_bytes(&bytes[keypair_offset..keypair_offset + 1819])?;

    Ok(ParsedCocoaSessionV2 {
        group_id,
        user_id,
        epoch_number,
        leaf_position,
        member_count,
        tree_depth,
        transcript_hash,
        epoch_secret,
        message_counter,
        our_keypair,
    })
}

// Internal helper to deserialize CocoaSession
fn deserialize_cocoa_session(bytes: &[u8]) -> trelis_error::Result<trelis_cocoa::CocoaSession> {
    let p = parse_cocoa_session_v2(bytes)?;

    // WR-06: reconstruct the session DIRECTLY at its stored epoch number from
    // the stored epoch secret. `serialize_cocoa_session` persists the CURRENT
    // epoch secret, so the only correct reconstruction is
    // EpochSecrets::derive(stored_epoch_secret) carried at `epoch_number`.
    //
    // The previous `join_group` (epoch 0) + `advance_epoch` * epoch_number loop
    // re-derived a FRESH secret at each step (h5_epoch_secret), moving AWAY from
    // the stored value — so at any epoch > 0 the restored app_secret differed
    // from the live group's and cocoa_encrypt/cocoa_decrypt after a round trip
    // produced keys no peer could match (AeadAuthenticationFailed). This is a
    // pure reconstruction fix: the serialised blob format is unchanged, and an
    // existing blob now restores correctly at epoch > 0.
    let mut session = trelis_cocoa::CocoaSession::restore_session(
        p.group_id,
        p.user_id,
        p.our_keypair,
        p.leaf_position,
        p.tree_depth,
        p.member_count,
        &p.epoch_secret,
        p.transcript_hash,
        p.epoch_number,
    );

    // Restore the message counter through the monotonic-forward guard. The
    // reconstructed epoch is fresh (counter 0), so a forward-set 0 -> N always
    // succeeds; the guard rejects only an attempt to roll an already-advanced
    // counter backwards (GAP-05 / F09).
    session.set_message_counter(p.message_counter)?;

    Ok(session)
}

// Native (host-testable) checked restore driver for a CoCoA session blob
// (RBK-01 / GAP-05). Parses the v2 blob via the single-sourced
// `parse_cocoa_session_v2`, enforces the caller's EXPECTED `(group_id, user_id)`
// identity against the blob, builds the caller's persisted `SessionWatermark`
// from its 16 bytes, and routes the restore through
// `CocoaSession::restore_session_checked` (the 58-01 safe door). A rollback —
// a blob whose `(epoch, counter)` is strictly below the watermark — surfaces
// `CryptoError::MessageCounterTooOld` via `?` BEFORE any session is
// reconstructed; an identity mismatch surfaces `CryptoError::MalformedMessage`
// even earlier (BEFORE the watermark check), so a caller that mis-keys its
// watermark store cannot silently disable the guard by pairing one identity's
// watermark with another identity's blob (WR-02). Returns the reconstructed
// session and the ADVANCED watermark (the lexicographic max of the persisted
// watermark and the blob's `(epoch, counter)`) for the caller to persist.
//
// This is the driver the cross-deserialise rollback regression tests exercise
// directly (mirroring how `test_cocoa_session_counter_restore_and_guard` drives
// `deserialize_cocoa_session`); `cocoa_deserialize_checked` is the thin
// `wasm_bindgen` wrapper over it.
fn deserialize_cocoa_session_checked(
    session: &[u8],
    watermark: &[u8],
    expected_group_id: &[u8],
    expected_user_id: &[u8],
) -> trelis_error::Result<(trelis_cocoa::CocoaSession, trelis_cocoa::SessionWatermark)> {
    let p = parse_cocoa_session_v2(session)?;

    // WR-02: enforce the caller's EXPECTED identity BEFORE the watermark check or
    // any reconstruction. The 16-byte watermark carries no identity, so a caller
    // that mis-keys its watermark store — applying identity A's watermark to
    // identity B's blob — would otherwise silently disable B's rollback guard.
    // Reject the mismatch here (Security-category `MalformedMessage`) so the guard
    // cannot be bypassed by a wrong `(group_id, user_id)` pairing.
    if p.group_id.as_slice() != expected_group_id || p.user_id.as_slice() != expected_user_id {
        return Err(trelis_error::CryptoError::MalformedMessage);
    }

    let wm = trelis_cocoa::SessionWatermark::from_bytes(watermark)?;
    let restored = trelis_cocoa::CocoaSession::restore_session_checked(
        &wm,
        p.group_id,
        p.user_id,
        p.our_keypair,
        p.leaf_position,
        p.tree_depth,
        p.member_count,
        &p.epoch_secret,
        p.transcript_hash,
        p.epoch_number,
        p.message_counter,
    )?;
    let advanced = wm.advanced(p.epoch_number, p.message_counter);
    Ok((restored, advanced))
}

/// Safe, durable-storage restore entry for a CoCoA session (RBK-01 / GAP-05) —
/// the application-facing half of the cross-invocation counter-rollback guard.
///
/// Deserialises `session` (the 1975-byte v2 blob) and routes the restore through
/// the 58-01 safe door against the caller's persisted 16-byte `watermark`
/// (`epoch_u64 || counter_u64`, little-endian — the value a prior
/// [`cocoa_session_watermark`] or `cocoa_deserialize_checked` returned). If the
/// blob's `(epoch, counter)` is strictly below the watermark — a stale blob
/// restored after a newer one already emitted — this REJECTS with an error
/// instead of returning a session, so no already-used `(key, nonce)` can be
/// re-derived across the restore boundary. An equal or higher `(epoch, counter)`
/// is accepted (the honest reload / forward restore).
///
/// # Identity binding (WR-02)
///
/// `expected_group_id` and `expected_user_id` are the 32-byte identity the caller
/// looked the `watermark` up under. Because the 16-byte watermark carries no
/// identity, this entry ENFORCES that the blob's own `(group_id, user_id)` equals
/// the expected pair BEFORE the watermark check — a mismatch is REJECTED, not
/// merely reported. This closes the silent-bypass where a caller that mis-keys
/// its per-identity watermark store (applies identity A's watermark to identity
/// B's blob) would otherwise disable B's rollback guard.
///
/// # Returns
///
/// An object with:
/// * `session` — the re-serialised v2 session blob (byte-identical format),
/// * `watermark` — the 16-byte ADVANCED watermark the caller MUST persist,
/// * `group_id` / `user_id` — the blob's own identity (now guaranteed to equal
///   the `expected_*` inputs, since a mismatch would have been rejected above).
///
/// # Caller duty
///
/// Persist the returned `watermark` keyed by `(group_id, user_id)`, route every
/// durable-storage load through this entry, and advance the persisted watermark
/// on every emit (read it from the post-op blob via [`cocoa_session_watermark`]).
/// The watermark is app-held SIDE-STATE: it is never stored in the session blob
/// (an in-blob watermark would roll back with the blob) and never threaded
/// through the per-op `cocoa_*` functions.
///
/// # Errors
///
/// Returns a `JsValue` error string if the blob or watermark is malformed, if the
/// blob's identity does not match `expected_group_id`/`expected_user_id`
/// (`MalformedMessage`), or if the restore is a rollback (`MessageCounterTooOld`).
#[wasm_bindgen]
pub fn cocoa_deserialize_checked(
    session: &[u8],
    watermark: &[u8],
    expected_group_id: &[u8],
    expected_user_id: &[u8],
) -> Result<JsValue, JsValue> {
    let (restored, advanced) =
        deserialize_cocoa_session_checked(session, watermark, expected_group_id, expected_user_id)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let reserialized = serialize_cocoa_session(&restored);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(reserialized.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"watermark".into(),
        &js_sys::Uint8Array::from(advanced.to_bytes().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"group_id".into(),
        &js_sys::Uint8Array::from(restored.group_id().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"user_id".into(),
        &js_sys::Uint8Array::from(restored.our_user_id().as_slice()),
    )?;

    Ok(obj.into())
}

/// Returns the 16-byte `(epoch || counter)` high-water watermark to persist for
/// this blob's identity (RBK-01 / GAP-05).
///
/// A post-op blob (e.g. the `session` a [`cocoa_encrypt`] call returns) already
/// carries the ADVANCED `(epoch, counter)`, so calling this on that blob yields
/// the advance-to watermark the caller MUST persist BEFORE releasing the
/// ciphertext — closing the crash-replay re-emit (an app that advances the
/// watermark only on restore, never on emit, re-opens it). `cocoa_encrypt` does
/// not return the counter today, so this helper is how the app reads it.
///
/// The returned bytes carry NO secret material — only the public `(epoch,
/// counter)` metadata already present, in the clear, in the blob. Note the
/// blob's field order (epoch at offset 64, counter at offset 148) differs from
/// the watermark byte order (`epoch || counter`); this helper reconciles them.
///
/// # Errors
///
/// Returns a `JsValue` error string if the blob is malformed.
#[wasm_bindgen]
pub fn cocoa_session_watermark(session: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = parse_cocoa_session_v2(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(
        trelis_cocoa::SessionWatermark::new(p.epoch_number, p.message_counter)
            .to_bytes()
            .to_vec(),
    )
}

// ============================================================================
// Multi-Device Support
// ============================================================================

/// Calculate the fingerprint of a device's signing public key.
///
/// # Arguments
/// * `public_key` - 2,009-byte hybrid signing public key
///
/// # Returns
/// 32-byte BLAKE3 fingerprint
#[wasm_bindgen]
pub fn device_fingerprint(public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pk = trelis_hybrid::HybridSigningPublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let fingerprint = trelis_multidevice::device_fingerprint(&pk);
    Ok(fingerprint.to_vec())
}

/// Create a device approval certificate (v0.7 layout — identity-rooted).
///
/// # Arguments
/// * `approving_device_id` - 16-byte device ID of the approving device
/// * `user_id` - 32-byte user-account identifier
/// * `new_device_fingerprint` - 32-byte fingerprint of the new device's public key
/// * `server_nonce` - 32-byte server-issued single-use nonce
/// * `account_identity_pk` - 2,009-byte account identity signing public key that
///   roots the device graph (bound as data; the SIGNER is still the approving
///   device keypair)
/// * `approved_at` - Unix timestamp (seconds)
/// * `signing_secret` - signing keypair secret bytes
///
/// # Returns
/// Serialised approval certificate (7,504 bytes). The embedded
/// `approving_device_pk` keeps the signature self-verifying; the bound
/// `account_identity_pk` roots the device graph in the account identity key, so
/// the cert is no longer fully self-contained for trust (TRN-01).
#[wasm_bindgen]
pub fn device_approval_create(
    approving_device_id: &[u8],
    user_id: &[u8],
    new_device_fingerprint: &[u8],
    server_nonce: &[u8],
    account_identity_pk: &[u8],
    approved_at: u64,
    signing_secret: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if approving_device_id.len() != 16 {
        return Err(JsValue::from_str("Device ID must be 16 bytes"));
    }
    if user_id.len() != 32 {
        return Err(JsValue::from_str("User ID must be 32 bytes"));
    }
    if new_device_fingerprint.len() != 32 {
        return Err(JsValue::from_str("Fingerprint must be 32 bytes"));
    }
    if server_nonce.len() != 32 {
        return Err(JsValue::from_str("Server nonce must be 32 bytes"));
    }
    if account_identity_pk.len() != 2009 {
        return Err(JsValue::from_str(
            "Account identity public key must be 2009 bytes",
        ));
    }

    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(approving_device_id);

    let mut uid = [0u8; 32];
    uid.copy_from_slice(user_id);

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(new_device_fingerprint);

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(server_nonce);

    let account_identity = trelis_hybrid::HybridSigningPublicKey::from_bytes(account_identity_pk)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let keypair = trelis_hybrid::HybridSigningKeypair::from_bytes(signing_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let cert = trelis_multidevice::DeviceApprovalCertificate::new(
        device_id,
        uid,
        fingerprint,
        nonce,
        &account_identity,
        approved_at,
        &keypair,
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(cert.to_bytes())
}

/// Verify a device approval certificate (v0.7 layout — identity-rooted).
///
/// # Arguments
/// * `certificate_bytes` - Serialised approval certificate
/// * `expected_account_identity_pk` - 2,009-byte account identity signing public
///   key the relying party independently trusts (the anchor the device graph is
///   rooted in)
/// * `now` - Verifier's current Unix timestamp (seconds)
/// * `window_seconds` - Validity window in seconds (e.g. 300 for the default
///   5-minute window). The signature verifies if `|now - approved_at|
///   <= window_seconds`.
///
/// The approving device's public key is embedded inside the certificate, so
/// the signature is self-verifying; identity ROOTING additionally requires the
/// trusted `expected_account_identity_pk` anchor — a mismatch surfaces as
/// `IdentityKeyMismatch`.
///
/// # Returns
/// Object with verification result and certificate fields
#[wasm_bindgen]
pub fn device_approval_verify(
    certificate_bytes: &[u8],
    expected_account_identity_pk: &[u8],
    now: u64,
    window_seconds: u64,
) -> Result<JsValue, JsValue> {
    let cert = trelis_multidevice::DeviceApprovalCertificate::from_bytes(certificate_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let expected_account_identity =
        trelis_hybrid::HybridSigningPublicKey::from_bytes(expected_account_identity_pk)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let window = trelis_multidevice::NonceWindow::seconds(window_seconds);
    let verify_result = cert.verify(&expected_account_identity, now, window);
    let valid = verify_result.is_ok();
    let error_str = match verify_result {
        Ok(()) => None,
        Err(e) => Some(format!("{:?}", e)),
    };

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"valid".into(), &JsValue::from_bool(valid))?;
    if let Some(err) = error_str {
        js_sys::Reflect::set(&obj, &"error".into(), &JsValue::from_str(&err))?;
    }
    js_sys::Reflect::set(
        &obj,
        &"approving_device_id".into(),
        &js_sys::Uint8Array::from(cert.approving_device_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"user_id".into(),
        &js_sys::Uint8Array::from(cert.user_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"new_device_fingerprint".into(),
        &js_sys::Uint8Array::from(cert.new_device_fingerprint.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"server_nonce".into(),
        &js_sys::Uint8Array::from(cert.server_nonce.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"approving_device_pk".into(),
        &js_sys::Uint8Array::from(cert.approving_device_pk.to_bytes().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"account_identity_pk".into(),
        &js_sys::Uint8Array::from(cert.account_identity_pk.to_bytes().as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"approved_at".into(),
        &JsValue::from_f64(cert.approved_at as f64),
    )?;

    Ok(obj.into())
}

/// Create a device revocation certificate.
///
/// # Arguments
/// * `device_id` - 16-byte device ID to revoke
/// * `reason` - Revocation reason (0=UserInitiated, 1=DeviceLost, 2=DeviceCompromised, 3=DeviceReplaced)
/// * `revoked_at` - Unix timestamp
/// * `signing_secret` - 4,089-byte signing secret key (user's identity key)
///
/// # Returns
/// Serialised revocation certificate
#[wasm_bindgen]
pub fn device_revocation_create(
    device_id: &[u8],
    reason: u8,
    revoked_at: u64,
    signing_secret: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if device_id.len() != 16 {
        return Err(JsValue::from_str("Device ID must be 16 bytes"));
    }

    let mut dev_id = [0u8; 16];
    dev_id.copy_from_slice(device_id);

    let reason = trelis_multidevice::RevocationReason::from_byte(reason)
        .ok_or_else(|| JsValue::from_str("Invalid revocation reason"))?;

    let keypair = trelis_hybrid::HybridSigningKeypair::from_bytes(signing_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let revocation =
        trelis_multidevice::DeviceRevocation::new(dev_id, reason, revoked_at, &keypair)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(revocation.to_bytes())
}

/// Verify a device revocation certificate.
///
/// # Arguments
/// * `revocation_bytes` - Serialised revocation certificate
/// * `user_public` - 2,009-byte user's identity signing public key
///
/// # Returns
/// Object with verification result and revocation fields
#[wasm_bindgen]
pub fn device_revocation_verify(
    revocation_bytes: &[u8],
    user_public: &[u8],
) -> Result<JsValue, JsValue> {
    let revocation = trelis_multidevice::DeviceRevocation::from_bytes(revocation_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let user_pk = trelis_hybrid::HybridSigningPublicKey::from_bytes(user_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let valid = revocation.verify(&user_pk).is_ok();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"valid".into(), &JsValue::from_bool(valid))?;
    js_sys::Reflect::set(
        &obj,
        &"device_id".into(),
        &js_sys::Uint8Array::from(revocation.device_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"reason".into(),
        &JsValue::from_f64(revocation.reason.to_byte() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"revoked_at".into(),
        &JsValue::from_f64(revocation.revoked_at as f64),
    )?;

    Ok(obj.into())
}

/// Wrap a 32-byte secret for a specific recipient device.
///
/// # Arguments
/// * `secret` - 32-byte secret to wrap
/// * `recipient_kem_public` - 1,214-byte recipient's KEM public key
/// * `recipient_key_id` - 8-byte recipient key ID
/// * `purpose` - Wrap purpose (1=BundleKey, 2=SessionSeed, 3=HistoryKey)
/// * `thread_id` - 32-byte thread ID
/// * `bundle_id` - 32-byte bundle ID
/// * `epoch` - CoCoA epoch number
///
/// # Returns
/// Serialised DeviceKeyWrap (1,207 bytes)
#[wasm_bindgen]
pub fn device_key_wrap_create(
    secret: &[u8],
    recipient_kem_public: &[u8],
    recipient_key_id: &[u8],
    purpose: u8,
    thread_id: &[u8],
    bundle_id: &[u8],
    epoch: u64,
) -> Result<Vec<u8>, JsValue> {
    if secret.len() != 32 {
        return Err(JsValue::from_str("Secret must be 32 bytes"));
    }
    if recipient_key_id.len() != 8 {
        return Err(JsValue::from_str("Recipient key ID must be 8 bytes"));
    }
    if thread_id.len() != 32 {
        return Err(JsValue::from_str("Thread ID must be 32 bytes"));
    }
    if bundle_id.len() != 32 {
        return Err(JsValue::from_str("Bundle ID must be 32 bytes"));
    }

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(secret);

    let recipient_pk = trelis_hybrid::HybridKemPublicKey::from_bytes(recipient_kem_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(recipient_key_id);

    let purpose = trelis_multidevice::WrapPurpose::from_byte(purpose)
        .ok_or_else(|| JsValue::from_str("Invalid wrap purpose"))?;

    let mut tid = [0u8; 32];
    tid.copy_from_slice(thread_id);

    let mut bid = [0u8; 32];
    bid.copy_from_slice(bundle_id);

    let context = trelis_multidevice::WrapContext::new(key_id, purpose, tid, bid, epoch);

    let wrap = trelis_multidevice::DeviceKeyWrap::wrap(&secret_arr, &recipient_pk, &context)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(wrap.to_bytes())
}

/// Unwrap a DeviceKeyWrap to recover the secret.
///
/// # Arguments
/// * `wrap_bytes` - Serialised DeviceKeyWrap (1,207 bytes)
/// * `recipient_kem_secret` - 1,819-byte recipient's KEM secret key
/// * `recipient_key_id` - 8-byte recipient key ID
/// * `purpose` - Expected wrap purpose
/// * `thread_id` - 32-byte thread ID
/// * `bundle_id` - 32-byte bundle ID
/// * `epoch` - Expected CoCoA epoch
///
/// # Returns
/// 32-byte unwrapped secret
#[wasm_bindgen]
pub fn device_key_wrap_unwrap(
    wrap_bytes: &[u8],
    recipient_kem_secret: &[u8],
    recipient_key_id: &[u8],
    purpose: u8,
    thread_id: &[u8],
    bundle_id: &[u8],
    epoch: u64,
) -> Result<Vec<u8>, JsValue> {
    if recipient_key_id.len() != 8 {
        return Err(JsValue::from_str("Recipient key ID must be 8 bytes"));
    }
    if thread_id.len() != 32 {
        return Err(JsValue::from_str("Thread ID must be 32 bytes"));
    }
    if bundle_id.len() != 32 {
        return Err(JsValue::from_str("Bundle ID must be 32 bytes"));
    }

    let wrap = trelis_multidevice::DeviceKeyWrap::from_bytes(wrap_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let recipient_keypair = trelis_hybrid::HybridKemKeypair::from_bytes(recipient_kem_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(recipient_key_id);

    let purpose = trelis_multidevice::WrapPurpose::from_byte(purpose)
        .ok_or_else(|| JsValue::from_str("Invalid wrap purpose"))?;

    let mut tid = [0u8; 32];
    tid.copy_from_slice(thread_id);

    let mut bid = [0u8; 32];
    bid.copy_from_slice(bundle_id);

    let context = trelis_multidevice::WrapContext::new(key_id, purpose, tid, bid, epoch);

    let secret = wrap
        .unwrap(&recipient_keypair, &context)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(secret.to_vec())
}

/// Create thread settings for history synchronisation.
///
/// # Arguments
/// * `thread_id` - 32-byte thread identifier
/// * `ephemeral` - If true, disable history sync (pure forward secrecy)
/// * `timestamp` - Unix timestamp (only used if ephemeral is true)
///
/// # Returns
/// Object with settings fields
#[wasm_bindgen]
pub fn thread_settings_create(
    thread_id: &[u8],
    ephemeral: bool,
    timestamp: u64,
) -> Result<JsValue, JsValue> {
    if thread_id.len() != 32 {
        return Err(JsValue::from_str("Thread ID must be 32 bytes"));
    }

    let mut tid = [0u8; 32];
    tid.copy_from_slice(thread_id);

    let settings = if ephemeral {
        trelis_multidevice::ThreadSettings::new_ephemeral(tid, timestamp)
    } else {
        trelis_multidevice::ThreadSettings::new(tid)
    };

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"thread_id".into(),
        &js_sys::Uint8Array::from(settings.thread_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"history_sync_enabled".into(),
        &JsValue::from_bool(settings.history_sync_enabled),
    )?;
    if let Some(ts) = settings.history_sync_changed_at {
        js_sys::Reflect::set(
            &obj,
            &"history_sync_changed_at".into(),
            &JsValue::from_f64(ts as f64),
        )?;
    }

    Ok(obj.into())
}

// ============================================================================
// CoCoA Group Operations (Add/Remove/Update)
// ============================================================================

/// Add a member to a CoCoA group.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `identity_secret` - 5,908-byte our identity secret key for signing
/// * `new_member_id` - 32-byte user ID of the new member
/// * `new_member_identity_public` - 3,223-byte identity public key
/// * `new_member_otk` - 1,222-byte one-time key (8-byte key_id + 1,214-byte KEM public)
///
/// # Returns
/// Object with updated `session`, `commit` (serialised AddCommit), and `welcome` (serialised Welcome)
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_add_member(
    session: &[u8],
    identity_secret: &[u8],
    new_member_id: &[u8],
    new_member_identity_public: &[u8],
    new_member_otk: &[u8],
) -> Result<JsValue, JsValue> {
    if new_member_id.len() != 32 {
        return Err(JsValue::from_str("Member ID must be 32 bytes"));
    }

    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse our identity keypair for signing
    let identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut member_id = [0u8; 32];
    member_id.copy_from_slice(new_member_id);

    // Parse the new member's identity public key
    let identity_pk =
        trelis_hybrid::HybridIdentityPublicKey::from_bytes(new_member_identity_public)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse the one-time key
    let otk = trelis_hybrid::HybridOneTimeKey::from_bytes(new_member_otk)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let bundle = trelis_hybrid::HybridPreKeyBundle::new(&identity_pk, otk);

    let (commit, welcome) =
        trelis_cocoa::operations::add_member(&mut cocoa_session, &identity, &bundle, member_id)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);
    let welcome_bytes = serialize_welcome(&welcome);
    let commit_bytes = serialize_add_commit(&commit);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"commit".into(),
        &js_sys::Uint8Array::from(commit_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"welcome".into(),
        &js_sys::Uint8Array::from(welcome_bytes.as_slice()),
    )?;

    Ok(obj.into())
}

/// Process an add commit from another group member.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `commit_bytes` - Serialised AddCommit
/// * `adder_identity_public` - 3,223-byte adder's identity public key for signature verification
///
/// # Returns
/// Object with updated `session`
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_process_add(
    session: &[u8],
    commit_bytes: &[u8],
    adder_identity_public: &[u8],
) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let commit = deserialize_add_commit(commit_bytes)?;

    // Parse the adder's identity public key for signature verification
    let adder_identity = trelis_hybrid::HybridIdentityPublicKey::from_bytes(adder_identity_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    trelis_cocoa::operations::process_add(&mut cocoa_session, &commit, &adder_identity)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

/// Create an update commit for post-compromise security.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `identity_secret` - 5,908-byte our identity secret key for signing
///
/// # Returns
/// Object with updated `session` and `commit` (serialised UpdateCommit)
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_create_update(session: &[u8], identity_secret: &[u8]) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse our identity keypair for signing
    let identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let commit = trelis_cocoa::operations::create_update(&mut cocoa_session, &identity)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);
    let commit_bytes = serialize_update_commit(&commit);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"commit".into(),
        &js_sys::Uint8Array::from(commit_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

/// Process an update commit from another group member.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `commit_bytes` - Serialised UpdateCommit
/// * `updater_identity_public` - 3,223-byte updater's identity public key for signature verification
///
/// # Returns
/// Object with updated `session`
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_process_update(
    session: &[u8],
    commit_bytes: &[u8],
    updater_identity_public: &[u8],
) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let commit = deserialize_update_commit(commit_bytes)?;

    // Parse the updater's identity public key for signature verification
    let updater_identity =
        trelis_hybrid::HybridIdentityPublicKey::from_bytes(updater_identity_public)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    trelis_cocoa::operations::process_update(&mut cocoa_session, &commit, &updater_identity)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

/// Remove a member from the CoCoA group.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `identity_secret` - 5,908-byte our identity secret key for signing
/// * `removed_member_id` - 32-byte user ID of the member to remove
/// * `removed_position` - Leaf position of the member to remove
///
/// # Returns
/// Object with updated `session` and `commit` (serialised RemoveCommit)
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_remove_member(
    session: &[u8],
    identity_secret: &[u8],
    removed_member_id: &[u8],
    removed_position: u32,
) -> Result<JsValue, JsValue> {
    if removed_member_id.len() != 32 {
        return Err(JsValue::from_str("Member ID must be 32 bytes"));
    }

    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    // Parse our identity keypair for signing
    let identity = trelis_hybrid::HybridIdentityKeypair::from_bytes(identity_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut member_id = [0u8; 32];
    member_id.copy_from_slice(removed_member_id);

    let commit = trelis_cocoa::operations::remove_member(
        &mut cocoa_session,
        &identity,
        member_id,
        removed_position,
    )
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);
    let commit_bytes = serialize_remove_commit(&commit);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"commit".into(),
        &js_sys::Uint8Array::from(commit_bytes.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

/// Process a remove commit from another group member.
///
/// # Arguments
/// * `session` - Serialised CoCoA session state
/// * `commit_bytes` - Serialised RemoveCommit
/// * `remover_identity_public` - 3,223-byte remover's identity public key for signature verification
///
/// # Returns
/// Object with updated `session`
///
/// # Rollback safety (RBK-01 / GAP-05)
///
/// This ergonomic path deserialises `session` through the UNCHECKED door and
/// performs NO cross-invocation rollback check. An app that restores a
/// durable/persisted blob MUST first validate it through
/// [`cocoa_deserialize_checked`] against the persisted `SessionWatermark`, and
/// MUST advance+persist the watermark on every emit (read it from the post-op
/// blob via [`cocoa_session_watermark`]) — otherwise a stale-blob restore can
/// re-emit an already-used `(key, nonce)` pair.
#[wasm_bindgen]
pub fn cocoa_process_remove(
    session: &[u8],
    commit_bytes: &[u8],
    remover_identity_public: &[u8],
) -> Result<JsValue, JsValue> {
    let mut cocoa_session =
        deserialize_cocoa_session(session).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let commit = deserialize_remove_commit(commit_bytes)?;

    // Parse the remover's identity public key for signature verification
    let remover_identity =
        trelis_hybrid::HybridIdentityPublicKey::from_bytes(remover_identity_public)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    trelis_cocoa::operations::process_remove(&mut cocoa_session, &commit, &remover_identity)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let new_session = serialize_cocoa_session(&cocoa_session);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"session".into(),
        &js_sys::Uint8Array::from(new_session.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"epoch".into(),
        &JsValue::from_f64(cocoa_session.epoch_number() as f64),
    )?;

    Ok(obj.into())
}

// Serialisation helpers for CoCoA commits
fn serialize_add_commit(commit: &trelis_cocoa::operations::AddCommit) -> Vec<u8> {
    let sig_bytes = commit.signature.to_bytes();
    let mut buf = Vec::with_capacity(32 + 32 + 4 + 8 + 32 + 32 + 4 + sig_bytes.len());

    buf.extend_from_slice(&commit.group_id);
    buf.extend_from_slice(&commit.new_member_id);
    buf.extend_from_slice(&commit.new_leaf_position.to_le_bytes());
    buf.extend_from_slice(&commit.epoch.to_le_bytes());
    buf.extend_from_slice(&commit.round_hash);
    buf.extend_from_slice(&commit.confirmation_tag);
    // GAP-03: committer's own leaf position (bound into the signed body).
    buf.extend_from_slice(&commit.committer_leaf_position.to_le_bytes());
    buf.extend_from_slice(&sig_bytes);

    buf
}

fn deserialize_add_commit(bytes: &[u8]) -> Result<trelis_cocoa::operations::AddCommit, JsValue> {
    if bytes.len() < 32 + 32 + 4 + 8 + 32 + 32 + 4 {
        return Err(JsValue::from_str("AddCommit too short"));
    }

    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&bytes[0..32]);

    let mut new_member_id = [0u8; 32];
    new_member_id.copy_from_slice(&bytes[32..64]);

    let new_leaf_position = u32::from_le_bytes(bytes[64..68].try_into().unwrap());
    let epoch = u64::from_le_bytes(bytes[68..76].try_into().unwrap());

    let mut round_hash = [0u8; 32];
    round_hash.copy_from_slice(&bytes[76..108]);

    let mut confirmation_tag = [0u8; 32];
    confirmation_tag.copy_from_slice(&bytes[108..140]);

    // GAP-03: committer's own leaf position.
    let committer_leaf_position = u32::from_le_bytes(bytes[140..144].try_into().unwrap());

    let signature = trelis_hybrid::HybridSignature::from_bytes(&bytes[144..])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(trelis_cocoa::operations::AddCommit {
        group_id,
        new_member_id,
        new_leaf_position,
        committer_leaf_position,
        epoch,
        path_updates: Vec::new(),
        signature,
        round_hash,
        confirmation_tag,
    })
}

fn serialize_update_commit(commit: &trelis_cocoa::operations::UpdateCommit) -> Vec<u8> {
    let sig_bytes = commit.signature.to_bytes();
    let mut buf = Vec::with_capacity(32 + 4 + 8 + 32 + 32 + sig_bytes.len());

    buf.extend_from_slice(&commit.group_id);
    buf.extend_from_slice(&commit.updater_leaf_position.to_le_bytes());
    buf.extend_from_slice(&commit.epoch.to_le_bytes());
    buf.extend_from_slice(&commit.round_hash);
    buf.extend_from_slice(&commit.confirmation_tag);
    buf.extend_from_slice(&sig_bytes);

    buf
}

fn deserialize_update_commit(
    bytes: &[u8],
) -> Result<trelis_cocoa::operations::UpdateCommit, JsValue> {
    if bytes.len() < 32 + 4 + 8 + 32 + 32 {
        return Err(JsValue::from_str("UpdateCommit too short"));
    }

    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&bytes[0..32]);

    let updater_leaf_position = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    let epoch = u64::from_le_bytes(bytes[36..44].try_into().unwrap());

    let mut round_hash = [0u8; 32];
    round_hash.copy_from_slice(&bytes[44..76]);

    let mut confirmation_tag = [0u8; 32];
    confirmation_tag.copy_from_slice(&bytes[76..108]);

    let signature = trelis_hybrid::HybridSignature::from_bytes(&bytes[108..])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(trelis_cocoa::operations::UpdateCommit {
        group_id,
        updater_leaf_position,
        epoch,
        path_updates: Vec::new(),
        signature,
        round_hash,
        confirmation_tag,
    })
}

fn serialize_remove_commit(commit: &trelis_cocoa::operations::RemoveCommit) -> Vec<u8> {
    let sig_bytes = commit.signature.to_bytes();
    let mut buf = Vec::with_capacity(32 + 32 + 4 + 8 + 32 + 32 + 4 + sig_bytes.len());

    buf.extend_from_slice(&commit.group_id);
    buf.extend_from_slice(&commit.removed_member_id);
    buf.extend_from_slice(&commit.removed_leaf_position.to_le_bytes());
    buf.extend_from_slice(&commit.epoch.to_le_bytes());
    buf.extend_from_slice(&commit.round_hash);
    buf.extend_from_slice(&commit.confirmation_tag);
    // GAP-03: committer's own leaf position (bound into the signed body).
    buf.extend_from_slice(&commit.committer_leaf_position.to_le_bytes());
    buf.extend_from_slice(&sig_bytes);

    buf
}

fn deserialize_remove_commit(
    bytes: &[u8],
) -> Result<trelis_cocoa::operations::RemoveCommit, JsValue> {
    if bytes.len() < 32 + 32 + 4 + 8 + 32 + 32 + 4 {
        return Err(JsValue::from_str("RemoveCommit too short"));
    }

    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&bytes[0..32]);

    let mut removed_member_id = [0u8; 32];
    removed_member_id.copy_from_slice(&bytes[32..64]);

    let removed_leaf_position = u32::from_le_bytes(bytes[64..68].try_into().unwrap());
    let epoch = u64::from_le_bytes(bytes[68..76].try_into().unwrap());

    let mut round_hash = [0u8; 32];
    round_hash.copy_from_slice(&bytes[76..108]);

    let mut confirmation_tag = [0u8; 32];
    confirmation_tag.copy_from_slice(&bytes[108..140]);

    // GAP-03: committer's own leaf position.
    let committer_leaf_position = u32::from_le_bytes(bytes[140..144].try_into().unwrap());

    let signature = trelis_hybrid::HybridSignature::from_bytes(&bytes[144..])
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(trelis_cocoa::operations::RemoveCommit {
        group_id,
        removed_member_id,
        removed_leaf_position,
        committer_leaf_position,
        epoch,
        path_updates: Vec::new(),
        signature,
        round_hash,
        confirmation_tag,
    })
}

// ============================================================================
// History Key Sharing
// ============================================================================

/// Create a retained key entry for history sync.
///
/// # Arguments
/// * `message_id` - 32-byte unique message identifier
/// * `message_key` - 32-byte symmetric key used to encrypt the message
/// * `sequence` - Sequence number within the thread
/// * `timestamp` - Unix timestamp when the message was sent/received
///
/// # Returns
/// 80-byte serialised retained key
#[wasm_bindgen]
pub fn retained_key_create(
    message_id: &[u8],
    message_key: &[u8],
    sequence: u64,
    timestamp: u64,
) -> Result<Vec<u8>, JsValue> {
    if message_id.len() != 32 {
        return Err(JsValue::from_str("Message ID must be 32 bytes"));
    }
    if message_key.len() != 32 {
        return Err(JsValue::from_str("Message key must be 32 bytes"));
    }

    let mut mid = [0u8; 32];
    mid.copy_from_slice(message_id);

    let mut mkey = [0u8; 32];
    mkey.copy_from_slice(message_key);

    let key = trelis_multidevice::RetainedKey::new(mid, mkey, sequence, timestamp);
    Ok(key.to_bytes().to_vec())
}

/// Parse a retained key from bytes.
///
/// # Arguments
/// * `bytes` - 80-byte serialised retained key
///
/// # Returns
/// Object with message_id, sequence, and timestamp (message_key is protected)
#[wasm_bindgen]
pub fn retained_key_parse(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let key = trelis_multidevice::RetainedKey::from_bytes(bytes)
        .map_err(|_| JsValue::from_str("Invalid retained key"))?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"message_id".into(),
        &js_sys::Uint8Array::from(key.message_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"sequence".into(),
        &JsValue::from_f64(key.sequence as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"timestamp".into(),
        &JsValue::from_f64(key.timestamp as f64),
    )?;

    Ok(obj.into())
}

/// Create a history key share message for a new device.
///
/// # Arguments
/// * `thread_id` - 32-byte thread identifier
/// * `retained_keys` - Array of 80-byte serialised retained keys
/// * `signing_secret` - 4,089-byte signing secret key
/// * `shared_at` - Unix timestamp
///
/// # Returns
/// Serialised HistoryKeyShareMessage
#[wasm_bindgen]
pub fn history_key_share_create(
    thread_id: &[u8],
    retained_keys: &[u8],
    signing_secret: &[u8],
    shared_at: u64,
) -> Result<Vec<u8>, JsValue> {
    if thread_id.len() != 32 {
        return Err(JsValue::from_str("Thread ID must be 32 bytes"));
    }
    if retained_keys.len() % 80 != 0 {
        return Err(JsValue::from_str(
            "Retained keys must be multiples of 80 bytes",
        ));
    }

    let mut tid = [0u8; 32];
    tid.copy_from_slice(thread_id);

    // Parse retained keys
    let mut keys = Vec::new();
    for chunk in retained_keys.chunks(80) {
        let key = trelis_multidevice::RetainedKey::from_bytes(chunk)
            .map_err(|_| JsValue::from_str("Invalid retained key in array"))?;
        keys.push(key);
    }

    let keypair = trelis_hybrid::HybridSigningKeypair::from_bytes(signing_secret)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let msg = trelis_multidevice::HistoryKeyShareMessage::new(tid, keys, &keypair, shared_at)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    Ok(msg.to_bytes())
}

/// Verify a history key share message.
///
/// # Arguments
/// * `message_bytes` - Serialised HistoryKeyShareMessage
/// * `sender_public` - 2,009-byte sender's signing public key
///
/// # Returns
/// Object with verification result and message metadata
#[wasm_bindgen]
pub fn history_key_share_verify(
    message_bytes: &[u8],
    sender_public: &[u8],
) -> Result<JsValue, JsValue> {
    let msg = trelis_multidevice::HistoryKeyShareMessage::from_bytes(message_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let sender_pk = trelis_hybrid::HybridSigningPublicKey::from_bytes(sender_public)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let valid = msg.verify(&sender_pk).is_ok();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"valid".into(), &JsValue::from_bool(valid))?;
    js_sys::Reflect::set(
        &obj,
        &"thread_id".into(),
        &js_sys::Uint8Array::from(msg.thread_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"key_count".into(),
        &JsValue::from_f64(msg.key_count() as f64),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"shared_at".into(),
        &JsValue::from_f64(msg.shared_at as f64),
    )?;

    Ok(obj.into())
}

/// Extract retained keys from a verified history key share message.
///
/// # Arguments
/// * `message_bytes` - Serialised HistoryKeyShareMessage
///
/// # Returns
/// Array of 80-byte serialised retained keys
#[wasm_bindgen]
pub fn history_key_share_extract_keys(message_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let msg = trelis_multidevice::HistoryKeyShareMessage::from_bytes(message_bytes)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let mut result = Vec::with_capacity(msg.keys.len() * 80);
    for key in &msg.keys {
        result.extend_from_slice(&key.to_bytes()[..]);
    }

    Ok(result)
}

// ============================================================================
// Thread Key Store
// ============================================================================

/// Create a new thread key store.
///
/// # Arguments
/// * `thread_id` - 32-byte thread identifier
///
/// # Returns
/// Serialised ThreadKeyStore (initially empty)
#[wasm_bindgen]
pub fn thread_key_store_create(thread_id: &[u8]) -> Result<Vec<u8>, JsValue> {
    if thread_id.len() != 32 {
        return Err(JsValue::from_str("Thread ID must be 32 bytes"));
    }

    let mut tid = [0u8; 32];
    tid.copy_from_slice(thread_id);

    let store = trelis_multidevice::ThreadKeyStore::new(tid);
    Ok(serialize_thread_key_store(&store))
}

/// Retain a message key in the store.
///
/// # Arguments
/// * `store_bytes` - Serialised ThreadKeyStore
/// * `retained_key` - 80-byte serialised RetainedKey
///
/// # Returns
/// Updated serialised ThreadKeyStore
#[wasm_bindgen]
pub fn thread_key_store_retain(
    store_bytes: &[u8],
    retained_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut store = deserialize_thread_key_store(store_bytes)?;

    let key = trelis_multidevice::RetainedKey::from_bytes(retained_key)
        .map_err(|_| JsValue::from_str("Invalid retained key"))?;

    store.retain_key(key);

    Ok(serialize_thread_key_store(&store))
}

/// Get all retained keys from a store.
///
/// # Arguments
/// * `store_bytes` - Serialised ThreadKeyStore
///
/// # Returns
/// Concatenated 80-byte serialised retained keys
#[wasm_bindgen]
pub fn thread_key_store_get_all_keys(store_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let store = deserialize_thread_key_store(store_bytes)?;

    let mut result = Vec::with_capacity(store.len() * 80);
    for key in store.get_all_keys() {
        result.extend_from_slice(&key.to_bytes()[..]);
    }

    Ok(result)
}

/// Get info about a thread key store.
///
/// # Arguments
/// * `store_bytes` - Serialised ThreadKeyStore
///
/// # Returns
/// Object with thread_id, key_count, sequence_range
#[wasm_bindgen]
pub fn thread_key_store_info(store_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let store = deserialize_thread_key_store(store_bytes)?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"thread_id".into(),
        &js_sys::Uint8Array::from(store.thread_id.as_slice()),
    )?;
    js_sys::Reflect::set(
        &obj,
        &"key_count".into(),
        &JsValue::from_f64(store.len() as f64),
    )?;

    if let Some((min, max)) = store.sequence_range() {
        js_sys::Reflect::set(&obj, &"min_sequence".into(), &JsValue::from_f64(min as f64))?;
        js_sys::Reflect::set(&obj, &"max_sequence".into(), &JsValue::from_f64(max as f64))?;
    }

    Ok(obj.into())
}

/// Prune keys older than a timestamp.
///
/// # Arguments
/// * `store_bytes` - Serialised ThreadKeyStore
/// * `before_timestamp` - Unix timestamp cutoff
///
/// # Returns
/// Updated serialised ThreadKeyStore
#[wasm_bindgen]
pub fn thread_key_store_prune(
    store_bytes: &[u8],
    before_timestamp: u64,
) -> Result<Vec<u8>, JsValue> {
    let mut store = deserialize_thread_key_store(store_bytes)?;
    store.prune_before(before_timestamp);
    Ok(serialize_thread_key_store(&store))
}

/// Merge keys from another store (deduplicating by message_id).
///
/// # Arguments
/// * `store_bytes` - Serialised ThreadKeyStore
/// * `other_keys` - Concatenated 80-byte serialised retained keys to merge
///
/// # Returns
/// Updated serialised ThreadKeyStore
#[wasm_bindgen]
pub fn thread_key_store_merge(store_bytes: &[u8], other_keys: &[u8]) -> Result<Vec<u8>, JsValue> {
    if other_keys.len() % 80 != 0 {
        return Err(JsValue::from_str(
            "Other keys must be multiples of 80 bytes",
        ));
    }

    let mut store = deserialize_thread_key_store(store_bytes)?;

    let mut keys = Vec::new();
    for chunk in other_keys.chunks(80) {
        let key = trelis_multidevice::RetainedKey::from_bytes(chunk)
            .map_err(|_| JsValue::from_str("Invalid retained key"))?;
        keys.push(key);
    }

    store.merge(keys);
    Ok(serialize_thread_key_store(&store))
}

// Thread key store serialisation helpers
fn serialize_thread_key_store(store: &trelis_multidevice::ThreadKeyStore) -> Vec<u8> {
    let key_count = store.len();
    let mut buf = Vec::with_capacity(32 + 8 + key_count * 80);

    buf.extend_from_slice(&store.thread_id);
    buf.extend_from_slice(&(key_count as u64).to_le_bytes());

    for key in store.get_all_keys() {
        buf.extend_from_slice(&key.to_bytes()[..]);
    }

    buf
}

fn deserialize_thread_key_store(
    bytes: &[u8],
) -> Result<trelis_multidevice::ThreadKeyStore, JsValue> {
    if bytes.len() < 40 {
        return Err(JsValue::from_str("ThreadKeyStore too short"));
    }

    let mut thread_id = [0u8; 32];
    thread_id.copy_from_slice(&bytes[0..32]);

    // The on-wire count is a u64; on 32-bit wasm `as usize` silently
    // truncates. Use try_from so a u64 that doesn't fit a usize is rejected
    // rather than producing a phantom small count.
    let key_count: usize =
        usize::try_from(u64::from_le_bytes(bytes[32..40].try_into().unwrap()))
            .map_err(|_| JsValue::from_str("ThreadKeyStore key_count exceeds platform usize"))?;

    // Use checked arithmetic — wasm32 has 32-bit usize, so a maximal
    // key_count multiplies / adds past usize::MAX without the guard.
    let required = key_count
        .checked_mul(80)
        .and_then(|x| x.checked_add(40))
        .ok_or_else(|| JsValue::from_str("ThreadKeyStore length overflow"))?;

    if bytes.len() < required {
        return Err(JsValue::from_str("ThreadKeyStore truncated"));
    }

    let mut store = trelis_multidevice::ThreadKeyStore::with_capacity(thread_id, key_count);

    for i in 0..key_count {
        // Safe: bytes.len() >= 40 + key_count*80 implies offset+80 <= bytes.len().
        let offset = 40 + i * 80;
        let key = trelis_multidevice::RetainedKey::from_bytes(&bytes[offset..offset + 80])
            .map_err(|_| JsValue::from_str("Invalid retained key in store"))?;
        store.retain_key(key);
    }

    Ok(store)
}

// ============================================================================
// Native Tests (run with `cargo test`)
// ============================================================================

#[cfg(test)]
mod native_tests {
    //! These tests run on native Rust, testing the underlying crypto
    //! without the JS binding layer.

    // ========================================================================
    // AEAD Tests
    // ========================================================================

    #[test]
    fn test_aead_roundtrip() {
        let key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let nonce: [u8; 24] = trelis_primitives::generate_bytes().unwrap();
        let plaintext = b"Hello, WASM world!";
        let aad = b"additional data";

        let aead_key = trelis_primitives::AeadKey::from_bytes(key);
        let aead_nonce = trelis_primitives::Nonce::from_bytes(nonce);

        let ciphertext =
            trelis_primitives::encrypt(&aead_key, &aead_nonce, plaintext, aad).unwrap();
        let decrypted =
            trelis_primitives::decrypt(&aead_key, &aead_nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let key1: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let key2: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let nonce: [u8; 24] = trelis_primitives::generate_bytes().unwrap();
        let plaintext = b"secret message";

        let aead_key1 = trelis_primitives::AeadKey::from_bytes(key1);
        let aead_key2 = trelis_primitives::AeadKey::from_bytes(key2);
        let aead_nonce = trelis_primitives::Nonce::from_bytes(nonce);

        let ciphertext =
            trelis_primitives::encrypt(&aead_key1, &aead_nonce, plaintext, &[]).unwrap();
        let result = trelis_primitives::decrypt(&aead_key2, &aead_nonce, &ciphertext, &[]);

        assert!(result.is_err());
    }

    // ========================================================================
    // KDF Tests
    // ========================================================================

    #[test]
    fn test_derive_key_deterministic() {
        let input = b"test input";
        let key1 = trelis_primitives::derive_key("test-context", input);
        let key2 = trelis_primitives::derive_key("test-context", input);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_contexts() {
        let input = b"test input";
        let key1 = trelis_primitives::derive_key("context-1", input);
        let key2 = trelis_primitives::derive_key("context-2", input);

        assert_ne!(key1, key2);
    }

    // ========================================================================
    // Ed448 Signature Tests
    // ========================================================================

    #[test]
    fn test_ed448_sign_verify() {
        let keypair = trelis_primitives::Ed448SigningKey::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message);
        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ed448_wrong_message_fails() {
        let keypair = trelis_primitives::Ed448SigningKey::generate().unwrap();
        let signature = keypair.sign(b"message 1");

        assert!(
            keypair
                .verifying_key()
                .verify(b"message 2", &signature)
                .is_err()
        );
    }

    // ========================================================================
    // ML-DSA-65 Signature Tests
    // ========================================================================

    #[test]
    fn test_mldsa65_sign_verify() {
        let keypair = trelis_primitives::MlDsa65SigningKey::generate().unwrap();
        let message = b"post-quantum secure message";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }

    // ========================================================================
    // X448 Key Exchange Tests
    // ========================================================================

    #[test]
    fn test_x448_key_exchange() {
        let alice = trelis_primitives::X448Secret::generate().unwrap();
        let bob = trelis_primitives::X448Secret::generate().unwrap();

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    // ========================================================================
    // Hybrid KEM Tests
    // ========================================================================

    #[test]
    fn test_hybrid_kem_encapsulate_decapsulate() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();

        // Verify key sizes
        assert_eq!(
            keypair.to_bytes().len(),
            1819,
            "KEM secret key should be 1819 bytes"
        );
        assert_eq!(
            keypair.public_key().to_bytes().len(),
            1214,
            "KEM public key should be 1214 bytes"
        );

        // Encapsulate
        let (shared_secret, encapsulation) = keypair.public_key().encapsulate().unwrap();

        // Decapsulate
        let decapsulated = keypair.decapsulate(&encapsulation).unwrap();

        assert_eq!(shared_secret.as_bytes(), decapsulated.as_bytes());
        assert_eq!(shared_secret.as_bytes().len(), 32);
    }

    #[test]
    fn test_hybrid_kem_serialization_roundtrip() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let bytes = keypair.to_bytes();
        let restored = trelis_hybrid::HybridKemKeypair::from_bytes(&bytes[..]).unwrap();

        assert_eq!(
            keypair.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }

    // ========================================================================
    // Hybrid Identity Tests
    // ========================================================================

    #[test]
    fn test_hybrid_identity_sign_verify() {
        let keypair = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();

        // Verify key sizes
        assert_eq!(
            keypair.to_bytes().len(),
            5908,
            "Identity secret key should be 5908 bytes"
        );
        assert_eq!(
            keypair.public_key().to_bytes().len(),
            3223,
            "Identity public key should be 3223 bytes"
        );

        // Sign
        let message = b"identity verification message";
        let signature = keypair.sign(message).unwrap();

        // Verify
        assert!(keypair.public_key().verify(message, &signature).is_ok());
        assert!(
            keypair
                .public_key()
                .verify(b"wrong message", &signature)
                .is_err()
        );
    }

    #[test]
    fn test_hybrid_identity_serialization_roundtrip() {
        let keypair = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let bytes = keypair.to_bytes();
        let restored = trelis_hybrid::HybridIdentityKeypair::from_bytes(&bytes[..]).unwrap();

        assert_eq!(
            keypair.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );

        // Verify signing still works after restoration
        let message = b"test after restore";
        let signature = restored.sign(message).unwrap();
        assert!(restored.public_key().verify(message, &signature).is_ok());
    }

    // ========================================================================
    // Safety Number Tests
    // ========================================================================

    #[test]
    fn test_safety_number_symmetric() {
        let alice = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let bob = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();

        let sn_alice = trelis_hybrid::SafetyNumber::new(alice.public_key(), bob.public_key());
        let sn_bob = trelis_hybrid::SafetyNumber::new(bob.public_key(), alice.public_key());

        // Safety numbers should be symmetric
        assert_eq!(sn_alice.fingerprint(), sn_bob.fingerprint());
    }

    #[test]
    fn test_safety_number_qr_roundtrip() {
        let alice = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let bob = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();

        let sn = trelis_hybrid::SafetyNumber::new(alice.public_key(), bob.public_key());
        let qr = sn.to_qr_string();

        let parsed = trelis_hybrid::SafetyNumber::from_qr_string(&qr).unwrap();
        assert_eq!(sn.fingerprint(), parsed.fingerprint());
    }

    // ========================================================================
    // X3DH-PQ Bundle Tests
    // ========================================================================

    #[test]
    fn test_x3dh_bundle_sign_verify() {
        let signing_keypair = trelis_hybrid::HybridSigningKeypair::generate().unwrap();
        let kem_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let otk_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();

        let bundle = trelis_x3dh_pq::PreKeyBundle::new(
            signing_keypair.public_key().clone(),
            kem_keypair.public_key().clone(),
            otk_keypair.public_key().clone(),
            12345,
            1000,
            2000,
        );

        let signed = bundle.sign(&signing_keypair).unwrap();
        assert!(signed.verify().is_ok());
        assert_eq!(signed.otk_key_id(), 12345);
    }

    // ========================================================================
    // KEM Ratchet Tests
    // ========================================================================

    #[test]
    fn test_ratchet_initiator_responder_roundtrip() {
        let session_key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let bob_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();

        // Alice initialises as initiator
        let mut alice = trelis_ratchet::KemRatchet::init_initiator(
            &session_key,
            bob_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // Bob initialises as responder
        let mut bob = trelis_ratchet::KemRatchet::init_responder(&session_key, bob_keypair, 1000);

        // Alice sends a message
        let plaintext = b"Hello from Alice!";
        let send_result = trelis_ratchet::send_message(&mut alice, plaintext, 1001).unwrap();

        // Bob receives the message
        let decrypted =
            trelis_ratchet::receive_message(&mut bob, &send_result.message, 1001).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ========================================================================
    // CoCoA Group Tests
    // ========================================================================

    #[test]
    fn test_cocoa_create_group() {
        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (session, welcomes) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        assert_eq!(session.epoch_number(), 0);
        assert_eq!(session.member_count(), 1);
        assert!(welcomes.is_empty());
    }

    #[test]
    fn test_cocoa_encrypt_decrypt() {
        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        let plaintext = b"Hello, CoCoA group!";
        let encrypted = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ========================================================================
    // Serialisation Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_ratchet_state_serialization() {
        use super::*;

        let session_key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let their_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();

        let state = trelis_ratchet::KemRatchet::init_initiator(
            &session_key,
            their_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // Serialise
        let bytes = serialize_ratchet_state(&state);

        // Deserialize
        let restored = deserialize_ratchet_state(&bytes).unwrap();

        // Verify key properties match
        assert_eq!(state.our_key_id(), restored.our_key_id());
        assert_eq!(state.send_count(), restored.send_count());
        assert_eq!(state.status(), restored.status());
    }

    /// PRF-04 (SC4) — non-vacuous counter round-trip.
    ///
    /// The control `test_ratchet_state_serialization` round-trips a FRESH state
    /// (`send_count == recv_count == 0`), so it cannot catch an off-by-one in
    /// the deserialize counter seam: `set_recv_count(n)` stores `n + 1`, so
    /// `deserialize_ratchet_state` restores with `set_recv_count(recv_count - 1)`
    /// (lib.rs:1502-1506, state.rs:294). This test drives BOTH counters to
    /// distinct non-zero values and asserts exact restore, locking that seam.
    ///
    /// PRF-04 is satisfied-by-prior-work: `trelis-wasm` has zero replay loops —
    /// `send_count` (RCH-02), `recv_count`, and `message_counter` (F09/GAP-05)
    /// already restore via direct/bounded setters. This is the lock, not a fix;
    /// no production code changes for PRF-04.
    #[test]
    fn test_ratchet_state_serialization_nonzero_counters() {
        use super::*;

        let session_key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let their_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();

        let mut state = trelis_ratchet::KemRatchet::init_initiator(
            &session_key,
            their_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // Drive BOTH counters to distinct non-zero values via the public
        // setters. `set_recv_count(n)` stores `n + 1`, so read the observed
        // values back rather than hardcoding the offset — the round-trip
        // assertion then locks whatever the live setter/accessor pair produces.
        state.set_send_count(5).unwrap();
        state.set_recv_count(6);
        let expected_send = state.send_count();
        let expected_recv = state.recv_count();
        assert!(
            expected_send > 0 && expected_recv > 0,
            "test must be non-vacuous: both counters must be non-zero"
        );

        // Round-trip through the wire serializer.
        let restored = deserialize_ratchet_state(&serialize_ratchet_state(&state)).unwrap();

        // Exact restore of BOTH counters — locks the `set_recv_count(n - 1)`/`+1`
        // seam where an off-by-one would otherwise hide (the counters==0 control
        // cannot detect it).
        assert_eq!(
            restored.send_count(),
            expected_send,
            "send_count must restore exactly"
        );
        assert_eq!(
            restored.recv_count(),
            expected_recv,
            "recv_count must restore exactly"
        );
    }

    // Regression test: deserialize_ratchet_state must reject a buffer that
    // satisfies the minimum-length entry guard but is too short for the
    // has_their_pk=true layout it claims, returning an error rather than
    // trapping on out-of-bounds indexing.
    #[test]
    fn ratchet_state_truncated_with_their_pk_flag_is_rejected() {
        use super::*;

        let session_key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let their_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let state = trelis_ratchet::KemRatchet::init_initiator(
            &session_key,
            their_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // The full form includes a 1214-byte their_public_key; the has_their_pk byte is at
        // index 1851. Truncate to 1877 bytes — past the no-their_pk minimum guard, but far
        // short of the 3091 bytes the has_their_pk=1 flag claims.
        let full = serialize_ratchet_state(&state);
        assert!(full.len() > 1877);
        assert_eq!(full[1851], 1, "fixture should have their_public_key set");
        assert!(deserialize_ratchet_state(&full[..1877]).is_err());
    }

    // RCH-02 (SC2): a state blob whose 8-byte send_count field is overwritten
    // with u64::MAX must be rejected by deserialize_ratchet_state WITHOUT
    // hanging. Pre-fix the `0..send_count` replay looped ~u64::MAX times (a
    // WASM-thread DoS); the bounded set_send_count now returns Err in O(1).
    // The test simply *terminating* is the proof the unbounded replay is gone.
    #[test]
    fn ratchet_state_out_of_range_send_count_is_rejected_without_hanging() {
        use super::*;

        let session_key: [u8; 32] = trelis_primitives::generate_bytes().unwrap();
        let their_keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let state = trelis_ratchet::KemRatchet::init_initiator(
            &session_key,
            their_keypair.public_key().clone(),
            1000,
        )
        .unwrap();

        // Initiator fixture => has_their_pk = true.
        let mut blob = serialize_ratchet_state(&state);
        assert_eq!(blob[1851], 1, "fixture should have their_public_key set");

        // Overwrite the little-endian send_count field with u64::MAX. Offset =
        // our_keypair(1819) + root_key(32) + has_their_pk(1) + their_pk(1214).
        const SEND_COUNT_OFFSET: usize = 1819 + 32 + 1 + 1214;
        blob[SEND_COUNT_OFFSET..SEND_COUNT_OFFSET + 8].copy_from_slice(&u64::MAX.to_le_bytes());

        assert!(deserialize_ratchet_state(&blob).is_err());
    }

    #[test]
    fn test_cocoa_session_serialization() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // Serialise
        let bytes = serialize_cocoa_session(&session);

        // Deserialize
        let restored = deserialize_cocoa_session(&bytes).unwrap();

        // Verify properties match
        assert_eq!(session.group_id(), restored.group_id());
        assert_eq!(session.our_user_id(), restored.our_user_id());
        assert_eq!(session.our_leaf_position(), restored.our_leaf_position());
        assert_eq!(session.member_count(), restored.member_count());
    }

    /// GAP-05 / F09: the WASM session (de)serialiser round-trips the message
    /// counter through the monotonic-forward guard. A session serialised at
    /// counter=100 restores to 100 (the reconstructed epoch is fresh at 0, so
    /// the forward-set 0 -> 100 always passes), and the guard remains active on
    /// the reconstructed object — an attempt to roll the restored counter
    /// backwards is rejected with `MessageCounterTooOld` and the counter is
    /// left unchanged. This exercises the exact `CocoaSession` setter boundary
    /// that `deserialize_cocoa_session` drives via `?`.
    #[test]
    fn test_cocoa_session_counter_restore_and_guard() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // Forward-set the source session's counter (allowed) and serialise at 100.
        session.set_message_counter(100).unwrap();
        assert_eq!(session.message_counter(), 100);
        let bytes = serialize_cocoa_session(&session);

        // Deserialise restores the counter through the guarded setter.
        let mut restored = deserialize_cocoa_session(&bytes).unwrap();
        assert_eq!(
            restored.message_counter(),
            100,
            "deserialise must restore the serialised counter"
        );

        // The guard is active on the reconstructed object: a regression is
        // rejected and the counter is unchanged.
        let regressed = restored.set_message_counter(50);
        assert!(
            matches!(
                regressed,
                Err(trelis_error::CryptoError::MessageCounterTooOld)
            ),
            "a restored session must reject an intra-epoch counter regression"
        );
        assert_eq!(
            restored.message_counter(),
            100,
            "counter must be unchanged after a rejected regression"
        );
    }

    /// WR-06: a session serialised at epoch > 0 must restore to the SAME epoch
    /// secret (and therefore the same per-message keys), so a message encrypted
    /// before the round trip still decrypts afterwards. The superseded
    /// deserialiser rebuilt at epoch 0 and advanced `epoch_number` times, which
    /// re-derived a fresh secret at each step (moving away from the stored one),
    /// so at epoch > 0 the restored app_secret diverged and cross-decrypt failed
    /// with AeadAuthenticationFailed.
    #[test]
    fn test_cocoa_session_restore_epoch_gt0_preserves_secret() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // Advance to epoch 2 (two commits' worth of epoch advances).
        session.advance_epoch(&[0x11u8; 32], [0x22u8; 32]);
        session.advance_epoch(&[0x33u8; 32], [0x44u8; 32]);
        assert_eq!(session.epoch_number(), 2);

        // Encrypt a message at epoch 2 BEFORE serialising.
        let plaintext = b"epoch 2 message";
        let encrypted = session.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.epoch, 2);

        let secret_before = *session.current_epoch_secret();

        // Round-trip the session through the WASM (de)serialiser.
        let bytes = serialize_cocoa_session(&session);
        let restored = deserialize_cocoa_session(&bytes).unwrap();

        // The reconstructed epoch number and secret must match the original.
        assert_eq!(restored.epoch_number(), 2, "epoch number must be restored");
        assert_eq!(
            &secret_before,
            restored.current_epoch_secret(),
            "restored epoch secret at epoch 2 must match the serialised secret"
        );

        // End-to-end: the restored session decrypts the epoch-2 message the
        // original encrypted — impossible under the buggy re-derivation.
        let decrypted = restored.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// RBK-01 / GAP-05 — the TRUE cross-deserialise counter rollback, driven
    /// through the WASM restore driver (`deserialize_cocoa_session_checked`, the
    /// native core of `cocoa_deserialize_checked`).
    ///
    /// Unlike the 52-05 in-object guard
    /// (`test_cocoa_session_counter_restore_and_guard`), which only sees a *live*
    /// object's counter go backwards within one invocation, this exercises the
    /// cross-INVOCATION case the audit named: the same timeline is serialised at
    /// `(E, 50)` and again at `(E, 150)`, the watermark is persisted from the
    /// NEWER blob, and the OLDER blob is restored against it. Per Pitfall 2 the
    /// watermark is NOT read out of the older blob (that would be a silent no-op);
    /// it is the app's independent high-water side-state.
    #[test]
    fn test_cocoa_cross_deserialise_rollback_rejected() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // WR-02: the checked door now enforces the expected identity; capture the
        // blob's own (group_id, user_id) to pass as the matching expected pair.
        let group_id = *session.group_id();

        // Older state at counter 50 -> serialise blob_old.
        session.set_message_counter(50).unwrap();
        let blob_old = serialize_cocoa_session(&session);

        // Advance the SAME timeline to counter 150 -> serialise blob_new, and
        // persist the watermark from the NEWER blob (epoch 0 from create_group,
        // counter 150). Equivalent to `SessionWatermark::of_session` of the
        // counter-150 session.
        session.set_message_counter(150).unwrap();
        let blob_new = serialize_cocoa_session(&session);
        let watermark = trelis_cocoa::SessionWatermark::new(0, 150)
            .to_bytes()
            .to_vec();

        // (a) HONEST: restoring the NEWER blob against the watermark is accepted
        // (equal), and the returned advanced watermark is exactly (0, 150).
        // (`unwrap` matches the crate-wide `allow(clippy::unwrap_used)`; the
        // honest equal restore of the newest blob must be accepted.)
        let (_restored, advanced) =
            deserialize_cocoa_session_checked(&blob_new, &watermark, &group_id, &user_id).unwrap();
        assert_eq!(advanced, trelis_cocoa::SessionWatermark::new(0, 150));

        // (b) ROLLBACK: restoring the OLDER blob (counter 50) against the newer
        // watermark (150) is REJECTED — the stale counter is never reused.
        let rolled = deserialize_cocoa_session_checked(&blob_old, &watermark, &group_id, &user_id);
        assert!(
            matches!(rolled, Err(trelis_error::CryptoError::MessageCounterTooOld)),
            "restoring a blob below the persisted watermark must be rejected"
        );

        // (c) INERT EQUAL: a second honest restore of the newer blob still
        // accepts (loading a session is inert; the real re-emit is closed by the
        // emit-time advance, see test_cocoa_cross_deserialise_advance_on_emit).
        assert!(
            deserialize_cocoa_session_checked(&blob_new, &watermark, &group_id, &user_id).is_ok()
        );
    }

    /// RBK-01 / GAP-05 Pitfall 1 (Assumption A5) — the emit-time-advance caller
    /// duty. `cocoa_session_watermark` reads the advance-to `(epoch, counter)`
    /// from any post-op blob, and advancing the persisted watermark on emit
    /// closes the crash-replay re-emit: a stale blob restored against the
    /// advanced watermark is rejected. "Allow equal" on restore is safe ONLY
    /// because emit moves the watermark past the reloaded blob.
    #[test]
    fn test_cocoa_cross_deserialise_advance_on_emit() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // WR-02: capture the blob's own identity to pass to the checked door.
        let group_id = *session.group_id();

        // The blob at counter 100: cocoa_session_watermark yields its (0, 100).
        session.set_message_counter(100).unwrap();
        let blob_at_100 = serialize_cocoa_session(&session);
        let wm_at_100 = cocoa_session_watermark(&blob_at_100).unwrap();
        assert_eq!(
            wm_at_100.len(),
            16,
            "watermark is the 16-byte (epoch||counter)"
        );
        assert_eq!(
            wm_at_100,
            trelis_cocoa::SessionWatermark::new(0, 100)
                .to_bytes()
                .to_vec()
        );

        // Model an emit: the post-op blob carries the advanced (0, 101). The app
        // reads and persists THAT advance-to watermark before releasing the
        // ciphertext.
        session.set_message_counter(101).unwrap();
        let blob_at_101 = serialize_cocoa_session(&session);
        let wm_after_emit = cocoa_session_watermark(&blob_at_101).unwrap();
        assert_eq!(
            wm_after_emit,
            trelis_cocoa::SessionWatermark::new(0, 101)
                .to_bytes()
                .to_vec()
        );

        // Restoring the STALE blob_at_100 against the advanced watermark is
        // rejected — advancing on emit closes the crash-replay re-emit.
        let replay =
            deserialize_cocoa_session_checked(&blob_at_100, &wm_after_emit, &group_id, &user_id);
        assert!(
            matches!(replay, Err(trelis_error::CryptoError::MessageCounterTooOld)),
            "a stale restore against the emit-advanced watermark must be rejected"
        );
    }

    /// WR-02 — the checked door ENFORCES the caller's expected `(group_id,
    /// user_id)` identity, it does not merely report it. A watermark looked up
    /// under the WRONG identity (a caller mis-keying its per-identity watermark
    /// store) is rejected BEFORE the counter check, so the rollback guard cannot
    /// be silently disabled by pairing one identity's watermark with another
    /// identity's blob.
    #[test]
    fn test_cocoa_deserialise_checked_identity_mismatch_rejected() {
        use super::*;

        let identity = trelis_hybrid::HybridIdentityKeypair::generate().unwrap();
        let kem = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let user_id = [0x42u8; 32];

        let (mut session, _) =
            trelis_cocoa::operations::create_group(&identity, kem, user_id, &[]).unwrap();

        // A blob at counter 100 and a LOW watermark at (0, 5) that would pass the
        // counter guard (100 >= 5) — so the ONLY thing that can reject the restore
        // is the identity check.
        session.set_message_counter(100).unwrap();
        let blob = serialize_cocoa_session(&session);
        let group_id = *session.group_id();
        let low_watermark = trelis_cocoa::SessionWatermark::new(0, 5)
            .to_bytes()
            .to_vec();

        // Sanity: with the MATCHING identity the low watermark is accepted (the
        // counter guard alone does not reject it), isolating the identity check.
        assert!(
            deserialize_cocoa_session_checked(&blob, &low_watermark, &group_id, &user_id).is_ok(),
            "matching identity + non-rollback watermark must be accepted"
        );

        // Wrong group_id (one byte flipped): rejected with the Security-category
        // MalformedMessage BEFORE the (passing) counter check — the guard is not
        // silently disabled by a mis-keyed watermark.
        let mut wrong_group = group_id;
        wrong_group[0] ^= 0xff;
        let mismatch_group =
            deserialize_cocoa_session_checked(&blob, &low_watermark, &wrong_group, &user_id);
        assert!(
            matches!(
                mismatch_group,
                Err(trelis_error::CryptoError::MalformedMessage)
            ),
            "a watermark applied under the wrong group_id must be rejected"
        );

        // Wrong user_id (one byte flipped): same rejection.
        let mut wrong_user = user_id;
        wrong_user[0] ^= 0xff;
        let mismatch_user =
            deserialize_cocoa_session_checked(&blob, &low_watermark, &group_id, &wrong_user);
        assert!(
            matches!(
                mismatch_user,
                Err(trelis_error::CryptoError::MalformedMessage)
            ),
            "a watermark applied under the wrong user_id must be rejected"
        );
    }

    // Regression test: the CoCoA WASM legacy-session context string is
    // intentionally DISTINCT from the X3DH-PQ SESSION_CONTEXT. They derive
    // different values (CoCoA group init_secret vs X3DH pairwise session
    // secret) from different inputs; sharing a context would be a
    // domain-separation violation, not an interop fix. This guards against
    // a well-meaning future change that makes them equal.
    #[test]
    fn wasm_cocoa_session_context_is_domain_separated_from_x3dh() {
        assert_ne!(
            super::COCOA_WASM_LEGACY_SESSION_CONTEXT,
            trelis_primitives::SESSION_CONTEXT,
            "CoCoA WASM legacy-session context must stay domain-separated from the X3DH-PQ session context"
        );
    }
}

// ============================================================================
// WASM-specific tests (run with wasm-pack test)
// ============================================================================

#[cfg(all(target_arch = "wasm32", test))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Tests can run in both Node.js and browser environments

    #[wasm_bindgen_test]
    fn wasm_test_aead_roundtrip() {
        let key = random_bytes_32().unwrap();
        let nonce = random_bytes_24().unwrap();
        let plaintext = b"WASM browser test!";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &ciphertext, &[]).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn wasm_test_hybrid_kem() {
        let keypair = hybrid_kem_generate().unwrap();

        let secret_key: Vec<u8> =
            js_sys::Uint8Array::from(js_sys::Reflect::get(&keypair, &"secret_key".into()).unwrap())
                .to_vec();
        let public_key: Vec<u8> =
            js_sys::Uint8Array::from(js_sys::Reflect::get(&keypair, &"public_key".into()).unwrap())
                .to_vec();

        let encap_result = hybrid_kem_encapsulate(&public_key).unwrap();
        let shared_secret: Vec<u8> = js_sys::Uint8Array::from(
            js_sys::Reflect::get(&encap_result, &"shared_secret".into()).unwrap(),
        )
        .to_vec();
        let encapsulation: Vec<u8> = js_sys::Uint8Array::from(
            js_sys::Reflect::get(&encap_result, &"encapsulation".into()).unwrap(),
        )
        .to_vec();

        let decapsulated = hybrid_kem_decapsulate(&secret_key, &encapsulation).unwrap();

        assert_eq!(shared_secret, decapsulated);
    }

    #[wasm_bindgen_test]
    fn wasm_test_hybrid_identity_sign_verify() {
        let keypair = hybrid_identity_generate().unwrap();

        let secret_key: Vec<u8> =
            js_sys::Uint8Array::from(js_sys::Reflect::get(&keypair, &"secret_key".into()).unwrap())
                .to_vec();
        let public_key: Vec<u8> =
            js_sys::Uint8Array::from(js_sys::Reflect::get(&keypair, &"public_key".into()).unwrap())
                .to_vec();

        let message = b"WASM browser signature test";
        let signature = hybrid_identity_sign(&secret_key, message).unwrap();

        assert!(hybrid_identity_verify(&public_key, message, &signature).unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_test_cocoa_group() {
        let identity = hybrid_identity_generate().unwrap();
        let kem = hybrid_kem_generate().unwrap();

        let identity_secret: Vec<u8> = js_sys::Uint8Array::from(
            js_sys::Reflect::get(&identity, &"secret_key".into()).unwrap(),
        )
        .to_vec();
        let kem_secret: Vec<u8> =
            js_sys::Uint8Array::from(js_sys::Reflect::get(&kem, &"secret_key".into()).unwrap())
                .to_vec();

        let user_id = [0x01u8; 32];

        let result = cocoa_create_group(&identity_secret, &kem_secret, &user_id).unwrap();

        let member_count = js_sys::Reflect::get(&result, &"member_count".into())
            .unwrap()
            .as_f64()
            .unwrap() as u32;

        assert_eq!(member_count, 1);
    }
}
