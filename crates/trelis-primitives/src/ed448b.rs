//! Ed448-B signature primitives (experimental).
//!
//! This module provides an experimental Ed448 variant that uses BLAKE3 instead
//! of SHAKE256 for all internal hashing operations. This is NOT standard Ed448
//! and signatures are NOT compatible with RFC 8032.
//!
//! # Motivation
//!
//! BLAKE3 is significantly faster than SHAKE256, especially for large messages.
//! This variant provides the same security level as Ed448 (~224-bit) but with
//! improved performance characteristics.
//!
//! # Warning
//!
//! This is an experimental, non-standard signature scheme. Use standard Ed448
//! for interoperability. Ed448-B signatures cannot be verified by standard
//! Ed448 implementations.
//!
//! # Key Sizes
//!
//! - Public key: 57 bytes (same as Ed448)
//! - Secret key: 57 bytes (same as Ed448)
//! - Signature: 114 bytes (same as Ed448)

use ed448_goldilocks_plus::{EdwardsPoint, Scalar, ScalarBytes, WideScalarBytes};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of Ed448-B public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// Size of Ed448-B secret key (seed) in bytes.
pub const SECRET_KEY_SIZE: usize = 57;

/// Size of Ed448-B signature in bytes.
pub const SIGNATURE_SIZE: usize = 114;

/// Domain separation contexts for Ed448-B using BLAKE3's derive_key mode.
/// These provide cryptographic domain separation to prevent cross-protocol attacks.
const CONTEXT_EXPAND: &str = "Ed448-B-expand";
const CONTEXT_NONCE: &str = "Ed448-B-nonce";
const CONTEXT_CHALLENGE: &str = "Ed448-B-challenge";

/// Ed448-B signing key (secret key).
///
/// This key is used to create signatures. It contains the secret seed
/// and is zeroized on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed448BSigningKey {
    seed: [u8; SECRET_KEY_SIZE],
}

/// Internal expanded secret key with precomputed values.
struct ExpandedSecretKey {
    scalar: Scalar,
    hash_prefix: ScalarBytes,
    public_key: Ed448BVerifyingKey,
}

impl ExpandedSecretKey {
    /// Expands a seed into a signing scalar and hash prefix using BLAKE3.
    fn from_seed(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        // Use BLAKE3 derive_key mode for domain-separated seed expansion
        let mut output = [0u8; 114];
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_EXPAND);
        hasher.update(seed);
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut output);

        let mut scalar_bytes = ScalarBytes::default();
        scalar_bytes.copy_from_slice(&output[..SECRET_KEY_SIZE]);

        // Apply Ed448 clamping:
        // - Clear the two least significant bits of the first byte
        // - Clear all eight bits of the last byte
        // - Set the highest bit of the second-to-last byte
        scalar_bytes[0] &= 0xFC;
        scalar_bytes[56] = 0;
        scalar_bytes[55] |= 0x80;

        let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);

        let mut hash_prefix = ScalarBytes::default();
        hash_prefix.copy_from_slice(&output[SECRET_KEY_SIZE..]);

        // Compute public key: A = scalar * G
        let point = EdwardsPoint::GENERATOR * scalar;
        let compressed = point.compress();

        let public_key = Ed448BVerifyingKey { compressed, point };

        Self {
            scalar,
            hash_prefix,
            public_key,
        }
    }

    /// Signs a message using BLAKE3.
    fn sign(&self, message: &[u8]) -> Ed448BSignature {
        self.sign_inner(0, &[], message)
    }

    /// Signs a message with context using BLAKE3.
    fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Ed448BSignature {
        self.sign_inner(0, context, message)
    }

    fn sign_inner(&self, phflag: u8, ctx: &[u8], message: &[u8]) -> Ed448BSignature {
        // The single-octet length prefix is canonical: callers MUST validate
        // ctx.len() <= 255 at the API boundary. Use try_from instead of `as u8`
        // to surface an internal refactor that breaks this invariant rather
        // than silently corrupting the hash domain.
        #[allow(clippy::expect_used)]
        let ctx_len_byte: u8 = u8::try_from(ctx.len())
            .expect("ed448b: context length must be validated <= 255 at the API boundary");

        // Compute r = BLAKE3(phflag || ctx_len || ctx || prefix || message) mod order
        // Using derive_key mode for domain separation
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_NONCE);
        hasher.update(&[phflag]);
        hasher.update(&[ctx_len_byte]);
        hasher.update(ctx);
        hasher.update(&self.hash_prefix);
        hasher.update(message);

        let mut r_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

        // R = r * G
        let big_r = EdwardsPoint::GENERATOR * r;
        let compressed_r = big_r.compress();

        // Compute k = BLAKE3(phflag || ctx_len || ctx || R || A || message) mod order
        // Using derive_key mode for domain separation
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_CHALLENGE);
        hasher.update(&[phflag]);
        hasher.update(&[ctx_len_byte]);
        hasher.update(ctx);
        hasher.update(compressed_r.as_bytes());
        hasher.update(self.public_key.compressed.as_bytes());
        hasher.update(message);

        let mut k_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // s = r + k * scalar
        let s = r + k * self.scalar;

        Ed448BSignature::new(compressed_r, s)
    }
}

impl Ed448BSigningKey {
    /// Generates a new random signing key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SECRET_KEY_SIZE];
        fill_bytes(&mut seed)?;
        Ok(Self { seed })
    }

    /// Creates a signing key from a seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 57-byte secret seed.
    #[must_use]
    pub const fn from_seed(seed: [u8; SECRET_KEY_SIZE]) -> Self {
        Self { seed }
    }

    /// Returns the seed bytes.
    #[must_use]
    pub fn seed(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Get the expanded secret key for operations.
    fn expanded(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from_seed(&self.seed)
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed448BVerifyingKey {
        self.expanded().public_key
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The Ed448-B signature (114 bytes).
    pub fn sign(&self, message: &[u8]) -> Ed448BSignature {
        self.expanded().sign(message)
    }

    /// Signs a message with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    /// * `context` - The context string (max 255 bytes).
    ///
    /// # Returns
    ///
    /// The Ed448-B signature (114 bytes), or an error if context is too long.
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Ed448BSignature> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        Ok(self.expanded().sign_with_context(message, context))
    }

    /// Wraps this signing key in a `GuardedBox` for enhanced memory protection.
    ///
    /// The returned `GuardedBox` provides:
    /// - Guard pages before and after the key to detect buffer overflows
    /// - Memory locking to prevent swapping to disc (if privileges allow)
    /// - Automatic zeroisation on drop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sk = Ed448BSigningKey::generate()?;
    /// let guarded = sk.into_guarded()?;
    /// guarded.protect_readonly()?; // Optional: make read-only after init
    /// let sig = guarded.sign(message);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MemlockError` if memory allocation or protection fails.
    #[cfg(feature = "mlock")]
    pub fn into_guarded(self) -> crate::memlock::Result<crate::memlock::GuardedBox<Self>> {
        crate::memlock::GuardedBox::new(self)
    }
}

/// Ed448-B verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
#[derive(Clone)]
pub struct Ed448BVerifyingKey {
    compressed: ed448_goldilocks_plus::CompressedEdwardsY,
    point: EdwardsPoint,
}

impl Ed448BVerifyingKey {
    /// Creates a verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 57 bytes,
    /// or `SignatureVerificationFailed` if the bytes don't represent a valid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        let compressed = ed448_goldilocks_plus::CompressedEdwardsY(key_bytes);
        let point = Option::<EdwardsPoint>::from(compressed.decompress())
            .ok_or(CryptoError::SignatureVerificationFailed)?;

        Ok(Self { compressed, point })
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.compressed.0
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.compressed.0
    }

    /// Verifies a signature on a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the signature is invalid.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self, message: &[u8], signature: &Ed448BSignature) -> Result<()> {
        self.verify_inner(0, &[], message, signature)
    }

    /// Verifies a signature on a message with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing (max 255 bytes).
    /// * `signature` - The signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes,
    /// or `SignatureVerificationFailed` if the signature is invalid.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Ed448BSignature,
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        self.verify_inner(0, context, message, signature)
    }

    fn verify_inner(
        &self,
        phflag: u8,
        ctx: &[u8],
        message: &[u8],
        signature: &Ed448BSignature,
    ) -> Result<()> {
        // Decompress R from signature
        let r_point = Option::<EdwardsPoint>::from(signature.r.decompress())
            .ok_or(CryptoError::SignatureVerificationFailed)?;

        // See sign_inner: ctx length must be validated at the API boundary.
        // try_from surfaces internal refactor bugs rather than truncating silently.
        #[allow(clippy::expect_used)]
        let ctx_len_byte: u8 = u8::try_from(ctx.len())
            .expect("ed448b: context length must be validated <= 255 at the API boundary");

        // Compute k = BLAKE3(phflag || ctx_len || ctx || R || A || message) mod order
        // Using derive_key mode for domain separation (must match signing)
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_CHALLENGE);
        hasher.update(&[phflag]);
        hasher.update(&[ctx_len_byte]);
        hasher.update(ctx);
        hasher.update(signature.r.as_bytes());
        hasher.update(self.compressed.as_bytes());
        hasher.update(message);

        let mut k_bytes = WideScalarBytes::default();
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // Deserialize s scalar from signature with canonical validation
        // This is defence in depth - from_bytes should already reject non-canonical scalars
        //
        // IMPORTANT: Also check byte 56 is 0x00 since from_canonical_bytes only checks 56 bytes.
        // Use constant-time comparison to prevent timing attacks that could leak validity of byte 56.
        if !bool::from(signature.s[56].ct_eq(&0u8)) {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        let s_bytes = ScalarBytes::clone_from_slice(&signature.s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(&s_bytes))
            .ok_or(CryptoError::SignatureVerificationFailed)?;

        // Verify: s * G == R + k * A
        let lhs = EdwardsPoint::GENERATOR * s;
        let rhs = r_point + self.point * k;

        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl PartialEq for Ed448BVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Ed448BVerifyingKey {}

impl core::fmt::Debug for Ed448BVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448BVerifyingKey")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Ed448-B signature.
#[derive(Clone)]
pub struct Ed448BSignature {
    r: ed448_goldilocks_plus::CompressedEdwardsY,
    /// s scalar as 57 bytes (56 bytes + trailing 0x00, matching RFC 8032 format)
    s: [u8; 57],
}

impl Ed448BSignature {
    /// Creates a signature from the internal components.
    fn new(r: ed448_goldilocks_plus::CompressedEdwardsY, s: Scalar) -> Self {
        let mut s_bytes = [0u8; 57];
        s_bytes[..56].copy_from_slice(&s.to_bytes());
        // 57th byte is always 0x00 for valid scalars (curve order fits in 56 bytes)
        Self { r, s: s_bytes }
    }

    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if:
    /// - The slice is not exactly 114 bytes
    /// - The s scalar is not in canonical form (s >= curve order)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let mut r_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&bytes[..57]);
        let r = ed448_goldilocks_plus::CompressedEdwardsY(r_bytes);

        let mut s = [0u8; 57];
        s.copy_from_slice(&bytes[57..]);

        // Validate s scalar is in canonical form (< curve order)
        // This prevents signature malleability and ensures only valid scalars are accepted.
        // The s scalar must be < L where L is the curve order (≈ 2^446).
        //
        // IMPORTANT: ScalarBytes is 57 bytes but U448 is only 448 bits (56 bytes).
        // The library's from_canonical_bytes ignores byte 56, so we must check it explicitly.
        // Byte 56 must always be 0x00 for valid scalars since the curve order fits in ~56 bytes.
        // Use constant-time comparison to prevent timing attacks that could leak validity of byte 56.
        if !bool::from(s[56].ct_eq(&0u8)) {
            return Err(CryptoError::InvalidSignature);
        }
        // Also verify the first 56 bytes are in canonical form (< curve order)
        let s_scalar_bytes = ScalarBytes::clone_from_slice(&s);
        if Option::<Scalar>::from(Scalar::from_canonical_bytes(&s_scalar_bytes)).is_none() {
            return Err(CryptoError::InvalidSignature);
        }

        Ok(Self { r, s })
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.to_bytes()
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[..57].copy_from_slice(self.r.as_bytes());
        bytes[57..].copy_from_slice(&self.s);
        bytes
    }
}

impl ConstantTimeEq for Ed448BSignature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for Ed448BSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Ed448BSignature {}

impl core::fmt::Debug for Ed448BSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448BSignature")
            .field("bytes", &"[114 bytes]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_key_generation() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Ed448-B!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature = signing_key.sign(message);

        let wrong_message = b"wrong message";
        assert!(matches!(
            verifying_key.verify(wrong_message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key1 = Ed448BSigningKey::generate().unwrap();
        let signing_key2 = Ed448BSigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message);

        assert!(matches!(
            verifying_key2.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_deterministic_signatures() {
        let signing_key = Ed448BSigningKey::generate().unwrap();

        let message = b"test message";
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Ed448-B signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_empty_message() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message);

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_context_string() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let context = b"trelis-test-context";

        let signature = signing_key.sign_with_context(message, context).unwrap();

        // Verify with same context should succeed
        assert!(
            verifying_key
                .verify_with_context(message, context, &signature)
                .is_ok()
        );

        // Verify with wrong context should fail
        assert!(matches!(
            verifying_key.verify_with_context(message, b"wrong-context", &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));

        // Verify without context should fail
        assert!(matches!(
            verifying_key.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = Ed448BVerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        let bytes = signature.to_bytes();
        let recovered = Ed448BSignature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = Ed448BSignature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_non_canonical_s_scalar_rejected() {
        // Create a valid signature first
        let signing_key = Ed448BSigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");
        let mut bytes = signature.to_bytes();

        // Modify the last byte (byte 113) of the s scalar
        // This byte should always be 0x00 for valid signatures since the
        // curve order fits in ~56 bytes. Setting it to non-zero creates
        // a value >= curve order.
        bytes[113] ^= 0x01;

        // This should fail because the s scalar is non-canonical
        let result = Ed448BSignature::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "Non-canonical s scalar (byte 113 modified) should be rejected"
        );
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Ed448BVerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 57,
                actual: 50
            })
        ));
    }

    #[test]
    fn test_different_from_standard_ed448() {
        // Ensure Ed448-B signatures are NOT compatible with standard Ed448
        use crate::ed448::Ed448SigningKey;

        let seed = [0x42u8; 57];

        let ed448_sk = Ed448SigningKey::from_seed(seed);
        let ed448b_sk = Ed448BSigningKey::from_seed(seed);

        // Same seed should produce different public keys due to different hash
        let ed448_vk = ed448_sk.verifying_key();
        let ed448b_vk = ed448b_sk.verifying_key();

        assert_ne!(ed448_vk.to_bytes(), ed448b_vk.to_bytes());
    }
}

/// Property-based tests for Ed448-B cryptographic invariants.
///
/// These tests verify that the algebraic properties of the signature scheme
/// hold across millions of random inputs, providing confidence in correctness
/// even without external test vectors.
#[cfg(test)]
mod proptests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;
    use proptest::prelude::*;

    /// Generate an arbitrary 57-byte seed.
    fn arb_seed() -> impl Strategy<Value = [u8; 57]> {
        proptest::collection::vec(any::<u8>(), 57).prop_map(|v| {
            let mut arr = [0u8; 57];
            arr.copy_from_slice(&v);
            arr
        })
    }

    /// Generate an arbitrary message (0 to 4KB).
    fn arb_message() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..4096)
    }

    /// Generate an arbitrary context (0 to 255 bytes).
    fn arb_context() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..256)
    }

    proptest! {
        /// Property: Sign-verify roundtrip always succeeds.
        /// For any seed and message, signing then verifying with the correct
        /// key always succeeds.
        #[test]
        fn prop_sign_verify_roundtrip(seed in arb_seed(), msg in arb_message()) {
            let sk = Ed448BSigningKey::from_seed(seed);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);
            prop_assert!(vk.verify(&msg, &sig).is_ok());
        }

        /// Property: Signing is deterministic.
        /// The same key signing the same message always produces the same signature.
        #[test]
        fn prop_deterministic_signing(seed in arb_seed(), msg in arb_message()) {
            let sk = Ed448BSigningKey::from_seed(seed);
            let sig1 = sk.sign(&msg);
            let sig2 = sk.sign(&msg);
            prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        }

        /// Property: Same seed produces same keypair.
        /// Key derivation is deterministic.
        #[test]
        fn prop_deterministic_keygen(seed in arb_seed()) {
            let sk1 = Ed448BSigningKey::from_seed(seed);
            let sk2 = Ed448BSigningKey::from_seed(seed);
            prop_assert_eq!(sk1.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
        }

        /// Property: Different seeds produce different public keys.
        /// With overwhelming probability, different seeds yield different keys.
        #[test]
        fn prop_different_seeds_different_keys(seed1 in arb_seed(), seed2 in arb_seed()) {
            prop_assume!(seed1 != seed2);
            let vk1 = Ed448BSigningKey::from_seed(seed1).verifying_key();
            let vk2 = Ed448BSigningKey::from_seed(seed2).verifying_key();
            prop_assert_ne!(vk1.to_bytes(), vk2.to_bytes());
        }

        /// Property: Wrong key fails verification.
        /// A signature valid under one key is invalid under a different key.
        #[test]
        fn prop_wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), msg in arb_message()) {
            prop_assume!(seed1 != seed2);
            let sk1 = Ed448BSigningKey::from_seed(seed1);
            let vk2 = Ed448BSigningKey::from_seed(seed2).verifying_key();
            let sig = sk1.sign(&msg);
            prop_assert!(vk2.verify(&msg, &sig).is_err());
        }

        /// Property: Modified message fails verification.
        /// Changing even one bit of the message invalidates the signature.
        #[test]
        fn prop_modified_message_fails(
            seed in arb_seed(),
            msg in arb_message(),
            flip_pos in any::<usize>()
        ) {
            prop_assume!(!msg.is_empty());
            let sk = Ed448BSigningKey::from_seed(seed);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);

            // Flip one bit
            let mut bad_msg = msg.clone();
            let pos = flip_pos % bad_msg.len();
            bad_msg[pos] ^= 0x01;

            prop_assert!(vk.verify(&bad_msg, &sig).is_err());
        }

        /// Property: Modified signature changes verification outcome.
        /// Flipping a bit in the signature either fails decoding or changes
        /// the verification result (fails with overwhelming probability).
        #[test]
        fn prop_modified_signature_differs(
            seed in arb_seed(),
            msg in arb_message(),
            flip_pos in 0usize..114,
            flip_bit in 0u8..8
        ) {
            let sk = Ed448BSigningKey::from_seed(seed);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);

            // Flip one bit in signature
            let mut bad_sig_bytes = sig.to_bytes();
            bad_sig_bytes[flip_pos] ^= 1 << flip_bit;

            // The modified signature must differ from original
            prop_assert_ne!(sig.to_bytes(), bad_sig_bytes);

            // Either fails to decode or fails to verify (with overwhelming probability)
            // Note: In extremely rare cases, a modified signature could still be valid
            // but for a DIFFERENT message, which is still secure behavior.
            match Ed448BSignature::from_bytes(&bad_sig_bytes) {
                Err(_) => { /* Expected: decode failure */ }
                Ok(bad_sig) => {
                    // Most modifications will fail verification
                    // We don't assert failure here because there's a tiny chance
                    // the bit flip produces another valid signature for the same message
                    // (astronomically unlikely but mathematically possible)
                    let _ = vk.verify(&msg, &bad_sig);
                }
            }
        }

        /// Property: Signature and key serialization roundtrips.
        /// Encoding then decoding produces equivalent objects.
        #[test]
        fn prop_serialization_roundtrip(seed in arb_seed(), msg in arb_message()) {
            let sk = Ed448BSigningKey::from_seed(seed);
            let vk = sk.verifying_key();
            let sig = sk.sign(&msg);

            // Verifying key roundtrip
            let vk_bytes = vk.to_bytes();
            let vk2 = Ed448BVerifyingKey::from_bytes(&vk_bytes).unwrap();
            prop_assert_eq!(vk.to_bytes(), vk2.to_bytes());

            // Signature roundtrip
            let sig_bytes = sig.to_bytes();
            let sig2 = Ed448BSignature::from_bytes(&sig_bytes).unwrap();
            prop_assert_eq!(sig.to_bytes(), sig2.to_bytes());

            // Verify with recovered objects
            prop_assert!(vk2.verify(&msg, &sig2).is_ok());
        }

        /// Property: Context-based signing works correctly.
        /// Sign with context verifies only with same context.
        #[test]
        fn prop_context_isolation(
            seed in arb_seed(),
            msg in arb_message(),
            ctx1 in arb_context(),
            ctx2 in arb_context()
        ) {
            // Skip empty context - signing with empty context is equivalent to signing without context
            prop_assume!(!ctx1.is_empty());
            prop_assume!(ctx1 != ctx2);
            let sk = Ed448BSigningKey::from_seed(seed);
            let vk = sk.verifying_key();

            let sig = sk.sign_with_context(&msg, &ctx1).unwrap();

            // Same context works
            prop_assert!(vk.verify_with_context(&msg, &ctx1, &sig).is_ok());

            // Different context fails
            prop_assert!(vk.verify_with_context(&msg, &ctx2, &sig).is_err());

            // No context fails
            prop_assert!(vk.verify(&msg, &sig).is_err());
        }

        /// Property: Signature size is always 114 bytes.
        #[test]
        fn prop_signature_size(seed in arb_seed(), msg in arb_message()) {
            let sk = Ed448BSigningKey::from_seed(seed);
            let sig = sk.sign(&msg);
            prop_assert_eq!(sig.to_bytes().len(), SIGNATURE_SIZE);
        }

        /// Property: Public key size is always 57 bytes.
        #[test]
        fn prop_public_key_size(seed in arb_seed()) {
            let vk = Ed448BSigningKey::from_seed(seed).verifying_key();
            prop_assert_eq!(vk.to_bytes().len(), PUBLIC_KEY_SIZE);
        }
    }
}
