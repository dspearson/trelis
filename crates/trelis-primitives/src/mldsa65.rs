//! ML-DSA-65 signature primitives.
//!
//! This module provides ML-DSA-65 digital signatures as specified in FIPS 204.
//! ML-DSA-65 is NIST's standardisation of the Dilithium3 lattice-based
//! post-quantum signature scheme, providing approximately 128-bit security
//! against quantum attacks (NIST Level 3).
//!
//! # Key Sizes
//!
//! - Public key: 1,952 bytes
//! - Secret key: 4,032 bytes
//! - Signature: 3,309 bytes
//!
//! # Security Properties
//!
//! - Post-quantum security (lattice-based)
//! - Strong unforgeability under chosen message attacks (SUF-CMA)
//! - Constant-time implementation
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::mldsa65::{MlDsa65SigningKey, MlDsa65VerifyingKey};
//!
//! // Generate a new signing key
//! let signing_key = MlDsa65SigningKey::generate().unwrap();
//!
//! // Get the corresponding verifying key
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, Trelis!";
//! let signature = signing_key.sign(message).unwrap();
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of ML-DSA-65 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = ml_dsa_65::PK_LEN;

/// Size of ML-DSA-65 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = ml_dsa_65::SK_LEN;

/// Size of ML-DSA-65 signature in bytes.
pub const SIGNATURE_SIZE: usize = ml_dsa_65::SIG_LEN;

/// ML-DSA-65 signing key (secret key).
///
/// This key is used to create signatures. It contains the secret key material
/// and is zeroized on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65SigningKey {
    bytes: [u8; SECRET_KEY_SIZE],
}

impl MlDsa65SigningKey {
    /// Generates a new random signing key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    pub fn generate() -> Result<Self> {
        // Create a CSPRNG that implements CryptoRngCore
        let mut rng = CsprngAdapter::new()?;
        let (_pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        Ok(Self {
            bytes: sk.into_bytes(),
        })
    }

    /// Generates a signing key deterministically from a 32-byte seed.
    ///
    /// This is used for recovery key derivation where the same seed must
    /// always produce the same key.
    ///
    /// # Errors
    ///
    /// Returns `KeyGenerationFailed` if key generation fails internally.
    pub fn generate_from_seed(seed: &[u8; 32]) -> Result<Self> {
        let mut rng = DeterministicRng::new(seed);
        let (_pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        Ok(Self {
            bytes: sk.into_bytes(),
        })
    }

    /// Creates a signing key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice length is wrong, or
    /// `KeyGenerationFailed` if the bytes don't represent a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        // Validate by attempting to expand the key
        let _ = ml_dsa_65::PrivateKey::try_from_bytes(key_bytes)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        Ok(Self { bytes: key_bytes })
    }

    /// Returns the secret key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> MlDsa65VerifyingKey {
        // Expand the private key and extract the public key
        // self.bytes was validated in the constructor; re-parsing is infallible.
        #[allow(clippy::expect_used)]
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(self.bytes)
            .expect("key bytes validated in constructor");
        let pk = sk.get_public_key();
        MlDsa65VerifyingKey {
            bytes: pk.into_bytes(),
        }
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The ML-DSA-65 signature (3,309 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if signing fails (e.g., RNG failure).
    pub fn sign(&self, message: &[u8]) -> Result<MlDsa65Signature> {
        // self.bytes was validated in the constructor; re-parsing is infallible.
        #[allow(clippy::expect_used)]
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(self.bytes)
            .expect("key bytes validated in constructor");
        let mut rng = CsprngAdapter::new()?;
        let sig = sk
            .try_sign_with_rng(&mut rng, message, &[])
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(MlDsa65Signature { bytes: sig })
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
    /// The ML-DSA-65 signature (3,309 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes,
    /// or `InvalidSignature` if signing fails.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<MlDsa65Signature> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        // self.bytes was validated in the constructor; re-parsing is infallible.
        #[allow(clippy::expect_used)]
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(self.bytes)
            .expect("key bytes validated in constructor");
        let mut rng = CsprngAdapter::new()?;
        let sig = sk
            .try_sign_with_rng(&mut rng, message, context)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(MlDsa65Signature { bytes: sig })
    }

    /// Signs a message using a **hedged-entropy RNG** so the signing
    /// randomness is bound to both the message and a fresh per-call
    /// random value.
    ///
    /// This is the spec's recommended ML-DSA-65 signing variant (see
    /// `crypto-spec/sections/05-signature-schemes.tex` §5.5). The hedge
    /// pattern is:
    ///
    /// ```text
    /// fresh_random   := system_RNG(32 bytes)
    /// hedge_entropy  := BLAKE3-derive_key(MLDSA_HEDGE_CONTEXT,
    ///                                     fresh_random || message)
    /// signing_RNG    := DeterministicRng(hedge_entropy)
    /// signature      := ml_dsa_65.try_sign_with_rng(signing_RNG, message, "")
    /// ```
    ///
    /// Compared to plain `sign`, hedging adds defence-in-depth: a
    /// partially-predictable system RNG cannot reveal the per-signature
    /// nonce, because the actual signing RNG is a deterministic PRNG keyed
    /// by both the fresh random AND the message digest. The signature
    /// produced is still a valid ML-DSA-65 signature that verifies under
    /// the standard `verify` path — the wire bytes are unchanged.
    ///
    /// # Errors
    ///
    /// - `RngFailure` if the system CSPRNG fails (still needed for the
    ///   fresh random input to the hedge).
    /// - `InvalidSignature` if the underlying ML-DSA-65 signing fails.
    pub fn sign_hedged(&self, message: &[u8]) -> Result<MlDsa65Signature> {
        // Fresh random input to the hedge — without this the construction
        // collapses to deterministic signing (which is also a valid mode but
        // is not what "hedged" means).
        let mut fresh_random = [0u8; 32];
        fill_bytes(&mut fresh_random)?;

        // hedge_entropy = BLAKE3-derive_key(MLDSA_HEDGE_CONTEXT,
        //                                   fresh_random || message)
        let mut hasher = blake3::Hasher::new_derive_key(crate::blake3_kdf::MLDSA_HEDGE_CONTEXT);
        hasher.update(&fresh_random);
        hasher.update(message);
        let mut hedge_entropy: [u8; 32] = *hasher.finalize().as_bytes();

        // Wipe the fresh_random bytes before the signing call — the hedge
        // entropy is downstream of them and the value is no longer needed.
        zeroize::Zeroize::zeroize(&mut fresh_random[..]);

        // `DeterministicRng::new` copies the seed into its own `state` field
        // (`state: *seed`), so the rng Zeroize-on-drops *its* copy of the seed
        // and per-block state. The `hedge_entropy` stack local is an
        // independent copy of the signing-RNG seed (key-recovery material),
        // so it must be wiped separately once the rng has taken its copy.
        let mut rng = DeterministicRng::new(&hedge_entropy);
        zeroize::Zeroize::zeroize(&mut hedge_entropy[..]);

        // self.bytes was validated in the constructor; re-parsing is infallible.
        #[allow(clippy::expect_used)]
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(self.bytes)
            .expect("key bytes validated in constructor");
        let sig = sk
            .try_sign_with_rng(&mut rng, message, &[])
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(MlDsa65Signature { bytes: sig })
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
    /// let sk = MlDsa65SigningKey::generate()?;
    /// let guarded = sk.into_guarded()?;
    /// guarded.protect_readonly()?; // Optional: make read-only after init
    /// let sig = guarded.sign(message)?;
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

/// ML-DSA-65 verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
#[derive(Clone)]
pub struct MlDsa65VerifyingKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl MlDsa65VerifyingKey {
    /// Creates a verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 1,952 bytes,
    /// or `SignatureVerificationFailed` if the bytes don't represent a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        // Validate by attempting to expand the key
        let _ = ml_dsa_65::PublicKey::try_from_bytes(key_bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        Ok(Self { bytes: key_bytes })
    }

    /// Creates a verifying key from a fixed-size array.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if the bytes don't represent a valid key.
    pub fn from_array(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self> {
        // Validate by attempting to expand the key
        let _ = ml_dsa_65::PublicKey::try_from_bytes(bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        Ok(Self { bytes })
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
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
    pub fn verify(&self, message: &[u8], signature: &MlDsa65Signature) -> Result<()> {
        let pk = ml_dsa_65::PublicKey::try_from_bytes(self.bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        if pk.verify(message, &signature.bytes, &[]) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
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
    /// Returns `SignatureVerificationFailed` if the signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsa65Signature,
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        let pk = ml_dsa_65::PublicKey::try_from_bytes(self.bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        if pk.verify(message, &signature.bytes, context) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl PartialEq for MlDsa65VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for MlDsa65VerifyingKey {}

impl core::fmt::Debug for MlDsa65VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65VerifyingKey")
            .field("bytes", &"[1952 bytes]")
            .finish()
    }
}

/// ML-DSA-65 signature.
#[derive(Clone)]
pub struct MlDsa65Signature {
    bytes: [u8; SIGNATURE_SIZE],
}

impl MlDsa65Signature {
    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 3,309 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: sig_bytes })
    }

    /// Creates a signature from a fixed-size array.
    #[must_use]
    pub const fn from_array(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.bytes
    }
}

impl ConstantTimeEq for MlDsa65Signature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for MlDsa65Signature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MlDsa65Signature {}

impl core::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65Signature")
            .field("bytes", &"[3309 bytes]")
            .finish()
    }
}

/// CSPRNG adapter that wraps our random module.
///
/// This allows us to use our getrandom-based RNG with fips204's CryptoRngCore trait.
///
/// # RNG Availability
///
/// The adapter pre-validates RNG availability during construction to fail early
/// with a proper error rather than panicking later during signing operations.
struct CsprngAdapter {
    /// Pre-fetched entropy to validate RNG availability and provide initial bytes.
    /// This ensures we fail at construction time if the RNG is unavailable.
    _validated: (),
}

impl CsprngAdapter {
    /// Creates a new CSPRNG adapter, validating that the system RNG is available.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG is not available (e.g., during
    /// early boot when entropy pool is not yet initialised).
    fn new() -> Result<Self> {
        // Pre-validate RNG availability by requesting a small amount of entropy.
        // This ensures we fail early with a proper error rather than panicking
        // later during signing when fill_bytes is called.
        let mut test = [0u8; 8];
        fill_bytes(&mut test)?;
        Ok(Self { _validated: () })
    }
}

impl fips204::RngCore for CsprngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    #[allow(clippy::expect_used)] // RngCore::fill_bytes is infallible by trait contract
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Delegate to try_fill_bytes for consistent error handling.
        // The RNG was validated during construction, so failure here indicates
        // a serious system issue (RNG became unavailable mid-operation).
        self.try_fill_bytes(dest)
            .expect("CSPRNG failed unexpectedly after successful validation");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), fips204::RngError> {
        fill_bytes(dest).map_err(|_| {
            // Use a custom error code for CSPRNG failure.
            // CUSTOM_START is a compile-time constant > 0, so NonZeroU32::new returns Some.
            #[allow(clippy::expect_used)]
            core::num::NonZeroU32::new(fips204::RngError::CUSTOM_START)
                .map(fips204::RngError::from)
                .expect("CUSTOM_START is non-zero")
        })
    }
}

impl fips204::CryptoRng for CsprngAdapter {}

/// Deterministic PRNG based on BLAKE3 for seed-based key generation.
///
/// This generates a stream of pseudo-random bytes from a 32-byte seed,
/// ensuring the same seed always produces the same output.
///
/// The state is zeroized on drop to prevent seed material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DeterministicRng {
    state: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            state: *seed,
            counter: 0,
        }
    }

    fn next_block(&mut self) -> [u8; 32] {
        // Use BLAKE3 keyed hash as a simple PRNG
        // state = BLAKE3(state || counter)
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.state);
        input[32..40].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        self.state = blake3::hash(&input).into();
        self.state
    }
}

impl fips204::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            let block = self.next_block();
            let copy_len = core::cmp::min(32, dest.len() - offset);
            dest[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), fips204::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl fips204::CryptoRng for DeterministicRng {}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_key_sizes() {
        // Verify sizes match FIPS 204 ML-DSA-65 specification
        assert_eq!(PUBLIC_KEY_SIZE, 1952);
        assert_eq!(SECRET_KEY_SIZE, 4032);
        assert_eq!(SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_key_generation() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, ML-DSA-65!";
        let signature = signing_key.sign(message).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test").unwrap();

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature = signing_key.sign(message).unwrap();

        let wrong_message = b"wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key1 = MlDsa65SigningKey::generate().unwrap();
        let signing_key2 = MlDsa65SigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message).unwrap();

        // Verify with wrong key should fail
        assert!(verifying_key2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_empty_message() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message).unwrap();

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    /// SIG-01 regression: sign_hedged is non-deterministic (same key + same
    /// message → distinct signatures across calls) because the per-signature
    /// entropy is hedged with fresh system randomness.
    #[test]
    fn test_sign_hedged_non_deterministic() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let message = b"hedged signing must not be deterministic";

        let sig1 = signing_key.sign_hedged(message).unwrap();
        let sig2 = signing_key.sign_hedged(message).unwrap();

        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "hedged signatures over the same message must differ"
        );
    }

    /// SIG-01 regression: hedged signatures verify under the standard verify
    /// path. The wire bytes are still a valid ML-DSA-65 signature; hedging
    /// only changes how the signing-side RNG is derived.
    #[test]
    fn test_sign_hedged_verifies_under_standard_verify() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let message = b"hedged signature still verifies normally";

        let sig = signing_key.sign_hedged(message).unwrap();

        assert!(
            verifying_key.verify(message, &sig).is_ok(),
            "hedged signature must verify under the unchanged verify path"
        );
    }

    /// HARD-03: hedged ML-DSA-65 signing fails closed on an RNG fault. With the
    /// CSPRNG forced to fail, `sign_hedged` must return `RngFailure` and produce
    /// no signature — it never silently falls back to deterministic signing.
    /// Disarming restores the happy path (the fault hook is not sticky). The
    /// fault flag is thread-local under `cfg(test)`, so this KAT is safe under
    /// cargo's parallel test runner.
    #[test]
    fn test_sign_hedged_fails_closed_on_rng_fault() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let message = b"hedged signing must fail closed when the CSPRNG fails";

        // Arm the fault on this thread, then attempt a hedged signature. Disarm
        // immediately so the happy-path assertion below is unaffected even if
        // the assertion between them were to panic.
        crate::random::set_force_rng_failure(true);
        let armed_result = signing_key.sign_hedged(message);
        crate::random::set_force_rng_failure(false);

        assert!(
            matches!(armed_result, Err(CryptoError::RngFailure)),
            "hedged signing must fail closed with RngFailure, never fall back \
             to deterministic signing"
        );

        // The hook is not sticky: once disarmed, hedged signing succeeds again.
        let recovered = signing_key.sign_hedged(message);
        assert!(
            recovered.is_ok(),
            "hedged signing must succeed after the forced fault is cleared"
        );
    }

    #[test]
    fn test_context_string() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
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
        assert!(
            verifying_key
                .verify_with_context(message, b"wrong-context", &signature)
                .is_err()
        );

        // Verify without context should fail
        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = MlDsa65VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test").unwrap();

        let bytes = signature.to_bytes();
        let recovered = MlDsa65Signature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = MlDsa65Signature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_key_length() {
        let result = MlDsa65VerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 1952,
                actual: 50
            })
        ));
    }

    #[test]
    fn test_signing_key_from_bytes_roundtrip() {
        let signing_key = MlDsa65SigningKey::generate().unwrap();
        let bytes = signing_key.as_bytes().clone();

        let recovered = MlDsa65SigningKey::from_bytes(&bytes).unwrap();

        // Sign with both keys and verify they produce working signatures
        let message = b"test roundtrip";
        let sig1 = signing_key.sign(message).unwrap();
        let sig2 = recovered.sign(message).unwrap();

        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &sig1).is_ok());
        assert!(verifying_key.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_generate_from_seed_deterministic() {
        let seed = [0x42u8; 32];

        let key1 = MlDsa65SigningKey::generate_from_seed(&seed).unwrap();
        let key2 = MlDsa65SigningKey::generate_from_seed(&seed).unwrap();

        // Same seed should produce identical keys
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_from_seed_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let key1 = MlDsa65SigningKey::generate_from_seed(&seed1).unwrap();
        let key2 = MlDsa65SigningKey::generate_from_seed(&seed2).unwrap();

        // Different seeds should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_from_seed_sign_verify() {
        let seed = [0xAAu8; 32];
        let key = MlDsa65SigningKey::generate_from_seed(&seed).unwrap();

        let message = b"Test message for seeded key";
        let signature = key.sign(message).unwrap();

        assert!(key.verifying_key().verify(message, &signature).is_ok());
        assert!(
            key.verifying_key()
                .verify(b"wrong message", &signature)
                .is_err()
        );
    }

    /// `DeterministicRng` carries the hedge-entropy seed and the per-block
    /// PRNG state in-struct, so both fields must be wiped by `Zeroize`.
    /// `ZeroizeOnDrop` is implemented in terms of `Zeroize::zeroize()`, so
    /// this test exercises the wipe directly rather than reading bytes
    /// after drop (which would be undefined behaviour).
    #[test]
    fn test_deterministic_rng_zeroize_wipes_state() {
        let seed = [0xAAu8; 32];
        let mut rng = DeterministicRng::new(&seed);
        // Advance the counter so we know both fields hold non-zero values
        // before the wipe.
        let _ = rng.next_block();
        assert_ne!(rng.state, [0u8; 32], "state must be non-zero before wipe");
        assert_ne!(rng.counter, 0, "counter must be non-zero before wipe");

        rng.zeroize();

        assert_eq!(rng.state, [0u8; 32], "state must be wiped");
        assert_eq!(rng.counter, 0, "counter must be wiped");
    }
}
