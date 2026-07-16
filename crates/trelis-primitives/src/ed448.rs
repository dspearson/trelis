//! Ed448 signature primitives.
//!
//! This module provides Ed448 digital signatures as specified in RFC 8032.
//! Ed448 is the Edwards-curve Digital Signature Algorithm using Curve448,
//! providing approximately 224-bit CLASSICAL security (EUF-CMA / ECDLP on
//! Curve448, RFC 8032). NIST PQC categories are a post-quantum-only taxonomy
//! and do not apply to a classical curve; Ed448 has zero quantum security —
//! broken in polynomial time by Shor's algorithm.
//!
//! # Key Sizes
//!
//! - Public key: 57 bytes
//! - Secret key: 57 bytes (seed)
//! - Signature: 114 bytes
//!
//! # Security Properties
//!
//! - Deterministic signatures (no randomness needed for signing)
//! - Strong unforgeability under chosen message attacks (SUF-CMA)
//! - Resistance to side-channel attacks when implemented correctly
//!
//! # Examples
//!
//! ```
//! use trelis_primitives::ed448::{Ed448SigningKey, Ed448VerifyingKey};
//!
//! // Generate a new signing key
//! let signing_key = Ed448SigningKey::generate().unwrap();
//!
//! // Get the corresponding verifying key
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, Trelis!";
//! let signature = signing_key.sign(message);
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```

use ed448_goldilocks_plus::{
    CompressedEdwardsY, EdwardsPoint, Scalar, ScalarBytes, Signature, SigningKey, VerifyingKey,
    WideScalarBytes,
    sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    },
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random::fill_bytes;
use trelis_error::{CryptoError, Result};

/// Size of Ed448 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// Size of Ed448 secret key (seed) in bytes.
pub const SECRET_KEY_SIZE: usize = 57;

/// Size of Ed448 signature in bytes.
pub const SIGNATURE_SIZE: usize = 114;

/// Size of an Ed448 Bird-of-Prey-2 Schnorr response (`rsp`) in bytes.
///
/// The response is a scalar encoded in the RFC 8032 57-byte form (56 canonical
/// little-endian bytes followed by a zero byte). It is the classical half of a
/// Bird-of-Prey-2 hybrid signature (Janneck, ePrint 2025/1844, Fig. 6).
pub const ED448_BOP_RESPONSE_SIZE: usize = 57;

/// Ed448 signing key (secret key).
///
/// This key is used to create signatures. It contains the secret seed
/// and is zeroized on drop to prevent key material leakage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed448SigningKey {
    seed: [u8; SECRET_KEY_SIZE],
    /// The RFC 8032 clamped Bird-of-Prey-2 secret scalar `s`, precomputed once
    /// from `seed` at construction (PRF-01). It is a pure function of the
    /// immutable seed — bit-identical to what [`bop_secret_scalar`] returns — so
    /// caching it leaves every signature byte unchanged while removing the
    /// per-signature SHAKE256 expansion from the `bop_commit` hot path. `Scalar`
    /// implements `Zeroize` (see the `Ed448BopSecretNonce` `Zeroize` impl below),
    /// so the `Zeroize`/`ZeroizeOnDrop` derive stays valid and the cached secret
    /// wipes on drop exactly like the seed.
    secret_scalar: Scalar,
}

impl Ed448SigningKey {
    /// Generates a new random signing key.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SECRET_KEY_SIZE];
        fill_bytes(&mut seed)?;
        // Precompute the BoP-2 secret scalar once (PRF-01); it is a pure function
        // of the immutable seed, so this is byte-transparent to every signature.
        let secret_scalar = bop_secret_scalar(&seed);
        Ok(Self {
            seed,
            secret_scalar,
        })
    }

    /// Creates a signing key from a seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 57-byte secret seed.
    #[must_use]
    pub fn from_seed(seed: [u8; SECRET_KEY_SIZE]) -> Self {
        // Precompute the BoP-2 secret scalar once (PRF-01). SHAKE256 is not
        // const-evaluable, so this constructor is no longer `const fn`; every
        // caller is a runtime `let`, so no const-context use is broken.
        let secret_scalar = bop_secret_scalar(&seed);
        Self {
            seed,
            secret_scalar,
        }
    }

    /// Returns the seed bytes.
    #[must_use]
    pub fn seed(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Get the internal signing key for operations.
    fn inner_signing_key(&self) -> SigningKey {
        let scalar_bytes = ScalarBytes::clone_from_slice(&self.seed);
        SigningKey::from(scalar_bytes)
    }

    /// Derives the verifying (public) key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed448VerifyingKey {
        let sk = self.inner_signing_key();
        let pk = sk.verifying_key();
        Ed448VerifyingKey { inner: pk }
    }

    /// Signs a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The Ed448 signature (114 bytes).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Ed448Signature {
        let sk = self.inner_signing_key();
        let sig = sk.sign_raw(message);
        Ed448Signature { inner: sig }
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
    /// The Ed448 signature (114 bytes), or an error if context is too long.
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes,
    /// or `InvalidSignature` if signing fails.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Ed448Signature> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        let sk = self.inner_signing_key();
        let sig = sk
            .sign_ctx(context, message)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Ed448Signature { inner: sig })
    }

    /// Produces a Bird-of-Prey-2 Schnorr commitment for hybrid signing.
    ///
    /// Samples a fresh Schnorr nonce `r` from the system CSPRNG, computes the
    /// commitment `R = r·B` (compressed to 57 bytes), and returns it alongside
    /// an opaque, zeroize-on-drop secret nonce holding `r` and the RFC 8032
    /// clamped secret scalar `s`. The caller binds `R` into `m'`, obtains the
    /// ML-DSA signature `σ₂`, then calls [`Ed448BopSecretNonce::respond`] with
    /// `chl = H2(σ₂)` to finish the response. This is the classical half of the
    /// Bird-of-Prey-2 SUF-preserving combiner (Janneck, ePrint 2025/1844,
    /// Fig. 6): the challenge is `H2(σ₂)`, not EdDSA's usual `H(R‖A‖M)`, so the
    /// crate's black-box `sign()` cannot be used and the commit/response is built
    /// from the public `Scalar`/`EdwardsPoint` primitives.
    ///
    /// A fresh nonce is sampled on every call and is never cached or reused
    /// (reusing `r` across two signatures would leak `s`).
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails.
    pub fn bop_commit(&self) -> Result<(Ed448BopCommitment, Ed448BopSecretNonce)> {
        // Read the precomputed secret scalar (PRF-01) instead of re-deriving it
        // via SHAKE256 on every signature. `Scalar: Copy`, so this copies the
        // cached value out of `&self`; it is identical to the former per-call
        // `bop_secret_scalar(&self.seed)`, so signature bytes are unchanged.
        let s = self.secret_scalar;
        // Fresh Schnorr nonce r via a 114-byte wide reduction (matching
        // `Scalar::random` semantics — negligible modulo bias) drawn from the
        // crate's fallible CSPRNG rather than a panicking rand_core adapter.
        let mut buf = [0u8; 114];
        fill_bytes(&mut buf)?;
        let r = Scalar::from_bytes_mod_order_wide(&WideScalarBytes::clone_from_slice(&buf));
        buf.zeroize();
        let commitment = Ed448BopCommitment((EdwardsPoint::GENERATOR * r).compress().0);
        Ok((commitment, Ed448BopSecretNonce { r, s }))
    }

    /// Deterministically derives a Bird-of-Prey-2 commitment from a nonce seed.
    ///
    /// **TEST / VECTOR-GENERATION ONLY — MUST NOT sign real messages.** This
    /// derives the Schnorr nonce `r` deterministically from `nonce_seed` (via a
    /// domain-separated BLAKE3 XOF) instead of the CSPRNG, so byte-exact
    /// known-answer test vectors can be reproduced (plan 04 emits
    /// `vectors/hybrid-sig.json`). It is gated behind `test` / the
    /// `expose-internals` feature so it cannot be reached from a production
    /// signing path. Using it to sign real messages is unsafe: reusing a nonce
    /// seed across two different messages leaks the secret scalar `s` (classic
    /// Schnorr nonce reuse — RESEARCH Pitfall 3).
    ///
    /// # Errors
    ///
    /// Never fails in practice; returns `Result` for API symmetry with
    /// [`Ed448SigningKey::bop_commit`].
    #[cfg(any(test, feature = "expose-internals"))]
    pub fn bop_commit_deterministic(
        &self,
        nonce_seed: &[u8; 32],
    ) -> Result<(Ed448BopCommitment, Ed448BopSecretNonce)> {
        // Read the precomputed secret scalar (PRF-01) — the same cached value the
        // production `bop_commit` uses, so this KAT/vector-generation path stays
        // byte-identical.
        let s = self.secret_scalar;
        // Deterministic nonce r = wide_reduce(BLAKE3-XOF_derive_key(ctx, seed)),
        // derived from the seed BEFORE the commitment (mirrors EdDSA nonce
        // derivation). NOT for production use — see the method doc.
        let mut hasher = blake3::Hasher::new_derive_key(BOP_DET_NONCE_CONTEXT);
        hasher.update(nonce_seed);
        let mut wide = WideScalarBytes::default();
        hasher.finalize_xof().fill(&mut wide);
        let r = Scalar::from_bytes_mod_order_wide(&wide);
        // Wipe the secret nonce expansion once `r` is derived (test/vector-gen
        // path, but keep parity with the production zeroization discipline).
        wide.zeroize();
        let commitment = Ed448BopCommitment((EdwardsPoint::GENERATOR * r).compress().0);
        Ok((commitment, Ed448BopSecretNonce { r, s }))
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
    /// let sk = Ed448SigningKey::generate()?;
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

/// Ed448 verifying key (public key).
///
/// This key is used to verify signatures created by the corresponding
/// signing key.
#[derive(Clone)]
pub struct Ed448VerifyingKey {
    inner: VerifyingKey,
}

impl Ed448VerifyingKey {
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
        let inner = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        Ok(Self { inner })
    }

    /// Returns the public key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Returns the public key as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
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
    pub fn verify(&self, message: &[u8], signature: &Ed448Signature) -> Result<()> {
        self.inner
            .verify_raw(&signature.inner, message)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
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
    #[must_use = "the verify outcome must be checked"]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Ed448Signature,
    ) -> Result<()> {
        if context.len() > 255 {
            return Err(CryptoError::InvalidContextLength {
                actual: context.len(),
                max: 255,
            });
        }
        self.inner
            .verify_ctx(&signature.inner, context, message)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Reconstructs the Bird-of-Prey-2 commitment `R` from a response (verifier side).
    ///
    /// Applies the Unique-Responses (UR) guard to `rsp`, decompresses this key's
    /// point `A`, reduces the 114-byte challenge identically to the signer, and
    /// computes the Schnorr extractor `R = rsp·B − chl·A`. The caller then
    /// recomputes `m' = H1(pkID ‖ pkSig ‖ m ‖ R)` and checks `σ₂` under ML-DSA.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if `rsp` is non-canonical (the UR
    /// guard, which is the SUF-CMA linchpin) or if this key does not decode to a
    /// valid curve point.
    #[must_use = "the reconstructed commitment must be checked by the caller"]
    pub fn bop_extcom(
        &self,
        challenge_wide: &[u8; 114],
        rsp: &Ed448BopResponse,
    ) -> Result<Ed448BopCommitment> {
        let rsp_scalar = rsp
            .to_scalar()
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        let a =
            Option::<EdwardsPoint>::from(CompressedEdwardsY(self.inner.to_bytes()).decompress())
                .ok_or(CryptoError::SignatureVerificationFailed)?;
        let chl = bop_reduce_challenge(challenge_wide);
        // ExtCom: R = rsp·B − chl·A (the standard Schnorr identity solved for R).
        let r = EdwardsPoint::GENERATOR * rsp_scalar - a * chl;
        Ok(Ed448BopCommitment(r.compress().0))
    }
}

impl PartialEq for Ed448VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Ed448VerifyingKey {}

impl core::fmt::Debug for Ed448VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak key material in debug output
        f.debug_struct("Ed448VerifyingKey")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Ed448 signature.
#[derive(Clone)]
pub struct Ed448Signature {
    inner: Signature,
}

impl Ed448Signature {
    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 114 bytes
    /// or if the bytes don't represent a valid signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        let inner = Signature::from_bytes(&sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self { inner })
    }

    /// Returns the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.inner.to_bytes()
    }

    /// Returns the signature as a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.inner.to_bytes()
    }
}

impl ConstantTimeEq for Ed448Signature {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for Ed448Signature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Ed448Signature {}

impl core::fmt::Debug for Ed448Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed448Signature")
            .field("bytes", &"[114 bytes]")
            .finish()
    }
}

// ============================================================================
// Bird-of-Prey-2 (BoP-2) Schnorr surface (plan 49-02, CMB-02 / v1.5 F03)
//
// BoP-2 (Janneck, ePrint 2025/1844, Fig. 6) composes the Ed448 Schnorr
// identification scheme with a black-box ML-DSA signature into a SUF-preserving
// hybrid combiner. Because the classical challenge is `chl = H2(σ₂)` rather than
// EdDSA's `H(R‖A‖M)`, the crate exposes no black-box API to produce the Schnorr
// response, so the commit/response is reimplemented here from the public
// `Scalar`/`EdwardsPoint` primitives (the "vendor/reimplement when upstream
// blocks the stronger construction" pattern). This surface is additive: the
// standard `sign()`/`verify()` paths above are untouched.
// ============================================================================

/// Domain-separation context for the **test-only** deterministic BoP nonce.
///
/// Used exclusively by [`Ed448SigningKey::bop_commit_deterministic`] for
/// reproducible KAT vector generation — never on a production signing path.
#[cfg(any(test, feature = "expose-internals"))]
const BOP_DET_NONCE_CONTEXT: &str = "trelis-ed448-bop-det-nonce-v1";

/// Re-derives the RFC 8032 clamped Ed448 secret scalar `s` from a 57-byte seed.
///
/// This reproduces `ed448-goldilocks-plus`'s own `ExpandedSecretKey::from_seed`
/// expansion exactly — `SHAKE256(seed) → 114 bytes`, take the first 57, clamp
/// `[0] &= 0xFC; [56] = 0; [55] |= 0x80`, then reduce mod L — so that
/// `EdwardsPoint::GENERATOR * s` equals the standard Ed448 verifying key. BoP-2
/// needs the clamped scalar to form `rsp = r + chl·s`; the anchor test
/// `bop_secret_scalar_matches_verifying_key` fails loudly on any drift. The
/// returned scalar is secret and is zeroized by the caller via
/// [`Ed448BopSecretNonce`].
fn bop_secret_scalar(seed: &[u8; SECRET_KEY_SIZE]) -> Scalar {
    let mut reader = Shake256::default().chain(seed).finalize_xof();
    let mut wide = WideScalarBytes::default();
    reader.read(&mut wide);
    let mut scalar_bytes = ScalarBytes::default();
    scalar_bytes.copy_from_slice(&wide[..SECRET_KEY_SIZE]);
    // RFC 8032 Ed448 clamp.
    scalar_bytes[0] &= 0xFC;
    scalar_bytes[56] = 0;
    scalar_bytes[55] |= 0x80;
    let s = Scalar::from_bytes_mod_order(&scalar_bytes);
    // Zeroize the secret intermediates before returning: `wide` holds the full
    // SHAKE256(seed) expansion (secret-scalar half + RFC 8032 nonce-prefix half)
    // and `scalar_bytes` holds the clamped secret scalar. Neither `GenericArray`
    // zeroizes on drop, so wipe them explicitly — matching `bop_commit`'s
    // `buf.zeroize()` and the crate's co-located-process threat model. The
    // derived scalar value `s` is unchanged (the anchor test still passes).
    wide.zeroize();
    scalar_bytes.zeroize();
    s
}

/// Reduces a 114-byte wide challenge (`H2(σ₂)` output) into an Ed448 scalar.
///
/// Both the signer ([`Ed448BopSecretNonce::respond`]) and the verifier
/// ([`Ed448VerifyingKey::bop_extcom`]) use this identical wide reduction so the
/// challenge scalar matches on both sides. A 114-byte input gives negligible
/// modulo bias (`from_bytes_mod_order_wide`).
fn bop_reduce_challenge(challenge_wide: &[u8; 114]) -> Scalar {
    let wide = WideScalarBytes::clone_from_slice(challenge_wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A Bird-of-Prey-2 Schnorr commitment: the 57-byte compressed point `R`.
///
/// Emitted by [`Ed448SigningKey::bop_commit`] and reconstructed by
/// [`Ed448VerifyingKey::bop_extcom`]. It carries no secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed448BopCommitment([u8; PUBLIC_KEY_SIZE]);

impl Ed448BopCommitment {
    /// Returns the 57-byte compressed commitment `R`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
}

/// A Bird-of-Prey-2 Schnorr response `rsp`, canonically encoded in 57 bytes.
///
/// The response is decoded with a Unique-Responses (UR) guard: byte 56 must be
/// zero and the low 56 bytes must be a canonical scalar (`< L`). This guard is
/// the SUF-CMA linchpin — a non-canonical `rsp` (e.g. `rsp + L`, the same scalar
/// value) MUST be rejected, or strong unforgeability silently breaks. Decoding
/// uses `Scalar::from_canonical_bytes`, never `from_bytes_mod_order`.
#[derive(Clone, Debug)]
pub struct Ed448BopResponse([u8; ED448_BOP_RESPONSE_SIZE]);

impl Ed448BopResponse {
    /// Decodes a response from raw bytes, applying the UR canonicality guard.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the slice is not exactly 57 bytes, if byte
    /// 56 is non-zero, or if the low 56 bytes are not a canonical scalar
    /// (`≥ L`). Non-canonical encodings are rejected to preserve Unique
    /// Responses (and therefore SUF-CMA).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ED448_BOP_RESPONSE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut buf = [0u8; ED448_BOP_RESPONSE_SIZE];
        buf.copy_from_slice(bytes);
        Self::guard_canonical(&buf)?;
        Ok(Self(buf))
    }

    /// Returns the canonical 57-byte response encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED448_BOP_RESPONSE_SIZE] {
        &self.0
    }

    /// Builds a response from a scalar (always canonical: `rsp < L`, byte 56 = 0).
    fn from_scalar(rsp: Scalar) -> Self {
        let mut buf = [0u8; ED448_BOP_RESPONSE_SIZE];
        buf[..56].copy_from_slice(&rsp.to_bytes());
        // Byte 56 stays 0x00 — the RFC 8032 canonical form.
        Self(buf)
    }

    /// UR guard: byte 56 must be zero (constant-time) and the low 56 bytes must
    /// decode as a canonical scalar (`< L`).
    ///
    /// `from_canonical_bytes` only inspects 56 bytes, so byte 56 is checked
    /// explicitly; `from_bytes_mod_order` is deliberately NOT used because it
    /// would reduce mod L and accept `rsp + L`, breaking Unique Responses.
    fn guard_canonical(bytes: &[u8; ED448_BOP_RESPONSE_SIZE]) -> Result<()> {
        if !bool::from(bytes[56].ct_eq(&0u8)) {
            return Err(CryptoError::InvalidSignature);
        }
        let sb = ScalarBytes::clone_from_slice(bytes);
        if Option::<Scalar>::from(Scalar::from_canonical_bytes(&sb)).is_none() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }

    /// Re-derives the scalar, re-applying the UR guard (defence in depth).
    fn to_scalar(&self) -> Result<Scalar> {
        Self::guard_canonical(&self.0)?;
        let sb = ScalarBytes::clone_from_slice(&self.0);
        Option::<Scalar>::from(Scalar::from_canonical_bytes(&sb))
            .ok_or(CryptoError::InvalidSignature)
    }
}

/// An opaque, zeroize-on-drop Bird-of-Prey-2 secret nonce.
///
/// Holds the Schnorr nonce `r` and the re-derived clamped secret scalar `s`
/// between [`Ed448SigningKey::bop_commit`] and [`Ed448BopSecretNonce::respond`].
/// Both scalars are zeroized on drop and neither is ever exposed. The nonce MUST
/// be consumed exactly once (by `respond`) and MUST NOT be reused across
/// signatures.
pub struct Ed448BopSecretNonce {
    r: Scalar,
    s: Scalar,
}

impl Ed448BopSecretNonce {
    /// Completes the Schnorr response `rsp = r + chl·s (mod L)`, consuming the nonce.
    ///
    /// `challenge_wide` is the 114-byte `H2(σ₂)` output; it is reduced into the
    /// challenge scalar identically to the verifier. The nonce is zeroized as it
    /// is consumed (its `Drop`). The returned response is public.
    #[must_use]
    pub fn respond(self, challenge_wide: &[u8; 114]) -> Ed448BopResponse {
        let chl = bop_reduce_challenge(challenge_wide);
        let rsp = self.r + chl * self.s;
        Ed448BopResponse::from_scalar(rsp)
        // `self` is dropped here, zeroizing `r` and `s`.
    }
}

impl Zeroize for Ed448BopSecretNonce {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
    }
}

impl Drop for Ed448BopSecretNonce {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Ed448BopSecretNonce {}

impl core::fmt::Debug for Ed448BopSecretNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never leak secret scalar material in debug output.
        f.debug_struct("Ed448BopSecretNonce")
            .field("r", &"[redacted]")
            .field("s", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    // === Bird-of-Prey-2 (BoP-2) Schnorr surface (plan 49-02) ===

    #[test]
    fn bop_secret_scalar_matches_verifying_key() {
        // Anchor (T-49-06): the re-derived clamped scalar s satisfies s·B == A,
        // matching the crate's SHAKE256 RFC-8032 expansion. If this drifts, the
        // BoP response will not verify.
        for _ in 0..8 {
            let sk = Ed448SigningKey::generate().unwrap();
            let s = bop_secret_scalar(sk.seed());
            let derived = (EdwardsPoint::GENERATOR * s).compress();
            assert_eq!(
                derived.0,
                sk.verifying_key().to_bytes(),
                "re-derived s·B must equal the standard Ed448 verifying key A"
            );
        }
    }

    #[test]
    fn secret_scalar_is_cached_and_matches_derivation() {
        // PRF-01 (T-60-01): the BoP-2 secret scalar is precomputed once at
        // construction and is bit-identical to the per-call derivation, so every
        // signature byte is unchanged. `Scalar` exposes no `PartialEq`, so each
        // equality is proven by effect — s·B is injective on secret scalars, so
        // comparing the compressed points compares the scalars. A = s·B is the
        // standard Ed448 verifying key, produced by the independent
        // `verifying_key()` path (upstream SHAKE256 expand + clamp); matching it
        // pins the cache to the vetted value.
        let sk = Ed448SigningKey::from_seed([7u8; SECRET_KEY_SIZE]);
        let a = sk.verifying_key().to_bytes();
        let cached_point = (EdwardsPoint::GENERATOR * sk.secret_scalar).compress().0;

        // (1) The cached scalar reproduces the standard Ed448 verifying key
        // A = s·B — the same value the vetted derivation yields, so KAT bytes
        // cannot drift.
        assert_eq!(
            cached_point, a,
            "cached secret_scalar must satisfy s·B == A"
        );

        // (2) The cached scalar equals the per-call free-function derivation of the
        // same seed (the value bop_commit re-derived on every call before PRF-01).
        let derived_point = (EdwardsPoint::GENERATOR * bop_secret_scalar(sk.seed()))
            .compress()
            .0;
        assert_eq!(
            cached_point, derived_point,
            "cached secret_scalar must equal the per-call bop_secret_scalar derivation"
        );

        // (3) Both bop_commit calls carry that cached scalar rather than a fresh
        // re-derivation: each returned nonce's secret s satisfies s·B == A. No
        // shared global counter is used (cargo runs tests in parallel), so this is
        // flake-free.
        for _ in 0..2 {
            let (_commitment, nonce) = sk.bop_commit().unwrap();
            assert_eq!(
                (EdwardsPoint::GENERATOR * nonce.s).compress().0,
                a,
                "each bop_commit nonce must carry the cached secret scalar (s·B == A)"
            );
        }
    }

    #[test]
    fn bop_commit_respond_extcom_roundtrip() {
        // commit -> respond -> extcom must reproduce the same commitment R for a
        // fixed challenge: rsp·B − chl·A == (r + chl·s)·B − chl·(s·B) == r·B == R.
        let sk = Ed448SigningKey::generate().unwrap();
        let vk = sk.verifying_key();
        let (commitment, nonce) = sk.bop_commit().unwrap();
        let challenge = [0x5au8; 114];
        let rsp = nonce.respond(&challenge);
        let recovered = vk.bop_extcom(&challenge, &rsp).unwrap();
        assert_eq!(
            recovered, commitment,
            "extcom(chl, respond(nonce, chl)) must equal the original commitment R"
        );
    }

    #[test]
    fn bop_commit_uses_fresh_nonce_each_call() {
        // Fresh CSPRNG nonce r per call => two commitments differ (Pitfall 3).
        let sk = Ed448SigningKey::generate().unwrap();
        let (c1, _) = sk.bop_commit().unwrap();
        let (c2, _) = sk.bop_commit().unwrap();
        assert_ne!(
            c1.as_bytes(),
            c2.as_bytes(),
            "each bop_commit must sample a fresh nonce"
        );
    }

    #[test]
    fn bop_response_rejects_non_canonical() {
        // UR / SUF linchpin (T-49-04): rsp + L (same scalar value, non-canonical
        // 57-byte encoding, byte 56 still 0) MUST be rejected by the canonical
        // decoder — this fails loudly if from_canonical_bytes is ever swapped for
        // from_bytes_mod_order.
        let sk = Ed448SigningKey::generate().unwrap();
        let (_commitment, nonce) = sk.bop_commit().unwrap();
        let challenge = [0x11u8; 114];
        let rsp = nonce.respond(&challenge);

        // Positive control (anti-tautology): the canonical response decodes.
        assert!(Ed448BopResponse::from_bytes(rsp.as_bytes()).is_ok());

        // Build L (the group order) as (L-1)+1 without hardcoding it: -ONE == L-1.
        let l_minus_1 = -Scalar::ONE;
        let mut l = [0u8; 57];
        l[..56].copy_from_slice(&l_minus_1.to_bytes());
        add_one_le(&mut l);

        // rsp + L: numerically >= L but < 2^448, so byte 56 stays 0 — this
        // exercises the canonical-scalar check specifically (not the byte-56 one).
        let rsp_plus_l = add_le(rsp.as_bytes(), &l);
        assert_eq!(
            rsp_plus_l[56], 0,
            "rsp + L must keep byte 56 zero for a genuine canonical-check witness"
        );
        assert!(
            Ed448BopResponse::from_bytes(&rsp_plus_l).is_err(),
            "rsp + L is non-canonical and MUST be rejected (from_canonical_bytes)"
        );
        // And bop_extcom must reject it too (the guard is re-applied verifier-side).
        let vk = sk.verifying_key();
        let forged = Ed448BopResponse(rsp_plus_l);
        assert!(vk.bop_extcom(&challenge, &forged).is_err());

        // Bonus: a non-zero byte 56 is also rejected.
        let mut bad56 = *rsp.as_bytes();
        bad56[56] = 0x01;
        assert!(
            Ed448BopResponse::from_bytes(&bad56).is_err(),
            "a non-zero byte 56 MUST be rejected"
        );
    }

    // Little-endian 57-byte add helpers for the rsp + L witness (test-only).
    fn add_one_le(bytes: &mut [u8; 57]) {
        let mut carry = 1u16;
        for b in bytes.iter_mut() {
            let v = u16::from(*b) + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
            if carry == 0 {
                break;
            }
        }
    }

    fn add_le(a: &[u8; 57], b: &[u8; 57]) -> [u8; 57] {
        let mut out = [0u8; 57];
        let mut carry = 0u16;
        for i in 0..57 {
            let v = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        out
    }

    #[test]
    fn bop_commit_deterministic_is_reproducible() {
        // T-49-16: the deterministic commit path reproduces R and rsp exactly
        // for a fixed seed (byte-exact KAT generation), still round-trips through
        // extcom, and differs for a different seed.
        let sk = Ed448SigningKey::generate().unwrap();
        let vk = sk.verifying_key();
        let seed = [0x33u8; 32];

        let (c1, n1) = sk.bop_commit_deterministic(&seed).unwrap();
        let (c2, n2) = sk.bop_commit_deterministic(&seed).unwrap();
        assert_eq!(c1, c2, "same nonce seed must reproduce commitment R");

        let challenge = [0x77u8; 114];
        let r1 = n1.respond(&challenge);
        let r2 = n2.respond(&challenge);
        assert_eq!(
            r1.as_bytes(),
            r2.as_bytes(),
            "same nonce seed and challenge must reproduce rsp"
        );

        // Still a valid, verifiable commit/respond/extcom triad.
        let (c3, n3) = sk.bop_commit_deterministic(&seed).unwrap();
        let r3 = n3.respond(&challenge);
        assert_eq!(vk.bop_extcom(&challenge, &r3).unwrap(), c3);

        // A different nonce seed yields a different commitment.
        let (c_other, _) = sk.bop_commit_deterministic(&[0x44u8; 32]).unwrap();
        assert_ne!(
            c1, c_other,
            "different nonce seeds must produce different R"
        );
    }

    #[test]
    fn test_key_generation() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Ed448!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = Ed448SigningKey::generate().unwrap();
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
        let signing_key1 = Ed448SigningKey::generate().unwrap();
        let signing_key2 = Ed448SigningKey::generate().unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        let message = b"test message";
        let signature = signing_key1.sign(message);

        // Verify with wrong key should fail
        assert!(matches!(
            verifying_key2.verify(message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_deterministic_signatures() {
        let signing_key = Ed448SigningKey::generate().unwrap();

        let message = b"test message";
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Ed448 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_empty_message() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = vec![0xffu8; 10000];
        let signature = signing_key.sign(&message);

        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_context_string() {
        let signing_key = Ed448SigningKey::generate().unwrap();
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
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let recovered = Ed448VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_signature_from_bytes() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");

        let bytes = signature.to_bytes();
        let recovered = Ed448Signature::from_bytes(&bytes).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = Ed448Signature::from_bytes(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_non_canonical_s_scalar_rejected() {
        // Verify the underlying library correctly rejects non-canonical s scalars.
        // Byte 56 of s (position 113 in signature) must be 0x00 for valid signatures.
        let signing_key = Ed448SigningKey::generate().unwrap();
        let signature = signing_key.sign(b"test");
        let mut bytes = signature.to_bytes();

        // Modify byte 56 of s scalar (position 113 in full signature)
        bytes[113] ^= 0x01;

        // Library should reject this as invalid
        let result = Ed448Signature::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "Non-canonical s scalar (byte 113 modified) should be rejected by library"
        );
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Ed448VerifyingKey::from_bytes(&[0u8; 50]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 57,
                actual: 50
            })
        ));
    }

    #[test]
    fn test_context_length_validation() {
        let signing_key = Ed448SigningKey::generate().unwrap();
        let verifying_key = signing_key.verifying_key();
        let message = b"test message";

        // 255 bytes is the maximum allowed
        let max_context = vec![0x42u8; 255];
        let sig = signing_key
            .sign_with_context(message, &max_context)
            .unwrap();
        assert!(
            verifying_key
                .verify_with_context(message, &max_context, &sig)
                .is_ok()
        );

        // 256 bytes exceeds the maximum
        let too_long_context = vec![0x42u8; 256];
        assert!(matches!(
            signing_key.sign_with_context(message, &too_long_context),
            Err(CryptoError::InvalidContextLength {
                actual: 256,
                max: 255
            })
        ));
        assert!(matches!(
            verifying_key.verify_with_context(message, &too_long_context, &sig),
            Err(CryptoError::InvalidContextLength {
                actual: 256,
                max: 255
            })
        ));
    }
}
