//! Hybrid signature scheme (Ed448 + ML-DSA-65).
//!
//! This module provides hybrid signatures that combine classical Ed448 with
//! post-quantum ML-DSA-65 using the Bird-of-Prey-2 SUF-preserving combiner
//! (Janneck, ePrint 2025/1844, Fig. 6 — the EdDSA + ML-DSA instantiation).
//! Unlike a naive parallel concatenation, BoP-2 intertwines the two halves: the
//! Ed448 Schnorr challenge is `H2(σ₂)`, so the combiner preserves strong
//! unforgeability (SUF-CMA) under the OR-security model (SUF holds if at least
//! one component is SUF) and all BUFF properties. Half-swap, half-strip, and
//! cross-key mixing therefore fail verification cryptographically.
//!
//! # ML-DSA Variants
//!
//! The hybrid signature types are generic over the ML-DSA variant:
//! - [`trelis_primitives::MlDsa65Fips204`]: Standard FIPS 204 with SHA-3/SHAKE (default)
//! - [`trelis_primitives::MlDsa65Blake3`]: BLAKE3 variant (requires `mldsa-blake3` feature)
//!
//! # Key Sizes
//!
//! - Public key: 2,009 bytes (Ed448 57B + ML-DSA-65 1,952B)
//! - Signature: 3,366 bytes (Ed448 BoP-2 response 57B + ML-DSA-65 3,309B)
//!
//! # Example
//!
//! ```
//! use trelis_hybrid::signature::HybridSigningKeypair;
//! use trelis_primitives::MlDsa65Fips204;
//!
//! // Use FIPS 204 (standard ML-DSA-65)
//! let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
//! let message = b"Hello, Trelis!";
//!
//! let signature = keypair.sign(message).unwrap();
//! assert!(keypair.public_key().verify(message, &signature).is_ok());
//! ```
//!
//! # Using Suite-B variant
//!
//! ```ignore
//! use trelis_hybrid::signature::HybridSigningKeypair;
//! use trelis_primitives::MlDsa65SuiteB;
//!
//! // Explicitly use Suite-B
//! let keypair = HybridSigningKeypair::<MlDsa65SuiteB>::generate().unwrap();
//! ```

use core::marker::PhantomData;
use subtle::ConstantTimeEq;
/// BLAKE3 context for splitting a 32-byte hybrid-signing seed into the Ed448
/// component's first 32-byte block (part 1 of the 57-byte Ed448 seed).
const HYBRID_SIGNING_ED448_SEED_CONTEXT: &str = "trelis-hybrid-signing-ed448-v1";

/// BLAKE3 context for splitting a 32-byte hybrid-signing seed into the Ed448
/// component's second 32-byte block (the first 25 bytes form part 2 of the
/// 57-byte Ed448 seed). Mirrors the `-v1-2` second-derivation pattern used by
/// `derive_recovery_keypair` in `recovery.rs`.
const HYBRID_SIGNING_ED448_SEED_CONTEXT_2: &str = "trelis-hybrid-signing-ed448-v1-2";

/// BLAKE3 context for deriving the ML-DSA-65 keypair seed from a 32-byte
/// hybrid-signing seed.
const HYBRID_SIGNING_MLDSA_SEED_CONTEXT: &str = "trelis-hybrid-signing-mldsa-v1";

use alloc::vec::Vec;
use trelis_primitives::{
    DefaultMlDsaScheme, ED448_BOP_RESPONSE_SIZE, Ed448BopResponse, Ed448SigningKey,
    Ed448VerifyingKey, MlDsaScheme, blake3_kdf,
};
use zeroize::{Zeroize, Zeroizing};

use trelis_error::{CryptoError, Result};

/// Size of Ed448 public key in bytes.
pub const ED448_PK_SIZE: usize = 57;

/// Size of ML-DSA-65 public key in bytes.
pub const MLDSA_PK_SIZE: usize = 1952;

/// Size of hybrid signing public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = ED448_PK_SIZE + MLDSA_PK_SIZE;

/// Size of the Ed448 Bird-of-Prey-2 response in bytes.
///
/// This is the classical half of the BoP-2 combiner — a 57-byte Schnorr response
/// `rsp`, not the 114-byte standalone EdDSA signature the pre-BoP-2 concat
/// combiner used.
pub const ED448_SIG_SIZE: usize = ED448_BOP_RESPONSE_SIZE;

/// Size of ML-DSA-65 signature in bytes.
pub const MLDSA_SIG_SIZE: usize = 3309;

/// Size of hybrid signature in bytes (BoP-2: rsp 57B || σ₂ 3309B = 3366B).
pub const SIGNATURE_SIZE: usize = ED448_SIG_SIZE + MLDSA_SIG_SIZE;

/// Size of Ed448 secret key seed in bytes.
pub const ED448_SK_SIZE: usize = 57;

/// Size of ML-DSA-65 secret key in bytes.
pub const MLDSA_SK_SIZE: usize = 4032;

/// Size of hybrid signing secret key in bytes.
pub const SECRET_KEY_SIZE: usize = ED448_SK_SIZE + MLDSA_SK_SIZE;

// ============================================================================
// Bird-of-Prey-2 (BoP-2) hybrid signature combiner (CMB-02 / v1.5 F03)
//
// Janneck, ePrint 2025/1844, Fig. 6 (EdDSA + ML-DSA-65 instantiation). The
// classical Ed448 Schnorr identification scheme is intertwined with the
// black-box ML-DSA-65 signature so the combiner *preserves* SUF-CMA under the
// hybrid OR-security model (SUF holds if at least one component is SUF) and all
// BUFF properties. The naive parallel-concat combiner it replaces did NOT
// preserve SUF: if either half's strong unforgeability failed, an existing
// message's combined signature became malleable.
//
//   sign(m):   (R, st) = bop_commit();  m' = H1_d(pkID‖pkSig‖m‖R);
//              σ₂ = ML_DSA.sign(m');    chl = H2(σ₂);   rsp = st.respond(chl)
//   verify:    chl = H2(σ₂);  R = ExtCom(rsp, chl);  m' = H1_d(pkID‖pkSig‖m‖R);
//              accept iff ML_DSA.verify(pkSig, m', σ₂)   (rsp UR-guarded in ExtCom)
//
// H1_d is the per-mode BoP-2 H1: each signing entry point derives m' under a
// distinct registered BLAKE3 context selected by `H1Domain` (Plain / Context /
// Prehashed, WR-03), so `sign_with_context` and `sign_prehashed` cannot collide
// with plain `sign` over the same bytes. H1 binds the FULL hybrid vk
// (pkID‖pkSig) into every signature (BUFF exclusive ownership); H2(σ₂) is the
// Ed448 challenge, which is what makes the two halves non-separable. All three
// signing entry points funnel through the shared core, so every downstream
// signed surface inherits non-separability.
// ============================================================================

/// Selects the BoP-2 `H1` domain — i.e. which registered BLAKE3 context the
/// `m'` preimage is derived under — per signing entry point (WR-03).
///
/// Each API mode is cryptographically independent because it derives `m'` under
/// a distinct `H1` context: `Plain` keeps the byte-frozen base context (so the
/// plain-sign KATs are unchanged), while `Context` and `Prehashed` route to
/// their own registered siblings. The signer and verifier for a given mode MUST
/// pass the same variant or every signature in that mode fails. Internal only
/// (never `pub`) — zero public-API and zero 3,366-B wire delta.
#[derive(Clone, Copy)]
enum H1Domain {
    /// Plain `sign` / `verify` — base `SIG_BOP2_H1_CONTEXT` (byte-frozen).
    Plain,
    /// `sign_with_context` / `verify_with_context` — `SIG_BOP2_H1_CTX_CONTEXT`.
    Context,
    /// `sign_prehashed` / `verify_prehashed` — `SIG_BOP2_H1_PREHASH_CONTEXT`.
    Prehashed,
}

impl H1Domain {
    /// Maps the domain to its registered BLAKE3 `H1` context string. `const` so
    /// the mapping stays a compile-time table with no runtime branch cost.
    const fn h1_context(self) -> &'static str {
        match self {
            H1Domain::Plain => blake3_kdf::SIG_BOP2_H1_CONTEXT,
            H1Domain::Context => blake3_kdf::SIG_BOP2_H1_CTX_CONTEXT,
            H1Domain::Prehashed => blake3_kdf::SIG_BOP2_H1_PREHASH_CONTEXT,
        }
    }
}

/// H1: `m' = derive_key(domain.h1_context(), pkID ‖ pkSig ‖ message ‖ com)`.
///
/// The `H1` context is domain-selected by [`H1Domain`] (Plain / Context /
/// Prehashed) rather than fixed, so the three signing APIs derive `m'` under
/// distinct registered contexts and cannot cross-verify (WR-03). Binds the full
/// hybrid verification key (`pk_id` = 57-byte Ed448 pk, `pk_sig` = 1952-byte
/// ML-DSA pk), the message region, and the Schnorr commitment `com` (the 57-byte
/// `R`) into the 32-byte digest that ML-DSA-65 actually signs. Binding the vk
/// here is what makes a cross-key / mixed-vk signature fail (BUFF exclusive
/// ownership).
fn bop_m_prime(
    domain: H1Domain,
    pk_id: &[u8],
    pk_sig: &[u8],
    message: &[u8],
    com: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut input = Vec::with_capacity(pk_id.len() + pk_sig.len() + message.len() + com.len());
    input.extend_from_slice(pk_id);
    input.extend_from_slice(pk_sig);
    input.extend_from_slice(message);
    input.extend_from_slice(com);
    blake3_kdf::derive_key(domain.h1_context(), &input)
}

/// H2: a 114-byte BLAKE3 XOF over `σ₂`, keyed by `SIG_BOP2_H2_CONTEXT`.
///
/// The 114 wide bytes are reduced into the Ed448 challenge scalar
/// (`from_bytes_mod_order_wide`) inside the primitives BoP surface, giving a
/// negligible modulo bias. Returned wide so both `respond` (signer) and
/// `bop_extcom` (verifier) apply the identical reduction.
fn h2_challenge(sigma2: &[u8]) -> [u8; 114] {
    let mut hasher = blake3::Hasher::new_derive_key(blake3_kdf::SIG_BOP2_H2_CONTEXT);
    hasher.update(sigma2);
    let mut wide = [0u8; 114];
    hasher.finalize_xof().fill(&mut wide);
    wide
}

/// Builds the length-prefixed, domain-separated message region that binds a
/// context string into the BoP-2 `m'`: `ctx_len(1) ‖ ctx ‖ message`.
///
/// The context is bound into `m'`, not into a resurrected standalone Ed448
/// signature, so a wrong or absent context changes `m'` and fails verification.
///
/// # Errors
///
/// Returns `InvalidContextLength` if `context` exceeds 255 bytes (the 1-byte
/// length-prefix bound, preserving the pre-BoP-2 contract).
fn bop_context_region(context: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::InvalidContextLength {
        actual: context.len(),
        max: 255,
    })?;
    let mut region = Vec::with_capacity(1 + context.len() + message.len());
    region.push(ctx_len);
    region.extend_from_slice(context);
    region.extend_from_slice(message);
    Ok(region)
}

/// Hybrid signing keypair (Ed448 + ML-DSA-65).
///
/// This keypair contains both classical and post-quantum signing keys.
/// Both algorithms are used to sign messages, providing security as long
/// as either algorithm remains secure.
///
/// The type parameter `S` selects the ML-DSA variant:
/// - `MlDsa65Fips204` (default): Standard FIPS 204
/// - `MlDsa65SuiteB`: PQC-Suite-B with BLAKE3
#[derive(Clone)]
pub struct HybridSigningKeypair<S: MlDsaScheme = DefaultMlDsaScheme> {
    public_key: HybridSigningPublicKey<S>,
    ed448_secret: Ed448SigningKey,
    mldsa_secret: S::SigningKey,
}

impl<S: MlDsaScheme> Zeroize for HybridSigningKeypair<S> {
    fn zeroize(&mut self) {
        self.ed448_secret.zeroize();
        self.mldsa_secret.zeroize();
    }
}

impl<S: MlDsaScheme> Drop for HybridSigningKeypair<S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<S: MlDsaScheme> HybridSigningKeypair<S> {
    /// Generates a new random hybrid signing keypair.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the system CSPRNG fails, or `KeyGenerationFailed`
    /// if key generation fails internally.
    ///
    /// # Note
    ///
    /// On Windows with default 1MB stack, this may overflow when combined with
    /// other large key operations. Use `HybridIdentityKeypair` which handles
    /// this via heap allocation, or run in a thread with larger stack.
    pub fn generate() -> Result<Self> {
        let ed448_secret = Ed448SigningKey::generate()?;
        let mldsa_secret = S::generate()?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Generates a hybrid signing keypair deterministically from a 32-byte
    /// seed.
    ///
    /// The seed is split via BLAKE3 with two domain-separated contexts (for
    /// Ed448 and for ML-DSA-65) before being fed to each primitive's seeded
    /// constructor. The same seed always produces the same keypair, so this
    /// is the right entry point for hardware-attested device identity (see
    /// `derive_device_seed` in `trelis-primitives` and
    /// `HybridIdentityKeypair::generate_from_seed`).
    ///
    /// # Errors
    ///
    /// Returns `KeyGenerationFailed` if the ML-DSA seeded constructor exhausts
    /// its rejection-sampling budget under the derived seed (RNG-broken
    /// indicator that should not occur with healthy inputs).
    pub fn generate_from_seed(seed: &[u8; 32]) -> Result<Self> {
        // 57-byte Ed448 seed expansion via two BLAKE3 derivations, matching the
        // pattern used by `derive_recovery_keypair` in `recovery.rs`.
        let ed448_seed_part1 = blake3_kdf::derive_key(HYBRID_SIGNING_ED448_SEED_CONTEXT, seed);
        let ed448_seed_part2 = blake3_kdf::derive_key(HYBRID_SIGNING_ED448_SEED_CONTEXT_2, seed);
        let mut ed448_seed = [0u8; 57];
        ed448_seed[..32].copy_from_slice(ed448_seed_part1.as_slice());
        ed448_seed[32..57].copy_from_slice(&ed448_seed_part2[..25]);

        let mldsa_seed = blake3_kdf::derive_key(HYBRID_SIGNING_MLDSA_SEED_CONTEXT, seed);

        let ed448_secret = Ed448SigningKey::from_seed(ed448_seed);
        let mldsa_secret = S::generate_from_seed(&mldsa_seed)?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Creates a hybrid signing keypair from individual components.
    ///
    /// This is used for deterministic key derivation (e.g., recovery keys).
    ///
    /// # Arguments
    ///
    /// * `ed448_secret` - The Ed448 signing key
    /// * `mldsa_secret` - The ML-DSA-65 signing key
    ///
    /// # Returns
    ///
    /// A hybrid keypair combining both components.
    pub fn from_components(ed448_secret: Ed448SigningKey, mldsa_secret: S::SigningKey) -> Self {
        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
        };

        Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        }
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &HybridSigningPublicKey<S> {
        &self.public_key
    }

    /// Returns the Ed448 signing key component.
    #[must_use]
    pub fn ed448_secret(&self) -> &Ed448SigningKey {
        &self.ed448_secret
    }

    /// Returns the ML-DSA signing key component.
    #[must_use]
    pub fn mldsa_secret(&self) -> &S::SigningKey {
        &self.mldsa_secret
    }

    /// Serialises the secret key to bytes.
    ///
    /// Format: Ed448 seed (57 bytes) || ML-DSA-65 secret (4,032 bytes)
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material and should be
    /// handled securely (encrypted storage, zeroisation after use).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_SIZE]> {
        let mut bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
        bytes[..ED448_SK_SIZE].copy_from_slice(self.ed448_secret.seed());
        bytes[ED448_SK_SIZE..].copy_from_slice(&S::signing_key_to_bytes(&self.mldsa_secret));
        bytes
    }

    /// Deserialises a keypair from secret key bytes.
    ///
    /// The public key is derived from the secret key components.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 4,089 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut ed448_seed = [0u8; ED448_SK_SIZE];
        ed448_seed.copy_from_slice(&bytes[..ED448_SK_SIZE]);
        let ed448_secret = Ed448SigningKey::from_seed(ed448_seed);

        let mldsa_secret = S::signing_key_from_bytes(&bytes[ED448_SK_SIZE..])?;

        let public_key = HybridSigningPublicKey {
            ed448: ed448_secret.verifying_key(),
            mldsa: S::verifying_key(&mldsa_secret),
            _marker: PhantomData,
        };

        Ok(Self {
            public_key,
            ed448_secret,
            mldsa_secret,
        })
    }

    /// Signs a message with both Ed448 and ML-DSA-65.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// A hybrid signature containing both Ed448 and ML-DSA-65 signatures.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the Schnorr-nonce CSPRNG fails, or the ML-DSA
    /// signing error if `σ₂` generation fails.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature<S>> {
        self.bop_sign_core(H1Domain::Plain, message)
    }

    /// Core Bird-of-Prey-2 signing over an already-prepared message region.
    ///
    /// All three public entry points funnel through here: `sign` passes the raw
    /// message under `H1Domain::Plain`, `sign_with_context` passes
    /// `ctx_len‖ctx‖message` under `H1Domain::Context`, and `sign_prehashed`
    /// passes the BLAKE3 prehash digest under `H1Domain::Prehashed`. The `domain`
    /// selects which registered `H1` context `m'` is derived under (WR-03), so
    /// the three APIs are cryptographically independent. See the BoP-2 module
    /// note above for the construction.
    ///
    /// # Errors
    ///
    /// Returns `RngFailure` if the Schnorr-nonce CSPRNG fails, or the ML-DSA
    /// signing error if `σ₂` generation fails.
    fn bop_sign_core(&self, domain: H1Domain, message: &[u8]) -> Result<HybridSignature<S>> {
        let pk_id = self.public_key.ed448.as_bytes();
        let pk_sig = S::verifying_key_to_bytes(&self.public_key.mldsa);
        // com = R = r·B with a fresh Schnorr nonce; `nonce` holds (r, s) and is
        // zeroized when consumed by `respond`. A fresh nonce is sampled per call
        // (reusing r across messages would leak the secret scalar s).
        let (com, nonce) = self.ed448_secret.bop_commit()?;
        let m_prime = bop_m_prime(domain, &pk_id, &pk_sig, message, com.as_bytes());
        // Route the ML-DSA-65 half through the hedged signer: binds fresh
        // per-call entropy + the full hybrid context m' into the signing RNG
        // (F14 defence-in-depth vs a weak/compromised RNG). MlDsa65Fips204
        // overrides `sign_hedged`; other schemes fall back to `sign` via the
        // trait default. Hedges every production hybrid signature (all three
        // entry points funnel through here); wire bytes + verify are unchanged.
        let mldsa_sig = S::sign_hedged(&self.mldsa_secret, m_prime.as_slice())?;
        // chl = H2(σ₂): the ML-DSA signature defines the Ed448 challenge.
        let chl = h2_challenge(&S::signature_to_bytes(&mldsa_sig));
        let rsp = nonce.respond(&chl);
        Ok(HybridSignature {
            rsp,
            mldsa: mldsa_sig,
            _marker: PhantomData,
        })
    }

    /// Signs a message with a context string.
    ///
    /// Both Ed448 and ML-DSA-65 support context strings for domain separation.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    /// * `context` - The context string (max 255 bytes).
    ///
    /// # Errors
    ///
    /// Returns `InvalidContextLength` if the context exceeds 255 bytes, or the
    /// signing error if generation fails. The context is bound into the BoP-2
    /// `m'` in a length-prefixed, domain-separated way (`ctx_len‖ctx‖message`),
    /// not into a standalone Ed448 signature.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<HybridSignature<S>> {
        let region = bop_context_region(context, message)?;
        self.bop_sign_core(H1Domain::Context, &region)
    }

    /// Signs a message using BLAKE3 prehash domain separation (spec §05.2).
    ///
    /// Computes `digest = blake3::derive_key(context, message)` (32 bytes) then
    /// passes the digest to both Ed448 and ML-DSA-65 signing algorithms.
    ///
    /// Use with the `trelis-sig-*` context constants from
    /// `trelis_primitives::blake3_kdf` (e.g. `SIG_COCOA_UPDATE_CONTEXT`).
    ///
    /// Verification: use `verify_prehashed` with the same context string.
    ///
    /// The prehash digest is folded into the BoP-2 construction (it becomes the
    /// message region), not signed by a resurrected standalone Ed448 signature.
    pub fn sign_prehashed(&self, context: &str, message: &[u8]) -> Result<HybridSignature<S>> {
        let digest = blake3_kdf::derive_key(context, message);
        self.bop_sign_core(H1Domain::Prehashed, digest.as_slice())
    }

    /// Wraps this keypair in a `GuardedBox` for enhanced memory protection.
    ///
    /// The returned `GuardedBox` provides:
    /// - Guard pages before and after the keypair to detect buffer overflows
    /// - Memory locking to prevent swapping to disc (if privileges allow)
    /// - Automatic zeroisation on drop
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = HybridSigningKeypair::generate()?;
    /// let guarded = keypair.into_guarded()?;
    /// guarded.protect_readonly()?; // Optional: make read-only after init
    /// let sig = guarded.sign(message)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MemlockError` if memory allocation or protection fails.
    #[cfg(feature = "mlock")]
    pub fn into_guarded(
        self,
    ) -> trelis_primitives::memlock::Result<trelis_primitives::GuardedBox<Self>> {
        trelis_primitives::GuardedBox::new(self)
    }
}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSigningKeypair<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningKeypair")
            .field("public_key", &self.public_key)
            .field("ed448_secret", &"[redacted]")
            .field("mldsa_secret", &"[redacted]")
            .finish()
    }
}

/// Hybrid signing public key (Ed448 + ML-DSA-65).
///
/// This public key is used to verify hybrid signatures. Both the Ed448
/// and ML-DSA-65 signatures must be valid for verification to succeed.
#[derive(Clone)]
pub struct HybridSigningPublicKey<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// Ed448 verifying key (57 bytes)
    pub ed448: Ed448VerifyingKey,
    /// ML-DSA-65 verifying key (1,952 bytes)
    pub mldsa: S::VerifyingKey,
    _marker: PhantomData<S>,
}

impl<S: MlDsaScheme> HybridSigningPublicKey<S> {
    /// Creates a public key from individual components.
    pub fn from_components(ed448: Ed448VerifyingKey, mldsa: S::VerifyingKey) -> Self {
        Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        }
    }

    /// Serialises the public key to bytes.
    ///
    /// Format: Ed448 (57 bytes) || ML-DSA-65 (1,952 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes[..ED448_PK_SIZE].copy_from_slice(&self.ed448.as_bytes());
        bytes[ED448_PK_SIZE..].copy_from_slice(&S::verifying_key_to_bytes(&self.mldsa));
        bytes
    }

    /// Deserialises a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if the slice is not exactly 2,009 bytes,
    /// or `SignatureVerificationFailed` if the keys are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let ed448 = Ed448VerifyingKey::from_bytes(&bytes[..ED448_PK_SIZE])?;
        let mldsa = S::verifying_key_from_bytes(&bytes[ED448_PK_SIZE..])?;

        Ok(Self {
            ed448,
            mldsa,
            _marker: PhantomData,
        })
    }

    /// Verifies a hybrid signature on a message.
    ///
    /// Both the Ed448 and ML-DSA-65 signatures must be valid.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if either signature is invalid.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify(&self, message: &[u8], signature: &HybridSignature<S>) -> Result<()> {
        self.bop_verify_core(H1Domain::Plain, message, signature)
    }

    /// Core Bird-of-Prey-2 verification over an already-prepared message region.
    ///
    /// Recomputes `chl = H2(σ₂)`, reconstructs the commitment `R = ExtCom(rsp,
    /// chl)` (which UR-guards `rsp`, rejecting a non-canonical `rsp+L`, and
    /// rejects an invalid Ed448 point), rebuilds `m' = H1(pkID‖pkSig‖message‖R)`,
    /// and accepts iff ML-DSA-65 verifies `σ₂` over `m'`. The ExtCom UR/point
    /// guard plus the single ML-DSA boolean together are the accept condition;
    /// the pipeline is strictly data-dependent (each stage consumes the previous
    /// output), so there is no independent two-signature branch to leak — unlike
    /// the parallel-concat combiner this replaces.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if `rsp` is non-canonical, this
    /// key's Ed448 point is invalid, or the ML-DSA check over the recomputed
    /// `m'` fails.
    ///
    /// The `domain` MUST match the one the signer used (Plain / Context /
    /// Prehashed) or the recomputed `m'` differs and verification fails (WR-03).
    fn bop_verify_core(
        &self,
        domain: H1Domain,
        message: &[u8],
        signature: &HybridSignature<S>,
    ) -> Result<()> {
        let sigma2 = S::signature_to_bytes(&signature.mldsa);
        let chl = h2_challenge(&sigma2);
        // ExtCom applies the UR canonicality guard on rsp (the SUF linchpin) and
        // rejects an invalid curve point. A failure here is a malformed-response
        // rejection (already known to the submitter), not a secret-dependent
        // branch.
        let com = self.ed448.bop_extcom(&chl, &signature.rsp)?;
        let pk_id = self.ed448.as_bytes();
        let pk_sig = S::verifying_key_to_bytes(&self.mldsa);
        let m_prime = bop_m_prime(domain, &pk_id, &pk_sig, message, com.as_bytes());
        if S::verify(&self.mldsa, m_prime.as_slice(), &signature.mldsa).is_ok() {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Verifies a hybrid signature with a context string.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed.
    /// * `context` - The context string used during signing (max 255 bytes).
    /// * `signature` - The hybrid signature to verify.
    ///
    /// # Errors
    ///
    /// Returns `SignatureVerificationFailed` if either signature is invalid,
    /// or `InvalidContextLength` if the context exceeds 255 bytes.
    #[must_use = "the verify outcome must be checked"]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &HybridSignature<S>,
    ) -> Result<()> {
        // The context is bound into m' via the same length-prefixed region used
        // by sign_with_context; InvalidContextLength (>255) is surfaced here.
        let region = bop_context_region(context, message)?;
        self.bop_verify_core(H1Domain::Context, &region, signature)
    }

    /// Verifies a signature produced by `sign_prehashed`.
    ///
    /// Recomputes `digest = blake3::derive_key(context, message)` then runs
    /// BoP-2 verification over that digest as the message region.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` if the signature verifies, or
    /// `SignatureVerificationFailed` otherwise (e.g. a wrong context yields a
    /// different digest). This returns `Result<()>` — aligned with its two
    /// sibling verifiers — so `.is_ok()` cannot silently accept an invalid
    /// signature (the prior `Result<bool>` `Ok(false)` footgun is removed).
    #[must_use = "the verify outcome must be checked"]
    pub fn verify_prehashed(
        &self,
        context: &str,
        message: &[u8],
        signature: &HybridSignature<S>,
    ) -> Result<()> {
        let digest = blake3_kdf::derive_key(context, message);
        self.bop_verify_core(H1Domain::Prehashed, digest.as_slice(), signature)
    }
}

impl<S: MlDsaScheme> PartialEq for HybridSigningPublicKey<S> {
    fn eq(&self, other: &Self) -> bool {
        self.ed448 == other.ed448 && self.mldsa == other.mldsa
    }
}

impl<S: MlDsaScheme> Eq for HybridSigningPublicKey<S> {}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSigningPublicKey<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSigningPublicKey")
            .field("ed448", &self.ed448)
            .field("mldsa", &"[1952 bytes]")
            .finish()
    }
}

/// Hybrid signature (Ed448 + ML-DSA-65).
///
/// Contains both classical and post-quantum signatures. Both must be
/// valid for the hybrid signature to verify successfully.
#[derive(Clone)]
pub struct HybridSignature<S: MlDsaScheme = DefaultMlDsaScheme> {
    /// Ed448 Bird-of-Prey-2 Schnorr response `rsp` (57 bytes, UR-guarded).
    pub rsp: Ed448BopResponse,
    /// ML-DSA-65 signature `σ₂` over `m'` (3,309 bytes).
    pub mldsa: S::Signature,
    _marker: PhantomData<S>,
}

impl<S: MlDsaScheme> HybridSignature<S> {
    /// Creates a signature from individual components.
    ///
    /// `rsp` is the 57-byte BoP-2 Schnorr response; `mldsa` is `σ₂` over `m'`.
    /// The SUF / non-separability tests build swap and cross-key witnesses via
    /// this public constructor — which is safe precisely because the BoP-2
    /// combiner rejects recombined halves and mixed keys cryptographically.
    pub fn from_components(rsp: Ed448BopResponse, mldsa: S::Signature) -> Self {
        Self {
            rsp,
            mldsa,
            _marker: PhantomData,
        }
    }

    /// Serialises the signature to bytes.
    ///
    /// Format: BoP-2 response (57 bytes) || ML-DSA-65 (3,309 bytes) = 3,366 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[..ED448_SIG_SIZE].copy_from_slice(self.rsp.as_bytes());
        bytes[ED448_SIG_SIZE..].copy_from_slice(&S::signature_to_bytes(&self.mldsa));
        bytes
    }

    /// Deserialises a signature from bytes.
    ///
    /// The 57-byte response half is UR-guarded on decode
    /// (`Ed448BopResponse::from_bytes` rejects a non-canonical `rsp`, e.g.
    /// `rsp + L`) — the SUF-CMA linchpin at the wire boundary.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if the bytes are the wrong length, the
    /// response half is non-canonical, or the ML-DSA half is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let rsp = Ed448BopResponse::from_bytes(&bytes[..ED448_SIG_SIZE])?;
        let mldsa = S::signature_from_bytes(&bytes[ED448_SIG_SIZE..])?;

        Ok(Self {
            rsp,
            mldsa,
            _marker: PhantomData,
        })
    }
}

impl<S: MlDsaScheme> PartialEq for HybridSignature<S> {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison of the 57-byte response, bitwise-ANDed (no
        // short-circuit) with ML-DSA-signature equality.
        let rsp_a: &[u8] = self.rsp.as_bytes();
        let rsp_b: &[u8] = other.rsp.as_bytes();
        let rsp_eq: bool = rsp_a.ct_eq(rsp_b).into();
        let mldsa_eq: bool = self.mldsa == other.mldsa;
        rsp_eq & mldsa_eq
    }
}

impl<S: MlDsaScheme> Eq for HybridSignature<S> {}

impl<S: MlDsaScheme> core::fmt::Debug for HybridSignature<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSignature")
            .field("rsp", &"[57 bytes]")
            .field("mldsa", &"[3309 bytes]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use trelis_primitives::MlDsa65Fips204;

    // Type aliases for tests - use FIPS 204 (standard) for test vectors
    type TestKeypair = HybridSigningKeypair<MlDsa65Fips204>;
    type TestPublicKey = HybridSigningPublicKey<MlDsa65Fips204>;
    type TestSignature = HybridSignature<MlDsa65Fips204>;

    #[test]
    fn test_public_key_size() {
        assert_eq!(PUBLIC_KEY_SIZE, 2009);
    }

    #[test]
    fn test_signature_size() {
        // BoP-2: Ed448 response (57) + ML-DSA-65 (3309) = 3366
        assert_eq!(SIGNATURE_SIZE, 3366);
    }

    #[test]
    fn test_key_generation() {
        let keypair = TestKeypair::generate().unwrap();
        let pk_bytes = keypair.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = TestKeypair::generate().unwrap();
        let message = b"Hello, hybrid signatures!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.public_key().verify(message, &signature).is_ok());
    }

    /// Randomization + verification regression guard for the hedged production
    /// hybrid path (SC2 / v1.5 F14). Pinned to `MlDsa65Fips204` so it always
    /// exercises the FIPS-204 `sign_hedged` override regardless of the
    /// `mldsa-blake3-default` feature.
    ///
    /// NOTE: this test does NOT by itself prove the hedge is *wired* — plain
    /// `sign` is already randomized and `bop_sign_core` samples a fresh Schnorr
    /// nonce every call (so `m'`, and therefore σ₂, differs per call anyway).
    /// The wiring proof is the source grep that `bop_sign_core` calls
    /// `S::sign_hedged`. This guard ensures the production path keeps producing
    /// distinct, verifying σ₂ halves — a determinism regression would trip it.
    #[test]
    fn hybrid_sign_mldsa_half_is_randomized() {
        let keypair = TestKeypair::generate().unwrap();
        let message = b"phase-55 hedged production path";

        let a = keypair.sign(message).unwrap();
        let b = keypair.sign(message).unwrap();

        // σ₂ (the ML-DSA-65 half) must differ across calls on the production path.
        assert_ne!(a.mldsa, b.mldsa, "hedged hybrid signing must randomize σ₂");

        // Both hedged signatures still verify under the unchanged verify path.
        assert!(keypair.public_key().verify(message, &a).is_ok());
        assert!(keypair.public_key().verify(message, &b).is_ok());
    }

    #[test]
    fn test_signature_serialisation() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"test").unwrap();

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);

        let recovered = TestSignature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_public_key_serialisation() {
        let keypair = TestKeypair::generate().unwrap();
        let pk = keypair.public_key();

        let bytes = pk.to_bytes();
        let recovered = TestPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk, &recovered);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"correct message").unwrap();

        assert!(
            keypair
                .public_key()
                .verify(b"wrong message", &signature)
                .is_err()
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = TestKeypair::generate().unwrap();
        let keypair2 = TestKeypair::generate().unwrap();

        let signature = keypair1.sign(b"test").unwrap();
        assert!(keypair2.public_key().verify(b"test", &signature).is_err());
    }

    #[test]
    fn test_context_string() {
        let keypair = TestKeypair::generate().unwrap();
        let message = b"test message";
        let context = b"test-context";

        let signature = keypair.sign_with_context(message, context).unwrap();

        // Correct context succeeds
        assert!(
            keypair
                .public_key()
                .verify_with_context(message, context, &signature)
                .is_ok()
        );

        // Wrong context fails
        assert!(
            keypair
                .public_key()
                .verify_with_context(message, b"wrong", &signature)
                .is_err()
        );

        // No context fails
        assert!(keypair.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_empty_message() {
        let keypair = TestKeypair::generate().unwrap();
        let signature = keypair.sign(b"").unwrap();
        assert!(keypair.public_key().verify(b"", &signature).is_ok());
    }

    #[test]
    fn test_keypair_serialisation_roundtrip() {
        let keypair = TestKeypair::generate().unwrap();
        let bytes = keypair.to_bytes();

        let recovered = TestKeypair::from_bytes(&bytes[..]).unwrap();

        // Verify the recovered keypair works
        let message = b"test roundtrip";
        let sig = recovered.sign(message).unwrap();
        assert!(recovered.public_key().verify(message, &sig).is_ok());

        // And the public keys match
        assert_eq!(
            keypair.public_key().to_bytes(),
            recovered.public_key().to_bytes()
        );
    }

    #[test]
    fn test_sign_prehashed_verify_prehashed_roundtrip() {
        use trelis_primitives::blake3_kdf::SIG_COCOA_UPDATE_CONTEXT;
        let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
        let pubkey = keypair.public_key();
        let msg = b"cocoa update payload";
        let sig = keypair
            .sign_prehashed(SIG_COCOA_UPDATE_CONTEXT, msg)
            .unwrap();
        assert!(
            pubkey
                .verify_prehashed(SIG_COCOA_UPDATE_CONTEXT, msg, &sig)
                .is_ok()
        );
    }

    #[test]
    fn test_sign_prehashed_context_separates_domains() {
        use trelis_primitives::blake3_kdf::{
            SIG_COCOA_UPDATE_CONTEXT, SIG_RATCHET_MESSAGE_CONTEXT,
        };
        let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
        let msg = b"same message bytes";
        let sig1 = keypair
            .sign_prehashed(SIG_COCOA_UPDATE_CONTEXT, msg)
            .unwrap();
        let sig2 = keypair
            .sign_prehashed(SIG_RATCHET_MESSAGE_CONTEXT, msg)
            .unwrap();
        // Different contexts produce different BoP-2 responses
        assert_ne!(sig1.rsp.as_bytes(), sig2.rsp.as_bytes());
    }

    #[test]
    fn test_sign_prehashed_not_equal_to_raw_sign() {
        use trelis_primitives::blake3_kdf::SIG_COCOA_UPDATE_CONTEXT;
        let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
        let msg = b"test message";
        let prehashed_sig = keypair
            .sign_prehashed(SIG_COCOA_UPDATE_CONTEXT, msg)
            .unwrap();
        let raw_sig = keypair.sign(msg).unwrap();
        // Prehashed signature is over derive_key(ctx, msg), not raw msg — they differ
        assert_ne!(prehashed_sig.rsp.as_bytes(), raw_sig.rsp.as_bytes());
    }

    #[test]
    fn test_sign_prehashed_wrong_context_fails_verify() {
        use trelis_primitives::blake3_kdf::{
            SIG_COCOA_UPDATE_CONTEXT, SIG_RATCHET_MESSAGE_CONTEXT,
        };
        let keypair = HybridSigningKeypair::<MlDsa65Fips204>::generate().unwrap();
        let pubkey = keypair.public_key();
        let msg = b"test message";
        let sig = keypair
            .sign_prehashed(SIG_COCOA_UPDATE_CONTEXT, msg)
            .unwrap();
        // Verifying with wrong context fails (different derive_key digest).
        // Result<()> shape: a wrong context is `is_err()`, not `Ok(false)`.
        assert!(
            pubkey
                .verify_prehashed(SIG_RATCHET_MESSAGE_CONTEXT, msg, &sig)
                .is_err()
        );
    }

    /// WR-03 regression: the explicit-context signing path is domain-separated
    /// from plain `sign()` at the BoP-2 `H1` root, so a context signature and a
    /// plain signature over the framed region `ctx_len‖ctx‖m` no longer
    /// cross-verify in EITHER direction. Pre-fix both cross-verifies ACCEPTED
    /// (identical `m'`); post-fix both REJECT.
    ///
    /// The non-collision asserts are DETERMINISTIC cross-verify (they depend
    /// only on `m'`), never a `to_bytes() != to_bytes()` differ-assert: σ₂ is
    /// hedged/randomized, so a differ-assert would be vacuous (Pitfall 1).
    #[test]
    fn wr03_context_domain_separated_from_plain() {
        let kp = TestKeypair::generate().unwrap();
        let pk = kp.public_key();
        let m = b"wr-03 target";
        let ctx = b"wr-03-context";

        let s_ctx = kp.sign_with_context(m, ctx).unwrap();
        let framed = bop_context_region(ctx, m).unwrap(); // ctx_len‖ctx‖m
        let s_plain = kp.sign(&framed).unwrap();

        // Cross-verify rejections (pre-fix these ACCEPTED — the WR-03 collision).
        assert!(
            pk.verify(&framed, &s_ctx).is_err(),
            "context sig must NOT verify as a plain sig over ctx_len||ctx||m"
        );
        assert!(
            pk.verify_with_context(m, ctx, &s_plain).is_err(),
            "plain sig over the framed region must NOT verify as a context sig"
        );

        // Positive controls (round-trips intact).
        assert!(pk.verify_with_context(m, ctx, &s_ctx).is_ok());
        assert!(pk.verify(&framed, &s_plain).is_ok());
        assert!(
            pk.verify(m, &s_ctx).is_err(),
            "no-context verify of a context sig still rejects (existing behaviour)"
        );
    }

    /// WR-03 regression: the BLAKE3-prehash signing path is domain-separated
    /// from plain `sign()` at the BoP-2 `H1` root, so `sign_prehashed(ctx, m)`
    /// and `sign(derive_key(ctx, m))` no longer cross-verify in EITHER
    /// direction. Pre-fix both cross-verifies ACCEPTED (identical `m'`);
    /// post-fix both REJECT. Deterministic cross-verify, never a differ-assert
    /// (Pitfall 1).
    #[test]
    fn wr03_prehash_domain_separated_from_plain() {
        use trelis_primitives::blake3_kdf::SIG_COCOA_UPDATE_CONTEXT;
        let kp = TestKeypair::generate().unwrap();
        let pk = kp.public_key();
        let m = b"wr-03 prehash target";
        let ctx = SIG_COCOA_UPDATE_CONTEXT;

        let s_pre = kp.sign_prehashed(ctx, m).unwrap();
        let digest = blake3_kdf::derive_key(ctx, m);
        let s_plain = kp.sign(digest.as_slice()).unwrap();

        // Cross-verify rejections (pre-fix these ACCEPTED — the prehash collision).
        assert!(
            pk.verify(digest.as_slice(), &s_pre).is_err(),
            "prehash sig must NOT verify as a plain sig over derive_key(ctx, m)"
        );
        assert!(
            pk.verify_prehashed(ctx, m, &s_plain).is_err(),
            "plain sig over the digest must NOT verify as a prehash sig"
        );

        // Positive controls (round-trips intact).
        assert!(pk.verify_prehashed(ctx, m, &s_pre).is_ok());
        assert!(pk.verify(digest.as_slice(), &s_plain).is_ok());
    }

    // ========================================================================
    // SUF-CMA / non-separability suite (CMB-02 / v1.5 F03).
    //
    // Non-tautological per 49-VALIDATION.md: these target a NEW signature on an
    // ALREADY-signed message (SUF) and the extraction / recombination of a
    // standalone component (non-separability) — not a new-message forgery, which
    // the old concat combiner already resisted. The swap / cross-key witnesses
    // are built via the PUBLIC `from_components` constructors, which is exactly
    // what makes keeping the struct fields public safe under BoP-2.
    // ========================================================================

    /// Ed448 (Goldilocks) base-point order `L`, little-endian (byte 56 = 0).
    /// `L = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885`.
    /// Used to build the non-canonical `rsp + L` witness (the SAME scalar value,
    /// a distinct 57-byte encoding) — the hybrid-layer expression of the plan-02
    /// Ed448 UR test, following the hardcoded-`p448` precedent in `combiner.rs`.
    const ED448_L_LE: [u8; 57] = [
        0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c,
        0x21, 0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00,
    ];

    /// Little-endian 57-byte add (wrapping mod 2^456), for the `rsp + L` witness.
    /// Pure `u8` arithmetic (no casts) so it stays clippy-pedantic clean.
    fn add_le_57(a: &[u8; 57], b: &[u8; 57]) -> [u8; 57] {
        let mut out = [0u8; 57];
        let mut carry = false;
        let mut i = 0;
        while i < 57 {
            let (s1, o1) = a[i].overflowing_add(b[i]);
            let (s2, o2) = s1.overflowing_add(u8::from(carry));
            out[i] = s2;
            carry = o1 || o2;
            i += 1;
        }
        out
    }

    #[test]
    fn suf_positive_control() {
        // Anti-tautology guard: an honestly produced signature verifies, so a
        // reject-everything harness cannot masquerade as correct.
        let keypair = TestKeypair::generate().unwrap();
        let msg = b"bird of prey positive control";
        let sig = keypair.sign(msg).unwrap();
        assert!(keypair.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn suf_strip_half() {
        // SUF / malleability: every mutation of a valid sigma=(rsp,sigma2) on m
        // is rejected. chl=H2(sigma2) ties rsp to THIS sigma2, and the ML-DSA
        // half is over m'=H1(..R); neither half can be dropped, zeroed, or
        // re-signed over a different m' and still verify.
        let keypair = TestKeypair::generate().unwrap();
        let pk = keypair.public_key();
        let msg = b"strip-half target";
        let sig = keypair.sign(msg).unwrap();
        assert!(
            pk.verify(msg, &sig).is_ok(),
            "control: honest sigma verifies"
        );

        // (a) Zero the ML-DSA half -> decode-or-verify must fail.
        let mut zeroed_mldsa = sig.to_bytes();
        zeroed_mldsa[ED448_SIG_SIZE..].fill(0);
        assert!(
            TestSignature::from_bytes(&zeroed_mldsa)
                .and_then(|s| pk.verify(msg, &s))
                .is_err(),
            "zeroed sigma2 must be rejected"
        );

        // (b) Re-sign the ML-DSA half over a DIFFERENT message and graft it under
        // the original rsp: chl=H2(sigma2') no longer matches rsp -> rejected.
        let other = keypair.sign(b"a different message").unwrap();
        let grafted = TestSignature::from_components(sig.rsp.clone(), other.mldsa.clone());
        assert!(
            pk.verify(msg, &grafted).is_err(),
            "grafting a foreign sigma2 under the original rsp must be rejected"
        );

        // (c) Zero the response half (rsp=0 decodes canonically, but R=-chl*A no
        // longer matches the signed m') -> rejected.
        let mut zeroed_rsp = sig.to_bytes();
        zeroed_rsp[..ED448_SIG_SIZE].fill(0);
        assert!(
            TestSignature::from_bytes(&zeroed_rsp)
                .and_then(|s| pk.verify(msg, &s))
                .is_err(),
            "zeroed rsp must be rejected"
        );
    }

    #[test]
    fn suf_swap_halves() {
        // Non-separability: given two valid signatures on different messages, the
        // cross recombinations (rsp_a,sigma2_b) and (rsp_b,sigma2_a) both FAIL on
        // either message — the halves are cryptographically bound, not
        // independently recombinable.
        let keypair = TestKeypair::generate().unwrap();
        let pk = keypair.public_key();
        let m_a = b"message A";
        let m_b = b"message B";
        let sig_a = keypair.sign(m_a).unwrap();
        let sig_b = keypair.sign(m_b).unwrap();
        assert!(pk.verify(m_a, &sig_a).is_ok());
        assert!(pk.verify(m_b, &sig_b).is_ok());

        let cross_ab = TestSignature::from_components(sig_a.rsp.clone(), sig_b.mldsa.clone());
        let cross_ba = TestSignature::from_components(sig_b.rsp.clone(), sig_a.mldsa.clone());
        for m in [m_a.as_slice(), m_b.as_slice()] {
            assert!(
                pk.verify(m, &cross_ab).is_err(),
                "(rsp_a,sigma2_b) must fail"
            );
            assert!(
                pk.verify(m, &cross_ba).is_err(),
                "(rsp_b,sigma2_a) must fail"
            );
        }
    }

    #[test]
    fn buff_cross_key_mix() {
        // BUFF exclusive ownership: a forged hybrid vk mixing one party's Ed448
        // pk with another's ML-DSA pk verifies NO signature, because the full
        // hybrid vk (pkID||pkSig) is bound into m'. This is what makes the public
        // struct fields safe under BoP-2.
        let victim = TestKeypair::generate().unwrap();
        let attacker = TestKeypair::generate().unwrap();
        let msg = b"exclusive ownership target";
        let sig = victim.sign(msg).unwrap();
        assert!(victim.public_key().verify(msg, &sig).is_ok(), "control");

        // attacker Ed448 pk + victim ML-DSA pk
        let mixed_1 = TestPublicKey::from_components(
            attacker.public_key().ed448.clone(),
            victim.public_key().mldsa.clone(),
        );
        // victim Ed448 pk + attacker ML-DSA pk
        let mixed_2 = TestPublicKey::from_components(
            victim.public_key().ed448.clone(),
            attacker.public_key().mldsa.clone(),
        );
        assert!(
            mixed_1.verify(msg, &sig).is_err(),
            "attacker-ID / victim-Sig vk must reject"
        );
        assert!(
            mixed_2.verify(msg, &sig).is_err(),
            "victim-ID / attacker-Sig vk must reject"
        );
    }

    #[test]
    fn suf_non_canonical_rsp_rejected() {
        // SUF linchpin (Unique Responses): re-encoding a valid rsp as rsp+L (the
        // SAME scalar value, a distinct non-canonical 57-byte encoding with byte
        // 56 still 0) MUST be rejected at the wire boundary. `Ed448BopResponse::
        // from_bytes` — the only path a response crosses into the hybrid layer —
        // uses `from_canonical_bytes`, so this fails loudly if it is ever swapped
        // for `from_bytes_mod_order` (which would reduce mod L and accept rsp+L,
        // silently breaking SUF-CMA). The guard is re-applied verifier-side in
        // `bop_extcom`.
        let keypair = TestKeypair::generate().unwrap();
        let msg = b"unique-responses target";
        let sig = keypair.sign(msg).unwrap();
        let bytes = sig.to_bytes();

        // Positive control: the canonical serialisation round-trips and verifies.
        let decoded = TestSignature::from_bytes(&bytes).unwrap();
        assert!(keypair.public_key().verify(msg, &decoded).is_ok());

        // rsp + L over the 57-byte response half. For any canonical rsp < L,
        // rsp + L < 2^447 < 2^448, so byte 56 stays 0 — this exercises the
        // canonical-scalar (< L) check specifically, not the byte-56 check.
        let mut rsp_half = [0u8; ED448_SIG_SIZE];
        rsp_half.copy_from_slice(&bytes[..ED448_SIG_SIZE]);
        let rsp_plus_l = add_le_57(&rsp_half, &ED448_L_LE);
        assert_eq!(
            rsp_plus_l[56], 0,
            "rsp + L must keep byte 56 zero for a genuine < L witness"
        );

        let mut forged = bytes;
        forged[..ED448_SIG_SIZE].copy_from_slice(&rsp_plus_l);
        assert!(
            TestSignature::from_bytes(&forged).is_err(),
            "rsp + L is non-canonical and MUST be rejected by the UR guard"
        );
    }

    // Test with BLAKE3 variant if available
    #[cfg(feature = "mldsa-blake3")]
    mod blake3_tests {
        use super::*;
        use trelis_primitives::MlDsa65Blake3;

        #[test]
        fn test_blake3_sign_verify() {
            let keypair = HybridSigningKeypair::<MlDsa65Blake3>::generate().unwrap();
            let message = b"Hello, BLAKE3!";

            let signature = keypair.sign(message).unwrap();
            assert!(keypair.public_key().verify(message, &signature).is_ok());
        }

        #[test]
        fn test_blake3_serialisation() {
            let keypair = HybridSigningKeypair::<MlDsa65Blake3>::generate().unwrap();
            let bytes = keypair.to_bytes();

            let recovered = HybridSigningKeypair::<MlDsa65Blake3>::from_bytes(&bytes[..]).unwrap();
            assert_eq!(
                keypair.public_key().to_bytes(),
                recovered.public_key().to_bytes()
            );
        }
    }
}
