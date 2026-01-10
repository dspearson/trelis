//! Internal implementation details for ML-DSA.
//!
//! This module contains hash-independent data structures and generic operations
//! that are parameterized over the hash suite. The public API wraps these with
//! hash-specific types.
//!
//! Note: Variable names like A_hat, K, etc. follow FIPS 204 specification notation.

// Allow non-snake_case for mathematical notation matching FIPS 204
#![allow(non_snake_case)]

use hybrid_array::typenum::Unsigned;
use zeroize::Zeroize;

use super::Signature;
use super::algebra::{AlgebraExt, Elem, NttMatrix, NttVector, Vector};
use super::hash::{HashState, HashSuite};
use super::hint::Hint;
use super::ntt::{Ntt, NttInverse};
use super::param::{
    EncodedSigningKey, EncodedVerifyingKey, MlDsaParams, ParameterSet, SamplingSize, SpecQ,
};
use super::sampling::{expand_a, expand_mask, expand_s, sample_in_ball};
use super::util::{B32, B64};

// ============================================================================
// Data Structures (hash-independent storage)
// ============================================================================

/// Internal signing key data storage.
///
/// This struct holds the raw key material without any hash-specific behavior.
/// Operations are performed via free functions that take a hash suite parameter.
#[derive(Clone, PartialEq)]
pub struct SigningKeyData<P: ParameterSet> {
    pub(crate) rho: B32,
    pub(crate) K: B32,
    pub(crate) tr: B64,
    pub(crate) s1: Vector<P::L>,
    pub(crate) s2: Vector<P::K>,
    pub(crate) t0: Vector<P::K>,

    // Derived/precomputed values
    pub(crate) s1_hat: NttVector<P::L>,
    pub(crate) s2_hat: NttVector<P::K>,
    pub(crate) t0_hat: NttVector<P::K>,
    pub(crate) A_hat: NttMatrix<P::K, P::L>,
}

impl<P: ParameterSet> Drop for SigningKeyData<P> {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.K.zeroize();
        self.tr.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
        self.t0.zeroize();
    }
}

/// Internal verifying key data storage.
#[derive(Clone, PartialEq)]
pub struct VerifyingKeyData<P: ParameterSet> {
    pub(crate) rho: B32,
    pub(crate) t1: Vector<P::K>,

    // Derived/precomputed values
    pub(crate) A_hat: NttMatrix<P::K, P::L>,
    pub(crate) t1_2d_hat: NttVector<P::K>,
    pub(crate) tr: B64,
}

// ============================================================================
// Key Construction (requires hash for derived values)
// ============================================================================

/// Create a SigningKeyData with precomputed values.
///
/// The `A_hat` matrix is computed from `rho` using the hash suite's G function.
pub fn new_signing_key<P: MlDsaParams, H: HashSuite>(
    rho: B32,
    K: B32,
    tr: B64,
    s1: Vector<P::L>,
    s2: Vector<P::K>,
    t0: Vector<P::K>,
    A_hat: Option<NttMatrix<P::K, P::L>>,
) -> SigningKeyData<P> {
    let A_hat = A_hat.unwrap_or_else(|| expand_a::<H::G, P::K, P::L>(&rho));
    let s1_hat = s1.ntt();
    let s2_hat = s2.ntt();
    let t0_hat = t0.ntt();

    SigningKeyData {
        rho,
        K,
        tr,
        s1,
        s2,
        t0,
        s1_hat,
        s2_hat,
        t0_hat,
        A_hat,
    }
}

/// Create a VerifyingKeyData with precomputed values.
///
/// The `A_hat` matrix is computed from `rho` using the hash suite's G function.
/// The `tr` transcript hash is computed using the hash suite's H function.
pub fn new_verifying_key<P: MlDsaParams, H: HashSuite>(
    rho: B32,
    t1: Vector<P::K>,
    A_hat: Option<NttMatrix<P::K, P::L>>,
    enc: Option<EncodedVerifyingKey<P>>,
) -> VerifyingKeyData<P> {
    let A_hat = A_hat.unwrap_or_else(|| expand_a::<H::G, P::K, P::L>(&rho));
    let enc = enc.unwrap_or_else(|| encode_verifying_key_internal::<P>(&rho, &t1));

    let t1_2d_hat = (Elem::new(1 << 13) * &t1).ntt();
    let tr: B64 = H::H::default().absorb(&enc).squeeze_new();

    VerifyingKeyData {
        rho,
        t1,
        A_hat,
        t1_2d_hat,
        tr,
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a key pair from a seed.
///
/// Algorithm 6 ML-DSA.KeyGen_internal from FIPS 204.
pub fn key_gen<P, H>(seed: &B32) -> (SigningKeyData<P>, VerifyingKeyData<P>)
where
    P: MlDsaParams,
    P::K: Unsigned,
    P::L: Unsigned,
    P::Eta: SamplingSize,
    H: HashSuite,
{
    // Derive seeds using H
    let mut h = H::H::default()
        .absorb(seed)
        .absorb(&[P::K::U8])
        .absorb(&[P::L::U8]);

    let rho: B32 = h.squeeze_new();
    let rhop: B64 = h.squeeze_new();
    let K: B32 = h.squeeze_new();

    // Sample private key components using H
    let A_hat = expand_a::<H::G, P::K, P::L>(&rho);
    let s1 = expand_s::<H::H, P::L>(&rhop, P::Eta::ETA, 0);
    let s2 = expand_s::<H::H, P::K>(&rhop, P::Eta::ETA, P::L::USIZE);

    // Compute derived values
    let As1_hat = &A_hat * &s1.ntt();
    let t = &As1_hat.ntt_inverse() + &s2;

    // Compress and encode
    let (t1, t0) = t.power2round();

    let vk = new_verifying_key::<P, H>(rho, t1, Some(A_hat.clone()), None);
    let sk = new_signing_key::<P, H>(rho, K, vk.tr, s1, s2, t0, Some(A_hat));

    (sk, vk)
}

/// Derive a verifying key from a signing key.
pub fn derive_verifying_key<P: MlDsaParams, H: HashSuite>(
    sk: &SigningKeyData<P>,
) -> VerifyingKeyData<P> {
    let As1 = &sk.A_hat * &sk.s1_hat;
    let t = &As1.ntt_inverse() + &sk.s2;

    // Discard t0
    let (t1, _) = t.power2round();

    new_verifying_key::<P, H>(sk.rho, t1, Some(sk.A_hat.clone()), None)
}

// ============================================================================
// Signing Operations
// ============================================================================

/// Compute message representative.
fn message_representative<H: HashState>(tr: &[u8], Mp: &[&[&[u8]]]) -> B64 {
    let mut h = H::default().absorb(tr);

    for m in Mp.iter().copied().flatten() {
        h = h.absorb(m);
    }

    h.squeeze_new()
}

/// Sign with pre-computed μ (message representative).
///
/// This is the core signing operation from Algorithm 7 ML-DSA.Sign_internal.
pub fn sign_mu<P, H>(sk: &SigningKeyData<P>, mu: &B64, rnd: &B32) -> Signature<P>
where
    P: MlDsaParams,
    P::L: Unsigned,
    P::Gamma2: Unsigned,
    P::Omega: Unsigned,
    H: HashSuite,
{
    // Compute the private random seed
    let rhopp: B64 = H::H::default()
        .absorb(&sk.K)
        .absorb(rnd)
        .absorb(mu)
        .squeeze_new();

    // Rejection sampling loop
    for kappa in (0..u16::MAX).step_by(P::L::USIZE) {
        let y = expand_mask::<H::H, P::L, P::Gamma1>(&rhopp, kappa);
        let w = (&sk.A_hat * &y.ntt()).ntt_inverse();
        let w1 = w.high_bits::<P::TwoGamma2>();

        let w1_tilde = P::encode_w1(&w1);
        let c_tilde = H::H::default()
            .absorb(mu)
            .absorb(&w1_tilde)
            .squeeze_new::<P::Lambda>();
        let c = sample_in_ball::<H::H>(&c_tilde, P::TAU);
        let c_hat = c.ntt();

        let cs1 = (&c_hat * &sk.s1_hat).ntt_inverse();
        let cs2 = (&c_hat * &sk.s2_hat).ntt_inverse();

        let z = &y + &cs1;
        let r0 = (&w - &cs2).low_bits::<P::TwoGamma2>();

        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA || r0.infinity_norm() >= P::GAMMA2_MINUS_BETA {
            continue;
        }

        let ct0 = (&c_hat * &sk.t0_hat).ntt_inverse();
        let minus_ct0 = -&ct0;
        let w_cs2_ct0 = &(&w - &cs2) + &ct0;
        let h = Hint::<P>::new(&minus_ct0, &w_cs2_ct0);

        if ct0.infinity_norm() >= P::Gamma2::U32 || h.hamming_weight() > P::Omega::USIZE {
            continue;
        }

        let z = z.mod_plus_minus::<SpecQ>();
        return Signature { c_tilde, z, h };
    }

    unreachable!("Rejection sampling failed to find a valid signature");
}

/// Sign a message (internal algorithm).
///
/// Algorithm 7 ML-DSA.Sign_internal from FIPS 204.
pub fn sign_internal<P: MlDsaParams, H: HashSuite>(
    sk: &SigningKeyData<P>,
    Mp: &[&[&[u8]]],
    rnd: &B32,
) -> Signature<P> {
    let mu = message_representative::<H::H>(&sk.tr, Mp);
    sign_mu::<P, H>(sk, &mu, rnd)
}

// ============================================================================
// Verification Operations
// ============================================================================

/// Verify with pre-computed μ (message representative).
pub fn verify_mu<P: MlDsaParams, H: HashSuite>(
    vk: &VerifyingKeyData<P>,
    mu: &B64,
    sigma: &Signature<P>,
) -> bool {
    // Reconstruct w
    let c = sample_in_ball::<H::H>(&sigma.c_tilde, P::TAU);

    let z_hat = sigma.z.ntt();
    let c_hat = c.ntt();
    let Az_hat = &vk.A_hat * &z_hat;
    let ct1_2d_hat = &c_hat * &vk.t1_2d_hat;

    let wp_approx = (&Az_hat - &ct1_2d_hat).ntt_inverse();
    let w1p = sigma.h.use_hint(&wp_approx);

    let w1p_tilde = P::encode_w1(&w1p);
    let cp_tilde = H::H::default()
        .absorb(mu)
        .absorb(&w1p_tilde)
        .squeeze_new::<P::Lambda>();

    sigma.c_tilde == cp_tilde
}

/// Verify a message (internal algorithm).
///
/// Algorithm 8 ML-DSA.Verify_internal from FIPS 204.
pub fn verify_internal<P: MlDsaParams, H: HashSuite>(
    vk: &VerifyingKeyData<P>,
    Mp: &[&[&[u8]]],
    sigma: &Signature<P>,
) -> bool {
    let mu = message_representative::<H::H>(&vk.tr, Mp);
    verify_mu::<P, H>(vk, &mu, sigma)
}

// ============================================================================
// Encoding/Decoding
// ============================================================================

/// Encode a signing key to bytes.
///
/// Algorithm 24 skEncode from FIPS 204.
pub fn encode_signing_key<P: MlDsaParams>(sk: &SigningKeyData<P>) -> EncodedSigningKey<P> {
    let s1_enc = P::encode_s1(&sk.s1);
    let s2_enc = P::encode_s2(&sk.s2);
    let t0_enc = P::encode_t0(&sk.t0);
    P::concat_sk(sk.rho, sk.K, sk.tr, s1_enc, s2_enc, t0_enc)
}

/// Decode a signing key from bytes.
///
/// Algorithm 25 skDecode from FIPS 204.
/// Requires hash suite to recompute A_hat from rho.
pub fn decode_signing_key<P: MlDsaParams, H: HashSuite>(
    enc: &EncodedSigningKey<P>,
) -> SigningKeyData<P> {
    let (rho, K, tr, s1_enc, s2_enc, t0_enc) = P::split_sk(enc);
    new_signing_key::<P, H>(
        *rho,
        *K,
        *tr,
        P::decode_s1(s1_enc),
        P::decode_s2(s2_enc),
        P::decode_t0(t0_enc),
        None,
    )
}

fn encode_verifying_key_internal<P: MlDsaParams>(
    rho: &B32,
    t1: &Vector<P::K>,
) -> EncodedVerifyingKey<P> {
    let t1_enc = P::encode_t1(t1);
    P::concat_vk(*rho, t1_enc)
}

/// Encode a verifying key to bytes.
///
/// Algorithm 22 pkEncode from FIPS 204.
pub fn encode_verifying_key<P: MlDsaParams>(vk: &VerifyingKeyData<P>) -> EncodedVerifyingKey<P> {
    encode_verifying_key_internal::<P>(&vk.rho, &vk.t1)
}

/// Decode a verifying key from bytes.
///
/// Algorithm 23 pkDecode from FIPS 204.
/// Requires hash suite to recompute A_hat and tr.
pub fn decode_verifying_key<P: MlDsaParams, H: HashSuite>(
    enc: &EncodedVerifyingKey<P>,
) -> VerifyingKeyData<P> {
    let (rho, t1_enc) = P::split_vk(enc);
    let t1 = P::decode_t1(t1_enc);
    new_verifying_key::<P, H>(*rho, t1, None, Some(enc.clone()))
}

// ============================================================================
// Debug implementations
// ============================================================================

impl<P: ParameterSet> core::fmt::Debug for SigningKeyData<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKeyData").finish_non_exhaustive()
    }
}

impl<P: ParameterSet> core::fmt::Debug for VerifyingKeyData<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKeyData")
            .field("rho", &self.rho)
            .finish_non_exhaustive()
    }
}
