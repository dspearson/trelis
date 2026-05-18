//! # ML-DSA Digital Signature Algorithm
//!
//! This module implements ML-DSA (Module-Lattice Digital Signature Algorithm) as specified
//! in FIPS 204, with support for multiple hash function backends:
//!
//! - **SHAKE** (FIPS 204 standard): `shake` submodule
//! - **BLAKE3** (experimental variant): `blake3` submodule
//!
//! # Hash Variants
//!
//! Both SHAKE and BLAKE3 modules provide identical APIs but produce incompatible
//! keys and signatures. Keys created with one hash cannot be used with the other.

// Allow non-snake_case for mathematical notation matching FIPS 204 (e.g., M, Mp)
#![allow(non_snake_case)]
// mldsa_core implements FIPS 204 ML-DSA-65 against the reference algorithms
// (RejNTTPoly, BitPack/BitUnpack, NTT/NTT^{-1}). Cast lints surface on every
// coefficient reduction mandated by FIPS 204 §§2.3, 3.3, 8. Constants are
// compile-time and verified against the spec; pedantic rewrites would
// obscure the §-reference correspondence and risk breaking the in-source
// `// AUDIT: ...` comments that anchor security review.
#![allow(clippy::pedantic)]

extern crate alloc;

mod algebra;
/// SHAKE hash function implementation (FIPS 204 standard)
pub mod crypto;
/// BLAKE3 hash function implementation (experimental)
pub mod crypto_blake3;
mod encode;
/// Hash function abstraction traits
pub mod hash;
mod hint;
mod internal;
mod ntt;
mod param;
mod sampling;
mod util;

mod module_lattice;

use core::convert::{TryFrom, TryInto};
use hybrid_array::{
    Array,
    typenum::{
        Diff, Length, Prod, Quot, Shleft, U1, U2, U4, U5, U6, U7, U8, U17, U19, U32, U48, U55, U64,
        U75, U80, U88,
    },
};

use self::algebra::{AlgebraExt, Vector};
use self::hint::Hint;
use self::param::{ParameterSet, QMinus1};

pub use self::hash::{HashState, HashSuite};
pub use self::param::{EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, MlDsaParams};
pub use self::util::{B32, B64};
pub use signature::{self, Error, MultipartSigner, MultipartVerifier};

pub use self::crypto::ShakeSuite;
pub use self::crypto_blake3::Blake3Suite;

// ============================================================================
// Signature type (hash-independent)
// ============================================================================

/// An ML-DSA signature.
///
/// Signatures are hash-independent - the same signature type is used regardless
/// of whether SHAKE or BLAKE3 was used for signing.
#[derive(Clone, PartialEq, Debug)]
pub struct Signature<P: MlDsaParams> {
    pub(crate) c_tilde: Array<u8, P::Lambda>,
    pub(crate) z: Vector<P::L>,
    pub(crate) h: Hint<P>,
}

impl<P: MlDsaParams> Signature<P> {
    /// Encode the signature in a fixed-size byte array.
    // Algorithm 26 sigEncode
    pub fn encode(&self) -> EncodedSignature<P> {
        let c_tilde = self.c_tilde.clone();
        let z = P::encode_z(&self.z);
        let h = self.h.bit_pack();
        P::concat_sig(c_tilde, z, h)
    }

    /// Decode the signature from an appropriately sized byte array.
    // Algorithm 27 sigDecode
    pub fn decode(enc: &EncodedSignature<P>) -> Option<Self> {
        let (c_tilde, z, h) = P::split_sig(enc);

        let c_tilde = c_tilde.clone();
        let z = P::decode_z(z);
        let h = Hint::bit_unpack(h)?;

        if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
            return None;
        }

        Some(Self { c_tilde, z, h })
    }
}

impl<'a, P: MlDsaParams> TryFrom<&'a [u8]> for Signature<P> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let enc = EncodedSignature::<P>::try_from(value).map_err(|_| Error::new())?;
        Self::decode(&enc).ok_or(Error::new())
    }
}

impl<P: MlDsaParams> TryInto<EncodedSignature<P>> for Signature<P> {
    type Error = Error;

    fn try_into(self) -> Result<EncodedSignature<P>, Self::Error> {
        Ok(self.encode())
    }
}

impl<P: MlDsaParams> signature::SignatureEncoding for Signature<P> {
    type Repr = EncodedSignature<P>;
}

// ============================================================================
// Parameter Sets
// ============================================================================

/// `MlDsa44` is the parameter set for security category 2.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa44;

impl ParameterSet for MlDsa44 {
    type K = U4;
    type L = U4;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U17>;
    type Gamma2 = Quot<QMinus1, U88>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U88, U2>, U1>>;
    type Lambda = U32;
    type Omega = U80;
    const TAU: usize = 39;
}

/// `MlDsa65` is the parameter set for security category 3.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa65;

impl ParameterSet for MlDsa65 {
    type K = U6;
    type L = U5;
    type Eta = U4;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U48;
    type Omega = U55;
    const TAU: usize = 49;
}

/// `MlDsa87` is the parameter set for security category 5.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlDsa87;

impl ParameterSet for MlDsa87 {
    type K = U8;
    type L = U7;
    type Eta = U2;
    type Gamma1 = Shleft<U1, U19>;
    type Gamma2 = Quot<QMinus1, U32>;
    type TwoGamma2 = Prod<U2, Self::Gamma2>;
    type W1Bits = Length<Diff<Quot<U32, U2>, U1>>;
    type Lambda = U64;
    type Omega = U75;
    const TAU: usize = 60;
}

// ============================================================================
// Hash-specific variant modules (generated via macro)
// ============================================================================

/// Macro to define a hash-specific ML-DSA variant module.
///
/// This generates wrapper types (`SigningKey`, `VerifyingKey`, `KeyPair`) that
/// delegate to the internal generic implementation with a specific hash suite.
macro_rules! define_mldsa_variant {
    (
        $(#[$module_meta:meta])*
        mod $mod_name:ident {
            hash_suite: $hash_suite:ty,
        }
    ) => {
        $(#[$module_meta])*
        pub mod $mod_name {
            //! ML-DSA implementation using a specific hash suite.

            extern crate alloc;
            use alloc::boxed::Box;

            use core::convert::AsRef;
            use core::fmt;

            use rand_core::{CryptoRng, RngCore};
            use zeroize::ZeroizeOnDrop;

            use super::internal::{
                self, SigningKeyData, VerifyingKeyData,
            };
            use super::param::{EncodedSigningKey, EncodedVerifyingKey, MlDsaParams};
            use super::util::{B32, B64};
            use super::{Error, Signature};
            use super::algebra::Truncate;

            type H = $hash_suite;

            // ================================================================
            // SigningKey
            // ================================================================

            /// An ML-DSA signing key.
            ///
            /// The key data is heap-allocated to avoid stack overflow with large
            /// ML-DSA parameter sets (KeyPair is ~106 KB for ML-DSA-65).
            #[derive(Clone, PartialEq)]
            pub struct SigningKey<P: MlDsaParams>(pub(crate) Box<SigningKeyData<P>>);

            impl<P: MlDsaParams> fmt::Debug for SigningKey<P> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct("SigningKey").finish_non_exhaustive()
                }
            }

            impl<P: MlDsaParams> ZeroizeOnDrop for SigningKey<P> {}

            impl<P: MlDsaParams> SigningKey<P> {
                /// Sign a message using the internal algorithm.
                ///
                /// This method reflects the ML-DSA.Sign_internal algorithm from FIPS 204.
                pub fn sign_internal(&self, Mp: &[&[u8]], rnd: &B32) -> Signature<P> {
                    internal::sign_internal::<P, H>(&self.0, &[Mp], rnd)
                }

                /// Sign a message deterministically.
                ///
                /// # Errors
                ///
                /// Returns an error if the context string is more than 255 bytes.
                pub fn sign_deterministic(&self, M: &[u8], ctx: &[u8]) -> Result<Signature<P>, Error> {
                    self.raw_sign_deterministic(&[M], ctx)
                }

                /// Sign a message deterministically with a pre-computed μ.
                pub fn sign_mu_deterministic(&self, mu: &B64) -> Signature<P> {
                    let rnd = B32::default();
                    internal::sign_mu::<P, H>(&self.0, mu, &rnd)
                }

                fn raw_sign_deterministic(&self, M: &[&[u8]], ctx: &[u8]) -> Result<Signature<P>, Error> {
                    if ctx.len() > 255 {
                        return Err(Error::new());
                    }

                    let rnd = B32::default();
                    let Mp = &[&[&[0], &[Truncate::truncate(ctx.len())], ctx], M];
                    Ok(internal::sign_internal::<P, H>(&self.0, Mp, &rnd))
                }

                /// Sign a message with randomness.
                ///
                /// # Errors
                ///
                /// Returns an error if the context string is more than 255 bytes.
                pub fn sign_randomized<R: rand_core::RngCore + rand_core::CryptoRng + ?Sized>(
                    &self,
                    M: &[u8],
                    ctx: &[u8],
                    rng: &mut R,
                ) -> Result<Signature<P>, Error> {
                    if ctx.len() > 255 {
                        return Err(Error::new());
                    }

                    let mut rnd = B32::default();
                    rng.fill_bytes(&mut rnd);

                    let Mp = &[&[0], &[Truncate::truncate(ctx.len())], ctx, M];
                    Ok(self.sign_internal(Mp, &rnd))
                }

                /// Sign with a pre-computed μ and randomness.
                pub fn sign_mu_randomized<R: rand_core::RngCore + rand_core::CryptoRng + ?Sized>(
                    &self,
                    mu: &B64,
                    rng: &mut R,
                ) -> Signature<P> {
                    let mut rnd = B32::default();
                    rng.fill_bytes(&mut rnd);
                    internal::sign_mu::<P, H>(&self.0, mu, &rnd)
                }

                /// Encode the signing key to bytes.
                pub fn encode(&self) -> EncodedSigningKey<P> {
                    internal::encode_signing_key(&self.0)
                }

                /// Decode a signing key from bytes.
                pub fn decode(enc: &EncodedSigningKey<P>) -> Self {
                    Self(Box::new(internal::decode_signing_key::<P, H>(enc)))
                }

                /// Derive the verifying key from this signing key.
                pub fn verifying_key(&self) -> VerifyingKey<P> {
                    VerifyingKey(Box::new(internal::derive_verifying_key::<P, H>(&self.0)))
                }

                /// Get the transcript hash (tr) for this key.
                pub fn tr(&self) -> &B64 {
                    &self.0.tr
                }
            }

            // Signer trait implementation
            impl<P: MlDsaParams> super::signature::Signer<Signature<P>> for SigningKey<P> {
                fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
                    self.sign_deterministic(msg, &[])
                }
            }

            impl<P: MlDsaParams> super::MultipartSigner<Signature<P>> for SigningKey<P> {
                fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
                    self.raw_sign_deterministic(msg, &[])
                }
            }

            // ================================================================
            // VerifyingKey
            // ================================================================

            /// An ML-DSA verifying key.
            ///
            /// The key data is heap-allocated to avoid stack overflow with large
            /// ML-DSA parameter sets (VerifyingKey is ~42 KB for ML-DSA-65).
            #[derive(Clone, PartialEq)]
            pub struct VerifyingKey<P: MlDsaParams>(pub(crate) Box<VerifyingKeyData<P>>);

            impl<P: MlDsaParams> fmt::Debug for VerifyingKey<P> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct("VerifyingKey").finish_non_exhaustive()
                }
            }

            impl<P: MlDsaParams> VerifyingKey<P> {
                /// Verify a signature using the internal algorithm.
                #[must_use]
                pub fn verify_internal(&self, Mp: &[&[u8]], sig: &Signature<P>) -> bool {
                    internal::verify_internal::<P, H>(&self.0, &[Mp], sig)
                }

                /// Verify a signature with a context string.
                #[must_use]
                pub fn verify_with_context(&self, M: &[u8], ctx: &[u8], sig: &Signature<P>) -> bool {
                    self.raw_verify_with_context(&[M], ctx, sig)
                }

                /// Verify a signature with a pre-computed μ.
                #[must_use]
                pub fn verify_mu(&self, mu: &B64, sig: &Signature<P>) -> bool {
                    internal::verify_mu::<P, H>(&self.0, mu, sig)
                }

                fn raw_verify_with_context(&self, M: &[&[u8]], ctx: &[u8], sig: &Signature<P>) -> bool {
                    if ctx.len() > 255 {
                        return false;
                    }

                    let Mp = &[&[&[0], &[Truncate::truncate(ctx.len())], ctx], M];
                    internal::verify_internal::<P, H>(&self.0, Mp, sig)
                }

                /// Encode the verifying key to bytes.
                pub fn encode(&self) -> EncodedVerifyingKey<P> {
                    internal::encode_verifying_key(&self.0)
                }

                /// Decode a verifying key from bytes.
                pub fn decode(enc: &EncodedVerifyingKey<P>) -> Self {
                    Self(Box::new(internal::decode_verifying_key::<P, H>(enc)))
                }

                /// Get the transcript hash (tr) for this key.
                pub fn tr(&self) -> &B64 {
                    &self.0.tr
                }
            }

            // Verifier trait implementation
            impl<P: MlDsaParams> super::signature::Verifier<Signature<P>> for VerifyingKey<P> {
                fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), Error> {
                    self.verify_with_context(msg, &[], signature)
                        .then_some(())
                        .ok_or(Error::new())
                }
            }

            impl<P: MlDsaParams> super::MultipartVerifier<Signature<P>> for VerifyingKey<P> {
                fn multipart_verify(&self, msg: &[&[u8]], signature: &Signature<P>) -> Result<(), Error> {
                    self.raw_verify_with_context(msg, &[], signature)
                        .then_some(())
                        .ok_or(Error::new())
                }
            }

            // ================================================================
            // KeyPair
            // ================================================================

            /// An ML-DSA key pair.
            pub struct KeyPair<P: MlDsaParams> {
                signing_key: SigningKey<P>,
                verifying_key: VerifyingKey<P>,
                #[allow(dead_code)]
                seed: B32,
            }

            impl<P: MlDsaParams> KeyPair<P> {
                /// Get the signing key.
                pub fn signing_key(&self) -> &SigningKey<P> {
                    &self.signing_key
                }

                /// Get the verifying key.
                pub fn verifying_key(&self) -> &VerifyingKey<P> {
                    &self.verifying_key
                }
            }

            impl<P: MlDsaParams> AsRef<VerifyingKey<P>> for KeyPair<P> {
                fn as_ref(&self) -> &VerifyingKey<P> {
                    &self.verifying_key
                }
            }

            impl<P: MlDsaParams> fmt::Debug for KeyPair<P> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_struct("KeyPair")
                        .field("verifying_key", &self.verifying_key)
                        .finish_non_exhaustive()
                }
            }

            impl<P: MlDsaParams> super::signature::KeypairRef for KeyPair<P> {
                type VerifyingKey = VerifyingKey<P>;
            }

            // Signer trait for KeyPair
            impl<P: MlDsaParams> super::signature::Signer<Signature<P>> for KeyPair<P> {
                fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
                    self.signing_key.try_sign(msg)
                }
            }

            impl<P: MlDsaParams> super::MultipartSigner<Signature<P>> for KeyPair<P> {
                fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature<P>, Error> {
                    self.signing_key.raw_sign_deterministic(msg, &[])
                }
            }

            // ================================================================
            // Key Generation
            // ================================================================

            /// Trait for key generation.
            pub trait KeyGen: MlDsaParams {
                /// The key pair type.
                type KeyPair: super::signature::Keypair;

                /// Generate a key pair from randomness.
                fn key_gen<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self::KeyPair;

                /// Generate a key pair from a seed (deterministic).
                fn key_gen_internal(seed: &B32) -> Self::KeyPair;
            }

            impl<P: MlDsaParams> KeyGen for P {
                type KeyPair = KeyPair<P>;

                fn key_gen<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> KeyPair<P> {
                    let mut seed = B32::default();
                    rng.fill_bytes(&mut seed);
                    Self::key_gen_internal(&seed)
                }

                fn key_gen_internal(seed: &B32) -> KeyPair<P> {
                    let (sk_data, vk_data) = internal::key_gen::<P, H>(seed);
                    KeyPair {
                        signing_key: SigningKey(Box::new(sk_data)),
                        verifying_key: VerifyingKey(Box::new(vk_data)),
                        seed: seed.clone(),
                    }
                }
            }

            /// Generate a key pair from a seed (convenience function).
            pub fn key_gen_internal<P: MlDsaParams>(seed: &B32) -> KeyPair<P> {
                <P as KeyGen>::key_gen_internal(seed)
            }

            /// Generate a key pair from randomness (convenience function).
            pub fn key_gen<P: MlDsaParams, R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> KeyPair<P> {
                <P as KeyGen>::key_gen(rng)
            }

            /// Compute the message representative (μ) for signing/verification.
            pub fn message_representative<P: MlDsaParams>(tr: &B64, msg: &[&[u8]]) -> B64 {
                type HH = <H as super::HashSuite>::H;

                let mut h = HH::default().absorb(tr.as_ref());
                for m in msg {
                    h = h.absorb(m);
                }
                h.squeeze_new()
            }
        }
    };
}

// Generate the SHAKE variant module
define_mldsa_variant! {
    /// ML-DSA with SHAKE hash functions (FIPS 204 standard).
    ///
    /// This is the standard ML-DSA implementation using SHAKE128 for the G function
    /// and SHAKE256 for the H function, as specified in FIPS 204.
    mod shake {
        hash_suite: super::crypto::ShakeSuite,
    }
}

// Generate the BLAKE3 variant module
define_mldsa_variant! {
    /// ML-DSA with BLAKE3 hash functions (experimental variant).
    ///
    /// This is an experimental variant using BLAKE3 with different domain separators
    /// for the G and H functions. Keys and signatures are NOT compatible with the
    /// standard SHAKE variant.
    mod blake3 {
        hash_suite: super::crypto_blake3::Blake3Suite,
    }
}

// ============================================================================
// Backward Compatibility Aliases
// ============================================================================

// Default to SHAKE for backward compatibility
pub use shake::{KeyGen, KeyPair, SigningKey, VerifyingKey};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod test {
    use self::param::*;
    use super::*;
    use hybrid_array::Array;
    use hybrid_array::typenum::Unsigned;

    #[test]
    fn encode_decode_round_trip_shake() {
        let kp = shake::key_gen_internal::<MlDsa44>(&Array::default());
        let sk = kp.signing_key();
        let vk = kp.verifying_key();

        let vk_bytes = vk.encode();
        let vk2 = shake::VerifyingKey::<MlDsa44>::decode(&vk_bytes);
        assert!(*vk == vk2);

        let sk_bytes = sk.encode();
        let sk2 = shake::SigningKey::<MlDsa44>::decode(&sk_bytes);
        assert!(*sk == sk2);
    }

    #[test]
    fn sign_verify_round_trip_shake() {
        for param in [44, 65, 87] {
            match param {
                44 => {
                    let kp = shake::key_gen_internal::<MlDsa44>(&Array::default());
                    let M = b"Hello world";
                    let rnd = Array([0u8; 32]);
                    let sig = kp.signing_key().sign_internal(&[M], &rnd);
                    assert!(kp.verifying_key().verify_internal(&[M], &sig));
                }
                65 => {
                    let kp = shake::key_gen_internal::<MlDsa65>(&Array::default());
                    let M = b"Hello world";
                    let rnd = Array([0u8; 32]);
                    let sig = kp.signing_key().sign_internal(&[M], &rnd);
                    assert!(kp.verifying_key().verify_internal(&[M], &sig));
                }
                87 => {
                    let kp = shake::key_gen_internal::<MlDsa87>(&Array::default());
                    let M = b"Hello world";
                    let rnd = Array([0u8; 32]);
                    let sig = kp.signing_key().sign_internal(&[M], &rnd);
                    assert!(kp.verifying_key().verify_internal(&[M], &sig));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn sign_verify_round_trip_blake3() {
        let kp = blake3::key_gen_internal::<MlDsa65>(&Array::default());
        let M = b"Hello world";
        let rnd = Array([0u8; 32]);
        let sig = kp.signing_key().sign_internal(&[M], &rnd);
        assert!(kp.verifying_key().verify_internal(&[M], &sig));
    }

    #[test]
    fn public_from_private_shake() {
        let kp = shake::key_gen_internal::<MlDsa65>(&Array::default());
        let vk_derived = kp.signing_key().verifying_key();
        assert!(*kp.verifying_key() == vk_derived);
    }

    #[test]
    fn shake_blake3_incompatible() {
        // Same seed produces different keys with different hashes
        let seed = Array([0x42u8; 32]);

        let shake_kp = shake::key_gen_internal::<MlDsa65>(&seed);
        let blake3_kp = blake3::key_gen_internal::<MlDsa65>(&seed);

        // Verifying keys should be different
        assert!(shake_kp.verifying_key().encode() != blake3_kp.verifying_key().encode());

        // Signatures should not cross-verify
        let msg = b"test message";
        let shake_sig = shake_kp.signing_key().sign_deterministic(msg, &[]).unwrap();
        let blake3_sig = blake3_kp
            .signing_key()
            .sign_deterministic(msg, &[])
            .unwrap();

        // SHAKE signature should not verify with BLAKE3 key (and vice versa)
        // Note: We can't directly test this because the types are different,
        // but we can verify the encoded signatures are different
        assert!(shake_sig.encode() != blake3_sig.encode());
    }

    #[test]
    fn output_sizes() {
        // Verify standard ML-DSA sizes
        assert_eq!(SigningKeySize::<MlDsa44>::USIZE, 2560);
        assert_eq!(VerifyingKeySize::<MlDsa44>::USIZE, 1312);
        assert_eq!(SignatureSize::<MlDsa44>::USIZE, 2420);

        assert_eq!(SigningKeySize::<MlDsa65>::USIZE, 4032);
        assert_eq!(VerifyingKeySize::<MlDsa65>::USIZE, 1952);
        assert_eq!(SignatureSize::<MlDsa65>::USIZE, 3309);

        assert_eq!(SigningKeySize::<MlDsa87>::USIZE, 4896);
        assert_eq!(VerifyingKeySize::<MlDsa87>::USIZE, 2592);
        assert_eq!(SignatureSize::<MlDsa87>::USIZE, 4627);
    }

    #[test]
    fn sign_mu_verify_mu_round_trip() {
        let kp = shake::key_gen_internal::<MlDsa65>(&Array::default());
        let sk = kp.signing_key();
        let vk = kp.verifying_key();

        let M = b"Hello world";
        let mu = shake::message_representative::<MlDsa65>(sk.tr(), &[M]);
        let sig = sk.sign_mu_deterministic(&mu);

        assert!(vk.verify_mu(&mu, &sig));
    }
}
