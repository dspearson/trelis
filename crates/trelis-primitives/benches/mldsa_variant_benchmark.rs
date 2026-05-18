//! Benchmark for ML-DSA: SHAKE vs BLAKE3 variant comparison.
//!
//! Run:
//!   cargo bench -p trelis-primitives --bench mldsa_variant_benchmark

// Internal benchmarks; pedantic warnings have no value here and are silenced
// wholesale. Phase 10 disposition (b) — `10-PEDANTIC-DRAFT.md`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    missing_docs
)]

use criterion::{Criterion, criterion_group, criterion_main};
use hybrid_array::{Array, ArraySize};
use rand::{CryptoRng, RngCore};

use trelis_primitives::mldsa_core::{
    B32, B64, MlDsa65, Signature,
    blake3::{self, SigningKey as Blake3SigningKey, VerifyingKey as Blake3VerifyingKey},
    shake::{self, SigningKey as ShakeSigningKey, VerifyingKey as ShakeVerifyingKey},
};

pub fn rand_arr<L: ArraySize, R: CryptoRng + RngCore + ?Sized>(rng: &mut R) -> Array<u8, L> {
    let mut val = Array::<u8, L>::default();
    rng.fill_bytes(&mut val);
    val
}

fn bench_mldsa_shake(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let xi: B32 = rand_arr(&mut rng);
    let ctx: B32 = rand_arr(&mut rng);

    let m64: B64 = rand_arr(&mut rng);
    let m1m = vec![0u8; 1024 * 1024];
    let m100m = vec![0u8; 100 * 1024 * 1024];

    let kp = shake::key_gen_internal::<MlDsa65>(&xi);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    let sig = sk.sign_deterministic(&m64, &ctx).unwrap();

    let sk_bytes = sk.encode();
    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    c.bench_function("mldsa shake sign 64B", |b| {
        b.iter(|| {
            let sk = ShakeSigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m64, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa shake sign 1MB", |b| {
        b.iter(|| {
            let sk = ShakeSigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m1m, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa shake sign 100MB", |b| {
        b.iter(|| {
            let sk = ShakeSigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m100m, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa shake verify 64B", |b| {
        b.iter(|| {
            let vk = ShakeVerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();
            let _ver = vk.verify_with_context(&m64, &ctx, &sig);
        });
    });

    let sig_1m = sk.sign_deterministic(&m1m, &ctx).unwrap();
    let sig_1m_bytes = sig_1m.encode();

    c.bench_function("mldsa shake verify 1MB", |b| {
        b.iter(|| {
            let vk = ShakeVerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_1m_bytes).unwrap();
            let _ver = vk.verify_with_context(&m1m, &ctx, &sig);
        });
    });

    let sig_100m = sk.sign_deterministic(&m100m, &ctx).unwrap();
    let sig_100m_bytes = sig_100m.encode();

    c.bench_function("mldsa shake verify 100MB", |b| {
        b.iter(|| {
            let vk = ShakeVerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_100m_bytes).unwrap();
            let _ver = vk.verify_with_context(&m100m, &ctx, &sig);
        });
    });
}

fn bench_mldsa_blake3(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let xi: B32 = rand_arr(&mut rng);
    let ctx: B32 = rand_arr(&mut rng);

    let m64: B64 = rand_arr(&mut rng);
    let m1m = vec![0u8; 1024 * 1024];
    let m100m = vec![0u8; 100 * 1024 * 1024];

    let kp = blake3::key_gen_internal::<MlDsa65>(&xi);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    let sig = sk.sign_deterministic(&m64, &ctx).unwrap();

    let sk_bytes = sk.encode();
    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();

    c.bench_function("mldsa blake3 sign 64B", |b| {
        b.iter(|| {
            let sk = Blake3SigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m64, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa blake3 sign 1MB", |b| {
        b.iter(|| {
            let sk = Blake3SigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m1m, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa blake3 sign 100MB", |b| {
        b.iter(|| {
            let sk = Blake3SigningKey::<MlDsa65>::decode(&sk_bytes);
            let _sig = sk.sign_randomized(&m100m, &ctx, &mut rng);
        });
    });

    c.bench_function("mldsa blake3 verify 64B", |b| {
        b.iter(|| {
            let vk = Blake3VerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();
            let _ver = vk.verify_with_context(&m64, &ctx, &sig);
        });
    });

    let sig_1m = sk.sign_deterministic(&m1m, &ctx).unwrap();
    let sig_1m_bytes = sig_1m.encode();

    c.bench_function("mldsa blake3 verify 1MB", |b| {
        b.iter(|| {
            let vk = Blake3VerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_1m_bytes).unwrap();
            let _ver = vk.verify_with_context(&m1m, &ctx, &sig);
        });
    });

    let sig_100m = sk.sign_deterministic(&m100m, &ctx).unwrap();
    let sig_100m_bytes = sig_100m.encode();

    c.bench_function("mldsa blake3 verify 100MB", |b| {
        b.iter(|| {
            let vk = Blake3VerifyingKey::<MlDsa65>::decode(&vk_bytes);
            let sig = Signature::<MlDsa65>::decode(&sig_100m_bytes).unwrap();
            let _ver = vk.verify_with_context(&m100m, &ctx, &sig);
        });
    });
}

criterion_group!(benches, bench_mldsa_shake, bench_mldsa_blake3);
criterion_main!(benches);
