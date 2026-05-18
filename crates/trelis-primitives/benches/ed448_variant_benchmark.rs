//! Benchmark for Ed448: SHAKE256 vs BLAKE3 variant comparison.
//!
//! Run:
//!   cargo bench -p trelis-primitives --bench ed448_variant_benchmark

// Internal benchmarks; pedantic warnings have no value here and are silenced
// wholesale.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    missing_docs
)]

use criterion::{Criterion, criterion_group, criterion_main};

use trelis_primitives::ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};
use trelis_primitives::ed448b::{Ed448BSignature, Ed448BSigningKey, Ed448BVerifyingKey};

fn bench_ed448_shake(c: &mut Criterion) {
    let sk = Ed448SigningKey::generate().unwrap();
    let vk = sk.verifying_key();

    let m64 = [0u8; 64];
    let m1m = vec![0u8; 1024 * 1024];
    let m100m = vec![0u8; 100 * 1024 * 1024];

    let sig = sk.sign(&m64);

    let sk_bytes = *sk.seed();
    let vk_bytes = vk.to_bytes();
    let sig_bytes = sig.to_bytes();

    c.bench_function("ed448 shake sign 64B", |b| {
        b.iter(|| {
            let sk = Ed448SigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m64);
        });
    });

    c.bench_function("ed448 shake sign 1MB", |b| {
        b.iter(|| {
            let sk = Ed448SigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m1m);
        });
    });

    c.bench_function("ed448 shake sign 100MB", |b| {
        b.iter(|| {
            let sk = Ed448SigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m100m);
        });
    });

    c.bench_function("ed448 shake verify 64B", |b| {
        b.iter(|| {
            let vk = Ed448VerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448Signature::from_bytes(&sig_bytes).unwrap();
            let _ver = vk.verify(&m64, &sig);
        });
    });

    let sig_1m = sk.sign(&m1m);
    let sig_1m_bytes = sig_1m.to_bytes();

    c.bench_function("ed448 shake verify 1MB", |b| {
        b.iter(|| {
            let vk = Ed448VerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448Signature::from_bytes(&sig_1m_bytes).unwrap();
            let _ver = vk.verify(&m1m, &sig);
        });
    });

    let sig_100m = sk.sign(&m100m);
    let sig_100m_bytes = sig_100m.to_bytes();

    c.bench_function("ed448 shake verify 100MB", |b| {
        b.iter(|| {
            let vk = Ed448VerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448Signature::from_bytes(&sig_100m_bytes).unwrap();
            let _ver = vk.verify(&m100m, &sig);
        });
    });
}

fn bench_ed448_blake3(c: &mut Criterion) {
    let sk = Ed448BSigningKey::generate().unwrap();
    let vk = sk.verifying_key();

    let m64 = [0u8; 64];
    let m1m = vec![0u8; 1024 * 1024];
    let m100m = vec![0u8; 100 * 1024 * 1024];

    let sig = sk.sign(&m64);

    let sk_bytes = *sk.seed();
    let vk_bytes = vk.to_bytes();
    let sig_bytes = sig.to_bytes();

    c.bench_function("ed448 blake3 sign 64B", |b| {
        b.iter(|| {
            let sk = Ed448BSigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m64);
        });
    });

    c.bench_function("ed448 blake3 sign 1MB", |b| {
        b.iter(|| {
            let sk = Ed448BSigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m1m);
        });
    });

    c.bench_function("ed448 blake3 sign 100MB", |b| {
        b.iter(|| {
            let sk = Ed448BSigningKey::from_seed(sk_bytes);
            let _sig = sk.sign(&m100m);
        });
    });

    c.bench_function("ed448 blake3 verify 64B", |b| {
        b.iter(|| {
            let vk = Ed448BVerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448BSignature::from_bytes(&sig_bytes).unwrap();
            let _ver = vk.verify(&m64, &sig);
        });
    });

    let sig_1m = sk.sign(&m1m);
    let sig_1m_bytes = sig_1m.to_bytes();

    c.bench_function("ed448 blake3 verify 1MB", |b| {
        b.iter(|| {
            let vk = Ed448BVerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448BSignature::from_bytes(&sig_1m_bytes).unwrap();
            let _ver = vk.verify(&m1m, &sig);
        });
    });

    let sig_100m = sk.sign(&m100m);
    let sig_100m_bytes = sig_100m.to_bytes();

    c.bench_function("ed448 blake3 verify 100MB", |b| {
        b.iter(|| {
            let vk = Ed448BVerifyingKey::from_bytes(&vk_bytes).unwrap();
            let sig = Ed448BSignature::from_bytes(&sig_100m_bytes).unwrap();
            let _ver = vk.verify(&m100m, &sig);
        });
    });
}

criterion_group!(benches, bench_ed448_shake, bench_ed448_blake3);
criterion_main!(benches);
