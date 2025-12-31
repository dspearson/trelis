//! Benchmarks for trelis-hybrid optimisation targets.
//!
//! Run with: `cargo bench -p trelis-hybrid`

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use trelis_hybrid::{HybridIdentityKeypair, HybridKemKeypair, SafetyNumber};

/// Benchmark safety number creation.
///
/// This involves hashing two 3,223-byte identity keys.
fn bench_safety_number_new(c: &mut Criterion) {
    let alice = HybridIdentityKeypair::generate().expect("keygen failed");
    let bob = HybridIdentityKeypair::generate().expect("keygen failed");

    c.bench_function("safety_number_new", |b| {
        b.iter(|| {
            let sn = SafetyNumber::new(black_box(alice.public_key()), black_box(bob.public_key()));
            black_box(sn)
        })
    });
}

/// Benchmark safety number with history sync (includes thread ID).
fn bench_safety_number_with_sync(c: &mut Criterion) {
    let alice = HybridIdentityKeypair::generate().expect("keygen failed");
    let bob = HybridIdentityKeypair::generate().expect("keygen failed");
    let thread_id = [0x42u8; 32];

    c.bench_function("safety_number_with_sync", |b| {
        b.iter(|| {
            let sn = SafetyNumber::new_with_history_sync(
                black_box(alice.public_key()),
                black_box(bob.public_key()),
                black_box(&thread_id),
            );
            black_box(sn)
        })
    });
}

/// Benchmark safety number display formatting.
fn bench_safety_number_display(c: &mut Criterion) {
    let alice = HybridIdentityKeypair::generate().expect("keygen failed");
    let bob = HybridIdentityKeypair::generate().expect("keygen failed");
    let sn = SafetyNumber::new(alice.public_key(), bob.public_key());

    c.bench_function("safety_number_display", |b| {
        b.iter(|| {
            let display = sn.display();
            black_box(display)
        })
    });
}

/// Benchmark safety number QR encoding.
fn bench_safety_number_qr(c: &mut Criterion) {
    let alice = HybridIdentityKeypair::generate().expect("keygen failed");
    let bob = HybridIdentityKeypair::generate().expect("keygen failed");
    let sn = SafetyNumber::new(alice.public_key(), bob.public_key());

    c.bench_function("safety_number_to_qr", |b| {
        b.iter(|| {
            let qr = sn.to_qr_string();
            black_box(qr)
        })
    });
}

/// Benchmark hybrid KEM public key serialization.
fn bench_kem_public_key_to_bytes(c: &mut Criterion) {
    let keypair = HybridKemKeypair::generate().expect("keygen failed");
    let public_key = keypair.public_key();

    c.bench_function("kem_public_key_to_bytes", |b| {
        b.iter(|| {
            let bytes = public_key.to_bytes();
            black_box(bytes)
        })
    });
}

/// Benchmark hybrid identity public key serialization.
fn bench_identity_public_key_to_bytes(c: &mut Criterion) {
    let keypair = HybridIdentityKeypair::generate().expect("keygen failed");
    let public_key = keypair.public_key();

    c.bench_function("identity_public_key_to_bytes", |b| {
        b.iter(|| {
            let bytes = public_key.to_bytes();
            black_box(bytes)
        })
    });
}

criterion_group!(
    benches,
    bench_safety_number_new,
    bench_safety_number_with_sync,
    bench_safety_number_display,
    bench_safety_number_qr,
    bench_kem_public_key_to_bytes,
    bench_identity_public_key_to_bytes,
);

criterion_main!(benches);
