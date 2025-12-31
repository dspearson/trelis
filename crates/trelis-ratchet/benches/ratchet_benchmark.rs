//! Benchmarks for trelis-ratchet optimisation targets.
//!
//! Run with: `cargo bench -p trelis-ratchet`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use trelis_hybrid::HybridKemKeypair;
use trelis_ratchet::kdf::{derive_initial_root_key, kdf_rk};
use trelis_ratchet::state::{KemRatchet, derive_key_id};

/// Benchmark the KDF root key derivation function.
///
/// This is a hot path that currently uses Vec allocation.
/// Target: eliminate heap allocation using fixed-size stack buffer.
fn bench_kdf_rk(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_rk");

    // Test with typical hybrid shared secret size (88 bytes: 32 X448 + 32 sntrup761 + overhead)
    let root_key = [0x42u8; 32];

    for secret_size in [32, 64, 88, 120] {
        let shared_secret = vec![0xABu8; secret_size];

        group.bench_with_input(
            BenchmarkId::new("derive", secret_size),
            &shared_secret,
            |b, ss| {
                b.iter(|| {
                    let output = kdf_rk(black_box(&root_key), black_box(ss));
                    black_box(output)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark the initial root key derivation.
fn bench_derive_initial_root_key(c: &mut Criterion) {
    let session_key = [0x42u8; 32];

    c.bench_function("derive_initial_root_key", |b| {
        b.iter(|| {
            let key = derive_initial_root_key(black_box(&session_key));
            black_box(key)
        })
    });
}

/// Benchmark key ID derivation from public key.
///
/// This involves BLAKE3 hashing of the serialised public key.
fn bench_derive_key_id(c: &mut Criterion) {
    let keypair = HybridKemKeypair::generate().expect("keygen failed");
    let public_key = keypair.public_key();

    c.bench_function("derive_key_id", |b| {
        b.iter(|| {
            let key_id = derive_key_id(black_box(public_key));
            black_box(key_id)
        })
    });
}

/// Benchmark keypair lookup in KemRatchet state.
///
/// This is currently O(n) linear search through previous_keypairs.
/// Target: use HashMap for O(1) lookup.
fn bench_find_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_keypair");

    let session_key = [0x42u8; 32];
    let their_keypair = HybridKemKeypair::generate().expect("keygen failed");

    for num_previous in [0, 2, 4, 6, 8] {
        // Create state with some previous keypairs
        let mut state =
            KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
                .expect("init failed");

        // Store key IDs to look up
        let mut key_ids = vec![state.our_key_id()];

        // Rotate keypairs to build up previous_keypairs
        for _ in 0..num_previous {
            let new_keypair = HybridKemKeypair::generate().expect("keygen failed");
            state.rotate_keypair(new_keypair);
            key_ids.push(state.our_key_id());
        }

        // Benchmark finding the oldest keypair (worst case for linear search)
        let oldest_key_id = key_ids[0];

        group.bench_with_input(
            BenchmarkId::new("oldest", num_previous),
            &oldest_key_id,
            |b, &key_id| {
                b.iter(|| {
                    let result = state.find_keypair(black_box(key_id));
                    black_box(result)
                })
            },
        );

        // Benchmark finding the current keypair (best case)
        let current_key_id = state.our_key_id();

        group.bench_with_input(
            BenchmarkId::new("current", num_previous),
            &current_key_id,
            |b, &key_id| {
                b.iter(|| {
                    let result = state.find_keypair(black_box(key_id));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark keypair rotation.
fn bench_rotate_keypair(c: &mut Criterion) {
    let session_key = [0x42u8; 32];
    let their_keypair = HybridKemKeypair::generate().expect("keygen failed");

    let mut state =
        KemRatchet::init_initiator(&session_key, their_keypair.public_key().clone(), 1000)
            .expect("init failed");

    // Pre-generate keypairs to avoid including keygen in benchmark
    let keypairs: Vec<_> = (0..100)
        .map(|_| HybridKemKeypair::generate().expect("keygen failed"))
        .collect();

    let mut idx = 0;

    c.bench_function("rotate_keypair", |b| {
        b.iter(|| {
            let new_keypair = keypairs[idx % keypairs.len()].clone();
            state.rotate_keypair(black_box(new_keypair));
            idx += 1;
        })
    });
}

/// Benchmark full ratchet initialisation.
fn bench_init_ratchet(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_ratchet");

    let session_key = [0x42u8; 32];
    let their_keypair = HybridKemKeypair::generate().expect("keygen failed");
    let our_keypair = HybridKemKeypair::generate().expect("keygen failed");

    group.bench_function("initiator", |b| {
        b.iter(|| {
            let state = KemRatchet::init_initiator(
                black_box(&session_key),
                black_box(their_keypair.public_key().clone()),
                black_box(1000),
            );
            black_box(state)
        })
    });

    group.bench_function("responder", |b| {
        b.iter(|| {
            let state = KemRatchet::init_responder(
                black_box(&session_key),
                black_box(our_keypair.clone()),
                black_box(1000),
            );
            black_box(state)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kdf_rk,
    bench_derive_initial_root_key,
    bench_derive_key_id,
    bench_find_keypair,
    bench_rotate_keypair,
    bench_init_ratchet,
);

criterion_main!(benches);
