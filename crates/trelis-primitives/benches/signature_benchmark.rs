//! Benchmarks comparing signature schemes: Ed448, Ed448-B, ML-DSA FIPS 204, and ML-DSA BLAKE3.
//!
//! Run with: `cargo bench -p trelis-primitives --features "mldsa-blake3,ed448-blake3" --bench signature_benchmark`
//!
//! This benchmark requires both `mldsa-blake3` and `ed448-blake3` features.

// Internal benchmarks; pedantic warnings have no value here and are silenced
// wholesale.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    missing_docs
)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// Ed448 standard implementation (SHAKE256)
use trelis_primitives::ed448::{Ed448Signature, Ed448SigningKey, Ed448VerifyingKey};

// Ed448-B implementation (BLAKE3, requires ed448-blake3 feature)
use trelis_primitives::ed448b::{Ed448BSignature, Ed448BSigningKey, Ed448BVerifyingKey};

// ML-DSA FIPS 204 implementation (SHA-3/SHAKE)
use trelis_primitives::mldsa65::{MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey};

// ML-DSA BLAKE3 implementation (requires mldsa-blake3 feature)
use trelis_primitives::mldsa65b::{MlDsa65BSignature, MlDsa65BSigningKey, MlDsa65BVerifyingKey};

/// Benchmark key generation for all implementations.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_keygen");

    group.bench_function("ed448", |b| {
        b.iter(|| {
            let sk = Ed448SigningKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.bench_function("ed448b", |b| {
        b.iter(|| {
            let sk = Ed448BSigningKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.bench_function("mldsa65_fips204", |b| {
        b.iter(|| {
            let sk = MlDsa65SigningKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.bench_function("mldsa65_blake3", |b| {
        b.iter(|| {
            let sk = MlDsa65BSigningKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.finish();
}

/// Benchmark seeded key generation for both implementations.
fn bench_keygen_seeded(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa65_keygen_seeded");
    let seed = [0x42u8; 32];

    group.bench_function("fips204_sha3", |b| {
        b.iter(|| {
            let sk = MlDsa65SigningKey::generate_from_seed(black_box(&seed)).unwrap();
            black_box(sk)
        })
    });

    group.bench_function("blake3", |b| {
        b.iter(|| {
            let sk = MlDsa65BSigningKey::generate_from_seed(black_box(&seed)).unwrap();
            black_box(sk)
        })
    });

    group.finish();
}

/// Benchmark signing for various message sizes.
fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_sign");

    // Pre-generate keys
    let ed448_sk = Ed448SigningKey::generate().unwrap();
    let ed448b_sk = Ed448BSigningKey::generate().unwrap();
    let fips_sk = MlDsa65SigningKey::generate().unwrap();
    let blake3_sk = MlDsa65BSigningKey::generate().unwrap();

    // Test message sizes
    let msg_64b = vec![0x42u8; 64];
    let msg_1kb = vec![0x42u8; 1024];
    let msg_1mb = vec![0x42u8; 1024 * 1024];

    // 64 byte messages
    group.throughput(Throughput::Bytes(64));
    group.bench_with_input(BenchmarkId::new("ed448", "64B"), &msg_64b, |b, msg| {
        b.iter(|| {
            let sig = ed448_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(BenchmarkId::new("ed448b", "64B"), &msg_64b, |b, msg| {
        b.iter(|| {
            let sig = ed448b_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(
        BenchmarkId::new("mldsa65_fips204", "64B"),
        &msg_64b,
        |b, msg| {
            b.iter(|| {
                let sig = fips_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("mldsa65_blake3", "64B"),
        &msg_64b,
        |b, msg| {
            b.iter(|| {
                let sig = blake3_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    // 1 KB messages
    group.throughput(Throughput::Bytes(1024));
    group.bench_with_input(BenchmarkId::new("ed448", "1KB"), &msg_1kb, |b, msg| {
        b.iter(|| {
            let sig = ed448_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(BenchmarkId::new("ed448b", "1KB"), &msg_1kb, |b, msg| {
        b.iter(|| {
            let sig = ed448b_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(
        BenchmarkId::new("mldsa65_fips204", "1KB"),
        &msg_1kb,
        |b, msg| {
            b.iter(|| {
                let sig = fips_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("mldsa65_blake3", "1KB"),
        &msg_1kb,
        |b, msg| {
            b.iter(|| {
                let sig = blake3_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    // 1 MB messages
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_with_input(BenchmarkId::new("ed448", "1MB"), &msg_1mb, |b, msg| {
        b.iter(|| {
            let sig = ed448_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(BenchmarkId::new("ed448b", "1MB"), &msg_1mb, |b, msg| {
        b.iter(|| {
            let sig = ed448b_sk.sign(black_box(msg));
            black_box(sig)
        })
    });

    group.bench_with_input(
        BenchmarkId::new("mldsa65_fips204", "1MB"),
        &msg_1mb,
        |b, msg| {
            b.iter(|| {
                let sig = fips_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("mldsa65_blake3", "1MB"),
        &msg_1mb,
        |b, msg| {
            b.iter(|| {
                let sig = blake3_sk.sign(black_box(msg)).unwrap();
                black_box(sig)
            })
        },
    );

    group.finish();
}

/// Benchmark verification for various message sizes.
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_verify");

    // Pre-generate keys and signatures
    let ed448_sk = Ed448SigningKey::generate().unwrap();
    let ed448_vk = ed448_sk.verifying_key();

    let ed448b_sk = Ed448BSigningKey::generate().unwrap();
    let ed448b_vk = ed448b_sk.verifying_key();

    let fips_sk = MlDsa65SigningKey::generate().unwrap();
    let fips_vk = fips_sk.verifying_key();

    let blake3_sk = MlDsa65BSigningKey::generate().unwrap();
    let blake3_vk = blake3_sk.verifying_key();

    // Test message sizes
    let msg_64b = vec![0x42u8; 64];
    let msg_1kb = vec![0x42u8; 1024];
    let msg_1mb = vec![0x42u8; 1024 * 1024];

    // Pre-sign messages
    let ed448_sig_64b = ed448_sk.sign(&msg_64b);
    let ed448_sig_1kb = ed448_sk.sign(&msg_1kb);
    let ed448_sig_1mb = ed448_sk.sign(&msg_1mb);

    let ed448b_sig_64b = ed448b_sk.sign(&msg_64b);
    let ed448b_sig_1kb = ed448b_sk.sign(&msg_1kb);
    let ed448b_sig_1mb = ed448b_sk.sign(&msg_1mb);

    let fips_sig_64b = fips_sk.sign(&msg_64b).unwrap();
    let fips_sig_1kb = fips_sk.sign(&msg_1kb).unwrap();
    let fips_sig_1mb = fips_sk.sign(&msg_1mb).unwrap();

    let blake3_sig_64b = blake3_sk.sign(&msg_64b).unwrap();
    let blake3_sig_1kb = blake3_sk.sign(&msg_1kb).unwrap();
    let blake3_sig_1mb = blake3_sk.sign(&msg_1mb).unwrap();

    // 64 byte messages
    group.throughput(Throughput::Bytes(64));
    group.bench_function(BenchmarkId::new("ed448", "64B"), |b| {
        b.iter(|| {
            let valid = ed448_vk.verify(black_box(&msg_64b), black_box(&ed448_sig_64b));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("ed448b", "64B"), |b| {
        b.iter(|| {
            let valid = ed448b_vk.verify(black_box(&msg_64b), black_box(&ed448b_sig_64b));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_fips204", "64B"), |b| {
        b.iter(|| {
            let valid = fips_vk.verify(black_box(&msg_64b), black_box(&fips_sig_64b));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_blake3", "64B"), |b| {
        b.iter(|| {
            let valid = blake3_vk.verify(black_box(&msg_64b), black_box(&blake3_sig_64b));
            black_box(valid)
        })
    });

    // 1 KB messages
    group.throughput(Throughput::Bytes(1024));
    group.bench_function(BenchmarkId::new("ed448", "1KB"), |b| {
        b.iter(|| {
            let valid = ed448_vk.verify(black_box(&msg_1kb), black_box(&ed448_sig_1kb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("ed448b", "1KB"), |b| {
        b.iter(|| {
            let valid = ed448b_vk.verify(black_box(&msg_1kb), black_box(&ed448b_sig_1kb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_fips204", "1KB"), |b| {
        b.iter(|| {
            let valid = fips_vk.verify(black_box(&msg_1kb), black_box(&fips_sig_1kb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_blake3", "1KB"), |b| {
        b.iter(|| {
            let valid = blake3_vk.verify(black_box(&msg_1kb), black_box(&blake3_sig_1kb));
            black_box(valid)
        })
    });

    // 1 MB messages
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function(BenchmarkId::new("ed448", "1MB"), |b| {
        b.iter(|| {
            let valid = ed448_vk.verify(black_box(&msg_1mb), black_box(&ed448_sig_1mb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("ed448b", "1MB"), |b| {
        b.iter(|| {
            let valid = ed448b_vk.verify(black_box(&msg_1mb), black_box(&ed448b_sig_1mb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_fips204", "1MB"), |b| {
        b.iter(|| {
            let valid = fips_vk.verify(black_box(&msg_1mb), black_box(&fips_sig_1mb));
            black_box(valid)
        })
    });

    group.bench_function(BenchmarkId::new("mldsa65_blake3", "1MB"), |b| {
        b.iter(|| {
            let valid = blake3_vk.verify(black_box(&msg_1mb), black_box(&blake3_sig_1mb));
            black_box(valid)
        })
    });

    group.finish();
}

/// Benchmark full sign+verify round-trip.
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_roundtrip");
    group.throughput(Throughput::Elements(1));

    // Pre-generate keys
    let ed448_sk = Ed448SigningKey::generate().unwrap();
    let ed448_vk = ed448_sk.verifying_key();

    let ed448b_sk = Ed448BSigningKey::generate().unwrap();
    let ed448b_vk = ed448b_sk.verifying_key();

    let fips_sk = MlDsa65SigningKey::generate().unwrap();
    let fips_vk = fips_sk.verifying_key();

    let blake3_sk = MlDsa65BSigningKey::generate().unwrap();
    let blake3_vk = blake3_sk.verifying_key();

    let message = b"Hello, signature benchmark!";

    group.bench_function("ed448", |b| {
        b.iter(|| {
            let sig = ed448_sk.sign(black_box(message));
            let valid = ed448_vk.verify(black_box(message), &sig);
            black_box(valid)
        })
    });

    group.bench_function("ed448b", |b| {
        b.iter(|| {
            let sig = ed448b_sk.sign(black_box(message));
            let valid = ed448b_vk.verify(black_box(message), &sig);
            black_box(valid)
        })
    });

    group.bench_function("mldsa65_fips204", |b| {
        b.iter(|| {
            let sig = fips_sk.sign(black_box(message)).unwrap();
            let valid = fips_vk.verify(black_box(message), &sig);
            black_box(valid)
        })
    });

    group.bench_function("mldsa65_blake3", |b| {
        b.iter(|| {
            let sig = blake3_sk.sign(black_box(message)).unwrap();
            let valid = blake3_vk.verify(black_box(message), &sig);
            black_box(valid)
        })
    });

    group.finish();
}

/// Benchmark serialization and deserialization.
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_serialization");

    // Generate keys and signatures
    let ed448_sk = Ed448SigningKey::generate().unwrap();
    let ed448_vk = ed448_sk.verifying_key();
    let ed448_sig = ed448_sk.sign(b"test");

    let ed448b_sk = Ed448BSigningKey::generate().unwrap();
    let ed448b_vk = ed448b_sk.verifying_key();
    let ed448b_sig = ed448b_sk.sign(b"test");

    let fips_sk = MlDsa65SigningKey::generate().unwrap();
    let fips_vk = fips_sk.verifying_key();
    let fips_sig = fips_sk.sign(b"test").unwrap();

    let blake3_sk = MlDsa65BSigningKey::generate().unwrap();
    let blake3_vk = blake3_sk.verifying_key();
    let blake3_sig = blake3_sk.sign(b"test").unwrap();

    // Serialize to bytes
    let ed448_vk_bytes = ed448_vk.to_bytes();
    let ed448_sig_bytes = ed448_sig.to_bytes();

    let ed448b_vk_bytes = ed448b_vk.to_bytes();
    let ed448b_sig_bytes = ed448b_sig.to_bytes();

    let fips_sk_bytes = fips_sk.as_bytes();
    let fips_vk_bytes = fips_vk.to_bytes();
    let fips_sig_bytes = fips_sig.to_bytes();

    let blake3_sk_bytes = blake3_sk.as_bytes();
    let blake3_vk_bytes = blake3_vk.to_bytes();
    let blake3_sig_bytes = blake3_sig.to_bytes();

    // Verifying key deserialization
    group.bench_function("ed448_vk_deserialize", |b| {
        b.iter(|| {
            let vk = Ed448VerifyingKey::from_bytes(black_box(&ed448_vk_bytes)).unwrap();
            black_box(vk)
        })
    });

    group.bench_function("ed448b_vk_deserialize", |b| {
        b.iter(|| {
            let vk = Ed448BVerifyingKey::from_bytes(black_box(&ed448b_vk_bytes)).unwrap();
            black_box(vk)
        })
    });

    group.bench_function("mldsa65_fips204_vk_deserialize", |b| {
        b.iter(|| {
            let vk = MlDsa65VerifyingKey::from_bytes(black_box(&fips_vk_bytes)).unwrap();
            black_box(vk)
        })
    });

    group.bench_function("mldsa65_blake3_vk_deserialize", |b| {
        b.iter(|| {
            let vk = MlDsa65BVerifyingKey::from_bytes(black_box(&blake3_vk_bytes)).unwrap();
            black_box(vk)
        })
    });

    // Signature deserialization
    group.bench_function("ed448_sig_deserialize", |b| {
        b.iter(|| {
            let sig = Ed448Signature::from_bytes(black_box(&ed448_sig_bytes)).unwrap();
            black_box(sig)
        })
    });

    group.bench_function("ed448b_sig_deserialize", |b| {
        b.iter(|| {
            let sig = Ed448BSignature::from_bytes(black_box(&ed448b_sig_bytes)).unwrap();
            black_box(sig)
        })
    });

    group.bench_function("mldsa65_fips204_sig_deserialize", |b| {
        b.iter(|| {
            let sig = MlDsa65Signature::from_bytes(black_box(&fips_sig_bytes)).unwrap();
            black_box(sig)
        })
    });

    group.bench_function("mldsa65_blake3_sig_deserialize", |b| {
        b.iter(|| {
            let sig = MlDsa65BSignature::from_bytes(black_box(&blake3_sig_bytes)).unwrap();
            black_box(sig)
        })
    });

    // ML-DSA signing key deserialization (Ed448 doesn't have equivalent)
    group.bench_function("mldsa65_fips204_sk_deserialize", |b| {
        b.iter(|| {
            let sk = MlDsa65SigningKey::from_bytes(black_box(fips_sk_bytes)).unwrap();
            black_box(sk)
        })
    });

    group.bench_function("mldsa65_blake3_sk_deserialize", |b| {
        b.iter(|| {
            let sk = MlDsa65BSigningKey::from_bytes(black_box(blake3_sk_bytes)).unwrap();
            black_box(sk)
        })
    });

    group.finish();
}

/// Benchmark batch signing (multiple messages signed in sequence).
fn bench_batch_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_batch_sign");

    // Pre-generate keys
    let ed448_sk = Ed448SigningKey::generate().unwrap();
    let ed448b_sk = Ed448BSigningKey::generate().unwrap();
    let fips_sk = MlDsa65SigningKey::generate().unwrap();
    let blake3_sk = MlDsa65BSigningKey::generate().unwrap();

    for batch_size in [1, 10, 100] {
        let messages: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| format!("Message number {i}").into_bytes())
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("ed448", batch_size),
            &messages,
            |b, msgs| {
                b.iter(|| {
                    for msg in msgs {
                        let sig = ed448_sk.sign(black_box(msg));
                        black_box(sig);
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ed448b", batch_size),
            &messages,
            |b, msgs| {
                b.iter(|| {
                    for msg in msgs {
                        let sig = ed448b_sk.sign(black_box(msg));
                        black_box(sig);
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("mldsa65_fips204", batch_size),
            &messages,
            |b, msgs| {
                b.iter(|| {
                    for msg in msgs {
                        let sig = fips_sk.sign(black_box(msg)).unwrap();
                        black_box(sig);
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("mldsa65_blake3", batch_size),
            &messages,
            |b, msgs| {
                b.iter(|| {
                    for msg in msgs {
                        let sig = blake3_sk.sign(black_box(msg)).unwrap();
                        black_box(sig);
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_keygen_seeded,
    bench_sign,
    bench_verify,
    bench_roundtrip,
    bench_serialization,
    bench_batch_sign,
);

criterion_main!(benches);
