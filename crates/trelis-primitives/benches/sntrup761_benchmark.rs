//! Benchmarks comparing C FFI and pure Rust sntrup761 implementations.
//!
//! Run with: `cargo bench -p trelis-primitives --features "std,wasm"`
//!
//! This benchmark requires both `std` and `wasm` features enabled to compare
//! the C FFI (pqcrypto-ntruprime) and pure Rust (ntrulp) implementations.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// C FFI implementation (std feature)
use trelis_primitives::sntrup761::{
    Sntrup761Ciphertext as CFfiCiphertext, Sntrup761PublicKey as CFfiPublicKey,
    Sntrup761SecretKey as CFfiSecretKey,
};

// Pure Rust implementation (wasm feature)
use trelis_primitives::sntrup761_pure_rust::{
    PureRustSntrup761Ciphertext, PureRustSntrup761PublicKey, PureRustSntrup761SecretKey,
};

/// Benchmark key generation for both implementations.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_keygen");

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let sk = CFfiSecretKey::generate();
            black_box(sk)
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let sk = PureRustSntrup761SecretKey::generate();
            black_box(sk)
        })
    });

    group.finish();
}

/// Benchmark encapsulation for both implementations.
fn bench_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_encapsulate");

    // Generate keys outside benchmark
    let c_sk = CFfiSecretKey::generate();
    let c_pk = c_sk.public_key();

    let rust_sk = PureRustSntrup761SecretKey::generate();
    let rust_pk = rust_sk.public_key();

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let (ss, ct) = c_pk.encapsulate();
            black_box((ss, ct))
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let (ss, ct) = rust_pk.encapsulate();
            black_box((ss, ct))
        })
    });

    group.finish();
}

/// Benchmark decapsulation for both implementations.
fn bench_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_decapsulate");

    // Generate keys and ciphertexts outside benchmark
    let c_sk = CFfiSecretKey::generate();
    let c_pk = c_sk.public_key();
    let (_, c_ct) = c_pk.encapsulate();

    let rust_sk = PureRustSntrup761SecretKey::generate();
    let rust_pk = rust_sk.public_key();
    let (_, rust_ct) = rust_pk.encapsulate();

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let ss = c_sk.decapsulate(&c_ct).unwrap();
            black_box(ss)
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let ss = rust_sk.decapsulate(&rust_ct).unwrap();
            black_box(ss)
        })
    });

    group.finish();
}

/// Benchmark full KEM round-trip for both implementations.
fn bench_full_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_full_kem");
    group.throughput(Throughput::Elements(1));

    // Pre-generate secret keys outside benchmark
    let c_sk = CFfiSecretKey::generate();
    let c_pk = c_sk.public_key();

    let rust_sk = PureRustSntrup761SecretKey::generate();
    let rust_pk = rust_sk.public_key();

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let (_, ct) = c_pk.encapsulate();
            let ss = c_sk.decapsulate(&ct).unwrap();
            black_box(ss)
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let (_, ct) = rust_pk.encapsulate();
            let ss = rust_sk.decapsulate(&ct).unwrap();
            black_box(ss)
        })
    });

    group.finish();
}

/// Benchmark encoding/decoding operations.
fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_encoding");

    // Generate test data
    let c_sk = CFfiSecretKey::generate();
    let c_pk = c_sk.public_key();
    let pk_bytes = c_pk.as_bytes();
    let (_, c_ct) = c_pk.encapsulate();
    let ct_bytes = c_ct.as_bytes();

    group.bench_function("public_key_decode", |b| {
        b.iter(|| {
            let pk = CFfiPublicKey::from_bytes(black_box(pk_bytes)).unwrap();
            black_box(pk)
        })
    });

    group.bench_function("ciphertext_decode", |b| {
        b.iter(|| {
            let ct = CFfiCiphertext::from_bytes(black_box(ct_bytes)).unwrap();
            black_box(ct)
        })
    });

    // Pure Rust encoding/decoding
    let rust_sk = PureRustSntrup761SecretKey::generate();
    let rust_pk = rust_sk.public_key();
    let rust_pk_bytes = rust_pk.as_bytes();
    let (_, rust_ct) = rust_pk.encapsulate();
    let rust_ct_bytes = rust_ct.as_bytes();

    group.bench_function("pure_rust_pk_decode", |b| {
        b.iter(|| {
            let pk = PureRustSntrup761PublicKey::from_bytes(black_box(rust_pk_bytes)).unwrap();
            black_box(pk)
        })
    });

    group.bench_function("pure_rust_ct_decode", |b| {
        b.iter(|| {
            let ct = PureRustSntrup761Ciphertext::from_bytes(black_box(rust_ct_bytes)).unwrap();
            black_box(ct)
        })
    });

    group.finish();
}

/// Benchmark batch operations (multiple KEM operations in sequence).
fn bench_batch_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_batch");

    for batch_size in [1, 10, 100] {
        // Pre-generate keys
        let c_keys: Vec<_> = (0..batch_size)
            .map(|_| {
                let sk = CFfiSecretKey::generate();
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        let rust_keys: Vec<_> = (0..batch_size)
            .map(|_| {
                let sk = PureRustSntrup761SecretKey::generate();
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(BenchmarkId::new("c_ffi", batch_size), &c_keys, |b, keys| {
            b.iter(|| {
                for (sk, pk) in keys {
                    let (_, ct) = pk.encapsulate();
                    let ss = sk.decapsulate(&ct).unwrap();
                    black_box(ss);
                }
            })
        });

        group.bench_with_input(
            BenchmarkId::new("pure_rust", batch_size),
            &rust_keys,
            |b, keys| {
                b.iter(|| {
                    for (sk, pk) in keys {
                        let (_, ct) = pk.encapsulate();
                        let ss = sk.decapsulate(&ct).unwrap();
                        black_box(ss);
                    }
                })
            },
        );
    }

    group.finish();
}

/// Benchmark interoperability scenario: C generates, Rust decapsulates and vice versa.
fn bench_interop(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_interop");

    // C generates key, encode to wire format, Rust decodes and encapsulates
    let c_sk = CFfiSecretKey::generate();
    let c_pk_bytes = c_sk.public_key().as_bytes().to_vec();

    // Rust generates key, encode to wire format, C decodes and encapsulates
    let rust_sk = PureRustSntrup761SecretKey::generate();
    let rust_pk_bytes = rust_sk.public_key().as_bytes().to_vec();

    group.bench_function("c_keygen_rust_encap", |b| {
        b.iter(|| {
            // Rust decodes C's public key and encapsulates
            let pk = PureRustSntrup761PublicKey::from_bytes(&c_pk_bytes).unwrap();
            let (ss, ct) = pk.encapsulate();
            black_box((ss, ct))
        })
    });

    group.bench_function("rust_keygen_c_encap", |b| {
        b.iter(|| {
            // C decodes Rust's public key and encapsulates
            let pk = CFfiPublicKey::from_bytes(&rust_pk_bytes).unwrap();
            let (ss, ct) = pk.encapsulate();
            black_box((ss, ct))
        })
    });

    // Full interop round-trip: one side generates, other encapsulates, first decapsulates
    group.bench_function("full_interop_c_to_rust", |b| {
        let sk = CFfiSecretKey::generate();
        let pk_bytes = sk.public_key().as_bytes().to_vec();

        b.iter(|| {
            // Rust encapsulates to C's key
            let pk = PureRustSntrup761PublicKey::from_bytes(&pk_bytes).unwrap();
            let (_, ct) = pk.encapsulate();

            // C decapsulates
            let ct_bytes = ct.as_bytes();
            let c_ct = CFfiCiphertext::from_bytes(ct_bytes).unwrap();
            let ss = sk.decapsulate(&c_ct).unwrap();
            black_box(ss)
        })
    });

    group.bench_function("full_interop_rust_to_c", |b| {
        let sk = PureRustSntrup761SecretKey::generate();
        let pk_bytes = sk.public_key().as_bytes().to_vec();

        b.iter(|| {
            // C encapsulates to Rust's key
            let pk = CFfiPublicKey::from_bytes(&pk_bytes).unwrap();
            let (_, ct) = pk.encapsulate();

            // Rust decapsulates
            let ct_bytes = ct.as_bytes();
            let rust_ct = PureRustSntrup761Ciphertext::from_bytes(ct_bytes).unwrap();
            let ss = sk.decapsulate(&rust_ct).unwrap();
            black_box(ss)
        })
    });

    group.finish();
}

/// Benchmark polynomial multiplication: NTT vs Karatsuba.
fn bench_poly_mult(c: &mut Criterion) {
    use trelis_primitives::sntrup761_poly::{P, rq_mult_r3, rq_mult_r3_ntt};

    let mut group = c.benchmark_group("sntrup761_poly_mult");

    // Create test polynomials with representative values
    let mut a = [0i16; P];
    let mut b = [0i8; P];
    for i in 0..P {
        a[i] = ((i as i32 * 17) % 2000 - 1000) as i16;
        b[i] = (i % 3) as i8 - 1; // -1, 0, or 1
    }

    group.bench_function("karatsuba", |bench| {
        bench.iter(|| {
            let result = rq_mult_r3(black_box(&a), black_box(&b));
            black_box(result)
        })
    });

    group.bench_function("ntt_barrett", |bench| {
        bench.iter(|| {
            let result = rq_mult_r3_ntt(black_box(&a), black_box(&b));
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encapsulate,
    bench_decapsulate,
    bench_full_kem,
    bench_encoding,
    bench_batch_kem,
    bench_interop,
    bench_poly_mult,
);

criterion_main!(benches);
