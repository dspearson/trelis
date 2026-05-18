//! Benchmarks comparing C FFI and pure Rust sntrup761 implementations.
//!
//! Run with: `cargo bench -p trelis-primitives --features "std,wasm"`
//!
//! This benchmark requires both `std` and `wasm` features enabled to compare
//! the C FFI (pqcrypto-ntruprime) and pure Rust (ntrulp) implementations.

// Internal benchmarks; pedantic warnings have no value here and are silenced
// wholesale. Phase 10 disposition (b) — `10-PEDANTIC-DRAFT.md`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    missing_docs
)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// C FFI implementation (std feature)
use trelis_primitives::sntrup761::ffi::{
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
            let sk = CFfiSecretKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let sk = PureRustSntrup761SecretKey::generate().unwrap();
            black_box(sk)
        })
    });

    group.finish();
}

/// Benchmark encapsulation for both implementations.
fn bench_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_encapsulate");

    // Generate keys outside benchmark
    let c_sk = CFfiSecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();

    let rust_sk = PureRustSntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let (ss, ct) = c_pk.encapsulate().unwrap();
            black_box((ss, ct))
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let (ss, ct) = rust_pk.encapsulate().unwrap();
            black_box((ss, ct))
        })
    });

    group.finish();
}

/// Benchmark decapsulation for both implementations.
fn bench_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("sntrup761_decapsulate");

    // Generate keys and ciphertexts outside benchmark
    let c_sk = CFfiSecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let (_, c_ct) = c_pk.encapsulate().unwrap();

    let rust_sk = PureRustSntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();
    let (_, rust_ct) = rust_pk.encapsulate().unwrap();

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
    let c_sk = CFfiSecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();

    let rust_sk = PureRustSntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();

    group.bench_function("c_ffi", |b| {
        b.iter(|| {
            let (_, ct) = c_pk.encapsulate().unwrap();
            let ss = c_sk.decapsulate(&ct).unwrap();
            black_box(ss)
        })
    });

    group.bench_function("pure_rust", |b| {
        b.iter(|| {
            let (_, ct) = rust_pk.encapsulate().unwrap();
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
    let c_sk = CFfiSecretKey::generate().unwrap();
    let c_pk = c_sk.public_key();
    let pk_bytes = c_pk.as_bytes();
    let (_, c_ct) = c_pk.encapsulate().unwrap();
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
    let rust_sk = PureRustSntrup761SecretKey::generate().unwrap();
    let rust_pk = rust_sk.public_key();
    let rust_pk_bytes = rust_pk.as_bytes();
    let (_, rust_ct) = rust_pk.encapsulate().unwrap();
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
                let sk = CFfiSecretKey::generate().unwrap();
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        let rust_keys: Vec<_> = (0..batch_size)
            .map(|_| {
                let sk = PureRustSntrup761SecretKey::generate().unwrap();
                let pk = sk.public_key();
                (sk, pk)
            })
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(BenchmarkId::new("c_ffi", batch_size), &c_keys, |b, keys| {
            b.iter(|| {
                for (sk, pk) in keys {
                    let (_, ct) = pk.encapsulate().unwrap();
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
                        let (_, ct) = pk.encapsulate().unwrap();
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
    let c_sk = CFfiSecretKey::generate().unwrap();
    let c_pk_bytes = c_sk.public_key().as_bytes().to_vec();

    // Rust generates key, encode to wire format, C decodes and encapsulates
    let rust_sk = PureRustSntrup761SecretKey::generate().unwrap();
    let rust_pk_bytes = rust_sk.public_key().as_bytes().to_vec();

    group.bench_function("c_keygen_rust_encap", |b| {
        b.iter(|| {
            // Rust decodes C's public key and encapsulates
            let pk = PureRustSntrup761PublicKey::from_bytes(&c_pk_bytes).unwrap();
            let (ss, ct) = pk.encapsulate().unwrap();
            black_box((ss, ct))
        })
    });

    group.bench_function("rust_keygen_c_encap", |b| {
        b.iter(|| {
            // C decodes Rust's public key and encapsulates
            let pk = CFfiPublicKey::from_bytes(&rust_pk_bytes).unwrap();
            let (ss, ct) = pk.encapsulate().unwrap();
            black_box((ss, ct))
        })
    });

    // Full interop round-trip: one side generates, other encapsulates, first decapsulates
    group.bench_function("full_interop_c_to_rust", |b| {
        let sk = CFfiSecretKey::generate().unwrap();
        let pk_bytes = sk.public_key().as_bytes().to_vec();

        b.iter(|| {
            // Rust encapsulates to C's key
            let pk = PureRustSntrup761PublicKey::from_bytes(&pk_bytes).unwrap();
            let (_, ct) = pk.encapsulate().unwrap();

            // C decapsulates
            let ct_bytes = ct.as_bytes();
            let c_ct = CFfiCiphertext::from_bytes(ct_bytes).unwrap();
            let ss = sk.decapsulate(&c_ct).unwrap();
            black_box(ss)
        })
    });

    group.bench_function("full_interop_rust_to_c", |b| {
        let sk = PureRustSntrup761SecretKey::generate().unwrap();
        let pk_bytes = sk.public_key().as_bytes().to_vec();

        b.iter(|| {
            // C encapsulates to Rust's key
            let pk = CFfiPublicKey::from_bytes(&pk_bytes).unwrap();
            let (_, ct) = pk.encapsulate().unwrap();

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
    use trelis_primitives::sntrup761::poly::{P, rq_mult_r3, rq_mult_r3_ntt};

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

/// Benchmark field element inversion: Extended GCD vs Fermat.
fn bench_fq_recip(c: &mut Criterion) {
    use trelis_primitives::sntrup761::fq;

    let mut group = c.benchmark_group("sntrup761_fq_recip");

    // Test values for inversion
    let test_values: Vec<i16> = vec![1, 7, 42, 761, 1234, 2000, 4000];

    group.bench_function("extended_gcd", |bench| {
        bench.iter(|| {
            for &a in &test_values {
                black_box(fq::recip(black_box(a)));
            }
        })
    });

    // Fermat's little theorem: a^(q-2) mod q
    fn fermat_recip(a: i16) -> i16 {
        const Q: i32 = 4591;
        const Q12: i32 = (Q - 1) / 2;
        let mut ai = a;
        for _ in 1..Q - 2 {
            let x = (a as i32 * ai as i32) % Q;
            ai = if x > Q12 {
                (x - Q) as i16
            } else if x < -Q12 {
                (x + Q) as i16
            } else {
                x as i16
            };
        }
        ai
    }

    group.bench_function("fermat", |bench| {
        bench.iter(|| {
            for &a in &test_values {
                black_box(fermat_recip(black_box(a)));
            }
        })
    });

    group.finish();
}

/// Benchmark Rq polynomial inversion: optimised vs ntrulp.
fn bench_rq_recip(c: &mut Criterion) {
    use ntrulp::poly::r3::R3;
    use trelis_primitives::sntrup761::fq::Rq as FastRq;

    let mut group = c.benchmark_group("sntrup761_rq_recip");
    group.sample_size(10); // Polynomial inversion is slow

    // Create a deterministic test polynomial (simple pattern that's invertible)
    let mut coeffs_i8 = [0i8; 761];
    // Create a short polynomial with appropriate weight
    for i in 0..286 {
        coeffs_i8[i * 2] = if i % 2 == 0 { 1 } else { -1 };
    }

    group.bench_function("optimized_egcd", |bench| {
        let f_rq: FastRq = (&coeffs_i8).into();
        bench.iter(|| {
            let result = f_rq.recip::<3>();
            black_box(result)
        })
    });

    group.bench_function("ntrulp_fermat", |bench| {
        let f_rq = R3::from(coeffs_i8).rq_from_r3();
        bench.iter(|| {
            let result = f_rq.recip::<3>();
            black_box(result)
        })
    });

    // Hybrid: our algorithm structure with ntrulp's freeze
    group.bench_function("hybrid_ntrulp_freeze", |bench| {
        use ntrulp::math::nums::{i16_negative_mask, i16_nonzero_mask};
        use ntrulp::poly::fq::freeze as ntrulp_freeze;
        use ntrulp::poly::fq::recip as ntrulp_fq_recip;

        const P: usize = 761;

        let mut input = [0i16; P];
        for i in 0..P {
            input[i] = coeffs_i8[i] as i16;
        }

        bench.iter(|| {
            let mut out = [0i16; P];
            let mut f = [0i16; P + 1];
            let mut g = [0i16; P + 1];
            let mut v = [0i16; P + 1];
            let mut r = [0i16; P + 1];

            r[0] = ntrulp_fq_recip(3);
            f[0] = 1;
            f[P - 1] = -1;
            f[P] = -1;

            for i in 0..P {
                g[P - 1 - i] = input[i];
            }
            g[P] = 0;

            let mut delta: i16 = 1;

            for _ in 0..2 * P - 1 {
                for i in (1..=P).rev() {
                    v[i] = v[i - 1];
                }
                v[0] = 0;

                let swap: i16 = i16_negative_mask(-delta) & i16_nonzero_mask(g[0]);
                delta ^= swap & (delta ^ -delta);
                delta += 1;

                for i in 0..=P {
                    let t = swap & (f[i] ^ g[i]);
                    f[i] ^= t;
                    g[i] ^= t;
                    let t = swap & (v[i] ^ r[i]);
                    v[i] ^= t;
                    r[i] ^= t;
                }

                let f0 = f[0] as i32;
                let g0 = g[0] as i32;

                for i in 0..=P {
                    g[i] = ntrulp_freeze(f0 * g[i] as i32 - g0 * f[i] as i32);
                }
                for i in 0..=P {
                    r[i] = ntrulp_freeze(f0 * r[i] as i32 - g0 * v[i] as i32);
                }

                for i in 0..P {
                    g[i] = g[i + 1];
                }
                g[P] = 0;
            }

            let scale = ntrulp_fq_recip(f[0]);
            for i in 0..P {
                out[i] = ntrulp_freeze(scale as i32 * v[P - 1 - i] as i32);
            }

            black_box(out)
        })
    });

    // Exact copy of ntrulp's structure with closure
    group.bench_function("exact_ntrulp_structure", |bench| {
        use ntrulp::math::nums::{i16_negative_mask, i16_nonzero_mask};
        use ntrulp::poly::fq;

        const P: usize = 761;

        let mut input_arr = [0i16; P];
        for i in 0..P {
            input_arr[i] = coeffs_i8[i] as i16;
        }

        bench.iter(|| {
            let input = input_arr; // Copy like ntrulp does
            let mut out = [0i16; P];
            let mut f = [0i16; P + 1];
            let mut g = [0i16; P + 1];
            let mut v = [0i16; P + 1];
            let mut r = [0i16; P + 1];
            let mut delta: i16;
            let mut swap: i16;
            let mut t: i16;
            let mut f0: i32;
            let mut g0: i32;

            // Closure exactly like ntrulp
            let quotient = |out: &mut [i16], f0: i32, g0: i32, fv: &[i16]| {
                for i in 0..P + 1 {
                    let x = f0 * out[i] as i32 - g0 * fv[i] as i32;
                    out[i] = fq::freeze(x);
                }
            };

            r[0] = fq::recip(3);
            f[0] = 1;
            f[P - 1] = -1;
            f[P] = -1;

            for i in 0..P {
                g[P - 1 - i] = input[i];
            }

            g[P] = 0;
            delta = 1;

            for _ in 0..2 * P - 1 {
                for i in (1..=P).rev() {
                    v[i] = v[i - 1];
                }
                v[0] = 0;

                swap = i16_negative_mask(-delta) & i16_nonzero_mask(g[0]);
                delta ^= swap & (delta ^ -delta);
                delta += 1;

                for i in 0..P + 1 {
                    t = swap & (f[i] ^ g[i]);
                    f[i] ^= t;
                    g[i] ^= t;
                    t = swap & (v[i] ^ r[i]);
                    v[i] ^= t;
                    r[i] ^= t;
                }

                f0 = f[0] as i32;
                g0 = g[0] as i32;

                quotient(&mut g, f0, g0, &f);
                quotient(&mut r, f0, g0, &v);

                for i in 0..P {
                    g[i] = g[i + 1];
                }

                g[P] = 0;
            }

            let scale = fq::recip(f[0]);

            for i in 0..P {
                let x = scale as i32 * (v[P - 1 - i] as i32);
                out[i] = fq::freeze(x);
            }

            black_box(out)
        })
    });

    group.finish();
}

/// Benchmark freeze function: optimised vs ntrulp.
fn bench_freeze(c: &mut Criterion) {
    use ntrulp::poly::fq::freeze as ntrulp_freeze;
    use trelis_primitives::sntrup761::fq::freeze as fast_freeze;

    let mut group = c.benchmark_group("sntrup761_freeze");

    // Test values covering typical range
    let test_values: Vec<i32> = (-5000..5000).collect();

    group.bench_function("optimized", |bench| {
        bench.iter(|| {
            let mut sum = 0i16;
            for &x in &test_values {
                sum = sum.wrapping_add(fast_freeze(black_box(x)));
            }
            black_box(sum)
        })
    });

    group.bench_function("ntrulp", |bench| {
        bench.iter(|| {
            let mut sum = 0i16;
            for &x in &test_values {
                sum = sum.wrapping_add(ntrulp_freeze(black_box(x)));
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmark R3 polynomial inversion: optimised vs ntrulp.
fn bench_r3_recip(c: &mut Criterion) {
    use ntrulp::poly::r3::R3 as NtrulpR3;
    use trelis_primitives::sntrup761::fq::R3 as FastR3;

    let mut group = c.benchmark_group("sntrup761_r3_recip");
    group.sample_size(10); // Polynomial inversion is slow

    // Create a deterministic test polynomial (simple pattern that's invertible)
    let mut coeffs_i8 = [0i8; 761];
    // Create a small polynomial that's likely invertible
    coeffs_i8[0] = 1;
    for (i, coeff) in coeffs_i8.iter_mut().enumerate().take(50).skip(1) {
        *coeff = if i % 3 == 0 {
            1
        } else if i % 3 == 1 {
            -1
        } else {
            0
        };
    }

    group.bench_function("optimized", |bench| {
        let g = FastR3::from(coeffs_i8);
        bench.iter(|| {
            let result = g.recip();
            black_box(result)
        })
    });

    // `ntrulp::poly::r3::R3::recip` increments a u8/i8 `delta` past 127 without
    // `wrapping_add`, so the algorithm relies on undefined-by-default wrapping
    // and panics under `overflow-checks` (i.e. under `cargo test --benches`
    // and any dev-profile bench smoke-test). Only invoke the ntrulp comparison
    // when overflow checks are off — i.e. real `cargo bench` release builds.
    if !cfg!(debug_assertions) {
        group.bench_function("ntrulp", |bench| {
            let g = NtrulpR3::from(coeffs_i8);
            bench.iter(|| {
                let result = g.recip();
                black_box(result)
            })
        });
    }

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
    bench_fq_recip,
    bench_rq_recip,
    bench_freeze,
    bench_r3_recip,
);

criterion_main!(benches);
