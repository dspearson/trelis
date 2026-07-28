use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::{Rng, RngCore};
use trelis_primitives::sntrup761::{CIPHERTEXT_SIZE, Sntrup761Ciphertext, Sntrup761SecretKey};

fn ct_sntrup761_decap(runner: &mut CtRunner, rng: &mut BenchRng) {
    let seed: [u8; 32] = rng.gen();
    let sk = Sntrup761SecretKey::generate_from_seed(&seed).expect("sntrup keygen");
    let pk = sk.public_key();

    // encapsulate() returns Result<(SharedSecret, Ciphertext)>
    let (_ss, valid_ct) = pk.encapsulate().expect("sntrup encap");

    let mut random_ct_bytes = [0u8; CIPHERTEXT_SIZE];
    rng.fill_bytes(&mut random_ct_bytes);
    let random_ct = Sntrup761Ciphertext::from_array(random_ct_bytes);

    // Use fewer samples — decap is expensive (~ms per call)
    let n = 1_000usize;
    let mut inputs: Vec<bool> = Vec::with_capacity(n);
    let mut classes = Vec::with_capacity(n);

    for _ in 0..n {
        if rng.gen::<bool>() {
            inputs.push(true);   // use valid_ct
            classes.push(Class::Left);
        } else {
            inputs.push(false);  // use random_ct
            classes.push(Class::Right);
        }
    }

    for (class, use_valid) in classes.into_iter().zip(inputs.into_iter()) {
        let ct = if use_valid { &valid_ct } else { &random_ct };
        runner.run_one(class, || {
            let result = sk.decapsulate(ct);
            std::hint::black_box(result.ok())
        });
    }
}

ctbench_main!(ct_sntrup761_decap);
