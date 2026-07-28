use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::{Rng, RngCore};
use trelis_primitives::ed448b::Ed448BSigningKey;

fn ct_ed448_scalarmult(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut seed = [0u8; 57];
    rng.fill_bytes(&mut seed);
    let sk = Ed448BSigningKey::from_seed(seed);

    let msg0 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let msg1 = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let n = 10_000usize;
    let mut classes = Vec::with_capacity(n);

    for _ in 0..n {
        if rng.r#gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for class in classes.into_iter() {
        let msg: &[u8] = match class {
            Class::Left  => msg0,
            Class::Right => msg1,
        };
        runner.run_one(class, || {
            let sig = sk.sign(msg);
            std::hint::black_box(sig)
        });
    }
}

ctbench_main!(ct_ed448_scalarmult);
