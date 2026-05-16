use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use trelis_primitives::mldsa65::{MlDsa65SigningKey, MlDsa65VerifyingKey};

fn ct_mldsa_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let sk = MlDsa65SigningKey::generate().expect("keygen failed");
    let vk: MlDsa65VerifyingKey = sk.verifying_key();

    let msg_valid = b"the quick brown fox";
    let msg_invalid = b"the quick brown fox ";

    let sig = sk.sign(msg_valid).expect("sign failed");

    let n = 10_000usize;
    let mut classes = Vec::with_capacity(n);

    for _ in 0..n {
        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for class in classes.into_iter() {
        let msg: &[u8] = match class {
            Class::Left  => msg_valid,
            Class::Right => msg_invalid,
        };
        runner.run_one(class, || {
            let result = vk.verify(msg, &sig);
            std::hint::black_box(result.ok())
        });
    }
}

ctbench_main!(ct_mldsa_verify);
