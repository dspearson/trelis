use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use trelis_primitives::aead::{AeadKey, Nonce, Tag, encrypt_in_place};
use subtle::ConstantTimeEq;

fn ct_aead_tag(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = AeadKey::from_bytes(rng.r#gen::<[u8; 32]>());
    let nonce = Nonce::from_bytes([0u8; 24]);
    let plaintext = b"benchmark plaintext data!";

    let mut buf = plaintext.to_vec();
    let valid_tag = encrypt_in_place(&key, &nonce, &mut buf, plaintext.len(), b"")
        .expect("encrypt_in_place failed");

    let mut wrong_tag_bytes = *valid_tag.as_bytes();
    wrong_tag_bytes[0] ^= 0xff;
    let wrong_tag = Tag::from_bytes(wrong_tag_bytes);

    let n = 100_000usize;
    let mut inputs = Vec::with_capacity(n);
    let mut classes = Vec::with_capacity(n);

    for _ in 0..n {
        if rng.r#gen::<bool>() {
            inputs.push(valid_tag);
            classes.push(Class::Left);
        } else {
            inputs.push(wrong_tag);
            classes.push(Class::Right);
        }
    }

    for (class, tag) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let result = bool::from(valid_tag.ct_eq(&tag));
            std::hint::black_box(result)
        });
    }
}

ctbench_main!(ct_aead_tag);
