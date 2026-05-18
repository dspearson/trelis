//! Test vectors for Ed448-B (BLAKE3 variant).
//!
//! These are frozen test vectors for regression testing. Since Ed448-B is a
//! non-standard variant, these vectors are self-generated and serve to detect
//! unintentional changes to the algorithm.
//!
//! To regenerate vectors (WILL BREAK EXISTING SIGNATURES):
//!   CREATE_VECTOR_SET=1 cargo test -p trelis-primitives --test ed448b_vectors
//!
//! To verify vectors:
//!   cargo test -p trelis-primitives --test ed448b_vectors

// Test code; Phase 10 disposition (b).
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use trelis_primitives::ed448b::{
    Ed448BSignature, Ed448BSigningKey, Ed448BVerifyingKey, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
    SIGNATURE_SIZE,
};

#[derive(Debug, Serialize, Deserialize)]
struct TestFile {
    algorithm: String,
    description: String,
    version: String,
    #[serde(rename = "domainContexts")]
    domain_contexts: DomainContexts,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DomainContexts {
    expand: String,
    nonce: String,
    challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(with = "hex::serde")]
    seed: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    tests: Vec<TestCase>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    #[serde(with = "hex::serde")]
    message: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
    reason: String,
}

fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/ed448b_sig-ver.json");
    p
}

fn load_test_vectors() -> TestFile {
    let content = fs::read_to_string(vectors_path()).expect("Failed to read test vectors file");
    serde_json::from_str(&content).expect("Failed to parse test vectors")
}

#[test]
fn test_ed448b_vectors() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        create_vector_set();
    } else {
        verify_vector_set();
    }
}

fn verify_vector_set() {
    let test_file = load_test_vectors();

    assert_eq!(test_file.algorithm, "Ed448-B");
    assert_eq!(test_file.domain_contexts.expand, "Ed448-B-expand");
    assert_eq!(test_file.domain_contexts.nonce, "Ed448-B-nonce");
    assert_eq!(test_file.domain_contexts.challenge, "Ed448-B-challenge");

    let mut total_passed = 0;
    let mut total_failed = 0;

    for group in &test_file.test_groups {
        // Verify seed produces expected public key
        assert_eq!(group.seed.len(), SECRET_KEY_SIZE);
        let mut seed = [0u8; SECRET_KEY_SIZE];
        seed.copy_from_slice(&group.seed);
        let sk = Ed448BSigningKey::from_seed(seed);
        let vk = sk.verifying_key();

        assert_eq!(
            vk.to_bytes().as_slice(),
            group.pk.as_slice(),
            "Public key mismatch for test group {}",
            group.tg_id
        );

        // Verify each test case
        let vk = Ed448BVerifyingKey::from_bytes(&group.pk).expect("Failed to decode public key");

        for tc in &group.tests {
            let sig_result = Ed448BSignature::from_bytes(&tc.signature);

            let verified = match sig_result {
                Ok(sig) => vk.verify(&tc.message, &sig).is_ok(),
                Err(_) => false,
            };

            if verified == tc.test_passed {
                total_passed += 1;
            } else {
                total_failed += 1;
                eprintln!(
                    "Test {} FAILED: expected {}, got {} (reason: {})",
                    tc.tc_id, tc.test_passed, verified, tc.reason
                );
            }
        }
    }

    println!(
        "Ed448-B vectors: {} passed, {} failed",
        total_passed, total_failed
    );
    assert_eq!(total_failed, 0, "Some test vectors failed");
}

fn create_vector_set() {
    // Deterministic seeds for reproducibility
    let seeds: Vec<[u8; 57]> = vec![
        // All zeros
        [0u8; 57],
        // All ones
        [0x01u8; 57],
        // All 0xFF
        [0xFFu8; 57],
        // Incrementing pattern
        {
            let mut s = [0u8; 57];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            s
        },
        // Decrementing pattern
        {
            let mut s = [0u8; 57];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (56 - i) as u8;
            }
            s
        },
    ];

    let messages: Vec<Vec<u8>> = vec![
        vec![],                      // Empty
        vec![0x00],                  // Single zero byte
        vec![0xFF],                  // Single 0xFF byte
        b"Hello, Ed448-B!".to_vec(), // ASCII text
        b"The quick brown fox jumps over the lazy dog".to_vec(),
        (0u8..=255).collect(), // All byte values
        vec![0xAB; 1024],      // 1KB message
    ];

    let mut test_groups = Vec::new();

    for (tg_idx, seed) in seeds.iter().enumerate() {
        let sk = Ed448BSigningKey::from_seed(*seed);
        let vk = sk.verifying_key();

        let mut tests = Vec::new();
        let mut tc_id = 1u32;

        for msg in &messages {
            // Valid signature
            let sig = sk.sign(msg);
            tests.push(TestCase {
                tc_id,
                test_passed: true,
                message: msg.clone(),
                signature: sig.to_bytes().to_vec(),
                reason: "valid signature".to_string(),
            });
            tc_id += 1;

            // Modified message (should fail)
            let mut bad_msg = msg.clone();
            bad_msg.push(0x00);
            tests.push(TestCase {
                tc_id,
                test_passed: false,
                message: bad_msg,
                signature: sig.to_bytes().to_vec(),
                reason: "modified message".to_string(),
            });
            tc_id += 1;

            // Modified signature (should fail)
            let mut bad_sig = sig.to_bytes();
            bad_sig[0] ^= 0xFF;
            tests.push(TestCase {
                tc_id,
                test_passed: false,
                message: msg.clone(),
                signature: bad_sig.to_vec(),
                reason: "modified signature".to_string(),
            });
            tc_id += 1;
        }

        test_groups.push(TestGroup {
            tg_id: (tg_idx + 1) as u32,
            seed: seed.to_vec(),
            pk: vk.to_bytes().to_vec(),
            tests,
        });
    }

    let test_file = TestFile {
        algorithm: "Ed448-B".to_string(),
        description: "Ed448 with BLAKE3 domain separation (non-standard variant)".to_string(),
        version: "1.0".to_string(),
        domain_contexts: DomainContexts {
            expand: "Ed448-B-expand".to_string(),
            nonce: "Ed448-B-nonce".to_string(),
            challenge: "Ed448-B-challenge".to_string(),
        },
        test_groups,
    };

    let json = serde_json::to_string_pretty(&test_file).expect("Failed to serialize");
    let mut file = File::create(vectors_path()).expect("Failed to create file");
    file.write_all(json.as_bytes()).expect("Failed to write");

    println!("Created Ed448-B test vectors at {:?}", vectors_path());
    println!(
        "Total: {} groups, {} tests per group",
        test_file.test_groups.len(),
        test_file.test_groups[0].tests.len()
    );
}

#[test]
fn test_key_sizes() {
    assert_eq!(PUBLIC_KEY_SIZE, 57);
    assert_eq!(SECRET_KEY_SIZE, 57);
    assert_eq!(SIGNATURE_SIZE, 114);
}

#[test]
fn test_deterministic_signing() {
    let seed = [0x42u8; 57];
    let sk = Ed448BSigningKey::from_seed(seed);
    let message = b"deterministic test";

    let sig1 = sk.sign(message);
    let sig2 = sk.sign(message);

    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn test_same_seed_same_keys() {
    let seed = [0x42u8; 57];

    let sk1 = Ed448BSigningKey::from_seed(seed);
    let sk2 = Ed448BSigningKey::from_seed(seed);

    assert_eq!(
        sk1.verifying_key().to_bytes(),
        sk2.verifying_key().to_bytes()
    );
}
