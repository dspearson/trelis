//! Test vectors for ML-DSA-B-65 (BLAKE3 variant).
//!
//! These tests use BLAKE3 variant test vectors from:
//! tests/vectors/blake3_sig-ver.json

use serde::Deserialize;
use std::fs;
use trelis_primitives::mldsa65b::{
    MlDsa65BSignature, MlDsa65BSigningKey, MlDsa65BVerifyingKey, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
    SIGNATURE_SIZE,
};

#[derive(Debug, Deserialize)]
struct TestFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    pk: String,
    sk: String,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    message: String,
    signature: String,
    reason: Option<String>,
}

fn load_test_vectors() -> TestFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/blake3_sig-ver.json"
    );
    let content = fs::read_to_string(path).expect("Failed to read test vectors file");
    serde_json::from_str(&content).expect("Failed to parse test vectors")
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

#[test]
fn test_sig_ver_vectors() {
    let test_file = load_test_vectors();

    // Find ML-DSA-B-65 test group
    let group = test_file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-B-65")
        .expect("ML-DSA-B-65 test group not found");

    // Decode the public key
    let pk_bytes = hex_decode(&group.pk);
    assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE, "Public key size mismatch");
    let vk = MlDsa65BVerifyingKey::from_bytes(&pk_bytes).expect("Failed to decode public key");

    // Decode the secret key
    let sk_bytes = hex_decode(&group.sk);
    assert_eq!(sk_bytes.len(), SECRET_KEY_SIZE, "Secret key size mismatch");
    let _sk = MlDsa65BSigningKey::from_bytes(&sk_bytes).expect("Failed to decode secret key");

    let mut passed = 0;
    let mut failed = 0;

    for test in &group.tests {
        let msg = hex_decode(&test.message);
        let sig_bytes = hex_decode(&test.signature);

        // Try to decode signature
        let sig = match MlDsa65BSignature::from_bytes(&sig_bytes) {
            Ok(sig) => sig,
            Err(_) => {
                // Invalid signature length - should fail verification
                if !test.test_passed {
                    passed += 1;
                } else {
                    failed += 1;
                    eprintln!(
                        "Test {} FAILED: signature decode failed but expected to pass",
                        test.tc_id
                    );
                }
                continue;
            }
        };

        // Verify signature using internal API (test vectors use sign_internal without context)
        let result = vk.verify_internal(&msg, &sig);

        if result == test.test_passed {
            passed += 1;
        } else {
            failed += 1;
            eprintln!(
                "Test {} FAILED: expected {}, got {} (reason: {:?})",
                test.tc_id, test.test_passed, result, test.reason
            );
        }
    }

    println!(
        "ML-DSA-B-65 sig-ver: {} passed, {} failed out of {} tests",
        passed,
        failed,
        group.tests.len()
    );
    assert_eq!(failed, 0, "Some test vectors failed");
}

#[test]
fn test_signing_key_derives_correct_verifying_key() {
    let test_file = load_test_vectors();

    let group = test_file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-B-65")
        .expect("ML-DSA-B-65 test group not found");

    let pk_bytes = hex_decode(&group.pk);
    let sk_bytes = hex_decode(&group.sk);

    let sk = MlDsa65BSigningKey::from_bytes(&sk_bytes).expect("Failed to decode secret key");
    let derived_vk = sk.verifying_key();

    assert_eq!(
        derived_vk.as_bytes(),
        pk_bytes.as_slice(),
        "Derived verifying key doesn't match expected public key"
    );
}

#[test]
fn test_deterministic_signing() {
    // ML-DSA-B uses deterministic signing, so signing the same message twice
    // with the same key should produce the same signature
    let test_file = load_test_vectors();

    let group = test_file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-B-65")
        .expect("ML-DSA-B-65 test group not found");

    let sk_bytes = hex_decode(&group.sk);
    let sk = MlDsa65BSigningKey::from_bytes(&sk_bytes).expect("Failed to decode secret key");

    let message = b"test deterministic signing";

    let sig1 = sk.sign(message).expect("Signing failed");
    let sig2 = sk.sign(message).expect("Signing failed");

    assert_eq!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "Deterministic signing should produce identical signatures"
    );
}

#[test]
fn test_key_sizes_match_spec() {
    assert_eq!(PUBLIC_KEY_SIZE, 1952);
    assert_eq!(SECRET_KEY_SIZE, 4032);
    assert_eq!(SIGNATURE_SIZE, 3309);
}
