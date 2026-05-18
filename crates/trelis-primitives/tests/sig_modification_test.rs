//! Test signature modification behavior - investigating potential bug
//!
//! Run with: cargo test -p trelis-primitives --test sig_modification_test -- --nocapture

// Test code; pedantic lints silenced wholesale.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use trelis_primitives::ed448::{Ed448Signature, Ed448SigningKey};
use trelis_primitives::ed448b::{Ed448BSignature, Ed448BSigningKey};

#[test]
fn test_ed448b_signature_modification_bug() {
    // The exact failing case from proptest
    let seed: [u8; 57] = [
        117, 10, 246, 24, 197, 147, 208, 165, 222, 3, 199, 229, 252, 56, 37, 229, 50, 170, 107,
        180, 233, 163, 129, 217, 1, 157, 46, 213, 14, 244, 214, 68, 52, 125, 129, 183, 10, 205,
        214, 17, 124, 225, 152, 130, 178, 113, 7, 72, 91, 2, 74, 0, 0, 0, 0, 0, 0,
    ];
    let msg: Vec<u8> = vec![91, 2, 74];
    let flip_pos = 113;

    println!("\n=== Testing Ed448-B signature modification ===");

    let sk = Ed448BSigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    let sig = sk.sign(&msg);

    println!("Signature bytes (all 114):");
    for (i, chunk) in sig.to_bytes().chunks(19).enumerate() {
        println!(
            "  [{:3}-{:3}]: {:02x?}",
            i * 19,
            i * 19 + chunk.len() - 1,
            chunk
        );
    }

    // Verify original
    let orig_result = vk.verify(&msg, &sig);
    println!("\nOriginal signature verifies: {:?}", orig_result.is_ok());
    assert!(orig_result.is_ok(), "Original should verify");

    // Flip bit at position 113
    let mut bad_sig_bytes = sig.to_bytes();
    println!(
        "\nByte at position {}: 0x{:02x}",
        flip_pos, bad_sig_bytes[flip_pos]
    );
    bad_sig_bytes[flip_pos] ^= 0x01;
    println!("After XOR 0x01:      0x{:02x}", bad_sig_bytes[flip_pos]);

    match Ed448BSignature::from_bytes(&bad_sig_bytes) {
        Err(e) => {
            println!("Modified signature failed to decode: {:?}", e);
            // This is acceptable
        }
        Ok(bad_sig) => {
            let bad_result = vk.verify(&msg, &bad_sig);
            println!(
                "Modified signature verifies: {:?} (SHOULD BE false!)",
                bad_result.is_ok()
            );

            if bad_result.is_ok() {
                println!("\n!!! CRITICAL BUG: Modified signature verified !!!");
                println!("This indicates a problem with signature verification.");

                // Let's dig deeper - check if the bytes are actually different
                println!("\nOriginal sig bytes: {:02x?}", &sig.to_bytes()[110..]);
                println!("Modified sig bytes: {:02x?}", &bad_sig_bytes[110..]);

                panic!("Modified signature should NOT verify!");
            }
        }
    }
}

#[test]
fn test_standard_ed448_signature_modification() {
    // Same seed/msg as above, but with standard Ed448
    let seed: [u8; 57] = [
        117, 10, 246, 24, 197, 147, 208, 165, 222, 3, 199, 229, 252, 56, 37, 229, 50, 170, 107,
        180, 233, 163, 129, 217, 1, 157, 46, 213, 14, 244, 214, 68, 52, 125, 129, 183, 10, 205,
        214, 17, 124, 225, 152, 130, 178, 113, 7, 72, 91, 2, 74, 0, 0, 0, 0, 0, 0,
    ];
    let msg: Vec<u8> = vec![91, 2, 74];
    let flip_pos = 113;

    println!("\n=== Testing Standard Ed448 signature modification ===");

    let sk = Ed448SigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    let sig = sk.sign(&msg);

    println!("Signature bytes (last 10): {:02x?}", &sig.to_bytes()[104..]);

    // Verify original
    let orig_result = vk.verify(&msg, &sig);
    println!("Original signature verifies: {:?}", orig_result.is_ok());
    assert!(orig_result.is_ok(), "Original should verify");

    // Flip bit at position 113
    let mut bad_sig_bytes = sig.to_bytes();
    println!(
        "Byte at position {}: 0x{:02x}",
        flip_pos, bad_sig_bytes[flip_pos]
    );
    bad_sig_bytes[flip_pos] ^= 0x01;
    println!("After XOR 0x01:      0x{:02x}", bad_sig_bytes[flip_pos]);

    match Ed448Signature::from_bytes(&bad_sig_bytes) {
        Err(e) => {
            println!("Modified signature failed to decode: {:?}", e);
        }
        Ok(bad_sig) => {
            let bad_result = vk.verify(&msg, &bad_sig);
            println!(
                "Modified signature verifies: {:?} (SHOULD BE false!)",
                bad_result.is_ok()
            );

            if bad_result.is_ok() {
                println!("\n!!! CRITICAL BUG in ed448-goldilocks-plus !!!");
                panic!("Modified signature should NOT verify!");
            }
        }
    }
}

#[test]
fn test_ed448b_all_positions() {
    // Test flipping every byte position
    let seed = [0x42u8; 57];
    let msg = b"test message for signature modification";

    let sk = Ed448BSigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    let sig = sk.sign(msg);

    println!("\n=== Testing all 114 byte positions ===");

    let mut failures = Vec::new();

    for pos in 0..114 {
        let mut bad_sig_bytes = sig.to_bytes();
        bad_sig_bytes[pos] ^= 0x01;

        if let Ok(bad_sig) = Ed448BSignature::from_bytes(&bad_sig_bytes) {
            if vk.verify(msg, &bad_sig).is_ok() {
                failures.push(pos);
            }
        }
    }

    if !failures.is_empty() {
        println!(
            "CRITICAL: Modified signatures verified at positions: {:?}",
            failures
        );
        panic!(
            "Modified signatures should NOT verify! Failed at {} positions",
            failures.len()
        );
    } else {
        println!("All 114 positions correctly reject modified signatures");
    }
}

#[test]
fn test_ed448_standard_all_positions() {
    // Test flipping every byte position for standard Ed448
    let seed = [0x42u8; 57];
    let msg = b"test message for signature modification";

    let sk = Ed448SigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    let sig = sk.sign(msg);

    println!("\n=== Testing standard Ed448 all 114 byte positions ===");

    let mut failures = Vec::new();

    for pos in 0..114 {
        let mut bad_sig_bytes = sig.to_bytes();
        bad_sig_bytes[pos] ^= 0x01;

        if let Ok(bad_sig) = Ed448Signature::from_bytes(&bad_sig_bytes) {
            if vk.verify(msg, &bad_sig).is_ok() {
                failures.push(pos);
            }
        }
    }

    if !failures.is_empty() {
        println!(
            "CRITICAL: Modified signatures verified at positions: {:?}",
            failures
        );
        panic!(
            "Modified signatures should NOT verify! Failed at {} positions",
            failures.len()
        );
    } else {
        println!("All 114 positions correctly reject modified signatures");
    }
}
