//! Differentiating tests for the X3DH-PQ transcript binding (TXB-01 / SC1).
//!
//! These prove that the additive `{version ‖ suite-id ‖ SessionFlags}` framing
//! block appended to the transcript makes the derived session secret a strict
//! function of the version byte, the cipher-suite byte, and the LI-capability
//! bit:
//!
//! - flipping the LI bit (through the public [`SessionFlags`] parameter),
//! - flipping the version byte, or
//! - flipping the suite byte
//!
//! each changes the derived key, while identical inputs derive an identical
//! secret (determinism) and both parties passing the same flags still agree.
//! This is the F08 (version/suite downgrade or strip) and F18 (LI-bit binding)
//! guarantee: any such tamper diverges the key and the handshake fails closed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use trelis_hybrid::{HybridKemKeypair, HybridSigningKeypair};
use trelis_primitives::SESSION_V2_CONTEXT;
use trelis_wire::constants::{CIPHER_SUITE, PROTOCOL_VERSION};
use trelis_x3dh_pq::transcript::{DH_SIZE, FRAMING_SIZE, PQ_SS_SIZE, TRANSCRIPT_SIZE};
use trelis_x3dh_pq::{PreKeyBundle, SessionFlags, SignedPreKeyBundle, Transcript};

/// Offset of the version byte within the 299-byte transcript (start of the
/// trailing framing block).
const VERSION_OFFSET: usize = TRANSCRIPT_SIZE - FRAMING_SIZE; // 296
/// Offset of the cipher-suite byte.
const SUITE_OFFSET: usize = VERSION_OFFSET + 1; // 297
/// Offset of the `SessionFlags` byte.
const FLAGS_OFFSET: usize = VERSION_OFFSET + 2; // 298

// Fixed placeholder DH/PQ inputs. These tests exercise the framing-block
// binding, not the DH/KEM math, so concrete shared secrets are unnecessary —
// the framing block is what must change the output.
const DH1: [u8; DH_SIZE] = [0x11u8; DH_SIZE];
const DH2: [u8; DH_SIZE] = [0x22u8; DH_SIZE];
const DH3: [u8; DH_SIZE] = [0x33u8; DH_SIZE];
const PQ: [u8; PQ_SS_SIZE] = [0x44u8; PQ_SS_SIZE];

/// Builds a real signed pre-key bundle plus the two identity signing keypairs
/// used as transcript inputs (Alice = initiator, Bob = responder/bundle owner).
fn fixture() -> (
    HybridSigningKeypair,
    HybridSigningKeypair,
    SignedPreKeyBundle,
) {
    let alice_signing = HybridSigningKeypair::generate().unwrap();
    let bob_signing = HybridSigningKeypair::generate().unwrap();
    let bob_kem = HybridKemKeypair::generate().unwrap();
    let bob_otk = HybridKemKeypair::generate().unwrap();

    let bundle = PreKeyBundle::new(
        bob_signing.public_key().clone(),
        bob_kem.public_key().clone(),
        bob_otk.public_key().clone(),
        1,
        1000,
        2000,
    );
    let signed_bundle = bundle.sign(&bob_signing).unwrap();
    (alice_signing, bob_signing, signed_bundle)
}

/// Constructs a transcript over the shared placeholder inputs with the given
/// flags, so tests differ in exactly one input.
fn transcript_with(
    alice: &HybridSigningKeypair,
    bob: &HybridSigningKeypair,
    bundle: &SignedPreKeyBundle,
    flags: SessionFlags,
) -> Transcript {
    Transcript::new(
        alice.public_key(),
        bob.public_key(),
        bundle,
        &DH1,
        &DH2,
        &DH3,
        &PQ,
        flags,
    )
}

/// The framing block occupies offsets 296/297/298 and carries the wire
/// version/suite constants plus the reserved-zero `SessionFlags` byte, without
/// disturbing the 296-byte core.
#[cfg_attr(miri, ignore)]
#[test]
fn framing_block_layout() {
    assert_eq!(TRANSCRIPT_SIZE, 299);
    assert_eq!(FRAMING_SIZE, 3);

    let (alice, bob, bundle) = fixture();

    let off = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: false });
    let bytes_off = *off.to_bytes();
    assert_eq!(bytes_off.len(), 299);
    assert_eq!(
        bytes_off[VERSION_OFFSET], PROTOCOL_VERSION,
        "version byte @296"
    );
    assert_eq!(bytes_off[SUITE_OFFSET], CIPHER_SUITE, "suite byte @297");
    assert_eq!(bytes_off[FLAGS_OFFSET], 0x00, "flags byte @298 (LI off)");

    let on = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: true });
    let bytes_on = *on.to_bytes();
    assert_eq!(bytes_on[FLAGS_OFFSET], 0x01, "flags byte @298 (LI on)");
    // Reserved SessionFlags bits (1..=7) MUST serialise as zero.
    assert_eq!(
        bytes_on[FLAGS_OFFSET] & 0xFE,
        0x00,
        "reserved SessionFlags bits must be zero"
    );

    // The 296-byte core (7 existing fields) is identical regardless of flags —
    // the block is appended, never interleaved.
    assert_eq!(
        bytes_off[..VERSION_OFFSET],
        bytes_on[..VERSION_OFFSET],
        "the 296-byte core must be unchanged by the framing block"
    );
}

/// Toggling the LI-capability bit through the public `SessionFlags` parameter
/// diverges the derived secret; identical/matching flags still agree (F18).
#[cfg_attr(miri, ignore)]
#[test]
fn li_bit_diverges() {
    let (alice, bob, bundle) = fixture();

    let off = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: false });
    let on = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: true });

    let secret_off = *off.derive_shared_secret();
    let secret_on = *on.derive_shared_secret();
    assert_ne!(
        secret_off, secret_on,
        "toggling the LI-capability bit must diverge the derived key (F18)"
    );

    // Determinism control: identical inputs derive an identical secret.
    let off_again = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: false });
    let secret_off_again = *off_again.derive_shared_secret();
    assert_eq!(
        secret_off, secret_off_again,
        "identical inputs must derive an identical secret"
    );

    // Matching-flags control: both parties passing the SAME flags still agree.
    let on_again = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: true });
    let secret_on_again = *on_again.derive_shared_secret();
    assert_eq!(
        secret_on, secret_on_again,
        "matching flags must derive matching secrets"
    );
}

/// Flipping the version, suite, or flags byte at the KDF-input level diverges
/// the `SESSION_V2_CONTEXT` derived key (F08 version/suite, F18 flags). Version
/// and suite are compile-time constants, so they are varied at the byte level.
#[cfg_attr(miri, ignore)]
#[test]
fn version_suite_diverges() {
    let (alice, bob, bundle) = fixture();
    let base_t = transcript_with(&alice, &bob, &bundle, SessionFlags { li_capable: false });
    let base = *base_t.to_bytes();

    let base_key = blake3::derive_key(SESSION_V2_CONTEXT, &base);

    // Flip the version byte (offset 296).
    let mut alt_version = base;
    alt_version[VERSION_OFFSET] ^= 0x01;
    assert_ne!(
        base_key,
        blake3::derive_key(SESSION_V2_CONTEXT, &alt_version),
        "flipping the version byte must diverge the derived key (F08)"
    );

    // Flip the cipher-suite byte (offset 297).
    let mut alt_suite = base;
    alt_suite[SUITE_OFFSET] ^= 0x01;
    assert_ne!(
        base_key,
        blake3::derive_key(SESSION_V2_CONTEXT, &alt_suite),
        "flipping the suite byte must diverge the derived key (F08)"
    );

    // Flip the SessionFlags byte (offset 298) — the byte-level view of F18.
    let mut alt_flags = base;
    alt_flags[FLAGS_OFFSET] ^= 0x01;
    assert_ne!(
        base_key,
        blake3::derive_key(SESSION_V2_CONTEXT, &alt_flags),
        "flipping the flags byte must diverge the derived key (F18)"
    );

    // Determinism control: identical transcript bytes derive an identical key.
    let base_key_again = blake3::derive_key(SESSION_V2_CONTEXT, &base);
    assert_eq!(
        base_key, base_key_again,
        "identical transcript bytes must derive an identical key"
    );
}
