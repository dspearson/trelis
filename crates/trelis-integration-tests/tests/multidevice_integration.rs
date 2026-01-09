//! Multi-device integration tests for Trelis.
//!
//! These tests verify the complete workflows for:
//! - Device onboarding (approval + key distribution)
//! - History synchronisation between devices
//! - Device revocation and its effects
//! - Cross-device message key sharing
//! - Error handling for invalid operations

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::needless_borrow)]

use trelis_error::CryptoError;
use trelis_hybrid::HybridKemKeypair;

// Type alias for explicit ML-DSA scheme selection
type HybridSigningKeypair =
    trelis_hybrid::HybridSigningKeypair<trelis_primitives::mldsa::MlDsa65Fips204>;
use trelis_multidevice::{
    DeviceApprovalCertificate, DeviceId, DeviceKeyWrap, DeviceRevocation, FINGERPRINT_SIZE,
    HistoryKeyShareMessage, RetainedKey, RevocationReason, RevocationRekeyEvent, ThreadId,
    ThreadKeyStore, ThreadSettings, WrapContext, WrapPurpose, device_fingerprint,
};
use trelis_primitives::hash;

// =============================================================================
// Device Onboarding Flow Tests
// =============================================================================

/// Tests the complete device onboarding flow:
/// 1. Existing device generates approval certificate
/// 2. New device verifies the certificate
/// 3. Existing device wraps keys for new device
/// 4. New device unwraps and uses the keys
#[test]
fn test_complete_device_onboarding_flow() {
    // === Setup: Existing device ===
    let existing_device_id: DeviceId = [0x01u8; 16];
    let existing_signing_key = HybridSigningKeypair::generate().unwrap();
    let _existing_kem_key = HybridKemKeypair::generate().unwrap();

    // === Setup: New device ===
    let new_device_signing_key = HybridSigningKeypair::generate().unwrap();
    let new_device_kem_key = HybridKemKeypair::generate().unwrap();
    let new_device_fingerprint = device_fingerprint(&new_device_signing_key.public_key());

    // === Step 1: Existing device creates approval certificate ===
    let approval_timestamp = 1000u64;
    let approval = DeviceApprovalCertificate::new(
        existing_device_id,
        new_device_fingerprint,
        approval_timestamp,
        &existing_signing_key,
    )
    .expect("Failed to create approval certificate");

    // === Step 2: New device verifies the approval ===
    approval
        .verify(&existing_signing_key.public_key())
        .expect("New device should be able to verify approval");

    // Verify the fingerprint matches
    let actual_fingerprint = device_fingerprint(&new_device_signing_key.public_key());
    assert_eq!(
        approval.new_device_fingerprint, actual_fingerprint,
        "Fingerprint in approval should match new device's key"
    );

    // === Step 3: Existing device wraps a secret key for new device ===
    let secret_to_share = [0xABu8; 32];
    let thread_id: ThreadId = [0x42u8; 32];
    let bundle_id = [0x33u8; 32];
    let epoch = 5u64;

    // Create key ID from new device's KEM public key
    let new_device_key_id = {
        let pk_bytes = new_device_kem_key.public_key().to_bytes();
        let h = hash(&pk_bytes);
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&h[..8]);
        key_id
    };

    let wrap_context = WrapContext::new(
        new_device_key_id,
        WrapPurpose::BundleKey,
        thread_id,
        bundle_id,
        epoch,
    );

    let wrapped = DeviceKeyWrap::wrap(
        &secret_to_share,
        new_device_kem_key.public_key(),
        &wrap_context,
    )
    .expect("Failed to wrap key");

    // === Step 4: New device unwraps the secret ===
    let unwrapped = wrapped
        .unwrap(&new_device_kem_key, &wrap_context)
        .expect("New device should be able to unwrap");

    assert_eq!(
        unwrapped, secret_to_share,
        "Unwrapped secret should match original"
    );

    println!("✓ Complete device onboarding flow verified");
}

/// Tests that approval certificates cannot be verified with wrong keys.
#[test]
fn test_approval_verification_fails_with_wrong_key() {
    let device_id: DeviceId = [0x01u8; 16];
    let signing_key = HybridSigningKeypair::generate().unwrap();
    let wrong_key = HybridSigningKeypair::generate().unwrap();
    let fingerprint = [0xAAu8; FINGERPRINT_SIZE];

    let approval =
        DeviceApprovalCertificate::new(device_id, fingerprint, 1000, &signing_key).unwrap();

    let result = approval.verify(&wrong_key.public_key());
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed)),
        "Verification with wrong key should fail"
    );

    println!("✓ Approval verification correctly rejects wrong key");
}

/// Tests approval certificate serialisation roundtrip.
#[test]
fn test_approval_certificate_serialisation_roundtrip() {
    let signing_key = HybridSigningKeypair::generate().unwrap();
    let original =
        DeviceApprovalCertificate::new([0x42u8; 16], [0xAAu8; 32], 12345, &signing_key).unwrap();

    let bytes = original.to_bytes();
    let recovered = DeviceApprovalCertificate::from_bytes(&bytes).unwrap();

    assert_eq!(recovered.approving_device_id, original.approving_device_id);
    assert_eq!(
        recovered.new_device_fingerprint,
        original.new_device_fingerprint
    );
    assert_eq!(recovered.approved_at, original.approved_at);

    // Signature should still verify
    recovered.verify(&signing_key.public_key()).unwrap();

    println!("✓ Approval certificate serialisation roundtrip verified");
}

// =============================================================================
// History Sync Flow Tests
// =============================================================================

/// Tests the complete history sync flow:
/// 1. Create retained keys for a thread
/// 2. Package them in a HistoryKeyShareMessage
/// 3. Serialise, deserialise, and verify
/// 4. Merge into new device's key store
#[test]
fn test_complete_history_sync_flow() {
    let thread_id: ThreadId = [0x42u8; 32];
    let signing_key = HybridSigningKeypair::generate().unwrap();

    // === Step 1: Create retained keys ===
    let keys: Vec<RetainedKey> = (0..10)
        .map(|i| {
            let mut message_id = [0u8; 32];
            message_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            RetainedKey::new(message_id, [0xAA + i as u8; 32], i as u64, 1000 + i as u64)
        })
        .collect();

    // === Step 2: Create history share message ===
    let share_timestamp = 5000u64;
    let share_message =
        HistoryKeyShareMessage::new(thread_id, keys.clone(), &signing_key, share_timestamp)
            .expect("Failed to create history share message");

    assert_eq!(share_message.key_count(), 10);

    // === Step 3: Serialise and deserialise ===
    let bytes = share_message.to_bytes();
    let recovered = HistoryKeyShareMessage::from_bytes(&bytes).expect("Failed to deserialise");

    // Verify signature
    recovered
        .verify(&signing_key.public_key())
        .expect("Signature verification failed");

    assert_eq!(recovered.thread_id, thread_id);
    assert_eq!(recovered.key_count(), 10);
    assert_eq!(recovered.shared_at, share_timestamp);

    // === Step 4: Merge into new device's key store ===
    let mut new_device_store = ThreadKeyStore::new(thread_id);
    assert!(new_device_store.is_empty());

    new_device_store.merge(recovered.keys);
    assert_eq!(new_device_store.len(), 10);

    // Verify sequence ordering
    let range = new_device_store.sequence_range().unwrap();
    assert_eq!(range, (0, 9));

    // Verify we can look up individual keys
    for i in 0..10 {
        let key = new_device_store.get_key_by_sequence(i as u64);
        assert!(key.is_some(), "Key with sequence {} should exist", i);
    }

    println!("✓ Complete history sync flow verified");
}

/// Tests that history sync messages cannot be verified with wrong sender key.
#[test]
fn test_history_sync_verification_fails_with_wrong_key() {
    let thread_id: ThreadId = [0x42u8; 32];
    let sender_key = HybridSigningKeypair::generate().unwrap();
    let wrong_key = HybridSigningKeypair::generate().unwrap();

    let keys = vec![RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 0, 1000)];

    let message = HistoryKeyShareMessage::new(thread_id, keys, &sender_key, 5000).unwrap();

    let result = message.verify(&wrong_key.public_key());
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed)),
        "Verification with wrong key should fail"
    );

    println!("✓ History sync verification correctly rejects wrong key");
}

/// Tests ThreadKeyStore merge deduplication.
#[test]
fn test_key_store_merge_deduplication() {
    let thread_id: ThreadId = [0x42u8; 32];
    let mut store = ThreadKeyStore::new(thread_id);

    // Add initial keys
    store.retain_key(RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 1, 1000));
    store.retain_key(RetainedKey::new([0x02u8; 32], [0xBBu8; 32], 2, 2000));

    assert_eq!(store.len(), 2);

    // Merge with overlapping + new keys
    let new_keys = vec![
        RetainedKey::new([0x01u8; 32], [0xAAu8; 32], 1, 1000), // Duplicate
        RetainedKey::new([0x03u8; 32], [0xCCu8; 32], 3, 3000), // New
        RetainedKey::new([0x02u8; 32], [0xBBu8; 32], 2, 2000), // Duplicate
        RetainedKey::new([0x04u8; 32], [0xDDu8; 32], 4, 4000), // New
    ];

    store.merge(new_keys);

    // Should have 4 keys (duplicates ignored)
    assert_eq!(store.len(), 4);

    // Verify sequence ordering
    assert_eq!(store.sequence_range(), Some((1, 4)));

    println!("✓ Key store merge deduplication verified");
}

/// Tests ThreadKeyStore pruning by timestamp.
#[test]
fn test_key_store_pruning() {
    let thread_id: ThreadId = [0x42u8; 32];
    let mut store = ThreadKeyStore::new(thread_id);

    // Add keys with various timestamps
    for i in 0..10 {
        store.retain_key(RetainedKey::new(
            [i as u8; 32],
            [0xAAu8; 32],
            i as u64,
            (i * 100) as u64, // timestamps: 0, 100, 200, ..., 900
        ));
    }

    assert_eq!(store.len(), 10);

    // Prune keys older than timestamp 500
    store.prune_before(500);

    // Should have 5 keys remaining (timestamps 500, 600, 700, 800, 900)
    assert_eq!(store.len(), 5);

    // Verify remaining keys have timestamps >= 500
    for key in store.get_all_keys() {
        assert!(key.timestamp >= 500);
    }

    println!("✓ Key store pruning verified");
}

// =============================================================================
// Device Revocation Flow Tests
// =============================================================================

/// Tests the complete device revocation flow:
/// 1. Create revocation certificate
/// 2. Verify the certificate
/// 3. Extract rekey event
/// 4. Verify priority based on reason
#[test]
fn test_complete_device_revocation_flow() {
    let device_id: DeviceId = [0x42u8; 16];
    let identity_key = HybridSigningKeypair::generate().unwrap();
    let revocation_timestamp = 5000u64;

    // === Test all revocation reasons ===
    for reason in [
        RevocationReason::UserInitiated,
        RevocationReason::DeviceLost,
        RevocationReason::DeviceCompromised,
        RevocationReason::DeviceReplaced,
    ] {
        // Create revocation
        let revocation =
            DeviceRevocation::new(device_id, reason, revocation_timestamp, &identity_key)
                .expect("Failed to create revocation");

        assert_eq!(revocation.device_id, device_id);
        assert_eq!(revocation.reason, reason);
        assert_eq!(revocation.revoked_at, revocation_timestamp);

        // Verify the certificate
        revocation
            .verify(&identity_key.public_key())
            .expect("Revocation verification failed");

        // Extract rekey event
        let rekey_event = RevocationRekeyEvent::from_revocation(&revocation);
        assert_eq!(rekey_event.device_id, device_id);
        assert_eq!(rekey_event.reason, reason);
        assert_eq!(rekey_event.revoked_at, revocation_timestamp);

        // Verify priority
        let requires_immediate = rekey_event.requires_immediate_rekey();
        match reason {
            RevocationReason::DeviceCompromised => {
                assert!(
                    requires_immediate,
                    "Compromised devices require immediate rekey"
                );
            }
            _ => {
                assert!(
                    !requires_immediate,
                    "Non-compromised revocations can be batched"
                );
            }
        }
    }

    println!("✓ Complete device revocation flow verified for all reasons");
}

/// Tests that revocation cannot be verified with wrong key.
#[test]
fn test_revocation_verification_fails_with_wrong_key() {
    let device_id: DeviceId = [0x42u8; 16];
    let identity_key = HybridSigningKeypair::generate().unwrap();
    let wrong_key = HybridSigningKeypair::generate().unwrap();

    let revocation =
        DeviceRevocation::new(device_id, RevocationReason::DeviceLost, 5000, &identity_key)
            .unwrap();

    let result = revocation.verify(&wrong_key.public_key());
    assert!(
        matches!(result, Err(CryptoError::SignatureVerificationFailed)),
        "Verification with wrong key should fail"
    );

    println!("✓ Revocation verification correctly rejects wrong key");
}

/// Tests revocation certificate serialisation roundtrip.
#[test]
fn test_revocation_serialisation_roundtrip() {
    let identity_key = HybridSigningKeypair::generate().unwrap();

    for reason in [
        RevocationReason::UserInitiated,
        RevocationReason::DeviceLost,
        RevocationReason::DeviceCompromised,
        RevocationReason::DeviceReplaced,
    ] {
        let original = DeviceRevocation::new([0x42u8; 16], reason, 12345, &identity_key).unwrap();

        let bytes = original.to_bytes();
        let recovered = DeviceRevocation::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.device_id, original.device_id);
        assert_eq!(recovered.reason, original.reason);
        assert_eq!(recovered.revoked_at, original.revoked_at);

        // Signature should still verify
        recovered.verify(&identity_key.public_key()).unwrap();
    }

    println!("✓ Revocation serialisation roundtrip verified for all reasons");
}

// =============================================================================
// DeviceKeyWrap Tests
// =============================================================================

/// Tests DeviceKeyWrap with all purpose types.
#[test]
fn test_device_key_wrap_all_purposes() {
    let keypair = HybridKemKeypair::generate().unwrap();
    let secret = [0xABu8; 32];
    let thread_id: ThreadId = [0x42u8; 32];
    let bundle_id = [0x33u8; 32];
    let key_id = [0x11u8; 8];

    for purpose in [
        WrapPurpose::BundleKey,
        WrapPurpose::SessionSeed,
        WrapPurpose::HistoryKey,
    ] {
        let context = WrapContext::new(key_id, purpose, thread_id, bundle_id, 100);

        let wrapped =
            DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context).expect("Wrap failed");

        let unwrapped = wrapped.unwrap(&keypair, &context).expect("Unwrap failed");

        assert_eq!(unwrapped, secret, "Secret should match for {:?}", purpose);
    }

    println!("✓ DeviceKeyWrap verified for all purposes");
}

/// Tests that wrong context causes unwrap to fail.
#[test]
fn test_device_key_wrap_context_binding() {
    let keypair = HybridKemKeypair::generate().unwrap();
    let secret = [0xABu8; 32];
    let key_id = [0x11u8; 8];

    let context1 = WrapContext::new(
        key_id,
        WrapPurpose::BundleKey,
        [0x42u8; 32], // thread_id
        [0x33u8; 32], // bundle_id
        100,          // epoch
    );

    let wrapped = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context1).unwrap();

    // Try unwrapping with different thread_id
    let context_wrong_thread = WrapContext::new(
        key_id,
        WrapPurpose::BundleKey,
        [0x99u8; 32], // Different thread_id
        [0x33u8; 32],
        100,
    );
    assert!(wrapped.unwrap(&keypair, &context_wrong_thread).is_err());

    // Try unwrapping with different purpose
    let context_wrong_purpose = WrapContext::new(
        key_id,
        WrapPurpose::HistoryKey, // Different purpose
        [0x42u8; 32],
        [0x33u8; 32],
        100,
    );
    assert!(wrapped.unwrap(&keypair, &context_wrong_purpose).is_err());

    // Try unwrapping with different epoch
    let context_wrong_epoch = WrapContext::new(
        key_id,
        WrapPurpose::BundleKey,
        [0x42u8; 32],
        [0x33u8; 32],
        999, // Different epoch
    );
    assert!(wrapped.unwrap(&keypair, &context_wrong_epoch).is_err());

    // Try unwrapping with different bundle_id
    let context_wrong_bundle = WrapContext::new(
        key_id,
        WrapPurpose::BundleKey,
        [0x42u8; 32],
        [0x99u8; 32], // Different bundle_id
        100,
    );
    assert!(wrapped.unwrap(&keypair, &context_wrong_bundle).is_err());

    println!("✓ DeviceKeyWrap context binding verified");
}

/// Tests that wrong key_id causes unwrap to fail early.
#[test]
fn test_device_key_wrap_key_id_binding() {
    let keypair = HybridKemKeypair::generate().unwrap();
    let secret = [0xABu8; 32];

    let context1 = WrapContext::new(
        [0x11u8; 8], // key_id
        WrapPurpose::BundleKey,
        [0x42u8; 32],
        [0x33u8; 32],
        100,
    );

    let wrapped = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context1).unwrap();

    // Try unwrapping with different key_id
    let context_wrong_key_id = WrapContext::new(
        [0x99u8; 8], // Different key_id
        WrapPurpose::BundleKey,
        [0x42u8; 32],
        [0x33u8; 32],
        100,
    );

    let result = wrapped.unwrap(&keypair, &context_wrong_key_id);
    assert!(
        matches!(result, Err(CryptoError::DecryptionFailed)),
        "Wrong key_id should fail with DecryptionFailed"
    );

    println!("✓ DeviceKeyWrap key_id binding verified");
}

/// Tests DeviceKeyWrap serialisation roundtrip.
#[test]
fn test_device_key_wrap_serialisation() {
    let keypair = HybridKemKeypair::generate().unwrap();
    let secret = [0xCDu8; 32];
    let context = WrapContext::new(
        [0x42u8; 8],
        WrapPurpose::SessionSeed,
        [0x11u8; 32],
        [0x22u8; 32],
        99999,
    );

    let original = DeviceKeyWrap::wrap(&secret, keypair.public_key(), &context).unwrap();

    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), 1175, "DeviceKeyWrap should be 1175 bytes");

    let recovered = DeviceKeyWrap::from_bytes(&bytes).unwrap();

    // Verify unwrap works with recovered wrap
    let unwrapped = recovered.unwrap(&keypair, &context).unwrap();
    assert_eq!(unwrapped, secret);

    println!("✓ DeviceKeyWrap serialisation roundtrip verified");
}

// =============================================================================
// Thread Settings Tests
// =============================================================================

/// Tests thread settings toggle behaviour.
#[test]
fn test_thread_settings_toggle() {
    let thread_id: ThreadId = [0x42u8; 32];

    // Default settings (history sync enabled)
    let mut settings = ThreadSettings::new(thread_id);
    assert!(settings.is_history_sync_enabled());
    assert!(settings.history_sync_changed_at.is_none());

    // Disable
    settings.disable_history_sync(1000);
    assert!(!settings.is_history_sync_enabled());
    assert_eq!(settings.history_sync_changed_at, Some(1000));

    // Enable again
    settings.enable_history_sync(2000);
    assert!(settings.is_history_sync_enabled());
    assert_eq!(settings.history_sync_changed_at, Some(2000));

    println!("✓ Thread settings toggle behaviour verified");
}

/// Tests ephemeral thread creation.
#[test]
fn test_ephemeral_thread() {
    let thread_id: ThreadId = [0x42u8; 32];
    let settings = ThreadSettings::new_ephemeral(thread_id, 1000);

    assert!(!settings.is_history_sync_enabled());
    assert_eq!(settings.history_sync_changed_at, Some(1000));

    println!("✓ Ephemeral thread creation verified");
}

// =============================================================================
// Multi-Device Scenario Tests
// =============================================================================

/// Tests a scenario with multiple devices receiving keys.
#[test]
fn test_multi_device_key_distribution() {
    let thread_id: ThreadId = [0x42u8; 32];
    let bundle_id = [0x33u8; 32];
    let epoch = 5u64;

    // Create 3 devices
    let device_keypairs: Vec<HybridKemKeypair> = (0..3)
        .map(|_| HybridKemKeypair::generate().unwrap())
        .collect();

    // Secret to distribute
    let secret = [0xABu8; 32];

    // Wrap secret for each device
    let wraps: Vec<DeviceKeyWrap> = device_keypairs
        .iter()
        .enumerate()
        .map(|(i, kp)| {
            let key_id = [i as u8; 8];
            let context =
                WrapContext::new(key_id, WrapPurpose::BundleKey, thread_id, bundle_id, epoch);
            DeviceKeyWrap::wrap(&secret, kp.public_key(), &context).unwrap()
        })
        .collect();

    // Each device unwraps with its own keypair
    for (i, (wrap, kp)) in wraps.iter().zip(device_keypairs.iter()).enumerate() {
        let key_id = [i as u8; 8];
        let context = WrapContext::new(key_id, WrapPurpose::BundleKey, thread_id, bundle_id, epoch);

        let unwrapped = wrap.unwrap(kp, &context).unwrap();
        assert_eq!(
            unwrapped, secret,
            "Device {} should unwrap correct secret",
            i
        );
    }

    // Verify cross-device unwrap fails
    let wrong_context = WrapContext::new(
        [0u8; 8],
        WrapPurpose::BundleKey,
        thread_id,
        bundle_id,
        epoch,
    );
    let result = wraps[0].unwrap(&device_keypairs[1], &wrong_context);
    assert!(result.is_err(), "Cross-device unwrap should fail");

    println!("✓ Multi-device key distribution verified");
}

/// Tests a complete onboarding + history sync scenario.
#[test]
fn test_onboarding_with_history_sync() {
    let thread_id: ThreadId = [0x42u8; 32];

    // === Existing device setup ===
    let existing_device_id: DeviceId = [0x01u8; 16];
    let existing_signing = HybridSigningKeypair::generate().unwrap();
    let _existing_kem = HybridKemKeypair::generate().unwrap();

    // Existing device's key store with history
    let mut existing_store = ThreadKeyStore::new(thread_id);
    for i in 0..50 {
        existing_store.retain_key(RetainedKey::new(
            [i as u8; 32],
            [0xAA + (i % 10) as u8; 32],
            i as u64,
            (1000 + i) as u64,
        ));
    }

    // === New device setup ===
    let new_signing = HybridSigningKeypair::generate().unwrap();
    let _new_kem = HybridKemKeypair::generate().unwrap();
    let new_fingerprint = device_fingerprint(&new_signing.public_key());

    // === Step 1: Create and verify approval ===
    let approval = DeviceApprovalCertificate::new(
        existing_device_id,
        new_fingerprint,
        5000,
        &existing_signing,
    )
    .unwrap();

    approval.verify(&existing_signing.public_key()).unwrap();

    // === Step 2: Create history share message ===
    let keys_to_share = existing_store.get_all_keys().to_vec();
    let history_message =
        HistoryKeyShareMessage::new(thread_id, keys_to_share, &existing_signing, 6000).unwrap();

    // === Step 3: New device receives and verifies ===
    history_message
        .verify(&existing_signing.public_key())
        .unwrap();

    // === Step 4: New device merges keys ===
    let mut new_store = ThreadKeyStore::new(thread_id);
    new_store.merge(history_message.keys);

    assert_eq!(new_store.len(), 50);
    assert_eq!(new_store.sequence_range(), Some((0, 49)));

    println!("✓ Onboarding with history sync verified");
}

// =============================================================================
// Error Path Tests
// =============================================================================

/// Tests malformed data handling.
#[test]
fn test_malformed_data_handling() {
    // Empty data
    assert!(DeviceApprovalCertificate::from_bytes(&[]).is_err());
    assert!(DeviceRevocation::from_bytes(&[]).is_err());
    assert!(HistoryKeyShareMessage::from_bytes(&[]).is_err());
    assert!(DeviceKeyWrap::from_bytes(&[]).is_err());

    // Truncated data
    assert!(DeviceApprovalCertificate::from_bytes(&[0u8; 30]).is_err());
    assert!(DeviceRevocation::from_bytes(&[0u8; 10]).is_err());
    assert!(HistoryKeyShareMessage::from_bytes(&[0u8; 20]).is_err());
    assert!(DeviceKeyWrap::from_bytes(&[0u8; 100]).is_err());

    // Wrong size for DeviceKeyWrap
    assert!(DeviceKeyWrap::from_bytes(&[0u8; 1174]).is_err()); // One byte short
    assert!(DeviceKeyWrap::from_bytes(&[0u8; 1176]).is_err()); // One byte long

    println!("✓ Malformed data handling verified");
}

/// Tests invalid revocation reason handling.
#[test]
fn test_invalid_revocation_reason() {
    assert!(RevocationReason::from_byte(99).is_none());
    assert!(RevocationReason::from_byte(255).is_none());

    println!("✓ Invalid revocation reason handling verified");
}

/// Tests invalid wrap purpose handling.
#[test]
fn test_invalid_wrap_purpose() {
    assert!(WrapPurpose::from_byte(0).is_none());
    assert!(WrapPurpose::from_byte(4).is_none());
    assert!(WrapPurpose::from_byte(255).is_none());

    println!("✓ Invalid wrap purpose handling verified");
}

// =============================================================================
// Fingerprint Tests
// =============================================================================

/// Tests device fingerprint determinism.
#[test]
fn test_device_fingerprint_determinism() {
    let keypair = HybridSigningKeypair::generate().unwrap();

    let fp1 = device_fingerprint(&keypair.public_key());
    let fp2 = device_fingerprint(&keypair.public_key());

    assert_eq!(fp1, fp2, "Same key should produce same fingerprint");

    // Different key should produce different fingerprint
    let other = HybridSigningKeypair::generate().unwrap();
    let fp3 = device_fingerprint(&other.public_key());

    assert_ne!(
        fp1, fp3,
        "Different keys should produce different fingerprints"
    );

    println!("✓ Device fingerprint determinism verified");
}

// =============================================================================
// Summary Test
// =============================================================================

#[test]
fn test_all_multidevice_components_present() {
    // Verify all expected exports are available
    let _thread_id: ThreadId = [0u8; 32];
    let _device_id: DeviceId = [0u8; 16];

    // Constants
    assert_eq!(FINGERPRINT_SIZE, 32);

    // Enum variants
    let _ = WrapPurpose::BundleKey;
    let _ = WrapPurpose::SessionSeed;
    let _ = WrapPurpose::HistoryKey;

    let _ = RevocationReason::UserInitiated;
    let _ = RevocationReason::DeviceLost;
    let _ = RevocationReason::DeviceCompromised;
    let _ = RevocationReason::DeviceReplaced;

    println!("✓ All multidevice components present");
}
