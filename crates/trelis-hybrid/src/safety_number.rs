//! Safety number derivation for out-of-band identity verification.
//!
//! Safety numbers provide a way for users to verify they are communicating
//! with the intended party, detecting man-in-the-middle attacks.

// `(carry as u8)` truncation is provably safe — `carry` is the
// `value % 10` residue, always in [0, 9].
// Single-char names (`c`, `s`) in the base64-URL helpers are local
// idiomatic and not part of the public API.
#![allow(clippy::cast_possible_truncation, clippy::many_single_char_names)]
//!
//! # Security Requirements
//!
//! Safety numbers MUST include ALL FOUR key components:
//! - **Signing keys**: Ed448 + ML-DSA-65
//! - **KEM keys**: X448 + sntrup761
//!
//! This prevents attacks where an adversary substitutes only one component
//! of a hybrid identity (e.g., replacing KEM keys while preserving signing keys).
//!
//! # Example
//!
//! ```rust,no_run
//! use trelis_hybrid::{HybridIdentityKeypair, SafetyNumber};
//!
//! let alice = HybridIdentityKeypair::generate().unwrap();
//! let bob = HybridIdentityKeypair::generate().unwrap();
//!
//! let safety_number = SafetyNumber::new(
//!     alice.public_key(),
//!     bob.public_key(),
//! );
//!
//! // Display as 60 decimal digits
//! println!("{}", safety_number.display());
//! ```

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::identity::HybridIdentityPublicKey;
use crate::signature::HybridSigningPublicKey;

/// Context strings re-exported from the central BLAKE3 derive-key registry
/// in `trelis_primitives::blake3_kdf` (PROTO-07-NEW1). The downstream-visible
/// names are preserved.
pub use trelis_primitives::{
    SAFETY_NUMBER_CONTEXT, SAFETY_NUMBER_DEVICE_SET_CONTEXT, SAFETY_NUMBER_SYNC_CONTEXT,
};

/// Size of the thread ID for history-sync safety numbers.
pub const THREAD_ID_SIZE: usize = 32;

/// Safety number for out-of-band identity verification.
///
/// A safety number is derived from two users' identity public keys
/// and can be compared visually or via QR code to verify identities.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 32-byte BLAKE3 fingerprint.
    fingerprint: [u8; 32],
}

impl SafetyNumber {
    /// Creates a new safety number from two hybrid identity public keys.
    ///
    /// The derivation includes all four key components (Ed448, ML-DSA-65,
    /// X448, sntrup761) to prevent partial key substitution attacks.
    ///
    /// The order of keys does not matter - the same safety number is
    /// produced regardless of which key is provided first.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn new(key_a: &HybridIdentityPublicKey, key_b: &HybridIdentityPublicKey) -> Self {
        // Hash each hybrid identity to a fixed-size digest
        let a_digest = Self::hash_identity(key_a);
        let b_digest = Self::hash_identity(key_b);

        // Sort digests for deterministic ordering (commutativity)
        let (first, second) = if a_digest.as_bytes() < b_digest.as_bytes() {
            (a_digest, b_digest)
        } else {
            (b_digest, a_digest)
        };

        // Combine and derive fingerprint
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(first.as_bytes());
        input[32..].copy_from_slice(second.as_bytes());

        let fingerprint = blake3::derive_key(SAFETY_NUMBER_CONTEXT, &input);

        Self { fingerprint }
    }

    /// Creates a safety number for a history-sync-enabled thread.
    ///
    /// Uses a distinct context string to differentiate from forward-secrecy-only
    /// threads. The thread ID is included in the derivation.
    ///
    /// # Arguments
    ///
    /// * `key_a` - First user's identity public key
    /// * `key_b` - Second user's identity public key
    /// * `thread_id` - 32-byte thread identifier
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn new_with_history_sync(
        key_a: &HybridIdentityPublicKey,
        key_b: &HybridIdentityPublicKey,
        thread_id: &[u8; THREAD_ID_SIZE],
    ) -> Self {
        // Hash each hybrid identity to a fixed-size digest
        let a_digest = Self::hash_identity(key_a);
        let b_digest = Self::hash_identity(key_b);

        // Sort digests for deterministic ordering (commutativity)
        let (first, second) = if a_digest.as_bytes() < b_digest.as_bytes() {
            (a_digest, b_digest)
        } else {
            (b_digest, a_digest)
        };

        // Combine with thread ID using stack buffer (96 bytes: 32 + 32 + 32)
        let mut input = [0u8; 96];
        input[..32].copy_from_slice(first.as_bytes());
        input[32..64].copy_from_slice(second.as_bytes());
        input[64..].copy_from_slice(thread_id);

        // DISTINCT context for sync-enabled threads
        let fingerprint = blake3::derive_key(SAFETY_NUMBER_SYNC_CONTEXT, &input);

        Self { fingerprint }
    }

    /// Creates a safety number bound to the current device set of both users.
    ///
    /// This is the spec §15.6 device-set-binding construction. The resulting
    /// safety number changes whenever either user adds or removes a device,
    /// giving cryptographic detection of silent device additions. Each user's
    /// device set is hashed in canonical (fingerprint-sorted) order so the
    /// safety number is independent of device insertion order.
    ///
    /// A distinct BLAKE3 context (`SAFETY_NUMBER_DEVICE_SET_CONTEXT`) ensures
    /// device-set-bound safety numbers are not confused with identity-only
    /// ones — they encode a stricter security claim.
    ///
    /// # Arguments
    ///
    /// * `key_a` — First user's identity public key
    /// * `key_b` — Second user's identity public key
    /// * `devices_a` — First user's current device-identity public keys
    /// * `devices_b` — Second user's current device-identity public keys
    ///
    /// # Commutativity
    ///
    /// `new_with_device_set(a, b, da, db) == new_with_device_set(b, a, db, da)`
    /// — the per-user (identity, device-set) tuples are paired then sorted.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn new_with_device_set(
        key_a: &HybridIdentityPublicKey,
        key_b: &HybridIdentityPublicKey,
        devices_a: &[HybridSigningPublicKey],
        devices_b: &[HybridSigningPublicKey],
    ) -> Self {
        // For each user, fold identity + sorted-device-set into one 32-byte
        // digest. The pairing is what gives the commutativity invariant: a
        // user's device set always travels with their identity.
        let a_combined = Self::hash_identity_with_devices(key_a, devices_a);
        let b_combined = Self::hash_identity_with_devices(key_b, devices_b);

        // Sort the two combined digests so swap-of-arguments produces the
        // same fingerprint.
        let (first, second) = if a_combined.as_bytes() < b_combined.as_bytes() {
            (a_combined, b_combined)
        } else {
            (b_combined, a_combined)
        };

        let mut input = [0u8; 64];
        input[..32].copy_from_slice(first.as_bytes());
        input[32..].copy_from_slice(second.as_bytes());

        let fingerprint = blake3::derive_key(SAFETY_NUMBER_DEVICE_SET_CONTEXT, &input);

        Self { fingerprint }
    }

    /// Folds a hybrid identity public key together with a sorted hash of its
    /// device set into a single 32-byte digest.
    ///
    /// Devices are sorted by `BLAKE3(device_pk_bytes)` ascending before
    /// concatenation, so the device-set hash is independent of insertion
    /// order.
    #[cfg(feature = "alloc")]
    fn hash_identity_with_devices(
        key: &HybridIdentityPublicKey,
        devices: &[HybridSigningPublicKey],
    ) -> blake3::Hash {
        // Step 1: per-device fingerprints (sorted)
        let mut device_fingerprints: Vec<[u8; 32]> = devices
            .iter()
            .map(|pk| *blake3::hash(&pk.to_bytes()).as_bytes())
            .collect();
        device_fingerprints.sort_unstable();

        // Step 2: hash the concatenated sorted fingerprints
        let mut device_set_input: Vec<u8> = Vec::with_capacity(device_fingerprints.len() * 32);
        for fp in &device_fingerprints {
            device_set_input.extend_from_slice(fp);
        }
        let device_set_hash = blake3::hash(&device_set_input);

        // Step 3: combine identity digest + device-set digest
        let identity_digest = Self::hash_identity(key);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(identity_digest.as_bytes());
        combined[32..].copy_from_slice(device_set_hash.as_bytes());
        blake3::hash(&combined)
    }

    /// Hashes a hybrid identity public key to a 32-byte digest.
    ///
    /// Includes all four key components:
    /// - Ed448 signing key (57 bytes)
    /// - ML-DSA-65 signing key (1,952 bytes)
    /// - X448 KEM key (56 bytes)
    /// - sntrup761 KEM key (1,158 bytes)
    #[cfg(feature = "alloc")]
    fn hash_identity(key: &HybridIdentityPublicKey) -> blake3::Hash {
        let mut data = Vec::with_capacity(3223); // Total size of all keys

        // Signing keys (use to_bytes() which includes both Ed448 and ML-DSA-65)
        data.extend_from_slice(&key.signing().to_bytes());

        // KEM keys (use to_bytes() which includes both X448 and sntrup761)
        data.extend_from_slice(&key.kem().to_bytes());

        blake3::hash(&data)
    }

    /// Returns the raw 32-byte fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Reconstructs a `SafetyNumber` from its raw 32-byte fingerprint.
    ///
    /// This is the wire-tier inverse of [`Self::fingerprint`] — used when
    /// deserialising structures that embed a safety number (e.g.
    /// `CertifiedSafetyNumber`). It does NOT re-verify that the bytes
    /// were produced by a real `new()` / `new_with_history_sync` /
    /// `new_with_device_set` call; callers must check the surrounding
    /// signature to ensure provenance.
    #[must_use]
    pub fn from_fingerprint_bytes(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    /// Formats the safety number as 60 decimal digits.
    ///
    /// The format is 12 groups of 5 digits each, displayed in 2 rows:
    /// ```text
    /// 12345 67890 12345 67890 12345 67890
    /// 12345 67890 12345 67890 12345 67890
    /// ```
    ///
    /// The 60 digits encode approximately 199 bits of information
    /// (log2(10^60) ≈ 199.3), providing strong collision resistance.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn display(&self) -> String {
        // Convert fingerprint to a large integer and extract decimal digits
        // We use 30 bytes (240 bits) and convert to 60 decimal digits
        let digits = Self::bytes_to_decimal(&self.fingerprint[..30], 60);

        // Format directly as 12 groups of 5 digits (avoids Vec allocation)
        format!(
            "{} {} {} {} {} {}\n{} {} {} {} {} {}",
            &digits[0..5],
            &digits[5..10],
            &digits[10..15],
            &digits[15..20],
            &digits[20..25],
            &digits[25..30],
            &digits[30..35],
            &digits[35..40],
            &digits[40..45],
            &digits[45..50],
            &digits[50..55],
            &digits[55..60],
        )
    }

    /// Converts bytes to a decimal string of specified length.
    ///
    /// Uses repeated division by 10 on a large integer representation.
    #[cfg(feature = "alloc")]
    fn bytes_to_decimal(bytes: &[u8], num_digits: usize) -> String {
        // Work with bytes as a big-endian large integer
        // We'll extract decimal digits by repeated division
        let mut data: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
        let mut digits = Vec::with_capacity(num_digits);

        for _ in 0..num_digits {
            // Divide by 10, collect remainder as digit
            let mut carry: u16 = 0;
            for byte in &mut data {
                let value = carry * 256 + *byte;
                *byte = value / 10;
                carry = value % 10;
            }
            digits.push((carry as u8) + b'0');
        }

        // Reverse to get most significant digit first
        digits.reverse();
        String::from_utf8(digits).unwrap_or_else(|_| "0".repeat(num_digits))
    }

    /// Returns the safety number as a QR-code-friendly string.
    ///
    /// Format: version byte (0x01) + 32-byte fingerprint, Base64-URL encoded.
    /// Total: 44 characters (no padding).
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_qr_string(&self) -> String {
        use alloc::vec;

        let mut data = vec![0x01u8]; // Version byte
        data.extend_from_slice(&self.fingerprint);

        // Base64-URL encode (no padding)
        base64_url_encode(&data)
    }

    /// Parses a safety number from a QR code string.
    ///
    /// # Errors
    ///
    /// Returns `None` if the string is invalid or has wrong version.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn from_qr_string(s: &str) -> Option<Self> {
        let data = base64_url_decode(s)?;

        if data.len() != 33 || data[0] != 0x01 {
            return None;
        }

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&data[1..]);

        Some(Self { fingerprint })
    }
}

impl core::fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Simple hex display without external dependencies
        write!(
            f,
            "SafetyNumber({:02x}{:02x}{:02x}{:02x}...)",
            self.fingerprint[0], self.fingerprint[1], self.fingerprint[2], self.fingerprint[3]
        )
    }
}

/// Base64-URL encode without padding.
#[cfg(feature = "alloc")]
fn base64_url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
    let mut i = 0;

    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        result.push(ALPHABET[n as usize & 0x3F] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
    }

    result
}

/// Base64-URL decode.
#[cfg(feature = "alloc")]
fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    fn char_to_value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;

    while i + 4 <= bytes.len() {
        let a = char_to_value(bytes[i])?;
        let b = char_to_value(bytes[i + 1])?;
        let c = char_to_value(bytes[i + 2])?;
        let d = char_to_value(bytes[i + 3])?;

        result.push((a << 2) | (b >> 4));
        result.push((b << 4) | (c >> 2));
        result.push((c << 6) | d);
        i += 4;
    }

    let remaining = bytes.len() - i;
    if remaining == 2 {
        let a = char_to_value(bytes[i])?;
        let b = char_to_value(bytes[i + 1])?;
        result.push((a << 2) | (b >> 4));
    } else if remaining == 3 {
        let a = char_to_value(bytes[i])?;
        let b = char_to_value(bytes[i + 1])?;
        let c = char_to_value(bytes[i + 2])?;
        result.push((a << 2) | (b >> 4));
        result.push((b << 4) | (c >> 2));
    }

    Some(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::HybridIdentityKeypair;

    #[test]
    fn test_safety_number_commutativity() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let sn1 = SafetyNumber::new(alice.public_key(), bob.public_key());
        let sn2 = SafetyNumber::new(bob.public_key(), alice.public_key());

        assert_eq!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Order should not matter"
        );
    }

    #[test]
    fn test_safety_number_different_keys_different_numbers() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();
        let carol = HybridIdentityKeypair::generate().unwrap();

        let sn_ab = SafetyNumber::new(alice.public_key(), bob.public_key());
        let sn_ac = SafetyNumber::new(alice.public_key(), carol.public_key());

        assert_ne!(
            sn_ab.fingerprint(),
            sn_ac.fingerprint(),
            "Different keys should produce different safety numbers"
        );
    }

    #[test]
    fn test_safety_number_same_keys_same_number() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let sn1 = SafetyNumber::new(alice.public_key(), bob.public_key());
        let sn2 = SafetyNumber::new(alice.public_key(), bob.public_key());

        assert_eq!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Same keys should produce same safety number"
        );
    }

    #[test]
    fn test_safety_number_display_format() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let sn = SafetyNumber::new(alice.public_key(), bob.public_key());
        let display = sn.display();

        // Should have 60 digits + 11 spaces + 1 newline = 72 characters
        let digits_only: String = display.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits_only.len(), 60, "Should have 60 decimal digits");

        // Check format: 2 lines
        let lines: Vec<&str> = display.lines().collect();
        assert_eq!(lines.len(), 2, "Should have 2 lines");
    }

    #[test]
    fn test_safety_number_qr_roundtrip() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let sn = SafetyNumber::new(alice.public_key(), bob.public_key());
        let qr = sn.to_qr_string();

        // Should be 44 characters (ceil(33 * 4 / 3))
        assert_eq!(qr.len(), 44, "QR string should be 44 characters");

        // Should decode back to same safety number
        let decoded = SafetyNumber::from_qr_string(&qr).expect("Should decode");
        assert_eq!(
            sn.fingerprint(),
            decoded.fingerprint(),
            "Should roundtrip correctly"
        );
    }

    #[test]
    fn test_history_sync_uses_different_context() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();
        let thread_id = [0x42u8; 32];

        let standard = SafetyNumber::new(alice.public_key(), bob.public_key());
        let sync =
            SafetyNumber::new_with_history_sync(alice.public_key(), bob.public_key(), &thread_id);

        assert_ne!(
            standard.fingerprint(),
            sync.fingerprint(),
            "Standard and sync safety numbers should differ"
        );
    }

    #[test]
    fn test_history_sync_commutativity() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();
        let thread_id = [0x42u8; 32];

        let sn1 =
            SafetyNumber::new_with_history_sync(alice.public_key(), bob.public_key(), &thread_id);
        let sn2 =
            SafetyNumber::new_with_history_sync(bob.public_key(), alice.public_key(), &thread_id);

        assert_eq!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Order should not matter for sync numbers"
        );
    }

    #[test]
    fn test_different_thread_ids_different_numbers() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();
        let thread_id_1 = [0x01u8; 32];
        let thread_id_2 = [0x02u8; 32];

        let sn1 =
            SafetyNumber::new_with_history_sync(alice.public_key(), bob.public_key(), &thread_id_1);
        let sn2 =
            SafetyNumber::new_with_history_sync(alice.public_key(), bob.public_key(), &thread_id_2);

        assert_ne!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Different thread IDs should produce different safety numbers"
        );
    }

    #[test]
    fn test_base64_url_encode_decode() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let encoded = base64_url_encode(&data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_device_set_safety_number_commutativity() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let alice_dev1 = HybridIdentityKeypair::generate().unwrap();
        let alice_dev2 = HybridIdentityKeypair::generate().unwrap();
        let bob_dev1 = HybridIdentityKeypair::generate().unwrap();

        let alice_devices = [
            alice_dev1.public_key().signing().clone(),
            alice_dev2.public_key().signing().clone(),
        ];
        let bob_devices = [bob_dev1.public_key().signing().clone()];

        let sn1 = SafetyNumber::new_with_device_set(
            alice.public_key(),
            bob.public_key(),
            &alice_devices,
            &bob_devices,
        );
        let sn2 = SafetyNumber::new_with_device_set(
            bob.public_key(),
            alice.public_key(),
            &bob_devices,
            &alice_devices,
        );

        assert_eq!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Order of (key, devices) tuples should not matter"
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_device_set_safety_number_changes_with_device_addition() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let alice_dev1 = HybridIdentityKeypair::generate().unwrap();
        let alice_dev2 = HybridIdentityKeypair::generate().unwrap();
        let bob_dev1 = HybridIdentityKeypair::generate().unwrap();

        let before = SafetyNumber::new_with_device_set(
            alice.public_key(),
            bob.public_key(),
            &[alice_dev1.public_key().signing().clone()],
            &[bob_dev1.public_key().signing().clone()],
        );

        let after = SafetyNumber::new_with_device_set(
            alice.public_key(),
            bob.public_key(),
            &[
                alice_dev1.public_key().signing().clone(),
                alice_dev2.public_key().signing().clone(),
            ],
            &[bob_dev1.public_key().signing().clone()],
        );

        assert_ne!(
            before.fingerprint(),
            after.fingerprint(),
            "Adding a device must change the safety number"
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_device_set_safety_number_independent_of_device_insertion_order() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let alice_dev1 = HybridIdentityKeypair::generate().unwrap();
        let alice_dev2 = HybridIdentityKeypair::generate().unwrap();
        let bob_dev1 = HybridIdentityKeypair::generate().unwrap();

        let devices_order_1 = [
            alice_dev1.public_key().signing().clone(),
            alice_dev2.public_key().signing().clone(),
        ];
        let devices_order_2 = [
            alice_dev2.public_key().signing().clone(),
            alice_dev1.public_key().signing().clone(),
        ];

        let sn1 = SafetyNumber::new_with_device_set(
            alice.public_key(),
            bob.public_key(),
            &devices_order_1,
            &[bob_dev1.public_key().signing().clone()],
        );
        let sn2 = SafetyNumber::new_with_device_set(
            alice.public_key(),
            bob.public_key(),
            &devices_order_2,
            &[bob_dev1.public_key().signing().clone()],
        );

        assert_eq!(
            sn1.fingerprint(),
            sn2.fingerprint(),
            "Device order must be canonicalised (sorted by fingerprint)"
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_device_set_distinct_from_identity_only_safety_number() {
        let alice = HybridIdentityKeypair::generate().unwrap();
        let bob = HybridIdentityKeypair::generate().unwrap();

        let identity_only = SafetyNumber::new(alice.public_key(), bob.public_key());
        let with_empty_device_sets =
            SafetyNumber::new_with_device_set(alice.public_key(), bob.public_key(), &[], &[]);

        // Distinct BLAKE3 context strings — even empty device sets must
        // produce a different fingerprint than the identity-only number.
        assert_ne!(
            identity_only.fingerprint(),
            with_empty_device_sets.fingerprint(),
            "Device-set-bound and identity-only safety numbers MUST live in distinct security domains"
        );
    }
}
