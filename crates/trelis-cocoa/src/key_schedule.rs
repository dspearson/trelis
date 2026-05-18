//! CoCoA key schedule: H1-H5 hash functions.
//!
//! These domain-separated BLAKE3 hash functions provide:
//! - H1: Seed chain advancement (leaf → root)
//! - H2: Deterministic keypair generation from seed
//! - H3: Tree labels, round hash, transcript hash
//! - H4: Parent hash for tree integrity
//! - H5: Epoch secret derivation

use trelis_hybrid::HybridKemPublicKey;
use zeroize::Zeroizing;

use crate::UserId;

/// Context string for H1 (seed derivation).
pub const H1_CONTEXT: &str = "cocoa-sa-seed-derive-v1";

/// Context string prefix for H2 (keypair generation).
/// The full context is `cocoa-sa-keygen-{key_type}-v1` where key_type is "x448" or "sntrup".
pub const H2_CONTEXT_PREFIX: &str = "cocoa-sa-keygen-";

/// H2 context for X448 key generation.
pub const H2_CONTEXT_X448: &str = "cocoa-sa-keygen-x448-v1";

/// H2 context for sntrup761 key generation.
pub const H2_CONTEXT_SNTRUP: &str = "cocoa-sa-keygen-sntrup-v1";

/// Context string for H3 (tree labels).
pub const H3_CONTEXT: &str = "cocoa-sa-tree-label-v1";

/// Context string for H4 (parent hash).
pub const H4_CONTEXT: &str = "cocoa-sa-parent-hash-v1";

/// Context string for H5 (epoch secret).
pub const H5_CONTEXT: &str = "cocoa-sa-epoch-secret-v1";

/// Context for round hash computation.
pub const ROUND_HASH_CONTEXT: &str = "cocoa-sa-round-hash-v1";

/// Context for transcript hash chaining.
pub const TRANSCRIPT_HASH_CONTEXT: &str = "cocoa-sa-transcript-hash-v1";

/// Context for app secret derivation.
pub const APP_SECRET_CONTEXT: &str = "cocoa-sa-app-secret-v1";

/// Context for confirmation key derivation.
pub const CONF_KEY_CONTEXT: &str = "cocoa-sa-conf-key-v1";

/// Context for init secret derivation.
pub const INIT_SECRET_CONTEXT: &str = "cocoa-sa-init-secret-v1";

/// Context for message key derivation.
pub const MESSAGE_KEY_CONTEXT: &str = "cocoa-sa-message-key-v1";

/// Context for message nonce derivation.
pub const MESSAGE_NONCE_CONTEXT: &str = "cocoa-sa-message-nonce-v1";

/// Context for root tree label derivation (used in ratchet tree path operations).
pub const ROOT_LABEL_CONTEXT: &str = "cocoa-sa-root-label-v1";

/// Context for confirmation tag derivation (used in commit validation).
pub const CONFIRMATION_TAG_CONTEXT: &str = "cocoa-sa-confirmation-tag-v1";

/// Context for user ID derivation (used in update operations).
pub const USER_ID_CONTEXT: &str = "cocoa-sa-user-id-v1";

/// H1: Seed chain advancement (leaf → root).
///
/// Each call advances the seed one level up the tree. Output is wrapped in
/// `Zeroizing<>` because the seed is secret material.
#[must_use]
pub fn derive_h1_seed(delta: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(H1_CONTEXT, delta))
}

/// Private const-context-only key-derivation helper (test-only).
///
/// **This function is private by design (`fn`, not `pub fn`) AND is
/// gated on `#[cfg(all(test, feature = "alloc"))]` — production code
/// never sees it.** Passing user-controlled bytes as a BLAKE3 derivation
/// context would silently weaken domain separation by allowing
/// adversarial context-string collisions with other registry entries.
///
/// The only legitimate callers are the const-context-wrapper public
/// functions [`h2_keygen_x448`] and [`h2_keygen_sntrup`] (which pin
/// `key_type` to a compile-time-constant string at the const registry
/// `H2_CONTEXT_X448` / `H2_CONTEXT_SNTRUP`). This dynamic-context
/// helper exists in the test module so the equivalence checks below
/// can cross-validate the wrappers against the spec template.
///
/// **Do NOT make this function `pub`** (nor relax the `#[cfg(test)]`
/// gate). If a new key type is needed, add a new `h2_keygen_<new_type>`
/// public wrapper whose `key_type` is a const string literal registered
/// in the central `H2_CONTEXT_*` constants block above.
#[cfg(all(test, feature = "alloc"))]
#[must_use]
fn h2_keygen_seed(seed: &[u8; 32], key_type: &str) -> [u8; 32] {
    use alloc::format;
    let context = format!("cocoa-sa-keygen-{}-v1", key_type);
    blake3::derive_key(&context, seed)
}

/// H2: Deterministic X448 keypair seed generation.
///
/// Convenience function for X448 key derivation. Output is wrapped in
/// `Zeroizing<>` because the seed is secret material.
#[must_use]
pub fn h2_keygen_x448(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(H2_CONTEXT_X448, seed))
}

/// H2: Deterministic sntrup761 keypair seed generation.
///
/// Convenience function for sntrup761 key derivation. Output is wrapped in
/// `Zeroizing<>` because the seed is secret material.
#[must_use]
pub fn h2_keygen_sntrup(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(H2_CONTEXT_SNTRUP, seed))
}

/// H3: Tree label computation.
///
/// Creates a unique label for a tree node based on its position and key.
#[must_use]
pub fn h3_tree_label(depth: u32, position: u32, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(H3_CONTEXT);
    hasher.update(&depth.to_le_bytes());
    hasher.update(&position.to_le_bytes());
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

/// H3: Round hash computation.
///
/// Creates a Merkle commitment over the tree state for a round.
/// H_round(n) = H3(tree_label(root), removed_users, added_users)
#[cfg(feature = "alloc")]
#[must_use]
pub fn h3_round_hash(
    root_tree_label: &[u8; 32],
    removed_users: &[UserId],
    added_users: &[UserId],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ROUND_HASH_CONTEXT);

    // Root tree label
    hasher.update(root_tree_label);

    // Encode removed users
    hasher.update(&(removed_users.len() as u32).to_le_bytes());
    for user in removed_users {
        hasher.update(user);
    }

    // Encode added users
    hasher.update(&(added_users.len() as u32).to_le_bytes());
    for user in added_users {
        hasher.update(user);
    }

    *hasher.finalize().as_bytes()
}

/// H3: Transcript hash chaining.
///
/// Chains round hashes together: H_trans(n) = H3(H_trans(n-1) || H_round(n))
#[must_use]
pub fn h3_transcript_hash(prev_transcript: &[u8; 32], round_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(TRANSCRIPT_HASH_CONTEXT);
    hasher.update(prev_transcript);
    hasher.update(round_hash);
    *hasher.finalize().as_bytes()
}

/// H4: Parent hash h1 component (sibling binding).
///
/// Computes h_1 = H4(pk_child || sibling_label)
/// This binds the node to its sibling's subtree state.
#[must_use]
pub fn h4_parent_hash_h1(child_pk: &HybridKemPublicKey, sibling_label: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(H4_CONTEXT);
    hasher.update(b"h1-sibling");
    hasher.update(&child_pk.to_bytes());
    hasher.update(sibling_label);
    *hasher.finalize().as_bytes()
}

/// H4: Parent hash h2 component (predecessor binding).
///
/// Computes h_2 = H4(pk_v, PKpr_v, h_2,child, {pk_w}_{w in R})
/// This binds to predecessor keys and resolution keys.
#[cfg(feature = "alloc")]
#[must_use]
pub fn h4_parent_hash_h2(
    child_pk: &HybridKemPublicKey,
    predecessor_keys: &[&HybridKemPublicKey],
    child_h2: &[u8; 32],
    resolution_keys: &[&HybridKemPublicKey],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(H4_CONTEXT);
    hasher.update(b"h2-predecessors");

    // Include child public key
    hasher.update(&child_pk.to_bytes());

    // Include all predecessor keys
    for pk in predecessor_keys {
        hasher.update(&pk.to_bytes());
    }

    // Include child's h_2 for chaining
    hasher.update(child_h2);

    // Include resolution keys
    for pk in resolution_keys {
        hasher.update(&pk.to_bytes());
    }

    *hasher.finalize().as_bytes()
}

/// H5: Epoch secret derivation.
///
/// Derives epoch secret from previous init secret, root seed, and transcript.
/// Output is wrapped in `Zeroizing<>` because the epoch secret is the seed
/// for every other epoch derivation.
#[must_use]
pub fn h5_epoch_secret(
    init_secret_prev: &[u8; 32],
    delta_root: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(H5_CONTEXT);
    hasher.update(init_secret_prev);
    hasher.update(delta_root);
    hasher.update(transcript_hash);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

/// Derives app secret from epoch secret. Output wrapped in `Zeroizing<>`.
#[must_use]
pub fn derive_app_secret(epoch_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(APP_SECRET_CONTEXT, epoch_secret))
}

/// Derives confirmation key from epoch secret. Output wrapped in `Zeroizing<>`.
#[must_use]
pub fn derive_conf_key(epoch_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(CONF_KEY_CONTEXT, epoch_secret))
}

/// Derives init secret for next epoch from epoch secret. Output wrapped in `Zeroizing<>`.
#[must_use]
pub fn derive_init_secret(epoch_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(INIT_SECRET_CONTEXT, epoch_secret))
}

/// Derives a per-sender message key from `app_secret`, the sender's tree leaf
/// position, and the sender's local message counter. Output wrapped in
/// `Zeroizing<>`.
///
/// Binding `sender_leaf_position` into the derivation guarantees that two
/// distinct senders at the same `(epoch, counter)` derive disjoint keys —
/// fixing the cross-sender nonce-reuse risk that existed in v0.4. The KDF
/// input layout is
/// `app_secret || sender_leaf_position_le_u32 || counter_le_u64`.
#[must_use]
pub fn derive_message_key(
    app_secret: &[u8; 32],
    sender_leaf_position: u32,
    counter: u64,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(MESSAGE_KEY_CONTEXT);
    hasher.update(app_secret);
    hasher.update(&sender_leaf_position.to_le_bytes());
    hasher.update(&counter.to_le_bytes());
    Zeroizing::new(*hasher.finalize().as_bytes())
}

/// Derives a per-sender message nonce from `app_secret`, the sender's tree leaf
/// position, and the sender's local message counter. Output wrapped in
/// `Zeroizing<>` for defence-in-depth — though AEAD nonces are conceptually
/// public, leaking them across sessions has been shown to enable key recovery
/// in several AEADs.
///
/// `sender_leaf_position` is bound into the nonce derivation alongside the key
/// (see `derive_message_key`) so that any future refactor that accidentally
/// re-derived one without the position would not silently re-introduce nonce
/// reuse across senders. The KDF input layout is
/// `app_secret || sender_leaf_position_le_u32 || counter_le_u64`.
#[must_use]
pub fn derive_message_nonce(
    app_secret: &[u8; 32],
    sender_leaf_position: u32,
    counter: u64,
) -> Zeroizing<[u8; 24]> {
    let mut hasher = blake3::Hasher::new_derive_key(MESSAGE_NONCE_CONTEXT);
    hasher.update(app_secret);
    hasher.update(&sender_leaf_position.to_le_bytes());
    hasher.update(&counter.to_le_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&hash.as_bytes()[..24]);
    Zeroizing::new(nonce)
}

/// Advances a seed through the chain (for path updates).
///
/// Given a leaf seed, advances it up the tree by applying H1 repeatedly.
/// Output wrapped in `Zeroizing<>`.
#[must_use]
pub fn advance_seed_chain(leaf_seed: &[u8; 32], levels: u32) -> Zeroizing<[u8; 32]> {
    let mut current = *leaf_seed;
    for _ in 0..levels {
        current = *derive_h1_seed(&current);
    }
    Zeroizing::new(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h1_deterministic() {
        let delta = [0x42u8; 32];
        let result1 = derive_h1_seed(&delta);
        let result2 = derive_h1_seed(&delta);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_h1_different_inputs() {
        let delta1 = [0x42u8; 32];
        let delta2 = [0x43u8; 32];
        assert_ne!(derive_h1_seed(&delta1), derive_h1_seed(&delta2));
    }

    #[test]
    fn test_h2_key_type_matters() {
        let seed = [0x42u8; 32];
        // Use spec-compliant key types: "x448" and "sntrup"
        let x448_seed = h2_keygen_seed(&seed, "x448");
        let sntrup_seed = h2_keygen_seed(&seed, "sntrup");
        assert_ne!(x448_seed, sntrup_seed);
    }

    #[test]
    fn test_h2_convenience_functions() {
        let seed = [0x42u8; 32];

        // Convenience functions should match h2_keygen_seed with the same key type
        assert_eq!(*h2_keygen_x448(&seed), h2_keygen_seed(&seed, "x448"));
        assert_eq!(*h2_keygen_sntrup(&seed), h2_keygen_seed(&seed, "sntrup"));
    }

    #[test]
    fn test_h2_context_strings() {
        // Verify context strings match the spec
        assert_eq!(H2_CONTEXT_X448, "cocoa-sa-keygen-x448-v1");
        assert_eq!(H2_CONTEXT_SNTRUP, "cocoa-sa-keygen-sntrup-v1");
    }

    #[test]
    fn test_h2_keygen_public_wrappers_are_the_only_entry_points() {
        // Visibility-confirming check: the only legitimate public entry
        // points are the const-context wrappers h2_keygen_x448 and
        // h2_keygen_sntrup. The dynamic-context helper h2_keygen_seed is
        // private and test-only (see its doc-comment).
        //
        // If h2_keygen_seed is ever made public, downstream callers can
        // supply user-controlled context strings — a domain-separation
        // failure mode. This test does not enforce visibility at compile
        // time (Rust has no negative-visibility test), but it pins the
        // public API in source control: any reviewer adding `pub` to
        // h2_keygen_seed must justify that change against this comment.
        let seed = [0x42u8; 32];
        let x = h2_keygen_x448(&seed);
        let s = h2_keygen_sntrup(&seed);
        assert_eq!(x.len(), 32);
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn test_h3_tree_label() {
        let pk = [0xABu8; 100];
        let label1 = h3_tree_label(2, 3, &pk);
        let label2 = h3_tree_label(2, 4, &pk);
        let label3 = h3_tree_label(3, 3, &pk);

        assert_ne!(label1, label2);
        assert_ne!(label1, label3);
    }

    #[test]
    fn test_h3_transcript_hash_chaining() {
        let prev = [0x11u8; 32];
        let round1 = [0x22u8; 32];
        let round2 = [0x33u8; 32];

        let trans1 = h3_transcript_hash(&prev, &round1);
        let trans2 = h3_transcript_hash(&trans1, &round2);

        // Order matters
        let alt = h3_transcript_hash(&prev, &round2);
        assert_ne!(trans1, alt);
        assert_ne!(trans2, alt);
    }

    #[test]
    fn test_h5_epoch_secret() {
        let init = [0x11u8; 32];
        let delta = [0x22u8; 32];
        let trans = [0x33u8; 32];

        let secret1 = h5_epoch_secret(&init, &delta, &trans);
        let secret2 = h5_epoch_secret(&init, &delta, &trans);

        assert_eq!(secret1, secret2);

        // Different inputs produce different outputs
        let secret3 = h5_epoch_secret(&init, &[0x44u8; 32], &trans);
        assert_ne!(secret1, secret3);
    }

    #[test]
    fn test_epoch_key_derivation() {
        let epoch_secret = [0x42u8; 32];

        let app = derive_app_secret(&epoch_secret);
        let conf = derive_conf_key(&epoch_secret);
        let init = derive_init_secret(&epoch_secret);

        // All different
        assert_ne!(app, conf);
        assert_ne!(app, init);
        assert_ne!(conf, init);
    }

    #[test]
    fn test_message_key_derivation() {
        let app = [0x42u8; 32];
        let leaf = 0u32;

        let key0 = derive_message_key(&app, leaf, 0);
        let key1 = derive_message_key(&app, leaf, 1);

        assert_ne!(key0, key1);
    }

    #[test]
    fn test_message_nonce_size() {
        let app = [0x42u8; 32];
        let nonce = derive_message_nonce(&app, 0, 0);
        assert_eq!(nonce.len(), 24);
    }

    /// Per-sender chains: two senders at the same epoch and counter derive disjoint
    /// keys and nonces. This is the regression guard against the v0.4 cross-sender
    /// nonce-reuse risk documented in audit-notes-impl-gaps §4.2.
    #[test]
    fn test_per_sender_chains_distinct() {
        let app = [0x42u8; 32];
        let counter = 0u64;

        let key_a = derive_message_key(&app, 0, counter);
        let key_b = derive_message_key(&app, 1, counter);
        let nonce_a = derive_message_nonce(&app, 0, counter);
        let nonce_b = derive_message_nonce(&app, 1, counter);

        assert_ne!(
            key_a, key_b,
            "two senders at same counter must derive disjoint keys"
        );
        assert_ne!(
            nonce_a, nonce_b,
            "two senders at same counter must derive disjoint nonces"
        );
    }

    #[test]
    fn test_advance_seed_chain() {
        let seed = [0x42u8; 32];

        let advanced0 = advance_seed_chain(&seed, 0);
        assert_eq!(*advanced0, seed);

        let advanced1 = advance_seed_chain(&seed, 1);
        assert_eq!(advanced1, derive_h1_seed(&seed));

        let advanced2 = advance_seed_chain(&seed, 2);
        assert_eq!(advanced2, derive_h1_seed(&derive_h1_seed(&seed)));
    }

    #[test]
    fn test_context_strings() {
        // Verify context strings are non-empty and unique
        let contexts = [
            H1_CONTEXT,
            H2_CONTEXT_X448,
            H2_CONTEXT_SNTRUP,
            H3_CONTEXT,
            H4_CONTEXT,
            H5_CONTEXT,
            ROUND_HASH_CONTEXT,
            TRANSCRIPT_HASH_CONTEXT,
        ];

        for ctx in &contexts {
            assert!(!ctx.is_empty());
        }

        // Check uniqueness
        for (i, a) in contexts.iter().enumerate() {
            for (j, b) in contexts.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_h3_round_hash_basic() {
        let root_label = [0x42u8; 32];
        let removed: [UserId; 0] = [];
        let added: [UserId; 0] = [];

        let hash = h3_round_hash(&root_label, &removed, &added);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_h3_round_hash_with_users() {
        let root_label = [0x42u8; 32];
        let user1: UserId = [0x01u8; 32];
        let user2: UserId = [0x02u8; 32];
        let user3: UserId = [0x03u8; 32];

        let removed = [user1];
        let added = [user2, user3];

        let hash = h3_round_hash(&root_label, &removed, &added);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_h3_round_hash_different_inputs() {
        let root_label = [0x42u8; 32];
        let user1: UserId = [0x01u8; 32];
        let user2: UserId = [0x02u8; 32];

        // Different removed users produce different hashes
        let hash1 = h3_round_hash(&root_label, &[user1], &[]);
        let hash2 = h3_round_hash(&root_label, &[user2], &[]);
        assert_ne!(hash1, hash2);

        // Different added users produce different hashes
        let hash3 = h3_round_hash(&root_label, &[], &[user1]);
        let hash4 = h3_round_hash(&root_label, &[], &[user2]);
        assert_ne!(hash3, hash4);

        // Removed vs added matters
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_h3_round_hash_order_matters() {
        let root_label = [0x42u8; 32];
        let user1: UserId = [0x01u8; 32];
        let user2: UserId = [0x02u8; 32];

        let hash1 = h3_round_hash(&root_label, &[user1, user2], &[]);
        let hash2 = h3_round_hash(&root_label, &[user2, user1], &[]);
        assert_ne!(hash1, hash2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h1_basic() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let sibling_label = [0x42u8; 32];

        let hash = h4_parent_hash_h1(keypair.public_key(), &sibling_label);
        assert_eq!(hash.len(), 32);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h1_deterministic() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let sibling_label = [0x42u8; 32];

        let hash1 = h4_parent_hash_h1(keypair.public_key(), &sibling_label);
        let hash2 = h4_parent_hash_h1(keypair.public_key(), &sibling_label);
        assert_eq!(hash1, hash2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h1_different_inputs() {
        let keypair1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let keypair2 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let label1 = [0x42u8; 32];
        let label2 = [0x43u8; 32];

        // Different public keys
        let hash1 = h4_parent_hash_h1(keypair1.public_key(), &label1);
        let hash2 = h4_parent_hash_h1(keypair2.public_key(), &label1);
        assert_ne!(hash1, hash2);

        // Different sibling labels
        let hash3 = h4_parent_hash_h1(keypair1.public_key(), &label1);
        let hash4 = h4_parent_hash_h1(keypair1.public_key(), &label2);
        assert_ne!(hash3, hash4);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h2_basic() {
        let keypair = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let child_h2 = [0x42u8; 32];

        let hash = h4_parent_hash_h2(keypair.public_key(), &[], &child_h2, &[]);
        assert_eq!(hash.len(), 32);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h2_with_predecessors() {
        let child = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred2 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let child_h2 = [0x42u8; 32];

        let predecessors = [pred1.public_key(), pred2.public_key()];
        let hash = h4_parent_hash_h2(child.public_key(), &predecessors, &child_h2, &[]);
        assert_eq!(hash.len(), 32);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h2_with_resolution_keys() {
        let child = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let res1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let res2 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let child_h2 = [0x42u8; 32];

        let resolution = [res1.public_key(), res2.public_key()];
        let hash = h4_parent_hash_h2(child.public_key(), &[], &child_h2, &resolution);
        assert_eq!(hash.len(), 32);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h2_full() {
        let child = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let res1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let child_h2 = [0x42u8; 32];

        let predecessors = [pred1.public_key()];
        let resolution = [res1.public_key()];
        let hash = h4_parent_hash_h2(child.public_key(), &predecessors, &child_h2, &resolution);
        assert_eq!(hash.len(), 32);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_h4_parent_hash_h2_different_inputs() {
        let child = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred1 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let pred2 = trelis_hybrid::HybridKemKeypair::generate().unwrap();
        let child_h2_a = [0x42u8; 32];
        let child_h2_b = [0x43u8; 32];

        // Different child_h2
        let hash1 = h4_parent_hash_h2(child.public_key(), &[], &child_h2_a, &[]);
        let hash2 = h4_parent_hash_h2(child.public_key(), &[], &child_h2_b, &[]);
        assert_ne!(hash1, hash2);

        // Different predecessor keys
        let hash3 = h4_parent_hash_h2(child.public_key(), &[pred1.public_key()], &child_h2_a, &[]);
        let hash4 = h4_parent_hash_h2(child.public_key(), &[pred2.public_key()], &child_h2_a, &[]);
        assert_ne!(hash3, hash4);

        // With vs without predecessors
        let hash5 = h4_parent_hash_h2(child.public_key(), &[], &child_h2_a, &[]);
        assert_ne!(hash3, hash5);
    }
}
