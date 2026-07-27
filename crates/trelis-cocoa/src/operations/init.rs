//! Group initialisation (CGKA.Init).
//!
//! Creates a new CoCoA group with the creator as the first member.
//!
//! # Welcome Message Encryption
//!
//! When adding members to a group, the creator sends encrypted welcome messages
//! containing the epoch secret and transcript hash. The encryption uses:
//!
//! 1. Hybrid KEM (X448 + sntrup761) to encapsulate to each member's identity key
//! 2. Committing AEAD (XChaCha20-Poly1305 + a 32-byte BLAKE3 key-commitment) for
//!    symmetric encryption — so the same epoch secret wrapped to N joiners cannot
//!    open under two joiners' keys (AEAD-01).
//!
//! This provides both classical and post-quantum security for the welcome data.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use trelis_error::{CryptoError, Result};
use trelis_hybrid::{
    HybridEncapsulation, HybridIdentityKeypair, HybridIdentityPublicKey, HybridKemKeypair,
    HybridPreKeyBundle, HybridSignature,
};
use trelis_primitives::aead::{self, AeadKey, Nonce};
use trelis_primitives::random::generate_bytes;

#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
use crate::limits::{check_group_growth_limits, check_size_limits};
use crate::session::CocoaSession;
use crate::{GroupId, UserId};

/// Size of welcome info plaintext: epoch_secret (32) + transcript_hash (32).
const WELCOME_INFO_PLAINTEXT_SIZE: usize = 64;

/// Context for deriving welcome encryption key from shared secret.
const WELCOME_KEY_CONTEXT: &str = "cocoa-sa-welcome-key-v1";

/// Domain-separation context for the Welcome committer signature (GAP-01,
/// Insider-A).
///
/// This is the SINGLE source of the welcome-sign context string. It is a NEW,
/// DISTINCT context from `cocoa-sa-commit-sign-v1` and is used with
/// `sign_with_context` / `verify_with_context` (bytes, not `derive_key`),
/// mirroring `commit_sign.rs`'s `COMMIT_SIGN_CONTEXT`. Using a distinct
/// registered context (rather than plain `sign()`) is what the commit path
/// already does, so GAP-01 does not worsen the deferred WR-03. Registered
/// additively in `vectors/context-strings.json`; the §14 registry entry lands
/// with the spec edit in 52-06.
pub(crate) const WELCOME_SIGN_CONTEXT: &[u8] = b"cocoa-sa-welcome-sign-v1";

/// Builds the canonical byte body the committer signs for a `Welcome` (GAP-01).
///
/// Layout (binds every joiner-visible field so a malicious server cannot forge
/// or swap any of them):
///
/// ```text
/// group_id (32) || epoch (u64 LE, 8) || leaf_position (u32 LE, 4)
///   || tree_depth (u32 LE, 4) || member_count (u32 LE, 4)
///   || len(encapsulation) (u32 LE, 4) || encapsulation
///   || len(encrypted_info) (u32 LE, 4) || encrypted_info
/// ```
///
/// WR-05: the two variable-length fields are LENGTH-PREFIXED (u32 LE) so the
/// signature commits their boundary. Without framing, any re-split of the same
/// concatenated `encapsulation || encrypted_info` bytes yields an identical
/// signed body and the same signature verifies — a canonicalisation smell that
/// today is caught only by the downstream fixed-size
/// `HybridEncapsulation::from_bytes` parse. The signed body is INTERNAL and
/// re-derived identically on both the sign (`create_group` /
/// `create_welcome_message`) and verify (`process_welcome`) sides, so this
/// framing does NOT change the on-wire `Welcome` format.
///
/// `encapsulation` (the KEM entry) and `encrypted_info` (the encrypted epoch /
/// tree state, carrying init_secret/transcript/delta_root/tree_info) together
/// bind the "entry + tree" without re-deriving it. Order is `encapsulation`
/// then `encrypted_info`.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn welcome_sign_body(
    group_id: &GroupId,
    epoch: u64,
    leaf_position: u32,
    tree_depth: u32,
    member_count: u32,
    encapsulation: &[u8],
    encrypted_info: &[u8],
) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(32 + 8 + 4 + 4 + 4 + 4 + encapsulation.len() + 4 + encrypted_info.len());
    body.extend_from_slice(group_id);
    body.extend_from_slice(&epoch.to_le_bytes());
    body.extend_from_slice(&leaf_position.to_le_bytes());
    body.extend_from_slice(&tree_depth.to_le_bytes());
    body.extend_from_slice(&member_count.to_le_bytes());
    // WR-05: u32 LE length prefix before each variable field pins the boundary.
    // LOW-02 (defense-in-depth): saturating usize->u32 so a pathological
    // >4 GiB field would clamp to u32::MAX rather than silently TRUNCATE (wrap)
    // and forge a shorter boundary in the signed body. Cannot trigger in
    // practice — group size is gated by MAX_GROUP_SIZE (1<<20) and Phase-87
    // `check_size_limits`, and the KEM/AEAD fields are fixed-size — so the byte
    // output is unchanged on every reachable input. `welcome_sign_body` returns
    // `Vec<u8>` (no `Result`), so a saturating clamp is the clean fit; no new
    // `CryptoError` variant.
    body.extend_from_slice(
        &u32::try_from(encapsulation.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(encapsulation);
    body.extend_from_slice(
        &u32::try_from(encrypted_info.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(encrypted_info);
    body
}

/// Welcome message sent to new members when joining a group.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Welcome {
    /// Group identifier.
    pub group_id: GroupId,
    /// Epoch number at time of welcome.
    pub epoch: u64,
    /// Recipient's assigned leaf position.
    pub leaf_position: u32,
    /// Tree depth.
    pub tree_depth: u32,
    /// Current member count.
    pub member_count: u32,
    /// Encrypted group info (epoch secret, tree state, transcript).
    /// Encrypted to the recipient's KEM key.
    pub encrypted_info: Vec<u8>,
    /// Encapsulation for decrypting the info.
    pub encapsulation: Vec<u8>,
    /// Committer's hybrid signature over the canonical welcome body (GAP-01,
    /// Insider-A).
    ///
    /// The constructing member (`create_group`'s creator or the adder in
    /// `add.rs::create_welcome_message`) signs `welcome_sign_body` with
    /// `WELCOME_SIGN_CONTEXT`; `process_welcome` verifies it against the
    /// caller-supplied committer identity BEFORE `join_group`. The size is
    /// single-sourced to `trelis_hybrid::signature::SIGNATURE_SIZE` (3,366 B
    /// post-BoP-2) — never a bare literal.
    pub signature: HybridSignature,
}

/// Creates a new CoCoA group.
///
/// # Arguments
///
/// * `creator_identity` - Creator's identity keypair (for signing)
/// * `creator_kem` - Creator's KEM keypair (for encryption)
/// * `creator_user_id` - Creator's user identifier
/// * `member_bundles` - Pre-key bundles of initial members (excluding creator)
///
/// # Returns
///
/// A tuple of (creator's session, welcome messages for other members).
///
/// # Security
///
/// Each welcome message is encrypted to the recipient's identity KEM key using
/// hybrid encryption (X448 + sntrup761). This ensures only the intended recipient
/// can decrypt the epoch secret.
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn create_group(
    creator_identity: &HybridIdentityKeypair,
    creator_kem: HybridKemKeypair,
    creator_user_id: UserId,
    member_bundles: &[&HybridPreKeyBundle],
) -> Result<(CocoaSession, Vec<Welcome>)> {
    // ── DoS size gate (DOS-03, local-growth defence-in-depth) — reject a group
    // whose size / resulting depth would exceed MAX_GROUP_SIZE / MAX_TREE_DEPTH
    // BEFORE any key material is generated. `saturating_add` keeps a pathological
    // bundle count from panicking under overflow-checks (Pitfall 6);
    // `check_group_growth_limits` maps the excess to `TreeDepthExceeded`. ──
    let total_members = (member_bundles.len() as u32).saturating_add(1);
    check_group_growth_limits(total_members)?;

    // Generate group ID
    let group_id: GroupId = generate_bytes()?;

    // Generate initial epoch secret
    let epoch_secret: [u8; 32] = generate_bytes()?;

    // Initial transcript hash (empty for new group)
    let transcript_hash = [0u8; 32];

    // Create creator's session
    let session = CocoaSession::create_group(
        group_id,
        creator_user_id,
        creator_kem,
        total_members,
        &epoch_secret,
    )?;

    // Generate welcome messages for other members
    let mut welcomes = Vec::with_capacity(member_bundles.len());

    for (i, bundle) in member_bundles.iter().enumerate() {
        let leaf_position = (i + 1) as u32; // Creator is at position 0

        // Encapsulate to the member's identity KEM key
        let (shared_secret, encap) = bundle.identity_kem().encapsulate()?;

        // Derive AEAD key from shared secret
        let aead_key = derive_welcome_key(shared_secret.as_bytes());

        // Build welcome info plaintext: epoch_secret || transcript_hash
        let mut plaintext = [0u8; WELCOME_INFO_PLAINTEXT_SIZE];
        plaintext[..32].copy_from_slice(&epoch_secret);
        plaintext[32..].copy_from_slice(&transcript_hash);

        // Generate random nonce for AEAD
        let nonce_bytes: [u8; 24] = generate_bytes()?;
        let nonce = Nonce::from_bytes(nonce_bytes);

        // Encrypt with group_id as AAD to bind welcome to this group. Committing
        // AEAD (AEAD-01): the same epoch_secret wrapped to N joiners carries a
        // 32-byte key-commitment, so one welcome cannot open under two joiner keys.
        let ciphertext = aead::encrypt_committing(&aead_key, &nonce, &plaintext, &group_id)?;

        // encrypted_info = nonce (24) || ciphertext (plaintext + 16 tag + 32 commitment)
        let mut encrypted_info = Vec::with_capacity(24 + ciphertext.len());
        encrypted_info.extend_from_slice(&nonce_bytes);
        encrypted_info.extend_from_slice(&ciphertext);

        let epoch = 0u64;
        let tree_depth = session.tree().tree_depth();
        let member_count = total_members;
        let encapsulation = encap.to_bytes().to_vec();

        // GAP-01 (Insider-A): the creator signs the canonical welcome body over
        // every joiner-visible field. `process_welcome` verifies this against the
        // creator's identity BEFORE `join_group`, so a malicious server cannot
        // forge, substitute, or tamper a welcome without detection.
        let sign_body = welcome_sign_body(
            &group_id,
            epoch,
            leaf_position,
            tree_depth,
            member_count,
            &encapsulation,
            &encrypted_info,
        );
        let signature = creator_identity.sign_with_context(&sign_body, WELCOME_SIGN_CONTEXT)?;

        let welcome = Welcome {
            group_id,
            epoch,
            leaf_position,
            tree_depth,
            member_count,
            encrypted_info,
            encapsulation,
            signature,
        };

        welcomes.push(welcome);
    }

    Ok((session, welcomes))
}

/// Derives the AEAD key for welcome message encryption.
fn derive_welcome_key(shared_secret: &[u8; 32]) -> AeadKey {
    let key_bytes = blake3::derive_key(WELCOME_KEY_CONTEXT, shared_secret);
    AeadKey::from_bytes(key_bytes)
}

/// Encrypts welcome information to a recipient's KEM key.
///
/// This is used when adding members to encrypt the group state.
///
/// # Arguments
///
/// * `info` - The information to encrypt (must implement `to_bytes()`)
/// * `recipient_key` - The recipient's KEM public key
///
/// # Returns
///
/// A tuple of (encrypted_info, encapsulation bytes).
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn encrypt_welcome_info<T: WelcomeInfoSerialise>(
    info: &T,
    recipient_key: &trelis_hybrid::HybridKemPublicKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Encapsulate to get shared secret
    let (shared_secret, encap) = recipient_key.encapsulate()?;

    // Derive AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Generate random nonce
    let nonce_bytes: [u8; 24] = generate_bytes()?;
    let nonce = Nonce::from_bytes(nonce_bytes);

    // Serialise and encrypt the info with the committing AEAD (AEAD-01).
    let plaintext = info.to_bytes();
    let ciphertext = aead::encrypt_committing(&aead_key, &nonce, &plaintext, b"cocoa-welcome-add")?;

    // encrypted_info = nonce (24) || ciphertext (plaintext + 16 tag + 32 commitment)
    let mut encrypted_info = Vec::with_capacity(24 + ciphertext.len());
    encrypted_info.extend_from_slice(&nonce_bytes);
    encrypted_info.extend_from_slice(&ciphertext);

    Ok((encrypted_info, encap.to_bytes().to_vec()))
}

/// Trait for types that can be serialised for welcome encryption.
#[cfg(feature = "alloc")]
pub trait WelcomeInfoSerialise {
    /// Serialises the info to bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Decrypts welcome information using the recipient's KEM keypair.
///
/// This is the inverse of [`encrypt_welcome_info`]. It decapsulates the shared
/// secret from the encapsulation bytes and decrypts the encrypted info.
///
/// # Arguments
///
/// * `encrypted_info` - Encrypted bytes in format: nonce (24 bytes) || ciphertext
/// * `encapsulation_bytes` - KEM encapsulation bytes from the sender
/// * `our_kem` - The recipient's KEM keypair for decapsulation
///
/// # Returns
///
/// The decrypted plaintext bytes.
///
/// # Internal primitive
///
/// Low-level decap primitive. Application code MUST reach it through the gated
/// entry point `process_welcome` (which verifies the committer signature BEFORE
/// this decap runs), never by calling this directly — there is no live bypass
/// caller. It stays `pub` for internal cross-module reuse and is not part of the
/// intended external surface (LOW-01, doc-only: symbol unchanged).
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
#[must_use = "the decrypted plaintext must be checked or used"]
pub fn decrypt_welcome_info(
    encrypted_info: &[u8],
    encapsulation_bytes: &[u8],
    our_kem: &HybridKemKeypair,
) -> Result<Vec<u8>> {
    if encrypted_info.len() < 24 {
        return Err(CryptoError::MalformedMessage);
    }

    // Parse the encapsulation
    let encapsulation = HybridEncapsulation::from_bytes(encapsulation_bytes)?;

    // Decapsulate to recover the shared secret
    let shared_secret = our_kem.decapsulate(&encapsulation)?;

    // Derive the AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Parse encrypted_info: nonce (24 bytes) || ciphertext
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&encrypted_info[..24]);
    let nonce = Nonce::from_bytes(nonce_bytes);
    let ciphertext = &encrypted_info[24..];

    // Decrypt using the same AAD as encrypt_welcome_info. The committing AEAD
    // verifies the 32-byte key-commitment before the Poly1305 open (AEAD-01).
    let plaintext = aead::decrypt_committing(&aead_key, &nonce, ciphertext, b"cocoa-welcome-add")?;

    Ok(plaintext)
}

/// Processes a welcome message to join a group.
///
/// # Arguments
///
/// * `our_user_id` - Our user identifier
/// * `our_kem` - Our KEM keypair (matching the one in our pre-key bundle)
/// * `welcome` - The welcome message
/// * `committer_identity` - The expected group-creator/adder's public identity
///   key, supplied out-of-band by the caller (same trust model as
///   `process_add`'s `adder_identity`). The committer's signature over the
///   welcome body is verified against this key BEFORE any group state is
///   adopted.
///
/// # Returns
///
/// A session for participating in the group.
///
/// # Errors
///
/// Returns an error if:
/// - The committer's signature does not verify against `committer_identity`
///   (`SignatureVerificationFailed`) — an unsigned/forged/tampered welcome is
///   rejected before `join_group` (GAP-01, Insider-A)
/// - Any carried `tree_info` fails parent-hash verification
///   (`ParentHashMismatch`) — a tampered joiner tree is rejected before it is
///   trusted (GAP-02 SC2 joiner clause, Insider-B)
/// - The encapsulation cannot be parsed
/// - Decapsulation fails (wrong key or corrupted data)
/// - Decryption fails (tampered ciphertext or wrong AAD)
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub fn process_welcome(
    our_user_id: UserId,
    our_kem: HybridKemKeypair,
    welcome: &Welcome,
    committer_identity: &HybridIdentityPublicKey,
) -> Result<CocoaSession> {
    // ── DoS size gate (DOS-01) — the FIRST statement, before verify_with_context
    // / decapsulate / AEAD (§13). The PROVEN welcome guarantee is DOS-01: bound
    // the welcome message size (encrypted_info + encapsulation) and reject an
    // oversized welcome with MessageTooLarge before any crypto. The resulting-
    // tree geometry (tree_depth, member_count) is passed as best-effort DOS-03
    // defence-in-depth — the attacker-controlled DOS-03 vectors are ordering-
    // proven on the add/update/remove ingest paths (Tasks 1-2), not here. ──
    check_size_limits(
        welcome
            .encrypted_info
            .len()
            .saturating_add(welcome.encapsulation.len()),
        0,
        welcome.tree_depth,
        welcome.member_count,
        0,
    )?;

    // GAP-01 (Insider-A): verify the committer's signature over the canonical
    // welcome body BEFORE adopting ANY group state — before the KEM/AEAD work and
    // before `join_group`. This rejects an unsigned, forged, wrong-key, or
    // tampered welcome as early as possible. The body is reconstructed purely from
    // the (public) welcome fields, so a flip of any bound field diverges it and
    // the signature no longer verifies.
    let sign_body = welcome_sign_body(
        &welcome.group_id,
        welcome.epoch,
        welcome.leaf_position,
        welcome.tree_depth,
        welcome.member_count,
        &welcome.encapsulation,
        &welcome.encrypted_info,
    );
    committer_identity.verify_with_context(&sign_body, WELCOME_SIGN_CONTEXT, &welcome.signature)?;

    // Parse the encapsulation from bytes
    let encapsulation = HybridEncapsulation::from_bytes(&welcome.encapsulation)?;

    // Decapsulate to recover the shared secret
    let shared_secret = our_kem.decapsulate(&encapsulation)?;

    // Derive the same AEAD key
    let aead_key = derive_welcome_key(shared_secret.as_bytes());

    // Parse encrypted_info: nonce (24) || ciphertext
    if welcome.encrypted_info.len() < 24 {
        return Err(CryptoError::MalformedMessage);
    }
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&welcome.encrypted_info[..24]);
    let nonce = Nonce::from_bytes(nonce_bytes);
    let ciphertext = &welcome.encrypted_info[24..];

    // Decrypt with group_id as AAD. The committing AEAD verifies the 32-byte
    // key-commitment before the Poly1305 open and strips it, so the returned
    // plaintext length is unchanged and the length gate below still holds (AEAD-01).
    let plaintext = aead::decrypt_committing(&aead_key, &nonce, ciphertext, &welcome.group_id)?;

    // Validate plaintext size. The `create_group` welcome is exactly
    // WELCOME_INFO_PLAINTEXT_SIZE (epoch_secret || transcript_hash) and carries
    // NO tree_info. A welcome that additionally carries the add-path
    // `WelcomeInfo.tree_info` appends it after the base 64 bytes; that tree_info
    // is parent-hash-verified below before the reconstructed tree is trusted.
    // (>= keeps the create_group flow intact — its 64-byte plaintext leaves an
    // empty tree_info tail.)
    if plaintext.len() < WELCOME_INFO_PLAINTEXT_SIZE {
        return Err(CryptoError::MalformedMessage);
    }

    // Extract epoch_secret and transcript_hash
    let mut epoch_secret = [0u8; 32];
    let mut transcript_hash = [0u8; 32];
    epoch_secret.copy_from_slice(&plaintext[..32]);
    transcript_hash.copy_from_slice(&plaintext[32..WELCOME_INFO_PLAINTEXT_SIZE]);

    // GAP-02 (SC2 joiner clause / Insider-B): verify the parent-hash chain of any
    // `tree_info` the welcome carries BEFORE the reconstructed tree is trusted.
    //
    // CR-01: this uses the joiner-specific `verify_welcome_tree_info`, NOT the
    // ingest-path `verify_parent_hashes` against an empty `PartialTreeView`. The
    // joiner holds only the adder's PATH nodes and no co-path, so recomputing a
    // non-leaf `h1` against a guaranteed-empty view provided zero real
    // protection (every expected label collapsed to `[0;32]`) AND false-rejected
    // honest welcomes whose non-leaf `h1` was built against populated co-path
    // siblings. The joiner verifier instead enforces the leaf invariant (keyed
    // off TRUE depth, so a dropped blank leaf does not desync it — IN-01) and
    // recomputes a non-leaf `h1` only where the sibling is actually present in
    // the reconstructed tree_info, SKIPPING (not rejecting) where it is absent.
    //
    // The `create_group` welcome carries NO tree_info (its plaintext is exactly
    // WELCOME_INFO_PLAINTEXT_SIZE), so this is a documented no-op for it. Full
    // join-path tree reconstruction + mandatory parent-hash enforcement remains
    // the tracked GAP-02 residual (out of scope here).
    let tree_info = &plaintext[WELCOME_INFO_PLAINTEXT_SIZE..];
    if !tree_info.is_empty() {
        let nodes = parse_welcome_tree_info(tree_info)?;
        crate::operations::path_update::verify_welcome_tree_info(&nodes, welcome.tree_depth)?;
    }

    let mut session = CocoaSession::join_group(
        welcome.group_id,
        our_user_id,
        our_kem,
        welcome.leaf_position,
        welcome.tree_depth,
        welcome.member_count,
        &epoch_secret,
        transcript_hash,
    );

    // Advance to the correct epoch if joining mid-session
    for _ in 0..welcome.epoch {
        session.advance_epoch(&[0u8; 32], transcript_hash);
    }

    Ok(session)
}

/// Parses the add-path serialised `tree_info` (see
/// [`super::add::serialise_tree_info`]) into `NodeUpdate`-shaped entries so the
/// joiner can run `verify_parent_hashes` (GAP-02 SC2 joiner clause) on them
/// before trusting the reconstructed tree.
///
/// # Format (per node, leaf → root)
///
/// ```text
/// depth (u32 LE, 4) || position (u32 LE, 4) || state_flag (1)
///   [ if populated (state_flag == 1):
///       pk_len (u16 LE, 2) || public_key (pk_len) || h1 (32) || h2 (32) ]
/// ```
///
/// Blank path nodes (`state_flag == 0`) carry no public key or parent hash, so
/// there is nothing to recompute for them — they are skipped. Each populated
/// node preserves its TRUE `(depth, position)` from the wire, so the consumer
/// ([`super::path_update::verify_welcome_tree_info`]) identifies the leaf by
/// `depth == tree_depth` rather than by a positional index — dropping blank
/// nodes here therefore no longer desyncs leaf detection (IN-01). Populated
/// nodes are returned with empty `encrypted_seeds` (the wire tree_info carries
/// no resolution seeds).
#[cfg(all(feature = "alloc", any(feature = "std", feature = "wasm")))]
pub(crate) fn parse_welcome_tree_info(
    tree_info: &[u8],
) -> Result<Vec<crate::operations::path_update::NodeUpdate>> {
    use crate::operations::path_update::NodeUpdate;
    use crate::tree::NodeIndex;
    use trelis_hybrid::HybridKemPublicKey;

    let mut nodes = Vec::new();
    let mut off = 0usize;

    while off < tree_info.len() {
        // Node header: depth (4) + position (4) + state flag (1).
        let hdr_end = off.checked_add(9).ok_or(CryptoError::MalformedMessage)?;
        if tree_info.len() < hdr_end {
            return Err(CryptoError::MalformedMessage);
        }
        let depth = u32::from_le_bytes(
            tree_info[off..off + 4]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let position = u32::from_le_bytes(
            tree_info[off + 4..off + 8]
                .try_into()
                .map_err(|_| CryptoError::MalformedMessage)?,
        );
        let state_flag = tree_info[off + 8];
        off = hdr_end;

        if state_flag == 1 {
            // pk_len (2) || public_key (pk_len) || h1 (32) || h2 (32)
            let plen_end = off.checked_add(2).ok_or(CryptoError::MalformedMessage)?;
            if tree_info.len() < plen_end {
                return Err(CryptoError::MalformedMessage);
            }
            let pk_len = u16::from_le_bytes(
                tree_info[off..plen_end]
                    .try_into()
                    .map_err(|_| CryptoError::MalformedMessage)?,
            ) as usize;
            off = plen_end;

            let pk_end = off
                .checked_add(pk_len)
                .ok_or(CryptoError::MalformedMessage)?;
            let hashes_end = pk_end
                .checked_add(64)
                .ok_or(CryptoError::MalformedMessage)?;
            if tree_info.len() < hashes_end {
                return Err(CryptoError::MalformedMessage);
            }

            let public_key = HybridKemPublicKey::from_bytes(&tree_info[off..pk_end])?;
            let mut h1 = [0u8; 32];
            let mut h2 = [0u8; 32];
            h1.copy_from_slice(&tree_info[pk_end..pk_end + 32]);
            h2.copy_from_slice(&tree_info[pk_end + 32..hashes_end]);
            off = hashes_end;

            nodes.push(NodeUpdate {
                node_index: NodeIndex::new(depth, position),
                public_key,
                parent_hash: (h1, h2),
                encrypted_seeds: Vec::new(),
            });
        }
        // Blank nodes (state_flag == 0) carry no pk/parent-hash — nothing to verify.
    }

    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trelis_hybrid::HybridOneTimeKeyPair;

    /// Helper to create a test pre-key bundle.
    fn create_test_bundle(identity: &HybridIdentityKeypair) -> HybridPreKeyBundle {
        let otk = HybridOneTimeKeyPair::generate().unwrap();
        HybridPreKeyBundle::new(&identity.public_key(), otk.public_key())
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_single_member() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let (session, welcomes) = create_group(&identity, kem, user_id, &[]).unwrap();

        assert_eq!(session.our_leaf_position(), 0);
        assert_eq!(session.member_count(), 1);
        assert!(welcomes.is_empty());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_multiple_members() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        // Create member bundles
        let member1_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle1 = create_test_bundle(&member1_identity);

        let member2_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle2 = create_test_bundle(&member2_identity);

        let bundles: Vec<&HybridPreKeyBundle> = vec![&bundle1, &bundle2];

        let (session, welcomes) = create_group(&identity, kem, user_id, &bundles).unwrap();

        assert_eq!(session.member_count(), 3);
        assert_eq!(welcomes.len(), 2);
        assert_eq!(welcomes[0].leaf_position, 1);
        assert_eq!(welcomes[1].leaf_position, 2);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_has_correct_group_id() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        let (session, welcomes) = create_group(&identity, kem, user_id, &[&bundle]).unwrap();

        assert_eq!(welcomes[0].group_id, *session.group_id());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_encryption_round_trip() {
        // Creator sets up the group
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        // Member's identity key - the bundle is created with this, and the member
        // keeps the keypair to decrypt the welcome
        let member_identity = HybridIdentityKeypair::generate().unwrap();
        // HybridKemKeypair is no longer Clone; reconstruct an owned copy
        // from the identity's KEM keypair bytes for process_welcome (which consumes it).
        let member_kem =
            HybridKemKeypair::from_bytes(&member_identity.kem().to_bytes()[..]).unwrap();
        let member_user_id = [0x02u8; 32];
        let bundle = create_test_bundle(&member_identity);

        // Create group with member
        let (creator_session, welcomes) =
            create_group(&creator_identity, creator_kem, creator_user_id, &[&bundle]).unwrap();

        assert_eq!(welcomes.len(), 1);
        let welcome = &welcomes[0];

        // Verify welcome has encrypted data
        assert!(!welcome.encrypted_info.is_empty());
        assert!(!welcome.encapsulation.is_empty());

        // Member processes the welcome using their identity KEM keypair, verifying
        // the creator's signature against the creator's public identity.
        let member_session = process_welcome(
            member_user_id,
            member_kem,
            welcome,
            creator_identity.public_key(),
        )
        .unwrap();

        // Verify both sessions are for the same group
        assert_eq!(member_session.group_id(), creator_session.group_id());

        // Verify member is at the correct position
        assert_eq!(member_session.our_leaf_position(), 1);
        assert_eq!(creator_session.our_leaf_position(), 0);

        // Both should be at epoch 0
        assert_eq!(member_session.epoch_number(), 0);
        assert_eq!(creator_session.epoch_number(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_decryption_fails_with_wrong_key() {
        // Creator sets up the group
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        // Create group
        let (_, welcomes) =
            create_group(&creator_identity, creator_kem, creator_user_id, &[&bundle]).unwrap();

        let welcome = &welcomes[0];

        // Try to process with a different KEM keypair (attacker scenario)
        let wrong_identity = HybridIdentityKeypair::generate().unwrap();
        // HybridKemKeypair is no longer Clone; reconstruct an owned copy.
        let wrong_kem = HybridKemKeypair::from_bytes(&wrong_identity.kem().to_bytes()[..]).unwrap();

        // The creator's signature verifies (correct committer identity), so this
        // reaches — and fails at — decapsulation because the wrong KEM key can't
        // decrypt.
        let result = process_welcome(
            [0x03u8; 32],
            wrong_kem,
            welcome,
            creator_identity.public_key(),
        );
        assert!(result.is_err());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_encryption_unique_per_member() {
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        let member1_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle1 = create_test_bundle(&member1_identity);

        let member2_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle2 = create_test_bundle(&member2_identity);

        let (_, welcomes) = create_group(
            &creator_identity,
            creator_kem,
            creator_user_id,
            &[&bundle1, &bundle2],
        )
        .unwrap();

        assert_eq!(welcomes.len(), 2);

        // Each welcome should have different encrypted data (different nonces, different encapsulations)
        assert_ne!(welcomes[0].encrypted_info, welcomes[1].encrypted_info);
        assert_ne!(welcomes[0].encapsulation, welcomes[1].encapsulation);

        // But same group parameters
        assert_eq!(welcomes[0].group_id, welcomes[1].group_id);
        assert_eq!(welcomes[0].epoch, welcomes[1].epoch);
    }

    // ─── WR-05: welcome signed-body length framing ──────────────────────────

    /// WR-05: the signed body length-frames its two variable-length fields, so a
    /// re-split of the same concatenated `encapsulation || encrypted_info` bytes
    /// no longer yields an identical signed body (the boundary is committed by
    /// the signature). Without framing `body_a == body_b` here — the exact
    /// canonicalisation smell the fix removes.
    #[test]
    fn test_welcome_sign_body_frames_variable_fields() {
        let group_id = [0x11u8; 32];

        // Same concatenated tail ("AAAABBBBBB"), two different field boundaries.
        let body_a = welcome_sign_body(&group_id, 1, 2, 3, 4, b"AAAA", b"BBBBBB");
        let body_b = welcome_sign_body(&group_id, 1, 2, 3, 4, b"AAAAB", b"BBBBB");
        assert_ne!(
            body_a, body_b,
            "length framing must distinguish re-split field boundaries"
        );

        // Determinism: identical inputs still produce identical bodies (sign and
        // verify sides must agree).
        let body_c = welcome_sign_body(&group_id, 1, 2, 3, 4, b"AAAA", b"BBBBBB");
        assert_eq!(body_a, body_c);
    }

    // ─── GAP-01: Welcome committer signature (Insider-A) ─────────────────────

    /// Sets up a creator + a single-member welcome, returning the creator
    /// identity, the (owned) member KEM keypair, and a clone of the welcome.
    fn signed_welcome_fixture() -> (HybridIdentityKeypair, UserId, HybridKemKeypair, Welcome) {
        let creator_identity = HybridIdentityKeypair::generate().unwrap();
        let creator_kem = HybridKemKeypair::generate().unwrap();
        let creator_user_id = [0x01u8; 32];

        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let member_kem =
            HybridKemKeypair::from_bytes(&member_identity.kem().to_bytes()[..]).unwrap();
        let member_user_id = [0x02u8; 32];
        let bundle = create_test_bundle(&member_identity);

        let (_, welcomes) =
            create_group(&creator_identity, creator_kem, creator_user_id, &[&bundle]).unwrap();
        (
            creator_identity,
            member_user_id,
            member_kem,
            welcomes[0].clone(),
        )
    }

    /// Positive control: an honestly signed welcome verifies against the
    /// creator's identity and joins.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_signed_round_trip() {
        let (creator_identity, member_user_id, member_kem, welcome) = signed_welcome_fixture();
        let session = process_welcome(
            member_user_id,
            member_kem,
            &welcome,
            creator_identity.public_key(),
        )
        .unwrap();
        assert_eq!(session.our_leaf_position(), 1);
    }

    /// A welcome whose signature is zeroed (stripped/unsigned) is rejected with
    /// `SignatureVerificationFailed` — `join_group` is never reached.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_unsigned_rejected() {
        let (creator_identity, member_user_id, member_kem, mut welcome) = signed_welcome_fixture();
        welcome.signature =
            HybridSignature::from_bytes(&[0u8; trelis_hybrid::signature::SIGNATURE_SIZE]).unwrap();
        let result = process_welcome(
            member_user_id,
            member_kem,
            &welcome,
            creator_identity.public_key(),
        );
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// A welcome signed by the creator but verified against a DIFFERENT
    /// (forged) committer identity is rejected.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_forged_signer_rejected() {
        let (_creator_identity, member_user_id, member_kem, welcome) = signed_welcome_fixture();
        let forger = HybridIdentityKeypair::generate().unwrap();
        let result = process_welcome(member_user_id, member_kem, &welcome, forger.public_key());
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// Flipping any bound field (here `leaf_position`) after signing diverges the
    /// reconstructed body, so the committer's signature no longer verifies.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_tampered_field_rejected() {
        let (creator_identity, member_user_id, member_kem, mut welcome) = signed_welcome_fixture();
        welcome.leaf_position ^= 0xFF; // tamper a signed field
        let result = process_welcome(
            member_user_id,
            member_kem,
            &welcome,
            creator_identity.public_key(),
        );
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));

        // A swapped encrypted_info byte is likewise rejected.
        let (creator2, member2, kem2, mut w2) = signed_welcome_fixture();
        w2.encrypted_info[0] ^= 0xFF;
        assert!(matches!(
            process_welcome(member2, kem2, &w2, creator2.public_key()),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    // ─── GAP-02 (SC2 joiner clause): tree_info parent-hash verification ──────

    /// The joiner's `tree_info` path nodes have their parent-hash chain verified
    /// via `verify_parent_hashes` before the reconstructed tree is trusted. Built
    /// as a self-contained 2-node (leaf → root) `serialise_tree_info` blob with
    /// honest parent hashes (blank siblings → `[0;32]` labels), this proves the
    /// parse + verify path accepts an honest tree and rejects a tampered non-leaf
    /// `h1` (`ParentHashMismatch`) — mirrors 52-02's direct-verifier test, since a
    /// full multi-party tree-sync join is infeasible in a unit test.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_tree_info_parent_hash_verified() {
        use crate::key_schedule::{h4_parent_hash_h1, h4_parent_hash_h2};
        use crate::operations::path_update::verify_parent_hashes;
        use crate::tree::PartialTreeView;

        let leaf_kp = HybridKemKeypair::generate().unwrap();
        let root_kp = HybridKemKeypair::generate().unwrap();
        let leaf_pk = leaf_kp.public_key().clone();
        let root_pk = root_kp.public_key().clone();

        // Honest root parent hashes: blank sibling ⇒ [0;32] label; leaf child h2
        // is 0; root-level resolution is empty.
        let preds: Vec<&trelis_hybrid::HybridKemPublicKey> = vec![&leaf_pk];
        let empty_res: Vec<&trelis_hybrid::HybridKemPublicKey> = Vec::new();
        let root_h1 = h4_parent_hash_h1(&root_pk, &[0u8; 32]);
        let root_h2 = h4_parent_hash_h2(&root_pk, &preds, &[0u8; 32], &empty_res);

        // Serialise a 2-node tree_info blob in add.rs::serialise_tree_info format.
        fn push_node(
            ti: &mut Vec<u8>,
            depth: u32,
            pos: u32,
            pk: &[u8],
            h1: &[u8; 32],
            h2: &[u8; 32],
        ) {
            ti.extend_from_slice(&depth.to_le_bytes());
            ti.extend_from_slice(&pos.to_le_bytes());
            ti.push(1u8); // populated
            ti.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            ti.extend_from_slice(pk);
            ti.extend_from_slice(h1);
            ti.extend_from_slice(h2);
        }
        let mut ti = Vec::new();
        push_node(&mut ti, 1, 0, &leaf_pk.to_bytes(), &[0u8; 32], &[0u8; 32]);
        push_node(&mut ti, 0, 0, &root_pk.to_bytes(), &root_h1, &root_h2);

        // Parse round-trips to 2 populated nodes.
        let nodes = parse_welcome_tree_info(&ti).unwrap();
        assert_eq!(nodes.len(), 2);

        // Honest verifies against the joiner's (empty) reconstructed view.
        let tree = PartialTreeView::new(0, 1);
        verify_parent_hashes(&tree, &nodes).unwrap();

        // Tampering the non-leaf (root) h1 is rejected.
        let mut tampered = nodes.clone();
        tampered[1].parent_hash.0[0] ^= 0xFF;
        assert!(matches!(
            verify_parent_hashes(&tree, &tampered),
            Err(CryptoError::ParentHashMismatch)
        ));
    }

    // ─── CR-01 / IN-01: honest joiner tree_info verification ─────────────────

    /// Serialises one populated node into `add.rs::serialise_tree_info` format.
    fn ti_push_node(
        ti: &mut Vec<u8>,
        depth: u32,
        pos: u32,
        pk: &[u8],
        h1: &[u8; 32],
        h2: &[u8; 32],
    ) {
        ti.extend_from_slice(&depth.to_le_bytes());
        ti.extend_from_slice(&pos.to_le_bytes());
        ti.push(1u8); // populated
        ti.extend_from_slice(&(pk.len() as u16).to_le_bytes());
        ti.extend_from_slice(pk);
        ti.extend_from_slice(h1);
        ti.extend_from_slice(h2);
    }

    /// Serialises one blank node (state flag 0, no pk / parent hash).
    fn ti_push_blank(ti: &mut Vec<u8>, depth: u32, pos: u32) {
        ti.extend_from_slice(&depth.to_le_bytes());
        ti.extend_from_slice(&pos.to_le_bytes());
        ti.push(0u8); // blank
    }

    /// CR-01 regression: an honest Welcome whose non-leaf `h1` was built against
    /// a POPULATED co-path sibling (a non-zero sibling label) must NOT be
    /// false-rejected by the joiner. The joiner holds only the adder's path (no
    /// co-path), so `verify_welcome_tree_info` SKIPS the non-leaf `h1` it cannot
    /// reconstruct instead of comparing it to a bogus zero-sibling label. The
    /// superseded empty-view `verify_parent_hashes` DID reject this honest input
    /// — asserted here as the regression witness.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_tree_info_honest_nonzero_h1_not_false_rejected() {
        use crate::key_schedule::{h3_tree_label, h4_parent_hash_h1};
        use crate::operations::path_update::{verify_parent_hashes, verify_welcome_tree_info};
        use crate::tree::PartialTreeView;

        let leaf_kp = HybridKemKeypair::generate().unwrap();
        let mid_kp = HybridKemKeypair::generate().unwrap();
        let root_kp = HybridKemKeypair::generate().unwrap();
        let sibling_kp = HybridKemKeypair::generate().unwrap();

        // (1,0)'s h1 binds to a POPULATED co-path sibling (1,1) — a non-zero
        // label — exactly as the honest builder computes it in a real group.
        let sib_label = h3_tree_label(1, 1, &sibling_kp.public_key().to_bytes());
        let mid_h1 = h4_parent_hash_h1(mid_kp.public_key(), &sib_label);
        assert_ne!(mid_h1, [0u8; 32]);

        // tree_depth 2, path leaf(2,0) -> (1,0) -> root(0,0). The co-path sibling
        // (1,1) is deliberately NOT part of the path-only tree_info.
        let mut ti = Vec::new();
        ti_push_node(
            &mut ti,
            2,
            0,
            &leaf_kp.public_key().to_bytes(),
            &[0u8; 32],
            &[0u8; 32],
        );
        ti_push_node(
            &mut ti,
            1,
            0,
            &mid_kp.public_key().to_bytes(),
            &mid_h1,
            &[0u8; 32],
        );
        ti_push_node(
            &mut ti,
            0,
            0,
            &root_kp.public_key().to_bytes(),
            &[0u8; 32],
            &[0u8; 32],
        );

        let nodes = parse_welcome_tree_info(&ti).unwrap();
        assert_eq!(nodes.len(), 3);

        // The honest welcome is ACCEPTED by the joiner verifier.
        verify_welcome_tree_info(&nodes, 2).unwrap();

        // Regression witness: the superseded empty-view verifier REJECTED it.
        let empty = PartialTreeView::new(0, 2);
        assert!(matches!(
            verify_parent_hashes(&empty, &nodes),
            Err(CryptoError::ParentHashMismatch)
        ));
    }

    /// The joiner still rejects a tampered LEAF parent hash (an honest leaf must
    /// carry zero h1/h2), and — IN-01 — a blank adder leaf dropped by the parser
    /// does NOT cause the first populated (internal) node to be mis-treated as
    /// the leaf and spuriously rejected for its non-zero parent hash.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_tree_info_leaf_tamper_rejected_and_blank_leaf_ok() {
        use crate::key_schedule::{h3_tree_label, h4_parent_hash_h1};
        use crate::operations::path_update::verify_welcome_tree_info;

        let leaf_kp = HybridKemKeypair::generate().unwrap();
        let mid_kp = HybridKemKeypair::generate().unwrap();
        let sibling_kp = HybridKemKeypair::generate().unwrap();

        // Leaf tamper: a populated leaf (depth == tree_depth) with a NON-ZERO h1
        // is rejected.
        let mut ti = Vec::new();
        ti_push_node(
            &mut ti,
            2,
            0,
            &leaf_kp.public_key().to_bytes(),
            &[0x01u8; 32],
            &[0u8; 32],
        );
        let nodes = parse_welcome_tree_info(&ti).unwrap();
        assert!(matches!(
            verify_welcome_tree_info(&nodes, 2),
            Err(CryptoError::ParentHashMismatch)
        ));

        // IN-01: the adder leaf is BLANK (dropped by the parser); the first
        // populated node is the internal (1,0) carrying a real non-zero h1.
        // Keyed off TRUE depth it is a non-leaf (skipped), NOT mis-treated as a
        // leaf and rejected for a non-zero parent hash.
        let sib_label = h3_tree_label(1, 1, &sibling_kp.public_key().to_bytes());
        let mid_h1 = h4_parent_hash_h1(mid_kp.public_key(), &sib_label);
        let mut ti2 = Vec::new();
        ti_push_blank(&mut ti2, 2, 0); // blank adder leaf -> dropped by parse
        ti_push_node(
            &mut ti2,
            1,
            0,
            &mid_kp.public_key().to_bytes(),
            &mid_h1,
            &[0u8; 32],
        );
        let nodes2 = parse_welcome_tree_info(&ti2).unwrap();
        assert_eq!(nodes2.len(), 1, "blank leaf must be dropped by the parser");
        verify_welcome_tree_info(&nodes2, 2).unwrap();
    }

    // ─── AEAD-01 (SC1): Welcome key-commitment (committing AEAD) ──────────────

    /// AEAD-01 (SC1): the §12 Welcome epoch-secret wrap now carries a DESIGNED
    /// key-commitment. Exercised on the matched committing pair
    /// (`encrypt_welcome_info` / `decrypt_welcome_info`, which share the
    /// `cocoa-welcome-add` AAD) so the commitment rejection is isolated from the
    /// `process_welcome` signature gate. An honest wrap round-trips at the grown
    /// size (`encrypted_info` 104->136 for a 64-byte plaintext: nonce 24 +
    /// ciphertext 64 + tag 16 + commitment 32), and flipping a byte inside the
    /// trailing 32-byte commitment region makes `decrypt_welcome_info` reject
    /// with the uniform authentication failure.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_welcome_commitment_tamper_rejected() {
        struct Info([u8; WELCOME_INFO_PLAINTEXT_SIZE]);
        impl WelcomeInfoSerialise for Info {
            fn to_bytes(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        let recipient_kem = HybridKemKeypair::generate().unwrap();
        let recipient_pub = recipient_kem.public_key().clone();

        let info = Info([0x5Au8; WELCOME_INFO_PLAINTEXT_SIZE]);
        let (mut encrypted_info, encapsulation) =
            encrypt_welcome_info(&info, &recipient_pub).unwrap();

        // Committing size is pinned: 24 nonce + (64 + 16 tag + 32 commitment) = 136.
        assert_eq!(
            encrypted_info.len(),
            24 + WELCOME_INFO_PLAINTEXT_SIZE + 16 + aead::COMMITMENT_SIZE
        );
        assert_eq!(encrypted_info.len(), 136);

        // Positive round-trip at the new size.
        let recovered =
            decrypt_welcome_info(&encrypted_info, &encapsulation, &recipient_kem).unwrap();
        assert_eq!(&recovered[..], &info.0[..]);

        // Flip a byte inside the trailing 32-byte commitment region -> rejected.
        let last = encrypted_info.len() - 1;
        encrypted_info[last] ^= 0xFF;
        assert!(matches!(
            decrypt_welcome_info(&encrypted_info, &encapsulation, &recipient_kem),
            Err(CryptoError::AeadAuthenticationFailed)
        ));
    }

    // ─── DOS-01/03: check_size_limits gate on the welcome + create_group paths ─

    /// DOS-01 ordering proof (reproduce-don't-assert): a welcome whose measured
    /// message size (encrypted_info + encapsulation) exceeds `MAX_MESSAGE_SIZE`
    /// AND whose committer signature is invalid returns `MessageTooLarge`, NOT
    /// `SignatureVerificationFailed` — the size gate precedes
    /// `verify_with_context` (and the subsequent decapsulation / AEAD).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_process_welcome_rejects_oversized_before_verify() {
        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let member_kem =
            HybridKemKeypair::from_bytes(&member_identity.kem().to_bytes()[..]).unwrap();
        let committer = HybridIdentityKeypair::generate().unwrap();

        let welcome = Welcome {
            group_id: [0x42u8; 32],
            epoch: 0,
            leaf_position: 1,
            tree_depth: 1,
            member_count: 2,
            encrypted_info: vec![0u8; crate::MAX_MESSAGE_SIZE + 1],
            encapsulation: Vec::new(),
            signature: HybridSignature::from_bytes(
                &[0u8; trelis_hybrid::signature::SIGNATURE_SIZE],
            )
            .unwrap(),
        };

        let result = process_welcome([0x02u8; 32], member_kem, &welcome, committer.public_key());
        assert!(
            matches!(&result, Err(CryptoError::MessageTooLarge)),
            "size gate MUST fire before verify_with_context (is_err={})",
            result.is_err()
        );
    }

    /// DOS-03 (local-growth defence-in-depth): a create_group whose member list
    /// would make the group exceed `MAX_GROUP_SIZE` is rejected with
    /// `TreeDepthExceeded` before any key material is generated. The gate reads
    /// only `member_bundles.len()` and rejects BEFORE the per-member
    /// encapsulation loop, so one repeated bundle reference exercises it without
    /// allocating a million distinct bundles.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_create_group_rejects_oversized_group() {
        let identity = HybridIdentityKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let member_identity = HybridIdentityKeypair::generate().unwrap();
        let bundle = create_test_bundle(&member_identity);

        // creator + MAX_GROUP_SIZE others = MAX_GROUP_SIZE + 1 > MAX_GROUP_SIZE.
        let bundles: Vec<&HybridPreKeyBundle> = vec![&bundle; crate::MAX_GROUP_SIZE as usize];
        let result = create_group(&identity, kem, [0x01u8; 32], &bundles);
        assert!(
            matches!(&result, Err(CryptoError::TreeDepthExceeded)),
            "create_group must reject an oversized group before crypto (is_err={})",
            result.is_err()
        );
    }
}
