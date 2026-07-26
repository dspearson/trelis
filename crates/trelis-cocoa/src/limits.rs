//! Centralised denial-of-service size-limit gate for CoCoA-SA session entries.
//!
//! The single [`check_size_limits`] function enforces the spec's DoS ceilings
//! (§13 `sec:cocoa-dos`) at every `CocoaSession` entry point, ordered strictly
//! ahead of all cryptographic work (before any signature verification, AEAD
//! operation, or KEM decapsulation). This implements the normative requirement
//! that resource-limit checks MUST precede cryptographic operations, so an
//! attacker cannot force expensive hybrid verification / decapsulation with a
//! malformed oversized or over-deep input.

use trelis_error::{CryptoError, Result};

use crate::{
    MAX_GROUP_SIZE, MAX_MERKLE_PROOF_DEPTH, MAX_MESSAGE_SIZE, MAX_TREE_DEPTH, MAX_UNMERGED_LEAVES,
};

/// Rejects an over-limit input BEFORE any cryptographic processing.
///
/// Every comparison is strict `>` (greater-than): a quantity exactly at its
/// ceiling is accepted; only a quantity past the ceiling is rejected. Channel
/// entry points that carry only a message length pass `0` for the four
/// structural arguments — every ceiling is `> 0`, so a zero argument can never
/// trip its check.
///
/// # Arguments
///
/// * `message_len` — message / ciphertext / serialised-commit length (DOS-01).
/// * `proof_depth` — commit path / opening depth (DOS-02); `0` on channel paths.
/// * `tree_depth` — resulting ratchet-tree depth (DOS-03); `0` on channel paths.
/// * `group_size` — resulting group member count (DOS-03); `0` on channel paths.
/// * `unmerged_leaves` — total unmerged-leaf count (DOS-03); `0` on channel paths.
///
/// # Errors
///
/// * [`CryptoError::MessageTooLarge`] if `message_len > MAX_MESSAGE_SIZE`.
/// * [`CryptoError::ProofTooDeep`] if `proof_depth > MAX_MERKLE_PROOF_DEPTH`.
/// * [`CryptoError::TreeDepthExceeded`] if the group size, tree depth, or
///   unmerged-leaf count exceeds `MAX_GROUP_SIZE`, `MAX_TREE_DEPTH`, or
///   `MAX_UNMERGED_LEAVES` respectively.
pub(crate) fn check_size_limits(
    message_len: usize,
    proof_depth: usize,
    tree_depth: u32,
    group_size: u32,
    unmerged_leaves: usize,
) -> Result<()> {
    if message_len > MAX_MESSAGE_SIZE {
        return Err(CryptoError::MessageTooLarge);
    }
    if proof_depth > MAX_MERKLE_PROOF_DEPTH {
        return Err(CryptoError::ProofTooDeep);
    }
    if group_size > MAX_GROUP_SIZE
        || tree_depth > MAX_TREE_DEPTH
        || unmerged_leaves > MAX_UNMERGED_LEAVES
    {
        return Err(CryptoError::TreeDepthExceeded);
    }
    Ok(())
}
