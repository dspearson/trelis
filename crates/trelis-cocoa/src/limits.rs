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

/// DOS-03 local-growth convenience: rejects a resulting `member_count` whose
/// group size or tree depth would exceed `MAX_GROUP_SIZE` / `MAX_TREE_DEPTH`.
///
/// Delegates to [`check_size_limits`] with the message-size and proof-depth
/// arguments zeroed — a local build path (`create_group` / `add_member`) carries
/// no attacker-controlled wire bytes, so only the DOS-03 structural ceilings
/// apply. The resulting tree depth is derived via `depth_for_members` so the
/// same geometry the caller is about to build is what gets bounded.
///
/// # Errors
///
/// [`CryptoError::TreeDepthExceeded`] if the resulting group size or tree depth
/// exceeds its ceiling.
pub(crate) fn check_group_growth_limits(member_count: u32) -> Result<()> {
    check_size_limits(
        0,
        0,
        crate::tree::PartialTreeView::depth_for_members(member_count),
        member_count,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive strict-`>` boundary proof for all five limits, independent of
    /// any call-site wiring: each limit's exact value passes and value+1 returns
    /// the correct variant; an all-zero call passes. This underpins DOS-04 at the
    /// gate level (the reject-before-crypto ORDERING proofs live on the reachable
    /// entry paths — Plan 01 wires decrypt, Plan 03 the ingest paths).
    #[test]
    fn test_check_size_limits_boundaries() {
        // A wholly zero call trips nothing (every ceiling is > 0).
        assert!(check_size_limits(0, 0, 0, 0, 0).is_ok());

        // message_len: at-limit accepted, +1 rejected.
        assert!(check_size_limits(MAX_MESSAGE_SIZE, 0, 0, 0, 0).is_ok());
        assert!(matches!(
            check_size_limits(MAX_MESSAGE_SIZE + 1, 0, 0, 0, 0),
            Err(CryptoError::MessageTooLarge)
        ));

        // proof_depth: at-limit accepted, +1 rejected.
        assert!(check_size_limits(0, MAX_MERKLE_PROOF_DEPTH, 0, 0, 0).is_ok());
        assert!(matches!(
            check_size_limits(0, MAX_MERKLE_PROOF_DEPTH + 1, 0, 0, 0),
            Err(CryptoError::ProofTooDeep)
        ));

        // tree_depth: at-limit accepted, +1 rejected.
        assert!(check_size_limits(0, 0, MAX_TREE_DEPTH, 0, 0).is_ok());
        assert!(matches!(
            check_size_limits(0, 0, MAX_TREE_DEPTH + 1, 0, 0),
            Err(CryptoError::TreeDepthExceeded)
        ));

        // group_size: at-limit accepted, +1 rejected.
        assert!(check_size_limits(0, 0, 0, MAX_GROUP_SIZE, 0).is_ok());
        assert!(matches!(
            check_size_limits(0, 0, 0, MAX_GROUP_SIZE + 1, 0),
            Err(CryptoError::TreeDepthExceeded)
        ));

        // unmerged_leaves: at-limit accepted, +1 rejected.
        assert!(check_size_limits(0, 0, 0, 0, MAX_UNMERGED_LEAVES).is_ok());
        assert!(matches!(
            check_size_limits(0, 0, 0, 0, MAX_UNMERGED_LEAVES + 1),
            Err(CryptoError::TreeDepthExceeded)
        ));
    }
}
