//! Skipped message key storage for out-of-order delivery.
//!
//! When messages arrive out of order, we need to derive and store
//! the message keys for skipped messages so they can be decrypted
//! later when they arrive.

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

use trelis_error::{CryptoError, Result};
use zeroize::Zeroize;

use crate::{MAX_SKIPPED_KEYS_TOTAL, SKIPPED_KEY_MAX_AGE};

/// Size of the sender key hash for indexing.
pub const SENDER_KEY_HASH_SIZE: usize = 32;

/// Size of a message key.
pub const MESSAGE_KEY_SIZE: usize = 32;

/// Index for looking up skipped message keys.
///
/// Combines a hash of the sender's public key with the message number
/// to uniquely identify each skipped key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkippedKeyIndex {
    /// BLAKE3 hash of the sender's hybrid public key.
    pub sender_key_hash: [u8; SENDER_KEY_HASH_SIZE],
    /// Message number this key corresponds to.
    pub message_number: u64,
}

impl SkippedKeyIndex {
    /// Creates a new skipped key index.
    pub fn new(sender_key_hash: [u8; SENDER_KEY_HASH_SIZE], message_number: u64) -> Self {
        Self {
            sender_key_hash,
            message_number,
        }
    }

    /// Creates an index from a sender public key and message number.
    pub fn from_sender_key(sender_public_key: &[u8], message_number: u64) -> Self {
        let hash = blake3::hash(sender_public_key);
        Self {
            sender_key_hash: *hash.as_bytes(),
            message_number,
        }
    }
}

/// A stored skipped message key with metadata.
#[derive(Clone)]
pub struct SkippedKeyEntry {
    /// The cached message key.
    pub message_key: [u8; MESSAGE_KEY_SIZE],
    /// Unix timestamp when this key was stored.
    pub created_at: u64,
}

impl Zeroize for SkippedKeyEntry {
    fn zeroize(&mut self) {
        self.message_key.zeroize();
    }
}

impl Drop for SkippedKeyEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Storage for skipped message keys.
///
/// This implements bounded storage with time-based and count-based
/// eviction to prevent denial-of-service attacks.
#[cfg(feature = "alloc")]
pub struct SkippedKeys {
    /// Map from (sender_key_hash, message_number) to message key.
    keys: BTreeMap<SkippedKeyIndex, SkippedKeyEntry>,
}

#[cfg(feature = "alloc")]
impl Default for SkippedKeys {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl SkippedKeys {
    /// Creates a new empty skipped keys store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Returns the number of stored skipped keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if no skipped keys are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Inserts a skipped key.
    ///
    /// # Arguments
    ///
    /// * `index` - The skipped key index
    /// * `message_key` - The 32-byte message key
    /// * `created_at` - Unix timestamp when storing
    ///
    /// # Errors
    ///
    /// Returns `TooManySkippedKeys` if the store is at capacity.
    pub fn insert(
        &mut self,
        index: SkippedKeyIndex,
        message_key: [u8; MESSAGE_KEY_SIZE],
        created_at: u64,
    ) -> Result<()> {
        if self.keys.len() >= MAX_SKIPPED_KEYS_TOTAL {
            return Err(CryptoError::TooManySkippedKeys {
                limit: MAX_SKIPPED_KEYS_TOTAL,
            });
        }

        self.keys.insert(
            index,
            SkippedKeyEntry {
                message_key,
                created_at,
            },
        );

        Ok(())
    }

    /// Removes and returns a skipped key if it exists.
    ///
    /// This consumes the key - it cannot be retrieved again.
    /// This is critical for preventing replay attacks.
    pub fn remove(&mut self, index: &SkippedKeyIndex) -> Option<[u8; MESSAGE_KEY_SIZE]> {
        self.keys.remove(index).map(|entry| entry.message_key)
    }

    /// Checks if a key exists without consuming it.
    #[must_use]
    pub fn contains(&self, index: &SkippedKeyIndex) -> bool {
        self.keys.contains_key(index)
    }

    /// Prunes expired keys based on age.
    ///
    /// # Arguments
    ///
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    ///
    /// The number of keys pruned.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let initial_len = self.keys.len();

        self.keys.retain(|_, entry| {
            let age = now.saturating_sub(entry.created_at);
            age < SKIPPED_KEY_MAX_AGE
        });

        initial_len - self.keys.len()
    }

    /// Prunes oldest keys until under the specified limit.
    ///
    /// Uses a simple strategy of removing the oldest entries first.
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of keys to retain
    ///
    /// # Returns
    ///
    /// The number of keys pruned.
    pub fn prune_to_limit(&mut self, limit: usize) -> usize {
        if self.keys.len() <= limit {
            return 0;
        }

        let to_remove = self.keys.len() - limit;
        let mut pruned = 0;

        // Collect oldest entries (by created_at timestamp)
        let mut entries: alloc::vec::Vec<_> = self
            .keys
            .iter()
            .map(|(k, v)| (k.clone(), v.created_at))
            .collect();

        entries.sort_by_key(|(_, created_at)| *created_at);

        // Remove oldest entries
        for (index, _) in entries.into_iter().take(to_remove) {
            self.keys.remove(&index);
            pruned += 1;
        }

        pruned
    }

    /// Returns an iterator over all skipped key indices.
    pub fn indices(&self) -> impl Iterator<Item = &SkippedKeyIndex> {
        self.keys.keys()
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for SkippedKeys {
    fn zeroize(&mut self) {
        for (_, entry) in self.keys.iter_mut() {
            entry.zeroize();
        }
        self.keys.clear();
    }
}

#[cfg(feature = "alloc")]
impl Drop for SkippedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skipped_key_index_from_sender_key() {
        let sender_pk = [0x42u8; 100];
        let index = SkippedKeyIndex::from_sender_key(&sender_pk, 42);

        assert_eq!(index.message_number, 42);
        assert_eq!(index.sender_key_hash.len(), 32);
    }

    #[test]
    fn test_skipped_keys_insert_and_remove() {
        let mut store = SkippedKeys::new();
        let index = SkippedKeyIndex::from_sender_key(b"test-key", 0);
        let message_key = [0xABu8; 32];

        store.insert(index.clone(), message_key, 1000).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.contains(&index));

        let removed = store.remove(&index).unwrap();
        assert_eq!(removed, message_key);
        assert_eq!(store.len(), 0);
        assert!(!store.contains(&index));
    }

    #[test]
    fn test_skipped_keys_remove_nonexistent() {
        let mut store = SkippedKeys::new();
        let index = SkippedKeyIndex::from_sender_key(b"test-key", 0);

        assert!(store.remove(&index).is_none());
    }

    #[test]
    fn test_skipped_keys_single_use() {
        let mut store = SkippedKeys::new();
        let index = SkippedKeyIndex::from_sender_key(b"test-key", 0);
        let message_key = [0xABu8; 32];

        store.insert(index.clone(), message_key, 1000).unwrap();

        // First remove succeeds
        assert!(store.remove(&index).is_some());

        // Second remove fails (key was consumed)
        assert!(store.remove(&index).is_none());
    }

    #[test]
    fn test_skipped_keys_prune_expired() {
        let mut store = SkippedKeys::new();

        // Insert keys with different timestamps
        for i in 0..10 {
            let index = SkippedKeyIndex::from_sender_key(b"test-key", i);
            store.insert(index, [0u8; 32], i * 1000).unwrap();
        }

        // Prune keys older than SKIPPED_KEY_MAX_AGE (7 days = 604800 seconds)
        // At now = 700000, keys created before 95200 should be pruned
        let pruned = store.prune_expired(700_000);

        // All keys created at timestamps 0-9000 should be pruned
        assert!(pruned > 0);
    }

    #[test]
    fn test_skipped_keys_prune_to_limit() {
        let mut store = SkippedKeys::new();

        // Insert 100 keys
        for i in 0..100 {
            let index = SkippedKeyIndex::from_sender_key(b"test-key", i);
            store.insert(index, [0u8; 32], i).unwrap();
        }

        assert_eq!(store.len(), 100);

        // Prune to 50
        let pruned = store.prune_to_limit(50);
        assert_eq!(pruned, 50);
        assert_eq!(store.len(), 50);
    }

    #[test]
    fn test_skipped_keys_max_limit() {
        let mut store = SkippedKeys::new();

        // Fill to capacity
        for i in 0..MAX_SKIPPED_KEYS_TOTAL {
            let index = SkippedKeyIndex::from_sender_key(&i.to_le_bytes(), 0);
            store.insert(index, [0u8; 32], 1000).unwrap();
        }

        // Next insert should fail
        let index = SkippedKeyIndex::from_sender_key(b"overflow", 0);
        let result = store.insert(index, [0u8; 32], 1000);
        assert!(matches!(result, Err(CryptoError::TooManySkippedKeys { .. })));
    }
}
