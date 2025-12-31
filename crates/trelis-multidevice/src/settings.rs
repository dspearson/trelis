//! Per-thread settings and key storage.
//!
//! Each thread has configurable history sync settings that control
//! whether message keys are retained for sharing with new devices.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ThreadId;
use crate::retained_key::RetainedKey;

/// Per-thread configuration for history synchronisation.
#[derive(Debug, Clone)]
pub struct ThreadSettings {
    /// Thread identifier.
    pub thread_id: ThreadId,

    /// If true: message keys are retained for sharing with new devices.
    /// If false: pure forward secrecy, keys deleted after use.
    pub history_sync_enabled: bool,

    /// When history sync was last toggled (Unix timestamp, for audit).
    pub history_sync_changed_at: Option<u64>,
}

impl ThreadSettings {
    /// Creates thread settings with history sync enabled (default).
    ///
    /// This is the recommended default for normal conversations where
    /// users expect new devices to access message history.
    #[must_use]
    pub fn new(thread_id: ThreadId) -> Self {
        Self {
            thread_id,
            history_sync_enabled: true,
            history_sync_changed_at: None,
        }
    }

    /// Creates thread settings with pure forward secrecy (no history sync).
    ///
    /// Use this for sensitive discussions where maximum security is required.
    /// Message keys are deleted immediately after use.
    #[must_use]
    pub fn new_ephemeral(thread_id: ThreadId, timestamp: u64) -> Self {
        Self {
            thread_id,
            history_sync_enabled: false,
            history_sync_changed_at: Some(timestamp),
        }
    }

    /// Enables history sync for this thread.
    ///
    /// Note: This does NOT retroactively retain keys that were already deleted.
    /// Only future messages will have their keys retained.
    pub fn enable_history_sync(&mut self, timestamp: u64) {
        self.history_sync_enabled = true;
        self.history_sync_changed_at = Some(timestamp);
    }

    /// Disables history sync for this thread.
    ///
    /// Note: This does NOT delete already-retained keys. Previously synced
    /// messages remain accessible. Only future messages will have pure
    /// forward secrecy.
    pub fn disable_history_sync(&mut self, timestamp: u64) {
        self.history_sync_enabled = false;
        self.history_sync_changed_at = Some(timestamp);
    }

    /// Returns true if history sync is enabled.
    #[must_use]
    pub fn is_history_sync_enabled(&self) -> bool {
        self.history_sync_enabled
    }
}

/// Per-thread key retention store.
///
/// When history sync is enabled, message keys are stored here for
/// potential sharing with new devices.
#[cfg(feature = "alloc")]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ThreadKeyStore {
    /// Thread identifier.
    #[zeroize(skip)]
    pub thread_id: ThreadId,

    /// Retained message keys, sorted by sequence number.
    pub keys: Vec<RetainedKey>,
}

#[cfg(feature = "alloc")]
impl ThreadKeyStore {
    /// Creates a new empty key store for a thread.
    #[must_use]
    pub fn new(thread_id: ThreadId) -> Self {
        Self {
            thread_id,
            keys: Vec::new(),
        }
    }

    /// Creates a key store with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(thread_id: ThreadId, capacity: usize) -> Self {
        Self {
            thread_id,
            keys: Vec::with_capacity(capacity),
        }
    }

    /// Adds a message key for retention (if history sync is enabled).
    ///
    /// Keys are automatically sorted by sequence number for efficient lookup.
    pub fn retain_key(&mut self, key: RetainedKey) {
        // Insert in sorted order by sequence
        let pos = self
            .keys
            .binary_search_by_key(&key.sequence, |k| k.sequence)
            .unwrap_or_else(|p| p);
        self.keys.insert(pos, key);
    }

    /// Gets all retained keys for sharing with a new device.
    #[must_use]
    pub fn get_all_keys(&self) -> &[RetainedKey] {
        &self.keys
    }

    /// Gets a specific key by message ID.
    #[must_use]
    pub fn get_key(&self, message_id: &[u8; 32]) -> Option<&RetainedKey> {
        self.keys.iter().find(|k| &k.message_id == message_id)
    }

    /// Gets a key by sequence number (efficient binary search).
    #[must_use]
    pub fn get_key_by_sequence(&self, sequence: u64) -> Option<&RetainedKey> {
        self.keys
            .binary_search_by_key(&sequence, |k| k.sequence)
            .ok()
            .map(|idx| &self.keys[idx])
    }

    /// Returns the number of retained keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if no keys are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Clears all retained keys (when disabling sync or leaving thread).
    ///
    /// Keys are securely zeroized before being removed.
    pub fn clear(&mut self) {
        for key in &mut self.keys {
            key.zeroize();
        }
        self.keys.clear();
    }

    /// Removes keys older than the specified timestamp.
    ///
    /// This can be used to implement bounded retention (e.g., only keep
    /// keys for the last 30 days).
    pub fn prune_before(&mut self, timestamp: u64) {
        self.keys.retain(|k| k.timestamp >= timestamp);
    }

    /// Merges keys from another device (deduplicating by message_id).
    ///
    /// This is used when receiving `HistoryKeyShareMessage` from multiple
    /// devices that may have overlapping key sets.
    pub fn merge(&mut self, other_keys: Vec<RetainedKey>) {
        for key in other_keys {
            // Skip if we already have this key
            if self.keys.iter().any(|k| k.message_id == key.message_id) {
                continue;
            }

            // Insert in sorted order
            let pos = self
                .keys
                .binary_search_by_key(&key.sequence, |k| k.sequence)
                .unwrap_or_else(|p| p);
            self.keys.insert(pos, key);
        }
    }

    /// Returns the sequence number range covered by retained keys.
    #[must_use]
    pub fn sequence_range(&self) -> Option<(u64, u64)> {
        if self.keys.is_empty() {
            None
        } else {
            Some((self.keys.first()?.sequence, self.keys.last()?.sequence))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_settings_default() {
        let settings = ThreadSettings::new([0x42u8; 32]);

        assert!(settings.history_sync_enabled);
        assert!(settings.history_sync_changed_at.is_none());
    }

    #[test]
    fn test_thread_settings_ephemeral() {
        let settings = ThreadSettings::new_ephemeral([0x42u8; 32], 1000);

        assert!(!settings.history_sync_enabled);
        assert_eq!(settings.history_sync_changed_at, Some(1000));
    }

    #[test]
    fn test_toggle_history_sync() {
        let mut settings = ThreadSettings::new([0x42u8; 32]);

        settings.disable_history_sync(2000);
        assert!(!settings.history_sync_enabled);
        assert_eq!(settings.history_sync_changed_at, Some(2000));

        settings.enable_history_sync(3000);
        assert!(settings.history_sync_enabled);
        assert_eq!(settings.history_sync_changed_at, Some(3000));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_new() {
        let store = ThreadKeyStore::new([0x42u8; 32]);

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_retain() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 5,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 3,
            timestamp: 900,
        });

        assert_eq!(store.len(), 2);

        // Keys should be sorted by sequence
        assert_eq!(store.keys[0].sequence, 3);
        assert_eq!(store.keys[1].sequence, 5);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_get_by_sequence() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 10,
            timestamp: 1000,
        });

        assert!(store.get_key_by_sequence(10).is_some());
        assert!(store.get_key_by_sequence(5).is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_merge_dedup() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 1,
            timestamp: 1000,
        });

        // Merge with overlapping key
        store.merge(vec![
            RetainedKey {
                message_id: [0x01u8; 32], // Duplicate
                message_key: [0xAAu8; 32],
                sequence: 1,
                timestamp: 1000,
            },
            RetainedKey {
                message_id: [0x02u8; 32], // New
                message_key: [0xBBu8; 32],
                sequence: 2,
                timestamp: 2000,
            },
        ]);

        // Should have 2 keys (duplicate ignored)
        assert_eq!(store.len(), 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_prune() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 1,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 2,
            timestamp: 2000,
        });

        store.prune_before(1500);

        assert_eq!(store.len(), 1);
        assert_eq!(store.keys[0].sequence, 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_sequence_range() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        assert!(store.sequence_range().is_none());

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 5,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 10,
            timestamp: 2000,
        });

        assert_eq!(store.sequence_range(), Some((5, 10)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_with_capacity() {
        let store = ThreadKeyStore::with_capacity([0x42u8; 32], 100);

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        // Capacity is internal, but we can verify the store works
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_get_key() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        let message_id = [0x01u8; 32];
        store.retain_key(RetainedKey {
            message_id,
            message_key: [0xAAu8; 32],
            sequence: 5,
            timestamp: 1000,
        });

        // Find by message_id
        let found = store.get_key(&message_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().sequence, 5);

        // Non-existent message_id
        let not_found = store.get_key(&[0x99u8; 32]);
        assert!(not_found.is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_get_all_keys() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 5,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 10,
            timestamp: 2000,
        });

        let all_keys = store.get_all_keys();
        assert_eq!(all_keys.len(), 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_clear() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 5,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 10,
            timestamp: 2000,
        });

        assert_eq!(store.len(), 2);

        store.clear();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_thread_settings_is_history_sync_enabled() {
        let settings = ThreadSettings::new([0x42u8; 32]);
        assert!(settings.is_history_sync_enabled());

        let ephemeral = ThreadSettings::new_ephemeral([0x42u8; 32], 1000);
        assert!(!ephemeral.is_history_sync_enabled());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_merge_maintains_order() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        // Add some keys out of order
        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 10,
            timestamp: 1000,
        });

        // Merge keys that fill in gaps
        store.merge(vec![
            RetainedKey {
                message_id: [0x02u8; 32],
                message_key: [0xBBu8; 32],
                sequence: 5,
                timestamp: 500,
            },
            RetainedKey {
                message_id: [0x03u8; 32],
                message_key: [0xCCu8; 32],
                sequence: 15,
                timestamp: 1500,
            },
        ]);

        assert_eq!(store.len(), 3);
        // Keys should be in sorted order
        assert_eq!(store.keys[0].sequence, 5);
        assert_eq!(store.keys[1].sequence, 10);
        assert_eq!(store.keys[2].sequence, 15);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_key_store_prune_all() {
        let mut store = ThreadKeyStore::new([0x42u8; 32]);

        store.retain_key(RetainedKey {
            message_id: [0x01u8; 32],
            message_key: [0xAAu8; 32],
            sequence: 1,
            timestamp: 1000,
        });

        store.retain_key(RetainedKey {
            message_id: [0x02u8; 32],
            message_key: [0xBBu8; 32],
            sequence: 2,
            timestamp: 2000,
        });

        // Prune all keys
        store.prune_before(10000);

        assert!(store.is_empty());
    }
}
