//! A byte-budgeted cache of the newest committed value per user key.
//!
//! A hot point read through the tree is a root-to-leaf descent — a page-cache
//! probe per level — plus a leaf binary search, plus (for a spilled value) a
//! value-cache probe. All of it recomputes an answer that has not changed
//! since the last time the same key was asked for. This cache short-circuits
//! the whole path to one hash probe and a reference-count bump, which is the
//! read the comparison engines effectively serve: sled's tree IS an in-memory
//! cache of refcounted buffers, and redb hands out slices of its mmap.
//!
//! ## Why this cannot serve a stale value
//!
//! Only [`Engine::get`] and [`Engine::get_shared`] consult it, and both admit
//! only keys that pass `validate_user_key` — so nothing under
//! `INTERNAL_PREFIX` (tombstones, the change log, index entries) is ever
//! cached. User keys mutate through exactly two paths, and both invalidate
//! here after the mutation becomes visible: `write_batch` (which every
//! embedded write, transaction commit, document write, and indexed write
//! funnels through) and the replica's record apply. Everything else that
//! touches the tree is content-preserving for user keys — write-back absorb,
//! checkpoint compaction — or runs before the engine serves reads at all
//! (recovery redo, point-in-time restore, portable import).
//!
//! Absent keys are deliberately not cached: a negative entry would have to be
//! invalidated on creation of a key never seen before, which is a second,
//! easy-to-miss invalidation rule. A miss on an absent key costs the descent
//! it always cost.
//!
//! Same replacement design as the page and value caches — a byte-budgeted
//! second-chance clock — for the same reason: one cold sweep must not evict
//! the hot set.

use crate::fast_hash::FastMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// The default budget, deliberately modest like the value cache's: the point
/// of the cache is removing per-read CPU, not holding the database in memory.
const DEFAULT_ROW_CACHE_BYTES: usize = 64 * 1024 * 1024;

fn budget_from_env() -> usize {
    std::env::var("VYRN_ROW_CACHE_BYTES")
        .ok()
        .and_then(|bytes| bytes.parse().ok())
        .unwrap_or(DEFAULT_ROW_CACHE_BYTES)
}

struct CachedRow {
    value: Arc<Vec<u8>>,
    /// Second-chance bit: a hit protects the entry for one eviction pass.
    referenced: bool,
}

struct Inner {
    entries: FastMap<Vec<u8>, CachedRow>,
    /// Eviction ring over the entry keys. The key bytes are duplicated here —
    /// the map owns one spelling, the ring another — which is accounted for
    /// in `bytes` and paid once per insert, not per hit.
    clock: VecDeque<Vec<u8>>,
    bytes: usize,
}

/// Behind its own mutex so reads take `&self`, exactly like the value cache.
pub(crate) struct RowCache {
    inner: Mutex<Inner>,
    budget: usize,
}

impl RowCache {
    pub(crate) fn new() -> Self {
        Self::with_budget(budget_from_env())
    }

    fn with_budget(budget: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: FastMap::default(),
                clock: VecDeque::new(),
                bytes: 0,
            }),
            budget,
        }
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<Arc<Vec<u8>>> {
        if self.budget == 0 {
            return None;
        }
        let mut inner = self.inner.lock().ok()?;
        let entry = inner.entries.get_mut(key)?;
        entry.referenced = true;
        Some(Arc::clone(&entry.value))
    }

    pub(crate) fn insert(&self, key: &[u8], value: Arc<Vec<u8>>) {
        // An entry that would occupy a large fraction of the budget evicts
        // the whole hot set to cache one thing; it keeps paying the descent.
        let entry_bytes = key.len() * 2 + value.len();
        if self.budget == 0 || entry_bytes > self.budget / 8 {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        while inner.bytes + entry_bytes > self.budget {
            let Some(victim) = inner.clock.pop_front() else {
                break;
            };
            match inner.entries.get_mut(&victim) {
                Some(entry) if entry.referenced => {
                    entry.referenced = false;
                    inner.clock.push_back(victim);
                }
                Some(_) => {
                    let removed = inner.entries.remove(&victim).expect("checked above");
                    inner.bytes -= victim.len() * 2 + removed.value.len();
                }
                // Invalidated since it was ringed; its slot is already free.
                None => {}
            }
        }
        match inner.entries.insert(
            key.to_vec(),
            CachedRow {
                value,
                referenced: false,
            },
        ) {
            Some(previous) => {
                // Replaced in place: the ring already holds this key once.
                inner.bytes -= previous.value.len();
                inner.bytes += entry_bytes - key.len() * 2;
            }
            None => {
                inner.clock.push_back(key.to_vec());
                inner.bytes += entry_bytes;
            }
        }
    }

    /// Drops a key after its commit became visible. The next read descends
    /// and repopulates; the ring slot is left to lapse, as the clocks above
    /// already tolerate.
    pub(crate) fn invalidate(&self, key: &[u8]) {
        if self.budget == 0 {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if let Some(removed) = inner.entries.remove(key) {
            inner.bytes -= key.len() * 2 + removed.value.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_respects_the_budget_and_the_hot_set() {
        let cache = RowCache::with_budget(1024);
        // Each entry: 3-byte key twice + 100-byte value = 106 bytes; ten
        // exceed the budget, so admitting them all must evict.
        for index in 0..10_u8 {
            cache.insert(&[b'k', b'0', index], Arc::new(vec![index; 100]));
        }
        let inner = cache.inner.lock().unwrap();
        assert!(inner.bytes <= 1024, "budget exceeded: {}", inner.bytes);
        assert!(inner.entries.len() < 10, "nothing was evicted");
    }

    #[test]
    fn invalidation_removes_and_reaccounts() {
        let cache = RowCache::with_budget(1024);
        cache.insert(b"key", Arc::new(vec![1; 64]));
        assert!(cache.get(b"key").is_some());
        cache.invalidate(b"key");
        assert!(cache.get(b"key").is_none());
        assert_eq!(cache.inner.lock().unwrap().bytes, 0);
    }
}
