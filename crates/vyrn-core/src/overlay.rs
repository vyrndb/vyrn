//! The write-back buffer: committed mutations the tree has not absorbed yet.
//!
//! With write-back enabled (`EngineOptions::write_back_buffer`), a commit's
//! durability is the WAL record alone; its mutations land here instead of in a
//! copy-on-write rewrite of the tree. The tree absorbs the whole buffer in one
//! amortised `prepare_batch` when the buffer crosses its byte threshold and on
//! every checkpoint, so the per-commit page cost — the leaf plus every internal
//! page up to the root, twice per commit once the change log's path is counted
//! — is paid once per *buffer* instead of once per *commit*.
//!
//! Entries carry the full keyspace: user keys, tombstones, change-log records,
//! index entries. The layers above address all of those as ordinary keys, so a
//! read path that merges this buffer over the tree needs no knowledge of any of
//! them. A `None` value is a delete that masks the tree's entry; it must not be
//! dropped from the buffer before the flush, or the masked tree entry would
//! come back from the dead.
//!
//! Never durable and never expected to be: on a crash the buffer's whole
//! content is reconstructed from the WAL, which is why write-back commits
//! encode a root that can never be adopted and recovery replays from the
//! checkpoint instead (see `WRITE_BACK_ROOT`).
//!
//! Two parties hold an overlay. The engine holds one and is its source of
//! truth. Each server [`crate::ReadEngine`] holds its own copy, fed the same
//! mutations through [`PublishedMutation`] after their WAL record is durable —
//! values are `Arc`-shared, so feeding a reader is a refcount bump per value,
//! not a copy. A reader's copy shrinks by LSN ([`Overlay::evict_through`])
//! once the tree it reads has provably absorbed those entries.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::page_tree::PageTree;
use crate::{MergedRow, MergedValue, Result};

/// One buffered mutation: the newest committed state of a key that the tree
/// does not know yet.
#[derive(Debug, Clone)]
pub(crate) struct BufferedEntry {
    /// `None` is a committed delete, masking any tree entry for the key.
    /// Shared rather than owned so an engine's entry and every reader's copy
    /// of it are one allocation.
    pub(crate) value: Option<Arc<Vec<u8>>>,
    /// The LSN of the commit that wrote this state, preserved through the
    /// flush so `revision()` and snapshot reads answer identically before and
    /// after the tree absorbs the buffer.
    pub(crate) revision: u64,
}

/// One committed mutation on its way to a read handle's overlay copy.
///
/// Produced by the engine for every write-back commit (see
/// `Engine::take_write_back_publish`) and applied to each [`crate::ReadEngine`]
/// only after the commit's WAL record is durable — the same
/// durable-then-publish order the classic path's root refresh follows.
#[derive(Debug, Clone)]
pub struct PublishedMutation {
    pub key: Vec<u8>,
    /// `None` is a delete. The `Arc` is shared with the engine's own buffer
    /// entry, so handing a batch to N readers copies no value bytes.
    pub value: Option<Arc<Vec<u8>>>,
    /// The commit's LSN, stamped on every mutation of the batch.
    pub revision: u64,
}

/// Everything one commit asks the read handles to learn, in order.
///
/// `mutations` are applied first; `absorbed_through` then licenses the reader
/// to drop every overlay entry at or below that LSN, because the tree root
/// published alongside this batch provably contains them.
#[derive(Debug, Clone, Default)]
pub struct WriteBackPublish {
    pub mutations: Vec<PublishedMutation>,
    /// The engine's cumulative absorb watermark at commit time: every entry
    /// with `revision <= absorbed_through` is in the tree behind the root this
    /// batch publishes. `None` when write-back is off and there is nothing to
    /// publish or evict.
    pub absorbed_through: Option<u64>,
}

impl WriteBackPublish {
    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty() && self.absorbed_through.is_none()
    }
}

pub(crate) struct Overlay {
    pub(crate) entries: BTreeMap<Vec<u8>, BufferedEntry>,
    /// Approximate heap footprint of `entries`, the flush trigger.
    bytes: usize,
    /// Byte threshold at which the engine flushes the buffer into the tree.
    /// `usize::MAX` on read handles, which never flush — their entries leave
    /// by [`Overlay::evict_through`] instead.
    flush_bytes: usize,
}

/// Fixed per-entry overhead charged on top of key and value bytes, so a flood
/// of tiny entries still trips the threshold on map bookkeeping it is actually
/// paying for.
const ENTRY_OVERHEAD: usize = 64;

impl Overlay {
    pub(crate) fn new(flush_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
            flush_bytes,
        }
    }

    /// Records a committed mutation, replacing any earlier buffered state of
    /// the key.
    pub(crate) fn record(&mut self, key: Vec<u8>, value: Option<Arc<Vec<u8>>>, revision: u64) {
        let value_len = value.as_deref().map_or(0, Vec::len);
        let key_len = key.len();
        match self.entries.insert(key, BufferedEntry { value, revision }) {
            Some(previous) => {
                // The key and its overhead were charged when the entry it
                // replaces arrived; only the value's size changed.
                let old = previous.value.as_deref().map_or(0, Vec::len);
                self.bytes = self.bytes.saturating_sub(old) + value_len;
            }
            None => self.bytes += ENTRY_OVERHEAD + key_len + value_len,
        }
    }

    pub(crate) fn get(&self, key: &[u8]) -> Option<&BufferedEntry> {
        self.entries.get(key)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn should_flush(&self) -> bool {
        self.bytes >= self.flush_bytes
    }

    /// Forgets everything, after the tree has durably absorbed it.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    /// Drops every entry the tree has absorbed: all with `revision <= lsn`.
    ///
    /// Only sound when the caller's tree already serves a root that contains
    /// those entries — on a read handle, that means the refresh to the
    /// absorbing root happens before this call, under the same exclusive
    /// borrow. An entry newer than `lsn` survives untouched, so an eviction
    /// racing later commits can never drop state the tree lacks.
    pub(crate) fn evict_through(&mut self, lsn: u64) {
        let mut freed = 0usize;
        self.entries.retain(|key, entry| {
            if entry.revision <= lsn {
                freed += ENTRY_OVERHEAD + key.len() + entry.value.as_deref().map_or(0, Vec::len);
                false
            } else {
                true
            }
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }
}

// --- Merged reads --------------------------------------------------------
//
// One implementation of "the buffer wins over the tree", shared by the
// engine and every read handle so the two cannot drift. Each function takes
// the overlay as an `Option`: `None` (or an empty overlay) is exactly the
// tree's own answer, which is the write-back-disabled path.

pub(crate) fn merged_get(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    match buffer.and_then(|buffer| buffer.get(key)) {
        Some(entry) => Ok(entry.value.as_deref().cloned()),
        None => tree.get(key),
    }
}

pub(crate) fn merged_revision(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    key: &[u8],
) -> Result<Option<u64>> {
    match buffer.and_then(|buffer| buffer.get(key)) {
        // A buffered delete masks the tree: the key has no live revision,
        // exactly as if the tree had already dropped it.
        Some(entry) => Ok(entry.value.is_some().then_some(entry.revision)),
        None => tree.revision(key),
    }
}

/// [`PageTree::get_many_revisions`] with the buffer merged over it.
/// `keys` must be sorted and deduplicated, as the tree requires.
pub(crate) fn merged_get_many_revisions(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    keys: &[Vec<u8>],
) -> Result<Vec<Option<u64>>> {
    match buffer {
        None => tree.get_many_revisions(keys),
        Some(buffer) if buffer.is_empty() => tree.get_many_revisions(keys),
        Some(buffer) => {
            let mut results = vec![None; keys.len()];
            let mut misses = Vec::new();
            let mut slots = Vec::new();
            for (index, key) in keys.iter().enumerate() {
                match buffer.get(key) {
                    Some(entry) => {
                        results[index] = entry.value.is_some().then_some(entry.revision)
                    }
                    None => {
                        // A subsequence of a sorted list stays sorted.
                        misses.push(key.clone());
                        slots.push(index);
                    }
                }
            }
            for (slot, found) in slots.into_iter().zip(tree.get_many_revisions(&misses)?) {
                results[slot] = found;
            }
            Ok(results)
        }
    }
}

/// [`PageTree::get_many_with_revision`] with the buffer merged over it.
pub(crate) fn merged_get_many_with_revision(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    keys: &[Vec<u8>],
) -> Result<Vec<MergedValue>> {
    match buffer {
        None => tree.get_many_with_revision(keys),
        Some(buffer) if buffer.is_empty() => tree.get_many_with_revision(keys),
        Some(buffer) => {
            let mut results = vec![None; keys.len()];
            let mut misses = Vec::new();
            let mut slots = Vec::new();
            for (index, key) in keys.iter().enumerate() {
                match buffer.get(key) {
                    Some(entry) => {
                        results[index] = entry
                            .value
                            .as_deref()
                            .map(|value| (value.clone(), entry.revision))
                    }
                    None => {
                        misses.push(key.clone());
                        slots.push(index);
                    }
                }
            }
            for (slot, found) in slots
                .into_iter()
                .zip(tree.get_many_with_revision(&misses)?)
            {
                results[slot] = found;
            }
            Ok(results)
        }
    }
}

/// One ordered pass over the buffer and the tree.
///
/// The tree is asked for `limit` plus the number of buffered deletes in
/// range: each delete can mask at most one tree row, so the tree rows that
/// survive the merge still reach `limit` whenever the tree has them. The
/// two sources are then zipped in key order, the buffer winning ties —
/// it is always newer than the tree for the same key.
pub(crate) fn merged_scan(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    start: Option<&[u8]>,
    end: Option<&[u8]>,
    limit: usize,
    excluded_prefix: Option<&[u8]>,
) -> Result<Vec<MergedRow>> {
    let Some(buffer) = buffer.filter(|buffer| !buffer.is_empty()) else {
        return tree.scan_with_revisions_excluding_prefix(start, end, limit, excluded_prefix);
    };
    if limit == 0 {
        return Ok(Vec::new());
    }
    use std::ops::Bound;
    let bounds = (
        start.map_or(Bound::Unbounded, Bound::Included),
        end.map_or(Bound::Unbounded, Bound::Excluded),
    );
    let wanted = |key: &[u8]| excluded_prefix.is_none_or(|prefix| !key.starts_with(prefix));
    let deletes = buffer
        .entries
        .range::<[u8], _>(bounds)
        .filter(|(key, entry)| wanted(key) && entry.value.is_none())
        .count();
    let tree_rows = tree.scan_with_revisions_excluding_prefix(
        start,
        end,
        limit.saturating_add(deletes),
        excluded_prefix,
    )?;
    let mut rows = Vec::with_capacity(limit.min(1024));
    let mut buffered = buffer
        .entries
        .range::<[u8], _>(bounds)
        .filter(|(key, _)| wanted(key))
        .peekable();
    let mut from_tree = tree_rows.into_iter().peekable();
    while rows.len() < limit {
        let take_buffered = match (buffered.peek(), from_tree.peek()) {
            (Some((buffered_key, _)), Some((tree_key, _, _))) => {
                buffered_key.as_slice() <= tree_key.as_slice()
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if take_buffered {
            let (key, entry) = buffered.next().expect("peeked");
            // The tree's copy of the same key is superseded either way.
            if from_tree
                .peek()
                .is_some_and(|(tree_key, _, _)| tree_key == key)
            {
                from_tree.next();
            }
            if let Some(value) = entry.value.as_deref() {
                rows.push((key.clone(), value.clone(), entry.revision));
            }
        } else {
            rows.push(from_tree.next().expect("peeked"));
        }
    }
    Ok(rows)
}

pub(crate) fn merged_changed_since(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    start: Option<&[u8]>,
    end: Option<&[u8]>,
    revision: u64,
    excluded_prefix: Option<&[u8]>,
) -> Result<bool> {
    if let Some(buffer) = buffer {
        use std::ops::Bound;
        let bounds = (
            start.map_or(Bound::Unbounded, Bound::Included),
            end.map_or(Bound::Unbounded, Bound::Excluded),
        );
        // A buffered delete is a change too; its entry carries the
        // deleting commit's revision.
        let changed = buffer.entries.range::<[u8], _>(bounds).any(|(key, entry)| {
            excluded_prefix.is_none_or(|prefix| !key.starts_with(prefix))
                && entry.revision > revision
        });
        if changed {
            return Ok(true);
        }
    }
    // No false positives from shadowed tree entries: the buffer is always
    // newer than the tree for the same key, so a tree revision above the
    // bound was a real change even if the buffer has since superseded it.
    tree.changed_since(start, end, revision, excluded_prefix)
}

/// [`PageTree::last_key_in`] with the buffer merged over it.
pub(crate) fn merged_last_key_in(
    tree: &PageTree,
    buffer: Option<&Overlay>,
    start: &[u8],
    end: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let Some(buffer) = buffer else {
        return tree.last_key_in(start, end);
    };
    use std::ops::Bound;
    let bounds = (
        Bound::Included(start),
        end.map_or(Bound::Unbounded, Bound::Excluded),
    );
    let buffered = buffer
        .entries
        .range::<[u8], _>(bounds)
        .rev()
        .find(|(_, entry)| entry.value.is_some())
        .map(|(key, _)| key.clone());
    // The tree's answer may be masked by a buffered delete; step the bound
    // down past each masked key. Bounded by the deletes in range.
    let mut bound = end.map(<[u8]>::to_vec);
    let from_tree = loop {
        match tree.last_key_in(start, bound.as_deref())? {
            Some(key) if buffer.get(&key).is_some_and(|entry| entry.value.is_none()) => {
                bound = Some(key);
            }
            other => break other,
        }
    };
    Ok(match (buffered, from_tree) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    })
}
