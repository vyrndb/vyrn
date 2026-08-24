//! Delete-heavy workloads must leave a compact tree: underfull pages merge
//! during copy-on-write rewrites instead of waiting for the next checkpoint
//! compaction.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, EngineOptions};

/// The profile counters are process-global, so every test in this binary
/// holds this lock: a measurement window must not include another test's
/// page reads.
static COUNTERS: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    COUNTERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Total tree page reads so far, cached or not: every read bumps exactly one
/// of the two counters, so the sum counts pages visited independently of
/// cache state.
fn page_reads() -> u64 {
    vyrn_core::profile::PAGE_HITS.load(Ordering::Relaxed)
        + vyrn_core::profile::PAGE_MISSES.load(Ordering::Relaxed)
}

fn key(index: u64) -> Vec<u8> {
    format!("user/{index:06}").into_bytes()
}

fn value(index: u64) -> Vec<u8> {
    vec![(index % 251) as u8; 64]
}

/// Puts or deletes applied through `write_batch` in bounded chunks.
fn apply(engine: &mut Engine, operations: Vec<BatchOperation>) {
    for chunk in operations.chunks(500) {
        engine.write_batch(chunk.to_vec()).unwrap();
    }
}

/// Pages a full scan of the user key range reads. The range bounds prune
/// the internal-prefix subtrees (tombstones), so the count is the live user
/// leaves plus the spine above them — exactly what merging must shrink.
fn user_scan_reads(engine: &Engine, expected_rows: usize) -> u64 {
    let start = page_reads();
    let rows = engine
        .scan(Some(b"user/"), Some(b"user0"), usize::MAX)
        .unwrap();
    assert_eq!(rows.len(), expected_rows, "scan lost or invented rows");
    page_reads() - start
}

/// The regression this change exists for: deleting 90% of the keys must
/// shrink the pages the live tree occupies, not just its entry count.
/// Before underfull pages merged, every leaf the deletes touched survived
/// holding a few entries, and a scan after the deletes read as many pages
/// as one before them.
#[test]
fn deleting_most_keys_shrinks_the_pages_a_scan_reads() {
    let _serial = serial();
    let directory = tempdir().unwrap();
    // The change log writes tree entries of its own, which would blur the
    // page counts this test asserts on.
    let options = EngineOptions {
        change_log: false,
        ..EngineOptions::default()
    };
    let mut engine = Engine::open_with_options(directory.path(), options).unwrap();
    const KEYS: u64 = 6_000;
    apply(
        &mut engine,
        (0..KEYS)
            .map(|index| BatchOperation::Put(key(index), value(index)))
            .collect(),
    );
    let before = user_scan_reads(&engine, KEYS as usize);
    apply(
        &mut engine,
        (0..KEYS)
            .filter(|index| index % 10 != 0)
            .map(|index| BatchOperation::Delete(key(index)))
            .collect(),
    );
    let survivors = (KEYS / 10) as usize;
    let after = user_scan_reads(&engine, survivors);
    assert!(
        after * 4 <= before,
        "a scan reads {after} pages after deleting 90% of the keys, versus \
         {before} before; underfull pages did not merge"
    );
    for index in (0..KEYS).step_by(10) {
        assert_eq!(engine.get(&key(index)).unwrap(), Some(value(index)));
    }
}

/// Merging must be invisible to reads: after rounds of interleaved inserts
/// and heavy deletes, every surviving key holds its value and scans return
/// exactly the surviving keys — compared against a `BTreeMap` fed the same
/// operations.
#[test]
fn heavy_delete_activity_matches_a_btree_map() {
    let _serial = serial();
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    // Deterministic xorshift so failures replay.
    let mut state = 0x1234_5678_9abc_def0_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..3 {
        let mut operations = Vec::new();
        for _ in 0..1_500 {
            let index = next() % 4_096;
            let key = format!("k/{index:05}").into_bytes();
            if next() % 100 < 55 {
                let value = vec![(next() % 251) as u8; (next() % 200) as usize];
                model.insert(key.clone(), value.clone());
                operations.push(BatchOperation::Put(key, value));
            } else {
                model.remove(&key);
                operations.push(BatchOperation::Delete(key));
            }
        }
        apply(&mut engine, operations);
        // Every third round ends delete-heavy: drop most of what remains,
        // which is what drives the merges under test.
        if round < 2 {
            let deletes: Vec<BatchOperation> = model
                .keys()
                .enumerate()
                .filter(|(position, _)| position % 10 != 0)
                .map(|(_, key)| BatchOperation::Delete(key.clone()))
                .collect();
            model = model
                .into_iter()
                .enumerate()
                .filter(|(position, _)| position % 10 == 0)
                .map(|(_, entry)| entry)
                .collect();
            apply(&mut engine, deletes);
        }
        let rows = engine.scan(None, None, usize::MAX).unwrap();
        let expected: Vec<(Vec<u8>, Vec<u8>)> = model
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(rows, expected, "scan diverged from the model");
        for (key, value) in &model {
            assert_eq!(engine.get(key).unwrap().as_ref(), Some(value));
        }
        assert_eq!(engine.get(b"k/99999").unwrap(), None);
    }
}

/// A merged tree must survive reopen. Without an intervening checkpoint the
/// reopen replays the whole history through redo — the single-key delete
/// path — so this also covers merging on recovery.
#[test]
fn a_merged_tree_survives_reopen_and_checkpoint() {
    let _serial = serial();
    let directory = tempdir().unwrap();
    const KEYS: u64 = 3_000;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        apply(
            &mut engine,
            (0..KEYS)
                .map(|index| BatchOperation::Put(key(index), value(index)))
                .collect(),
        );
        apply(
            &mut engine,
            (0..KEYS)
                .filter(|index| index % 10 != 0)
                .map(|index| BatchOperation::Delete(key(index)))
                .collect(),
        );
        engine.sync().unwrap();
    }
    let mut engine = Engine::open(directory.path()).unwrap();
    let verify = |engine: &Engine| {
        for index in 0..KEYS {
            let expected = (index % 10 == 0).then(|| value(index));
            assert_eq!(engine.get(&key(index)).unwrap(), expected);
        }
        let rows = engine
            .scan(Some(b"user/"), Some(b"user0"), usize::MAX)
            .unwrap();
        assert_eq!(rows.len(), (KEYS / 10) as usize);
    };
    verify(&engine);
    // Checkpoint compaction rebuilds the tree from a scan of the merged one;
    // reads must agree before and after.
    engine.checkpoint().unwrap();
    verify(&engine);
    // The reopened, checkpointed tree still takes writes.
    engine.put(key(1), b"back again".to_vec()).unwrap();
    assert_eq!(engine.get(&key(1)).unwrap(), Some(b"back again".to_vec()));
}
