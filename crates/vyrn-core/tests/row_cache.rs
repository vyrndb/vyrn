//! The row cache must never serve a value a newer commit displaced.
//!
//! `Engine::get` and `Engine::get_shared` answer hot keys from a cache that
//! `write_batch` invalidates after every commit becomes visible. These tests
//! pin the read-your-write guarantee through every embedded write shape —
//! overwrites, deletes, multi-key batches, write-back mode with threshold
//! flushes, and a reopen — in exactly the order that would expose a missed
//! invalidation: read (populate), write (displace), read again (must be new).

use vyrn_core::{BatchOperation, DurabilityMode, Engine, EngineOptions};

fn open(directory: &std::path::Path, write_back: usize) -> Engine {
    Engine::open_with_options(
        directory,
        EngineOptions {
            durability: DurabilityMode::Durable,
            write_back_buffer: write_back,
            ..EngineOptions::default()
        },
    )
    .unwrap()
}

fn shared(engine: &Engine, key: &[u8]) -> Option<Vec<u8>> {
    engine
        .get_shared(key)
        .unwrap()
        .map(|value| value.as_slice().to_vec())
}

/// Classic and write-back engines both: a value read into the cache must be
/// displaced by the very next commit that touches its key.
#[test]
fn reads_after_writes_never_see_the_displaced_value() {
    for write_back in [0usize, 1 << 20] {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = open(directory.path(), write_back);
        engine.put(b"user/1".to_vec(), b"one".to_vec()).unwrap();
        // Both read APIs populate the cache.
        assert_eq!(engine.get(b"user/1").unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(shared(&engine, b"user/1").as_deref(), Some(&b"one"[..]));
        engine.put(b"user/1".to_vec(), b"two".to_vec()).unwrap();
        assert_eq!(
            shared(&engine, b"user/1").as_deref(),
            Some(&b"two"[..]),
            "stale value served after an overwrite (write_back={write_back})"
        );
        assert_eq!(engine.get(b"user/1").unwrap().as_deref(), Some(&b"two"[..]));
        // A delete must not leave the old value answerable.
        assert!(engine.delete(b"user/1").unwrap());
        assert_eq!(
            shared(&engine, b"user/1"),
            None,
            "stale value served after a delete (write_back={write_back})"
        );
        // Every key of a multi-key batch is displaced, not just the first.
        engine.put(b"user/2".to_vec(), b"a".to_vec()).unwrap();
        let _ = shared(&engine, b"user/2");
        engine
            .write_batch(vec![
                BatchOperation::Put(b"user/2".to_vec(), b"b".to_vec()),
                BatchOperation::Put(b"user/1".to_vec(), b"resurrected".to_vec()),
            ])
            .unwrap();
        assert_eq!(shared(&engine, b"user/2").as_deref(), Some(&b"b"[..]));
        assert_eq!(
            shared(&engine, b"user/1").as_deref(),
            Some(&b"resurrected"[..])
        );
    }
}

/// A write-back engine whose buffer flushes between the read and the next
/// read must keep answering the same bytes: the flush moves the value from
/// the overlay into the tree without changing it, so the cache entry made
/// from the overlay's allocation stays true.
#[test]
fn a_threshold_flush_does_not_change_a_cached_answer() {
    let directory = tempfile::tempdir().unwrap();
    // A buffer small enough that the filler batch below forces an absorb.
    let mut engine = open(directory.path(), 4096);
    engine.put(b"pinned".to_vec(), b"before".to_vec()).unwrap();
    assert_eq!(shared(&engine, b"pinned").as_deref(), Some(&b"before"[..]));
    for index in 0..64_u32 {
        engine
            .put(format!("filler/{index:04}").into_bytes(), vec![9; 128])
            .unwrap();
    }
    assert_eq!(
        shared(&engine, b"pinned").as_deref(),
        Some(&b"before"[..]),
        "the flush changed an answer it must not touch"
    );
    engine.put(b"pinned".to_vec(), b"after".to_vec()).unwrap();
    assert_eq!(shared(&engine, b"pinned").as_deref(), Some(&b"after"[..]));
}

/// Reopening builds a fresh engine and a fresh cache; the answers come from
/// the recovered tree and must match what was committed, then keep tracking
/// further writes.
#[test]
fn a_reopened_engine_answers_from_recovered_state_then_tracks_writes() {
    let directory = tempfile::tempdir().unwrap();
    {
        let mut engine = open(directory.path(), 1 << 20);
        engine.put(b"user/1".to_vec(), b"durable".to_vec()).unwrap();
        assert_eq!(shared(&engine, b"user/1").as_deref(), Some(&b"durable"[..]));
    }
    let mut engine = open(directory.path(), 1 << 20);
    assert_eq!(shared(&engine, b"user/1").as_deref(), Some(&b"durable"[..]));
    engine.put(b"user/1".to_vec(), b"newer".to_vec()).unwrap();
    assert_eq!(shared(&engine, b"user/1").as_deref(), Some(&b"newer"[..]));
}
