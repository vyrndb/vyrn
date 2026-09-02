//! `drain_wal` is the embedded group-commit barrier: it hands async-buffered
//! WAL records to the kernel under the engine lock and leaves the fsync —
//! `Wal::sync_through` on the handle `Engine::wal()` shares — to run outside
//! it. Its durability claim is WAL-only, the same claim a durable-mode
//! commit's own barrier makes, so the test crashes the engine the honest
//! way: by copying the live data directory mid-flight and opening the copy,
//! which holds exactly the bytes a power cut would have left.

use vyrn_core::{DurabilityMode, Engine, EngineOptions};

fn open_async(directory: &std::path::Path) -> Engine {
    Engine::open_with_options(
        directory,
        EngineOptions {
            durability: DurabilityMode::Async,
            write_back_buffer: 1 << 20,
            ..EngineOptions::default()
        },
    )
    .unwrap()
}

/// Byte-for-byte copy of the live data directory: what a crash preserves.
fn crash_copy(live: &std::path::Path) -> tempfile::TempDir {
    let copy = tempfile::tempdir().unwrap();
    copy_tree(live, copy.path());
    copy
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The two directions that make the crash model self-verifying: a commit
/// acknowledged after `drain_wal` + `sync_through` survives the crash, and a
/// commit still sitting in the async buffer does not — proving the copy
/// really models a crash rather than riding on a clean shutdown's sync.
#[test]
fn drained_commits_survive_a_crash_and_undrained_ones_do_not() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = open_async(directory.path());
    let wal = engine.wal();

    engine.put(b"acked".to_vec(), b"durable".to_vec()).unwrap();
    let owed = engine.drain_wal().unwrap();
    wal.sync_through(owed).unwrap();
    // Buffered but never drained: visible to this engine, owed nothing.
    engine
        .put(b"unacked".to_vec(), b"volatile".to_vec())
        .unwrap();
    assert_eq!(
        engine.get(b"unacked").unwrap().as_deref(),
        Some(&b"volatile"[..])
    );

    let crashed = crash_copy(directory.path());
    drop(engine); // AFTER the copy: the copy must not see drop's clean sync.
    let recovered = Engine::open(crashed.path()).unwrap();
    assert_eq!(
        recovered.get(b"acked").unwrap().as_deref(),
        Some(&b"durable"[..]),
        "a commit acknowledged after drain_wal + sync_through must survive"
    );
    assert_eq!(
        recovered.get(b"unacked").unwrap(),
        None,
        "an async commit that was never drained must NOT survive — if it \
         does, the crash copy is not modelling a crash"
    );
}

/// The served shape: `DurabilityMode::Durable` with `buffered_appends`, where
/// applying a batch touches no file and the flush stage owns both hand-offs.
/// A deferred commit is volatile until `drain_wal` + `sync_through` have run
/// — a crash copy taken in between must lose it — and an immediate-barrier
/// commit (an index change, a document write) must self-drain: it is durable
/// with no caller drain at all. Both directions, so the copy provably models
/// a crash and the drain provably carries the durability.
#[test]
fn buffered_durable_commits_survive_only_after_drain_and_sync() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open_with_options(
        directory.path(),
        EngineOptions {
            durability: DurabilityMode::Durable,
            buffered_appends: true,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    let wal = engine.wal();

    // Immediate barrier: `commit_batch` drains and syncs before returning.
    engine
        .put(b"immediate".to_vec(), b"self-drained".to_vec())
        .unwrap();

    // Deferred barrier: the server's write path. Applied, visible to this
    // engine, and owed a drain and a barrier before anyone may be told so.
    let (_, lsn) = engine
        .write_batch_deferred(vec![vyrn_core::BatchOperation::Put(
            b"deferred".to_vec(),
            b"needs-the-flush-stage".to_vec(),
        )])
        .unwrap();
    let lsn = lsn.expect("a durable deferred commit owes a flush");

    let crashed_before_drain = crash_copy(directory.path());
    let owed = engine.drain_wal().unwrap();
    assert!(
        owed >= lsn,
        "the drain must cover every record buffered before it ran"
    );
    wal.sync_through(owed).unwrap();
    let crashed_after_sync = crash_copy(directory.path());
    drop(engine); // AFTER the copies: neither may see drop's clean sync.

    let lost = Engine::open(crashed_before_drain.path()).unwrap();
    assert_eq!(
        lost.get(b"immediate").unwrap().as_deref(),
        Some(&b"self-drained"[..]),
        "an immediate-barrier commit must be durable with no caller drain"
    );
    assert_eq!(
        lost.get(b"deferred").unwrap(),
        None,
        "a deferred commit must NOT survive a crash before its drain — if it \
         does, applying a batch is touching the file and the Windows convoy \
         is back"
    );

    let recovered = Engine::open(crashed_after_sync.path()).unwrap();
    assert_eq!(
        recovered.get(b"deferred").unwrap().as_deref(),
        Some(&b"needs-the-flush-stage"[..]),
        "a deferred commit must survive once drained and synced"
    );
}

/// The barrier splits cleanly: `drain_wal` twice with nothing new buffered
/// owes the same LSN, and `sync_through` at or below the watermark returns
/// without work — the group-commit fast path followers take.
#[test]
fn drain_is_idempotent_and_the_barrier_coalesces() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = open_async(directory.path());
    let wal = engine.wal();
    engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
    engine.put(b"b".to_vec(), b"2".to_vec()).unwrap();
    let owed = engine.drain_wal().unwrap();
    assert_eq!(
        engine.drain_wal().unwrap(),
        owed,
        "an empty buffer must owe the same LSN"
    );
    wal.sync_through(owed).unwrap();
    wal.sync_through(owed).unwrap(); // covered: must be a no-op, not an error
}

/// `sync_directory` was a silent no-op off Unix, which made every
/// rename-publish (manifests, archive segments, backup outputs) unproven on
/// Windows. The Windows arm opens the directory with backup semantics and
/// write access and flushes it; this pins that the open+flush path actually
/// succeeds on the platform the suite runs on, so a permissions or flags
/// regression cannot quietly turn the flush back into a no-op that errors.
#[test]
fn a_data_directory_survives_a_directory_sync() {
    let directory = tempfile::tempdir().unwrap();
    // Exercised through the public surface: a put followed by a checkpointed
    // engine drop runs the manifest rename + directory sync path end to end.
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"k".to_vec(), b"v".to_vec()).unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
}

/// The phased checkpoint's whole point: commits that land while the
/// compactor runs WITHOUT the engine lock must survive the checkpoint —
/// they reach the compacted tree through the WAL delta replay in
/// `finish_checkpoint`, and losing them there would be silent data loss at
/// exactly the moment the WAL segments holding them get retired. Exercised
/// through the phase API the server uses; the composed `checkpoint()` is
/// the degenerate case with an empty delta.
#[test]
fn writes_during_an_unlocked_compaction_survive_the_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open_with_options(
        directory.path(),
        EngineOptions {
            durability: DurabilityMode::Durable,
            write_back_buffer: 1 << 20,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    for index in 0..500_u32 {
        engine
            .put(format!("pre/{index:05}").into_bytes(), vec![1; 64])
            .unwrap();
    }
    let mut job = engine.begin_checkpoint().unwrap();
    // The engine is fully writable between the phases — that is the point.
    for index in 0..200_u32 {
        engine
            .put(format!("during/{index:05}").into_bytes(), vec![2; 64])
            .unwrap();
    }
    engine.delete(b"pre/00000").unwrap();
    job.compact().unwrap();
    // And still writable between compact and finish.
    engine
        .put(b"after-compact".to_vec(), b"also-here".to_vec())
        .unwrap();
    engine.finish_checkpoint(job).unwrap();

    let check = |engine: &Engine| {
        assert_eq!(
            engine.get(b"pre/00499").unwrap().as_deref(),
            Some(&[1; 64][..])
        );
        assert_eq!(
            engine.get(b"pre/00000").unwrap(),
            None,
            "the delete must hold"
        );
        for index in [0_u32, 137, 199] {
            assert_eq!(
                engine
                    .get(format!("during/{index:05}").as_bytes().to_vec().as_slice())
                    .unwrap()
                    .as_deref(),
                Some(&[2; 64][..]),
                "a write during compaction vanished"
            );
        }
        assert_eq!(
            engine.get(b"after-compact").unwrap().as_deref(),
            Some(&b"also-here"[..])
        );
    };
    check(&engine);
    // The checkpoint retired the WAL segments; the reopen must answer from
    // the published generation alone.
    drop(engine);
    let engine = Engine::open(directory.path()).unwrap();
    check(&engine);
}
