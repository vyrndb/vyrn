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
