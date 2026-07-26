//! Point-in-time recovery driven end to end through the public API: base
//! backup, WAL archive, `recover_to`, and the ordinary opens that follow.
//!
//! The recovery bound is enforced only by what `recover_to` leaves on disk, so
//! every test here reopens the target with a completely stock `Engine::open`
//! afterwards — the one code path that would replay and resurrect anything the
//! trim failed to remove physically.

use proptest::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vyrn_core::{backup, manifest_lsn, recover, wal_archive, Engine, Error};

/// One put per LSN with the LSN baked into both key and value, so the exact
/// expected state at any bound `b` is `k0001..=k{b:04}` with no bookkeeping.
fn key_for(index: u64) -> Vec<u8> {
    format!("k{index:04}").into_bytes()
}

fn value_for(index: u64) -> Vec<u8> {
    format!("value-{index:04}").into_bytes()
}

/// The state a scan must report after recovering to `bound`.
fn expected_through(bound: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    (1..=bound).map(|i| (key_for(i), value_for(i))).collect()
}

/// Source timeline over small (128-byte) segments so several seal naturally:
/// LSNs 1..=25, checkpoint at 10, base backup taken at 15 with the engine
/// stopped, then LSNs 16..=25, a seal, and an archive of every sealed segment.
/// The interesting bounds — 9 (below base), 10 (equal), 20 (mid-archive),
/// 25 (reachable end) — all exist in one seeded world.
fn seed(source: &Path, backup_file: &Path, archive: &Path) {
    {
        let mut engine = Engine::open_with_segment_size(source, 128).unwrap();
        for index in 1..=10 {
            engine.put(key_for(index), value_for(index)).unwrap();
        }
        engine.checkpoint().unwrap();
        for index in 11..=15 {
            engine.put(key_for(index), value_for(index)).unwrap();
        }
    }
    backup::create_backup(source, backup_file).unwrap();
    {
        let mut engine = Engine::open_with_segment_size(source, 128).unwrap();
        for index in 16..=25 {
            engine.put(key_for(index), value_for(index)).unwrap();
        }
        engine.rotate_for_archive().unwrap();
    }
    wal_archive::archive_pending(&source.join("wal"), archive).unwrap();
}

/// Restores the seeded base backup into `<auxiliary>/restored`.
fn restore(backup_file: &Path, auxiliary: &Path) -> std::path::PathBuf {
    let target = auxiliary.join("restored");
    backup::restore_backup(backup_file, &target).unwrap();
    target
}

/// The bound must be physical — records trimmed and segments deleted, not
/// filtered in recovery's memory. If any record past the bound survives on
/// disk, the next stock `Engine::open` replays it and silently resurrects the
/// timeline the caller asked to discard, so the recovered state must be proven
/// stable across repeated plain reopens, not just inside `recover_to`.
#[test]
fn recover_to_bound_survives_restart() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    seed(source.path(), &backup_file, &archive);
    let target = restore(&backup_file, auxiliary.path());

    let achieved = recover::recover_to(&target, Some(&archive), Some(20), false).unwrap();
    assert_eq!(achieved, 20);
    // The closing checkpoint publishes the bound as the manifest LSN; anything
    // else means the recovery is only as durable as the WAL trim.
    assert_eq!(manifest_lsn(&target).unwrap(), 20);

    let expected = expected_through(20);
    for reopen in 0..3 {
        let engine = Engine::open(&target).unwrap();
        assert_eq!(
            engine.scan(None, None, usize::MAX).unwrap(),
            expected,
            "reopen {reopen} diverged from the recovered state"
        );
        assert_eq!(
            engine.sequence(),
            20,
            "reopen {reopen} replayed past the bound"
        );
        assert_eq!(
            engine.get(&key_for(21)).unwrap(),
            None,
            "reopen {reopen} resurrected a discarded commit"
        );
    }
}

/// A recovered database must be an ordinary database: its trimmed WAL and
/// fresh checkpoint have to accept and persist new commits exactly like a
/// never-recovered one. If recovery left stale segments or a wrong sequence
/// behind, new writes would collide with (or be shadowed by) the discarded
/// timeline's LSNs on the next replay.
#[test]
fn writes_after_recovery_are_durable() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    seed(source.path(), &backup_file, &archive);
    let target = restore(&backup_file, auxiliary.path());
    assert_eq!(
        recover::recover_to(&target, Some(&archive), Some(20), false).unwrap(),
        20
    );

    {
        let mut engine = Engine::open(&target).unwrap();
        for index in 1..=10u64 {
            engine
                .put(
                    format!("new{index:04}").into_bytes(),
                    format!("fresh-{index:04}").into_bytes(),
                )
                .unwrap();
        }
    }
    let engine = Engine::open(&target).unwrap();
    for index in 1..=10u64 {
        assert_eq!(
            engine.get(format!("new{index:04}").as_bytes()).unwrap(),
            Some(format!("fresh-{index:04}").into_bytes())
        );
    }
    // The pre-recovery history at or below the bound is intact...
    assert_eq!(engine.get(&key_for(20)).unwrap(), Some(value_for(20)));
    // ...and the new writes did not unearth the timeline past it.
    assert_eq!(engine.get(&key_for(21)).unwrap(), None);
    assert_eq!(engine.sequence(), 30);
}

/// The base checkpoint's root already contains every commit at or below its
/// manifest LSN and redo only rolls forward, so a bound below it cannot be
/// honoured; accepting it would return a database containing commits past the
/// requested point while claiming it stopped there.
#[test]
fn bound_below_base_checkpoint_is_rejected() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    seed(source.path(), &backup_file, &archive);
    let target = restore(&backup_file, auxiliary.path());
    let error = recover::recover_to(&target, Some(&archive), Some(9), false).unwrap_err();
    assert!(matches!(error, Error::CorruptBackup(_)));
}

/// A bound past what the merged log reaches cannot be satisfied; stopping
/// short silently would hand back a database missing commits the caller asked
/// for, so the fallback to the reachable LSN must be an explicit opt-in.
#[test]
fn bound_above_reachable_is_rejected_without_allow_partial() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    seed(source.path(), &backup_file, &archive);
    let target = restore(&backup_file, auxiliary.path());
    let error = recover::recover_to(&target, Some(&archive), Some(999), false).unwrap_err();
    assert!(matches!(error, Error::CorruptBackup(_)));
    // The archive stops at the last sealed record: LSN 25.
    assert_eq!(
        recover::recover_to(&target, Some(&archive), Some(999), true).unwrap(),
        25
    );
    let engine = Engine::open(&target).unwrap();
    assert_eq!(
        engine.scan(None, None, usize::MAX).unwrap(),
        expected_through(25)
    );
}

/// The bound may legally equal the base checkpoint LSN: everything needed is
/// already in the checkpointed root and redo has zero records to apply. This
/// is the edge where an off-by-one in the trim-segment search (`first_lsn <=
/// bound + 1` against a segment that starts exactly at the checkpoint) would
/// either reject a valid bound or leave the first post-checkpoint record
/// behind for the next open to replay.
#[test]
fn bound_equal_to_checkpoint_is_a_no_redo_recovery() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    seed(source.path(), &backup_file, &archive);
    let target = restore(&backup_file, auxiliary.path());
    assert_eq!(
        recover::recover_to(&target, Some(&archive), Some(10), false).unwrap(),
        10
    );
    let engine = Engine::open(&target).unwrap();
    assert_eq!(
        engine.scan(None, None, usize::MAX).unwrap(),
        expected_through(10)
    );
    assert_eq!(engine.sequence(), 10);
    assert_eq!(engine.get(&key_for(11)).unwrap(), None);
}

/// A base backup copies the then-active segment mid-write, so the same segment
/// id exists in the restored wal/ as a strict byte prefix of the sealed copy
/// the archive later shipped. A merge that blindly keeps the base copy (or
/// rejects the pair as foreign) either loses the sealed tail's commits or
/// refuses every recovery whose backup raced the log.
#[test]
fn merges_partial_base_segment_with_full_archive_copy() {
    let source = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let backup_file = auxiliary.path().join("base.bkp");
    let archive = auxiliary.path().join("archive");
    // Default segment size: nothing seals on its own, so the backup is
    // guaranteed to catch the shared segment while it is still active.
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(key_for(1), value_for(1)).unwrap();
        engine.checkpoint().unwrap();
        engine.put(key_for(2), value_for(2)).unwrap();
    }
    backup::create_backup(source.path(), &backup_file).unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(key_for(3), value_for(3)).unwrap();
        engine.put(key_for(4), value_for(4)).unwrap();
        engine.rotate_for_archive().unwrap();
    }
    wal_archive::archive_pending(&source.path().join("wal"), &archive).unwrap();

    let target = restore(&backup_file, auxiliary.path());
    // Prove the scenario is real before relying on it: some archived segment
    // also exists in the base with strictly fewer bytes.
    let shared_partial = fs::read_dir(&archive)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            name.ends_with(".vwal").then_some(name)
        })
        .any(|name| {
            fs::metadata(target.join("wal").join(&name))
                .is_ok_and(|base| base.len() < fs::metadata(archive.join(&name)).unwrap().len())
        });
    assert!(
        shared_partial,
        "the backup should hold a strict prefix of an archived segment"
    );

    assert_eq!(
        recover::recover_to(&target, Some(&archive), None, false).unwrap(),
        4
    );
    let engine = Engine::open(&target).unwrap();
    // k3 and k4 exist only in the sealed tail the archive carries, so their
    // presence proves the merge preferred the archived copy over the prefix.
    assert_eq!(
        engine.scan(None, None, usize::MAX).unwrap(),
        expected_through(4)
    );
}

/// Every database numbers its segments from 1 with dense LSNs, so a backup of
/// one database merged with another database's archive presents fully valid
/// segments under identical ids and LSN ranges but with unrelated contents.
/// Without the shared-prefix identity check the merge would splice two
/// histories into one WAL and replay would materialise a database that never
/// existed anywhere.
#[test]
fn rejects_archive_from_a_different_timeline() {
    /// Two timelines diverge from LSN 1 onward: same keys, different values.
    /// The early checkpoint gives the backup a readable manifest while leaving
    /// segment 1 (still active at checkpoint time) in place to collide.
    fn fill(path: &Path, tag: u8) {
        let mut engine = Engine::open_with_segment_size(path, 128).unwrap();
        for index in 0..20u8 {
            engine
                .put(
                    format!("d{index:02}").into_bytes(),
                    vec![tag.wrapping_add(index); 40],
                )
                .unwrap();
            if index == 0 {
                engine.checkpoint().unwrap();
            }
        }
    }
    let first = tempdir().unwrap();
    let second = tempdir().unwrap();
    let auxiliary = tempdir().unwrap();
    let archive = auxiliary.path().join("archive");
    fill(first.path(), 1);
    fill(second.path(), 200);
    wal_archive::archive_pending(&first.path().join("wal"), &archive).unwrap();

    let backup_file = auxiliary.path().join("second.bkp");
    backup::create_backup(second.path(), &backup_file).unwrap();
    let target = restore(&backup_file, auxiliary.path());
    let error = recover::recover_to(&target, Some(&archive), None, false).unwrap_err();
    let Error::CorruptBackup(message) = error else {
        panic!("expected a hard CorruptBackup error, got {error:?}");
    };
    assert!(
        message.contains("timeline"),
        "the error should name the timeline mismatch, got: {message}"
    );
}

#[derive(Debug, Clone)]
enum Op {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// Small key alphabet so puts overwrite and deletes hit real keys often.
