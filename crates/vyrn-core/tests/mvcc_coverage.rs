//! MVCC history coverage, and the reads that used to be answered without it.
//!
//! History is only retained while a snapshot is open: `Engine::maintain_history`
//! records what a batch displaced, and it is called only when
//! `oldest_active_snapshot` says somebody is watching. The garbage-collection
//! floor, meanwhile, only moves when `collect_versions` runs. So a database that
//! opens a transaction, closes it, and keeps writing accumulates revisions that
//! sit ABOVE the floor with no history behind them — and every snapshot read
//! against one of those revisions was answered from whatever versions happened to
//! remain, silently and wrongly.
//!
//! The three tests named after the reviewer's repro recipes are the three shapes
//! that came out of that. Each one asserts the read now FAILS rather than lies;
//! each one is a wrong answer without the coverage watermark, not a panic, which
//! is what made the bug worth its own suite.

use vyrn_core::{BatchOperation, Engine, Error, IndexUpdate};

/// Vanishing keys: a key readable at a snapshot must not disappear from a later
/// read at that same snapshot.
///
/// The pin is taken and released, then the key is overwritten. That overwrite
/// retains nothing — no snapshot was open when it ran — so the version the first
/// read answered from is simply gone by the time of the second. Two reads at one
/// revision returning different values is the least defensible thing a snapshot
/// can do, and it needs no concurrency to produce.
#[test]
fn a_key_readable_at_a_snapshot_does_not_vanish_from_a_later_read() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();
    let snapshot = engine.register_snapshot();
    // While the pin is held the displaced version is retained, so this read is
    // answerable and answers correctly.
    engine.put(b"key".to_vec(), b"second".to_vec()).unwrap();
    assert_eq!(
        engine.get_at(b"key", snapshot).unwrap(),
        Some(b"first".to_vec())
    );
    engine.release_snapshot(snapshot);

    // Now nothing is watching, so this commit keeps no pre-image. The engine can
    // no longer reconstruct `snapshot`, and must say so instead of answering from
    // the live tree.
    engine.put(b"key".to_vec(), b"third".to_vec()).unwrap();
    assert!(
        matches!(
            engine.get_at(b"key", snapshot),
            Err(Error::SnapshotTooOld { .. })
        ),
        "a snapshot whose history was dropped must be refused, not answered \
         from whatever versions happen to remain"
    );
}

/// Present-as-past: a read at an old snapshot must never return a value written
/// AFTER it.
///
/// This is the stale-shadowing half of the bug rather than the coverage half.
/// `revision()` consulted the retained history FIRST and used the live tree only
/// as a fallback, so a key with a stale retained version reported that stale
/// revision — `get_at` then compared it against the requested snapshot, decided
/// the live tree was old enough to answer, and returned the newest value as
/// though it had always been there. The retained version is a lower bound on a
/// key's revision, never an authority.
#[test]
fn a_read_at_an_old_snapshot_never_returns_a_later_write() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();

    // A pin held across one write, so `key` acquires a retained version — and
    // then released, so the retained version starts going stale.
    let pin = engine.register_snapshot();
    engine.put(b"key".to_vec(), b"second".to_vec()).unwrap();
    let snapshot = engine.sequence();
    engine.release_snapshot(pin);

    // Written with nothing watching. `key` still carries the retained version
    // from the pinned write, which now names a revision the tree has left behind.
    engine.put(b"key".to_vec(), b"third".to_vec()).unwrap();

    // Whatever the engine does here, it must not claim `third` was the state at
    // `snapshot`: that value did not exist then. Refusing is correct, and so is
    // answering `second`; returning `third` is the bug.
    match engine.get_at(b"key", snapshot) {
        Err(Error::SnapshotTooOld { .. }) => {}
        Ok(value) => assert_ne!(
            value,
            Some(b"third".to_vec()),
            "a read at an old snapshot returned a value written after it"
        ),
        Err(error) => panic!("unexpected error: {error}"),
    }
}

/// Missed conflicts: two transactions that overwrote each other must not both
/// pass validation.
///
/// `any_changed_since` is what the server's transaction validation calls, and it
/// treated a retained version as the whole answer for any key that had one —
/// skipping the tree lookup entirely. A key whose retained version had gone stale
/// therefore reported "unchanged" across a write that had definitely changed it,
/// which is a lost update: the second transaction's read set was validated
/// against a revision the database had already moved past.
#[test]
fn a_stale_retained_version_does_not_hide_a_conflict() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();

    // Give `key` a retained version, then stop watching so it can go stale.
    let pin = engine.register_snapshot();
    engine.put(b"key".to_vec(), b"second".to_vec()).unwrap();
    engine.release_snapshot(pin);

    // A transaction reads `key` at this revision.
    let snapshot = engine.sequence();

    // A concurrent writer changes it. `key` still carries the stale retained
    // version from the pinned write, which is at or below `snapshot`.
    engine.put(b"key".to_vec(), b"third".to_vec()).unwrap();

    // Validation must see the change through either entry point.
    assert!(
        engine
            .any_changed_since(&[b"key".to_vec()], snapshot)
            .unwrap(),
        "a committed overwrite was invisible to conflict validation, so two \
         transactions that overwrote each other would both commit"
    );
    assert!(
        engine.changed_since(b"key", snapshot).unwrap(),
        "changed_since reported a stale retained revision instead of the \
         tree's newer one"
    );
    assert_eq!(
        engine.revision(b"key").unwrap(),
        Some(engine.sequence()),
        "revision() must report the newest write, not the newest retained version"
    );
}

/// Registering a snapshot for an uncovered revision must fail at registration.
///
/// The check used to be against `gc_floor`, which only moves when collection
/// runs — so a revision whose history was never retained was accepted as
/// pinnable, and the caller was told its snapshot existed. After
/// `register_snapshot_at` returns Ok a caller is entitled to believe its reads
/// mean something, so this is where the refusal belongs.
#[test]
fn registering_a_snapshot_below_coverage_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();
    let stale = engine.sequence();
    // No pin is held across either write, so neither retains a pre-image and
    // coverage advances past `stale`.
    engine.put(b"key".to_vec(), b"second".to_vec()).unwrap();
    engine.put(b"key".to_vec(), b"third".to_vec()).unwrap();

    assert!(
        matches!(
            engine.register_snapshot_at(stale),
            Err(Error::SnapshotTooOld { .. })
        ),
        "a revision with no retained history must not be pinnable"
    );
    // The newest committed revision is always covered: it is the live tree.
    engine.register_snapshot_at(engine.sequence()).unwrap();
    engine.release_snapshot(engine.sequence());
}

/// Coverage must not swallow the reads it exists to protect.
///
/// The watermark only ever rises to the newest committed revision, and only on
/// commits that retain nothing. A snapshot held across a run of writes keeps
/// coverage where it needs it, so every read at that snapshot stays answerable —
/// including the historical index lookups, which read through the same history.
#[test]
fn a_held_snapshot_stays_readable_across_many_writes() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.create_index(b"tag".to_vec(), false).unwrap();
    engine
        .write_indexed(
            vec![BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec())],
            vec![IndexUpdate {
                index: b"tag".to_vec(),
                primary_key: b"user/1".to_vec(),
                old_value: None,
                new_value: Some(b"admin".to_vec()),
            }],
        )
        .unwrap();
    engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();

    let snapshot = engine.register_snapshot();
    for index in 0..16 {
        engine
            .put(b"key".to_vec(), format!("v{index}").into_bytes())
            .unwrap();
        engine
            .put(format!("other-{index}").into_bytes(), b"x".to_vec())
            .unwrap();
    }
    engine
        .write_indexed(
            vec![BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec())],
            vec![IndexUpdate {
                index: b"tag".to_vec(),
                primary_key: b"user/1".to_vec(),
                old_value: Some(b"admin".to_vec()),
                new_value: Some(b"member".to_vec()),
            }],
        )
        .unwrap();

    assert_eq!(
        engine.get_at(b"key", snapshot).unwrap(),
        Some(b"first".to_vec()),
        "a held snapshot must still read the value that was live when it began"
    );
    // Keys created after the snapshot must not appear in it.
    assert_eq!(engine.get_at(b"other-0", snapshot).unwrap(), None);
    let rows = engine.scan_at(None, None, 100, snapshot).unwrap();
    assert!(rows
        .iter()
        .any(|(key, value)| key == b"key" && value == b"first"));
    assert!(!rows.iter().any(|(key, _)| key.starts_with(b"other-")));
    assert_eq!(
        engine
            .lookup_index_at(b"tag", b"admin", 10, snapshot)
            .unwrap(),
        vec![b"user/1".to_vec()],
        "the index value live at the snapshot must still be found there"
    );
    engine.release_snapshot(snapshot);
}

/// A reopened database answers for its committed revision and refuses the ones
/// before it.
///
/// `Engine::open` replays the WAL into a fresh history and then collects it away
/// against no active snapshot, so after an open the only answerable revision is
/// the committed LSN. That is exactly what coverage should report — the replayed
/// history is gone, so claiming otherwise would re-admit the vanishing-key read
/// on the far side of a restart.
#[test]
fn a_reopened_database_covers_only_its_committed_revision() {
    let directory = tempfile::tempdir().unwrap();
    let stale;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"key".to_vec(), b"first".to_vec()).unwrap();
        stale = engine.sequence();
        engine.put(b"key".to_vec(), b"second".to_vec()).unwrap();
    }
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.get(b"key").unwrap(), Some(b"second".to_vec()));
    assert!(
        matches!(
            engine.get_at(b"key", stale),
            Err(Error::SnapshotTooOld { .. })
        ),
        "replayed history is collected away on open, so a pre-restart \
         revision must be refused rather than answered"
    );
    // The committed revision is the live tree, so it is always answerable.
    assert_eq!(
        engine.get_at(b"key", engine.sequence()).unwrap(),
        Some(b"second".to_vec())
    );
}
