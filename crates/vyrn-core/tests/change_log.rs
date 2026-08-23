use serde_json::json;
use tempfile::tempdir;
use vyrn_core::{change_log::Cursor, document::IndexDefinition, BatchOperation, Engine, Error};

#[test]
fn changes_survive_reopen_and_replay_in_commit_order() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        engine
            .write_batch(vec![
                BatchOperation::Put(b"b".to_vec(), b"2".to_vec()),
                BatchOperation::Put(b"c".to_vec(), b"3".to_vec()),
            ])
            .unwrap();
        engine.delete(b"a").unwrap();
    }

    let engine = Engine::open(directory.path()).unwrap();
    let changes = engine.read_changes(Cursor::start(), 100).unwrap();
    let observed: Vec<_> = changes
        .iter()
        .map(|change| {
            (
                String::from_utf8(change.key.clone()).unwrap(),
                change.value.clone().map(|v| String::from_utf8(v).unwrap()),
            )
        })
        .collect();
    assert_eq!(
        observed,
        vec![
            ("a".to_owned(), Some("1".to_owned())),
            ("b".to_owned(), Some("2".to_owned())),
            ("c".to_owned(), Some("3".to_owned())),
            ("a".to_owned(), None),
        ]
    );

    // Cursors are strictly increasing, so a subscriber can order them globally.
    for pair in changes.windows(2) {
        assert!(pair[0].cursor() < pair[1].cursor());
    }
    // Both operations of the one batch share a commit sequence.
    assert_eq!(changes[1].sequence, changes[2].sequence);
    assert_ne!(changes[1].index, changes[2].index);
}

#[test]
fn resuming_from_a_cursor_delivers_exactly_the_missed_changes() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"first".to_vec(), b"1".to_vec()).unwrap();

    let seen = engine.read_changes(Cursor::start(), 100).unwrap();
    let resume = seen.last().unwrap().cursor();
    assert!(engine.read_changes(resume, 100).unwrap().is_empty());

    // Writes that happen while a subscriber is disconnected.
    engine.put(b"second".to_vec(), b"2".to_vec()).unwrap();
    engine.put(b"third".to_vec(), b"3".to_vec()).unwrap();

    let missed = engine.read_changes(resume, 100).unwrap();
    assert_eq!(missed.len(), 2);
    assert_eq!(missed[0].key, b"second");
    assert_eq!(missed[1].key, b"third");

    // Resuming again from the newest cursor yields nothing, so no duplicates.
    let latest = missed.last().unwrap().cursor();
    assert!(engine.read_changes(latest, 100).unwrap().is_empty());
}

#[test]
fn changes_are_delivered_across_a_crash_gap() {
    let directory = tempdir().unwrap();
    let resume = {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"before".to_vec(), b"1".to_vec()).unwrap();
        engine
            .read_changes(Cursor::start(), 100)
            .unwrap()
            .last()
            .unwrap()
            .cursor()
    };

    // Simulates writes committed while the subscriber process was gone.
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"during".to_vec(), b"2".to_vec()).unwrap();
    }

    let engine = Engine::open(directory.path()).unwrap();
    let missed = engine.read_changes(resume, 100).unwrap();
    assert_eq!(missed.len(), 1);
    assert_eq!(missed[0].key, b"during");
}

#[test]
fn limit_pages_through_the_backlog_without_gaps() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    for index in 0..10_u32 {
        engine
            .put(index.to_be_bytes().to_vec(), vec![index as u8])
            .unwrap();
    }

    let mut cursor = Cursor::start();
    let mut collected = Vec::new();
    loop {
        let page = engine.read_changes(cursor, 3).unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 3);
        cursor = page.last().unwrap().cursor();
        collected.extend(page.into_iter().map(|change| change.key));
    }
    assert_eq!(collected.len(), 10);
    for (index, key) in collected.iter().enumerate() {
        assert_eq!(key.as_slice(), (index as u32).to_be_bytes());
    }
}

#[test]
fn trimmed_cursors_fail_loudly_instead_of_skipping_changes() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
    engine.put(b"b".to_vec(), b"2".to_vec()).unwrap();
    let changes = engine.read_changes(Cursor::start(), 100).unwrap();
    let stale = changes[0].cursor();

    assert_eq!(engine.trim_changes(changes[1].cursor()).unwrap(), 2);
    assert_eq!(engine.change_log_len().unwrap(), 0);

    let error = engine.read_changes(stale, 100).unwrap_err();
    assert!(matches!(error, Error::CursorTooOld { .. }));

    // Positions at or after the retention floor still work.
    assert!(engine.read_changes(changes[1].cursor(), 100).is_ok());

    // New changes after a trim are still delivered.
    engine.put(b"c".to_vec(), b"3".to_vec()).unwrap();
    let after = engine.read_changes(changes[1].cursor(), 100).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].key, b"c");
}

#[test]
fn internal_keys_and_index_entries_are_not_published() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut users = engine
        .collection("users", &[IndexDefinition::new("email", true)])
        .unwrap();
    users
        .put("u1", &json!({"email": "u1@example.com"}))
        .unwrap();
    drop(users);

    let changes = engine.read_changes(Cursor::start(), 100).unwrap();
    assert_eq!(changes.len(), 1, "one document write means one change");
    let target = changes[0]
        .document
        .as_ref()
        .expect("document writes carry a collection and ID");
    assert_eq!(target.collection, "users");
    assert_eq!(target.id, "u1");
    assert!(changes[0].value.is_some());
}

/// A delete that hits nothing mutates nothing, so it must not be published. The
/// change log is built before the engine knows which keys exist, which is how a
/// phantom deletion for a key that never existed reached subscribers: the write
/// itself correctly reported `existed: false` while the log said otherwise.
#[test]
fn a_delete_that_hits_nothing_is_not_published() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();

    assert!(!engine.delete(b"absent").unwrap());
    assert!(
        engine
            .read_changes(Cursor::start(), 100)
            .unwrap()
            .is_empty(),
        "a delete that hit nothing published a change"
    );

    // A batch mixes hits and misses, and only the hits may publish.
    engine.put(b"live".to_vec(), b"1".to_vec()).unwrap();
    let from_now = engine.latest_cursor().unwrap();
    engine
        .write_batch(vec![
            BatchOperation::Delete(b"live".to_vec()),
            BatchOperation::Delete(b"absent".to_vec()),
        ])
        .unwrap();
    let changes = engine.read_changes(from_now, 100).unwrap();
    assert_eq!(changes.len(), 1, "a missing key published a deletion");
    assert_eq!(changes[0].key, b"live");
    assert_eq!(changes[0].value, None);

    // A key created earlier in the same batch is present by the time the delete
    // runs, so that deletion is real and must publish.
    let from_now = engine.latest_cursor().unwrap();
    engine
        .write_batch(vec![
            BatchOperation::Put(b"fresh".to_vec(), b"1".to_vec()),
            BatchOperation::Delete(b"fresh".to_vec()),
        ])
        .unwrap();
    let keys: Vec<_> = engine
        .read_changes(from_now, 100)
        .unwrap()
        .into_iter()
        .map(|change| (change.key, change.value))
        .collect();
    assert_eq!(
        keys,
        vec![
            (b"fresh".to_vec(), Some(b"1".to_vec())),
            (b"fresh".to_vec(), None),
        ],
        "a delete of a key created in the same batch was not published"
    );
}

/* THE CHANGE RECORD SHARES THE CALLER'S VALUE BUDGET, and these two tests are
 * the shape of that. Both are `#[ignore]`d because they fail today: they record
 * a known defect executably rather than only in prose, so the fix is verified by
 * removing an attribute instead of by writing the test from scratch after the
 * fact. Run them with `cargo test -p vyrn-core --test change_log -- --ignored`.
 *
 * Every commit appends one extra put whose value is `encode_batch` of every
 * published key and value in the batch. That blob is validated against the same
 * `MAX_VALUE_SIZE` the caller's own values were checked against, so the record's
 * framing — four count bytes, nine per entry, plus each key — is charged to the
 * caller's budget without being visible in it.
 *
 * The fix needs the record split across several keys, which touches cursor
 * semantics at five read sites (`read_changes`, `published_cursor`, the retained
 * count, `trim_changes`, and the eight-byte suffix `change_log_sequence`
 * demands), and per-commit indices have to stay continuous across the parts or
 * every cursor a subscriber holds becomes wrong. Raising the cap for this one
 * value is NOT the fix: the WAL payload validator independently rejects an
 * operation over `MAX_VALUE_SIZE` during replay, so a commit that succeeded
 * would fail its own recovery. See `todo.md`.
 */

#[test]
#[ignore = "known defect: the change record is charged to the caller's value budget"]
fn a_single_value_of_the_documented_maximum_size_commits() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();

    /* Not a batch problem, and this is the case that shows it: ONE put of
     * exactly the advertised maximum. It fails by 21 bytes — the record's own
     * count field, its per-entry header, and this key — so the limit the README
     * and `MAX_VALUE_SIZE` both name is unreachable by any caller. Measured:
     * `MAX_VALUE_SIZE - 21` is the largest value that actually commits. */
    let result = engine.put(b"k".to_vec(), vec![7; vyrn_core::MAX_VALUE_SIZE]);
    assert!(
        result.is_ok(),
        "a value of exactly MAX_VALUE_SIZE must commit: {result:?}"
    );
}

#[test]
#[ignore = "known defect: the change record is charged to the caller's value budget"]
fn a_batch_of_individually_legal_values_commits() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();

    // Sixteen values, each a sixteenth of the limit. The cap scales with the
    // size of the BATCH rather than of any value in it, so this overshoots by
    // roughly the per-entry framing.
    let operations: Vec<_> = (0..16u64)
        .map(|index| BatchOperation::Put(index.to_be_bytes().to_vec(), vec![7; 1 << 20]))
        .collect();
    let result = engine.write_batch(operations);
    assert!(
        result.is_ok(),
        "a batch of individually legal values must commit: {result:?}"
    );
}

#[test]
fn the_largest_committable_value_is_documented_accurately() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();

    /* Guards the number in the docs against drift while the defect above stands.
     * If a change to the record's framing moves this ceiling, this fails and the
     * documented figure gets corrected with it rather than quietly going stale.
     * The overhead is: 4 bytes of entry count, 9 bytes of entry header, and the
     * key itself — 8 bytes here. */
    const OVERHEAD: usize = 4 + 9 + 8;
    let mut engine_ok = |size: usize| {
        engine
            .put(0u64.to_be_bytes().to_vec(), vec![7; size])
            .is_ok()
    };
    assert!(
        engine_ok(vyrn_core::MAX_VALUE_SIZE - OVERHEAD),
        "MAX_VALUE_SIZE minus the change-record overhead must commit"
    );
    assert!(
        !engine_ok(vyrn_core::MAX_VALUE_SIZE - OVERHEAD + 1),
        "one byte more than that must not, or the documented overhead is wrong"
    );
}

#[test]
fn latest_cursor_subscribes_to_future_changes_only() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    engine.put(b"old".to_vec(), b"1".to_vec()).unwrap();

    let from_now = engine.latest_cursor().unwrap();
    assert!(engine.read_changes(from_now, 100).unwrap().is_empty());

    engine.put(b"new".to_vec(), b"2".to_vec()).unwrap();
    let changes = engine.read_changes(from_now, 100).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].key, b"new");
}
