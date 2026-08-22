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
