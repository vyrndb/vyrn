//! A logical dump has to be a lossless image of the published keyspace.
//!
//! This is the migration path across storage-format changes, so a bug here loses
//! data silently at exactly the moment an operator is trusting it most: the
//! source database is about to be discarded. The cases that matter are the ones
//! that would leave the loss invisible — a paged scan dropping a key at a chunk
//! boundary, a deleted key coming back, or a damaged dump importing as if it
//! were complete.

use std::collections::BTreeMap;
use tempfile::tempdir;
use vyrn_core::{portable, Engine};

fn populate(engine: &mut Engine, count: usize, value_size: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut expected = BTreeMap::new();
    for index in 0..count {
        let key = format!("key/{index:08}").into_bytes();
        let value = vec![(index % 251) as u8; value_size];
        engine.put(key.clone(), value.clone()).unwrap();
        expected.insert(key, value);
    }
    expected
}

fn round_trip(expected: &BTreeMap<Vec<u8>, Vec<u8>>, source: &mut Engine) {
    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    let exported = portable::export(source, &dump).unwrap();
    assert_eq!(exported, expected.len() as u64, "exported pair count");

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    let imported = portable::import(&mut target, &dump).unwrap();
    assert_eq!(imported, expected.len() as u64, "imported pair count");

    for (key, value) in expected {
        assert_eq!(
            target.get(key).unwrap().as_ref(),
            Some(value),
            "key {} did not survive the round trip",
            String::from_utf8_lossy(key)
        );
    }
    // Nothing extra came across either — an export that invented keys would be
    // just as wrong as one that dropped them.
    let scanned = target.scan(None, None, usize::MAX).unwrap();
    let user_keys = scanned
        .iter()
        .filter(|(key, _)| !key.starts_with(b"\0vyrn:"))
        .count();
    assert_eq!(user_keys, expected.len(), "target holds extra user keys");
}

#[test]
fn round_trips_an_empty_database() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    round_trip(&BTreeMap::new(), &mut engine);
}

#[test]
fn round_trips_across_scan_chunk_boundaries() {
    // The exporter pages the scan, and a resume that is off by one either drops
    // the boundary key or repeats it. 9,000 pairs crosses several chunks.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let expected = populate(&mut engine, 9_000, 32);
    round_trip(&expected, &mut engine);
}

#[test]
fn round_trips_values_that_live_outside_the_page() {
    // Values above the inline limit are stored in the value log, so the export
    // has to resolve them rather than copy a reference that means nothing to a
    // different database.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let expected = populate(&mut engine, 64, 8 * 1024);
    round_trip(&expected, &mut engine);
}

#[test]
fn deleted_keys_do_not_come_back() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut expected = populate(&mut engine, 500, 32);
    for index in (0..500).step_by(3) {
        let key = format!("key/{index:08}").into_bytes();
        assert!(engine.delete(&key).unwrap());
        expected.remove(&key);
    }
    round_trip(&expected, &mut engine);
}

#[test]
fn overwritten_keys_export_their_latest_value() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut expected = populate(&mut engine, 200, 32);
    for index in 0..200 {
        let key = format!("key/{index:08}").into_bytes();
        let value = vec![0xAB; 64];
        engine.put(key.clone(), value.clone()).unwrap();
        expected.insert(key, value);
    }
    round_trip(&expected, &mut engine);
}

#[test]
fn internal_bookkeeping_is_not_exported() {
    // Tombstones and the change log live under the reserved prefix. Carrying them
    // would tie the dump to internal layout and could resurrect deletions.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut expected = populate(&mut engine, 100, 32);
    let doomed = b"key/00000042".to_vec();
    assert!(engine.delete(&doomed).unwrap());
    expected.remove(&doomed);

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    let exported = portable::export(&engine, &dump).unwrap();
    assert_eq!(exported, expected.len() as u64);

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    portable::import(&mut target, &dump).unwrap();
    assert_eq!(target.get(&doomed).unwrap(), None, "deleted key came back");
}

#[test]
fn documents_survive_a_round_trip() {
    // Documents are stored under the reserved prefix, so an exporter that filters
    // the way the public scan does drops the entire collection and still reports
    // success. That is the silent loss this format exists to prevent.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    {
        let mut people = engine.collection("people", &[]).unwrap();
        people
            .put("ada", &serde_json::json!({"name": "Ada", "born": 1815}))
            .unwrap();
        people
            .put("alan", &serde_json::json!({"name": "Alan", "born": 1912}))
            .unwrap();
    }

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    assert_eq!(portable::export(&engine, &dump).unwrap(), 2);

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    assert_eq!(portable::import(&mut target, &dump).unwrap(), 2);

    let people = target.open_collection("people").unwrap();
    let ada = people.get("ada").unwrap().expect("document was lost");
    assert_eq!(ada.value["born"], serde_json::json!(1815));
    assert!(people.get("alan").unwrap().is_some(), "document was lost");
}

#[test]
fn rebuilding_indexes_after_an_import_makes_documents_findable() {
    // A dump carries documents but not the index entries derived from them, so
    // an imported document is readable by ID and invisible to `find`. That is a
    // wrong answer rather than an error, which is the worst shape for a bug in a
    // migration path, so the repair has to work and has to be idempotent.
    use vyrn_core::document::IndexDefinition;

    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let indexes = vec![IndexDefinition::new("email", true)];
    {
        let mut users = engine.collection("users", &indexes).unwrap();
        users
            .put("ada", &serde_json::json!({"email": "ada@x"}))
            .unwrap();
    }

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    portable::export(&engine, &dump).unwrap();

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    target.collection("users", &indexes).unwrap();
    portable::import(&mut target, &dump).unwrap();

    // Before the rebuild the document is present but unfindable, which is the
    // trap this exists to close.
    {
        let users = target.open_collection("users").unwrap();
        assert!(users.get("ada").unwrap().is_some(), "document was lost");
        assert!(
            users
                .find("email", &serde_json::json!("ada@x"), 10)
                .unwrap()
                .is_empty(),
            "an import unexpectedly carried index entries"
        );
    }

    assert_eq!(
        vyrn_core::document::rebuild_indexes(&mut target, "users").unwrap(),
        1
    );
    // Twice, because an operator who is unsure whether the first run finished
    // will run it again, and a rebuild that doubled entries would break the
    // unique index it just repaired.
    vyrn_core::document::rebuild_indexes(&mut target, "users").unwrap();

    let users = target.open_collection("users").unwrap();
    let found = users
        .find("email", &serde_json::json!("ada@x"), 10)
        .unwrap();
    assert_eq!(found.len(), 1, "rebuild did not make the document findable");
    assert_eq!(found[0].id, "ada");
}

#[test]
fn a_dump_cannot_write_vyrns_own_bookkeeping() {
    // A dump is an ordinary file an operator may have edited or received. If it
    // could carry reserved keys, a crafted one would plant tombstones or index
    // entries that the engine treats as its own.
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    populate(&mut engine, 4, 8);
    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    portable::export(&engine, &dump).unwrap();

    // Splice a tombstone record in ahead of the real ones.
    let original = std::fs::read(&dump).unwrap();
    let key = b"\0vyrn:tombstone:key/00000001".to_vec();
    let mut forged = original[0..9].to_vec();
    forged.extend_from_slice(&(key.len() as u32).to_be_bytes());
    forged.extend_from_slice(&key);
    forged.extend_from_slice(&0u32.to_be_bytes());
    forged.extend_from_slice(&original[9..]);
    std::fs::write(&dump, &forged).unwrap();

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    assert!(
        portable::import(&mut target, &dump).is_err(),
        "a dump wrote a reserved key"
    );
}

#[test]
fn a_damaged_dump_is_refused_rather_than_partially_imported() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    populate(&mut engine, 300, 32);

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    portable::export(&engine, &dump).unwrap();

    // Flip a byte in the middle of the record stream.
    let mut bytes = std::fs::read(&dump).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    std::fs::write(&dump, &bytes).unwrap();

    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    let result = portable::import(&mut target, &dump);
    assert!(
        result.is_err(),
        "a corrupted dump imported as if it were complete"
    );
}

#[test]
fn a_foreign_file_is_refused() {
    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("not-a-dump");
    std::fs::write(&dump, b"this is not a Vyrn dump at all").unwrap();
    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    assert!(portable::import(&mut target, &dump).is_err());
}
