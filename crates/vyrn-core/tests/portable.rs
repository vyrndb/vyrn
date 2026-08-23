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

/// The standard reflected CRC-32 the engine's checksums use, computed bitwise.
///
/// Reimplemented because `crc32fast` is not a dev-dependency and these tests
/// must produce trailers byte-identical to an export's; the polynomial, the
/// initial and final XOR are the zlib parameters every CRC-32 tool agrees on.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Builds a well-formed dump from raw pairs — magic, version, framing, trailer
/// with a correct pair count and checksum — so tests can craft inputs no export
/// would ever produce while keeping everything around them honest.
fn build_dump(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"VYRNDUMP");
    out.push(1);
    let mut covered = Vec::new();
    for (key, value) in pairs {
        covered.extend_from_slice(key);
        covered.extend_from_slice(value);
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(pairs.len() as u64).to_be_bytes());
    out.extend_from_slice(&crc32(&covered).to_be_bytes());
    out
}

/// Imports `bytes` as a dump into a fresh engine, asserting the import is
/// refused and the target still holds nothing — a half-imported database is
/// precisely what a refused import must never leave behind, because the CLI's
/// fresh-directory requirement makes it unreachable for a retry.
fn assert_refused_and_empty(dump: &std::path::Path, why: &str) {
    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    let result = portable::import(&mut target, dump);
    assert!(result.is_err(), "{why}: the damaged dump imported");
    let scanned = target.scan(None, None, usize::MAX).unwrap();
    assert!(
        scanned.is_empty(),
        "{why}: the failed import left {} pairs behind",
        scanned.len()
    );
}

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
    let original = std::fs::read(&dump).unwrap();

    // A flipped byte in the middle of the record stream: the checksum damage
    // the format's threat model assumes.
    let mut flipped = original.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0xFF;
    std::fs::write(&dump, &flipped).unwrap();
    assert_refused_and_empty(&dump, "a bit-flipped dump");

    // A truncated tail — an interrupted copy. The trailer is what proves the
    // whole file arrived, so losing any of it must refuse too.
    std::fs::write(&dump, &original[..original.len() - 1]).unwrap();
    assert_refused_and_empty(&dump, "a truncated dump");

    // And the same truncation taken well into the body, where hundreds of
    // pairs would have been applied before the old reader ever reached the
    // trailer and noticed.
    std::fs::write(&dump, &original[..original.len() / 2]).unwrap();
    assert_refused_and_empty(&dump, "a half-truncated dump");
}

/// Lengths in a dump are untrusted input: a twelve-byte file declaring a
/// four-gibibyte key used to be honoured with `vec![0; len]` and could abort
/// the process inside the allocator. The caps are the engine's own write
/// limits, so anything larger is damaged-dump error however intact the framing.
#[test]
fn an_untrustworthy_length_is_refused_rather_than_allocated() {
    // A legal key at exactly the engine's limit still imports; one byte over is
    // refused. This pins the boundary to MAX_KEY_SIZE rather than to some
    // arbitrary local cap.
    let boundary_key = vec![b'k'; 64 * 1024];
    let legal = build_dump(&[(boundary_key.clone(), b"v".to_vec())]);
    let dump_path = tempdir().unwrap();
    let dump = dump_path.path().join("boundary.vyrnl");
    std::fs::write(&dump, &legal).unwrap();
    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    assert_eq!(portable::import(&mut target, &dump).unwrap(), 1);

    let oversized_key = build_dump(&[(vec![b'k'; 64 * 1024 + 1], b"v".to_vec())]);
    std::fs::write(&dump, &oversized_key).unwrap();
    assert_refused_and_empty(&dump, "an over-limit key length");

    let oversized_value = build_dump(&[(b"k".to_vec(), vec![b'v'; 16 * 1024 * 1024 + 1])]);
    std::fs::write(&dump, &oversized_value).unwrap();
    assert_refused_and_empty(&dump, "an over-limit value length");

    // The allocation abort itself: a declared length with no bytes behind it.
    // This must die at the cap check, not in `vec![0; 0xFFFF_FFFF]`.
    let mut lying = Vec::new();
    lying.extend_from_slice(b"VYRNDUMP");
    lying.push(1);
    lying.extend_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&dump, &lying).unwrap();
    assert_refused_and_empty(&dump, "a key length that lies about the file's size");
}

/// The physical backup reader refuses bytes after its footer; a logical dump is
/// held to the same rule, because trailing data means a splice or a different
/// file wearing this one's trailer.
#[test]
fn trailing_data_after_the_trailer_is_refused() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    populate(&mut engine, 10, 32);

    let dump_dir = tempdir().unwrap();
    let dump = dump_dir.path().join("dump.vyrnl");
    portable::export(&engine, &dump).unwrap();
    let mut bytes = std::fs::read(&dump).unwrap();
    bytes.extend_from_slice(b"a passenger after the trailer");
    std::fs::write(&dump, &bytes).unwrap();

    assert_refused_and_empty(&dump, "a dump with trailing data");
}

/// Import writes document pairs as raw bytes under the reserved prefix, so the
/// document layer never validates them on the way in: without a check here a
/// crafted dump plants documents that surface as errors on every later read.
/// Import must enforce what the document layer enforces on write.
#[test]
fn a_document_that_would_fail_at_read_time_is_refused_at_import() {
    // `document_change_key` builds keys exactly as the document layer does, so
    // the crafted pairs below are indistinguishable from stored documents by
    // shape alone.
    let ada = vyrn_core::document::document_change_key("people", "ada").unwrap();

    let cases = [
        (b"{not json at all".to_vec(), "invalid JSON"),
        (b"[1, 2, 3]".to_vec(), "JSON but not an object"),
    ];
    for (value, why) in cases {
        let dump_path = tempdir().unwrap();
        let dump = dump_path.path().join("forged.vyrnl");
        std::fs::write(&dump, build_dump(&[(ada.clone(), value)])).unwrap();
        assert_refused_and_empty(&dump, why);
    }

    // A malformed document key gets the same treatment: it can never be read
    // back as a document, so accepting it would plant unreachable bytes.
    let malformed = b"\0vyrn:doc:not-length-prefixed".to_vec();
    let dump_path = tempdir().unwrap();
    let dump = dump_path.path().join("malformed.vyrnl");
    std::fs::write(
        &dump,
        build_dump(&[(malformed, b"{\"ok\": true}".to_vec())]),
    )
    .unwrap();
    assert_refused_and_empty(&dump, "a malformed document key");

    // And the mirror case: a hand-built dump carrying a perfectly ordinary
    // document must still import, proving the validation tracks the document
    // layer instead of merely rejecting everything.
    let genuine = serde_json::to_vec(&serde_json::json!({"name": "Ada", "born": 1815})).unwrap();
    let dump_path = tempdir().unwrap();
    let dump = dump_path.path().join("genuine.vyrnl");
    std::fs::write(&dump, build_dump(&[(ada.clone(), genuine)])).unwrap();
    let target_dir = tempdir().unwrap();
    let mut target = Engine::open(target_dir.path()).unwrap();
    assert_eq!(portable::import(&mut target, &dump).unwrap(), 1);
    let people = target.open_collection("people").unwrap();
    let stored = people
        .get("ada")
        .unwrap()
        .expect("document was not planted");
    assert_eq!(stored.value["born"], serde_json::json!(1815));
}

/// Batches flush on accumulated bytes as well as pair count. Values may legally
/// reach 16 MiB each, so a count-only trigger of 512 pairs buffered up to eight
/// gibibytes of importer memory at once; these twelve values cross the byte
/// trigger mid-import, which the old rule never left the ground for.
#[test]
fn batches_flush_on_accumulated_bytes_not_only_on_count() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    let mut expected = BTreeMap::new();
    for index in 0..12u8 {
        let key = format!("big/{index:03}").into_bytes();
        let value = vec![index; 1024 * 1024];
        engine.put(key.clone(), value.clone()).unwrap();
        expected.insert(key, value);
    }
    round_trip(&expected, &mut engine);
}

/// An export truncates its output, so a path spelled like engine state — or
/// anywhere under a wal directory — must be refused before `File::create`
/// destroys something irreplaceable.
#[test]
fn export_refuses_to_truncate_a_file_vyrn_owns() {
    let directory = tempdir().unwrap();
    let mut engine = Engine::open(directory.path()).unwrap();
    populate(&mut engine, 4, 8);

    let scratch = tempdir().unwrap();
    let manifest = scratch.path().join("CURRENT");
    std::fs::write(&manifest, b"manifest bytes").unwrap();
    let segment = scratch.path().join("00000000000000000001.vwal");
    std::fs::write(&segment, b"segment bytes").unwrap();
    let log = scratch.path().join("overflow.vlog");
    std::fs::write(&log, b"log bytes").unwrap();

    assert!(portable::export(&engine, &manifest).is_err());
    assert!(portable::export(&engine, &segment).is_err());
    assert!(portable::export(&engine, &log).is_err());
    // Inside a wal/ directory counts even under an innocent name.
    let wal_directory = scratch.path().join("wal");
    std::fs::create_dir(&wal_directory).unwrap();
    let hidden = wal_directory.join("dump.vyrnl");
    assert!(portable::export(&engine, &hidden).is_err());

    // Clean refusal: every victim byte-for-byte intact, nothing planted.
    assert_eq!(std::fs::read(&manifest).unwrap(), b"manifest bytes");
    assert_eq!(std::fs::read(&segment).unwrap(), b"segment bytes");
    assert_eq!(std::fs::read(&log).unwrap(), b"log bytes");
    assert!(!hidden.exists(), "the export created a file inside wal/");
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
