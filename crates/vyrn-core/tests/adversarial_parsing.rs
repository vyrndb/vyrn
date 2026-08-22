//! Every parser that reads bytes Vyrn did not just write, attacked on purpose.
//!
//! The parsers here are the ones an attacker or a failing disk actually reaches:
//! the document key/JSON decoder, the logical dump format, the WAL archive's
//! index and its sealed-segment scanner, the recovery merge, and the change-log
//! record decoder (which a *replica* parses from bytes its primary sent). None of
//! them is protected by the thing that protects the rest of the engine — that the
//! bytes were produced by this build a moment ago. A dump is a file an operator
//! edits or receives; an archive is a directory a backup script assembles; a
//! replication stream comes from a peer that may be running a different build,
//! behind a proxy that reassembled frames wrongly, on memory that rotted.
//!
//! THE BAR, for every case in this file: a clean `Err`, or a bounded and correct
//! parse. Never a panic, never an out-of-bounds index or slice, never an
//! allocation driven by an untrusted length, never a hang, never an arithmetic
//! overflow — `[profile.release]` keeps `overflow-checks` on precisely so that a
//! wraparound in an LSN or a byte offset cannot pass silently, which means an
//! overflow is a panic in release too and counts as a failure here.
//!
//! Three families per parser, because they fail in different places:
//!
//!   * **arbitrary bytes** — random and structured-random payloads, the latter
//!     wearing a valid header so the fuzzing reaches past the magic check;
//!   * **truncation walks** — every prefix of a *valid* artifact, which is what
//!     an interrupted copy or a torn write leaves behind;
//!   * **forged counts and lengths** — `u32::MAX` element counts and payload
//!     lengths, the shape that makes a naive parser reserve absurd amounts before
//!     any per-element check can reject it.
//!
//! Two live defects were found by writing this and are fixed in place, each with
//! its own regression case below: an arithmetic overflow in `verify_archive`'s
//! LSN-chain check, and an unbounded enumeration in `recover_to`'s segment-gap
//! report that hung the process on a forged segment name.

use proptest::prelude::*;
use std::path::Path;
use tempfile::{tempdir, TempDir};
use vyrn_core::{backup, document, portable, recover, replication, wal_archive, Engine};

// ---------------------------------------------------------------------------
// Format constants and builders.
//
// Reimplemented from the on-disk formats rather than imported, for the same
// reason `tests/portable.rs` reimplements CRC-32 and `tests/wal_archive.rs`
// reimplements the segment naming: the crate's own encoders are private, and a
// test that forged its inputs through them could not express a byte sequence the
// encoder refuses to produce — which is exactly the input class this file is
// about.
// ---------------------------------------------------------------------------

const SEGMENT_HEADER_LEN: usize = 32;
const RECORD_HEADER_LEN: usize = 45;
const RECORD_FOOTER_LEN: usize = 8;
const FORMAT_VERSION: u8 = 4;
const OP_PUT: u8 = 1;
const MAX_KEY_SIZE: usize = 64 * 1024;
const MAX_VALUE_SIZE: usize = 16 * 1024 * 1024;
const ARCHIVE_INDEX_ENTRY_LEN: usize = 44;

/// The standard reflected CRC-32 (zlib parameters) the engine's checksums use.
fn crc32(chunks: &[&[u8]]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for chunk in chunks {
        for &byte in *chunk {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }
    !crc
}

fn segment_name(id: u64) -> String {
    format!("{id:020}.vwal")
}

/// A well-formed logical dump: magic, version, framed pairs, and a trailer whose
/// pair count and checksum are correct.
fn build_dump(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"VYRNDUMP".to_vec();
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
    out.extend_from_slice(&crc32(&[&covered]).to_be_bytes());
    out
}

/// One ARCHIVE index entry, in the order `read_index` decodes them.
#[derive(Clone, Copy)]
struct IndexEntry {
    segment_id: u64,
    first_lsn: u64,
    last_lsn: u64,
    byte_len: u64,
    crc: u32,
    archived_at: u64,
}

/// An ARCHIVE index whose header count and trailing checksum are both correct,
/// so every framing check passes and the *contents* are what is under test.
fn build_archive_index(entries: &[IndexEntry]) -> Vec<u8> {
    let mut bytes = b"VARCIDX1".to_vec();
    bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.segment_id.to_be_bytes());
        bytes.extend_from_slice(&entry.first_lsn.to_be_bytes());
        bytes.extend_from_slice(&entry.last_lsn.to_be_bytes());
        bytes.extend_from_slice(&entry.byte_len.to_be_bytes());
        bytes.extend_from_slice(&entry.crc.to_be_bytes());
        bytes.extend_from_slice(&entry.archived_at.to_be_bytes());
    }
    let checksum = crc32(&[&bytes]);
    bytes.extend_from_slice(&checksum.to_be_bytes());
    bytes
}

/// A 32-byte segment header the scanner accepts: magic, version, id, first LSN,
/// and the checksum over the first 24 bytes.
fn build_segment_header(segment_id: u64, first_lsn: u64) -> Vec<u8> {
    let mut header = vec![0u8; SEGMENT_HEADER_LEN];
    header[0..4].copy_from_slice(b"VSEG");
    header[4] = FORMAT_VERSION;
    header[8..16].copy_from_slice(&segment_id.to_be_bytes());
    header[16..24].copy_from_slice(&first_lsn.to_be_bytes());
    let checksum = crc32(&[&header[0..24]]);
    header[24..28].copy_from_slice(&checksum.to_be_bytes());
    header
}

/// One WAL record framed exactly as the engine frames it, carrying a single put.
///
/// This is the shape a primary ships to a replica, so it is also the way an
/// external caller reaches the change-log record decoder and the document
/// decoder: both parse values that arrive as ordinary key/value writes, and
/// `Engine::write_batch` refuses the reserved keys they live under.
fn build_record(lsn: u64, key: &[u8], value: &[u8], root: u64, len: u64) -> Vec<u8> {
    let mut payload = vec![OP_PUT];
    payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(key);
    payload.extend_from_slice(value);

    let total_len = RECORD_HEADER_LEN + payload.len() + RECORD_FOOTER_LEN;
    let mut bytes = vec![0u8; total_len];
    bytes[0..4].copy_from_slice(b"VTXN");
    bytes[4] = FORMAT_VERSION;
    bytes[5..13].copy_from_slice(&lsn.to_be_bytes());
    bytes[13..17].copy_from_slice(&1u32.to_be_bytes());
    bytes[17..21].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let checksum = crc32(&[
        &[FORMAT_VERSION],
        &lsn.to_be_bytes(),
        &1u32.to_be_bytes(),
        &(payload.len() as u32).to_be_bytes(),
        &root.to_be_bytes(),
        &len.to_be_bytes(),
        &payload,
    ]);
    bytes[21..25].copy_from_slice(&checksum.to_be_bytes());
    bytes[25..33].copy_from_slice(&root.to_be_bytes());
    bytes[33..41].copy_from_slice(&len.to_be_bytes());
    bytes[RECORD_HEADER_LEN..RECORD_HEADER_LEN + payload.len()].copy_from_slice(&payload);
    bytes[total_len - RECORD_FOOTER_LEN..total_len - 4]
        .copy_from_slice(&(total_len as u32).to_be_bytes());
    bytes[total_len - 4..].copy_from_slice(b"VEND");
    bytes
}

/// Writes `value` under `key` into a fresh engine through the replication path.
///
/// The reserved-prefix keys that hold documents and change-log records are
/// unreachable from `write_batch`, so a hostile *value* under one of them can
/// only arrive from a peer — which is the honest threat model anyway: a confused
/// primary is the documented reason `replication::verify_record` exists. The
/// framing is verified first, so what reaches the tree is a record whose bytes
/// are beyond reproach and whose *payload contents* are the attack.
fn plant_via_replication(directory: &Path, key: &[u8], value: &[u8]) -> Engine {
    let mut engine = Engine::open(directory).unwrap();
    let (root, len, _) = engine.committed_root();
    let record = build_record(1, key, value, root, len);
    replication::verify_record(&record).expect("the framing must be valid for this to be a test of contents");
    engine.apply_replicated_record(&record).unwrap();
    engine
}

/// A database with a handful of user keys and one document, closed.
fn seeded(directory: &Path) {
    let mut engine = Engine::open(directory).unwrap();
    for index in 0..12u32 {
        engine
            .put(format!("key/{index:04}").into_bytes(), vec![index as u8; 40])
            .unwrap();
    }
    let mut people = engine.collection("people", &[]).unwrap();
    people
        .put("ada", &serde_json::json!({"name": "Ada", "born": 1815}))
        .unwrap();
}

/// A database with several sealed segments and its archive, ready to tamper with.
fn archived(segment_size: u64) -> (TempDir, TempDir, std::path::PathBuf) {
    let database = tempdir().unwrap();
    let store = tempdir().unwrap();
    let archive = store.path().join("archive");
    {
        let mut engine = Engine::open_with_segment_size(database.path(), segment_size).unwrap();
        for index in 0..20u8 {
            engine
                .put(format!("key-{index}").into_bytes(), vec![index; 40])
                .unwrap();
        }
    }
    wal_archive::archive_pending(&database.path().join("wal"), &archive).unwrap();
    (database, store, archive)
}

// ---------------------------------------------------------------------------
// The document parser: keys and stored JSON.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A document key is `\0vyrn:doc:<u16 len><collection><u16 len><id>`, and
    /// both length prefixes come off disk. `change_target` is called on every key
    /// a commit publishes, so a single malformed one would panic the change-log
    /// broadcast rather than fall back to publishing the raw key, which is what
    /// its contract promises. Random bytes and bytes wearing the real prefix are
    /// both fed in; the only acceptable outcomes are a decoded target or `None`.
    #[test]
    fn arbitrary_bytes_are_decoded_or_declined_by_the_document_key_parser(
        raw in prop::collection::vec(any::<u8>(), 0..96),
        length in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        // Family one, unstructured: nothing here even reaches the prefix check
        // most of the time, which is the point — the guard has to hold for a key
        // that is simply not a document key.
        let _ = document::change_target(&raw);
        let _ = document::document_id_from_key("people", &raw);

        // Family one, structured: the real prefix plus a forged length prefix, so
        // the fuzzing lands *inside* the decoder rather than bouncing off its
        // magic. A length of u16::MAX over a two-byte body is the shape that
        // would slice out of bounds if the bound were `<=` instead of `<`.
        let mut key = b"\0vyrn:doc:".to_vec();
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(&body);
        let _ = document::change_target(&key);
        let _ = document::document_id_from_key("people", &key);

        // And with a second segment, so the id decoder is reached with a forged
        // length of its own rather than only the collection decoder.
        let mut two = b"\0vyrn:doc:".to_vec();
        two.extend_from_slice(&(body.len() as u16).to_be_bytes());
        two.extend_from_slice(&body);
        two.extend_from_slice(&length.to_be_bytes());
        two.extend_from_slice(&body);
        let _ = document::change_target(&two);
        let _ = document::document_id_from_key("people", &two);
    }
}

/// Family two for the key parser. A key truncated mid-segment is what a torn
/// page or a botched migration leaves in the tree, and `change_target` must
/// answer `None` for every one of them rather than slicing past the end: the
/// change log calls it on keys it is *about* to publish, so a panic here would
/// take down the commit that produced the key.
#[test]
fn every_prefix_of_a_valid_document_key_parses_or_declines_cleanly() {
    let key = document::document_change_key("people", "ada").unwrap();
    let mut decoded = 0usize;
    for length in 0..=key.len() {
        let prefix = &key[..length];
        // Only the whole key describes this document; a prefix that decoded to a
        // *different* target would mean the encoding is ambiguous, which is worse
        // than a prefix failing to decode at all.
        if let Some(target) = document::change_target(prefix) {
            decoded += 1;
            assert_eq!(length, key.len(), "a truncated document key decoded");
            assert_eq!((target.collection.as_str(), target.id.as_str()), ("people", "ada"));
        }
        // The collection-scoped decoder is held to the same rule; it returns an
        // error rather than an Option, and an error is a clean outcome.
        let _ = document::document_id_from_key("people", prefix);
    }
    assert_eq!(decoded, 1, "exactly the whole key should decode");
}

/// Family three for the key parser: the length prefix is a `u16` promising bytes
/// the key does not carry. `65535` over a short body is the classic
/// forged-length slice, and `0` is the other end — a zero-length segment is
/// rejected outright because it would make two distinct documents share a key.
#[test]
fn a_forged_document_key_segment_length_is_declined_rather_than_sliced() {
    for length in [0u16, 1, 2, 3, 0x7FFF, 0xFFFE, 0xFFFF] {
        let mut key = b"\0vyrn:doc:".to_vec();
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(b"ab");
        assert!(
            document::change_target(&key).is_none(),
            "a segment claiming {length} bytes over a 2-byte body decoded"
        );
        assert!(document::document_id_from_key("ab", &key).is_err());
    }
    // A collection segment that *is* honest, followed by an id segment that is
    // not: the decoder has to keep its footing after one good segment.
    let mut key = b"\0vyrn:doc:".to_vec();
    key.extend_from_slice(&2u16.to_be_bytes());
    key.extend_from_slice(b"ab");
    key.extend_from_slice(&0xFFFFu16.to_be_bytes());
    key.extend_from_slice(b"x");
    assert!(document::change_target(&key).is_none());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// The stored side of the document parser. A document's value is JSON parsed
    /// on every read, and a hostile primary can put any bytes at all under a
    /// document key — `write_batch` refuses reserved keys, replication does not.
    /// Reads must report the damage as an error; nothing may panic, and a
    /// pathologically nested value must not blow the stack, which is why the
    /// depth cases below climb past anything a recursive descent survives
    /// unguarded.
    #[test]
    fn arbitrary_bytes_stored_under_a_document_key_read_back_as_an_error(
        value in prop::collection::vec(any::<u8>(), 0..160),
    ) {
        let directory = tempdir().unwrap();
        let key = document::document_change_key("people", "ada").unwrap();
        let engine = plant_via_replication(directory.path(), &key, &value);
        let collection = engine.open_collection("people").unwrap();
        // Either the bytes happen to be a JSON object (proptest will not find one
        // by chance, but nothing here depends on that) or the read is a clean
        // error. The prohibited outcome is a panic inside the decoder.
        let _ = collection.get("ada");
        let _ = collection.all(16);
        // The change log parses the same key on its way out to subscribers.
        let _ = engine.read_changes(vyrn_core::change_log::Cursor::start(), 16);
    }
}

/// Nesting is the JSON attack that costs nothing to send: a few hundred kilobytes
/// of `[` recurses as deep as the parser allows. `serde_json` caps recursion by
/// default, so this must surface as an ordinary invalid-document error rather
/// than a stack overflow — which is not a catchable panic and would take the
/// process down with it.
#[test]
fn a_pathologically_nested_document_is_an_error_rather_than_a_stack_overflow() {
    let ada = document::document_change_key("people", "ada").unwrap();
    for depth in [128usize, 512, 10_000, 200_000] {
        let mut value = Vec::with_capacity(2 * depth + 8);
        value.extend_from_slice(b"{\"a\":");
        value.extend(std::iter::repeat_n(b'[', depth));
        value.extend(std::iter::repeat_n(b']', depth));
        value.push(b'}');

        // Through import, which is the path an operator drives with a file they
        // did not write, and which validates document JSON before storing it.
        let dump_directory = tempdir().unwrap();
        let dump = dump_directory.path().join("nested.vyrnl");
        std::fs::write(&dump, build_dump(&[(ada.clone(), value.clone())])).unwrap();
        let target_directory = tempdir().unwrap();
        let mut target = Engine::open(target_directory.path()).unwrap();
        let imported = portable::import(&mut target, &dump);
        // 128 levels is legal JSON that serde_json accepts, so it imports; the
        // deeper ones hit the recursion limit and are refused. Both are clean.
        if depth > 128 {
            assert!(imported.is_err(), "{depth} levels of nesting imported");
        }

        // And through replication, which stores the bytes without parsing them,
        // so the depth is met by the *read* decoder instead of the import one.
        let planted_directory = tempdir().unwrap();
        let engine = plant_via_replication(planted_directory.path(), &ada, &value);
        let people = engine.open_collection("people").unwrap();
        if depth > 128 {
            assert!(people.get("ada").is_err(), "{depth} levels read back as valid");
        }
    }
}

// ---------------------------------------------------------------------------
// The portable dump format.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Family one for the dump reader. A dump is the migration path across
    /// storage formats, so it is the one file an operator is *told* to move
    /// between machines and builds — and therefore the one most likely to arrive
    /// damaged, spliced, or hand-edited. Bytes with a valid header are generated
    /// as well as raw ones, because the magic check would otherwise absorb almost
    /// every case before the framing loop is reached.
    #[test]
    fn arbitrary_bytes_are_refused_as_a_logical_dump(
        raw in prop::collection::vec(any::<u8>(), 0..192),
        wear_header in any::<bool>(),
    ) {
        let dump_directory = tempdir().unwrap();
        let dump = dump_directory.path().join("fuzz.vyrnl");
        let bytes = if wear_header {
            let mut bytes = b"VYRNDUMP".to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&raw);
            bytes
        } else {
            raw
        };
        std::fs::write(&dump, &bytes).unwrap();

        let target_directory = tempdir().unwrap();
        let mut target = Engine::open(target_directory.path()).unwrap();
        // An empty dump — header, terminator, zero pairs, matching checksum — is
        // legal and would import zero pairs, so success is not forbidden. What is
        // forbidden is a *partial* import: verify-then-apply means a dump that
        // fails leaves the target byte-for-byte untouched, which is the property
        // that makes a failed import retryable against the fresh directory the
        // CLI insists on.
        if portable::import(&mut target, &dump).is_err() {
            let scanned = target.scan(None, None, usize::MAX).unwrap();
            prop_assert!(
                scanned.is_empty(),
                "a refused dump left {} pairs behind",
                scanned.len()
            );
        }
    }
}

/// Family two for the dump reader: every prefix of a real export, which is what
/// an interrupted `scp` or a filesystem that lost its tail produces. Only the
/// whole file may import. The trailer is what proves the file arrived, so a
/// prefix that imported would mean an operator could discard the source database
/// after loading a dump that was missing its last thousand keys — the exact
/// silent loss this format exists to prevent.
#[test]
fn every_prefix_of_a_valid_dump_is_refused_except_the_whole_file() {
    let source_directory = tempdir().unwrap();
    seeded(source_directory.path());
    let engine = Engine::open(source_directory.path()).unwrap();
    let dump_directory = tempdir().unwrap();
    let dump = dump_directory.path().join("dump.vyrnl");
    let exported = portable::export(&engine, &dump).unwrap();
    let original = std::fs::read(&dump).unwrap();
    assert!(original.len() > 200, "the fixture must be worth walking");

    let scratch = tempdir().unwrap();
    let prefix_path = scratch.path().join("prefix.vyrnl");
    let mut accepted = 0usize;
    for length in 0..=original.len() {
        std::fs::write(&prefix_path, &original[..length]).unwrap();
        let target_directory = tempdir().unwrap();
        let mut target = Engine::open(target_directory.path()).unwrap();
        match portable::import(&mut target, &prefix_path) {
            Ok(pairs) => {
                accepted += 1;
                assert_eq!(length, original.len(), "a dump truncated at {length} imported");
                assert_eq!(pairs, exported);
            }
            Err(_) => {
                // Refused imports write nothing, at every truncation point —
                // including ones well into the body, where a stream-and-apply
                // reader would have committed hundreds of pairs before reaching
                // the trailer it never gets to check.
                let scanned = target.scan(None, None, usize::MAX).unwrap();
                assert!(
                    scanned.is_empty(),
                    "the import refused at length {length} left {} pairs behind",
                    scanned.len()
                );
            }
        }
    }
    assert_eq!(accepted, 1, "exactly the complete dump should import");
}

/// Family three for the dump reader. Twelve crafted bytes can claim a four
/// gibibyte key, and honouring that claim with `vec![0; len]` is an abort inside
/// the allocator rather than a refusal — the failure mode this whole family
/// exists to catch. The trailer's `u64` pair count gets the same treatment: it is
/// compared against what was actually read, never used to reserve.
#[test]
fn forged_dump_lengths_and_counts_are_refused_rather_than_allocated() {
    let dump_directory = tempdir().unwrap();
    let dump = dump_directory.path().join("forged.vyrnl");

    // A declared length with nothing at all behind it, at every field that
    // carries one: the key length, the value length after an honest key, and both
    // at their absolute maximum.
    let mut cases: Vec<(Vec<u8>, &str)> = Vec::new();
    for length in [u32::MAX, u32::MAX - 1, 1 << 31, 1 << 24] {
        let mut key_only = b"VYRNDUMP".to_vec();
        key_only.push(1);
        key_only.extend_from_slice(&length.to_be_bytes());
        cases.push((key_only, "a key length with no bytes behind it"));

        let mut after_key = b"VYRNDUMP".to_vec();
        after_key.push(1);
        after_key.extend_from_slice(&1u32.to_be_bytes());
        after_key.push(b'k');
        after_key.extend_from_slice(&length.to_be_bytes());
        cases.push((after_key, "a value length with no bytes behind it"));
    }

    // Lengths at and just past the engine's own write limits. The boundary
    // matters: the caps must be MAX_KEY_SIZE and MAX_VALUE_SIZE rather than some
    // arbitrary smaller number, or a legal dump would be refused.
    cases.push((
        build_dump(&[(vec![b'k'; MAX_KEY_SIZE + 1], b"v".to_vec())]),
        "a key one byte over the engine's limit",
    ));
    cases.push((
        build_dump(&[(b"k".to_vec(), vec![b'v'; MAX_VALUE_SIZE + 1])]),
        "a value one byte over the engine's limit",
    ));

    // A trailer that lies about how many pairs precede it, in both directions.
    for claimed in [u64::MAX, u64::MAX / 2, 2, 0] {
        let mut bytes = build_dump(&[(b"k".to_vec(), b"v".to_vec())]);
        let end = bytes.len();
        bytes[end - 12..end - 4].copy_from_slice(&claimed.to_be_bytes());
        if claimed != 1 {
            cases.push((bytes, "a trailer that miscounts its pairs"));
        }
    }

    for (bytes, why) in cases {
        std::fs::write(&dump, &bytes).unwrap();
        let target_directory = tempdir().unwrap();
        let mut target = Engine::open(target_directory.path()).unwrap();
        assert!(
            portable::import(&mut target, &dump).is_err(),
            "{why}: the dump imported"
        );
        assert!(
            target.scan(None, None, usize::MAX).unwrap().is_empty(),
            "{why}: the refused import left data behind"
        );
    }

    // The mirror case, so the caps are proven to be the engine's limits and not
    // a blanket refusal: a key at exactly MAX_KEY_SIZE still imports.
    std::fs::write(
        &dump,
        build_dump(&[(vec![b'k'; MAX_KEY_SIZE], b"v".to_vec())]),
    )
    .unwrap();
    let target_directory = tempdir().unwrap();
    let mut target = Engine::open(target_directory.path()).unwrap();
    assert_eq!(
        portable::import(&mut target, &dump).unwrap(),
        1,
        "a key at exactly the engine's limit must still import"
    );
}

// ---------------------------------------------------------------------------
// The WAL archive: the ARCHIVE index, and the sealed-segment scanner.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Family one for the archive index. `ARCHIVE` is a 44-bytes-per-entry table
    /// in a directory an operator's backup script owns — on an NFS mount, in an
    /// object store's local cache, on the disk that just started returning
    /// garbage. It is also the file `verify_archive` reads, which is the command
    /// an operator runs precisely *because* they suspect damage, so a panic here
    /// fires exactly when the tool is needed most.
    #[test]
    fn arbitrary_bytes_are_refused_as_an_archive_index(
        raw in prop::collection::vec(any::<u8>(), 0..160),
        wear_magic in any::<bool>(),
        checksum_it in any::<bool>(),
    ) {
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        std::fs::create_dir_all(&archive).unwrap();
        let mut bytes = if wear_magic {
            let mut bytes = b"VARCIDX1".to_vec();
            bytes.extend_from_slice(&raw);
            bytes
        } else {
            raw
        };
        // Half the cases get a correct trailing checksum, so the fuzzing reaches
        // the entry decoding and the chain checks instead of stopping at the
        // integrity gate. This is the structured half of the family, and it is
        // where the overflow regressed below was actually found.
        if checksum_it && bytes.len() >= 4 {
            let end = bytes.len();
            let checksum = crc32(&[&bytes[..end - 4]]);
            bytes[end - 4..].copy_from_slice(&checksum.to_be_bytes());
        }
        std::fs::write(archive.join("ARCHIVE"), &bytes).unwrap();
        // No segment files exist, so a structurally valid index still fails on
        // the read; the outcome that matters is that it is an outcome at all.
        let _ = wal_archive::verify_archive(&archive);
    }
}

/// Family two for the archive index. The index is published by tmp-write, sync,
/// rename, so a torn one should be impossible — but the rename's durability is
/// exactly what `sync_directory` cannot promise off Unix, and a filesystem that
/// loses a directory entry leaves a prefix behind. Every prefix must read as a
/// clean corruption error; only the whole file verifies.
#[test]
fn every_prefix_of_a_valid_archive_index_is_refused_except_the_whole_file() {
    let (_database, _store, archive) = archived(128);
    let original = std::fs::read(archive.join("ARCHIVE")).unwrap();
    assert!(
        original.len() > 16 + ARCHIVE_INDEX_ENTRY_LEN,
        "the fixture must hold several entries"
    );
    let mut accepted = 0usize;
    for length in 0..=original.len() {
        std::fs::write(archive.join("ARCHIVE"), &original[..length]).unwrap();
        if wal_archive::verify_archive(&archive).is_ok() {
            accepted += 1;
            assert_eq!(length, original.len(), "an index truncated at {length} verified");
        }
    }
    assert_eq!(accepted, 1, "exactly the complete index should verify");
}

/// Family three for the archive index, and the regression for the first defect
/// this suite found.
///
/// `verify_archive` chained its entries with plain adds — `pair[0].last_lsn + 1`,
/// `pair[0].segment_id + 1`. Every one of those fields comes off disk, and the
/// index's own checksum proves only that the bytes are the bytes that were
/// written, not that they describe a real archive. An index whose `last_lsn` is
/// `u64::MAX` therefore panicked with "attempt to add with overflow" instead of
/// reporting the broken chain, in release as well as debug because
/// `[profile.release]` keeps `overflow-checks` on — an abort inside the one
/// command an operator runs to find out whether their archive is sound.
///
/// The forged `u32::MAX` entry count is the other half: it must die on the
/// length-versus-count comparison, never on a reservation for 4.29 billion
/// entries (189 GB at 44 bytes each).
#[test]
fn a_forged_archive_index_count_or_lsn_is_a_clean_error_rather_than_an_overflow() {
    let store = tempdir().unwrap();
    let archive = store.path().join("archive");
    std::fs::create_dir_all(&archive).unwrap();

    // The overflow case: a chain whose predecessor ends at the top of the u64
    // range. Both the LSN add and the segment-id add are exercised.
    let saturating_cases: Vec<Vec<IndexEntry>> = vec![
        vec![
            IndexEntry { segment_id: 1, first_lsn: 1, last_lsn: u64::MAX, byte_len: 0, crc: 0, archived_at: 0 },
            IndexEntry { segment_id: 2, first_lsn: 5, last_lsn: 5, byte_len: 0, crc: 0, archived_at: 0 },
        ],
        vec![
            IndexEntry { segment_id: u64::MAX - 1, first_lsn: 1, last_lsn: u64::MAX, byte_len: 0, crc: 0, archived_at: 0 },
            IndexEntry { segment_id: u64::MAX, first_lsn: u64::MAX, last_lsn: u64::MAX, byte_len: u64::MAX, crc: u32::MAX, archived_at: u64::MAX },
        ],
        vec![
            IndexEntry { segment_id: 1, first_lsn: u64::MAX, last_lsn: u64::MAX, byte_len: 0, crc: 0, archived_at: 0 },
            IndexEntry { segment_id: 2, first_lsn: 0, last_lsn: 0, byte_len: 0, crc: 0, archived_at: 0 },
        ],
    ];
    for entries in saturating_cases {
        std::fs::write(archive.join("ARCHIVE"), build_archive_index(&entries)).unwrap();
        let error = wal_archive::verify_archive(&archive)
            .expect_err("an index with u64::MAX LSNs must be reported, not accepted");
        assert!(
            matches!(error, vyrn_core::Error::CorruptBackup(_)),
            "expected a corrupt-archive error, got {error:?}"
        );
    }

    // The forged-count case. Sixteen bytes of header and a checksum, claiming
    // 4.29 billion 44-byte entries.
    for count in [u32::MAX, u32::MAX - 1, 1 << 30, 1 << 20] {
        let mut bytes = b"VARCIDX1".to_vec();
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        let end = bytes.len();
        let checksum = crc32(&[&bytes[..end - 4]]);
        bytes[end - 4..].copy_from_slice(&checksum.to_be_bytes());
        std::fs::write(archive.join("ARCHIVE"), &bytes).unwrap();
        let error = wal_archive::verify_archive(&archive)
            .expect_err("an index claiming {count} entries in 16 bytes must be refused");
        assert!(
            matches!(error, vyrn_core::Error::CorruptBackup(_)),
            "expected a corrupt-archive error for a count of {count}, got {error:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Family one for the sealed-segment scanner. `archive_pending` is the only
    /// reader that walks a segment with no engine lock held and then declares
    /// those bytes trustworthy enough to ship, so it decides what PITR will later
    /// replay. A valid header is generated for most cases, because the header
    /// check would otherwise reject nearly everything before a single record is
    /// framed.
    #[test]
    fn arbitrary_bytes_are_refused_as_a_sealed_wal_segment(
        body in prop::collection::vec(any::<u8>(), 0..200),
        wear_header in any::<bool>(),
    ) {
        let store = tempdir().unwrap();
        let wal = store.path().join("wal");
        let archive = store.path().join("archive");
        std::fs::create_dir_all(&wal).unwrap();
        let candidate = if wear_header {
            let mut bytes = build_segment_header(1, 1);
            bytes.extend_from_slice(&body);
            bytes
        } else {
            body
        };
        std::fs::write(wal.join(segment_name(1)), &candidate).unwrap();
        // The active segment is never a candidate, so a second file is what makes
        // segment 1 one; its header is valid so the scan under test is segment 1's.
        std::fs::write(wal.join(segment_name(2)), build_segment_header(2, 2)).unwrap();
        // A header with an all-zero runway behind it is a legally empty sealed
        // segment and archives fine, so success is permitted — but only when the
        // archive it produces then verifies end to end, which is what "bounded
        // and correct" means for this parser.
        if wal_archive::archive_pending(&wal, &archive).is_ok() {
            prop_assert!(
                wal_archive::verify_archive(&archive).is_ok(),
                "archive_pending accepted bytes its own verifier rejects"
            );
        }
    }
}

/// Family two for the segment scanner. A sealed segment was synced whole before
/// rotation, so unlike replay the scanner refuses torn tails outright — a prefix
/// of one is not the segment it claims to be.
///
/// "Whole" is not the same as "the whole file", which is what makes this walk
/// worth computing rather than asserting loosely. A sealed segment ends in the
/// unused tail of its zero-filled runway, so a prefix that drops runway bytes is
/// still the same history; and a prefix that stops exactly on a record boundary is
/// a shorter but entirely valid segment, which the scanner accepts because every
/// byte it holds is a complete record. The acceptable lengths are therefore
/// exactly the frame boundaries plus everything from the last record's end
/// onwards — including the bare 32-byte header, which is a legally empty sealed
/// segment. Anything else cuts a record in half and must be refused. Deriving that
/// set here rather than approximating it is what makes the test able to fail.
#[test]
fn every_prefix_of_a_sealed_segment_is_archived_only_when_its_records_are_whole() {
    let (database, _store, _archive) = archived(128);
    let source = std::fs::read(database.path().join("wal").join(segment_name(1))).unwrap();
    assert!(
        source.len() > SEGMENT_HEADER_LEN + RECORD_HEADER_LEN,
        "the fixture segment must hold at least one record"
    );
    // One past the last byte a writer touched: everything above it is runway.
    let written_through = source
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(SEGMENT_HEADER_LEN, |index| index + 1);

    // Every offset at which a record frame starts or ends, walked with the
    // declared lengths exactly as the scanner walks them. The header alone is the
    // first boundary: a segment with no records at all is valid.
    let mut boundaries = vec![SEGMENT_HEADER_LEN];
    let mut offset = SEGMENT_HEADER_LEN;
    while offset + RECORD_HEADER_LEN <= written_through
        && &source[offset..offset + 4] == b"VTXN"
    {
        let payload_len =
            u32::from_be_bytes(source[offset + 17..offset + 21].try_into().unwrap()) as usize;
        offset += RECORD_HEADER_LEN + payload_len + RECORD_FOOTER_LEN;
        boundaries.push(offset);
    }
    assert!(
        boundaries.len() >= 2,
        "the fixture must hold at least one walkable record frame"
    );
    assert_eq!(
        *boundaries.last().unwrap(),
        written_through,
        "the last record should end exactly at the last byte a writer touched"
    );

    let mut accepted = 0usize;
    for length in 0..=source.len() {
        let store = tempdir().unwrap();
        let wal = store.path().join("wal");
        let archive = store.path().join("archive");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join(segment_name(1)), &source[..length]).unwrap();
        // The active segment is never a candidate, so a second file is what makes
        // segment 1 one.
        std::fs::write(wal.join(segment_name(2)), build_segment_header(2, 2)).unwrap();
        let whole_records = boundaries.contains(&length) || length >= written_through;
        match wal_archive::archive_pending(&wal, &archive) {
            Ok(_) => {
                assert!(
                    whole_records,
                    "a segment truncated at {length}, inside a record, was archived"
                );
                // Bounded and correct, not merely non-panicking: whatever the
                // scanner accepted, its own verifier must agree end to end.
                assert!(
                    wal_archive::verify_archive(&archive).is_ok(),
                    "the archive published from a {length}-byte segment does not verify"
                );
                accepted += 1;
            }
            Err(error) => {
                assert!(
                    !whole_records,
                    "a segment truncated at {length}, on a record boundary, was refused: {error:?}"
                );
                assert!(
                    matches!(
                        error,
                        vyrn_core::Error::CorruptWal { .. } | vyrn_core::Error::CorruptBackup(_)
                    ),
                    "a segment truncated at {length} failed with an unexpected error: {error:?}"
                );
            }
        }
    }
    // Sanity on the walk itself: both outcomes have to actually occur, or the
    // test would pass just as happily against a scanner that accepted everything.
    assert!(accepted >= boundaries.len(), "no prefix was accepted");
    assert!(accepted < source.len(), "every prefix was accepted");
}

/// Family three for the segment scanner: a record header whose declared lengths
/// are forged. `payload_len` is the dangerous one — it is what a naive scanner
/// slices with, and `RECORD_HEADER_LEN + payload_len + RECORD_FOOTER_LEN`
/// overflows `usize` on a 32-bit target for a large enough claim.
///
/// This is also the one documented format limitation the suite deliberately does
/// NOT try to fix: the record header carries no checksum of its own, so a flipped
/// bit in `payload_len` cannot be *detected* — closing that needs a format
/// version bump, and `tests/corruption.rs` records the same limitation for
/// replay. What is required here is narrower and still worth pinning: whatever
/// the forged length says, the outcome is a clean error rather than a panic, an
/// out-of-range slice, or a multi-gigabyte allocation.
#[test]
fn a_forged_segment_record_length_is_a_clean_error_rather_than_an_allocation() {
    let store = tempdir().unwrap();
    let wal = store.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();

    for (payload_len, operation_count) in [
        (u32::MAX, 1u32),
        (u32::MAX - 1, u32::MAX),
        (1 << 31, 0),
        (1 << 24, 1 << 24),
        (0, u32::MAX),
        (0, 0),
    ] {
        let mut bytes = build_segment_header(1, 1);
        let mut record = vec![0u8; RECORD_HEADER_LEN + RECORD_FOOTER_LEN];
        record[0..4].copy_from_slice(b"VTXN");
        record[4] = FORMAT_VERSION;
        record[5..13].copy_from_slice(&1u64.to_be_bytes());
        record[13..17].copy_from_slice(&operation_count.to_be_bytes());
        record[17..21].copy_from_slice(&payload_len.to_be_bytes());
        let total = (RECORD_HEADER_LEN + RECORD_FOOTER_LEN) as u32;
        record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 4].copy_from_slice(&total.to_be_bytes());
        record[RECORD_HEADER_LEN + 4..].copy_from_slice(b"VEND");
        bytes.extend_from_slice(&record);

        let archive = store.path().join(format!("archive-{payload_len}-{operation_count}"));
        std::fs::write(wal.join(segment_name(1)), &bytes).unwrap();
        std::fs::write(wal.join(segment_name(2)), build_segment_header(2, 2)).unwrap();
        let error = wal_archive::archive_pending(&wal, &archive).expect_err(
            "a record declaring {payload_len} payload bytes over none must be refused",
        );
        assert!(
            matches!(
                error,
                vyrn_core::Error::CorruptWal { .. } | vyrn_core::Error::CorruptBackup(_)
            ),
            "payload_len {payload_len} / count {operation_count} gave {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Recovery: the merge that adopts archived bytes, and the segment listing.
// ---------------------------------------------------------------------------

/// The regression for the second defect this suite found.
///
/// `recover_to` reports which segment ids a broken merge is missing, and it built
/// that report by enumerating every id in each gap: `for id in pair[0] + 1 ..
/// pair[1] { missing.push(id.to_string()) }`. The ids come from *filenames* in a
/// directory an operator assembled by hand out of a restored backup and an
/// archive, so anything matching `{digits}.vwal` lands in the list. A directory
/// holding segments 1 and `u64::MAX` — a typo, a truncated copy, a hostile
/// tarball — therefore asked for 1.8x10^19 heap-allocated strings and hung the
/// process instead of reporting the gap. `pair[0] + 1` was also a plain add on an
/// untrusted `u64`, so a segment literally named `u64::MAX` overflowed.
///
/// The report is now bounded: a handful of named ids plus a count. The test's
/// proof is that the call *returns at all*.
#[test]
fn a_forged_segment_id_reports_the_gap_instead_of_enumerating_it() {
    for (low, high) in [
        (1u64, u64::MAX),
        (1, u64::MAX - 1),
        (1, 1 << 40),
        (0, u64::MAX),
        // Adjacent, so there is no gap at all: this pair proves the arithmetic is
        // safe on the *boundary* ids rather than only inside a span. It gets past
        // the gap check and is caught by the header read instead, which is the
        // correct outcome and a different code path.
        (u64::MAX - 1, u64::MAX),
    ] {
        let auxiliary = tempdir().unwrap();
        let target = auxiliary.path().join("assembled");
        std::fs::create_dir_all(target.join("wal")).unwrap();
        for id in [low, high] {
            std::fs::write(target.join("wal").join(segment_name(id)), [0u8; 64]).unwrap();
        }
        // The gap's own width, computed the way the fix computes it. Adjacent ids
        // have no gap, and demanding a missing-segment message for them would be
        // asserting the wrong thing.
        let gap = high.saturating_sub(low).saturating_sub(1);
        let error = recover::recover_to(&target, None, None, false)
            .expect_err("a WAL of two zero-filled segments must not recover");
        match error {
            vyrn_core::Error::CorruptBackup(message) => {
                if gap != 0 {
                    assert!(
                        message.contains("missing segment"),
                        "the gap between {low} and {high} was reported as: {message}"
                    );
                }
                // A bounded report, which is the whole fix: the old code's
                // message would have been exabytes of comma-separated integers
                // if it had ever finished building it.
                assert!(
                    message.len() < 512,
                    "the missing-segment report is unbounded ({} bytes)",
                    message.len()
                );
            }
            other => panic!("expected a corrupt-backup error, got {other:?}"),
        }
    }
}

proptest! {
    // Each case builds a database, a base backup, an archive and a restored
    // target, then drives a full recovery — several engine opens and a pile of
    // fsyncs apiece. The repo's usual 48 would dominate the suite's runtime for
    // no extra coverage, so this one runs 24, the same reasoning `pitr.rs` uses.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Family one for the merge. Recovery is the one reader that adopts archived
    /// bytes wholesale under a name replay trusts, so the archived copy is
    /// re-checked against the index checksum on the way in. Here the *index
    /// agrees* with the forged bytes — the attacker rewrote both, which is what a
    /// compromised or simply mis-restored archive directory looks like — so the
    /// checksum gate is bypassed on purpose and the framing walkers meet the
    /// bytes directly.
    #[test]
    fn arbitrary_archived_bytes_adopted_by_recovery_fail_closed(
        archived_bytes in prop::collection::vec(any::<u8>(), 0..192),
    ) {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        {
            let mut engine = Engine::open(database.path()).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.checkpoint().unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        }
        backup::create_backup(database.path(), &backup_file).unwrap();
        {
            let mut engine = Engine::open(database.path()).unwrap();
            engine.put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
            engine.rotate_for_archive().unwrap();
        }
        wal_archive::archive_pending(&database.path().join("wal"), &archive).unwrap();

        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        // The shared segment: present in the base backup as a partial prefix and
        // in the archive as the sealed copy, which is the one case the merge is
        // allowed to overwrite. Forge both the bytes and the index entry that
        // vouches for them.
        std::fs::write(archive.join(segment_name(2)), &archived_bytes).unwrap();
        std::fs::write(
            archive.join("ARCHIVE"),
            build_archive_index(&[IndexEntry {
                segment_id: 2,
                first_lsn: 2,
                last_lsn: 3,
                byte_len: archived_bytes.len() as u64,
                crc: crc32(&[&archived_bytes]),
                archived_at: 0,
            }]),
        )
        .unwrap();

        // Whatever happens, the recovered directory must never claim to have
        // reached a bound it did not: `recover_to` re-opens and compares replay's
        // LSN against the bound, so a success here is a success that was proved.
        if let Ok(reached) = recover::recover_to(&target, Some(&archive), None, true) {
            let engine = Engine::open(&target).unwrap();
            prop_assert_eq!(engine.sequence(), reached);
            prop_assert_eq!(engine.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        }
        std::fs::remove_dir_all(&target).ok();
    }
}

// ---------------------------------------------------------------------------
// The change-log record decoder.
//
// Reached from outside the crate the same way a real hostile record reaches it:
// as the *value* of a change-log key, appended by a primary. A replica parses
// these to serve its own subscribers, so the bytes are as untrusted as any file
// on disk — and unlike a file, they arrive without an operator in the loop.
// ---------------------------------------------------------------------------

/// One commit's change record, encoded as `encode_batch` encodes it: a `u32`
/// entry count, then per entry a presence flag, a `u32` key length, a `u32` value
/// length, the key, and the value.
fn build_change_record(entries: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
    let mut encoded = (entries.len() as u32).to_be_bytes().to_vec();
    for (key, value) in entries {
        encoded.push(u8::from(value.is_some()));
        encoded.extend_from_slice(&(key.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(value.map_or(0, <[u8]>::len) as u32).to_be_bytes());
        encoded.extend_from_slice(key);
        if let Some(value) = value {
            encoded.extend_from_slice(value);
        }
    }
    encoded
}

/// The change-log key a commit at `sequence` is filed under.
fn change_log_key(sequence: u64) -> Vec<u8> {
    let mut key = b"\0vyrn:changelog:".to_vec();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

/// Family three for the change-log decoder, first because it is the case with a
/// known history: a corrupt entry count near `u32::MAX` used to drive
/// `Vec::with_capacity` directly, which is the ~481 GB reservation that aborted
/// the process before any per-entry check could reject it. The clamp is to what
/// the remaining buffer could physically hold, so a forged count is a truncation
/// error and a real batch never notices the clamp.
///
/// Planted through replication rather than constructed in a unit test, because
/// that is the path a hostile record actually travels: framing verified, CRC
/// verified, payload structure verified — and then a value under a reserved key
/// that `write_batch` would have refused outright.
#[test]
fn a_forged_change_log_entry_count_from_a_primary_is_a_clean_error() {
    for value in [
        u32::MAX.to_be_bytes().to_vec(),
        (u32::MAX - 1).to_be_bytes().to_vec(),
        (1u32 << 30).to_be_bytes().to_vec(),
        // A count of one with a header that promises a u32::MAX key.
        {
            let mut bytes = 1u32.to_be_bytes().to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&u32::MAX.to_be_bytes());
            bytes.extend_from_slice(&u32::MAX.to_be_bytes());
            bytes
        },
        // And one with an honest key length and a forged value length, which is
        // the case the decoder's checked adds exist for: on a 32-bit target a
        // plain `offset + key_len + value_len` wraps into a bound that passes.
        {
            let mut bytes = 1u32.to_be_bytes().to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&1u32.to_be_bytes());
            bytes.extend_from_slice(&u32::MAX.to_be_bytes());
            bytes.push(b'k');
            bytes
        },
    ] {
        let directory = tempdir().unwrap();
        let engine = plant_via_replication(directory.path(), &change_log_key(1), &value);
        let error = engine
            .read_changes(vyrn_core::change_log::Cursor::start(), 64)
            .expect_err("a forged change-log record must not decode");
        assert!(
            matches!(error, vyrn_core::Error::CorruptManifest(_)),
            "expected a corrupt-record error, got {error:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Family one for the change-log decoder.
    #[test]
    fn arbitrary_change_log_record_bytes_from_a_primary_are_a_clean_error(
        value in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let directory = tempdir().unwrap();
        let engine = plant_via_replication(directory.path(), &change_log_key(1), &value);
        // An empty record (a four-byte zero count) is a legal batch of nothing, so
        // Ok is permitted; the forbidden outcome is a panic or an allocation
        // driven by the count.
        let _ = engine.read_changes(vyrn_core::change_log::Cursor::start(), 64);
        let _ = engine.latest_published_cursor();
        let _ = engine.change_log_len();
    }
}

/// Family two for the change-log decoder. A change record shares its commit's
/// atomicity, so a truncated one should never exist — but it is stored as an
/// ordinary tree value, which means a torn page or a hostile primary can produce
/// one. Only the whole record may decode: a prefix that decoded would hand a
/// subscriber a commit with some of its mutations silently missing, which is a
/// wrong answer rather than an error and therefore the worst available outcome.
#[test]
fn every_prefix_of_a_valid_change_log_record_decodes_only_in_full() {
    let entries: Vec<(&[u8], Option<&[u8]>)> = vec![
        (b"users/1", Some(&b"active"[..])),
        (b"users/2", None),
        (b"users/3", Some(&b""[..])),
    ];
    let record = build_change_record(&entries);
    let mut accepted = 0usize;
    for length in 0..=record.len() {
        let directory = tempdir().unwrap();
        let engine = plant_via_replication(directory.path(), &change_log_key(1), &record[..length]);
        match engine.read_changes(vyrn_core::change_log::Cursor::start(), 64) {
            Ok(changes) => {
                accepted += 1;
                // The one legal short read is a zero count, which is four bytes
                // of nothing rather than a prefix of these three entries.
                if length == record.len() {
                    assert_eq!(changes.len(), entries.len());
                } else {
                    assert!(
                        changes.is_empty(),
                        "a record truncated at {length} yielded {} of {} changes",
                        changes.len(),
                        entries.len()
                    );
                }
            }
            Err(error) => assert!(
                matches!(error, vyrn_core::Error::CorruptManifest(_)),
                "a record truncated at {length} failed with {error:?}"
            ),
        }
    }
    assert!(accepted >= 1, "the complete record should decode");
}

/// A change-log key whose sequence suffix is the wrong width, and a cursor token
/// whose halves are not hexadecimal. Both are parsed from data a client or a peer
/// supplies — the cursor token is literally a string an HTTP caller passes in a
/// query parameter — so both must be errors rather than slices.
#[test]
fn a_malformed_change_log_key_or_cursor_token_is_an_error_not_a_panic() {
    use vyrn_core::change_log::Cursor;

    // Suffix widths either side of the eight bytes a sequence occupies. A key of
    // exactly eight is well formed and decodes; a wider or narrower one is damage
    // and must be reported rather than sliced.
    //
    // Width 0 is deliberately excluded from the error assertion, and the reason is
    // worth stating because it looks like a miss. A key of the bare prefix sorts
    // strictly *below* the scan's start bound — `read_changes` starts at
    // `prefix + 8` zero bytes for a start cursor — so that key is not in the range
    // being read at all, and answering "no changes" is the correct outcome rather
    // than a swallowed error. It is still planted and still exercised: what is
    // being checked for it is that every change-log entry point tolerates its
    // presence in the tree.
    for width in [0usize, 1, 4, 7, 8, 9, 16, 64] {
        let directory = tempdir().unwrap();
        let mut key = b"\0vyrn:changelog:".to_vec();
        key.extend(std::iter::repeat_n(0xAAu8, width));
        let engine = plant_via_replication(directory.path(), &key, &build_change_record(&[]));
        let read = engine.read_changes(Cursor::start(), 16);
        if width != 8 && width != 0 {
            assert!(
                read.is_err(),
                "a change-log key with a {width}-byte sequence was accepted"
            );
        }
        // Reached whatever the width: these walk the same keys by prefix rather
        // than from a cursor, so the bare-prefix key is in range for them.
        let _ = engine.latest_published_cursor();
        let _ = engine.change_log_len();
    }

    for token in [
        "",
        "-",
        "--",
        "zz-01",
        "0-",
        "-0",
        &"f".repeat(1_024),
        &format!("{}-{}", "f".repeat(64), "f".repeat(64)),
        &format!("{:016x}-{:08x}", u64::MAX, u32::MAX),
    ] {
        // The last case is the maximum legal token and must round-trip; the rest
        // are refusals. Either way, no panic and no overflow parsing the radix.
        match Cursor::parse_token(token) {
            Ok(cursor) => assert_eq!(cursor, Cursor::new(u64::MAX, u32::MAX)),
            Err(error) => assert!(matches!(error, vyrn_core::Error::InvalidCursor(_)), "{error:?}"),
        }
    }
}
