use std::fs;
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine};

/// One past the last byte of a segment that holds a record.
///
/// A segment runs a zero-filled runway ahead of its records so that committing
/// never extends the file. These cases enumerate every position in the log, and
/// the log is the records: damage inside the runway is covered by its own case
/// below, and iterating a megabyte of zeros would take this suite from seconds
/// to hours.
fn record_end(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1)
}

#[test]
fn every_single_byte_truncation_recovers_or_fails_closed() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        for index in 0..8_u32 {
            engine
                .put(format!("key-{index}").into_bytes(), vec![index as u8; 64])
                .unwrap();
        }
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for length in 0..=record_end(&original) {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        fs::write(
            case.path().join("wal/00000000000000000001.vwal"),
            &original[..length],
        )
        .unwrap();
        let result = Engine::open(case.path());
        if let Ok(engine) = result {
            let rows = engine.scan(None, None, usize::MAX).unwrap();
            assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
    }
}

#[test]
fn every_batch_truncation_recovers_all_or_none() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"before".to_vec(), b"present".to_vec()).unwrap();
        engine
            .write_batch(vec![
                BatchOperation::Put(b"a".to_vec(), b"one".to_vec()),
                BatchOperation::Put(b"b".to_vec(), b"two".to_vec()),
                BatchOperation::Delete(b"before".to_vec()),
            ])
            .unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for length in 32..=record_end(&original) {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        fs::write(
            case.path().join("wal/00000000000000000001.vwal"),
            &original[..length],
        )
        .unwrap();
        if let Ok(engine) = Engine::open(case.path()) {
            let a = engine.get(b"a").unwrap();
            let b = engine.get(b"b").unwrap();
            let before = engine.get(b"before").unwrap();
            assert!(
                (a.is_none() && b.is_none())
                    || (a == Some(b"one".to_vec())
                        && b == Some(b"two".to_vec())
                        && before.is_none()),
                "batch was partially recovered at WAL length {length}: a={a:?}, b={b:?}, before={before:?}"
            );
        }
    }
}

#[test]
fn every_record_bit_flip_fails_closed_or_remains_structurally_valid() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    for index in 32..record_end(&original) {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        let mut changed = original.clone();
        changed[index] ^= 1;
        fs::write(case.path().join("wal/00000000000000000001.vwal"), changed).unwrap();
        if let Ok(engine) = Engine::open(case.path()) {
            let _ = engine.scan(None, None, usize::MAX).unwrap();
        }
    }
}

/// Records are written into a zero-filled runway, so a record interrupted by a
/// crash is followed by zeros instead of by end of file. That removed the signal
/// recovery used to recognise a torn tail, and without a replacement an ordinary
/// crash would read as corruption and the database would refuse to open. Every
/// prefix of a record has to come back as "that commit never happened".
#[test]
fn a_record_torn_by_a_crash_truncates_instead_of_failing_to_open() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"first".to_vec(), b"one".to_vec()).unwrap();
        engine.put(b"second".to_vec(), b"two".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let committed = record_end(&fs::read(&wal).unwrap());
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"third".to_vec(), b"three".to_vec()).unwrap();
    }
    let logged = fs::read(&wal).unwrap();
    let full = record_end(&logged);
    assert!(full > committed, "the third put should have been logged");

    for written in 0..full - committed {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        let mut bytes = logged.clone();
        // Whatever the interrupted write never reached is still runway.
        bytes[committed + written..].fill(0);
        fs::write(case.path().join("wal/00000000000000000001.vwal"), bytes).unwrap();

        let engine = Engine::open(case.path()).unwrap_or_else(|error| {
            panic!("a crash {written} bytes into a record failed to open: {error}")
        });
        assert_eq!(engine.get(b"first").unwrap(), Some(b"one".to_vec()));
        assert_eq!(engine.get(b"second").unwrap(), Some(b"two".to_vec()));
        assert_eq!(
            engine.get(b"third").unwrap(),
            None,
            "a record that was never finished must not be applied"
        );
    }
}

/// The other half of that rule: tolerating a torn tail must not become
/// tolerating damage. A record whose bytes are all present is validated in full,
/// so a flip inside one must not quietly truncate the log.
#[test]
fn a_flip_inside_a_complete_record_is_still_corruption() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"first".to_vec(), b"one".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let first = record_end(&fs::read(&wal).unwrap());
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"second".to_vec(), b"two".to_vec()).unwrap();
    }
    let original = fs::read(&wal).unwrap();
    let last = record_end(&original);

    for index in first..last {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        let mut changed = original.clone();
        changed[index] ^= 1;
        fs::write(case.path().join("wal/00000000000000000001.vwal"), changed).unwrap();
        // The four bytes at +17 are the record's declared payload length, and a
        // record header carries no checksum of its own to catch a flip in them:
        // an inflated length makes the frame overrun the log and be truncated as
        // a torn tail. That is pre-existing rather than a cost of the runway —
        // before it, the same flip pushed the frame past end of file and was
        // truncated identically. Closing it needs a header checksum, which is a
        // record format change.
        let declared_length = (first + 17..first + 21).contains(&index);
        match Engine::open(case.path()) {
            Err(_) => {}
            Ok(_) if declared_length => {}
            Ok(engine) => assert_eq!(
                engine.get(b"second").unwrap(),
                Some(b"two".to_vec()),
                "a flip at byte {index} silently dropped a committed record"
            ),
        }
    }
}

/// Damage inside the unused runway must not be mistaken for the end of the log
/// either: it either fails closed or leaves every acknowledged write readable.
#[test]
fn a_flip_in_the_unused_runway_never_drops_a_committed_record() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"first".to_vec(), b"one".to_vec()).unwrap();
        engine.put(b"second".to_vec(), b"two".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let original = fs::read(&wal).unwrap();
    let end = record_end(&original);
    assert!(
        original.len() > end,
        "the segment should carry a zero-filled runway past its records"
    );

    for index in [end, end + 1, (end + original.len()) / 2, original.len() - 1] {
        let case = tempdir().unwrap();
        copy_database(source.path(), case.path());
        let mut changed = original.clone();
        changed[index] ^= 1;
        fs::write(case.path().join("wal/00000000000000000001.vwal"), changed).unwrap();
        if let Ok(engine) = Engine::open(case.path()) {
            assert_eq!(engine.get(b"first").unwrap(), Some(b"one".to_vec()));
            assert_eq!(
                engine.get(b"second").unwrap(),
                Some(b"two".to_vec()),
                "a flip at byte {index} in the runway dropped a committed record"
            );
        }
    }
}

/// A record's fixed header: 4 magic + 1 version + 8 LSN + 4 operation count +
/// 4 payload length + 4 checksum + 8 root + 8 length.
const RECORD_HEADER_BYTES: usize = 45;

fn copy_database(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target.join("wal")).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "LOCK" || entry.file_name() == "wal" {
            continue;
        }
        fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }
    for entry in fs::read_dir(source.join("wal")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), target.join("wal").join(entry.file_name())).unwrap();
    }
}

/// One past the last byte of a segment that holds a record; reused here to
/// reach the page files the same way.
fn newest_page_file(directory: &std::path::Path) -> std::path::PathBuf {
    fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            path.extension()
                .is_some_and(|extension| extension == "vdb")
                .then_some(path)
        })
        .max()
        .expect("a page file should exist")
}

/// A manifest naming a generation whose page file is gone is damage, not an
/// empty database. Opening used to materialise the missing file as a fresh page
/// store and only then fail looking up the root — after writing an empty file
/// over the very name a restored backup could have recovered the real bytes
/// from, leaving the directory permanently broken.
#[test]
fn a_missing_page_file_is_reported_without_being_created() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
        engine.checkpoint().unwrap();
    }
    let case = tempdir().unwrap();
    copy_database(source.path(), case.path());
    let pages = newest_page_file(case.path());
    assert!(pages.exists());
    fs::remove_file(&pages).unwrap();

    let error = match Engine::open(case.path()) {
        Ok(_) => panic!("opening a database whose page file is gone must fail"),
        Err(error) => error,
    };
    assert!(
        matches!(error, vyrn_core::Error::CorruptManifest(_)),
        "a missing generation's page file must be reported as corruption, got {error:?}"
    );
    assert!(
        !pages.exists(),
        "opening must not recreate the page file it failed to find"
    );
}

/// A write-back cache can persist a multi-page record's tail while losing its
/// head. The frame then lies wholly inside the last byte the writer touched, so
/// the overrun rule never sees it, and an ordinary crash used to read as fatal
/// corruption: a database lost to a power cut rather than to damage. An all-zero
/// header is the unwritten page's signature — the runway ahead of the records is
/// zero-filled, and no bit flip produces forty-five zero bytes — so recovery
/// treats exactly that as a torn tail in the ACTIVE segment: everything from the
/// torn record on is discarded, which is sound because a record whose head was
/// lost can never have been acknowledged, and nothing after it can either.
#[test]
fn a_record_whose_head_page_never_persisted_truncates_instead_of_failing_to_open() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"first".to_vec(), b"one".to_vec()).unwrap();
    }
    let wal = source.path().join("wal/00000000000000000001.vwal");
    let committed = record_end(&fs::read(&wal).unwrap());
    {
        let mut engine = Engine::open(source.path()).unwrap();
        engine.put(b"second".to_vec(), b"two".to_vec()).unwrap();
    }
    let logged = fs::read(&wal).unwrap();
    let full = record_end(&logged);
    assert!(full > committed, "the second put should have been logged");

    // The crash kept the second record's tail but not its head.
    let mut torn = logged.clone();
    torn[committed..committed + RECORD_HEADER_BYTES].fill(0);
    assert!(
        torn[committed + RECORD_HEADER_BYTES..full]
            .iter()
            .any(|byte| *byte != 0),
        "the tail must survive for this to be the case the overrun rule misses"
    );

    let case = tempdir().unwrap();
    copy_database(source.path(), case.path());
    fs::write(case.path().join("wal/00000000000000000001.vwal"), torn).unwrap();

    let mut engine = Engine::open(case.path())
        .unwrap_or_else(|error| panic!("a lost head page must not make open fail: {error}"));
    assert_eq!(engine.get(b"first").unwrap(), Some(b"one".to_vec()));
    assert_eq!(
        engine.get(b"second").unwrap(),
        None,
        "a record whose head was lost was never acknowledged and must be discarded"
    );
    let truncated = fs::metadata(case.path().join("wal/00000000000000000001.vwal"))
        .unwrap()
        .len();
    assert!(
        truncated <= committed as u64,
        "replay should have truncated the tail at {committed}, segment is {truncated}"
    );
    // The engine keeps working, and only the surviving records come back.
    engine.put(b"third".to_vec(), b"three".to_vec()).unwrap();
    drop(engine);
    let engine = Engine::open(case.path()).unwrap();
    assert_eq!(engine.get(b"first").unwrap(), Some(b"one".to_vec()));
    assert_eq!(engine.get(b"third").unwrap(), Some(b"three".to_vec()));
    assert_eq!(engine.get(b"second").unwrap(), None);
}

/// The other half of the torn-head rule: sealed segments keep strict validation.
/// Their tails were truncated by the open that sealed them, so a frame that
/// cannot parse in one is historical rot — and rot must stay loud rather than
/// quietly buy a truncated log.
#[test]
fn a_zeroed_head_in_a_sealed_segment_stays_fatal() {
    let source = tempdir().unwrap();
    {
        let mut engine = Engine::open_with_segment_size(source.path(), 1024).unwrap();
        for index in 0..12_u32 {
            engine
                .put(format!("key-{index}").into_bytes(), vec![index as u8; 32])
                .unwrap();
        }
    }
    let wal_directory = source.path().join("wal");
    assert!(
        fs::read_dir(&wal_directory).unwrap().count() >= 2,
        "the workload must rotate so that segment 1 is sealed"
    );
    let sealed = wal_directory.join("00000000000000000001.vwal");
    let mut bytes = fs::read(&sealed).unwrap();
    bytes[32..32 + RECORD_HEADER_BYTES].fill(0);
    fs::write(&sealed, bytes).unwrap();

    let error = match Engine::open(source.path()) {
        Ok(_) => panic!("rot in a sealed segment must not be silently truncated"),
        Err(error) => error,
    };
    assert!(
        matches!(error, vyrn_core::Error::CorruptWal { .. }),
        "a zeroed frame in a sealed segment must be reported as corruption, got {error:?}"
    );
}
