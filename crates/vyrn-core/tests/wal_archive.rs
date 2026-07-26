use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tempfile::tempdir;
use vyrn_core::wal_archive::archive_pending;
use vyrn_core::{DurabilityMode, Engine, EngineOptions, Error};

/// Segment ids present in a directory, ascending. Reimplemented from the file
/// naming convention (`{id:020}.vwal`) because the crate's own lister is
/// private and these tests must observe the directory the way an external
/// archiver process would.
fn segment_ids(directory: &Path) -> Vec<u64> {
    let mut ids: Vec<u64> = std::fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|extension| extension == "vwal")
            {
                Some(path.file_stem().unwrap().to_str().unwrap().parse().unwrap())
            } else {
                None
            }
        })
        .collect();
    ids.sort_unstable();
    ids
}

fn segment_path(directory: &Path, id: u64) -> PathBuf {
    directory.join(format!("{id:020}.vwal"))
}

/// Writes enough small commits at a tiny segment size to seal several
/// segments, then closes the engine.
fn fill(path: &Path, seed: u8) {
    let mut engine = Engine::open_with_segment_size(path, 128).unwrap();
    for index in 0..20u8 {
        engine
            .put(
                format!("key-{index}").into_bytes(),
                vec![seed.wrapping_add(index); 40],
            )
            .unwrap();
    }
}

/// The active segment is the only file recovery may later truncate in place,
/// so archiving it would capture bytes that can legally change; and a re-run
/// driven by a timer must not redo finished work, or every tick would rewrite
/// the whole archive and its index.
#[test]
fn archive_pending_is_idempotent_and_skips_the_active_segment() {
    let database = tempdir().unwrap();
    let store = tempdir().unwrap();
    let archive = store.path().join("archive");
    fill(database.path(), 0);
    let wal_directory = database.path().join("wal");
    let segments = segment_ids(&wal_directory);
    let highest = *segments.last().unwrap();
    assert!(segments.len() >= 3, "expected several sealed segments");

    let watermark = archive_pending(&wal_directory, &archive).unwrap();
    assert_eq!(watermark, highest - 1);
    let sealed: Vec<u64> = segments[..segments.len() - 1].to_vec();
    assert_eq!(segment_ids(&archive), sealed);
    assert!(!segment_path(&archive, highest).exists());

    let index_bytes = std::fs::read(archive.join("ARCHIVE")).unwrap();
    let mtimes: Vec<SystemTime> = sealed
        .iter()
        .map(|&id| {
            std::fs::metadata(segment_path(&archive, id))
                .unwrap()
                .modified()
                .unwrap()
        })
        .collect();

    let second = archive_pending(&wal_directory, &archive).unwrap();
    assert_eq!(second, watermark);
    assert_eq!(segment_ids(&archive), sealed);
    // The index embeds per-copy timestamps, so byte-identical index contents
    // prove no segment was re-recorded; unchanged mtimes prove none was
    // re-copied.
    assert_eq!(std::fs::read(archive.join("ARCHIVE")).unwrap(), index_bytes);
    let mtimes_after: Vec<SystemTime> = sealed
        .iter()
        .map(|&id| {
            std::fs::metadata(segment_path(&archive, id))
                .unwrap()
                .modified()
                .unwrap()
        })
        .collect();
    assert_eq!(mtimes_after, mtimes);
}

/// Once pages are checkpointed, an unarchived sealed segment is the only copy
/// of its LSN range anywhere. The old checkpoint deleted every sealed segment
/// unconditionally, so a checkpoint racing a slow archiver would silently
/// destroy history the archive can never recover.
#[test]
fn checkpoint_retains_unarchived_segments() {
    let database = tempdir().unwrap();
    let wal_directory = database.path().join("wal");
    let watermark = Arc::new(AtomicU64::new(0));
    let mut engine = Engine::open_with_options(
        database.path(),
        EngineOptions {
            segment_size: 128,
            archived_through: Some(Arc::clone(&watermark)),
            ..EngineOptions::default()
        },
    )
    .unwrap();
    for round in 0..3u8 {
        for index in 0..8u8 {
            engine
                .put(format!("key-{round}-{index}").into_bytes(), vec![index; 40])
                .unwrap();
        }
        let before = segment_ids(&wal_directory);
        engine.checkpoint().unwrap();
        let after = segment_ids(&wal_directory);
        // A watermark of 0 means nothing is archived, so every pre-checkpoint
        // segment must survive, and the id space must stay gap-free — a hole
        // would make the WAL unlistable on the next open.
        for id in &before {
            assert!(
                after.contains(id),
                "checkpoint deleted unarchived segment {id}"
            );
        }
        let full: Vec<u64> = (after[0]..=*after.last().unwrap()).collect();
        assert_eq!(after, full, "checkpoint left a gap in the segment ids");
    }

    // Raise the watermark part-way: the next checkpoint may now delete exactly
    // the ids the archiver claims to hold, and nothing above them.
    let segments = segment_ids(&wal_directory);
    let highest = *segments.last().unwrap();
    let through = highest - 2;
    assert!(through >= 1);
    watermark.store(through, Ordering::Release);
    engine.checkpoint().unwrap();
    let survivors = segment_ids(&wal_directory);
    let new_highest = *survivors.last().unwrap();
    let expected: Vec<u64> = (through + 1..=new_highest).collect();
    assert_eq!(survivors, expected);
    drop(engine);

    // With no archiver configured the barrier must not exist at all: a
    // checkpoint deletes everything below the fresh active segment, exactly
    // the pre-archiving behavior operators without archiving rely on for
    // disk-space reclamation.
    let plain = tempdir().unwrap();
    let plain_wal = plain.path().join("wal");
    let mut engine = Engine::open_with_segment_size(plain.path(), 128).unwrap();
    for index in 0..8u8 {
        engine
            .put(format!("key-{index}").into_bytes(), vec![index; 40])
            .unwrap();
    }
    assert!(segment_ids(&plain_wal).len() >= 2);
    engine.checkpoint().unwrap();
    let remaining = segment_ids(&plain_wal);
    assert_eq!(
        remaining.len(),
        1,
        "None watermark should delete all sealed segments"
    );
}

/// Every database numbers segments from 1 with dense LSNs, so a second
/// database pointed at the first one's archive presents fully valid segments
/// under ids the index already holds. Skipping or overwriting them would
/// poison the first timeline's only history while the returned watermark
/// still advances — and a checkpoint then deletes the real bytes locally.
#[test]
fn rejects_reused_segment_id_with_divergent_crc() {
    let first = tempdir().unwrap();
    let second = tempdir().unwrap();
    let store = tempdir().unwrap();
    let archive = store.path().join("archive");
    fill(first.path(), 0);
    fill(second.path(), 99);
    archive_pending(&first.path().join("wal"), &archive).unwrap();
    let error = archive_pending(&second.path().join("wal"), &archive).unwrap_err();
    assert!(
        matches!(error, Error::CorruptBackup(_)),
        "divergent timeline must hard-error, got {error:?}"
    );
}

/// In async mode `last_lsn` runs ahead of the records actually written to the
/// segment file: commits sit in the in-memory buffer until a flush. A rotation
/// that seals the file without draining that buffer stamps the new segment's
/// header with `first_lsn = last_lsn + 1` while the buffered records land
/// after it — a header lie that recovery and the archive scanner both reject.
#[test]
fn forced_rotation_seals_pending_records() {
    let database = tempdir().unwrap();
    let wal_directory = database.path().join("wal");
    let mut engine = Engine::open_with_options(
        database.path(),
        EngineOptions {
            durability: DurabilityMode::Async,
            ..EngineOptions::default()
        },
    )
    .unwrap();
    for index in 0..3u8 {
        engine
            .put(format!("key-{index}").into_bytes(), vec![index; 16])
            .unwrap();
    }
    engine.rotate_for_archive().unwrap();

    let sealed = std::fs::read(segment_path(&wal_directory, 1)).unwrap();
    assert!(
        sealed.len() > 32 + 45,
        "the buffered async records must have been drained into the sealed segment"
    );
    let header_first_lsn = u64::from_be_bytes(sealed[16..24].try_into().unwrap());
    let first_record_lsn = u64::from_be_bytes(sealed[32 + 5..32 + 13].try_into().unwrap());
    assert_eq!(
        first_record_lsn, header_first_lsn,
        "sealed segment's first record contradicts its header first_lsn"
    );
}

/// A timer drives rotation on low-write databases, so an idle tick must not
/// mint an empty segment: a cron firing every minute against a quiet database
/// would otherwise grow the WAL directory without bound.
#[test]
fn rotate_for_archive_is_a_noop_on_an_idle_segment() {
    let database = tempdir().unwrap();
    let wal_directory = database.path().join("wal");
    let mut engine = Engine::open_with_segment_size(database.path(), 1 << 20).unwrap();
    engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
    engine.rotate_for_archive().unwrap();
    let count = segment_ids(&wal_directory).len();
    assert_eq!(count, 2, "the first rotation should have sealed a segment");
    engine.rotate_for_archive().unwrap();
    assert_eq!(
        segment_ids(&wal_directory).len(),
        count,
        "rotating an idle segment must not create a new one"
    );
}

/// A stalled archiver retains sealed segments whose every LSN is already
/// checkpointed. Scanning their bodies at open would make startup
/// O(retained bytes) — and one flipped bit in a semantically dead segment
/// would brick the database. But the same leniency must never extend to
/// segments recovery actually replays: rot there is real data corruption and
/// open must fail closed.
#[test]
fn bitrot_in_dead_retained_segment_still_opens() {
    let database = tempdir().unwrap();
    let wal_directory = database.path().join("wal");
    let watermark = Arc::new(AtomicU64::new(0));
    {
        let mut engine = Engine::open_with_options(
            database.path(),
            EngineOptions {
                segment_size: 128,
                archived_through: Some(Arc::clone(&watermark)),
                ..EngineOptions::default()
            },
        )
        .unwrap();
        for index in 0..8u8 {
            engine
                .put(format!("key-{index}").into_bytes(), vec![index; 40])
                .unwrap();
        }
        // The checkpoint publishes a manifest at the current LSN, so every
        // segment sealed before it is now semantically dead — retained only
        // because the watermark says the archiver has not copied it yet.
        engine.checkpoint().unwrap();
        // Live records after the checkpoint: only the WAL guarantees these,
        // so the segments holding them must still be scanned byte-for-byte.
        for index in 0..3u8 {
            engine
                .put(format!("live-{index}").into_bytes(), vec![index; 40])
                .unwrap();
        }
    }
    let segments = segment_ids(&wal_directory);
    assert!(segments.len() >= 3);
    let oldest = segments[0];
    let last = *segments.last().unwrap();

    // Flip a byte in the dead segment's body, past the 32-byte header. The
    // header must stay intact: recovery still reads it to walk the LSN chain.
    let dead = segment_path(&wal_directory, oldest);
    let mut bytes = std::fs::read(&dead).unwrap();
    assert!(bytes.len() > 40);
    bytes[40] ^= 0xff;
    std::fs::write(&dead, &bytes).unwrap();
    {
        let engine = Engine::open(database.path())
            .expect("bitrot below the checkpoint must not brick the database");
        assert_eq!(engine.get(b"live-0").unwrap(), Some(vec![0; 40]));
    }

    // The same flip in a segment recovery replays must fail closed: these
    // bytes are the only copy of acknowledged post-checkpoint commits.
    let live = segment_path(&wal_directory, last);
    let mut bytes = std::fs::read(&live).unwrap();
    assert!(
        bytes.len() > 32 + 45,
        "the last segment should hold at least one live record"
    );
    // Inside the first record's payload: the framing stays intact, so this is
    // unambiguous corruption rather than a torn tail recovery may truncate.
    bytes[32 + 45 + 2] ^= 0xff;
    std::fs::write(&live, &bytes).unwrap();
    assert!(
        Engine::open(database.path()).is_err(),
        "corruption in a replayed segment must fail closed"
    );
}
