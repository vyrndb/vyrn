use std::path::{Path, PathBuf};
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, MAX_KEY_SIZE};

/// The newest page file is the one the manifest's checkpoint generation points
/// at (checkpoint deletes the old generation), so every post-checkpoint page
/// sits in its tail.
fn newest_page_file(directory: &Path) -> PathBuf {
    std::fs::read_dir(directory)
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

/// Simulates the only crash the commit path is allowed to suffer: pages
/// appended after `keep` bytes never reached disk while the WAL that
/// acknowledged them did. `keep` must cover the checkpoint image — recovery
/// deliberately refuses to open when pre-checkpoint pages are gone, because no
/// amount of redo can reconstruct them.
fn truncate_page_file(path: &Path, keep: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(keep).unwrap();
    file.sync_all().unwrap();
}

/// The commit path syncs only the WAL, so a crash can leave a committed root
/// whose pages never reached disk. Recovery must reapply the logged mutations
/// instead of trusting that root.
///
/// This truncates the page file to simulate exactly that loss: the WAL still
/// names a root that no longer exists on disk.
#[test]
fn recovers_acknowledged_writes_when_page_tail_is_lost() {
    let directory = tempdir().unwrap();
    let checkpointed;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"one".to_vec()).unwrap();
        engine.checkpoint().unwrap();
        // Only bytes up to here are part of the durable checkpoint image; the
        // crash may drop anything appended afterwards.
        checkpointed = std::fs::metadata(newest_page_file(directory.path()))
            .unwrap()
            .len();
        // Committed after the checkpoint, so only the WAL guarantees these.
        engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
        engine
            .write_batch(vec![
                BatchOperation::Put(b"c".to_vec(), b"three".to_vec()),
                BatchOperation::Delete(b"a".to_vec()),
            ])
            .unwrap();
    }

    let pages = newest_page_file(directory.path());
    let original = std::fs::metadata(&pages).unwrap().len();
    assert!(
        original > checkpointed,
        "post-checkpoint commits should have appended pages"
    );
    // Drop the pages written after the checkpoint. The cut lands on a page
    // boundary only because the checkpoint image is whole pages; a crash that
    // stopped part-way into a page is truncated away by the same open, which
    // `a_partial_page_at_the_tail_is_truncated_on_open` covers separately.
    truncate_page_file(&pages, checkpointed);

    let engine = Engine::open(directory.path()).expect("recovery should redo the lost commits");
    assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
    assert_eq!(engine.get(b"c").unwrap(), Some(b"three".to_vec()));
    assert_eq!(engine.get(b"a").unwrap(), None, "the delete was logged too");
}

/// A crash can stop part-way into a page: pages appended since the last
/// checkpoint never get a barrier of their own, so the kernel may have reached
/// only some of the final page's bytes. `open` used to refuse any non-aligned
/// page file outright, which turned an ordinary power loss into a permanently
/// unopenable database even though redo reconstructs every page the WAL still
/// needs.
#[test]
fn a_partial_page_at_the_tail_is_truncated_on_open() {
    let directory = tempdir().unwrap();
    let checkpointed;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"one".to_vec()).unwrap();
        engine.checkpoint().unwrap();
        checkpointed = std::fs::metadata(newest_page_file(directory.path()))
            .unwrap()
            .len();
        engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
    }
    let pages = newest_page_file(directory.path());
    // The crash stopped 123 bytes into the page after the checkpoint image:
    // shorter than it was, but no whole-page truncation could have produced it.
    let damaged = checkpointed + 123;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&pages)
        .unwrap();
    file.set_len(damaged).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let engine = Engine::open(directory.path())
        .expect("a torn page tail must be repaired on open, not refused");
    assert_eq!(engine.get(b"a").unwrap(), Some(b"one".to_vec()));
    assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
    // Redo re-appends the pages the fragment's page held, so length alone does
    // not prove the truncation — but whatever the file now ends with has to be
    // whole pages, which a refusal (or a pad-to-alignment) would not produce.
    let repaired = std::fs::metadata(&pages).unwrap().len();
    assert_eq!(
        repaired % 4096,
        0,
        "open must leave the page file page-aligned"
    );
}

/// An append that fails part-way (ENOSPC) leaves less than a page at the tail
/// while the manager still counts whole pages only. The next append used to
/// seek to the raw end of the file, landing its page past the fragment — and
/// shifting every later offset with it — so the file came back misaligned and
/// permanently unopenable even though nothing was ever acknowledged.
#[test]
fn an_append_after_a_partial_write_lands_on_the_next_page_boundary() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"first".to_vec(), b"one".to_vec()).unwrap();
        // Simulate the interrupted append: a fragment shorter than a page
        // appears at the tail without the manager being told, exactly as a
        // failed `write_all` leaves the file.
        let pages = newest_page_file(directory.path());
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&pages)
            .unwrap();
        use std::io::Write;
        file.write_all(&[0u8; 100]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        // More writes through the SAME handle: its page cursor is still at the
        // aligned end, and every append must land there rather than past the
        // fragment.
        engine.put(b"second".to_vec(), b"two".to_vec()).unwrap();
        engine.put(b"third".to_vec(), b"three".to_vec()).unwrap();
    }
    let pages = newest_page_file(directory.path());
    let engine = Engine::open(directory.path())
        .expect("appends must resume from the page-aligned end of the file");
    assert_eq!(engine.get(b"first").unwrap(), Some(b"one".to_vec()));
    assert_eq!(engine.get(b"second").unwrap(), Some(b"two".to_vec()));
    assert_eq!(engine.get(b"third").unwrap(), Some(b"three".to_vec()));
    assert_eq!(
        std::fs::metadata(&pages).unwrap().len() % 4096,
        0,
        "the recovered appends leave the file page-aligned"
    );
}

/// The server applies batches with the flush deferred, then flushes once for
/// several batches after dropping the write lock. A write acknowledged that way
/// must be just as durable as one committed inline, including when the page tail
/// is lost and recovery has to redo from the WAL.
#[test]
fn deferred_commits_survive_a_lost_page_tail_once_flushed() {
    let directory = tempdir().unwrap();
    let checkpointed;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"base".to_vec(), b"zero".to_vec()).unwrap();
        engine.checkpoint().unwrap();
        checkpointed = std::fs::metadata(newest_page_file(directory.path()))
            .unwrap()
            .len();

        // Three batches applied without flushing, exactly as the write worker
        // queues them, then one barrier covering all of them.
        let wal = engine.wal();
        let (_, first) = engine
            .write_batch_deferred(vec![BatchOperation::Put(b"a".to_vec(), b"one".to_vec())])
            .unwrap();
        let (_, second) = engine
            .write_batch_deferred(vec![BatchOperation::Put(b"b".to_vec(), b"two".to_vec())])
            .unwrap();
        let (_, third) = engine
            .write_batch_deferred(vec![
                BatchOperation::Put(b"c".to_vec(), b"three".to_vec()),
                BatchOperation::Delete(b"base".to_vec()),
            ])
            .unwrap();
        assert!(first.is_some() && second.is_some(), "a flush is owed");
        // One flush through the highest LSN, which is what the flush stage does.
        wal.sync_through(third.unwrap()).unwrap();
    }

    let pages = newest_page_file(directory.path());
    assert!(std::fs::metadata(&pages).unwrap().len() > checkpointed);
    truncate_page_file(&pages, checkpointed);

    let engine = Engine::open(directory.path()).expect("recovery should redo the flushed commits");
    assert_eq!(engine.get(b"a").unwrap(), Some(b"one".to_vec()));
    assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
    assert_eq!(engine.get(b"c").unwrap(), Some(b"three".to_vec()));
    assert_eq!(engine.get(b"base").unwrap(), None);
}

/// Tombstones never ride the WAL payload — they exist only as page-level
/// mutations derived at apply time — so redo must re-derive them with exactly
/// the commit path's rules. Before the fix a redone database lost every delete
/// revision, and point-in-time restore makes redo the normal path, not the
/// disaster path.
#[test]
fn redo_preserves_delete_revision() {
    let directory = tempdir().unwrap();
    let delete_lsn;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        // Checkpoint while empty so the checkpoint image is exactly the super
        // page and the truncation below drops only post-checkpoint pages.
        engine.checkpoint().unwrap();
        engine.put(b"k".to_vec(), b"v".to_vec()).unwrap();
        assert!(engine.delete(b"k").unwrap());
        delete_lsn = engine.sequence();
    }

    let pages = newest_page_file(directory.path());
    assert!(std::fs::metadata(&pages).unwrap().len() > 4096);
    truncate_page_file(&pages, 4096);

    let engine = Engine::open(directory.path()).expect("recovery should redo the lost commits");
    assert_eq!(engine.get(b"k").unwrap(), None);
    assert_eq!(
        engine.revision(b"k").unwrap(),
        Some(delete_lsn),
        "a redone delete must keep the deleting record's LSN as the key's revision"
    );
    assert!(
        engine.changed_since(b"k", delete_lsn - 1).unwrap(),
        "a watcher standing at the put's LSN must still observe the delete after redo"
    );
}

/// The rejected design shipped tombstones in the WAL payload, where a max-size
/// key's tombstone key (prefix + key) would exceed MAX_KEY_SIZE and fail
/// validate_payload on replay — an acknowledged, fsynced delete would have made
/// the database permanently unopenable. Redo must round-trip the largest legal
/// key instead.
#[test]
fn max_size_key_delete_round_trips_through_redo() {
    let directory = tempdir().unwrap();
    let key = vec![0x6b; MAX_KEY_SIZE];
    let delete_lsn;
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.checkpoint().unwrap();
        engine.put(key.clone(), b"value".to_vec()).unwrap();
        assert!(engine.delete(&key).unwrap());
        delete_lsn = engine.sequence();
    }

    let pages = newest_page_file(directory.path());
    assert!(std::fs::metadata(&pages).unwrap().len() > 4096);
    truncate_page_file(&pages, 4096);

    let engine = Engine::open(directory.path())
        .expect("an acknowledged delete must never make the database unopenable");
    assert_eq!(engine.get(&key).unwrap(), None);
    assert_eq!(engine.revision(&key).unwrap(), Some(delete_lsn));
}

/// Recovery must be idempotent: reopening repeatedly converges on the same state.
#[test]
fn repeated_recovery_is_stable() {
    let directory = tempdir().unwrap();
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        for index in 0..25_u32 {
            engine
                .put(index.to_be_bytes().to_vec(), vec![index as u8; 32])
                .unwrap();
        }
    }
    let expected = {
        let engine = Engine::open(directory.path()).unwrap();
        engine.scan(None, None, usize::MAX).unwrap()
    };
    for _ in 0..3 {
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.scan(None, None, usize::MAX).unwrap(), expected);
    }
}
