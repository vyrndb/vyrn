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
    // Drop the pages written after the checkpoint, keeping the file page-aligned.
    truncate_page_file(&pages, checkpointed);

    let engine = Engine::open(directory.path()).expect("recovery should redo the lost commits");
    assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
    assert_eq!(engine.get(b"c").unwrap(), Some(b"three".to_vec()));
    assert_eq!(engine.get(b"a").unwrap(), None, "the delete was logged too");
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
