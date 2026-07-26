use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, RwLock,
    },
    thread,
};
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, ReadEngine};

/// Independent read handles must never observe a root whose pages are missing.
///
/// The server opens `ReadEngine` handles that read the page file directly, so any
/// write-path buffering has to keep committed pages visible to them. A previous
/// attempt at buffering passed every single-threaded test and then failed
/// instantly against a live server with "page reference is out of bounds"; this
/// exercises that interaction in-process.
#[test]
fn read_handles_never_see_a_root_with_missing_pages() {
    let directory = tempdir().unwrap();
    let engine = Arc::new(RwLock::new(Engine::open(directory.path()).unwrap()));
    let readers: Vec<_> = (0..4)
        .map(|_| RwLock::new(ReadEngine::open(directory.path()).unwrap()))
        .collect();
    let readers = Arc::new(readers);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    for index in 0..4 {
        let readers = Arc::clone(&readers);
        let stop = Arc::clone(&stop);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                {
                    let reader = readers[index].read().unwrap();
                    // Any error here means a published root referenced a page the
                    // reader could not load, which is the failure mode under test.
                    reader.scan(None, None, 64).expect("reader saw a torn root");
                    for key in 0..16_u32 {
                        reader
                            .get(&key.to_be_bytes())
                            .expect("reader saw a torn page");
                    }
                }
                // Drop the read guard and yield before reacquiring.
                //
                // `std::sync::RwLock` gives no writer-preference guarantee, so
                // readers that reacquire in a tight loop can starve the writer
                // almost indefinitely: without this the writer's four `refresh`
                // calls measured 2.39 s per round against a 1.3 ms commit, one
                // taking 6.96 s, and the whole test took 871 s. Yielding also
                // matches a real workload, where requests arrive with gaps
                // rather than back-to-back off a spinning thread.
                thread::yield_now();
            }
        }));
    }

    let writer = {
        let engine = Arc::clone(&engine);
        let readers = Arc::clone(&readers);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            for round in 0..300_u32 {
                let operations = (0..4_u32)
                    .map(|slot| {
                        BatchOperation::Put(
                            (slot + (round % 4) * 4).to_be_bytes().to_vec(),
                            vec![round as u8; 96],
                        )
                    })
                    .collect();
                let (generation, root, len) = {
                    let mut engine = engine.write().unwrap();
                    engine.write_batch(operations).unwrap();
                    engine.committed_root()
                };
                // Publish exactly as the server does, immediately after commit.
                for reader in readers.iter() {
                    reader
                        .write()
                        .unwrap()
                        .refresh(generation, root, len)
                        .expect("refresh must not expose a root whose pages are not readable");
                }
            }
        })
    };

    writer.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle.join().unwrap();
    }

    // Every key written in the final round must be readable through a fresh handle.
    let reader = ReadEngine::open(directory.path()).unwrap();
    let engine = engine.read().unwrap();
    let (generation, root, len) = engine.committed_root();
    let mut fresh = reader;
    fresh.refresh(generation, root, len).unwrap();
    assert!(!fresh.scan(None, None, 64).unwrap().is_empty());
}

/// A read handle opens from the checkpoint manifest and does not replay the WAL,
/// so after a crash it starts behind the engine — at the empty generation-0 root
/// when no checkpoint had run at all. The server used to leave it there until the
/// next commit published a root, so a database that was killed and then only read
/// from answered "not found" for writes it had acknowledged as durable. Whoever
/// opens read handles has to publish the recovered root to them.
#[test]
fn a_fresh_read_handle_is_behind_the_recovered_engine_until_refreshed() {
    let directory = tempdir().unwrap();
    {
        // Dropped without a checkpoint, so recovery is pure WAL replay and no
        // manifest exists — exactly the state a kill leaves behind.
        let mut engine = Engine::open(directory.path()).unwrap();
        engine
            .put(b"smoke/key".to_vec(), b"value".to_vec())
            .unwrap();
        engine
            .put(b"smoke/second".to_vec(), b"durable".to_vec())
            .unwrap();
    }
    assert!(
        !directory.path().join("CURRENT").exists(),
        "this case is only meaningful without a manifest"
    );

    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(
        engine.get(b"smoke/key").unwrap(),
        Some(b"value".to_vec()),
        "replay itself must recover the acknowledged writes"
    );

    let mut reader = ReadEngine::open(directory.path()).unwrap();
    let (generation, root, len) = engine.committed_root();
    reader.refresh(generation, root, len).unwrap();
    assert_eq!(reader.get(b"smoke/key").unwrap(), Some(b"value".to_vec()));
    assert_eq!(
        reader.get(b"smoke/second").unwrap(),
        Some(b"durable".to_vec())
    );
    assert_eq!(reader.scan(None, None, 64).unwrap().len(), 2);
}
