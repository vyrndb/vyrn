//! Temporary probe: where does `concurrent_visibility` spend 871 seconds?
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier, RwLock,
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use vyrn_core::{BatchOperation, Engine, ReadEngine};

/// Same shape as `concurrent_visibility`, but timing the writer's refresh
/// acquisition separately from its commit, with spinning readers present.
#[test]
fn measure_with_spinning_readers() {
    let directory = tempdir().unwrap();
    let engine = Arc::new(RwLock::new(Engine::open(directory.path()).unwrap()));
    let readers: Vec<_> = (0..4)
        .map(|_| RwLock::new(ReadEngine::open(directory.path()).unwrap()))
        .collect();
    let readers = Arc::new(readers);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(5));
    let reads = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();

    for index in 0..4 {
        let readers = Arc::clone(&readers);
        let stop = Arc::clone(&stop);
        let barrier = Arc::clone(&barrier);
        let reads = Arc::clone(&reads);
        handles.push(thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                let reader = readers[index].read().unwrap();
                reader.scan(None, None, 64).unwrap();
                for key in 0..16_u32 {
                    reader.get(&key.to_be_bytes()).unwrap();
                }
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    let rounds = 20_u32;
    let writer = {
        let engine = Arc::clone(&engine);
        let readers = Arc::clone(&readers);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let mut commit_total = Duration::ZERO;
            let mut refresh_total = Duration::ZERO;
            let mut worst_refresh = Duration::ZERO;
            for round in 0..rounds {
                let operations = (0..4_u32)
                    .map(|slot| {
                        BatchOperation::Put(
                            (slot + (round % 4) * 4).to_be_bytes().to_vec(),
                            vec![round as u8; 96],
                        )
                    })
                    .collect();

                let start = Instant::now();
                let (generation, root, len) = {
                    let mut engine = engine.write().unwrap();
                    engine.write_batch(operations).unwrap();
                    engine.committed_root()
                };
                commit_total += start.elapsed();

                let start = Instant::now();
                for reader in readers.iter() {
                    reader
                        .write()
                        .unwrap()
                        .refresh(generation, root, len)
                        .unwrap();
                }
                let elapsed = start.elapsed();
                refresh_total += elapsed;
                worst_refresh = worst_refresh.max(elapsed);
            }
            (commit_total, refresh_total, worst_refresh)
        })
    };

    let wall = Instant::now();
    let (commit_total, refresh_total, worst_refresh) = writer.join().unwrap();
    let wall = wall.elapsed();
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle.join().unwrap();
    }

    println!("--- {rounds} rounds with 4 spinning readers ---");
    println!("wall clock:            {wall:?}");
    println!("per round commit:      {:?}", commit_total / rounds);
    println!("per round refresh x4:  {:?}", refresh_total / rounds);
    println!("worst single refresh:  {worst_refresh:?}");
    println!("reader iterations:     {}", reads.load(Ordering::Relaxed));
}
