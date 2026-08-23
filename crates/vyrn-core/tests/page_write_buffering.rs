//! A commit's pages are buffered and reach the file as one write; this is the
//! shape that stresses it: a batch that rewrites far more pages than the page
//! cache holds, so its own buffered pages are evicted before the flush, and
//! nothing but the buffer can be the source of what lands on disk.
//!
//! Runs in its own file because the cache size comes from an environment
//! variable read when the engine opens, and setting one is only safe before
//! this process's engine exists.

use vyrn_core::{BatchOperation, Engine};

#[test]
fn a_batch_larger_than_the_page_cache_survives_buffering_and_reopen() {
    // Small enough that one batch's rewrite overflows it many times over.
    std::env::set_var("VYRN_PAGE_CACHE_PAGES", "8");
    let directory = tempfile::tempdir().unwrap();
    let value = vec![7u8; 128];
    {
        let mut engine = Engine::open(directory.path()).unwrap();
        let operations: Vec<BatchOperation> = (0..5_000u32)
            .map(|index| BatchOperation::Put(format!("key/{index:08}").into_bytes(), value.clone()))
            .collect();
        engine.write_batch(operations).unwrap();
        for index in (0..5_000u32).step_by(97) {
            assert_eq!(
                engine.get(format!("key/{index:08}").as_bytes()).unwrap(),
                Some(value.clone()),
                "key {index} must read back within the writing session"
            );
        }
        assert_eq!(engine.len(), 5_000);
    }
    // Everything reached the file at flush time, so a fresh open — which reads
    // only from disk — sees the same database.
    let engine = Engine::open(directory.path()).unwrap();
    assert_eq!(engine.len(), 5_000);
    for index in (0..5_000u32).step_by(431) {
        assert_eq!(
            engine.get(format!("key/{index:08}").as_bytes()).unwrap(),
            Some(value.clone()),
            "key {index} must read back after reopen"
        );
    }
}
