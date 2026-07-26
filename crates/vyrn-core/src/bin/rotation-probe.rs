//! Does WAL segment rotation stall a commit?
//!
//! A 256-client run showed p999 218 ms against a max of 9.37 s — a handful of
//! extreme outliers rather than general queueing — while a bare `fdatasync` on
//! the same filesystem never exceeded 243 ms during that run. So the stall is
//! Vyrn's own and it is rare. Rotation is a rare event that holds the WAL
//! writer lock, which makes it the obvious suspect.
//!
//! This drives the engine directly with a small segment size, so rotations are
//! frequent and countable, and reports the slowest commits alongside where the
//! rotations fell.
use std::time::Instant;
use vyrn_core::{BatchOperation, Engine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let segment_size: u64 = std::env::var("SEGMENT_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 * 1024 * 1024);
    let batches: u64 = std::env::var("BATCHES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let keys_per_batch: u64 = std::env::var("KEYS_PER_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let value_size: usize = std::env::var("VALUE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);

    let directory = std::env::temp_dir().join("vyrn-rotation-probe");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory)?;
    let mut engine = Engine::open_with_segment_size(&directory, segment_size)?;
    let value = vec![7u8; value_size];

    let mut timings: Vec<(u64, u128)> = Vec::with_capacity(batches as usize);
    for batch in 0..batches {
        let operations: Vec<BatchOperation> = (0..keys_per_batch)
            .map(|k| {
                BatchOperation::Put(
                    format!("load/{k:04}/{batch:012}").into_bytes(),
                    value.clone(),
                )
            })
            .collect();
        let started = Instant::now();
        engine.write_batch(operations)?;
        timings.push((batch, started.elapsed().as_micros()));
    }

    let mut sorted: Vec<u128> = timings.iter().map(|(_, us)| *us).collect();
    sorted.sort_unstable();
    let pick = |p: f64| sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)];

    let segments = std::fs::read_dir(directory.join("wal"))
        .map(|entries| entries.count())
        .unwrap_or(0);

    println!(
        "\nsegment_size={} KiB  batches={} keys/batch={}",
        segment_size / 1024,
        batches,
        keys_per_batch
    );
    println!("  WAL segments on disk: {segments}");
    println!(
        "  commit latency: p50={}us p95={}us p99={}us p999={}us max={}us",
        pick(0.50),
        pick(0.95),
        pick(0.99),
        pick(0.999),
        sorted.last().unwrap()
    );
    let mut slowest = timings.clone();
    slowest.sort_by_key(|(_, us)| std::cmp::Reverse(*us));
    println!("  slowest 10 commits (batch index -> us):");
    for (batch, us) in slowest.iter().take(10) {
        println!("    batch {batch:6} -> {us:>10} us");
    }
    let over_100ms = sorted.iter().filter(|us| **us > 100_000).count();
    let over_1s = sorted.iter().filter(|us| **us > 1_000_000).count();
    println!("  commits over 100ms: {over_100ms}   over 1s: {over_1s}");
    let _ = std::fs::remove_dir_all(&directory);
    Ok(())
}
