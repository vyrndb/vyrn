//! Splits `apply_batch`'s cost into its phases.
//!
//! The server reports `apply` as one number, measured at ~55 us per request and
//! constant across concurrency, which is what caps write throughput. This drives
//! the engine directly with the load generator's key pattern — one ascending
//! keyspace per simulated client, so a batch lands on as many distinct leaves as
//! it has clients — and prints where that time goes.
use std::time::Instant;
use vyrn_core::{profile, BatchOperation, Engine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let clients: u64 = std::env::var("CLIENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let batches: u64 = std::env::var("BATCHES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let prefill: u64 = std::env::var("PREFILL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let value_size: usize = std::env::var("VALUE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);

    let directory = std::env::temp_dir().join("vyrn-apply-profile");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory)?;
    let mut engine = Engine::open(&directory)?;
    let value = vec![7u8; value_size];

    // Build a tree of realistic depth first; a batch against an empty tree
    // rewrites one leaf and tells you nothing about the steady state.
    let mut op = 0u64;
    while op < prefill {
        let operations: Vec<BatchOperation> = (0..clients)
            .map(|client| {
                BatchOperation::Put(
                    format!("load/{client:04}/{:012}", op / clients).into_bytes(),
                    value.clone(),
                )
            })
            .collect();
        engine.write_batch(operations)?;
        op += clients;
    }

    let before = profile::snapshot();
    let wall = Instant::now();
    for batch in 0..batches {
        let operations: Vec<BatchOperation> = (0..clients)
            .map(|client| {
                BatchOperation::Put(
                    format!("load/{client:04}/{:012}", prefill / clients + batch).into_bytes(),
                    value.clone(),
                )
            })
            .collect();
        engine.write_batch(operations)?;
    }
    let elapsed = wall.elapsed();
    let after = profile::snapshot();

    let delta = |name: &str| -> u64 {
        let a = after.iter().find(|(k, _)| *k == name).map(|(_, v)| *v).unwrap_or(0);
        let b = before.iter().find(|(k, _)| *k == name).map(|(_, v)| *v).unwrap_or(0);
        a - b
    };
    let requests = delta("__requests").max(1);
    let batch_count = delta("__batches").max(1);

    println!(
        "\napply phase budget  clients={clients} value_size={value_size} prefill={prefill}"
    );
    println!(
        "  {requests} requests in {batch_count} batches ({:.1} per batch), wall {:?}",
        requests as f64 / batch_count as f64,
        elapsed
    );
    println!("  {:<12} {:>12} {:>14}", "phase", "us/request", "% of apply");
    let phases = ["change_log", "prestate", "plan", "tree", "mvcc", "wal"];
    let total: u64 = phases.iter().map(|p| delta(p)).sum();
    for phase in phases {
        let ns = delta(phase);
        println!(
            "  {:<12} {:>9.2} us {:>12.1}%",
            phase,
            ns as f64 / requests as f64 / 1000.0,
            if total > 0 { ns as f64 * 100.0 / total as f64 } else { 0.0 }
        );
    }
    println!(
        "  {:<12} {:>9.2} us  (sum of phases, per request)",
        "TOTAL",
        total as f64 / requests as f64 / 1000.0
    );
    let hits = delta("__page_hits");
    let misses = delta("__page_misses");
    let appends = delta("__page_appends");
    println!(
        "  pages: {:.1} appended/request ({:.0} KiB written per request), \
         reads {:.1}/request at {:.1}% cache hit",
        appends as f64 / requests as f64,
        appends as f64 / requests as f64 * 4.0,
        (hits + misses) as f64 / requests as f64,
        if hits + misses > 0 {
            hits as f64 * 100.0 / (hits + misses) as f64
        } else {
            0.0
        }
    );
    Ok(())
}
