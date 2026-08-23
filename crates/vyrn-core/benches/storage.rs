//! The shape of the workload the external comparison harness measures.
//!
//! This used to be three cases at one value size — a durable put, a 32-key
//! batch, and a cached get, all at 128 B — which is why an external benchmark
//! could report Vyrn five to thirteen times behind its competitors on large
//! values while every case here looked healthy. Nothing at 128 B can see the
//! costs that dominate a 1 MiB commit: the value never leaves the leaf page, so
//! the value log is untouched, the WAL record is a few hundred bytes rather than
//! megabytes, and a stray full-value memcpy is lost in the noise of an
//! `fdatasync`. The matrix below therefore straddles the engine's 1 KiB inline
//! limit in both directions and covers reads, single writes, and batched writes
//! at each size, so a change can be attributed to the size class it actually
//! affected.
//!
//! Absolute numbers here are host-specific — this file is run on Windows as well
//! as Linux, and `fdatasync` costs differ by an order of magnitude between them.
//! What travels between hosts is the ratio between two runs of this file and the
//! deterministic counters in `vyrn_core::profile` (page reads, appends), which is
//! what a claim about a fix should rest on.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use tempfile::TempDir;
use vyrn_core::{BatchOperation, Engine};

/// Value sizes the comparison harness reports.
///
/// 128 B is stored inline in the leaf page; every larger size is written to the
/// value log and referenced from the leaf, which is a different code path with a
/// different cost structure — one that only these rows exercise.
const SIZES: [(&str, usize); 4] = [
    ("128b", 128),
    ("4kib", 4 * 1024),
    ("64kib", 64 * 1024),
    ("1mib", 1024 * 1024),
];

/// How many keys one measured iteration writes, per value size.
///
/// Held roughly constant in bytes rather than in operations: 32 iterations of a
/// 1 MiB put would move 32 MiB per sample and spend the whole benchmark budget
/// on a handful of samples, and criterion's variance estimate needs more samples
/// than that to be worth reading.
fn writes_per_iteration(size: usize) -> u64 {
    match size {
        0..=1_024 => 32,
        1_025..=8_192 => 16,
        8_193..=131_072 => 4,
        _ => 2,
    }
}

/// How many keys one batch may carry, per value size.
///
/// Not just a pacing choice: a batch is currently capped by the change-log
/// record it generates. `Engine::with_change_log` encodes every published key and
/// value of the batch into ONE tree value, and that value is then validated
/// against `MAX_VALUE_SIZE` like any other — so a batch of 16 × 1 MiB values,
/// every one of them individually legal, fails the whole commit with
/// `ValueTooLarge`. This benchmark found that by asking for it; the first version
/// of these rows panicked on a 16 × 1 MiB fixture write. Keeping a batch under
/// ~4 MiB of values stays clear of the ceiling at every size in the matrix.
fn batch_keys(size: usize) -> u64 {
    ((4 * 1024 * 1024 / size.max(1)) as u64).clamp(1, 16)
}

/// How many keys the read and overwrite fixtures hold, per value size.
///
/// Sized by total bytes for the same reason as [`writes_per_iteration`]: 4,000
/// keys of 1 MiB is 4 GiB of fixture per benchmark row. The 128 B and 4 KiB rows
/// keep enough keys for the tree to be several levels deep, which is the only
/// regime where a descent's cost is visible at all.
fn fixture_keys(size: usize) -> u64 {
    match size {
        0..=4_096 => 4_000,
        4_097..=131_072 => 256,
        _ => 32,
    }
}

fn key(index: u64) -> Vec<u8> {
    format!("bench/{index:012}").into_bytes()
}

fn engine() -> (TempDir, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open(directory.path()).unwrap();
    (directory, engine)
}

/// An engine with an 8 MiB write-back buffer, for the rows that measure the
/// WAL-only commit path against the classic per-commit tree rewrite.
fn write_back_engine() -> (TempDir, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_options(
        directory.path(),
        vyrn_core::EngineOptions {
            write_back_buffer: 8 * 1024 * 1024,
            ..vyrn_core::EngineOptions::default()
        },
    )
    .unwrap();
    (directory, engine)
}

/// An engine holding `count` keys of `size` bytes, for the read cases.
///
/// Filled through batches rather than one put at a time so building a fixture
/// large enough to give the tree real depth does not cost one `fdatasync` per
/// key.
fn prefilled(count: u64, size: usize) -> (TempDir, Engine) {
    let (directory, mut engine) = engine();
    let value = vec![7; size];
    let mut written = 0;
    while written < count {
        let batch = (count - written).min(batch_keys(size));
        let operations = (written..written + batch)
            .map(|index| BatchOperation::Put(key(index), value.clone()))
            .collect();
        engine.write_batch(operations).unwrap();
        written += batch;
    }
    (directory, engine)
}

/// One durable put per operation: the acknowledged-write latency path, where
/// every commit pays its own WAL barrier.
fn durable_put(c: &mut Criterion) {
    let mut group = c.benchmark_group("durable_put");
    for (name, size) in SIZES {
        let operations = writes_per_iteration(size);
        group.throughput(Throughput::Bytes(operations * size as u64));
        group.bench_function(name, |bench| {
            bench.iter_batched(
                || (engine(), vec![7; size]),
                |((directory, mut engine), value)| {
                    for index in 0..operations {
                        engine.put(key(index), value.clone()).unwrap();
                    }
                    // Handed back rather than dropped here: criterion drops a
                    // routine's output outside the timed region, and deleting a
                    // temporary directory holding 32 MiB of 1 MiB values costs
                    // more than the writes being measured.
                    (directory, engine)
                },
                BatchSize::PerIteration,
            )
        });
    }
    group.finish();
}

/// The whole iteration's keys in one batch: one barrier, one tree pass, one WAL
/// record. This is the bulk-load path, and the ratio between it and
/// `durable_put` at the same size is how much of a commit is the barrier and how
/// much is the work.
fn durable_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("durable_batch");
    for (name, size) in SIZES {
        // Capped by what one commit can carry, not by the iteration budget: see
        // [`batch_keys`] for the change-log ceiling this stays under.
        let operations = writes_per_iteration(size).min(batch_keys(size));
        group.throughput(Throughput::Bytes(operations * size as u64));
        group.bench_function(name, |bench| {
            bench.iter_batched(
                || {
                    let value = vec![7; size];
                    let batch: Vec<BatchOperation> = (0..operations)
                        .map(|index| BatchOperation::Put(key(index), value.clone()))
                        .collect();
                    (engine(), batch)
                },
                |((directory, mut engine), batch)| {
                    engine.write_batch(batch).unwrap();
                    // See `durable_put`: the fixture teardown must land outside
                    // the timed region.
                    (directory, engine)
                },
                BatchSize::PerIteration,
            )
        });
    }
    group.finish();
}

/// `durable_put` with the write-back buffer on: the same acknowledged-write
/// latency path, minus the per-commit copy-on-write tree rewrite. The gap
/// between this row and `durable_put/128b` is exactly what the tree rewrite
/// costs a commit; what remains here is the WAL barrier plus bookkeeping.
fn durable_put_write_back(c: &mut Criterion) {
    let mut group = c.benchmark_group("durable_put_write_back");
    let size = 128;
    let operations = writes_per_iteration(size);
    group.throughput(Throughput::Bytes(operations * size as u64));
    group.bench_function("128b", |bench| {
        bench.iter_batched(
            || (write_back_engine(), vec![7; size]),
            |((directory, mut engine), value)| {
                for index in 0..operations {
                    engine.put(key(index), value.clone()).unwrap();
                }
                (directory, engine)
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

/// `durable_batch` with the write-back buffer on: one barrier, one WAL record,
/// and no tree pass at all until the buffer flushes.
fn durable_batch_write_back(c: &mut Criterion) {
    let mut group = c.benchmark_group("durable_batch_write_back");
    let size = 128;
    let operations = writes_per_iteration(size).min(batch_keys(size));
    group.throughput(Throughput::Bytes(operations * size as u64));
    group.bench_function("128b", |bench| {
        bench.iter_batched(
            || {
                let value = vec![7; size];
                let batch: Vec<BatchOperation> = (0..operations)
                    .map(|index| BatchOperation::Put(key(index), value.clone()))
                    .collect();
                (write_back_engine(), batch)
            },
            |((directory, mut engine), batch)| {
                engine.write_batch(batch).unwrap();
                (directory, engine)
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

/// Overwrites of keys that already exist, in a tree deep enough to need a real
/// descent.
///
/// A put into a fresh engine rewrites one leaf and touches nothing else; a put
/// into a populated tree rewrites its whole root-to-leaf path and has to read
/// that path first. The second is what a benchmark's steady state measures.
fn overwrite(c: &mut Criterion) {
    let mut group = c.benchmark_group("overwrite_batch");
    for (name, size) in SIZES {
        let keys = fixture_keys(size);
        let per_batch = batch_keys(size);
        group.throughput(Throughput::Bytes(per_batch * size as u64));
        group.bench_function(name, |bench| {
            let (_directory, mut engine) = prefilled(keys, size);
            let value = vec![7; size];
            let mut round = 0_u64;
            bench.iter(|| {
                let batch = (0..per_batch)
                    .map(|slot| {
                        BatchOperation::Put(key((round * per_batch + slot) % keys), value.clone())
                    })
                    .collect();
                round += 1;
                engine.write_batch(batch).unwrap()
            })
        });
    }
    group.finish();
}

/// Point reads of keys already in the tree.
///
/// 128 B is answered entirely from the page cache; every larger size costs a
/// value-log read on top of the descent, so these rows separate "the tree is
/// slow to search" from "reading the bytes back is slow".
fn point_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_get");
    for (name, size) in SIZES {
        let keys = fixture_keys(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(name, |bench| {
            let (_directory, engine) = prefilled(keys, size);
            let mut index = 0_u64;
            bench.iter(|| {
                let value = engine.get(&key(index % keys)).unwrap();
                index += 1;
                std::hint::black_box(value)
            })
        });
    }
    group.finish();
}

/// Reads of a hot key range while copy-on-write commits churn elsewhere.
///
/// The other read rows all fit their whole tree in the page cache, so none of
/// them can see an eviction policy at all. This one deliberately does not: the
/// cache is set small enough that the fixture does not fit, and then a read-hot
/// subset competes with a stream of commits whose rewritten pages are admitted to
/// the same cache. That is the case where admitting freshly appended pages as
/// referenced — which `PageManager::append` did, contradicting its own doc comment
/// — evicts the pages readers are hitting in favour of pages nothing will read
/// again.
fn hot_read_under_writes(c: &mut Criterion) {
    // Read before any engine is opened: the cache size is read once per open.
    let previous = std::env::var("VYRN_PAGE_CACHE_PAGES").ok();
    std::env::set_var("VYRN_PAGE_CACHE_PAGES", "64");
    let mut group = c.benchmark_group("hot_read_under_writes");
    // 128 B only. The point is the page cache, and a size that puts its values in
    // the value log instead of the leaf would measure that log's reads instead.
    let keys = 4_000;
    let (_directory, mut engine) = prefilled(keys, 128);
    let value = vec![7; 128];
    group.bench_function("128b", |bench| {
        let mut round = 0_u64;
        bench.iter(|| {
            // Sixteen reads of a narrow hot range against one commit far away
            // from it, which is the ratio a read-mostly workload runs at.
            for slot in 0..16_u64 {
                std::hint::black_box(engine.get(&key(slot)).unwrap());
            }
            let cold = keys + (round % keys);
            round += 1;
            engine.put(key(cold), value.clone()).unwrap();
        })
    });
    group.finish();
    match previous {
        Some(pages) => std::env::set_var("VYRN_PAGE_CACHE_PAGES", pages),
        None => std::env::remove_var("VYRN_PAGE_CACHE_PAGES"),
    }
}

/// An ordered read of many keys at once, which is what a range query costs.
///
/// Kept at 128 B and 4 KiB only: the point of this case is the per-row cost of
/// walking leaves and materialising values, and at 1 MiB a thousand-row scan is
/// a gigabyte of copying that tells you about memory bandwidth instead.
fn range_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_1000");
    for (name, size) in SIZES.iter().take(2) {
        group.throughput(Throughput::Bytes(1_000 * *size as u64));
        group.bench_function(*name, |bench| {
            let (_directory, engine) = prefilled(4_000, *size);
            bench.iter(|| {
                let rows = engine
                    .scan(Some(&key(1_000)), Some(&key(2_000)), 1_000)
                    .unwrap();
                debug_assert_eq!(rows.len(), 1_000);
                std::hint::black_box(rows)
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    durable_put,
    durable_put_write_back,
    durable_batch,
    durable_batch_write_back,
    overwrite,
    point_get,
    hot_read_under_writes,
    range_scan
);
criterion_main!(benches);
