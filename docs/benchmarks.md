# Comparative benchmarks

Run Vyrn and PostgreSQL on the same Linux host, storage device, CPU power policy, and idle system. The harness uses durable Vyrn and PostgreSQL 17 with `synchronous_commit`, `fsync`, and `full_page_writes` enabled.

```bash
bash scripts/benchmark-compare-linux.sh
```

The default matrix covers:

- 1, 16, 64, and 256 persistent clients;
- 128 B, 4 KiB, 64 KiB, and 1 MiB values;
- point reads, durable upserts, 70/30 read/write mix, four-key transactions, and non-unique index equality lookup;
- throughput plus p50, p95, p99, p99.9, and maximum request latency.

Each matrix cell starts fresh Vyrn and PostgreSQL databases. Connection and fixture setup time is excluded from the measurements. Results are written to a timestamped ignored CSV file at the repository root.

Override the matrix for a quick run:

```bash
CLIENT_MATRIX='1 16' \
VALUE_SIZE_MATRIX='128 4096' \
MODES='read mixed transaction' \
OPERATIONS=5000 \
RESULTS=/tmp/vyrn-comparison.csv \
  bash scripts/benchmark-compare-linux.sh
```

The PostgreSQL runner needs Docker and publishes its temporary instance on port `15432` by default. Override `POSTGRES_PORT`, `POSTGRES_CONTAINER`, or `DOCKER` when needed. The scripts delete only the temporary container and temporary Vyrn directory they create.

## Measured 2026-07-25 (WSL2, 32 cores, 15 GB RAM, ext4)

16 clients, 128-byte values, 600 operations per client, both databases durable
with `fsync` and `synchronous_commit` enabled. These are development-machine
numbers on WSL2, not deployment guarantees.

| Workload | Vyrn | PostgreSQL 17 | Ratio |
| --- | ---: | ---: | ---: |
| Point reads | 76,844/s (p50 204 µs) | 9,404/s (p50 968 µs) | 8.2× faster |
| Index equality lookup | 11,302/s (p50 1.4 ms) | 9,708/s (p50 960 µs) | 1.2× faster |
| 70/30 mixed | 4,919/s | 4,820/s | about even |
| Durable writes | 1,088/s (p50 10 ms) | 5,066/s (p50 2.4 ms) | 4.7× slower |
| Four-key transactions | 65/s (p50 295 ms) | 1,303/s (p50 6.9 ms) | 20× slower |

Vyrn leads on point reads and index lookups and roughly matches PostgreSQL on the
mixed workload. It remains behind on durable single-row writes and well behind on
multi-key transactions.

### Fixed

- **Page cache thrashing.** Copy-on-write appends entered the cache and evicted
  read-hot pages under FIFO replacement, so index lookups degraded from ~42k/s to
  ~24/s once unrelated writes had run. The cache is now a second-chance clock
  where a reader touch protects a page for one eviction pass.
- **Index lookups on the write lock.** `IndexLookup` and the document read paths
  went through the shared `Engine` behind an `RwLock`; they now run on the same
  dedicated `ReadEngine` handles as `get` and `scan`.
- **A change-log scan on every commit.** `latest_published_cursor` scanned the
  whole change log with `usize::MAX` to find its last key, making each commit cost
  O(total changes). The engine now records what a commit published, and the tree
  can seek the greatest key under a prefix directly.
- **Per-commit MVCC sweep.** Releasing a transaction snapshot ran a full history
  collection under the write lock; that is left to the background GC task.
- **No group commit for transactions.** The write worker batched single-key writes
  but not transactions, so every transaction paid its own `fsync`. Transactions
  now group-commit, with each one still validated against its own snapshot and
  against earlier writes in the same batch.

### Remaining bottlenecks

- **Multi-key transactions are the largest gap.** Each commit still serializes on
  the single writer, and the durable change log doubles the writes per commit.
  PostgreSQL amortizes far more aggressively across concurrent committers.
- **Durable single-row writes** are bounded by one `fsync` per group; the batch
  window (`VYRN_WRITE_BATCH_DELAY_US`) trades latency for throughput.
- Write-heavy p95/p99 latencies remain spiky (46–50 ms at p95) because
  checkpoint compaction runs under the write lock.

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
