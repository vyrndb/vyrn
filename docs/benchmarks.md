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

Median of three consecutive runs:

| Workload | Vyrn | PostgreSQL 17 | Ratio |
| --- | ---: | ---: | ---: |
| Point reads | 73,356/s (p50 212 µs) | 9,903/s (p50 923 µs) | 7.4× faster |
| Index equality lookup | 25,899/s (p50 605 µs) | 9,935/s (p50 945 µs) | 2.6× faster |
| 70/30 mixed | 6,043/s (p50 302 µs) | 9,033/s (p50 1.1 ms) | 1.5× slower |
| Durable writes | 2,459/s (p50 5.9 ms) | 6,485/s (p50 2.2 ms) | 2.6× slower |
| Four-key transactions | 225/s (p50 65.8 ms) | 1,121/s (p50 7.1 ms) | 5.0× slower |

Vyrn leads on point reads and index lookups by a wide margin, and its p50 latency
is lower than PostgreSQL's on every workload. It remains behind on durable
writes, the mixed workload, and multi-key transactions.

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

### Also fixed

- **One change-log key per mutation.** The durable change log inserted a separate
  tree key for every mutation, doubling copy-on-write page churn on the write
  path. A commit now writes a single record containing all of its changes, keyed
  by commit sequence, with the per-mutation index carried inside the record.
- **Inline checkpoint compaction.** Whichever client's commit happened to cross
  the write threshold paid to compact the whole tree. Crossing the threshold now
  sets a flag and the background task compacts, then republishes the new
  generation to the read handles.

### Also fixed: one fsync per commit instead of several

The durable commit path used to sync pages and the historical value log before
writing and syncing the WAL. Recovery adopted the committed root straight from
the WAL record, so those page barriers were load-bearing: without them a record
could name a root whose pages never reached disk.

Recovery now redoes logged mutations (`redo_from_checkpoint`) when the committed
root is unreachable, rebuilding from the last checkpoint root — which *is*
guaranteed synced, because the checkpoint manifest is published after its pages.
With that in place the commit path syncs only the WAL. Pages reach disk at the
next checkpoint or on clean shutdown.

Two smaller barriers went with it: page and value-log files now track whether
they are dirty and skip `fsync` entirely when untouched (values under the 1 KiB
inline limit never reach the value log at all), and WAL rotation no longer stats
the segment on every commit.

`tests/redo_recovery.rs` covers this directly by truncating the page file to drop
everything written after a checkpoint, then asserting the acknowledged writes —
including a delete — come back.

### Remaining bottleneck: fsync latency per transaction

The floor on this host is a single flush:

    mean fdatasync: 1.481 ms over 200 calls

At one client a single durable write takes 3.1 ms and a four-key transaction
6.1 ms, so both are dominated by sync barriers rather than by round-trips or
validation. Transaction throughput peaks near 816/s at 16 clients and falls off
at 64, so concurrency past that point adds queueing rather than throughput.

PostgreSQL stays ahead on write-heavy workloads because many concurrent
committers share one WAL flush more effectively than Vyrn's current group commit
does. Closing that gap means coalescing independent transactions into a single
barrier — a genuine concurrent commit pipeline, not further micro-optimisation.
Measurements on a host with faster durable writes than WSL2 would also shift
these ratios.

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
