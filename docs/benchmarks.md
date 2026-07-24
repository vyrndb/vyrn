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
| Point reads | 76,248/s (p50 203 µs) | 10,104/s (p50 913 µs) | 7.5× faster |
| Index equality lookup | 26,626/s (p50 591 µs) | 10,032/s (p50 938 µs) | 2.7× faster |
| 70/30 mixed | 3,900/s (p50 316 µs) | 8,960/s (p50 1.1 ms) | 2.3× slower |
| Durable writes | 1,040/s (p50 10.8 ms) | 4,725/s (p50 2.3 ms) | 4.5× slower |
| Four-key transactions | 197/s (p50 74.8 ms) | 1,271/s (p50 6.7 ms) | 6.5× slower |

Vyrn leads clearly on point reads and index lookups. It is still behind on
durable writes and multi-key transactions, and the mixed result varies between
runs because it is write-bound.

Note the median latencies: Vyrn's p50 is lower than PostgreSQL's on every
workload including the mixed one. The throughput gap on write-heavy modes comes
from tail latency, where commits queue behind the single writer's `fsync` pair.

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

### Remaining bottleneck: two fsyncs per commit

The durable commit path syncs pages and the value log, then writes and syncs the
WAL — two barriers per commit, serialized through one writer. That is what keeps
durable writes and transactions behind PostgreSQL, which lets many concurrent
committers share a single WAL flush.

Widening the group-commit window does not help; it makes things worse. Measured
at 16 clients, 600 operations each:

| `VYRN_WRITE_BATCH_DELAY_US` | Writes | Transactions |
| ---: | ---: | ---: |
| 200 | 1,040/s | 193/s |
| 500 | 929/s | 195/s |
| 2000 | 868/s | 122/s |
| 5000 | 833/s | 177/s |

Batching is already saturated at the default window, so the remaining work is
structural: the page sync currently has to precede the WAL write because recovery
adopts the committed root directly from the WAL record rather than replaying
mutations into the tree. Removing that barrier requires redo recovery — replaying
operations from WAL payloads — after which pages could be flushed lazily by a
background writer and only the WAL sync would remain on the commit path. That is
a change to the durability core and is not attempted here.

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
