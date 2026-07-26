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

## Measured 2026-07-26 (WSL2, 32 cores, 15 GB RAM, ext4)

16 clients, 128-byte values, 600 operations per client, both databases durable
with `fsync` and `synchronous_commit` enabled. These are development-machine
numbers on WSL2, not deployment guarantees.

Median of three consecutive runs:

| Workload | Vyrn | PostgreSQL 17 | Ratio |
| --- | ---: | ---: | ---: |
| Point reads | 78,588/s (p50 197 µs) | 10,226/s (p50 916 µs) | 7.7× faster |
| Index equality lookup | 75,780/s (p50 204 µs) | 9,939/s (p50 946 µs) | 7.6× faster |
| 70/30 mixed | 11,102/s (p50 286 µs) | 8,914/s (p50 1.1 ms) | 1.25× faster |
| Four-key transactions | 1,940/s (p50 7.4 ms) | 1,217/s (p50 7.0 ms) | 1.6× faster |
| Durable writes | 3,362/s (p50 4.8 ms) | 6,982/s (p50 2.2 ms) | 2.1× slower |

Vyrn leads on reads, index lookups, and the mixed workload by margins far larger
than this host's run-to-run spread, so those three rows are solid. It is behind on
single-key durable writes, where PostgreSQL commits roughly twice as fast, and
that gap is wide enough to be real too.

The transaction row is the one to be careful with. Vyrn's write-heavy throughput
varies by roughly 2× run to run on this host (see the caveat under the flush
change below), and 1,940/s against 1,217/s is inside that spread. The p50s beside
it, 7.4 ms against 7.0 ms, are the more stable comparison and say something
different from the throughput ratio: the two are close to parity per commit, and
Vyrn's apparent lead is throughput under concurrency, not commit latency.

Two rows moved against the run recorded earlier on this host, both on the
PostgreSQL side: writes measured 6,982/s here against 2,782/s before, and mixed
8,914/s against 4,897/s. That is not a storage-placement artifact — the
`fdatasync` floor inside the PostgreSQL container (1.41 ms) and on the ext4
filesystem serving Vyrn (1.53 ms) are within noise of each other. The earlier
figures did not reproduce, and the earlier write row was internally inconsistent
besides: 2,782/s across 16 clients implies a 5.8 ms mean latency against the
2.6 ms p50 recorded beside it. Treat the numbers above as the current measurement
and the write comparison as a genuine deficit rather than a regression.

PostgreSQL also keeps the lower p50 on both write-heavy workloads. Vyrn's
remaining edge on transactions is throughput, not single-commit latency.

### Fixed: the WAL flush held the write lock

With per-key page rewrites gone, the barrier was the whole commit. Timing the
stages of a 16-client four-key transaction run gave, per commit:

    change log      29 µs
    pre-state read 161 µs
    tree apply     545 µs
    MVCC prepare    79 µs
    WAL encode      18 µs
    WAL write       20 µs
    fdatasync    2,642 µs

So 2.6 ms of a 4.5 ms commit was one `fdatasync`, and it ran with the engine's
write lock held: no other batch could apply its mutations, plan its pages, or
validate itself while a flush was in flight. Every batch also paid its own
barrier.

The flush now happens off the write lock. `Engine::write_batch_deferred` applies a
batch and appends its WAL record but does not flush, returning the LSN that has to
be made durable; the server queues that to a second stage which flushes,
refreshes the read handles, and only then answers the clients. Two descriptors
onto the same segment keep those independent — `Wal::append` takes one, the
`fdatasync` takes the other — so batch N's flush overlaps batch N+1's tree work.
Nothing is acknowledged before its record is durable, which is the property the
whole change has to preserve.

Coalescing then has to be made explicit, and this is the part that is easy to get
wrong. The old blocking flush was *accidentally* batching: while the write worker
sat in `fdatasync`, arriving requests piled up behind it and the next iteration
swept them into one large batch. Pipelining removes that pile-up, and the first
working version of this change doubled the barrier count as a result: 614 batches
became 1,234 for the same 38,400 operations. That counter, not a throughput
reading, is the reliable signal here — it is deterministic, where throughput on
this host is not. Two things fix it:

- The flush stage drains its queue and issues **one** `sync_through` for the
  highest LSN present. A flush covers every record appended before it began, so
  one barrier makes all of those batches durable.
- The write worker keeps accumulating for as long as a barrier is outstanding,
  and stops the moment it lands. Those clients cannot be answered until that
  flush finishes anyway, so the wait costs them nothing, and it is self-tuning:
  slow storage means a long flush and larger batches, fast storage means the wait
  collapses and latency stays low. `VYRN_WRITE_BATCH_DELAY_US` is now only a
  ceiling on that wait rather than an unconditional sleep.

`vyrn_wal_flushes_total` and `vyrn_flushed_batches_total` expose the ratio, so how
much the barrier is actually being amortised is visible rather than inferred.

One smaller cost went with it: the write worker cloned every operation twice on
the way to the engine, once to assemble the batch and once to move it into the
blocking task. At 128 keys per batch that is two copies of every key and value
for nothing.

Measured effect at 16 clients, alternating between the two builds within one
session, five runs each:

| Workload | Before (p50) | After (p50) |
| --- | ---: | ---: |
| Four-key transactions | 7,376 µs | 6,557 µs |
| Single-key writes | 3,876 µs | 3,977 µs |

Transaction p50 improves about 11%, and it improved in every one of the five
paired runs, which is why this is quotable. Single-key writes do not move: that
path commits one small batch at a time, so there is nothing for the barrier to be
amortised across and the change buys it nothing. Reads, index lookups, and the
mixed workload are unchanged, as expected — they never touched the barrier.

Throughput is deliberately not quoted, and the method above is not incidental —
getting it wrong produced three different conclusions on this host. Transaction
throughput ranges from roughly 1,200/s to 2,500/s for *identical* code, single-key
writes from 1,745/s to 4,005/s, and p99 from 9 ms to 104 ms, because WSL2
intermittently stalls a flush for tens of milliseconds. Every misleading result
came from comparing runs taken at different moments: a 19% transaction gain, a 13%
loss, a 45% write gain, and a p99 regression from 11 ms to 41 ms were all
artifacts, and each one disappeared once the two builds were interleaved in one
session rather than benchmarked one after the other. The low outliers occur on the
unmodified baseline at the same rate. Treat the tail numbers in the comparison
table as properties of this host, not of either database.

`tests/redo_recovery.rs` covers the new path directly: three batches applied with
the flush deferred, one barrier for all of them, then the page file truncated to
drop everything after the checkpoint. All three commits plus a delete come back.
`wal.rs` unit tests pin the coalescing rule in both directions — one flush covers
every earlier append, and a record appended after a flush started is not treated
as durable by it.

### Fixed: one copy-on-write path rewrite per key

The dominant write-path cost was not `fsync`. `write_batch` applied each key with
its own `prepare_put`/`prepare_delete` call, and each of those rebuilt the whole
root-to-leaf path as fresh copy-on-write pages. A 64-key batch wrote **133 pages**
— about two per key — and spent ~125 µs per key inside the tree, against a
measured 1.48 ms `fdatasync` floor for the entire batch.

`PageTree::prepare_batch` now applies a whole batch in one descent: mutations are
sorted by key, each affected subtree is visited once, and each touched page is
rewritten once no matter how many keys in the batch land on it. The same 64-key
batch now writes **6 pages**, and the engine-level batch time fell from 10.3 ms to
4.5 ms — at which point the WAL flush really is the largest single component.

Two follow-on costs came from the same per-key pattern and are batched the same way:

- **Pre-commit state reads.** A commit has to know each key's prior value and
  revision (to maintain its entry count, clear tombstones, and record MVCC
  pre-images). That was up to three separate root-to-leaf descents per key, which
  cost 6.5 ms of a 10 ms commit once the tree had grown. `get_many_with_revision`
  resolves the whole batch in one ordered sweep.
- **Transaction validation.** `has_conflict` called `changed_since` per key, and
  each call descended the tree up to twice. `any_changed_since` answers from the
  in-memory MVCC history where possible and batches the remaining tree lookups
  into two sweeps.

Together these took four-key transactions from 225/s to ~1,375/s (6.1×), writes
from 2,459/s to 3,113/s, and the mixed workload from 6,043/s to 10,031/s. Index
lookups also improved sharply, because the tree the readers traverse is far more
compact.

Those throughput figures predate the measurement caveat above and were taken from
consecutive rather than interleaved runs, so the exact ratios should be treated as
approximate. The page-count reduction behind them — 133 pages per 64-key batch down
to 6 — is a deterministic count rather than a timing, and that is what the change
actually rests on.

`tests/batch_model.rs` covers the batched path against a `BTreeMap` model,
including batches that mutate one key repeatedly, delete a key written earlier in
the same batch, and split leaves. That property test caught a real entry-count
corruption during development: the first version of `prepare_batch` counted its
size delta once per mutation rather than once per distinct key, so a batch
touching the same key twice left the tree reporting more entries than it held.

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

### Remaining bottleneck: single-key write latency

The barrier is now off the write lock and shared between committers, so the
remaining write-path gap is per-commit latency rather than throughput. The floor
on this host is one flush:

    mean fdatasync: 1.529 ms over 200 calls

A single-key durable write measures a 3.9–4.8 ms p50 against that 1.5 ms floor,
and PostgreSQL commits the same workload at 2.2 ms. So roughly 2.5–3 ms per write
is still not the barrier, and closing that is the next piece of work — group commit
cannot help here, because this path offers it nothing to group. Two candidates,
neither yet measured:

- **The request's own round trip.** A write crosses an `mpsc` queue to the write
  worker, a `spawn_blocking` hop to take the engine lock, a channel to the flush
  stage, another `spawn_blocking` for the sync, and a `oneshot` back. Point reads
  show what that scaffolding costs at minimum: ~197 µs p50 with no barrier at all.
- **Per-commit work that scales with the tree rather than the batch.** The
  pre-state read and MVCC prepare measured 161 µs and 79 µs at benchmark size;
  both grow with depth, and neither has been profiled on a large tree.

An `fdatasync` is also not independent of what else is dirty. Appending 200 MB to
an unrelated file and never syncing it moved the same WAL flush from 1.73 ms to
2.14 ms on this host, and the measured per-commit sync climbed from 1.99 ms to
2.64 ms over a single benchmark run. Pages are deliberately left for the
checkpoint, so a long run accumulates dirty page-cache data that every WAL barrier
then shares a journal commit with. Whether syncing pages more eagerly is a net win
is untested.

Measurements on a host with faster durable writes than WSL2 would shift all of
these ratios.

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
