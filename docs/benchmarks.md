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

## Where a write's time goes

`scripts/profile-writes-linux.sh` runs one load mode and prints the per-request
stage budget behind it, from the server's own counters:

```bash
MODE=write bash scripts/profile-writes-linux.sh
```

The stages are the hand-offs a durable commit crosses — queue wait, engine lock,
apply, flush queue, `fdatasync`, publish — with a mean and a p50 for each. Read the
p50 column: a mean on a host that intermittently stalls a flush tells you about the
stall, not the path. `vyrn_commit_*` on the metrics endpoint exposes the same
counters for a running server, quantiles over the process lifetime.

## Keep the log out of the measurement

Benchmark at the default `VYRN_LOG=info`, or with `VYRN_LOG=off`. Do not benchmark at `debug`: that level emits a record per request, which puts a synchronous stderr write on the request path and measures your terminal or log collector rather than the database.

`info` is safe to measure at because nothing on a request path formats anything there. Every record is guarded by a level test that runs before its message and field expressions are evaluated, so a disabled record costs one relaxed atomic load and no allocation. If a comparison between two builds shows an unexplained gap, confirm both runs used the same `VYRN_LOG` before looking anywhere else.

## Comparing two builds on a noisy host

`scripts/compare-builds-linux.sh` alternates two sets of binaries within one
session and reports each paired round:

```bash
A=/tmp/bin-before B=/tmp/bin-after ROUNDS=5 MODE=write \
  bash scripts/compare-builds-linux.sh
```

Use this for any write-path change rather than benchmarking one build after the
other. Both directions of a spurious result have been produced on this host by
consecutive runs of identical code; the "won N of M paired rounds" line is what
distinguishes a real change from the host's mood.

## Measured 2026-07-27 (WSL2, 32 cores, 15 GB RAM, ext4)

16 clients, 128-byte values, 1,000 operations per client, both databases durable.
Single runs, not medians — this host varies by roughly 2× on write-heavy work, so
read the write and transaction rows as a snapshot rather than a precise figure.

| Workload | Vyrn | PostgreSQL 17 | Ratio |
| --- | ---: | ---: | ---: |
| Point reads | 83,049/s (p50 189 µs) | 10,129/s (p50 926 µs) | 8.2× faster |
| Index equality lookup | 50,456/s (p50 302 µs) | 10,676/s (p50 902 µs) | 4.7× faster |
| 70/30 mixed | 13,759/s (p50 299 µs) | 7,722/s (p50 1.03 ms) | 1.78× faster |
| Four-key transactions | 2,618/s (p50 5.4 ms) | 1,223/s (p50 6.5 ms) | 2.14× faster |
| Durable writes | 5,666/s (p50 2.78 ms) | 7,260/s (p50 2.12 ms) | 1.28× slower |

### Write throughput against client count

Every table above this one was taken at 16 clients. That is the point where Vyrn
looks best on writes, and it hides the shape of the curve. Measured across the
matrix the harness already supports:

| Clients | Vyrn | Vyrn p50 | Vyrn p99 | PostgreSQL | PostgreSQL p50 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 940/s | 1.04 ms | 1.44 ms | 816/s | 1.20 ms |
| 16 | 5,666/s | 2.78 ms | 4.72 ms | 7,260/s | 2.12 ms |
| 64 | 8,624/s | 6.20 ms | 48.3 ms | 9,361/s | 3.31 ms |
| 256 | 7,732/s | 14.6 ms | 217 ms | — | — |

PostgreSQL's default `max_connections` is 100, so the 256-client cell cannot be
run against it without raising that first.

Three things this says that the 16-client table cannot:

- **Vyrn wins at one client** and loses as concurrency rises. A durable commit
  costs one `fdatasync` in both systems, so the deficit is not the barrier — it is
  what happens when many writers meet a single write lock.
- **Throughput saturates.** 256 clients is *slower* than 64. Serialised `apply`
  caps the write path regardless of how many clients offer work; measured at
  ~55 µs of lock-held time per request before the `node_ref` fix below.
- **Group commit is not engaging.** `vyrn_flushed_batches_total` divided by
  `vyrn_wal_flushes_total` measures **1.007** under a 256-client load: essentially
  one barrier per batch, no amortisation at all. `apply` outlasts `sync`, so each
  flush finishes before the next batch is ready and the flush queue never has two
  batches to coalesce.

### The tail is not yet attributed

At 256 clients the tail is p99 217 ms, p999 586 ms, and a maximum between 8 and
12 seconds, reproducibly, across every run taken. That is the number that would
break an application, and **it is not yet known whether it is Vyrn or the host.**

Ruled out by measurement: kernel dirty-page throttling (peak `Dirty` 1,378 MB
against a 3,119 MB threshold, with `Writeback` near zero during the collapses),
WAL segment rotation (forcing eight rotations instead of one *improved* the tail,
24.7 ms against 58.5 ms maximum; a rotation costs about 8 ms), checkpointing and
MVCC GC (`vyrn_checkpoints_total` and `vyrn_mvcc_versions_collected_total` both
zero across the run), and the storage engine itself (3,000 batches driven straight
through `Engine::write_batch` produced no commit over one second).

Not ruled out: the host. A bare `fdatasync` loop on the same filesystem, run
beside the load, was caught stalling **5.6 seconds** in one round — and in another
round of the same experiment never exceeded 243 ms. One round of that probe is
worth nothing; an early reading of it wrongly concluded the tail was Vyrn's alone.
Settling this needs the probe run against the load perhaps ten times, comparing
the distribution of second-scale stalls on each side. Until that exists, no
production claim should rest on the tail either way.

### Fixed: `node_ref` decoded a whole page to read one field

`PageTree::node_ref` reached `children[0].page_id` by calling `decode_internal`,
which materialises every child of the page as an owned `NodeRef` — a `Vec<u8>`
key for each of roughly a hundred children. That value is a fixed header field at
offset 24, which `decode_internal` itself reads directly. Worse, `decode_internal`
calls `node_ref` for its own first child, so the two recursed into each other:
decoding one root page walked and re-decoded the entire leftmost spine, allocating
fanout-many keys at every level. Both hot descents paid it — `collect_many` for a
commit's pre-state read, `apply_node` for the copy-on-write rewrite.

Per request against a 200,000-key tree:

    decode_internal   85.77 us -> 15.31 us
    prestate          27.36 us -> 11.16 us
    tree              76.20 us -> 59.36 us
    apply            104.40 us -> 71.40 us
    page reads            23.4 -> 16.2

The page-read count is the load-bearing number: it is exact, where a timing on
this host is not. End to end, the one-line change alternated against its parent
within a single session at 64 clients won **5 of 5** paired rounds, p50 7,604 µs
against 6,364 µs (1.19×) and 7,405/s against 9,453/s (1.28×).

Three earlier attempts at this bottleneck were wrong and each was killed by
measurement rather than by review: removing value materialisation from the commit
path (0.98×, 3 of 5 rounds — the load generator writes a unique key per operation,
so the value read never fires), removing an entry clone in `write_leaf_level`
(91 µs to 94 µs), and growing the page cache from 16 MiB to 256 MiB (88 µs to
84 µs — the hit rate was already 100%). `apply-profile` and `rotation-probe` split
a commit into phases and report deterministic page counts; they are what found the
real one.

### Fixed: one write per commit instead of one per page, and a pre-state read
that decodes nothing

Three changes, measured on Windows (a host where syscalls and allocation are
dearer than on the Linux host above, so the shares differ but the structure is
the same). The instrument was a new split of the `tree` phase —
`tree_decode` / `tree_encode` / `tree_append` / `tree_flush`, printed by
`apply-profile` — which is what located each of these; it stays in
`vyrn_core::profile` so the next regression in the copy-on-write path is
attributable rather than one opaque number.

**Page-append buffering.** `PageManager::append` wrote each copy-on-write page
with its own positional write. The pure syscall time measured ~30 µs of a 58 µs
tree phase at the 32-client batch shape — the largest single cost of a commit
after its `fdatasync`, paid for pages that carry no barrier of their own and
that nothing reads from the file before the commit publishes. Pages now
accumulate in a buffer and reach the file as **one contiguous write per
mutation**, flushed before the new root can escape, so every invariant about
what is on disk when a root is publishable is unchanged. Paired runs, same
session, 32 clients × 128 B against a 200,000-key tree:

    tree            58.0 us -> 30.2 us per request
    apply total     81.1 us -> 50.0 us per request
    page writes     3.5 syscalls/request -> 1 write/batch

A failed mutation now discards its buffered pages and their ids, so it leaves
the page file exactly as it found it — before the buffer, a failed batch's
pages were already on disk and stayed there as permanent orphans.

**The pre-state read decoded whole leaves.** `collect_many` — the descent that
reads each key's presence and revision before a batch applies — called
`decode_leaf`, allocating a key `Vec` and a value `Vec` for every entry of
every touched leaf to answer for a handful of keys, usually without wanting
values at all. A single-key commit touches three leaves in pre-state (the key,
its tombstone, the change log), which is ~600 allocations per commit for
nothing. It now walks cells in place, the same shape as `find_in_leaf`'s
documented fix. Paired runs, single-key commits:

    prestate        34.6 us -> 7.0 us per request
    page reads      32.0 -> 23.0 per request (deterministic)

**`write_internal_level` cloned the whole level.** Chunking children into
per-page vectors cloned every child's `min_key` even when a commit touched one
child of a hundred-way level. It now records page boundaries as index ranges,
exactly as `write_leaf_level` already did and for the reason its comment gives.
Too small to isolate in a timing on this host; taken on the strength of the
precedent.

### Fixed (opt-in): write-back buffering removes the tree from the commit path

The persistence-strategy change the section below has been predicting: with
`EngineOptions::write_back_buffer` set, a commit's durability is its WAL record
alone. The mutations land in an in-memory buffer that every read on the engine
merges over the tree — tombstones, change-log records, and index entries are
ordinary keys, so every layer inherits the merge — and the tree absorbs the
whole buffer in one amortised `prepare_batch` when the buffer crosses its byte
threshold and on every checkpoint. Recovery needed no new mechanism: a
write-back record names a root that can never be adopted (`WRITE_BACK_ROOT`),
so an open falls back to the redo-from-checkpoint path that has always covered
pages that failed to survive; a kill without a checkpoint reconstructs the
whole buffer from the log. Reverting that sentinel to the stale tree root makes
the recovery tests fail with silent data loss, which is exactly the hazard it
exists to close.

Measured on the same Windows host, same probe, 200,000-key tree, 128 B values:

    32-client batches   apply 20.5 us/request, of which 15.5 us is the shared
                        fdatasync; engine CPU ~5 us/request against ~70 us at
                        the start of this round (14x), pages 0.1/request
    single-key commits  engine CPU ~16 us/request beside the fdatasync,
                        against ~200 us at the start of this round (12x),
                        pages 0.0/request between flushes

A 600-step randomized model test drives a write-back engine and a classic
engine through the identical workload across several threshold flushes and
compares every read, scan, length, change-detection and change-log answer.

The trade, stated plainly: reopening replays the WAL from the last checkpoint
instead of adopting the newest root (bounded by checkpoint cadence); the commit
that crosses the threshold pays the buffer's whole tree pass (bounded by the
buffer size); and the buffer holds up to its size in memory. ~~Embedded use
only for now~~ — the server learned the buffer in the round below and enables
it with `--write-back-bytes`.

### Fixed: the server's read handles learned the write-back buffer

The queued follow-up from the round above, which is what lets `vyrn-server`
turn write-back on. Every `ReadEngine` now carries its own copy of the buffer
— an overlay fed one durable commit at a time — and every read on a handle
merges it over the tree through the same shared implementation the engine
itself uses (`overlay::merged_*`), so the two views cannot drift.

The publication rides the machinery that already existed rather than adding
any: the flush stage already took each reader's write lock per batch to
refresh the root, so `PendingFlush` now carries the commit's raw mutations
(`Engine::take_write_back_publish`, captured under the engine lock exactly
like `last_published`) and the same loop applies them under the same guard —
root first, then mutations, then any eviction the absorb watermark licenses.
Values are `Arc`-shared between the engine's buffer and every reader's copy,
so feeding N readers costs N map inserts per mutation and no value bytes.
Ordering is the flush queue's: one writer, one publication point, commit
order. Nothing is applied before the commit's `fdatasync`, so the
durable-then-publish rule is unchanged.

The absorb hand-off is watermark-based and per-entry, not clear-all, because
the checkpoint task publishes concurrently with the flush stage: an eviction
may only drop entries at or below the LSN the reader's tree provably contains,
so a commit that reached a reader after a checkpoint absorbed — but before the
checkpoint task's republish — survives it. The reader-parity model test drives
exactly that interleaving, plus 500 mixed steps across many threshold absorbs,
against a classic reader fed only refreshes; a read-your-write probe on every
step is what catches an eviction running even three LSNs ahead (a sampled
probe provably does not — the first version of the test passed that mutation).

Two things fell out of building it:

- **`drop_index` missed buffered entries** (pre-existing, embedded write-back
  only): it enumerated the doomed index's entries with a raw tree scan, so
  entries still in the buffer survived the drop, and recreating an index of
  the same name resurrected them as stale lookup answers — first from the
  buffer, then permanently once absorbed. Same defect in
  `clear_index_entries`. Both now use the merged scan; mutation-verified.
- **Index creates and drops now publish through the flush stage** (they
  commit alone with an immediate barrier and used to answer directly), so a
  new index's definition reaches the read handles without waiting for the
  next unrelated commit. In classic mode their publication is empty and the
  old behaviour is untouched.

End-to-end coverage: `tests/correctness.rs` runs the shipped server with
`VYRN_WRITE_BACK_BYTES=4096`, checks read-your-write on every one of 300
writes, deletes, documents, index visibility, then kills the process and
verifies the WAL alone brings everything back. Reverting the reader
publication makes it fail at the third read.

No served-path timings are quoted here on purpose: they need the Linux paired
harness (`compare-builds-linux.sh`), and this host's numbers do not travel.
The deterministic engine-side facts from the round above are what this change
transports to the server: ~5 µs of engine CPU beside the shared fsync at the
32-client shape and 0.1 pages per request, against 38.5 µs and 3.5 pages
classic.

### Fixed: reading a spilled value cost two syscalls and a checksum pass, every time

Values over the 1 KiB inline limit live in the value log, and reading one
back paid, per read: a `metadata` syscall (a bounds check against the file
length), one or two `pread`s, a CRC pass over the value, and an allocation.
Every store this engine is compared against answers a hot large-value read
from an in-process cache with a memcpy. That difference is exactly the shape
of the rows vyrn was losing: point reads and scans of 4 KiB and 64 KiB
values, while 128 B rows — inline, never touching the log — were winning.

Three changes, measured with criterion against a saved baseline in one
session on this host (reads do not suffer the fsync noise that makes write
timings untrustworthy here, and the baseline comparison is paired by
construction):

- **The per-read `metadata` syscall is a cached length.** It existed for a
  real reason — several handles share one log file (the engine's plus one per
  read handle), and only the writer sees its own appends — so the cache
  refreshes from the file once when a reference points past it and is
  monotonic from there. A reader pays one `metadata` per growth epoch it
  discovers instead of one per read; a mutation that removed the refresh
  makes the cross-handle test fail.
- **Scans resolve a leaf's values in one batch.** `read_many` sorts a leaf's
  spilled references, coalesces exactly-adjacent records into single
  positioned reads (capped at 1 MiB per read), and validates each record
  individually — the same framing, CRC, and reference-metadata checks as the
  single-read path, pinned by a corruption test inside a coalesced run. Keys
  written in order sit in the log in order, so a range scan's thousand
  values are typically a handful of preads instead of a thousand.
- **A byte-budgeted cache of validated values** (`VYRN_VALUE_CACHE_BYTES`,
  default 64 MiB per handle, 0 disables): a hit is a map lookup and one
  memcpy, skipping the syscall AND the checksum pass. Second-chance clock,
  same replacement design as the page cache and for the same reason — one
  cold sweep must not evict the hot set. Sound because the log is
  append-only under a live handle and every generation change reopens it;
  entries carry the reference's revision and length, so a forged reference
  sharing an offset falls through to the file read, which refuses it.

Paired numbers (criterion `--baseline`, this host):

    point_get/4kib     12.1 us ->  2.7 us   (4.4x)
    point_get/64kib    ~49 us  ->  5.3 us   (9.3x)
    point_get/1mib     750 us  ->  341 us   (2.2x)
    scan_1000/4kib     11.16 ms -> 442 us   (25x, hot; 3.35x of it is the
                                             coalescing alone, measured before
                                             the cache landed — that is the
                                             cold-scan factor)
    point_get/128b     unchanged (inline values never touch the log)
    scan_1000/128b     +2.5% (the per-row placeholder branch; accepted, the
                              row was already the winning one)

The honest split: the coalescing and the length cache help every read, cold
or hot; the value cache's full factors apply to working sets that fit its
budget, which is also precisely the regime the comparison stores' own caches
were serving in.

### Fixed: reads that copy nothing — `get_shared` and `scan_shared`

The engines vyrn is compared against do not hand back owned bytes: sled's
`get` returns a refcounted buffer, redb's returns a guard borrowing its mmap.
vyrn's API copied every value into a fresh `Vec` even when the bytes were
already sitting in a cached page or the value cache — at 64 KiB that copy was
most of a hot read. `get_shared` and `scan_shared` return [`SharedBytes`]:
inline values still inside their cached page (the `Arc` keeps it alive),
spilled values as the value cache's own allocation, buffered values as the
write-back overlay's. A hit is a descent plus a reference-count bump. The
copying `get`/`scan` remain, now thin materialising wrappers over the same
paths, and the model tests assert both agree on every probe.

Two costs found while measuring left with it: the write-back publish staging
(a key clone per mutation) is now opt-in via `Engine::enable_write_back_publish`
— the server calls it, an embedded engine no longer pays for a publication
nobody reads — and the WAL runway now scales its fill with the record size
(`reserve` covers ~64 records of whatever size per expensive extension
barrier, capped at 8 MiB, small records unchanged, the self-initialising rule
for records larger than a step untouched).

Measured against sled and redb in one process on this host (the standalone
harness in `../vyrn-compare`, each engine on its zero-copy read API and
1 GiB cache parity, sled additionally forced to `flush()` per put in its
durable row — its default is a 500 ms background flush, which is the number
naive durability comparisons quote):

    #1 for vyrn      point_get 128 B (~2.0–2.3 M/s, 1.3–2.4x over both),
                     scan_1000 128 B (~9.9 M rows/s, trading ±5% with redb's
                     guards run to run), scan_1000 4 KiB (~9.7 M rows/s, 2.3x
                     over redb — scan rows allocate nothing since the shared
                     keys and the in-place cell walk, and `scan_each` hands
                     out borrowed slices with no rows built at all),
                     durable_put 128 B and 4 KiB (at the shared fsync floor,
                     ahead of flushed sled; redb behind)
    still behind     point_get 4 KiB and 64 KiB (redb's mmap guard wins).
                     The scan floor (~100 ns/row) and these point_get rows
                     are the same cost — the per-cell parse of
                     variable-length cells — and share the same fix: a page
                     format with a fixed-width cell-offset directory (binary
                     search in leaves, branchless scan emission). Format
                     bump, queued. Also batch_put 128 B (redb ~1.2x — per-op
                     allocation diet) and durable_put 64 KiB (sled ~1.15x,
                     inside this host's fsync noise band but consistent)

Write rows on this host vary ±10–15% run to run; the read rows are stable and
the rankings reproduced across runs.

### Fixed: point reads answered on the connection task

A point read against a warm cache is about a microsecond of engine work, and
the served path wrapped it in a bounded-channel send, two cross-thread
wakeups, and a oneshot allocation — the reader-thread hop was most of a served
Get that isn't network. `submit_get` now takes a shared `try_read` on a read
handle and answers inline on the connection task. A shared read lock succeeds
alongside anything but a publish — including a scan holding the same handle's
guard on its worker thread, so point reads no longer wait behind scans at all
— and when it does fail (a publish or refresh holds the handle exclusively),
the request falls back to the queue path unchanged. Scans, multi-gets, and
document reads stay on the worker threads with their chunking and deadline
machinery; a cache-miss descent inline is a handful of positional page reads,
which is bounded and small in a way a scan is not.

### Fixed: the protocol pipelines

The session loop was read-one, answer-one, flush-one: every request paid two
socket syscalls and a full round trip, which is why a served read was ~190 µs
around 1 µs of storage work. Two halves, both order-preserving:

- **Server**: after answering a request, the session drains every further
  request the read buffer already holds (a non-blocking poll, so a lockstep
  client is served exactly as before), feeding responses into the codec's
  write buffer; the flush happens once, when the burst is exhausted. The
  codec's own backpressure boundary bounds what a burst of large responses
  can hold in memory, and the wedged-peer write timeout wraps the feed and
  the flush exactly as it wrapped `send`.
- **Client**: `Client::pipeline` submits a batch of independent get/put/delete
  operations in one write and collects their answers in order — one round
  trip for the batch, per-operation results, and a refused operation consumes
  its own slot without derailing the rest. Semantics are identical to issuing
  the operations one at a time; the integration test pins that with a
  put→get→delete→get chain on one key inside a single burst.

The TypeScript SDK has not grown the pipeline API yet; the server side
benefits any client that writes several frames before reading.

### Remaining: write amplification (classic path)

With write-back off, every 128-byte durable write still allocates and writes
**3.5 pages, 14 KiB** — about 112× amplification, measured deterministically.
The page-append buffering above removed the per-page syscalls, not the bytes:
copy-on-write cannot amortise them the way an in-place engine does. PostgreSQL
dirties one shared buffer and lets the checkpointer write it once for many
commits, whereas every classic Vyrn commit must allocate and write a new leaf
plus every internal page up to the root. It is also why a soak accumulates
on-disk volume quickly. Write-back buffering is that change of persistence
strategy; the server's readers learned the buffer in the section above, so
`--write-back-bytes` now carries it to the served path.

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
| Four-key transactions | 2,131/s (p50 6.0 ms) | 1,217/s (p50 7.0 ms) | p50 1.2× faster |
| Durable writes | 5,411/s (p50 2.9 ms) | 6,914/s (p50 2.2 ms) | 1.24× slower |

Vyrn leads on reads, index lookups, and the mixed workload by margins far larger
than this host's run-to-run spread, so those three rows are solid. It is still
behind on single-key durable writes, but by 1.24× rather than the 2.1× recorded
before the WAL runway change below; that row and the transaction row are the two
this host measures least reliably, and both were re-measured by pairing the builds
within one session rather than by consecutive runs.

The transaction row still needs care. Vyrn's write-heavy throughput varies by
roughly 2× run to run on this host (see the caveat under the flush change below),
so the throughput figure beside it is not quotable on its own; the p50s, 6.0 ms
against 7.0 ms, are the stable comparison. Per commit the two are close, with Vyrn
now slightly ahead, and Vyrn's larger edge is throughput under concurrency rather
than commit latency.

Two rows moved against the run recorded earlier on this host, both on the
PostgreSQL side: writes measured 6,982/s here against 2,782/s before, and mixed
8,914/s against 4,897/s. That is not a storage-placement artifact — the
`fdatasync` floor inside the PostgreSQL container (1.41 ms) and on the ext4
filesystem serving Vyrn (1.53 ms) are within noise of each other. The earlier
figures did not reproduce, and the earlier write row was internally inconsistent
besides: 2,782/s across 16 clients implies a 5.8 ms mean latency against the
2.6 ms p50 recorded beside it. Treat the numbers above as the current measurement
and the write comparison as a genuine deficit rather than a regression.

PostgreSQL keeps the lower p50 on single-key writes. On transactions the two are
close enough per commit that the ordering depends on the round.

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

### Fixed: every commit extended the WAL file

The stage budget above says where a write's 4.5 ms went. Instrumenting the six
hand-offs a commit crosses — `vyrn_commit_*_nanoseconds` on the metrics endpoint,
with p50 and p99 per stage, since a mean on this host is dominated by whichever
run stalled — gave this for a 16-client single-key run:

    stage          mean      p50      p99
    front          1358 us  1180 us  2359 us
    lock             41 us    37 us    74 us
    apply           561 us   426 us  1180 us
    flush_queue     536 us     8 us  1966 us
    sync           2095 us  1704 us  4719 us
    publish          44 us    37 us    90 us

`sync` is the barrier and `front` is the queue wait ahead of it, which is mostly
the barrier again seen from the client's side. So the earlier guess that ~2.5–3 ms
was scaffolding around the flush was wrong: the flush itself was that big, and the
question was why a 1.5 ms `fdatasync` floor was costing 1.7–2.1 ms per commit.

Because the floor was not 1.5 ms. Every commit appended to the segment, so every
barrier had an extent-tree update to journal along with the data. Writing the same
1.5 KiB records into blocks that were already allocated and already initialised
measured, on this host, alternating the two within one process:

    appending (file grows)     p50 1444 us   p95 1860 us
    sparse set_len ahead       p50  712 us   p95 2143 us
    preallocated and zeroed    p50  593 us   p95  904 us

`set_len` is not enough — a sparse file still updates its extents on first write
into each hole. The blocks have to be really written.

`Wal` therefore keeps a zero-filled runway ahead of the write point and writes
records into it positionally, rather than appending. The runway is pushed forward
1 MiB at a time; that fill costs one expensive sync (4.6 ms measured) which the
several hundred records it covers then amortise. Segment rotation restarts the
runway at the new segment's header.

The cost is that end of file stops meaning end of log. Three places that read the
log had to learn the difference, and one of them is a durability property rather
than a detail:

- **A torn tail no longer runs past end of file.** That was how recovery
  recognised a commit interrupted by a crash. With zeros after the records, a
  half-written record instead looks like a complete record with a corrupt body —
  which recovery is required to refuse, so an ordinary crash would have made the
  database unopenable. The replacement is exact rather than heuristic: replay
  finds the last non-zero byte in the segment, and because every record ends with
  the four non-zero bytes of `RECORD_END`, a frame reaching past that point cannot
  have been written in full. Frames that end at or before it are validated as
  strictly as before, so damage to a complete record is still corruption.
- **The archiver** scans a sealed segment to confirm it is the segment it claims
  to be. It now stops at the records and requires every remaining byte to be zero,
  so a splice into the unused tail is still caught.
- **Point-in-time restore** compared a base backup's copy of a segment against the
  archived copy by file length. Both copies now carry a runway, and the archived
  one wrote further records into bytes the backup copied as zeros, so the two can
  be the same size with different amounts of history. The comparison is by record
  boundary now, not by length.

Running `scripts/smoke-linux.sh` against this change also surfaced two durability
bugs that predate it and reproduce on the unmodified commit. Neither is caused by
the runway; both are fixed here because the script cannot pass otherwise:

- **A read handle opened behind the recovered engine and stayed there.**
  `ReadEngine::open` reads the checkpoint manifest and does not replay the WAL, so
  after a crash it starts at the last checkpoint — at the empty generation-0 root
  when no checkpoint had run. Nothing published the recovered root to the readers
  at startup; only the next commit did. A database that was killed and then only
  read from therefore answered `not found` for writes it had acknowledged as
  durable. The engine itself had them the whole time, which is why the crash tests
  never caught it: they call `Engine::open` directly, and only the server uses read
  handles. Fixed by refreshing every handle to the engine's recovered root during
  startup, covered by `concurrent_visibility.rs`.
- **Backup refused any database that had not checkpointed yet.** No checkpoint
  means no `CURRENT`, and `create_backup` treated that as corruption
  ("checkpoint it first"). It is an ordinary early state: the backup includes the
  WAL, and restore replays it onto the empty base root exactly as a normal open
  would. So the first backup of a new deployment was impossible, including right
  after a clean shutdown. The guard now rejects only a directory with no page
  file, and `recover_to` treats a manifest-less base as a floor of LSN 0 rather
  than an error.

Measured by alternating the two builds within one session, five paired rounds,
fresh server and fresh database per round:

| Workload | Baseline (p50) | Runway (p50) | Paired rounds won |
| --- | ---: | ---: | ---: |
| Single-key durable writes | 4,495 µs | 2,838 µs | 5 of 5 |
| Four-key transactions | 7,187 µs | 5,953 µs | 5 of 5 |
| 70/30 mixed | 332 µs | 331 µs | 4 of 6 |
| Point reads | 199 µs | 203 µs | 1 of 5 |

Writes improve 1.58× and transactions 1.21×, and both moved the same way in every
paired round, with the per-round spread narrow on both sides (writes 4,358–4,605
against 2,781–2,960). Re-running the write pairing against the unmodified commit
after the two bug fixes below reproduced it at 1.56×, again 5 of 5. Mixed and reads are parity, as expected — reads never touch
the barrier. The stage budget after the change confirms where the gain came from:
`sync` p50 1,704 µs → 721 µs, `front` 1,180 µs → 852 µs, everything else within
noise of itself.

The tail improves too, on the rounds where this host was not stalling: write p99
went from 5,991–6,665 µs to 4,308–4,425 µs. The 34–53 ms p99 rounds occur on both
builds at the same rate and are the host, as documented above.

Against PostgreSQL 17 on the same host and settings, three runs each, this closes
most of the write deficit: PostgreSQL 2,220–2,329 µs p50 against Vyrn's
2,781–2,960 µs. That is 1.24× behind rather than 1.97× behind.

### Remaining bottleneck: single-key write latency

The barrier is off the write lock, shared between committers, and no longer
extends the file, so a single-key durable write now measures 2.8–3.0 ms p50 with
its stage budget at:

    front  852 us    lock  45 us    apply  426 us
    sync   721 us    flush_queue 8 us    publish 37 us

Two things are left, in order of size:

- **`front` and `sync` are the same barrier counted twice.** A client waits for
  the batch ahead of it to flush (`front`) and then for its own (`sync`). Together
  that is about 1.6 ms of a 2.9 ms write, against a 593 µs floor for one flush
  into allocated blocks. The remaining multiple is queueing: at 16 clients and 8
  requests per batch, a request waits roughly one barrier before its own. Group
  commit already covers this for concurrent writers; what it cannot fix is a
  single writer's serial latency, which is one flush plus `apply`.
- **`apply` at 426 µs.** Change log, pre-state read, tree apply, MVCC prepare, and
  WAL encode, all under the engine write lock. The pre-state read and MVCC prepare
  grow with tree depth and have still not been profiled on a large tree, which is
  the honest gap in this table.

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
