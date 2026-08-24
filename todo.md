# vyrn — production-readiness TODO

## 🚢 1.0.0 release gates (2026-08-24)

- [x] WAL record header self-checksum (record format v5) — the last known format defect; the
      bit-flip test now runs with NO exemptions, mutation-verified; v4 records readable forever.
- [x] Compatibility contract (`docs/compatibility.md`) and security model (`docs/security.md`);
      production.md envelope references both. Value-size ceiling: documented limit IS the 1.0
      contract; the change-record split may raise it in 1.x.
- [x] CI gates: crash-soak on Linux (both modes — this discharges the "never executed" gate on
      every push, including SIGTERM shutdown-sync coverage), docker build, bench smoke.
- [x] Server Windows convoy: confirmed (eager appends under the engine lock vs flush-stage
      fsync), documented in production.md as a Windows caveat; Linux unaffected. Post-1.0:
      teach the flush stage the Async+drain_wal split.
- [x] Version 1.0.0 across workspace, SDK, docs; CHANGELOG 1.0.0 entry.
- [ ] Windows flake: named — vyrnd integration binaries `hardening` and `replication` under
      full-workspace parallel load (2 of 6 runs); test-name capture in progress. Windows is a
      development platform; gate is "named and tracked", not "fixed".
- [ ] REMAINING before the tag: CI green on the push (first-ever crash-soak run included), and
      the sandbox items that need real hardware — multi-hour larger-than-memory soak and the
      operational restore + PITR drill (production.md exit gates; tooling exists). Tag
      v1.0.0 once CI passes; run the soak/drill as the first post-tag action or hold the tag
      for them — owner's call.

Living checklist for the fix fleet. Baseline commit: `ac4c506`.

## ✅ Done (verified green at time of completion)

- [x] **B1** `page_tree.rs` / `recover.rs` — torn-tail repair on open, resume-safe append,
      forged-count allocation caps, cycle/depth guards, no materializing missing generations,
      PITR frame-walker respects the WAL runway, archive CRC verified on adoption, splice
      detection, honest torn-tail regression test *(core suite 154/154)*
- [x] **B2** `backup.rs` / `portable.rs` / `wal_archive.rs` — two-pass verify-before-commit
      import, untrusted length caps, byte-based batching, trailing-data rejection, doc JSON
      validation on import, WAL↔manifest continuity check (incl. middle-segment holes),
      output-path clobber guards, archive rot self-heal, unique temp names, dir fsync
- [x] **B3** `document.rs` / `change_log.rs` / `mvcc.rs` — corrupt documents deletable &
      replaceable (with index cleanup), corruption-controlled allocations bounded (~481 GB abort
      → clean error, proven pre-fix), checked arithmetic, numeric-equality docs
- [x] **B4** protocol crate — empty multi-get framed correctly, encoder enforces decoder limits
      (`FieldTooLong` locally), version mismatch named codec error, pre-auth frame-cap builder,
      fuzz suite gaps closed (4 → 29 tests)
- [x] **B5** Rust client — timeout retires connection (`UnusableConnection`), commit/rollback
      keep tx flag until definitive answer, subscription version checks, async CA load
      (3 → 15 tests)
- [x] **B6** HTTP gateway — idle-pool stale-connection bug fixed (retry-once on dead-connection
      class + idle expiry), internal errors scrubbed, backend connection cap, health probes
      pooled, base64 query alphabets, SSE heartbeats, OPTIONS before auth, extractor envelope
      (2 → 10 tests)
- [x] **B7** TypeScript SDK — pool wedge fixed (capacity reclaim, waiter settlement),
      subscription dispatch race fixed (pre-registered buffering handler), abandoned-tx
      auto-rollback on release, bounded stream buffers, timeout socket destroy, SSE/base64 nits
      (11 → 22 tests, mutation-verified)
- [x] **E2** build/docs hygiene — `[profile.release]` overflow-checks+LTO, Dockerfile admin bind
      → loopback default, README v6 + milestone fixes, .gitignore credential files, compose
      resource limits/log rotation, CHANGELOG stub

## ✅ Done — second round (all pushed)

- [x] **C1** `lib.rs` criticals — **audited rather than rewritten**: all five turned out to be
      already applied and documented, so there was nothing to finish. checkpoint_generation commit
      point (`lib.rs:1898`, counter moves immediately after `write_manifest`), apply_batch staging
      order (`:1466`, historical values staged before `publish` so every failure happens while the
      mutation is invisible), torn-tail replay with splice detection (`:2524`), per-record sync
      LSNs + poison (`:1852`), segment-gap temp+rename (`:2389`, was `remove_file` then create,
      where a kill between the two bricked the database permanently).
- [x] **D1** server hardening — **DONE**. `main.rs` was truncated to 1346 of 3784 lines
      (298 errors); restored by splicing HEAD's head onto the surviving hardened tail, then
      repairing two mid-edit casualties (a `.replace("eded","ed")` botched typo-fix inside a
      `format!`, and a lost `RESPONSE_WRITE_TIMEOUT` const). All 9 items implemented:
      snapshot-pin release on every exit path (session extracted into `run_session` so the
      release is unavoidable), response write timeouts, `AuthThrottle` + `vyrn_auth_failures_total`
      (refusal happens *before* Argon2), broadcast-ring byte bound (`ChangeRing`, elides payload
      rather than dropping the notification), write-worker supervision + all pipeline
      `unreachable!()` panics → error responses (dispatch rewritten as one exhaustive match),
      drain-race fix (register the `Notified` future before checking the count) + final sync on
      shutdown, pre-auth frame cap (64 KiB, raised via `map_codec` after auth),
      write-queue memory bound (`WriteBudget`, 256 MiB, RAII), flush-stage failure now answers
      the rest of the coalesced group with "durable but not published" instead of dropping their
      senders. `tests/hardening.rs` 3 → 5 tests, both new ones mutation-verified (each fails when
      its fix is reverted). Added `vyrn_active_transaction_snapshots` gauge — the pin-leak test
      needs it, because `mvcc_versions_collected_total` stays 0 with no open transaction and
      would have passed either way.
      *Not covered by a test:* the shutdown final sync needs a graceful SIGTERM, which Windows
      cannot send to a child from `std`; deferred to `scripts/crash-soak.sh` (E3). Reviewed, not
      tested — noted in the test file too.
- [x] **E3** adversarial parsing — 20 tests in `crates/vyrn-core/tests/adversarial_parsing.rs`
      across 7 parsers × arbitrary bytes / truncation walks / forged counts, plus
      `scripts/crash-soak.sh`. Two real defects, both reachable from a directory an operator
      assembles by hand: `verify_archive` panicked on an entry claiming `last_lsn = u64::MAX` —
      an abort inside the one command you run *because* you suspect archive damage — and
      `recover_to` hung asking for 1.8×10^19 heap strings on a forged segment gap. Both
      mutation-verified. Every other parser held; re-proved rather than re-fixed.

- [x] **C2** MVCC history coverage watermark — `covered_through` distinct from `gc_floor`,
      published on exactly the commits that retain nothing, which is the case the floor cannot see;
      reads *and registrations* below coverage refused with `SnapshotTooOld`. `revision()` and
      `any_changed_since` now take the **max** of history and tree: a retained version is a lower
      bound, never an authority, and treating it as one let two transactions that overwrote each
      other both pass validation. 6 tests in `tests/mvcc_coverage.rs`.
- [x] **C3** lib.rs medium batch — all seven, each mutation-verified. Unique-index moves and swaps
      now legal (keyed by index+value+primary key, so a genuine third holder still violates),
      `last_published` reset on entry, `limit == 0`, `Cursor::start()` clamp, registry expects →
      `Poisoned`, replay/live filter parity (replay was nearly doubling the revision value log on
      every recovery — 21590 vs 10640 bytes, measured), `validate_index_name` namespace with the
      document layer's own prefix exempt.
- [x] **D2** server correctness — publication happens only in `publish_commit`, and `readers` +
      `changes` were **removed** from `WriteWorkerConfig`, so the reorder is unrepresentable rather
      than merely fixed. Batch validation now includes plain ops, both sides of an index move,
      index-update primary keys, and range phantoms. Chunked scans with admission between chunks
      (the read guard is held across chunks deliberately — releasing it would trade a stall for a
      torn read), `--statement-deadline-ms`, and an honest dead-reader message.
- [x] **D3** replication gap recovery — **not** via `recover_to`: it calls `Engine::open`, so it
      cannot run on a replica that already holds the data-directory lock. Instead `decide_join`
      gained `Rebuild` — the primary streams from its oldest held LSN and the replica closes the
      gap from the WAL archive, reusing the streaming verify→append→sync→publish path. No new
      protocol message (`ReplicaStream` already meant "records start here"). Replaces a refusal
      that left a merely-lagging replica permanently broken while a `min-acks 1` primary blocked
      writes waiting for the quorum that replica was supposed to provide.
- [x] **E1/E1b** logging — new dependency-free `vyrn-log` crate, extracted from vyrn-client so the
      *server* need not depend on the *client* to write a log line. All three binaries converted;
      zero `eprintln!`/`println!` left in `main.rs`. `record_storage_error` names the failing
      operation, which is what finally makes production.md's promise true; `withdraw_readiness`
      names the task that died at 11 sites; auth distinguishes throttled from rejected, a
      distinction the client deliberately cannot see; checkpoints report duration and trigger; a
      timed-out drain no longer looks identical to a clean one. Redaction fixed a real leak — an
      unencoded `/` in a password defeated every URL parser. Nothing logs a credential: asserted,
      and verified by leaking one on purpose.
- [x] **PERF** — point read 21.6 µs → 1.08 µs. `find_leaf` decoded every internal page, and each
      decode walked a child's whole leftmost spine to recover a key the caller already had
      (7000 → 4000 page reads per 1000 gets); `get_with_revision` decoded an entire leaf to keep
      one value; the WAL pre-filled runway *underneath* large records and then overwrote it; the
      value log copied large values twice in each direction. `benches/storage.rs` 3 → 19 cases,
      because three could not substantiate any claim about this engine's throughput.
- [x] **Final sweep** — 308 tests across 44 binaries, 0 failures, 0 warnings; clippy
      `-D warnings` clean workspace-wide; TypeScript build and 22/22 SDK tests green.
- [x] **PERF round 2 (write path)** — apply cost per request 81 → 50 µs at the 32-client batch
      shape, paired runs same host/session (Windows). Three changes, each found by a new
      `tree_decode`/`tree_encode`/`tree_append`/`tree_flush` split of the `tree` phase (now printed
      by `apply-profile`): (1) page-append buffering — one contiguous write per mutation instead of
      one syscall per copy-on-write page (~30 µs/request of pure `WriteFile` time at 3.5
      pages/request), flushed before the new root can escape so every on-disk invariant is
      unchanged, and a failed batch now *discards* its buffered pages instead of leaving disk
      orphans (mutation-verified test); (2) `collect_many` walks cells in place like
      `find_in_leaf` — pre-state 34.6 → 7.0 µs/request, page reads 32 → 23 (deterministic);
      (3) `write_internal_level` chunks by index ranges like `write_leaf_level` instead of cloning
      every child's min_key. Full write-up with measurements in docs/benchmarks.md. Workspace 311
      tests green ×2, clippy `-D warnings` clean. Bytes-level write amplification (14 KiB per 128 B
      write) still stands — that one is the persistence-strategy change, still queued.

- [x] **PERF round 5 (value-log reads)** — the rows vyrn lost to sled/redb were exactly the
      spilled-value rows (>1 KiB inline limit); every such read paid a `metadata` syscall, 1–2
      preads, and a CRC pass. Three fixes, criterion-paired on this host: cached file length with
      cross-handle refresh-on-overrun (mutation-verified — the metadata call WAS the multi-handle
      coherence, readers must still see the writer's appends), per-leaf `read_many` coalescing of
      exactly-adjacent records (validation per record unchanged, corruption-in-run test), and a
      64 MiB/handle second-chance cache of validated values keyed by offset+revision+len
      (`VYRN_VALUE_CACHE_BYTES`, 0 disables; sound because the log is append-only under a live
      handle and generation changes reopen it). point_get 4 KiB 4.4×, 64 KiB 9.3×, 1 MiB 2.2×,
      scan_1000 4 KiB 25× hot / 3.35× cold; 128 B rows untouched (never in the log);
      scan_1000/128b −2.5% accepted. Full write-up in docs/benchmarks.md.

- [x] **PERF round 6 (zero-copy reads + head-to-head)** — `get_shared`/`scan_shared` on Engine and
      ReadEngine return `SharedBytes` (page-backed inline values, value-cache-backed spilled ones,
      overlay-backed buffered ones; copying APIs are now materialising wrappers over the same
      paths, equivalence asserted in the model tests). Write-back publish staging opt-in
      (`enable_write_back_publish`, server calls it; embedded pays nothing). WAL runway fill
      scales with record size (~64 records per extension barrier at any size, cap 8 MiB,
      self-initialising rule untouched). Standalone 3-engine harness in `../vyrn-compare`
      (sled + redb, zero-copy APIs all around, sled flushed per put in its durable row): vyrn #1
      on point_get 128 B, both scans, durable_put 128 B/4 KiB. docs/benchmarks.md has the table.
- [x] **PERF round 7 (scan floor)** — scan rows stopped allocating: `scan_shared` rows carry
      shared keys AND values (the per-row key `Vec` was a third of a 128 B row's cost), the scan
      walks leaf cells in place instead of decoding whole leaves, and `scan_each` (generic
      visitor, borrowed slices, nothing built) is the new fastest range read — all three
      equivalence-tested against `scan` in the model suite, merge fallback covered by the
      buffered engine. scan_1000 4 KiB 9.6–9.7M rows/s (#1, 2.3× redb), 128 B ~9.9M (#1 by a
      nose, trading ±5% with redb's guards run to run).
- [x] **PERF round 8 (slot-directory pages, format v5)** — a u16 cell-offset directory at the
      page tail, purely additive over v4 (cells identical, sequential readers unchanged, v4 pages
      readable forever and converted on rewrite, CRC covers the directory for free). Leaf lookups
      and internal descents binary-search; scans enter their first leaf by binary search, read
      only the fields a row needs, and stopped calling `decode_internal` (a NodeRef alloc per
      child + a leftmost-spine walk per internal page). Found real data loss: `prepare_delete`
      kept only the first replacement — a delete could never split before, now it can (packed
      legacy leaf + slot bytes), and the new test fails against the old code. Forged-directory
      test mutation-verified. Harness: point_get 4 KiB 624K → 1.18M (2.1× behind redb → 1.14×),
      64 KiB 1.11M → 1.70M (1.8× → 1.19×), scan_1000 4 KiB 10.2M rows/s (#1 by 2.5×), everything
      else held. Write-up in docs/benchmarks.md.
- [x] **PERF round 9 (commit diet + cache hashing + honest cache parity)** — `apply-profile` at
      the 1000-op batch shape showed prestate at 48% of apply. (1) The pre-state machinery
      collapsed: `wanted` BTreeSet → sorted Vec, the `existing` BTreeMap (whose revisions nothing
      read) deleted, keys MOVE into the presence overlay (now a fast-hash map) and update through
      `get_mut` — two maps and ~4 key clones per op became one map and one clone. (2) Page cache
      and value cache left SipHash for a dependency-free multiply-xor u64 hasher (keys are
      engine-allocated ids; spread-test pinned). (3) `collect_many` binary-searches sparse leaves
      via the slot directory, merge-walks dense ones. (4) Harness fairness fix: only vyrn's VALUE
      cache had 1 GiB parity — its page cache sat at the 16 MiB default against sled's 1 GiB
      tree cache and redb's unbounded mmap; `VYRN_PAGE_CACHE_PAGES` now gets the same 1 GiB.
      Harness: batch_put 211K → ~268K (now trading with redb), point_get 4 KiB now trading
      (1.27M vs 1.19M in the confirming run), scan_4KiB #1 by 2.3–2.8×. Write-up in
      docs/benchmarks.md.
- [x] **PERF round 10 (row cache + segment scans + tombstone skip)** — 8 of 9 harness rows #1.
      (1) Row cache (`row_cache.rs`, `VYRN_ROW_CACHE_BYTES`, default 64 MiB): newest committed
      value per user key, one fast-hash probe per hit; invalidated in write_batch and replica
      apply after visibility — the only two paths that can mutate a cacheable key (get/get_shared
      refuse internal keys; everything else is content-preserving or pre-serving). Absence never
      cached. `tests/row_cache.rs` ×3, all fail with invalidation removed. point_get 128 B/4 KiB/
      64 KiB → 3.0–3.7 M/s, ALL #1 over redb by 1.75–2.7× (4 KiB and 64 KiB were the contested
      rows). (2) Scans emit between binary-searched index bounds — range and excluded-prefix
      filters computed once per leaf, zero per-row key comparisons; scan_4KiB 12.5–13.1M rows/s
      (3× redb). (3) `tombstones_possible` flag (open probe + monotonic set on first
      tombstone-writing delete, live within a batch) halves a delete-free commit's pre-state
      sweep; batch_put 328K #1 over redb (row noisy on this host: one run dipped to 162K with
      sled dipping alongside). Docs in benchmarks.md. NOT done: row cache on the server's
      ReadEngines (their overlay refresh is a separate design — publications already carry the
      keys, so the same invalidate-on-apply rule fits; queued), row cache metrics counters.
- [x] **PERF round 11 (embedded group commit — `Engine::drain_wal`)** — the durable rows went
      from disk-floor to 10K+: `durable_c64` 128 B **34,592/s** (16.7× the single-writer floor,
      8.7× sled's group, 27× redb), 4 KiB **11,055/s**, 64 KiB 1,340/s trading with sled at the
      device's bandwidth wall (10K × 64 KiB = 640 MB/s payload — past this SSD with durability on
      OR off). Found and named the Windows convoy: FlushFileBuffers serializes against WriteFile
      on the same file, so eager appends under the engine lock collapse a group to ONE commit per
      fsync (measured 2,110/s at 32 writers = the single rate). Fix = the server's split, now
      expressible embedded: Async-mode commits buffer records in memory under the lock;
      `drain_wal` (new, refactored out of `Engine::sync`) hands them to the kernel under the lock
      and returns the owed LSN; `Wal::sync_through` runs OUTSIDE the lock on the shared handle.
      WAL-only durability — identical to a durable-mode commit's own barrier. Proof in
      tests/group_commit.rs: crash-copy the live dir mid-flight; the acked commit survives, the
      un-drained one does NOT (which is what proves the copy models a crash). Harness grew
      `durable_c64` rows for all three engines (sled coalesces flush(), redb serializes
      exclusive txns — its design, reported as found).
- [ ] **Single-writer durable on cheap-barrier hosts: vyrn ~200 µs/commit vs sled ~50.** A Linux
      sandbox run (fsync ~45 µs) showed vyrn 4.9–5.3K/s single-writer against sled's 19.7–22K —
      overhead the Windows fsync hid completely. The WAL phase is now split (wal_encode/fill/
      write/sync + bytes and fills per request, printed by apply-profile) so the next sandbox run
      can attribute it. Run `CLIENTS=1 WRITE_BACK=8388608 CHANGE_LOG=0 apply-profile` there and
      read the split before changing anything. **First bite taken (round 12):**
      `EngineOptions::change_log` (default true, server unchanged) lets an embedded engine
      decline the subscription feature — the change record was riding a FULL COPY of every value
      through the WAL (a 64 KiB put wrote its value three times: value log, WAL op, change
      record; a 128 B put's WAL payload was ~2×). Declined in the harness (sled/redb have no
      change log). Even under this host's fsync: durable_c64 4 KiB 11.1K → 17.3K/s, 64 KiB
      1.34K → 2.13K/s, single 64 KiB now #1 over flushed sled, batch_put 354K. The sandbox's
      single-writer rows should close much of the 3.8× — rerun there. If a gap remains, the
      remaining suspects are wal_write shape and the runway fill's fdatasync on that filesystem.
- [ ] **What's still open on the bench front.** durable 64 KiB: bounded by the 2× spill
      amplification (value log + WAL both carry the bytes) and then by the device — the
      persistence-strategy change (WAL referencing value-log extents + value-log fsync in the
      barrier) buys at most 2× and costs recovery complexity; decide deliberately. The served
      path should expose the same group-commit shape the harness now proves embedded (the server
      already has the flush stage; check whether its worker appends eagerly under the engine lock
      — if so it convoys on Windows exactly as the harness did; Linux unaffected, write() and
      fsync don't serialize there). scan 128 B trades ±10% with redb; batch_put trades on good
      runs. Linux paired runs still queued and now cover group commit too.

## ⬜ Queued

- [ ] **Measure PERF round 4 on the Linux host, paired.** Three separate pairings with
      `compare-builds-linux.sh`: write-back on vs off (write + transaction modes — also read
      `vyrn_flushed_batches_total / vyrn_wal_flushes_total`, which round 2's apply shrink plus
      write-back should finally move off 1.007: apply no longer outlasts the barrier, so batches
      should coalesce and the 256-client saturation should lift), inline reads vs parent (read
      mode), and a pipelined-client run vs lockstep (needs a `MODES=pipeline` arm in the harness;
      the client API exists). No served-path claim goes in benchmarks.md until these run.
- [ ] **TypeScript SDK pipeline API** — the server side already serves any client that writes
      several frames before reading; the SDK just cannot express it yet. Mirror
      `Client::pipeline`: one write per burst, per-operation answers, refused ops consume their
      own slot.

- [ ] **Split the change record so a commit is not charged for its own bookkeeping.** Reported as
      a batch-only problem; it is worse than that. Measured: a *single* put of exactly
      `MAX_VALUE_SIZE` is refused, and `MAX_VALUE_SIZE - 21` is the largest value that commits with
      an 8-byte key. Every commit appends one internal record encoding its published keys and
      values, and that record is validated against the same ceiling as the caller's values, so its
      framing (4 count bytes, 9 per entry, plus each key) is charged to a budget it does not appear
      in. The advertised 16 MiB limit is therefore unreachable by anyone, and the ceiling scales
      with *batch* size as well — sixteen 1 MiB puts are refused. The error names the value, which
      is misleading: nothing the caller passed was too large.
      **Raising the cap is not the fix.** The WAL payload validator (`lib.rs:3098`) independently
      rejects an operation over `MAX_VALUE_SIZE` during replay, so a commit that succeeded would
      fail its own recovery. The record has to split across keys.
      Splitting is feasible — `change_log_key` is prefix + `sequence.to_be_bytes()`, so a part
      suffix preserves commit-then-part sort order — but it touches cursor semantics at five sites
      that each assume one key is one commit: `read_changes` (`lib.rs:1903`, whose `scan_limit + 1`
      counts commits), `published_cursor` (`:1953`, which reads the last key's record count for the
      cursor index), the retained count (`:1983`), `trim_changes` (`:1999`, which must not drop
      part 0 while part 1 is undelivered), and `change_log_sequence`'s 8-byte suffix assertion.
      `ChangeRecord.index` is per-commit, so indices must stay continuous across parts or every
      cursor a subscriber holds becomes wrong.
      *Landed already:* both failures are recorded as `#[ignore]`d tests in
      `tests/change_log.rs` (run with `--ignored`), a passing test pins the current ceiling so the
      documented overhead cannot go stale, and `docs/production.md` plus the README now state the
      real limit instead of the one nobody can reach.
      **Delete `batch_keys()` from `benches/storage.rs` when this lands** — it exists only to work
      around this, and is marked as such.
- [x] **`DOCUMENT_INDEX_PREFIX` no longer duplicates `document::INDEX_PREFIX`** — the exemption in
      `validate_index_name` imports the document layer's constant instead of restating it, so the
      test that pinned the two spellings together now covers the routing rather than guarding
      against drift.
- [x] **PERF round 3 (zero-copy + write-back)** — two changes on top of round 2, both measured
      with the same probe on the same host. (1) Zero-copy page decode: `Entry.key`,
      `EntryValue::Inline`, and `NodeRef.min_key` became `Bytes` (owned, or an `Arc<Page>`-backed
      slice read in place), and `prepare_batch` takes its mutations by move — decode cost
      26.4 → 9.8 µs/commit at the single-key shape, apply 50.0 → 44.6 µs/request at the 32-client
      shape. (2) **Write-back buffering, opt-in via `EngineOptions::write_back_buffer`** (default
      0 = off; server and replicas unchanged, replica apply refuses it explicitly): a commit is a
      WAL record plus an in-memory buffer entry, every read merges the buffer over the tree, the
      tree absorbs the buffer in one amortised pass at a byte threshold and on checkpoint. WAL
      records name `WRITE_BACK_ROOT` (never adoptable) so reopen always takes the existing
      redo-from-checkpoint path — mutation-verified: encoding the stale tree root instead makes
      both recovery tests fail with silent data loss. Measured: engine CPU per request beside the
      fsync went ~70 → ~5 µs (32-client shape) and ~200 → ~16 µs (single-key), pages/request
      3.5 → 0.1. Six tests in `tests/write_back.rs`, including a 600-step classic-vs-write-back
      equivalence model crossing several threshold flushes. `docs/benchmarks.md` has the full
      write-up. ~~Queued follow-up: the server's `ReadEngine`s must learn to see the buffer~~ —
      done in PERF round 4 below.
- [x] **PERF round 4 (served-path structure)** — three changes, all tested, none timed on this
      host (Windows timings do not travel; the paired Linux runs are queued below).
      (1) **Server write-back** (`--write-back-bytes`): every `ReadEngine` keeps its own overlay
      copy of the buffer, fed one durable commit at a time by the flush stage — `PendingFlush`
      carries `Engine::take_write_back_publish()` (captured under the engine lock like
      `last_published`, taken only on success), applied under the same reader write lock as the
      root refresh, evicted per-entry by absorb watermark (never clear-all: the checkpoint task
      publishes concurrently, and a commit that reached a reader after the checkpoint absorbed
      must survive its eviction — reader-parity model test pins exactly that interleaving, with a
      read-your-write probe per step because a sampled probe provably missed a 3-LSN-early
      eviction). Merge logic extracted to `overlay::merged_*`, one implementation for Engine and
      ReadEngine. Index create/drop now publish through the flush stage (empty publication in
      classic mode — behavior unchanged there). Found and fixed pre-existing: `drop_index` /
      `clear_index_entries` scanned the raw tree and missed buffered entries — a recreated index
      resurrected them as stale lookups (mutation-verified). End-to-end: shipped server at
      `VYRN_WRITE_BACK_BYTES=4096`, read-your-write ×300 + docs + index visibility + kill and
      WAL-only recovery; fails at the third read with the publication reverted.
      (2) **Inline point reads**: `submit_get` answers on the connection task via shared
      `try_read` on a read handle (succeeds even beside a running scan; falls back to the reader
      queue while a publish holds the handle). Scans/multi-gets/documents stay on workers.
      (3) **Protocol pipelining**: the session drains every buffered request before flushing
      (lockstep clients unchanged), responses leave in one write per burst under the same
      wedged-peer timeout; `Client::pipeline` submits a get/put/delete batch in one round trip
      with per-operation answers — in-burst ordering pinned by a put→get→delete→get chain test.
      Workspace green, clippy `-D warnings` clean.
- [ ] **Run `scripts/crash-soak.sh` on Linux.** Written, `bash -n` clean, and every env var and
      CLI flag it uses was verified to exist — but never executed, because it is Linux-only by
      design and this host is Windows. Its `shutdown` mode is also the only coverage that exists
      for the shutdown-sync fix, which has no Rust test for the same reason.
- [ ] **Prove the change-broadcast ordering.** The D2 fix is structurally enforced — the write
      worker no longer *holds* a broadcast handle — but its test passes against the unfixed server
      too: three workload designs failed to open the reorder window on this machine, because both
      paths fsync and the flush stage's starts first. Needs a slower disk, a fault injector, or a
      deterministic scheduler before it demonstrates anything.
- [ ] **`vyrn_checkpoints_total` counts the wrong event** — incremented where a checkpoint is
      *scheduled*, on the write path, not where it runs in the maintenance task, so the counter and
      the work can disagree. Noted in production.md; the new `vyrnd.checkpoint` log record, which
      carries the duration and the trigger, is the reliable signal in the meantime.

## 🔽 Deferred — reviewed, deliberately out of fleet scope (do not lose these)

Design-level / roadmap:
- Single shared credential; no per-principal ACLs, revocation, or audit trail (security
  reviewer: the design that makes brute-force and gateway DoS single-point failures)
- No automatic failover/fencing for replication — manual promotion is documented behavior
- B-tree deletes never rebalance: monotonic space growth + tree height inflation between
  checkpoint compactions (delete-heavy workloads)
- WAL record header carries no checksum of its own — one flipped bit in `payload_len`
  silently discards that record and everything after it (needs a format-version bump;
  documented in tests/corruption.rs)
- `>2^53` integers: TS SDK `Number` precision loss + `JSON.parse` corruption for values
  written by Rust clients (cross-language fidelity, needs protocol-level decimal/BigInt)
- TS SDK subscription auto-reconnect (silent death is fixed; resurrection is not)

Platform/ops limitations (document, don't code):
- `sync_directory` is a no-op off Unix — Windows directory-entry durability is unproven
- `production.md` exit gates still need RUNNING on real Linux hardware: multi-hour
  larger-than-memory soak, restore + PITR drill (crash-soak.sh gives you the tool)
- CI gaps: no coverage measurement, no benchmark-regression gate, no docker build job.
  `benches/storage.rs` is no longer part of this — it went 3 → 19 cases in the perf round and now
  covers four value sizes across point read, single write, batched write, overwrite, scans, and
  cache pressure. What is still missing is a *gate*: nothing fails when a number regresses

Small items parked (fix opportunistically):
- ~~Page-cache admission~~ **fixed in the perf round**: `append()` now admits unreferenced, as its
  doc comment always claimed. Misses under cache pressure 27 → 14; no timing change, because the
  commit's fsync dominates that case
- Snapshot tokens are bare `u64` from two parallel registries — mismatched release silently
  pins revisions forever; an RAII guard would make it unrepresentable. Partly mitigated: the
  release is now unavoidable on every connection exit path, and
  `vyrn_active_transaction_snapshots` makes a leak visible instead of silent
- `write_indexed` trusts caller-supplied `old_value`/`new_value`; wrong input silently
  corrupts the index with no detection
- `recover_to` merge/trim runs without the data-dir lock (narrow concurrent-backup window)
- Header rot in a semantically dead SEALED segment still blocks open (tolerance goal
  half-implemented — body scan skips, header read is strict)
- Gateway has no per-route rate limiting (connection cap only); connection-slot squatting
  by authenticated idle clients has no per-IP fairness
- ~~Dead reader thread reports "queue is full"~~ **fixed in D2**: a disconnected reader now says
  "storage reader stopped; this node cannot serve reads until it is restarted". Untested — a
  reader thread cannot be killed from a test without poisoning a lock
- Deps not hoisted to `[workspace.dependencies]` (rand_core, tokio-postgres, criterion…)
- Rust client clamps over-limit `limit` silently; TS SDK throws — same input, different
  behavior per SDK (deliberate, but worth documenting)

## Rules the fleet works under

File ownership per task; never touch teammates' files; regression test per fix; no commits
(commit split belongs to the owner); compile after each edit in `main.rs`; retry on transient
teammate noise instead of fixing foreign files; honest test numbers in every report.

Two rules earned the hard way, worth keeping:

**A regression test is not done until it has failed.** Revert the fix, watch the test fail, restore
it. Two tests in this round would otherwise have been worthless: a snapshot-pin leak test built on
`vyrn_mvcc_versions_collected_total` passed either way, because history is only retained for
versions a live snapshot needs, so with no open transaction the counter sits at zero whether or not
the pin leaked — it needed a new gauge that observes the pin directly. And a metric helper that
matched on a bare string prefix silently returned the wrong series for any metric whose name
prefixed another.

**Never run a tree-wide git operation while agents are working.** `git stash`, `git checkout -- .`,
`reset --hard` — any of them yanks in-progress edits out from under a running task. To check that a
staged subset stands alone, inspect the other diffs for new public items it might depend on, or
build it in a separate worktree; do not mutate the shared tree.
