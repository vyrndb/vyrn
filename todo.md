# vyrn — production-readiness TODO

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

## 🔶 In flight — damaged by rate-limit/infra kills, must be finished or redone

- [ ] **C1** `lib.rs` criticals — *mostly applied* (checkpoint_generation commit point,
      apply_batch atomicity Case A/B, active-segment stop-at-first-invalid replay, sync()
      per-record LSNs + poison, startup segment-gap temp+rename). Needs: audit vs list, finish
      missing pieces, zero warnings, full core tests green.
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
- [ ] **E3** adversarial parsing suites — *not started* (three infra deaths). Create
      `crates/vyrn-core/tests/adversarial_parsing.rs` (document/portable/archive parsers:
      arbitrary bytes, truncation walks, forged u32::MAX counts → clean errors) and
      `scripts/crash-soak.sh` (kill -9 loop asserting acknowledged writes survive).

## ⬜ Queued

- [ ] **C2** MVCC history coverage watermark (lib.rs + mvcc.rs): track covered-through LSN
      distinct from gc_floor; reject reads below coverage (`SnapshotTooOld`); stop stale history
      shadowing tree revision in `revision()`/`changed_since()`; regression tests from reviewer
      repro recipes (vanishing keys, present-as-past, missed conflicts).
- [ ] **C3** lib.rs medium batch: unique-index same-batch claims (moves/swaps legal),
      `last_published` scoping, `limit == 0` scans, `Cursor::start()` clamp, snapshot-registry
      expects → Poisoned, replay/live version-filter parity, `validate_index_name` namespace.
- [ ] **D2** server correctness: single ordered change-broadcast point (no reorder/drop under
      mixed doc+KV load), batch conflict validation includes plain ops + index keys, slow-scan
      stall mitigation, dead-reader error message, per-statement deadline.
- [ ] **D3** replication gap recovery: wire `recover_to` into replica join so a lagging replica
      rebuilds from base backup instead of failing; extend replication tests.
- [ ] **E1** logging/tracing: structured logs with timestamps/levels; storage errors actually
      logged (production.md promises this), auth failures, lifecycle events, checkpoint/backup
      outcomes; gateway logs upstream detail.
- [ ] **Final sweep**: full workspace tests + clippy `-D warnings` + TS build, plus fresh
      adversarial re-review of the entire diff.

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
- CI gaps: no coverage measurement, no benchmark-regression gate, `benches/storage.rs`
  (3 cases) doesn't substantiate the headline benchmark figures, no docker build job

Small items parked (fix opportunistically):
- Page-cache admission: `append()` admits pages referenced, contradicting the function's
  doc comment claiming unreferenced (COW bursts can evict read-hot pages)
- Snapshot tokens are bare `u64` from two parallel registries — mismatched release silently
  pins revisions forever; an RAII guard would make it unrepresentable
- `write_indexed` trusts caller-supplied `old_value`/`new_value`; wrong input silently
  corrupts the index with no detection
- `recover_to` merge/trim runs without the data-dir lock (narrow concurrent-backup window)
- Header rot in a semantically dead SEALED segment still blocks open (tolerance goal
  half-implemented — body scan skips, header read is strict)
- Gateway has no per-route rate limiting (connection cap only); connection-slot squatting
  by authenticated idle clients has no per-IP fairness
- Dead reader thread reports "queue is full" instead of "reader stopped"
- Deps not hoisted to `[workspace.dependencies]` (rand_core, tokio-postgres, criterion…)
- Rust client clamps over-limit `limit` silently; TS SDK throws — same input, different
  behavior per SDK (deliberate, but worth documenting)

## Rules the fleet works under

File ownership per task; never touch teammates' files; regression test per fix; no commits
(commit split belongs to the owner); compile after each edit in `main.rs`; retry on transient
teammate noise instead of fixing foreign files; honest test numbers in every report.
