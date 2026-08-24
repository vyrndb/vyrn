# Changelog

All notable changes to Vyrn are documented here. From 1.0.0 the on-disk
formats follow the contract in `docs/compatibility.md`: every 1.x build
reads what any earlier build wrote, and downgrade is unsupported.

## [1.1.0] - 2026-08-25

The "what it is not" release: four of the five 1.0 limitations fell.

### Added

- **Automatic failover** (`--cluster`, 3+ members): epoch-fenced quorum
  elections where a vote requires the candidate to hold every acknowledged
  write; primaries self-demote on lease loss and campaign again; two-member
  clusters are refused with the split-brain argument. Safety argument and
  operator procedure in docs/replication.md. Additive protocol messages,
  sent only when configured.
- **Per-user accounts, prefix ACLs, and an audit trail**
  (`VYRN_USERS_FILE`, `VYRN_AUDIT_LOG`): read/write/admin per key prefix,
  revocation by file edit, denials distinct from auth failures, audit lines
  that never contain values or credentials. The single-credential mode is
  unchanged; the wire protocol is unchanged.
- **Delete rebalancing**: underfull pages merge during copy-on-write
  rewrites on both delete paths; deleting 90% of a tree's keys now shrinks
  it ~9x instead of leaving it full-size until compaction.
- **Windows directory durability**: `sync_directory` performs a real
  directory flush on Windows (was a silent no-op), covering every
  rename-publish. Linux remains the soak-certified production platform.

## [1.0.0] - 2026-08-24

The first stable release. What "stable" freezes: the on-disk formats (tree
pages v5 with the slot directory, WAL records v5 with the header
self-checksum — v4 of both readable forever), the wire protocol, the
documented limits, and the upgrade rules (`docs/compatibility.md`). The
security model is a stated contract (`docs/security.md`): one shared
credential on a private network — read it before deploying.

### Added

- **Slot-directory pages (format v5)** — leaf lookups and descents
  binary-search; scans address cells directly and emit between
  binary-searched bounds with zero per-row key comparisons. Purely additive
  over v4: legacy pages stay readable and convert as they are rewritten.
- **WAL record header self-checksum (record format v5)** — one flipped bit
  in a record's declared lengths used to read as a torn tail and silently
  truncate the log; it is now loud corruption, and the exhaustive bit-flip
  test runs with no exemptions.
- **Row cache** (`VYRN_ROW_CACHE_BYTES`) — hot point reads in one hash
  probe, invalidated at the two paths that can mutate a cacheable key,
  with staleness tests that fail when the invalidation is removed.
- **Embedded group commit** (`Engine::drain_wal` + `Wal::sync_through`) —
  N writers share one barrier with per-op durability intact; proven by a
  crash-copy test where an unacknowledged commit vanishing is what proves
  the test models a crash.
- **Write-back mode end to end** — commit = WAL record + in-memory buffer,
  reader overlays on the served path, absorb on threshold and checkpoint.
- **Pay-for-what-you-use change log** (`EngineOptions::change_log`) — the
  subscription feature's cost (a change record carrying a copy of every
  written value) is declinable by embedded engines with no subscribers.
- **Compatibility and security contracts** — `docs/compatibility.md`,
  `docs/security.md`; CI grew a Linux crash soak (SIGKILL mid-write and
  SIGTERM-under-async against the shipped stack), a docker build gate, and
  a bench smoke.

### Performance

Measured against sled and redb in the 3-engine harness (fairness rules in
`docs/benchmarks.md`): first or trading on every row on the development
hosts — point reads 3.0–3.7 M/s at every value size, scans to 13 M rows/s,
group-commit durable writes to 34 K/s at 64 writers, batch puts ~350 K/s —
with the full write-ups, caveats, and the rows that are host-arithmetic
rather than engineering stated plainly in `docs/benchmarks.md`.

### Fixed

Production-readiness fixes from an 11-agent audit; each carries a regression
test. Highlights:

- **core**: a failed checkpoint no longer leaves `checkpoint_generation`
  stale, which previously let the next checkpoint unlink the live generation's
  files (potential unrecoverable database); post-manifest cleanup failures are
  now non-fatal.
- **core**: `apply_batch` is atomic across MVCC value-preparation and
  post-commit history appends — failures can no longer expose unacknowledged
  writes or report durable writes as failed.
- **core/page_tree**: torn page-file tails are truncated on open instead of
  permanently refusing to start; appends resume safely after partial writes;
  forged page headers can no longer drive huge allocations, hangs, or stack
  overflows.
- **core/recover**: point-in-time recovery handles crash-torn WAL tails
  (the runway zero-fill no longer fools the frame walker); archived segments
  are checksum-verified before adoption.
- **server**: transaction snapshot pins are released on disconnect paths;
  write timeouts and TCP keepalive prevent wedged peers from exhausting the
  connection budget; authentication failures are rate-limited.
- **protocol**: encoder enforces the decoder's field limits locally;
  protocol-version mismatches fail at decode; empty multi-get is framed
  correctly.
- **clients/gateway/sdk**: response timeouts retire the connection; abandoned
  transactions roll back on session release (Rust + TypeScript); the gateway
  retries once when the database closed an idle pooled connection.

### Added

- **Structured logging.** Every binary writes single-line records to stderr with
  an RFC 3339 UTC timestamp, a level, a target, and `key=value` fields, so logs
  can be filtered, correlated, and shipped. `VYRN_LOG` selects the level
  (`off`/`error`/`warn`/`info`/`debug`/`trace`, default `info`); an unrecognised
  value falls back to `info` rather than muting the log. No dependency was
  added — the facility is ~250 lines in `vyrn-client`, the one crate every
  binary already links.
- Secrets never reach a record: connection URLs are redacted before logging
  (a `vyrn://` URL carries the password in its userinfo), and a rejected bearer
  token is not logged even in part. Field values are escaped and quoted, so
  client-supplied text cannot forge a second record.
- **gateway**: a scrubbed 500/503 is now attributable. Clients still receive a
  generic error, while the log keeps the upstream cause together with the
  request method and route; previously the detail was discarded and the failure
  was undiagnosable. Readiness transitions, drain, and startup with the
  effective configuration are logged; readiness edges only, not every probe.
- **cli**: backup, restore, verify, export/import, WAL prune, and point-in-time
  recovery report their outcome with a duration, and archive size where a file
  can be measured. A recovery failure is recorded before the runbook has the
  operator delete the target directory.

### Known limitations

- `docs/production.md` now states the limitations an operator can hit: the
  single shared credential and absent audit trail, unproven Windows
  directory-entry durability (`sync_directory` is a no-op off Unix), the
  unchecksummed WAL record header (a flipped `payload_len` bit silently
  discards the rest of a segment), monotonic space growth from non-rebalancing
  B-tree deletes, `>2^53` integer precision loss in the TypeScript SDK, and the
  absence of automatic failover.
- `vyrnd` is converted too, so the runbook's instruction to act on a logged
  storage error is now something the process can actually do. Storage failures
  carry the operation that failed; a readiness withdrawal names the background
  task that stopped, which no counter could; a rejected handshake distinguishes a
  throttled address from a checked-and-failed password, a difference the client
  deliberately cannot see; and a completed checkpoint reports its duration and
  what triggered it.

### Changed

- Release builds enable overflow checks, thin LTO, and one codegen unit.
- The Docker image defaults the admin listener to loopback inside the
  container; override `VYRN_ADMIN_BIND` to publish metrics deliberately.
