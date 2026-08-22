# Changelog

All notable changes to Vyrn are documented here. Until the 1.0 release the
on-disk storage formats may change incompatibly between versions — see
`docs/production.md` for the current compatibility statement.

## [Unreleased]

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
