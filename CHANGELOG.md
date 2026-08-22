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

### Changed

- Release builds enable overflow checks, thin LTO, and one codegen unit.
- The Docker image defaults the admin listener to loopback inside the
  container; override `VYRN_ADMIN_BIND` to publish metrics deliberately.
