# Vyrn single-node production runbook

## Supported envelope

Vyrn `1.0.0` is a single-node production database for Linux x86-64 on local persistent ext4/XFS storage. It is not highly available. A host or disk failure causes downtime and may require restore.

Use it only when:

- the application can tolerate single-node downtime;
- automated verified backups exist outside the host;
- TLS 1.3 is enabled and the admin listener remains private;
- the data directory is on local persistent storage, not an ephemeral container layer;
- `durable` mode is used for authoritative records; `async` is limited to reconstructable realtime state and its bounded loss window is accepted;
- monitoring alerts on readiness, failed requests, disk space, backup age, and write-batch efficiency;
- the security model in `docs/security.md` matches the deployment's requirements (single shared credential, no ACLs, no audit trail — read it before assuming otherwise), and the upgrade rules in `docs/compatibility.md` are followed (replicas upgrade before primaries; downgrade is unsupported).

Current observed WSL2/Linux baseline in `durable` mode with 16 persistent clients and 128-byte values, measured 2026-07-27: approximately 83k snapshot reads/s (p50 0.19 ms, p99 0.33 ms), 5.7k durable writes/s (p50 2.8 ms, p99 4.7 ms), 13.8k ops/s in a 70/30 durable mix (p50 0.30 ms, p99 5.3 ms), 50k index lookups/s, and 2.6k four-key transactions/s. See `docs/benchmarks.md` for the full matrix. The async-mode and commit-to-subscription figures previously quoted here were not re-measured and have been removed rather than carried forward stale.

Two properties matter more than the averages when sizing a deployment:

- **Write throughput does not scale with client count.** It saturates near 8.6k/s at 64 clients and is *lower* at 256 than at 64, because commits serialise through a single engine write lock. Offering more concurrent writers past that point buys latency, not throughput.
- **The write tail is unresolved.** At 256 concurrent writers, p99 is roughly 200 ms and the maximum is several seconds, reproducibly. It is not yet established whether that originates in Vyrn or in this host's storage — a bare `fdatasync` on the same filesystem has itself been caught stalling 5.6 seconds. Do not put a latency SLO in front of concurrent durable writes until this is measured on the intended hardware.

These are development-machine measurements, not deployment guarantees; benchmark the actual host and disk.

## Deployment

- Run one `vyrnd` process per data directory.
- Mount `/var/lib/vyrn` on persistent storage.
- Mount the TLS key and Argon2id verifier as read-only secrets.
- Expose port 7432 only to application networks.
- Keep port 7433 on loopback or a private monitoring network.
- Stop routing traffic when `/health/ready` returns 503.

## Backup policy

Backups are offline and acquire the database lock. Stop `vyrnd`, then:

```bash
vyrn backup --data /var/lib/vyrn --output /backups/vyrn-$(date +%F).vyrn
vyrn verify-backup /backups/vyrn-$(date +%F).vyrn
```

Copy the verified archive to another host or object store. Regularly prove restoration:

```bash
vyrn restore backup.vyrn --target /var/lib/vyrn-restored
```

Restore refuses non-empty targets and verifies every file checksum before completing.

A database that has not checkpointed yet has no `CURRENT` manifest, which is a
normal early state rather than a fault: backup includes the WAL, and both restore
and point-in-time recovery replay it onto the empty base root. Backup refuses only
a directory with no page file at all, which is not a Vyrn database. Earlier builds
refused any database without a manifest, so the first backup of a new deployment
had to wait for a checkpoint.

### Continuous WAL archiving

Offline backups bound loss to the backup interval. Add continuous archiving to shrink the loss window to the rotation interval plus archive latency:

- Set `VYRN_WAL_ARCHIVE_DIR` to a local directory outside the data directory (the server refuses a nested one) and keep `VYRN_WAL_ARCHIVE_INTERVAL_MS` at its 5000 ms default unless the loss window demands less; the minimum is 100.
- Archiving never blocks writes: it copies only sealed, immutable segments, and checkpoints keep any sealed segment the archiver has not durably copied.
- The archive directory is local by design. Ship it off-host yourself (rsync, object-storage sync) on a schedule at least as frequent as your loss-window target.
- Run `vyrn verify-archive <dir>` periodically; it re-reads and re-checksums every archived byte, catching disk rot the index alone cannot see.
- Reclaim local WAL disk only with `vyrn wal-prune --data <data> --archive <dir> --through <id>` against a stopped server; it refuses to delete anything the archive does not provably hold, and it keeps any segment holding records above the published checkpoint regardless of `--through` — replay still needs those records locally, so pruning fewer segments than requested is normal on a database stopped between checkpoints.

**Alert rule:** `vyrn_wal_archive_lag_segments` growing over time means the archiver is falling behind the write rate and the local WAL directory is growing without bound, because checkpoints cannot delete unarchived segments. Alert on sustained growth, and on any increase of `vyrn_wal_archive_failures_total`.

### Point-in-time recovery procedure

1. Stop routing traffic; do not start a replacement writer against the old archive.
2. Copy the archive directory from off-host storage to the recovery host.
3. `vyrn verify-archive /path/to/archive` — confirm the reported LSN range covers the target point.
4. `vyrn verify-backup base.vyrn` for the newest base backup taken at or before the target LSN.
5. `vyrn recover --base base.vyrn --archive /path/to/archive --target /var/lib/vyrn-recovered --until-lsn N` (omit `--until-lsn` to roll forward to the archive's end). The bound cannot be below the base checkpoint's LSN; `--allow-partial` is required to accept an earlier LSN than requested.
6. If recovery fails, delete the target directory and start over from step 5; a failed target is unusable by design.
7. Start `vyrnd` against the recovered directory with a **new, empty** `VYRN_WAL_ARCHIVE_DIR`. The recovered database is a new timeline, and archiving it into the old directory would poison the only copy of the old history.
8. Smoke-test reads of known keys before restoring traffic.

**Windows caveat:** `sync_directory` is a no-op on non-Unix platforms, so archive-directory durability (the rename publishing a copied segment or the index) is not certified on Windows. Windows remains a development-only platform; run archiving in production on Linux ext4/XFS only.

**Windows caveat, concurrent writes:** on Windows, `FlushFileBuffers` serializes against `WriteFile` on the same file, and `vyrnd`'s write worker appends WAL records eagerly under the engine lock while the flush stage syncs — so group commit degrades toward one commit per fsync there. Linux is unaffected (the production platform). The embedded engine offers the convoy-free shape (`DurabilityMode::Async` + `drain_wal`); teaching the server's flush stage the same split is queued.

## Logs

Every Vyrn binary writes structured single-line records to **stderr**. Each record is a timestamp, a level, a target, a message, and `key=value` fields:

```text
2026-08-22T19:40:49.722Z ERROR vyrn-http.request request failed upstream method=POST path=/v1/put status=503 detail="database reported Storage: corrupt WAL segment 5 at byte 1234"
```

The timestamp is RFC 3339 UTC with millisecond precision. Values containing a space, an `=`, or a quote are quoted, and control characters are escaped, so a record is always exactly one line and cannot be forged by client-supplied text. Each record is written in a single call, so concurrent writers cannot interleave halves of a line.

Set `VYRN_LOG` to `off`, `error`, `warn`, `info` (the default), `debug`, or `trace`. An unrecognised value falls back to `info` rather than muting the log, so a typo in a deployment's environment cannot be the reason an incident has no diagnostics.

What each level is for:

- **error** — the process cannot do what it was asked and you must act: storage failures, a background worker that will not come back, a failed startup connection.
- **warn** — something was refused or degraded and the process carried on: rejected credentials, a readiness loss, a failed probe.
- **info** — lifecycle only: startup with the effective configuration, bind addresses, whether TLS is on, readiness transitions, drain and shutdown, and checkpoint/backup/recovery outcomes with durations. Safe to run in production; there is no per-request record at this level.
- **debug** — per-request and per-connection detail for chasing a specific failure. Expect one or more records per request; do not leave this on for a busy deployment.

Run at `info` in production. `debug` is what you raise to when you are investigating.

Two properties are deliberate:

- **Secrets are never logged.** No passwords, no bearer tokens, no Argon2 verifiers. Connection URLs are redacted before they reach a record (`vyrn://user:[REDACTED]@host:7432/app`) because a Vyrn URL carries the database password in its userinfo — and the startup record is the one most likely to be pasted into a ticket. A rejected bearer token is never recorded, not even truncated: a near-miss is still a live credential.
- **The HTTP gateway scrubs for the client and logs in full.** API clients get `database storage error` with no internals, while the log keeps the upstream cause together with the method and route it failed on. A 503 from the gateway is always attributable to something in the log.

Logs complement the metrics on the admin listener; they do not replace them. Alert on the metrics, then read the logs to find out why. Note that `vyrn_checkpoints_total` counts checkpoints *scheduled* by the write pipeline, not completed by the maintenance task.

All three binaries — `vyrnd`, the `vyrn-http` gateway, and the `vyrn` CLI — emit the format above throughout. In `vyrnd` specifically, the records worth knowing about are:

- **`vyrnd.storage`** — every storage failure, carrying the `operation` that failed. At `error` when the engine is poisoned or I/O failed, which is also when readiness drops; at `warn` for a single failed operation on a server that is still healthy.
- **`vyrnd` `readiness withdrawn`** — emitted with a `reason` naming the task that stopped (`wal flush task`, `mvcc gc`, `async sync`, `write worker supervisor`, and so on). This is the record that tells you *which* background worker died, which no counter can.
- **`vyrnd.auth`** — a rejected handshake, with `reason=throttled` when the address was locked out before the password was checked and `reason=rejected` when it was checked and failed. The client cannot distinguish these two, deliberately, so the log is the only place the difference exists. A run of `throttled` means the address is being held out and is no longer costing you Argon2 work.
- **`vyrnd.checkpoint`** — a completed compaction with its `duration_ms` and the `trigger` that fired. A checkpoint is the longest operation this process performs and the first thing to suspect when write latency spikes.
- **`vyrnd.replication`** — join decisions, rebuilds, divergence, and stream failures.

Two conditions are reported at `debug` on purpose, because they are per-connection: a connection that closed with an error, and a successful authentication. A client looping on a refused credential would otherwise fill the log with records about itself.

There is no log rotation and no file sink. Vyrn writes to stderr and expects the supervisor to handle the stream — systemd's journal, Docker's logging driver (`docker-compose.yml` configures rotation), or a collector of your choosing.

## Failure handling

The trigger is `/health/ready` returning 503, since `vyrnd` sets readiness false on every storage failure that poisons the engine. Alert on that rather than on a log line: readiness is a state you can poll, and a log record is an event you might miss. Then read the log to find out why — a `vyrnd.storage` record names the operation that failed, and the accompanying `readiness withdrawn` record names the task that stopped. The gateway logs its upstream cause too, so a `database_storage_error` there names what the database reported.

When readiness becomes false:

1. Stop routing traffic.
2. Stop the process; do not repeatedly retry writes against a poisoned engine.
3. Preserve a copy of the data directory.
4. Restart once to run normal WAL recovery.
5. Read back a key known to have been acknowledged shortly before the failure.
   Recovery replays the WAL, but read handles open from the checkpoint manifest,
   so this is the check that the two agree; earlier builds could serve
   `not found` for an acknowledged write after a crash until the next commit.
6. If corruption prevents startup, restore the latest verified backup.
7. Do not delete or edit WAL/page files manually.

## Known limitations

These are reviewed, understood, and deliberately not fixed in `1.0.0`. Each one can affect a production deployment, so plan around them rather than discovering them during an incident.

### The largest value you can actually write is under 16 MiB

`MAX_VALUE_SIZE` is 16 MiB and both the README and the protocol describe values up to that size. A value of exactly that size is refused with `ValueTooLarge`.

Every commit appends one extra internal record describing the changes it published, and that record is validated against the same 16 MiB ceiling as the values the caller supplied. Its framing — four bytes of entry count, nine bytes per entry, plus a copy of each key — therefore comes out of the caller's budget without appearing in it. With an 8-byte key, the largest value that commits is `MAX_VALUE_SIZE - 21`.

The same accounting makes the ceiling scale with the size of a *batch* rather than of any value in it, so sixteen 1 MiB puts in one `write_batch` are refused even though each is a sixteenth of the limit. The reported error names the value, which is misleading: nothing the caller passed was too large.

Plan around it by keeping values a few kilobytes below 16 MiB, and by keeping the total payload of a single batch under that too. Raising the constant is not the fix — the WAL validator independently enforces the same bound during replay, so a commit that succeeded would fail its own recovery. The fix is to split the change record across several keys, which changes cursor semantics and is tracked in `todo.md`; `crates/vyrn-core/tests/change_log.rs` carries both failing cases as `#[ignore]`d tests, runnable with `--ignored`.

### One shared credential, and no audit trail

The server authenticates a single username and password against one Argon2id verifier. There are no per-principal accounts, no per-key or per-collection authorization, no revocation short of rotating the one credential and restarting, and no record of which client did what — the log records that authentication failed and from which address, never who succeeded at what.

Consequences to plan for: every application sharing a database shares one identity, so a leak anywhere is a leak everywhere and rotation is a coordinated restart of every client. Repeated authentication failures from one address are rate-limited (`vyrn_auth_failures_total`, plus a lockout), but the gateway's own bearer token has no equivalent throttle. Treat network reachability as the real access control: keep port 7432 on application networks only and the admin listener on loopback or a private monitoring network.

### Windows directory durability is unproven

`sync_directory` is a no-op on non-Unix platforms. On Windows, the directory entry created by a rename — publishing a checkpoint manifest, a copied WAL segment, or an archive index — is not forced to disk, so a power loss can leave a file whose contents are durable but whose name is not. Vyrn's recovery is built to survive a missing rename, but that path is not certified on Windows.

Windows is a development platform only. Run production on Linux ext4/XFS.

### A WAL record header carries no checksum of its own

Record payloads are CRC32-checked, but the header holding `payload_len` is not. A single flipped bit in that field makes the record decode at the wrong length: the record and **everything after it in that segment** are silently discarded as an incomplete tail. Recovery reports success and the database comes up short of acknowledged writes without ever reporting an error.

This needs a storage-format version bump to fix, so it is deferred. It is why the runbook's failure-handling procedure has you read back a key known to have been acknowledged shortly before the failure (step 5) instead of trusting a clean startup, and why verified off-host backups plus WAL archiving matter more than they would otherwise: a base backup plus an archive gives you a second copy of the history. `crates/vyrn-core/tests/corruption.rs` documents the behaviour.

### B-tree deletes never rebalance

Deleting keys frees space inside pages but never merges underfull pages back together. A delete-heavy or delete-then-reinsert workload therefore grows the page file monotonically and inflates tree height, which shows up as slower point reads as depth increases. Space and depth are only reclaimed by checkpoint compaction, which writes a fresh generation.

Plan for it: size disk for the high-water mark of live data plus churn, not for the current live set, and do not leave `VYRN_CHECKPOINT_WRITES` raised high enough to suppress compaction — a soak run at this repository's own expense grew a data directory to 41 GB that way. Watch data-directory size against the key count you expect.

### Integers above 2^53 lose precision in the TypeScript SDK

The TypeScript SDK decodes document JSON with `JSON.parse`, so every number becomes an IEEE-754 double. An integer written by a Rust client above 2^53 comes back rounded, silently and without error — and a document read, modified, and written back through the SDK persists the rounded value, corrupting data that was previously correct.

Affected values include 64-bit ids, nanosecond timestamps, and monetary amounts in minor units past ~9 quadrillion. Until the protocol carries a decimal or BigInt type, store such values as strings if any TypeScript client touches them. Rust clients are unaffected. The Rust and TypeScript SDKs also disagree on an over-limit scan `limit`: the Rust client clamps silently, the TypeScript SDK throws.

### No automatic failover

Replication is synchronous and acknowledges a commit only once N replicas hold it durably, but there is no automatic failover, leader election, or fencing. Promotion is a manual, documented procedure — see `docs/replication.md`. A primary failure is downtime until an operator acts.

## Upgrade policy

Before replacing a Vyrn binary:

1. Stop the server.
2. Create and verify a backup.
3. Keep the prior binary and backup until the new version passes application smoke tests.
4. Development storage formats may be incompatible until Vyrn reaches 1.0.

## Production-candidate exit gates

Before calling the exact build generally available:

- CI is green on native Linux and Windows.
- The Linux crash, corruption, backup, and restore jobs pass repeatedly.
- A multi-hour soak with a larger-than-memory dataset has stable memory and latency.
- Backup restoration is tested in the intended deployment environment.
- A restore-plus-PITR drill (restore a base backup, roll forward through a real archive to a chosen LSN, verify the data) passes in the intended deployment environment.
- Security and operational review is complete.

### Status as of 2026-07-27

Exercised on the WSL2 development host, which is **not** the intended deployment environment, so none of these close a gate on their own:

- Full test suite passes (30 binaries, no failures) and `scripts/smoke-linux.sh` passes, covering crash, corruption, backup, verification, and restore.
- A restore-plus-PITR drill ran against a live server over 146 archived segments spanning LSN 1..=15995. Rolling forward to the archive end restored every marker; bounding recovery to the phase-A LSN restored all of phase A and correctly excluded all of phase B.

Still open, and these are the gates that matter:

- **The multi-hour larger-than-memory soak has never validly completed.** One attempt was run with `VYRN_CHECKPOINT_WRITES` raised high enough to disable compaction, so the data directory grew to 41 GB and the server stopped answering; that result says nothing about the database and must be re-run with checkpointing at its default. The one usable signal from it: write p50 degraded from 2.6 ms to 4.2 ms as the tree grew to roughly 3 GB, which matches the tree-depth sensitivity documented in `docs/benchmarks.md`.
- Security and operational review has not been done.
- Backup restoration and the PITR drill have not been run on the intended deployment hardware.
