# Vyrn single-node production runbook

## Supported envelope

Vyrn `0.1.0-dev` is a single-node production candidate for Linux x86-64 on local persistent ext4/XFS storage. It is not highly available. A host or disk failure causes downtime and may require restore.

Use it only when:

- the application can tolerate single-node downtime;
- automated verified backups exist outside the host;
- TLS 1.3 is enabled and the admin listener remains private;
- the data directory is on local persistent storage, not an ephemeral container layer;
- `durable` mode is used for authoritative records; `async` is limited to reconstructable realtime state and its bounded loss window is accepted;
- monitoring alerts on readiness, failed requests, disk space, backup age, and write-batch efficiency.

Current observed WSL2/Linux baseline with 16 persistent clients and 128-byte values is approximately 105k snapshot reads/s (p99 0.33 ms), 1.2k durable writes/s (p99 64 ms), and 2.9k ops/s in a 70/30 durable mix (p99 46 ms). Async mode reached roughly 100k reads/s and 5k mixed ops/s. Persistent async commit-to-subscription latency measured p50 1.56 ms, p95 4.36 ms, and p99 5.93 ms. These are development-machine measurements, not deployment guarantees; benchmark the actual host and disk.

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

## Failure handling

If readiness becomes false or a storage error is logged:

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
