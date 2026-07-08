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

## Failure handling

If readiness becomes false or a storage error is logged:

1. Stop routing traffic.
2. Stop the process; do not repeatedly retry writes against a poisoned engine.
3. Preserve a copy of the data directory.
4. Restart once to run normal WAL recovery.
5. If corruption prevents startup, restore the latest verified backup.
6. Do not delete or edit WAL/page files manually.

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
- Security and operational review is complete.
