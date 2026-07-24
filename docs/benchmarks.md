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

## Measured 2026-07-25 (WSL2, 32 cores, 15 GB RAM, ext4)

16 clients, 128-byte values, 600 operations per client, both databases durable
with `fsync` and `synchronous_commit` enabled. These are development-machine
numbers on WSL2, not deployment guarantees.

| Workload | Vyrn | PostgreSQL 17 |
| --- | ---: | ---: |
| Point reads | 42,431/s (p50 137 µs) | 9,781/s (p50 942 µs) |
| Durable writes | 1,864/s (p50 8.4 ms) | 6,268/s (p50 2.2 ms) |
| 70/30 mixed | 3,872/s | 3,628/s |
| Four-key transactions | 103/s | 1,379/s |
| Index equality lookup | 24/s | 10,268/s |

Vyrn is roughly 4× faster on point reads, which use dedicated reader handles and
the bounded page cache. It is slower on durable writes, substantially slower on
multi-key transactions, and far slower on index lookups.

### Known performance defects

Running each mode against a fresh database isolates two problems that the
sequential matrix compounds:

- **Index lookup cost scales with total row count, not matching rows.** A
  single-match lookup takes 186 µs on an empty database and 1,622 µs after 9,600
  unrelated writes, measured at one client. Point reads over the same data stay
  at ~150 µs, so this is specific to the index path.
- **Index lookups serialize on the shared engine lock.** They run through the
  engine's `RwLock` rather than the dedicated reader handles used by `get` and
  `scan`. Concurrency scales normally while each lookup is fast (16 clients reach
  38k/s on an empty database), but once a lookup costs ~1.6 ms, 16 clients queue
  behind each other for a 23 ms p50 and ~681/s aggregate.

Fresh-database figures for comparison: index 42,022/s, reads 48,127/s, writes
1,890/s, mixed 5,190/s, transactions 147/s.

Transaction throughput is also low because commit validation re-checks every
read key and scanned range against the tree.

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
