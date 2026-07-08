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

Treat the included matrix as the in-memory baseline. For larger-than-memory testing, prefill both databases to the target size, restart them to remove warm process caches, and run the same binaries against datasets sized to 1×, 4×, and 10× host RAM. Record host CPU, RSS, disk bytes, and database-directory growth alongside the CSV; those measurements are host-specific and intentionally are not guessed by the client harness.
