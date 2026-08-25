# served-compare: vyrnd vs single-node ScyllaDB

Same box, same client concurrency, same durability semantics. Linux only —
ScyllaDB does not run elsewhere.

## The fairness rules, before any number is quoted

1. **Scylla's default `commitlog_sync` is `periodic` (10 s window)**: an
   acknowledged write can be lost to power failure for up to that window.
   The durable comparison requires `--commitlog-sync batch` (Scylla's group
   commit, against vyrn's). The harness checks the live config and refuses
   otherwise; `--allow-periodic` exists for knowingly measuring the
   non-durable configuration, clearly labeled.
2. **Single node, replication factor 1** on both sides. This measures the
   engines and their served paths, not cluster coordination.
3. **Same value shape** (128 B), same keyspace size, prefill plus warm
   access pattern, identical per-task deterministic RNG.
4. Report **p50/p99 alongside throughput**. Aggregate ops/s favors whoever
   queues deepest; applications feel the percentiles.
5. Give Scylla its recommended setup where possible (XFS or ext4, its own
   disk, `--developer-mode 0` if the host qualifies). If the host forces
   `--developer-mode 1`, say so next to the numbers.

## Run

Scylla (adjust `--smp`/`--memory` to the host; keep them equal in spirit to
what vyrnd gets):

```bash
docker run --name scylla-bench -d --network host \
  scylladb/scylla --smp 4 --memory 4G \
  --commitlog-sync batch --commitlog-sync-batch-window-in-ms 2 \
  --developer-mode 1
# wait for: docker exec scylla-bench nodetool status  ->  UN
```

vyrnd (release build, its shipped fast config):

```bash
cargo build --release -p vyrnd -p vyrn
target/release/vyrn --hash-password /tmp/bench.phc --password-input <(echo benchpass)
VYRN_PASSWORD_HASH_FILE=/tmp/bench.phc VYRN_ALLOW_PLAINTEXT=true \
VYRN_WRITE_BACK_BYTES=8388608 \
  target/release/vyrnd --data /tmp/vyrn-bench --bind 127.0.0.1:7432
```

The harness (its own toolchain; the Scylla driver needs a newer rustc than
the repo pin):

```bash
cd bench/served-compare
cargo run --release -- vyrn  'vyrn://vyrn:benchpass@127.0.0.1:7432/default?tls=disable' 64
cargo run --release -- scylla 127.0.0.1:9042 64
```

Run each at 16, 64, and 256 clients. Fresh data directories per run. Quote
medians of three runs; write rows vary.

## Reading the results

- vyrn's `durable_put` acknowledges after its own group-commit fsync;
  Scylla's (in batch mode) after the commitlog barrier — comparable
  promises.
- Scylla schedules per-core with shard-aware drivers; vyrnd currently
  serializes commits through one engine write lock. If Scylla wins the
  high-concurrency write rows on many-core hosts, that architectural gap is
  the expected cause — measure before building the answer to it.
