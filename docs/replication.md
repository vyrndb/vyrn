# Replication

Vyrn supports **synchronous** replication: a write is acknowledged to its client
only once the record is durable on the primary *and* on at least N replicas.
Losing the primary therefore cannot lose an acknowledged write.

Replication is off by default. A node with `--replication-min-acks 0` (the
default) takes exactly the write path it took before this feature existed.

## What is and is not guaranteed

**Guaranteed.** Any write the client saw succeed is on at least `min-acks`
replicas, `fdatasync`'d there before the acknowledgement was sent. A replica's WAL
holds the primary's records byte for byte, at the same LSNs, so its data directory
can be opened as a primary directly.

**Not guaranteed, and deliberately so:**

- **No automatic failover.** Nothing elects a new primary. If the primary dies,
  writes stop until an operator promotes a replica. This is a scope decision, not
  an oversight — leader election without consensus is how split-brain happens, and
  a wrong answer there loses more data than no answer.
- **No read-your-writes across nodes.** A replica applies a record before
  acknowledging it, so a read there immediately after a primary write will
  normally see it — but that ordering is not enforced for reads and must not be
  relied on.
- **A quorum failure does not roll the write back.** See below; this is the most
  surprising behaviour here.

## Configuration

### Primary

```bash
vyrnd --replication-min-acks 1 --replication-ack-timeout-ms 5000
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--replication-min-acks` | `VYRN_REPLICATION_MIN_ACKS` | `0` | Replicas that must acknowledge before a commit is answered. 0 disables replication. |
| `--replication-ack-timeout-ms` | `VYRN_REPLICATION_ACK_TIMEOUT_MS` | `5000` | How long a commit waits for those acknowledgements. |

`min-acks` is a **requirement, not a target**. Setting it to 2 with one replica
running makes every write wait the full timeout and then fail. Set it to the
number of replicas you are willing to depend on, never more.

### Replica

The same binary, with `--replica-of`. One image serves both roles, so promotion
needs no different artifact.

```bash
vyrnd \
  --data /var/lib/vyrn \
  --replica-of 'vyrn://repl@primary.internal:7432/default' \
  --replica-password-file /run/secrets/replica-password \
  --replica-ca-file /run/secrets/ca.crt.pem \
  --replica-id replica-a
```

A replica authenticates with the **same credentials as any client** — replication
is a role a connection adopts after authenticating, not a separate door into the
server. TLS is required unless the URL carries `?tls=disable`, which needs
`--allow-plaintext` and is meant only for isolated local testing.

A replica serves reads on its own `--bind` and **refuses client writes**:

```
InvalidRequest: this node is a replica and does not accept writes; send writes
to the primary, or promote this node by restarting it without --replica-of
```

That refusal is not a convenience. A local write would take the next LSN from the
replica's own counter, so the same LSN would then hold different bytes on the two
nodes — after which the primary's next record is rejected as non-contiguous and the
replica can never be promoted without serving a history the primary never had.

## The behaviour that will surprise you

**When a quorum is not reached, the write fails but the data is still there.**

On timeout the client gets:

```
replication quorum not reached after 5.0s: 0 of 1 replicas acknowledged.
The write is durable on this node but is NOT replicated; it may be lost if
this node fails.
```

That message is precise. At that point the record is:

- **in the WAL and applied to the tree**, so it survives a restart of this node.
  Verified: a write rejected this way was readable after reopening the directory.
- **not visible to readers**, because the commit is never published to the read
  handles on the error path — until some later commit succeeds and moves them
  forward.

So "write failed" here means *"the durability you asked for was not achieved"*,
not *"nothing happened"*. Rolling the record back instead would mean un-writing a
committed WAL entry, which is far more dangerous than reporting the truth.

Retrying is safe: a re-put of the same key is idempotent.

## Operating it

### Metrics

On the admin endpoint (`--admin-bind`, default `127.0.0.1:7433`):

| Metric | Meaning |
| --- | --- |
| `vyrn_replication_enabled` | 1 when `min-acks >= 1`. |
| `vyrn_replicas_connected` | Replicas currently streaming. |
| `vyrn_replication_max_lag_lsn` | **Alert on this.** Worst replica's lag in commits. |
| `vyrn_replication_quorum_failing` | 1 after a quorum wait has timed out. |
| `vyrn_replication_ack_timeouts_total` | Commits that failed for want of a quorum. |
| `vyrn_replication_dropped_replicas_total` | Replica streams ended. |

Lag is in LSNs — one LSN is one commit — rather than bytes, because "40 commits
behind" is what an operator reasons about, and byte lag varies with value size for
identical replication health.

### Readiness

`/health/ready` returns **503 while a quorum cannot be met**. A primary in that
state is running but cannot honour the durability it promises, so it should not be
sent traffic.

`/health/live` deliberately still returns 200. The process is healthy, and
restarting it cannot bring a replica back.

### Promotion

Manual, and simple: **stop the replica and restart it without `--replica-of`.**

```bash
# On the replica, after confirming the primary is truly gone.
vyrnd --data /var/lib/vyrn --bind 0.0.0.0:7432   # no --replica-of
```

Its WAL already holds the primary's records at the primary's LSNs, so it opens and
accepts writes immediately. Verified end to end: after `kill -9` on a primary with
6 acknowledged commits, the replica held all 6 at the same LSN, served them after
its own restart, and accepted new writes.

**Confirm the old primary is dead before promoting.** Two nodes both accepting
writes will diverge, and nothing here detects or repairs that. There is no
fencing — that is the main thing automatic failover would have to add.

## Failure modes

| Situation | What happens |
| --- | --- |
| Replica disconnects | Deregistered immediately, so writes fail fast rather than waiting the timeout. Readiness goes 503. |
| Replica reconnects | Resumes from its own last LSN. Duplicate records are skipped, not treated as errors. |
| Replica falls too far behind | Its stream is dropped with an explanation once it exceeds the 8192-record buffer; it reconnects and resumes. |
| Replica is ahead of the primary | **Refused.** Streaming cannot reconcile it; rebuild from a base backup. |
| Record fails validation | Refused before it reaches the WAL, as `InvalidReplicatedRecord`. |
| Primary and replica on different builds | Refused as `FormatVersion`, distinct from corruption — the data is intact, the versions disagree. |

## What this costs

One network round trip on the write path. The local `fdatasync` and the replica
acknowledgement are awaited **concurrently**, so the added latency is
`max(fsync, rtt) - fsync`, not the sum.

On a LAN where an fsync outweighs an RTT the difference is small. Over a WAN it is
not, and that is a deployment decision rather than something this document should
pretend away. Measure it with `scripts/profile-writes-linux.sh`, reading **p50 not
mean** per that script's own guidance.

## Still missing

Replication removes the single-point-of-failure objection. It does not make Vyrn
production-certified — the README's other gaps stand: sustained crash loops,
fuzzing beyond the decoder, performance characterisation under failure, and
external review. In particular:

- **No automatic failover or fencing** (above).
- **No gap recovery from the WAL archive yet.** A replica that falls behind the
  live buffer reconnects and resumes, but if the primary has already checkpointed
  and pruned those segments the replica cannot catch up and must be rebuilt from a
  base backup. Wiring `recover_to` into the join path is the next piece of work.
- **Service-token authentication only**, inherited from the client protocol.
