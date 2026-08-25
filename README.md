# vyrn

A key-value database in Rust. Use it as an embedded library the way SQLite
is used, or run `vyrnd`: a TLS 1.3 server with a binary protocol, an
HTTP/SSE gateway, Rust and TypeScript clients, and optional synchronous
replication.

Storage is a copy-on-write B+tree over checksummed 4 KiB pages, a segmented
write-ahead log, and a value log for large values. Every on-disk structure
carries its own checksum, WAL record headers included. Recovery replays the
log from the last checkpoint; an exhaustive bit-flip suite asserts that any
single-bit change to a committed record either fails the open loudly or
leaves every acknowledged write readable.

Version 1.1.1. Formats are frozen per [docs/compatibility.md](docs/compatibility.md):
every 1.x build reads what any earlier build wrote, downgrade is
unsupported, replicas upgrade before primaries.

## Embedded

```rust
use vyrn_core::Engine;

let mut db = Engine::open("./data")?;
db.put(b"user/1".to_vec(), b"alice".to_vec())?;
let value = db.get(b"user/1")?;          // Option<Vec<u8>>
db.scan_each(Some(b"user/"), Some(b"user0"), 1000, &mut |key, value| {
    // borrowed slices, nothing allocated per row
})?;
```

Writes are durable when the call returns (the default mode). For concurrent
writers, `write_batch_deferred` / `drain_wal` / `Wal::sync_through` expose
group commit: many commits share one fsync, each acknowledged only after
its own barrier. MVCC snapshots, serializable transactions, secondary
indexes, and a durable change log sit on top; the change log is opt-out
(`EngineOptions::change_log`) when nothing subscribes.

JSON documents with declared indexes, kept consistent in one atomic commit:

```rust
use serde_json::{json, Value};
use vyrn_core::document::IndexDefinition;

let indexes = [IndexDefinition::new("email", true), IndexDefinition::new("role", false)];
let mut users = db.collection("users", &indexes)?;
users.put("user_1", &json!({"email": "a@example.com", "role": "admin"}))?;
let admins = users.find("role", &Value::String("admin".into()), 100)?;
```

One process owns a data directory at a time, enforced by a lock. Embed the
crate when the database belongs to one application; run `vyrnd` when
several processes or machines need it. Same format either way — stop the
one owner, start the other.

## Server

```bash
# one-time: create an Argon2id verifier (the password itself is never stored)
cargo run -p vyrn -- --hash-password secrets/password.phc --password-input password.txt

VYRN_PASSWORD_HASH_FILE=./secrets/password.phc \
VYRN_TLS_CERT_FILE=./secrets/server.crt.pem \
VYRN_TLS_KEY_FILE=./secrets/server.key.pem \
  cargo run -p vyrnd -- --data ./data
```

```bash
export VYRN_URL='vyrn://vyrn@localhost:7432/default'
export VYRN_PASSWORD_FILE='./client-password.txt'
export VYRN_TLS_CA_FILE='./secrets/ca.crt.pem'

cargo run -p vyrn -- put users/1 '{"name":"alice"}'
cargo run -p vyrn -- scan --start users/ --end users0
```

Readiness, liveness, and Prometheus metrics on the admin port. `docker
compose up --build` runs the server plus the HTTP gateway. Deployment,
offline backups, continuous WAL archiving, and point-in-time recovery are
in [docs/production.md](docs/production.md).

Rust client — snapshot transactions with serializable validation, and
prefix subscriptions over committed changes:

```rust
let mut client = Client::connect("vyrn://user:password@db:7432/app").await?;
let mut tx = client.transaction().await?;
tx.put(b"users/alica".to_vec(), b"active".to_vec()).await?;
tx.put(b"rooms/1/owner".to_vec(), b"alica".to_vec()).await?;
tx.commit().await?;   // ErrorCode::Conflict if the snapshot was invalidated
```

TypeScript, over the native protocol from Node or through the gateway from
browsers:

```ts
import { VyrnClient } from "@vyrn/client/node";

const db = new VyrnClient({ url, password, caFile });
await db.transaction(async (tx) => {
  await tx.put("balance/a", "75");
  await tx.put("balance/b", "25");
});
```

## Performance

Measured against sled and redb in one process on one host, each engine on
its zero-copy read API and equal cache budgets, sled forced to flush in the
durable rows (its default is a 500 ms background flush — the number naive
benchmarks quote):

| workload | vyrn | sled | redb |
| --- | ---: | ---: | ---: |
| point_get 128 B | 3.3 M/s | 1.1 M/s | 1.8 M/s |
| point_get 64 KiB | 3.7 M/s | 1.5 M/s | 2.1 M/s |
| scan, 1000-row ranges | 12.4 M rows/s | 2.6 M | 4.0 M |
| durable put, 64 writers | 34.6 K/s | 4.0 K | 1.3 K |
| durable put, 1 writer | 2.1 K/s | 1.8 K | 1.4 K |

Single-writer durable throughput is the disk's fsync latency on any engine;
the 64-writer row is group commit with per-op durability intact. The
methodology, the caveats, and the rows where the ranking is host arithmetic
rather than engineering are in [docs/benchmarks.md](docs/benchmarks.md).
Benchmark your own hardware.

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Property tests drive the engine against a `BTreeMap` model through
randomized puts, deletes, checkpoints, and reopens. A failure simulator
injects one-shot errors around page sync, WAL write and sync, and manifest
publication, then verifies recovery against reference states. The crash
harness force-kills a writer process and asserts every acknowledged write
survives; CI runs it on Linux alongside SIGTERM shutdown coverage,
corruption and PITR suites, and a dependency audit. Regression tests are
mutation-verified: revert the fix, watch the test fail.

## What it is not

No SQL, by intent. One writer per keyspace: synchronous replication with
quorum acknowledgement, and — for clusters of three or more — automatic
failover with epoch fencing, where an elected leader provably holds every
acknowledged write (the safety argument is in
[docs/replication.md](docs/replication.md)). Per-user accounts with
prefix-granularity ACLs and an audit trail, or a single shared credential;
either way [docs/security.md](docs/security.md) is the full trust model,
read it before deploying. The production platform is Linux on ext4/XFS;
Windows durability is implemented and tested but not yet soak-certified.

## Documentation

| | |
| --- | --- |
| [docs/production.md](docs/production.md) | deployment, backups, PITR, monitoring, known limitations |
| [docs/compatibility.md](docs/compatibility.md) | format and upgrade contract |
| [docs/security.md](docs/security.md) | trust model |
| [docs/replication.md](docs/replication.md) | synchronous replication and promotion |
| [docs/benchmarks.md](docs/benchmarks.md) | the numbers and how they were taken |

## License

Apache-2.0
