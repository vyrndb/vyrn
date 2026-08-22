# Vyrn

Vyrn is a correctness-first database built in Rust from its storage format upward. `0.1.0-dev` is a byte key/value database with Vyrn-owned storage, a native `vyrn://` protocol, TLS 1.3, Argon2id authentication, segmented transaction-WAL recovery, an online persistent B+ tree, and optional synchronous replication.

> **Maturity:** development preview. The core features now exist and are tested, but production certification still requires sustained Linux crash loops, fuzzing, performance characterization, backups, monitoring, and external review.

## Implemented

- `GET`, `PUT`, `DELETE`, ordered half-open `SCAN [start, end)`
- Connection-scoped serializable transactions with read-your-writes, rollback, atomic multi-key commit, and point/range conflict detection
- Active-window historical MVCC value/tombstone chains, snapshot reads at a revision, and immediate release after the oldest active transaction advances
- Transactional byte-oriented unique and non-unique secondary indexes stored under the same committed tree root
- Compact binary protocol v6 with bounded decoding, batched multi-get, and predictable support for 16 MiB values
- Opaque binary keys up to 64 KiB and values up to 16 MiB
- Segmented transaction WAL with sequence numbers, committed root generations, CRC32 checksums, record footers, and `sync_data` before acknowledgement
- Records written into a preallocated zero-filled runway, so a commit's barrier has no file extension to journal
- Recovery that publishes only complete committed roots and truncates only the incomplete tail of the active segment
- Checksummed 4 KiB fixed pages and a bounded 4,096-page (~16 MiB) clock cache
- Vyrn-owned online copy-on-write B+ tree with inline small keys/values, leaf/internal splitting, deletion/root collapse, and a checksummed versioned value log for large values
- Generation-named compacted page files, atomically published checkpoint manifests, and obsolete-WAL/page cleanup
- TLS 1.3-only server and client with CA and hostname verification
- Argon2id PHC verifier files; the server never stores plaintext credentials
- Bounded authentication workers, connections, frames, and scans
- Child-process force-kill, corruption/truncation, and randomized model testing
- Checksummed offline backup verification and empty-directory restore
- Continuous non-blocking WAL archiving with lag/failure metrics, archive verification, safe WAL pruning, and point-in-time recovery from a base backup plus archive
- Readiness/liveness endpoints, Prometheus-format metrics, SIGINT/SIGTERM connection draining, and bounded server-side group commit
- Structured stderr logs with RFC 3339 timestamps, levels, and `key=value` fields, filtered by `VYRN_LOG`, with connection-URL passwords redacted, across the server, the gateway, and the CLI
- Point reads and consistent scans through the persistent B+ tree and bounded page cache, without duplicating all live values in server memory
- Ordered prefix subscriptions/change notifications with bounded lag detection
- Durable mode by default plus explicit bounded-loss async mode for realtime ephemeral workloads
- Native Linux/Windows CI, Linux durability smoke, dependency audit, and a production runbook
- Non-root, read-only-root Docker deployment
- Authenticated HTTP/SSE gateway and dependency-free TypeScript SDK for Node.js and modern browsers
- Optional synchronous replication: a commit is acknowledged only once N replicas hold it durably, so losing a node cannot lose an acknowledged write. Off by default; promotion is manual. See `docs/replication.md`

## Create credentials

Keep all generated files outside version control. To create a verifier without placing the password in shell arguments:

```bash
printf '%s\n' 'replace-with-a-long-random-password' > password.txt
cargo run -p vyrn -- \
  --hash-password secrets/password.phc \
  --password-input password.txt
rm password.txt
```

Generate a local development certificate for `localhost` with your preferred PKI tooling. The client must receive the CA certificate, while the server receives its certificate chain and private key.

## Run with TLS

```bash
cargo build --workspace

VYRN_PASSWORD_HASH_FILE=./secrets/password.phc \
VYRN_TLS_CERT_FILE=./secrets/server.crt.pem \
VYRN_TLS_KEY_FILE=./secrets/server.key.pem \
  cargo run -p vyrnd -- --data ./data
```

Use a password file on the client so it is not embedded in the connection string or shell history:

```bash
printf '%s\n' 'replace-with-a-long-random-password' > client-password.txt
export VYRN_URL='vyrn://vyrn@localhost:7432/default'
export VYRN_PASSWORD_FILE='./client-password.txt'
export VYRN_TLS_CA_FILE='./secrets/ca.crt.pem'

cargo run -p vyrn -- put users/alica '{"score":1000}'
cargo run -p vyrn -- get users/alica
cargo run -p vyrn -- scan --start users/ --end users0
cargo run -p vyrn -- delete users/alica
```

The full library connection-string form remains supported:

```text
vyrn://username:password@host:7432/database?tls=require
```

TLS is required by default. `?tls=disable` works only against a server explicitly started with `--allow-plaintext`; that mode is solely for isolated local testing.

## Durability modes

`VYRN_DURABILITY=durable` is the default. Pages and WAL are synchronized before acknowledgement, so acknowledged writes survive process crashes under the documented filesystem/device assumptions.

`VYRN_DURABILITY=async` acknowledges after staging the transaction in memory and synchronizes pages followed by WAL every `VYRN_ASYNC_SYNC_MS` milliseconds (default 5). It is intended for presence, transient sessions, counters, signaling, and other reconstructable realtime state. Sudden host/power failure may lose the most recent sync interval. Graceful shutdown synchronizes pending data.

## Docker

Place the database TLS/verifier secrets and the gateway password, CA, and API-token files at the paths declared in `docker-compose.yml`, then run:

```bash
docker compose up --build
```

Secrets are mounted at runtime and are excluded from the Docker build context. The service publishes the database and admin endpoints only on localhost by default and persists `/var/lib/vyrn` in a named volume. Docker health checks use `http://127.0.0.1:7433/health/ready`; Prometheus metrics are available at `/metrics`.

## Web gateway and TypeScript

`vyrn-http` is a separate authenticated HTTP/SSE gateway. It keeps native database credentials server-side, reuses up to 64 idle native connections by default (`VYRN_HTTP_IDLE_CONNECTIONS`), and binds to loopback by default. Put it behind an HTTPS reverse proxy before exposing it publicly.

```bash
printf '%s\n' 'replace-with-a-long-random-api-token' > secrets/http-token.txt

VYRN_URL='vyrn://vyrn@127.0.0.1:7432/default' \
VYRN_PASSWORD_FILE='./client-password.txt' \
VYRN_TLS_CA_FILE='./secrets/ca.crt.pem' \
VYRN_HTTP_TOKEN_FILE='./secrets/http-token.txt' \
  cargo run -p vyrn-http
```

The gateway provides authenticated `/v1/get`, `/v1/multi-get`, `/v1/put`, `/v1/delete`, `/v1/scan`, `/v1/transaction`, and `/v1/subscribe` endpoints. Keys and values are standard base64 strings so opaque bytes round-trip through JSON. `/v1/subscribe` uses Server-Sent Events. Liveness and readiness are available without authentication at `/health/live` and `/health/ready`.

Document collections are also available as plain JSON, without base64 encoding: `/v1/collections/create`, `/v1/documents/get`, `/v1/documents/put`, `/v1/documents/delete`, `/v1/documents/list`, `/v1/documents/query`, and the Server-Sent Events stream `/v1/documents/subscribe?collection=<name>`.

Build and test the TypeScript client:

```bash
cd sdk/typescript
npm install
npm test
```

Node.js backend servers should use the native SDK entry point instead of the gateway. It speaks the `vyrn://` protocol directly over TCP/TLS 1.3, supports interactive transactions, and pools connections:

```ts
import { VyrnClient } from "@vyrn/client/node";

const db = new VyrnClient({
  url: "vyrn://app@localhost:7432/app",
  password: process.env.VYRN_PASSWORD!,
  caFile: process.env.VYRN_TLS_CA_FILE!,
});

await db.putDocument("users", "user_1", { email: "alica@example.com" });

await db.transaction(async (tx) => {
  await tx.put("balance/a", "75");
  await tx.put("balance/b", "25");
});
```

The `vyrn://` URL resembles a PostgreSQL connection string, but Vyrn speaks its own protocol; existing PostgreSQL drivers cannot connect. PostgreSQL wire compatibility remains a later milestone.

```ts
import { VyrnClient, text } from "@vyrn/client";

const db = new VyrnClient({
  url: "https://db.example.com",
  token: process.env.VYRN_HTTP_TOKEN!,
});

await db.put("users/1", JSON.stringify({ name: "Alica" }));
const user = await db.get("users/1");
if (user) console.log(JSON.parse(text(user)));
```

The current gateway uses one service token. Keep it on trusted application servers; do not embed it in public browser bundles. Scoped project and end-user credentials remain required before offering direct browser access.

## Backup and restore

Backups are deliberately offline for a clean single-node consistency boundary. Stop `vyrnd`, then run:

```bash
vyrn backup --data ./data --output ./backup.vyrn
vyrn verify-backup ./backup.vyrn
vyrn restore ./backup.vyrn --target ./restored-data
```

The archive stores per-file sizes and CRC32 checksums, ends with a commit footer, refuses unsafe paths, and restores only into an empty directory. Always copy verified archives off the database host and perform scheduled restore drills.

### Continuous WAL archiving and point-in-time recovery

Set `VYRN_WAL_ARCHIVE_DIR` to a local directory outside the data directory. `vyrnd` then rotates the active segment and copies every sealed WAL segment into that directory on each tick of `VYRN_WAL_ARCHIVE_INTERVAL_MS` (default 5000, minimum 100). Archiving takes no engine lock and never blocks writes; checkpoints simply refuse to delete a sealed segment the archiver has not durably copied yet. Progress is exported at `/metrics` as `vyrn_wal_archive_lag_segments` (sealed-but-uncopied segments; growth means the archiver is falling behind), `vyrn_wal_archived_total`, and `vyrn_wal_archive_failures_total`. With archiving enabled the data-loss window after losing the host shrinks from "since the last offline backup" to the rotation interval plus archive latency. The destination is deliberately a plain local directory: ship it off-host yourself with rsync or object-storage sync on your own schedule.

Point-in-time recovery rolls a restored base backup forward through the archive to a chosen LSN:

```bash
vyrn recover --base backup.vyrn --archive /var/backups/vyrn-archive --target ./recovered --until-lsn 12345
vyrn verify-archive /var/backups/vyrn-archive
vyrn wal-prune --data ./data --archive /var/backups/vyrn-archive --through 41
```

`recover` restores the base backup into an empty target, merges the archived segments into its WAL, physically trims the log at the bound, and replays through the ordinary open path; omit `--until-lsn` to roll forward to the archive's end. The bound cannot be below the base checkpoint's LSN, and a bound past what the archive reaches requires `--allow-partial`. A recovered database is a new timeline: give it a new, empty archive directory before archiving from it, or the old timeline's archive would be poisoned. `verify-archive` re-reads and re-checksums every archived byte; `wal-prune` deletes local sealed segments only when the archive provably holds them and only against a stopped database.

## Storage layout

```text
data/
├── LOCK
├── CURRENT
├── pages-00000000000000000001.vdb
├── values-00000000000000000001.vlog
├── revisions-00000000000000000001.vmvcc
├── revision-values-00000000000000000001.vlog
└── wal/
    ├── 00000000000000000001.vwal
    └── 00000000000000000002.vwal
```

Each commit writes new copy-on-write pages and historical values, then appends one checksummed WAL transaction containing every mutation and the final committed root. Durable mode synchronizes them before acknowledging the client. Recovery publishes the whole record or none of it, and uncommitted pages remain unreachable. MVCC metadata stores fixed-size references into the checksummed historical value log instead of duplicating payloads. Checkpoints compact live keys and retained historical versions into new generation-named files, atomically publish `CURRENT`, open a new durable WAL segment, and only then remove obsolete segments and generations.

A failed write has an ambiguous commit outcome and poisons the running engine. Reopen it to recover before serving more operations.

Legacy `data.vwal` databases from the initial prototype are rejected rather than silently ignored. Export/reimport is currently required.

## Architecture

```text
CLI / Rust client
       │ TLS 1.3 + framed native protocol
       ▼
     vyrnd (Tokio)
       │ bounded blocking work
       ▼
 vyrn-core Engine
   ├── bounded page manager/cache
   ├── checksummed segmented transaction WAL
   └── online copy-on-write fixed-page B+ tree
```

The B+ tree is the primary runtime storage path: writes copy only the affected path and atomically publish a new root. Small fields remain inside leaf pages instead of consuming dedicated blobs. Checkpoints compact unreachable page generations. The core `write_batch` API groups multiple ordered mutations behind one page flush and one WAL flush. The server feeds it through a bounded single-writer queue that collects up to 64 writes over a default 200 µs window. Point reads and scans use positional I/O through the persistent tree and its bounded concurrent page cache rather than duplicating every live value in a server-side map. An `RwLock` permits concurrent readers while commits and checkpoints retain exclusive access.

## Document collections

Documents are JSON objects addressed by a collection name and a stable string ID. Declare a collection's equality indexes once; Vyrn then keeps the document and its index entries in one atomic commit.

Embedded:

```rust
use serde_json::{json, Value};
use vyrn_core::{document::IndexDefinition, Engine};

let mut engine = Engine::open("./data")?;
let indexes = [
    IndexDefinition::new("email", true),
    IndexDefinition::new("role", false),
];
let mut users = engine.collection("users", &indexes)?;

users.put("user_1", &json!({"email": "alica@example.com", "role": "admin"}))?;
let user = users.get("user_1")?;
let admins = users.find("role", &Value::String("admin".into()), 100)?;
users.delete("user_1")?;
```

Over the network, using the same `vyrn://` connection string:

```rust
use serde_json::json;
use vyrn_client::{Client, CollectionIndex};

let mut client = Client::connect("vyrn://user:password@localhost:7432/app").await?;
client
    .create_collection("users", &[CollectionIndex::new("email", true)])
    .await?;
client
    .put_document("users", "user_1", &json!({"email": "alica@example.com"}))
    .await?;
let user = client.get_document("users", "user_1").await?;
let matches = client
    .query_documents("users", "email", &json!("alica@example.com"), Some(100))
    .await?;
```

A collection's declared indexes must match the stored definition exactly, and indexes cannot be added after a collection already holds documents. Writing a duplicate value into a unique index fails without storing the document or its index entries. Indexed fields must be `null`, a boolean, a number, or a string.

`subscribe_collection` streams committed document changes for one collection. Delivery is process-ordered and starts from the moment the subscription is established: there is no durable cursor yet, so a subscriber that connects late or reconnects must resynchronize with `list_documents`.

## Transactions

The Rust client exposes connection-scoped snapshot transactions:

```rust
let mut client = Client::connect("vyrn://user:password@db:7432/app").await?;
let mut transaction = client.transaction().await?;
transaction.put(b"users/alica".to_vec(), b"active".to_vec()).await?;
transaction.put(b"rooms/1/owner".to_vec(), b"alica".to_vec()).await?;
transaction.commit().await?;
```

Reads and scans use the committed snapshot captured by `transaction()`, plus the transaction's pending writes. Commit fails with `ErrorCode::Conflict` if another commit changed a written key, a point-read key, or any key inside a scanned range after that snapshot. This conservative serializable validation prevents write skew and phantoms; applications should retry conflicts from a fresh transaction. Dropping a transaction without committing marks it for rollback; the client automatically sends that rollback before its next request. Use explicit `rollback()` when the outcome matters immediately.

## Realtime subscriptions

The Rust client can consume committed changes for a byte prefix:

```rust
let client = Client::connect("vyrn://user:password@db:7432/app").await?;
let mut changes = client.subscribe(b"presence/".to_vec()).await?;
while let Some(change) = changes.next().await? {
    println!("{} {:?}", String::from_utf8_lossy(&change.key), change.value);
}
```

Events are emitted only after the corresponding write batch or transaction commits. Every operation in one transaction carries the same commit sequence. Delivery is ordered per server process. A slow subscriber that exceeds the bounded broadcast buffer receives a lag error and must reconnect and resynchronize from a normal scan.

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

The crash harness starts a separate writer process, waits for acknowledged durable writes, force-kills it, reopens the database, and verifies every acknowledged write. Property tests run randomized puts, deletes, checkpoints, and reopens against a standard-library `BTreeMap` model. A deterministic failure simulator injects one-shot errors around page synchronization, WAL write/synchronization, and manifest publication, then verifies recovery against pre/post-commit reference states—including transactional index consistency.

Run repeatable microbenchmarks with:

```bash
cargo bench -p vyrn-core --bench storage
```

## Next milestones

1. Parser/protocol fuzzing and Linux ext4/XFS power-loss matrix
2. Online index construction, covering indexes, and index statistics
3. Single-writer commit latency below one flush, adaptive group-commit timing, and direct-I/O experiments
4. Free-page accounting between compactions
5. Online base backup (point-in-time recovery is implemented) and richer operational metrics
6. SQL planner/executor and PostgreSQL wire compatibility
7. Automatic failover on top of synchronous replication, sharding, and online rebalancing

The operational checklist and failure/upgrade procedures are in [`docs/production.md`](docs/production.md).

The supported production-candidate target is Linux x86-64 on local persistent ext4/XFS storage. Synchronous replication is available (see `docs/replication.md`), so an acknowledged write can survive losing a node — but promotion is a manual operator action: there is no automatic failover and no fencing. Windows is a development platform until equivalent durability behavior is certified.
