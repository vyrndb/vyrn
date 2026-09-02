mod admin;
mod audit;
mod auth;
mod changes;
mod cli;
mod epoch;
mod failover;
mod metrics;
mod read;
mod replica;
mod replication;
mod write;
use write::{operation_key, start_flush_worker, start_write_worker};
mod stream;
use admin::{serve_admin, withdraw_readiness};
use read::{
    document_read_collection, document_write_collection, next_reader, read_dispatch_error,
    start_read_workers, submit_get, submit_multi_get, submit_scan,
};
use stream::{
    catch_up_from_wal, resolve_cursor, send_primary_epoch, stream_changes, stream_document_changes,
    stream_from_cursor, stream_records, subscribe_merged, CursorStream,
};
mod tasks;
use changes::ChangeRing;
use cli::Args;
use tasks::{start_async_sync, start_mvcc_gc, start_wal_archiver};
mod limits;
use limits::{
    document_write_bytes, operation_bytes, AuthThrottle, WriteBudget, WRITE_QUEUE_MAX_BYTES,
};
use metrics::{ConnectionGuard, Metrics};

use anyhow::{bail, Context, Result};
use argon2::password_hash::PasswordHashString;
use clap::Parser;
use futures_util::{FutureExt, SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::BTreeMap,
    fs::File,
    io::BufReader,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    signal,
    sync::{mpsc, oneshot, watch, Semaphore},
    task,
    time::{timeout, Duration},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use vyrn_core::{
    change_log, document::IndexDefinition, BatchOperation, BatchResult, DurabilityMode, Engine,
    EngineOptions, Error as StorageError, IndexUpdate, ReadEngine,
};
use vyrn_log::{log_debug, log_error, log_info, log_warn};
use vyrn_protocol::{
    Envelope, ErrorCode, Message, VyrnCodec, MAX_DOCUMENT_INDEXES, MAX_SCAN_LIMIT, PROTOCOL_VERSION,
};

const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CHANGE_REPLAY_BATCH: usize = 512;

/// Frame ceiling applied until a connection has authenticated.
///
/// An unauthenticated peer can otherwise make the server buffer up to the full
/// 64 MiB `MAX_FRAME_SIZE` per connection just by sending a length header, before
/// showing a single credential — multiply that by the connection limit and a
/// handful of sockets exhaust server memory for free. Nothing legitimate needs
/// the large ceiling during a handshake: the only frame accepted here is an
/// `Authenticate`, whose password this server caps at 4 KiB anyway. The full
/// ceiling is restored once the peer is trusted.
const PREAUTH_MAX_FRAME_SIZE: usize = 64 * 1024;

/// How long a single response write may stay pending before the peer is
/// treated as gone.
///
/// Generous on purpose: a healthy but slow consumer on a thin link must not be
/// disconnected mid-scan, so this bounds pathological wedges rather than
/// policing throughput. See `send_frame` for why every response path is bounded.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default for `--statement-deadline-ms`; see that argument for the reasoning.
const DEFAULT_STATEMENT_DEADLINE_MS: u64 = 30_000;

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
type BoxedTransport = Box<dyn Transport>;
type ReadRange = (Option<Vec<u8>>, Option<Vec<u8>>);
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Rows one scan reads before it yields its worker to other queued requests.
///
/// WHY A SCAN IS CHUNKED AT ALL: a read handle is served by ONE thread reading
/// ONE queue, and requests are handed to handles round-robin. A request that
/// runs long is therefore not merely slow for the client that sent it — every
/// client that lands on the same handle waits behind it. `limit` bounds the ROWS
/// a scan returns, which is not a bound on its cost: `MAX_SCAN_LIMIT` rows of
/// `MAX_VALUE_SIZE` values is a value-log read measured in gigabytes, and one
/// client asking for that used to stall every `Get` queued behind it for the
/// whole time, on a server whose other fifteen handles sat idle.
///
/// 256 rows keeps the wait a queued point read can inherit down to one chunk,
/// while leaving the per-chunk overhead — one extra root-to-leaf descent, plus
/// one row re-read to resume — noise against the rows the chunk returns.
const SCAN_CHUNK_ROWS: usize = 256;

/// Requests admitted between two chunks of the scans in flight.
///
/// Bounded in both directions on purpose. Draining the queue without a cap would
/// let a steady stream of point reads hold a scan at its first chunk forever;
/// admitting nothing would put those point reads back behind the whole scan.
const SCAN_YIELD_REQUESTS: usize = 32;

/// Why a read produced no rows.
///
/// Wider than [`StorageError`] because a deadline is not a storage fault: the
/// engine did not fail and the database is not damaged, the server simply
/// refused to spend more of a shared worker on one statement. Reporting it as
/// [`StorageError::Io`] would be worse than imprecise — `record_storage_error`
/// treats an I/O error as a reason to fail readiness, so one client's oversized
/// scan would take the whole node out of service.
enum ReadFailure {
    Storage(StorageError),
    /// Abandoned at the statement deadline, with the rows read so far discarded.
    DeadlineExceeded,
}

impl From<StorageError> for ReadFailure {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// A scan part-way through its chunks.
struct ScanJob {
    /// Lower bound for the next chunk. Starts as the client's `start`, and after
    /// each chunk becomes the last key collected.
    ///
    /// Resuming from the last key INCLUSIVE and dropping it (`skip_resume`) is
    /// deliberate, rather than computing the key that follows it: appending a
    /// zero byte to a `MAX_KEY_SIZE` key would exceed the limit and turn a legal
    /// scan into a validation error, and incrementing the last byte with carry
    /// has the same edge at the other end of the key space. One re-read row per
    /// chunk costs less than either edge case being wrong.
    from: Option<Vec<u8>>,
    skip_resume: bool,
    end: Option<Vec<u8>>,
    limit: usize,
    rows: Rows,
    response: oneshot::Sender<std::result::Result<Rows, ReadFailure>>,
    /// When this scan reached the worker, for the statement deadline.
    started: Instant,
}

enum ReadRequest {
    Get {
        key: Vec<u8>,
        response: oneshot::Sender<vyrn_core::Result<Option<Vec<u8>>>>,
    },
    MultiGet {
        keys: Vec<Vec<u8>>,
        response: oneshot::Sender<std::result::Result<Vec<Option<Vec<u8>>>, ReadFailure>>,
    },
    Scan {
        start: Option<Vec<u8>>,
        end: Option<Vec<u8>>,
        limit: usize,
        response: oneshot::Sender<std::result::Result<Rows, ReadFailure>>,
    },
    IndexLookup {
        index: Vec<u8>,
        value: Vec<u8>,
        limit: usize,
        response: oneshot::Sender<vyrn_core::Result<Vec<Vec<u8>>>>,
    },
    Document {
        request: DocumentRead,
        response: oneshot::Sender<vyrn_core::Result<Message>>,
    },
}

enum DocumentRead {
    Get {
        collection: String,
        id: String,
    },
    List {
        collection: String,
        limit: usize,
    },
    Query {
        collection: String,
        field: String,
        value: serde_json::Value,
        limit: usize,
    },
}

enum WriteRequest {
    Operation {
        operation: BatchOperation,
        response: oneshot::Sender<std::result::Result<BatchResult, String>>,
        /// When the connection handed this off, so the write worker can charge
        /// the queue wait to the right stage.
        queued: Instant,
    },
    Document {
        request: DocumentWrite,
        /// `Ok` carries the rendered answer — including a rendered storage error,
        /// so its error code survives the trip through the ordered publication
        /// point; `Err` is text supplied by the pipeline itself when a commit
        /// could not be published. See [`DeferredAnswer`].
        response: oneshot::Sender<std::result::Result<Message, String>>,
    },
    CreateIndex {
        name: Vec<u8>,
        unique: bool,
        response: oneshot::Sender<vyrn_core::Result<()>>,
    },
    DropIndex {
        name: Vec<u8>,
        response: oneshot::Sender<vyrn_core::Result<()>>,
    },
    Transaction {
        snapshot_sequence: u64,
        read_keys: Vec<Vec<u8>>,
        read_ranges: Vec<ReadRange>,
        index_reads: Vec<(Vec<u8>, Vec<u8>)>,
        operations: Vec<BatchOperation>,
        index_updates: Vec<IndexUpdate>,
        response: oneshot::Sender<std::result::Result<Vec<BatchResult>, String>>,
        queued: Instant,
    },
}

impl WriteRequest {
    /// When this request entered the write queue, for the data requests that
    /// group-commit. The others take the engine lock alone and are not profiled.
    fn queued(&self) -> Option<Instant> {
        match self {
            WriteRequest::Operation { queued, .. } | WriteRequest::Transaction { queued, .. } => {
                Some(*queued)
            }
            WriteRequest::Document { .. }
            | WriteRequest::CreateIndex { .. }
            | WriteRequest::DropIndex { .. } => None,
        }
    }
}

/// One batched transaction's validation inputs, pulled out of the queue so the
/// check can run on a blocking thread without holding the request.
struct TransactionCheck {
    index: usize,
    snapshot_sequence: u64,
    read_keys: Vec<Vec<u8>>,
    read_ranges: Vec<ReadRange>,
    index_reads: Vec<(Vec<u8>, Vec<u8>)>,
    operations: Vec<BatchOperation>,
    index_updates: Vec<IndexUpdate>,
}

/// One member of a batch, as conflict validation sees it.
///
/// A plain operation carries only the key it writes. It can never be the request
/// that gets rejected — it has no snapshot and read nothing, so nothing can have
/// invalidated it — but it MUST be visible to the transactions ordered after it,
/// which is precisely what was missing: a batch validated as if bare puts and
/// deletes were not there.
enum BatchEntry {
    Plain { key: Vec<u8> },
    Transaction(TransactionCheck),
}

/// What the write pipeline needs.
///
/// NO `readers` AND NO `changes`, deliberately. This stage applies batches and
/// hands them on; refreshing the read handles and broadcasting changes belong to
/// the flush stage alone, because that is the stage that knows a commit is
/// durable and that visits commits in order. The write worker held both handles
/// while the document arm published from here, which is exactly how a document
/// change could reach a subscriber ahead of an earlier key/value commit still
/// waiting on its barrier. Their absence is what makes that reorder
/// unrepresentable rather than merely fixed: there is nothing here to publish
/// with.
struct WriteWorkerConfig {
    maximum_batch: usize,
    delay: Duration,
    checkpoint_writes: u64,
    metrics: Arc<Metrics>,
    /// Set when accumulated writes have crossed the checkpoint threshold, so the
    /// background task compacts instead of a client's commit paying for it.
    checkpoint_due: Arc<AtomicBool>,
    /// Batches applied but not yet durable. Non-zero means a barrier is in
    /// flight, which is when accumulating a larger batch costs nothing.
    in_flight: Arc<AtomicU64>,
    /// Bumped by the flush stage whenever a barrier lands.
    flush_completed: watch::Sender<u64>,
}

struct FlushWorkerConfig {
    readers: Arc<Vec<RwLock<ReadEngine>>>,
    changes: Arc<ChangeRing>,
    metrics: Arc<Metrics>,
    /// The engine, consulted only when a reader refresh fails, to decide
    /// whether a concurrent checkpoint retired the batch's generation (a lost
    /// race, not a fault) or storage is actually broken. Never locked on the
    /// happy path: routing every batch through the engine lock would put the
    /// flush stage back in contention with the apply stage, which is exactly
    /// what this split exists to avoid.
    engine: Arc<RwLock<Engine>>,
    /// Batches applied but not yet durable, and a signal for when that count
    /// drops. The write worker uses these to size the next batch against the
    /// barrier actually in flight rather than against a fixed timer.
    in_flight: Arc<AtomicU64>,
    flush_completed: watch::Sender<u64>,
    /// Replica acknowledgement barrier, awaited alongside the local `fdatasync`.
    ///
    /// Always present; a `min_acks` of 0 makes `await_quorum` return immediately,
    /// so the disabled path needs no branch here.
    replication: Arc<replication::Replication>,
}

/// An applied batch waiting for its WAL flush before it can be acknowledged.
///
/// The mutations are already in the tree and their WAL record is already written,
/// but neither is durable until `lsn` has been flushed. Handing this to the
/// completion stage lets the write worker start the next batch immediately, so
/// one batch's `fdatasync` overlaps the next batch's tree work.
struct PendingFlush {
    /// `None` when no flush is owed: async durability, where records are buffered
    /// for the background sync, and document writes, which take an immediate
    /// barrier inside the engine write lock and are already durable when they
    /// reach this stage. They pass through it anyway so their changes are
    /// broadcast in commit order — see [`DeferredAnswer`].
    lsn: Option<u64>,
    requests: Vec<WriteRequest>,
    results: Vec<BatchResult>,
    /// Clients of requests that committed alone rather than joining the batch.
    answers: Vec<DeferredAnswer>,
    published: Vec<change_log::ChangeRecord>,
    /// What this commit asks the read handles' overlay copies to learn —
    /// its raw mutations plus the absorb watermark. Empty when write-back is
    /// off, in which case the root refresh below is the whole publication.
    write_back: vyrn_core::WriteBackPublish,
    generation: u64,
    root: u64,
    len: u64,
    /// When this batch was handed to the flush stage, so the wait for a barrier
    /// already in flight is charged separately from the barrier itself.
    queued: Instant,
}

/// A committed request whose answer waits on the ordered publication point.
///
/// WHY THIS EXISTS — the change-feed reorder it removes. Document writes commit
/// alone under the engine write lock with an IMMEDIATE barrier, so they are
/// durable the moment they are applied, while batched key/value commits defer
/// their barrier to the flush stage. Broadcasting each from where it committed
/// therefore raced by construction: the document arm published straight from the
/// write pipeline while an EARLIER key/value commit was still sitting in the
/// flush queue waiting for its `fdatasync`. A subscriber under mixed document and
/// key/value load saw the later change first, and a subscriber replaying from a
/// cursor afterwards saw them in the other order — the same stream in two
/// different orders, which makes a change feed unusable for anything that
/// reconstructs state from it.
///
/// So a successful document write no longer answers where it commits. It carries
/// its answer here, through the flush stage, and `publish_commit` broadcasts and
/// answers it in flush-queue order. That queue is fed by ONE task that applies
/// batches sequentially, so its order IS commit order, and there is now exactly
/// one place in this file that touches [`ChangeRing::send`].
///
/// The answer is a rendered [`Message`] rather than a `Result`, so a typed
/// storage error keeps the error code `storage_error_message` chose for it
/// (a unique-index violation stays `Conflict`, invalid JSON stays
/// `InvalidRequest`) while the flush stage can still fail the request with text
/// of its own.
struct DeferredAnswer {
    response: oneshot::Sender<std::result::Result<Message, String>>,
    message: Message,
}

enum DocumentWrite {
    CreateCollection {
        collection: String,
        indexes: Vec<IndexDefinition>,
    },
    Put {
        collection: String,
        id: String,
        document: Vec<u8>,
    },
    Delete {
        collection: String,
        id: String,
    },
}

struct ConnectionTransaction {
    /// Snapshot sequences, one per shard, all registered at `Begin` so the
    /// transaction reads a consistent revision wherever its first key lands.
    sequences: Vec<u64>,
    /// The shard the first-touched key hashed to — see [`transaction_shard`].
    /// `None` until a key arrives; always 0 unsharded.
    shard: Option<usize>,
    started: tokio::time::Instant,
    read_keys: BTreeMap<Vec<u8>, ()>,
    read_ranges: Vec<ReadRange>,
    index_reads: Vec<(Vec<u8>, Vec<u8>)>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    index_updates: Vec<IndexUpdate>,
}

/// One shard's full serving stack: an engine with its own write lock, WAL
/// and group commit, its read handles and reader threads, its write
/// pipeline, and its change ring. With `--shards 1` there is exactly one,
/// over the data directory itself — the unsharded server IS the one-shard
/// case, not a separate code path.
struct Shard {
    writes: mpsc::Sender<WriteRequest>,
    changes: Arc<ChangeRing>,
    read_queues: Vec<std::sync::mpsc::SyncSender<ReadRequest>>,
    readers: Arc<Vec<RwLock<ReadEngine>>>,
    next_reader: AtomicU64,
    engine: Arc<RwLock<Engine>>,
    wal_directory: PathBuf,
}

/// FNV-1a 64 over the key bytes. AN ON-DISK CONTRACT: a sharded directory's
/// key placement depends on this exact function forever — changing it
/// orphans every key it moves. Stated in docs/compatibility.md.
fn shard_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Records the shard count a data directory was created with, so a restart
/// with a different `--shards` is refused instead of silently misrouting
/// every key.
fn check_shard_marker(data: &Path, shards: usize) -> Result<()> {
    let marker = data.join("SHARDS");
    match std::fs::read_to_string(&marker) {
        Ok(recorded) => {
            let recorded: usize = recorded
                .trim()
                .parse()
                .with_context(|| format!("{marker:?} is not a shard count"))?;
            if recorded != shards {
                bail!(
                    "this data directory was created with --shards {recorded}, got --shards \
                     {shards}; the shard count is fixed at creation because key placement \
                     depends on it"
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if shards > 1 {
                // Sharding an existing unsharded database would strand its
                // keys: they live in the root directory, not in any shard.
                if std::fs::read_dir(data).ok().is_some_and(|entries| {
                    entries
                        .flatten()
                        .any(|entry| entry.file_name().to_string_lossy().starts_with("pages-"))
                }) {
                    bail!(
                        "this data directory holds an unsharded database; --shards {shards} \
                         would strand its keys. Export and re-import to shard existing data."
                    );
                }
                std::fs::create_dir_all(data)?;
                let temp = data.join("SHARDS.tmp");
                std::fs::write(&temp, format!("{shards}\n"))?;
                std::fs::rename(&temp, &marker)?;
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {marker:?}")),
    }
}

struct ServerState {
    /// The serving stacks, one per shard; length 1 by default. Routing
    /// helpers below pick one by key or collection; paths that only exist
    /// unsharded (replication, cursors) use `lone_shard`.
    shards: Vec<Shard>,
    /// The credential store — one shared verifier or the users file — and the
    /// permission sets sessions are checked against.
    auth: Arc<auth::Authenticator>,
    /// The audit trail, absent unless `VYRN_AUDIT_LOG` is set.
    audit: Option<audit::AuditLog>,
    database: String,
    auth_limit: Arc<Semaphore>,
    /// Per-address failed-authentication throttle; see [`AuthThrottle`].
    auth_throttle: Arc<AuthThrottle>,
    /// Bytes of pending write payload allowed in the pipeline; see
    /// [`WRITE_QUEUE_MAX_BYTES`].
    write_budget: Arc<Semaphore>,
    transaction_timeout: Duration,
    metrics: Arc<Metrics>,
    /// Shared with the flush worker: connection handlers register replicas here,
    /// and the flush worker waits on the watermarks they publish.
    replication: Arc<replication::Replication>,
    /// True when this node is following a primary (`--replica-of`).
    ///
    /// CLIENT WRITES MUST BE REFUSED while this is set. A replica's log has to
    /// contain only what its primary sent: a local write would allocate the next
    /// LSN from this node's own counter, so the same LSN would then exist with
    /// different contents on the two nodes. Nothing detects that afterwards —
    /// `apply_replicated_record` would reject the primary's next record as
    /// non-contiguous, and the replica could never be promoted without silently
    /// serving a history that never existed on the primary.
    read_only: bool,
    /// Present when `--cluster` configured automatic failover. Writes are
    /// then governed by the ROLE (primary/follower/deposed) rather than the
    /// static `read_only`, `ReplicaHello` streams only from the primary, and
    /// vote requests are answered — see the safety argument in [`failover`].
    failover: Option<Arc<failover::Failover>>,
}

impl ServerState {
    fn shard_for_key(&self, key: &[u8]) -> &Shard {
        &self.shards[self.shard_index_for_key(key)]
    }

    fn shard_index_for_key(&self, key: &[u8]) -> usize {
        if self.shards.len() == 1 {
            0
        } else {
            (shard_hash(key) % self.shards.len() as u64) as usize
        }
    }

    /// A collection lives wholly on one shard, chosen by its NAME, so
    /// document atomicity and collection indexes keep full semantics.
    fn shard_for_collection(&self, collection: &str) -> &Shard {
        if self.shards.len() == 1 {
            &self.shards[0]
        } else {
            &self.shards[(shard_hash(collection.as_bytes()) % self.shards.len() as u64) as usize]
        }
    }

    /// The one shard of an unsharded server, for paths that are refused in
    /// sharded mode at startup or dispatch (replication, change cursors,
    /// global indexes) and therefore only ever run with one.
    fn lone_shard(&self) -> &Shard {
        &self.shards[0]
    }

    fn sharded(&self) -> bool {
        self.shards.len() > 1
    }
}

/// Everything `build_shard` needs that is shared across shards or decided
/// before any of them exists.
struct ShardDeps {
    durability: DurabilityMode,
    archived_through: Option<Arc<AtomicU64>>,
    record_sink: Option<Arc<dyn vyrn_core::RecordSink>>,
    replication: Arc<replication::Replication>,
    metrics: Arc<Metrics>,
}

/// Opens one shard's engine over `directory` and starts its whole pipeline:
/// read workers, write worker, flush stage, MVCC GC, and (in async mode)
/// the periodic sync. The unsharded server is exactly one of these over the
/// data directory itself.
fn build_shard(args: &Args, directory: &Path, deps: &ShardDeps) -> Result<Shard> {
    let mut engine = Engine::open_with_options(
        directory,
        EngineOptions {
            durability: deps.durability,
            archived_through: deps.archived_through.clone(),
            record_sink: deps.record_sink.clone(),
            write_back_buffer: args.write_back_bytes,
            ..EngineOptions::default()
        },
    )
    .context("failed to open Vyrn data directory")?;
    // The read handles are fed from this engine's commits, so every
    // write-back commit must stage its publication. A no-op in classic mode.
    engine.enable_write_back_publish();
    let readers = Arc::new(
        (0..args.read_handles)
            .map(|_| {
                // A handle for a write-back engine must be told so: it keeps
                // its own overlay copy, fed by the flush stage, and a plain
                // handle would silently serve only what the tree has absorbed.
                if args.write_back_bytes > 0 {
                    ReadEngine::open_with_write_back(directory).map(RwLock::new)
                } else {
                    ReadEngine::open(directory).map(RwLock::new)
                }
            })
            .collect::<vyrn_core::Result<Vec<_>>>()?,
    );
    // A read handle opens from the checkpoint manifest, which is the last root
    // whose pages are known complete — it does not replay the WAL. The engine
    // does, so after a crash it holds commits the manifest does not name, and
    // until this refresh those reads would answer "not found" for writes that
    // were acknowledged as durable. Only the next commit's publish used to move
    // the readers forward, so a database that was killed and then only read from
    // served a stale snapshot indefinitely.
    {
        let (generation, root, len) = engine.committed_root();
        for reader in readers.iter() {
            reader
                .write()
                .map_err(|_| anyhow::anyhow!("read handle lock poisoned during startup"))?
                .refresh(generation, root, len)
                .context("failed to publish the recovered root to a read handle")?;
        }
    }
    let read_queues = start_read_workers(
        &readers,
        args.write_queue_capacity,
        Duration::from_millis(args.statement_deadline_ms),
    );
    let engine = Arc::new(RwLock::new(engine));
    let (write_sender, write_receiver) = mpsc::channel(args.write_queue_capacity);
    let changes = Arc::new(ChangeRing::new(args.write_queue_capacity));
    if deps.durability == DurabilityMode::Async {
        start_async_sync(
            Arc::clone(&engine),
            Duration::from_millis(args.async_sync_ms),
            Arc::clone(&deps.metrics),
        );
    }
    let checkpoint_due = Arc::new(AtomicBool::new(false));
    start_mvcc_gc(
        Arc::clone(&engine),
        Duration::from_millis(args.mvcc_gc_ms),
        args.mvcc_gc_checkpoint_versions,
        Arc::clone(&deps.metrics),
        Arc::clone(&checkpoint_due),
        Arc::clone(&readers),
    );
    // The WAL handle is shared so the flush stage can sync without taking the
    // engine's write lock, which is what lets one barrier cover several batches.
    let wal = engine
        .read()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?
        .wal();
    let (flush_sender, flush_receiver) = mpsc::channel(args.write_queue_capacity);
    // Shared between the two stages: the write worker grows a batch only while a
    // barrier is outstanding, and the flush stage tells it when one lands.
    let in_flight = Arc::new(AtomicU64::new(0));
    let (flush_completed, _) = watch::channel(0);
    start_flush_worker(
        wal,
        flush_receiver,
        FlushWorkerConfig {
            readers: Arc::clone(&readers),
            changes: Arc::clone(&changes),
            metrics: Arc::clone(&deps.metrics),
            engine: Arc::clone(&engine),
            in_flight: Arc::clone(&in_flight),
            flush_completed: flush_completed.clone(),
            replication: Arc::clone(&deps.replication),
        },
    );
    start_write_worker(
        Arc::clone(&engine),
        write_receiver,
        flush_sender,
        WriteWorkerConfig {
            maximum_batch: args.write_batch_size,
            delay: Duration::from_micros(args.write_batch_delay_us),
            checkpoint_writes: args.checkpoint_writes,
            metrics: Arc::clone(&deps.metrics),
            checkpoint_due: Arc::clone(&checkpoint_due),
            in_flight,
            flush_completed,
        },
    );
    Ok(Shard {
        writes: write_sender,
        changes,
        read_queues,
        readers,
        next_reader: AtomicU64::new(0),
        engine,
        wal_directory: directory.join("wal"),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.username.is_empty() || args.database.is_empty() {
        bail!("username and database must not be empty");
    }
    if args.max_connections == 0
        || args.max_auth_jobs == 0
        || args.checkpoint_writes == 0
        || args.write_batch_size == 0
        || args.write_queue_capacity == 0
        || args.read_handles == 0
    {
        bail!("connection, authentication, checkpoint, and write queue limits must be greater than zero");
    }
    /* A zero deadline would abandon every read before it began, including the
     * ones a health check makes, so the server would start and then serve
     * nothing. Refused at startup rather than discovered in production. */
    if args.statement_deadline_ms == 0 {
        bail!("VYRN_STATEMENT_DEADLINE_MS must be greater than zero");
    }
    if args.allow_plaintext && args.tls_cert_file.is_some() {
        bail!("choose TLS or plaintext; one listener cannot serve both");
    }
    if !args.allow_plaintext && args.tls_cert_file.is_none() {
        bail!("TLS certificate and key are required unless --allow-plaintext is explicit");
    }

    /* Exactly one credential store. Both set is refused rather than picking a
     * winner: the two modes disagree about who can do what, and a server that
     * silently ignored one file would enforce a policy nobody wrote down. */
    let authenticator = match (&args.password_hash_file, &args.users_file) {
        (Some(_), Some(_)) => bail!(
            "VYRN_PASSWORD_HASH_FILE and VYRN_USERS_FILE are both set; choose the \
             single-credential mode or the users file, not both"
        ),
        (Some(hash_path), None) => {
            auth::Authenticator::single(args.username.clone(), load_password_hash(hash_path)?)
        }
        (None, Some(users_path)) => auth::Authenticator::users(users_path.clone())?,
        (None, None) => bail!(
            "set VYRN_PASSWORD_HASH_FILE (single credential) or VYRN_USERS_FILE \
             (per-user accounts)"
        ),
    };
    // Failing startup rather than serving without the trail the operator
    // asked for; ongoing write failures degrade gracefully instead (see
    // `audit.rs`).
    let audit_log = args
        .audit_log
        .as_deref()
        .map(audit::AuditLog::open)
        .transpose()?;
    let tls_acceptor = match (&args.tls_cert_file, &args.tls_key_file) {
        (Some(certificate), Some(key)) => Some(load_tls(certificate, key)?),
        (None, None) => None,
        _ => unreachable!("clap validates paired TLS arguments"),
    };
    let durability = match args.durability.as_str() {
        "durable" => DurabilityMode::Durable,
        "async" => DurabilityMode::Async,
        _ => bail!("VYRN_DURABILITY must be durable or async"),
    };
    if durability == DurabilityMode::Async && args.async_sync_ms == 0 {
        bail!("VYRN_ASYNC_SYNC_MS must be greater than zero in async mode");
    }
    /* SHARDED-MODE SHAPE CHECKS. Everything sharding cannot yet compose with
     * is refused at startup rather than degraded at runtime: replication
     * streams exactly one WAL and the archiver archives exactly one, so
     * either would silently cover 1/N of the data if allowed through. */
    if args.shards == 0 {
        bail!("VYRN_SHARDS must be at least 1");
    }
    if args.shards > 1 {
        if args.replica_of.is_some() || args.cluster.is_some() {
            bail!(
                "--shards {} cannot be combined with replication or failover: each \
                 shard keeps its own WAL and LSN sequence, and the replication \
                 stream carries exactly one",
                args.shards
            );
        }
        if args.replication_min_acks > 0 {
            bail!("--replication-min-acks requires an unsharded server (--shards 1)");
        }
        if args.wal_archive_dir.is_some() {
            bail!(
                "--wal-archive-dir requires an unsharded server (--shards 1): the \
                 archive format holds one WAL sequence"
            );
        }
        if durability == DurabilityMode::Async {
            bail!(
                "--shards {} cannot be combined with async durability: async \
                 mode deliberately acknowledges writes before a WAL barrier, and \
                 a sharded server has one WAL per shard — a crash could then \
                 lose acknowledged writes the operator believed were durable. \
                 Sharded servers are fully ACID; run them in durable mode. \
                 Async remains available on a single shard for reconstructable \
                 realtime state.",
                args.shards
            );
        }
    }
    check_shard_marker(&args.data, args.shards)?;
    if let Some(archive_dir) = &args.wal_archive_dir {
        if args.wal_archive_interval_ms < 100 {
            bail!("VYRN_WAL_ARCHIVE_INTERVAL_MS must be at least 100");
        }
        // The archive must live outside the data directory: backup's file
        // enumeration is non-recursive, so a nested archive would be silently
        // excluded from backups yet destroyed by a restore. Both directories
        // are created up front because canonicalize requires them to exist.
        std::fs::create_dir_all(&args.data)
            .with_context(|| format!("failed to create data directory {}", args.data.display()))?;
        std::fs::create_dir_all(archive_dir).with_context(|| {
            format!(
                "failed to create WAL archive directory {}",
                archive_dir.display()
            )
        })?;
        let data = args.data.canonicalize().context("data directory")?;
        let archive = archive_dir
            .canonicalize()
            .context("WAL archive directory")?;
        if archive.starts_with(&data) {
            bail!("VYRN_WAL_ARCHIVE_DIR must not be inside the data directory");
        }
    }
    // The watermark exists before the engine so checkpoints observe the
    // archiver's progress from the very first deletion decision.
    let archived_through = args
        .wal_archive_dir
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(0)));

    /* Replication state is built before the engine so the record sink exists for
     * the very first commit. A record that slipped through before the sink was
     * attached would be a silent hole in the replica's log. */
    let replication = replication::Replication::new(
        args.replication_min_acks,
        Duration::from_millis(args.replication_ack_timeout_ms),
    );
    if replication.enabled() {
        log_info!(
            "vyrnd.replication",
            "synchronous replication enabled",
            min_acks = args.replication_min_acks,
            ack_timeout_ms = args.replication_ack_timeout_ms
        );
    }
    /* Automatic failover, only when the full membership is declared. The
     * shape checks (N >= 3, min-acks >= majority) are the safety argument
     * and refuse startup rather than degrade — see failover.rs. */
    let failover_state = match (&args.cluster, &args.cluster_self) {
        (Some(spec), Some(self_name)) => {
            let members = failover::parse_cluster(spec, self_name, args.replication_min_acks)?;
            let epochs = epoch::EpochStore::open(&args.data)?;
            log_info!(
                "vyrnd.failover",
                "automatic failover enabled",
                members = members.len(),
                self_name = self_name.clone(),
                epoch = epochs.current,
                role = if args.replica_of.is_some() {
                    "follower"
                } else {
                    "primary"
                }
            );
            Some(Arc::new(failover::Failover::new(
                members,
                self_name.clone(),
                epochs,
                args.replica_of.is_none(),
                Duration::from_millis(args.failover_lease_ms),
                Duration::from_millis(args.failover_election_ms),
            )))
        }
        _ => None,
    };
    /* The sink is attached ONLY when replication is on. With it absent the
     * engine's commit path is byte-for-byte what it was before this feature
     * existed — no clone of the record, no call, nothing to go wrong for the
     * overwhelming majority of deployments that run a single node. */
    let record_sink: Option<Arc<dyn vyrn_core::RecordSink>> = if replication.enabled() {
        Some(Arc::new(replication::ReplicationSink::new(Arc::clone(
            &replication,
        ))))
    } else {
        None
    };

    if args.write_back_bytes > 0 && args.replica_of.is_some() {
        anyhow::bail!(
            "--write-back-bytes cannot be used on a replica: replica apply writes \
             the primary's records straight to the tree and does not route through \
             a write-back buffer"
        );
    }
    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    let admin_listener = TcpListener::bind(&args.admin_bind)
        .await
        .with_context(|| format!("failed to bind admin endpoint {}", args.admin_bind))?;
    if args.transaction_timeout_seconds == 0
        || args.mvcc_gc_ms == 0
        || args.mvcc_gc_checkpoint_versions == 0
    {
        bail!("transaction timeout and MVCC GC interval must be greater than zero");
    }
    let metrics = Arc::new(Metrics::default());
    let deps = ShardDeps {
        durability,
        archived_through: archived_through.clone(),
        record_sink,
        replication: Arc::clone(&replication),
        metrics: Arc::clone(&metrics),
    };
    let mut shards = Vec::with_capacity(args.shards);
    for index in 0..args.shards {
        // One shard IS the data directory, so `--shards 1` serves exactly
        // what an older server left there; only a sharded layout introduces
        // subdirectories.
        let directory = if args.shards == 1 {
            args.data.clone()
        } else {
            args.data.join(format!("shard-{index}"))
        };
        shards.push(build_shard(&args, &directory, &deps)?);
    }
    // Started only after the engine is open, so the archiver can never see a
    // WAL tail that recovery is still truncating. Unsharded only; the shape
    // checks above refused the combination.
    if let (Some(archive_dir), Some(watermark)) = (&args.wal_archive_dir, &archived_through) {
        start_wal_archiver(
            Arc::clone(&shards[0].engine),
            shards[0].wal_directory.clone(),
            archive_dir.clone(),
            Arc::clone(watermark),
            Duration::from_millis(args.wal_archive_interval_ms),
            Arc::clone(&metrics),
        );
    }
    let state = Arc::new(ServerState {
        shards,
        auth: Arc::new(authenticator),
        audit: audit_log,
        database: args.database.clone(),
        auth_limit: Arc::new(Semaphore::new(args.max_auth_jobs)),
        auth_throttle: Arc::new(AuthThrottle::new()),
        write_budget: Arc::new(Semaphore::new(WRITE_QUEUE_MAX_BYTES)),
        transaction_timeout: Duration::from_secs(args.transaction_timeout_seconds),
        metrics: Arc::clone(&metrics),
        replication: Arc::clone(&replication),
        read_only: args.replica_of.is_some(),
        failover: failover_state.clone(),
    });
    /* REPLICA MODE. Started after the engine and the write pipeline exist,
     * because the replica task appends through the same engine handle. Reads are
     * served normally; client writes are refused (see the guard in the write
     * path), since a replica's log must contain only what its primary sent. */
    if let Some(primary_url) = args.replica_of.clone() {
        let password_file = args
            .replica_password_file
            .clone()
            .context("--replica-of requires --replica-password-file")?;
        let password = std::fs::read_to_string(&password_file)
            .with_context(|| format!("failed to read {password_file:?}"))?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        if password.is_empty() {
            bail!("replica password file {password_file:?} is empty");
        }
        // Defaults to the bind address so two replicas are distinguishable in the
        // primary's logs without extra configuration.
        let replica_id = args.replica_id.clone().unwrap_or_else(|| args.bind.clone());
        let replica_engine = Arc::clone(&state.lone_shard().engine);
        let config = replica::ReplicaConfig {
            primary_url,
            password,
            ca_file: args.replica_ca_file.clone(),
            replica_id,
            allow_plaintext: args.allow_plaintext,
            wal_archive_dir: args.replica_wal_archive_dir.clone(),
            failover: failover_state.clone(),
            readers: Arc::clone(&state.lone_shard().readers),
        };
        tokio::spawn(async move {
            if let Err(error) = replica::run(replica_engine, config).await {
                // Fatal replica errors are divergence, which retrying cannot fix.
                log_error!(
                    "vyrnd.replication",
                    "replication stopped; this replica will not catch up without an operator",
                    detail = format!("{error:#}")
                );
            }
        });
    }

    /* The failover coordinator: the lease on a primary, elections on a
     * follower. A follower dials its peers with the same credentials it
     * streams with; the initial primary has none and never stands — it
     * leads until deposed and rejoins via operator restart. */
    if let Some(failover) = failover_state.clone() {
        let credentials = match &args.replica_password_file {
            Some(file) => {
                let password = std::fs::read_to_string(file)
                    .with_context(|| format!("failed to read {file:?}"))?
                    .trim_end_matches(['\r', '\n'])
                    .to_owned();
                Some(failover::PeerCredentials {
                    password,
                    ca_file: args.replica_ca_file.clone(),
                    allow_plaintext: args.allow_plaintext,
                })
            }
            None => None,
        };
        tokio::spawn(failover::run_coordinator(
            failover,
            Arc::clone(&replication),
            Arc::clone(&state.lone_shard().engine),
            credentials,
        ));
    }

    let admin_metrics = Arc::clone(&metrics);
    let admin_replication = Arc::clone(&replication);
    let admin_engine = Arc::clone(&state.lone_shard().engine);
    let admin_shards = state.shards.len();
    tokio::spawn(async move {
        serve_admin(
            admin_listener,
            admin_metrics,
            admin_replication,
            admin_engine,
            admin_shards,
        )
        .await
    });
    metrics.ready.store(true, Ordering::Release);
    let connection_limit = Arc::new(Semaphore::new(args.max_connections));

    log_info!(
        "vyrnd",
        "listening",
        version = env!("CARGO_PKG_VERSION"),
        bind = args.bind,
        admin_bind = args.admin_bind,
        tls = tls_acceptor.is_some(),
        data = args.data.display(),
        durability = args.durability,
        checkpoint_writes = args.checkpoint_writes,
        max_connections = args.max_connections
    );
    /* Plaintext gets its own record at WARN rather than a parenthetical on the
     * line above. An operator scanning for problems filters by severity; a
     * server accepting unencrypted credentials on a network is a problem, and
     * hiding it inside an INFO message about binding is how it reaches
     * production unnoticed. */
    if tls_acceptor.is_none() {
        log_warn!(
            "vyrnd",
            "TLS is disabled; credentials and data cross the network in the clear",
            bind = args.bind
        );
    }

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept connection")?;
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let state = Arc::clone(&state);
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        handle_connection(stream, tls_acceptor, state, peer.ip()).await
                    {
                        /* DEBUG, not INFO: this fires once per connection that
                         * ends badly, and a client looping on a refused
                         * credential or a flaky network would otherwise fill the
                         * log with records about itself. The counters and the
                         * auth records carry what an operator needs at INFO. */
                        log_debug!(
                            "vyrnd.connection",
                            "connection closed with an error",
                            peer = peer,
                            detail = error
                        );
                    }
                });
            }
            result = shutdown_signal() => {
                result.context("failed to listen for shutdown signal")?;
                metrics.ready.store(false, Ordering::Release);
                log_info!(
                    "vyrnd",
                    "signal received, draining connections",
                    open = metrics.active_connections.load(Ordering::Acquire),
                    timeout_s = args.shutdown_timeout_seconds
                );
                break;
            }
        }
    }

    /* DRAIN, WITHOUT THE RACE.
     *
     * `Notify::notify_waiters` only wakes waiters that are ALREADY registered —
     * it stores no permit for a future one. Checking the count and then awaiting
     * `notified()` left a window between the two in which the last connection
     * finished and notified nobody, and shutdown then waited the entire
     * `--shutdown-timeout-seconds` with an idle server. That turned a clean
     * redeploy into a 30-second stall often enough to look like a hang.
     *
     * Registering the future FIRST closes the window: any notification from here
     * on is delivered to this waiter, so the count can be re-checked safely
     * afterwards. `tokio::pin!` because the future must stay put across the
     * check.
     */
    let drained = metrics.drained.notified();
    tokio::pin!(drained);
    if metrics.active_connections.load(Ordering::Acquire) != 0 {
        /* The timeout's result was discarded, which made a drain that ran out of
         * time indistinguishable from one that finished: both were followed by
         * "shutdown complete" and an exit code of zero. Those are different
         * events for whoever is reading the log after a rolling restart — one
         * means every client finished its work, the other means some number of
         * them were cut off mid-request — so the difference is now recorded. */
        if timeout(Duration::from_secs(args.shutdown_timeout_seconds), drained)
            .await
            .is_err()
        {
            log_warn!(
                "vyrnd",
                "drain timed out; connections were closed with work in flight",
                open = metrics.active_connections.load(Ordering::Acquire),
                timeout_s = args.shutdown_timeout_seconds
            );
        }
    }

    /* FINAL SYNC. In `--durability async` mode a commit is acknowledged before
     * its WAL record is flushed, and the background syncer runs on an interval,
     * so a clean shutdown here would otherwise discard whatever landed in that
     * last interval — losing acknowledged writes on an ORDERLY stop, which is
     * exactly when an operator expects nothing to be lost. In durable mode this
     * is a cheap no-op: everything is already synced.
     *
     * `spawn_blocking` because `sync` is blocking, and failures are reported
     * rather than ignored: a shutdown that could not make acknowledged writes
     * durable must not exit 0 and let a deploy script conclude all is well.
     */
    for shard in &state.shards {
        let sync_engine = Arc::clone(&shard.engine);
        match task::spawn_blocking(move || {
            sync_engine
                .write()
                .map_err(|_| StorageError::Poisoned)?
                .sync()
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log_error!(
                    "vyrnd.shutdown",
                    "storage sync failed on shutdown; acknowledged writes may be lost",
                    detail = error
                );
                bail!("shutdown could not make acknowledged writes durable: {error}");
            }
            Err(error) => {
                log_error!(
                    "vyrnd.shutdown",
                    "storage sync task failed on shutdown; acknowledged writes may be lost",
                    detail = error
                );
                bail!("shutdown could not make acknowledged writes durable");
            }
        }
    }
    log_info!("vyrnd", "shutdown complete");
    Ok(())
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    signal::ctrl_c().await
}

async fn handle_connection(
    stream: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    state: Arc<ServerState>,
    peer: IpAddr,
) -> Result<()> {
    state
        .metrics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    let _connection = ConnectionGuard(Arc::clone(&state.metrics));
    stream.set_nodelay(true)?;
    let transport: BoxedTransport = if let Some(acceptor) = tls_acceptor {
        let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .context("TLS handshake timed out")?
            .context("TLS handshake failed")?;
        Box::new(tls)
    } else {
        Box::new(stream)
    };
    // Small ceiling for the handshake; raised after authentication below.
    let mut framed = Framed::new(
        transport,
        VyrnCodec::builder()
            .max_frame_length(PREAUTH_MAX_FRAME_SIZE)
            .build(),
    );
    let Some(first) = next_message(&mut framed, HANDSHAKE_TIMEOUT).await? else {
        return Ok(());
    };

    if first.version != PROTOCOL_VERSION {
        send_error(
            &mut framed,
            first.request_id,
            ErrorCode::UnsupportedVersion,
            "unsupported protocol version",
        )
        .await?;
        return Ok(());
    }

    /* Locked-out addresses are refused here, BEFORE the Argon2 verification and
     * before the auth-job permit is taken. That ordering is the whole point:
     * refusing after the hash would leave the expensive work reachable by an
     * unauthenticated peer, which is what the throttle exists to prevent. */
    let locked_out = state.auth_throttle.is_locked_out(peer);
    let outcome = if locked_out {
        auth::AuthOutcome::Refused { known_user: None }
    } else {
        match first.message {
            Message::Authenticate {
                username,
                password,
                database,
            } if password.len() <= 4096 => {
                let permit = Arc::clone(&state.auth_limit).acquire_owned().await?;
                let expected_database = state.database.clone();
                let authenticator = Arc::clone(&state.auth);
                task::spawn_blocking(move || {
                    let _permit = permit;
                    match authenticator.authenticate(&username, &password) {
                        outcome if database == expected_database => outcome,
                        // A wrong database is refused identically to a wrong
                        // credential, after paying for the same verification.
                        auth::AuthOutcome::Granted(session) => auth::AuthOutcome::Refused {
                            known_user: Some(session.user),
                        },
                        refused => refused,
                    }
                })
                .await
                .context("authentication worker failed")?
            }
            _ => auth::AuthOutcome::Refused { known_user: None },
        }
    };
    let session = match outcome {
        auth::AuthOutcome::Granted(session) => Some(session),
        auth::AuthOutcome::Refused { known_user } => {
            /* The audit trail names the account only when the attempt named a
             * real one: an unknown "username" is as likely a mistyped
             * password, and the trail must never store credentials. */
            if let Some(audit) = &state.audit {
                let outcome = if locked_out { "throttled" } else { "rejected" };
                audit.auth(outcome, known_user.as_deref().unwrap_or("unknown"), &peer);
            }
            None
        }
    };
    if session.is_none() {
        /* Counted before the response is written, so a rejection is recorded even
         * if the peer has already gone away and the write fails. */
        state
            .metrics
            .auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
        state.auth_throttle.record_failure(peer);
        /* A THROTTLE REFUSAL AND A BAD PASSWORD ARE DIFFERENT EVENTS, and the
         * client cannot tell them apart by design — the response is identical so
         * a guesser learns nothing about which addresses are locked. The log is
         * where the distinction has to live: a run of `reason=throttled` means
         * this address is being held out and is no longer paying for password
         * hashes, while a run of `reason=rejected` means it still is.
         *
         * Nothing here names the credential. Not the password, not the username
         * as supplied, not the stored hash — a log that records a failed
         * authentication attempt records, by definition, a string somebody
         * believed was a password, and those turn up in the right log often
         * enough. The peer address is what an operator can act on.
         *
         * The reason is honest about its own precision: the verification folds
         * hash, username and database mismatch into one boolean, and a malformed
         * first frame lands here too, so `rejected` claims only that the
         * handshake was refused. */
        log_warn!(
            "vyrnd.auth",
            "authentication failed",
            peer = peer,
            reason = if locked_out { "throttled" } else { "rejected" }
        );
        send_error(
            &mut framed,
            first.request_id,
            ErrorCode::AuthenticationFailed,
            "authentication failed",
        )
        .await?;
        return Ok(());
    }
    let session = session.expect("refusals returned above");
    state.auth_throttle.record_success(peer);
    // DEBUG: one record per successful connection is per-request-shaped volume.
    log_debug!("vyrnd.auth", "authenticated", peer = peer);
    if let Some(audit) = &state.audit {
        audit.auth("success", &session.user, &peer);
    }
    send_frame(
        &mut framed,
        Envelope::new(first.request_id, Message::Authenticated),
    )
    .await?;
    /* The peer is trusted now, so it gets the full frame ceiling. Swapping the
     * codec keeps any bytes already buffered: `map_codec` preserves the read
     * buffer, and a client that pipelined its first request behind the
     * handshake would otherwise have it silently dropped. */
    let framed = framed.map_codec(|_| VyrnCodec::default());
    let mut transaction: Option<ConnectionTransaction> = None;

    /* The session runs in its own function purely so that the release below is
     * unavoidable.
     *
     * WHY: a transaction pins an engine snapshot, and that pin is what stops
     * MVCC collection from reclaiming versions the transaction can still see.
     * The loop is full of `?` on response writes, and a client that vanishes
     * mid-transaction makes those writes fail — which returned straight out of
     * `handle_connection`, past the release. The pin then survived the
     * connection that owned it, and because the MVCC floor is the minimum over
     * live snapshots, one such disconnect stopped version collection for the
     * remaining lifetime of the process: history grew without bound while every
     * metric still looked healthy.
     *
     * Holding the release in the caller makes every exit — clean end, protocol
     * error, failed write, or an early `return` some later edit adds inside the
     * loop — pass through it.
     */
    let served = run_session(framed, Arc::clone(&state), session, &mut transaction).await;
    if let Some(transaction) = transaction {
        release_transaction_snapshots(&state, transaction.sequences).await;
    }
    served
}

/// Serves authenticated requests until the connection ends.
///
/// Takes the transaction by `&mut` rather than owning it so that
/// `handle_connection` still sees an in-progress transaction after any exit
/// from here and can release its snapshot pin. See the comment at the call site.
async fn run_session(
    mut framed: Framed<BoxedTransport, VyrnCodec>,
    state: Arc<ServerState>,
    mut session: auth::SessionAuth,
    transaction: &mut Option<ConnectionTransaction>,
) -> Result<()> {
    let mut connection_error = None;
    /* PIPELINING: a request decoded during the previous iteration's drain
     * check, carried here so it is served before the connection waits on the
     * socket again. While one of these is in hand, responses are FED into the
     * codec's write buffer rather than flushed — a client that keeps several
     * requests in flight gets all of their answers in one write, so the
     * per-request syscall pair becomes a per-burst one. A client that sends
     * one request at a time never has a queued frame, takes the flush on
     * every iteration, and behaves exactly as before. */
    let mut queued_frame: Option<Envelope> = None;
    let mut unflushed = 0usize;
    loop {
        let request = if let Some(request) = queued_frame.take() {
            request
        } else {
            // The burst is over: everything answered so far leaves in one
            // write before the connection goes back to waiting.
            if unflushed > 0 {
                flush_frames(&mut framed).await?;
                unflushed = 0;
            }
            let request_timeout = transaction
                .as_ref()
                .map_or(CLIENT_IDLE_TIMEOUT, |transaction| {
                    state
                        .transaction_timeout
                        .saturating_sub(transaction.started.elapsed())
                        .min(CLIENT_IDLE_TIMEOUT)
                });
            match next_message(&mut framed, request_timeout).await {
                Ok(Some(request)) => request,
                Ok(None) => break,
                Err(error) => {
                    connection_error = Some(error);
                    break;
                }
            }
        };
        let request_id = request.request_id;
        if request.version != PROTOCOL_VERSION {
            send_error(
                &mut framed,
                request_id,
                ErrorCode::UnsupportedVersion,
                "unsupported protocol version",
            )
            .await?;
            continue;
        }
        /* THE AUTHORIZATION CHOKE POINT. Every decoded request — plain
         * operations, each statement inside a transaction, subscriptions, the
         * replica handshake — passes here before it is dispatched, so
         * enforcement lives in exactly one place. Two checks, in order:
         *
         * 1. The session is still current. A users-file reload bumps a
         *    generation; a stale session re-reads its permissions, and a user
         *    removed from the file is terminated on this, their next
         *    operation — revocation without a restart.
         * 2. The session's grants cover this request. A refusal is its own
         *    error shape, distinct from AuthenticationFailed: the credential
         *    is fine, the operation is not allowed. */
        if let auth::Refresh::Revoked = state.auth.refresh(&mut session) {
            if let Some(audit) = &state.audit {
                audit.auth("revoked", &session.user, &"-");
            }
            send_error(
                &mut framed,
                request_id,
                ErrorCode::AuthenticationFailed,
                "user is no longer authorized; session terminated",
            )
            .await?;
            return Ok(());
        }
        let mut intent = match auth::authorize(
            &session.permissions,
            &request.message,
            state.audit.is_some(),
        ) {
            Ok(intent) => intent,
            Err(denial) => {
                state.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
                state
                    .metrics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(audit) = &state.audit {
                    audit.denied(&session.user, denial.op, &denial.scope);
                }
                feed_frame(
                    &mut framed,
                    Envelope::new(
                        request_id,
                        server_error(
                            ErrorCode::InvalidRequest,
                            &format!("permission denied for {} on {}", denial.op, denial.scope),
                        ),
                    ),
                )
                .await?;
                unflushed += 1;
                continue;
            }
        };
        let response = match request.message {
            /* A replica converts its authenticated connection into a replication
             * stream. Placed before the ordinary request arms because from here
             * on the connection is a one-way record feed plus acknowledgements,
             * not a request/response channel.
             *
             * `transaction.is_none()` guard: a connection mid-transaction has
             * pinned engine state, and turning it into a stream would leak that.
             */
            /* A candidacy. Granting is durable before it is answered (see
             * `Failover::consider_vote`), and merely SEEING a higher epoch
             * deposes a primary — the request is proof an election it cannot
             * win is underway. */
            Message::VoteRequest { epoch, durable_lsn } if transaction.is_none() => {
                match &state.failover {
                    None => server_error(
                        ErrorCode::InvalidRequest,
                        "this node is not configured for automatic failover (--cluster)",
                    ),
                    Some(failover) => {
                        let own_lsn = state
                            .lone_shard()
                            .engine
                            .read()
                            .map(|engine| engine.last_lsn())
                            .unwrap_or(u64::MAX);
                        match failover.consider_vote(epoch, durable_lsn, own_lsn) {
                            Ok(granted) => {
                                log_info!(
                                    "vyrnd.failover",
                                    "vote requested",
                                    epoch = epoch,
                                    candidate_lsn = durable_lsn,
                                    own_lsn = own_lsn,
                                    granted = granted
                                );
                                Message::VoteResponse {
                                    granted,
                                    epoch: failover.epoch(),
                                }
                            }
                            /* A vote that cannot be persisted must not be
                             * granted — an unremembered grant can be cast
                             * twice. Refusing is always safe. */
                            Err(error) => {
                                log_error!(
                                    "vyrnd.failover",
                                    "vote refused: epoch persistence failed",
                                    detail = format!("{error:#}")
                                );
                                Message::VoteResponse {
                                    granted: false,
                                    epoch: failover.epoch(),
                                }
                            }
                        }
                    }
                }
            }
            Message::ReplicaHello {
                database,
                last_lsn,
                replica_id,
            } if transaction.is_none() => {
                /* Under automatic failover only the PRIMARY streams. Answered
                 * as an ordinary error, not ReplicaDiverged: divergence is
                 * fatal to a replica by design, while "not the primary" is
                 * exactly what a searching replica's member rotation retries
                 * past until it finds the member that is. */
                let not_primary = state.failover.as_ref().and_then(|failover| {
                    (failover.role() != failover::Role::Primary).then(|| {
                        format!(
                            "this member is not the primary ({:?} at epoch {}); \
                             try the other cluster members",
                            failover.role(),
                            failover.epoch()
                        )
                    })
                });
                if let Some(reason) = not_primary {
                    server_error(ErrorCode::InvalidRequest, &reason)
                } else if database != state.database {
                    server_error(
                        ErrorCode::InvalidRequest,
                        "replica requested a different database",
                    )
                } else if !state.replication.enabled() {
                    /* Refusing rather than streaming to a primary configured with
                     * min-acks 0 is deliberate: such a primary never waits for
                     * acknowledgements, so a replica would receive records while
                     * the operator believed nothing was replicated. Better to
                     * fail loudly at connect time. */
                    server_error(
                        ErrorCode::InvalidRequest,
                        "this node is not configured for replication \
                         (set --replication-min-acks to 1 or more)",
                    )
                } else {
                    let primary_lsn = state
                        .lone_shard()
                        .engine
                        .read()
                        .map(|engine| engine.last_lsn())
                        .unwrap_or(0);
                    /* The earliest LSN this primary can still supply. Checkpoints
                     * delete sealed segments, so this rises over time and is the
                     * fact that decides whether a lagging replica can be streamed
                     * to at all. Read from the WAL directory rather than kept in
                     * memory: which segments exist is something checkpoints change
                     * without announcing, and a cached copy would go stale exactly
                     * when a replica needs it to be right.
                     *
                     * A read failure reports 0, which means "nothing has been
                     * pruned" and lets the replica stream. That is the safe
                     * direction: the replica validates the join itself and refuses
                     * a stream that does not abut its log, so an over-optimistic
                     * answer here becomes a clear error there rather than a
                     * silently holed log. */
                    let oldest_available = task::spawn_blocking({
                        let wal = state.lone_shard().wal_directory.clone();
                        move || vyrn_core::replication::oldest_available_lsn(&wal)
                    })
                    .await
                    .ok()
                    .and_then(|result| result.ok())
                    .unwrap_or(0);
                    match replication::decide_join(last_lsn, primary_lsn, oldest_available) {
                        replication::JoinDecision::Refuse(reason) => {
                            log_warn!(
                                "vyrnd.replication",
                                "replica refused as diverged",
                                replica = format!("{replica_id:?}"),
                                last_lsn = last_lsn,
                                reason = reason
                            );
                            framed
                                .send(Envelope::new(
                                    request_id,
                                    Message::ReplicaDiverged { reason },
                                ))
                                .await?;
                            return Ok(());
                        }
                        /* A GAP, ANSWERED WITH THE TRUTH RATHER THAN A REFUSAL.
                         *
                         * The records this replica needs next have been pruned, so
                         * the primary says where streaming can actually begin —
                         * `oldest_available` — instead of pretending it can resume
                         * from the replica's last LSN. That is not a special
                         * protocol case: `ReplicaStream` has always meant "records
                         * start here", and `replication::check_join` on the replica
                         * side has always classified a `first_lsn` past its log as
                         * `GapBeforeStream`. Telling the truth is therefore enough
                         * for the replica to recognise the gap, size it exactly,
                         * and close it from the WAL archive before consuming the
                         * stream.
                         *
                         * This replaces a `ReplicaDiverged` refusal that left a
                         * merely-lagging replica permanently broken — it retried,
                         * was refused, retried again — while a `min-acks 1` primary
                         * BLOCKED WRITES waiting for the quorum that replica was
                         * supposed to provide. An outage that only manual
                         * intervention could end, for the ordinary event of a
                         * replica being offline across a few checkpoints.
                         */
                        replication::JoinDecision::Rebuild { reason } => {
                            log_info!(
                                "vyrnd.replication",
                                "replica needs a rebuild; streaming from the oldest \
                                 available LSN so it can close the gap from the archive",
                                replica = format!("{replica_id:?}"),
                                last_lsn = last_lsn,
                                first_lsn = oldest_available,
                                reason = reason
                            );
                            framed
                                .send(Envelope::new(
                                    request_id,
                                    Message::ReplicaStream {
                                        first_lsn: oldest_available,
                                    },
                                ))
                                .await?;
                            send_primary_epoch(&mut framed, state.failover.as_deref()).await?;
                            let resume = catch_up_from_wal(
                                &mut framed,
                                &state.lone_shard().wal_directory,
                                oldest_available,
                            )
                            .await?;
                            stream_records(
                                &mut framed,
                                &state.replication,
                                resume,
                                &replica_id,
                                state.failover.as_deref(),
                            )
                            .await?;
                            return Ok(());
                        }
                        replication::JoinDecision::Stream { first_lsn } => {
                            log_info!(
                                "vyrnd.replication",
                                "replica joined",
                                replica = format!("{replica_id:?}"),
                                first_lsn = first_lsn,
                                primary_lsn = primary_lsn
                            );
                            framed
                                .send(Envelope::new(
                                    request_id,
                                    Message::ReplicaStream { first_lsn },
                                ))
                                .await?;
                            send_primary_epoch(&mut framed, state.failover.as_deref()).await?;
                            let resume = catch_up_from_wal(
                                &mut framed,
                                &state.lone_shard().wal_directory,
                                first_lsn,
                            )
                            .await?;
                            stream_records(
                                &mut framed,
                                &state.replication,
                                resume,
                                &replica_id,
                                state.failover.as_deref(),
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                }
            }
            Message::Subscribe { prefix } if transaction.is_none() => {
                if prefix.len() > vyrn_core::MAX_KEY_SIZE {
                    server_error(
                        ErrorCode::InvalidRequest,
                        "subscription prefix is too large",
                    )
                } else {
                    framed
                        .send(Envelope::new(request_id, Message::Subscribed))
                        .await?;
                    record_audit(&state, &session, &mut intent, "ok");
                    stream_changes(&mut framed, subscribe_merged(&state), prefix).await?;
                    return Ok(());
                }
            }
            Message::SubscribeFrom { prefix, cursor } if transaction.is_none() => {
                if prefix.len() > vyrn_core::MAX_KEY_SIZE {
                    server_error(
                        ErrorCode::InvalidRequest,
                        "subscription prefix is too large",
                    )
                } else if state.sharded() {
                    /* A cursor token names a position in ONE change log, and a
                     * sharded server has one per shard. Refused rather than
                     * merged: an interleaved replay could not honor "resume
                     * exactly where the token says". Collection subscriptions
                     * still resume — a collection lives on one shard. */
                    server_error(
                        ErrorCode::InvalidRequest,
                        "SubscribeFrom is not available on a sharded server; \
                         subscribe live, or use collection subscriptions",
                    )
                } else {
                    match resolve_cursor(state.lone_shard(), cursor.as_deref()).await {
                        Ok(start) => {
                            framed
                                .send(Envelope::new(request_id, Message::Subscribed))
                                .await?;
                            record_audit(&state, &session, &mut intent, "ok");
                            stream_from_cursor(
                                &mut framed,
                                state.lone_shard(),
                                start,
                                CursorStream::Keys { prefix },
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(error) => storage_error_message(error),
                    }
                }
            }
            Message::SubscribeCollectionFrom { collection, cursor } if transaction.is_none() => {
                // A collection lives wholly on one shard, so its cursor tokens
                // all name positions in that shard's change log — resumable
                // even on a sharded server, unlike key-space SubscribeFrom.
                let shard = state.shard_for_collection(&collection);
                match resolve_cursor(shard, cursor.as_deref()).await {
                    Ok(start) => {
                        framed
                            .send(Envelope::new(request_id, Message::CollectionSubscribed))
                            .await?;
                        record_audit(&state, &session, &mut intent, "ok");
                        stream_from_cursor(
                            &mut framed,
                            shard,
                            start,
                            CursorStream::Collection { collection },
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(error) => storage_error_message(error),
                }
            }
            Message::SubscribeCollection { collection } if transaction.is_none() => {
                match vyrn_core::document::collection_key_prefix(&collection) {
                    Ok(prefix) => {
                        framed
                            .send(Envelope::new(request_id, Message::CollectionSubscribed))
                            .await?;
                        record_audit(&state, &session, &mut intent, "ok");
                        stream_document_changes(
                            &mut framed,
                            state.shard_for_collection(&collection).changes.subscribe(),
                            &collection,
                            prefix,
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(error) => storage_error_message(error),
                }
            }
            Message::Begin if transaction.is_none() => {
                match register_transaction_snapshots(&state).await {
                    Ok(sequences) => {
                        *transaction = Some(ConnectionTransaction {
                            sequences,
                            shard: None,
                            started: tokio::time::Instant::now(),
                            read_keys: BTreeMap::new(),
                            read_ranges: Vec::new(),
                            index_reads: Vec::new(),
                            writes: BTreeMap::new(),
                            index_updates: Vec::new(),
                        });
                        Message::Begun
                    }
                    Err(message) => server_error(ErrorCode::Storage, &message),
                }
            }
            Message::Commit if transaction.is_some() => {
                let transaction = transaction.take().unwrap();
                if transaction.started.elapsed() > state.transaction_timeout {
                    release_transaction_snapshots(&state, transaction.sequences).await;
                    server_error(
                        ErrorCode::Conflict,
                        "transaction exceeded its lifetime limit",
                    )
                } else {
                    commit_transaction(&state, transaction).await
                }
            }
            Message::Rollback if transaction.is_some() => {
                let transaction = transaction.take().unwrap();
                release_transaction_snapshots(&state, transaction.sequences).await;
                Message::RolledBack
            }
            Message::Begin
            | Message::Commit
            | Message::Rollback
            | Message::Subscribe { .. }
            | Message::SubscribeCollection { .. } => {
                server_error(ErrorCode::InvalidRequest, "invalid transaction state")
            }
            message => {
                if let Some(transaction) = transaction.as_mut() {
                    execute_transaction(&state, transaction, message).await
                } else {
                    execute(Arc::clone(&state), message).await
                }
            }
        };
        if intent.is_some() {
            let result = match &response {
                Message::Error { code, .. } => format!("error:{code:?}"),
                _ => "ok".to_owned(),
            };
            record_audit(&state, &session, &mut intent, &result);
        }
        feed_frame(&mut framed, Envelope::new(request_id, response)).await?;
        unflushed += 1;
        /* One non-blocking poll of the stream: decodes a frame the read
         * buffer already holds (or that a ready socket yields) without
         * waiting for one. `None` means nothing is immediately there — the
         * next iteration flushes and parks in `next_message` as before. */
        queued_frame = match framed.next().now_or_never() {
            Some(Some(Ok(request))) => Some(request),
            Some(Some(Err(error))) => {
                connection_error = Some(error.into());
                break;
            }
            // Peer closed after its last request; its answers still go out
            // through the flush below.
            Some(None) => break,
            None => None,
        };
    }
    /* Answers owed for requests served before the peer closed or broke the
     * stream. Best effort: the write's own failure must not mask the error
     * that ended the session. */
    if unflushed > 0 {
        let _ = flush_frames(&mut framed).await;
    }
    match connection_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Writes one audit line for a permitted operation, consuming the intent so a
/// request is recorded exactly once. A no-op without an audit log — the intent
/// is only built when one is configured.
fn record_audit(
    state: &ServerState,
    session: &auth::SessionAuth,
    intent: &mut Option<auth::Intent>,
    result: &str,
) {
    if let (Some(audit), Some(intent)) = (&state.audit, intent.take()) {
        audit.operation(&session.user, &intent, result);
    }
}

/// Registers a transaction's snapshot on every shard, using only read locks.
///
/// Beginning a transaction just reads the committed sequence and bumps a
/// refcount, so taking write locks here would make every transaction queue
/// behind the writers before doing any work. All shards are pinned at `Begin`
/// because the shard the transaction will use is not known until its first
/// key arrives, and a pin taken later would read a younger revision.
async fn register_transaction_snapshots(
    state: &ServerState,
) -> std::result::Result<Vec<u64>, String> {
    let mut sequences = Vec::with_capacity(state.shards.len());
    for shard in &state.shards {
        let engine = Arc::clone(&shard.engine);
        // Registration itself can fail on a poisoned snapshot registry, and that
        // failure must reach the client as a refused `Begin`: a transaction whose
        // pin was never recorded would read at a revision nothing is retaining.
        let registered = task::spawn_blocking(move || {
            let engine = engine.read().map_err(|_| StorageError::Poisoned)?;
            engine.register_snapshot_shared()
        })
        .await
        .map_err(|_| "snapshot registration task failed".to_owned())
        .and_then(|result| result.map_err(|error| error.to_string()));
        match registered {
            Ok(sequence) => sequences.push(sequence),
            Err(message) => {
                // A Begin that failed on one shard must not leave pins on the
                // shards registered before it. The gauge was never incremented,
                // so this path must not decrement it either.
                release_shard_pins(state, sequences).await;
                return Err(message);
            }
        }
    }
    // Counted only once every pin actually exists, so a failed registration
    // cannot inflate the gauge that is used to detect leaks.
    state
        .metrics
        .active_transaction_snapshots
        .fetch_add(1, Ordering::Relaxed);
    Ok(sequences)
}

/// Releases per-shard pins without touching the transaction gauge — for a
/// `Begin` that failed partway, before the transaction was ever counted.
/// Reports whether every pin was really dropped.
async fn release_shard_pins(state: &ServerState, sequences: Vec<u64>) -> bool {
    let mut all_released = true;
    for (index, sequence) in sequences.into_iter().enumerate() {
        let engine = Arc::clone(&state.shards[index].engine);
        let released = task::spawn_blocking(move || {
            // Two ways this can fail to release: the ENGINE lock is poisoned, or
            // the snapshot REGISTRY's own mutex is. Both leave the revision
            // pinned, so both report false and leave the gauge saying so.
            match engine.read() {
                Ok(engine) => engine.release_snapshot_shared(sequence).is_ok(),
                Err(_) => false,
            }
        })
        .await;
        all_released &= matches!(released, Ok(true));
    }
    all_released
}

/// Releases a transaction's snapshots.
///
/// Version collection is deliberately left to the background MVCC task: running
/// a full history sweep here would put an O(retained versions) scan under the
/// write lock on every single commit.
async fn release_transaction_snapshots(state: &ServerState, sequences: Vec<u64>) {
    let all_released = release_shard_pins(state, sequences).await;
    /* Decremented only when every pin was really dropped. A poisoned lock
     * leaves a snapshot pinned, and the gauge should keep saying so — that is
     * exactly the state an operator needs to see, and hiding it would defeat
     * the purpose of publishing the number. */
    if all_released {
        let _ = state.metrics.active_transaction_snapshots.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |count| {
                // Saturating: a double release would otherwise wrap the gauge to
                // u64::MAX and look like a catastrophic leak.
                Some(count.saturating_sub(1))
            },
        );
    }
}

/// Whether a message mutates storage, and so must be refused on a replica.
///
/// Listed explicitly rather than by a catch-all, so a NEW write message defaults
/// to being caught here: if someone adds a mutation and forgets this list, the
/// compiler's exhaustiveness check on the `match` in `execute` is what reminds
/// them, and until then the message simply is not classified as a read.
///
/// `Begin` counts: a transaction on a replica can only end in a commit that must
/// be refused, so refusing it at the start gives a clearer error than letting it
/// accumulate writes and fail later.
fn mutates_storage(message: &Message) -> bool {
    matches!(
        message,
        Message::Put { .. }
            | Message::Delete { .. }
            | Message::CreateIndex { .. }
            | Message::DropIndex { .. }
            | Message::IndexUpdate { .. }
            | Message::CreateCollection { .. }
            | Message::PutDocument { .. }
            | Message::DeleteDocument { .. }
            | Message::Begin
            | Message::Commit
    )
}

async fn execute(state: Arc<ServerState>, request: Message) -> Message {
    state.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
    /* A REPLICA REFUSES CLIENT WRITES. Its log must contain only what its primary
     * sent — a local write would take the next LSN from this node's own counter,
     * leaving the same LSN holding different bytes on the two nodes. The primary's
     * next record would then be rejected as non-contiguous, and the replica could
     * never be promoted without serving a history the primary never had.
     *
     * Checked here because `execute` is the single funnel every client request
     * passes through, so one guard covers every mutation path rather than six. */
    if mutates_storage(&request) {
        /* With failover configured the ROLE governs writes — a follower may
         * be promoted at runtime, and a deposed primary must refuse forever —
         * so the static flag defers to it. Without failover the flag is the
         * whole story, exactly as before the feature existed. */
        let refusal = match &state.failover {
            Some(failover) => match failover.role() {
                failover::Role::Primary => None,
                failover::Role::Follower => Some(format!(
                    "this node is a follower at epoch {}; send writes to the primary",
                    failover.epoch()
                )),
            },
            None if state.read_only => Some(
                "this node is a replica and does not accept writes; \
                 send writes to the primary, or promote this node by restarting it \
                 without --replica-of"
                    .to_owned(),
            ),
            None => None,
        };
        if let Some(refusal) = refusal {
            state
                .metrics
                .failed_requests
                .fetch_add(1, Ordering::Relaxed);
            return server_error(ErrorCode::InvalidRequest, &refusal);
        }
    }
    match request {
        Message::Put { key, value } => {
            state.metrics.writes.fetch_add(1, Ordering::Relaxed);
            submit_write(&state, BatchOperation::Put(key, value)).await
        }
        Message::Delete { key } => {
            state.metrics.writes.fetch_add(1, Ordering::Relaxed);
            submit_write(&state, BatchOperation::Delete(key)).await
        }
        Message::Get { key } => {
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            submit_get(&state, key).await
        }
        Message::MultiGet { keys } => {
            state
                .metrics
                .reads
                .fetch_add(keys.len() as u64, Ordering::Relaxed);
            if keys.is_empty() || keys.len() > MAX_SCAN_LIMIT as usize {
                return server_error(
                    ErrorCode::InvalidRequest,
                    "multi-get key count is out of range",
                );
            }
            submit_multi_get(&state, keys).await
        }
        Message::CreateCollection {
            collection,
            indexes,
        } => {
            if indexes.len() > MAX_DOCUMENT_INDEXES {
                return server_error(ErrorCode::InvalidRequest, "too many document indexes");
            }
            state.metrics.writes.fetch_add(1, Ordering::Relaxed);
            submit_document(
                &state,
                DocumentWrite::CreateCollection {
                    collection,
                    indexes: indexes
                        .into_iter()
                        .map(|index| IndexDefinition::new(index.field, index.unique))
                        .collect(),
                },
            )
            .await
        }
        Message::PutDocument {
            collection,
            id,
            document,
        } => {
            state.metrics.writes.fetch_add(1, Ordering::Relaxed);
            submit_document(
                &state,
                DocumentWrite::Put {
                    collection,
                    id,
                    document,
                },
            )
            .await
        }
        Message::DeleteDocument { collection, id } => {
            state.metrics.writes.fetch_add(1, Ordering::Relaxed);
            submit_document(&state, DocumentWrite::Delete { collection, id }).await
        }
        Message::GetDocument { collection, id } => {
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            submit_document_read(&state, DocumentRead::Get { collection, id }).await
        }
        Message::ListDocuments { collection, limit } => {
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "document limit is out of range");
            }
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            submit_document_read(
                &state,
                DocumentRead::List {
                    collection,
                    limit: limit as usize,
                },
            )
            .await
        }
        Message::QueryDocuments {
            collection,
            field,
            value,
            limit,
        } => {
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "document limit is out of range");
            }
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&value) else {
                return server_error(
                    ErrorCode::InvalidRequest,
                    "document query value is not valid JSON",
                );
            };
            submit_document_read(
                &state,
                DocumentRead::Query {
                    collection,
                    field,
                    value,
                    limit: limit as usize,
                },
            )
            .await
        }
        Message::CreateIndex { name, unique } => submit_create_index(&state, name, unique).await,
        Message::DropIndex { name } => submit_drop_index(&state, name).await,
        Message::IndexLookup {
            index,
            value,
            limit,
        } => {
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "index limit is out of range");
            }
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            submit_index_lookup(&state, index, value, limit as usize).await
        }
        Message::Scan { start, end, limit } => {
            state.metrics.reads.fetch_add(1, Ordering::Relaxed);
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "scan limit is out of range");
            }
            if start
                .as_deref()
                .zip(end.as_deref())
                .is_some_and(|(start, end)| start > end)
            {
                return server_error(ErrorCode::InvalidRequest, "scan start must not exceed end");
            }
            submit_scan(&state, start, end, limit as usize).await
        }
        _ => server_error(ErrorCode::InvalidRequest, "message is not a valid request"),
    }
}

async fn submit_document_read(state: &ServerState, request: DocumentRead) -> Message {
    let shard = state.shard_for_collection(document_read_collection(&request));
    let (response, receiver) = oneshot::channel();
    if let Err(error) =
        shard.read_queues[next_reader(shard)].try_send(ReadRequest::Document { request, response })
    {
        return read_dispatch_error(error);
    }
    match receiver.await {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn submit_index_lookup(
    state: &ServerState,
    index: Vec<u8>,
    value: Vec<u8>,
    limit: usize,
) -> Message {
    /* A global index would need every shard's updates in one tree — exactly
     * the cross-shard atomicity sharding gives up. Refused at creation, so a
     * lookup could never find anything anyway; refusing it too keeps the
     * error at the operation the client actually got wrong. Collection
     * indexes still work — they live with their collection's shard. */
    if state.sharded() {
        return server_error(
            ErrorCode::InvalidRequest,
            "global indexes are not available on a sharded server; collection \
             indexes work — a collection lives on one shard",
        );
    }
    let shard = state.lone_shard();
    let (response, receiver) = oneshot::channel();
    if let Err(error) = shard.read_queues[next_reader(shard)].try_send(ReadRequest::IndexLookup {
        index,
        value,
        limit,
        response,
    }) {
        return read_dispatch_error(error);
    }
    match receiver.await {
        Ok(Ok(keys)) => Message::Keys { keys },
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn execute_engine_shared<F>(engine: &Arc<RwLock<Engine>>, operation: F) -> Message
where
    F: FnOnce(&Engine) -> vyrn_core::Result<Message> + Send + 'static,
{
    let engine = Arc::clone(engine);
    match task::spawn_blocking(move || {
        let engine = engine.read().map_err(|_| StorageError::Poisoned)?;
        operation(&engine)
    })
    .await
    {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage operation task failed"),
    }
}

fn storage_error_message(error: StorageError) -> Message {
    match error {
        StorageError::Conflict | StorageError::UniqueViolation { .. } => {
            server_error(ErrorCode::Conflict, &error.to_string())
        }
        StorageError::EmptyKey
        | StorageError::ReservedKey
        | StorageError::KeyTooLarge
        | StorageError::ValueTooLarge
        | StorageError::InvalidRange
        | StorageError::SnapshotTooOld { .. }
        | StorageError::IndexExists
        | StorageError::IndexNotFound => {
            server_error(ErrorCode::InvalidRequest, &error.to_string())
        }
        _ => server_error(ErrorCode::Storage, &error.to_string()),
    }
}

async fn submit_create_index(state: &Arc<ServerState>, name: Vec<u8>, unique: bool) -> Message {
    if state.sharded() {
        return server_error(
            ErrorCode::InvalidRequest,
            "global indexes are not available on a sharded server; collection \
             indexes work — a collection lives on one shard",
        );
    }
    let (sender, receiver) = oneshot::channel();
    if state
        .lone_shard()
        .writes
        .send(WriteRequest::CreateIndex {
            name,
            unique,
            response: sender,
        })
        .await
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage writer is unavailable");
    }
    match receiver.await {
        Ok(Ok(())) => Message::IndexCreated,
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    }
}

async fn submit_drop_index(state: &Arc<ServerState>, name: Vec<u8>) -> Message {
    if state.sharded() {
        return server_error(
            ErrorCode::InvalidRequest,
            "global indexes are not available on a sharded server; collection \
             indexes work — a collection lives on one shard",
        );
    }
    let (sender, receiver) = oneshot::channel();
    if state
        .lone_shard()
        .writes
        .send(WriteRequest::DropIndex {
            name,
            response: sender,
        })
        .await
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage writer is unavailable");
    }
    match receiver.await {
        Ok(Ok(())) => Message::IndexDropped,
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    }
}

fn encode_document(
    value: &serde_json::Map<String, serde_json::Value>,
) -> vyrn_core::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| {
        StorageError::InvalidDocument(format!("document encoding failed: {error}"))
    })
}

fn encode_documents(documents: Vec<vyrn_core::document::Document>) -> vyrn_core::Result<Message> {
    Ok(Message::Documents {
        documents: documents
            .into_iter()
            .map(|document| Ok((document.id, encode_document(&document.value)?)))
            .collect::<vyrn_core::Result<Vec<_>>>()?,
    })
}

async fn submit_document(state: &Arc<ServerState>, request: DocumentWrite) -> Message {
    let _budget = WriteBudget::acquire(&state.write_budget, document_write_bytes(&request)).await;
    let (sender, receiver) = oneshot::channel();
    if state
        .shard_for_collection(document_write_collection(&request))
        .writes
        .send(WriteRequest::Document {
            request,
            response: sender,
        })
        .await
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage writer is unavailable");
    }
    match receiver.await {
        // Already a rendered message, storage errors included: the pipeline
        // renders them so an error code chosen for the fault survives the trip
        // through the ordered publication point.
        Ok(Ok(message)) => message,
        Ok(Err(message)) => server_error(ErrorCode::Storage, &message),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    }
}

async fn submit_write(state: &Arc<ServerState>, operation: BatchOperation) -> Message {
    // Held until this request has been answered; see `WriteBudget`.
    let _budget = WriteBudget::acquire(&state.write_budget, operation_bytes(&operation)).await;
    let (sender, receiver) = oneshot::channel();
    if state
        .shard_for_key(operation_key(&operation))
        .writes
        .send(WriteRequest::Operation {
            operation,
            response: sender,
            queued: Instant::now(),
        })
        .await
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage writer is unavailable");
    }
    match receiver.await {
        Ok(Ok(BatchResult::Put)) => Message::Written,
        Ok(Ok(BatchResult::Delete { existed })) => Message::Deleted { existed },
        Ok(Err(message)) => server_error(ErrorCode::Storage, &message),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    }
}

/// The shard a transaction runs against, pinned by its first key.
///
/// Every later key must land on the same shard: reads are validated and
/// writes committed against ONE shard's snapshot at commit, so an operation
/// quietly routed to another shard's engine would escape conflict detection
/// entirely. Unsharded every key hashes to shard 0 and nothing is refused.
fn transaction_shard(
    state: &ServerState,
    transaction: &mut ConnectionTransaction,
    key: &[u8],
) -> std::result::Result<usize, Message> {
    let index = state.shard_index_for_key(key);
    match transaction.shard {
        None => {
            transaction.shard = Some(index);
            Ok(index)
        }
        Some(pinned) if pinned == index => Ok(index),
        Some(_) => Err(server_error(
            ErrorCode::InvalidRequest,
            "cross-shard transaction: this key lives on a different shard than \
             the transaction's earlier keys; commit and use a second transaction",
        )),
    }
}

async fn execute_transaction(
    state: &Arc<ServerState>,
    transaction: &mut ConnectionTransaction,
    request: Message,
) -> Message {
    match request {
        Message::Get { key } => {
            let shard = match transaction_shard(state, transaction, &key) {
                Ok(shard) => shard,
                Err(refusal) => return refusal,
            };
            transaction.read_keys.insert(key.clone(), ());
            if let Some(value) = transaction.writes.get(&key) {
                return Message::Value {
                    value: value.clone(),
                };
            }
            let revision = transaction.sequences[shard];
            execute_engine_shared(&state.shards[shard].engine, move |engine| {
                Ok(Message::Value {
                    value: engine.get_at(&key, revision)?,
                })
            })
            .await
        }
        Message::Put { key, value } => {
            if let Err(refusal) = transaction_shard(state, transaction, &key) {
                return refusal;
            }
            transaction.writes.insert(key, Some(value));
            Message::Written
        }
        Message::Delete { key } => {
            let shard = match transaction_shard(state, transaction, &key) {
                Ok(shard) => shard,
                Err(refusal) => return refusal,
            };
            let existed = if let Some(value) = transaction.writes.get(&key) {
                value.is_some()
            } else {
                let revision = transaction.sequences[shard];
                let lookup_key = key.clone();
                match execute_engine_shared(&state.shards[shard].engine, move |engine| {
                    Ok(Message::Value {
                        value: engine.get_at(&lookup_key, revision)?,
                    })
                })
                .await
                {
                    Message::Value { value } => value.is_some(),
                    error => return error,
                }
            };
            transaction.writes.insert(key, None);
            Message::Deleted { existed }
        }
        // Global indexes are refused at creation on a sharded server, so
        // inside a transaction the answer is the same.
        Message::IndexUpdate { .. } | Message::IndexLookup { .. } if state.sharded() => {
            server_error(
                ErrorCode::InvalidRequest,
                "global indexes are not available on a sharded server",
            )
        }
        Message::IndexUpdate {
            index,
            primary_key,
            old_value,
            new_value,
        } => {
            transaction.index_updates.push(IndexUpdate {
                index,
                primary_key,
                old_value,
                new_value,
            });
            Message::IndexUpdated
        }
        Message::IndexLookup {
            index,
            value,
            limit,
        } => {
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "index limit is out of range");
            }
            transaction.index_reads.push((index.clone(), value.clone()));
            let revision = transaction.sequences[0];
            let fetch_limit = limit as usize + transaction.index_updates.len();
            let lookup_index = index.clone();
            let lookup_value = value.clone();
            let keys = match execute_engine_shared(&state.lone_shard().engine, move |engine| {
                Ok(Message::Keys {
                    keys: engine.lookup_index_at(
                        &lookup_index,
                        &lookup_value,
                        fetch_limit,
                        revision,
                    )?,
                })
            })
            .await
            {
                Message::Keys { keys } => keys,
                error => return error,
            };
            let mut keys: BTreeMap<_, _> = keys.into_iter().map(|key| (key, ())).collect();
            for update in &transaction.index_updates {
                if update.index != index || update.old_value == update.new_value {
                    continue;
                }
                if update.old_value.as_ref() == Some(&value) {
                    keys.remove(&update.primary_key);
                }
                if update.new_value.as_ref() == Some(&value) {
                    keys.insert(update.primary_key.clone(), ());
                }
            }
            Message::Keys {
                keys: keys.into_keys().take(limit as usize).collect(),
            }
        }
        /* Hash placement makes every range cross-shard, and a transaction
         * validates its reads against ONE shard's snapshot at commit — a
         * merged scan would return rows no single snapshot can vouch for.
         * Scans outside a transaction still merge across shards. */
        Message::Scan { .. } if state.sharded() => server_error(
            ErrorCode::InvalidRequest,
            "range scans inside a transaction are not available on a sharded \
             server; scan outside the transaction",
        ),
        Message::Scan { start, end, limit } => {
            if limit == 0 || limit > MAX_SCAN_LIMIT {
                return server_error(ErrorCode::InvalidRequest, "scan limit is out of range");
            }
            if start
                .as_deref()
                .zip(end.as_deref())
                .is_some_and(|(start, end)| start > end)
            {
                return server_error(ErrorCode::InvalidRequest, "scan start must not exceed end");
            }
            transaction.read_ranges.push((start.clone(), end.clone()));
            let revision = transaction.sequences[0];
            let fetch_limit = limit as usize + transaction.writes.len();
            let scan_start = start.clone();
            let scan_end = end.clone();
            let rows = match execute_engine_shared(&state.lone_shard().engine, move |engine| {
                Ok(Message::Rows {
                    rows: engine.scan_at(
                        scan_start.as_deref(),
                        scan_end.as_deref(),
                        fetch_limit,
                        revision,
                    )?,
                })
            })
            .await
            {
                Message::Rows { rows } => rows,
                error => return error,
            };
            let mut view: BTreeMap<_, _> = rows.into_iter().collect();
            for (key, value) in &transaction.writes {
                if start.as_ref().is_some_and(|start| key < start)
                    || end.as_ref().is_some_and(|end| key >= end)
                {
                    continue;
                }
                if let Some(value) = value {
                    view.insert(key.clone(), value.clone());
                } else {
                    view.remove(key);
                }
            }
            Message::Rows {
                rows: view.into_iter().take(limit as usize).collect(),
            }
        }
        _ => server_error(
            ErrorCode::InvalidRequest,
            "message is not valid in a transaction",
        ),
    }
}

async fn commit_transaction(
    state: &Arc<ServerState>,
    transaction: ConnectionTransaction,
) -> Message {
    let ConnectionTransaction {
        sequences,
        shard,
        read_keys,
        read_ranges,
        index_reads,
        writes,
        index_updates,
        ..
    } = transaction;
    if writes.is_empty() && index_updates.is_empty() {
        release_transaction_snapshots(state, sequences).await;
        return Message::Committed;
    }
    // Everything the transaction touched was pinned to one shard (index
    // updates only exist unsharded, where every shard index is 0), so the
    // commit is one shard's atomic batch, validated against that shard's
    // snapshot.
    let shard_index = shard.unwrap_or(0);
    let snapshot_sequence = sequences[shard_index];
    let operations: Vec<_> = writes
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => BatchOperation::Put(key, value),
            None => BatchOperation::Delete(key),
        })
        .collect();
    /* A transaction is the largest thing that enters the queue — every write it
     * accumulated arrives as one request — so this is the path the byte bound
     * exists for. Acquired after the early return above, so an empty commit
     * never waits on budget. */
    let _budget = WriteBudget::acquire(
        &state.write_budget,
        operations.iter().map(operation_bytes).sum(),
    )
    .await;
    let (sender, receiver) = oneshot::channel();
    if state.shards[shard_index]
        .writes
        .send(WriteRequest::Transaction {
            snapshot_sequence,
            read_keys: read_keys.into_keys().collect(),
            read_ranges,
            index_reads,
            operations,
            index_updates,
            response: sender,
            queued: Instant::now(),
        })
        .await
        .is_err()
    {
        release_transaction_snapshots(state, sequences).await;
        return server_error(ErrorCode::Storage, "storage writer is unavailable");
    }
    let response = match receiver.await {
        Ok(Ok(_)) => Message::Committed,
        Ok(Err(message)) if message == StorageError::Conflict.to_string() => {
            server_error(ErrorCode::Conflict, &message)
        }
        Ok(Err(message)) => server_error(ErrorCode::Storage, &message),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    };
    release_transaction_snapshots(state, sequences).await;
    response
}

fn server_error(code: ErrorCode, message: &str) -> Message {
    Message::Error {
        code,
        message: message.to_owned(),
    }
}

async fn next_message(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    duration: Duration,
) -> Result<Option<Envelope>> {
    match timeout(duration, framed.next()).await {
        Ok(Some(Ok(message))) => Ok(Some(message)),
        Ok(Some(Err(error))) => Err(error.into()),
        Ok(None) => Ok(None),
        Err(_) => bail!("client idle timeout"),
    }
}

/// Sends one frame, refusing to block forever on a peer that stopped reading.
///
/// A `send` only completes once the kernel has accepted every byte; a peer that
/// never reads — a wedged consumer, a half-open NAT mapping — leaves its socket
/// buffer full and this future pending indefinitely, while the session task
/// keeps holding a connection-limit permit and an active-connections slot (and,
/// mid-transaction, an engine snapshot pin). Bounding the write turns such a
/// peer into an ordinary disconnect: the session ends through the same cleanup
/// path as any other exit, so nothing is leaked. Every response path in this
/// file goes through here for exactly that reason.
async fn send_frame(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    envelope: Envelope,
) -> Result<()> {
    match timeout(RESPONSE_WRITE_TIMEOUT, framed.send(envelope)).await {
        Ok(result) => Ok(result?),
        Err(_) => bail!("peer stopped reading; response write exceeded {RESPONSE_WRITE_TIMEOUT:?}"),
    }
}

/// Buffers one frame in the codec without flushing, for pipelined bursts whose
/// answers leave in one write.
///
/// Not free of I/O: once the codec's write buffer crosses its backpressure
/// boundary, `feed` flushes before accepting more, which is what bounds the
/// memory a burst of large responses can hold. That flush can wedge on a peer
/// that stopped reading, so it wears the same timeout as [`send_frame`], for
/// the same reason.
async fn feed_frame(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    envelope: Envelope,
) -> Result<()> {
    match timeout(RESPONSE_WRITE_TIMEOUT, framed.feed(envelope)).await {
        Ok(result) => Ok(result?),
        Err(_) => bail!("peer stopped reading; response write exceeded {RESPONSE_WRITE_TIMEOUT:?}"),
    }
}

/// Writes out everything [`feed_frame`] buffered, ending a pipelined burst.
async fn flush_frames(framed: &mut Framed<BoxedTransport, VyrnCodec>) -> Result<()> {
    match timeout(RESPONSE_WRITE_TIMEOUT, framed.flush()).await {
        Ok(result) => Ok(result?),
        Err(_) => bail!("peer stopped reading; response flush exceeded {RESPONSE_WRITE_TIMEOUT:?}"),
    }
}

async fn send_error(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    request_id: u64,
    code: ErrorCode,
    message: &str,
) -> Result<()> {
    send_frame(
        framed,
        Envelope::new(request_id, server_error(code, message)),
    )
    .await
}

fn load_password_hash(path: &Path) -> Result<PasswordHashString> {
    let hash = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read password hash file {}", path.display()))?;
    let hash = hash.trim_end_matches(['\r', '\n']);
    if hash.is_empty() || hash.contains(['\r', '\n']) || !hash.starts_with("$argon2id$") {
        bail!("password hash file must contain exactly one Argon2id PHC string");
    }
    PasswordHashString::new(hash)
        .map_err(|_| anyhow::anyhow!("password hash file contains an invalid PHC string"))
}

fn load_tls(certificate_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(
        File::open(certificate_path).context("failed to open TLS certificate")?,
    ))
    .collect::<std::result::Result<_, _>>()
    .context("failed to parse TLS certificate")?;
    if certificates.is_empty() {
        bail!("TLS certificate file contains no certificates");
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(key_path).context("failed to open TLS private key")?,
    ))
    .context("failed to parse TLS private key")?
    .context("TLS private key file contains no key")?;
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("TLS certificate and key are invalid or do not match")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests;
