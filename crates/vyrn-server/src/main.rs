use anyhow::{bail, Context, Result};
use argon2::{password_hash::PasswordHashString, Argon2, PasswordVerifier};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::{broadcast, mpsc, oneshot, watch, Notify, Semaphore},
    task,
    time::{sleep, timeout, Duration},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use vyrn_core::{
    change_log, document::IndexDefinition, BatchOperation, BatchResult, DurabilityMode, Engine,
    EngineOptions, Error as StorageError, IndexUpdate, ReadEngine,
};
use vyrn_protocol::{
    Envelope, ErrorCode, Message, VyrnCodec, MAX_DOCUMENT_INDEXES, MAX_SCAN_LIMIT, PROTOCOL_VERSION,
};

const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CHANGE_REPLAY_BATCH: usize = 512;

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
type BoxedTransport = Box<dyn Transport>;
type ReadRange = (Option<Vec<u8>>, Option<Vec<u8>>);
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Parser)]
#[command(name = "vyrnd", version, about = "Vyrn database server")]
struct Args {
    #[arg(long, env = "VYRN_BIND", default_value = "127.0.0.1:7432")]
    bind: String,
    #[arg(long, env = "VYRN_DATA", default_value = "./data")]
    data: PathBuf,
    #[arg(long, env = "VYRN_USERNAME", default_value = "vyrn")]
    username: String,
    #[arg(long, env = "VYRN_PASSWORD_HASH_FILE")]
    password_hash_file: PathBuf,
    #[arg(long, env = "VYRN_DATABASE", default_value = "default")]
    database: String,
    #[arg(long, env = "VYRN_TLS_CERT_FILE", requires = "tls_key_file")]
    tls_cert_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_TLS_KEY_FILE", requires = "tls_cert_file")]
    tls_key_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_ALLOW_PLAINTEXT", default_value_t = false)]
    allow_plaintext: bool,
    #[arg(long, env = "VYRN_MAX_CONNECTIONS", default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, env = "VYRN_MAX_AUTH_JOBS", default_value_t = 8)]
    max_auth_jobs: usize,
    #[arg(long, env = "VYRN_CHECKPOINT_WRITES", default_value_t = 10_000)]
    checkpoint_writes: u64,
    #[arg(long, env = "VYRN_ADMIN_BIND", default_value = "127.0.0.1:7433")]
    admin_bind: String,
    #[arg(long, env = "VYRN_SHUTDOWN_TIMEOUT_SECONDS", default_value_t = 30)]
    shutdown_timeout_seconds: u64,
    #[arg(long, env = "VYRN_WRITE_BATCH_SIZE", default_value_t = 64)]
    write_batch_size: usize,
    #[arg(long, env = "VYRN_WRITE_BATCH_DELAY_US", default_value_t = 200)]
    write_batch_delay_us: u64,
    #[arg(long, env = "VYRN_WRITE_QUEUE_CAPACITY", default_value_t = 4096)]
    write_queue_capacity: usize,
    #[arg(long, env = "VYRN_DURABILITY", default_value = "durable")]
    durability: String,
    #[arg(long, env = "VYRN_ASYNC_SYNC_MS", default_value_t = 5)]
    async_sync_ms: u64,
    #[arg(long, env = "VYRN_TRANSACTION_TIMEOUT_SECONDS", default_value_t = 30)]
    transaction_timeout_seconds: u64,
    #[arg(long, env = "VYRN_READ_HANDLES", default_value_t = 16)]
    read_handles: usize,
    #[arg(long, env = "VYRN_MVCC_GC_MS", default_value_t = 1_000)]
    mvcc_gc_ms: u64,
    #[arg(
        long,
        env = "VYRN_MVCC_GC_CHECKPOINT_VERSIONS",
        default_value_t = 10_000
    )]
    mvcc_gc_checkpoint_versions: usize,
    #[arg(long, env = "VYRN_WAL_ARCHIVE_DIR")]
    wal_archive_dir: Option<PathBuf>,
    #[arg(long, env = "VYRN_WAL_ARCHIVE_INTERVAL_MS", default_value_t = 5_000)]
    wal_archive_interval_ms: u64,
}

struct Metrics {
    ready: AtomicBool,
    active_connections: AtomicU64,
    total_requests: AtomicU64,
    failed_requests: AtomicU64,
    reads: AtomicU64,
    writes: AtomicU64,
    checkpoints: AtomicU64,
    write_batches: AtomicU64,
    batched_writes: AtomicU64,
    /// WAL barriers actually issued, and applied batches they covered. The ratio
    /// is how much group commit is amortising the sync.
    wal_flushes: AtomicU64,
    flushed_batches: AtomicU64,
    mvcc_versions_collected: AtomicU64,
    mvcc_gc_runs: AtomicU64,
    /// Where a durable commit spends its time, stage by stage.
    write_profile: WriteProfile,
    /// Sealed segments the archiver has not copied out yet (gauge). Growth
    /// means the archiver is falling behind the write rate.
    wal_archive_lag_segments: AtomicU64,
    wal_archived_total: AtomicU64,
    wal_archive_failures_total: AtomicU64,
    storage_failed: AtomicBool,
    drained: Notify,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            ready: AtomicBool::new(false),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            checkpoints: AtomicU64::new(0),
            write_batches: AtomicU64::new(0),
            batched_writes: AtomicU64::new(0),
            wal_flushes: AtomicU64::new(0),
            flushed_batches: AtomicU64::new(0),
            mvcc_versions_collected: AtomicU64::new(0),
            mvcc_gc_runs: AtomicU64::new(0),
            write_profile: WriteProfile::default(),
            wal_archive_lag_segments: AtomicU64::new(0),
            wal_archived_total: AtomicU64::new(0),
            wal_archive_failures_total: AtomicU64::new(0),
            storage_failed: AtomicBool::new(false),
            drained: Notify::new(),
        }
    }
}

/// A log-spaced latency histogram with four buckets per octave.
///
/// Totals are not enough to read this path: on a host whose p95 is thirty times
/// its median, one stalled batch moves a mean further than a real regression
/// does. Four buckets per octave holds the quantile error near 9%, which is far
/// inside the differences worth acting on, for 160 atomics and one increment per
/// observation.
struct Histogram {
    buckets: [AtomicU64; Self::BUCKETS],
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Histogram {
    /// 40 octaves reaches about 18 minutes, so nothing observable saturates.
    const BUCKETS: usize = 160;

    /// The first octave whose values are wide enough to subdivide. Below it each
    /// nanosecond value is its own bucket, which costs nothing and keeps the
    /// index arithmetic total.
    const FLAT: u32 = 2;

    fn index(nanoseconds: u64) -> usize {
        let octave = 63 - nanoseconds.max(1).leading_zeros();
        if octave < Self::FLAT {
            return nanoseconds as usize;
        }
        let sub = (nanoseconds >> (octave - Self::FLAT)) & 3;
        ((octave * 4 + sub as u32) as usize).min(Self::BUCKETS - 1)
    }

    /// The inclusive lower bound of `index`, used to place a quantile.
    fn lower_bound(index: usize) -> u64 {
        let octave = index as u32 / 4;
        if octave < Self::FLAT {
            return index as u64;
        }
        let sub = index as u64 % 4;
        (4 + sub) << (octave - Self::FLAT)
    }

    fn record(&self, elapsed: Duration) {
        self.buckets[Self::index(elapsed.as_nanos() as u64)].fetch_add(1, Ordering::Relaxed);
    }

    /// The value at `permille`, taken as the midpoint of the bucket it lands in.
    fn quantile(&self, permille: u64) -> u64 {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return 0;
        }
        let wanted = total.saturating_mul(permille).div_ceil(1_000).max(1);
        let mut seen = 0;
        for (index, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= wanted {
                let lower = Self::lower_bound(index);
                let upper = Self::lower_bound(index + 1).max(lower + 1);
                return lower + (upper - lower) / 2;
            }
        }
        Self::lower_bound(Self::BUCKETS - 1)
    }
}

/// Nanoseconds spent in each stage of the durable commit path.
///
/// A commit crosses four hand-offs — request queue, engine lock, flush queue,
/// acknowledgement — and the barrier is only one of them. Summed totals beside
/// the batch and request counts turn a p50 into a budget, which is the only way
/// to tell a slow `fdatasync` apart from scaffolding around it.
///
/// `front` is per request, since each one waits its own time before the batch it
/// joins is closed; every other stage is per batch and shared by everything in
/// it. Adding `front / requests` to the remaining stages divided by `batches`
/// reconstructs the mean server-side latency of one write.
#[derive(Default)]
struct WriteProfile {
    batches: AtomicU64,
    requests: AtomicU64,
    /// Client enqueue until the batch it joined stopped accumulating.
    front: Stage,
    /// Batch closed until the engine write lock is held: the `spawn_blocking`
    /// hop plus contention with readers, checkpoints, and the previous batch.
    lock: Stage,
    /// Inside `write_batch_deferred`: change log, pre-state read, tree apply,
    /// MVCC prepare, WAL encode and append.
    apply: Stage,
    /// Handed to the flush stage until that stage begins this batch's barrier.
    flush_queue: Stage,
    /// The `fdatasync` itself, including its `spawn_blocking` hop.
    sync: Stage,
    /// Durable until answered: reader refresh, change broadcast, response send.
    publish: Stage,
}

impl WriteProfile {
    fn stages(&self) -> [(&'static str, &Stage); 6] {
        [
            ("front", &self.front),
            ("lock", &self.lock),
            ("apply", &self.apply),
            ("flush_queue", &self.flush_queue),
            ("sync", &self.sync),
            ("publish", &self.publish),
        ]
    }

    /// A summed total plus p50 and p99 for each stage.
    ///
    /// Quantiles are over the process lifetime rather than a window, so a caller
    /// comparing two configurations starts a server per configuration. The
    /// totals are monotonic counters and can be differenced as usual.
    fn render(&self) -> String {
        let mut body = String::new();
        for (name, stage) in self.stages() {
            body.push_str(&format!(
                "vyrn_commit_{name}_nanoseconds_total {}\nvyrn_commit_{name}_p50_nanoseconds {}\nvyrn_commit_{name}_p99_nanoseconds {}\n",
                stage.total.load(Ordering::Relaxed),
                stage.latency.quantile(500),
                stage.latency.quantile(990),
            ));
        }
        body
    }
}

/// One stage's summed cost and its distribution.
#[derive(Default)]
struct Stage {
    total: AtomicU64,
    latency: Histogram,
}

impl Stage {
    fn record(&self, elapsed: Duration) {
        self.total
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        self.latency.record(elapsed);
    }
}

struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.0.active_connections.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_waiters();
        }
    }
}

#[derive(Clone)]
struct ChangeEvent {
    sequence: u64,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    /// Durable position of this change, when it was published to the change log.
    cursor: Option<change_log::Cursor>,
}

enum ReadRequest {
    Get {
        key: Vec<u8>,
        response: oneshot::Sender<vyrn_core::Result<Option<Vec<u8>>>>,
    },
    MultiGet {
        keys: Vec<Vec<u8>>,
        response: oneshot::Sender<vyrn_core::Result<Vec<Option<Vec<u8>>>>>,
    },
    Scan {
        start: Option<Vec<u8>>,
        end: Option<Vec<u8>>,
        limit: usize,
        response: oneshot::Sender<vyrn_core::Result<Rows>>,
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
        response: oneshot::Sender<vyrn_core::Result<Message>>,
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

struct WriteWorkerConfig {
    maximum_batch: usize,
    delay: Duration,
    checkpoint_writes: u64,
    readers: Arc<Vec<RwLock<ReadEngine>>>,
    changes: broadcast::Sender<ChangeEvent>,
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
    changes: broadcast::Sender<ChangeEvent>,
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
}

/// An applied batch waiting for its WAL flush before it can be acknowledged.
///
/// The mutations are already in the tree and their WAL record is already written,
/// but neither is durable until `lsn` has been flushed. Handing this to the
/// completion stage lets the write worker start the next batch immediately, so
/// one batch's `fdatasync` overlaps the next batch's tree work.
struct PendingFlush {
    /// `None` when no flush is owed, as in async durability, where records are
    /// buffered for the background sync instead of being written on commit.
    lsn: Option<u64>,
    requests: Vec<WriteRequest>,
    results: Vec<BatchResult>,
    published: Vec<change_log::ChangeRecord>,
    generation: u64,
    root: u64,
    len: u64,
    /// When this batch was handed to the flush stage, so the wait for a barrier
    /// already in flight is charged separately from the barrier itself.
    queued: Instant,
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
    sequence: u64,
    started: tokio::time::Instant,
    read_keys: BTreeMap<Vec<u8>, ()>,
    read_ranges: Vec<ReadRange>,
    index_reads: Vec<(Vec<u8>, Vec<u8>)>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    index_updates: Vec<IndexUpdate>,
}

struct ServerState {
    writes: mpsc::Sender<WriteRequest>,
    username: String,
    password_hash: PasswordHashString,
    database: String,
    auth_limit: Arc<Semaphore>,
    changes: broadcast::Sender<ChangeEvent>,
    read_queues: Vec<std::sync::mpsc::SyncSender<ReadRequest>>,
    next_reader: AtomicU64,
    engine: Arc<RwLock<Engine>>,
    transaction_timeout: Duration,
    metrics: Arc<Metrics>,
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
    if args.allow_plaintext && args.tls_cert_file.is_some() {
        bail!("choose TLS or plaintext; one listener cannot serve both");
    }
    if !args.allow_plaintext && args.tls_cert_file.is_none() {
        bail!("TLS certificate and key are required unless --allow-plaintext is explicit");
    }

    let password_hash = load_password_hash(&args.password_hash_file)?;
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
    let engine = Engine::open_with_options(
        &args.data,
        EngineOptions {
            durability,
            archived_through: archived_through.clone(),
            ..EngineOptions::default()
        },
    )
    .context("failed to open Vyrn data directory")?;
    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    let admin_listener = TcpListener::bind(&args.admin_bind)
        .await
        .with_context(|| format!("failed to bind admin endpoint {}", args.admin_bind))?;
    let metrics = Arc::new(Metrics::default());
    let readers = Arc::new(
        (0..args.read_handles)
            .map(|_| ReadEngine::open(&args.data).map(RwLock::new))
            .collect::<vyrn_core::Result<Vec<_>>>()?,
    );
    // READER_FIX_PLACEHOLDER
    let read_queues = start_read_workers(&readers, args.write_queue_capacity);
    let engine = Arc::new(RwLock::new(engine));
    let (write_sender, write_receiver) = mpsc::channel(args.write_queue_capacity);
    let (change_sender, _) = broadcast::channel(args.write_queue_capacity);
    if args.transaction_timeout_seconds == 0
        || args.mvcc_gc_ms == 0
        || args.mvcc_gc_checkpoint_versions == 0
    {
        bail!("transaction timeout and MVCC GC interval must be greater than zero");
    }
    if durability == DurabilityMode::Async {
        start_async_sync(
            Arc::clone(&engine),
            Duration::from_millis(args.async_sync_ms),
            Arc::clone(&metrics),
        );
    }
    let checkpoint_due = Arc::new(AtomicBool::new(false));
    start_mvcc_gc(
        Arc::clone(&engine),
        Duration::from_millis(args.mvcc_gc_ms),
        args.mvcc_gc_checkpoint_versions,
        Arc::clone(&metrics),
        Arc::clone(&checkpoint_due),
        Arc::clone(&readers),
    );
    // Started only after the engine is open, so the archiver can never see a
    // WAL tail that recovery is still truncating.
    if let (Some(archive_dir), Some(watermark)) = (&args.wal_archive_dir, &archived_through) {
        start_wal_archiver(
            Arc::clone(&engine),
            args.data.join("wal"),
            archive_dir.clone(),
            Arc::clone(watermark),
            Duration::from_millis(args.wal_archive_interval_ms),
            Arc::clone(&metrics),
        );
    }
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
            changes: change_sender.clone(),
            metrics: Arc::clone(&metrics),
            engine: Arc::clone(&engine),
            in_flight: Arc::clone(&in_flight),
            flush_completed: flush_completed.clone(),
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
            readers: Arc::clone(&readers),
            changes: change_sender.clone(),
            metrics: Arc::clone(&metrics),
            checkpoint_due: Arc::clone(&checkpoint_due),
            in_flight,
            flush_completed,
        },
    );
    let state = Arc::new(ServerState {
        writes: write_sender,
        username: args.username,
        password_hash,
        database: args.database,
        auth_limit: Arc::new(Semaphore::new(args.max_auth_jobs)),
        changes: change_sender,
        read_queues,
        next_reader: AtomicU64::new(0),
        engine: Arc::clone(&engine),
        transaction_timeout: Duration::from_secs(args.transaction_timeout_seconds),
        metrics: Arc::clone(&metrics),
    });
    let admin_metrics = Arc::clone(&metrics);
    tokio::spawn(async move { serve_admin(admin_listener, admin_metrics).await });
    metrics.ready.store(true, Ordering::Release);
    let connection_limit = Arc::new(Semaphore::new(args.max_connections));

    println!(
        "vyrnd {} listening on {} ({})",
        env!("CARGO_PKG_VERSION"),
        args.bind,
        if tls_acceptor.is_some() {
            "TLS 1.3"
        } else {
            "PLAINTEXT DEVELOPMENT MODE"
        }
    );

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
                    if let Err(error) = handle_connection(stream, tls_acceptor, state).await {
                        eprintln!("connection {peer} closed: {error}");
                    }
                });
            }
            result = shutdown_signal() => {
                result.context("failed to listen for shutdown signal")?;
                metrics.ready.store(false, Ordering::Release);
                println!("vyrnd draining connections");
                break;
            }
        }
    }

    if metrics.active_connections.load(Ordering::Acquire) != 0 {
        let _ = timeout(
            Duration::from_secs(args.shutdown_timeout_seconds),
            metrics.drained.notified(),
        )
        .await;
    }
    println!("vyrnd shutdown complete");
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
    let mut framed = Framed::new(transport, VyrnCodec::default());
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

    let authenticated = match first.message {
        Message::Authenticate {
            username,
            password,
            database,
        } if password.len() <= 4096 => {
            let permit = Arc::clone(&state.auth_limit).acquire_owned().await?;
            let expected_username = state.username.clone();
            let expected_database = state.database.clone();
            let password_hash = state.password_hash.clone();
            task::spawn_blocking(move || {
                let _permit = permit;
                let verified = Argon2::default()
                    .verify_password(password.as_bytes(), &password_hash.password_hash())
                    .is_ok();
                verified && username == expected_username && database == expected_database
            })
            .await
            .context("authentication worker failed")?
        }
        _ => false,
    };
    if !authenticated {
        send_error(
            &mut framed,
            first.request_id,
            ErrorCode::AuthenticationFailed,
            "authentication failed",
        )
        .await?;
        return Ok(());
    }
    framed
        .send(Envelope::new(first.request_id, Message::Authenticated))
        .await?;
    let mut transaction: Option<ConnectionTransaction> = None;

    let mut connection_error = None;
    loop {
        let request_timeout = transaction
            .as_ref()
            .map_or(CLIENT_IDLE_TIMEOUT, |transaction| {
                state
                    .transaction_timeout
                    .saturating_sub(transaction.started.elapsed())
                    .min(CLIENT_IDLE_TIMEOUT)
            });
        let request = match next_message(&mut framed, request_timeout).await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(error) => {
                connection_error = Some(error);
                break;
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
        let response = match request.message {
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
                    stream_changes(&mut framed, state.changes.subscribe(), prefix).await?;
                    return Ok(());
                }
            }
            Message::SubscribeFrom { prefix, cursor } if transaction.is_none() => {
                if prefix.len() > vyrn_core::MAX_KEY_SIZE {
                    server_error(
                        ErrorCode::InvalidRequest,
                        "subscription prefix is too large",
                    )
                } else {
                    match resolve_cursor(&state, cursor.as_deref()).await {
                        Ok(start) => {
                            framed
                                .send(Envelope::new(request_id, Message::Subscribed))
                                .await?;
                            stream_from_cursor(
                                &mut framed,
                                &state,
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
                match resolve_cursor(&state, cursor.as_deref()).await {
                    Ok(start) => {
                        framed
                            .send(Envelope::new(request_id, Message::CollectionSubscribed))
                            .await?;
                        stream_from_cursor(
                            &mut framed,
                            &state,
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
                        stream_document_changes(
                            &mut framed,
                            state.changes.subscribe(),
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
                match register_transaction_snapshot(&state).await {
                    Ok(sequence) => {
                        transaction = Some(ConnectionTransaction {
                            sequence,
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
                    release_transaction_snapshot(&state, transaction.sequence).await;
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
                release_transaction_snapshot(&state, transaction.sequence).await;
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
                    execute_transaction(&state.engine, transaction, message).await
                } else {
                    execute(Arc::clone(&state), message).await
                }
            }
        };
        framed.send(Envelope::new(request_id, response)).await?;
    }
    if let Some(transaction) = transaction {
        release_transaction_snapshot(&state, transaction.sequence).await;
    }
    match connection_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Registers a transaction's snapshot using only a read lock.
///
/// Beginning a transaction just reads the committed sequence and bumps a
/// refcount, so taking the write lock here would make every transaction queue
/// behind the writer before doing any work.
async fn register_transaction_snapshot(state: &ServerState) -> std::result::Result<u64, String> {
    let engine = Arc::clone(&state.engine);
    task::spawn_blocking(move || {
        let engine = engine.read().map_err(|_| StorageError::Poisoned)?;
        Ok::<_, StorageError>(engine.register_snapshot_shared())
    })
    .await
    .map_err(|_| "snapshot registration task failed".to_owned())?
    .map_err(|error| error.to_string())
}

/// Releases a transaction's snapshot.
///
/// Version collection is deliberately left to the background MVCC task: running
/// a full history sweep here would put an O(retained versions) scan under the
/// write lock on every single commit.
async fn release_transaction_snapshot(state: &ServerState, sequence: u64) {
    let engine = Arc::clone(&state.engine);
    let _ = task::spawn_blocking(move || {
        if let Ok(engine) = engine.read() {
            engine.release_snapshot_shared(sequence);
        }
    })
    .await;
}

async fn stream_changes(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    mut receiver: broadcast::Receiver<ChangeEvent>,
    prefix: Vec<u8>,
) -> Result<()> {
    loop {
        match receiver.recv().await {
            Ok(change) if change.key.starts_with(&prefix) => {
                framed
                    .send(Envelope::new(
                        0,
                        Message::Change {
                            sequence: change.sequence,
                            key: change.key,
                            value: change.value,
                        },
                    ))
                    .await?;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => {
                send_error(
                    framed,
                    0,
                    ErrorCode::Storage,
                    "subscription lagged; reconnect and resynchronize",
                )
                .await?;
                return Ok(());
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

async fn stream_document_changes(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    mut receiver: broadcast::Receiver<ChangeEvent>,
    collection: &str,
    prefix: Vec<u8>,
) -> Result<()> {
    loop {
        match receiver.recv().await {
            Ok(change) if change.key.starts_with(&prefix) => {
                let Ok(id) = vyrn_core::document::document_id_from_key(collection, &change.key)
                else {
                    continue;
                };
                framed
                    .send(Envelope::new(
                        0,
                        Message::DocumentChange {
                            sequence: change.sequence,
                            id,
                            document: change.value,
                        },
                    ))
                    .await?;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => {
                send_error(
                    framed,
                    0,
                    ErrorCode::Storage,
                    "subscription lagged; reconnect and resynchronize",
                )
                .await?;
                return Ok(());
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

enum CursorStream {
    Keys { prefix: Vec<u8> },
    Collection { collection: String },
}

/// Resolves a client cursor token into a starting position.
///
/// `None` means "live changes only" and resolves to the newest cursor, so a
/// fresh subscriber does not replay history it never asked for.
async fn resolve_cursor(
    state: &ServerState,
    cursor: Option<&str>,
) -> vyrn_core::Result<change_log::Cursor> {
    match cursor {
        Some("") => Ok(change_log::Cursor::start()),
        Some(token) => change_log::Cursor::parse_token(token),
        None => {
            let engine = Arc::clone(&state.engine);
            task::spawn_blocking(move || {
                engine
                    .read()
                    .map_err(|_| StorageError::Poisoned)?
                    .latest_cursor()
            })
            .await
            .map_err(|_| StorageError::Poisoned)?
        }
    }
}

/// Streams the durable backlog from `start`, then live changes, without gaps.
///
/// The live broadcast is subscribed to before the backlog is read, so changes
/// committed during replay are buffered instead of lost. Records already
/// replayed are then dropped by cursor, so nothing is delivered twice.
async fn stream_from_cursor(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    state: &ServerState,
    start: change_log::Cursor,
    stream: CursorStream,
) -> Result<()> {
    let mut live = state.changes.subscribe();
    let mut cursor = start;

    loop {
        let engine = Arc::clone(&state.engine);
        let from = cursor;
        let batch = task::spawn_blocking(move || {
            engine
                .read()
                .map_err(|_| StorageError::Poisoned)?
                .read_changes(from, CHANGE_REPLAY_BATCH)
        })
        .await;
        let batch = match batch {
            Ok(Ok(batch)) => batch,
            Ok(Err(error)) => {
                send_error(framed, 0, cursor_error_code(&error), &error.to_string()).await?;
                return Ok(());
            }
            Err(_) => {
                send_error(framed, 0, ErrorCode::Storage, "change log read failed").await?;
                return Ok(());
            }
        };
        if batch.is_empty() {
            break;
        }
        for record in &batch {
            if let Some(message) = cursor_message(&stream, record) {
                framed.send(Envelope::new(0, message)).await?;
            }
        }
        cursor = batch.last().unwrap().cursor();
    }
    framed
        .send(Envelope::new(
            0,
            Message::Caught {
                cursor: cursor.to_token(),
            },
        ))
        .await?;

    loop {
        match live.recv().await {
            Ok(change) => {
                // Skip anything the backlog replay already delivered.
                if change.cursor.is_some_and(|position| position <= cursor) {
                    continue;
                }
                if let Some(position) = change.cursor {
                    cursor = position;
                }
                let record = change_log::ChangeRecord {
                    sequence: change.sequence,
                    index: change.cursor.map_or(0, |position| position.index),
                    document: vyrn_core::document::change_target(&change.key),
                    key: change.key,
                    value: change.value,
                };
                if let Some(message) = cursor_message(&stream, &record) {
                    framed.send(Envelope::new(0, message)).await?;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // The durable log still holds these changes, so resume from the
                // last delivered cursor instead of dropping the subscription.
                send_error(
                    framed,
                    0,
                    ErrorCode::Storage,
                    &format!(
                        "subscription lagged; resume from cursor {}",
                        cursor.to_token()
                    ),
                )
                .await?;
                return Ok(());
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

fn cursor_message(stream: &CursorStream, record: &change_log::ChangeRecord) -> Option<Message> {
    match stream {
        CursorStream::Keys { prefix } => {
            // Document keys are internal encodings; they belong to collection
            // subscriptions, not raw key-prefix subscriptions.
            if record.document.is_some() || !record.key.starts_with(prefix) {
                return None;
            }
            Some(Message::CursorChange {
                cursor: record.cursor().to_token(),
                key: record.key.clone(),
                value: record.value.clone(),
            })
        }
        CursorStream::Collection { collection } => {
            let target = record.document.as_ref()?;
            if &target.collection != collection {
                return None;
            }
            Some(Message::CursorDocumentChange {
                cursor: record.cursor().to_token(),
                collection: target.collection.clone(),
                id: target.id.clone(),
                document: record.value.clone(),
            })
        }
    }
}

fn cursor_error_code(error: &StorageError) -> ErrorCode {
    match error {
        StorageError::CursorTooOld { .. } | StorageError::InvalidCursor(_) => {
            ErrorCode::InvalidRequest
        }
        _ => ErrorCode::Storage,
    }
}

async fn execute(state: Arc<ServerState>, request: Message) -> Message {
    state.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
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

fn start_read_workers(
    readers: &Arc<Vec<RwLock<ReadEngine>>>,
    capacity: usize,
) -> Vec<std::sync::mpsc::SyncSender<ReadRequest>> {
    readers
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
            let readers = Arc::clone(readers);
            thread::Builder::new()
                .name(format!("vyrn-reader-{index}"))
                .spawn(move || {
                    while let Ok(request) = receiver.recv() {
                        let reader = match readers[index].read() {
                            Ok(reader) => reader,
                            Err(_) => break,
                        };
                        match request {
                            ReadRequest::Get { key, response } => {
                                let _ = response.send(reader.get(&key));
                            }
                            ReadRequest::MultiGet { keys, response } => {
                                let result = keys.into_iter().map(|key| reader.get(&key)).collect();
                                let _ = response.send(result);
                            }
                            ReadRequest::Scan {
                                start,
                                end,
                                limit,
                                response,
                            } => {
                                let _ = response.send(reader.scan(
                                    start.as_deref(),
                                    end.as_deref(),
                                    limit,
                                ));
                            }
                            ReadRequest::IndexLookup {
                                index,
                                value,
                                limit,
                                response,
                            } => {
                                let _ = response.send(reader.lookup_index(&index, &value, limit));
                            }
                            ReadRequest::Document { request, response } => {
                                let _ = response.send(read_document(&reader, request));
                            }
                        }
                    }
                })
                .expect("failed to start storage reader");
            sender
        })
        .collect()
}

async fn submit_get(state: &ServerState, key: Vec<u8>) -> Message {
    let (response, receiver) = oneshot::channel();
    let index =
        state.next_reader.fetch_add(1, Ordering::Relaxed) as usize % state.read_queues.len();
    if state.read_queues[index]
        .try_send(ReadRequest::Get { key, response })
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage reader queue is full");
    }
    match receiver.await {
        Ok(Ok(value)) => Message::Value { value },
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn submit_multi_get(state: &ServerState, keys: Vec<Vec<u8>>) -> Message {
    let (response, receiver) = oneshot::channel();
    let index =
        state.next_reader.fetch_add(1, Ordering::Relaxed) as usize % state.read_queues.len();
    if state.read_queues[index]
        .try_send(ReadRequest::MultiGet { keys, response })
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage reader queue is full");
    }
    match receiver.await {
        Ok(Ok(values)) => Message::Values { values },
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn submit_scan(
    state: &ServerState,
    start: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
    limit: usize,
) -> Message {
    let (response, receiver) = oneshot::channel();
    let index =
        state.next_reader.fetch_add(1, Ordering::Relaxed) as usize % state.read_queues.len();
    if state.read_queues[index]
        .try_send(ReadRequest::Scan {
            start,
            end,
            limit,
            response,
        })
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage reader queue is full");
    }
    match receiver.await {
        Ok(Ok(rows)) => Message::Rows { rows },
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

/// Dispatches to a reader thread, round-robin across the read handles.
fn next_reader(state: &ServerState) -> usize {
    state.next_reader.fetch_add(1, Ordering::Relaxed) as usize % state.read_queues.len()
}

fn read_document(reader: &ReadEngine, request: DocumentRead) -> vyrn_core::Result<Message> {
    match request {
        DocumentRead::Get { collection, id } => Ok(Message::DocumentValue {
            document: reader
                .get_document(&collection, &id)?
                .map(|document| encode_document(&document.value))
                .transpose()?,
        }),
        DocumentRead::List { collection, limit } => {
            encode_documents(reader.list_documents(&collection, limit)?)
        }
        DocumentRead::Query {
            collection,
            field,
            value,
            limit,
        } => encode_documents(reader.find_documents(&collection, &field, &value, limit)?),
    }
}

async fn submit_document_read(state: &ServerState, request: DocumentRead) -> Message {
    let (response, receiver) = oneshot::channel();
    if state.read_queues[next_reader(state)]
        .try_send(ReadRequest::Document { request, response })
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage reader queue is full");
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
    let (response, receiver) = oneshot::channel();
    if state.read_queues[next_reader(state)]
        .try_send(ReadRequest::IndexLookup {
            index,
            value,
            limit,
            response,
        })
        .is_err()
    {
        return server_error(ErrorCode::Storage, "storage reader queue is full");
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
    let (sender, receiver) = oneshot::channel();
    if state
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
    let (sender, receiver) = oneshot::channel();
    if state
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
    let (sender, receiver) = oneshot::channel();
    if state
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
        Ok(Ok(message)) => message,
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage writer stopped"),
    }
}

async fn submit_write(state: &Arc<ServerState>, operation: BatchOperation) -> Message {
    let (sender, receiver) = oneshot::channel();
    if state
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

async fn execute_transaction(
    engine: &Arc<RwLock<Engine>>,
    transaction: &mut ConnectionTransaction,
    request: Message,
) -> Message {
    match request {
        Message::Get { key } => {
            transaction.read_keys.insert(key.clone(), ());
            if let Some(value) = transaction.writes.get(&key) {
                return Message::Value {
                    value: value.clone(),
                };
            }
            let revision = transaction.sequence;
            execute_engine_shared(engine, move |engine| {
                Ok(Message::Value {
                    value: engine.get_at(&key, revision)?,
                })
            })
            .await
        }
        Message::Put { key, value } => {
            transaction.writes.insert(key, Some(value));
            Message::Written
        }
        Message::Delete { key } => {
            let existed = if let Some(value) = transaction.writes.get(&key) {
                value.is_some()
            } else {
                let revision = transaction.sequence;
                let lookup_key = key.clone();
                match execute_engine_shared(engine, move |engine| {
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
            let revision = transaction.sequence;
            let fetch_limit = limit as usize + transaction.index_updates.len();
            let lookup_index = index.clone();
            let lookup_value = value.clone();
            let keys = match execute_engine_shared(engine, move |engine| {
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
            let revision = transaction.sequence;
            let fetch_limit = limit as usize + transaction.writes.len();
            let scan_start = start.clone();
            let scan_end = end.clone();
            let rows = match execute_engine_shared(engine, move |engine| {
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
    let snapshot_sequence = transaction.sequence;
    if transaction.writes.is_empty() && transaction.index_updates.is_empty() {
        release_transaction_snapshot(state, snapshot_sequence).await;
        return Message::Committed;
    }
    let operations = transaction
        .writes
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => BatchOperation::Put(key, value),
            None => BatchOperation::Delete(key),
        })
        .collect();
    let (sender, receiver) = oneshot::channel();
    if state
        .writes
        .send(WriteRequest::Transaction {
            snapshot_sequence: transaction.sequence,
            read_keys: transaction.read_keys.into_keys().collect(),
            read_ranges: transaction.read_ranges,
            index_reads: transaction.index_reads,
            operations,
            index_updates: transaction.index_updates,
            response: sender,
            queued: Instant::now(),
        })
        .await
        .is_err()
    {
        release_transaction_snapshot(state, snapshot_sequence).await;
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
    release_transaction_snapshot(state, snapshot_sequence).await;
    response
}

fn start_mvcc_gc(
    engine: Arc<RwLock<Engine>>,
    interval: Duration,
    checkpoint_versions: usize,
    metrics: Arc<Metrics>,
    checkpoint_due: Arc<AtomicBool>,
    readers: Arc<Vec<RwLock<ReadEngine>>>,
) {
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            let engine_for_refresh = Arc::clone(&engine);
            let engine = Arc::clone(&engine);
            // Take the pending flag before compacting so writes that arrive
            // during the checkpoint schedule the next one instead of being lost.
            let due = checkpoint_due.swap(false, Ordering::AcqRel);
            let result = task::spawn_blocking(move || {
                engine
                    .write()
                    .map_err(|_| StorageError::Poisoned)
                    .and_then(|mut engine| {
                        let collected = engine.collect_versions();
                        if due || collected >= checkpoint_versions {
                            engine.checkpoint()?;
                        }
                        Ok(collected)
                    })
            })
            .await;
            // Republish the compacted generation to the read handles; otherwise
            // they keep serving the old generation's pages.
            if matches!(result, Ok(Ok(_))) && due {
                let engine = Arc::clone(&engine_for_refresh);
                let readers = Arc::clone(&readers);
                let refreshed = task::spawn_blocking(move || {
                    // The engine read lock is held across the reader refreshes
                    // so the next checkpoint cannot retire this generation and
                    // delete its files mid-loop; every path opened here still
                    // exists until the loop finishes.
                    let engine = engine.read().map_err(|_| StorageError::Poisoned)?;
                    let (new_generation, root, len) = engine.committed_root();
                    for reader in readers.iter() {
                        reader
                            .write()
                            .map_err(|_| StorageError::Poisoned)?
                            .refresh(new_generation, root, len)?;
                    }
                    Ok::<_, StorageError>(())
                })
                .await;
                if !matches!(refreshed, Ok(Ok(()))) {
                    metrics.storage_failed.store(true, Ordering::Release);
                    metrics.ready.store(false, Ordering::Release);
                    return;
                }
            }
            if let Ok(Ok(collected)) = result {
                metrics.mvcc_gc_runs.fetch_add(1, Ordering::Relaxed);
                metrics
                    .mvcc_versions_collected
                    .fetch_add(collected as u64, Ordering::Relaxed);
            } else {
                metrics.storage_failed.store(true, Ordering::Release);
                metrics.ready.store(false, Ordering::Release);
                return;
            }
        }
    });
}

/// Rotates the active WAL segment on a timer and copies sealed segments into
/// the archive directory, publishing the watermark checkpoints consult before
/// deleting a segment.
///
/// A rotation failure is a storage error and poisons the server like the GC
/// task's failure path. A copy failure only counts and logs: archiving must
/// never block or kill writes, and the retention barrier already guarantees
/// the uncopied segment survives until a later tick succeeds.
fn start_wal_archiver(
    engine: Arc<RwLock<Engine>>,
    wal_directory: PathBuf,
    archive_directory: PathBuf,
    watermark: Arc<AtomicU64>,
    interval: Duration,
    metrics: Arc<Metrics>,
) {
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            // Seal the active segment so the loss window is bounded by time,
            // not just by the segment size trigger.
            let rotate_engine = Arc::clone(&engine);
            let rotated = task::spawn_blocking(move || {
                rotate_engine
                    .write()
                    .map_err(|_| StorageError::Poisoned)?
                    .rotate_for_archive()
            })
            .await;
            if !matches!(rotated, Ok(Ok(()))) {
                metrics.storage_failed.store(true, Ordering::Release);
                metrics.ready.store(false, Ordering::Release);
                return;
            }
            // Copied without the engine lock: sealed segments are immutable,
            // and a segment deleted mid-copy is only ever an already-archived
            // one, which archive_pending tolerates.
            let wal = wal_directory.clone();
            let archive = archive_directory.clone();
            let result = task::spawn_blocking(move || {
                let through = vyrn_core::wal_archive::archive_pending(&wal, &archive)?;
                Ok::<_, StorageError>((through, wal_archive_lag(&wal, through)))
            })
            .await;
            match result {
                Ok(Ok((through, lag))) => {
                    // AcqRel: the Release half publishes the watermark to the
                    // checkpoint's Acquire load only after the copies are
                    // durable; the returned previous value turns the dense
                    // segment ids into a newly-archived count. After a restart
                    // the first tick also counts segments archived by earlier
                    // runs, which only front-loads a monotonic counter.
                    let previous = watermark.swap(through, Ordering::AcqRel);
                    metrics
                        .wal_archived_total
                        .fetch_add(through.saturating_sub(previous), Ordering::Relaxed);
                    metrics
                        .wal_archive_lag_segments
                        .store(lag, Ordering::Relaxed);
                }
                other => {
                    metrics
                        .wal_archive_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    if let Ok(Err(error)) = other {
                        eprintln!("wal archive tick failed: {error}");
                    }
                }
            }
        }
    });
}

/// Sealed-but-unarchived segment count: WAL files with an id above the
/// watermark, minus the one active segment. Approximate by design — the write
/// path may rotate concurrently — but a growing value still means the
/// archiver is falling behind.
fn wal_archive_lag(wal_directory: &Path, archived_through: u64) -> u64 {
    let Ok(entries) = std::fs::read_dir(wal_directory) else {
        return 0;
    };
    let pending = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name();
            let id = name.to_str()?.strip_suffix(".vwal")?.parse::<u64>().ok()?;
            (id > archived_through).then_some(id)
        })
        .count() as u64;
    pending.saturating_sub(1)
}

fn start_async_sync(engine: Arc<RwLock<Engine>>, interval: Duration, metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            let engine = Arc::clone(&engine);
            let result = task::spawn_blocking(move || {
                engine.write().map_err(|_| StorageError::Poisoned)?.sync()
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                metrics.storage_failed.store(true, Ordering::Release);
                metrics.ready.store(false, Ordering::Release);
                return;
            }
        }
    });
}

fn start_write_worker(
    engine: Arc<RwLock<Engine>>,
    mut receiver: mpsc::Receiver<WriteRequest>,
    flushes: mpsc::Sender<PendingFlush>,
    config: WriteWorkerConfig,
) {
    tokio::spawn(async move {
        let mut writes_since_checkpoint = 0_u64;
        let mut pending = None;
        loop {
            let first = match pending.take() {
                Some(request) => request,
                None => match receiver.recv().await {
                    Some(request) => request,
                    None => break,
                },
            };
            let mut requests = vec![first];
            if matches!(requests.first(), Some(WriteRequest::Document { .. })) {
                let Some(WriteRequest::Document { request, response }) = requests.pop() else {
                    unreachable!()
                };
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    let outcome = apply_document_write(&mut engine, request);
                    let published = engine.last_published().to_vec();
                    let (generation, root, len) = engine.committed_root();
                    Ok::<_, StorageError>((outcome, published, generation, root, len))
                })
                .await;
                match result {
                    Ok(Ok((outcome, published, generation, root, len))) => {
                        if let Err(error) = &outcome {
                            record_storage_error(&config.metrics, error);
                        }
                        let mut reader_failed = false;
                        for reader in config.readers.iter() {
                            match reader.write() {
                                Ok(mut reader) => {
                                    if let Err(error) = reader.refresh(generation, root, len) {
                                        record_storage_error(&config.metrics, &error);
                                        reader_failed = true;
                                    }
                                }
                                Err(_) => {
                                    config.metrics.storage_failed.store(true, Ordering::Release);
                                    config.metrics.ready.store(false, Ordering::Release);
                                    reader_failed = true;
                                }
                            }
                        }
                        for record in published {
                            let _ = config.changes.send(ChangeEvent {
                                sequence: record.sequence,
                                key: record.key,
                                value: record.value,
                                cursor: Some(change_log::Cursor::new(
                                    record.sequence,
                                    record.index,
                                )),
                            });
                        }
                        let _ = response.send(match outcome {
                            Ok((message, _)) if !reader_failed => Ok(message),
                            Ok(_) => Err(StorageError::Poisoned),
                            Err(error) => Err(error),
                        });
                    }
                    Ok(Err(error)) => {
                        record_storage_error(&config.metrics, &error);
                        let _ = response.send(Err(error));
                    }
                    Err(_) => {
                        config.metrics.storage_failed.store(true, Ordering::Release);
                        config.metrics.ready.store(false, Ordering::Release);
                        let _ = response.send(Err(StorageError::Poisoned));
                    }
                }
                continue;
            }
            if matches!(
                requests.first(),
                Some(WriteRequest::CreateIndex { .. } | WriteRequest::DropIndex { .. })
            ) {
                let request = requests.pop().unwrap();
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    match request {
                        WriteRequest::CreateIndex {
                            name,
                            unique,
                            response,
                        } => {
                            let result = engine.create_index(name, unique);
                            Ok::<_, StorageError>((response, result))
                        }
                        WriteRequest::DropIndex { name, response } => {
                            let result = engine.drop_index(&name);
                            Ok((response, result))
                        }
                        _ => unreachable!(),
                    }
                })
                .await;
                match result {
                    Ok(Ok((response, result))) => {
                        let _ = response.send(result);
                    }
                    Ok(Err(error)) => record_storage_error(&config.metrics, &error),
                    Err(_) => {
                        config.metrics.storage_failed.store(true, Ordering::Release);
                        config.metrics.ready.store(false, Ordering::Release);
                    }
                }
                continue;
            }
            // Group-commit: collect more single writes or transactions so one
            // page/WAL flush covers many clients. Each transaction is still
            // validated against its own snapshot below, so batching does not
            // weaken serializability.
            if matches!(
                requests.first(),
                Some(WriteRequest::Operation { .. } | WriteRequest::Transaction { .. })
            ) {
                // Take everything already queued first. Under load the queue is
                // rarely empty, and sleeping in that case only adds latency to a
                // batch that was already worth committing.
                drain_writes(
                    &mut receiver,
                    &mut requests,
                    &mut pending,
                    config.maximum_batch,
                );
                // Then keep accumulating for as long as a barrier is already in
                // flight. Those clients cannot be answered until that flush
                // finishes regardless, so the wait is free, and it is self-tuning:
                // on slow storage the flush is long and batches grow, on fast
                // storage it returns immediately and latency stays low.
                //
                // Without this, the pipeline's own success works against it. When
                // the flush blocked the write worker, arriving requests piled up
                // behind it and were swept into one batch; now that it does not
                // block, each small batch would take its own barrier.
                if requests.len() < config.maximum_batch {
                    let mut completed = config.flush_completed.subscribe();
                    // A hard ceiling, so a permanently busy flush stage cannot
                    // hold a batch open indefinitely.
                    let deadline = tokio::time::Instant::now() + config.delay;
                    while requests.len() < config.maximum_batch
                        && config.in_flight.load(Ordering::Acquire) > 0
                    {
                        let timeout = tokio::time::sleep_until(deadline);
                        tokio::select! {
                            biased;
                            received = receiver.recv() => match received {
                                Some(
                                    request @ (WriteRequest::Operation { .. }
                                    | WriteRequest::Transaction { .. }),
                                ) => requests.push(request),
                                Some(request) => {
                                    pending = Some(request);
                                    break;
                                }
                                None => break,
                            },
                            // The barrier this batch was waiting behind has landed,
                            // so stop accumulating and commit what is here.
                            _ = completed.changed() => break,
                            _ = timeout => break,
                        }
                    }
                }
            }
            // Validate every batched transaction against its own snapshot, and
            // also against the writes of earlier transactions in this same batch
            // so grouping cannot let two conflicting commits through together.
            if requests
                .iter()
                .any(|request| matches!(request, WriteRequest::Transaction { .. }))
            {
                let checks: Vec<_> = requests
                    .iter()
                    .enumerate()
                    .filter_map(|(index, request)| match request {
                        WriteRequest::Transaction {
                            snapshot_sequence,
                            read_keys,
                            read_ranges,
                            index_reads,
                            operations,
                            index_updates,
                            ..
                        } => Some(TransactionCheck {
                            index,
                            snapshot_sequence: *snapshot_sequence,
                            read_keys: read_keys.clone(),
                            read_ranges: read_ranges.clone(),
                            index_reads: index_reads.clone(),
                            operations: operations.clone(),
                            index_updates: index_updates.clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                let conflict_engine = Arc::clone(&engine);
                let verdict = task::spawn_blocking(move || {
                    let engine = conflict_engine.read().map_err(|_| StorageError::Poisoned)?;
                    let mut rejected = Vec::new();
                    // A hash set rather than a list: scanning every earlier write
                    // for each read key made validation quadratic in batch size,
                    // which capped transaction throughput as queue depth grew.
                    let mut committed_keys: HashSet<Vec<u8>> = HashSet::new();
                    for check in &checks {
                        let overlaps_batch = check
                            .read_keys
                            .iter()
                            .any(|key| committed_keys.contains(key));
                        if overlaps_batch
                            || has_conflict(
                                &engine,
                                check.snapshot_sequence,
                                &check.read_keys,
                                &check.read_ranges,
                                &check.index_reads,
                                &check.operations,
                                &check.index_updates,
                            )?
                        {
                            rejected.push(check.index);
                        } else {
                            committed_keys.extend(
                                check.operations.iter().map(|op| operation_key(op).to_vec()),
                            );
                        }
                    }
                    Ok::<_, StorageError>(rejected)
                })
                .await;
                match verdict {
                    Ok(Ok(rejected)) if !rejected.is_empty() => {
                        // Answer the conflicted transactions now and re-queue the
                        // rest of the batch for this same loop iteration.
                        let mut survivors = Vec::with_capacity(requests.len());
                        let mut conflicted = Vec::with_capacity(rejected.len());
                        for (index, request) in requests.into_iter().enumerate() {
                            if rejected.contains(&index) {
                                conflicted.push(request);
                            } else {
                                survivors.push(request);
                            }
                        }
                        respond_writes(conflicted, Err(StorageError::Conflict.to_string()));
                        requests = survivors;
                        if requests.is_empty() {
                            continue;
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => {
                        record_storage_error(&config.metrics, &error);
                        respond_writes(requests, Err(error.to_string()));
                        continue;
                    }
                    Err(_) => {
                        config.metrics.storage_failed.store(true, Ordering::Release);
                        config.metrics.ready.store(false, Ordering::Release);
                        respond_writes(requests, Err("conflict check task failed".into()));
                        continue;
                    }
                }
            }
            // Everything up to here — queue wait, accumulation, and any conflict
            // validation — is time a client spent before its batch could start
            // work, so it is charged per request rather than per batch.
            let batch_closed = Instant::now();
            {
                let profile = &config.metrics.write_profile;
                for queued in requests.iter().filter_map(WriteRequest::queued) {
                    profile
                        .front
                        .record(batch_closed.saturating_duration_since(queued));
                    profile.requests.fetch_add(1, Ordering::Relaxed);
                }
            }
            let operations: Vec<_> = requests
                .iter()
                .flat_map(|request| match request {
                    WriteRequest::Operation { operation, .. } => vec![operation.clone()],
                    WriteRequest::Transaction { operations, .. } => operations.clone(),
                    WriteRequest::Document { .. }
                    | WriteRequest::CreateIndex { .. }
                    | WriteRequest::DropIndex { .. } => {
                        unreachable!()
                    }
                })
                .collect();
            let index_updates: Vec<_> = requests
                .iter()
                .flat_map(|request| match request {
                    WriteRequest::Transaction { index_updates, .. } => index_updates.clone(),
                    _ => Vec::new(),
                })
                .collect();
            let operation_count = operations.len() as u64;
            config.metrics.write_batches.fetch_add(1, Ordering::Relaxed);
            config
                .metrics
                .batched_writes
                .fetch_add(operation_count, Ordering::Relaxed);
            // Checkpoint compaction rewrites the whole tree, so it is handed to
            // the background task rather than run inline. Otherwise the client
            // whose commit happened to cross the threshold pays for compacting
            // everyone else's writes, which is what produced the write-path p95
            // spikes.
            let should_checkpoint =
                writes_since_checkpoint + operation_count >= config.checkpoint_writes;
            if should_checkpoint {
                config.checkpoint_due.store(true, Ordering::Release);
            }
            // Moved rather than cloned: a 128-key batch of 128-byte values copied
            // every key and value twice on the way to the engine.
            let commit_operations = operations;
            let commit_index_updates = index_updates;
            let apply_engine = Arc::clone(&engine);
            // Apply the batch and write its WAL record, but do not flush here.
            // The flush is the most expensive part of a commit, and holding the
            // write lock across it would stop the next batch from doing any work
            // until this one is durable.
            let result = task::spawn_blocking(move || {
                let mut engine = apply_engine.write().map_err(|_| StorageError::Poisoned)?;
                let locked = Instant::now();
                let (results, lsn) = if commit_index_updates.is_empty() {
                    engine.write_batch_deferred(commit_operations)?
                } else {
                    engine.write_indexed_deferred(commit_operations, commit_index_updates)?
                };
                // The engine records what it published, so no change-log scan is
                // needed on the commit path.
                let published = engine.last_published().to_vec();
                let (generation, root, len) = engine.committed_root();
                Ok::<_, StorageError>((
                    PendingFlush {
                        lsn,
                        requests: Vec::new(),
                        results,
                        published,
                        generation,
                        root,
                        len,
                        queued: locked,
                    },
                    locked,
                ))
            })
            .await;
            match result {
                Ok(Ok((mut flush, locked))) => {
                    let applied = Instant::now();
                    let profile = &config.metrics.write_profile;
                    profile.batches.fetch_add(1, Ordering::Relaxed);
                    profile
                        .lock
                        .record(locked.saturating_duration_since(batch_closed));
                    profile
                        .apply
                        .record(applied.saturating_duration_since(locked));
                    flush.queued = applied;
                    flush.requests = requests;
                    writes_since_checkpoint = if should_checkpoint {
                        config.metrics.checkpoints.fetch_add(1, Ordering::Relaxed);
                        0
                    } else {
                        writes_since_checkpoint + operation_count
                    };
                    // Counted before queueing so the next iteration sees that a
                    // barrier is outstanding and accumulates behind it.
                    config.in_flight.fetch_add(1, Ordering::AcqRel);
                    // Queued rather than awaited: the completion stage flushes and
                    // acknowledges in arrival order while this loop moves on to the
                    // next batch, so the barrier is amortised across committers.
                    if flushes.send(flush).await.is_err() {
                        config.in_flight.fetch_sub(1, Ordering::AcqRel);
                        return;
                    }
                }
                Ok(Err(error)) => {
                    record_storage_error(&config.metrics, &error);
                    respond_writes(requests, Err(error.to_string()));
                }
                Err(_) => {
                    config.metrics.storage_failed.store(true, Ordering::Release);
                    config.metrics.ready.store(false, Ordering::Release);
                    respond_writes(requests, Err("storage writer task failed".into()));
                }
            }
        }
    });
}

/// Moves every already-queued data write into `requests` without waiting.
///
/// A non-data request ends the batch and is parked in `pending` for the next loop
/// iteration, since index and document writes take the engine lock on their own.
fn drain_writes(
    receiver: &mut mpsc::Receiver<WriteRequest>,
    requests: &mut Vec<WriteRequest>,
    pending: &mut Option<WriteRequest>,
    maximum: usize,
) {
    while requests.len() < maximum {
        match receiver.try_recv() {
            Ok(request @ (WriteRequest::Operation { .. } | WriteRequest::Transaction { .. })) => {
                requests.push(request)
            }
            Ok(request) => {
                *pending = Some(request);
                break;
            }
            Err(_) => break,
        }
    }
}

/// Flushes applied batches and acknowledges them, in order.
///
/// Runs as its own stage so the write worker never waits on `fdatasync`. Batches
/// are handled strictly in arrival order, and a flush covers every record written
/// before it began, so a batch queued while an earlier flush was running is often
/// already durable by the time it is examined — several commits then share one
/// barrier. Nothing is acknowledged, and no reader is refreshed, before the
/// record behind it is durable.
fn start_flush_worker(
    wal: Arc<vyrn_core::Wal>,
    mut flushes: mpsc::Receiver<PendingFlush>,
    config: FlushWorkerConfig,
) {
    tokio::spawn(async move {
        while let Some(first) = flushes.recv().await {
            // Take every batch already waiting, so one barrier covers all of them.
            // This is where group commit actually happens now: the write worker no
            // longer blocks on the flush, so without coalescing here each batch
            // would pay its own `fdatasync` and the barrier count would rise.
            let mut batch = vec![first];
            while let Ok(next) = flushes.try_recv() {
                batch.push(next);
            }
            // Every batch here waited from its own hand-off until this point, and
            // from here they all wait on the same barrier.
            let barrier_started = Instant::now();
            for flush in batch.iter() {
                config
                    .metrics
                    .write_profile
                    .flush_queue
                    .record(barrier_started.saturating_duration_since(flush.queued));
            }
            config.metrics.wal_flushes.fetch_add(1, Ordering::Relaxed);
            config
                .metrics
                .flushed_batches
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            // One flush through the highest LSN makes every batch here durable,
            // because all of their records were appended before this call.
            if let Some(lsn) = batch.iter().filter_map(|flush| flush.lsn).max() {
                let wal_handle = Arc::clone(&wal);
                let synced = task::spawn_blocking(move || wal_handle.sync_through(lsn)).await;
                let error = match synced {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => {
                        record_storage_error(&config.metrics, &error);
                        Some(error.to_string())
                    }
                    Err(_) => {
                        config.metrics.storage_failed.store(true, Ordering::Release);
                        config.metrics.ready.store(false, Ordering::Release);
                        Some("WAL flush task failed".into())
                    }
                };
                if let Some(message) = error {
                    let covered = batch.len() as u64;
                    for flush in batch {
                        respond_writes(flush.requests, Err(message.clone()));
                    }
                    // Release these before looping, or the write worker would keep
                    // accumulating behind a barrier that has already failed.
                    config.in_flight.fetch_sub(covered, Ordering::AcqRel);
                    config
                        .flush_completed
                        .send_modify(|generation| *generation += 1);
                    continue;
                }
            }
            // Charged to every batch in the group, not once: each of them waited
            // the whole barrier before it could be answered.
            let durable = Instant::now();
            {
                let sync = durable.saturating_duration_since(barrier_started);
                for _ in 0..batch.len() {
                    config.metrics.write_profile.sync.record(sync);
                }
            }
            let covered = batch.len() as u64;
            let mut stop = false;
            for flush in batch {
                let PendingFlush {
                    requests,
                    results,
                    published,
                    generation,
                    root,
                    len,
                    ..
                } = flush;
                if !publish_commit(&config, requests, results, published, generation, root, len) {
                    stop = true;
                    break;
                }
                // Measured from the barrier rather than from the previous batch,
                // so a batch waiting its turn behind earlier ones in the same
                // group carries that wait.
                config
                    .metrics
                    .write_profile
                    .publish
                    .record(Instant::now().saturating_duration_since(durable));
            }
            // Release the writer before returning, so a failure here cannot leave
            // it accumulating behind a barrier that will never land.
            config.in_flight.fetch_sub(covered, Ordering::AcqRel);
            config
                .flush_completed
                .send_modify(|generation| *generation += 1);
            if stop {
                return;
            }
        }
    });
}

/// Refreshes the read handles, broadcasts the commit, and answers its clients.
///
/// Returns false when storage has failed and the flush stage must stop.
fn publish_commit(
    config: &FlushWorkerConfig,
    requests: Vec<WriteRequest>,
    results: Vec<BatchResult>,
    published: Vec<change_log::ChangeRecord>,
    generation: u64,
    root: u64,
    len: u64,
) -> bool {
    // Only now is the batch durable, so only now may readers publish it.
    //
    // A checkpoint may have compacted the tree while this batch was being
    // flushed, retiring the generation the batch recorded and deleting its
    // page files. `ReadEngine::refresh` ignores a generation older than the
    // one a reader already serves, checked under that reader's own write lock
    // — a single load of a shared atomic before this loop left a window in
    // which the checkpoint task moved a reader forward mid-loop and the stale
    // refresh here reopened the deleted files, failing every write from then
    // on. The checkpoint task republishes the compacted generation itself.
    let mut refresh_error = None;
    for reader in config.readers.iter() {
        match reader.write() {
            Ok(mut reader) => {
                if let Err(error) = reader.refresh(generation, root, len) {
                    refresh_error = Some(error);
                    break;
                }
            }
            Err(_) => {
                config.metrics.storage_failed.store(true, Ordering::Release);
                config.metrics.ready.store(false, Ordering::Release);
                respond_writes(requests, Err("storage reader lock poisoned".into()));
                return false;
            }
        }
    }
    if let Some(error) = refresh_error {
        // A refresh can still lose the race in the other direction: the
        // batch's generation was ahead of the reader's, but a second
        // checkpoint retired it before the refresh reopened its files. The
        // engine lock arbitrates — files are only deleted inside `checkpoint`
        // under the engine write lock, so once this read lock is acquired the
        // committed generation provably differs from a raced batch's. Only a
        // failure for the live generation means storage is actually broken;
        // a retired one is skipped like any stale refresh, and the checkpoint
        // task republishes the readers. No reader lock is held here, so this
        // cannot invert the checkpoint task's engine-then-reader lock order,
        // and the engine lock is only ever taken on this cold path.
        let retired = config
            .engine
            .read()
            .is_ok_and(|engine| engine.committed_root().0 != generation);
        if !retired {
            record_storage_error(&config.metrics, &error);
            respond_writes(requests, Err(error.to_string()));
            return false;
        }
    }
    // Broadcast the records the commit actually published, so a live cursor
    // always matches a durable one.
    for record in published {
        let _ = config.changes.send(ChangeEvent {
            sequence: record.sequence,
            key: record.key,
            value: record.value,
            cursor: Some(change_log::Cursor::new(record.sequence, record.index)),
        });
    }
    respond_writes(requests, Ok(results));
    true
}

type DocumentChangeEvent = (Vec<u8>, Option<Vec<u8>>);

fn apply_document_write(
    engine: &mut Engine,
    request: DocumentWrite,
) -> vyrn_core::Result<(Message, Option<DocumentChangeEvent>)> {
    match request {
        DocumentWrite::CreateCollection {
            collection,
            indexes,
        } => {
            engine.collection(collection, &indexes)?;
            Ok((Message::CollectionCreated, None))
        }
        DocumentWrite::Put {
            collection,
            id,
            document,
        } => {
            let value: serde_json::Value = serde_json::from_slice(&document).map_err(|error| {
                StorageError::InvalidDocument(format!("document is not valid JSON: {error}"))
            })?;
            let indexes = document_indexes(engine, &collection)?;
            let mut handle = engine.collection(collection.clone(), &indexes)?;
            handle.put(&id, &value)?;
            let key = vyrn_core::document::document_change_key(&collection, &id)?;
            Ok((Message::DocumentWritten, Some((key, Some(document)))))
        }
        DocumentWrite::Delete { collection, id } => {
            let indexes = document_indexes(engine, &collection)?;
            let mut handle = engine.collection(collection.clone(), &indexes)?;
            let existed = handle.delete(&id)?;
            let change = if existed {
                Some((
                    vyrn_core::document::document_change_key(&collection, &id)?,
                    None,
                ))
            } else {
                None
            };
            Ok((Message::DocumentDeleted { existed }, change))
        }
    }
}

fn document_indexes(engine: &Engine, collection: &str) -> vyrn_core::Result<Vec<IndexDefinition>> {
    Ok(engine
        .collection_indexes(collection)?
        .into_iter()
        .map(|(field, unique)| IndexDefinition::new(field, unique))
        .collect())
}

fn operation_key(operation: &BatchOperation) -> &[u8] {
    match operation {
        BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
    }
}

fn respond_writes(
    requests: Vec<WriteRequest>,
    result: std::result::Result<Vec<BatchResult>, String>,
) {
    match result {
        Ok(results) => {
            let mut results = results.into_iter();
            for request in requests {
                match request {
                    WriteRequest::Operation { response, .. } => {
                        let result = results
                            .next()
                            .ok_or_else(|| "storage returned no write result".into());
                        let _ = response.send(result);
                    }
                    WriteRequest::Document { .. }
                    | WriteRequest::CreateIndex { .. }
                    | WriteRequest::DropIndex { .. } => {
                        unreachable!()
                    }
                    WriteRequest::Transaction {
                        operations,
                        response,
                        ..
                    } => {
                        let transaction_results: Vec<_> =
                            results.by_ref().take(operations.len()).collect();
                        let result = if transaction_results.len() == operations.len() {
                            Ok(transaction_results)
                        } else {
                            Err("storage returned too few transaction results".into())
                        };
                        let _ = response.send(result);
                    }
                }
            }
        }
        Err(message) => {
            for request in requests {
                match request {
                    WriteRequest::Operation { response, .. } => {
                        let _ = response.send(Err(message.clone()));
                    }
                    WriteRequest::Document { .. }
                    | WriteRequest::CreateIndex { .. }
                    | WriteRequest::DropIndex { .. } => {
                        unreachable!()
                    }
                    WriteRequest::Transaction { response, .. } => {
                        let _ = response.send(Err(message.clone()));
                    }
                }
            }
        }
    }
}

fn has_conflict(
    engine: &Engine,
    snapshot_sequence: u64,
    read_keys: &[Vec<u8>],
    read_ranges: &[ReadRange],
    index_reads: &[(Vec<u8>, Vec<u8>)],
    operations: &[BatchOperation],
    index_updates: &[IndexUpdate],
) -> vyrn_core::Result<bool> {
    // One batched sweep for every key this transaction wrote or read, rather than
    // a root-to-leaf descent per key.
    let keys: Vec<Vec<u8>> = operations
        .iter()
        .map(|operation| operation_key(operation).to_vec())
        .chain(
            index_updates
                .iter()
                .map(|update| update.primary_key.clone()),
        )
        .chain(read_keys.iter().cloned())
        .collect();
    if engine.any_changed_since(&keys, snapshot_sequence)? {
        return Ok(true);
    }
    for (start, end) in read_ranges {
        if engine.range_changed_since(start.as_deref(), end.as_deref(), snapshot_sequence)? {
            return Ok(true);
        }
    }
    for (index, value) in index_reads {
        if engine.index_value_changed_since(index, value, snapshot_sequence)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn record_storage_error(metrics: &Metrics, error: &StorageError) {
    metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
    if matches!(error, StorageError::Poisoned | StorageError::Io(_)) {
        metrics.storage_failed.store(true, Ordering::Release);
        metrics.ready.store(false, Ordering::Release);
    }
}

async fn serve_admin(listener: TcpListener, metrics: Arc<Metrics>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut request = [0; 2048];
            let Ok(count) = timeout(Duration::from_secs(5), stream.read(&mut request)).await else {
                return;
            };
            let Ok(count) = count else { return };
            let line = String::from_utf8_lossy(&request[..count]);
            let path = line.split_whitespace().nth(1).unwrap_or("/");
            let ready = metrics.ready.load(Ordering::Acquire)
                && !metrics.storage_failed.load(Ordering::Acquire);
            let (status, content_type, body) = match path {
                "/health/live" => ("200 OK", "text/plain", "ok\n".to_owned()),
                "/health/ready" if ready => ("200 OK", "text/plain", "ready\n".to_owned()),
                "/health/ready" => ("503 Service Unavailable", "text/plain", "not ready\n".to_owned()),
                "/metrics" => (
                    "200 OK",
                    "text/plain; version=0.0.4",
                    format!(
                        "vyrn_ready {}\nvyrn_storage_failed {}\nvyrn_active_connections {}\nvyrn_requests_total {}\nvyrn_requests_failed_total {}\nvyrn_reads_total {}\nvyrn_writes_total {}\nvyrn_checkpoints_total {}\nvyrn_write_batches_total {}\nvyrn_batched_writes_total {}\nvyrn_wal_flushes_total {}\nvyrn_flushed_batches_total {}\nvyrn_mvcc_gc_runs_total {}\nvyrn_mvcc_versions_collected_total {}\nvyrn_wal_archive_lag_segments {}\nvyrn_wal_archived_total {}\nvyrn_wal_archive_failures_total {}\nvyrn_commit_batches_total {}\nvyrn_commit_requests_total {}\n{}",
                        u8::from(ready),
                        u8::from(metrics.storage_failed.load(Ordering::Relaxed)),
                        metrics.active_connections.load(Ordering::Relaxed),
                        metrics.total_requests.load(Ordering::Relaxed),
                        metrics.failed_requests.load(Ordering::Relaxed),
                        metrics.reads.load(Ordering::Relaxed),
                        metrics.writes.load(Ordering::Relaxed),
                        metrics.checkpoints.load(Ordering::Relaxed),
                        metrics.write_batches.load(Ordering::Relaxed),
                        metrics.batched_writes.load(Ordering::Relaxed),
                        metrics.wal_flushes.load(Ordering::Relaxed),
                        metrics.flushed_batches.load(Ordering::Relaxed),
                        metrics.mvcc_gc_runs.load(Ordering::Relaxed),
                        metrics.mvcc_versions_collected.load(Ordering::Relaxed),
                        metrics.wal_archive_lag_segments.load(Ordering::Relaxed),
                        metrics.wal_archived_total.load(Ordering::Relaxed),
                        metrics.wal_archive_failures_total.load(Ordering::Relaxed),
                        metrics.write_profile.batches.load(Ordering::Relaxed),
                        metrics.write_profile.requests.load(Ordering::Relaxed),
                        metrics.write_profile.render(),
                    ),
                ),
                _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
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

async fn send_error(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    request_id: u64,
    code: ErrorCode,
    message: &str,
) -> Result<()> {
    framed
        .send(Envelope::new(request_id, server_error(code, message)))
        .await?;
    Ok(())
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
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    /// The quantile is only worth reading if the bucket it names actually holds
    /// the value, so index and lower bound have to agree in both directions.
    #[test]
    fn histogram_buckets_contain_the_values_indexed_into_them() {
        for nanoseconds in (0..64).chain((6..40).map(|shift| (1_u64 << shift) + 12_345)) {
            let index = Histogram::index(nanoseconds);
            assert!(
                Histogram::lower_bound(index) <= nanoseconds,
                "{nanoseconds} below the bound of bucket {index}"
            );
            assert!(
                index + 1 == Histogram::BUCKETS || nanoseconds < Histogram::lower_bound(index + 1),
                "{nanoseconds} above the bound of bucket {index}"
            );
        }
    }

    /// Four buckets per octave is the accuracy the stage budget is read at.
    #[test]
    fn histogram_quantiles_land_within_a_quarter_octave() {
        let histogram = Histogram::default();
        for micros in 1..=1_000_u64 {
            histogram.record(Duration::from_micros(micros));
        }
        for (permille, expected) in [(500_u64, 500_000_u64), (990, 990_000)] {
            let measured = histogram.quantile(permille);
            let error = measured.abs_diff(expected) as f64 / expected as f64;
            assert!(
                error < 0.10,
                "p{permille} measured {measured} against {expected}"
            );
        }
    }

    /// An empty stage must report zero rather than the bottom bucket, or an
    /// unused path reads as a fast one.
    #[test]
    fn histogram_without_observations_reports_zero() {
        assert_eq!(Histogram::default().quantile(500), 0);
    }

    #[tokio::test]
    async fn transaction_reads_persisted_snapshot_and_its_writes() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"old".to_vec()).unwrap();
        engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
        let sequence = engine.register_snapshot();
        engine.put(b"a".to_vec(), b"current".to_vec()).unwrap();
        let engine = Arc::new(RwLock::new(engine));
        let mut transaction = ConnectionTransaction {
            sequence,
            started: tokio::time::Instant::now(),
            read_keys: BTreeMap::new(),
            read_ranges: Vec::new(),
            index_reads: Vec::new(),
            writes: BTreeMap::new(),
            index_updates: Vec::new(),
        };
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Get { key: b"a".to_vec() }
            )
            .await,
            Message::Value {
                value: Some(b"old".to_vec())
            }
        );
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Put {
                    key: b"a".to_vec(),
                    value: b"new".to_vec()
                }
            )
            .await,
            Message::Written
        );
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Get { key: b"a".to_vec() }
            )
            .await,
            Message::Value {
                value: Some(b"new".to_vec())
            }
        );
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Delete { key: b"b".to_vec() }
            )
            .await,
            Message::Deleted { existed: true }
        );
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Get { key: b"b".to_vec() }
            )
            .await,
            Message::Value { value: None }
        );
        assert_eq!(
            execute_transaction(
                &engine,
                &mut transaction,
                Message::Scan {
                    start: None,
                    end: None,
                    limit: 10
                }
            )
            .await,
            Message::Rows {
                rows: vec![(b"a".to_vec(), b"new".to_vec())]
            }
        );
    }

    #[test]
    fn conflict_detection_only_rejects_keys_changed_after_snapshot() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"b".to_vec(), b"old".to_vec()).unwrap();
        let snapshot = engine.sequence();
        engine.put(b"a".to_vec(), b"new".to_vec()).unwrap();
        assert!(has_conflict(
            &engine,
            snapshot,
            &[],
            &[],
            &[],
            &[BatchOperation::Put(b"a".to_vec(), b"new".to_vec())],
            &[]
        )
        .unwrap());
        assert!(!has_conflict(
            &engine,
            snapshot,
            &[],
            &[],
            &[],
            &[BatchOperation::Delete(b"b".to_vec())],
            &[]
        )
        .unwrap());
        assert!(!has_conflict(
            &engine,
            snapshot,
            &[],
            &[],
            &[],
            &[BatchOperation::Put(b"c".to_vec(), b"new".to_vec())],
            &[]
        )
        .unwrap());
    }

    #[test]
    fn serializable_conflicts_cover_reads_and_phantoms() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.create_index(b"tag".to_vec(), false).unwrap();
        let snapshot = engine.sequence();
        engine
            .write_indexed(
                vec![
                    BatchOperation::Put(b"account/a".to_vec(), b"1".to_vec()),
                    BatchOperation::Put(b"users/new".to_vec(), b"1".to_vec()),
                ],
                vec![IndexUpdate {
                    index: b"tag".to_vec(),
                    primary_key: b"users/new".to_vec(),
                    old_value: None,
                    new_value: Some(b"admin".to_vec()),
                }],
            )
            .unwrap();
        assert!(has_conflict(
            &engine,
            snapshot,
            &[b"account/a".to_vec()],
            &[],
            &[],
            &[BatchOperation::Put(b"account/b".to_vec(), b"1".to_vec())],
            &[]
        )
        .unwrap());
        assert!(has_conflict(
            &engine,
            snapshot,
            &[],
            &[(Some(b"users/".to_vec()), Some(b"users0".to_vec()))],
            &[],
            &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
            &[]
        )
        .unwrap());
        assert!(has_conflict(
            &engine,
            snapshot,
            &[],
            &[],
            &[(b"tag".to_vec(), b"admin".to_vec())],
            &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
            &[]
        )
        .unwrap());
        assert!(!has_conflict(
            &engine,
            engine.sequence(),
            &[b"account/a".to_vec()],
            &[(Some(b"users/".to_vec()), Some(b"users0".to_vec()))],
            &[(b"tag".to_vec(), b"admin".to_vec())],
            &[BatchOperation::Put(b"audit".to_vec(), b"1".to_vec())],
            &[]
        )
        .unwrap());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn generated_serializable_histories_detect_stale_reads_and_phantoms(
            suffix in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            let directory = tempdir().unwrap();
            let mut engine = Engine::open(directory.path()).unwrap();
            let snapshot = engine.sequence();
            let mut point_key = b"point/".to_vec();
            point_key.extend_from_slice(&suffix);
            let mut range_key = b"range/".to_vec();
            range_key.extend_from_slice(&suffix);
            engine.put(point_key.clone(), b"point".to_vec()).unwrap();
            engine.put(range_key, b"range".to_vec()).unwrap();
            prop_assert!(has_conflict(
                &engine,
                snapshot,
                std::slice::from_ref(&point_key),
                &[],
                &[],
                &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
                &[],
            ).unwrap());
            prop_assert!(has_conflict(
                &engine,
                snapshot,
                &[],
                &[(Some(b"range/".to_vec()), Some(b"range0".to_vec()))],
                &[],
                &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
                &[],
            ).unwrap());
            prop_assert!(!has_conflict(
                &engine,
                engine.sequence(),
                std::slice::from_ref(&point_key),
                &[(Some(b"range/".to_vec()), Some(b"range0".to_vec()))],
                &[],
                &[BatchOperation::Put(b"other".to_vec(), b"value".to_vec())],
                &[],
            ).unwrap());
        }
    }
}
