use anyhow::{bail, Context, Result};
use argon2::{password_hash::PasswordHashString, Argon2, PasswordVerifier};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::BTreeMap,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::{broadcast, mpsc, oneshot, Notify, Semaphore},
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
    mvcc_versions_collected: AtomicU64,
    mvcc_gc_runs: AtomicU64,
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
            mvcc_versions_collected: AtomicU64::new(0),
            mvcc_gc_runs: AtomicU64::new(0),
            storage_failed: AtomicBool::new(false),
            drained: Notify::new(),
        }
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
}

enum WriteRequest {
    Operation {
        operation: BatchOperation,
        response: oneshot::Sender<std::result::Result<BatchResult, String>>,
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
    },
}

struct WriteWorkerConfig {
    maximum_batch: usize,
    delay: Duration,
    checkpoint_writes: u64,
    readers: Arc<Vec<RwLock<ReadEngine>>>,
    changes: broadcast::Sender<ChangeEvent>,
    metrics: Arc<Metrics>,
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
    let engine = Engine::open_with_options(
        &args.data,
        EngineOptions {
            durability,
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
