mod audit;
mod auth;
mod epoch;
mod failover;
mod replica;
mod replication;

use anyhow::{bail, Context, Result};
use argon2::password_hash::PasswordHashString;
use clap::Parser;
use futures_util::{FutureExt, SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::BufReader,
    net::IpAddr,
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

#[derive(Parser)]
#[command(name = "vyrnd", version, about = "Vyrn database server")]
struct Args {
    #[arg(long, env = "VYRN_BIND", default_value = "127.0.0.1:7432")]
    bind: String,
    #[arg(long, env = "VYRN_DATA", default_value = "./data")]
    data: PathBuf,
    #[arg(long, env = "VYRN_USERNAME", default_value = "vyrn")]
    username: String,
    /// Single-credential mode: one Argon2id verifier for `--username`, with
    /// every permission. Mutually exclusive with `--users-file`.
    #[arg(long, env = "VYRN_PASSWORD_HASH_FILE")]
    password_hash_file: Option<PathBuf>,
    /// Per-user accounts with prefix ACLs; see docs/security.md for the JSON
    /// format. Re-checked on every authentication attempt, so edits (adding,
    /// removing, or re-scoping a user) need no restart. Mutually exclusive
    /// with `--password-hash-file`.
    #[arg(long, env = "VYRN_USERS_FILE")]
    users_file: Option<PathBuf>,
    /// Append-only audit trail; unset disables it. Reads are included only
    /// when `VYRN_AUDIT_READS=1`.
    #[arg(long, env = "VYRN_AUDIT_LOG")]
    audit_log: Option<PathBuf>,
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
    /// Write-back buffer size in bytes; 0 disables it.
    ///
    /// With a buffer, a durable commit is its WAL record alone: mutations sit
    /// in memory, every read merges them over the tree, and the tree absorbs
    /// the whole buffer in one amortised pass at this threshold and on every
    /// checkpoint. Cuts the engine CPU beside the commit fsync by an order of
    /// magnitude at batch shapes (see docs/benchmarks.md). The trade: reopening
    /// after a crash replays the WAL from the last checkpoint instead of
    /// adopting the newest root, and up to this many bytes of committed state
    /// live only in memory (they are always durable in the WAL).
    ///
    /// Refused on a replica: its log must stay byte-identical to the
    /// primary's, and replica apply does not route through the buffer.
    #[arg(long, env = "VYRN_WRITE_BACK_BYTES", default_value_t = 0)]
    write_back_bytes: usize,
    #[arg(long, env = "VYRN_ASYNC_SYNC_MS", default_value_t = 5)]
    async_sync_ms: u64,
    #[arg(long, env = "VYRN_TRANSACTION_TIMEOUT_SECONDS", default_value_t = 30)]
    transaction_timeout_seconds: u64,
    #[arg(long, env = "VYRN_READ_HANDLES", default_value_t = 16)]
    read_handles: usize,
    /// How long one read statement may occupy a read worker before it is
    /// abandoned and its client told to narrow the request.
    ///
    /// WHY THIS EXISTS: a read handle is served by ONE thread reading ONE queue,
    /// so a request that runs long is not merely slow for the client that sent it
    /// — it is a queue every client on that handle waits behind. A `limit` bounds
    /// how many ROWS a scan returns, which is not a bound on its cost:
    /// `MAX_SCAN_LIMIT` rows of `MAX_VALUE_SIZE` values is a value-log read
    /// measured in gigabytes, and nothing in the protocol lets a client promise
    /// its statement is cheap. So the server is what stops.
    ///
    /// Enforced BETWEEN chunks of a scan (see `advance_scan`), which is what makes
    /// it a bound on worker occupancy rather than merely on how long one client
    /// waits: the worker abandons the statement and serves the next one.
    ///
    /// DELIBERATELY NOT APPLIED TO WRITES. A write that has entered the pipeline
    /// may already be in the WAL, so answering "deadline exceeded" would report an
    /// unknown outcome as a failure and invite a retry that applies it twice — the
    /// same reasoning as the flush stage's "durable but not published". Write
    /// occupancy is bounded by the pipeline's stages and its supervision instead.
    #[arg(
        long,
        env = "VYRN_STATEMENT_DEADLINE_MS",
        default_value_t = DEFAULT_STATEMENT_DEADLINE_MS
    )]
    statement_deadline_ms: u64,
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
    /// Replica acknowledgements required before a commit is answered.
    ///
    /// 0 (the default) disables replication and leaves the single-node write path
    /// exactly as it was. 1 or more makes writes synchronous: a commit is
    /// acknowledged only once that many replicas hold it durably, so losing this
    /// node cannot lose an acknowledged write.
    ///
    /// This is a REQUIREMENT, not a target. Setting it above the number of
    /// replicas actually running makes every write block until the timeout.
    #[arg(long, env = "VYRN_REPLICATION_MIN_ACKS", default_value_t = 0)]
    replication_min_acks: usize,
    /// How long a commit waits for replica acknowledgements before failing.
    ///
    /// Bounded on purpose: an unbounded wait turns one unreachable replica into a
    /// hung database. On timeout the write fails with an error saying it is
    /// durable locally but not replicated, which is the honest outcome — the
    /// alternative, acknowledging it anyway, silently voids the guarantee the
    /// operator asked for.
    #[arg(long, env = "VYRN_REPLICATION_ACK_TIMEOUT_MS", default_value_t = 5_000)]
    replication_ack_timeout_ms: u64,
    /// Run as a replica of this primary, e.g. `vyrn://repl@primary:7432/default`.
    ///
    /// One binary serves both roles deliberately: promotion then needs no
    /// different image, only a restart without this flag.
    ///
    /// A replica still serves reads on `--bind`, but writes from clients are
    /// refused — its log must contain only what the primary sent, or the two
    /// histories diverge and it can never be promoted.
    #[arg(long, env = "VYRN_REPLICA_OF")]
    replica_of: Option<String>,
    /// File holding the password used to authenticate to the primary.
    ///
    /// A file rather than a flag so the secret does not appear in `ps` output or
    /// shell history.
    #[arg(long, env = "VYRN_REPLICA_PASSWORD_FILE", requires = "replica_of")]
    replica_password_file: Option<PathBuf>,
    /// CA certificate used to verify the primary's TLS certificate.
    #[arg(long, env = "VYRN_REPLICA_CA_FILE", requires = "replica_of")]
    replica_ca_file: Option<PathBuf>,
    /// Name for this replica in the primary's logs and metrics.
    #[arg(long, env = "VYRN_REPLICA_ID", requires = "replica_of")]
    replica_id: Option<String>,
    /// WAL archive this replica recovers pruned records from when it has fallen
    /// too far behind to be streamed to.
    ///
    /// WHY A REPLICA NEEDS ONE. A primary's checkpoints delete sealed WAL
    /// segments, so a replica offline across a few of them comes back needing
    /// records the primary no longer holds. Without this, that is fatal and
    /// permanent: the join is refused on every reconnect, and a primary running
    /// `--replication-min-acks 1` blocks writes for want of the very replica that
    /// cannot rejoin. With it, the replica reads exactly those pruned records from
    /// the archive — they are the primary's own WAL segments, byte for byte — and
    /// then streams on from where the archive ends.
    ///
    /// Point it at the same directory the primary's `--wal-archive-dir` writes to,
    /// by whatever means that directory is shared. Read-only here: a replica never
    /// writes to the archive.
    #[arg(long, env = "VYRN_REPLICA_WAL_ARCHIVE_DIR", requires = "replica_of")]
    replica_wal_archive_dir: Option<PathBuf>,
    /// Static cluster membership for automatic failover:
    /// `name=vyrn://user@host:port/db,name=...`, every member listed,
    /// including this one. Absent (the default) means no automatic failover —
    /// promotion stays the manual procedure in docs/replication.md.
    ///
    /// Requires at least 3 members and `--replication-min-acks >= floor(N/2)`;
    /// both are refused at startup otherwise, with the safety argument in the
    /// error. See docs/replication.md for why 2-member automatic failover is
    /// split-brain by construction.
    #[arg(long, env = "VYRN_CLUSTER", requires = "cluster_self")]
    cluster: Option<String>,
    /// This member's name in `--cluster`.
    #[arg(long, env = "VYRN_CLUSTER_SELF", requires = "cluster")]
    cluster_self: Option<String>,
    /// How long a primary may go without holding its quorum before it
    /// self-fences (refuses writes as deposed).
    #[arg(long, env = "VYRN_FAILOVER_LEASE_MS", default_value_t = 3_000)]
    failover_lease_ms: u64,
    /// How long a follower waits without hearing from a primary before
    /// standing for election. Jittered per member to avoid split votes.
    #[arg(long, env = "VYRN_FAILOVER_ELECTION_MS", default_value_t = 6_000)]
    failover_election_ms: u64,
    /// Number of independent shards, each a full engine with its own write
    /// lock, WAL, and group commit — the write path parallelizes across
    /// them. 1 (the default) is byte-identical to the unsharded server.
    ///
    /// Fixed at creation: the count is recorded in a SHARDS marker file and
    /// a mismatch refuses startup, because key placement depends on it.
    /// Sharded mode restricts cross-shard atomicity — see the Sharding
    /// section of docs/production.md before enabling it.
    #[arg(long, env = "VYRN_SHARDS", default_value_t = 1)]
    shards: usize,
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
    /// Every rejected authentication, including throttle refusals that never
    /// reached the password check. A rising rate here is the signal that someone
    /// is guessing; without it a lockout is invisible to operators.
    auth_failures_total: AtomicU64,
    /// Engine snapshots currently pinned by open client transactions (gauge).
    ///
    /// The MVCC floor is the minimum over live snapshots, so a pin that is never
    /// released stops version collection for the rest of the process's life. That
    /// failure is otherwise invisible — throughput and error rates stay normal
    /// while history grows without bound — so the count is published: if this
    /// does not return to zero on an idle server, a pin has leaked.
    active_transaction_snapshots: AtomicU64,
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
            auth_failures_total: AtomicU64::new(0),
            active_transaction_snapshots: AtomicU64::new(0),
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

/// Total bytes of pending write payload allowed in the pipeline at once.
///
/// WHY A BYTE BOUND AND NOT JUST A SLOT COUNT: `--write-queue-capacity` bounds
/// the number of queued requests, not their size. At the default 4096 slots and
/// the 16 MiB `MAX_VALUE_SIZE`, a queue that is merely full holds up to ~64 GiB
/// of values — and it fills exactly when the pipeline is slowest, because the
/// write worker stalls behind a checkpoint or a slow barrier while clients keep
/// submitting. The process is then killed by the OOM killer at the worst possible
/// moment: mid-checkpoint, with a full WAL to replay.
///
/// 256 MiB is chosen to be far above any legitimate burst (it is 16 concurrent
/// maximum-size values, or tens of thousands of ordinary ones) while keeping the
/// worst case a number a host can actually hold. Exceeding it makes writers wait
/// rather than fail: back-pressure is the correct response to a slow disk, and a
/// client that waits gets its commit, where a client that is refused has to
/// decide whether retrying is safe.
const WRITE_QUEUE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Consecutive failed authentications from one address before it is locked out.
const AUTH_FAILURE_LIMIT: u32 = 10;

/// How long a locked-out address stays refused, and how long an idle address's
/// failure count is remembered.
const AUTH_LOCKOUT: Duration = Duration::from_secs(60);

/// Addresses tracked at once, bounding the throttle's own memory.
const AUTH_THROTTLE_CAPACITY: usize = 4096;

/// Reserves queue memory for one pending write, releasing it on drop.
///
/// A permit is acquired before the request enters the channel and held until the
/// client's answer has been received, which is the whole interval during which
/// the payload occupies memory: the channel slot, then the write worker's batch,
/// then the `PendingFlush` awaiting its barrier. Releasing any earlier would
/// under-count exactly the backlog this bounds.
///
/// Tied to a semaphore rather than a counter so that an over-budget writer waits
/// instead of failing, and so the release cannot be forgotten on an error path —
/// dropping the guard is the release, and every early return drops it.
struct WriteBudget {
    /// `None` for requests too large to ever fit the budget on their own; they
    /// proceed unmetered rather than deadlocking. A single request cannot exceed
    /// `MAX_VALUE_SIZE` plus a key, which is far under the budget, so this is
    /// unreachable in practice and exists so the arithmetic has no failure mode.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl WriteBudget {
    /// Waits until `bytes` of queue budget is available.
    async fn acquire(budget: &Arc<Semaphore>, bytes: usize) -> Self {
        // Clamped because `acquire_many` takes a u32 and panics if the request
        // exceeds the semaphore's total.
        let permits = bytes.min(WRITE_QUEUE_MAX_BYTES) as u32;
        let permit = Arc::clone(budget)
            .acquire_many_owned(permits.max(1))
            .await
            .ok();
        Self { _permit: permit }
    }
}

/// Queue-memory cost of one write request.
///
/// Counts payload only. The per-request overhead is a fixed few hundred bytes
/// against a budget measured in hundreds of megabytes, so tracking it would add
/// arithmetic without changing when the bound trips.
fn operation_bytes(operation: &BatchOperation) -> usize {
    match operation {
        BatchOperation::Put(key, value) => key.len() + value.len(),
        BatchOperation::Delete(key) => key.len(),
    }
}

fn document_write_bytes(request: &DocumentWrite) -> usize {
    match request {
        DocumentWrite::CreateCollection {
            collection,
            indexes,
        } => collection.len() + indexes.iter().map(|index| index.field.len()).sum::<usize>(),
        DocumentWrite::Put {
            collection,
            id,
            document,
        } => collection.len() + id.len() + document.len(),
        DocumentWrite::Delete { collection, id } => collection.len() + id.len(),
    }
}

/// Per-address failed-authentication throttle.
///
/// WHY THIS EXISTS: verifying a password is deliberately expensive — that is what
/// makes the stored hash worth storing. Argon2 with the default parameters costs
/// tens of milliseconds and a chunk of memory per attempt, so an unauthenticated
/// peer could pin server CPU and memory just by guessing, and the guesses are
/// free for it. `--max-auth-jobs` already caps how many verifications run at
/// once, but a cap alone does not end the attack: it converts CPU exhaustion into
/// a queue every legitimate client also waits in.
///
/// So refusal has to happen BEFORE the verification. After
/// `AUTH_FAILURE_LIMIT` consecutive failures an address is refused outright for
/// `AUTH_LOCKOUT`, without touching Argon2 — which is also why the correct
/// password is refused during a lockout, and why that is the observable proof
/// the check runs early enough to matter.
///
/// Keyed on IP, not on address-with-port: a source port changes per connection,
/// so counting it would reset on every attempt and never trip.
///
/// SCOPE, stated plainly: this raises the cost of online guessing against a
/// single-credential server. It is not a defence against a distributed attacker,
/// who simply spreads attempts across addresses, and against a spoofed source it
/// is a self-inflicted denial of service for the address being impersonated.
/// The real fix for both is per-principal credentials with revocation, which
/// this server does not have (see the deferred list in `todo.md`).
struct AuthThrottle {
    /// Sorted by nothing — small, capacity-bounded, and only touched on the
    /// handshake path, so a plain map under a mutex is cheaper than anything
    /// cleverer. Never held across an `await`.
    addresses: std::sync::Mutex<HashMap<IpAddr, AuthFailures>>,
}

struct AuthFailures {
    consecutive: u32,
    /// When the most recent failure was recorded, so entries expire.
    last: Instant,
}

impl AuthThrottle {
    fn new() -> Self {
        Self {
            addresses: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// True when this address is currently locked out.
    fn is_locked_out(&self, address: IpAddr) -> bool {
        let Ok(mut addresses) = self.addresses.lock() else {
            /* A poisoned throttle must not become an authentication bypass, but
             * it must not lock everyone out either: the mutex only guards a
             * counter, and a panic while holding it cannot corrupt anything a
             * later attempt depends on. Fail open on the throttle and let the
             * password check decide, which is the pre-throttle behaviour. */
            return false;
        };
        match addresses.get(&address) {
            Some(failures) if failures.consecutive >= AUTH_FAILURE_LIMIT => {
                if failures.last.elapsed() < AUTH_LOCKOUT {
                    true
                } else {
                    // The lockout expired: forget it and let this attempt run.
                    addresses.remove(&address);
                    false
                }
            }
            _ => false,
        }
    }

    fn record_failure(&self, address: IpAddr) {
        let Ok(mut addresses) = self.addresses.lock() else {
            return;
        };
        let now = Instant::now();
        // Drop expired entries before inserting, so a long run of one-off
        // failures from many addresses cannot grow this map without bound.
        if addresses.len() >= AUTH_THROTTLE_CAPACITY {
            addresses.retain(|_, failures| failures.last.elapsed() < AUTH_LOCKOUT);
            /* Still full: every tracked address is live, so this is either a
             * broad attack or a very large legitimate fleet. Refusing to track
             * the new address is the safe direction — it gets the ordinary
             * password check, and the addresses already failing stay locked. */
            if addresses.len() >= AUTH_THROTTLE_CAPACITY {
                return;
            }
        }
        let entry = addresses.entry(address).or_insert(AuthFailures {
            consecutive: 0,
            last: now,
        });
        // Saturating so a very long attack cannot wrap the counter back under
        // the limit and release the lockout.
        entry.consecutive = entry.consecutive.saturating_add(1);
        entry.last = now;
    }

    /// Clears an address's history after a successful authentication.
    fn record_success(&self, address: IpAddr) {
        if let Ok(mut addresses) = self.addresses.lock() {
            addresses.remove(&address);
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
    /// True when the ring dropped this event's value to stay inside its byte
    /// bound, so `value` is `None` for a change that was NOT a delete.
    ///
    /// Subscribers must not report this as a deletion. They treat it exactly like
    /// a lagged subscription — tell the client to resynchronize — because that is
    /// what it is: a change whose contents this server can no longer supply from
    /// memory. See [`ChangeRing`].
    elided: bool,
}

/// Bytes of change payload the broadcast ring may hold.
///
/// WHY: the ring keeps the last `--write-queue-capacity` events so slow
/// subscribers can catch up, and it keeps them whether or not anybody is
/// subscribed. At the default 4096 events and the 16 MiB `MAX_VALUE_SIZE` that is
/// another ~64 GiB of resident memory reachable by ordinary writes — the same
/// exposure as the write queue, on a structure that exists purely as a
/// convenience for subscribers.
///
/// 64 MiB is far more than any subscriber needs to ride out a scheduling hiccup,
/// and it is bounded regardless of value size.
const CHANGE_RING_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The change broadcast plus enough accounting to bound its memory.
///
/// A `broadcast::Sender` retains the last `capacity` messages and offers no way
/// to ask how much memory that is, so this mirrors the ring: one entry per live
/// message, evicted in the same order the channel evicts. That mirror is exact
/// because tokio's ring holds precisely the most recent `capacity` sends.
///
/// When admitting an event would exceed the byte bound, its VALUE is dropped and
/// `elided` set, rather than dropping the event or blocking the writer. That
/// choice is deliberate:
///
///   - dropping the event would make a subscriber miss a change silently, which
///     is the one failure a change feed must never have;
///   - blocking the commit path on subscriber memory would let one idle
///     subscription stall every writer.
///
/// An elided event still carries its key and sequence, so a subscriber learns
/// that the key changed and is told to resynchronize. Losing the payload is
/// visible and recoverable; losing the notification is neither.
struct ChangeRing {
    sender: broadcast::Sender<ChangeEvent>,
    /// Sizes of the events currently retained, oldest first, with their total.
    /// Never held across an `await`.
    live: std::sync::Mutex<RingBytes>,
    capacity: usize,
}

#[derive(Default)]
struct RingBytes {
    sizes: std::collections::VecDeque<usize>,
    total: usize,
}

impl ChangeRing {
    fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            live: std::sync::Mutex::new(RingBytes::default()),
            capacity,
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<ChangeEvent> {
        self.sender.subscribe()
    }

    /// Publishes one change, eliding its value if the ring is at its byte bound.
    fn send(&self, mut event: ChangeEvent) {
        let value_bytes = event.value.as_ref().map_or(0, Vec::len);
        let mut bytes = event.key.len() + value_bytes;
        if let Ok(mut live) = self.live.lock() {
            if live.total + bytes > CHANGE_RING_MAX_BYTES && value_bytes > 0 {
                /* Keep the notification, drop the payload. A key alone is at
                 * most `MAX_KEY_SIZE`, so even an all-elided ring stays bounded
                 * by capacity × 64 KiB. */
                event.value = None;
                event.elided = true;
                bytes = event.key.len();
            }
            live.sizes.push_back(bytes);
            live.total = live.total.saturating_add(bytes);
            // Mirror the channel's eviction: one message leaves for each that
            // arrives once the ring is full.
            while live.sizes.len() > self.capacity {
                let evicted = live.sizes.pop_front().unwrap_or(0);
                live.total = live.total.saturating_sub(evicted);
            }
        }
        /* A send with no subscribers is not an error: the ring exists for
         * whoever attaches next, and the commit path must not care. */
        let _ = self.sender.send(event);
    }
}

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

/// Streams the WAL-resident records `[from_lsn, ..]` to a joining replica,
/// returning the LSN the live broadcast should resume from.
///
/// The live broadcast only carries records shipped AFTER a subscriber
/// registers, so a replica that is behind by even one record — a fresh
/// leader whose quorum-failed writes advanced its LSN is the everyday case —
/// could never catch up from the stream alone and, without a WAL archive,
/// never at all: the trio test found followers orbiting a leader they could
/// not join while it demoted for want of them. The records are on this
/// primary's disk; archives are only needed for what checkpoints pruned.
/// Archive segments are verbatim WAL segments, so the archive reader parses
/// the live WAL directory unchanged, runway tails included.
async fn catch_up_from_wal(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    wal_directory: &std::path::Path,
    from_lsn: u64,
) -> Result<u64> {
    const BATCH_RECORDS: usize = 1_024;
    const BATCH_BYTES: usize = 32 * 1024 * 1024;
    let mut next = from_lsn;
    loop {
        let directory = wal_directory.to_path_buf();
        let records = task::spawn_blocking(move || {
            vyrn_core::replication::archived_records_from(
                &directory,
                next,
                BATCH_RECORDS,
                BATCH_BYTES,
            )
        })
        .await
        .map_err(|error| anyhow::anyhow!("WAL catch-up task failed: {error}"))??;
        let Some(last) = records.last() else {
            return Ok(next);
        };
        next = vyrn_core::read_wal_record_lsn(last).saturating_add(1);
        framed
            .send(Envelope::new(0, Message::ReplicaRecords { records }))
            .await?;
    }
}

/// The primary's fencing epoch, sent immediately after `ReplicaStream` and
/// then as the stream's heartbeat — only when automatic failover is
/// configured, so a node without it never sees the tag.
async fn send_primary_epoch(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    failover: Option<&failover::Failover>,
) -> Result<()> {
    if let Some(failover) = failover {
        framed
            .send(Envelope::new(
                0,
                Message::PrimaryEpoch {
                    epoch: failover.epoch(),
                },
            ))
            .await?;
    }
    Ok(())
}

/// Both directions on one connection, driven by `select!`: records go out as the
/// engine produces them, acknowledgements come back as the replica syncs. They
/// cannot be sequenced — waiting for an acknowledgement before sending the next
/// record would serialise replication to one record per round trip, and waiting
/// for a record before reading an acknowledgement would deadlock a quorum the
/// moment the stream went briefly idle.
///
/// The replica is registered for the duration and deregistered on exit, so a
/// dropped connection stops counting toward quorum immediately rather than
/// holding writes until a timeout.
async fn stream_records(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    replication: &Arc<replication::Replication>,
    first_lsn: u64,
    replica_id: &str,
    failover: Option<&failover::Failover>,
) -> Result<()> {
    let (id, mut records) = replication.register();
    let result =
        stream_records_inner(framed, replication, &mut records, first_lsn, id, failover).await;
    // Always, on every exit path.
    replication.deregister(id);
    match &result {
        Ok(()) => log_info!(
            "vyrnd.replication",
            "replica stream ended",
            replica = format!("{replica_id:?}")
        ),
        Err(error) => log_warn!(
            "vyrnd.replication",
            "replica stream failed",
            replica = format!("{replica_id:?}"),
            detail = error
        ),
    }
    result
}

async fn stream_records_inner(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    replication: &Arc<replication::Replication>,
    records: &mut broadcast::Receiver<replication::Shipment>,
    first_lsn: u64,
    id: u64,
    failover: Option<&failover::Failover>,
) -> Result<()> {
    /* Under failover the stream carries the primary's epoch as an idle
     * heartbeat: it is what keeps followers from timing out into an election
     * while the primary is healthy but idle, and each tick re-checks the
     * role so a primary deposed mid-stream stops feeding within one beat.
     * A third of the lease, so a follower misses two beats before its own
     * timers can even begin to matter. */
    let heartbeat = failover.map(|failover| failover.lease / 3);
    let mut beat = tokio::time::interval(heartbeat.unwrap_or(std::time::Duration::from_secs(3600)));
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = beat.tick(), if heartbeat.is_some() => {
                let failover = failover.expect("ticking only when configured");
                if failover.role() != failover::Role::Primary {
                    anyhow::bail!(
                        "this member was deposed at epoch {} and stops streaming",
                        failover.epoch()
                    );
                }
                framed
                    .send(Envelope::new(0, Message::PrimaryEpoch { epoch: failover.epoch() }))
                    .await?;
            }
            shipment = records.recv() => match shipment {
                Ok(shipment) => {
                    // Records below the join point are skipped rather than sent:
                    // the subscription starts at whatever the broadcast held when
                    // this replica connected, which can predate `first_lsn`, and
                    // the replica would reject them as duplicates anyway.
                    if shipment.lsn < first_lsn {
                        continue;
                    }
                    framed
                        .send(Envelope::new(
                            0,
                            Message::ReplicaRecords {
                                records: vec![shipment.bytes.as_ref().clone()],
                            },
                        ))
                        .await?;
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    /* This replica fell far enough behind that records it never
                     * received have been dropped from the buffer. Continuing
                     * would send a non-contiguous stream, which the replica must
                     * refuse — so end the stream here with an explanation and let
                     * it reconnect and close the gap from the archive. */
                    let reason = format!(
                        "replica fell behind by {missed} records (buffer holds {}); \
                         reconnect to resume from the WAL archive",
                        replication::Replication::backlog()
                    );
                    log_warn!(
                        "vyrnd.replication",
                        "dropping replica stream",
                        reason = reason
                    );
                    framed
                        .send(Envelope::new(0, Message::ReplicaDiverged { reason }))
                        .await?;
                    return Ok(());
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            incoming = framed.next() => match incoming {
                Some(Ok(envelope)) => match envelope.message {
                    Message::ReplicaAck { durable_lsn } => {
                        replication.acknowledge(id, durable_lsn);
                    }
                    Message::ReplicaDiverged { reason } => {
                        // The replica is refusing what it was sent. Its own log is
                        // the authority on that, so stop rather than keep pushing.
                        log_error!(
                            "vyrnd.replication",
                            "replica reported divergence",
                            reason = reason
                        );
                        return Ok(());
                    }
                    _ => {
                        send_error(
                            framed,
                            envelope.request_id,
                            ErrorCode::InvalidRequest,
                            "only acknowledgements are accepted on a replication stream",
                        )
                        .await?;
                    }
                },
                Some(Err(error)) => return Err(error.into()),
                None => return Ok(()),
            },
        }
    }
}

/// Capacity of the channel a sharded live subscription is merged into.
/// Sized like a generous change ring: past this, the subscriber is told it
/// lagged, exactly as it would be on a single ring.
const SUBSCRIBE_MERGE_CAPACITY: usize = 4096;

/// One receiver covering every shard's change ring.
///
/// Unsharded this is the ring's own receiver: no task, no copy, nothing new
/// on the default path. Sharded, one forwarder task per shard feeds a fresh
/// channel. Order holds within a shard — each forwarder reads one ring in
/// order — but not across shards, which matches the write path's promise:
/// only same-key order is observable, and a key lives on one shard.
///
/// A forwarder that itself misses events (its ring lagged it out) sends one
/// synthetic elided event with an EMPTY key — a key no client can write, so
/// it passes every prefix filter — and every subscriber gets the same
/// "reconnect and resynchronize" ending a lag produces, instead of a silent
/// gap in one shard's changes. The tasks end with the subscription: once the
/// receiver drops, their sends fail and they return.
fn subscribe_merged(state: &ServerState) -> broadcast::Receiver<ChangeEvent> {
    if !state.sharded() {
        return state.lone_shard().changes.subscribe();
    }
    let (sender, receiver) = broadcast::channel(SUBSCRIBE_MERGE_CAPACITY);
    for shard in &state.shards {
        let mut source = shard.changes.subscribe();
        let sender = sender.clone();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(event) => {
                        // A send error means the subscriber is gone; the other
                        // forwarders notice the same way and the channel dies.
                        if sender.send(event).is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = sender.send(ChangeEvent {
                            sequence: 0,
                            key: Vec::new(),
                            value: None,
                            cursor: None,
                            elided: true,
                        });
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }
    receiver
}

async fn stream_changes(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    mut receiver: broadcast::Receiver<ChangeEvent>,
    prefix: Vec<u8>,
) -> Result<()> {
    loop {
        match receiver.recv().await {
            /* An elided event has lost its payload to the ring's byte bound, so
             * forwarding it would say `value: None` — indistinguishable from a
             * delete, and a subscriber applying that would erase a live key.
             * Treated like a lag, because it is the same situation: this server
             * cannot supply the contents from memory, and the client must reread.
             * Checked before the prefix filter so the guard cannot be skipped. */
            Ok(change) if change.elided => {
                if change.key.is_empty() || change.key.starts_with(&prefix) {
                    send_error(
                        framed,
                        0,
                        ErrorCode::Storage,
                        "change payload dropped under memory pressure; \
                         reconnect and resynchronize",
                    )
                    .await?;
                    return Ok(());
                }
            }
            Ok(change) if change.key.starts_with(&prefix) => {
                send_frame(
                    framed,
                    Envelope::new(
                        0,
                        Message::Change {
                            sequence: change.sequence,
                            key: change.key,
                            value: change.value,
                        },
                    ),
                )
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
            // See `stream_changes`: a payload the ring dropped must not reach a
            // subscriber as `document: None`, which reads as a deletion.
            Ok(change) if change.elided => {
                if change.key.is_empty() || change.key.starts_with(&prefix) {
                    send_error(
                        framed,
                        0,
                        ErrorCode::Storage,
                        "change payload dropped under memory pressure; \
                         reconnect and resynchronize",
                    )
                    .await?;
                    return Ok(());
                }
            }
            Ok(change) if change.key.starts_with(&prefix) => {
                let Ok(id) = vyrn_core::document::document_id_from_key(collection, &change.key)
                else {
                    continue;
                };
                send_frame(
                    framed,
                    Envelope::new(
                        0,
                        Message::DocumentChange {
                            sequence: change.sequence,
                            id,
                            document: change.value,
                        },
                    ),
                )
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
    shard: &Shard,
    cursor: Option<&str>,
) -> vyrn_core::Result<change_log::Cursor> {
    match cursor {
        Some("") => Ok(change_log::Cursor::start()),
        Some(token) => change_log::Cursor::parse_token(token),
        None => {
            let engine = Arc::clone(&shard.engine);
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
    shard: &Shard,
    start: change_log::Cursor,
    stream: CursorStream,
) -> Result<()> {
    let mut live = shard.changes.subscribe();
    let mut cursor = start;

    loop {
        let engine = Arc::clone(&shard.engine);
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
                /* The ring dropped this payload, but a cursor subscription is
                 * recoverable without the client doing anything: the change log
                 * on disk still has the record. Tell it to resume from the last
                 * cursor actually delivered — NOT from this event's position,
                 * which would skip the change whose payload is missing. */
                if change.elided {
                    send_error(
                        framed,
                        0,
                        ErrorCode::Storage,
                        &format!(
                            "change payload dropped under memory pressure; \
                             resume from cursor {}",
                            cursor.to_token()
                        ),
                    )
                    .await?;
                    return Ok(());
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

fn start_read_workers(
    readers: &Arc<Vec<RwLock<ReadEngine>>>,
    capacity: usize,
    deadline: Duration,
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
                        /* Scans this turn owes more chunks to, oldest first.
                         *
                         * THE STALL THIS FIXES: one thread serves one queue, so
                         * a request that runs long is a queue every client on
                         * this handle waits behind — a 10,000-row scan of large
                         * values used to hold every point read behind it while
                         * the other fifteen handles sat idle. Serving the scan
                         * in chunks and admitting queued requests between them
                         * turns "wait for the whole scan" into "wait for one
                         * chunk".
                         */
                        let mut scans = std::collections::VecDeque::new();
                        serve_read(&reader, request, &mut scans, deadline);
                        /* THE SAME READ GUARD FOR EVERY CHUNK, deliberately.
                         *
                         * `ReadEngine::refresh` needs this handle's WRITE lock,
                         * so holding the read guard across the chunks is what
                         * keeps a chunked scan a snapshot: all of its chunks
                         * descend one tree root, and no publish can move the
                         * root out from under it mid-scan. Releasing the guard
                         * between chunks would be the cheaper-looking choice and
                         * would quietly make a single scan able to return rows
                         * from two different commits — trading a stall for a
                         * torn read, which is a worse bug than the one being
                         * fixed.
                         *
                         * It costs nothing that was not already paid: a long
                         * scan held this guard for its whole duration before
                         * this change too, so writers wait exactly as long as
                         * they did. What changes is only that OTHER READS no
                         * longer wait for all of it.
                         */
                        while !scans.is_empty() {
                            // Bounded admission: unbounded would let a steady
                            // stream of point reads hold a scan at its first
                            // chunk forever, and admitting none would put those
                            // reads back behind the whole scan.
                            for _ in 0..SCAN_YIELD_REQUESTS {
                                match receiver.try_recv() {
                                    Ok(request) => {
                                        serve_read(&reader, request, &mut scans, deadline)
                                    }
                                    // Empty or disconnected: either way there is
                                    // nothing to admit. A disconnect is noticed
                                    // by the outer `recv` once the scans in hand
                                    // have been answered, so their clients still
                                    // get their rows during a shutdown.
                                    Err(_) => break,
                                }
                            }
                            let Some(mut job) = scans.pop_front() else {
                                break;
                            };
                            match advance_scan(&reader, &mut job, deadline) {
                                Some(result) => {
                                    let _ = job.response.send(result);
                                }
                                // Still owed chunks; back of the queue, so
                                // several concurrent scans share the worker.
                                None => scans.push_back(job),
                            }
                        }
                    }
                })
                .expect("failed to start storage reader");
            sender
        })
        .collect()
}

/// Serves one read request, parking a scan for chunked execution.
///
/// Everything except a scan is answered here and now: a point read is one
/// root-to-leaf descent, and chunking it would add bookkeeping to the cheapest
/// path on the server.
fn serve_read(
    reader: &ReadEngine,
    request: ReadRequest,
    scans: &mut std::collections::VecDeque<ScanJob>,
    deadline: Duration,
) {
    match request {
        ReadRequest::Get { key, response } => {
            let _ = response.send(reader.get(&key));
        }
        ReadRequest::MultiGet { keys, response } => {
            let _ = response.send(multi_get(reader, keys, deadline));
        }
        ReadRequest::Scan {
            start,
            end,
            limit,
            response,
        } => scans.push_back(ScanJob {
            from: start,
            skip_resume: false,
            end,
            limit,
            rows: Vec::new(),
            response,
            started: Instant::now(),
        }),
        ReadRequest::IndexLookup {
            index,
            value,
            limit,
            response,
        } => {
            let _ = response.send(reader.lookup_index(&index, &value, limit));
        }
        ReadRequest::Document { request, response } => {
            let _ = response.send(read_document(reader, request));
        }
    }
}

/// Reads every key of a multi-get, abandoning the statement at its deadline.
///
/// A multi-get is up to `MAX_SCAN_LIMIT` independent descents, so it is the
/// other request that can occupy a worker far longer than any single read. It is
/// not chunked — a partially-read multi-get has nothing useful to resume from,
/// since the answer is positional — but the deadline is checked as it goes, so
/// the worker stops rather than finishing 10,000 descents nobody is waiting for.
fn multi_get(
    reader: &ReadEngine,
    keys: Vec<Vec<u8>>,
    deadline: Duration,
) -> std::result::Result<Vec<Option<Vec<u8>>>, ReadFailure> {
    let started = Instant::now();
    let mut values = Vec::with_capacity(keys.len());
    for (position, key) in keys.iter().enumerate() {
        // Checked every so often rather than per key: `Instant::now` is a
        // syscall on some platforms and a point read is fast enough that
        // sampling it 64 keys at a time still bounds the overshoot to
        // milliseconds.
        if position % 64 == 0 && started.elapsed() >= deadline {
            return Err(ReadFailure::DeadlineExceeded);
        }
        values.push(reader.get(key)?);
    }
    Ok(values)
}

/// Reads the next chunk of `job`, returning its answer once it is complete.
///
/// `None` means the scan is unfinished and owes more chunks. The deadline is
/// enforced HERE, between chunks, which is what makes it a bound on how long one
/// statement may occupy a shared worker rather than merely a bound on how long
/// its own client waits.
fn advance_scan(
    reader: &ReadEngine,
    job: &mut ScanJob,
    deadline: Duration,
) -> Option<std::result::Result<Rows, ReadFailure>> {
    if job.started.elapsed() >= deadline {
        /* Answered as a failure with the partial rows discarded. Returning what
         * was collected would be worse than useless: `Rows` carries no "there is
         * more" marker, so a truncated result is indistinguishable from a range
         * that genuinely ended there, and a client would silently process a
         * prefix of its data believing it had all of it. */
        return Some(Err(ReadFailure::DeadlineExceeded));
    }
    // One extra row when resuming, because the chunk restarts AT the last key
    // already collected and drops it again.
    let wanted = (job.limit - job.rows.len()).min(SCAN_CHUNK_ROWS) + usize::from(job.skip_resume);
    let chunk = match reader.scan(job.from.as_deref(), job.end.as_deref(), wanted) {
        Ok(chunk) => chunk,
        Err(error) => return Some(Err(error.into())),
    };
    // Short of what was asked for means the range is exhausted, so this is the
    // last chunk however few rows the limit still allowed.
    let exhausted = chunk.len() < wanted;
    let mut chunk = chunk.into_iter().peekable();
    if job.skip_resume
        && chunk
            .peek()
            .is_some_and(|(key, _)| Some(key) == job.from.as_ref())
    {
        // The row this chunk resumed from, already delivered. The equality check
        // makes the skip depend on what was actually read rather than on the
        // assumption that the tree did not move — true today because the read
        // guard is held across the chunks, and a fact this code should not
        // silently rely on if that ever changes.
        chunk.next();
    }
    job.rows.extend(chunk);
    match job.rows.last() {
        Some((key, _)) => {
            job.from = Some(key.clone());
            job.skip_resume = true;
        }
        // An empty first chunk: the range holds nothing at all.
        None => return Some(Ok(std::mem::take(&mut job.rows))),
    }
    if exhausted || job.rows.len() >= job.limit {
        return Some(Ok(std::mem::take(&mut job.rows)));
    }
    None
}

/// Names why a read request could not be handed to a worker.
///
/// THE MESSAGE THIS FIXES: every dispatch site used to answer "storage reader
/// queue is full" for both `Full` and `Disconnected`. A disconnected queue means
/// the worker THREAD IS GONE — it broke out of its loop on a poisoned handle
/// lock, or it panicked — and that condition never clears, whereas a full queue
/// clears as soon as the worker catches up. Telling an operator the queue is full
/// sends them to look at load and concurrency limits for a fault that is neither:
/// the honest answer is that the reader stopped and the process needs restarting.
/// Distinguishing them costs one match on an error the channel already returns.
fn read_dispatch_error(error: std::sync::mpsc::TrySendError<ReadRequest>) -> Message {
    match error {
        std::sync::mpsc::TrySendError::Full(_) => {
            server_error(ErrorCode::Storage, "storage reader queue is full")
        }
        std::sync::mpsc::TrySendError::Disconnected(_) => server_error(
            ErrorCode::Storage,
            "storage reader stopped; this node cannot serve reads until it is restarted",
        ),
    }
}

/// Turns a read worker's failure into the client's answer.
///
/// A deadline is `InvalidRequest`, not `Storage`: nothing is broken, the
/// statement asked for more of a shared worker than one statement may have, and
/// the fix is in the request — a smaller limit or a narrower range. Classifying
/// it as a storage fault would also route it through the retry logic clients
/// apply to storage errors, so the same oversized scan would be resubmitted.
fn read_failure_message(failure: ReadFailure) -> Message {
    match failure {
        ReadFailure::Storage(error) => storage_error_message(error),
        ReadFailure::DeadlineExceeded => server_error(
            ErrorCode::InvalidRequest,
            "read exceeded its time limit and was abandoned; \
             narrow the range or lower the limit",
        ),
    }
}

async fn submit_get(state: &ServerState, key: Vec<u8>) -> Message {
    let shard = state.shard_for_key(&key);
    /* THE FAST PATH: answer here, on the connection task.
     *
     * A point read against a warm cache is about a microsecond of work, and
     * the queue path wraps it in two cross-thread wakeups, a bounded-channel
     * send, and a oneshot allocation — the engine does under 1% of a served
     * Get; this plumbing was most of the rest. A shared `try_read` never
     * waits: it succeeds alongside other reads (including a scan holding the
     * same handle's guard on its worker thread — reads don't exclude each
     * other) and fails only while a publish or refresh holds the handle
     * exclusively, which is exactly when queueing behind it is correct.
     *
     * Held across the descent, deliberately: the guard is what keeps the
     * root from moving mid-read, the same invariant the worker thread relies
     * on. A cache-miss descent does a handful of positional page reads
     * inline; that is bounded and small, unlike a scan, which is why scans
     * and multi-gets stay on the workers with their deadline machinery. */
    {
        if let Ok(reader) = shard.readers[next_reader(shard)].try_read() {
            return match reader.get(&key) {
                Ok(value) => Message::Value { value },
                Err(error) => storage_error_message(error),
            };
        }
    }
    let (response, receiver) = oneshot::channel();
    if let Err(error) =
        shard.read_queues[next_reader(shard)].try_send(ReadRequest::Get { key, response })
    {
        return read_dispatch_error(error);
    }
    match receiver.await {
        Ok(Ok(value)) => Message::Value { value },
        Ok(Err(error)) => storage_error_message(error),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn submit_multi_get(state: &ServerState, keys: Vec<Vec<u8>>) -> Message {
    if !state.sharded() {
        return multi_get_on(state.lone_shard(), keys).await;
    }
    /* Split by shard, remembering each key's position: the protocol's promise
     * is positional — values[i] answers keys[i] — and the shards return their
     * own subsets in their own order. */
    let mut positions: Vec<Vec<usize>> = vec![Vec::new(); state.shards.len()];
    let mut split: Vec<Vec<Vec<u8>>> = vec![Vec::new(); state.shards.len()];
    let total = keys.len();
    for (at, key) in keys.into_iter().enumerate() {
        let index = state.shard_index_for_key(&key);
        positions[index].push(at);
        split[index].push(key);
    }
    // Dispatched to every involved shard before awaiting any, so the shards
    // work concurrently instead of in sequence.
    let mut pending = Vec::new();
    for (index, keys) in split.into_iter().enumerate() {
        if keys.is_empty() {
            continue;
        }
        let shard = &state.shards[index];
        let (response, receiver) = oneshot::channel();
        if let Err(error) =
            shard.read_queues[next_reader(shard)].try_send(ReadRequest::MultiGet { keys, response })
        {
            return read_dispatch_error(error);
        }
        pending.push((index, receiver));
    }
    let mut values: Vec<Option<Vec<u8>>> = vec![None; total];
    for (index, receiver) in pending {
        match receiver.await {
            Ok(Ok(shard_values)) => {
                for (at, value) in positions[index].iter().zip(shard_values) {
                    values[*at] = value;
                }
            }
            Ok(Err(failure)) => return read_failure_message(failure),
            Err(_) => return server_error(ErrorCode::Storage, "storage reader stopped"),
        }
    }
    Message::Values { values }
}

async fn multi_get_on(shard: &Shard, keys: Vec<Vec<u8>>) -> Message {
    let (response, receiver) = oneshot::channel();
    if let Err(error) =
        shard.read_queues[next_reader(shard)].try_send(ReadRequest::MultiGet { keys, response })
    {
        return read_dispatch_error(error);
    }
    match receiver.await {
        Ok(Ok(values)) => Message::Values { values },
        Ok(Err(failure)) => read_failure_message(failure),
        Err(_) => server_error(ErrorCode::Storage, "storage reader stopped"),
    }
}

async fn submit_scan(
    state: &ServerState,
    start: Option<Vec<u8>>,
    end: Option<Vec<u8>>,
    limit: usize,
) -> Message {
    /* Sharded, a range lives everywhere: every shard scans it and the sorted
     * results merge below. Each shard is asked for the FULL limit because in
     * the worst case one shard holds the entire range. Dispatched to all
     * shards before awaiting any, so they scan concurrently. */
    let mut pending = Vec::with_capacity(state.shards.len());
    for shard in &state.shards {
        let (response, receiver) = oneshot::channel();
        if let Err(error) = shard.read_queues[next_reader(shard)].try_send(ReadRequest::Scan {
            start: start.clone(),
            end: end.clone(),
            limit,
            response,
        }) {
            return read_dispatch_error(error);
        }
        pending.push(receiver);
    }
    let mut per_shard = Vec::with_capacity(state.shards.len());
    for receiver in pending {
        match receiver.await {
            Ok(Ok(rows)) => per_shard.push(rows),
            Ok(Err(failure)) => return read_failure_message(failure),
            Err(_) => return server_error(ErrorCode::Storage, "storage reader stopped"),
        }
    }
    Message::Rows {
        rows: merge_scan_rows(per_shard, limit),
    }
}

/// Merges per-shard scan results — each sorted, keys disjoint across shards
/// because a key lives on exactly one — into one ordered result of at most
/// `limit` rows.
fn merge_scan_rows(mut per_shard: Vec<Rows>, limit: usize) -> Rows {
    if per_shard.len() == 1 {
        // The lone shard's worker already ordered and limited it.
        return per_shard.pop().expect("checked length");
    }
    let mut rows: Rows = per_shard.into_iter().flatten().collect();
    rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    rows.truncate(limit);
    rows
}

/// Dispatches to a reader thread, round-robin across the shard's read handles.
fn next_reader(shard: &Shard) -> usize {
    shard.next_reader.fetch_add(1, Ordering::Relaxed) as usize % shard.read_queues.len()
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

fn document_read_collection(request: &DocumentRead) -> &str {
    match request {
        DocumentRead::Get { collection, .. }
        | DocumentRead::List { collection, .. }
        | DocumentRead::Query { collection, .. } => collection,
    }
}

fn document_write_collection(request: &DocumentWrite) -> &str {
    match request {
        DocumentWrite::CreateCollection { collection, .. }
        | DocumentWrite::Put { collection, .. }
        | DocumentWrite::Delete { collection, .. } => collection,
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
                /* THE LOCK IS NOT HELD ACROSS THE COMPACTION. A checkpoint
                 * rewrites the whole tree — the longest thing this process
                 * does — and holding the write lock across it stalled every
                 * writer for its full duration (measured in the served
                 * head-to-head: hundreds of ops/s where thousands run
                 * between checkpoints). The three-phase split takes the lock
                 * twice, briefly: snapshot, and delta-replay + publish. */
                let job = {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    /* `collect_versions` reports a poisoned shared-snapshot
                     * registry rather than collecting without consulting it,
                     * so the failure propagates here and the loop below takes
                     * readiness down. Swallowing it would collect past a live
                     * transaction's snapshot, which is the one thing the
                     * registry exists to prevent. */
                    let collected = engine.collect_versions()?;
                    if !(due || collected >= checkpoint_versions) {
                        return Ok::<(usize, Option<Duration>), StorageError>((collected, None));
                    }
                    (collected, engine.begin_checkpoint()?)
                };
                let (collected, mut job) = job;
                let started = Instant::now();
                if let Err(error) = job.compact() {
                    job.abandon();
                    return Err(error);
                }
                let finished = {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    engine.finish_checkpoint(job)
                };
                match finished {
                    Ok(()) => Ok((collected, Some(started.elapsed()))),
                    Err(error) => Err(error),
                }
            })
            .await;
            match &result {
                Ok(Ok((collected, Some(elapsed)))) => log_info!(
                    "vyrnd.checkpoint",
                    "checkpoint completed",
                    duration_ms = elapsed.as_millis(),
                    versions_collected = collected,
                    // Which threshold fired: a write-count trigger or the
                    // retained-version one. They point at different workloads.
                    trigger = if due {
                        "write count"
                    } else {
                        "retained versions"
                    }
                ),
                Ok(Ok((collected, None))) => log_debug!(
                    "vyrnd.mvcc_gc",
                    "collected versions without compacting",
                    versions_collected = collected
                ),
                // Both failure paths take readiness down in the loop below, which
                // is where the reason is recorded.
                Ok(Err(_)) | Err(_) => {}
            }
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
                    // A checkpoint absorbed the write-back buffer into the
                    // tree, so the readers' overlay copies may drop everything
                    // the compacted root now carries. Refresh first: eviction
                    // is only sound on a handle already serving that root.
                    let absorbed = engine.write_back_absorbed_through();
                    for reader in readers.iter() {
                        let mut reader = reader.write().map_err(|_| StorageError::Poisoned)?;
                        reader.refresh(new_generation, root, len)?;
                        if let Some(absorbed) = absorbed {
                            reader.evict_write_back_through(absorbed);
                        }
                    }
                    Ok::<_, StorageError>(())
                })
                .await;
                if !matches!(refreshed, Ok(Ok(()))) {
                    withdraw_readiness(&metrics, "mvcc gc reader refresh");
                    return;
                }
            }
            if let Ok(Ok((collected, _))) = result {
                metrics.mvcc_gc_runs.fetch_add(1, Ordering::Relaxed);
                metrics
                    .mvcc_versions_collected
                    .fetch_add(collected as u64, Ordering::Relaxed);
            } else {
                withdraw_readiness(&metrics, "mvcc gc");
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
                withdraw_readiness(&metrics, "wal archive rotate");
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
                        log_error!("vyrnd.wal_archive", "archive tick failed", detail = error);
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
                withdraw_readiness(&metrics, "async sync");
                return;
            }
        }
    });
}

/// Starts the write pipeline under supervision.
///
/// WHY: the pipeline is a single task, and if it dies — a panic today, or
/// an early return some future edit introduces — writes would fail while
/// `/health/ready` kept answering 200 forever. Silence is the worst failure
/// mode a readiness probe exists to catch, so the probe is wired to the
/// worker's survival: an abnormal termination marks storage failed and
/// readiness down exactly like an engine error does, plus stderr.
///
/// RESTART IS DELIBERATELY NOT ATTEMPTED. A batch can be half-way through
/// the pipeline at death: applied to the tree with its WAL record written
/// but not yet flushed or acknowledged, while `in_flight` and
/// `flush_completed` carry barrier accounting shared with the flush stage.
/// A replacement worker cannot know which requests were already applied,
/// so restarting risks answering a client twice for one commit, or
/// stranding later batches behind a barrier nobody will ever complete.
/// A panic here is a bug rather than a transient fault, so the honest
/// behaviour is readiness down and "storage writer stopped" errors until
/// an operator restarts the process, which recovery handles cleanly.
fn start_write_worker(
    engine: Arc<RwLock<Engine>>,
    receiver: mpsc::Receiver<WriteRequest>,
    flushes: mpsc::Sender<PendingFlush>,
    config: WriteWorkerConfig,
) {
    let metrics = Arc::clone(&config.metrics);
    tokio::spawn(async move {
        let pipeline = task::spawn(run_write_pipeline(engine, receiver, flushes, config));
        match pipeline.await {
            /* A clean return happens only when every write sender was
             * dropped, which is process shutdown. The flush-stage-gone exit
             * reports itself inside the pipeline. */
            Ok(()) => {}
            Err(error) => {
                log_error!(
                    "vyrnd.write_worker",
                    "write worker terminated abnormally; writes are unavailable \
                     until the process is restarted",
                    detail = error
                );
                withdraw_readiness(&metrics, "write worker supervisor");
            }
        }
    });
}

async fn run_write_pipeline(
    engine: Arc<RwLock<Engine>>,
    mut receiver: mpsc::Receiver<WriteRequest>,
    flushes: mpsc::Sender<PendingFlush>,
    config: WriteWorkerConfig,
) {
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
        /* Non-data requests are dispatched by MOVING the request out of `first`
         * in one exhaustive match, rather than by pushing it into the batch and
         * popping it back out under a `matches!` guard.
         *
         * The guard-and-pop version needed `unreachable!()` arms to discharge
         * pattern matches the guard had already decided. Each one was a panic in
         * the write pipeline — which takes down writes for EVERY client, not just
         * the request that tripped it — sitting one careless edit away from a new
         * request kind that the guard and the pattern disagreed about. Matching
         * on the value proves the correspondence to the compiler, so a new
         * variant becomes a compile error here instead of a runtime panic.
         *
         * Data requests fall through to the batching path below, carrying the
         * request with them.
         */
        let first = match first {
            /* A document write commits ALONE under the engine write lock, with an
             * immediate barrier, so it is already durable when the blocking task
             * returns. What it must NOT do is broadcast its own changes here: a
             * key/value commit that happened earlier may still be in the flush
             * queue waiting for its `fdatasync`, and publishing from this arm
             * would put the later change on a subscriber's stream first. So the
             * answer and the change records are handed to the flush stage, which
             * is the one ordered publication point. See [`DeferredAnswer`].
             */
            WriteRequest::Document { request, response } => {
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    let outcome = apply_document_write(&mut engine, request);
                    /* Change records are taken ONLY on success. `last_published`
                     * holds whatever the previous successful commit published, and
                     * a document write that fails before reaching the change log —
                     * invalid JSON, an unknown collection, a unique violation —
                     * leaves it untouched. Reading it unconditionally therefore
                     * re-broadcast the PREVIOUS commit's records, delivering them
                     * to every subscriber a second time under a cursor they had
                     * already processed. */
                    let published = match &outcome {
                        Ok(_) => engine.last_published().to_vec(),
                        Err(_) => Vec::new(),
                    };
                    // Same rule as the change records: taken only on success,
                    // or a failed document write would replay the PREVIOUS
                    // commit's mutations onto every read handle a second time.
                    let write_back = match &outcome {
                        Ok(_) => engine.take_write_back_publish(),
                        Err(_) => vyrn_core::WriteBackPublish::default(),
                    };
                    let (generation, root, len) = engine.committed_root();
                    Ok::<_, StorageError>((outcome, published, write_back, generation, root, len))
                })
                .await;
                let (message, published, write_back, generation, root, len) = match result {
                    Ok(Ok((outcome, published, write_back, generation, root, len))) => {
                        match outcome {
                            Ok((message, _)) => {
                                (message, published, write_back, generation, root, len)
                            }
                            /* Nothing committed, so nothing is owed to the ordered
                             * publication point and the client is answered here.
                             * Rendered through `storage_error_message` so the code the
                             * error deserves survives — a unique-index violation stays
                             * `Conflict` rather than becoming a generic storage fault. */
                            Err(error) => {
                                record_storage_error(&config.metrics, "document write", &error);
                                let _ = response.send(Ok(storage_error_message(error)));
                                continue;
                            }
                        }
                    }
                    // The engine lock was poisoned: the write never ran.
                    Ok(Err(error)) => {
                        record_storage_error(&config.metrics, "document write", &error);
                        let _ = response.send(Ok(storage_error_message(error)));
                        continue;
                    }
                    Err(_) => {
                        withdraw_readiness(&config.metrics, "document write task");
                        let _ = response.send(Ok(storage_error_message(StorageError::Poisoned)));
                        continue;
                    }
                };
                // Counted like a batch's barrier, so the flush stage's matching
                // decrement balances and the write worker sees work outstanding.
                config.in_flight.fetch_add(1, Ordering::AcqRel);
                let queued = Instant::now();
                if flushes
                    .send(PendingFlush {
                        // Already durable: this commit took its own barrier, so it
                        // passes through the flush stage purely to be published in
                        // order and must not make the group sync again.
                        lsn: None,
                        requests: Vec::new(),
                        results: Vec::new(),
                        answers: vec![DeferredAnswer { response, message }],
                        published,
                        write_back,
                        generation,
                        root,
                        len,
                        queued,
                    })
                    .await
                    .is_err()
                {
                    config.in_flight.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                continue;
            }
            /* Index changes rewrite the whole index under the engine write lock,
             * so they run alone rather than joining a batch. Both arms are
             * handled here, with the response extracted before the blocking task
             * so the task returns only the result. */
            WriteRequest::CreateIndex {
                name,
                unique,
                response,
            } => {
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    let outcome = engine.create_index(name, unique);
                    // Taken only on success, like a document write's change
                    // records: a refused index change committed nothing and
                    // must publish nothing.
                    let write_back = match &outcome {
                        Ok(()) => engine.take_write_back_publish(),
                        Err(_) => vyrn_core::WriteBackPublish::default(),
                    };
                    let (generation, root, len) = engine.committed_root();
                    Ok::<_, StorageError>((outcome, write_back, generation, root, len))
                })
                .await;
                finish_index_change(&config, &flushes, response, result).await;
                continue;
            }
            WriteRequest::DropIndex { name, response } => {
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    let outcome = engine.drop_index(&name);
                    let write_back = match &outcome {
                        Ok(()) => engine.take_write_back_publish(),
                        Err(_) => vyrn_core::WriteBackPublish::default(),
                    };
                    let (generation, root, len) = engine.committed_root();
                    Ok::<_, StorageError>((outcome, write_back, generation, root, len))
                })
                .await;
                finish_index_change(&config, &flushes, response, result).await;
                continue;
            }
            // Data requests: batched below.
            request @ (WriteRequest::Operation { .. } | WriteRequest::Transaction { .. }) => {
                request
            }
        };
        let mut requests = vec![first];
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
        /* Validate every batched transaction against its own snapshot, and
         * against everything EARLIER IN THIS SAME BATCH already writes, so
         * grouping cannot admit a conflicting pair.
         *
         * WHAT "EARLIER IN THIS BATCH" MEANS, and why position decides. The whole
         * batch becomes one WAL record at one LSN, so no client can observe a
         * state between two of its members. Validation therefore picks the
         * serial order the queue already implies: request `i` is serialized after
         * requests `0..i`. A transaction that read a key an EARLIER member writes
         * read a value that order says it should not have seen, so it is
         * rejected; a transaction that read a key a LATER member writes is fine,
         * because it legitimately precedes that write.
         *
         * TWO HOLES THIS CLOSES, both of which let a conflicting pair commit
         * together:
         *
         *   - PLAIN OPERATIONS WERE INVISIBLE. Only `Transaction` requests
         *     contributed keys, so a bare `Put`/`Delete` batched alongside a
         *     transaction that had READ that key was not a conflict for anybody:
         *     the transaction validated clean against its snapshot (the put was
         *     not committed yet — it is in this very batch) and the put has no
         *     reads of its own to invalidate. Both committed, and the
         *     transaction's write was decided from a value the same commit
         *     overwrote. A plain operation can never be the request that is
         *     rejected — it has no snapshot and no reads — but it must be visible
         *     to the transactions ordered after it.
         *
         *   - INDEX CLAIMS WERE INVISIBLE. A transaction's `index_reads` were
         *     checked against the engine but not against the index entries
         *     earlier members of the batch add or remove, so "look up who holds
         *     this index value, then write based on the answer" — the shape of
         *     every uniqueness check a client performs itself — grouped with the
         *     transaction that changes that answer and both committed.
         *
         * Tracked as `(index, value)` pairs rather than as encoded index entry
         * keys because the encoding is `vyrn-core`'s private business; the pair
         * is what an `index_reads` entry names anyway, so the comparison is
         * direct.
         */
        if requests
            .iter()
            .any(|request| matches!(request, WriteRequest::Transaction { .. }))
        {
            let entries: Vec<_> = requests
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
                    } => Some(BatchEntry::Transaction(TransactionCheck {
                        index,
                        snapshot_sequence: *snapshot_sequence,
                        read_keys: read_keys.clone(),
                        read_ranges: read_ranges.clone(),
                        index_reads: index_reads.clone(),
                        operations: operations.clone(),
                        index_updates: index_updates.clone(),
                    })),
                    WriteRequest::Operation { operation, .. } => Some(BatchEntry::Plain {
                        key: operation_key(operation).to_vec(),
                    }),
                    /* Nothing else can be in a batch — the dispatch match above
                     * `continue`s on every other kind and `drain_writes` parks
                     * them — and if one ever were, contributing no claims is the
                     * safe direction: it cannot mask a conflict, because a
                     * request that reaches the batch responder it does not belong
                     * to is answered with an error rather than applied. */
                    WriteRequest::Document { .. }
                    | WriteRequest::CreateIndex { .. }
                    | WriteRequest::DropIndex { .. } => None,
                })
                .collect();
            let conflict_engine = Arc::clone(&engine);
            let verdict = task::spawn_blocking(move || {
                let engine = conflict_engine.read().map_err(|_| StorageError::Poisoned)?;
                reject_conflicts(&entries, |check| {
                    has_conflict(
                        &engine,
                        check.snapshot_sequence,
                        &check.read_keys,
                        &check.read_ranges,
                        &check.index_reads,
                        &check.operations,
                        &check.index_updates,
                    )
                })
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
                    record_storage_error(&config.metrics, "transaction conflict check", &error);
                    respond_writes(requests, Err(error.to_string()));
                    continue;
                }
                Err(_) => {
                    withdraw_readiness(&config.metrics, "conflict check task");
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
        /* Only data requests reach here — the dispatch match above `continue`s on
         * every other kind, and `drain_writes` parks them in `pending`. An empty
         * contribution rather than a panic if that ever stops holding: a
         * misrouted request then gets an error from `respond_writes` below and
         * the pipeline keeps serving everyone else, where a panic would take
         * writes down for every connected client. */
        let operations: Vec<_> = requests
            .iter()
            .flat_map(|request| match request {
                WriteRequest::Operation { operation, .. } => vec![operation.clone()],
                WriteRequest::Transaction { operations, .. } => operations.clone(),
                WriteRequest::Document { .. }
                | WriteRequest::CreateIndex { .. }
                | WriteRequest::DropIndex { .. } => Vec::new(),
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
            let write_back = engine.take_write_back_publish();
            let (generation, root, len) = engine.committed_root();
            Ok::<_, StorageError>((
                PendingFlush {
                    lsn,
                    requests: Vec::new(),
                    results,
                    // Only a request that committed alone carries one of these; a
                    // batched commit answers through `requests`.
                    answers: Vec::new(),
                    published,
                    write_back,
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
                record_storage_error(&config.metrics, "batch apply", &error);
                respond_writes(requests, Err(error.to_string()));
            }
            Err(_) => {
                withdraw_readiness(&config.metrics, "batch apply task");
                respond_writes(requests, Err("storage writer task failed".into()));
            }
        }
    }
}

/// Answers an index create/drop and records any storage failure.
///
/// Shared by both index arms of the write loop so the two cannot drift: the
/// earlier version handled them in one blocking task and needed an
/// `unreachable!()` arm to name the variant it had already matched on.
/// What an index change's blocking task hands back: the outcome, plus the
/// write-back publication and committed root captured under the same lock,
/// so a successful change can be replayed onto the read handles in order.
type IndexChangeOutcome = (
    vyrn_core::Result<()>,
    vyrn_core::WriteBackPublish,
    u64,
    u64,
    u64,
);

async fn finish_index_change(
    config: &WriteWorkerConfig,
    flushes: &mpsc::Sender<PendingFlush>,
    response: oneshot::Sender<vyrn_core::Result<()>>,
    result: std::result::Result<
        std::result::Result<IndexChangeOutcome, StorageError>,
        task::JoinError,
    >,
) {
    match result {
        Ok(Ok((outcome, write_back, generation, root, len))) => {
            if let Err(error) = &outcome {
                record_storage_error(&config.metrics, "index change", error);
            }
            /* A successful index change committed mutations the read handles'
             * overlay copies have to learn, exactly like a batch's — so they
             * travel the same ordered path, the flush queue. Classic mode
             * skips this (the publication is empty) and keeps its existing
             * behaviour: readers adopt the new root at the next commit.
             * Queued BEFORE the client is answered, mirroring publish-then-
             * answer everywhere else. Already durable — index changes take an
             * immediate barrier — hence `lsn: None`. */
            if outcome.is_ok() && !write_back.is_empty() {
                config.in_flight.fetch_add(1, Ordering::AcqRel);
                if flushes
                    .send(PendingFlush {
                        lsn: None,
                        requests: Vec::new(),
                        results: Vec::new(),
                        answers: Vec::new(),
                        published: Vec::new(),
                        write_back,
                        generation,
                        root,
                        len,
                        queued: Instant::now(),
                    })
                    .await
                    .is_err()
                {
                    config.in_flight.fetch_sub(1, Ordering::AcqRel);
                    let _ = response.send(Err(StorageError::Poisoned));
                    return;
                }
            }
            let _ = response.send(outcome);
        }
        // The engine lock was poisoned, so the request never ran.
        Ok(Err(error)) => {
            record_storage_error(&config.metrics, "index change", &error);
            let _ = response.send(Err(error));
        }
        /* The blocking task itself died. Earlier this left the client waiting on
         * a dropped sender, which surfaces as the generic "storage writer
         * stopped"; answering explicitly keeps the reason attached to the
         * request. */
        Err(_) => {
            withdraw_readiness(&config.metrics, "index change task");
            let _ = response.send(Err(StorageError::Poisoned));
        }
    }
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
                /* TWO BARRIERS, AWAITED TOGETHER.
                 *
                 * The local `fdatasync` and the replicas' acknowledgements are
                 * independent: each side is making the same record durable on its
                 * own storage. Awaiting them concurrently means a commit costs
                 * `max(fsync, rtt)` rather than `fsync + rtt`, which is the
                 * difference between synchronous replication being usable and
                 * being a tax nobody accepts.
                 *
                 * `join!` rather than `select!` — BOTH must complete. Taking the
                 * first to finish is exactly the bug this feature exists to
                 * prevent: it would acknowledge a write whose replica copy had
                 * not landed.
                 *
                 * When replication is disabled `await_quorum` returns
                 * immediately, so this is the previous single-node path with one
                 * extra ready future.
                 */
                let replication = Arc::clone(&config.replication);
                let (synced, quorum) = tokio::join!(
                    task::spawn_blocking(move || wal_handle.sync_through(lsn)),
                    replication.await_quorum(lsn),
                );
                let error = match synced {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => {
                        record_storage_error(&config.metrics, "WAL flush", &error);
                        Some(error.to_string())
                    }
                    Err(_) => {
                        withdraw_readiness(&config.metrics, "wal flush task");
                        Some("WAL flush task failed".into())
                    }
                };
                /* A local sync failure outranks a quorum failure: if this node's
                 * own storage is broken, that is the more urgent fact and the
                 * more specific message. Only report the quorum problem when the
                 * local write actually succeeded.
                 *
                 * WHAT A QUORUM FAILURE MEANS FOR THE DATA — measured, not
                 * assumed. On timeout the client gets an error, but the record is
                 * already in the WAL and already applied to the tree, so:
                 *
                 *   - it SURVIVES a restart. Verified: a write rejected with
                 *     "quorum not reached" was readable after reopening the
                 *     directory.
                 *   - it is NOT visible to readers until some later commit
                 *     succeeds, because `publish_commit` below is skipped on the
                 *     error path and the read engines never refresh onto this
                 *     batch's generation.
                 *
                 * That combination is deliberate but genuinely surprising, so the
                 * error message says exactly it: durable here, not replicated.
                 * Rolling the record back instead would mean un-writing a
                 * committed WAL entry, which is a far more dangerous operation
                 * than reporting the truth. The client can retry; a re-put of the
                 * same key is idempotent.
                 *
                 * docs/replication.md must state this, or an operator will read
                 * "write failed" as "write did not happen".
                 */
                let error = error.or_else(|| quorum.err().map(|failure| failure.to_string()));
                if let Some(message) = error {
                    let covered = batch.len() as u64;
                    for flush in batch {
                        /* A document write coalesced into this group is answered
                         * too, even though its own barrier already succeeded: it
                         * is NOT published, because the ordered publication point
                         * below is skipped, so reporting success would tell a
                         * client to expect its change on a feed that never carried
                         * it. Every request in a failed group gets the same answer
                         * for the same reason. */
                        fail_commit(flush.requests, flush.answers, &message);
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
            let mut remaining = batch.into_iter();
            for flush in remaining.by_ref() {
                if !publish_commit(&config, flush) {
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
            /* ANSWER THE REST OF THE GROUP, rather than dropping it.
             *
             * The publish stage failed part-way through a coalesced group. Every
             * batch here already crossed the same barrier as the one that failed,
             * so their records are durable — but they have not been published to
             * the read engines, and this worker is about to stop.
             *
             * Dropping them was the bug: a `PendingFlush` owns its requests, and
             * each request owns the oneshot sender its client is waiting on.
             * Dropping the struct closed those channels, so the client saw the
             * generic "storage writer died" that a closed channel produces — the
             * least informative answer available, for a write that is in fact on
             * disk and will be there after a restart.
             *
             * The message says exactly that instead. It is still an error: the
             * commit is not visible to readers yet, so reporting success would be
             * a lie in the other direction. `publish_commit` has already answered
             * the batch it failed on, which is why this drains what is left
             * rather than the whole group.
             */
            for flush in remaining {
                fail_commit(
                    flush.requests,
                    flush.answers,
                    "write is durable but was not published: \
                     the storage writer stopped before readers were refreshed; \
                     it is readable after a restart",
                );
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
/// THE ONE ORDERED PUBLICATION POINT. Every change this server broadcasts goes
/// through here, and this runs on the flush stage, which takes batches strictly
/// in the order the single write pipeline produced them. That is what makes a
/// subscriber's stream commit-ordered: commit order is queue order, and queue
/// order is the order of the `ChangeRing::send` calls below.
///
/// Document writes reach here already durable (they took their own barrier) and
/// carry their answers in `answers`; batched key/value commits carry theirs in
/// `requests`. Both are answered after the same broadcast, so no client is told
/// its write succeeded before the change it produced has been published.
///
/// Returns false when storage has failed and the flush stage must stop.
///
/// Takes the whole [`PendingFlush`] rather than its fields: everything here needs
/// them together, and destructuring at the boundary means adding one more piece of
/// per-commit state cannot silently miss a call site.
fn publish_commit(config: &FlushWorkerConfig, flush: PendingFlush) -> bool {
    let PendingFlush {
        requests,
        results,
        answers,
        published,
        write_back,
        generation,
        root,
        len,
        ..
    } = flush;
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
                /* The write-back half of the publication, under the SAME
                 * guard as the refresh so a read on this handle sees the
                 * commit entirely or not at all. Root first, mutations
                 * second, matters: the publication's absorb watermark may
                 * evict overlay entries, which is only sound once the tree
                 * this handle serves provably contains them. A failure here
                 * is as fatal as a refresh failure — a handle that missed a
                 * commit's mutations would lag the log forever. */
                if let Err(error) = reader.publish_write_back(&write_back) {
                    refresh_error = Some(error);
                    break;
                }
            }
            Err(_) => {
                withdraw_readiness(&config.metrics, "reader lock poisoned");
                fail_commit(requests, answers, "storage reader lock poisoned");
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
            record_storage_error(&config.metrics, "reader refresh", &error);
            fail_commit(requests, answers, &error.to_string());
            return false;
        }
    }
    // Broadcast the records the commit actually published, so a live cursor
    // always matches a durable one.
    for record in published {
        config.changes.send(ChangeEvent {
            sequence: record.sequence,
            key: record.key,
            value: record.value,
            cursor: Some(change_log::Cursor::new(record.sequence, record.index)),
            // The ring sets this if it has to shed the payload.
            elided: false,
        });
    }
    respond_writes(requests, Ok(results));
    // Answered after the broadcast, like the batched requests above: a client
    // must never learn its write committed before the change it produced is on
    // the feed, or it can read its own write's absence from a subscription.
    for answer in answers {
        let _ = answer.response.send(Ok(answer.message));
    }
    true
}

/// Fails everything one flush was carrying, whatever kind of request it was.
///
/// Both kinds have to be answered from every failure path: a `oneshot` sender
/// dropped without a send tells its client only that the channel closed, which is
/// the least informative answer available for a write whose fate this stage
/// actually knows.
fn fail_commit(requests: Vec<WriteRequest>, answers: Vec<DeferredAnswer>, message: &str) {
    respond_writes(requests, Err(message.to_owned()));
    for answer in answers {
        let _ = answer.response.send(Err(message.to_owned()));
    }
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

/// Answer for a request that reached the batch responder it does not belong to.
///
/// A routing bug rather than a storage fault, so it says so instead of borrowing
/// `Poisoned`'s "reopen the database to recover", which would send an operator
/// looking for damage that does not exist. Answering at all is the point: the
/// sender is owned here, and dropping it would leave the client waiting for its
/// connection to time out. See the arms below for why this is not a panic.
const MISROUTED_REQUEST: &str =
    "request reached the wrong stage of the write pipeline and was not applied; \
     this is a server routing bug — retrying is safe";

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
                    /* Not expected: this function answers batched data requests,
                     * and every other kind is dispatched before batching. If one
                     * arrives anyway it is answered with an error instead of
                     * panicking — the panic would run inside the write pipeline
                     * and stop writes for every client, to report a routing bug
                     * that affects one request. Dropping the request silently is
                     * not an option either: its sender is owned here, so the
                     * client would block until its connection timed out. */
                    WriteRequest::Document { response, .. } => {
                        let _ = response.send(Err(MISROUTED_REQUEST.to_owned()));
                    }
                    WriteRequest::CreateIndex { response, .. }
                    | WriteRequest::DropIndex { response, .. } => {
                        let _ = response.send(Err(StorageError::Poisoned));
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
                    // See the matching arms above: answered, not panicked.
                    WriteRequest::Document { response, .. } => {
                        let _ = response.send(Err(MISROUTED_REQUEST.to_owned()));
                    }
                    WriteRequest::CreateIndex { response, .. }
                    | WriteRequest::DropIndex { response, .. } => {
                        let _ = response.send(Err(StorageError::Poisoned));
                    }
                    WriteRequest::Transaction { response, .. } => {
                        let _ = response.send(Err(message.clone()));
                    }
                }
            }
        }
    }
}

/// Decides which transactions in one batch must be rejected, returning their
/// positions in the batch.
///
/// THE BATCH-LOCAL HALF OF SERIALIZABILITY. `against_engine` answers "did anything
/// COMMITTED invalidate this transaction"; this function answers the question that
/// check cannot see — "did anything EARLIER IN THIS SAME BATCH invalidate it" —
/// and the two together are what make grouping safe.
///
/// The whole batch becomes one WAL record at one LSN, so no client can observe a
/// state between two of its members. Validation therefore adopts the serial order
/// the queue already implies: entry `i` is serialized after entries `0..i`. A
/// transaction that read something an EARLIER entry writes read a value that order
/// says it could not have seen, and is rejected; one that read something a LATER
/// entry writes is fine, because it legitimately precedes that write.
///
/// Split out of the pipeline as a pure function over the batch so it can be tested
/// without spawning a server and racing two clients into the same batch — the
/// grouping window is a timing property, and a test that has to win a race to
/// reach the code under test is a test that passes when the code is broken.
/// `against_engine` is injected for the same reason.
fn reject_conflicts(
    entries: &[BatchEntry],
    mut against_engine: impl FnMut(&TransactionCheck) -> vyrn_core::Result<bool>,
) -> vyrn_core::Result<Vec<usize>> {
    let mut rejected = Vec::new();
    // Hash sets rather than lists: scanning every earlier write for each read key
    // made validation quadratic in batch size, which capped transaction
    // throughput as queue depth grew.
    let mut committed_keys: HashSet<Vec<u8>> = HashSet::new();
    let mut committed_index_values: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
    for entry in entries {
        let check = match entry {
            /* A plain operation joins the committed set unconditionally and is
             * never a rejection candidate: it has no snapshot and read nothing, so
             * nothing can have invalidated it. Being VISIBLE is its whole role
             * here, and its absence was the hole — a batch was validated as if
             * bare puts and deletes were not in it. */
            BatchEntry::Plain { key } => {
                committed_keys.insert(key.clone());
                continue;
            }
            BatchEntry::Transaction(check) => check,
        };
        let overlaps_batch = check
            .read_keys
            .iter()
            .any(|key| committed_keys.contains(key))
            || check
                .index_reads
                .iter()
                .any(|read| committed_index_values.contains(read))
            /* Ranges are checked against the batch's own writes for the same
             * reason they are checked against the engine: a key appearing inside
             * a scanned range is a phantom whether the write that created it is
             * already committed or merely earlier in this batch. The committed
             * keys are iterated per range rather than the reverse because a
             * transaction has a handful of ranges at most, while the batch's key
             * set is the larger side. */
            || check.read_ranges.iter().any(|(start, end)| {
                committed_keys.iter().any(|key| {
                    start.as_ref().is_none_or(|start| key >= start)
                        && end.as_ref().is_none_or(|end| key < end)
                })
            });
        if overlaps_batch || against_engine(check)? {
            rejected.push(check.index);
            // Deliberately contributes nothing: a rejected transaction does not
            // commit, so its writes must not invalidate the ones ordered after it.
            continue;
        }
        committed_keys.extend(check.operations.iter().map(|op| operation_key(op).to_vec()));
        for update in &check.index_updates {
            // The primary key too: `has_conflict` treats an index update as
            // touching it, so the batch-local check has to agree or the two
            // disagree about what counts as a write.
            committed_keys.insert(update.primary_key.clone());
            /* BOTH sides of a move. Removing a primary key from one index value
             * and adding it to another changes the answer to a lookup of either,
             * so a transaction that read either value is stale. */
            for value in [&update.old_value, &update.new_value].into_iter().flatten() {
                committed_index_values.insert((update.index.clone(), value.clone()));
            }
        }
    }
    Ok(rejected)
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

/// Marks storage failed, takes readiness down, and says why.
///
/// The two stores always moved together, at thirteen sites, and not one of them
/// recorded a reason. So `/health/ready` began answering 503 and the process
/// offered no account of which background task had died — the single hardest
/// state to diagnose in this server, because every counter keeps its last value
/// and the log stayed silent. `reason` names the site.
///
/// `record_storage_error` handles the case where a `StorageError` is in hand;
/// this is for the ones where there is no error to report, only a task that
/// cannot continue — a `JoinError` from a panicked worker, or a poisoned lock.
fn withdraw_readiness(metrics: &Metrics, reason: &str) {
    metrics.storage_failed.store(true, Ordering::Release);
    metrics.ready.store(false, Ordering::Release);
    log_error!(
        "vyrnd",
        "readiness withdrawn; this node has stopped serving",
        reason = reason
    );
}

/// Counts a storage failure, withdraws readiness when it is one, and logs it.
///
/// `operation` names the path that failed. It is worth the parameter: nine call
/// sites funnel through here, and "storage operation failed" without a subject
/// tells an operator only that something broke somewhere in the engine.
///
/// LOGGED HERE RATHER THAN AT THE CALL SITES, for the reason the logging exists
/// at all: `docs/production.md` tells an operator to act when a storage error is
/// logged, and until now nothing logged one. Every path that records a storage
/// failure already passes through this function, so putting the record here makes
/// that promise true everywhere at once and keeps a future call site from
/// silently opting out of it.
///
/// The severity split matches the readiness split rather than inventing a second
/// judgement. `Poisoned` and `Io` mean this node's storage is broken and it has
/// stopped serving, which is an operator's problem now; anything else is a single
/// failed operation on a server that is still healthy, which is a warning.
fn record_storage_error(metrics: &Metrics, operation: &str, error: &StorageError) {
    metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
    if matches!(error, StorageError::Poisoned | StorageError::Io(_)) {
        metrics.storage_failed.store(true, Ordering::Release);
        metrics.ready.store(false, Ordering::Release);
        log_error!(
            "vyrnd.storage",
            "storage failure; readiness withdrawn",
            operation = operation,
            detail = error
        );
    } else {
        log_warn!(
            "vyrnd.storage",
            "storage operation failed",
            operation = operation,
            detail = error
        );
    }
}

async fn serve_admin(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    replication: Arc<replication::Replication>,
    engine: Arc<RwLock<Engine>>,
    shards: usize,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let metrics = Arc::clone(&metrics);
        let replication = Arc::clone(&replication);
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            let mut request = [0; 2048];
            let Ok(count) = timeout(Duration::from_secs(5), stream.read(&mut request)).await else {
                return;
            };
            let Ok(count) = count else { return };
            let line = String::from_utf8_lossy(&request[..count]);
            let path = line.split_whitespace().nth(1).unwrap_or("/");
            /* READINESS INCLUDES REPLICATION. A primary that cannot reach its
             * configured quorum is up but cannot honour the durability it
             * promises, so it must not be sent traffic — that is exactly what a
             * readiness probe is for. Liveness is deliberately left alone: the
             * process is healthy and must not be restarted, since restarting it
             * cannot bring a replica back. */
            let quorum_ok = !replication.quorum_failing();
            let ready = metrics.ready.load(Ordering::Acquire)
                && !metrics.storage_failed.load(Ordering::Acquire)
                && quorum_ok;
            let (status, content_type, body) = match path {
                "/health/live" => ("200 OK", "text/plain", "ok\n".to_owned()),
                "/health/ready" if ready => ("200 OK", "text/plain", "ready\n".to_owned()),
                "/health/ready" => ("503 Service Unavailable", "text/plain", "not ready\n".to_owned()),
                "/metrics" => (
                    "200 OK",
                    "text/plain; version=0.0.4",
                    format!(
                        "vyrn_ready {}\nvyrn_shards {shards}\nvyrn_storage_failed {}\nvyrn_active_connections {}\nvyrn_requests_total {}\nvyrn_requests_failed_total {}\nvyrn_reads_total {}\nvyrn_writes_total {}\nvyrn_checkpoints_total {}\nvyrn_write_batches_total {}\nvyrn_batched_writes_total {}\nvyrn_wal_flushes_total {}\nvyrn_flushed_batches_total {}\nvyrn_mvcc_gc_runs_total {}\nvyrn_mvcc_versions_collected_total {}\nvyrn_wal_archive_lag_segments {}\nvyrn_wal_archived_total {}\nvyrn_wal_archive_failures_total {}\nvyrn_auth_failures_total {}\nvyrn_active_transaction_snapshots {}\nvyrn_commit_batches_total {}\nvyrn_commit_requests_total {}\n{}",
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
                        metrics.auth_failures_total.load(Ordering::Relaxed),
                        metrics.active_transaction_snapshots.load(Ordering::Relaxed),
                        metrics.write_profile.batches.load(Ordering::Relaxed),
                        metrics.write_profile.requests.load(Ordering::Relaxed),
                        metrics.write_profile.render(),
                    ) + &render_replication(&replication, &engine),
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

/// Replication gauges and counters, in Prometheus text format.
///
/// Lag is reported in LSNs rather than bytes: an LSN is one commit, which is the
/// unit an operator reasons about ("we are 40 commits behind"), and byte lag
/// would vary with value size for identical replication health.
///
/// `vyrn_replication_max_lag_lsn` is the number to alert on — with several
/// replicas, the worst one is what determines whether a quorum can be met.
fn render_replication(
    replication: &Arc<replication::Replication>,
    engine: &Arc<RwLock<Engine>>,
) -> String {
    let last_lsn = engine.read().map(|engine| engine.last_lsn()).unwrap_or(0);
    let lag = replication.lag(last_lsn);
    let max_lag = lag.iter().map(|(_, lag)| *lag).max().unwrap_or(0);
    let metrics = &replication.metrics;
    format!(
        "vyrn_replication_enabled {}\n\
         vyrn_replication_min_acks {}\n\
         vyrn_replicas_connected {}\n\
         vyrn_replication_quorum_failing {}\n\
         vyrn_replication_max_lag_lsn {}\n\
         vyrn_replication_last_lsn {}\n\
         vyrn_replication_ack_waits_total {}\n\
         vyrn_replication_ack_timeouts_total {}\n\
         vyrn_replication_records_shipped_total {}\n\
         vyrn_replication_dropped_replicas_total {}\n",
        u8::from(replication.enabled()),
        replication.min_acks(),
        replication.connected(),
        u8::from(replication.quorum_failing()),
        max_lag,
        last_lsn,
        metrics.ack_waits.load(Ordering::Relaxed),
        metrics.ack_timeouts.load(Ordering::Relaxed),
        metrics.records_shipped.load(Ordering::Relaxed),
        metrics.dropped_replicas.load(Ordering::Relaxed),
    )
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
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    /// A transaction check that has read `read_keys` and writes `writes`.
    ///
    /// `snapshot_sequence` is irrelevant to these tests: they pass an
    /// `against_engine` that always answers false, isolating the batch-local half
    /// of validation, which is the half the grouping bugs were in.
    fn check(
        index: usize,
        read_keys: &[&[u8]],
        writes: &[&[u8]],
        index_reads: &[(&[u8], &[u8])],
        index_updates: Vec<IndexUpdate>,
    ) -> BatchEntry {
        BatchEntry::Transaction(TransactionCheck {
            index,
            snapshot_sequence: 0,
            read_keys: read_keys.iter().map(|key| key.to_vec()).collect(),
            read_ranges: Vec::new(),
            index_reads: index_reads
                .iter()
                .map(|(index, value)| (index.to_vec(), value.to_vec()))
                .collect(),
            operations: writes
                .iter()
                .map(|key| BatchOperation::Put(key.to_vec(), b"v".to_vec()))
                .collect(),
            index_updates,
        })
    }

    /// Validation with the engine check stubbed out to "nothing committed".
    fn rejected(entries: &[BatchEntry]) -> Vec<usize> {
        reject_conflicts(entries, |_| Ok(false)).expect("validation should not fail")
    }

    /* THE HOLE THIS CLOSES: a bare `Put`/`Delete` batched with a transaction that
     * had READ that key was invisible to validation. The transaction validated
     * clean against its snapshot — the put is in this very batch, not yet
     * committed — and the put has no reads of its own, so neither was rejected.
     * Both committed, and the transaction's write was decided from a value the
     * same commit overwrote: write skew created purely by grouping.
     *
     * A unit test rather than two racing clients: whether two requests land in one
     * batch is a timing property of an idle server's accumulation window, so an
     * integration test would have to win a race to reach this code at all — and
     * would pass, quietly, whenever it lost. */
    #[test]
    fn a_plain_write_earlier_in_the_batch_conflicts_with_a_transaction_that_read_it() {
        let entries = vec![
            BatchEntry::Plain {
                key: b"balance".to_vec(),
            },
            check(1, &[b"balance"], &[b"withdrawal"], &[], Vec::new()),
        ];
        assert_eq!(
            rejected(&entries),
            vec![1],
            "a transaction that read a key a plain write earlier in its own batch \
             overwrites must be rejected; admitting both is write skew that only \
             grouping created"
        );
    }

    /// The mirror case, which is what stops the fix from being "reject everything":
    /// a plain write ORDERED AFTER the transaction invalidates nothing, because the
    /// transaction legitimately precedes it in the batch's serial order.
    #[test]
    fn a_plain_write_later_in_the_batch_does_not_conflict() {
        let entries = vec![
            check(0, &[b"balance"], &[b"withdrawal"], &[], Vec::new()),
            BatchEntry::Plain {
                key: b"balance".to_vec(),
            },
        ];
        assert!(
            rejected(&entries).is_empty(),
            "a transaction serialized BEFORE a plain write in the same batch is legal; \
             rejecting it would fail commits that have no conflict"
        );
    }

    /* THE SECOND HOLE: index claims. A client's own uniqueness check is "look up
     * who holds this value, then write based on the answer", and two transactions
     * doing that concurrently must not both commit. Index reads were checked
     * against the engine but not against the index entries earlier members of the
     * same batch add or remove, so grouped they both passed. */
    #[test]
    fn an_index_claim_earlier_in_the_batch_conflicts_with_a_lookup_of_that_value() {
        let claim = IndexUpdate {
            index: b"email".to_vec(),
            primary_key: b"users/first".to_vec(),
            old_value: None,
            new_value: Some(b"a@example.com".to_vec()),
        };
        let entries = vec![
            check(0, &[], &[b"users/first"], &[], vec![claim]),
            check(
                1,
                &[],
                &[b"users/second"],
                &[(b"email", b"a@example.com")],
                Vec::new(),
            ),
        ];
        assert_eq!(
            rejected(&entries),
            vec![1],
            "a transaction that looked up an index value another member of its batch \
             claims must be rejected, or the uniqueness it verified is violated by the \
             pair of them"
        );
    }

    /// Both sides of a move, because removing a primary key from one index value
    /// changes the answer to a lookup of THAT value just as much as adding it
    /// changes the answer for the new one.
    #[test]
    fn vacating_an_index_value_conflicts_with_a_lookup_of_the_old_value() {
        let move_away = IndexUpdate {
            index: b"email".to_vec(),
            primary_key: b"users/first".to_vec(),
            old_value: Some(b"old@example.com".to_vec()),
            new_value: Some(b"new@example.com".to_vec()),
        };
        let entries = vec![
            check(0, &[], &[b"users/first"], &[], vec![move_away]),
            check(
                1,
                &[],
                &[b"audit"],
                &[(b"email", b"old@example.com")],
                Vec::new(),
            ),
        ];
        assert_eq!(
            rejected(&entries),
            vec![1],
            "a lookup of the index value an earlier batch member VACATED is stale too; \
             only checking the new value would miss half of every move"
        );
    }

    /// An index read of an untouched value must still pass, or the check would
    /// reject every transaction that consults any index at all.
    #[test]
    fn an_index_lookup_of_an_untouched_value_does_not_conflict() {
        let claim = IndexUpdate {
            index: b"email".to_vec(),
            primary_key: b"users/first".to_vec(),
            old_value: None,
            new_value: Some(b"a@example.com".to_vec()),
        };
        let entries = vec![
            check(0, &[], &[b"users/first"], &[], vec![claim]),
            check(
                1,
                &[],
                &[b"audit"],
                &[(b"email", b"someone-else@example.com")],
                Vec::new(),
            ),
        ];
        assert!(
            rejected(&entries).is_empty(),
            "an index lookup of a value nothing in the batch touched is not a conflict"
        );
    }

    /// A rejected transaction must not invalidate the ones after it: it does not
    /// commit, so its writes never happen and cannot have been read.
    #[test]
    fn a_rejected_transaction_does_not_reject_the_ones_after_it() {
        let entries = vec![
            BatchEntry::Plain {
                key: b"balance".to_vec(),
            },
            // Rejected: read a key the plain write above overwrites.
            check(1, &[b"balance"], &[b"doomed"], &[], Vec::new()),
            // Reads only what the rejected transaction would have written.
            check(2, &[b"doomed"], &[b"fine"], &[], Vec::new()),
        ];
        assert_eq!(
            rejected(&entries),
            vec![1],
            "a transaction reading a key that only a REJECTED transaction would have \
             written must commit: that write never happened"
        );
    }

    /// A scanned range is checked against the batch's own writes, because a key
    /// appearing inside it is a phantom whether the write that created it is
    /// already committed or merely earlier in the same batch.
    #[test]
    fn a_batch_write_inside_a_scanned_range_is_a_phantom() {
        let mut inside = check(1, &[], &[b"audit"], &[], Vec::new());
        if let BatchEntry::Transaction(check) = &mut inside {
            check.read_ranges = vec![(Some(b"users/".to_vec()), Some(b"users0".to_vec()))];
        }
        let entries = vec![
            BatchEntry::Plain {
                key: b"users/new".to_vec(),
            },
            inside,
        ];
        assert_eq!(
            rejected(&entries),
            vec![1],
            "a key written earlier in the batch inside a range this transaction \
             scanned is a phantom and must be caught"
        );

        // And a write OUTSIDE the range is not.
        let mut outside = check(1, &[], &[b"audit"], &[], Vec::new());
        if let BatchEntry::Transaction(check) = &mut outside {
            check.read_ranges = vec![(Some(b"users/".to_vec()), Some(b"users0".to_vec()))];
        }
        let entries = vec![
            BatchEntry::Plain {
                key: b"accounts/new".to_vec(),
            },
            outside,
        ];
        assert!(
            rejected(&entries).is_empty(),
            "a write outside every scanned range is not a phantom"
        );
    }

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

    /// A one-shard server state around an already-open engine, enough for the
    /// transaction path. The write channel's receiver is dropped — these tests
    /// never commit through the queue.
    fn transaction_test_state(engine: Engine) -> Arc<ServerState> {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let (writes, _closed) = mpsc::channel(1);
        let salt = SaltString::from_b64("dGVzdHNhbHQ").unwrap();
        let hash = argon2::Argon2::default()
            .hash_password(b"pw", &salt)
            .unwrap()
            .serialize();
        Arc::new(ServerState {
            shards: vec![Shard {
                writes,
                changes: Arc::new(ChangeRing::new(4)),
                read_queues: Vec::new(),
                readers: Arc::new(Vec::new()),
                next_reader: AtomicU64::new(0),
                engine: Arc::new(RwLock::new(engine)),
                wal_directory: PathBuf::new(),
            }],
            auth: Arc::new(auth::Authenticator::single("vyrn".into(), hash)),
            audit: None,
            database: "default".into(),
            auth_limit: Arc::new(Semaphore::new(1)),
            auth_throttle: Arc::new(AuthThrottle::new()),
            write_budget: Arc::new(Semaphore::new(WRITE_QUEUE_MAX_BYTES)),
            transaction_timeout: Duration::from_secs(30),
            metrics: Arc::new(Metrics::default()),
            replication: replication::Replication::new(0, Duration::from_secs(1)),
            read_only: false,
            failover: None,
        })
    }

    #[tokio::test]
    async fn transaction_reads_persisted_snapshot_and_its_writes() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"old".to_vec()).unwrap();
        engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
        let sequence = engine.register_snapshot();
        engine.put(b"a".to_vec(), b"current".to_vec()).unwrap();
        let state = transaction_test_state(engine);
        let mut transaction = ConnectionTransaction {
            sequences: vec![sequence],
            shard: None,
            started: tokio::time::Instant::now(),
            read_keys: BTreeMap::new(),
            read_ranges: Vec::new(),
            index_reads: Vec::new(),
            writes: BTreeMap::new(),
            index_updates: Vec::new(),
        };
        assert_eq!(
            execute_transaction(
                &state,
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
                &state,
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
                &state,
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
                &state,
                &mut transaction,
                Message::Delete { key: b"b".to_vec() }
            )
            .await,
            Message::Deleted { existed: true }
        );
        assert_eq!(
            execute_transaction(
                &state,
                &mut transaction,
                Message::Get { key: b"b".to_vec() }
            )
            .await,
            Message::Value { value: None }
        );
        assert_eq!(
            execute_transaction(
                &state,
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
