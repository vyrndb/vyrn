mod replica;
mod replication;

use anyhow::{bail, Context, Result};
use argon2::{password_hash::PasswordHashString, Argon2, PasswordVerifier};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
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
        } => {
            collection.len() + indexes.iter().map(|index| index.field.len()).sum::<usize>()
        }
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
    changes: Arc<ChangeRing>,
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
    /// Per-address failed-authentication throttle; see [`AuthThrottle`].
    auth_throttle: Arc<AuthThrottle>,
    /// Bytes of pending write payload allowed in the pipeline; see
    /// [`WRITE_QUEUE_MAX_BYTES`].
    write_budget: Arc<Semaphore>,
    changes: Arc<ChangeRing>,
    read_queues: Vec<std::sync::mpsc::SyncSender<ReadRequest>>,
    next_reader: AtomicU64,
    engine: Arc<RwLock<Engine>>,
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

    /* Replication state is built before the engine so the record sink exists for
     * the very first commit. A record that slipped through before the sink was
     * attached would be a silent hole in the replica's log. */
    let replication = replication::Replication::new(
        args.replication_min_acks,
        Duration::from_millis(args.replication_ack_timeout_ms),
    );
    if replication.enabled() {
        eprintln!(
            "synchronous replication enabled: {} acknowledgement(s) required, {}ms timeout",
            args.replication_min_acks, args.replication_ack_timeout_ms
        );
    }
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

    let engine = Engine::open_with_options(
        &args.data,
        EngineOptions {
            durability,
            archived_through: archived_through.clone(),
            record_sink,
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
    let read_queues = start_read_workers(&readers, args.write_queue_capacity);
    let engine = Arc::new(RwLock::new(engine));
    let (write_sender, write_receiver) = mpsc::channel(args.write_queue_capacity);
    let change_sender = Arc::new(ChangeRing::new(args.write_queue_capacity));
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
            changes: Arc::clone(&change_sender),
            metrics: Arc::clone(&metrics),
            engine: Arc::clone(&engine),
            in_flight: Arc::clone(&in_flight),
            flush_completed: flush_completed.clone(),
            replication: Arc::clone(&replication),
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
            changes: Arc::clone(&change_sender),
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
        auth_throttle: Arc::new(AuthThrottle::new()),
        write_budget: Arc::new(Semaphore::new(WRITE_QUEUE_MAX_BYTES)),
        changes: change_sender,
        read_queues,
        next_reader: AtomicU64::new(0),
        engine: Arc::clone(&engine),
        transaction_timeout: Duration::from_secs(args.transaction_timeout_seconds),
        metrics: Arc::clone(&metrics),
        replication: Arc::clone(&replication),
        read_only: args.replica_of.is_some(),
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
        let replica_engine = Arc::clone(&engine);
        let config = replica::ReplicaConfig {
            primary_url,
            password,
            ca_file: args.replica_ca_file.clone(),
            replica_id,
            allow_plaintext: args.allow_plaintext,
            readers: Arc::clone(&readers),
        };
        tokio::spawn(async move {
            if let Err(error) = replica::run(replica_engine, config).await {
                // Fatal replica errors are divergence, which retrying cannot fix.
                eprintln!("replication stopped: {error:#}");
            }
        });
    }

    let admin_metrics = Arc::clone(&metrics);
    let admin_replication = Arc::clone(&replication);
    let admin_engine = Arc::clone(&engine);
    tokio::spawn(async move {
        serve_admin(
            admin_listener,
            admin_metrics,
            admin_replication,
            admin_engine,
        )
        .await
    });
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
                    if let Err(error) =
                        handle_connection(stream, tls_acceptor, state, peer.ip()).await
                    {
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
        let _ = timeout(Duration::from_secs(args.shutdown_timeout_seconds), drained).await;
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
    let sync_engine = Arc::clone(&engine);
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
            eprintln!("failed to sync storage on shutdown: {error}");
            bail!("shutdown could not make acknowledged writes durable: {error}");
        }
        Err(error) => {
            eprintln!("storage sync task failed on shutdown: {error}");
            bail!("shutdown could not make acknowledged writes durable");
        }
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
    let authenticated = if state.auth_throttle.is_locked_out(peer) {
        false
    } else {
        match first.message {
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
        }
    };
    if !authenticated {
        /* Counted before the response is written, so a rejection is recorded even
         * if the peer has already gone away and the write fails. */
        state
            .metrics
            .auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
        state.auth_throttle.record_failure(peer);
        send_error(
            &mut framed,
            first.request_id,
            ErrorCode::AuthenticationFailed,
            "authentication failed",
        )
        .await?;
        return Ok(());
    }
    state.auth_throttle.record_success(peer);
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
    let session = run_session(framed, Arc::clone(&state), &mut transaction).await;
    if let Some(transaction) = transaction {
        release_transaction_snapshot(&state, transaction.sequence).await;
    }
    session
}

/// Serves authenticated requests until the connection ends.
///
/// Takes the transaction by `&mut` rather than owning it so that
/// `handle_connection` still sees an in-progress transaction after any exit
/// from here and can release its snapshot pin. See the comment at the call site.
async fn run_session(
    mut framed: Framed<BoxedTransport, VyrnCodec>,
    state: Arc<ServerState>,
    transaction: &mut Option<ConnectionTransaction>,
) -> Result<()> {
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
            /* A replica converts its authenticated connection into a replication
             * stream. Placed before the ordinary request arms because from here
             * on the connection is a one-way record feed plus acknowledgements,
             * not a request/response channel.
             *
             * `transaction.is_none()` guard: a connection mid-transaction has
             * pinned engine state, and turning it into a stream would leak that.
             */
            Message::ReplicaHello {
                database,
                last_lsn,
                replica_id,
            } if transaction.is_none() => {
                if database != state.database {
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
                        .engine
                        .read()
                        .map(|engine| engine.last_lsn())
                        .unwrap_or(0);
                    match replication::decide_join(last_lsn, primary_lsn) {
                        replication::JoinDecision::Refuse(reason) => {
                            eprintln!(
                                "refused replica {replica_id:?} at LSN {last_lsn}: {reason}"
                            );
                            framed
                                .send(Envelope::new(
                                    request_id,
                                    Message::ReplicaDiverged { reason },
                                ))
                                .await?;
                            return Ok(());
                        }
                        replication::JoinDecision::Stream { first_lsn } => {
                            eprintln!(
                                "replica {replica_id:?} joined at LSN {first_lsn} \
                                 (primary at {primary_lsn})"
                            );
                            framed
                                .send(Envelope::new(
                                    request_id,
                                    Message::ReplicaStream { first_lsn },
                                ))
                                .await?;
                            stream_records(
                                &mut framed,
                                &state.replication,
                                first_lsn,
                                &replica_id,
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
                        *transaction = Some(ConnectionTransaction {
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
        send_frame(&mut framed, Envelope::new(request_id, response)).await?;
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
    let sequence = task::spawn_blocking(move || {
        let engine = engine.read().map_err(|_| StorageError::Poisoned)?;
        Ok::<_, StorageError>(engine.register_snapshot_shared())
    })
    .await
    .map_err(|_| "snapshot registration task failed".to_owned())?
    .map_err(|error| error.to_string())?;
    // Counted only once the pin actually exists, so a failed registration cannot
    // inflate the gauge that is used to detect leaks.
    state
        .metrics
        .active_transaction_snapshots
        .fetch_add(1, Ordering::Relaxed);
    Ok(sequence)
}

/// Releases a transaction's snapshot.
///
/// Version collection is deliberately left to the background MVCC task: running
/// a full history sweep here would put an O(retained versions) scan under the
/// write lock on every single commit.
async fn release_transaction_snapshot(state: &ServerState, sequence: u64) {
    let engine = Arc::clone(&state.engine);
    let released = task::spawn_blocking(move || {
        if let Ok(engine) = engine.read() {
            engine.release_snapshot_shared(sequence);
            true
        } else {
            false
        }
    })
    .await;
    /* Decremented only when the pin was really dropped. A poisoned lock leaves
     * the snapshot pinned, and the gauge should keep saying so — that is exactly
     * the state an operator needs to see, and hiding it would defeat the purpose
     * of publishing the number. */
    if matches!(released, Ok(true)) {
        let _ = state
            .metrics
            .active_transaction_snapshots
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                // Saturating: a double release would otherwise wrap the gauge to
                // u64::MAX and look like a catastrophic leak.
                Some(count.saturating_sub(1))
            });
    }
}

/// Feeds WAL records to a replica and collects its acknowledgements.
///
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
) -> Result<()> {
    let (id, mut records) = replication.register();
    let result = stream_records_inner(framed, replication, &mut records, first_lsn, id).await;
    // Always, on every exit path.
    replication.deregister(id);
    match &result {
        Ok(()) => eprintln!("replica {replica_id:?} stream ended"),
        Err(error) => eprintln!("replica {replica_id:?} stream failed: {error}"),
    }
    result
}

async fn stream_records_inner(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    replication: &Arc<replication::Replication>,
    records: &mut broadcast::Receiver<replication::Shipment>,
    first_lsn: u64,
    id: u64,
) -> Result<()> {
    loop {
        tokio::select! {
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
                    eprintln!("dropping replica stream: {reason}");
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
                        eprintln!("replica reported divergence: {reason}");
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
                if change.key.starts_with(&prefix) {
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
                if change.key.starts_with(&prefix) {
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
    if state.read_only && mutates_storage(&request) {
        state.metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
        return server_error(
            ErrorCode::InvalidRequest,
            "this node is a replica and does not accept writes; \
             send writes to the primary, or promote this node by restarting it \
             without --replica-of",
        );
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
    let _budget = WriteBudget::acquire(&state.write_budget, document_write_bytes(&request)).await;
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
    // Held until this request has been answered; see `WriteBudget`.
    let _budget = WriteBudget::acquire(&state.write_budget, operation_bytes(&operation)).await;
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
    let operations: Vec<_> = transaction
        .writes
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
                eprintln!(
                    "write worker terminated abnormally: {error}; \
                     writes are unavailable until the process is restarted"
                );
                metrics.storage_failed.store(true, Ordering::Release);
                metrics.ready.store(false, Ordering::Release);
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
            WriteRequest::Document { request, response } => {
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
                            config.changes.send(ChangeEvent {
                                sequence: record.sequence,
                                key: record.key,
                                value: record.value,
                                cursor: Some(change_log::Cursor::new(
                                    record.sequence,
                                    record.index,
                                )),
                                // The ring sets this if it has to shed the payload.
                                elided: false,
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
                    Ok::<_, StorageError>(engine.create_index(name, unique))
                })
                .await;
                finish_index_change(&config, response, result);
                continue;
            }
            WriteRequest::DropIndex { name, response } => {
                let engine = Arc::clone(&engine);
                let result = task::spawn_blocking(move || {
                    let mut engine = engine.write().map_err(|_| StorageError::Poisoned)?;
                    Ok::<_, StorageError>(engine.drop_index(&name))
                })
                .await;
                finish_index_change(&config, response, result);
                continue;
            }
            // Data requests: batched below.
            request @ (WriteRequest::Operation { .. } | WriteRequest::Transaction { .. }) => request,
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
}

/// Answers an index create/drop and records any storage failure.
///
/// Shared by both index arms of the write loop so the two cannot drift: the
/// earlier version handled them in one blocking task and needed an
/// `unreachable!()` arm to name the variant it had already matched on.
fn finish_index_change(
    config: &WriteWorkerConfig,
    response: oneshot::Sender<vyrn_core::Result<()>>,
    result: std::result::Result<
        std::result::Result<vyrn_core::Result<()>, StorageError>,
        task::JoinError,
    >,
) {
    match result {
        Ok(Ok(outcome)) => {
            if let Err(error) = &outcome {
                record_storage_error(&config.metrics, error);
            }
            let _ = response.send(outcome);
        }
        // The engine lock was poisoned, so the request never ran.
        Ok(Err(error)) => {
            record_storage_error(&config.metrics, &error);
            let _ = response.send(Err(error));
        }
        /* The blocking task itself died. Earlier this left the client waiting on
         * a dropped sender, which surfaces as the generic "storage writer
         * stopped"; answering explicitly keeps the reason attached to the
         * request. */
        Err(_) => {
            config.metrics.storage_failed.store(true, Ordering::Release);
            config.metrics.ready.store(false, Ordering::Release);
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
                        record_storage_error(&config.metrics, &error);
                        Some(error.to_string())
                    }
                    Err(_) => {
                        config.metrics.storage_failed.store(true, Ordering::Release);
                        config.metrics.ready.store(false, Ordering::Release);
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
            let mut remaining = batch.into_iter();
            for flush in remaining.by_ref() {
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
                respond_writes(
                    flush.requests,
                    Err("write is durable but was not published: \
                         the storage writer stopped before readers were refreshed; \
                         it is readable after a restart"
                        .into()),
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
                    /* Not expected: this function answers batched data requests,
                     * and every other kind is dispatched before batching. If one
                     * arrives anyway it is answered with an error instead of
                     * panicking — the panic would run inside the write pipeline
                     * and stop writes for every client, to report a routing bug
                     * that affects one request. Dropping the request silently is
                     * not an option either: its sender is owned here, so the
                     * client would block until its connection timed out. */
                    WriteRequest::Document { response, .. } => {
                        let _ = response.send(Err(StorageError::Poisoned));
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
                        let _ = response.send(Err(StorageError::Poisoned));
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

async fn serve_admin(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    replication: Arc<replication::Replication>,
    engine: Arc<RwLock<Engine>>,
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
                        "vyrn_ready {}\nvyrn_storage_failed {}\nvyrn_active_connections {}\nvyrn_requests_total {}\nvyrn_requests_failed_total {}\nvyrn_reads_total {}\nvyrn_writes_total {}\nvyrn_checkpoints_total {}\nvyrn_write_batches_total {}\nvyrn_batched_writes_total {}\nvyrn_wal_flushes_total {}\nvyrn_flushed_batches_total {}\nvyrn_mvcc_gc_runs_total {}\nvyrn_mvcc_versions_collected_total {}\nvyrn_wal_archive_lag_segments {}\nvyrn_wal_archived_total {}\nvyrn_wal_archive_failures_total {}\nvyrn_auth_failures_total {}\nvyrn_active_transaction_snapshots {}\nvyrn_commit_batches_total {}\nvyrn_commit_requests_total {}\n{}",
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
        Err(_) => bail!(
            "peer stopped reading; response write exceeded {RESPONSE_WRITE_TIMEOUT:?}"
        ),
    }
}

async fn send_error(
    framed: &mut Framed<BoxedTransport, VyrnCodec>,
    request_id: u64,
    code: ErrorCode,
    message: &str,
) -> Result<()> {
    send_frame(framed, Envelope::new(request_id, server_error(code, message))).await
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
