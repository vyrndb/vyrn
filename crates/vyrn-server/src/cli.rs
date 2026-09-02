//! Command-line and environment configuration for the server.

use clap::Parser;
use std::path::PathBuf;

use crate::DEFAULT_STATEMENT_DEADLINE_MS;

#[derive(Parser)]
#[command(name = "vyrnd", version, about = "Vyrn database server")]
pub(crate) struct Args {
    #[arg(long, env = "VYRN_BIND", default_value = "127.0.0.1:7432")]
    pub(crate) bind: String,
    #[arg(long, env = "VYRN_DATA", default_value = "./data")]
    pub(crate) data: PathBuf,
    #[arg(long, env = "VYRN_USERNAME", default_value = "vyrn")]
    pub(crate) username: String,
    /// Single-credential mode: one Argon2id verifier for `--username`, with
    /// every permission. Mutually exclusive with `--users-file`.
    #[arg(long, env = "VYRN_PASSWORD_HASH_FILE")]
    pub(crate) password_hash_file: Option<PathBuf>,
    /// Per-user accounts with prefix ACLs; see docs/security.md for the JSON
    /// format. Re-checked on every authentication attempt, so edits (adding,
    /// removing, or re-scoping a user) need no restart. Mutually exclusive
    /// with `--password-hash-file`.
    #[arg(long, env = "VYRN_USERS_FILE")]
    pub(crate) users_file: Option<PathBuf>,
    /// Append-only audit trail; unset disables it. Reads are included only
    /// when `VYRN_AUDIT_READS=1`.
    #[arg(long, env = "VYRN_AUDIT_LOG")]
    pub(crate) audit_log: Option<PathBuf>,
    #[arg(long, env = "VYRN_DATABASE", default_value = "default")]
    pub(crate) database: String,
    #[arg(long, env = "VYRN_TLS_CERT_FILE", requires = "tls_key_file")]
    pub(crate) tls_cert_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_TLS_KEY_FILE", requires = "tls_cert_file")]
    pub(crate) tls_key_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_ALLOW_PLAINTEXT", default_value_t = false)]
    pub(crate) allow_plaintext: bool,
    #[arg(long, env = "VYRN_MAX_CONNECTIONS", default_value_t = 1024)]
    pub(crate) max_connections: usize,
    #[arg(long, env = "VYRN_MAX_AUTH_JOBS", default_value_t = 8)]
    pub(crate) max_auth_jobs: usize,
    #[arg(long, env = "VYRN_CHECKPOINT_WRITES", default_value_t = 10_000)]
    pub(crate) checkpoint_writes: u64,
    #[arg(long, env = "VYRN_ADMIN_BIND", default_value = "127.0.0.1:7433")]
    pub(crate) admin_bind: String,
    #[arg(long, env = "VYRN_SHUTDOWN_TIMEOUT_SECONDS", default_value_t = 30)]
    pub(crate) shutdown_timeout_seconds: u64,
    #[arg(long, env = "VYRN_WRITE_BATCH_SIZE", default_value_t = 64)]
    pub(crate) write_batch_size: usize,
    #[arg(long, env = "VYRN_WRITE_BATCH_DELAY_US", default_value_t = 200)]
    pub(crate) write_batch_delay_us: u64,
    #[arg(long, env = "VYRN_WRITE_QUEUE_CAPACITY", default_value_t = 4096)]
    pub(crate) write_queue_capacity: usize,
    #[arg(long, env = "VYRN_DURABILITY", default_value = "durable")]
    pub(crate) durability: String,
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
    pub(crate) write_back_bytes: usize,
    #[arg(long, env = "VYRN_ASYNC_SYNC_MS", default_value_t = 5)]
    pub(crate) async_sync_ms: u64,
    #[arg(long, env = "VYRN_TRANSACTION_TIMEOUT_SECONDS", default_value_t = 30)]
    pub(crate) transaction_timeout_seconds: u64,
    #[arg(long, env = "VYRN_READ_HANDLES", default_value_t = 16)]
    pub(crate) read_handles: usize,
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
    pub(crate) statement_deadline_ms: u64,
    #[arg(long, env = "VYRN_MVCC_GC_MS", default_value_t = 1_000)]
    pub(crate) mvcc_gc_ms: u64,
    #[arg(
        long,
        env = "VYRN_MVCC_GC_CHECKPOINT_VERSIONS",
        default_value_t = 10_000
    )]
    pub(crate) mvcc_gc_checkpoint_versions: usize,
    #[arg(long, env = "VYRN_WAL_ARCHIVE_DIR")]
    pub(crate) wal_archive_dir: Option<PathBuf>,
    #[arg(long, env = "VYRN_WAL_ARCHIVE_INTERVAL_MS", default_value_t = 5_000)]
    pub(crate) wal_archive_interval_ms: u64,
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
    pub(crate) replication_min_acks: usize,
    /// How long a commit waits for replica acknowledgements before failing.
    ///
    /// Bounded on purpose: an unbounded wait turns one unreachable replica into a
    /// hung database. On timeout the write fails with an error saying it is
    /// durable locally but not replicated, which is the honest outcome — the
    /// alternative, acknowledging it anyway, silently voids the guarantee the
    /// operator asked for.
    #[arg(long, env = "VYRN_REPLICATION_ACK_TIMEOUT_MS", default_value_t = 5_000)]
    pub(crate) replication_ack_timeout_ms: u64,
    /// Run as a replica of this primary, e.g. `vyrn://repl@primary:7432/default`.
    ///
    /// One binary serves both roles deliberately: promotion then needs no
    /// different image, only a restart without this flag.
    ///
    /// A replica still serves reads on `--bind`, but writes from clients are
    /// refused — its log must contain only what the primary sent, or the two
    /// histories diverge and it can never be promoted.
    #[arg(long, env = "VYRN_REPLICA_OF")]
    pub(crate) replica_of: Option<String>,
    /// File holding the password used to authenticate to the primary.
    ///
    /// A file rather than a flag so the secret does not appear in `ps` output or
    /// shell history.
    #[arg(long, env = "VYRN_REPLICA_PASSWORD_FILE", requires = "replica_of")]
    pub(crate) replica_password_file: Option<PathBuf>,
    /// CA certificate used to verify the primary's TLS certificate.
    #[arg(long, env = "VYRN_REPLICA_CA_FILE", requires = "replica_of")]
    pub(crate) replica_ca_file: Option<PathBuf>,
    /// Name for this replica in the primary's logs and metrics.
    #[arg(long, env = "VYRN_REPLICA_ID", requires = "replica_of")]
    pub(crate) replica_id: Option<String>,
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
    pub(crate) replica_wal_archive_dir: Option<PathBuf>,
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
    pub(crate) cluster: Option<String>,
    /// This member's name in `--cluster`.
    #[arg(long, env = "VYRN_CLUSTER_SELF", requires = "cluster")]
    pub(crate) cluster_self: Option<String>,
    /// How long a primary may go without holding its quorum before it
    /// self-fences (refuses writes as deposed).
    #[arg(long, env = "VYRN_FAILOVER_LEASE_MS", default_value_t = 3_000)]
    pub(crate) failover_lease_ms: u64,
    /// How long a follower waits without hearing from a primary before
    /// standing for election. Jittered per member to avoid split votes.
    #[arg(long, env = "VYRN_FAILOVER_ELECTION_MS", default_value_t = 6_000)]
    pub(crate) failover_election_ms: u64,
    /// Number of independent shards, each a full engine with its own write
    /// lock, WAL, and group commit — the write path parallelizes across
    /// them. 1 (the default) is byte-identical to the unsharded server.
    ///
    /// Fixed at creation: the count is recorded in a SHARDS marker file and
    /// a mismatch refuses startup, because key placement depends on it.
    /// Sharded mode restricts cross-shard atomicity — see the Sharding
    /// section of docs/production.md before enabling it.
    #[arg(long, env = "VYRN_SHARDS", default_value_t = 1)]
    pub(crate) shards: usize,
}
