//! Primary-side replication: fan records out to replicas, and wait for their
//! acknowledgements before a commit is answered.
//!
//! THE GUARANTEE. With `--replication-min-acks N` where N >= 1, a write is
//! acknowledged to its client only after the record is durable on this node AND
//! on at least N replicas. Losing this node therefore cannot lose an
//! acknowledged write, because at least N other nodes hold it on their own
//! storage.
//!
//! WHAT THIS COSTS. One network round trip on the write path. The local
//! `fdatasync` and the replica acknowledgement are awaited CONCURRENTLY, so the
//! added latency is `max(local_fsync, network_rtt) - local_fsync`, not the sum.
//! On a LAN where an fsync outweighs an RTT the difference is small; over a WAN
//! it is not, and that is a deployment decision rather than something to hide.
//!
//! WHAT IT DOES NOT DO. There is no leader election and no automatic failover.
//! Promotion is an operator action. A quorum that cannot be met blocks writes
//! and fails readiness rather than silently degrading to asynchronous
//! replication — a "synchronous" mode that quietly stops waiting is how systems
//! lose data they promised to keep.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{broadcast, watch};
use vyrn_core::RecordSink;

/// How many records a replica may fall behind before its stream is dropped.
///
/// A replica that stops reading must not be able to grow the primary's memory
/// without bound. Dropping it is safe: it reconnects and resumes from its own
/// last LSN, closing the gap from the WAL archive if the records have since been
/// pruned.
const STREAM_BACKLOG: usize = 8_192;

/// A record on its way to the replicas.
#[derive(Clone)]
pub struct Shipment {
    pub lsn: u64,
    /// The WAL record itself. `Arc` so fanning out to N replicas clones a
    /// pointer rather than the bytes.
    pub bytes: Arc<Vec<u8>>,
}

/// One connected replica's acknowledgement watermark.
#[derive(Debug)]
struct Replica {
    /// Highest LSN this replica reports durable on its own storage.
    durable_lsn: AtomicU64,
}

/// Shared replication state for the primary.
#[derive(Debug)]
pub struct Replication {
    /// Acknowledgements required before a commit is answered. 0 disables
    /// replication entirely, leaving the single-node write path untouched.
    min_acks: usize,
    /// How long to wait for those acknowledgements before failing the write.
    ack_timeout: Duration,
    replicas: Mutex<HashMap<u64, Arc<Replica>>>,
    next_replica: AtomicU64,
    /// Bumped whenever a watermark moves or the replica set changes, so a waiter
    /// re-evaluates instead of polling.
    progress: watch::Sender<u64>,
    /// Live record stream. New subscribers see records from their join point on;
    /// anything earlier comes from the WAL archive.
    stream: broadcast::Sender<Shipment>,
    /// Set when a quorum wait has timed out, so readiness can report it.
    quorum_failing: AtomicBool,
    pub metrics: ReplicationMetrics,
}

#[derive(Debug, Default)]
pub struct ReplicationMetrics {
    pub ack_waits: AtomicU64,
    pub ack_timeouts: AtomicU64,
    pub records_shipped: AtomicU64,
    pub dropped_replicas: AtomicU64,
}

/// Why a commit could not be acknowledged.
#[derive(Debug)]
pub enum QuorumError {
    /// The wait exceeded `ack_timeout`.
    ///
    /// The record IS durable locally; what failed is the promise that a replica
    /// also holds it. Reported as an error rather than a success because the
    /// client asked for a guarantee this node could not provide.
    Timeout {
        required: usize,
        achieved: usize,
        waited: Duration,
    },
}

impl std::fmt::Display for QuorumError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout {
                required,
                achieved,
                waited,
            } => write!(
                formatter,
                "replication quorum not reached after {waited:?}: {achieved} of {required} \
                 replicas acknowledged. The write is durable on this node but is NOT \
                 replicated; it may be lost if this node fails."
            ),
        }
    }
}

impl Replication {
    pub fn new(min_acks: usize, ack_timeout: Duration) -> Arc<Self> {
        let (progress, _) = watch::channel(0);
        let (stream, _) = broadcast::channel(STREAM_BACKLOG);
        Arc::new(Self {
            min_acks,
            ack_timeout,
            replicas: Mutex::new(HashMap::new()),
            next_replica: AtomicU64::new(1),
            progress,
            stream,
            quorum_failing: AtomicBool::new(false),
            metrics: ReplicationMetrics::default(),
        })
    }

    pub fn enabled(&self) -> bool {
        self.min_acks > 0
    }

    pub fn min_acks(&self) -> usize {
        self.min_acks
    }

    /// Replicas currently connected, whatever their lag.
    pub fn connected(&self) -> usize {
        self.replicas.lock().map(|map| map.len()).unwrap_or(0)
    }

    /// True once a quorum wait has timed out, until one succeeds again.
    ///
    /// Readiness reads this: a primary that cannot meet its configured
    /// durability is not ready to serve, even though it is still up.
    pub fn quorum_failing(&self) -> bool {
        self.quorum_failing.load(Ordering::Acquire)
    }

    /// Highest LSN acknowledged by at least `min_acks` replicas.
    ///
    /// Nth-highest watermark, not the maximum: with `min_acks = 2` and replicas
    /// at 90 and 100, only 90 is held by two nodes. Taking the maximum here would
    /// acknowledge a commit that exists on one replica while claiming two.
    fn quorum_lsn(&self) -> u64 {
        let Ok(replicas) = self.replicas.lock() else {
            return 0;
        };
        if replicas.len() < self.min_acks {
            return 0;
        }
        let mut watermarks: Vec<u64> = replicas
            .values()
            .map(|replica| replica.durable_lsn.load(Ordering::Acquire))
            .collect();
        watermarks.sort_unstable_by(|a, b| b.cmp(a));
        watermarks
            .get(self.min_acks - 1)
            .copied()
            .unwrap_or_default()
    }

    /// Registers a replica, returning its id and a live record stream.
    pub fn register(&self) -> (u64, broadcast::Receiver<Shipment>) {
        let id = self.next_replica.fetch_add(1, Ordering::Relaxed);
        // Subscribe BEFORE inserting, so no record shipped between the two is
        // missed by this receiver.
        let receiver = self.stream.subscribe();
        if let Ok(mut replicas) = self.replicas.lock() {
            replicas.insert(
                id,
                Arc::new(Replica {
                    durable_lsn: AtomicU64::new(0),
                }),
            );
        }
        // A new replica can complete a quorum that waiters are blocked on.
        self.progress.send_modify(|generation| *generation += 1);
        (id, receiver)
    }

    pub fn deregister(&self, id: u64) {
        if let Ok(mut replicas) = self.replicas.lock() {
            replicas.remove(&id);
        }
        self.metrics.dropped_replicas.fetch_add(1, Ordering::Relaxed);
        // Wake waiters: losing a replica cannot complete a quorum, but it can
        // make one permanently unreachable, and a waiter should find that out now
        // rather than at its timeout.
        self.progress.send_modify(|generation| *generation += 1);
    }

    /// Records a replica's durable watermark.
    ///
    /// `fetch_max` rather than a store: acknowledgements can arrive out of order
    /// across a reconnect, and a watermark must never move backwards or a commit
    /// already acknowledged to a client would appear unreplicated.
    pub fn acknowledge(&self, id: u64, durable_lsn: u64) {
        let replica = self
            .replicas
            .lock()
            .ok()
            .and_then(|replicas| replicas.get(&id).cloned());
        if let Some(replica) = replica {
            replica.durable_lsn.fetch_max(durable_lsn, Ordering::AcqRel);
            self.progress.send_modify(|generation| *generation += 1);
        }
    }

    /// Waits until `lsn` is acknowledged by a quorum.
    ///
    /// Called from the flush worker, concurrently with the local `fdatasync`.
    pub async fn await_quorum(&self, lsn: u64) -> Result<(), QuorumError> {
        if !self.enabled() {
            return Ok(());
        }
        self.metrics.ack_waits.fetch_add(1, Ordering::Relaxed);

        let started = std::time::Instant::now();
        let mut progress = self.progress.subscribe();
        loop {
            if self.quorum_lsn() >= lsn {
                // Clear the failing flag only on success, so readiness recovers
                // as soon as replication does.
                self.quorum_failing.store(false, Ordering::Release);
                return Ok(());
            }
            let remaining = self.ack_timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                self.metrics.ack_timeouts.fetch_add(1, Ordering::Relaxed);
                self.quorum_failing.store(true, Ordering::Release);
                return Err(QuorumError::Timeout {
                    required: self.min_acks,
                    achieved: self.acked_at_least(lsn),
                    waited: started.elapsed(),
                });
            }
            // `changed()` resolves on the next notification; the timeout bounds
            // the wait so a silent replica cannot hang the write forever.
            if tokio::time::timeout(remaining, progress.changed())
                .await
                .is_err()
            {
                continue;
            }
        }
    }

    /// How many replicas hold `lsn`, for diagnostics only.
    fn acked_at_least(&self, lsn: u64) -> usize {
        self.replicas
            .lock()
            .map(|replicas| {
                replicas
                    .values()
                    .filter(|replica| replica.durable_lsn.load(Ordering::Acquire) >= lsn)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Per-replica lag against `last_lsn`, for metrics.
    pub fn lag(&self, last_lsn: u64) -> Vec<(u64, u64)> {
        self.replicas
            .lock()
            .map(|replicas| {
                replicas
                    .iter()
                    .map(|(id, replica)| {
                        let durable = replica.durable_lsn.load(Ordering::Acquire);
                        (*id, last_lsn.saturating_sub(durable))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The [`RecordSink`] the engine calls as it appends.
///
/// Deliberately thin: this runs with the engine's write lock held, so it does no
/// I/O and never blocks. `broadcast::send` copies an `Arc` into each subscriber's
/// queue and returns; a full or absent queue is not an error here.
#[derive(Debug)]
pub struct ReplicationSink {
    replication: Arc<Replication>,
}

impl ReplicationSink {
    pub fn new(replication: Arc<Replication>) -> Self {
        Self { replication }
    }
}

impl RecordSink for ReplicationSink {
    fn record(&self, lsn: u64, record: &[u8]) {
        // `send` errors only when there are no subscribers, which is the normal
        // state of a primary with no replicas attached. The quorum wait is what
        // notices a missing replica; failing the commit here would make the
        // primary's own durability depend on someone listening.
        let _ = self.replication.stream.send(Shipment {
            lsn,
            bytes: Arc::new(record.to_vec()),
        });
        self.replication
            .metrics
            .records_shipped
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// What the primary must decide when a replica says hello.
///
/// Returned rather than acted on so this stays testable without a socket: the
/// caller owns the connection, this owns the policy.
pub enum JoinDecision {
    /// Stream live records starting at `first_lsn`.
    Stream { first_lsn: u64 },
    /// Refuse: the histories cannot be joined by streaming.
    Refuse(String),
}

/// Decides whether a replica at `replica_lsn` can join a primary at `primary_lsn`.
///
/// The gap case is the interesting one. A replica behind the primary is normal
/// and streaming closes the gap — but only if the primary still HOLDS those
/// records. Live records are broadcast from the point of subscription, so a
/// replica that is behind by more than the broadcast buffer cannot be caught up
/// by streaming alone and must replay from the WAL archive first.
///
/// This function deliberately does not consult the archive: whether the archive
/// can serve a given LSN is an I/O question, and answering it here would put
/// filesystem access on the connection-accept path. The replica is told what it
/// needs and asks for it.
pub fn decide_join(replica_lsn: u64, primary_lsn: u64) -> JoinDecision {
    // Ahead of the primary: unreachable by streaming, and appending the
    // primary's next record would rewrite this replica's history.
    if replica_lsn > primary_lsn {
        return JoinDecision::Refuse(format!(
            "replica is at LSN {replica_lsn} but this primary is only at {primary_lsn}; \
             streaming cannot reconcile this. Rebuild the replica from a base backup."
        ));
    }
    JoinDecision::Stream {
        first_lsn: replica_lsn.saturating_add(1),
    }
}

impl Replication {
    /// The broadcast backlog, so a caller can explain a lag failure in terms of
    /// the actual limit rather than a magic number.
    pub const fn backlog() -> usize {
        STREAM_BACKLOG
    }
}
