//! Server metrics: counters, histograms, and per-stage write profiling.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

pub(crate) struct Metrics {
    pub(crate) ready: AtomicBool,
    pub(crate) active_connections: AtomicU64,
    pub(crate) total_requests: AtomicU64,
    pub(crate) failed_requests: AtomicU64,
    pub(crate) reads: AtomicU64,
    pub(crate) writes: AtomicU64,
    pub(crate) checkpoints: AtomicU64,
    pub(crate) write_batches: AtomicU64,
    pub(crate) batched_writes: AtomicU64,
    /// WAL barriers actually issued, and applied batches they covered. The ratio
    /// is how much group commit is amortising the sync.
    pub(crate) wal_flushes: AtomicU64,
    pub(crate) flushed_batches: AtomicU64,
    pub(crate) mvcc_versions_collected: AtomicU64,
    pub(crate) mvcc_gc_runs: AtomicU64,
    /// Where a durable commit spends its time, stage by stage.
    pub(crate) write_profile: WriteProfile,
    /// Sealed segments the archiver has not copied out yet (gauge). Growth
    /// means the archiver is falling behind the write rate.
    pub(crate) wal_archive_lag_segments: AtomicU64,
    pub(crate) wal_archived_total: AtomicU64,
    pub(crate) wal_archive_failures_total: AtomicU64,
    /// Every rejected authentication, including throttle refusals that never
    /// reached the password check. A rising rate here is the signal that someone
    /// is guessing; without it a lockout is invisible to operators.
    pub(crate) auth_failures_total: AtomicU64,
    /// Engine snapshots currently pinned by open client transactions (gauge).
    ///
    /// The MVCC floor is the minimum over live snapshots, so a pin that is never
    /// released stops version collection for the rest of the process's life. That
    /// failure is otherwise invisible — throughput and error rates stay normal
    /// while history grows without bound — so the count is published: if this
    /// does not return to zero on an idle server, a pin has leaked.
    pub(crate) active_transaction_snapshots: AtomicU64,
    pub(crate) storage_failed: AtomicBool,
    pub(crate) drained: Notify,
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
pub(crate) struct Histogram {
    pub(crate) buckets: [AtomicU64; Self::BUCKETS],
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
    pub(crate) const BUCKETS: usize = 160;

    /// The first octave whose values are wide enough to subdivide. Below it each
    /// nanosecond value is its own bucket, which costs nothing and keeps the
    /// index arithmetic total.
    const FLAT: u32 = 2;

    pub(crate) fn index(nanoseconds: u64) -> usize {
        let octave = 63 - nanoseconds.max(1).leading_zeros();
        if octave < Self::FLAT {
            return nanoseconds as usize;
        }
        let sub = (nanoseconds >> (octave - Self::FLAT)) & 3;
        ((octave * 4 + sub as u32) as usize).min(Self::BUCKETS - 1)
    }

    /// The inclusive lower bound of `index`, used to place a quantile.
    pub(crate) fn lower_bound(index: usize) -> u64 {
        let octave = index as u32 / 4;
        if octave < Self::FLAT {
            return index as u64;
        }
        let sub = index as u64 % 4;
        (4 + sub) << (octave - Self::FLAT)
    }

    pub(crate) fn record(&self, elapsed: Duration) {
        self.buckets[Self::index(elapsed.as_nanos() as u64)].fetch_add(1, Ordering::Relaxed);
    }

    /// The value at `permille`, taken as the midpoint of the bucket it lands in.
    pub(crate) fn quantile(&self, permille: u64) -> u64 {
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
pub(crate) struct WriteProfile {
    pub(crate) batches: AtomicU64,
    pub(crate) requests: AtomicU64,
    /// Client enqueue until the batch it joined stopped accumulating.
    pub(crate) front: Stage,
    /// Batch closed until the engine write lock is held: the `spawn_blocking`
    /// hop plus contention with readers, checkpoints, and the previous batch.
    pub(crate) lock: Stage,
    /// Inside `write_batch_deferred`: change log, pre-state read, tree apply,
    /// MVCC prepare, WAL encode and append.
    pub(crate) apply: Stage,
    /// Handed to the flush stage until that stage begins this batch's barrier.
    pub(crate) flush_queue: Stage,
    /// The `fdatasync` itself, including its `spawn_blocking` hop.
    pub(crate) sync: Stage,
    /// Durable until answered: reader refresh, change broadcast, response send.
    pub(crate) publish: Stage,
}

impl WriteProfile {
    pub(crate) fn stages(&self) -> [(&'static str, &Stage); 6] {
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
    pub(crate) fn render(&self) -> String {
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
pub(crate) struct Stage {
    pub(crate) total: AtomicU64,
    pub(crate) latency: Histogram,
}

impl Stage {
    pub(crate) fn record(&self, elapsed: Duration) {
        self.total
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        self.latency.record(elapsed);
    }
}

pub(crate) struct ConnectionGuard(pub(crate) Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.0.active_connections.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_waiters();
        }
    }
}
