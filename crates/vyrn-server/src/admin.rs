//! The admin listener: health, readiness, and the metrics endpoint.

use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use vyrn_core::{Engine, Error as StorageError};
use vyrn_log::{log_error, log_warn};

use crate::metrics::Metrics;
use crate::replication;

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
pub(crate) fn withdraw_readiness(metrics: &Metrics, reason: &str) {
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
pub(crate) fn record_storage_error(metrics: &Metrics, operation: &str, error: &StorageError) {
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

pub(crate) async fn serve_admin(
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
pub(crate) fn render_replication(
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
