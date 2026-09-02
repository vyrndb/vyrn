//! Background maintenance tasks: MVCC GC, WAL archiving, async sync.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::{task, time::sleep};
use vyrn_core::{Engine, Error as StorageError, ReadEngine};
use vyrn_log::{log_debug, log_error, log_info};

use crate::metrics::Metrics;
use crate::withdraw_readiness;

pub(crate) fn start_mvcc_gc(
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
pub(crate) fn start_wal_archiver(
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
pub(crate) fn wal_archive_lag(wal_directory: &Path, archived_through: u64) -> u64 {
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

pub(crate) fn start_async_sync(
    engine: Arc<RwLock<Engine>>,
    interval: Duration,
    metrics: Arc<Metrics>,
) {
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
