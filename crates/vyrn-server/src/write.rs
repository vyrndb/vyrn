//! The write pipeline: the write worker, the flush stage, and commit validation.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use vyrn_core::{
    change_log, document::IndexDefinition, BatchOperation, BatchResult, Engine,
    Error as StorageError, IndexUpdate,
};
use vyrn_log::log_error;
use vyrn_protocol::Message;

use crate::admin::{record_storage_error, withdraw_readiness};
use crate::changes::ChangeEvent;
use crate::{
    storage_error_message, BatchEntry, DeferredAnswer, DocumentWrite, FlushWorkerConfig,
    PendingFlush, ReadRange, TransactionCheck, WriteRequest, WriteWorkerConfig,
};

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
pub(crate) fn start_write_worker(
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

pub(crate) async fn run_write_pipeline(
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
pub(crate) type IndexChangeOutcome = (
    vyrn_core::Result<()>,
    vyrn_core::WriteBackPublish,
    u64,
    u64,
    u64,
);

pub(crate) async fn finish_index_change(
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
pub(crate) fn drain_writes(
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
pub(crate) fn start_flush_worker(
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
pub(crate) fn publish_commit(config: &FlushWorkerConfig, flush: PendingFlush) -> bool {
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
pub(crate) fn fail_commit(
    requests: Vec<WriteRequest>,
    answers: Vec<DeferredAnswer>,
    message: &str,
) {
    respond_writes(requests, Err(message.to_owned()));
    for answer in answers {
        let _ = answer.response.send(Err(message.to_owned()));
    }
}

pub(crate) type DocumentChangeEvent = (Vec<u8>, Option<Vec<u8>>);

pub(crate) fn apply_document_write(
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

pub(crate) fn document_indexes(
    engine: &Engine,
    collection: &str,
) -> vyrn_core::Result<Vec<IndexDefinition>> {
    Ok(engine
        .collection_indexes(collection)?
        .into_iter()
        .map(|(field, unique)| IndexDefinition::new(field, unique))
        .collect())
}

pub(crate) fn operation_key(operation: &BatchOperation) -> &[u8] {
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
pub(crate) const MISROUTED_REQUEST: &str =
    "request reached the wrong stage of the write pipeline and was not applied; \
     this is a server routing bug — retrying is safe";

pub(crate) fn respond_writes(
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
pub(crate) fn reject_conflicts(
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

pub(crate) fn has_conflict(
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
