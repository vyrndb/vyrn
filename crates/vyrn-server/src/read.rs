//! The read path: per-handle worker threads, point reads, and scans.

use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Instant;
use tokio::sync::oneshot;
use tokio::time::Duration;
use vyrn_core::ReadEngine;
use vyrn_protocol::{ErrorCode, Message};

use crate::{
    encode_document, encode_documents, server_error, storage_error_message, DocumentRead,
    DocumentWrite, ReadFailure, ReadRequest, Rows, ScanJob, ServerState, Shard, SCAN_CHUNK_ROWS,
    SCAN_YIELD_REQUESTS,
};

pub(crate) fn start_read_workers(
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
pub(crate) fn serve_read(
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
pub(crate) fn multi_get(
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
pub(crate) fn advance_scan(
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
pub(crate) fn read_dispatch_error(error: std::sync::mpsc::TrySendError<ReadRequest>) -> Message {
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
pub(crate) fn read_failure_message(failure: ReadFailure) -> Message {
    match failure {
        ReadFailure::Storage(error) => storage_error_message(error),
        ReadFailure::DeadlineExceeded => server_error(
            ErrorCode::InvalidRequest,
            "read exceeded its time limit and was abandoned; \
             narrow the range or lower the limit",
        ),
    }
}

pub(crate) async fn submit_get(state: &ServerState, key: Vec<u8>) -> Message {
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

pub(crate) async fn submit_multi_get(state: &ServerState, keys: Vec<Vec<u8>>) -> Message {
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

pub(crate) async fn multi_get_on(shard: &Shard, keys: Vec<Vec<u8>>) -> Message {
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

pub(crate) async fn submit_scan(
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
pub(crate) fn merge_scan_rows(mut per_shard: Vec<Rows>, limit: usize) -> Rows {
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
pub(crate) fn next_reader(shard: &Shard) -> usize {
    shard.next_reader.fetch_add(1, Ordering::Relaxed) as usize % shard.read_queues.len()
}

pub(crate) fn read_document(
    reader: &ReadEngine,
    request: DocumentRead,
) -> vyrn_core::Result<Message> {
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

pub(crate) fn document_read_collection(request: &DocumentRead) -> &str {
    match request {
        DocumentRead::Get { collection, .. }
        | DocumentRead::List { collection, .. }
        | DocumentRead::Query { collection, .. } => collection,
    }
}

pub(crate) fn document_write_collection(request: &DocumentWrite) -> &str {
    match request {
        DocumentWrite::CreateCollection { collection, .. }
        | DocumentWrite::Put { collection, .. }
        | DocumentWrite::Delete { collection, .. } => collection,
    }
}
