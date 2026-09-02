//! Streaming: replica record streams, change feeds, and cursor replay.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task;
use tokio_util::codec::Framed;
use vyrn_core::{change_log, Error as StorageError};
use vyrn_log::{log_error, log_info, log_warn};
use vyrn_protocol::{Envelope, ErrorCode, Message, VyrnCodec};

use crate::changes::ChangeEvent;
use crate::{failover, replication};
use crate::{send_error, send_frame, BoxedTransport, ServerState, Shard, CHANGE_REPLAY_BATCH};

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
pub(crate) async fn catch_up_from_wal(
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
pub(crate) async fn send_primary_epoch(
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
pub(crate) async fn stream_records(
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

pub(crate) async fn stream_records_inner(
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
pub(crate) const SUBSCRIBE_MERGE_CAPACITY: usize = 4096;

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
pub(crate) fn subscribe_merged(state: &ServerState) -> broadcast::Receiver<ChangeEvent> {
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

pub(crate) async fn stream_changes(
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

pub(crate) async fn stream_document_changes(
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

pub(crate) enum CursorStream {
    Keys { prefix: Vec<u8> },
    Collection { collection: String },
}

/// Resolves a client cursor token into a starting position.
///
/// `None` means "live changes only" and resolves to the newest cursor, so a
/// fresh subscriber does not replay history it never asked for.
pub(crate) async fn resolve_cursor(
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
pub(crate) async fn stream_from_cursor(
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

pub(crate) fn cursor_message(
    stream: &CursorStream,
    record: &change_log::ChangeRecord,
) -> Option<Message> {
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

pub(crate) fn cursor_error_code(error: &StorageError) -> ErrorCode {
    match error {
        StorageError::CursorTooOld { .. } | StorageError::InvalidCursor(_) => {
            ErrorCode::InvalidRequest
        }
        _ => ErrorCode::Storage,
    }
}
