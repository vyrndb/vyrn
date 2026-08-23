//! Replica-side handling of WAL records received from a primary.
//!
//! DELIBERATELY SYNCHRONOUS AND SOCKET-FREE. `vyrn-core` has no async runtime —
//! its dependencies are `crc32fast`, `fs2`, `serde`, `serde_json`, `thiserror` —
//! and replication must not be the thing that drags tokio into the storage
//! engine. Everything here is a function over bytes; `vyrn-server` owns the
//! connection, the streaming and the acknowledgements.
//!
//! The records arriving from a primary are the primary's own WAL records, byte
//! for byte, so this module validates them with exactly the checks recovery
//! applies to a segment on disk: magic, format version, declared lengths, CRC32
//! over the framed fields, the `VEND` footer, and the operation payload's own
//! structure. A record that fails any of them is rejected rather than appended.
//!
//! WHY VALIDATE AT ALL, given the primary already wrote these bytes and TLS
//! protects them in transit: because the failure this defends against is not a
//! malicious peer, it is a *confused* one — a primary running a different build,
//! a replica pointed at the wrong cluster, a proxy that reassembled frames
//! wrongly, memory that rotted before the record was sent. Appending a record
//! this replica cannot itself parse would produce a WAL that its own recovery
//! later refuses to open, turning a detectable stream error into an undetectable
//! corrupt replica.

use crate::{
    Error, Result, RECORD_END, RECORD_FOOTER_LEN, RECORD_HEADER_LEN, RECORD_MAGIC, VERSION,
};
use std::path::Path;

/// What a received record describes, once its framing has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub lsn: u64,
    pub operation_count: u32,
    pub payload_len: u32,
    /// Page id of the tree root this commit produced on the primary.
    pub root: u64,
    /// User-visible entry count after this commit.
    pub len: u64,
    /// Total framed size, header + payload + footer.
    pub total_len: usize,
}

/// Why a stream cannot continue.
///
/// Separate from [`Error`] because these are stream-level conditions a replica
/// reports back to its primary and then halts on, not storage faults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The replica holds records the primary does not.
    ///
    /// Unreachable by streaming: the primary has no records to send that would
    /// reconcile the two, and appending its next record would leave this
    /// replica's log with a gap or a rewritten history. Only a rebuild from a
    /// base backup fixes it.
    ReplicaAhead { replica_lsn: u64, primary_lsn: u64 },
    /// The primary's stream starts past where this replica's log ends.
    ///
    /// The records in between were checkpointed and pruned before this replica
    /// asked for them. Recoverable, but not by streaming: the gap has to be
    /// closed from the WAL archive first.
    GapBeforeStream { replica_lsn: u64, first_lsn: u64 },
    /// A record arrived out of order, so the stream is not a log.
    NonContiguous { expected: u64, received: u64 },
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReplicaAhead {
                replica_lsn,
                primary_lsn,
            } => write!(
                formatter,
                "replica is ahead of the primary (replica at LSN {replica_lsn}, primary at {primary_lsn}); \
                 streaming cannot reconcile this, rebuild the replica from a base backup"
            ),
            Self::GapBeforeStream {
                replica_lsn,
                first_lsn,
            } => write!(
                formatter,
                "primary's stream starts at LSN {first_lsn} but this replica ends at {replica_lsn}; \
                 close the gap from the WAL archive before streaming"
            ),
            Self::NonContiguous { expected, received } => write!(
                formatter,
                "expected LSN {expected} but received {received}; the stream is not contiguous"
            ),
        }
    }
}

/// Verifies a received record's framing and returns what it declares.
///
/// The order of checks matters and mirrors `replay_segment`:
///
/// 1. Enough bytes for a header at all.
/// 2. Magic, then **version before anything else**. A record written by another
///    build is intact data this build cannot read, which is a different situation
///    from damage and must not be reported as corruption — the same distinction
///    `replay_segment` makes, surfaced through the same [`Error::FormatVersion`].
/// 3. Declared lengths, checked with overflow-safe arithmetic against what is
///    actually present.
/// 4. CRC32 over the framed fields and payload.
/// 5. The `VEND` footer and the redundant total length.
/// 6. The payload's own operation structure.
///
/// A checksum that passes over a length that was never bounds-checked proves
/// nothing, which is why the lengths come first.
pub fn verify_record(bytes: &[u8]) -> Result<RecordHeader> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(stream_error(
            "replication record is shorter than its header",
        ));
    }
    if &bytes[0..4] != RECORD_MAGIC {
        return Err(stream_error("replication record has invalid magic"));
    }
    // Before every other check, so "sent by a newer primary" never surfaces as
    // "corrupt".
    if bytes[4] != VERSION {
        return Err(Error::FormatVersion {
            structure: "replicated WAL record",
            found: bytes[4],
            expected: VERSION,
        });
    }

    let lsn = crate::read_u64(bytes, 5);
    let operation_count = crate::read_u32(bytes, 13);
    let payload_len = crate::read_u32(bytes, 17);
    let expected_checksum = crate::read_u32(bytes, 21);
    let root = crate::read_u64(bytes, 25);
    let len = crate::read_u64(bytes, 33);

    // LSN 0 is not a valid record: the engine's first commit is LSN 1, and 0 is
    // what a replica reports when it holds nothing at all.
    if lsn == 0 {
        return Err(stream_error("replication record has LSN 0"));
    }

    // Bytes 41..45 are UNUSED PADDING in the 45-byte header: the declared fields
    // end at 41 (`len` occupies 33..41), and nothing reads the remainder. They
    // are consequently outside `transaction_checksum`, so a flip in them is
    // invisible to every other check here — an exhaustive bit-flip test over a
    // real record is what surfaced that.
    //
    // Requiring them to be zero matters for a replica specifically. A record this
    // build encodes always zero-fills them (`vec![0; total_len]`), so a non-zero
    // byte means the bytes on the wire are not the bytes the primary encoded.
    // Appending them anyway would leave the replica's segment differing from the
    // primary's for the same LSN, which quietly breaks the one property that
    // makes shipping raw records safe: that both sides hold identical logs.
    //
    // A future format that claims these bytes is caught by the version check
    // above before reaching here.
    if bytes[41..RECORD_HEADER_LEN].iter().any(|byte| *byte != 0) {
        return Err(stream_error(
            "replication record has non-zero padding in its header",
        ));
    }

    let total_len = RECORD_HEADER_LEN
        .checked_add(payload_len as usize)
        .and_then(|size| size.checked_add(RECORD_FOOTER_LEN))
        .ok_or_else(|| stream_error("replication record length overflows"))?;
    // Exactly, not at least: a record carrying a tail beyond what it declares is
    // not a record this build produced, and accepting the prefix would append
    // bytes the sender did not intend as one record.
    if total_len != bytes.len() {
        return Err(stream_error(
            "replication record length does not match its declared size",
        ));
    }

    let payload = &bytes[RECORD_HEADER_LEN..total_len - RECORD_FOOTER_LEN];
    if crate::transaction_checksum(lsn, operation_count as usize, payload, root, len)
        != expected_checksum
    {
        return Err(stream_error("replication record failed its checksum"));
    }

    // The footer repeats the total length and ends in `VEND`. Both are what let
    // recovery tell a torn record from a rotten one, so a replica must not append
    // a record whose footer it has not confirmed.
    let footer = &bytes[total_len - RECORD_FOOTER_LEN..];
    if crate::read_u32(footer, 0) as usize != total_len {
        return Err(stream_error("replication record footer length disagrees"));
    }
    if &footer[4..] != RECORD_END {
        return Err(stream_error("replication record has invalid footer"));
    }

    crate::validate_payload(payload, operation_count as usize).map_err(stream_error)?;

    Ok(RecordHeader {
        lsn,
        operation_count,
        payload_len,
        root,
        len,
        total_len,
    })
}

/// Decides whether a primary's stream can be joined to this replica's log.
///
/// `replica_lsn` is 0 for a replica with no records. `first_lsn` is where the
/// primary says it will start sending.
///
/// The acceptable case is exactly one: the stream begins at the record directly
/// after the replica's last. Anything else is reported rather than papered over —
/// silently accepting a stream that does not abut the local log is how a replica
/// ends up with a history no recovery can explain.
pub fn check_join(replica_lsn: u64, primary_lsn: u64, first_lsn: u64) -> Option<Divergence> {
    if replica_lsn > primary_lsn {
        return Some(Divergence::ReplicaAhead {
            replica_lsn,
            primary_lsn,
        });
    }
    if first_lsn > replica_lsn.saturating_add(1) {
        return Some(Divergence::GapBeforeStream {
            replica_lsn,
            first_lsn,
        });
    }
    None
}

/// Checks that `lsn` is the next record this replica expects.
///
/// Records at or below `last_lsn` are duplicates — a reconnect can legitimately
/// resend them — and are reported as `Ok(false)` so the caller can skip them
/// rather than treat them as an error. Anything beyond the next LSN is a gap.
pub fn check_contiguous(last_lsn: u64, lsn: u64) -> std::result::Result<bool, Divergence> {
    let expected = last_lsn.saturating_add(1);
    if lsn == expected {
        return Ok(true);
    }
    if lsn <= last_lsn {
        return Ok(false);
    }
    Err(Divergence::NonContiguous {
        expected,
        received: lsn,
    })
}

/// The oldest LSN a primary can still supply from its live WAL.
///
/// A joining replica has to be told whether the records it is missing still
/// exist. Checkpoints delete sealed segments once their commits are baked into a
/// checkpoint root, so a replica that was offline across a few checkpoints needs
/// records the primary no longer holds — and streaming to it anyway would hand it
/// a log with a hole, which [`check_join`] refuses and no recovery could explain.
/// The primary compares this against the replica's next needed LSN and asks for a
/// rebuild instead.
///
/// The FIRST LSN of the oldest segment, read from that segment's header, rather
/// than a scan of its records: the header is 32 bytes and the answer only has to
/// be a floor. An empty WAL directory reports 0, which reads as "nothing has been
/// pruned" and lets any replica stream — correct, because a primary with no
/// segments has no history to be missing.
///
/// Deliberately a directory read rather than engine state: which segments exist is
/// a fact about the filesystem that checkpoints change without telling anyone, and
/// caching it would be a cache that goes stale exactly when it matters.
pub fn oldest_available_lsn(wal_directory: &Path) -> Result<u64> {
    let mut oldest: Option<u64> = None;
    for entry in std::fs::read_dir(wal_directory)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(id) = name
            .strip_suffix(".vwal")
            .and_then(|number| number.parse::<u64>().ok())
        {
            oldest = Some(oldest.map_or(id, |current: u64| current.min(id)));
        }
    }
    let Some(oldest) = oldest else {
        return Ok(0);
    };
    crate::read_segment_first_lsn(&wal_directory.join(crate::segment_name(oldest)))
}

/// Records the archive holds from `from_lsn` onward, up to the given bounds.
///
/// WHAT THIS IS FOR. A replica that fell behind far enough for the primary to
/// prune the segments it needs cannot be caught up by streaming — the records are
/// gone from the primary's live WAL. They are not gone from the ARCHIVE, though,
/// which is exactly what an archive is for, and archived segments are the
/// primary's own WAL segments byte for byte. So the replica closes its gap by
/// reading them from the archive and applying them through
/// [`crate::Engine::apply_replicated_record`] — the same path a streamed record
/// takes, with the same validation and the same durability ordering.
///
/// A READER RATHER THAN A RECOVERY. The obvious alternative is
/// [`crate::recover::recover_to`], which merges the archive into a data directory
/// and replays it — but that opens the target with `Engine::open`, and a running
/// replica already holds that directory's lock. Handing the bytes back and letting
/// the caller apply them through the engine it already has needs no second open,
/// works while the replica is serving reads, and reuses the append path whose
/// ordering guarantees are already established.
///
/// BOUNDED IN BOTH DIRECTIONS because an archive can hold far more than fits in
/// memory: the caller loops, applying one batch and asking for the next from the
/// LSN it reached. `max_records` and `max_bytes` are both honoured, and at least
/// one record is always returned when one exists at or after `from_lsn`, so a
/// single record larger than `max_bytes` cannot stall the loop forever.
///
/// Records are returned FRAMED AND UNVERIFIED, in LSN order. Verification belongs
/// to the caller, which already runs [`verify_record`] on every record it accepts
/// from a primary: an archive is no more trusted than a socket, and having one
/// check for both sources means there is one place where that judgement lives.
pub fn archived_records_from(
    archive_directory: &Path,
    from_lsn: u64,
    max_records: usize,
    max_bytes: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut segments = Vec::new();
    for entry in std::fs::read_dir(archive_directory)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(id) = name
            .strip_suffix(".vwal")
            .and_then(|number| number.parse::<u64>().ok())
        {
            segments.push(id);
        }
    }
    segments.sort_unstable();

    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0;
    for (position, id) in segments.iter().enumerate() {
        /* Skip a segment whose successor already begins at or below the wanted
         * LSN: everything in it precedes what the caller asked for, so there is
         * no reason to read its body. The LAST segment is never skipped, since
         * nothing follows it to prove it is exhausted. */
        if let Some(next) = segments.get(position + 1) {
            let next_first = read_segment_first_lsn_of(archive_directory, *next).unwrap_or(0);
            if next_first != 0 && next_first <= from_lsn {
                continue;
            }
        }
        let bytes_of_segment = std::fs::read(archive_directory.join(crate::segment_name(*id)))?;
        if bytes_of_segment.len() < crate::SEGMENT_HEADER_LEN {
            return Err(stream_error(format!(
                "archived segment {id} is shorter than its header"
            )));
        }
        let mut offset = crate::SEGMENT_HEADER_LEN;
        while offset + RECORD_HEADER_LEN <= bytes_of_segment.len() {
            let header = &bytes_of_segment[offset..offset + RECORD_HEADER_LEN];
            /* A frame that does not begin with a record is the end of this
             * segment's records, not damage: every segment carries a zero-filled
             * runway past its last record. Treated as end-of-segment exactly as
             * replay treats it, so the runway is not mistaken for a corrupt
             * archive. A record whose CONTENTS are damaged is a different matter
             * and is caught by the caller's `verify_record`. */
            if &header[0..4] != RECORD_MAGIC {
                break;
            }
            let lsn = crate::read_u64(header, 5);
            let payload_len = crate::read_u32(header, 17) as usize;
            let Some(total_len) = RECORD_HEADER_LEN
                .checked_add(payload_len)
                .and_then(|size| size.checked_add(RECORD_FOOTER_LEN))
            else {
                return Err(stream_error(format!(
                    "archived segment {id} declares a record length that overflows"
                )));
            };
            // A record running past the end of the file is a truncated archive,
            // not a runway: the magic matched, so bytes were meant to be here.
            if offset + total_len > bytes_of_segment.len() {
                return Err(stream_error(format!(
                    "archived segment {id} ends inside a record at byte {offset}"
                )));
            }
            if lsn >= from_lsn {
                // The byte bound yields only once something is in hand, so one
                // oversized record still makes progress instead of deadlocking.
                if !records.is_empty()
                    && (records.len() >= max_records || bytes + total_len > max_bytes)
                {
                    return Ok(records);
                }
                records.push(bytes_of_segment[offset..offset + total_len].to_vec());
                bytes += total_len;
            }
            offset += total_len;
        }
    }
    Ok(records)
}

/// A segment header's first LSN, or `None` when it cannot be read.
///
/// Absence is not fatal here: this only decides whether a segment can be SKIPPED,
/// and failing to skip means reading a segment whose records are then filtered by
/// LSN anyway. A genuinely damaged segment is caught when its records are read.
fn read_segment_first_lsn_of(archive_directory: &Path, id: u64) -> Option<u64> {
    crate::read_segment_first_lsn(&archive_directory.join(crate::segment_name(id))).ok()
}

/// A stream-level failure, distinct from storage corruption.
///
/// [`Error::InvalidReplicatedRecord`] rather than [`Error::CorruptWal`]: these
/// bytes never became part of a segment, so a segment id and offset would be
/// fabricated, and an operator reading "corrupt WAL segment 0" would go hunting
/// for local damage that does not exist. The fault is in the stream or the peer.
fn stream_error(reason: impl Into<String>) -> Error {
    Error::InvalidReplicatedRecord {
        reason: reason.into(),
    }
}
