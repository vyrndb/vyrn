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
        return Err(stream_error("replication record is shorter than its header"));
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
