//! Continuous archiving of sealed WAL segments to a local directory.
//!
//! Archiving never blocks writes: it takes no engine lock and reads only
//! sealed segments, which are immutable — the active (highest-id) segment is
//! the only file recovery may truncate in place, so it is never a candidate.
//! Coordination with a live engine is one-way: the engine's checkpoint
//! consults the archiver's watermark before deleting a sealed segment, so the
//! archiver can always re-read anything it has not yet durably copied.

use crate::{Error, Result};
use fs2::FileExt;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

/// Deliberately not the WAL's magic, so a tool pointed at the wrong file can
/// never mistake the index for a segment or replay the index as one.
const INDEX_MAGIC: &[u8; 8] = b"VARCIDX1";
const INDEX_FILE: &str = "ARCHIVE";
const INDEX_ENTRY_LEN: usize = 44;

/// One archived segment as recorded in the ARCHIVE index.
///
/// `last_lsn` is `first_lsn - 1` for a segment sealed with no records, which
/// keeps the LSN chain (`next.first_lsn == prev.last_lsn + 1`) exact across
/// empty segments instead of special-casing them everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexEntry {
    pub(crate) segment_id: u64,
    pub(crate) first_lsn: u64,
    pub(crate) last_lsn: u64,
    pub(crate) byte_len: u64,
    pub(crate) crc: u32,
    pub(crate) archived_at: u64,
}

/// What [`verify_archive`] proved the archive covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub segments: usize,
    pub first_lsn: u64,
    pub last_lsn: u64,
}

/// Copies every sealed segment not yet archived into `archive_directory` and
/// returns the highest archived segment id (0 when nothing is archived yet).
///
/// Each copy becomes durable — file synced, renamed into place, index
/// rewritten and synced — before the next candidate is touched, so a crash
/// loses at most one in-flight copy, which the next run simply redoes. The
/// caller feeds the returned watermark to [`crate::EngineOptions`]'s
/// `archived_through` so checkpoints never delete an uncopied segment.
pub fn archive_pending(wal_directory: &Path, archive_directory: &Path) -> Result<u64> {
    fs::create_dir_all(archive_directory)?;
    let segments = wal_segment_ids(wal_directory)?;
    let mut entries = read_index(archive_directory)?;
    // The returned watermark authorizes checkpoints to delete local segments,
    // so it must never exceed what this WAL can corroborate. On the archive's
    // own timeline the index reaches at most the active segment's predecessor
    // (the active segment is never a candidate), so an index reaching the
    // active id or beyond was written against some other WAL — a wiped or
    // re-created data directory still pointed at its predecessor's archive.
    // Returning that index's watermark would let checkpoints delete this
    // timeline's first sealed segments before they are ever copied, and the
    // per-candidate guards below never fire when there is nothing sealed
    // locally to compare against.
    if let Some(entry) = entries.last() {
        if segments
            .last()
            .is_none_or(|&highest| entry.segment_id >= highest)
        {
            return Err(Error::CorruptBackup(format!(
                "archive already indexes segment {} but the local WAL only reaches segment {}; the archive belongs to a different timeline",
                entry.segment_id,
                segments.last().copied().unwrap_or(0)
            )));
        }
    }
    // Everything but the highest id: the active segment is the only file
    // recovery may truncate in place, so only its predecessors are immutable
    // and safe to copy byte-for-byte.
    let candidates = segments
        .split_last()
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    for &segment_id in candidates {
        let name = crate::segment_name(segment_id);
        let indexed = entries
            .iter()
            .find(|entry| entry.segment_id == segment_id)
            .copied();
        let bytes = match fs::read(wal_directory.join(&name)) {
            Ok(bytes) => bytes,
            Err(error)
                if indexed.is_some()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) =>
            {
                // A checkpoint deleted it concurrently. That is legal: the
                // engine only deletes at or below the archiver's watermark,
                // so a durable copy already exists. Windows reports a file in
                // the delete-pending state as PermissionDenied rather than
                // NotFound, so both spell "already deleted" here.
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Error::CorruptBackup(format!(
                    "WAL segment {segment_id} disappeared before it was archived"
                )));
            }
            Err(error) => return Err(error.into()),
        };
        // One full scan: header, every record's framing and checksum. Any
        // failure is fatal — an archive exists to be trusted later, so rot is
        // rejected at the door rather than shipped.
        let (first_lsn, last_lsn) = scan_segment(segment_id, &bytes)?;
        let crc = crate::checksum(&bytes);
        // Timeline guards. A recovered database continues its predecessor's
        // segment-id space, so a foreign or diverged database pointed at this
        // archive presents valid segments under ids (or LSN ranges) already
        // indexed. Silently skipping or overwriting would poison the
        // predecessor's archive while the watermark still advances — and a
        // checkpoint then deletes the only local copy of the real bytes.
        if let Some(existing) = indexed {
            if existing.crc == crc
                && existing.first_lsn == first_lsn
                && existing.byte_len == bytes.len() as u64
            {
                continue;
            }
            return Err(Error::CorruptBackup(format!(
                "segment {segment_id} (LSNs {first_lsn}..={last_lsn}) does not match the archived copy (LSNs {}..={}); the archive belongs to a different timeline",
                existing.first_lsn, existing.last_lsn
            )));
        }
        if let Some(other) = entries.iter().find(|entry| {
            entry.segment_id != segment_id
                && entry.first_lsn <= entry.last_lsn
                && first_lsn <= last_lsn
                && first_lsn <= entry.last_lsn
                && entry.first_lsn <= last_lsn
        }) {
            return Err(Error::CorruptBackup(format!(
                "segment {segment_id} (LSNs {first_lsn}..={last_lsn}) overlaps archived segment {} (LSNs {}..={}); the archive belongs to a different timeline",
                other.segment_id, other.first_lsn, other.last_lsn
            )));
        }
        // The bytes written are exactly the buffer that was just validated, so
        // the archived copy matches the scan's checksum by construction; a
        // concurrent rewrite of the source (illegal for a sealed segment)
        // cannot leak unvalidated bytes into the archive.
        let temporary = archive_directory.join(format!("{name}.tmp"));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, archive_directory.join(&name))?;
        crate::sync_directory(archive_directory)?;
        let archived_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        entries.push(IndexEntry {
            segment_id,
            first_lsn,
            last_lsn,
            byte_len: bytes.len() as u64,
            crc,
            archived_at,
        });
        entries.sort_unstable_by_key(|entry| entry.segment_id);
        // Durable before the next candidate: the index is the archive's source
        // of truth, and an unindexed copy is merely redone after a crash.
        write_index(archive_directory, &entries)?;
    }
    Ok(entries.last().map_or(0, |entry| entry.segment_id))
}

/// Re-proves every archived byte: index checksum, id contiguity, LSN chain,
/// and a full re-scan of each segment against its index entry.
