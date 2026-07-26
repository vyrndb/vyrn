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
pub fn verify_archive(archive_directory: &Path) -> Result<ArchiveSummary> {
    let entries = read_index(archive_directory)?;
    for pair in entries.windows(2) {
        if pair[1].segment_id != pair[0].segment_id + 1 {
            return Err(Error::CorruptBackup(format!(
                "archive is missing segment {} between {} and {}",
                pair[0].segment_id + 1,
                pair[0].segment_id,
                pair[1].segment_id
            )));
        }
        if pair[1].first_lsn != pair[0].last_lsn + 1 {
            return Err(Error::CorruptBackup(format!(
                "archive LSN chain breaks between segment {} (ends at {}) and segment {} (starts at {})",
                pair[0].segment_id, pair[0].last_lsn, pair[1].segment_id, pair[1].first_lsn
            )));
        }
    }
    for entry in &entries {
        let bytes = fs::read(archive_directory.join(crate::segment_name(entry.segment_id)))
            .map_err(|error| {
                Error::CorruptBackup(format!(
                    "cannot read archived segment {}: {error}",
                    entry.segment_id
                ))
            })?;
        let (first_lsn, last_lsn) = scan_segment(entry.segment_id, &bytes).map_err(|error| {
            Error::CorruptBackup(format!(
                "archived segment {} failed verification: {error}",
                entry.segment_id
            ))
        })?;
        if first_lsn != entry.first_lsn
            || last_lsn != entry.last_lsn
            || bytes.len() as u64 != entry.byte_len
            || crate::checksum(&bytes) != entry.crc
        {
            return Err(Error::CorruptBackup(format!(
                "archived segment {} does not match its index entry",
                entry.segment_id
            )));
        }
    }
    Ok(ArchiveSummary {
        segments: entries.len(),
        first_lsn: entries.first().map_or(0, |entry| entry.first_lsn),
        last_lsn: entries.last().map_or(0, |entry| entry.last_lsn),
    })
}

/// Deletes archived WAL segments with id at most `through` from an offline
/// database, returning how many were removed.
///
/// Takes the database's exclusive LOCK exactly like `backup::create_backup`:
/// pruning under a live server would race checkpoint's own segment deletions
/// and the archiver's watermark, so it only runs when nothing else can touch
/// wal/. Refuses to delete anything the archive has not indexed — once pages
/// are checkpointed those bytes are the only point-in-time copy of their LSN
/// range — refuses anything the published checkpoint does not cover, and
/// never deletes the highest segment, which the next open adopts as its
/// active file.
pub fn prune_wal(data_directory: &Path, archive_directory: &Path, through: u64) -> Result<usize> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(data_directory.join("LOCK"))?;
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            Error::AlreadyOpen
        } else {
            Error::Io(error)
        }
    })?;
    let entries = read_index(archive_directory)?;
    let wal_directory = data_directory.join("wal");
    let segments = crate::list_segments(&wal_directory)?;
    let Some(&highest) = segments.last() else {
        return Ok(0);
    };
    for &segment in &segments {
        if segment <= through && !entries.iter().any(|entry| entry.segment_id == segment) {
            return Err(Error::CorruptBackup(format!(
                "segment {segment} is not archived; pruning it would destroy the only copy of its LSN range"
            )));
        }
    }
    // Being archived proves a durable copy exists somewhere, but replay still
    // needs every record above the published checkpoint locally: the manifest
    // seeds replay's starting LSN and replay refuses a discontinuous sequence,
    // so deleting an archived segment whose records exceed the manifest LSN
    // leaves a database that never opens again — its acknowledged commits
    // exist only in the archive. Segments seal between checkpoints as a matter
    // of routine (size trigger, archive rotation timer), so `through` alone
    // must never authorize deletion. A segment's records end exactly where its
    // successor's header starts (the rule replay's dead-segment skip already
    // trusts), which decides coverage without scanning bodies.
    let manifest_lsn = crate::read_manifest(data_directory)?.map_or(0, |state| state.lsn);
    let mut covered = 0;
    for pair in segments.windows(2) {
        let successor_first_lsn =
            crate::read_segment_first_lsn(&wal_directory.join(crate::segment_name(pair[1])))?;
        if successor_first_lsn.saturating_sub(1) > manifest_lsn {
            break;
        }
        covered = pair[0];
    }
    let cutoff = through.min(highest.saturating_sub(1)).min(covered);
    let mut deleted = 0;
    for &segment in segments.iter().take_while(|&&segment| segment <= cutoff) {
        fs::remove_file(wal_directory.join(crate::segment_name(segment)))?;
        deleted += 1;
    }
    crate::sync_directory(&wal_directory)?;
    Ok(deleted)
}

/// Segment ids present in wal/, sorted, without `list_segments`' gap check.
///
/// The archiver enumerates a live wal/ holding no lock while checkpoints
/// delete archived segments concurrently, and `read_dir` is not an atomic
/// snapshot: an enumeration that yields segment 1 before a checkpoint deletes
/// segments 1 and 2, then resumes at 3, observes a gap no on-disk instant
/// ever had — failing the whole tick for it would fire alerts on a healthy
/// database. A genuinely lost segment is still caught, by the unindexed
/// missing-candidate check rather than by the listing.
fn wal_segment_ids(wal_directory: &Path) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(wal_directory)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(number) = name.strip_suffix(".vwal") {
            ids.push(
                number
                    .parse::<u64>()
                    .map_err(|_| Error::CorruptManifest(format!("invalid segment name {name}")))?,
            );
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Reads and validates the ARCHIVE index; a missing file is an empty archive.
pub(crate) fn read_index(archive_directory: &Path) -> Result<Vec<IndexEntry>> {
    let bytes = match fs::read(archive_directory.join(INDEX_FILE)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() < 16 || &bytes[0..8] != INDEX_MAGIC {
        return Err(Error::CorruptBackup(
            "archive index has an invalid header".into(),
        ));
    }
    let count = crate::read_u32(&bytes, 8) as usize;
    let expected = 16u64 + count as u64 * INDEX_ENTRY_LEN as u64;
    if bytes.len() as u64 != expected {
        return Err(Error::CorruptBackup(
            "archive index length does not match its entry count".into(),
        ));
    }
    if crate::checksum(&bytes[..bytes.len() - 4]) != crate::read_u32(&bytes, bytes.len() - 4) {
        return Err(Error::CorruptBackup(
            "archive index checksum mismatch".into(),
        ));
    }
    let mut entries = Vec::with_capacity(count);
    let mut offset = 12;
    for _ in 0..count {
        entries.push(IndexEntry {
            segment_id: crate::read_u64(&bytes, offset),
            first_lsn: crate::read_u64(&bytes, offset + 8),
            last_lsn: crate::read_u64(&bytes, offset + 16),
            byte_len: crate::read_u64(&bytes, offset + 24),
            crc: crate::read_u32(&bytes, offset + 32),
            archived_at: crate::read_u64(&bytes, offset + 36),
        });
        offset += INDEX_ENTRY_LEN;
    }
    for pair in entries.windows(2) {
        if pair[1].segment_id <= pair[0].segment_id {
            return Err(Error::CorruptBackup(
                "archive index entries are not sorted by segment id".into(),
            ));
        }
    }
    Ok(entries)
}

/// Rewrites the whole index durably: tmp file, sync, rename, directory sync.
///
/// The index is small (44 bytes per segment), so rewriting it whole keeps a
/// single-checksum, single-rename publication instead of an appendable format
/// whose torn tail would need its own recovery.
fn write_index(archive_directory: &Path, entries: &[IndexEntry]) -> Result<()> {
    let count: u32 = entries
        .len()
        .try_into()
        .map_err(|_| Error::CorruptBackup("too many archived segments".into()))?;
    let mut bytes = Vec::with_capacity(16 + entries.len() * INDEX_ENTRY_LEN);
    bytes.extend_from_slice(INDEX_MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.segment_id.to_be_bytes());
        bytes.extend_from_slice(&entry.first_lsn.to_be_bytes());
        bytes.extend_from_slice(&entry.last_lsn.to_be_bytes());
        bytes.extend_from_slice(&entry.byte_len.to_be_bytes());
        bytes.extend_from_slice(&entry.crc.to_be_bytes());
        bytes.extend_from_slice(&entry.archived_at.to_be_bytes());
    }
    let index_checksum = crate::checksum(&bytes);
    bytes.extend_from_slice(&index_checksum.to_be_bytes());
    let temporary = archive_directory.join(format!("{INDEX_FILE}.tmp"));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, archive_directory.join(INDEX_FILE))?;
    crate::sync_directory(archive_directory)?;
    Ok(())
}

/// Validates a sealed segment end to end and returns its record LSN range
/// (`(first_lsn, first_lsn - 1)` for a segment with no records).
///
/// Unlike replay this refuses torn tails outright: a sealed segment was synced
/// whole before rotation, so any framing damage means the source is not the
/// segment it claims to be.
fn scan_segment(segment_id: u64, bytes: &[u8]) -> Result<(u64, u64)> {
    if bytes.len() < crate::SEGMENT_HEADER_LEN {
        return Err(crate::corrupt(segment_id, 0, "incomplete segment header"));
    }
    let header = &bytes[..crate::SEGMENT_HEADER_LEN];
    if &header[0..4] != crate::SEGMENT_MAGIC
        || header[4] != crate::VERSION
        || crate::read_u64(header, 8) != segment_id
        || crate::checksum(&header[0..24]) != crate::read_u32(header, 24)
    {
        return Err(crate::corrupt(segment_id, 0, "invalid segment header"));
    }
    let first_lsn = crate::read_u64(header, 16);
    let mut last_lsn = first_lsn.saturating_sub(1);
    let mut saw_record = false;
    let mut offset = crate::SEGMENT_HEADER_LEN;
    while offset < bytes.len() {
        // A sealed segment ends in the unused tail of its zero-filled runway,
        // so records stopping before the end of the file is expected. Every
        // remaining byte must be zero, though: this scan is what decides
        // whether a segment is the one it claims to be, and anything else past
        // the records is either a splice or damage.
        let remainder = &bytes[offset..];
        if remainder.len() < crate::RECORD_HEADER_LEN
            || remainder[..crate::RECORD_HEADER_LEN]
                .iter()
                .all(|byte| *byte == 0)
        {
            if remainder.iter().all(|byte| *byte == 0) {
                break;
            }
            return Err(crate::corrupt(
                segment_id,
                offset as u64,
                "incomplete transaction in sealed segment",
            ));
        }
        let record = &bytes[offset..offset + crate::RECORD_HEADER_LEN];
        if &record[0..4] != crate::RECORD_MAGIC || record[4] != crate::VERSION {
            return Err(crate::corrupt(
                segment_id,
                offset as u64,
                "invalid transaction header",
            ));
        }
        let lsn = crate::read_u64(record, 5);
        let operation_count = crate::read_u32(record, 13) as usize;
        let payload_len = crate::read_u32(record, 17) as usize;
        let expected_checksum = crate::read_u32(record, 21);
        let root = crate::read_u64(record, 25);
        let len = crate::read_u64(record, 33);
        let total_len = crate::RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(crate::RECORD_FOOTER_LEN))
            .ok_or_else(|| {
                crate::corrupt(segment_id, offset as u64, "transaction length overflow")
            })?;
        if total_len > bytes.len() - offset {
            return Err(crate::corrupt(
                segment_id,
                offset as u64,
                "incomplete transaction in sealed segment",
            ));
        }
        let payload = &bytes
            [offset + crate::RECORD_HEADER_LEN..offset + total_len - crate::RECORD_FOOTER_LEN];
        let footer = &bytes[offset + total_len - crate::RECORD_FOOTER_LEN..offset + total_len];
        if crate::read_u32(footer, 0) as usize != total_len
            || &footer[4..8] != crate::RECORD_END
            || crate::transaction_checksum(lsn, operation_count, payload, root, len)
                != expected_checksum
        {
            return Err(crate::corrupt(
                segment_id,
                offset as u64,
                "transaction checksum or footer mismatch",
            ));
        }
        // Same cross-check replay performs: a valid body under the wrong
        // header is a splice, and archiving it would launder the splice into
        // the trusted copy.
        if !saw_record {
            saw_record = true;
            if lsn != first_lsn {
                return Err(crate::corrupt(
                    segment_id,
                    offset as u64,
                    "segment first LSN does not match its header",
                ));
            }
        }
        last_lsn = lsn;
        offset += total_len;
    }
    Ok((first_lsn, last_lsn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engine, EngineOptions};
    use std::sync::{atomic::AtomicU64, Arc};
    use tempfile::tempdir;

    /// Fills a database with enough small commits to seal several segments.
    fn fill(path: &Path, seed: u8) {
        let mut engine = Engine::open_with_segment_size(path, 128).unwrap();
        for index in 0..20u8 {
            engine
                .put(
                    format!("key-{index}").into_bytes(),
                    vec![seed.wrapping_add(index); 40],
                )
                .unwrap();
        }
    }

    /// The active segment is the only file recovery may truncate in place, so
    /// archiving it would capture bytes that can later legally change; and a
    /// re-run must not duplicate work, or a cron-driven archiver would rewrite
    /// the whole archive every tick.
    #[test]
    fn archives_sealed_segments_idempotently_and_excludes_the_active_one() {
        let database = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        fill(database.path(), 0);
        let wal_directory = database.path().join("wal");
        let segments = crate::list_segments(&wal_directory).unwrap();
        let highest = *segments.last().unwrap();
        assert!(segments.len() > 1);
        let watermark = archive_pending(&wal_directory, &archive).unwrap();
        assert_eq!(watermark, highest - 1);
        assert!(archive.join(crate::segment_name(1)).exists());
        assert!(!archive.join(crate::segment_name(highest)).exists());
        let index_bytes = fs::read(archive.join(INDEX_FILE)).unwrap();
        assert_eq!(
            archive_pending(&wal_directory, &archive).unwrap(),
            highest - 1
        );
        assert_eq!(fs::read(archive.join(INDEX_FILE)).unwrap(), index_bytes);
        let summary = verify_archive(&archive).unwrap();
        assert_eq!(summary.segments, segments.len() - 1);
        assert_eq!(summary.first_lsn, 1);
    }

    /// A wiped or re-created data directory pointed at its predecessor's
    /// archive presents an index whose ids this WAL never sealed, and on a
    /// tick with nothing sealed locally the per-candidate identity guards
    /// validate nothing at all; returning the foreign index's watermark would
    /// then let checkpoints delete this timeline's first sealed segments
    /// before they are ever copied — destroying the only bytes of their LSN
    /// range while every metric reads healthy.
    #[test]
    fn refuses_an_index_reaching_beyond_the_local_wal() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        fill(first.path(), 0);
        archive_pending(&first.path().join("wal"), &archive).unwrap();
        // The second database is fresh: a single active segment, so the
        // candidate loop runs zero times and only the index-versus-WAL guard
        // can notice the mismatch.
        {
            let mut engine = Engine::open(second.path()).unwrap();
            engine.put(b"k".to_vec(), b"v".to_vec()).unwrap();
        }
        let error = archive_pending(&second.path().join("wal"), &archive).unwrap_err();
        assert!(matches!(error, Error::CorruptBackup(_)));
    }

    /// Every database numbers its segments from 1, so an archive pointed at a
    /// second (or recovered-then-diverged) database sees fully valid segments
    /// under ids it has already indexed; without the identity guard the second
    /// timeline would silently poison the first one's only history.
    #[test]
    fn rejects_a_divergent_segment_under_an_archived_id() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        fill(first.path(), 0);
        fill(second.path(), 99);
        archive_pending(&first.path().join("wal"), &archive).unwrap();
        let error = archive_pending(&second.path().join("wal"), &archive).unwrap_err();
        assert!(matches!(error, Error::CorruptBackup(_)));
    }

    /// The index alone cannot notice disk rot that happens after archiving, so
    /// verification must re-read and re-checksum every archived byte.
    #[test]
    fn verify_archive_detects_a_flipped_byte() {
        let database = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        fill(database.path(), 0);
        archive_pending(&database.path().join("wal"), &archive).unwrap();
        verify_archive(&archive).unwrap();
        let path = archive.join(crate::segment_name(1));
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        assert!(verify_archive(&archive).is_err());
    }

    /// Once pages are checkpointed, a sealed segment's bytes are the only
    /// point-in-time copy of its LSN range anywhere, so pruning must refuse
    /// anything the archive cannot prove it holds.
    #[test]
    fn prune_refuses_unarchived_segments_and_deletes_an_archived_prefix() {
        let database = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        // A watermark of 0 keeps every sealed segment through the checkpoint,
        // which is what leaves something to prune afterwards.
        let watermark = Arc::new(AtomicU64::new(0));
        {
            let mut engine = Engine::open_with_options(
                database.path(),
                EngineOptions {
                    segment_size: 128,
                    archived_through: Some(Arc::clone(&watermark)),
                    ..EngineOptions::default()
                },
            )
            .unwrap();
            for index in 0..20u8 {
                engine
                    .put(format!("key-{index}").into_bytes(), vec![index; 40])
                    .unwrap();
            }
            engine.checkpoint().unwrap();
        }
        let wal_directory = database.path().join("wal");
        let segments = crate::list_segments(&wal_directory).unwrap();
        assert!(segments.len() > 1);
        let error = prune_wal(database.path(), &archive, 1).unwrap_err();
        assert!(matches!(error, Error::CorruptBackup(_)));
        let archived = archive_pending(&wal_directory, &archive).unwrap();
        let deleted = prune_wal(database.path(), &archive, archived).unwrap();
        assert_eq!(deleted, segments.len() - 1);
        // The prefix rule left the active segment, so the database still opens
        // and serves the checkpointed data.
        let engine = Engine::open(database.path()).unwrap();
        assert_eq!(engine.get(b"key-0").unwrap(), Some(vec![0; 40]));
    }

    /// Segments seal between checkpoints as a matter of routine (size trigger,
    /// archive rotation timer), so an archived segment can hold records the
    /// published checkpoint does not cover. Replay seeds its LSN from the
    /// manifest and refuses discontinuous sequences, so pruning such a segment
    /// — every check "is it archived?" happily passes — leaves a database that
    /// never opens again, with its acknowledged commits only in the archive.
    #[test]
    fn prune_keeps_archived_segments_the_checkpoint_does_not_cover() {
        let database = tempdir().unwrap();
        let store = tempdir().unwrap();
        let archive = store.path().join("archive");
        // A watermark of 0 keeps every sealed segment through the checkpoint.
        let watermark = Arc::new(AtomicU64::new(0));
        {
            let mut engine = Engine::open_with_options(
                database.path(),
                EngineOptions {
                    segment_size: 128,
                    archived_through: Some(Arc::clone(&watermark)),
                    ..EngineOptions::default()
                },
            )
            .unwrap();
            engine.put(b"base".to_vec(), vec![1; 40]).unwrap();
            engine.checkpoint().unwrap();
            // Committed after the checkpoint: sealed and archived, but covered
            // by no published manifest.
            for index in 0..10u8 {
                engine
                    .put(format!("tail-{index}").into_bytes(), vec![index; 40])
                    .unwrap();
            }
            engine.rotate_for_archive().unwrap();
        }
        let wal_directory = database.path().join("wal");
        let sealed = crate::list_segments(&wal_directory).unwrap().len() - 1;
        let archived = archive_pending(&wal_directory, &archive).unwrap();
        let deleted = prune_wal(database.path(), &archive, archived).unwrap();
        // Only the pre-checkpoint segment is covered; everything holding
        // records above the manifest LSN must survive even though the archive
        // provably holds it.
        assert_eq!(deleted, 1);
        assert!(deleted < sealed);
        // Every acknowledged commit still replays from the local WAL alone.
        let engine = Engine::open(database.path()).unwrap();
        assert_eq!(engine.get(b"base").unwrap(), Some(vec![1; 40]));
        for index in 0..10u8 {
            assert_eq!(
                engine.get(format!("tail-{index}").as_bytes()).unwrap(),
                Some(vec![index; 40])
            );
        }
    }
}
