//! Point-in-time recovery from a restored base backup plus a WAL archive.
//!
//! `recover_to` merges archived segments into the restored wal/, physically
//! trims the log at the requested LSN, and then lets a completely stock
//! `Engine::open` replay to the trim point. Recovery therefore has no special
//! replay mode to test or trust: the bound is enforced by what is on disk.

use crate::{wal_archive, Engine, Error, Result};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// Rolls a restored base backup forward to `until_lsn` (or as far as the log
/// reaches when `None`), returning the LSN actually achieved.
///
/// The caller has already restored a base backup into `target` (CURRENT,
/// pages, wal/). Redo is roll-forward only: the base checkpoint's root already
/// contains every commit at or below its manifest LSN, so bounds below it are
/// rejected rather than silently ignored.
///
/// Crash-safe before the final checkpoint by construction: merging is
/// idempotent, and once the trim completes the WAL physically ends at the
/// bound, so a crash anywhere in between is repaired by re-running
/// `recover_to` — or, after the trim, even a plain `Engine::open` lands at the
/// bound. Only the closing checkpoint publishes the result and deletes the
/// now-covered segments.
pub fn recover_to(
    target: &Path,
    archive_directory: Option<&Path>,
    until_lsn: Option<u64>,
    allow_partial: bool,
) -> Result<u64> {
    // A base taken from a database that had never checkpointed carries no
    // manifest, which is a valid backup rather than a broken one. Its floor is
    // LSN 0: nothing is baked into a checkpoint root, so every logged commit is
    // still replayable and any bound the archive can reach is legal. A manifest
    // that exists but cannot be read is still fatal — that is damage, not
    // absence.
    let base_lsn = if target.join("CURRENT").exists() {
        crate::manifest_lsn(target).map_err(|error| {
            failed(format!(
                "recovery target has an unreadable checkpoint manifest ({error})"
            ))
        })?
    } else {
        0
    };
    let wal_directory = target.join("wal");
    if !wal_directory.is_dir() {
        return Err(failed("recovery target has no wal directory".into()));
    }
    if let Some(archive) = archive_directory {
        merge_archive(&wal_directory, archive)?;
    }
    let ids = wal_ids(&wal_directory)?;
    if ids.is_empty() {
        return Err(failed(
            "recovery target has no WAL segments after merging".into(),
        ));
    }
    let mut missing = Vec::new();
    for pair in ids.windows(2) {
        for id in pair[0] + 1..pair[1] {
            missing.push(id.to_string());
        }
    }
    if !missing.is_empty() {
        return Err(failed(format!(
            "merged WAL is missing segment(s) {}; the archive and base backup do not connect",
            missing.join(", ")
        )));
    }
    let mut headers = Vec::with_capacity(ids.len());
    for &id in &ids {
        let first_lsn = crate::read_segment_first_lsn(&wal_directory.join(crate::segment_name(id)))
            .map_err(|error| failed(format!("segment {id} has an unreadable header ({error})")))?;
        headers.push((id, first_lsn));
    }
    for pair in headers.windows(2) {
        if pair[1].1 < pair[0].1 {
            return Err(failed(format!(
                "segment {} starts at LSN {} before its predecessor segment {} at {}",
                pair[1].0, pair[1].1, pair[0].0, pair[0].1
            )));
        }
    }
    let (last_id, last_first_lsn) = *headers.last().expect("ids is non-empty");
    let reachable = last_record_lsn(
        &wal_directory.join(crate::segment_name(last_id)),
        last_first_lsn,
    )?;
    let mut bound = until_lsn.unwrap_or(reachable);
    if bound < base_lsn {
        return Err(failed(format!(
            "recovery bound {bound} is below the base checkpoint LSN {base_lsn}: the checkpoint root already contains commits through {base_lsn} and redo only rolls forward, so the earliest reachable point is {base_lsn}; restore an older base backup to go earlier"
        )));
    }
    if bound > reachable {
        if !allow_partial {
            return Err(failed(format!(
                "recovery bound {bound} is beyond the last record the WAL and archive reach ({reachable}); pass allow_partial to accept {reachable}"
            )));
        }
        bound = reachable;
    }
    // The bound must be physical — truncate and delete, never filter in
    // memory. Records left on disk past the bound would be replayed by the
    // next ordinary open, silently resurrecting the timeline the caller asked
    // to discard.
    //
    // Header first LSNs locate the one segment that can contain the first
    // record past the bound without scanning every body: a segment whose
    // successor starts at or below `bound + 1` ends at or below the bound.
    let position = headers
        .iter()
        .rposition(|(_, first_lsn)| *first_lsn <= bound.saturating_add(1))
        .ok_or_else(|| {
            failed(format!(
                "no WAL segment reaches LSN {}; the log does not connect to the base checkpoint",
                bound.saturating_add(1)
            ))
        })?;
    let (trim_id, _) = headers[position];
    let trim_path = wal_directory.join(crate::segment_name(trim_id));
    if let Some(offset) = crate::scan_to_lsn(&trim_path, trim_id, bound)? {
        let file = OpenOptions::new().write(true).open(&trim_path)?;
        file.set_len(offset)?;
        file.sync_all()?;
    }
    for (id, _) in &headers[position + 1..] {
        fs::remove_file(wal_directory.join(crate::segment_name(*id)))?;
    }
    crate::sync_directory(&wal_directory)?;
    // A stock open replays to the physical end of the log, which the trim just
    // made the bound; no state repairs and no recovery-only code paths.
    let mut engine = Engine::open(target)?;
    if engine.sequence() != bound {
        return Err(failed(format!(
            "replay ended at LSN {} instead of the requested bound {bound}",
            engine.sequence()
        )));
    }
    // The checkpoint makes the recovery durable: CURRENT now names the bound,
    // and its segment cleanup drops everything the new root covers.
    engine.checkpoint()?;
    drop(engine);
    Ok(bound)
}

/// A failed recovery leaves `target` in an undefined intermediate state, so
/// every error tells the caller to discard it rather than patch it in place.
fn failed(message: String) -> Error {
    Error::CorruptBackup(format!(
        "{message}; delete the recovery target and start over"
    ))
}

/// Unions the archive's segments into the restored wal/.
///
/// A segment id present in both places is not automatically a conflict: the
/// base backup copied the then-active segment mid-write, so its copy is a
/// legitimate partial prefix of the sealed archive copy. The comparison stops
/// at the shorter file's last complete record boundary because the source may
/// have truncated a torn tail after the backup was taken — a raw full-length
/// prefix check would reject that healthy pair as foreign.
fn merge_archive(wal_directory: &Path, archive_directory: &Path) -> Result<()> {
    let entries = wal_archive::read_index(archive_directory)?;
    let present: BTreeSet<u64> = wal_ids(wal_directory)?.into_iter().collect();
    for entry in &entries {
        let name = crate::segment_name(entry.segment_id);
        let source = archive_directory.join(&name);
        let destination = wal_directory.join(&name);
        if present.contains(&entry.segment_id) {
            let base = fs::read(&destination)?;
            let archived = fs::read(&source)?;
            // Compared by records rather than by file length. Both copies carry
            // a zero-filled runway past their records, and the archived copy
            // wrote further records into the very bytes the base backup copied
            // as runway, so the two files can be the same size while holding
            // different amounts of history. Whichever stops first is as far as
            // they can be expected to agree.
            let base_end = last_record_boundary(&base);
            let archived_end = last_record_boundary(&archived);
            let boundary = base_end.min(archived_end);
            if base[..boundary] != archived[..boundary] {
                return Err(failed(format!(
                    "segment {} in {} does not share a history with the archived copy in {}; the archive belongs to a different timeline",
                    entry.segment_id,
                    destination.display(),
                    source.display()
                )));
            }
            if archived_end > base_end {
                write_segment(wal_directory, &name, &archived)?;
            }
        } else {
            // Only in the archive: a checkpoint deleted the local copy after
            // it was archived. The base's own newest segment may equally be
            // absent from the archive (it was never sealed) — it is kept as is.
            let archived = fs::read(&source)?;
            write_segment(wal_directory, &name, &archived)?;
        }
    }
    crate::sync_directory(wal_directory)?;
    Ok(())
}

/// Writes a merged segment durably next to its final name before renaming it
/// in, so an interrupted merge never leaves a half-copied segment under a name
/// replay would trust.
fn write_segment(wal_directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = wal_directory.join(format!("{name}.tmp"));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, wal_directory.join(name))?;
    Ok(())
}

/// Segment ids present in a wal directory, without `list_segments`' gap
/// check, so recovery can name exactly which ids a broken merge is missing.
fn wal_ids(directory: &Path) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(number) = name.strip_suffix(".vwal") {
            ids.push(
                number.parse::<u64>().map_err(|_| {
                    failed(format!("invalid segment name {name} in recovery target"))
                })?,
            );
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// The length of the record frame at `offset`, or `None` where the records end.
///
/// A segment is longer than its records: the writer keeps a zero-filled runway
/// ahead of them so its barrier has no extent update to journal. Walking the
/// declared lengths alone would step through that runway frame by frame, since
/// zeros decode as a zero-length payload, so the frame's magic is what says
/// whether a record is there at all. Bodies are still left unverified — replay
/// re-validates every byte it applies, and the framing alone is enough to find
/// where a torn or partial copy stops being comparable.
fn record_frame_len(bytes: &[u8], offset: usize) -> Option<usize> {
    if bytes.len() - offset < crate::RECORD_HEADER_LEN
        || &bytes[offset..offset + 4] != crate::RECORD_MAGIC
        || bytes[offset + 4] != crate::VERSION
    {
        return None;
    }
    let payload_len = crate::read_u32(bytes, offset + 17) as usize;
    crate::RECORD_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|size| size.checked_add(crate::RECORD_FOOTER_LEN))
        .filter(|total| *total <= bytes.len() - offset)
}

/// Byte offset just past the last complete record frame.
fn last_record_boundary(bytes: &[u8]) -> usize {
    let mut offset = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    while let Some(total_len) = record_frame_len(bytes, offset) {
        offset += total_len;
    }
    offset
}

/// LSN of the last complete record in a segment, or `first_lsn - 1` when it
/// has none. The restored active segment may carry a torn tail (replay will
/// truncate it), so an incomplete final frame is ignored rather than fatal.
fn last_record_lsn(path: &Path, first_lsn: u64) -> Result<u64> {
    let bytes = fs::read(path)?;
    let mut last = first_lsn.saturating_sub(1);
    let mut offset = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    while let Some(total_len) = record_frame_len(&bytes, offset) {
        last = crate::read_u64(&bytes, offset + 5);
        offset += total_len;
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backup, Engine};
    use tempfile::tempdir;

    /// Base at LSN 1 (k1 checkpointed), backup taken with k2 in the active
    /// segment, then k3/k4 committed and the segment sealed and archived. The
    /// backup's copy of that segment is a strict byte prefix of the archived
    /// one.
    fn seed(database: &Path, backup_file: &Path, archive: &Path) {
        {
            let mut engine = Engine::open(database).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.checkpoint().unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        }
        backup::create_backup(database, backup_file).unwrap();
        {
            let mut engine = Engine::open(database).unwrap();
            engine.put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
            engine.put(b"k4".to_vec(), b"v4".to_vec()).unwrap();
            engine.rotate_for_archive().unwrap();
        }
        wal_archive::archive_pending(&database.join("wal"), archive).unwrap();
    }

    /// A base backup copies the then-active segment mid-write, so the same id
    /// exists in both the base and the archive with different lengths; a raw
    /// full-file compare (or blindly keeping the base copy) would either
    /// reject every recovery or silently drop the sealed tail.
    #[test]
    fn recovers_past_the_backup_through_a_partially_backed_up_segment() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        seed(database.path(), &backup_file, &archive);
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        let shared = crate::segment_name(2);
        assert!(
            fs::metadata(target.join("wal").join(&shared))
                .unwrap()
                .len()
                < fs::metadata(archive.join(&shared)).unwrap().len()
        );
        let achieved = recover_to(&target, Some(&archive), None, false).unwrap();
        assert_eq!(achieved, 4);
        let engine = Engine::open(&target).unwrap();
        for (key, value) in [
            (b"k1", b"v1"),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
            (b"k4", b"v4"),
        ] {
            assert_eq!(engine.get(key).unwrap(), Some(value.to_vec()));
        }
    }

    /// The checkpoint root in the base already contains every commit at or
    /// below its manifest LSN and redo only rolls forward, so accepting an
    /// earlier bound would return a database containing commits past the
    /// requested point while claiming it stopped there.
    #[test]
    fn rejects_a_bound_below_the_base_checkpoint() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        seed(database.path(), &backup_file, &archive);
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        let error = recover_to(&target, Some(&archive), Some(0), false).unwrap_err();
        assert!(matches!(error, Error::CorruptBackup(_)));
    }

    /// A bound past the archive's end cannot be reached; stopping short
    /// silently would hand back a database missing commits the caller asked
    /// for, so falling back to the reachable LSN must be an explicit opt-in.
    #[test]
    fn rejects_a_bound_beyond_the_archive_unless_partial_is_allowed() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        seed(database.path(), &backup_file, &archive);
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        let error = recover_to(&target, Some(&archive), Some(999), false).unwrap_err();
        assert!(matches!(error, Error::CorruptBackup(_)));
        assert_eq!(
            recover_to(&target, Some(&archive), Some(999), true).unwrap(),
            4
        );
    }

    /// A crash mid-append leaves a torn frame at the active segment's tail —
    /// a state a plain `Engine::open` repairs by truncation — and
    /// `create_backup` copies the crashed, never-reopened directory verbatim,
    /// so the tear survives into the restored base. The trim scan used to be
    /// strict about framing, which made `recover_to` fail on exactly those
    /// bytes on every retry, leaving a fully intact backup permanently
    /// unrecoverable through the recovery path.
    #[test]
    fn recovers_a_base_backup_whose_active_segment_has_a_torn_tail() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        {
            let mut engine = Engine::open(database.path()).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.checkpoint().unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        }
        // Simulate the crash: 20 bytes of a record header, torn inside the
        // 45-byte header, appended to the active segment (id 2 after the
        // checkpoint's rotation).
        let segment = database.path().join("wal").join(crate::segment_name(2));
        let mut torn = vec![0u8; 20];
        torn[0..4].copy_from_slice(b"VTXN");
        torn[4] = crate::VERSION;
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(&torn).unwrap();
        drop(file);
        backup::create_backup(database.path(), &backup_file).unwrap();
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        assert_eq!(recover_to(&target, None, None, false).unwrap(), 2);
        let engine = Engine::open(&target).unwrap();
        assert_eq!(engine.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(engine.get(b"k2").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(engine.sequence(), 2);
    }

    /// Records left on disk past the bound would be replayed by the next
    /// ordinary open, silently resurrecting the discarded timeline; the trim
    /// must survive a plain reopen, not just the recovery process's memory.
    #[test]
    fn trims_records_past_the_bound_physically() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        seed(database.path(), &backup_file, &archive);
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        assert_eq!(
            recover_to(&target, Some(&archive), Some(3), false).unwrap(),
            3
        );
        let engine = Engine::open(&target).unwrap();
        assert_eq!(engine.get(b"k3").unwrap(), Some(b"v3".to_vec()));
        assert_eq!(engine.get(b"k4").unwrap(), None);
        assert_eq!(engine.sequence(), 3);
    }
}
