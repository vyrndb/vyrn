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
    // Segment ids come from filenames, which are untrusted: a recovery target is
    // a directory an operator assembled by hand from a restored backup and an
    // archive, and anything matching `{digits}.vwal` lands in `ids`. Enumerating
    // every id in a gap would materialize the whole span, so a directory holding
    // segments 1 and u64::MAX — a typo, a truncated copy, a hostile tarball —
    // pushed 1.8×10^19 strings and hung the process instead of reporting the
    // gap. The names of the gap's edges say everything an operator needs, so the
    // report is bounded: the first few missing ids and, when the span exceeds
    // them, how many there are in total.
    const NAMED_MISSING: usize = 8;
    let mut missing: Vec<String> = Vec::new();
    let mut missing_count: u64 = 0;
    for pair in ids.windows(2) {
        // Saturating throughout: `pair[0] + 1` overflows on a segment literally
        // named u64::MAX, and release keeps overflow-checks on, so that is a
        // panic rather than a wrap.
        missing_count =
            missing_count.saturating_add(pair[1].saturating_sub(pair[0]).saturating_sub(1));
        missing.extend(
            (pair[0].saturating_add(1)..pair[1])
                .take(NAMED_MISSING.saturating_sub(missing.len()))
                .map(|id| id.to_string()),
        );
    }
    if missing_count != 0 {
        let unnamed = missing_count - missing.len() as u64;
        let named = missing.join(", ");
        let detail = if unnamed == 0 {
            named
        } else {
            format!("{named} and {unnamed} more")
        };
        return Err(failed(format!(
            "merged WAL is missing segment(s) {detail}; the archive and base backup do not connect"
        )));
    }
    let mut headers = Vec::with_capacity(ids.len());
    for &id in &ids {
        let first_lsn = crate::read_segment_first_lsn(&wal_directory.join(crate::segment_name(id)))
            .map_err(|error| failed(format!("segment {id} has an unreadable header ({error})")))?;
        headers.push((id, first_lsn));
    }
    for pair in headers.windows(2) {
        // Equality is a splice too: segment headers carry no filename to
        // contradict, so one file copied over another's name presents two
        // adjacent segments claiming the same first LSN. Replaying both would
        // silently skip or repeat the shared records depending on where the
        // copy sits, so the merged log must be strictly increasing.
        if pair[1].1 <= pair[0].1 {
            return Err(failed(format!(
                "segment {} starts at LSN {}, at or before its predecessor segment {} at {}; the merged WAL contains a duplicated or reordered segment",
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
        // The index is the archive's own claim about the bytes it shipped, and
        // recovery is the one reader that adopts those bytes wholesale, so the
        // claim has to be re-checked here: `archive_pending` verifies on every
        // run, but an archive damaged after it was written would otherwise
        // replace a good base copy with rot under a name replay trusts.
        let archived = fs::read(&source)?;
        if crate::checksum(&archived) != entry.crc {
            return Err(failed(format!(
                "archived segment {} does not match the checksum recorded for it in the archive index; the archived copy is damaged",
                entry.segment_id
            )));
        }
        if present.contains(&entry.segment_id) {
            let base = fs::read(&destination)?;
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

/// One past the last non-zero byte in `bytes`, or the header length when the
/// segment holds no records at all.
///
/// The writer zero-fills and syncs a runway ahead of its records before writing
/// them, so a crash-torn record still has every physical byte its header
/// declares — a declared-length check alone therefore counts a torn tail as a
/// complete record. What separates torn from whole is the last byte a writer
/// actually touched: every complete record ends with the four non-zero bytes of
/// its end marker, so a whole record can never reach past this point, and a
/// frame that does is necessarily torn. The same rule replay itself applies.
fn last_written_byte(bytes: &[u8]) -> usize {
    let floor = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(floor, |index| (index + 1).max(floor))
}

/// The length of the record frame at `offset`, or `None` where the records end.
///
/// A segment is longer than its records: the writer keeps a zero-filled runway
/// ahead of them so its barrier has no extent update to journal. Walking the
/// declared lengths alone would step through that runway frame by frame, since
/// zeros decode as a zero-length payload, so the frame's magic is what says
/// whether a record starts here at all. The magic alone is not enough — the
/// runway means even a torn record's declared bytes are all physically present —
/// so a frame also has to end at or before `written_through`. A tear inside the
/// header decodes a garbage length or LSN from zeros; either way the forged
/// frame reaches past the last written byte and stops the walk. Bodies stay
/// unverified either way — replay re-validates every byte it applies, and the
/// framing only has to find where comparable history ends.
fn record_frame_len(bytes: &[u8], offset: usize, written_through: usize) -> Option<usize> {
    if bytes.len() - offset < crate::RECORD_HEADER_LEN
        || offset + crate::RECORD_HEADER_LEN > written_through
        || &bytes[offset..offset + 4] != crate::RECORD_MAGIC
        || !crate::record_version_known(&bytes[offset..offset + crate::RECORD_HEADER_LEN])
        // A header that fails its own checksum declares lengths this walk
        // must not step by; the frame boundary is here.
        || !crate::record_header_crc_ok(&bytes[offset..offset + crate::RECORD_HEADER_LEN])
    {
        return None;
    }
    let payload_len = crate::read_u32(bytes, offset + 17) as usize;
    crate::RECORD_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|size| size.checked_add(crate::RECORD_FOOTER_LEN))
        .filter(|total| offset + *total <= written_through)
}

/// Byte offset just past the last complete record frame.
fn last_record_boundary(bytes: &[u8]) -> usize {
    let written_through = last_written_byte(bytes);
    let mut offset = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    while let Some(total_len) = record_frame_len(bytes, offset, written_through) {
        offset += total_len;
    }
    offset
}

/// LSN of the last complete record in a segment, or `first_lsn - 1` when it
/// has none. The restored active segment may carry a torn tail (replay will
/// truncate it), so an incomplete final frame — including one whose declared
/// bytes the runway makes fully present — is ignored rather than fatal.
fn last_record_lsn(path: &Path, first_lsn: u64) -> Result<u64> {
    let bytes = fs::read(path)?;
    let written_through = last_written_byte(&bytes);
    let mut last = first_lsn.saturating_sub(1);
    let mut offset = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    while let Some(total_len) = record_frame_len(&bytes, offset, written_through) {
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

    /// A crash mid-append tears the active segment's tail: the runway was
    /// zero-filled and synced before the record began, its first bytes reached
    /// the disk, and the rest never happened. `create_backup` copies the
    /// crashed, never-reopened directory verbatim, so recovery meets exactly
    /// those bytes. Counting declared lengths used to mistake such a tail for a
    /// complete record — the runway always supplies enough physical bytes — so
    /// default PITR demanded an LSN the torn log could never deliver and failed
    /// on every retry; the reachable bound now stops at the last record whose
    /// every byte lies at or before the last byte a writer touched.
    #[test]
    fn recovers_a_base_backup_whose_active_segment_has_a_torn_tail() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let segment = database.path().join("wal").join(crate::segment_name(2));
        {
            let mut engine = Engine::open(database.path()).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.checkpoint().unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        }
        // Everything up to the last non-zero byte is durable history (records
        // k2's commit); past it is the runway the writer synced before starting
        // the next record.
        let history = fs::read(&segment).unwrap();
        let written_through = last_written_byte(&history);
        {
            let mut engine = Engine::open(database.path()).unwrap();
            engine.put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
        }
        let logged = fs::read(&segment).unwrap();
        let full = last_written_byte(&logged);
        assert!(
            full > written_through + crate::RECORD_HEADER_LEN,
            "the third put should have been logged whole"
        );
        // Reconstruct the crash: the record's head landed over the zeroed
        // runway and the write stopped part-way through its payload, leaving
        // the header intact and everything from there on untouched zeros.
        let torn_at = written_through
            + crate::RECORD_HEADER_LEN
            + (full - written_through - crate::RECORD_HEADER_LEN) / 2;
        let mut crashed = vec![0u8; logged.len()];
        crashed[..torn_at].copy_from_slice(&logged[..torn_at]);
        fs::write(&segment, &crashed).unwrap();

        backup::create_backup(database.path(), &backup_file).unwrap();
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();
        assert_eq!(recover_to(&target, None, None, false).unwrap(), 2);
        let engine = Engine::open(&target).unwrap();
        assert_eq!(engine.get(b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(engine.get(b"k2").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(
            engine.get(b"k3").unwrap(),
            None,
            "the torn commit must not be applied"
        );
        assert_eq!(engine.sequence(), 2);
    }

    /// The archive index records a checksum beside every segment it shipped,
    /// and recovery is the one reader that adopts archived bytes wholesale.
    /// Skipping that check let damage above the base boundary — invisible to
    /// the shared-prefix comparison, which stops where the base copy's records
    /// stop — silently replace good base bytes with rot under a name replay
    /// trusts.
    #[test]
    fn rejects_an_archived_segment_that_no_longer_matches_its_index_checksum() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        let backup_file = auxiliary.path().join("base.bkp");
        let archive = auxiliary.path().join("archive");
        seed(database.path(), &backup_file, &archive);
        let target = auxiliary.path().join("restored");
        backup::restore_backup(&backup_file, &target).unwrap();

        // Flip a bit in the archived copy of the shared segment, somewhere the
        // base backup never copied: inside the sealed tail's last record, past
        // everything the prefix comparison can see.
        let shared = archive.join(crate::segment_name(2));
        let mut bytes = fs::read(&shared).unwrap();
        let base_boundary = last_record_boundary(
            &fs::read(target.join("wal").join(crate::segment_name(2))).unwrap(),
        );
        let flip_at = last_record_boundary(&bytes) - 4;
        assert!(
            flip_at > base_boundary,
            "the damage must sit above the base copy's records for this test to be honest"
        );
        bytes[flip_at] ^= 0x80;
        fs::write(&shared, &bytes).unwrap();

        let error = recover_to(&target, Some(&archive), None, false).unwrap_err();
        match error {
            Error::CorruptBackup(message) => assert!(
                message.contains("checksum"),
                "the error should name the index checksum mismatch, got: {message}"
            ),
            other => panic!("expected a checksum failure, got {other:?}"),
        }
    }

    /// Segment headers carry no filename to contradict, so one file copied over
    /// another's name presents two adjacent segments claiming the same first
    /// LSN. Only strict increase was enforced, so the duplicate sailed into
    /// replay, where the shared records are skipped or repeated depending on
    /// where the copy sits — a spliced WAL recovering as success.
    #[test]
    fn rejects_two_adjacent_segments_claiming_the_same_first_lsn() {
        let database = tempdir().unwrap();
        let auxiliary = tempdir().unwrap();
        // Small segments seal after a record or two, giving the log several
        // real segments to splice.
        {
            let mut engine = Engine::open_with_segment_size(database.path(), 128).unwrap();
            for index in 1..=6_u64 {
                engine
                    .put(format!("k{index}").into_bytes(), vec![index as u8; 16])
                    .unwrap();
            }
        }
        let target = auxiliary.path().join("spliced");
        copy_wal_tree(database.path(), &target);
        fs::copy(
            target.join("wal").join(crate::segment_name(1)),
            target.join("wal").join(crate::segment_name(2)),
        )
        .unwrap();

        let error = recover_to(&target, None, None, false).unwrap_err();
        match error {
            Error::CorruptBackup(message) => assert!(
                message.contains("duplicated or reordered"),
                "the error should name the duplicated segment, got: {message}"
            ),
            other => panic!("expected a splice rejection, got {other:?}"),
        }
    }

    /// Copies a stopped database directory without its lock file, so a scenario
    /// can be tampered with in place.
    fn copy_wal_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target.join("wal")).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == "LOCK" || entry.file_name() == "wal" {
                continue;
            }
            fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
        for entry in fs::read_dir(source.join("wal")).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), target.join("wal").join(entry.file_name())).unwrap();
        }
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
