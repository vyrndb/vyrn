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
    let base_lsn = crate::manifest_lsn(target).map_err(|error| {
        failed(format!(
            "recovery target has no readable checkpoint manifest ({error})"
        ))
    })?;
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
            let shorter: &[u8] = if base.len() <= archived.len() {
                &base
            } else {
                &archived
            };
            let boundary = last_record_boundary(shorter);
            if base[..boundary] != archived[..boundary] {
                return Err(failed(format!(
                    "segment {} in {} does not share a history with the archived copy in {}; the archive belongs to a different timeline",
                    entry.segment_id,
                    destination.display(),
                    source.display()
                )));
            }
            if archived.len() > base.len() {
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

/// Byte offset just past the last complete record frame, walking only the
/// declared lengths. Bodies are left unverified because replay re-validates
/// every byte it applies; the framing alone is enough to find where a torn or
/// partial copy stops being comparable.
fn last_record_boundary(bytes: &[u8]) -> usize {
    let mut offset = crate::SEGMENT_HEADER_LEN.min(bytes.len());
    while bytes.len() - offset >= crate::RECORD_HEADER_LEN {
        let payload_len = crate::read_u32(bytes, offset + 17) as usize;
        let Some(total_len) = crate::RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(crate::RECORD_FOOTER_LEN))
        else {
            break;
        };
        if total_len > bytes.len() - offset {
            break;
        }
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
    while bytes.len() - offset >= crate::RECORD_HEADER_LEN {
        let payload_len = crate::read_u32(&bytes, offset + 17) as usize;
        let Some(total_len) = crate::RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(crate::RECORD_FOOTER_LEN))
        else {
            break;
        };
        if total_len > bytes.len() - offset {
            break;
        }
        last = crate::read_u64(&bytes, offset + 5);
        offset += total_len;
    }
    Ok(last)
}

