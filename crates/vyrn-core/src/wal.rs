//! The active WAL segment, shared so its `fdatasync` can run off the write lock.
//!
//! The commit path used to hold the engine's write lock across the flush, which
//! made the barrier strictly serial: no other batch could apply its mutations
//! while a sync was in flight, and every batch paid its own sync. `fdatasync` is
//! the most expensive step in a commit by an order of magnitude, so both of those
//! matter.
//!
//! Appends and syncs therefore use separate descriptors for the same file. A
//! writer can append the next batch's record while a previous batch's flush is
//! still running, and `sync_through` coalesces: a flush that begins after a
//! record was appended also makes that record durable, so concurrent committers
//! waiting on the same barrier are satisfied by one call instead of one each.
//!
//! Records are written into a zero-filled runway rather than appended to the end
//! of the file. A commit that extends the segment makes `fdatasync` journal an
//! extent-tree update as well as the data, which on ext4 measured 1,444 µs
//! against 593 µs for the same write into blocks that were already allocated and
//! initialised — the single largest component of write latency. The runway is
//! pushed ahead in 1 MiB steps, and each step costs one expensive sync that
//! thousands of commits then amortise.

use crate::Result;
use std::{
    fs::File,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

/// How far ahead of the write point the segment is zero-filled.
///
/// Large enough that extending it is rare — one 1 MiB fill served roughly seven
/// hundred 1.5 KiB records when this was measured — and small enough that a
/// sealed segment's unused tail, which archives and backups copy verbatim, stays
/// negligible beside a 64 MiB segment.
const RUNWAY: u64 = 1 << 20;

/// A shared handle to the active WAL segment.
pub struct Wal {
    /// The descriptor records are written through, with its write position.
    writer: Mutex<Writer>,
    /// A second descriptor for the same file, used only for `fdatasync`.
    ///
    /// Syncing through its own descriptor means a flush never holds the append
    /// lock, so the next batch can be written while this one is being flushed.
    syncer: Mutex<File>,
    /// The highest LSN whose record has been handed to the kernel.
    appended_lsn: AtomicU64,
    /// The highest LSN known to be durable.
    synced_lsn: AtomicU64,
}

/// The append side of a segment: where records end, and how far the file has
/// been zero-filled past that point.
struct Writer {
    file: File,
    /// Offset the next record is written at. This is the end of the records, not
    /// the end of the file, which runs ahead of it by the unused runway.
    offset: u64,
    /// Bytes zero-filled and made durable. A record written below this point
    /// lands in blocks that already exist and are already initialised, so its
    /// barrier has no metadata to journal.
    zeroed: u64,
    /// Ceiling on how far a single extension reaches, so a segment smaller than
    /// the runway is not zero-filled far past its own size.
    runway: u64,
    /// Zero bytes this writer has laid down, counted for the test that a large
    /// record is not pre-filled.
    ///
    /// The waste that test guards against is bytes WRITTEN, not bytes left
    /// behind: a fill sized to the record covers exactly the span the record then
    /// overwrites, so the finished file is byte-for-byte identical either way and
    /// its length cannot tell the two apart. This counter can.
    #[cfg(test)]
    zero_filled: u64,
}

impl Writer {
    /// Zero-fills forward until `wanted` bytes past `offset` are covered.
    ///
    /// Synced here rather than left for the next record's barrier so that every
    /// record pays the same cheap flush and the expensive one is isolated to the
    /// extension that caused it.
    ///
    /// A record that does not fit inside one runway step is left to initialise its
    /// own blocks. The fill used to be widened to `max(runway, wanted)`, which
    /// meant a record larger than the runway had its whole span written twice:
    /// once as zeros, with an `fdatasync` behind them, and once as the record that
    /// overwrote every one of those zeros microseconds later. At 128 B that is
    /// invisible; at 1 MiB it is the dominant cost of the commit, and it is why a
    /// four-value 1 MiB workload left an 8 MiB WAL segment behind for 4 MiB of
    /// data. The runway's whole purpose is to amortise one expensive
    /// extent-extending barrier over many small records, and a record of a
    /// megabyte amortises that barrier over its own payload perfectly well by
    /// itself — there is nothing left for the pre-fill to buy.
    fn reserve(&mut self, wanted: u64) -> Result<()> {
        let required = self.offset.saturating_add(wanted);
        if required <= self.zeroed {
            return Ok(());
        }
        let target = self.zeroed.saturating_add(self.runway);
        if required > target {
            // The record's own write extends and initialises the file here.
            // `append` records how far that reached, so the bytes it covered are
            // not zero-filled again afterwards.
            return Ok(());
        }
        let zeros = vec![0; (target - self.zeroed) as usize];
        write_all_at(&self.file, &zeros, self.zeroed)?;
        self.file.sync_data()?;
        #[cfg(test)]
        {
            self.zero_filled += zeros.len() as u64;
        }
        self.zeroed = target;
        Ok(())
    }
}

impl Wal {
    /// Opens `file` for appending at `offset`, which must be the end of its
    /// records rather than the end of the file.
    pub(crate) fn new(file: File, offset: u64, runway: u64) -> Result<Self> {
        let syncer = file.try_clone()?;
        Ok(Self {
            writer: Mutex::new(Writer {
                file,
                offset,
                // Nothing past the records is trusted to be initialised: a
                // segment may have been truncated by replay, restored from a
                // backup, or left by an older build that appended. The first
                // record re-establishes the runway from here.
                zeroed: offset,
                runway: runway.clamp(1, RUNWAY),
                #[cfg(test)]
                zero_filled: 0,
            }),
            syncer: Mutex::new(syncer),
            appended_lsn: AtomicU64::new(0),
            synced_lsn: AtomicU64::new(0),
        })
    }

    /// Writes `record` to the segment without flushing it.
    ///
    /// The record is durable only once [`Wal::sync_through`] has returned for
    /// `lsn`, so a caller must not acknowledge the commit before then.
    pub(crate) fn append(&self, record: &[u8], lsn: u64) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| crate::Error::Poisoned)?;
        writer.reserve(record.len() as u64)?;
        let offset = writer.offset;
        write_all_at(&writer.file, record, offset)?;
        writer.offset = offset + record.len() as u64;
        // A record that `reserve` declined to pre-fill has just initialised those
        // blocks itself. The frontier MUST move with it: `reserve` writes its
        // zeros starting at `zeroed`, so leaving `zeroed` behind the record end
        // would make the next small record's pre-fill lay zeros straight over the
        // record just written.
        writer.zeroed = writer.zeroed.max(writer.offset);
        drop(writer);
        // Publish only after the bytes are in the kernel, so a concurrent flush
        // never reports an LSN durable whose write had not been issued yet.
        self.appended_lsn.fetch_max(lsn, Ordering::AcqRel);
        Ok(())
    }

    /// Makes every record up to and including `lsn` durable.
    ///
    /// Coalescing: the LSN a flush covers is read before the flush begins, so
    /// any record appended before that point is durable when it returns. Callers
    /// that were waiting for an earlier LSN then find their work already done and
    /// return without flushing again.
    pub fn sync_through(&self, lsn: u64) -> Result<()> {
        if self.synced_lsn.load(Ordering::Acquire) >= lsn {
            return Ok(());
        }
        let syncer = self.syncer.lock().map_err(|_| crate::Error::Poisoned)?;
        // Another flush may have covered this LSN while this caller waited.
        if self.synced_lsn.load(Ordering::Acquire) >= lsn {
            return Ok(());
        }
        // Read before flushing, never after: a record appended once the flush is
        // already running may not be included in it.
        let covered = self.appended_lsn.load(Ordering::Acquire);
        syncer.sync_data()?;
        self.synced_lsn.fetch_max(covered, Ordering::AcqRel);
        Ok(())
    }

    /// The highest LSN handed to the kernel, durable or not.
    pub(crate) fn appended(&self) -> u64 {
        self.appended_lsn.load(Ordering::Acquire)
    }

    /// Flushes the current segment and then switches to `file`, whose records
    /// end at `offset`.
    ///
    /// The outgoing segment is made fully durable first. Recovery stops at the
    /// first gap it finds, so a durable record in a new segment must never sit
    /// behind an unflushed record in the previous one.
    pub(crate) fn rotate(&self, file: File, offset: u64) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| crate::Error::Poisoned)?;
        let mut syncer = self.syncer.lock().map_err(|_| crate::Error::Poisoned)?;
        let covered = self.appended_lsn.load(Ordering::Acquire);
        syncer.sync_data()?;
        self.synced_lsn.fetch_max(covered, Ordering::AcqRel);
        *syncer = file.try_clone()?;
        writer.file = file;
        writer.offset = offset;
        writer.zeroed = offset;
        Ok(())
    }

    /// Adopts `lsn` as the durability floor for a freshly opened segment.
    pub(crate) fn adopt(&self, lsn: u64) {
        self.appended_lsn.fetch_max(lsn, Ordering::AcqRel);
        self.synced_lsn.fetch_max(lsn, Ordering::AcqRel);
    }

    #[cfg(test)]
    fn synced(&self) -> u64 {
        self.synced_lsn.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn offset(&self) -> u64 {
        self.writer.lock().unwrap().offset
    }

    #[cfg(test)]
    fn zero_filled(&self) -> u64 {
        self.writer.lock().unwrap().zero_filled
    }
}

#[cfg(unix)]
fn write_all_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buffer, offset)
}

#[cfg(windows)]
fn write_all_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0;
    while written < buffer.len() {
        match file.seek_write(&buffer[written..], offset + written as u64) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ))
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;

    fn wal(path: &std::path::Path, runway: u64) -> Wal {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        Wal::new(file, 0, runway).unwrap()
    }

    /// One barrier must cover every record appended before it began. This is what
    /// lets several applied batches share a single `fdatasync`.
    #[test]
    fn one_flush_covers_every_earlier_append() {
        let directory = tempdir().unwrap();
        let wal = wal(&directory.path().join("segment"), RUNWAY);
        wal.append(b"first", 1).unwrap();
        wal.append(b"second", 2).unwrap();
        wal.append(b"third", 3).unwrap();
        assert_eq!(wal.synced(), 0, "appending must not flush");

        wal.sync_through(3).unwrap();
        assert_eq!(wal.synced(), 3);

        // Earlier waiters are already satisfied, so they must not flush again.
        wal.sync_through(1).unwrap();
        wal.sync_through(2).unwrap();
        assert_eq!(wal.synced(), 3);
    }

    /// A flush must never report an LSN durable whose record it did not cover.
    #[test]
    fn a_later_append_is_not_covered_by_an_earlier_flush() {
        let directory = tempdir().unwrap();
        let wal = wal(&directory.path().join("segment"), RUNWAY);
        wal.append(b"first", 1).unwrap();
        wal.sync_through(1).unwrap();
        assert_eq!(wal.synced(), 1);

        wal.append(b"second", 2).unwrap();
        assert_eq!(
            wal.synced(),
            1,
            "the new record is not durable until it is flushed"
        );
        wal.sync_through(2).unwrap();
        assert_eq!(wal.synced(), 2);
    }

    /// Records must land end to end at the write offset, not wherever the runway
    /// left the file cursor.
    #[test]
    fn records_are_written_consecutively_inside_the_runway() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("segment");
        let wal = wal(&path, 64);
        wal.append(b"first", 1).unwrap();
        wal.append(b"second", 2).unwrap();
        wal.append(b"third", 3).unwrap();
        assert_eq!(wal.offset(), 16);

        let mut contents = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(&contents[0..16], b"firstsecondthird");
        assert!(
            contents.len() >= 64,
            "the runway should have been zero-filled ahead of the records"
        );
        assert!(
            contents[16..].iter().all(|byte| *byte == 0),
            "the runway past the records must be zeros"
        );
    }

    /// A record too large for one runway step must not have its span written
    /// twice.
    ///
    /// `reserve` used to widen its fill to `max(runway, wanted)`, so a 1 MiB
    /// record was preceded by 1 MiB of zeros AND an `fdatasync` behind them,
    /// every byte of which the record then overwrote. Both writes are counted
    /// here through the file's own byte counter rather than by timing, because
    /// the waste is deterministic and a timing on this host is not: a four-value
    /// 1 MiB workload left an 8 MiB segment behind for 4 MiB of records.
    #[test]
    fn a_record_larger_than_the_runway_is_not_written_twice() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("segment");
        // A runway far smaller than the record, which is the shape a large value
        // takes against the 1 MiB default.
        let wal = wal(&path, 4_096);
        let record = vec![7; 512 * 1024];
        wal.append(&record, 1).unwrap();
        wal.sync_through(1).unwrap();
        // Bytes written, not bytes left behind: a fill sized to the record covers
        // exactly the span the record overwrites, so the finished file is
        // identical either way and its length cannot tell the two apart. Before
        // the fix this was 512 KiB of zeros — the record's whole span, written and
        // fsynced immediately before the record itself landed on top of it.
        assert_eq!(
            wal.zero_filled(),
            0,
            "a record larger than the runway must not have its span pre-filled; \
             those zeros are written and flushed only to be overwritten at once"
        );

        // The frontier has to follow the record, or the next small record's
        // pre-fill lays zeros over the record just written.
        wal.append(b"after", 2).unwrap();
        wal.sync_through(2).unwrap();
        let mut contents = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(
            &contents[..record.len()],
            &record[..],
            "the large record was overwritten by a later runway fill"
        );
        assert_eq!(&contents[record.len()..record.len() + 5], b"after");
    }

    /// The runway has to grow past its step size for a record larger than it,
    /// or a large transaction could not be written at all.
    #[test]
    fn a_record_larger_than_the_runway_still_fits() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("segment");
        let wal = wal(&path, 16);
        let record = vec![7; 5_000];
        wal.append(&record, 1).unwrap();
        wal.append(b"after", 2).unwrap();
        assert_eq!(wal.offset(), 5_005);

        let mut contents = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(&contents[0..5_000], &record[..]);
        assert_eq!(&contents[5_000..5_005], b"after");
    }

    /// Rotation moves the writer to the new segment's record end, and the runway
    /// restarts from there rather than carrying the old segment's frontier.
    #[test]
    fn rotation_restarts_the_runway_at_the_new_segments_records() {
        let directory = tempdir().unwrap();
        let wal = wal(&directory.path().join("first"), 64);
        wal.append(b"first", 1).unwrap();

        let next = directory.path().join("second");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&next)
            .unwrap();
        wal.rotate(file, 8).unwrap();
        wal.append(b"second", 2).unwrap();
        assert_eq!(wal.offset(), 14);

        let mut contents = Vec::new();
        std::fs::File::open(&next)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(&contents[8..14], b"second");
    }
}
