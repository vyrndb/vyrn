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

use crate::Result;
use std::{
    fs::File,
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

/// A shared handle to the active WAL segment.
pub struct Wal {
    /// The descriptor records are appended through.
    writer: Mutex<File>,
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

impl Wal {
    pub(crate) fn new(file: File) -> Result<Self> {
        let syncer = file.try_clone()?;
        Ok(Self {
            writer: Mutex::new(file),
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
        writer.write_all(record)?;
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

    /// Flushes the current segment and then switches to `file`.
    ///
    /// The outgoing segment is made fully durable first. Recovery stops at the
    /// first gap it finds, so a durable record in a new segment must never sit
    /// behind an unflushed record in the previous one.
    pub(crate) fn rotate(&self, file: File) -> Result<()> {
        let mut writer = self.writer.lock().map_err(|_| crate::Error::Poisoned)?;
        let mut syncer = self.syncer.lock().map_err(|_| crate::Error::Poisoned)?;
        let covered = self.appended_lsn.load(Ordering::Acquire);
        syncer.sync_data()?;
        self.synced_lsn.fetch_max(covered, Ordering::AcqRel);
        *syncer = file.try_clone()?;
        *writer = file;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn wal(path: &std::path::Path) -> Wal {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        Wal::new(file).unwrap()
    }

    /// One barrier must cover every record appended before it began. This is what
    /// lets several applied batches share a single `fdatasync`.
    #[test]
    fn one_flush_covers_every_earlier_append() {
        let directory = tempdir().unwrap();
        let wal = wal(&directory.path().join("segment"));
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
        let wal = wal(&directory.path().join("segment"));
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
}
