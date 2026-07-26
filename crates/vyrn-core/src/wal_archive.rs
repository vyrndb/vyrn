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
