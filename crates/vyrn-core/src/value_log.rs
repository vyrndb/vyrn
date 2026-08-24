use crate::{fast_hash::U64Map, Error, Result, MAX_VALUE_SIZE};
use crc32fast::Hasher;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, Mutex},
};

const MAGIC: &[u8; 4] = b"VVAL";
const END: &[u8; 4] = b"VEND";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 24;
const FOOTER_LEN: usize = 8;

/// Value size below which `read` reads the whole framed record at once and
/// copies the value out, rather than reading the framing separately to avoid
/// that copy.
///
/// The trade is one memcpy of the value against one extra positioned read. A
/// read syscall on this host costs roughly 2 µs regardless of size, which a
/// 64 KiB copy comfortably beats and a 4 KiB copy does not: reading the framing
/// separately for every value regressed `scan_1000/4kib` from 11.6 ms to 14.9 ms,
/// while at 1 MiB the same change took `point_get` from 1.13 ms to 788 µs. 32 KiB
/// sits between the two measured points; the exact crossover is host-specific and
/// the curve is flat around it, so this is deliberately a round number rather
/// than a tuned one.
const COPY_RATHER_THAN_SEEK: usize = 32 * 1024;

/// Upper bound on one coalesced read in [`ValueLog::read_many`], so a run of
/// large adjacent values cannot demand an arbitrarily large buffer.
const MAX_COALESCED_READ: usize = 1024 * 1024;

/// Default byte budget for one handle's validated-value cache.
///
/// `VYRN_VALUE_CACHE_BYTES` overrides it; `0` disables the cache. The budget
/// is PER HANDLE — the engine and every read handle keep their own — so a
/// server with the default sixteen read handles can hold up to seventeen
/// times this much in hot values. The default is deliberately far below what
/// comparable embedded stores reserve (sled defaults to a gigabyte): the OS
/// page cache already keeps the bytes warm, and what this cache removes is
/// the per-read syscall and checksum pass, which do not need a large budget
/// to disappear for a hot working set.
const DEFAULT_VALUE_CACHE_BYTES: usize = 64 * 1024 * 1024;

fn cache_budget() -> usize {
    std::env::var("VYRN_VALUE_CACHE_BYTES")
        .ok()
        .and_then(|bytes| bytes.parse().ok())
        .unwrap_or(DEFAULT_VALUE_CACHE_BYTES)
}

/// A validated value, cached so a hot read pays neither the `pread` nor the
/// checksum pass again.
///
/// The revision and length are kept so a hit can prove it answers for the
/// same record the reference names — a reference forged or rotted to point
/// mid-file must fall through to the file read, whose framing checks refuse
/// it, rather than be answered by whatever true record shares the offset.
struct CachedValue {
    value: Arc<Vec<u8>>,
    revision: u64,
    /// Second-chance bit: a hit protects the entry for one eviction pass.
    referenced: bool,
}

/// A byte-budgeted second-chance clock over validated values, keyed by record
/// offset — the same replacement design as the page cache, for the same
/// reason: a scan sweeping the log once must not evict the point-read hot set.
struct ValueCache {
    /// Keyed by record offset on the crate's multiplicative hasher — probed
    /// once per spilled-value read, same reasoning as the page cache.
    entries: U64Map<CachedValue>,
    clock: VecDeque<u64>,
    bytes: usize,
    budget: usize,
}

impl ValueCache {
    fn new(budget: usize) -> Self {
        Self {
            entries: U64Map::default(),
            clock: VecDeque::new(),
            bytes: 0,
            budget,
        }
    }

    fn get(&mut self, offset: u64, revision: u64, len: u32) -> Option<Arc<Vec<u8>>> {
        let entry = self.entries.get_mut(&offset)?;
        if entry.revision != revision || entry.value.len() != len as usize {
            return None;
        }
        entry.referenced = true;
        Some(Arc::clone(&entry.value))
    }

    fn insert(&mut self, offset: u64, revision: u64, value: Arc<Vec<u8>>) {
        // A value that would occupy a large fraction of the budget evicts the
        // whole hot set to cache one thing; it stays uncached and keeps
        // paying the file read, which at that size is bandwidth-bound anyway.
        if self.budget == 0 || value.len() > self.budget / 8 {
            return;
        }
        while self.bytes + value.len() > self.budget {
            let Some(victim) = self.clock.pop_front() else {
                break;
            };
            match self.entries.get_mut(&victim) {
                Some(entry) if entry.referenced => {
                    entry.referenced = false;
                    self.clock.push_back(victim);
                }
                Some(_) => {
                    let removed = self.entries.remove(&victim).expect("checked above");
                    self.bytes -= removed.value.len();
                }
                // Already replaced; its clock slot is stale.
                None => {}
            }
        }
        let len = value.len();
        if let Some(previous) = self.entries.insert(
            offset,
            CachedValue {
                value,
                revision,
                referenced: false,
            },
        ) {
            self.bytes -= previous.value.len();
        } else {
            self.clock.push_back(offset);
        }
        self.bytes += len;
    }
}

#[cfg(test)]
pub(crate) const fn record_overhead() -> usize {
    HEADER_LEN + FOOTER_LEN
}

#[derive(Clone, Debug)]
pub(crate) struct ValueRef {
    pub(crate) offset: u64,
    pub(crate) len: u32,
    pub(crate) revision: u64,
}

pub(crate) struct ValueLog {
    file: File,
    /// Whether anything has been appended since the last successful sync.
    ///
    /// Values below the inline limit never reach this log, so most commits leave
    /// it untouched and must not pay for an `fsync` of an unchanged file.
    dirty: bool,
    /// The file length as far as this handle knows, so a read's bounds check
    /// does not cost a `metadata` syscall — which it used to pay on EVERY
    /// read, doubling the syscalls of every value-log hit.
    ///
    /// "As far as this handle knows" is load-bearing: several handles share
    /// one file (the engine's, plus one per read handle), and only the
    /// engine's sees its own appends. The file is append-only while open —
    /// the sole truncation is tail repair inside `open`, before any sharing —
    /// so this only ever needs to move FORWARD: a read past the cached length
    /// refreshes it from the file once and re-checks, and a reference is only
    /// refused as out of bounds against the refreshed answer. A reader
    /// therefore pays one `metadata` per growth epoch it discovers instead of
    /// one per read. Monotonic under `fetch_max`, and relaxed ordering is
    /// enough: the value is a bounds hint, never a synchronization point —
    /// the tree only hands out a reference after its record is fully written.
    len: std::sync::atomic::AtomicU64,
    /// Validated values by record offset, so a hot read costs a map lookup
    /// and one memcpy instead of a syscall plus a checksum pass. Sound
    /// because the log is append-only while open: an offset's bytes never
    /// change under a live handle, so a validated value stays true for the
    /// handle's lifetime. Behind its own mutex — reads take `&self` and run
    /// concurrently under shared locks above.
    cache: Mutex<ValueCache>,
}

impl ValueLog {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        recover_tail(&mut file)?;
        let len = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            dirty: false,
            len: std::sync::atomic::AtomicU64::new(len),
            cache: Mutex::new(ValueCache::new(cache_budget())),
        })
    }

    /// Answers from the cache, or `None` on a miss (a poisoned cache counts
    /// as a miss — losing the cache must never lose the read).
    fn cached(&self, reference: &ValueRef) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().ok()?;
        cache
            .get(reference.offset, reference.revision, reference.len)
            .map(|value| (*value).clone())
    }

    /// Remembers a just-validated value for future hits.
    fn remember(&self, reference: &ValueRef, value: &[u8]) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                reference.offset,
                reference.revision,
                Arc::new(value.to_vec()),
            );
        }
    }

    /// Checks that `[offset, offset + total_len)` lies inside the file,
    /// refreshing the cached length once if it appears not to — the reference
    /// may simply be newer than this handle's last look at the file.
    fn check_bounds(&self, offset: u64, total_len: usize) -> Result<()> {
        use std::sync::atomic::Ordering;
        let Some(end) = offset.checked_add(total_len as u64) else {
            return Err(corrupt_value(offset, "value reference is out of bounds"));
        };
        if end <= self.len.load(Ordering::Relaxed) {
            return Ok(());
        }
        let fresh = self.file.metadata()?.len();
        self.len.fetch_max(fresh, Ordering::Relaxed);
        if end <= fresh {
            return Ok(());
        }
        Err(corrupt_value(offset, "value reference is out of bounds"))
    }

    /// Appends `value` as one record and returns where it landed.
    ///
    /// The record is assembled by appending into an empty buffer rather than by
    /// writing fields into a zero-filled one. `vec![0; total_len]` writes every
    /// byte of the record twice — once as a zero the allocator's memset lays down,
    /// once as the real content — which at 1 MiB is a full extra pass over the
    /// value before the write syscall is even issued. The single `write_all` is
    /// deliberately kept: `recover_tail` repairs a torn tail by truncating to the
    /// last complete record, and that reasoning rests on a partial append leaving
    /// a prefix rather than a record with a hole in it.
    pub(crate) fn append(&mut self, value: &[u8], revision: u64) -> Result<ValueRef> {
        let len: u32 = value.len().try_into().map_err(|_| Error::ValueTooLarge)?;
        let total_len = HEADER_LEN + value.len() + FOOTER_LEN;
        let total_len_u32: u32 = total_len.try_into().map_err(|_| Error::ValueTooLarge)?;
        let offset = self.file.seek(SeekFrom::End(0))?;
        let mut record = Vec::with_capacity(total_len);
        record.extend_from_slice(MAGIC);
        record.push(VERSION);
        record.extend_from_slice(&revision.to_be_bytes());
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(&value_checksum(revision, value).to_be_bytes());
        // The header's fields stop at 21 bytes; the remaining three are reserved
        // padding that the zero-filled buffer this replaced supplied implicitly.
        // They are part of the on-disk format — `read` and `recover_tail` both
        // expect the value to start at HEADER_LEN — so they have to be written
        // explicitly now that nothing pre-zeroes the record. The assertion below
        // is what caught their absence.
        record.resize(HEADER_LEN, 0);
        debug_assert_eq!(record.len(), HEADER_LEN);
        record.extend_from_slice(value);
        record.extend_from_slice(&total_len_u32.to_be_bytes());
        record.extend_from_slice(END);
        debug_assert_eq!(record.len(), total_len);
        self.file.write_all(&record)?;
        self.dirty = true;
        self.len.fetch_max(
            offset + total_len as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(ValueRef {
            offset,
            len,
            revision,
        })
    }

    pub(crate) fn read(&self, reference: &ValueRef) -> Result<Vec<u8>> {
        if let Some(value) = self.cached(reference) {
            return Ok(value);
        }
        let value = self.read_uncached(reference)?;
        self.remember(reference, &value);
        Ok(value)
    }

    /// [`ValueLog::read`] without the copy: a cache hit is a reference-count
    /// bump, and a miss returns the same allocation the cache keeps. This is
    /// what a zero-copy `get` serves large values through.
    pub(crate) fn read_shared(&self, reference: &ValueRef) -> Result<Arc<Vec<u8>>> {
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(value) = cache.get(reference.offset, reference.revision, reference.len) {
                return Ok(value);
            }
        }
        let shared = Arc::new(self.read_uncached(reference)?);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(reference.offset, reference.revision, Arc::clone(&shared));
        }
        Ok(shared)
    }

    /// The file read behind both `read` paths: framing, CRC, and reference
    /// metadata verified exactly as always; no cache involved.
    fn read_uncached(&self, reference: &ValueRef) -> Result<Vec<u8>> {
        let total_len = HEADER_LEN
            .checked_add(reference.len as usize)
            .and_then(|length| length.checked_add(FOOTER_LEN))
            .ok_or_else(|| corrupt_value(reference.offset, "value record length overflow"))?;
        self.check_bounds(reference.offset, total_len)?;
        // Two ways to get the value out, chosen by which cost dominates.
        //
        // The whole framed record used to be read into one buffer and the value
        // then copied out of the middle of it with `to_vec()` — a second
        // allocation the size of the value and a second full pass over its bytes.
        // At 1 MiB that copy is most of the read; removing it took `point_get/1mib`
        // from 1.13 ms to 788 µs.
        //
        // But reading the framing separately costs an extra positioned read, and
        // on this host a read syscall is around 2 µs whatever its size. For a small
        // value that is worse than the copy it saves: doing it unconditionally
        // regressed `scan_1000/4kib`, which reads a thousand values, from 11.6 ms
        // to 14.9 ms. So a small value keeps the single read and pays the copy,
        // and a large value takes the extra read and pays nothing.
        //
        // Verification does not vary between the two. Both hand the same header,
        // value, and footer bytes to `validate_framing`, which checks the same
        // fields and the same CRC over the same value either way.
        let (header, value) = if reference.len as usize <= COPY_RATHER_THAN_SEEK {
            let mut record = vec![0; total_len];
            read_exact_at(&self.file, &mut record, reference.offset)?;
            let mut header = [0; HEADER_LEN];
            header.copy_from_slice(&record[..HEADER_LEN]);
            validate_framing(
                &header,
                &record[total_len - FOOTER_LEN..],
                &record[HEADER_LEN..total_len - FOOTER_LEN],
                total_len,
                reference.offset,
            )?;
            let value = record[HEADER_LEN..total_len - FOOTER_LEN].to_vec();
            (header, value)
        } else {
            let mut header = [0; HEADER_LEN];
            read_exact_at(&self.file, &mut header, reference.offset)?;
            // The value and the footer come back in one read, and the footer is
            // then dropped with `truncate` — which only moves the length, so the
            // value is never copied or reallocated. That is why this is two reads
            // rather than three.
            let mut value = vec![0; reference.len as usize + FOOTER_LEN];
            read_exact_at(&self.file, &mut value, reference.offset + HEADER_LEN as u64)?;
            let split = reference.len as usize;
            validate_framing(
                &header,
                &value[split..],
                &value[..split],
                total_len,
                reference.offset,
            )?;
            value.truncate(split);
            (header, value)
        };
        if read_u64(&header, 5) != reference.revision || read_u32(&header, 13) != reference.len {
            return Err(corrupt_value(
                reference.offset,
                "value reference metadata mismatch",
            ));
        }
        Ok(value)
    }

    /// Reads many values, coalescing physically adjacent records into single
    /// positioned reads.
    ///
    /// A scan resolves its rows' values in key order, and keys written in
    /// order sit in this log in that same order — so a thousand-row scan of
    /// spilled values is typically a handful of contiguous byte ranges, which
    /// this reads with a handful of syscalls instead of one (or two) per row.
    /// Records that do not abut anything are read exactly as [`ValueLog::read`]
    /// would have read them, so nothing is lost on a scattered batch.
    ///
    /// Verification is per record and identical to the single-read path: the
    /// same framing, the same CRC over the same bytes, the same reference
    /// metadata check. Coalescing changes how bytes reach memory, never what
    /// is accepted.
    pub(crate) fn read_many(&self, references: &[ValueRef]) -> Result<Vec<Arc<Vec<u8>>>> {
        if references.len() < 2 {
            return references.iter().map(|r| self.read_shared(r)).collect();
        }
        let mut results: Vec<Option<Arc<Vec<u8>>>> = Vec::with_capacity(references.len());
        results.resize_with(references.len(), || None);
        // The cache first; only the misses go to the file. A hit is handed
        // back as the cache's own allocation — no copy at all.
        let mut order: Vec<usize> = Vec::with_capacity(references.len());
        if let Ok(mut cache) = self.cache.lock() {
            for (slot, reference) in references.iter().enumerate() {
                match cache.get(reference.offset, reference.revision, reference.len) {
                    Some(value) => results[slot] = Some(value),
                    None => order.push(slot),
                }
            }
        } else {
            order.extend(0..references.len());
        }
        // Physical order over the misses, remembering each one's output slot.
        order.sort_unstable_by_key(|&index| references[index].offset);
        let mut run: Vec<usize> = Vec::new();
        let mut run_bytes = 0usize;
        let mut run_end = 0u64;
        for &slot in &order {
            let reference = &references[slot];
            let total = HEADER_LEN
                .checked_add(reference.len as usize)
                .and_then(|length| length.checked_add(FOOTER_LEN))
                .ok_or_else(|| corrupt_value(reference.offset, "value record length overflow"))?;
            // A run extends only through EXACT adjacency: a gap would mean
            // reading bytes no reference asked for, and an overlap would mean
            // the references disagree about the file — both are served
            // one-by-one, where each read validates on its own terms.
            let extends = !run.is_empty()
                && reference.offset == run_end
                && run_bytes + total <= MAX_COALESCED_READ;
            if !extends && !run.is_empty() {
                self.read_run(references, &run, &mut results)?;
                run.clear();
                run_bytes = 0;
            }
            run.push(slot);
            run_bytes += total;
            run_end = reference.offset + total as u64;
        }
        if !run.is_empty() {
            self.read_run(references, &run, &mut results)?;
        }
        Ok(results
            .into_iter()
            .map(|value| value.expect("every reference lands in exactly one run"))
            .collect())
    }

    /// Reads one physically contiguous run of records and fills each one's
    /// output slot. A run of one falls back to [`ValueLog::read`], keeping
    /// that path's copy-versus-seek choice for lone large values.
    fn read_run(
        &self,
        references: &[ValueRef],
        slots: &[usize],
        results: &mut [Option<Arc<Vec<u8>>>],
    ) -> Result<()> {
        if let [slot] = slots {
            results[*slot] = Some(self.read_shared(&references[*slot])?);
            return Ok(());
        }
        let start = references[slots[0]].offset;
        let mut run_len = 0usize;
        for &slot in slots {
            run_len += HEADER_LEN + references[slot].len as usize + FOOTER_LEN;
        }
        self.check_bounds(start, run_len)?;
        let mut buffer = vec![0; run_len];
        read_exact_at(&self.file, &mut buffer, start)?;
        let mut cursor = 0usize;
        for &slot in slots {
            let reference = &references[slot];
            let record_len = HEADER_LEN + reference.len as usize + FOOTER_LEN;
            let record = &buffer[cursor..cursor + record_len];
            let offset = start + cursor as u64;
            validate_record(record, offset)?;
            if read_u64(record, 5) != reference.revision || read_u32(record, 13) != reference.len {
                return Err(corrupt_value(offset, "value reference metadata mismatch"));
            }
            let value = Arc::new(record[HEADER_LEN..record_len - FOOTER_LEN].to_vec());
            if let Ok(mut cache) = self.cache.lock() {
                cache.insert(reference.offset, reference.revision, Arc::clone(&value));
            }
            results[slot] = Some(value);
            cursor += record_len;
        }
        Ok(())
    }

    /// Flushes appended values, skipping the barrier when nothing was written.
    pub(crate) fn sync(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.file.sync_data()?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buffer, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset).and_then(|count| {
        if count == buffer.len() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        }
    })
}

fn recover_tail(file: &mut File) -> Result<()> {
    let file_len = file.metadata()?.len();
    let mut offset = 0_u64;
    while offset < file_len {
        if file_len - offset < HEADER_LEN as u64 {
            file.set_len(offset)?;
            file.sync_all()?;
            break;
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0; HEADER_LEN];
        file.read_exact(&mut header)?;
        if &header[0..4] != MAGIC || header[4] != VERSION {
            return Err(corrupt_value(offset, "invalid value record header"));
        }
        let value_len = read_u32(&header, 13) as usize;
        if value_len > MAX_VALUE_SIZE {
            return Err(corrupt_value(offset, "invalid value length"));
        }
        let total_len = HEADER_LEN + value_len + FOOTER_LEN;
        if total_len as u64 > file_len - offset {
            file.set_len(offset)?;
            file.sync_all()?;
            break;
        }
        let mut record = vec![0; total_len];
        record[..HEADER_LEN].copy_from_slice(&header);
        file.read_exact(&mut record[HEADER_LEN..])?;
        validate_record(&record, offset)?;
        offset += total_len as u64;
    }
    Ok(())
}

fn validate_record(record: &[u8], offset: u64) -> Result<()> {
    if record.len() < HEADER_LEN + FOOTER_LEN {
        return Err(corrupt_value(offset, "invalid value record header"));
    }
    let (header, rest) = record.split_at(HEADER_LEN);
    let (value, footer) = rest.split_at(rest.len() - FOOTER_LEN);
    validate_framing(header, footer, value, record.len(), offset)
}

/// Checks a record's header, checksum, and footer against its value.
///
/// Split out of [`validate_record`] so `read` can verify a record whose header,
/// value, and footer were read into three separate buffers — it no longer
/// assembles the framed record in memory just to check it. Both callers reach the
/// same conclusions from the same bytes; nothing here is skipped for either.
fn validate_framing(
    header: &[u8],
    footer: &[u8],
    value: &[u8],
    total_len: usize,
    offset: u64,
) -> Result<()> {
    if header.len() != HEADER_LEN
        || footer.len() != FOOTER_LEN
        || &header[0..4] != MAGIC
        || header[4] != VERSION
    {
        return Err(corrupt_value(offset, "invalid value record header"));
    }
    let value_len = read_u32(header, 13) as usize;
    if value_len > MAX_VALUE_SIZE
        || value_len != value.len()
        || total_len != HEADER_LEN + value_len + FOOTER_LEN
    {
        return Err(corrupt_value(offset, "invalid value record length"));
    }
    if read_u32(header, 17) != value_checksum(read_u64(header, 5), value)
        || read_u32(footer, 0) as usize != total_len
        || &footer[4..] != END
    {
        return Err(corrupt_value(offset, "value checksum or footer mismatch"));
    }
    Ok(())
}

fn value_checksum(revision: u64, value: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&[VERSION]);
    hasher.update(&revision.to_be_bytes());
    hasher.update(&(value.len() as u32).to_be_bytes());
    hasher.update(value);
    hasher.finalize()
}

fn corrupt_value(offset: u64, reason: impl Into<String>) -> Error {
    Error::CorruptValue {
        offset,
        reason: reason.into(),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn values_persist_and_incomplete_tail_is_removed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("values.vlog");
        let reference = {
            let mut log = ValueLog::open(&path).unwrap();
            let reference = log.append(&vec![7; 4096], 11).unwrap();
            log.sync().unwrap();
            reference
        };
        let original_len = fs::metadata(&path).unwrap().len();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let log = ValueLog::open(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), original_len);
        assert_eq!(log.read(&reference).unwrap(), vec![7; 4096]);
    }

    /// A flip anywhere in a value record must be reported, on BOTH read paths.
    ///
    /// `read` now picks between reading the framed record in one go and reading
    /// the framing separately to avoid a copy of the value, chosen by size against
    /// [`COPY_RATHER_THAN_SEEK`]. The copy is the only thing that differs: a flip
    /// in the magic, the version, the revision, the stored length, the checksum,
    /// the value itself, or either footer field has to come back as corruption
    /// either way. So the sizes below straddle the threshold, and each case flips
    /// one byte in one region and insists on an error.
    #[test]
    fn a_flip_anywhere_in_a_value_record_is_still_detected() {
        for size in [4_096, COPY_RATHER_THAN_SEEK + 1] {
            // One offset in each region of the record, named by what it damages.
            let regions = [
                (0, "magic"),
                (4, "version"),
                (5, "revision"),
                (13, "stored length"),
                (17, "checksum"),
                (HEADER_LEN, "first value byte"),
                (HEADER_LEN + size / 2, "middle of the value"),
                (HEADER_LEN + size - 1, "last value byte"),
                (HEADER_LEN + size, "footer length"),
                (HEADER_LEN + size + 4, "footer magic"),
            ];
            for (offset, region) in regions {
                let directory = tempdir().unwrap();
                let path = directory.path().join("values.vlog");
                let reference = {
                    let mut log = ValueLog::open(&path).unwrap();
                    let reference = log.append(&vec![7; size], 11).unwrap();
                    log.sync().unwrap();
                    reference
                };
                let mut bytes = fs::read(&path).unwrap();
                bytes[offset] ^= 0xff;
                fs::write(&path, &bytes).unwrap();
                // Read through a fresh handle, because `open` itself walks and
                // validates the log: either layer may catch it, but something must.
                let detected = match ValueLog::open(&path) {
                    Err(_) => true,
                    Ok(log) => log.read(&reference).is_err(),
                };
                assert!(
                    detected,
                    "a flip in the {region} of a {size}-byte value was returned \
                     as data instead of corruption"
                );
            }
        }
    }

    /// `read_many` must return exactly what `read` returns, whatever the
    /// physical layout: one contiguous run, runs split by gaps, references
    /// out of offset order, and a duplicated reference. The answers come back
    /// in ARGUMENT order, not file order — that is the contract the scan
    /// relies on when it fills its rows.
    #[test]
    fn read_many_matches_read_for_every_layout() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("values.vlog");
        let mut log = ValueLog::open(&path).unwrap();
        let mut references = Vec::new();
        for index in 0..20u64 {
            // Mixed sizes so runs cross the copy-versus-seek threshold too.
            let size = if index % 5 == 4 {
                COPY_RATHER_THAN_SEEK + 3
            } else {
                512 + index as usize
            };
            let value: Vec<u8> = (0..size).map(|byte| (byte as u64 + index) as u8).collect();
            references.push((log.append(&value, index + 1).unwrap(), value));
        }
        log.sync().unwrap();
        let layouts: Vec<Vec<usize>> = vec![
            (0..20).collect(),                       // one contiguous run
            vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18], // gaps: no two adjacent
            vec![7, 3, 11, 3, 0, 19, 12],            // unsorted, one duplicate
            vec![5],                                 // single
        ];
        for layout in layouts {
            let batch: Vec<ValueRef> = layout
                .iter()
                .map(|&index| references[index].0.clone())
                .collect();
            // Twice: the first pass reads the file (and populates the cache),
            // the second answers from the cache. Both must return the same
            // bytes in the same argument order.
            for pass in ["cold", "warm"] {
                let values = log.read_many(&batch).unwrap();
                assert_eq!(values.len(), layout.len());
                for (position, &index) in layout.iter().enumerate() {
                    assert_eq!(
                        *values[position], references[index].1,
                        "{pass} read_many returned the wrong value at position \
                         {position} for reference {index}"
                    );
                }
            }
        }
    }

    /// A flip inside a coalesced run must be reported as corruption, exactly
    /// as the single-record path reports it — coalescing changes how bytes
    /// reach memory, never what is accepted.
    #[test]
    fn a_flip_inside_a_coalesced_run_is_detected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("values.vlog");
        let mut references = Vec::new();
        {
            let mut log = ValueLog::open(&path).unwrap();
            for index in 0..3u64 {
                references.push(log.append(&vec![7; 4096], index + 1).unwrap());
            }
            log.sync().unwrap();
        }
        let mut bytes = fs::read(&path).unwrap();
        // The middle record's value, so the flip sits inside the run.
        let middle = references[1].offset as usize + HEADER_LEN + 100;
        bytes[middle] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        // Opening validates the log too; read through the reference either way.
        let detected = match ValueLog::open(&path) {
            Err(_) => true,
            Ok(log) => log.read_many(&references).is_err(),
        };
        assert!(
            detected,
            "a flipped byte inside a coalesced run was returned as data"
        );
    }

    /// A handle must serve values appended through ANOTHER handle after it
    /// opened. The engine and every read handle share one file this way, and
    /// the cached length exists to remove a per-read `metadata` syscall — it
    /// must refresh when a reference points past it, or every reader would
    /// refuse everything committed after it opened.
    #[test]
    fn a_reader_handle_sees_values_appended_after_it_opened() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("values.vlog");
        let mut writer = ValueLog::open(&path).unwrap();
        writer.append(&vec![1; 2048], 1).unwrap();
        writer.sync().unwrap();
        let reader = ValueLog::open(&path).unwrap();
        // Appended AFTER the reader opened, so the reader's cached length
        // does not cover it.
        let late = writer.append(&vec![9; 2048], 2).unwrap();
        writer.sync().unwrap();
        assert_eq!(
            reader.read(&late).unwrap(),
            vec![9; 2048],
            "a reference newer than the handle's cached length must be served"
        );
        // And a genuinely out-of-bounds reference is still refused.
        let bogus = ValueRef {
            offset: late.offset + 1_000_000,
            len: 16,
            revision: 3,
        };
        assert!(reader.read(&bogus).is_err());
    }

    /// Both read paths must return the value that was written.
    ///
    /// Guards the split itself rather than its error handling: an off-by-one in
    /// where the large-value path cuts the footer off would return a value with
    /// eight bytes of framing glued to it, or eight bytes missing, and every
    /// checksum in the record would still verify because the framing is intact.
    #[test]
    fn both_read_paths_return_the_value_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("values.vlog");
        let sizes = [
            1,
            COPY_RATHER_THAN_SEEK - 1,
            COPY_RATHER_THAN_SEEK,
            COPY_RATHER_THAN_SEEK + 1,
            COPY_RATHER_THAN_SEEK * 4,
        ];
        let mut log = ValueLog::open(&path).unwrap();
        let mut written = Vec::new();
        for (index, size) in sizes.iter().enumerate() {
            // Content varies with position so a read of the wrong record, or of
            // the right record shifted, cannot pass.
            let value: Vec<u8> = (0..*size).map(|byte| (byte + index) as u8).collect();
            let reference = log.append(&value, index as u64 + 1).unwrap();
            written.push((reference, value));
        }
        log.sync().unwrap();
        for (reference, value) in &written {
            let read = log.read(reference).unwrap();
            assert_eq!(read.len(), value.len(), "value length changed on read");
            assert_eq!(&read, value, "value bytes changed on read");
        }
    }
}
