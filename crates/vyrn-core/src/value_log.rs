use crate::{Error, Result, MAX_VALUE_SIZE};
use crc32fast::Hasher;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
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
        file.seek(SeekFrom::End(0))?;
        Ok(Self { file, dirty: false })
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
        Ok(ValueRef {
            offset,
            len,
            revision,
        })
    }

    pub(crate) fn read(&self, reference: &ValueRef) -> Result<Vec<u8>> {
        let file_len = self.file.metadata()?.len();
        let total_len = HEADER_LEN
            .checked_add(reference.len as usize)
            .and_then(|length| length.checked_add(FOOTER_LEN))
            .ok_or_else(|| corrupt_value(reference.offset, "value record length overflow"))?;
        if reference
            .offset
            .checked_add(total_len as u64)
            .is_none_or(|end| end > file_len)
        {
            return Err(corrupt_value(
                reference.offset,
                "value reference is out of bounds",
            ));
        }
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
