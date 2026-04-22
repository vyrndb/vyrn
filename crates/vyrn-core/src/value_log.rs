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
        Ok(Self { file })
    }

    pub(crate) fn append(&mut self, value: &[u8], revision: u64) -> Result<ValueRef> {
        let len: u32 = value.len().try_into().map_err(|_| Error::ValueTooLarge)?;
        let total_len = HEADER_LEN + value.len() + FOOTER_LEN;
        let total_len_u32: u32 = total_len.try_into().map_err(|_| Error::ValueTooLarge)?;
        let offset = self.file.seek(SeekFrom::End(0))?;
        let mut record = vec![0; total_len];
        record[0..4].copy_from_slice(MAGIC);
        record[4] = VERSION;
        write_u64(&mut record, 5, revision);
        write_u32(&mut record, 13, len);
        write_u32(&mut record, 17, value_checksum(revision, value));
        record[HEADER_LEN..HEADER_LEN + value.len()].copy_from_slice(value);
        write_u32(&mut record, total_len - FOOTER_LEN, total_len_u32);
        record[total_len - 4..].copy_from_slice(END);
        self.file.write_all(&record)?;
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
        let mut record = vec![0; total_len];
        read_exact_at(&self.file, &mut record, reference.offset)?;
        validate_record(&record, reference.offset)?;
        if read_u64(&record, 5) != reference.revision || read_u32(&record, 13) != reference.len {
            return Err(corrupt_value(
                reference.offset,
                "value reference metadata mismatch",
            ));
        }
        Ok(record[HEADER_LEN..total_len - FOOTER_LEN].to_vec())
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.file.sync_data()?;
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
    if record.len() < HEADER_LEN + FOOTER_LEN || &record[0..4] != MAGIC || record[4] != VERSION {
        return Err(corrupt_value(offset, "invalid value record header"));
    }
    let value_len = read_u32(record, 13) as usize;
    if value_len > MAX_VALUE_SIZE || record.len() != HEADER_LEN + value_len + FOOTER_LEN {
        return Err(corrupt_value(offset, "invalid value record length"));
    }
    let value = &record[HEADER_LEN..HEADER_LEN + value_len];
    if read_u32(record, 17) != value_checksum(read_u64(record, 5), value)
        || read_u32(record, record.len() - FOOTER_LEN) as usize != record.len()
        || &record[record.len() - 4..] != END
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

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
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
}
