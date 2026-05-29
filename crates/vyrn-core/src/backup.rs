use crate::{Error, Result};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"VYRNBKP1";
const FOOTER: &[u8; 8] = b"VYRNEND1";
const MAX_FILES: usize = 1_000_000;
const MAX_PATH: usize = 4 * 1024;

pub fn create_backup(data_directory: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    let data_directory = data_directory.as_ref();
    let output = output.as_ref();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(data_directory.join("LOCK"))?;
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Error::AlreadyOpen
        } else {
            Error::Io(error)
        }
    })?;

    let files = database_files(data_directory)?;
    let temporary = output.with_extension("tmp");
    let _ = fs::remove_file(&temporary);
    let mut archive = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    archive.write_all(MAGIC)?;
    write_u32(&mut archive, files.len() as u32)?;
    for relative in files {
        let path_bytes = relative.to_string_lossy().replace('\\', "/").into_bytes();
        if path_bytes.len() > MAX_PATH {
            return Err(Error::CorruptBackup("backup path is too long".into()));
        }
        let mut source = File::open(data_directory.join(&relative))?;
        let length = source.metadata()?.len();
        write_u32(&mut archive, path_bytes.len() as u32)?;
        archive.write_all(&path_bytes)?;
        write_u64(&mut archive, length)?;
        let checksum_offset = archive.stream_position()?;
        write_u32(&mut archive, 0)?;
        let mut hasher = crc32fast::Hasher::new();
        let mut remaining = length;
        let mut buffer = vec![0; 1024 * 1024];
        while remaining != 0 {
            let chunk = remaining.min(buffer.len() as u64) as usize;
            let count = source.read(&mut buffer[..chunk])?;
            if count == 0 {
                return Err(Error::CorruptBackup(
                    "source file changed during backup".into(),
                ));
            }
            archive.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let end = archive.stream_position()?;
        archive.seek(std::io::SeekFrom::Start(checksum_offset))?;
        write_u32(&mut archive, hasher.finalize())?;
        archive.seek(std::io::SeekFrom::Start(end))?;
    }
    archive.write_all(FOOTER)?;
    archive.sync_all()?;
    drop(archive);
    fs::rename(&temporary, output)?;
    if let Some(parent) = output.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

pub fn verify_backup(path: impl AsRef<Path>) -> Result<()> {
    read_archive(path.as_ref(), None)
}

pub fn restore_backup(archive: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<()> {
    let target = target.as_ref();
    if target.exists() && fs::read_dir(target)?.next().is_some() {
        return Err(Error::RestoreTargetNotEmpty);
    }
    fs::create_dir_all(target)?;
    let result = read_archive(archive.as_ref(), Some(target));
    if result.is_err() {
        let _ = fs::remove_dir_all(target);
        return result;
    }
    sync_directory(target)?;
    Ok(())
}

fn read_archive(path: &Path, target: Option<&Path>) -> Result<()> {
    let mut archive = File::open(path)?;
    let mut magic = [0; 8];
    archive.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::CorruptBackup("invalid backup magic".into()));
    }
    let count = read_u32(&mut archive)? as usize;
    if count > MAX_FILES {
        return Err(Error::CorruptBackup("too many backup files".into()));
    }
    for _ in 0..count {
        let path_len = read_u32(&mut archive)? as usize;
        if path_len == 0 || path_len > MAX_PATH {
            return Err(Error::CorruptBackup("invalid path length".into()));
        }
        let mut path_bytes = vec![0; path_len];
        archive.read_exact(&mut path_bytes)?;
        let relative = safe_relative_path(&path_bytes)?;
        let length = read_u64(&mut archive)?;
        let expected_checksum = read_u32(&mut archive)?;
        let mut output = if let Some(target) = target {
            let output_path = target.join(&relative);
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            Some(
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(output_path)?,
            )
        } else {
            None
        };
        let mut hasher = crc32fast::Hasher::new();
        let mut remaining = length;
        let mut buffer = vec![0; 1024 * 1024];
        while remaining != 0 {
            let chunk = remaining.min(buffer.len() as u64) as usize;
            let count = archive.read(&mut buffer[..chunk])?;
            if count == 0 {
                return Err(Error::CorruptBackup("truncated file content".into()));
            }
            hasher.update(&buffer[..count]);
            if let Some(output) = &mut output {
                output.write_all(&buffer[..count])?;
            }
            remaining -= count as u64;
        }
        if hasher.finalize() != expected_checksum {
            return Err(Error::CorruptBackup(format!(
