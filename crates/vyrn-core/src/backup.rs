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
                "checksum mismatch for {}",
                relative.display()
            )));
        }
        if let Some(output) = output {
            output.sync_all()?;
        }
    }
    let mut footer = [0; 8];
    archive.read_exact(&mut footer)?;
    if &footer != FOOTER || archive.read(&mut [0])? != 0 {
        return Err(Error::CorruptBackup(
            "invalid footer or trailing data".into(),
        ));
    }
    Ok(())
}

fn database_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "CURRENT"
            || name.starts_with("pages-") && name.ends_with(".vdb")
            || name.starts_with("values-") && name.ends_with(".vlog")
            || name.starts_with("revision-values-") && name.ends_with(".vlog")
            || name.starts_with("revisions-") && name.ends_with(".vmvcc")
        {
            files.push(PathBuf::from(name.as_ref()));
        } else if name == "wal" {
            for segment in fs::read_dir(entry.path())? {
                let segment = segment?;
                if segment.file_type()?.is_file() {
                    files.push(PathBuf::from("wal").join(segment.file_name()));
                }
            }
        }
    }
    files.sort();
    if !files.iter().any(|path| path == Path::new("CURRENT")) {
        return Err(Error::CorruptBackup(
            "database has no CURRENT manifest; checkpoint it first".into(),
        ));
    }
    Ok(files)
}

fn safe_relative_path(bytes: &[u8]) -> Result<PathBuf> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| Error::CorruptBackup("path is not UTF-8".into()))?;
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Error::CorruptBackup("unsafe path in backup".into()));
    }
    Ok(path.to_owned())
}

fn write_u32(output: &mut File, value: u32) -> Result<()> {
    output.write_all(&value.to_be_bytes())?;
    Ok(())
}
fn write_u64(output: &mut File, value: u64) -> Result<()> {
    output.write_all(&value.to_be_bytes())?;
    Ok(())
}
fn read_u32(input: &mut File) -> Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}
fn read_u64(input: &mut File) -> Result<u64> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use tempfile::tempdir;

    #[test]
    fn backup_verifies_restores_and_reopens() {
        let source = tempdir().unwrap();
        {
            let mut engine = Engine::open(source.path()).unwrap();
            engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
            engine.checkpoint().unwrap();
        }
        let archive = source.path().join("../backup.vyrn");
        create_backup(source.path(), &archive).unwrap();
        verify_backup(&archive).unwrap();
        let restored = tempdir().unwrap();
        let target = restored.path().join("db");
        restore_backup(&archive, &target).unwrap();
        let engine = Engine::open(target).unwrap();
        assert_eq!(engine.get(b"key").unwrap(), Some(b"value".to_vec()));
        let _ = fs::remove_file(archive);
    }

    #[test]
    fn corruption_is_detected() {
        let source = tempdir().unwrap();
        {
            let mut engine = Engine::open(source.path()).unwrap();
            engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
            engine.checkpoint().unwrap();
        }
        let archive = source.path().join("../corrupt.vyrn");
        create_backup(source.path(), &archive).unwrap();
        let mut bytes = fs::read(&archive).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        fs::write(&archive, bytes).unwrap();
        assert!(verify_backup(&archive).is_err());
        let _ = fs::remove_file(archive);
    }
}
