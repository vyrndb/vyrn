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
    reject_reserved_output(output)?;
    if resolves_inside(data_directory, output)? {
        return Err(Error::CorruptBackup(format!(
            "{} is inside the data directory being backed up; writing an archive into a live database lets one mistyped --output destroy what it claims to preserve",
            output.display()
        )));
    }
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

/// Refuses an output path that collides with files Vyrn itself writes.
///
/// Publication is `fs::rename`, which replaces an existing destination without
/// complaint, and the logical export truncates what it is handed — so
/// `--output ./db/CURRENT` reports success and destroys the live manifest.
/// The names checked here are the engine's own (see `database_files`), plus
/// anything inside a `wal/` directory; a dump or archive has no business
/// wearing either. Shared with `portable::export`, whose output path carries
/// the same hazard without a data directory to compare against.
pub(crate) fn reject_reserved_output(output: &Path) -> Result<()> {
    if let Some(name) = output.file_name().and_then(|name| name.to_str()) {
        if is_reserved_file_name(name) {
            return Err(Error::CorruptBackup(format!(
                "output path {output:?} collides with a file Vyrn owns ({name}); choose an output outside the data directory"
            )));
        }
    }
    // The segment files live one level down, so the destination's ancestors,
    // not just its final name, decide whether it lands on engine state.
    if output
        .ancestors()
        .any(|ancestor| ancestor.file_name().is_some_and(|name| name == "wal"))
    {
        return Err(Error::CorruptBackup(format!(
            "output path {output:?} resolves inside a wal directory"
        )));
    }
    Ok(())
}

/// Whether `name` is one the engine writes into a data directory or an
/// extension only engine files carry.
fn is_reserved_file_name(name: &str) -> bool {
    name == "CURRENT"
        || name.starts_with("pages-")
        || name.starts_with("values-")
        || name.starts_with("revisions-")
        || name.starts_with("revision-values-")
        || name.ends_with(".vwal")
        || name.ends_with(".vlog")
}

/// Whether `output` resolves inside `directory`, for an output that usually
/// does not exist yet: the nearest existing ancestor is canonicalized through
/// the filesystem and the not-yet-existing tail appended, so `.`, `..`, and
/// Windows short-path spellings of the same place compare equal instead of
/// lexically.
fn resolves_inside(directory: &Path, output: &Path) -> std::io::Result<bool> {
    let directory = std::fs::canonicalize(directory)?;
    // A bare relative name has no ancestor to resolve through, so anchor it to
    // the working directory first; otherwise the walk below would end at an
    // empty path instead of at a real directory.
    let mut probe = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    let mut tail = Vec::new();
    loop {
        match std::fs::canonicalize(&probe) {
            Ok(resolved) => {
                let mut resolved = resolved;
                for component in &tail {
                    resolved.push(component);
                }
                return Ok(resolved.starts_with(directory));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match probe.file_name() {
            Some(name) => tail.insert(0, name.to_owned()),
            None => return Ok(false),
        }
        match probe.parent() {
            Some(parent) => probe = parent.to_path_buf(),
            None => return Ok(false),
        }
    }
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
    // A database that has never checkpointed has no manifest, and that is a
    // legitimate state rather than a corrupt one: `Engine::open` falls back to
    // generation 0 at an empty root and replays the WAL onto it, which is exactly
    // what it does for a restored copy. Absent `CURRENT` also proves no
    // checkpoint ran, so no segment was ever deleted and segment 1 onwards is
    // the complete log. Refusing here made backup unavailable for the whole
    // early life of a database — including immediately after a clean shutdown,
    // which is when an operator is most likely to take the first one.
    //
    // What must be present is a page file to replay onto. Its absence means the
    // directory is not a database at all.
    if !files
        .iter()
        .any(|path| path.to_string_lossy().starts_with("pages-"))
    {
        return Err(Error::CorruptBackup(
            "database has no page file; the directory is not a Vyrn database".into(),
        ));
    }
    // A published manifest claims every commit above its LSN lives only in the
    // WAL, so the surviving segments have to be able to deliver them. Two
    // shapes of loss pass every other guard here and verify clean, because an
    // empty segment list simply skips replay:
    //
    //   - wal/ wiped entirely. Restore rolls silently back to the last
    //     checkpoint, discarding acknowledged commits.
    //   - a middle segment deleted. The lowest survivor still starts below the
    //     manifest's LSN, so nothing above looks wrong until restore refuses a
    //     discontinuous sequence hours later, with no live database left.
    //
    // Both mean the bytes exist nowhere else, so refusing costs only a backup
    // of an already-broken directory and catches the damage while it can still
    // be repaired from the source or its archive.
    if let Some(state) = crate::read_manifest(directory)? {
        let mut segments: Vec<u64> = files
            .iter()
            .filter(|path| path.starts_with("wal"))
            .filter_map(|path| {
                path.file_name()?
                    .to_str()?
                    .strip_suffix(".vwal")?
                    .parse()
                    .ok()
            })
            .collect();
        segments.sort_unstable();
        let Some(&lowest) = segments.first() else {
            return Err(Error::CorruptBackup(
                "the database has a checkpoint manifest but no WAL segments; restoring it would roll back to the checkpoint and silently drop every commit since".into(),
            ));
        };
        // Segment ids are contiguous in any healthy wal/ — `Engine::open`
        // refuses a gapped sequence too — so a hole in the ids is a deleted
        // segment rather than an unusual layout.
        if segments.windows(2).any(|pair| pair[1] != pair[0] + 1) {
            return Err(Error::CorruptBackup(format!(
                "the WAL is missing a segment between {} and {}; replay would refuse the restored copy as discontinuous",
                segments[0],
                segments[1]
            )));
        }
        let lowest_first_lsn = crate::read_segment_first_lsn(
            &directory.join("wal").join(crate::segment_name(lowest)),
        )?;
        if lowest_first_lsn > state.lsn.saturating_add(1) {
            return Err(Error::CorruptBackup(format!(
                "the earliest surviving WAL segment starts at record {lowest_first_lsn} but the checkpoint manifest covers only through {}; the records between were lost and restore cannot reproduce them",
                state.lsn
            )));
        }
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

    /// A database only gets a manifest once it checkpoints, so refusing to back
    /// one up without it made backup unavailable for the whole early life of a
    /// database — including right after a clean shutdown. The restored copy has
    /// to come back complete, which it does because replay rebuilds the tree from
    /// segment 1 onto the empty generation-0 root.
    #[test]
    fn a_database_that_never_checkpointed_can_be_backed_up_and_restored() {
        let source = tempdir().unwrap();
        {
            let mut engine = Engine::open(source.path()).unwrap();
            engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
            engine.put(b"second".to_vec(), b"durable".to_vec()).unwrap();
            engine.delete(b"key").unwrap();
            engine.put(b"key".to_vec(), b"rewritten".to_vec()).unwrap();
        }
        assert!(
            !source.path().join("CURRENT").exists(),
            "this case is only meaningful without a manifest"
        );

        let archive = source.path().join("../no-manifest.vyrn");
        create_backup(source.path(), &archive).unwrap();
        verify_backup(&archive).unwrap();
        let restored = tempdir().unwrap();
        let target = restored.path().join("db");
        restore_backup(&archive, &target).unwrap();

        let engine = Engine::open(target).unwrap();
        assert_eq!(engine.get(b"key").unwrap(), Some(b"rewritten".to_vec()));
        assert_eq!(engine.get(b"second").unwrap(), Some(b"durable".to_vec()));
        let _ = fs::remove_file(archive);
    }

    /// The replacement guard: a directory with no page file is not a database,
    /// and backing it up would produce an archive that restores to nothing.
    #[test]
    fn a_directory_without_a_page_file_is_refused() {
        let empty = tempdir().unwrap();
        fs::write(empty.path().join("LOCK"), b"").unwrap();
        let archive = empty.path().join("../not-a-database.vyrn");
        assert!(create_backup(empty.path(), &archive).is_err());
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
