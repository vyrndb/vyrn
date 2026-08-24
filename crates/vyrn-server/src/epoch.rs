//! Persisted election state: the epoch this node believes in, and the highest
//! epoch it has voted in.
//!
//! Both are fencing state, and fencing state must survive a crash or it is
//! not fencing: a node that forgot the epoch it voted in could grant a second
//! vote in the same epoch and hand two candidates a majority, and a deposed
//! primary that forgot the higher epoch it saw could come back believing it
//! still leads. Every mutation here is therefore durable BEFORE the caller
//! acts on it — the write is temp file, `sync_all`, rename, directory sync,
//! the same publish discipline the engine's manifests use.
//!
//! The file is `EPOCH` in the data directory: magic, version, the two
//! epochs, CRC over everything before it. Absent means epoch 0 (a cluster
//! that has never elected), which is also what every pre-failover data
//! directory reads as — no migration step.

use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"VEPO";
const VERSION: u8 = 1;
const LEN: usize = 4 + 1 + 8 + 8 + 4;

pub struct EpochStore {
    path: PathBuf,
    directory: PathBuf,
    /// The highest epoch this node has adopted (led in, followed, or seen).
    pub current: u64,
    /// The highest epoch this node has granted a vote in.
    pub voted: u64,
}

impl EpochStore {
    pub fn open(data_directory: &Path) -> Result<Self> {
        let path = data_directory.join("EPOCH");
        let mut store = Self {
            path,
            directory: data_directory.to_owned(),
            current: 0,
            voted: 0,
        };
        match File::open(&store.path) {
            Ok(mut file) => {
                let mut bytes = Vec::with_capacity(LEN);
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("failed to read {:?}", store.path))?;
                let (current, voted) = decode(&bytes)
                    .with_context(|| format!("{:?} is not a valid epoch file", store.path))?;
                store.current = current;
                store.voted = voted;
                Ok(store)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(store),
            Err(error) => {
                Err(error).with_context(|| format!("failed to open {:?}", store.path))
            }
        }
    }

    /// Adopts `epoch` as current (never moving backward) and persists before
    /// returning. Voting in an epoch implies believing in it, so `voted`
    /// advances together with `current` when a vote is being recorded.
    pub fn advance(&mut self, epoch: u64, voted_in_it: bool) -> Result<()> {
        let current = self.current.max(epoch);
        let voted = if voted_in_it {
            self.voted.max(epoch)
        } else {
            self.voted
        };
        if current == self.current && voted == self.voted {
            return Ok(());
        }
        self.persist(current, voted)?;
        self.current = current;
        self.voted = voted;
        Ok(())
    }

    fn persist(&self, current: u64, voted: u64) -> Result<()> {
        let mut bytes = Vec::with_capacity(LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&current.to_be_bytes());
        bytes.extend_from_slice(&voted.to_be_bytes());
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&bytes);
        let crc = hasher.finalize();
        bytes.extend_from_slice(&crc.to_be_bytes());

        let temp = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .with_context(|| format!("failed to create {temp:?}"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &self.path)
            .with_context(|| format!("failed to publish {:?}", self.path))?;
        sync_directory(&self.directory)?;
        Ok(())
    }
}

fn decode(bytes: &[u8]) -> Result<(u64, u64)> {
    if bytes.len() != LEN || &bytes[0..4] != MAGIC {
        bail!("wrong length or magic");
    }
    if bytes[4] != VERSION {
        bail!("unsupported epoch file version {}", bytes[4]);
    }
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..LEN - 4]);
    let expected = u32::from_be_bytes(bytes[LEN - 4..].try_into().expect("length checked"));
    if hasher.finalize() != expected {
        bail!("checksum mismatch");
    }
    let current = u64::from_be_bytes(bytes[5..13].try_into().expect("length checked"));
    let voted = u64::from_be_bytes(bytes[13..21].try_into().expect("length checked"));
    Ok((current, voted))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

/// Same rename-publish durability as vyrn-core's `sync_directory`: the
/// directory handle is opened with backup semantics and flushed.
#[cfg(windows)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_survive_reopen_and_never_move_backward() {
        let directory = tempfile::tempdir().unwrap();
        {
            let mut store = EpochStore::open(directory.path()).unwrap();
            assert_eq!((store.current, store.voted), (0, 0), "absent file is epoch 0");
            store.advance(3, true).unwrap();
            store.advance(2, false).unwrap(); // lower: must not regress
            assert_eq!((store.current, store.voted), (3, 3));
        }
        let mut store = EpochStore::open(directory.path()).unwrap();
        assert_eq!((store.current, store.voted), (3, 3), "epochs must be durable");
        store.advance(5, false).unwrap();
        assert_eq!((store.current, store.voted), (5, 3));
    }

    #[test]
    fn a_damaged_epoch_file_is_refused_not_read_as_zero() {
        let directory = tempfile::tempdir().unwrap();
        {
            let mut store = EpochStore::open(directory.path()).unwrap();
            store.advance(7, true).unwrap();
        }
        // Reading a rotted file as epoch 0 would un-fence a deposed primary.
        let path = directory.path().join("EPOCH");
        let mut bytes = fs::read(&path).unwrap();
        bytes[6] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(EpochStore::open(directory.path()).is_err());
    }
}
