pub mod backup;
pub mod change_log;
pub mod document;
mod mvcc;
mod page_tree;
mod value_log;

use crc32fast::Hasher;
use fs2::FileExt;
use page_tree::PageTree;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const SEGMENT_MAGIC: &[u8; 4] = b"VSEG";
const RECORD_MAGIC: &[u8; 4] = b"VTXN";
const RECORD_END: &[u8; 4] = b"VEND";
const MANIFEST_MAGIC: &[u8; 4] = b"VMAN";
const VERSION: u8 = 4;
const SEGMENT_HEADER_LEN: usize = 32;
const RECORD_HEADER_LEN: usize = 45;
const RECORD_FOOTER_LEN: usize = 8;
const OP_HEADER_LEN: usize = 9;
const MANIFEST_LEN: usize = 48;
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
const DEFAULT_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;
const INTERNAL_PREFIX: &[u8] = b"\0vyrn:";
const TOMBSTONE_PREFIX: &[u8] = b"\0vyrn:tombstone:";
const CHANGE_LOG_PREFIX: &[u8] = b"\0vyrn:changelog:";
const CHANGE_LOG_START_KEY: &[u8] = b"\0vyrn:changelog-start";
pub const MAX_KEY_SIZE: usize = 64 * 1024;
pub(crate) const MAX_STORED_KEY_SIZE: usize = MAX_KEY_SIZE + TOMBSTONE_PREFIX.len();
pub const MAX_VALUE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePoint {
    BeforePageSync,
    AfterPageSync,
    AfterWalWrite,
    BeforeWalSync,
    BeforeManifestPublish,
    AfterManifestPublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureInjector {
    point: FailurePoint,
    remaining: usize,
}

impl FailureInjector {
    pub fn once(point: FailurePoint) -> Self {
        Self {
            point,
            remaining: 1,
        }
    }

    fn hit(&mut self, point: FailurePoint) -> io::Result<()> {
        if self.point == point && self.remaining != 0 {
            self.remaining -= 1;
            Err(io::Error::other(format!("injected failure at {point:?}")))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("key cannot be empty")]
    EmptyKey,
    #[error("key uses Vyrn's reserved internal prefix")]
    ReservedKey,
    #[error("key exceeds {MAX_KEY_SIZE} bytes")]
    KeyTooLarge,
    #[error("value exceeds {MAX_VALUE_SIZE} bytes")]
    ValueTooLarge,
    #[error("invalid document: {0}")]
    InvalidDocument(String),
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),
    #[error("cursor {requested} is older than the retained change log start {oldest}")]
    CursorTooOld { requested: String, oldest: String },
    #[error("scan start must not be greater than end")]
    InvalidRange,
    #[error("transaction conflicted with a committed write")]
    Conflict,
    #[error("snapshot revision {requested} is older than retained revision {oldest}")]
    SnapshotTooOld { requested: u64, oldest: u64 },
    #[error("unique index {index:?} already contains value {value:?}")]
    UniqueViolation { index: Vec<u8>, value: Vec<u8> },
    #[error("index already exists")]
    IndexExists,
    #[error("index does not exist")]
    IndexNotFound,
    #[error("database is already open by another process")]
    AlreadyOpen,
    #[error("database uses an unsupported earlier development format")]
    LegacyFormat,
    #[error("storage is poisoned after a failed commit; reopen to recover")]
    Poisoned,
    #[error("corrupt WAL segment {segment} at byte {offset}: {reason}")]
    CorruptWal {
        segment: u64,
        offset: u64,
        reason: String,
    },
    #[error("corrupt page {page_id}: {reason}")]
    CorruptPage { page_id: u64, reason: String },
    #[error("corrupt value log at byte {offset}: {reason}")]
    CorruptValue { offset: u64, reason: String },
    #[error("corrupt checkpoint manifest: {0}")]
    CorruptManifest(String),
    #[error("corrupt backup: {0}")]
    CorruptBackup(String),
    #[error("restore target must be empty")]
    RestoreTargetNotEmpty,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum BatchOperation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchResult {
    Put,
    Delete { existed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexUpdate {
    pub index: Vec<u8>,
    pub primary_key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityMode {
    Durable,
    Async,
}

#[derive(Debug, Clone, Copy)]
pub struct EngineOptions {
    pub segment_size: u64,
    pub durability: DurabilityMode,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            durability: DurabilityMode::Durable,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EngineStats {
    pub entries: usize,
    pub last_lsn: u64,
    pub checkpoint_generation: u64,
    pub wal_segments: usize,
    pub pages: u64,
}

#[derive(Clone, Copy)]
struct TreeState {
    root: u64,
    len: u64,
    generation: u64,
    lsn: u64,
}

struct PendingCommit {
    op: u8,
    key: Vec<u8>,
    value: Vec<u8>,
}

pub struct ReadEngine {
    path: PathBuf,
    generation: u64,
    tree: PageTree,
}

impl ReadEngine {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let state = read_manifest(path)?.unwrap_or(TreeState {
            root: 0,
            len: 0,
            generation: 0,
            lsn: 0,
        });
        let tree = PageTree::open(
            &path.join(page_file_name(state.generation)),
            &path.join(value_file_name(state.generation)),
            state.root,
            state.len,
        )?;
        Ok(Self {
            path: path.to_owned(),
            generation: state.generation,
            tree,
        })
    }

    pub fn refresh(&mut self, generation: u64, root: u64, len: u64) -> Result<()> {
        if generation != self.generation {
            self.tree = PageTree::open(
                &self.path.join(page_file_name(generation)),
                &self.path.join(value_file_name(generation)),
                root,
                len,
            )?;
            self.generation = generation;
            Ok(())
        } else {
            self.tree.refresh(root, len)
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_user_key(key)?;
        self.tree.get(key)
    }

    pub fn scan(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if let Some(key) = start {
            validate_user_key(key)?;
        }
        if let Some(key) = end {
            validate_user_key(key)?;
        }
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidRange);
        }
        self.tree
            .scan_excluding_prefix(start, end, limit, Some(INTERNAL_PREFIX))
    }
}

pub struct Engine {
    path: PathBuf,
    tree: PageTree,
    wal: File,
    segment_id: u64,
    last_lsn: u64,
    checkpoint_generation: u64,
    lock: File,
    poisoned: bool,
    segment_size: u64,
    durability: DurabilityMode,
    mvcc: mvcc::State,
    mvcc_values: value_log::ValueLog,
    indexes: BTreeMap<Vec<u8>, bool>,
    active_snapshots: BTreeMap<u64, usize>,
    user_len: usize,
    pending_wal: Vec<Vec<u8>>,
    failure: Option<FailureInjector>,
}

impl Engine {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, EngineOptions::default())
    }

    pub fn open_with_segment_size(path: impl AsRef<Path>, segment_size: u64) -> Result<Self> {
        Self::open_with_options(
            path,
            EngineOptions {
                segment_size,
                ..EngineOptions::default()
            },
        )
    }

    pub fn open_with_options(path: impl AsRef<Path>, options: EngineOptions) -> Result<Self> {
        let path = path.as_ref();
        let existed = path.exists();
        fs::create_dir_all(path)?;
