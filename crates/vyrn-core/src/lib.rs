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
        if !existed {
            sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))?;
        }
        let lock = open_lock(path)?;
        if path.join("data.vwal").exists() {
            return Err(Error::LegacyFormat);
        }
        let wal_directory = path.join("wal");
        let wal_existed = wal_directory.exists();
        fs::create_dir_all(&wal_directory)?;
        if !wal_existed {
            sync_directory(path)?;
        }

        let mut state = read_manifest(path)?.unwrap_or(TreeState {
            root: 0,
            len: 0,
            generation: 0,
            lsn: 0,
        });
        let page_path = path.join(page_file_name(state.generation));
        let value_path = path.join(value_file_name(state.generation));
        let revision_path = path.join(revision_file_name(state.generation));
        let revision_value_path = path.join(revision_value_file_name(state.generation));
        let mut mvcc_values = value_log::ValueLog::open(&revision_value_path)?;
        let mut mvcc = mvcc::read(&revision_path, state.lsn, &mut mvcc_values)?;
        let segments = list_segments(&wal_directory)?;
        for (index, segment_id) in segments.iter().copied().enumerate() {
            replay_segment(
                &wal_directory.join(segment_name(segment_id)),
                segment_id,
                index + 1 == segments.len(),
                &mut state,
                &mut mvcc,
                &mut mvcc_values,
            )?;
        }
        let tree = PageTree::open(&page_path, &value_path, state.root, state.len)?;
        tree.validate()?;
        let indexes = load_indexes(&tree)?;
        let user_len = tree.count_excluding_prefix(INTERNAL_PREFIX)?;
        mvcc::collect(&mut mvcc, None, state.lsn);
        let segment_id = segments.last().copied().unwrap_or(1);
        let wal_path = wal_directory.join(segment_name(segment_id));
        let mut wal = if wal_path.exists() {
            OpenOptions::new().read(true).write(true).open(wal_path)?
        } else {
            create_segment(&wal_directory, segment_id, state.lsn + 1)?
        };
        wal.seek(SeekFrom::End(0))?;

        Ok(Self {
            path: path.to_owned(),
            tree,
            wal,
            segment_id,
            last_lsn: state.lsn,
            checkpoint_generation: state.generation,
            lock,
            poisoned: false,
            segment_size: options.segment_size.max((SEGMENT_HEADER_LEN + 1) as u64),
            durability: options.durability,
            mvcc,
            mvcc_values,
            indexes,
            active_snapshots: BTreeMap::new(),
            user_len,
            pending_wal: Vec::new(),
            failure: None,
        })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_user_key(key)?;
        self.get_internal(key)
    }

    pub(crate) fn get_internal(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_healthy()?;
        validate_key(key)?;
        self.tree.get(key)
    }

    pub fn revision(&self, key: &[u8]) -> Result<Option<u64>> {
        self.ensure_healthy()?;
        validate_key(key)?;
        Ok(self
            .mvcc
            .histories
            .get(key)
            .and_then(|versions| versions.last())
            .map(|version| version.revision)
            .or(self.tree.revision(key)?)
            .or(self.tree.revision(&tombstone_key(key))?))
    }

    pub fn revisions(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        self.ensure_healthy()?;
        let mut revisions: BTreeMap<_, _> = self
            .tree
            .scan_with_revisions(None, None, usize::MAX)?
            .into_iter()
            .map(
                |(key, _, revision)| match key.strip_prefix(TOMBSTONE_PREFIX) {
                    Some(key) => (key.to_vec(), revision),
                    None => (key, revision),
                },
            )
            .collect();
        revisions.extend(mvcc::revisions(&self.mvcc));
        Ok(revisions.into_iter().collect())
    }

    pub fn set_failure_injector(&mut self, injector: Option<FailureInjector>) {
        self.failure = injector;
    }

    pub fn register_snapshot(&mut self) -> u64 {
        let revision = self.last_lsn;
        *self.active_snapshots.entry(revision).or_default() += 1;
        revision
    }

    pub fn register_snapshot_at(&mut self, revision: u64) -> Result<()> {
        if revision < self.mvcc.gc_floor || revision > self.last_lsn {
            return Err(Error::SnapshotTooOld {
                requested: revision,
                oldest: self.mvcc.gc_floor,
            });
        }
        *self.active_snapshots.entry(revision).or_default() += 1;
        Ok(())
    }

    pub fn release_snapshot(&mut self, revision: u64) {
        if let Some(count) = self.active_snapshots.get_mut(&revision) {
            *count -= 1;
            if *count == 0 {
                self.active_snapshots.remove(&revision);
            }
        }
    }

    pub fn get_at(&self, key: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        self.ensure_healthy()?;
        validate_user_key(key)?;
        if revision < self.mvcc.gc_floor {
            return Err(Error::SnapshotTooOld {
                requested: revision,
                oldest: self.mvcc.gc_floor,
            });
        }
        if self
            .revision(key)?
            .is_none_or(|current| current <= revision)
        {
            self.tree.get(key)
        } else {
            mvcc::get_at(&self.mvcc, &self.mvcc_values, key, revision)
        }
    }

    pub fn scan_at(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        revision: u64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.ensure_healthy()?;
        if let Some(key) = start {
            validate_user_key(key)?;
        }
        if let Some(key) = end {
            validate_user_key(key)?;
        }
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidRange);
        }
        if revision < self.mvcc.gc_floor {
            return Err(Error::SnapshotTooOld {
                requested: revision,
                oldest: self.mvcc.gc_floor,
            });
        }
        let candidate_limit = limit.saturating_add(self.mvcc.histories.len());
        let mut keys: BTreeMap<Vec<u8>, ()> = self
            .tree
            .scan_excluding_prefix(start, end, candidate_limit, Some(INTERNAL_PREFIX))?
            .into_iter()
            .map(|(key, _)| (key, ()))
            .collect();
        for key in self.mvcc.histories.keys() {
            if !key.starts_with(INTERNAL_PREFIX)
                && start.is_none_or(|start| key.as_slice() >= start)
                && end.is_none_or(|end| key.as_slice() < end)
            {
                keys.insert(key.clone(), ());
            }
        }
        let mut rows = Vec::with_capacity(limit.min(1024));
        for key in keys.into_keys() {
            if let Some(value) = self.get_at(&key, revision)? {
                rows.push((key, value));
                if rows.len() == limit {
                    break;
                }
            }
        }
        Ok(rows)
    }

    pub fn changed_since(&self, key: &[u8], revision: u64) -> Result<bool> {
        self.ensure_healthy()?;
        validate_user_key(key)?;
        Ok(self
            .revision(key)?
            .is_some_and(|current| current > revision))
    }

    pub fn range_changed_since(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        revision: u64,
    ) -> Result<bool> {
        self.ensure_healthy()?;
        if self
            .tree
            .changed_since(start, end, revision, Some(INTERNAL_PREFIX))?
        {
            return Ok(true);
        }
        let tombstone_start = start
            .map(tombstone_key)
            .unwrap_or_else(|| TOMBSTONE_PREFIX.to_vec());
        let tombstone_end = end
            .map(tombstone_key)
            .or_else(|| prefix_end(TOMBSTONE_PREFIX));
        self.tree.changed_since(
            Some(&tombstone_start),
            tombstone_end.as_deref(),
            revision,
            None,
        )
    }

    pub fn index_value_changed_since(
        &self,
        index: &[u8],
        value: &[u8],
        revision: u64,
    ) -> Result<bool> {
        self.ensure_healthy()?;
        let start = index_value_prefix(index, value);
        let end = prefix_end(&start);
        if self
            .tree
            .changed_since(Some(&start), end.as_deref(), revision, None)?
        {
            return Ok(true);
        }
        Ok(self
            .mvcc
            .histories
            .range(start.clone()..)
            .take_while(|(key, _)| key.starts_with(&start))
            .any(|(_, versions)| {
                versions
                    .last()
                    .is_some_and(|version| version.revision > revision)
            }))
    }

    pub fn collect_versions(&mut self) -> usize {
        mvcc::collect(
            &mut self.mvcc,
            self.active_snapshots
                .first_key_value()
                .map(|(revision, _)| *revision),
            self.last_lsn,
        )
    }

    pub fn retained_versions(&self) -> usize {
        self.mvcc.histories.values().map(Vec::len).sum()
    }

    pub fn create_index(&mut self, name: Vec<u8>, unique: bool) -> Result<()> {
        validate_index_name(&name)?;
        if self.indexes.contains_key(&name) {
            return Err(Error::IndexExists);
        }
        self.write_batch_internal(vec![BatchOperation::Put(
            index_definition_key(&name),
            vec![u8::from(unique)],
        )])?;
        self.indexes.insert(name, unique);
        Ok(())
    }

    pub fn drop_index(&mut self, name: &[u8]) -> Result<()> {
        if !self.indexes.contains_key(name) {
            return Err(Error::IndexNotFound);
        }
        let start = index_entry_prefix(name);
        let end = prefix_end(&start);
        let mut operations: Vec<_> = self
            .tree
            .scan(Some(&start), end.as_deref(), usize::MAX)?
            .into_iter()
            .map(|(key, _)| BatchOperation::Delete(key))
            .collect();
        operations.push(BatchOperation::Delete(index_definition_key(name)));
        self.write_batch_internal(operations)?;
        self.indexes.remove(name);
        Ok(())
    }

    pub fn write_indexed(
