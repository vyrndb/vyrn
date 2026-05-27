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
        &mut self,
        operations: Vec<BatchOperation>,
        updates: Vec<IndexUpdate>,
    ) -> Result<Vec<BatchResult>> {
        for operation in &operations {
            validate_user_operation(operation)?;
        }
        for update in &updates {
            validate_user_key(&update.primary_key)?;
            validate_index_value(update.old_value.as_deref())?;
            validate_index_value(update.new_value.as_deref())?;
            if !self.indexes.contains_key(&update.index) {
                return Err(Error::IndexNotFound);
            }
        }
        self.write_indexed_internal(operations, updates)
    }

    pub(crate) fn write_indexed_internal(
        &mut self,
        operations: Vec<BatchOperation>,
        updates: Vec<IndexUpdate>,
    ) -> Result<Vec<BatchResult>> {
        for update in &updates {
            validate_key(&update.primary_key)?;
            validate_index_value(update.old_value.as_deref())?;
            validate_index_value(update.new_value.as_deref())?;
            if !self.indexes.contains_key(&update.index) {
                return Err(Error::IndexNotFound);
            }
        }
        let mut index_operations = Vec::new();
        let mut unique_claims: BTreeMap<(Vec<u8>, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for update in &updates {
            if update.old_value == update.new_value {
                continue;
            }
            if let Some(old) = &update.old_value {
                index_operations.push(BatchOperation::Delete(index_entry_key(
                    &update.index,
                    old,
                    &update.primary_key,
                )));
            }
            if let Some(new) = &update.new_value {
                if self.indexes[&update.index] {
                    let claim = (update.index.clone(), new.clone());
                    if unique_claims
                        .insert(claim, update.primary_key.clone())
                        .is_some_and(|primary| primary != update.primary_key)
                    {
                        return Err(Error::UniqueViolation {
                            index: update.index.clone(),
                            value: new.clone(),
                        });
                    }
                    let existing = self.lookup_index(&update.index, new, 2)?;
                    if existing
                        .iter()
                        .any(|primary| primary.as_slice() != update.primary_key)
                    {
                        return Err(Error::UniqueViolation {
                            index: update.index.clone(),
                            value: new.clone(),
                        });
                    }
                }
                index_operations.push(BatchOperation::Put(
                    index_entry_key(&update.index, new, &update.primary_key),
                    Vec::new(),
                ));
            }
        }
        let primary_count = operations.len();
        let mut combined = operations;
        combined.extend(index_operations);
        let mut results = self.write_batch_internal(combined)?;
        results.truncate(primary_count);
        Ok(results)
    }

    pub fn lookup_index(&self, name: &[u8], value: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        if !self.indexes.contains_key(name) {
            return Err(Error::IndexNotFound);
        }
        validate_index_value(Some(value))?;
        let prefix = index_value_prefix(name, value);
        let end = prefix_end(&prefix);
        self.tree
            .scan(Some(&prefix), end.as_deref(), limit)?
            .into_iter()
            .map(|(key, _)| decode_index_primary(&key, &prefix))
            .collect()
    }

    pub fn lookup_index_at(
        &self,
        name: &[u8],
        value: &[u8],
        limit: usize,
        revision: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.ensure_healthy()?;
        validate_index_name(name)?;
        validate_index_value(Some(value))?;
        let definition = index_definition_key(name);
        if self.value_at_internal(&definition, revision)?.is_none() {
            return Err(Error::IndexNotFound);
        }
        let prefix = index_value_prefix(name, value);
        let end = prefix_end(&prefix);
        let candidate_limit = limit.saturating_add(self.mvcc.histories.len());
        let mut entries: BTreeMap<Vec<u8>, ()> = self
            .tree
            .scan(Some(&prefix), end.as_deref(), candidate_limit)?
            .into_iter()
            .map(|(key, _)| (key, ()))
            .collect();
        for key in self
            .mvcc
            .histories
            .range(prefix.clone()..)
            .map(|(key, _)| key)
        {
            if !key.starts_with(&prefix) {
                break;
            }
            entries.insert(key.clone(), ());
        }
        let mut keys = Vec::with_capacity(limit.min(1024));
        for key in entries.into_keys() {
            if self.value_at_internal(&key, revision)?.is_some() {
                keys.push(decode_index_primary(&key, &prefix)?);
                if keys.len() == limit {
                    break;
                }
            }
        }
        Ok(keys)
    }

    fn value_at_internal(&self, key: &[u8], revision: u64) -> Result<Option<Vec<u8>>> {
        if self
            .revision(key)?
            .is_none_or(|current| current <= revision)
        {
            self.tree.get(key)
        } else {
            mvcc::get_at(&self.mvcc, &self.mvcc_values, key, revision)
        }
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.write_batch(vec![BatchOperation::Put(key, value)])?;
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<bool> {
        let result = self.write_batch(vec![BatchOperation::Delete(key.to_vec())])?;
        Ok(matches!(
            result.first(),
            Some(BatchResult::Delete { existed: true })
        ))
    }

    pub fn write_batch(&mut self, operations: Vec<BatchOperation>) -> Result<Vec<BatchResult>> {
        for operation in &operations {
            validate_user_operation(operation)?;
        }
        self.write_batch_internal(operations)
    }

    fn write_batch_internal(
        &mut self,
        operations: Vec<BatchOperation>,
    ) -> Result<Vec<BatchResult>> {
        self.ensure_healthy()?;
        if operations.is_empty() {
            return Ok(Vec::new());
        }
        for operation in &operations {
            match operation {
                BatchOperation::Put(key, value) => {
                    validate_key(key)?;
                    validate_value(value)?;
                }
                BatchOperation::Delete(key) => validate_key(key)?,
            }
        }
        let requested = operations.len();
        let operations = self.with_change_log(operations)?;
        let original_root = self.tree.root_id();
        let original_len = self.tree.len();
        let original_user_len = self.user_len;
        let oldest_snapshot = self
            .active_snapshots
            .first_key_value()
            .map(|(revision, _)| *revision);
        let mut previous = BTreeMap::new();
        if oldest_snapshot.is_some() {
            for operation in &operations {
                let key = match operation {
                    BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
                };
                if is_versioned_key(key) {
                    previous
                        .entry(key.clone())
                        .or_insert((self.tree.revision(key)?, self.tree.get(key)?));
                }
            }
        }
        let mut pending = Vec::with_capacity(operations.len());
        let mut results = Vec::with_capacity(operations.len());
        for operation in operations {
            match operation {
                BatchOperation::Put(key, value) => {
                    validate_key(&key)?;
                    validate_value(&value)?;
                    let revision = self.last_lsn.checked_add(1).ok_or_else(|| {
                        Error::Io(io::Error::other("WAL sequence number exhausted"))
                    })?;
                    if !key.starts_with(INTERNAL_PREFIX) {
                        let tombstone = tombstone_key(&key);
                        if let Some((root, len)) = self.tree.prepare_delete(&tombstone)? {
                            self.tree.publish(root, len);
                        }
                    }
                    let existed = self.tree.get(&key)?.is_some();
                    let (root, len) = self.tree.prepare_put(&key, &value, revision)?;
                    if !key.starts_with(INTERNAL_PREFIX) && !existed {
                        self.user_len += 1;
                    }
                    pending.push(PendingCommit {
                        op: OP_PUT,
                        key,
                        value,
                    });
                    self.tree.publish(root, len);
                    results.push(BatchResult::Put);
                }
                BatchOperation::Delete(key) => {
                    validate_key(&key)?;
                    if let Some((root, len)) = self.tree.prepare_delete(&key)? {
                        self.tree.publish(root, len);
                        if !key.starts_with(INTERNAL_PREFIX) {
                            self.user_len -= 1;
                        }
                        if !key.starts_with(INTERNAL_PREFIX) {
                            let revision = self.last_lsn.checked_add(1).ok_or_else(|| {
                                Error::Io(io::Error::other("WAL sequence number exhausted"))
                            })?;
                            let tombstone = tombstone_key(&key);
                            let (root, len) = self.tree.prepare_put(&tombstone, &[], revision)?;
                            self.tree.publish(root, len);
                        }
                        pending.push(PendingCommit {
                            op: OP_DELETE,
                            key,
                            value: Vec::new(),
                        });
                        results.push(BatchResult::Delete { existed: true });
                    } else {
                        results.push(BatchResult::Delete { existed: false });
                    }
                }
            }
        }
        if pending.is_empty() {
            return Ok(results);
        }
        let revision = self
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL sequence number exhausted")))?;
        let mut prepared = Vec::with_capacity(pending.len());
        if oldest_snapshot.is_some() {
            for operation in pending.iter().filter(|op| is_versioned_key(&op.key)) {
                prepared.push((
                    operation.key.clone(),
                    mvcc::prepare_value(
                        &mut self.mvcc_values,
                        revision,
                        (operation.op == OP_PUT).then_some(operation.value.as_slice()),
                    )?,
                ));
            }
        }
        if let Err(error) = self.commit_batch(&pending, self.tree.root_id(), self.tree.len()) {
            self.tree.publish(original_root, original_len);
            self.user_len = original_user_len;
            self.poisoned = true;
            return Err(error);
        }
        if let Some(oldest_snapshot) = oldest_snapshot {
            for (key, (revision, value)) in previous {
                if let Some(revision) = revision.filter(|revision| *revision <= oldest_snapshot) {
                    if self.mvcc.histories.get(&key).is_none_or(|versions| {
                        versions
                            .last()
                            .is_none_or(|version| version.revision < revision)
                    }) {
                        mvcc::append(&mut self.mvcc, &mut self.mvcc_values, key, revision, value)?;
                    }
                }
            }
            for (key, value) in prepared {
                mvcc::append_prepared(&mut self.mvcc, key, self.last_lsn, value);
            }
        }
        // Hide results for the change records appended by with_change_log.
        results.truncate(requested);
        Ok(results)
    }

    pub fn scan(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
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
        self.tree
            .scan_excluding_prefix(start, end, limit, Some(INTERNAL_PREFIX))
    }

    /// Appends a durable change record for every user mutation in `operations`.
    ///
    /// The records join the same batch as the data they describe, so a change is
    /// visible after recovery exactly when its mutation committed.
    fn with_change_log(&mut self, operations: Vec<BatchOperation>) -> Result<Vec<BatchOperation>> {
        let sequence = self
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL sequence number exhausted")))?;
        let mut records = Vec::new();
        let mut index: u32 = 0;
        for operation in &operations {
            let published = match operation {
                BatchOperation::Put(key, value) if is_published_key(key) => {
                    Some((key.as_slice(), Some(value.as_slice())))
                }
                BatchOperation::Delete(key) if is_published_key(key) => {
                    Some((key.as_slice(), None))
                }
                _ => None,
            };
            let Some((key, value)) = published else {
                continue;
            };
            records.push(BatchOperation::Put(
                change_log_key(change_log::Cursor::new(sequence, index)),
                change_log::encode_entry(key, value),
            ));
            index = index
                .checked_add(1)
                .ok_or_else(|| Error::Io(io::Error::other("too many changes in one commit")))?;
        }
        // Change records are appended after the caller's operations so their
        // results stay contiguous at the front of the batch.
        let mut combined = operations;
        combined.extend(records);
        Ok(combined)
    }

    /// Reads up to `limit` changes committed strictly after `cursor`.
    ///
    /// Pass `Cursor::start()` to replay everything still retained. Fails with
    /// `CursorTooOld` when the requested position has already been trimmed, so a
    /// resuming subscriber learns it must resynchronize instead of silently
    /// skipping changes.
    pub fn read_changes(
        &self,
        cursor: change_log::Cursor,
        limit: usize,
    ) -> Result<Vec<change_log::ChangeRecord>> {
        self.ensure_healthy()?;
        let retained = self.change_log_start()?;
        if cursor < retained {
            return Err(Error::CursorTooOld {
                requested: cursor.to_token(),
                oldest: retained.to_token(),
            });
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut start = CHANGE_LOG_PREFIX.to_vec();
        start.extend_from_slice(&cursor.suffix());
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let mut records = Vec::new();
        for (key, value) in self.tree.scan(Some(&start), end.as_deref(), limit + 1)? {
            let suffix = &key[CHANGE_LOG_PREFIX.len()..];
            let record = change_log::decode_entry(suffix, &value)?;
            if record.cursor() <= cursor && cursor != change_log::Cursor::start() {
                continue;
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
        Ok(records)
    }

    /// The newest published cursor, for subscribing to future changes only.
    pub fn latest_cursor(&self) -> Result<change_log::Cursor> {
        self.ensure_healthy()?;
        Ok(change_log::Cursor::new(self.last_lsn, u32::MAX))
    }

    /// The cursor of the newest record actually present in the change log.
    ///
    /// Unlike [`Engine::latest_cursor`] this never points past a real record, so
    /// a caller can commit and then read back exactly the records it published.
    pub fn latest_published_cursor(&self) -> Result<change_log::Cursor> {
        self.ensure_healthy()?;
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let records = self
            .tree
            .scan(Some(CHANGE_LOG_PREFIX), end.as_deref(), usize::MAX)?;
        match records.last() {
            Some((key, _)) => change_log::Cursor::from_suffix(&key[CHANGE_LOG_PREFIX.len()..]),
            None => Ok(change_log::Cursor::start()),
        }
    }

    /// The oldest cursor still retained; anything earlier has been trimmed.
    pub fn change_log_start(&self) -> Result<change_log::Cursor> {
        match self.tree.get(CHANGE_LOG_START_KEY)? {
            Some(value) => change_log::Cursor::from_suffix(&value),
            None => Ok(change_log::Cursor::start()),
        }
    }

    /// Number of retained change records.
    pub fn change_log_len(&self) -> Result<usize> {
        let end = prefix_end(CHANGE_LOG_PREFIX);
        Ok(self
            .tree
            .scan(Some(CHANGE_LOG_PREFIX), end.as_deref(), usize::MAX)?
            .len())
    }

    /// Drops change records at or before `cursor` and records the new retention
    /// floor, so later resume attempts from trimmed positions fail loudly.
    pub fn trim_changes(&mut self, cursor: change_log::Cursor) -> Result<usize> {
        self.ensure_healthy()?;
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let mut operations = Vec::new();
        for (key, _) in self
            .tree
            .scan(Some(CHANGE_LOG_PREFIX), end.as_deref(), usize::MAX)?
        {
            let position = change_log::Cursor::from_suffix(&key[CHANGE_LOG_PREFIX.len()..])?;
            if position <= cursor {
                operations.push(BatchOperation::Delete(key));
            }
        }
        let removed = operations.len();
        if removed == 0 {
            return Ok(0);
        }
        operations.push(BatchOperation::Put(
            CHANGE_LOG_START_KEY.to_vec(),
            cursor.suffix(),
        ));
        self.write_batch_internal(operations)?;
        Ok(removed)
    }

    pub(crate) fn scan_internal(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.ensure_healthy()?;
        if let Some(key) = start {
            validate_key(key)?;
        }
        if let Some(key) = end {
            validate_key(key)?;
        }
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidRange);
        }
        self.tree.scan(start, end, limit)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if !self.pending_wal.is_empty() {
            self.tree.sync()?;
            self.mvcc_values.sync()?;
            for record in self.pending_wal.drain(..) {
                self.wal.write_all(&record)?;
            }
            self.wal.sync_data()?;
        }
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        self.sync()?;
        self.tree.validate()?;
        let generation = self.checkpoint_generation + 1;
        let temporary = self
            .path
            .join(format!("{}.tmp", page_file_name(generation)));
        let published = self.path.join(page_file_name(generation));
        let old = self.path.join(page_file_name(self.checkpoint_generation));
        let temporary_values = self
            .path
            .join(format!("{}.tmp", value_file_name(generation)));
        let published_values = self.path.join(value_file_name(generation));
        let old_values = self.path.join(value_file_name(self.checkpoint_generation));
        let temporary_revisions = self
            .path
            .join(format!("{}.tmp", revision_file_name(generation)));
        let published_revisions = self.path.join(revision_file_name(generation));
        let old_revisions = self
            .path
            .join(revision_file_name(self.checkpoint_generation));
        let temporary_revision_values = self
            .path
            .join(format!("{}.tmp", revision_value_file_name(generation)));
        let published_revision_values = self.path.join(revision_value_file_name(generation));
        let old_revision_values = self
            .path
            .join(revision_value_file_name(self.checkpoint_generation));
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_file(&published);
        let _ = fs::remove_file(&temporary_values);
        let _ = fs::remove_file(&published_values);
        let _ = fs::remove_file(&temporary_revisions);
        let _ = fs::remove_file(&published_revisions);
        let _ = fs::remove_file(&temporary_revision_values);
        let _ = fs::remove_file(&published_revision_values);
        let (root, len) = self.tree.compact_to(&temporary, &temporary_values)?;
        let mut compacted_values = value_log::ValueLog::open(&temporary_revision_values)?;
        let compacted_mvcc = mvcc::compact(&self.mvcc, &self.mvcc_values, &mut compacted_values)?;
        compacted_values.sync()?;
        mvcc::write(&temporary_revisions, &compacted_mvcc)?;
        fs::rename(&temporary, &published)?;
        fs::rename(&temporary_values, &published_values)?;
        fs::rename(&temporary_revisions, &published_revisions)?;
        fs::rename(&temporary_revision_values, &published_revision_values)?;
        sync_directory(&self.path)?;
        let new_state = TreeState {
            root,
            len,
            generation,
            lsn: self.last_lsn,
        };
        self.inject(FailurePoint::BeforeManifestPublish)?;
        write_manifest(&self.path, new_state)?;
        self.inject(FailurePoint::AfterManifestPublish)?;
        self.tree = PageTree::open(&published, &published_values, root, len)?;
        self.tree.validate()?;
        self.mvcc_values = value_log::ValueLog::open(&published_revision_values)?;
        self.mvcc = compacted_mvcc;
        self.rotate_segment()?;
        let wal_directory = self.path.join("wal");
        for segment in list_segments(&wal_directory)? {
            if segment < self.segment_id {
                fs::remove_file(wal_directory.join(segment_name(segment)))?;
            }
        }
        sync_directory(&wal_directory)?;
        if old.exists() {
            fs::remove_file(old)?;
        }
        if old_values.exists() {
            fs::remove_file(old_values)?;
        }
        if old_revisions.exists() {
            fs::remove_file(old_revisions)?;
        }
        if old_revision_values.exists() {
            fs::remove_file(old_revision_values)?;
        }
        sync_directory(&self.path)?;
        self.checkpoint_generation = generation;
        Ok(())
    }

    pub fn stats(&self) -> Result<EngineStats> {
        self.ensure_healthy()?;
        Ok(EngineStats {
            entries: self.len(),
            last_lsn: self.last_lsn,
            checkpoint_generation: self.checkpoint_generation,
            wal_segments: list_segments(&self.path.join("wal"))?.len(),
            pages: self.tree.page_count(),
        })
    }

    pub fn sequence(&self) -> u64 {
        self.last_lsn
    }

    pub fn committed_root(&self) -> (u64, u64, u64) {
        (
            self.checkpoint_generation,
            self.tree.root_id(),
            self.tree.len(),
        )
    }

    pub fn len(&self) -> usize {
        self.user_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn inject(&mut self, point: FailurePoint) -> Result<()> {
        if let Some(injector) = &mut self.failure {
            injector.hit(point)?;
        }
        Ok(())
    }

    fn commit_batch(&mut self, operations: &[PendingCommit], root: u64, len: u64) -> Result<()> {
        let lsn = self
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL sequence number exhausted")))?;
        let record = encode_record(lsn, operations, root, len)?;
        let pending_len: u64 = self
            .pending_wal
            .iter()
            .map(|record| record.len() as u64)
            .sum();
        let current_len = self.wal.metadata()?.len() + pending_len;
        if current_len > SEGMENT_HEADER_LEN as u64
            && current_len + record.len() as u64 > self.segment_size
        {
            self.sync()?;
            self.rotate_segment()?;
        }
        if self.durability == DurabilityMode::Durable {
            self.inject(FailurePoint::BeforePageSync)?;
            self.tree.sync()?;
            self.mvcc_values.sync()?;
            self.inject(FailurePoint::AfterPageSync)?;
            self.wal.write_all(&record)?;
            self.inject(FailurePoint::AfterWalWrite)?;
            self.inject(FailurePoint::BeforeWalSync)?;
            self.wal.sync_data()?;
        } else {
            self.pending_wal.push(record);
        }
        self.last_lsn = lsn;
        Ok(())
    }

    fn rotate_segment(&mut self) -> Result<()> {
        let next = self
            .segment_id
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL segment number exhausted")))?;
        self.wal = create_segment(&self.path.join("wal"), next, self.last_lsn + 1)?;
        self.segment_id = next;
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.sync();
        let _ = FileExt::unlock(&self.lock);
    }
}

fn open_lock(path: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.join("LOCK"))?;
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            Error::AlreadyOpen
        } else {
            Error::Io(error)
        }
    })?;
    Ok(lock)
}

fn create_segment(directory: &Path, segment_id: u64, first_lsn: u64) -> Result<File> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.join(segment_name(segment_id)))?;
    let mut header = [0; SEGMENT_HEADER_LEN];
    header[0..4].copy_from_slice(SEGMENT_MAGIC);
    header[4] = VERSION;
    write_u64(&mut header, 8, segment_id);
    write_u64(&mut header, 16, first_lsn);
    let header_checksum = checksum(&header[0..24]);
    write_u32(&mut header, 24, header_checksum);
    file.write_all(&header)?;
    file.sync_all()?;
    sync_directory(directory)?;
    Ok(file)
}

fn replay_segment(
    path: &Path,
    segment_id: u64,
    is_last: bool,
    state: &mut TreeState,
    mvcc: &mut mvcc::State,
    mvcc_values: &mut value_log::ValueLog,
) -> Result<()> {
    let mut file = OpenOptions::new().read(true).write(is_last).open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SEGMENT_HEADER_LEN as u64 {
        return Err(corrupt(segment_id, 0, "incomplete segment header"));
    }
    let mut header = [0; SEGMENT_HEADER_LEN];
    file.read_exact(&mut header)?;
    if &header[0..4] != SEGMENT_MAGIC
        || header[4] != VERSION
        || read_u64(&header, 8) != segment_id
        || checksum(&header[0..24]) != read_u32(&header, 24)
    {
        return Err(corrupt(segment_id, 0, "invalid segment header"));
    }

    let mut offset = SEGMENT_HEADER_LEN as u64;
    while offset < file_len {
        if file_len - offset < RECORD_HEADER_LEN as u64 {
            return truncate_or_corrupt(&mut file, is_last, segment_id, offset);
        }
        let mut record_header = [0; RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)?;
        if &record_header[0..4] != RECORD_MAGIC || record_header[4] != VERSION {
            return Err(corrupt(segment_id, offset, "invalid transaction header"));
        }
        let lsn = read_u64(&record_header, 5);
        let operation_count = read_u32(&record_header, 13) as usize;
        let payload_len = read_u32(&record_header, 17) as usize;
        let expected_checksum = read_u32(&record_header, 21);
        let root = read_u64(&record_header, 25);
        let len = read_u64(&record_header, 33);
        if operation_count == 0 || payload_len < operation_count.saturating_mul(OP_HEADER_LEN) {
            return Err(corrupt(segment_id, offset, "invalid transaction metadata"));
        }
        let total_len = RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(RECORD_FOOTER_LEN))
            .ok_or_else(|| corrupt(segment_id, offset, "transaction length overflow"))?;
        if total_len as u64 > file_len - offset {
            return truncate_or_corrupt(&mut file, is_last, segment_id, offset);
        }
        let mut payload = vec![0; payload_len];
        let mut footer = [0; RECORD_FOOTER_LEN];
        file.read_exact(&mut payload)?;
        file.read_exact(&mut footer)?;
        validate_payload(&payload, operation_count)
            .map_err(|reason| corrupt(segment_id, offset, reason))?;
        if read_u32(&footer, 0) as usize != total_len
            || &footer[4..8] != RECORD_END
            || transaction_checksum(lsn, operation_count, &payload, root, len) != expected_checksum
        {
            return Err(corrupt(
                segment_id,
                offset,
                "transaction checksum or footer mismatch",
            ));
        }
        if lsn > state.lsn {
            if lsn != state.lsn + 1 {
                return Err(corrupt(segment_id, offset, "WAL sequence is discontinuous"));
            }
            state.root = root;
            state.len = len;
            state.lsn = lsn;
            record_versions(&payload, operation_count, lsn, mvcc, mvcc_values)?;
        }
        offset += total_len as u64;
    }
    Ok(())
}

fn truncate_or_corrupt(file: &mut File, is_last: bool, segment: u64, offset: u64) -> Result<()> {
    if !is_last {
        return Err(corrupt(
            segment,
            offset,
            "incomplete transaction in sealed segment",
        ));
    }
    file.set_len(offset)?;
    file.sync_all()?;
    Ok(())
}

fn encode_record(lsn: u64, operations: &[PendingCommit], root: u64, len: u64) -> Result<Vec<u8>> {
    let operation_count: u32 = operations
        .len()
        .try_into()
        .map_err(|_| Error::Io(io::Error::other("too many operations in transaction")))?;
    let mut payload = Vec::new();
    for operation in operations {
        let key_len: u32 = operation
            .key
            .len()
            .try_into()
            .map_err(|_| Error::KeyTooLarge)?;
        let value_len: u32 = operation
            .value
            .len()
            .try_into()
            .map_err(|_| Error::ValueTooLarge)?;
        payload.push(operation.op);
        payload.extend_from_slice(&key_len.to_be_bytes());
        payload.extend_from_slice(&value_len.to_be_bytes());
        payload.extend_from_slice(&operation.key);
        payload.extend_from_slice(&operation.value);
    }
    let payload_len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| Error::Io(io::Error::other("transaction exceeds WAL record limit")))?;
    let total_len = RECORD_HEADER_LEN + payload.len() + RECORD_FOOTER_LEN;
    let total_len_u32: u32 = total_len
        .try_into()
        .map_err(|_| Error::Io(io::Error::other("transaction exceeds WAL record limit")))?;
    let mut record = vec![0; total_len];
    record[0..4].copy_from_slice(RECORD_MAGIC);
    record[4] = VERSION;
    write_u64(&mut record, 5, lsn);
    write_u32(&mut record, 13, operation_count);
    write_u32(&mut record, 17, payload_len);
    write_u32(
        &mut record,
        21,
        transaction_checksum(lsn, operations.len(), &payload, root, len),
    );
    write_u64(&mut record, 25, root);
    write_u64(&mut record, 33, len);
    record[RECORD_HEADER_LEN..total_len - RECORD_FOOTER_LEN].copy_from_slice(&payload);
    write_u32(&mut record, total_len - RECORD_FOOTER_LEN, total_len_u32);
    record[total_len - 4..].copy_from_slice(RECORD_END);
    Ok(record)
}

fn validate_payload(
    payload: &[u8],
    operation_count: usize,
) -> std::result::Result<(), &'static str> {
    let mut offset = 0;
    for _ in 0..operation_count {
        if payload.len().saturating_sub(offset) < OP_HEADER_LEN {
            return Err("truncated transaction operation");
        }
        let op = payload[offset];
        let key_len = read_u32(payload, offset + 1) as usize;
        let value_len = read_u32(payload, offset + 5) as usize;
        if !matches!(op, OP_PUT | OP_DELETE)
            || key_len == 0
            || key_len > MAX_KEY_SIZE
            || value_len > MAX_VALUE_SIZE
            || (op == OP_DELETE && value_len != 0)
        {
            return Err("invalid transaction operation");
        }
        offset = offset
            .checked_add(OP_HEADER_LEN)
            .and_then(|value| value.checked_add(key_len))
            .and_then(|value| value.checked_add(value_len))
            .ok_or("transaction operation length overflow")?;
        if offset > payload.len() {
            return Err("truncated transaction operation");
        }
    }
    if offset != payload.len() {
        return Err("trailing transaction payload");
    }
    Ok(())
}

fn record_versions(
    payload: &[u8],
    operation_count: usize,
    revision: u64,
    state: &mut mvcc::State,
    values: &mut value_log::ValueLog,
) -> Result<()> {
    let mut offset = 0;
    for _ in 0..operation_count {
        let op = payload[offset];
        let key_len = read_u32(payload, offset + 1) as usize;
        let value_len = read_u32(payload, offset + 5) as usize;
        offset += OP_HEADER_LEN;
        let key = payload[offset..offset + key_len].to_vec();
        offset += key_len;
        let value = (op == OP_PUT).then(|| payload[offset..offset + value_len].to_vec());
        mvcc::append(state, values, key, revision, value)?;
        offset += value_len;
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Option<TreeState>> {
    let manifest_path = path.join("CURRENT");
    if !manifest_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(manifest_path)?;
    if bytes.len() != MANIFEST_LEN
        || &bytes[0..4] != MANIFEST_MAGIC
        || bytes[4] != VERSION
        || checksum(&bytes[0..40]) != read_u32(&bytes, 40)
    {
        return Err(Error::LegacyFormat);
    }
    Ok(Some(TreeState {
        generation: read_u64(&bytes, 8),
        lsn: read_u64(&bytes, 16),
        root: read_u64(&bytes, 24),
        len: read_u64(&bytes, 32),
    }))
}

fn write_manifest(path: &Path, state: TreeState) -> Result<()> {
    let mut manifest = [0; MANIFEST_LEN];
    manifest[0..4].copy_from_slice(MANIFEST_MAGIC);
    manifest[4] = VERSION;
    write_u64(&mut manifest, 8, state.generation);
    write_u64(&mut manifest, 16, state.lsn);
    write_u64(&mut manifest, 24, state.root);
    write_u64(&mut manifest, 32, state.len);
    let manifest_checksum = checksum(&manifest[0..40]);
    write_u32(&mut manifest, 40, manifest_checksum);
    let temporary = path.join("CURRENT.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&manifest)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path.join("CURRENT"))?;
    sync_directory(path)?;
    Ok(())
}

fn list_segments(path: &Path) -> Result<Vec<u64>> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(number) = name.strip_suffix(".vwal") {
            segments.push(
                number
                    .parse::<u64>()
                    .map_err(|_| Error::CorruptManifest(format!("invalid segment name {name}")))?,
            );
        }
    }
    segments.sort_unstable();
    for pair in segments.windows(2) {
        if pair[1] != pair[0] + 1 {
            return Err(Error::CorruptManifest(
                "WAL segment sequence has a gap".into(),
            ));
        }
    }
    Ok(segments)
}

fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        Err(Error::EmptyKey)
    } else if key.len() > MAX_KEY_SIZE {
        Err(Error::KeyTooLarge)
    } else {
        Ok(())
    }
}

fn validate_user_key(key: &[u8]) -> Result<()> {
    validate_key(key)?;
    if key.starts_with(INTERNAL_PREFIX) {
        Err(Error::ReservedKey)
    } else {
        Ok(())
    }
}

fn validate_user_operation(operation: &BatchOperation) -> Result<()> {
    let key = match operation {
        BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
    };
    if key.starts_with(INTERNAL_PREFIX) {
        Err(Error::ReservedKey)
    } else {
        Ok(())
    }
}

fn validate_index_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        Err(Error::EmptyKey)
    } else if name.len() > u16::MAX as usize {
        Err(Error::KeyTooLarge)
    } else {
        Ok(())
    }
}

fn validate_index_value(value: Option<&[u8]>) -> Result<()> {
    if value.is_some_and(|value| value.len() > u32::MAX as usize) {
        Err(Error::ValueTooLarge)
    } else {
        Ok(())
    }
}

/// Whether a key needs MVCC history.
///
/// Change log records are append-only and are never read at an older snapshot,
/// so retaining historical versions of them would waste space and slow
/// collection without making any read correct.
fn is_versioned_key(key: &[u8]) -> bool {
    !key.starts_with(CHANGE_LOG_PREFIX) && key != CHANGE_LOG_START_KEY
}

/// Whether a committed key is part of the published change stream.
///
/// User keys and documents are published; Vyrn's own bookkeeping (secondary
/// index entries, tombstones, index definitions, and the change log itself) is
/// not, so subscribers never see internal representation details.
fn is_published_key(key: &[u8]) -> bool {
    !key.starts_with(INTERNAL_PREFIX) || key.starts_with(document::DOCUMENT_KEY_PREFIX)
}

fn change_log_key(cursor: change_log::Cursor) -> Vec<u8> {
    let mut key = CHANGE_LOG_PREFIX.to_vec();
    key.extend_from_slice(&cursor.suffix());
    key
}

fn tombstone_key(key: &[u8]) -> Vec<u8> {
    let mut tombstone = TOMBSTONE_PREFIX.to_vec();
    tombstone.extend_from_slice(key);
    tombstone
}

fn index_definition_key(name: &[u8]) -> Vec<u8> {
    let mut key = INTERNAL_PREFIX.to_vec();
    key.extend_from_slice(b"index:def:");
    key.extend_from_slice(&(name.len() as u16).to_be_bytes());
    key.extend_from_slice(name);
    key
}

fn index_entry_prefix(name: &[u8]) -> Vec<u8> {
    let mut key = INTERNAL_PREFIX.to_vec();
    key.extend_from_slice(b"index:entry:");
    key.extend_from_slice(&(name.len() as u16).to_be_bytes());
    key.extend_from_slice(name);
    key
}

fn index_value_prefix(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut key = index_entry_prefix(name);
    key.extend_from_slice(&(value.len() as u32).to_be_bytes());
    key.extend_from_slice(value);
    key
}

fn index_entry_key(name: &[u8], value: &[u8], primary_key: &[u8]) -> Vec<u8> {
    let mut key = index_value_prefix(name, value);
    key.extend_from_slice(primary_key);
    key
}

fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    for index in (0..end.len()).rev() {
        if end[index] != u8::MAX {
            end[index] += 1;
            end.truncate(index + 1);
            return Some(end);
        }
    }
    None
}

fn decode_index_primary(key: &[u8], prefix: &[u8]) -> Result<Vec<u8>> {
    let primary = key
        .strip_prefix(prefix)
        .ok_or_else(|| Error::CorruptManifest("invalid index entry key".into()))?;
    validate_key(primary)?;
    Ok(primary.to_vec())
}

fn load_indexes(tree: &PageTree) -> Result<BTreeMap<Vec<u8>, bool>> {
    let mut prefix = INTERNAL_PREFIX.to_vec();
    prefix.extend_from_slice(b"index:def:");
    let end = prefix_end(&prefix);
    let mut indexes = BTreeMap::new();
    for (key, value) in tree.scan(Some(&prefix), end.as_deref(), usize::MAX)? {
        let encoded = key
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| Error::CorruptManifest("invalid index definition key".into()))?;
        if encoded.len() < 2 || read_u16(encoded, 0) as usize != encoded.len() - 2 {
            return Err(Error::CorruptManifest(
                "invalid index definition name".into(),
            ));
        }
        let unique = match value.as_slice() {
            [0] => false,
            [1] => true,
            _ => {
                return Err(Error::CorruptManifest(
                    "invalid index definition value".into(),
                ))
            }
        };
        indexes.insert(encoded[2..].to_vec(), unique);
    }
    Ok(indexes)
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_SIZE {
        Err(Error::ValueTooLarge)
    } else {
        Ok(())
    }
}

fn transaction_checksum(
    lsn: u64,
    operation_count: usize,
    payload: &[u8],
    root: u64,
    len: u64,
) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&[VERSION]);
    hasher.update(&lsn.to_be_bytes());
    hasher.update(&(operation_count as u32).to_be_bytes());
    hasher.update(&(payload.len() as u32).to_be_bytes());
    hasher.update(&root.to_be_bytes());
    hasher.update(&len.to_be_bytes());
    hasher.update(payload);
    hasher.finalize()
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn segment_name(segment: u64) -> String {
    format!("{segment:020}.vwal")
}

fn page_file_name(generation: u64) -> String {
    format!("pages-{generation:020}.vdb")
}

fn value_file_name(generation: u64) -> String {
    format!("values-{generation:020}.vlog")
}

fn revision_file_name(generation: u64) -> String {
    format!("revisions-{generation:020}.vmvcc")
}

fn revision_value_file_name(generation: u64) -> String {
    format!("revision-values-{generation:020}.vlog")
}

fn corrupt(segment: u64, offset: u64, reason: impl Into<String>) -> Error {
    Error::CorruptWal {
        segment,
        offset,
        reason: reason.into(),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
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

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn online_tree_persists_checkpoint_and_later_writes() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"a".to_vec(), b"one".to_vec()).unwrap();
            engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();
            engine.checkpoint().unwrap();
            engine.delete(b"a").unwrap();
            engine.put(b"c".to_vec(), b"three".to_vec()).unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.get(b"a").unwrap(), None);
        assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
        assert_eq!(engine.get(b"c").unwrap(), Some(b"three".to_vec()));
        assert_eq!(engine.stats().unwrap().checkpoint_generation, 1);
    }

    #[test]
    fn transactional_indexes_enforce_uniqueness_and_survive_reopen() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.create_index(b"email".to_vec(), true).unwrap();
            engine.create_index(b"tag".to_vec(), false).unwrap();
            engine
                .write_indexed(
                    vec![BatchOperation::Put(b"user/1".to_vec(), b"alice".to_vec())],
                    vec![
                        IndexUpdate {
                            index: b"email".to_vec(),
                            primary_key: b"user/1".to_vec(),
                            old_value: None,
