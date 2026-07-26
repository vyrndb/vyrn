pub mod backup;
pub mod change_log;
pub mod document;
mod mvcc;
mod page_tree;
pub mod recover;
mod value_log;
mod wal;
pub mod wal_archive;

pub use wal::Wal;

use crc32fast::Hasher;
use fs2::FileExt;
use page_tree::PageTree;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
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

/// When a durable batch's WAL flush happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Barrier {
    /// Flush before returning, so the batch is durable once the call completes.
    Immediate,
    /// Append only, leaving the flush to the caller once it has dropped the
    /// write lock. The batch must not be acknowledged until then.
    Deferred,
}

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub segment_size: u64,
    pub durability: DurabilityMode,
    /// Highest WAL segment id the archiver has durably copied out, shared so
    /// the checkpoint's segment deletion can observe it without taking a lock.
    ///
    /// `None` disables the retention barrier entirely: checkpoints delete
    /// sealed segments exactly as they did before archiving existed.
    pub archived_through: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            durability: DurabilityMode::Durable,
            archived_through: None,
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

    /// Looks up primary keys by secondary index value.
    ///
    /// Runs on a read-only handle so index queries do not contend with the
    /// writer. The index definition is read from the committed tree rather than
    /// an in-memory map, so a reader needs no coordination to see new indexes.
    pub fn lookup_index(&self, name: &[u8], value: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        validate_index_name(name)?;
        validate_index_value(Some(value))?;
        if self.tree.get(&index_definition_key(name))?.is_none() {
            return Err(Error::IndexNotFound);
        }
        let prefix = index_value_prefix(name, value);
        let end = prefix_end(&prefix);
        self.tree
            .scan(Some(&prefix), end.as_deref(), limit)?
            .into_iter()
            .map(|(key, _)| decode_index_primary(&key, &prefix))
            .collect()
    }

    /// Reads documents from a collection by indexed field value.
    pub fn find_documents(
        &self,
        collection: &str,
        field: &str,
        value: &serde_json::Value,
        limit: usize,
    ) -> Result<Vec<document::Document>> {
        document::find_on_reader(self, collection, field, value, limit)
    }

    /// Reads one document by collection and ID.
    pub fn get_document(&self, collection: &str, id: &str) -> Result<Option<document::Document>> {
        document::get_on_reader(self, collection, id)
    }

    /// Lists documents in a collection in key order.
    pub fn list_documents(
        &self,
        collection: &str,
        limit: usize,
    ) -> Result<Vec<document::Document>> {
        document::list_on_reader(self, collection, limit)
    }

    pub(crate) fn read_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        self.tree.get(key)
    }

    pub(crate) fn scan_raw(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.tree.scan(start, end, limit)
    }
}

pub struct Engine {
    path: PathBuf,
    tree: PageTree,
    /// Shared so a commit's flush can run after the write lock is released.
    wal: Arc<Wal>,
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
    /// Change records published by the most recent commit, so subscribers can be
    /// notified without re-reading the change log.
    last_published: Vec<change_log::ChangeRecord>,
    /// Snapshots registered without the write lock, keyed by revision.
    ///
    /// Behind its own mutex so beginning and ending a transaction never blocks on
    /// the writer. MVCC collection consults this alongside `active_snapshots`.
    shared_snapshots: std::sync::Mutex<BTreeMap<u64, usize>>,
    /// Bytes written to the active WAL segment, tracked so the rotation check
    /// does not stat the file on every commit.
    wal_len: u64,
    /// Highest segment id the archiver has durably copied out; sealed segments
    /// above this survive checkpoints because they are the only copy of their
    /// LSN range once the pages behind them are checkpointed.
    archived_through: Option<Arc<std::sync::atomic::AtomicU64>>,
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
        // The checkpoint root was synced before its manifest was published, so it
        // is the newest root recovery can rely on if the page tail was lost.
        let checkpoint = state;
        let mut redo = Vec::new();
        for (index, segment_id) in segments.iter().copied().enumerate() {
            replay_segment(
                &wal_directory.join(segment_name(segment_id)),
                segment_id,
                index + 1 == segments.len(),
                &mut state,
                &mut mvcc,
                &mut mvcc_values,
                &mut redo,
            )?;
        }
        // The WAL names a committed root, but the pages behind it are only
        // guaranteed present if they were synced before the record was written.
        // Try to adopt the root; if it is unreachable or structurally incomplete,
        // reapply the logged mutations onto the last known-good root instead.
        let tree = match PageTree::open(&page_path, &value_path, state.root, state.len)
            .and_then(|tree| tree.validate().map(|()| tree))
        {
            Ok(tree) => tree,
            Err(_) => redo_from_checkpoint(&page_path, &value_path, checkpoint, &redo, &mut state)?,
        };
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
        let wal_len = wal.seek(SeekFrom::End(0))?;

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
            last_published: Vec::new(),
            shared_snapshots: std::sync::Mutex::new(BTreeMap::new()),
            wal_len,
            archived_through: options.archived_through,
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

    /// Whether any of `keys` changed after `revision`.
    ///
    /// Batches the tree lookups into two ordered sweeps (live keys, then
    /// tombstones) rather than descending from the root twice per key, which is
    /// what made transaction validation scale with the number of keys read.
    pub fn any_changed_since(&self, keys: &[Vec<u8>], revision: u64) -> Result<bool> {
        self.ensure_healthy()?;
        let mut pending: BTreeSet<Vec<u8>> = BTreeSet::new();
        for key in keys {
            validate_user_key(key)?;
            // An in-memory history is authoritative and cheap, so a key with a
            // recorded version never needs a tree lookup.
            match self
                .mvcc
                .histories
                .get(key)
                .and_then(|versions| versions.last())
            {
                Some(version) => {
                    if version.revision > revision {
                        return Ok(true);
                    }
                }
                None => {
                    pending.insert(key.clone());
                }
            }
        }
        if pending.is_empty() {
            return Ok(false);
        }
        let live: Vec<Vec<u8>> = pending.into_iter().collect();
        let mut unresolved = Vec::new();
        for (key, entry) in live.iter().zip(self.tree.get_many_with_revision(&live)?) {
            match entry {
                Some((_, current)) => {
                    if current > revision {
                        return Ok(true);
                    }
                }
                None => unresolved.push(tombstone_key(key)),
            }
        }
        if unresolved.is_empty() {
            return Ok(false);
        }
        // A deleted key's revision lives on its tombstone.
        unresolved.sort();
        Ok(self
            .tree
            .get_many_with_revision(&unresolved)?
            .into_iter()
            .flatten()
            .any(|(_, current)| current > revision))
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

    /// Registers a snapshot at the newest committed revision without needing
    /// exclusive access.
    ///
    /// Beginning a transaction only reads the current sequence and bumps a
    /// refcount, so forcing it through the engine's write lock would make every
    /// transaction contend with the writer before it has done any work.
    pub fn register_snapshot_shared(&self) -> u64 {
        let revision = self.last_lsn;
        *self
            .shared_snapshots
            .lock()
            .expect("snapshot registry is never poisoned")
            .entry(revision)
            .or_default() += 1;
        revision
    }

    /// Releases a snapshot taken by [`Engine::register_snapshot_shared`].
    pub fn release_snapshot_shared(&self, revision: u64) {
        let mut snapshots = self
            .shared_snapshots
            .lock()
            .expect("snapshot registry is never poisoned");
        if let Some(count) = snapshots.get_mut(&revision) {
            *count -= 1;
            if *count == 0 {
                snapshots.remove(&revision);
            }
        }
    }

    /// The oldest revision any active reader still needs, across both registries.
    fn oldest_active_snapshot(&self) -> Option<u64> {
        let shared = self
            .shared_snapshots
            .lock()
            .expect("snapshot registry is never poisoned")
            .keys()
            .next()
            .copied();
        match (
            self.active_snapshots.first_key_value().map(|(key, _)| *key),
            shared,
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (value, None) | (None, value) => value,
        }
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
        // Must consider both registries; collecting past a shared snapshot would
        // drop versions a live transaction still needs to read.
        let oldest = self.oldest_active_snapshot();
        mvcc::collect(&mut self.mvcc, oldest, self.last_lsn)
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
        self.write_indexed_batch(operations, updates, Barrier::Immediate)
            .map(|(results, _)| results)
    }

    fn write_indexed_batch(
        &mut self,
        operations: Vec<BatchOperation>,
        updates: Vec<IndexUpdate>,
        barrier: Barrier,
    ) -> Result<(Vec<BatchResult>, Option<u64>)> {
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
        let (mut results, lsn) = self.apply_batch(combined, barrier)?;
        results.truncate(primary_count);
        Ok((results, lsn))
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

    /// Applies a batch and returns the LSN that must be flushed to make it
    /// durable, without flushing it here.
    ///
    /// Lets a caller release the engine's write lock and only then wait on
    /// [`Wal::sync_through`], so the next batch's tree work overlaps this batch's
    /// flush and one barrier can cover several batches. The caller must not
    /// acknowledge these writes before that call returns.
    /// The returned LSN is `None` when no flush is owed, which is the case in
    /// [`DurabilityMode::Async`]: those records are buffered for the background
    /// sync rather than written here, so there is nothing for a caller to wait on.
    pub fn write_batch_deferred(
        &mut self,
        operations: Vec<BatchOperation>,
    ) -> Result<(Vec<BatchResult>, Option<u64>)> {
        for operation in &operations {
            validate_user_operation(operation)?;
        }
        self.apply_batch(operations, Barrier::Deferred)
    }

    /// [`Engine::write_indexed`] with the flush deferred to the caller.
    pub fn write_indexed_deferred(
        &mut self,
        operations: Vec<BatchOperation>,
        updates: Vec<IndexUpdate>,
    ) -> Result<(Vec<BatchResult>, Option<u64>)> {
        for operation in &operations {
            validate_user_operation(operation)?;
        }
        self.write_indexed_batch(operations, updates, Barrier::Deferred)
    }

    fn write_batch_internal(
        &mut self,
        operations: Vec<BatchOperation>,
    ) -> Result<Vec<BatchResult>> {
        self.apply_batch(operations, Barrier::Immediate)
            .map(|(results, _)| results)
    }

    /// Returns the batch's results and, when a flush is owed to the caller, the
    /// LSN that must be made durable before those results may be acknowledged.
    fn apply_batch(
        &mut self,
        operations: Vec<BatchOperation>,
        barrier: Barrier,
    ) -> Result<(Vec<BatchResult>, Option<u64>)> {
        self.ensure_healthy()?;
        if operations.is_empty() {
            return Ok((Vec::new(), None));
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
        // Includes shared snapshots, so a transaction that began without the
        // write lock still forces its prior versions to be retained.
        let oldest_snapshot = self.oldest_active_snapshot();
        // Each key's pre-batch state, read once. This doubles as the presence
        // check below: reading the value and revision in a single descent avoids
        // paying three separate root-to-leaf lookups per key, which is what made
        // commits under an open transaction scale with tree depth.
        let mut wanted: BTreeSet<Vec<u8>> = BTreeSet::new();
        for operation in &operations {
            let key = match operation {
                BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
            };
            wanted.insert(key.clone());
            // A put clears any tombstone, and a delete writes one, so their
            // presence matters too.
            if !key.starts_with(INTERNAL_PREFIX) {
                wanted.insert(tombstone_key(key));
            }
        }
        let wanted: Vec<Vec<u8>> = wanted.into_iter().collect();
        let existing: BTreeMap<Vec<u8>, Option<(Vec<u8>, u64)>> = wanted
            .iter()
            .cloned()
            .zip(self.tree.get_many_with_revision(&wanted)?)
            .collect();
        let mut previous = BTreeMap::new();
        if oldest_snapshot.is_some() {
            for operation in &operations {
                let key = match operation {
                    BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
                };
                if is_versioned_key(key) {
                    let entry = existing.get(key).and_then(Option::as_ref);
                    previous.entry(key.clone()).or_insert((
                        entry.map(|(_, revision)| *revision),
                        entry.map(|(value, _)| value.clone()),
                    ));
                }
            }
        }
        let mut pending = Vec::with_capacity(operations.len());
        let mut results = Vec::with_capacity(operations.len());
        // Resolve each key's presence first, without writing pages. Whether a
        // delete reports a hit, and whether a put must clear a tombstone, both
        // depend on the state left by earlier operations in the same batch, so this
        // starts from the pre-batch state read above and tracks what the batch has
        // changed so far. The page rewrites then happen once for the whole batch
        // rather than once per key.
        let mut overlay: BTreeMap<Vec<u8>, bool> = existing
            .iter()
            .map(|(key, entry)| (key.clone(), entry.is_some()))
            .collect();
        let mut mutations: Vec<(Vec<u8>, page_tree::Mutation)> =
            Vec::with_capacity(operations.len());
        let mut user_delta: i64 = 0;
        let revision = self
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL sequence number exhausted")))?;
        for operation in operations {
            match operation {
                BatchOperation::Put(key, value) => {
                    validate_key(&key)?;
                    validate_value(&value)?;
                    let internal = key.starts_with(INTERNAL_PREFIX);
                    if !internal {
                        let tombstone = tombstone_key(&key);
                        if present(&overlay, &tombstone) {
                            mutations.push((tombstone.clone(), page_tree::Mutation::Delete));
                            overlay.insert(tombstone, false);
                        }
                    }
                    let existed = present(&overlay, &key);
                    mutations.push((
                        key.clone(),
                        page_tree::Mutation::Put {
                            value: value.clone(),
                            revision,
                        },
                    ));
                    overlay.insert(key.clone(), true);
                    if !internal && !existed {
                        user_delta += 1;
                    }
                    pending.push(PendingCommit {
                        op: OP_PUT,
                        key,
                        value,
                    });
                    results.push(BatchResult::Put);
                }
                BatchOperation::Delete(key) => {
                    validate_key(&key)?;
                    if !present(&overlay, &key) {
                        results.push(BatchResult::Delete { existed: false });
                        continue;
                    }
                    let internal = key.starts_with(INTERNAL_PREFIX);
                    mutations.push((key.clone(), page_tree::Mutation::Delete));
                    overlay.insert(key.clone(), false);
                    if !internal {
                        user_delta -= 1;
                        let tombstone = tombstone_key(&key);
                        mutations.push((
                            tombstone.clone(),
                            page_tree::Mutation::Put {
                                value: Vec::new(),
                                revision,
                            },
                        ));
                        overlay.insert(tombstone, true);
                    }
                    pending.push(PendingCommit {
                        op: OP_DELETE,
                        key,
                        value: Vec::new(),
                    });
                    results.push(BatchResult::Delete { existed: true });
                }
            }
        }
        if pending.is_empty() {
            return Ok((results, None));
        }
        let outcome = self.tree.prepare_batch(&mutations)?;
        self.tree.publish(outcome.root, outcome.len);
        self.user_len = self.user_len.saturating_add_signed(user_delta as isize);
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
        // A deferred barrier only appends here; the caller flushes once it has
        // released the write lock, and must not acknowledge before it returns.
        let deferred = barrier == Barrier::Deferred && self.durability == DurabilityMode::Durable;
        let committed = match barrier {
            Barrier::Immediate => self
                .commit_batch(&pending, self.tree.root_id(), self.tree.len())
                .map(|()| None),
            Barrier::Deferred => self
                .append_batch(&pending, self.tree.root_id(), self.tree.len())
                // In async mode the record is buffered rather than written, so
                // there is no barrier for the caller to wait on.
                .map(|lsn| deferred.then_some(lsn)),
        };
        let lsn = match committed {
            Ok(lsn) => lsn,
            Err(error) => {
                self.tree.publish(original_root, original_len);
                self.user_len = original_user_len;
                self.poisoned = true;
                return Err(error);
            }
        };
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
        Ok((results, lsn))
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
        let entries: Vec<(&[u8], Option<&[u8]>)> = operations
            .iter()
            .filter_map(|operation| match operation {
                BatchOperation::Put(key, value) if is_published_key(key) => {
                    Some((key.as_slice(), Some(value.as_slice())))
                }
                BatchOperation::Delete(key) if is_published_key(key) => {
                    Some((key.as_slice(), None))
                }
                _ => None,
            })
            .collect();
        if entries.is_empty() {
            self.last_published = Vec::new();
            return Ok(operations);
        }
        if entries.len() > u32::MAX as usize {
            return Err(Error::Io(io::Error::other(
                "too many changes in one commit",
            )));
        }
        let record = change_log::encode_batch(&entries);
        self.last_published = entries
            .iter()
            .enumerate()
            .map(|(index, (key, value))| change_log::ChangeRecord {
                sequence,
                index: index as u32,
                document: document::change_target(key),
                key: key.to_vec(),
                value: value.map(<[u8]>::to_vec),
            })
            .collect();
        // One change record per commit, appended after the caller's operations so
        // their results stay contiguous at the front of the batch.
        let mut combined = operations;
        combined.push(BatchOperation::Put(change_log_key(sequence), record));
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
        // Start at the commit the cursor points into: its remaining mutations
        // still need delivering, and the per-mutation index is filtered below.
        let start = change_log_key(cursor.sequence);
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let mut records = Vec::new();
        for (key, value) in self.tree.scan(Some(&start), end.as_deref(), limit + 1)? {
            let sequence = change_log_sequence(&key)?;
            for record in change_log::decode_batch(sequence, &value)? {
                if cursor != change_log::Cursor::start() && record.cursor() <= cursor {
                    continue;
                }
                records.push(record);
                if records.len() == limit {
                    return Ok(records);
                }
            }
        }
        Ok(records)
    }

    /// Change records published by the most recent successful commit.
    ///
    /// Lets a caller broadcast exactly what it committed without paying for a
    /// change-log scan on every commit.
    pub fn last_published(&self) -> &[change_log::ChangeRecord] {
        &self.last_published
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
        // Seek the greatest key under the prefix. Scanning the whole log here
        // would make every commit cost O(total changes).
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let Some(key) = self.tree.last_key_in(CHANGE_LOG_PREFIX, end.as_deref())? else {
            return Ok(change_log::Cursor::start());
        };
        let sequence = change_log_sequence(&key)?;
        // Point just past the last mutation of that commit.
        let count = self
            .tree
            .get(&key)?
            .map(|value| change_log::decode_batch(sequence, &value))
            .transpose()?
            .map_or(0, |records| records.len());
        Ok(change_log::Cursor::new(
            sequence,
            count.saturating_sub(1) as u32,
        ))
    }

    /// The oldest cursor still retained; anything earlier has been trimmed.
    pub fn change_log_start(&self) -> Result<change_log::Cursor> {
        match self.tree.get(CHANGE_LOG_START_KEY)? {
            Some(value) => change_log::Cursor::from_suffix(&value),
            None => Ok(change_log::Cursor::start()),
        }
    }

    /// Number of retained individual changes across all retained commits.
    pub fn change_log_len(&self) -> Result<usize> {
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let mut total = 0;
        for (key, value) in self
            .tree
            .scan(Some(CHANGE_LOG_PREFIX), end.as_deref(), usize::MAX)?
        {
            total += change_log::decode_batch(change_log_sequence(&key)?, &value)?.len();
        }
        Ok(total)
    }

    /// Drops change records at or before `cursor` and records the new retention
    /// floor, so later resume attempts from trimmed positions fail loudly.
    pub fn trim_changes(&mut self, cursor: change_log::Cursor) -> Result<usize> {
        self.ensure_healthy()?;
        let end = prefix_end(CHANGE_LOG_PREFIX);
        let mut operations = Vec::new();
        let mut removed = 0;
        for (key, value) in self
            .tree
            .scan(Some(CHANGE_LOG_PREFIX), end.as_deref(), usize::MAX)?
        {
            let sequence = change_log_sequence(&key)?;
            let records = change_log::decode_batch(sequence, &value)?;
            // A commit record is only dropped once every change in it has been
            // consumed, so a cursor mid-commit never loses undelivered changes.
            if records
                .last()
                .is_some_and(|record| record.cursor() <= cursor)
            {
                removed += records.len();
                operations.push(BatchOperation::Delete(key));
            }
        }
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
            let lsn = self.last_lsn;
            for record in self.pending_wal.drain(..) {
                self.wal.append(&record, lsn)?;
            }
        }
        // Also covers a durable commit whose flush was deferred to the caller,
        // so a shutdown or checkpoint never leaves an acknowledged write behind.
        self.wal.sync_through(self.wal.appended())?;
        Ok(())
    }

    /// A handle for flushing the WAL without holding the engine's write lock.
    ///
    /// Pair with [`Engine::write_batch_deferred`]: the returned LSN is durable
    /// once `sync_through` has been called for it.
    pub fn wal(&self) -> Arc<Wal> {
        Arc::clone(&self.wal)
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
        // Once pages are checkpointed, an unarchived sealed segment is the only
        // copy of its LSN range anywhere, so deletion additionally waits for
        // the archiver's watermark. With no archiver configured the barrier is
        // absent and behavior is byte-identical to the pre-archiving rule.
        let archived_through = self
            .archived_through
            .as_ref()
            .map(|watermark| watermark.load(std::sync::atomic::Ordering::Acquire));
        for segment in list_segments(&wal_directory)? {
            if segment < self.segment_id
                && archived_through.is_none_or(|watermark| segment <= watermark)
            {
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

    /// Seals the active WAL segment so the archiver can copy it out.
    ///
    /// The size trigger alone bounds archive lag by bytes, which on a low-write
    /// database can mean days of committed data sitting in one open segment;
    /// calling this on a timer bounds the loss window by time instead. A no-op
    /// when the active segment holds no records, so an idle database does not
    /// accumulate empty segments.
    pub fn rotate_for_archive(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if self.wal_len <= SEGMENT_HEADER_LEN as u64 {
            return Ok(());
        }
        self.rotate_segment()
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
        let lsn = self.append_batch(operations, root, len)?;
        if self.durability == DurabilityMode::Durable {
            self.wal.sync_through(lsn)?;
        }
        Ok(())
    }

    /// Appends this batch's WAL record without flushing it.
    ///
    /// Returns the LSN that must be passed to [`Wal::sync_through`] before the
    /// batch may be acknowledged.
    fn append_batch(&mut self, operations: &[PendingCommit], root: u64, len: u64) -> Result<u64> {
        let lsn = self
            .last_lsn
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL sequence number exhausted")))?;
        let record = encode_record(lsn, operations, root, len)?;
        // Tracked in memory rather than stat'ing the WAL on every commit. A
        // buffered async record is already counted here when it is pushed onto
        // `pending_wal`, so adding those lengths again would double-count them
        // and rotate early. `rotate_segment` drains the buffer itself.
        let current_len = self.wal_len;
        if current_len > SEGMENT_HEADER_LEN as u64
            && current_len + record.len() as u64 > self.segment_size
        {
            self.rotate_segment()?;
        }
        if self.durability == DurabilityMode::Durable {
            // Only the WAL is written here. Pages and historical values are left
            // for the background flush: redo recovery reapplies logged mutations
            // when the committed root's pages did not survive, so a commit no
            // longer needs a page barrier before naming its root.
            self.inject(FailurePoint::BeforePageSync)?;
            self.inject(FailurePoint::AfterPageSync)?;
            self.wal_len += record.len() as u64;
            self.wal.append(&record, lsn)?;
            self.inject(FailurePoint::AfterWalWrite)?;
            self.inject(FailurePoint::BeforeWalSync)?;
        } else {
            self.wal_len += record.len() as u64;
            self.pending_wal.push(record);
        }
        self.last_lsn = lsn;
        Ok(lsn)
    }

    fn rotate_segment(&mut self) -> Result<()> {
        // The new segment's header claims `first_lsn = last_lsn + 1`, so every
        // record at or below `last_lsn` must be in the outgoing segment before
        // the switch. In async mode `last_lsn` runs ahead of the buffered
        // records, and draining them after rotation would put them in the new
        // segment, above LSNs its header says it starts at.
        self.sync()?;
        debug_assert!(self.pending_wal.is_empty());
        let next = self
            .segment_id
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("WAL segment number exhausted")))?;
        let wal_directory = self.path.join("wal");
        let mut file = create_segment(&wal_directory, next, self.last_lsn + 1)?;
        // Nothing about this engine changes until the writer has actually
        // switched. The header just created is a durable promise that LSNs
        // from `last_lsn + 1` live in segment `next`; if the switch fails the
        // writer keeps appending to the outgoing segment, so any further
        // commit would falsify that promise — and after two restarts replay
        // rejects the segment whose first record contradicts its header. On
        // failure the orphan successor is therefore removed again and the
        // engine poisoned so no commit can land behind the stale state;
        // reopening rebuilds `segment_id` and `wal_len` from disk. `wal_len`
        // in particular must not restart at the new header's length early, or
        // a failed rotation would also disarm the size trigger for the old,
        // still-active segment.
        let switched = file
            .seek(SeekFrom::End(0))
            .map_err(Error::from)
            // Flushes the outgoing segment before adopting the new one, so a
            // durable record never sits behind an unflushed one in an earlier
            // segment.
            .and_then(|length| self.wal.rotate(file).map(|()| length));
        match switched {
            Ok(length) => {
                // The new segment starts at its header, so the tracked length
                // restarts too.
                self.wal_len = length;
                self.segment_id = next;
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                let _ = fs::remove_file(wal_directory.join(segment_name(next)));
                let _ = sync_directory(&wal_directory);
                Err(error)
            }
        }
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

/// One committed WAL record's mutations, kept so recovery can reapply them when
/// the committed root is not reachable in the page file.
struct RedoRecord {
    lsn: u64,
    operations: Vec<(u8, Vec<u8>, Option<Vec<u8>>)>,
}

/// Rebuilds the tree by reapplying logged mutations from the checkpoint root.
///
/// This is the redo half of recovery. A commit's pages may be absent if the
/// process died before they reached disk, so the root named by the WAL cannot be
/// trusted unconditionally. Replaying the mutations reconstructs an equivalent
/// tree from the last root that is known to be complete, which is what lets the
/// commit path skip syncing pages before the WAL.
fn redo_from_checkpoint(
    page_path: &Path,
    value_path: &Path,
    base: TreeState,
    redo: &[RedoRecord],
    state: &mut TreeState,
) -> Result<PageTree> {
    let checkpoint_lsn = base.lsn;
    // Start from the checkpoint root, which was synced before the manifest was
    // published. If even that is unreachable the page file lost more than the
    // unsynced tail, so rebuild from empty and redo everything still logged.
    let mut tree = match PageTree::open(page_path, value_path, base.root, base.len)
        .and_then(|tree| tree.validate().map(|()| tree))
    {
        Ok(tree) => tree,
        Err(_) => PageTree::open(page_path, value_path, 0, 0)?,
    };

    for record in redo.iter().filter(|record| record.lsn > checkpoint_lsn) {
        for (op, key, value) in &record.operations {
            if *op == OP_PUT {
                let value = value.as_deref().unwrap_or_default();
                let (root, len) = tree.prepare_put(key, value, record.lsn)?;
                tree.publish(root, len);
            } else if let Some((root, len)) = tree.prepare_delete(key)? {
                tree.publish(root, len);
            }
        }
    }
    tree.sync()?;
    state.root = tree.root_id();
    state.len = tree.len();
    Ok(tree)
}

/// Replays one segment's committed records into `state`.
///
/// `next_first_lsn` is the successor segment's header first LSN, which states
/// exactly where this segment's records end. `None` means there is no
/// successor, so this is the last segment — the only one allowed a torn tail.
fn replay_segment(
    path: &Path,
    segment_id: u64,
    next_first_lsn: Option<u64>,
    state: &mut TreeState,
    mvcc: &mut mvcc::State,
    mvcc_values: &mut value_log::ValueLog,
    redo: &mut Vec<RedoRecord>,
) -> Result<()> {
    let is_last = next_first_lsn.is_none();
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
    // A stalled archiver retains dead segments indefinitely, so scanning their
    // bodies would make open O(retained bytes) — and one flipped bit in a
    // semantically dead segment would make the database unopenable. When every
    // LSN a sealed segment can contain is already at or below the replayed
    // state, nothing in its body can change recovery's outcome; skip it.
    if let Some(next) = next_first_lsn {
        if next.saturating_sub(1) <= state.lsn {
            return Ok(());
        }
    }

    let header_first_lsn = read_u64(&header, 16);
    let mut saw_record = false;
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
        // The header's first LSN is written by create_segment but was never
        // read back, so a body spliced from another segment (or a botched
        // archive restore) went undetected. Checked against the first verified
        // record only: an empty segment has nothing to contradict its header.
        if !saw_record {
            saw_record = true;
            if lsn != header_first_lsn {
                return Err(corrupt(
                    segment_id,
                    offset,
                    "segment first LSN does not match its header",
                ));
            }
        }
        if lsn > state.lsn {
            if lsn != state.lsn + 1 {
                return Err(corrupt(segment_id, offset, "WAL sequence is discontinuous"));
            }
            state.root = root;
            state.len = len;
            state.lsn = lsn;
            record_versions(&payload, operation_count, lsn, mvcc, mvcc_values)?;
            // Keep the mutations so recovery can redo them if the committed root
            // turns out not to be reachable in the page file.
            redo.push(RedoRecord {
                lsn,
                operations: decode_operations(&payload, operation_count),
            });
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
    for (op, key, value) in decode_operations(payload, operation_count) {
        mvcc::append(state, values, key, revision, value)?;
        let _ = op;
    }
    Ok(())
}

/// Splits a WAL record payload back into its individual mutations.
fn decode_operations(
    payload: &[u8],
    operation_count: usize,
) -> Vec<(u8, Vec<u8>, Option<Vec<u8>>)> {
    let mut operations = Vec::with_capacity(operation_count);
    let mut offset = 0;
    for _ in 0..operation_count {
        let op = payload[offset];
        let key_len = read_u32(payload, offset + 1) as usize;
        let value_len = read_u32(payload, offset + 5) as usize;
        offset += OP_HEADER_LEN;
        let key = payload[offset..offset + key_len].to_vec();
        offset += key_len;
        let value = (op == OP_PUT).then(|| payload[offset..offset + value_len].to_vec());
        offset += value_len;
        operations.push((op, key, value));
    }
    operations
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

/// Change records are keyed by commit sequence; the per-mutation index lives
/// inside the record, so one commit costs one tree insert.
fn change_log_key(sequence: u64) -> Vec<u8> {
    let mut key = CHANGE_LOG_PREFIX.to_vec();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn change_log_sequence(key: &[u8]) -> Result<u64> {
    let suffix = &key[CHANGE_LOG_PREFIX.len()..];
    if suffix.len() != 8 {
        return Err(Error::CorruptManifest(
            "change log key has an invalid sequence".into(),
        ));
    }
    Ok(u64::from_be_bytes(suffix.try_into().unwrap()))
}

/// Whether a key is present given the batch's view of the tree.
///
/// Every key a batch touches is read before any pages are written, so a missing
/// entry here means the key was never looked up and cannot be present.
fn present(overlay: &BTreeMap<Vec<u8>, bool>, key: &[u8]) -> bool {
    overlay.get(key).copied().unwrap_or(false)
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
                            new_value: Some(b"a@example.com".to_vec()),
                        },
                        IndexUpdate {
                            index: b"tag".to_vec(),
                            primary_key: b"user/1".to_vec(),
                            old_value: None,
                            new_value: Some(b"admin".to_vec()),
                        },
                    ],
                )
                .unwrap();
            let error = engine
                .write_indexed(
                    vec![BatchOperation::Put(b"user/2".to_vec(), b"other".to_vec())],
                    vec![IndexUpdate {
                        index: b"email".to_vec(),
                        primary_key: b"user/2".to_vec(),
                        old_value: None,
                        new_value: Some(b"a@example.com".to_vec()),
                    }],
                )
                .unwrap_err();
            assert!(matches!(error, Error::UniqueViolation { .. }));
            assert_eq!(engine.get(b"user/2").unwrap(), None);
            let error = engine
                .write_indexed(
                    vec![
                        BatchOperation::Put(b"user/2".to_vec(), b"two".to_vec()),
                        BatchOperation::Put(b"user/3".to_vec(), b"three".to_vec()),
                    ],
                    vec![
                        IndexUpdate {
                            index: b"email".to_vec(),
                            primary_key: b"user/2".to_vec(),
                            old_value: None,
                            new_value: Some(b"shared@example.com".to_vec()),
                        },
                        IndexUpdate {
                            index: b"email".to_vec(),
                            primary_key: b"user/3".to_vec(),
                            old_value: None,
                            new_value: Some(b"shared@example.com".to_vec()),
                        },
                    ],
                )
                .unwrap_err();
            assert!(matches!(error, Error::UniqueViolation { .. }));
            assert_eq!(engine.get(b"user/2").unwrap(), None);
            assert_eq!(engine.get(b"user/3").unwrap(), None);
            assert_eq!(
                engine.lookup_index(b"tag", b"admin", 10).unwrap(),
                vec![b"user/1".to_vec()]
            );
            assert_eq!(
                engine.scan(None, None, 1).unwrap(),
                vec![(b"user/1".to_vec(), b"alice".to_vec())]
            );
            engine.checkpoint().unwrap();
        }
        let mut engine = Engine::open(directory.path()).unwrap();
        assert_eq!(
            engine.lookup_index(b"email", b"a@example.com", 10).unwrap(),
            vec![b"user/1".to_vec()]
        );
        engine.drop_index(b"tag").unwrap();
        assert!(matches!(
            engine.lookup_index(b"tag", b"admin", 10),
            Err(Error::IndexNotFound)
        ));
    }

    #[test]
    fn index_lookup_at_reads_one_historical_revision() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.create_index(b"tag".to_vec(), false).unwrap();
        engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec())],
                vec![IndexUpdate {
                    index: b"tag".to_vec(),
                    primary_key: b"user/1".to_vec(),
                    old_value: None,
                    new_value: Some(b"admin".to_vec()),
                }],
            )
            .unwrap();
        let snapshot = engine.register_snapshot();
        engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec())],
                vec![IndexUpdate {
                    index: b"tag".to_vec(),
                    primary_key: b"user/1".to_vec(),
                    old_value: Some(b"admin".to_vec()),
                    new_value: Some(b"member".to_vec()),
                }],
            )
            .unwrap();
        assert_eq!(
            engine
                .lookup_index_at(b"tag", b"admin", 10, snapshot)
                .unwrap(),
            vec![b"user/1".to_vec()]
        );
        assert!(engine
            .lookup_index_at(b"tag", b"member", 10, snapshot)
            .unwrap()
            .is_empty());
        engine.release_snapshot(snapshot);
    }

    #[test]
    fn active_snapshot_retains_history_until_release() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"key".to_vec(), b"one".to_vec()).unwrap();
        let snapshot = engine.register_snapshot();
        engine.put(b"key".to_vec(), b"two".to_vec()).unwrap();
        engine.delete(b"key").unwrap();
        assert_eq!(
            engine.get_at(b"key", snapshot).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(engine.collect_versions(), 0);
        assert_eq!(
            engine.get_at(b"key", snapshot).unwrap(),
            Some(b"one".to_vec())
        );
        engine.release_snapshot(snapshot);
        assert_eq!(engine.collect_versions(), 3);
        assert_eq!(engine.retained_versions(), 0);
        assert!(matches!(
            engine.get_at(b"key", snapshot),
            Err(Error::SnapshotTooOld { .. })
        ));
    }

    #[test]
    fn current_revisions_survive_updates_deletes_and_checkpoint() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"updated".to_vec(), b"one".to_vec()).unwrap();
            engine.put(b"deleted".to_vec(), b"value".to_vec()).unwrap();
            engine.put(b"updated".to_vec(), b"two".to_vec()).unwrap();
            engine.delete(b"deleted").unwrap();
            assert_eq!(engine.revision(b"updated").unwrap(), Some(3));
            assert_eq!(engine.revision(b"deleted").unwrap(), Some(4));
            engine.checkpoint().unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.revision(b"updated").unwrap(), Some(3));
        assert_eq!(engine.revision(b"deleted").unwrap(), Some(4));
    }

    #[test]
    fn deleted_revision_survives_wal_only_reopen() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"deleted".to_vec(), b"value".to_vec()).unwrap();
            engine.delete(b"deleted").unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.revision(b"deleted").unwrap(), Some(2));
    }

    #[test]
    fn rotates_transaction_segments_and_recovers() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open_with_segment_size(directory.path(), 128).unwrap();
            for index in 0..20 {
                engine
                    .put(format!("key-{index}").into_bytes(), vec![index as u8; 40])
                    .unwrap();
            }
            assert!(engine.stats().unwrap().wal_segments > 1);
        }
        assert_eq!(Engine::open(directory.path()).unwrap().len(), 20);
    }

    #[test]
    fn write_batch_recovers_as_one_transaction() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            let before = engine.sequence();
            let results = engine
                .write_batch(vec![
                    BatchOperation::Put(b"a".to_vec(), b"one".to_vec()),
                    BatchOperation::Put(b"b".to_vec(), b"two".to_vec()),
                    BatchOperation::Delete(b"missing".to_vec()),
                ])
                .unwrap();
            assert_eq!(results.len(), 3);
            assert_eq!(engine.sequence(), before + 1);
        }
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.sequence(), 1);
        assert_eq!(engine.get(b"a").unwrap(), Some(b"one".to_vec()));
        assert_eq!(engine.get(b"b").unwrap(), Some(b"two".to_vec()));
    }

    #[test]
    fn async_wal_is_published_only_by_sync() {
        let directory = tempdir().unwrap();
        let wal = directory.path().join("wal/00000000000000000001.vwal");
        let mut engine = Engine::open_with_options(
            directory.path(),
            EngineOptions {
                durability: DurabilityMode::Async,
                ..EngineOptions::default()
            },
        )
        .unwrap();
        engine.put(b"a".to_vec(), b"one".to_vec()).unwrap();
        assert_eq!(fs::metadata(&wal).unwrap().len(), SEGMENT_HEADER_LEN as u64);
        engine.sync().unwrap();
        assert!(fs::metadata(&wal).unwrap().len() > SEGMENT_HEADER_LEN as u64);
    }

    #[test]
    fn scan_is_ordered_and_rejects_reversed_bounds() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        for key in [b"c", b"a", b"b", b"d"] {
            engine.put(key.to_vec(), key.to_vec()).unwrap();
        }
        let rows = engine.scan(Some(b"b"), Some(b"d"), 10).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.0.as_slice()).collect::<Vec<_>>(),
            vec![b"b", b"c"]
        );
        assert!(matches!(
            engine.scan(Some(b"z"), Some(b"a"), 10),
            Err(Error::InvalidRange)
        ));
    }
}
