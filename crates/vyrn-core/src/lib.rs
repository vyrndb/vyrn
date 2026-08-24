pub mod backup;
pub mod change_log;
pub mod document;
mod fast_hash;
mod mvcc;
mod row_cache;
mod overlay;
mod page_tree;
pub mod portable;
pub mod recover;
pub mod replication;
mod value_log;
mod wal;
pub mod wal_archive;

pub use overlay::{PublishedMutation, WriteBackPublish};
pub use wal::Wal;

/// A value returned without copying its bytes.
///
/// `get_shared` hands back the engine's own storage of the value — a slice
/// of a cached tree page, the value cache's allocation, or the write-back
/// buffer's — kept alive through a reference count for as long as this
/// handle exists. Cloning is a count bump. Dereferences to `[u8]`; call
/// [`SharedBytes::to_vec`] when owned bytes are genuinely needed.
///
/// The trade against [`Engine::get`]: a large value costs nothing to return,
/// and in exchange the handle pins its backing — a cached page or cache slot
/// stays resident while the handle lives, so hold these briefly rather than
/// accumulating them.
#[derive(Clone, Debug)]
pub struct SharedBytes(SharedRepr);

#[derive(Clone, Debug)]
enum SharedRepr {
    Tree(page_tree::SharedTreeValue),
    Buffered(Arc<Vec<u8>>),
}

impl SharedBytes {
    fn tree(value: page_tree::SharedTreeValue) -> Self {
        Self(SharedRepr::Tree(value))
    }

    pub(crate) fn tree_key(key: page_tree::Bytes) -> Self {
        Self(SharedRepr::Tree(page_tree::SharedTreeValue::Paged(key)))
    }

    pub(crate) fn owned(bytes: Vec<u8>) -> Self {
        Self(SharedRepr::Tree(page_tree::SharedTreeValue::Paged(
            page_tree::Bytes::Owned(bytes),
        )))
    }

    fn buffered(value: Arc<Vec<u8>>) -> Self {
        Self(SharedRepr::Buffered(value))
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            SharedRepr::Tree(value) => value.as_slice(),
            SharedRepr::Buffered(value) => value,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// The value as one shared allocation, for the row cache: when the bytes
    /// already live in a reference-counted buffer — the value cache's or the
    /// write-back overlay's — that buffer is reused with a count bump, and
    /// only page-backed bytes are copied out.
    fn shared_vec(&self) -> Arc<Vec<u8>> {
        match &self.0 {
            SharedRepr::Buffered(value) => Arc::clone(value),
            SharedRepr::Tree(page_tree::SharedTreeValue::Log(value)) => Arc::clone(value),
            SharedRepr::Tree(value) => Arc::new(value.as_slice().to_vec()),
        }
    }
}

impl std::ops::Deref for SharedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Diagnostic breakdown of the work `apply_batch` does under the engine write
/// lock.
///
/// The server's `vyrn_commit_*` counters report `apply` as one number; this
/// splits that number into its phases so the dominant one is visible rather than
/// inferred. Counters are process-wide and free-running: read them either side
/// of a workload and divide by the request delta.
pub mod profile {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static CHANGE_LOG_NS: AtomicU64 = AtomicU64::new(0);
    pub static PRESTATE_NS: AtomicU64 = AtomicU64::new(0);
    pub static PLAN_NS: AtomicU64 = AtomicU64::new(0);
    pub static TREE_NS: AtomicU64 = AtomicU64::new(0);
    pub static MVCC_NS: AtomicU64 = AtomicU64::new(0);
    pub static WAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
    pub static BATCHES: AtomicU64 = AtomicU64::new(0);
    /// Deterministic page counts. Unlike a timing on a host that stalls, these
    /// are exact, so they are the reliable signal for whether a change actually
    /// reduced the work a commit does.
    pub static PAGE_HITS: AtomicU64 = AtomicU64::new(0);
    pub static PAGE_MISSES: AtomicU64 = AtomicU64::new(0);
    pub static PAGE_APPENDS: AtomicU64 = AtomicU64::new(0);
    // Sub-phases of `tree`, the phase that dominates a commit once the WAL
    // barrier is amortised. This split is what located the per-page write
    // syscalls that page-append buffering removed; it stays so the next
    // regression in the copy-on-write path is attributable rather than one
    // opaque number.
    /// Time decoding leaf and internal pages into owned entries.
    pub static TREE_DECODE_NS: AtomicU64 = AtomicU64::new(0);
    /// Time encoding entries and children into new pages.
    pub static TREE_ENCODE_NS: AtomicU64 = AtomicU64::new(0);
    /// Time in `PageManager::append`: checksum, buffer, cache admission.
    pub static TREE_APPEND_NS: AtomicU64 = AtomicU64::new(0);
    /// Time writing each batch's buffered pages to the file in one call.
    pub static TREE_FLUSH_NS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn add(counter: &AtomicU64, started: std::time::Instant) {
        counter.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// Phase totals in nanoseconds, plus the request and batch counts they cover.
    pub fn snapshot() -> Vec<(&'static str, u64)> {
        vec![
            ("change_log", CHANGE_LOG_NS.load(Ordering::Relaxed)),
            ("prestate", PRESTATE_NS.load(Ordering::Relaxed)),
            ("plan", PLAN_NS.load(Ordering::Relaxed)),
            ("tree", TREE_NS.load(Ordering::Relaxed)),
            ("mvcc", MVCC_NS.load(Ordering::Relaxed)),
            ("wal", WAL_NS.load(Ordering::Relaxed)),
            ("__requests", REQUESTS.load(Ordering::Relaxed)),
            ("__batches", BATCHES.load(Ordering::Relaxed)),
            ("__page_hits", PAGE_HITS.load(Ordering::Relaxed)),
            ("__page_misses", PAGE_MISSES.load(Ordering::Relaxed)),
            ("__page_appends", PAGE_APPENDS.load(Ordering::Relaxed)),
            ("tree_decode", TREE_DECODE_NS.load(Ordering::Relaxed)),
            ("tree_encode", TREE_ENCODE_NS.load(Ordering::Relaxed)),
            ("tree_append", TREE_APPEND_NS.load(Ordering::Relaxed)),
            ("tree_flush", TREE_FLUSH_NS.load(Ordering::Relaxed)),
        ]
    }
}

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
/// A found key's stored value and the revision that wrote it, absent when the
/// key is gone; one row of a merged scan carries the key as well.
type MergedValue = Option<(Vec<u8>, u64)>;
type MergedRow = (Vec<u8>, Vec<u8>, u64);

/// The root and length a write-back commit's WAL record names.
///
/// With write-back the tree lags the log by design, so no root the tree holds
/// at commit time covers the record being written. Naming one anyway would let
/// the next open adopt a tree that lacks every buffered commit. This value can
/// never be adopted — no page file holds a page at `u64::MAX` — so an open
/// after write-back commits always falls back to redo from the checkpoint,
/// which reconstructs exactly the state the buffer held. The record checksum
/// covers these fields like any others, so the sentinel is as tamper-evident
/// as a real root.
const WRITE_BACK_ROOT: u64 = u64::MAX;

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
    /// Fails the staging of historical MVCC values in `apply_batch`, before the
    /// batch's root is published — the shape of an ENOSPC inside the revision
    /// value log while the mutation is still invisible.
    BeforeValuePrepare,
    /// Fails the post-commit maintenance of MVCC history, after the batch's WAL
    /// record is durable and its root visible.
    BeforeHistoryAppend,
    BeforeManifestPublish,
    AfterManifestPublish,
    /// Fails a checkpoint after the engine has adopted the published generation:
    /// the manifest names it, the tree and value log live on it, and only the
    /// cleanup (segment rotation and retirement) remains.
    AfterTreeAdoption,
    /// Fails a `sync` that is draining buffered async records, after at least
    /// one record has already left the buffer — the shape of an ENOSPC
    /// mid-drain rather than before the first write.
    BetweenBufferedAppends,
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
    /// An on-disk structure carried a format version this build does not speak.
    ///
    /// Distinct from the corruption errors on purpose. A version mismatch means
    /// intact data written by a different build; reporting it as corruption
    /// invites an operator to discard or "repair" a healthy database. Storage
    /// formats may change until 1.0, so this is the expected outcome of moving a
    /// data directory across versions, and the way across is a logical export
    /// taken with the build that wrote it.
    #[error(
        "{structure} was written in format version {found}, but this build speaks version \
         {expected}. The data is not damaged. Export it with the Vyrn version that wrote it \
         (`vyrn export --data <dir> --output dump.vyrnl`) and load it into a fresh directory \
         with this version (`vyrn import dump.vyrnl --target <dir>`)."
    )]
    FormatVersion {
        structure: &'static str,
        found: u8,
        expected: u8,
    },
    #[error("storage is poisoned after a failed commit; reopen to recover")]
    Poisoned,
    /// A commit that reached the WAL and was fsynced, after which maintaining
    /// the engine's in-memory read state failed.
    ///
    /// Deliberately distinct from [`Error::Poisoned`]: `Poisoned` promises that
    /// nothing was acknowledged, so a caller may retry the batch. Here the write
    /// IS on disk — retrying it would apply it twice — and the missing history
    /// entry would corrupt snapshot reads if the engine kept serving. The engine
    /// refuses all further work either way; the only honest answer is to tell
    /// the caller their data survived and make them reopen before continuing.
    #[error(
        "commit {lsn} is durable but the engine was poisoned before its read state \
         caught up; do not retry the write — reopen the database to recover"
    )]
    CommittedThenPoisoned { lsn: u64 },
    #[error("corrupt WAL segment {segment} at byte {offset}: {reason}")]
    CorruptWal {
        segment: u64,
        offset: u64,
        reason: String,
    },
    /// A record arriving from a primary failed validation before it was appended.
    ///
    /// Its own variant rather than [`Error::CorruptWal`] because nothing is wrong
    /// with this node's storage: the bytes never reached a segment, so a segment
    /// id and byte offset would be fabricated. An operator reading
    /// "corrupt WAL segment 0" would go looking for local damage that does not
    /// exist, when the fault is in the stream or in the peer.
    #[error("invalid replicated record: {reason}")]
    InvalidReplicatedRecord { reason: String },
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
    /// A write-back commit was published to a read handle that was not opened
    /// for write-back replay. A wiring bug in the embedding process rather
    /// than damage — refused because silently dropping the mutations would
    /// leave the handle answering from a tree that permanently lags the log.
    #[error("write-back replay mismatch: {reason}")]
    WriteBackMismatch { reason: String },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The pre-batch state of every key a batch touched: its previous revision and
/// value, or `None` for a key that did not exist.
///
/// Used to hand `maintain_history` what the batch displaced, so those versions
/// can be retained for snapshots that still need them.
type PreviousVersions = BTreeMap<Vec<u8>, (Option<u64>, Option<Vec<u8>>)>;

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
    /// Observes every WAL record as it is appended, for replication.
    ///
    /// `None` — the default — leaves the commit path exactly as it was before
    /// replication existed: no extra clone, no extra call, nothing to fail.
    pub record_sink: Option<Arc<dyn RecordSink>>,
    /// Write-back buffer size in bytes; `0` — the default — disables it.
    ///
    /// With a buffer, a commit's durability is its WAL record alone: the
    /// mutations land in an in-memory buffer that every read merges over the
    /// tree, and the tree absorbs the whole buffer in one amortised pass when
    /// it crosses this size and on every checkpoint. This removes the
    /// copy-on-write page rewrite — the dominant CPU cost of a commit — from
    /// the write path entirely, at three costs stated plainly: reopening the
    /// database replays the WAL from the last checkpoint instead of adopting
    /// the newest root (bounded by checkpoint cadence); the commit that
    /// crosses the threshold pays the whole buffer's tree pass (bounded by
    /// this size); and the buffer itself holds up to this many bytes in
    /// memory.
    ///
    /// EMBEDDED USE ONLY for now: [`ReadEngine`] handles opened on the same
    /// directory read the tree, not the writer's buffer, so a server built on
    /// separate read handles must leave this at `0` until those handles learn
    /// to see the buffer. Same-`Engine` reads — everything on this type — see
    /// every committed write immediately, exactly as without the buffer.
    pub write_back_buffer: usize,
}

/// Receives WAL records as the engine appends them.
///
/// The bytes handed over are the record itself, already framed and checksummed
/// by [`encode_record`] — the same bytes recovery reads back. A replica can
/// therefore append them verbatim, and there is no second encoding of a mutation
/// that could drift from the first.
///
/// CALLED WITH THE ENGINE'S WRITE LOCK HELD, so an implementation must not block:
/// hand the bytes to a queue and return. Blocking here stalls every writer.
///
/// A record reaching the sink is NOT yet durable, locally or anywhere else. The
/// engine calls this at append time; the caller is responsible for pairing it
/// with [`Wal::sync_through`] before treating the LSN as committed.
/// `Debug` is a supertrait so `EngineOptions` can keep its `derive(Debug)`. An
/// implementation should print its identity, never buffered record contents:
/// those are user data.
pub trait RecordSink: Send + Sync + std::fmt::Debug {
    /// Offers `record` at `lsn`.
    ///
    /// Infallible on purpose. A replication transport that has fallen over must
    /// not be able to fail a local commit — the primary's own durability does not
    /// depend on it, and turning a transport error into a write error here would
    /// make replication strictly worse than not having it. Report the failure out
    /// of band (metrics, readiness) and let the quorum wait decide.
    fn record(&self, lsn: u64, record: &[u8]);
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            durability: DurabilityMode::Durable,
            archived_through: None,
            record_sink: None,
            write_back_buffer: 0,
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
    /// This handle's copy of the writer's write-back buffer, `None` when the
    /// engine it mirrors runs classic commits. Fed one durable commit at a
    /// time through [`ReadEngine::publish_write_back`], under the same
    /// exclusive borrow as the root refreshes, so every read on this handle
    /// sees a commit entirely or not at all. Values are `Arc`-shared with the
    /// writer's buffer; only keys and map nodes are this handle's own memory.
    overlay: Option<overlay::Overlay>,
    /// The absorb watermark this handle has already evicted through, so a
    /// republished (stale or repeated) watermark costs nothing.
    overlay_evicted_through: u64,
}

impl ReadEngine {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Opens a read handle for an engine running write-back commits.
    ///
    /// Such a handle answers from its overlay merged over the tree, and MUST
    /// be fed every commit through [`ReadEngine::publish_write_back`] — a
    /// handle opened plainly against a write-back engine would silently serve
    /// only what the tree has absorbed.
    pub fn open_with_write_back(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    fn open_inner(path: &Path, write_back: bool) -> Result<Self> {
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
            // A read handle never flushes its overlay — entries leave only by
            // eviction — so the threshold is irrelevant.
            overlay: write_back.then(|| overlay::Overlay::new(usize::MAX)),
            overlay_evicted_through: 0,
        })
    }

    /// Learns one durable write-back commit: its mutations, then any overlay
    /// eviction its absorb watermark licenses.
    ///
    /// Call under the same exclusive borrow as the [`ReadEngine::refresh`]
    /// that publishes the commit's root, refresh first: eviction is only
    /// sound once the tree this handle serves contains the evicted entries.
    ///
    /// Refused when this handle was not opened for write-back — dropping the
    /// mutations instead would leave every read on this handle answering
    /// from a tree that permanently lags the log.
    pub fn publish_write_back(&mut self, publish: &overlay::WriteBackPublish) -> Result<()> {
        if publish.is_empty() {
            return Ok(());
        }
        let Some(overlay) = &mut self.overlay else {
            return Err(Error::WriteBackMismatch {
                reason: "commit published to a read handle opened without write-back replay"
                    .into(),
            });
        };
        for mutation in &publish.mutations {
            overlay.record(
                mutation.key.clone(),
                mutation.value.clone(),
                mutation.revision,
            );
        }
        if let Some(absorbed) = publish.absorbed_through {
            if absorbed > self.overlay_evicted_through {
                overlay.evict_through(absorbed);
                self.overlay_evicted_through = absorbed;
            }
        }
        Ok(())
    }

    /// Drops overlay entries the tree behind this handle has absorbed, for
    /// publication points that carry a watermark but no mutations — the
    /// checkpoint task's republish. Idempotent and monotonic.
    pub fn evict_write_back_through(&mut self, lsn: u64) {
        if let Some(overlay) = &mut self.overlay {
            if lsn > self.overlay_evicted_through {
                overlay.evict_through(lsn);
                self.overlay_evicted_through = lsn;
            }
        }
    }

    /// Publishes a newer committed root to this read handle.
    ///
    /// A refresh below the handle's current generation is ignored rather than
    /// applied: durability and checkpoints publish concurrently, so a batch
    /// whose flush ran long can ask a reader to move back onto a generation a
    /// checkpoint has already retired — and whose files it has already
    /// deleted, so reopening them by path would fail (or worse, recreate them
    /// empty). Skipping loses nothing: the retiring checkpoint compacted at a
    /// later LSN, so the generation the reader already serves contains
    /// everything the stale root did. The comparison happens under the
    /// caller's exclusive borrow, leaving no window between deciding the
    /// refresh is stale and acting on it.
    pub fn refresh(&mut self, generation: u64, root: u64, len: u64) -> Result<()> {
        if generation < self.generation {
            return Ok(());
        }
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
        overlay::merged_get(&self.tree, self.overlay.as_ref(), key)
    }

    /// [`ReadEngine::get`] without copying the value out — see [`SharedBytes`].
    pub fn get_shared(&self, key: &[u8]) -> Result<Option<SharedBytes>> {
        validate_user_key(key)?;
        overlay::merged_get_shared(&self.tree, self.overlay.as_ref(), key)
    }

    /// [`Engine::scan_each`] on a read handle: borrowed-slice rows, nothing
    /// built, valid only inside the callback.
    pub fn scan_each<F: FnMut(&[u8], &[u8])>(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        visit: &mut F,
    ) -> Result<()> {
        if let Some(key) = start {
            validate_user_key(key)?;
        }
        if let Some(key) = end {
            validate_user_key(key)?;
        }
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidRange);
        }
        match &self.overlay {
            Some(buffer) if !buffer.is_empty() => {
                for (key, value, _) in overlay::merged_scan_shared(
                    &self.tree,
                    self.overlay.as_ref(),
                    start,
                    end,
                    limit,
                    Some(INTERNAL_PREFIX),
                )? {
                    visit(&key, &value);
                }
                Ok(())
            }
            _ => self
                .tree
                .scan_visit(start, end, limit, Some(INTERNAL_PREFIX), visit),
        }
    }

    /// [`ReadEngine::scan`] without copying values out — see [`SharedBytes`].
    pub fn scan_shared(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(SharedBytes, SharedBytes)>> {
        if let Some(key) = start {
            validate_user_key(key)?;
        }
        if let Some(key) = end {
            validate_user_key(key)?;
        }
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidRange);
        }
        Ok(overlay::merged_scan_shared(
            &self.tree,
            self.overlay.as_ref(),
            start,
            end,
            limit,
            Some(INTERNAL_PREFIX),
        )?
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect())
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
        Ok(overlay::merged_scan(
            &self.tree,
            self.overlay.as_ref(),
            start,
            end,
            limit,
            Some(INTERNAL_PREFIX),
        )?
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect())
    }

    /// Looks up primary keys by secondary index value.
    ///
    /// Runs on a read-only handle so index queries do not contend with the
    /// writer. The index definition is read from the committed tree rather than
    /// an in-memory map, so a reader needs no coordination to see new indexes.
    pub fn lookup_index(&self, name: &[u8], value: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        validate_index_name(name)?;
        validate_index_value(Some(value))?;
        if overlay::merged_get(&self.tree, self.overlay.as_ref(), &index_definition_key(name))?
            .is_none()
        {
            return Err(Error::IndexNotFound);
        }
        let prefix = index_value_prefix(name, value);
        let end = prefix_end(&prefix);
        overlay::merged_scan(
            &self.tree,
            self.overlay.as_ref(),
            Some(&prefix),
            end.as_deref(),
            limit,
            None,
        )?
        .into_iter()
        .map(|(key, _, _)| decode_index_primary(&key, &prefix))
        .collect()
    }

    /// Reads documents from a collection by indexed field value.
    ///
    /// Numeric equality is encoding-exact: a query for `10` matches stored `10`,
    /// not `10.0`.
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
        overlay::merged_get(&self.tree, self.overlay.as_ref(), key)
    }

    pub(crate) fn scan_raw(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(
            overlay::merged_scan(&self.tree, self.overlay.as_ref(), start, end, limit, None)?
                .into_iter()
                .map(|(key, value, _)| (key, value))
                .collect(),
        )
    }
}

pub struct Engine {
    path: PathBuf,
    tree: PageTree,
    /// Committed mutations the tree has not absorbed yet; `None` when
    /// write-back is disabled and every commit rewrites the tree itself.
    /// Reads on this engine merge it over the tree — see [`overlay::Overlay`].
    write_back: Option<overlay::Overlay>,
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
    /// Async-mode records awaiting their flush, each paired with the LSN it was
    /// issued at. The LSN travels with the record because `last_lsn` names only
    /// the newest one; stamping it onto every drained append would let a
    /// concurrent barrier declare records durable that were never written.
    pending_wal: Vec<(u64, Vec<u8>)>,
    failure: Option<FailureInjector>,
    /// Change records published by the most recent commit, so subscribers can be
    /// notified without re-reading the change log.
    last_published: Vec<change_log::ChangeRecord>,
    /// The raw mutations the most recent write-back commit put in the buffer,
    /// staged for the server to replay onto its read handles once the commit
    /// is durable. Always empty when write-back is off; follows the
    /// `last_published` lifecycle otherwise (cleared on the way into every
    /// batch, taken by the caller after a successful one).
    write_back_publish: Vec<overlay::PublishedMutation>,
    /// Whether commits stage `write_back_publish` at all. Off by default:
    /// staging clones every mutation's key on the commit path, and only an
    /// embedder with read handles to feed — the server — ever takes it.
    /// An embedded engine must not pay for a publication nobody reads.
    write_back_publish_enabled: bool,
    /// The LSN through which the tree has absorbed the write-back buffer:
    /// every buffered entry at or below it is also behind the tree's current
    /// root, so a read handle serving that root may drop its overlay copies.
    /// Monotonic; equals `last_lsn` at open because recovery replays the whole
    /// WAL into the tree itself.
    write_back_absorbed: u64,
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
    /// Replication tap, `None` when replication is off.
    record_sink: Option<Arc<dyn RecordSink>>,
    /// Newest committed value per hot user key — see [`row_cache`] for the
    /// invalidation argument. Budget from `VYRN_ROW_CACHE_BYTES`.
    row_cache: row_cache::RowCache,
    /// Whether any tombstone can exist: probed once at open, set — never
    /// cleared — by every delete that writes one. While false, a commit's
    /// pre-state read skips the tombstone half of its key sweep, which
    /// doubles the descents of a delete-free workload for lookups that can
    /// only miss. Conservative by construction: a spurious `true` costs
    /// descents, a spurious `false` would corrupt revision bookkeeping —
    /// so it only ever moves toward `true` between opens.
    tombstones_possible: bool,
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
        let mut record_end = SEGMENT_HEADER_LEN as u64;
        for (index, segment_id) in segments.iter().copied().enumerate() {
            // The successor's header states where this segment's records end,
            // which lets replay skip the bodies of segments retained only for
            // the archiver.
            let next_first_lsn = segments
                .get(index + 1)
                .map(|next| read_segment_first_lsn(&wal_directory.join(segment_name(*next))))
                .transpose()?;
            // Only the active segment's value is used: it is where the next
            // record goes, which is the end of the records rather than the end
            // of the file now that a runway runs ahead of them.
            record_end = replay_segment(
                &wal_directory.join(segment_name(segment_id)),
                segment_id,
                next_first_lsn,
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
        let (mut wal_file, mut wal_len) = if wal_path.exists() {
            (
                OpenOptions::new().read(true).write(true).open(&wal_path)?,
                record_end,
            )
        } else {
            (
                create_segment(&wal_directory, segment_id, state.lsn + 1)?,
                SEGMENT_HEADER_LEN as u64,
            )
        };
        // An empty active segment carries the only claim about where its
        // records' LSNs start, and replay has no record to contradict it. A
        // failed rotation in an earlier run (crash or I/O error after the
        // successor's header became durable but before the writer switched)
        // can leave such a segment claiming a first LSN below records that
        // later landed in its predecessor; adopting the lie would place the
        // next commit's LSN in a segment whose header disagrees, which replay
        // rejects on the open after this one. The segment provably holds no
        // records, so recreate it with the header the log actually requires.
        if wal_len == SEGMENT_HEADER_LEN as u64
            && read_segment_first_lsn(&wal_path)? != state.lsn + 1
        {
            drop(wal_file);
            wal_file = republish_segment_header(&wal_directory, segment_id, state.lsn + 1)?;
            wal_len = SEGMENT_HEADER_LEN as u64;
        }
        let segment_size = options.segment_size.max((SEGMENT_HEADER_LEN + 1) as u64);
        let wal = Arc::new(Wal::new(wal_file, wal_len, segment_size)?);
        // Everything already in the segment survived recovery, so it is durable.
        wal.adopt(state.lsn);

        // One bounded probe: does any tombstone survive recovery? The
        // write-back buffer is always empty at open, so the tree alone
        // answers.
        let tombstones_possible = !tree
            .scan(
                Some(TOMBSTONE_PREFIX),
                prefix_end(TOMBSTONE_PREFIX).as_deref(),
                1,
            )?
            .is_empty();
        Ok(Self {
            path: path.to_owned(),
            tree,
            // Recovery replayed the WAL into the tree itself, so the buffer
            // always starts empty: the tree is the whole state at open.
            write_back: (options.write_back_buffer > 0)
                .then(|| overlay::Overlay::new(options.write_back_buffer)),
            wal,
            segment_id,
            last_lsn: state.lsn,
            checkpoint_generation: state.generation,
            lock,
            poisoned: false,
            segment_size,
            durability: options.durability,
            mvcc,
            mvcc_values,
            indexes,
            active_snapshots: BTreeMap::new(),
            user_len,
            pending_wal: Vec::new(),
            failure: None,
            last_published: Vec::new(),
            write_back_publish: Vec::new(),
            write_back_publish_enabled: false,
            write_back_absorbed: state.lsn,
            shared_snapshots: std::sync::Mutex::new(BTreeMap::new()),
            wal_len,
            archived_through: options.archived_through,
            record_sink: options.record_sink,
            row_cache: row_cache::RowCache::new(),
            tombstones_possible,
        })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_user_key(key)?;
        self.ensure_healthy()?;
        validate_key(key)?;
        // The health check runs before the cache: a poisoned engine refuses
        // reads outright, cached or not.
        if let Some(hit) = self.row_cache.get(key) {
            return Ok(Some(hit.as_ref().clone()));
        }
        let value = self.tree_get(key)?;
        if let Some(value) = &value {
            self.row_cache.insert(key, Arc::new(value.clone()));
        }
        Ok(value)
    }

    /// [`Engine::get`] without copying the value out — see [`SharedBytes`].
    pub fn get_shared(&self, key: &[u8]) -> Result<Option<SharedBytes>> {
        validate_user_key(key)?;
        self.ensure_healthy()?;
        validate_key(key)?;
        // The health check runs before the cache: a poisoned engine refuses
        // reads outright, cached or not.
        if let Some(hit) = self.row_cache.get(key) {
            return Ok(Some(SharedBytes::buffered(hit)));
        }
        let value = overlay::merged_get_shared(&self.tree, self.write_back.as_ref(), key)?;
        if let Some(value) = &value {
            self.row_cache.insert(key, value.shared_vec());
        }
        Ok(value)
    }

    /// The fastest scan there is: every row reaches `visit` as two borrowed
    /// slices, in key order, and nothing is built — no vector, no row
    /// structs, no reference counts. The slices are valid only inside the
    /// callback; when rows must outlive the walk, use [`Engine::scan`] or
    /// [`Engine::scan_shared`].
    pub fn scan_each<F: FnMut(&[u8], &[u8])>(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        visit: &mut F,
    ) -> Result<()> {
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
        match &self.write_back {
            // Buffered state has to merge, which needs the rows in hand; the
            // buffer is empty between absorbs, so this is the rare shape.
            Some(buffer) if !buffer.is_empty() => {
                for (key, value, _) in overlay::merged_scan_shared(
                    &self.tree,
                    self.write_back.as_ref(),
                    start,
                    end,
                    limit,
                    Some(INTERNAL_PREFIX),
                )? {
                    visit(&key, &value);
                }
                Ok(())
            }
            _ => self
                .tree
                .scan_visit(start, end, limit, Some(INTERNAL_PREFIX), visit),
        }
    }

    /// [`Engine::scan`] without copying values out — see [`SharedBytes`].
    pub fn scan_shared(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(SharedBytes, SharedBytes)>> {
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
        Ok(overlay::merged_scan_shared(
            &self.tree,
            self.write_back.as_ref(),
            start,
            end,
            limit,
            Some(INTERNAL_PREFIX),
        )?
        .into_iter()
        .map(|(key, value, _)| (key, value))
        .collect())
    }

    pub(crate) fn get_internal(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_healthy()?;
        validate_key(key)?;
        self.tree_get(key)
    }

    // --- Write-back merged reads -------------------------------------------
    //
    // Every read on this engine goes through these rather than the tree
    // directly, so a key's newest committed state is found whether the tree
    // has absorbed it or it still sits in the write-back buffer. Tombstones,
    // change-log records, and index entries are ordinary keys, so the layers
    // built on them inherit the merge without knowing it exists. With
    // write-back disabled — every replica today — each of these is exactly
    // its tree counterpart. The merge itself lives in [`overlay`], shared
    // with [`ReadEngine`] so the writer's view and a read handle's view are
    // one implementation.

    fn tree_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        overlay::merged_get(&self.tree, self.write_back.as_ref(), key)
    }

    fn tree_revision(&self, key: &[u8]) -> Result<Option<u64>> {
        overlay::merged_revision(&self.tree, self.write_back.as_ref(), key)
    }

    /// [`PageTree::get_many_revisions`] with the buffer merged over it.
    /// `keys` must be sorted and deduplicated, as the tree requires.
    fn tree_get_many_revisions(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<u64>>> {
        overlay::merged_get_many_revisions(&self.tree, self.write_back.as_ref(), keys)
    }

    /// [`PageTree::get_many_with_revision`] with the buffer merged over it.
    fn tree_get_many_with_revision(&self, keys: &[Vec<u8>]) -> Result<Vec<MergedValue>> {
        overlay::merged_get_many_with_revision(&self.tree, self.write_back.as_ref(), keys)
    }

    /// One ordered pass over the buffer and the tree — see [`overlay::merged_scan`].
    fn tree_scan_merged(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<Vec<MergedRow>> {
        overlay::merged_scan(
            &self.tree,
            self.write_back.as_ref(),
            start,
            end,
            limit,
            excluded_prefix,
        )
    }

    fn tree_scan(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .tree_scan_merged(start, end, limit, None)?
            .into_iter()
            .map(|(key, value, _)| (key, value))
            .collect())
    }

    fn tree_scan_excluding_prefix(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .tree_scan_merged(start, end, limit, excluded_prefix)?
            .into_iter()
            .map(|(key, value, _)| (key, value))
            .collect())
    }

    fn tree_changed_since(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        revision: u64,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<bool> {
        overlay::merged_changed_since(
            &self.tree,
            self.write_back.as_ref(),
            start,
            end,
            revision,
            excluded_prefix,
        )
    }

    /// [`PageTree::last_key_in`] with the buffer merged over it.
    fn tree_last_key_in(&self, start: &[u8], end: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        overlay::merged_last_key_in(&self.tree, self.write_back.as_ref(), start, end)
    }

    /// The revision that last wrote `key`, across the live tree and the retained
    /// history.
    ///
    /// The MAXIMUM of the two, not the history's answer with the tree as a
    /// fallback. History is only recorded while a snapshot is open — see
    /// `maintain_history` — so a key's newest retained version is a LOWER BOUND
    /// on its revision, never an authority: open a transaction, write the key,
    /// close the transaction, write the key again, and the history still names
    /// the first write while the tree has moved on. Preferring the history there
    /// reported a revision the database had already left behind, and two callers
    /// acted on it:
    ///
    /// - `get_at` compared it against the requested snapshot, concluded the live
    ///   tree was old enough to answer, and returned a value written AFTER the
    ///   snapshot as though it had always been there.
    /// - `changed_since` answered "unchanged" for a key that had changed, so two
    ///   transactions that overwrote each other both committed.
    ///
    /// Both tree lookups were already unconditional — `.or(x)` evaluates `x`
    /// eagerly — so taking the maximum costs nothing that the old shape was not
    /// already paying.
    pub fn revision(&self, key: &[u8]) -> Result<Option<u64>> {
        self.ensure_healthy()?;
        validate_key(key)?;
        let retained = self
            .mvcc
            .histories
            .get(key)
            .and_then(|versions| versions.last())
            .map(|version| version.revision);
        // A live entry and a tombstone are mutually exclusive, so this is one
        // answer rather than two competing ones.
        let live = self
            .tree_revision(key)?
            .or(self.tree_revision(&tombstone_key(key))?);
        Ok(match (retained, live) {
            (Some(retained), Some(live)) => Some(retained.max(live)),
            (value, None) | (None, value) => value,
        })
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
            // A retained version is a LOWER BOUND on the key's revision, not an
            // authority — history is only recorded while a snapshot is open, so
            // the newest retained version can name a write the tree has since
            // moved past (see `Engine::revision`). The bound is enough to prove a
            // change, so a history above `revision` short-circuits; it can never
            // prove the absence of one, so anything else still costs a tree
            // lookup. Treating the history as the whole answer here is what let
            // two transactions that overwrote each other both pass validation and
            // commit.
            if self
                .mvcc
                .histories
                .get(key)
                .and_then(|versions| versions.last())
                .is_some_and(|version| version.revision > revision)
            {
                return Ok(true);
            }
            pending.insert(key.clone());
        }
        if pending.is_empty() {
            return Ok(false);
        }
        let live: Vec<Vec<u8>> = pending.into_iter().collect();
        let mut unresolved = Vec::new();
        for (key, entry) in live.iter().zip(self.tree_get_many_revisions(&live)?) {
            match entry {
                Some(current) => {
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
            .tree_get_many_revisions(&unresolved)?
            .into_iter()
            .flatten()
            .any(|current| current > revision))
    }

    pub fn revisions(&self) -> Result<Vec<(Vec<u8>, u64)>> {
        self.ensure_healthy()?;
        let mut revisions: BTreeMap<_, _> = self
            .tree_scan_merged(None, None, usize::MAX, None)?
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

    /// Refuses a snapshot read whose history was never retained.
    ///
    /// The bound is the coverage watermark rather than the collection floor; see
    /// [`mvcc::State::covered_through`] for why the two differ and what reading
    /// below coverage used to return instead of an error. `oldest` reports the
    /// watermark, so a caller learns the earliest revision it *could* have asked
    /// for rather than only that its own was refused.
    fn ensure_covered(&self, revision: u64) -> Result<()> {
        if revision < self.mvcc.covered_through {
            return Err(Error::SnapshotTooOld {
                requested: revision,
                oldest: self.mvcc.covered_through,
            });
        }
        Ok(())
    }

    /// Declares every revision below `self.last_lsn` unanswerable, for a commit
    /// that retained no history.
    ///
    /// Called on exactly the commits `maintain_history` does not run for — the
    /// ones with no snapshot open. Those commits displace values without keeping
    /// them, so afterwards the only revision the engine can answer for is the one
    /// it just wrote. Leaving coverage where it was is what let a snapshot be
    /// registered for a revision whose history had already been thrown away, and
    /// the reads against it came back wrong rather than refused.
    ///
    /// Only ever raises the watermark. A snapshot open across this commit keeps
    /// `oldest_snapshot` populated, so this is not reached and coverage stays
    /// where that snapshot needs it.
    fn publish_coverage(&mut self) {
        self.mvcc.covered_through = self.mvcc.covered_through.max(self.last_lsn);
    }

    /// Locks the shared snapshot registry, reporting a poisoned mutex as an
    /// error rather than panicking.
    ///
    /// The registry is only ever held for a `BTreeMap` refcount bump, so nothing
    /// in here can panic and poison it on its own — but a panic anywhere else in
    /// the process while the guard is held (a caller unwinding through a
    /// `spawn_blocking` body, a test harness aborting a thread) poisons it all
    /// the same, and `expect` then turned that into a second panic inside the
    /// storage engine. The server already maps [`Error::Poisoned`] onto "reopen
    /// the database", which is the correct answer for a registry whose contents
    /// can no longer be trusted; panicking instead took down the write pipeline
    /// for every client.
    fn shared_snapshots(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<u64, usize>>> {
        self.shared_snapshots.lock().map_err(|_| Error::Poisoned)
    }

    /// Registers a snapshot at the newest committed revision without needing
    /// exclusive access.
    ///
    /// Beginning a transaction only reads the current sequence and bumps a
    /// refcount, so forcing it through the engine's write lock would make every
    /// transaction contend with the writer before it has done any work.
    /// Fails with [`Error::Poisoned`] rather than panicking when the registry's
    /// mutex is poisoned — see [`Engine::shared_snapshots`].
    pub fn register_snapshot_shared(&self) -> Result<u64> {
        let revision = self.last_lsn;
        *self.shared_snapshots()?.entry(revision).or_default() += 1;
        Ok(revision)
    }

    /// Releases a snapshot taken by [`Engine::register_snapshot_shared`].
    ///
    /// Fails with [`Error::Poisoned`] rather than panicking when the registry's
    /// mutex is poisoned. A caller that cannot release its pin should say so:
    /// the revision stays retained, which is the state an operator needs to see.
    pub fn release_snapshot_shared(&self, revision: u64) -> Result<()> {
        let mut snapshots = self.shared_snapshots()?;
        if let Some(count) = snapshots.get_mut(&revision) {
            *count -= 1;
            if *count == 0 {
                snapshots.remove(&revision);
            }
        }
        Ok(())
    }

    /// The oldest revision any active reader still needs, across both registries.
    fn oldest_active_snapshot(&self) -> Result<Option<u64>> {
        let shared = self.shared_snapshots()?.keys().next().copied();
        Ok(
            match (
                self.active_snapshots.first_key_value().map(|(key, _)| *key),
                shared,
            ) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (value, None) | (None, value) => value,
            },
        )
    }

    /// Pins an explicit revision, refusing one whose history was never retained.
    ///
    /// The floor check here was the other half of the coverage bug: a revision
    /// above `gc_floor` was accepted as pinnable even when no history covered it,
    /// so a caller could register a snapshot, be told it succeeded, and then read
    /// values that were never the state at that revision. Registering is where
    /// that has to be refused — after this returns Ok the caller is entitled to
    /// believe its reads mean something.
    pub fn register_snapshot_at(&mut self, revision: u64) -> Result<()> {
        self.ensure_covered(revision)?;
        if revision > self.last_lsn {
            return Err(Error::SnapshotTooOld {
                requested: revision,
                oldest: self.mvcc.covered_through,
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
        self.ensure_covered(revision)?;
        if self
            .revision(key)?
            .is_none_or(|current| current <= revision)
        {
            self.tree_get(key)
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
        self.ensure_covered(revision)?;
        // A zero limit is a request for nothing, and the loop below cannot serve
        // it: it only stops on `rows.len() == limit`, which a length that starts
        // at zero has already passed, so every candidate key in range was read at
        // `revision` and returned. The tree's own scan already treats zero this
        // way (`scan_with_revisions_excluding_prefix` skips the descent), so this
        // is the history-overlay half of the same rule.
        if limit == 0 {
            return Ok(Vec::new());
        }
        let candidate_limit = limit.saturating_add(self.mvcc.histories.len());
        let mut keys: BTreeMap<Vec<u8>, ()> = self
            .tree_scan_excluding_prefix(start, end, candidate_limit, Some(INTERNAL_PREFIX))?
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
        if self.tree_changed_since(start, end, revision, Some(INTERNAL_PREFIX))? {
            return Ok(true);
        }
        let tombstone_start = start
            .map(tombstone_key)
            .unwrap_or_else(|| TOMBSTONE_PREFIX.to_vec());
        let tombstone_end = end
            .map(tombstone_key)
            .or_else(|| prefix_end(TOMBSTONE_PREFIX));
        self.tree_changed_since(
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

    /// Fails with [`Error::Poisoned`] rather than panicking when the shared
    /// snapshot registry's mutex is poisoned; collecting without consulting it
    /// would drop versions a live transaction still needs.
    pub fn collect_versions(&mut self) -> Result<usize> {
        // Must consider both registries; collecting past a shared snapshot would
        // drop versions a live transaction still needs to read.
        let oldest = self.oldest_active_snapshot()?;
        Ok(mvcc::collect(&mut self.mvcc, oldest, self.last_lsn))
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
        // The merged scan, not the raw tree: with write-back on, entries this
        // index gained since the last absorb exist only in the buffer, and a
        // drop that misses them leaves orphans for a later recreation of the
        // same name to resurrect as stale lookup answers.
        let mut operations: Vec<_> = self
            .tree_scan(Some(&start), end.as_deref(), usize::MAX)?
            .into_iter()
            .map(|(key, _)| BatchOperation::Delete(key))
            .collect();
        operations.push(BatchOperation::Delete(index_definition_key(name)));
        self.write_batch_internal(operations)?;
        self.indexes.remove(name);
        Ok(())
    }

    /// Deletes every entry of an index while keeping its definition.
    ///
    /// Unlike [`Engine::drop_index`], the index still exists afterwards and is
    /// simply empty, which is what a rebuild needs: the definition has to stay so
    /// writes keep maintaining it, and the stale entries have to go so a rebuild
    /// cannot leave behind ones pointing at values a document no longer holds.
    pub(crate) fn clear_index_entries(&mut self, name: &[u8]) -> Result<()> {
        if !self.indexes.contains_key(name) {
            return Err(Error::IndexNotFound);
        }
        let start = index_entry_prefix(name);
        let end = prefix_end(&start);
        // Merged for the same reason as `drop_index`: a rebuild must clear
        // entries the buffer holds, or they survive as stale index rows.
        let operations: Vec<_> = self
            .tree_scan(Some(&start), end.as_deref(), usize::MAX)?
            .into_iter()
            .map(|(key, _)| BatchOperation::Delete(key))
            .collect();
        if !operations.is_empty() {
            self.write_batch_internal(operations)?;
        }
        Ok(())
    }

    pub fn write_indexed(
        &mut self,
        operations: Vec<BatchOperation>,
        updates: Vec<IndexUpdate>,
    ) -> Result<Vec<BatchResult>> {
        // The user-key and reserved-prefix checks below reject without reaching
        // `write_indexed_batch`, so the buffer is emptied here too.
        self.reset_published();
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
        // Before the index validation below, which can reject the batch — with a
        // unique violation most often — without ever reaching `apply_batch`.
        self.reset_published();
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
        // Every unique-index entry this batch DELETES, collected before any claim
        // is judged.
        //
        // The uniqueness check below asks the live tree who holds the value, and
        // the live tree does not know what this batch is about to remove. So
        // moving a value from one key to another — and swapping two keys' values,
        // which is the same thing twice — was rejected as a duplicate against the
        // very entry the batch deletes: the batch was refused for conflicting with
        // itself, and there was no legal way to express either operation in one
        // atomic batch. Keyed by (index, value, primary key) rather than
        // (index, value), because one key releasing a value must not excuse a
        // duplicate that some THIRD key still holds — that is a genuine violation
        // and stays one.
        let mut released: BTreeSet<(Vec<u8>, Vec<u8>, Vec<u8>)> = BTreeSet::new();
        for update in &updates {
            if update.old_value == update.new_value {
                continue;
            }
            if let Some(old) = &update.old_value {
                released.insert((
                    update.index.clone(),
                    old.clone(),
                    update.primary_key.clone(),
                ));
            }
        }
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
                    // Read past the limit of 2 the check used to use: with
                    // releases discounted, the holders that matter are the ones
                    // this batch does NOT remove, and a bounded read cannot tell
                    // whether the entries it happened to return are those. Two
                    // keys swapping values would return exactly the two entries
                    // being deleted and conclude, wrongly, that nothing else
                    // holds the value.
                    let existing = self.lookup_index(&update.index, new, usize::MAX)?;
                    if existing.iter().any(|primary| {
                        primary.as_slice() != update.primary_key
                            && !released.contains(&(
                                update.index.clone(),
                                new.clone(),
                                primary.clone(),
                            ))
                    }) {
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
        self.tree_scan(Some(&prefix), end.as_deref(), limit)?
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
        self.ensure_covered(revision)?;
        let definition = index_definition_key(name);
        if self.value_at_internal(&definition, revision)?.is_none() {
            return Err(Error::IndexNotFound);
        }
        // Same rule as `scan_at`: the loop below only stops on
        // `keys.len() == limit`, so a zero limit would walk every entry under the
        // prefix and return all of them.
        if limit == 0 {
            return Ok(Vec::new());
        }
        let prefix = index_value_prefix(name, value);
        let end = prefix_end(&prefix);
        let candidate_limit = limit.saturating_add(self.mvcc.histories.len());
        let mut entries: BTreeMap<Vec<u8>, ()> = self
            .tree_scan(Some(&prefix), end.as_deref(), candidate_limit)?
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
            self.tree_get(key)
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
        // The reserved-prefix check below rejects without reaching `apply_batch`.
        self.reset_published();
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
        // The reserved-prefix check below rejects without reaching `apply_batch`.
        self.reset_published();
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
        // The reserved-prefix check below rejects without reaching
        // `write_indexed_batch`.
        self.reset_published();
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
        // Cleared before anything can fail or return early — see
        // `Engine::reset_published` for the leak this closes.
        self.reset_published();
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
        profile::REQUESTS.fetch_add(requested as u64, std::sync::atomic::Ordering::Relaxed);
        profile::BATCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let phase = std::time::Instant::now();
        let operations = self.with_change_log(operations)?;
        profile::add(&profile::CHANGE_LOG_NS, phase);
        let original_root = self.tree.root_id();
        let original_len = self.tree.len();
        let original_user_len = self.user_len;
        // Includes shared snapshots, so a transaction that began without the
        // write lock still forces its prior versions to be retained.
        let oldest_snapshot = self.oldest_active_snapshot()?;
        // Each key's pre-batch state, read once. This doubles as the presence
        // check below: reading the value and revision in a single descent avoids
        // paying three separate root-to-leaf lookups per key, which is what made
        // commits under an open transaction scale with tree depth.
        // A sorted, deduplicated Vec rather than a BTreeSet: one sort over the
        // batch beats a log-depth memcmp walk per insert, and the keys move on
        // into the overlay below instead of being cloned into a second map.
        let mut wanted: Vec<Vec<u8>> = Vec::with_capacity(operations.len() * 2);
        for operation in &operations {
            let key = match operation {
                BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
            };
            wanted.push(key.clone());
            // A put clears any tombstone, and a delete writes one, so their
            // presence matters too — unless none can exist, in which case
            // the whole tombstone half of the sweep is descents that can
            // only miss.
            if self.tombstones_possible && !key.starts_with(INTERNAL_PREFIX) {
                wanted.push(tombstone_key(key));
            }
        }
        wanted.sort_unstable();
        wanted.dedup();
        let phase = std::time::Instant::now();
        // Presence only. The batch needs to know which keys and tombstones
        // exist, not what they hold — reading the values here cost a value-log
        // read per external value while holding the write lock, and the
        // revisions this read also yields go unused.
        let revisions = self.tree_get_many_revisions(&wanted)?;
        let mut previous = BTreeMap::new();
        if oldest_snapshot.is_some() {
            // Only an active snapshot forces a pre-image, and only the versioned
            // keys the batch actually writes need one — not their tombstones. So
            // the value read is a second, narrower sweep rather than a cost every
            // commit pays for every key it touches.
            let mut pre_image: BTreeSet<Vec<u8>> = BTreeSet::new();
            for operation in &operations {
                let key = match operation {
                    BatchOperation::Put(key, _) | BatchOperation::Delete(key) => key,
                };
                if is_versioned_key(key) {
                    pre_image.insert(key.clone());
                }
            }
            let pre_image: Vec<Vec<u8>> = pre_image.into_iter().collect();
            for (key, entry) in pre_image
                .iter()
                .cloned()
                .zip(self.tree_get_many_with_revision(&pre_image)?)
            {
                previous.insert(
                    key,
                    (
                        entry.as_ref().map(|(_, revision)| *revision),
                        entry.map(|(value, _)| value),
                    ),
                );
            }
        }
        profile::add(&profile::PRESTATE_NS, phase);
        let phase = std::time::Instant::now();
        let mut pending = Vec::with_capacity(operations.len());
        let mut results = Vec::with_capacity(operations.len());
        // Resolve each key's presence first, without writing pages. Whether a
        // delete reports a hit, and whether a put must clear a tombstone, both
        // depend on the state left by earlier operations in the same batch, so this
        // starts from the pre-batch state read above and tracks what the batch has
        // changed so far. The page rewrites then happen once for the whole batch
        // rather than once per key.
        // `wanted`'s keys move in; nothing is cloned. Hash map on the crate's
        // fast hasher rather than a BTreeMap: the loop below probes it once
        // or twice per operation and needs membership, never order.
        let mut overlay: fast_hash::FastMap<Vec<u8>, bool> = wanted
            .into_iter()
            .zip(revisions)
            .map(|(key, revision)| (key, revision.is_some()))
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
                    // `tombstones_possible` is read live, not snapshotted: a
                    // delete earlier in this same batch may have written the
                    // first tombstone ever, and it seeded the overlay on its
                    // way — so this probe still sees it.
                    if !internal && self.tombstones_possible {
                        let tombstone = tombstone_key(&key);
                        // Every key and tombstone the loop probes was seeded
                        // into the overlay from `wanted` (or by an earlier
                        // delete in this batch), so updates go through
                        // `get_mut` — the `insert` this replaces cloned the
                        // key just to hand the map a spelling it already
                        // owned.
                        if let Some(slot) = overlay.get_mut(&tombstone) {
                            if *slot {
                                *slot = false;
                                mutations.push((tombstone, page_tree::Mutation::Delete));
                            }
                        }
                    }
                    let existed = match overlay.get_mut(&key) {
                        Some(slot) => std::mem::replace(slot, true),
                        None => {
                            overlay.insert(key.clone(), true);
                            false
                        }
                    };
                    mutations.push((
                        key.clone(),
                        page_tree::Mutation::Put {
                            value: value.clone(),
                            revision,
                        },
                    ));
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
                    let existed = overlay
                        .get_mut(&key)
                        .map(|slot| std::mem::replace(slot, false))
                        .unwrap_or(false);
                    if !existed {
                        results.push(BatchResult::Delete { existed: false });
                        continue;
                    }
                    let internal = key.starts_with(INTERNAL_PREFIX);
                    mutations.push((key.clone(), page_tree::Mutation::Delete));
                    if !internal {
                        user_delta -= 1;
                        // From here on, tombstones exist — for this batch's
                        // own later puts and for every commit after it.
                        self.tombstones_possible = true;
                        let tombstone = tombstone_key(&key);
                        if let Some(slot) = overlay.get_mut(&tombstone) {
                            *slot = true;
                        } else {
                            overlay.insert(tombstone.clone(), true);
                        }
                        mutations.push((
                            tombstone,
                            page_tree::Mutation::Put {
                                value: Vec::new(),
                                revision,
                            },
                        ));
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
        profile::add(&profile::PLAN_NS, phase);
        // Historical values are staged BEFORE the batch's root is published.
        // Appending to the revision value log is the one commit step that fails
        // on resources the caller controls — a full disk most of all — and it
        // used to run after `publish`, so such a failure returned an error for a
        // batch that was already visible with no rollback; worse, the next
        // successful commit encoded the phantom root into its own WAL record,
        // letting a crash promote the unacknowledged write into permanent
        // existence. Staging first means every failure below happens while the
        // mutation is still invisible. The cost is unreachable bytes: values
        // staged here are orphaned if the batch later fails anywhere before its
        // WAL record lands, and stay as garbage until checkpoint compaction
        // reclaims them.
        let mut prepared = Vec::with_capacity(pending.len());
        if oldest_snapshot.is_some() {
            if let Err(error) = self.inject(FailurePoint::BeforeValuePrepare) {
                self.abandon_staged_changes();
                return Err(error);
            }
            for operation in pending.iter().filter(|op| is_versioned_key(&op.key)) {
                let staged = mvcc::prepare_value(
                    &mut self.mvcc_values,
                    revision,
                    (operation.op == OP_PUT).then_some(operation.value.as_slice()),
                );
                match staged {
                    Ok(value) => prepared.push((operation.key.clone(), value)),
                    Err(error) => {
                        self.abandon_staged_changes();
                        return Err(error);
                    }
                }
            }
        }
        profile::add(&profile::MVCC_NS, phase);
        // A deferred barrier only appends here; the caller flushes once it has
        // released the write lock, and must not acknowledge before it returns.
        let deferred = barrier == Barrier::Deferred && self.durability == DurabilityMode::Durable;
        let lsn = if self.write_back.is_some() {
            // WRITE-BACK: durability is the WAL record alone, and the tree is
            // not touched — the mutations land in the buffer, which every read
            // on this engine merges over the tree, and the tree absorbs the
            // buffer in one amortised pass at the flush below or at a
            // checkpoint. The WAL is written FIRST: until it succeeds nothing
            // is visible, so an append failure needs no rollback. The record
            // names WRITE_BACK_ROOT rather than the tree's stale root, so an
            // open can never adopt a tree that lacks the buffered commits and
            // instead replays the WAL from the checkpoint — the redo path that
            // has always covered pages that failed to survive.
            let phase = std::time::Instant::now();
            let committed = match barrier {
                Barrier::Immediate => self
                    .commit_batch(&pending, WRITE_BACK_ROOT, WRITE_BACK_ROOT)
                    .map(|()| None),
                Barrier::Deferred => self
                    .append_batch(&pending, WRITE_BACK_ROOT, WRITE_BACK_ROOT)
                    .map(|lsn| deferred.then_some(lsn)),
            };
            profile::add(&profile::WAL_NS, phase);
            let lsn = match committed {
                Ok(lsn) => lsn,
                Err(error) => {
                    // Nothing is visible yet, but the record may sit torn at
                    // the segment's tail while `wal_len` already points past
                    // it; a further append would land beyond the tear and be
                    // lost to recovery, so the engine stops here — the same
                    // convention as the classic path below.
                    self.abandon_staged_changes();
                    self.poisoned = true;
                    return Err(error);
                }
            };
            let phase = std::time::Instant::now();
            let buffer = self.write_back.as_mut().expect("checked above");
            for (key, mutation) in mutations {
                // Staged alongside the buffer entry so the server can replay
                // this commit onto its read handles once it is durable. The
                // value is one shared allocation between the buffer, this
                // staging, and every read handle it reaches.
                let (value, entry_revision) = match mutation {
                    page_tree::Mutation::Put { value, revision } => {
                        (Some(Arc::new(value)), revision)
                    }
                    // Every mutation of a batch commits at one LSN, which is
                    // `revision` — the same stamp its puts carry.
                    page_tree::Mutation::Delete => (None, revision),
                };
                if self.write_back_publish_enabled {
                    self.write_back_publish.push(overlay::PublishedMutation {
                        key: key.clone(),
                        value: value.clone(),
                        revision: entry_revision,
                    });
                }
                buffer.record(key, value, entry_revision);
            }
            self.user_len = self.user_len.saturating_add_signed(user_delta as isize);
            profile::add(&profile::TREE_NS, phase);
            lsn
        } else {
            let phase = std::time::Instant::now();
            let outcome = match self.tree.prepare_batch(mutations) {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.abandon_staged_changes();
                    return Err(error);
                }
            };
            profile::add(&profile::TREE_NS, phase);
            // Past this line the batch is visible, so only the WAL-stage error
            // path below may answer for it.
            self.tree.publish(outcome.root, outcome.len);
            self.user_len = self.user_len.saturating_add_signed(user_delta as isize);
            let phase = std::time::Instant::now();
            let committed = match barrier {
                Barrier::Immediate => self
                    .commit_batch(&pending, self.tree.root_id(), self.tree.len())
                    .map(|()| None),
                Barrier::Deferred => self
                    .append_batch(&pending, self.tree.root_id(), self.tree.len())
                    // In async mode the record is buffered rather than written,
                    // so there is no barrier for the caller to wait on.
                    .map(|lsn| deferred.then_some(lsn)),
            };
            profile::add(&profile::WAL_NS, phase);
            match committed {
                Ok(lsn) => lsn,
                Err(error) => {
                    // The tree is copy-on-write, so the pre-batch root is still
                    // intact and republishing it withdraws every mutation the
                    // batch made. It does not undo the WAL record if one landed
                    // — hence the poison below.
                    self.tree.publish(original_root, original_len);
                    self.user_len = original_user_len;
                    self.abandon_staged_changes();
                    self.poisoned = true;
                    return Err(error);
                }
            }
        };
        // The batch is visible — and, in durable mode, durable — so its keys
        // leave the row cache before this method returns. `&mut self` means
        // no read can interleave between the publish above and this point;
        // the change-log record's internal key was never cached, and the
        // invalidate is a cheap miss for it. Tombstones ride only
        // `mutations`, and the cache never holds them either.
        for operation in &pending {
            self.row_cache.invalidate(&operation.key);
        }
        // History maintenance runs after `commit_batch` has fsynced, so a
        // failure here must not travel to the caller as an ordinary error: the
        // write IS durable, and returning "retry" would invite a double apply.
        // Poisoning matches the WAL-stage convention, with an error that says
        // the data survived.
        match oldest_snapshot {
            Some(oldest_snapshot) => {
                if let Err(error) = self.maintain_history(previous, prepared, oldest_snapshot) {
                    self.poisoned = true;
                    eprintln!(
                        "vyrn: commit {} is durable but history maintenance failed ({error}); \
                         the engine refuses further work until it is reopened",
                        self.last_lsn
                    );
                    return Err(Error::CommittedThenPoisoned { lsn: self.last_lsn });
                }
            }
            // No snapshot was open, so this commit displaced its keys' previous
            // values without keeping any of them. Say so, or the engine goes on
            // claiming it can answer for revisions whose history it just threw
            // away — and the reads that follow come back wrong rather than
            // refused. Infallible, so it needs none of the poisoning above.
            None => self.publish_coverage(),
        }
        // The commit that crosses the buffer's threshold pays the buffer's
        // whole tree pass; that is the write-back trade, stated on the option.
        // A flush failure fails no commit: everything above is durable in the
        // WAL and visible through the buffer, which stays intact, so the flush
        // simply retries on a later commit or checkpoint.
        if self
            .write_back
            .as_ref()
            .is_some_and(overlay::Overlay::should_flush)
        {
            if let Err(error) = self.flush_write_back() {
                eprintln!(
                    "vyrn: write-back flush failed ({error}); the buffered commits are \
                     durable in the WAL and the flush will be retried"
                );
            }
        }
        // Hide results for the change records appended by with_change_log.
        results.truncate(requested);
        Ok((results, lsn))
    }

    /// Applies the whole write-back buffer to the tree in one amortised pass.
    ///
    /// Each buffered entry keeps the revision its commit stamped, so
    /// `revision()` and snapshot reads answer identically before and after the
    /// tree absorbs it. The buffer is cleared only after the tree publishes;
    /// on failure it is untouched and every read keeps merging it, so a failed
    /// flush loses nothing and can simply run again.
    fn flush_write_back(&mut self) -> Result<()> {
        let Some(buffer) = &self.write_back else {
            return Ok(());
        };
        if buffer.is_empty() {
            return Ok(());
        }
        let mutations: Vec<(Vec<u8>, page_tree::Mutation)> = buffer
            .entries
            .iter()
            .map(|(key, entry)| {
                let mutation = match entry.value.as_deref() {
                    Some(value) => page_tree::Mutation::Put {
                        value: value.clone(),
                        revision: entry.revision,
                    },
                    None => page_tree::Mutation::Delete,
                };
                (key.clone(), mutation)
            })
            .collect();
        let outcome = self.tree.prepare_batch(mutations)?;
        self.tree.publish(outcome.root, outcome.len);
        self.write_back.as_mut().expect("checked above").clear();
        // Everything buffered so far carried a revision at or below the
        // current LSN, and all of it just reached the tree, so read handles
        // serving the root published above may drop their overlay entries
        // through here.
        self.write_back_absorbed = self.last_lsn;
        Ok(())
    }

    /// Takes what the most recent write-back commit asks read handles to
    /// learn: its raw mutations, plus the absorb watermark that licenses
    /// overlay eviction. Empty (`absorbed_through: None`) when write-back is
    /// off, so callers need no mode check of their own.
    ///
    /// Must be read under the same exclusive access as the commit that staged
    /// it — the next batch clears the staging on its way in, exactly like
    /// [`Engine::last_published`].
    /// Makes every write-back commit stage its mutations for
    /// [`Engine::take_write_back_publish`].
    ///
    /// Call once after open, before serving writes, when read handles are fed
    /// from this engine — the server does. Off by default because staging
    /// clones every mutation's key, a cost an embedded engine with no read
    /// handles must not pay.
    pub fn enable_write_back_publish(&mut self) {
        self.write_back_publish_enabled = true;
    }

    pub fn take_write_back_publish(&mut self) -> overlay::WriteBackPublish {
        if self.write_back.is_none() {
            return overlay::WriteBackPublish::default();
        }
        overlay::WriteBackPublish {
            mutations: std::mem::take(&mut self.write_back_publish),
            absorbed_through: Some(self.write_back_absorbed),
        }
    }

    /// The LSN through which the tree has absorbed the write-back buffer;
    /// `None` when write-back is off. Read handles serving the engine's
    /// current root may evict overlay entries at or below it.
    pub fn write_back_absorbed_through(&self) -> Option<u64> {
        self.write_back
            .as_ref()
            .map(|_| self.write_back_absorbed)
    }

    /// Discards the change records `with_change_log` staged for a batch that
    /// failed before it became visible.
    ///
    /// The staging happens at the very start of a batch, before anything can
    /// fail. A batch that never published must not leave those records behind:
    /// they describe mutations that did not happen, and `last_published` is
    /// exactly what subscribers are told to broadcast.
    fn abandon_staged_changes(&mut self) {
        self.reset_published();
    }

    /// Empties the published-records buffer so it can only ever describe the
    /// call that is running now.
    ///
    /// `last_published` is ONE buffer on the engine, and the server reads it
    /// after every write to decide what to broadcast. Nothing used to clear it on
    /// the way IN — only `with_change_log` overwrote it, and only once a batch had
    /// got as far as producing published entries. Every path that returned before
    /// then left the previous batch's records sitting in it:
    ///
    /// - an empty batch, which returns early and never reaches `with_change_log`;
    /// - a batch rejected by key or value validation;
    /// - a `write_indexed` batch rejected for an unknown index or a unique
    ///   violation, which happens before `apply_batch` is even called.
    ///
    /// In each case the caller's next read of `last_published()` returned records
    /// belonging to a DIFFERENT batch, so subscribers were told about mutations a
    /// second time — and for the rejected batches, told them under the impression
    /// that the request they had just refused was what produced them. Clearing on
    /// entry makes the buffer's contents unambiguous: whatever is in it was put
    /// there by the call in progress, or the call published nothing.
    fn reset_published(&mut self) {
        self.last_published = Vec::new();
        // The write-back staging describes the same commit and has the same
        // hazard: left behind, a failed or empty batch would replay the
        // PREVIOUS commit's mutations onto every read handle a second time.
        self.write_back_publish = Vec::new();
    }

    /// Records a committed batch's historical versions in the MVCC state.
    ///
    /// Fallible only through the revision value log, and only ever called after
    /// the batch's WAL record is durable — see the caller for what that means
    /// for error handling.
    fn maintain_history(
        &mut self,
        previous: PreviousVersions,
        prepared: Vec<(Vec<u8>, Option<value_log::ValueRef>)>,
        oldest_snapshot: u64,
    ) -> Result<()> {
        self.inject(FailurePoint::BeforeHistoryAppend)?;
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
        Ok(())
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
        self.tree_scan_excluding_prefix(start, end, limit, Some(INTERNAL_PREFIX))
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
        // A delete of a key that is not there mutates nothing: `apply_batch` drops
        // it and reports `existed: false`. Publishing it anyway would tell every
        // subscriber a key was deleted that never existed, so presence is checked
        // here too. A later operation in the same batch may have created the key,
        // so the scan below tracks the batch's own effect rather than only disk.
        let mut live: BTreeMap<&[u8], bool> = BTreeMap::new();
        let mut entries: Vec<(&[u8], Option<&[u8]>)> = Vec::new();
        for operation in &operations {
            match operation {
                BatchOperation::Put(key, value) => {
                    if is_published_key(key) {
                        entries.push((key.as_slice(), Some(value.as_slice())));
                    }
                    live.insert(key.as_slice(), true);
                }
                BatchOperation::Delete(key) => {
                    let present = match live.get(key.as_slice()) {
                        Some(present) => *present,
                        None => self.tree_get(key)?.is_some(),
                    };
                    if present && is_published_key(key) {
                        entries.push((key.as_slice(), None));
                    }
                    live.insert(key.as_slice(), false);
                }
            }
        }
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
        // One commit past the limit, because the cursor's own commit may contribute
        // no records once its delivered mutations are filtered out. Saturating:
        // `usize::MAX` is a legitimate "give me everything" limit, and adding to
        // it panicked in debug and silently scanned nothing in release.
        let scan_limit = limit.saturating_add(1);
        for (key, value) in self.tree_scan(Some(&start), end.as_deref(), scan_limit)? {
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
        let Some(key) = self.tree_last_key_in(CHANGE_LOG_PREFIX, end.as_deref())? else {
            // An empty log is not necessarily a log that never had records: a
            // trim that consumed every retained commit leaves the prefix empty
            // AND a retention floor above `Cursor::start()`. Returning the
            // unclamped start there handed the caller a position below the
            // retained range, and `read_changes` refuses exactly that with
            // `CursorTooOld` — so "where should I resume from?" answered with a
            // cursor that the very next call rejects as too old, on a database
            // whose only fault was that its change log had been trimmed. The
            // retained floor is the honest answer: nothing before it exists to
            // deliver, and it is the oldest position a subscriber may hold.
            return self.change_log_start();
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
        match self.tree_get(CHANGE_LOG_START_KEY)? {
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
        self.tree_scan(start, end, limit)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if !self.pending_wal.is_empty() {
            self.tree.sync()?;
            self.mvcc_values.sync()?;
            self.drain_pending_wal()?;
        }
        // Also covers a durable commit whose flush was deferred to the caller,
        // so a shutdown or checkpoint never leaves an acknowledged write behind.
        self.wal.sync_through(self.wal.appended())?;
        Ok(())
    }

    /// Hands every async-buffered WAL record to the kernel and returns the
    /// LSN the caller must pass to [`Wal::sync_through`] (via
    /// [`Engine::wal`]) before acknowledging anything — the group-commit
    /// shape: drain under the engine's write lock, barrier outside it, so
    /// commits keep flowing while the flush runs. On Windows this split is
    /// what makes group commit group at all: `FlushFileBuffers` serializes
    /// against writes to the same file, so a barrier held under the same
    /// lock as the appends collapses the group to one.
    ///
    /// Durability is WAL-only, which is exactly a durable-mode commit's own
    /// barrier: pages and spilled values are written but not synced, and
    /// redo recovery reconstructs them from the log when they do not
    /// survive. [`Engine::sync`] remains the shutdown/checkpoint barrier
    /// that also syncs the tree and value files.
    pub fn drain_wal(&mut self) -> Result<u64> {
        self.ensure_healthy()?;
        self.drain_pending_wal()?;
        Ok(self.wal.appended())
    }

    fn drain_pending_wal(&mut self) -> Result<()> {
        if self.pending_wal.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending_wal);
        // Each record is appended with the LSN it was issued at. Draining
        // them all at `last_lsn` published that highest LSN to
        // `appended_lsn` on the very first append, so a concurrent
        // `sync_through` could declare every buffered record durable while
        // most of them had not even been handed to the kernel.
        let flushed = pending
            .into_iter()
            .enumerate()
            .try_for_each(|(index, (lsn, record))| {
                // Offered from the second record on only, so an injected
                // failure lands after one record has already left the
                // buffer — the shape of an ENOSPC mid-drain.
                if index > 0 {
                    self.inject(FailurePoint::BetweenBufferedAppends)?;
                }
                self.wal.append(&record, lsn)
            });
        if let Err(error) = flushed {
            // Whatever was drained is gone from the buffer and the records
            // behind it were never issued; neither can be put back. Keeping
            // quiet here would leave an engine that looks healthy while
            // acknowledged async writes silently vanish at the next
            // restart, which is the one outcome worse than refusing work.
            self.poisoned = true;
            return Err(error);
        }
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
        // The tree absorbs the write-back buffer before anything below reads
        // or copies it: the manifest this checkpoint publishes must name a
        // root that holds every commit, because segment cleanup then deletes
        // the WAL records that were those commits' only other copy.
        self.flush_write_back()?;
        self.tree.validate()?;
        // The next generation is derived from the published manifest rather than
        // read back from this counter alone. Both belt and braces, because each
        // guards a different failure:
        //
        // - Updating the counter immediately after `write_manifest` (below) is
        //   what makes a FAILED checkpoint harmless. The manifest publish is the
        //   commit point — past it, recovery will name that generation whether
        //   or not the rest of the checkpoint finished — so the counter must
        //   move at the same instant. It used to move only on the last line,
        //   so any failure in between left the engine live on files of
        //   generation G+1 while the counter still said G; the NEXT checkpoint
        //   recomputed G+1 and its pre-cleanup unlinked those very files, which
        //   on POSIX deleted the ground under the running engine (and, once the
        //   sealed segments were gone, made a crash there unrecoverable) and on
        //   Windows failed every future rename over the still-open file.
        //
        // - Deriving from the manifest on entry additionally protects against
        //   drift from any other source — an earlier crash between publishing a
        //   generation's files and writing the manifest, or a stale counter
        //   carried by an older build — by refusing to reuse a number the disk
        //   already claims. One 48-byte read per checkpoint costs nothing.
        let generation = read_manifest(&self.path)?
            .map(|state| state.generation)
            .unwrap_or(0)
            .max(self.checkpoint_generation)
            + 1;
        // Whichever generation is newest on disk is the one whose files this
        // checkpoint retires.
        let retiring = generation - 1;
        let temporary = self
            .path
            .join(format!("{}.tmp", page_file_name(generation)));
        let published = self.path.join(page_file_name(generation));
        let old = self.path.join(page_file_name(retiring));
        let temporary_values = self
            .path
            .join(format!("{}.tmp", value_file_name(generation)));
        let published_values = self.path.join(value_file_name(generation));
        let old_values = self.path.join(value_file_name(retiring));
        let temporary_revisions = self
            .path
            .join(format!("{}.tmp", revision_file_name(generation)));
        let published_revisions = self.path.join(revision_file_name(generation));
        let old_revisions = self.path.join(revision_file_name(retiring));
        let temporary_revision_values = self
            .path
            .join(format!("{}.tmp", revision_value_file_name(generation)));
        let published_revision_values = self.path.join(revision_value_file_name(generation));
        let old_revision_values = self.path.join(revision_value_file_name(retiring));
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
        // The publish above was the commit point, so the counter moves NOW —
        // before anything else can fail. Every step after this line either
        // adopts what was published (and may fail without unmaking the
        // checkpoint) or retires files this engine no longer needs (and must
        // never fail the checkpoint at all).
        self.checkpoint_generation = generation;
        self.inject(FailurePoint::AfterManifestPublish)?;
        // Adopting the published generation can fail (a bad page file, an I/O
        // error). That aborts the checkpoint safely now: the manifest already
        // names `generation` and its files are complete, the previous
        // generation's files and every sealed segment are still in place
        // because the retirement below never runs, and the engine keeps serving
        // from its current tree. The next checkpoint simply tries again.
        self.tree = PageTree::open(&published, &published_values, root, len)?;
        self.tree.validate()?;
        self.mvcc_values = value_log::ValueLog::open(&published_revision_values)?;
        self.mvcc = compacted_mvcc;
        self.inject(FailurePoint::AfterTreeAdoption)?;
        self.rotate_segment()?;
        let wal_directory = self.path.join("wal");
        // Everything past this point is janitorial: the checkpoint is committed
        // and adopted, so a failed deletion or directory sync is a warning about
        // leaked files, not a reason to report the checkpoint as failed.
        //
        // Once pages are checkpointed, an unarchived sealed segment is the only
        // copy of its LSN range anywhere, so deletion additionally waits for
        // the archiver's watermark. With no archiver configured the barrier is
        // absent and behavior is byte-identical to the pre-archiving rule.
        let archived_through = self
            .archived_through
            .as_ref()
            .map(|watermark| watermark.load(std::sync::atomic::Ordering::Acquire));
        match list_segments(&wal_directory) {
            Ok(segments) => {
                for segment in segments {
                    if segment < self.segment_id
                        && archived_through.is_none_or(|watermark| segment <= watermark)
                    {
                        retire(wal_directory.join(segment_name(segment)), "WAL segment");
                    }
                }
            }
            Err(error) => eprintln!(
                "vyrn: checkpoint could not list retired WAL segments ({error}); \
                 they will be offered again by the next checkpoint"
            ),
        }
        let _ = sync_directory(&wal_directory);
        retire(old, "page file");
        retire(old_values, "value log");
        retire(old_revisions, "revision log");
        retire(old_revision_values, "revision value log");
        let _ = sync_directory(&self.path);
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

    /// The highest LSN this engine has appended.
    ///
    /// A field read rather than [`Engine::stats`], which walks the WAL directory
    /// to count segments. A replica handshake only needs the LSN, and doing
    /// directory I/O on the connection-accept path would make the cost of
    /// accepting a replica depend on how many segments are retained.
    pub fn last_lsn(&self) -> u64 {
        self.last_lsn
    }

    /// Applies a WAL record received from a primary, preserving its LSN.
    ///
    /// Returns the LSN that must be passed to [`Wal::sync_through`] before the
    /// record may be acknowledged to the primary. **Acknowledging before that
    /// call returns would make the primary's promise to its client false**, which
    /// is the one mistake this whole feature exists to avoid.
    ///
    /// WHY THIS IS NOT `write_batch`. A normal write allocates the next local LSN;
    /// a replica must adopt the LSN the primary assigned, or the two logs diverge
    /// immediately and neither `check_contiguous` nor a later promotion can line
    /// them up. So this takes the record's own LSN and asserts continuity rather
    /// than generating one.
    ///
    /// The record must already have been checked by
    /// [`replication::verify_record`], which is what guarantees the framing, the
    /// CRC and the payload structure. This method re-reads the header fields it
    /// needs but does not re-validate them.
    pub fn apply_replicated_record(&mut self, record: &[u8]) -> Result<u64> {
        self.ensure_healthy()?;
        // A replica applies records straight to its tree; routing them through
        // a write-back buffer instead has never been exercised, and silently
        // mixing the two disciplines on one node is how drift starts. Refused
        // until replicas learn the buffer deliberately.
        if self.write_back.is_some() {
            return Err(Error::InvalidReplicatedRecord {
                reason: "write-back buffering is not supported on a replica".into(),
            });
        }

        let lsn = read_u64(record, 5);
        let operation_count = read_u32(record, 13) as usize;
        let payload_len = read_u32(record, 17) as usize;

        // Continuity is enforced here as well as in the caller: this is the last
        // point before bytes reach the log, and a gap would produce a WAL whose
        // own recovery rejects it (replay checks that a segment's first record
        // matches its header, and that segments are contiguous).
        let expected = self.last_lsn.saturating_add(1);
        if lsn != expected {
            return Err(Error::InvalidReplicatedRecord {
                reason: format!(
                    "record LSN {lsn} does not follow this replica's last LSN {}; \
                     expected {expected}",
                    self.last_lsn
                ),
            });
        }

        let payload = &record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + payload_len];
        let operations = decode_operations(payload, operation_count);

        // Rotate on the same size trigger a primary uses, so a replica's segment
        // boundaries track its own configuration rather than the primary's. The
        // records themselves are identical either way; only the file they land in
        // differs, and recovery does not care which segment a record is in as
        // long as the headers stay contiguous.
        let current_len = self.wal_len;
        if current_len > SEGMENT_HEADER_LEN as u64
            && current_len + record.len() as u64 > self.segment_size
        {
            self.rotate_segment()?;
        }

        // The record is written verbatim — NOT re-encoded from the decoded
        // operations. Re-encoding would produce equivalent bytes today and would
        // silently stop doing so the moment the encoder changed, leaving the two
        // logs byte-different for the same LSN. Shipping and storing the identical
        // bytes is what makes a replica's WAL interchangeable with its primary's.
        self.wal_len += record.len() as u64;
        self.wal.append(record, lsn)?;

        /* Applied with EXACTLY the redo path's rules, including the tombstone
         * bookkeeping — see the long comment above the redo loop in
         * `rebuild_tree`. Tombstones are what carry a deleted key's revision, and
         * they cannot be derived later: a max-size key's tombstone would exceed
         * MAX_KEY_SIZE and fail validation. Getting this subtly wrong would give
         * the replica a tree that answers `revision()` differently from its
         * primary for every deleted key, which is precisely the kind of drift
         * that stays invisible until a promotion.
         *
         * `prepare_*` then `publish` rather than a single mutate call: the tree is
         * copy-on-write, so a mutation produces a new root that must be published
         * to become visible.
         */
        for (op, key, value) in operations {
            // A replica serves reads while it applies, so every applied key
            // leaves the row cache — the same rule `write_batch` follows at
            // the same point: after the mutation is visible, under the same
            // exclusive access that keeps reads from interleaving.
            self.row_cache.invalidate(&key);
            if op == OP_PUT {
                let value = value.unwrap_or_default();
                let (root, len) = self.tree.prepare_put(&key, &value, lsn)?;
                self.tree.publish(root, len);
                // A put clears any tombstone an earlier delete left, so the key's
                // revision comes from the live entry again.
                if !key.starts_with(INTERNAL_PREFIX) {
                    if let Some((root, len)) = self.tree.prepare_delete(&tombstone_key(&key))? {
                        self.tree.publish(root, len);
                    }
                }
            } else if op == OP_DELETE {
                if let Some((root, len)) = self.tree.prepare_delete(&key)? {
                    self.tree.publish(root, len);
                    // A delete of an existing user key records its revision on a
                    // tombstone at the deleting record's LSN.
                    if !key.starts_with(INTERNAL_PREFIX) {
                        self.tombstones_possible = true;
                        let (root, len) = self.tree.prepare_put(&tombstone_key(&key), &[], lsn)?;
                        self.tree.publish(root, len);
                    }
                }
            } else {
                return Err(Error::InvalidReplicatedRecord {
                    reason: format!("unknown operation code {op}"),
                });
            }
        }

        self.last_lsn = lsn;
        // Excludes internal keys and tombstones, matching what a primary reports.
        self.user_len = self.tree.count_excluding_prefix(INTERNAL_PREFIX)?;
        Ok(lsn)
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
        // Offered BEFORE the local append, and to both durability modes.
        //
        // Before, because the two are independent: the replica's copy and the
        // primary's copy each become durable on their own storage, and whichever
        // finishes second is the one the acknowledgement waits for. Offering
        // first lets the network round trip overlap the local `fdatasync`
        // instead of starting after it.
        //
        // Both modes, because a replica must receive every record the primary
        // logged regardless of when the primary chooses to flush. Async
        // durability is a statement about the primary's own barrier, not about
        // what it replicates.
        //
        // Borrowed rather than moved, so the async branch below can still take
        // ownership of `record` without a clone.
        if let Some(sink) = &self.record_sink {
            sink.record(lsn, &record);
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
            self.pending_wal.push((lsn, record));
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
        let file = create_segment(&wal_directory, next, self.last_lsn + 1)?;
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
        // Flushes the outgoing segment before adopting the new one, so a durable
        // record never sits behind an unflushed one in an earlier segment. The
        // new segment's records start directly after its header.
        match self.wal.rotate(file, SEGMENT_HEADER_LEN as u64) {
            Ok(()) => {
                // The new segment starts at its header, so the tracked length
                // restarts too.
                self.wal_len = SEGMENT_HEADER_LEN as u64;
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
        // Shutdown is the last chance to flush buffered async records, and a
        // failure here used to vanish without a trace: those writes were
        // acknowledged in memory, so discarding them quietly turns "async" into
        // "lost". No caller remains to receive an error, so the failure is
        // announced loudly — plain stderr until tracing lands — and recorded in
        // the engine state for anything still holding a handle.
        //
        // This path is not covered by an automated test: failing the flush
        // requires a fault between the last `sync` and the drop, which only a
        // manual run can arrange (inject a WAL failure into `sync`, drop the
        // engine without retrying, watch for the warning).
        if !self.poisoned {
            if let Err(error) = self.sync() {
                self.poisoned = true;
                eprintln!(
                    "vyrn: shutdown flush failed ({error}); async commits since the \
                     last successful flush were discarded"
                );
            }
        }
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
    write_segment_header(&mut file, segment_id, first_lsn)?;
    sync_directory(directory)?;
    Ok(file)
}

/// Replaces an empty segment's header without ever unlinking the segment.
///
/// The replacement is built under a temporary name and renamed into place. It
/// used to be `remove_file` then `create_segment`: a kill between the two left
/// a permanent hole in the segment sequence, which `list_segments` rejects on
/// every future open — a database bricked by its own repair. A rename is atomic,
/// so after a crash at any point the directory holds either the old header (and
/// the next open retries the repair) or the new one. A temporary left behind by
/// an interrupted attempt is truncated and reused rather than an obstacle.
fn republish_segment_header(directory: &Path, segment_id: u64, first_lsn: u64) -> Result<File> {
    let target = directory.join(segment_name(segment_id));
    let temporary = directory.join(format!("{}.tmp", segment_name(segment_id)));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&temporary)?;
    write_segment_header(&mut file, segment_id, first_lsn)?;
    drop(file);
    fs::rename(&temporary, &target)?;
    sync_directory(directory)?;
    Ok(OpenOptions::new().read(true).write(true).open(target)?)
}

fn write_segment_header(file: &mut File, segment_id: u64, first_lsn: u64) -> Result<()> {
    let mut header = [0; SEGMENT_HEADER_LEN];
    header[0..4].copy_from_slice(SEGMENT_MAGIC);
    header[4] = VERSION;
    write_u64(&mut header, 8, segment_id);
    write_u64(&mut header, 16, first_lsn);
    let header_checksum = checksum(&header[0..24]);
    write_u32(&mut header, 24, header_checksum);
    file.write_all(&header)?;
    file.sync_all()?;
    Ok(())
}

/// Deletes a file a finished checkpoint has retired, treating failure as a
/// warning rather than an error.
///
/// Everything past the manifest publish is janitorial: the checkpoint is
/// committed and adopted, so a deletion that fails — an antivirus handle on
/// Windows, a read handle still open — must not fail it. Failing here used to
/// strand the engine between generations; warning instead leaks at worst a file
/// that the next checkpoint will offer again. A missing file is not a warning:
/// retiring a generation that never existed is the common case on a database
/// that has checkpointed once.
fn retire(path: PathBuf, description: &str) {
    if let Err(error) = fs::remove_file(&path) {
        if path.exists() {
            eprintln!(
                "vyrn: checkpoint could not delete retired {description} {}: {error}",
                path.display()
            );
        }
    }
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
    // published. If even that is unreachable the page file lost pre-checkpoint
    // data that no amount of redo can reconstruct: the old fallback rebuilt
    // from an empty tree while still filtering `lsn > checkpoint_lsn`, which
    // silently discarded everything written before the checkpoint and
    // returned Ok. Fail loudly instead.
    let mut tree = match PageTree::open(page_path, value_path, base.root, base.len)
        .and_then(|tree| tree.validate().map(|()| tree))
    {
        Ok(tree) => tree,
        Err(_) => {
            return Err(Error::CorruptManifest(
                "checkpoint root is unreachable; the page file lost pre-checkpoint data — restore from a backup".into(),
            ))
        }
    };

    // Tombstones ride only the page-level mutation list, never the WAL payload
    // (a max-size key's tombstone would exceed MAX_KEY_SIZE and fail
    // validate_payload — see MAX_STORED_KEY_SIZE), so redo must re-derive them
    // with exactly apply_batch's rules or every redone database loses its
    // delete revisions — and point-in-time restore makes redo the normal path,
    // not the disaster path.
    for record in redo.iter().filter(|record| record.lsn > checkpoint_lsn) {
        for (op, key, value) in &record.operations {
            if *op == OP_PUT {
                let value = value.as_deref().unwrap_or_default();
                let (root, len) = tree.prepare_put(key, value, record.lsn)?;
                tree.publish(root, len);
                // A put clears any tombstone left by an earlier delete, so the
                // key's revision comes from the live entry again.
                if !key.starts_with(INTERNAL_PREFIX) {
                    if let Some((root, len)) = tree.prepare_delete(&tombstone_key(key))? {
                        tree.publish(root, len);
                    }
                }
            } else if let Some((root, len)) = tree.prepare_delete(key)? {
                tree.publish(root, len);
                // A delete of an existing user key records its revision on a
                // tombstone at the deleting record's LSN.
                if !key.starts_with(INTERNAL_PREFIX) {
                    let (root, len) = tree.prepare_put(&tombstone_key(key), &[], record.lsn)?;
                    tree.publish(root, len);
                }
            }
        }
    }
    tree.sync()?;
    state.root = tree.root_id();
    state.len = tree.len();
    Ok(tree)
}

/// Replays one segment's committed records into `state`, returning the offset at
/// which its records end.
///
/// That offset is where the next record belongs, which is not the end of the
/// file: the writer keeps a zero-filled runway ahead of the records so its
/// barrier never has to journal an extent update.
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
) -> Result<u64> {
    let is_last = next_first_lsn.is_none();
    let mut file = OpenOptions::new().read(true).write(is_last).open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SEGMENT_HEADER_LEN as u64 {
        return Err(corrupt(segment_id, 0, "incomplete segment header"));
    }
    let mut header = [0; SEGMENT_HEADER_LEN];
    file.read_exact(&mut header)?;
    // Checked before the rest of the header: a segment written by another build
    // is intact data this build cannot read, which is a different situation from
    // damage and must not be reported as corruption.
    if &header[0..4] == SEGMENT_MAGIC && header[4] != VERSION {
        return Err(Error::FormatVersion {
            structure: "WAL segment",
            found: header[4],
            expected: VERSION,
        });
    }
    if &header[0..4] != SEGMENT_MAGIC
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
            return Ok(file_len);
        }
    }

    // The last byte a writer actually touched. Everything past it is untouched
    // runway, which is what separates a record torn by a crash from one that was
    // written whole and has since rotted: a torn record's declared body runs
    // past this point, a rotten one does not.
    let written_through = last_written_byte(&mut file, file_len)?;
    let header_first_lsn = read_u64(&header, 16);
    let mut saw_record = false;
    let mut offset = SEGMENT_HEADER_LEN as u64;
    while offset < file_len {
        // Nothing from here on was ever written, so the records end here and the
        // rest is untouched runway. A sealed segment reaches this on its unused
        // tail, the active one on every open. Records are not lost silently: a
        // segment whose tail was zeroed by damage rather than never written
        // leaves the next segment's first LSN discontinuous, which is rejected
        // below.
        if offset >= written_through {
            break;
        }
        // Part of this frame was written and part was not, so the crash landed
        // inside it. This is exact rather than heuristic: every record ends with
        // the four non-zero bytes of `RECORD_END`, so a complete record can
        // never reach past the last byte a writer touched, and a frame that does
        // is necessarily torn. A record that is wholly present falls through to
        // full validation, so damage to one is still reported as corruption.
        if file_len - offset < RECORD_HEADER_LEN as u64
            || offset + RECORD_HEADER_LEN as u64 > written_through
        {
            return truncate_or_corrupt(&mut file, is_last, segment_id, offset).map(|()| offset);
        }
        let mut record_header = [0; RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)?;
        if &record_header[0..4] != RECORD_MAGIC || record_header[4] != VERSION {
            // An all-zero header is the signature of a head page that never
            // reached the disk, not of damage. The runway ahead of the records
            // is zero-filled, and a write-back cache can persist a multi-page
            // record's tail while losing its head; the frame then lies wholly
            // inside `written_through` — so the overrun rule below never sees
            // it — with its header still holding the runway's zeros. No bit
            // flip or rot produces forty-five zero bytes, so accepting exactly
            // that signature as a torn tail survives an ordinary crash without
            // turning damage into silence. A tear that spares the header (an
            // intact first page, lost middle pages) still fails its checksum and
            // stays fatal: it is indistinguishable from rot, and rotting bytes
            // must not buy a truncated log.
            return stop_at_torn_record(
                &mut file,
                is_last,
                segment_id,
                offset,
                &record_header,
                "invalid transaction header",
            )
            .map(|()| offset);
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
        // Torn rather than rotten, by the same rule as the header above, and
        // checked before the payload is validated: a half-written record's tail
        // reads as zeros and would otherwise fail its checksum and be reported
        // as corruption, which would make an ordinary crash unrecoverable.
        if total_len as u64 > file_len - offset
            || offset.saturating_add(total_len as u64) > written_through
        {
            return truncate_or_corrupt(&mut file, is_last, segment_id, offset).map(|()| offset);
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
    Ok(offset)
}

/// One past the last non-zero byte in `file`, or the header length when the
/// segment holds no records at all.
///
/// Scans backwards from the end, so it reads only the unused runway rather than
/// the whole segment. The result bounds where a writer can have reached: a
/// record whose body extends past it cannot have been written in full.
///
/// Leaves the read cursor at the first record, where the caller resumes.
fn last_written_byte(file: &mut File, file_len: u64) -> Result<u64> {
    const CHUNK: usize = 64 * 1024;
    let floor = SEGMENT_HEADER_LEN as u64;
    let mut end = file_len;
    let mut buffer = vec![0; CHUNK];
    let mut written = floor;
    while end > floor {
        let start = end.saturating_sub(CHUNK as u64).max(floor);
        let span = (end - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer[..span])?;
        if let Some(index) = buffer[..span].iter().rposition(|byte| *byte != 0) {
            written = start + index as u64 + 1;
            break;
        }
        end = start;
    }
    file.seek(SeekFrom::Start(floor))?;
    Ok(written)
}

/// Byte offset of the first record in a segment whose LSN exceeds `bound`, or
/// `None` when every record is at or below it.
///
/// Point-in-time restore truncates a copied segment at this offset so replay
/// stops exactly at the requested LSN; record bodies are left unverified here
/// because replay re-validates every byte it applies.
///
/// A frame that cannot be complete — a partial header, damaged header magic,
/// or a declared length past end of file — is returned as the truncation
/// point rather than an error. The trimmed segment is (or becomes) the last
/// segment of the log, the only one allowed a torn tail, and replay would
/// truncate exactly the same bytes; a base backup of a database that crashed
/// mid-append carries such a tail verbatim, so failing on it would make
/// recovery from that backup deterministically impossible while a plain open
/// of the same tree succeeds. Truncating a genuinely rotten mid-segment frame
/// is caught instead by `recover_to`'s replay-reached-the-bound check.
pub(crate) fn scan_to_lsn(path: &Path, segment_id: u64, bound: u64) -> Result<Option<u64>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SEGMENT_HEADER_LEN as u64 {
        return Err(corrupt(segment_id, 0, "incomplete segment header"));
    }
    let mut header = [0; SEGMENT_HEADER_LEN];
    file.read_exact(&mut header)?;
    // Checked before the rest of the header: a segment written by another build
    // is intact data this build cannot read, which is a different situation from
    // damage and must not be reported as corruption.
    if &header[0..4] == SEGMENT_MAGIC && header[4] != VERSION {
        return Err(Error::FormatVersion {
            structure: "WAL segment",
            found: header[4],
            expected: VERSION,
        });
    }
    if &header[0..4] != SEGMENT_MAGIC
        || read_u64(&header, 8) != segment_id
        || checksum(&header[0..24]) != read_u32(&header, 24)
    {
        return Err(corrupt(segment_id, 0, "invalid segment header"));
    }
    let mut offset = SEGMENT_HEADER_LEN as u64;
    while offset < file_len {
        if file_len - offset < RECORD_HEADER_LEN as u64 {
            return Ok(Some(offset));
        }
        let mut record_header = [0; RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)?;
        if &record_header[0..4] != RECORD_MAGIC || record_header[4] != VERSION {
            return Ok(Some(offset));
        }
        if read_u64(&record_header, 5) > bound {
            return Ok(Some(offset));
        }
        let payload_len = read_u32(&record_header, 17) as usize;
        let Some(total_len) = RECORD_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|size| size.checked_add(RECORD_FOOTER_LEN))
        else {
            return Ok(Some(offset));
        };
        if total_len as u64 > file_len - offset {
            return Ok(Some(offset));
        }
        file.seek(SeekFrom::Current((payload_len + RECORD_FOOTER_LEN) as i64))?;
        offset += total_len as u64;
    }
    Ok(None)
}

/// Reads and validates a segment's 32-byte header, returning its first LSN.
///
/// Recovery consults a successor's header to decide whether the segment before
/// it is semantically dead without paying to scan the dead segment's body.
fn read_segment_first_lsn(path: &Path) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut header = [0; SEGMENT_HEADER_LEN];
    file.read_exact(&mut header)?;
    if &header[0..4] != SEGMENT_MAGIC
        || header[4] != VERSION
        || checksum(&header[0..24]) != read_u32(&header, 24)
    {
        return Err(corrupt(read_u64(&header, 8), 0, "invalid segment header"));
    }
    Ok(read_u64(&header, 16))
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

/// Ends replay at `offset`, where the frame that begins there failed to parse.
///
/// The tail is truncated only when the segment is the active one AND the frame
/// carries the zero-header tear signature — a record whose head page never
/// persisted, which is an ordinary crash rather than damage. Everything else is
/// reported as corruption: sealed segments were truncated at the open that
/// sealed them, so a frame that cannot parse in one is historical rot, and rot
/// must stay loud. See the call site for why nothing narrower qualifies.
fn stop_at_torn_record(
    file: &mut File,
    is_last: bool,
    segment: u64,
    offset: u64,
    record_header: &[u8; RECORD_HEADER_LEN],
    reason: &'static str,
) -> Result<()> {
    if is_last && record_header.iter().all(|byte| *byte == 0) {
        return truncate_or_corrupt(file, true, segment, offset);
    }
    Err(corrupt(segment, offset, reason))
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

/// Records a replayed record's mutations as historical versions.
///
/// Filtered by [`is_versioned_key`], which is the SAME filter the live commit
/// path applies when it stages historical values (see the `prepared` loop in
/// `apply_batch`). Replay used to record every key in the record, change-log
/// entries included, so the two paths disagreed about which keys have a history
/// at all — and a filter that exists in one direction only is a filter that will
/// eventually be wrong in the other. The concrete cost today is measurable rather
/// than visible: every replayed change-log value is copied into the revision
/// value log, where nothing will ever read it, so a database's revision value log
/// grew by the whole replayed change stream on every recovery and only a
/// checkpoint compaction took it back. Point-in-time restore replays by design,
/// which makes that the normal path rather than the disaster path.
fn record_versions(
    payload: &[u8],
    operation_count: usize,
    revision: u64,
    state: &mut mvcc::State,
    values: &mut value_log::ValueLog,
) -> Result<()> {
    for (_, key, value) in decode_operations(payload, operation_count)
        .into_iter()
        .filter(|(_, key, _)| is_versioned_key(key))
    {
        mvcc::append(state, values, key, revision, value)?;
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
    if bytes.len() == MANIFEST_LEN && &bytes[0..4] == MANIFEST_MAGIC && bytes[4] != VERSION {
        return Err(Error::FormatVersion {
            structure: "checkpoint manifest",
            found: bytes[4],
            expected: VERSION,
        });
    }
    if bytes.len() != MANIFEST_LEN
        || &bytes[0..4] != MANIFEST_MAGIC
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

/// The LSN recorded in a database's published checkpoint manifest.
///
/// Point-in-time tooling needs the replay floor of a data directory it does
/// not own, so this reads CURRENT directly instead of opening an engine and
/// taking the process lock.
pub fn manifest_lsn(path: impl AsRef<Path>) -> Result<u64> {
    match read_manifest(path.as_ref())? {
        Some(state) => Ok(state.lsn),
        None => Err(Error::CorruptManifest(
            "database has no CURRENT manifest".into(),
        )),
    }
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

/// The one region of the reserved keyspace an index name may occupy.
///
/// Document collections name their indexes `\0vyrn:doc-index:<collection><field>`,
/// so the internal prefix cannot simply be refused outright — the document layer
/// routes its own index names through the same `create_index` entry point a user
/// calls. Taken from `document` rather than restated here: a second copy of a
/// prefix is a divergence waiting for someone to change one of them.
use document::INDEX_PREFIX as DOCUMENT_INDEX_PREFIX;

/// Checks that an index name is usable and stays inside the keyspace it is
/// allowed to address.
///
/// An index name is not just a label: it is spliced into the internal keys that
/// address the index's definition and entries (see [`index_definition_key`] and
/// [`index_entry_prefix`]), and it is the only caller-supplied part of them. It
/// cannot escape those keys — the name is appended after its own length prefix,
/// so no spelling of it reaches a neighbouring key — but it CAN collide inside
/// them, and one collision is reachable from the public API.
///
/// `document::stored_indexes` decides which fields a collection has by scanning
/// the index map for names under `\0vyrn:doc-index:<collection>`. An index created
/// through plain [`Engine::create_index`] with a name in that space is
/// indistinguishable from one the document layer created, so it becomes a phantom
/// field of a collection nobody indexed: opening the collection either fails with
/// a corruption-shaped `InvalidDocument` (the trailing bytes are parsed as a
/// length-prefixed field name) or succeeds and reports a field no document has
/// ever written. Refusing the whole reserved prefix except the document layer's
/// own space closes that, and needs no argument about which particular spellings
/// collide under today's encoding.
fn validate_index_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        Err(Error::EmptyKey)
    } else if name.len() > u16::MAX as usize {
        Err(Error::KeyTooLarge)
    } else if name.starts_with(INTERNAL_PREFIX) && !name.starts_with(DOCUMENT_INDEX_PREFIX) {
        Err(Error::ReservedKey)
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

    /// A rotation that fails between creating the successor's header and
    /// switching the writer leaves an empty segment whose header claims a
    /// first LSN below records that stayed in its predecessor. An empty
    /// segment has no record to contradict its header, so an open that adopts
    /// it as-is places the next commit under the lie — and the open after
    /// that rejects the segment, leaving a database that never opens again
    /// with every acknowledged record intact on disk.
    #[test]
    fn open_repairs_an_empty_active_segment_with_a_stale_header() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
            engine.put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
        }
        // The orphan successor of a failed rotation: created as though the
        // switch happened after LSN 1, while records 2 and 3 actually stayed
        // in segment 1.
        drop(create_segment(&directory.path().join("wal"), 2, 2).unwrap());
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            assert_eq!(engine.sequence(), 3);
            engine.put(b"k4".to_vec(), b"v4".to_vec()).unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        for (key, value) in [
            (b"k1", b"v1"),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
            (b"k4", b"v4"),
        ] {
            assert_eq!(engine.get(key).unwrap(), Some(value.to_vec()));
        }
        assert_eq!(engine.sequence(), 4);
    }

    /// The same repair must never unlink the segment it is replacing. Removing
    /// the segment and creating its replacement as two steps meant a kill
    /// between them left a permanent hole in the segment sequence — which
    /// `list_segments` rejects on every future open, so the database could never
    /// open again. The replacement is now built under a temporary name and
    /// renamed into place; a temporary left behind by an interrupted attempt is
    /// truncated and reused rather than an obstacle. (The crash window itself is
    /// not injectable; what is testable is that a retry after an interrupted
    /// attempt succeeds and leaves nothing temporary behind.)
    #[test]
    fn open_repairs_an_empty_active_segment_without_unlinking_it() {
        let directory = tempdir().unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            engine.put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
            engine.put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
            engine.put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
        }
        let wal_directory = directory.path().join("wal");
        // The orphan successor of a failed rotation: empty, with a header
        // claiming a first LSN the log does not support.
        drop(create_segment(&wal_directory, 2, 2).unwrap());
        // What a repair killed before its rename leaves behind.
        fs::write(
            wal_directory.join(format!("{}.tmp", segment_name(2))),
            b"half-written",
        )
        .unwrap();
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            assert_eq!(engine.sequence(), 3);
            engine.put(b"k4".to_vec(), b"v4".to_vec()).unwrap();
        }
        let engine = Engine::open(directory.path()).unwrap();
        for (key, value) in [
            (b"k1", b"v1"),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
            (b"k4", b"v4"),
        ] {
            assert_eq!(engine.get(key).unwrap(), Some(value.to_vec()));
        }
        assert_eq!(engine.sequence(), 4);
        // The repair renamed its replacement into place; nothing temporary
        // remains to confuse the next open.
        assert!(!wal_directory
            .join(format!("{}.tmp", segment_name(2)))
            .exists());
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
        assert_eq!(engine.collect_versions().unwrap(), 0);
        assert_eq!(
            engine.get_at(b"key", snapshot).unwrap(),
            Some(b"one".to_vec())
        );
        engine.release_snapshot(snapshot);
        assert_eq!(engine.collect_versions().unwrap(), 3);
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

    /// Moving a unique-index value between keys, and swapping two keys' values,
    /// must both be legal in one batch — while a genuine duplicate stays refused.
    ///
    /// The uniqueness check asks the LIVE tree who holds the value, and the live
    /// tree does not know what the batch is about to delete. So a move was
    /// rejected as a duplicate of the very entry the same batch removes: the
    /// batch conflicted with itself, and neither operation could be expressed
    /// atomically at all. A swap is the same fault twice, and worse for the old
    /// bounded `lookup_index(.., 2)` — the two entries it returned were exactly
    /// the two being deleted, so no limit could have told it otherwise.
    #[test]
    fn a_unique_index_value_can_move_or_swap_within_one_batch() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.create_index(b"email".to_vec(), true).unwrap();
        let claim = |primary: &[u8], old: Option<&[u8]>, new: Option<&[u8]>| IndexUpdate {
            index: b"email".to_vec(),
            primary_key: primary.to_vec(),
            old_value: old.map(<[u8]>::to_vec),
            new_value: new.map(<[u8]>::to_vec),
        };
        engine
            .write_indexed(
                vec![
                    BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec()),
                    BatchOperation::Put(b"user/2".to_vec(), b"two".to_vec()),
                ],
                vec![
                    claim(b"user/1", None, Some(b"a@example.com")),
                    claim(b"user/2", None, Some(b"b@example.com")),
                ],
            )
            .unwrap();

        // A move: user/1 releases the value in the same batch user/3 claims it.
        engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/3".to_vec(), b"three".to_vec())],
                vec![
                    claim(b"user/1", Some(b"a@example.com"), None),
                    claim(b"user/3", None, Some(b"a@example.com")),
                ],
            )
            .unwrap();
        assert_eq!(
            engine.lookup_index(b"email", b"a@example.com", 10).unwrap(),
            vec![b"user/3".to_vec()]
        );

        // A swap: each key claims the value the other releases, so both claims
        // collide with an entry the batch itself deletes.
        engine
            .write_indexed(
                Vec::new(),
                vec![
                    claim(b"user/2", Some(b"b@example.com"), Some(b"a@example.com")),
                    claim(b"user/3", Some(b"a@example.com"), Some(b"b@example.com")),
                ],
            )
            .unwrap();
        assert_eq!(
            engine.lookup_index(b"email", b"a@example.com", 10).unwrap(),
            vec![b"user/2".to_vec()]
        );
        assert_eq!(
            engine.lookup_index(b"email", b"b@example.com", 10).unwrap(),
            vec![b"user/3".to_vec()]
        );

        // A third key claiming a value that nothing releases is still a genuine
        // duplicate. Discounting releases must not become discounting holders.
        let error = engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/4".to_vec(), b"four".to_vec())],
                vec![claim(b"user/4", None, Some(b"a@example.com"))],
            )
            .unwrap_err();
        assert!(matches!(error, Error::UniqueViolation { .. }));
        assert_eq!(engine.get(b"user/4").unwrap(), None);

        // And a release by ONE key does not excuse a duplicate between two
        // others: user/2 stepping aside leaves the value free for exactly one
        // claimant, not both.
        let error = engine
            .write_indexed(
                Vec::new(),
                vec![
                    claim(b"user/2", Some(b"a@example.com"), None),
                    claim(b"user/5", None, Some(b"a@example.com")),
                    claim(b"user/6", None, Some(b"a@example.com")),
                ],
            )
            .unwrap_err();
        assert!(matches!(error, Error::UniqueViolation { .. }));
    }

    /// `last_published` is one buffer on the engine, read by the server after
    /// every write. A batch that fails before publishing anything must not leave
    /// the PREVIOUS batch's records in it.
    ///
    /// Nothing used to clear the buffer on the way in — only `with_change_log`
    /// overwrote it, and only once a batch got as far as producing entries. Every
    /// earlier return therefore left the last batch's records readable, so the
    /// server broadcast them a second time, under a request it had just rejected.
    #[test]
    fn last_published_never_leaks_one_batch_into_another() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.create_index(b"email".to_vec(), true).unwrap();
        engine
            .put(b"published".to_vec(), b"value".to_vec())
            .unwrap();
        assert_eq!(engine.last_published().len(), 1);

        // An empty batch returns before `with_change_log` runs.
        engine.write_batch(Vec::new()).unwrap();
        assert!(
            engine.last_published().is_empty(),
            "an empty batch published nothing, so the buffer must say so"
        );

        // A batch rejected for a reserved key never reaches `apply_batch`.
        engine
            .put(b"published".to_vec(), b"again".to_vec())
            .unwrap();
        assert_eq!(engine.last_published().len(), 1);
        let error = engine
            .write_batch(vec![BatchOperation::Put(
                b"\0vyrn:forbidden".to_vec(),
                b"x".to_vec(),
            )])
            .unwrap_err();
        assert!(matches!(error, Error::ReservedKey));
        assert!(
            engine.last_published().is_empty(),
            "a rejected batch must not answer with the previous batch's records"
        );

        // A unique violation is rejected inside `write_indexed_batch`, before
        // `apply_batch` — the most common way a real client trips this.
        engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/1".to_vec(), b"one".to_vec())],
                vec![IndexUpdate {
                    index: b"email".to_vec(),
                    primary_key: b"user/1".to_vec(),
                    old_value: None,
                    new_value: Some(b"a@example.com".to_vec()),
                }],
            )
            .unwrap();
        assert_eq!(engine.last_published().len(), 1);
        let error = engine
            .write_indexed(
                vec![BatchOperation::Put(b"user/2".to_vec(), b"two".to_vec())],
                vec![IndexUpdate {
                    index: b"email".to_vec(),
                    primary_key: b"user/2".to_vec(),
                    old_value: None,
                    new_value: Some(b"a@example.com".to_vec()),
                }],
            )
            .unwrap_err();
        assert!(matches!(error, Error::UniqueViolation { .. }));
        assert!(
            engine.last_published().is_empty(),
            "a batch refused for a unique violation published nothing"
        );

        // A batch whose only operation is a no-op delete publishes nothing
        // either, and that too must clear what came before.
        engine
            .put(b"published".to_vec(), b"third".to_vec())
            .unwrap();
        assert_eq!(engine.last_published().len(), 1);
        engine.delete(b"never-existed").unwrap();
        assert!(engine.last_published().is_empty());
    }

    /// A zero limit means "no rows", on every scan entry point.
    ///
    /// The snapshot scans stop only on `rows.len() == limit`, which a length that
    /// starts at zero has already passed — so a zero limit read every candidate
    /// key in range at `revision` and returned all of them, which is the opposite
    /// of what was asked for and unbounded work besides.
    #[test]
    fn a_zero_limit_scan_returns_nothing() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.create_index(b"tag".to_vec(), false).unwrap();
        for key in [b"a", b"b", b"c"] {
            engine.put(key.to_vec(), b"value".to_vec()).unwrap();
        }
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
        // A write under the pin, so history exists for the scans to overlay.
        engine.put(b"b".to_vec(), b"second".to_vec()).unwrap();

        assert!(engine.scan(None, None, 0).unwrap().is_empty());
        assert!(engine.scan_at(None, None, 0, snapshot).unwrap().is_empty());
        assert!(engine.lookup_index(b"tag", b"admin", 0).unwrap().is_empty());
        assert!(engine
            .lookup_index_at(b"tag", b"admin", 0, snapshot)
            .unwrap()
            .is_empty());
        assert!(engine
            .read_changes(change_log::Cursor::start(), 0)
            .unwrap()
            .is_empty());
        // A non-zero limit still works, so the guard is a floor and not a wall.
        assert_eq!(engine.scan_at(None, None, 2, snapshot).unwrap().len(), 2);
        engine.release_snapshot(snapshot);
    }

    /// The cursor a caller is told to resume from must never sit below the
    /// retained range.
    ///
    /// A trim that consumes every retained commit leaves the change-log prefix
    /// empty AND a retention floor above `Cursor::start()`. Answering the empty
    /// case with the unclamped start handed back a position `read_changes`
    /// immediately refuses as `CursorTooOld` — so "where do I resume?" was
    /// answered with a cursor that the next call rejects, on a database whose only
    /// fault was a trimmed log.
    #[test]
    fn the_published_cursor_never_falls_below_the_retained_range() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"a".to_vec(), b"one".to_vec()).unwrap();
        engine.put(b"b".to_vec(), b"two".to_vec()).unwrap();

        // Trim past everything the log holds, leaving the prefix empty and the
        // retention floor well above the start.
        let latest = engine.latest_published_cursor().unwrap();
        assert!(engine.trim_changes(latest).unwrap() > 0);
        assert_eq!(engine.change_log_len().unwrap(), 0);
        let retained = engine.change_log_start().unwrap();
        assert_ne!(retained, change_log::Cursor::start());

        let resume = engine.latest_published_cursor().unwrap();
        assert!(
            resume >= retained,
            "the resume cursor {resume:?} is below the retained floor {retained:?}"
        );
        // The point of the clamp: the cursor it returns is actually usable.
        engine.read_changes(resume, 10).unwrap();
    }

    /// An index name must not reach into Vyrn's internal keyspace.
    ///
    /// The name is the only caller-supplied part of an index's definition and
    /// entry keys. It cannot escape them, but it CAN collide inside them: a name
    /// under `\0vyrn:doc-index:<collection>` is indistinguishable from one the
    /// document layer created, so it becomes a phantom field of a collection
    /// nobody indexed.
    #[test]
    fn an_index_name_cannot_reach_into_the_internal_keyspace() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        for name in [
            INTERNAL_PREFIX.to_vec(),
            b"\0vyrn:index:def:".to_vec(),
            b"\0vyrn:tombstone:x".to_vec(),
            b"\0vyrn:changelog:x".to_vec(),
        ] {
            assert!(
                matches!(
                    engine.create_index(name.clone(), false),
                    Err(Error::ReservedKey)
                ),
                "index name {name:?} reached the reserved keyspace"
            );
            assert!(matches!(
                engine.lookup_index_at(&name, b"v", 10, engine.sequence()),
                Err(Error::ReservedKey)
            ));
        }
        // An ordinary name is unaffected.
        engine.create_index(b"email".to_vec(), false).unwrap();
    }

    /// The document layer's own index names must keep working.
    ///
    /// They live under `\0vyrn:doc-index:`, inside the reserved prefix, and reach
    /// `create_index` through the same entry point a user calls — so the namespace
    /// check has to exempt exactly that space. The exemption now reads the
    /// document layer's own constant, so this covers the routing rather than
    /// guarding against two copies of a prefix drifting apart.
    #[test]
    fn a_document_collection_index_name_survives_validation() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine
            .collection("users", &[document::IndexDefinition::new("email", true)])
            .unwrap();
        assert_eq!(
            engine.collection_indexes("users").unwrap(),
            vec![("email".to_owned(), true)]
        );
    }

    /// WAL replay must record history for exactly the keys the live commit path
    /// records it for.
    ///
    /// The live path filters through [`is_versioned_key`] when it stages
    /// historical values; replay recorded every key in the record, change-log
    /// entries included. A filter that exists in one direction only is a filter
    /// that will eventually be wrong in the other, and the cost is already
    /// measurable: every replayed change-log value is copied into the revision
    /// value log where nothing will ever read it, so the log grew by the whole
    /// replayed change stream on each recovery. Point-in-time restore replays by
    /// design, so that is the normal path.
    ///
    /// Asserted as a bound against the data the writes actually contain rather
    /// than an exact byte count, so the test states the property (change-log
    /// values are not retained) instead of pinning today's framing overhead.
    #[test]
    fn replay_records_history_for_the_same_keys_the_live_path_does() {
        let directory = tempdir().unwrap();
        const VALUE_LEN: usize = 500;
        const WRITES: usize = 20;
        {
            let mut engine = Engine::open(directory.path()).unwrap();
            for index in 0..WRITES {
                engine
                    .put(format!("k{index}").into_bytes(), vec![b'x'; VALUE_LEN])
                    .unwrap();
            }
        }
        // A reopen replays every record above the (absent) checkpoint.
        let engine = Engine::open(directory.path()).unwrap();
        assert_eq!(engine.len(), WRITES);
        let log = fs::metadata(directory.path().join(revision_value_file_name(0)))
            .unwrap()
            .len();
        // Each user value is retained once. A change-log record wraps a copy of
        // the same value, so recording those too roughly doubles the log — the
        // bound sits between the two, generously above the framing overhead of
        // the honest half and well below the other.
        let user_bytes = (WRITES * VALUE_LEN) as u64;
        assert!(
            log < user_bytes + user_bytes / 2,
            "the revision value log holds {log} bytes for {user_bytes} bytes of \
             user values, so replay retained the change-log values the live \
             commit path filters out"
        );
    }

    /// A poisoned snapshot registry is reported, not panicked on.
    ///
    /// The registry is only ever held for a refcount bump, so nothing inside it
    /// can panic on its own — but a panic anywhere else in the process while the
    /// guard is held poisons the mutex all the same, and `expect` then turned that
    /// into a second panic inside the storage engine. In the server that meant the
    /// write pipeline going down for every client, where [`Error::Poisoned`]
    /// already means the honest thing: reopen the database.
    #[test]
    fn a_poisoned_snapshot_registry_is_an_error_not_a_panic() {
        let directory = tempdir().unwrap();
        let mut engine = Engine::open(directory.path()).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();

        // Poison the mutex the way a real one gets poisoned: panic while its
        // guard is held. The engine reference is passed as a pointer because a
        // panicking closure must not borrow it across the unwind.
        let registry: &std::sync::Mutex<BTreeMap<u64, usize>> = &engine.shared_snapshots;
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.lock().unwrap();
            panic!("poisoning the registry");
        }));
        assert!(poisoned.is_err());
        assert!(engine.shared_snapshots.is_poisoned());

        // Every path through the registry now reports it instead of panicking.
        assert!(matches!(
            engine.register_snapshot_shared(),
            Err(Error::Poisoned)
        ));
        assert!(matches!(
            engine.release_snapshot_shared(1),
            Err(Error::Poisoned)
        ));
        assert!(matches!(engine.collect_versions(), Err(Error::Poisoned)));
        // Including the commit path, which consults the registry to decide what
        // history to retain — and must not guess when it cannot read it.
        assert!(matches!(
            engine.put(b"key".to_vec(), b"again".to_vec()),
            Err(Error::Poisoned)
        ));
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
