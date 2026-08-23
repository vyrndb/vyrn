use crate::{
    value_log::{ValueLog, ValueRef},
    Error, Result, MAX_STORED_KEY_SIZE, MAX_VALUE_SIZE,
};
use crc32fast::Hasher;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

pub(crate) const PAGE_SIZE: usize = 4 * 1024;
const HEADER_SIZE: usize = 40;
const MAGIC: &[u8; 4] = b"VPGE";
const VERSION: u8 = 4;
const SUPER: u8 = 1;
const LEAF: u8 = 2;
const INTERNAL: u8 = 3;
const BLOB: u8 = 4;
const INLINE_LIMIT: usize = 1024;
const LEAF_CELL_HEADER: usize = 33;
const INTERNAL_CELL_HEADER: usize = 21;
const EXTERNAL_KEY: u8 = 1;
const EXTERNAL_VALUE: u8 = 2;
const DEFAULT_CACHE_PAGES: usize = 4_096;

/// The most entries a leaf page can physically hold.
///
/// Every entry needs at least its cell header inside the page, so a count above
/// this is not a large tree but a forged field — and `decode_leaf` used to hand
/// such a field straight to `Vec::with_capacity`, letting four on-disk bytes
/// request a quarter-terabyte of memory. The page checksum does not help: it
/// sits next to the count and is trivially recomputed by whoever rewrites it.
const MAX_LEAF_ENTRIES: usize = (PAGE_SIZE - HEADER_SIZE) / LEAF_CELL_HEADER;

/// The most children an internal page can physically hold.
///
/// The first child lives in the header; each further one needs its cell in the
/// body. Same reasoning as [`MAX_LEAF_ENTRIES`]: a stored count past this bound
/// describes a page that cannot exist.
const MAX_INTERNAL_CHILDREN: usize = (PAGE_SIZE - HEADER_SIZE) / INTERNAL_CELL_HEADER + 1;

/// The deepest root-to-leaf descent any traversal will follow.
///
/// A 4 KiB internal page addresses at most [`MAX_INTERNAL_CHILDREN`] children,
/// so a real tree reaches single-digit height long before it reaches a trillion
/// keys. The bound exists for pages this build did not write: an internal page
/// whose first child is itself — or whose children form a ring — otherwise walks
/// every read path forever, and a long chain of degenerate internal pages
/// overflows the stack in the recursive walkers. 64 leaves orders of magnitude
/// of headroom above anything a healthy tree produces while turning both
/// failures into an ordinary corrupt-page report.
const MAX_TREE_DEPTH: usize = 64;

/// How many 4 KiB pages the tree may hold in memory.
///
/// The default is 16 MiB, which a tree of any real size outgrows immediately;
/// past that point every commit's descent and every copy-on-write rewrite starts
/// missing the cache, and the two of them are most of a commit's time under the
/// engine write lock.
fn cache_pages() -> usize {
    std::env::var("VYRN_PAGE_CACHE_PAGES")
        .ok()
        .and_then(|pages| pages.parse().ok())
        .filter(|pages| *pages > 0)
        .unwrap_or(DEFAULT_CACHE_PAGES)
}

type Page = [u8; PAGE_SIZE];
type VersionedRow = (Vec<u8>, Vec<u8>, u64);
/// A key's stored value and the revision that wrote it, absent when the key is gone.
type RevisionedValue = Option<(Vec<u8>, u64)>;
/// A found key's revision and its value, where the value is present only when
/// the caller asked for one. Lets one descent serve both the callers that need
/// the bytes and the callers that only need presence and revision.
type MaybeValued = Option<(Option<Vec<u8>>, u64)>;

/// Bytes that either own their buffer or read it in place from a cached page.
///
/// Decoding a page used to allocate an owned `Vec` for every key and every
/// inline value it holds — a leaf of 128 B values carries dozens of entries,
/// and a copy-on-write commit decodes several leaves and internal pages only
/// to re-encode most of their bytes unchanged moments later. A `Paged` slice
/// keeps the page alive through its `Arc` and reads the bytes where they lie,
/// so a decode costs two reference-count bumps per entry instead of two heap
/// allocations and a copy. `Owned` remains for bytes that never lived in a
/// page: new entries from a batch's mutations, and blob-backed keys.
#[derive(Clone, Debug)]
enum Bytes {
    Owned(Vec<u8>),
    Paged {
        page: Arc<Page>,
        offset: u32,
        len: u32,
    },
}

impl Bytes {
    fn paged(page: &Arc<Page>, offset: usize, len: usize) -> Self {
        Bytes::Paged {
            page: Arc::clone(page),
            offset: offset as u32,
            len: len as u32,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Bytes::Owned(bytes) => bytes,
            Bytes::Paged { page, offset, len } => {
                &page[*offset as usize..*offset as usize + *len as usize]
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Bytes::Owned(bytes) => bytes.len(),
            Bytes::Paged { len, .. } => *len as usize,
        }
    }

    fn into_vec(self) -> Vec<u8> {
        match self {
            Bytes::Owned(bytes) => bytes,
            Bytes::Paged { page, offset, len } => {
                page[offset as usize..offset as usize + len as usize].to_vec()
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Entry {
    key: Bytes,
    value: EntryValue,
    revision: u64,
}

#[derive(Clone, Debug)]
enum EntryValue {
    Inline(Bytes),
    External(ValueRef),
}

#[derive(Clone, Debug)]
struct NodeRef {
    page_id: u64,
    min_key: Bytes,
}

/// A single key's change within one batched tree mutation.
#[derive(Clone, Debug)]
pub(crate) enum Mutation {
    Put { value: Vec<u8>, revision: u64 },
    Delete,
}

/// The result of applying one batch.
#[derive(Debug)]
pub(crate) struct BatchOutcome {
    pub(crate) root: u64,
    pub(crate) len: u64,
}

/// A mutation with its value already written to the value log, sorted by key.
struct PreparedMutation {
    key: Vec<u8>,
    /// `None` for a delete.
    value: Option<(EntryValue, u64)>,
    /// Position in the caller's original list, used to report `existed`.
    index: usize,
}

struct PageCache {
    pages: HashMap<u64, CachedPage>,
    clock: VecDeque<u64>,
    hand: usize,
}

struct CachedPage {
    page: Arc<Page>,
    /// Set when a reader touches the page, cleared when the clock hand passes
    /// it. Pages referenced since the last sweep survive one eviction round.
    referenced: bool,
}

struct PageManager {
    file: File,
    /// Pages this manager holds, including those still in `pending`.
    page_count: u64,
    /// Pages actually written to the file. `page_count - flushed_count` pages
    /// sit encoded in `pending`, awaiting one contiguous write.
    flushed_count: u64,
    /// Encoded pages `[flushed_count, page_count)`, in page order.
    ///
    /// A copy-on-write commit appends its whole root-to-leaf rewrite here and
    /// [`PageManager::flush_appends`] hands the kernel one contiguous write for
    /// all of it. Writing each page as its own syscall measured ~30 µs per
    /// request of a 58 µs tree phase — the single largest cost of a commit
    /// after its `fdatasync` — for pages that never needed to reach the file
    /// one at a time: they carry no barrier of their own, and nothing reads
    /// them from the file before the flush.
    ///
    /// The buffer only lives inside one `prepare_put` / `prepare_batch` /
    /// `prepare_delete` call: each flushes before returning, so every page a
    /// returned root can reach is on the file before that root can be
    /// published, and checkpoints, backups, readers on their own descriptors,
    /// and drop-time syncs never observe a page file behind the tree they were
    /// handed. Behind a `Mutex` because a cache miss on a not-yet-flushed page
    /// (evicted mid-batch under cache pressure) is served from here on the
    /// `&self` read path.
    pending: Mutex<Vec<u8>>,
    cache: Mutex<PageCache>,
    cache_capacity: usize,
    /// Whether pages have been appended since the last successful sync, so a
    /// read-only commit does not pay for an `fsync` of an unchanged file.
    dirty: bool,
}

impl PageCache {
    /// Inserts a page, evicting one victim when the cache is full.
    ///
    /// Second-chance clock: a referenced page gets its bit cleared and survives
    /// this pass, an unreferenced page is evicted and the newcomer takes its
    /// slot. Reusing the slot keeps this O(1) amortized; removing from the
    /// middle of the ring would cost a memmove on every write.
    fn admit(&mut self, page_id: u64, page: Arc<Page>, referenced: bool, capacity: usize) {
        if let Some(existing) = self.pages.get_mut(&page_id) {
            existing.page = page;
            existing.referenced = referenced || existing.referenced;
            return;
        }
        let entry = CachedPage { page, referenced };
        if self.clock.len() < capacity {
            self.pages.insert(page_id, entry);
            self.clock.push_back(page_id);
            return;
        }
        // Sweep for a victim. Bounded by one full lap plus the clearing pass, so
        // it terminates even when every page was recently referenced.
        for _ in 0..=self.clock.len() {
            if self.hand >= self.clock.len() {
                self.hand = 0;
            }
            let candidate = self.clock[self.hand];
            match self.pages.get_mut(&candidate) {
                Some(cached) if cached.referenced => {
                    cached.referenced = false;
                    self.hand += 1;
                }
                _ => {
                    self.pages.remove(&candidate);
                    self.clock[self.hand] = page_id;
                    self.pages.insert(page_id, entry);
                    self.hand += 1;
                    return;
                }
            }
        }
        // Every page survived its second chance; replace at the hand anyway.
        if self.hand >= self.clock.len() {
            self.hand = 0;
        }
        let victim = self.clock[self.hand];
        self.pages.remove(&victim);
        self.clock[self.hand] = page_id;
        self.pages.insert(page_id, entry);
        self.hand += 1;
    }
}

impl PageManager {
    fn open(path: &Path, cache_capacity: usize) -> Result<Self> {
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        if created || file.metadata()?.len() == 0 {
            let mut super_page = new_page(SUPER, 0);
            finalize_page(&mut super_page);
            file.write_all(&super_page)?;
            file.sync_all()?;
        }
        let mut file_len = file.metadata()?.len();
        // Commits fsync only the WAL between checkpoints; page appends ride
        // along without a barrier of their own, so a power loss routinely
        // leaves part of one final page on disk. Refusing the file made an
        // ordinary crash permanently fatal even though redo reconstructs every
        // lost page from the log. A page is finished and checksummed before its
        // append begins and is written with a single `write_all`, so any page a
        // manifest or WAL record still names starts on a page boundary: the
        // fragment can only be the head of a page whose loss redo already
        // recovers from. Drop it, exactly as the WAL and the value logs repair
        // their own tails.
        if file_len % PAGE_SIZE as u64 != 0 {
            file_len -= file_len % PAGE_SIZE as u64;
            file.set_len(file_len)?;
            file.sync_all()?;
        }
        let page_count = file_len / PAGE_SIZE as u64;
        let manager = Self {
            file,
            page_count,
            flushed_count: page_count,
            pending: Mutex::new(Vec::new()),
            cache: Mutex::new(PageCache {
                pages: HashMap::new(),
                clock: VecDeque::new(),
                hand: 0,
            }),
            cache_capacity: cache_capacity.max(1),
            dirty: false,
        };
        let super_page = manager.read(0)?;
        require_type(&super_page, 0, SUPER)?;
        Ok(manager)
    }

    fn read(&self, page_id: u64) -> Result<Arc<Page>> {
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| Error::Poisoned)?
            .pages
            .get_mut(&page_id)
        {
            // Mark the page as recently used so a burst of writes cannot evict
            // pages that readers are actively hitting.
            cached.referenced = true;
            crate::profile::PAGE_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Arc::clone(&cached.page));
        }
        crate::profile::PAGE_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if page_id >= self.page_count {
            return Err(Error::CorruptPage {
                page_id,
                reason: "page reference is out of bounds".into(),
            });
        }
        let mut page = [0; PAGE_SIZE];
        if page_id >= self.flushed_count {
            // Appended and not yet flushed: the page is in the buffer, not the
            // file. No current caller reads a page id before the mutation that
            // appended it returns — copy-on-write only reads the OLD root's
            // pages, and every mutation flushes before its new root escapes —
            // so this arm is defense in depth: the buffer's correctness should
            // not rest on that argument holding forever.
            let pending = self.pending.lock().map_err(|_| Error::Poisoned)?;
            let start = (page_id - self.flushed_count) as usize * PAGE_SIZE;
            page.copy_from_slice(&pending[start..start + PAGE_SIZE]);
        } else {
            read_exact_at(&self.file, &mut page, page_id * PAGE_SIZE as u64)?;
        }
        validate_page(&mut page, page_id)?;
        let page = Arc::new(page);
        self.insert_cache(page_id, Arc::clone(&page))?;
        Ok(page)
    }

    fn append(&mut self, page: Page) -> Result<u64> {
        let started = std::time::Instant::now();
        let result = self.append_inner(page);
        crate::profile::add(&crate::profile::TREE_APPEND_NS, started);
        result
    }

    fn append_inner(&mut self, mut page: Page) -> Result<u64> {
        crate::profile::PAGE_APPENDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let page_id = self.page_count;
        write_u64(&mut page, 8, page_id);
        finalize_page(&mut page);
        // Buffered rather than written: the batch's pages reach the file as one
        // contiguous write in `flush_appends`, at the page-aligned offset the
        // in-memory counters name. See the field comment on `pending` for why,
        // and for the invariant that keeps this safe.
        self.pending
            .get_mut()
            .map_err(|_| Error::Poisoned)?
            .extend_from_slice(&page);
        self.page_count += 1;
        // Appended pages enter UNREFERENCED, which is what `insert_cache_with`'s
        // doc comment has always claimed and what the code did not do: it passed
        // `true`, so every page a copy-on-write commit wrote arrived holding a
        // second chance. Under cache pressure that inverts the policy the clock is
        // there to implement. A commit rewrites its whole root-to-leaf path, and
        // those pages are immediately superseded by the next commit's rewrite of
        // the same path — nothing reads them again — yet each one arrived able to
        // survive an eviction pass, and the pages it could push out were the
        // reader-touched ones whose bit had just been cleared by the hand. A burst
        // of writes therefore evicted exactly the pages readers were hitting.
        //
        // The comment claiming they "are usually on the next commit's
        // copy-on-write path" is true of the path's SHAPE, not of these page ids:
        // the next commit reads the current root's pages, and these have already
        // been replaced. Entering unreferenced still leaves them cached and still
        // lets a reader that does touch one set the bit; it only stops them
        // outranking pages that earned their bit by being read.
        self.insert_cache_with(page_id, Arc::new(page), false)?;
        Ok(page_id)
    }

    /// Writes every buffered page to the file in one contiguous write.
    ///
    /// Written at the page-aligned end the counters name, never the raw file
    /// end: a flush cut off mid-write (ENOSPC) leaves a fragment at the tail
    /// while `flushed_count` still counts whole flushed pages, so the retry
    /// overwrites the fragment — it is the head of exactly the span this flush
    /// writes — and every later offset stays aligned. The offset is computed
    /// rather than discovered with `seek`, which cost two syscalls per page
    /// when appends went to the file one at a time.
    fn flush_appends(&mut self) -> Result<()> {
        let pending = self.pending.get_mut().map_err(|_| Error::Poisoned)?;
        if pending.is_empty() {
            return Ok(());
        }
        let write_started = std::time::Instant::now();
        write_all_at(&self.file, pending, self.flushed_count * PAGE_SIZE as u64)?;
        crate::profile::add(&crate::profile::TREE_FLUSH_NS, write_started);
        pending.clear();
        self.flushed_count = self.page_count;
        self.dirty = true;
        Ok(())
    }

    /// Drops every buffered page and reclaims their ids after a failed
    /// mutation.
    ///
    /// Nothing can reference them: the mutation returned an error, so its root
    /// was never published and its WAL record never written. Before the buffer
    /// existed a failed batch left its pages behind on disk as permanent
    /// orphans; discarding them here means it no longer leaves anything at
    /// all. The ids are removed from the cache as well, or a corrupt page
    /// naming one of them after the id is reused could hit the stale copy
    /// instead of the bounds check. Their clock slots are left to dangle; the
    /// eviction sweep already treats a slot whose page is gone as free.
    fn discard_appends(&mut self) {
        let Ok(pending) = self.pending.get_mut() else {
            return;
        };
        if pending.is_empty() {
            return;
        }
        pending.clear();
        if let Ok(mut cache) = self.cache.lock() {
            for page_id in self.flushed_count..self.page_count {
                cache.pages.remove(&page_id);
            }
        }
        self.page_count = self.flushed_count;
    }

    fn sync(&mut self) -> Result<()> {
        self.flush_appends()?;
        if !self.dirty {
            return Ok(());
        }
        self.file.sync_data()?;
        self.dirty = false;
        Ok(())
    }

    fn page_count(&self) -> u64 {
        self.page_count
    }

    fn refresh_page_count(&mut self) -> Result<()> {
        // The buffer is empty between tree mutations, which is the only time a
        // refresh runs; flushing here keeps that true by construction rather
        // than by convention.
        self.flush_appends()?;
        let file_len = self.file.metadata()?.len();
        if file_len % PAGE_SIZE as u64 != 0 {
            return Err(Error::CorruptPage {
                page_id: 0,
                reason: "page file length is not page-aligned".into(),
            });
        }
        self.page_count = file_len / PAGE_SIZE as u64;
        self.flushed_count = self.page_count;
        Ok(())
    }

    fn insert_cache(&self, page_id: u64, page: Arc<Page>) -> Result<()> {
        self.insert_cache_with(page_id, page, true)
    }

    /// Inserts a page, marking it referenced only when a reader asked for it.
    ///
    /// Newly appended pages enter unreferenced so a stream of copy-on-write
    /// commits evicts its own pages first instead of the read-hot ones.
    fn insert_cache_with(&self, page_id: u64, page: Arc<Page>, referenced: bool) -> Result<()> {
        self.cache.lock().map_err(|_| Error::Poisoned)?.admit(
            page_id,
            page,
            referenced,
            self.cache_capacity,
        );
        Ok(())
    }
}

pub(crate) struct PageTree {
    pages: PageManager,
    values: ValueLog,
    root: u64,
    len: u64,
}

impl PageTree {
    pub(crate) fn open(path: &Path, value_path: &Path, root: u64, len: u64) -> Result<Self> {
        // A manifest naming a generation whose page file is gone is damage, not
        // an empty database. Opening used to materialise the missing file as a
        // fresh page store and only then fail looking up the root — after
        // writing an empty file over a name that a restored backup or an older
        // copy may still hold the real bytes for. Creation stays legal for a
        // genuinely fresh database, whose manifest is absent and whose root and
        // length are both zero.
        if !path.exists() && (root != 0 || len != 0) {
            return Err(Error::CorruptManifest(format!(
                "the checkpoint names page file {} and it does not exist",
                path.display()
            )));
        }
        let pages = PageManager::open(path, cache_pages())?;
        let values = ValueLog::open(value_path)?;
        if root != 0 {
            let page = pages.read(root)?;
            if page[5] != LEAF && page[5] != INTERNAL {
                return Err(Error::CorruptPage {
                    page_id: root,
                    reason: "root is not a tree node".into(),
                });
            }
        } else if len != 0 {
            return Err(Error::CorruptManifest(
                "empty root has a nonzero entry count".into(),
            ));
        }
        Ok(Self {
            pages,
            values,
            root,
            len,
        })
    }

    pub(crate) fn root_id(&self) -> u64 {
        self.root
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn page_count(&self) -> u64 {
        self.pages.page_count()
    }

    pub(crate) fn count_excluding_prefix(&self, prefix: &[u8]) -> Result<usize> {
        if self.root == 0 {
            return Ok(0);
        }
        self.count_node_excluding_prefix(self.root, prefix, 0)
    }

    pub(crate) fn publish(&mut self, root: u64, len: u64) {
        self.root = root;
        self.len = len;
    }

    pub(crate) fn refresh(&mut self, root: u64, len: u64) -> Result<()> {
        self.pages.refresh_page_count()?;
        self.publish(root, len);
        Ok(())
    }

    pub(crate) fn sync(&mut self) -> Result<()> {
        self.values.sync()?;
        self.pages.sync()
    }

    pub(crate) fn compact_to(&self, path: &Path, value_path: &Path) -> Result<(u64, u64)> {
        let rows = self.scan_with_revisions(None, None, self.len as usize)?;
        let mut compact = PageTree::open(path, value_path, 0, 0)?;
        for (key, value, revision) in rows {
            let (root, len) = compact.prepare_put(&key, &value, revision)?;
            compact.publish(root, len);
        }
        compact.sync()?;
        Ok((compact.root, compact.len))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let mut visited = HashSet::new();
        let count = if self.root == 0 {
            0
        } else {
            self.validate_node(self.root, None, None, &mut visited, 0)?
        };
        if count != self.len {
            return Err(Error::CorruptPage {
                page_id: self.root,
                reason: format!(
                    "tree contains {count} entries but metadata reports {}",
                    self.len
                ),
            });
        }
        Ok(())
    }

    pub(crate) fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_with_revision(key)
            .map(|entry| entry.map(|(value, _)| value))
    }

    pub(crate) fn revision(&self, key: &[u8]) -> Result<Option<u64>> {
        self.get_with_revision(key)
            .map(|entry| entry.map(|(_, revision)| revision))
    }

    /// Reads many keys' values and revisions in a single ordered sweep.
    ///
    /// `keys` must be sorted and deduplicated. Results are returned positionally.
    /// One descent shared across the batch reads each internal page once instead
    /// of once per key, which matters on the commit path where a batch has to know
    /// the prior state of every key it touches.
    pub(crate) fn get_many_with_revision(&self, keys: &[Vec<u8>]) -> Result<Vec<RevisionedValue>> {
        let mut results = vec![None; keys.len()];
        if self.root != 0 && !keys.is_empty() {
            self.collect_many(self.root, keys, &mut results, true, 0)?;
        }
        Ok(results
            .into_iter()
            .map(|found| found.map(|(value, revision)| (value.unwrap_or_default(), revision)))
            .collect())
    }

    /// Reads many keys' revisions in a single ordered sweep, without reading
    /// their values.
    ///
    /// The commit path and transaction validation both need to know whether a
    /// key is present and at what revision, but not what it holds. Materialising
    /// the value costs an allocation and copy for an inline value and a value-log
    /// file read for an external one — on the commit path that read happens under
    /// the engine write lock, where it blocks every other writer. Only an MVCC
    /// pre-image genuinely needs the bytes, so the value read is now asked for
    /// explicitly rather than paid for by every caller.
    pub(crate) fn get_many_revisions(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<u64>>> {
        let mut results = vec![None; keys.len()];
        if self.root != 0 && !keys.is_empty() {
            self.collect_many(self.root, keys, &mut results, false, 0)?;
        }
        Ok(results
            .into_iter()
            .map(|found| found.map(|(_, revision)| revision))
            .collect())
    }

    fn collect_many(
        &self,
        page_id: u64,
        keys: &[Vec<u8>],
        results: &mut [MaybeValued],
        want_values: bool,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => {
                // Cells are walked in place for the same reason `find_in_leaf`
                // walks them: this used to call `decode_leaf`, which allocates a
                // `Vec` for the key AND a `Vec` for the value of every entry in
                // the page, and a commit's pre-state read wants presence and
                // revision for a handful of keys — usually without the values at
                // all. Both sides are sorted, so a merge walk finds every hit in
                // one pass and stops once the last wanted key is resolved.
                // Measured on the commit path (three leaves per single-key
                // commit: the key, its tombstone, the change log): pre-state
                // 34.6 us to 7.0 us per request, page reads 32 to 23.
                let count = read_u32(page.as_ref(), 20) as usize;
                if count > MAX_LEAF_ENTRIES {
                    return Err(Error::CorruptPage {
                        page_id,
                        reason: format!(
                            "leaf claims {count} entries but a page holds at most {MAX_LEAF_ENTRIES}"
                        ),
                    });
                }
                let mut offset = HEADER_SIZE;
                let mut cursor = 0;
                for _ in 0..count {
                    if cursor == keys.len() {
                        break;
                    }
                    require_page(offset, LEAF_CELL_HEADER, page_id)?;
                    let flags = page[offset];
                    let key_len = read_u32(page.as_ref(), offset + 1) as usize;
                    let value_len = read_u32(page.as_ref(), offset + 5) as usize;
                    if key_len == 0
                        || key_len > MAX_STORED_KEY_SIZE
                        || value_len > MAX_VALUE_SIZE
                        || flags & !(EXTERNAL_KEY | EXTERNAL_VALUE) != 0
                    {
                        return Err(Error::CorruptPage {
                            page_id,
                            reason: "invalid leaf cell metadata".into(),
                        });
                    }
                    let key_page = read_u64(page.as_ref(), offset + 9);
                    let value_offset = read_u64(page.as_ref(), offset + 17);
                    let revision = read_u64(page.as_ref(), offset + 25);
                    offset += LEAF_CELL_HEADER;
                    // An external key is a blob read, so it is compared by
                    // reading it; an inline key is compared against the page
                    // bytes with no copy at all, as in `find_in_leaf`.
                    let external_key = flags & EXTERNAL_KEY != 0;
                    let stored_key = if external_key {
                        Some(self.read_blob(key_page, key_len)?)
                    } else {
                        require_page(offset, key_len, page_id)?;
                        None
                    };
                    let cell_key: &[u8] = match &stored_key {
                        Some(stored) => stored,
                        None => &page[offset..offset + key_len],
                    };
                    if !external_key {
                        offset += key_len;
                    }
                    // Wanted keys that sort before this cell are absent from the
                    // tree; their slots stay `None`.
                    cursor += keys[cursor..].partition_point(|key| key.as_slice() < cell_key);
                    let hit = keys
                        .get(cursor)
                        .is_some_and(|key| key.as_slice() == cell_key);
                    let value_external = flags & EXTERNAL_VALUE != 0;
                    if !value_external {
                        require_page(offset, value_len, page_id)?;
                    }
                    if hit {
                        let value = match (want_values, value_external) {
                            (false, _) => None,
                            (true, true) => Some(self.values.read(&ValueRef {
                                offset: value_offset,
                                len: value_len as u32,
                                revision,
                            })?),
                            (true, false) => Some(page[offset..offset + value_len].to_vec()),
                        };
                        results[cursor] = Some((value, revision));
                        cursor += 1;
                    }
                    if !value_external {
                        offset += value_len;
                    }
                }
                Ok(())
            }
            INTERNAL => {
                // Boundaries are read from the cells in place rather than through
                // `decode_internal`, which materialises an owned `NodeRef` — a
                // heap key each — for every child of the page, and reads the
                // first child's page besides, only to route a few keys. Cell `i`
                // holds the minimum key and page id of child `i + 1`; the header
                // holds child 0's page id, and child 0 owns everything below
                // child 1's minimum.
                let count = read_u32(page.as_ref(), 20) as usize;
                if count >= MAX_INTERNAL_CHILDREN {
                    return Err(Error::CorruptPage {
                        page_id,
                        reason: format!(
                            "internal page claims {} children but a page holds at most {MAX_INTERNAL_CHILDREN}",
                            count + 1
                        ),
                    });
                }
                let mut child_id = read_u64(page.as_ref(), 24);
                let mut offset = HEADER_SIZE;
                let mut cursor = 0;
                for _ in 0..count {
                    require_page(offset, INTERNAL_CELL_HEADER, page_id)?;
                    let flags = page[offset];
                    let key_len = read_u32(page.as_ref(), offset + 1) as usize;
                    let key_page = read_u64(page.as_ref(), offset + 5);
                    let next_child = read_u64(page.as_ref(), offset + 13);
                    if key_len == 0 || key_len > MAX_STORED_KEY_SIZE || flags & !EXTERNAL_KEY != 0 {
                        return Err(Error::CorruptPage {
                            page_id,
                            reason: "invalid internal cell metadata".into(),
                        });
                    }
                    offset += INTERNAL_CELL_HEADER;
                    let external_key = flags & EXTERNAL_KEY != 0;
                    let stored_key = if external_key {
                        Some(self.read_blob(key_page, key_len)?)
                    } else {
                        require_page(offset, key_len, page_id)?;
                        None
                    };
                    let boundary: &[u8] = match &stored_key {
                        Some(stored) => stored,
                        None => &page[offset..offset + key_len],
                    };
                    if !external_key {
                        offset += key_len;
                    }
                    let end =
                        cursor + keys[cursor..].partition_point(|key| key.as_slice() < boundary);
                    if end > cursor {
                        self.collect_many(
                            child_id,
                            &keys[cursor..end],
                            &mut results[cursor..end],
                            want_values,
                            depth + 1,
                        )?;
                    }
                    cursor = end;
                    child_id = next_child;
                }
                if cursor < keys.len() {
                    self.collect_many(
                        child_id,
                        &keys[cursor..],
                        &mut results[cursor..],
                        want_values,
                        depth + 1,
                    )?;
                }
                Ok(())
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    /// Reads a key's value and revision in one descent.
    ///
    /// The leaf's cells are walked in place rather than decoded. `read_leaf` was
    /// called here, and `decode_leaf` allocates a `Vec` for the key AND a `Vec`
    /// for the value of every entry in the page — a 4 KiB leaf of 128 B values
    /// holds around thirty, and a leaf of small values many more — all to answer
    /// a lookup that keeps one value and drops the rest. Walking the cells copies
    /// exactly the one value that matched. Measured on a 4,000-key tree of 128 B
    /// values, this took a cached `get` from 21.6 µs to 1.9 µs.
    pub(crate) fn get_with_revision(&self, key: &[u8]) -> Result<RevisionedValue> {
        if self.root == 0 {
            return Ok(None);
        }
        let leaf_id = self.find_leaf(key, None)?;
        let page = self.pages.read(leaf_id)?;
        require_type(&page, leaf_id, LEAF)?;
        self.find_in_leaf(&page, leaf_id, key)
    }

    /// Finds one key's value inside a leaf page without decoding the page.
    ///
    /// The value is materialised here rather than handed back as an
    /// [`EntryValue`] for the caller to resolve: an inline value returned that way
    /// would be copied out of the page and then cloned again by `read_value`, and
    /// at 1 MiB one avoidable copy of the bytes is most of the cost of the read.
    /// Cells ascend by key, so the walk stops at the first cell past the target.
    fn find_in_leaf(&self, page: &Page, page_id: u64, key: &[u8]) -> Result<RevisionedValue> {
        let count = read_u32(page, 20) as usize;
        // Same bound and same reasoning as `decode_leaf`: a count past what the
        // page can physically hold is a forged field, not a large tree.
        if count > MAX_LEAF_ENTRIES {
            return Err(Error::CorruptPage {
                page_id,
                reason: format!(
                    "leaf claims {count} entries but a page holds at most {MAX_LEAF_ENTRIES}"
                ),
            });
        }
        let mut offset = HEADER_SIZE;
        for _ in 0..count {
            require_page(offset, LEAF_CELL_HEADER, page_id)?;
            let flags = page[offset];
            let key_len = read_u32(page, offset + 1) as usize;
            let value_len = read_u32(page, offset + 5) as usize;
            if key_len == 0
                || key_len > MAX_STORED_KEY_SIZE
                || value_len > MAX_VALUE_SIZE
                || flags & !(EXTERNAL_KEY | EXTERNAL_VALUE) != 0
            {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "invalid leaf cell metadata".into(),
                });
            }
            let key_page = read_u64(page, offset + 9);
            let value_offset = read_u64(page, offset + 17);
            let revision = read_u64(page, offset + 25);
            offset += LEAF_CELL_HEADER;
            // An external key is a blob read, so it is compared by reading it;
            // an inline key is compared against the page bytes with no copy at
            // all, which is the case every ordinary key takes.
            let external_key = flags & EXTERNAL_KEY != 0;
            let stored_key = if external_key {
                Some(self.read_blob(key_page, key_len)?)
            } else {
                require_page(offset, key_len, page_id)?;
                None
            };
            let ordering = match &stored_key {
                Some(stored) => stored.as_slice().cmp(key),
                None => page[offset..offset + key_len].cmp(key),
            };
            if !external_key {
                offset += key_len;
            }
            // Keys ascend, so nothing past this cell can match.
            if ordering == std::cmp::Ordering::Greater {
                return Ok(None);
            }
            let value_external = flags & EXTERNAL_VALUE != 0;
            if !value_external {
                require_page(offset, value_len, page_id)?;
            }
            if ordering == std::cmp::Ordering::Equal {
                let value = if value_external {
                    self.values.read(&ValueRef {
                        offset: value_offset,
                        len: value_len as u32,
                        revision,
                    })?
                } else {
                    page[offset..offset + value_len].to_vec()
                };
                return Ok(Some((value, revision)));
            }
            if !value_external {
                offset += value_len;
            }
        }
        Ok(None)
    }

    pub(crate) fn prepare_put(
        &mut self,
        key: &[u8],
        value: &[u8],
        revision: u64,
    ) -> Result<(u64, u64)> {
        // Every page the returned root reaches must be on the file before the
        // caller can publish that root — readers on their own descriptors and
        // manifests both depend on it — so the batch's buffered pages flush
        // here, as one write, before the root leaves this method. A failure
        // anywhere surfaces while the mutation is still invisible, and takes
        // its buffered pages with it.
        let result = self
            .prepare_put_inner(key, value, revision)
            .and_then(|result| {
                self.pages.flush_appends()?;
                Ok(result)
            });
        if result.is_err() {
            self.pages.discard_appends();
        }
        result
    }

    fn prepare_put_inner(&mut self, key: &[u8], value: &[u8], revision: u64) -> Result<(u64, u64)> {
        let value = if value.len() > INLINE_LIMIT {
            EntryValue::External(self.values.append(value, revision)?)
        } else {
            EntryValue::Inline(Bytes::Owned(value.to_vec()))
        };
        let new_entry = Entry {
            key: Bytes::Owned(key.to_vec()),
            value,
            revision,
        };
        if self.root == 0 {
            let node = self.write_leaf(&[new_entry])?;
            return Ok((node.page_id, 1));
        }
        let mut path = Vec::new();
        let leaf_id = self.find_leaf(key, Some(&mut path))?;
        let mut entries = self.read_leaf(leaf_id)?;
        let (position, existed) = find_entry(&entries, key);
        if existed {
            entries[position] = new_entry;
        } else {
            entries.insert(position, new_entry);
        }
        let mut replacements = self.write_leaf_level(&entries)?;
        while let Some((parent_id, child_index)) = path.pop() {
            let mut children = self.read_internal_children(parent_id)?;
            children.splice(child_index..=child_index, replacements);
            replacements = self.write_internal_level(&children)?;
        }
        let root = if replacements.len() == 1 {
            replacements[0].page_id
        } else {
            self.write_internal(&replacements)?.page_id
        };
        Ok((root, self.len + u64::from(!existed)))
    }

    /// Applies many mutations in a single copy-on-write pass.
    ///
    /// Rewrites each affected root-to-leaf path once for the whole batch instead
    /// of once per key, so a commit's page cost is proportional to the paths it
    /// touches rather than to the number of keys it changes. Applying keys one at
    /// a time made a 64-key batch write ~133 pages where this writes a few dozen.
    ///
    /// Mutations are applied in the given order, so a later mutation of the same
    /// key wins and sees the earlier one's effect, matching what repeated
    /// single-key calls would have produced.
    pub(crate) fn prepare_batch(
        &mut self,
        mutations: Vec<(Vec<u8>, Mutation)>,
    ) -> Result<BatchOutcome> {
        // Same rule as `prepare_put`: the buffered pages reach the file before
        // the outcome's root can be published, and a failed batch discards
        // them rather than leaving orphans for the next flush to write.
        let outcome = self.prepare_batch_inner(mutations).and_then(|outcome| {
            self.pages.flush_appends()?;
            Ok(outcome)
        });
        if outcome.is_err() {
            self.pages.discard_appends();
        }
        outcome
    }

    fn prepare_batch_inner(&mut self, mutations: Vec<(Vec<u8>, Mutation)>) -> Result<BatchOutcome> {
        if mutations.is_empty() {
            return Ok(BatchOutcome {
                root: self.root,
                len: self.len,
            });
        }
        // Tracks which keys were present before the batch, so the entry count can
        // be adjusted without re-reading the tree.
        let mut existed = vec![false; mutations.len()];
        let mut prepared = Vec::with_capacity(mutations.len());
        // Taken by move: keys and values pass through to the prepared list
        // without the clone-per-operation the borrowed signature forced on
        // every caller.
        for (index, (key, mutation)) in mutations.into_iter().enumerate() {
            let value = match mutation {
                Mutation::Put { value, revision } => {
                    let stored = if value.len() > INLINE_LIMIT {
                        EntryValue::External(self.values.append(&value, revision)?)
                    } else {
                        EntryValue::Inline(Bytes::Owned(value))
                    };
                    Some((stored, revision))
                }
                Mutation::Delete => None,
            };
            prepared.push(PreparedMutation { key, value, index });
        }
        // Descending in key order lets one pass group each leaf's mutations
        // together; a stable sort keeps same-key mutations in arrival order.
        prepared.sort_by(|left, right| left.key.cmp(&right.key));
        let mut replacements = if self.root == 0 {
            let entries = merge_entries(Vec::new(), &prepared, &mut existed);
            if entries.is_empty() {
                Vec::new()
            } else {
                self.write_leaf_level(&entries)?
            }
        } else {
            self.apply_node(self.root, &prepared, true, &mut existed, 0)?
        };
        while replacements.len() > 1 {
            replacements = self.write_internal_level(&replacements)?;
        }
        // Count one delta per distinct key, not per mutation: a batch that writes
        // and then deletes the same key changes the entry count by whatever its
        // last mutation leaves behind, not by both of them. `prepared` is sorted
        // by key, so each run of equal keys is contiguous.
        let mut delta: i64 = 0;
        let mut index = 0;
        while index < prepared.len() {
            let mut last = index;
            while last + 1 < prepared.len() && prepared[last + 1].key == prepared[index].key {
                last += 1;
            }
            match (&prepared[last].value, existed[prepared[index].index]) {
                (Some(_), false) => delta += 1,
                (None, true) => delta -= 1,
                _ => {}
            }
            index = last + 1;
        }
        let root = replacements.first().map_or(0, |node| node.page_id);
        let len = if root == 0 {
            0
        } else {
            self.len.saturating_add_signed(delta)
        };
        Ok(BatchOutcome { root, len })
    }

    /// Rewrites one subtree for the mutations that fall inside it.
    ///
    /// Returns the nodes that replace `page_id` in its parent, which may be more
    /// than one when a page split, or none when the subtree became empty.
    fn apply_node(
        &mut self,
        page_id: u64,
        mutations: &[PreparedMutation],
        is_root: bool,
        existed: &mut [bool],
        depth: usize,
    ) -> Result<Vec<NodeRef>> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => {
                let entries = self.decode_leaf(&page, page_id)?;
                let entries = merge_entries(entries, mutations, existed);
                if entries.is_empty() {
                    Ok(Vec::new())
                } else {
                    self.write_leaf_level(&entries)
                }
            }
            INTERNAL => {
                let children = self.decode_internal(&page, page_id)?;
                let mut new_children = Vec::with_capacity(children.len());
                let mut cursor = 0;
                for (index, child) in children.iter().enumerate() {
                    // Child 0 owns everything below child 1's minimum, so keys
                    // smaller than the subtree's current minimum land there.
                    let end = match children.get(index + 1) {
                        Some(next) => {
                            cursor
                                + mutations[cursor..].partition_point(|mutation| {
                                    mutation.key.as_slice() < next.min_key.as_slice()
                                })
                        }
                        None => mutations.len(),
                    };
                    if end > cursor {
                        let replacements = self.apply_node(
                            child.page_id,
                            &mutations[cursor..end],
                            false,
                            existed,
                            depth + 1,
                        )?;
                        new_children.extend(replacements);
                    } else {
                        new_children.push(child.clone());
                    }
                    cursor = end;
                }
                if new_children.is_empty() {
                    return Ok(Vec::new());
                }
                // Collapse a root that deletes reduced to a single child, rather
                // than keeping an internal page that points at just one node.
                if is_root && new_children.len() == 1 {
                    return Ok(new_children);
                }
                self.write_internal_level(&new_children)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    pub(crate) fn prepare_delete(&mut self, key: &[u8]) -> Result<Option<(u64, u64)>> {
        // Same rule as `prepare_put`: the buffered pages reach the file before
        // the returned root can be published, and a failure discards them.
        let result = self.prepare_delete_inner(key).and_then(|result| {
            self.pages.flush_appends()?;
            Ok(result)
        });
        if result.is_err() {
            self.pages.discard_appends();
        }
        result
    }

    fn prepare_delete_inner(&mut self, key: &[u8]) -> Result<Option<(u64, u64)>> {
        if self.root == 0 {
            return Ok(None);
        }
        let mut path = Vec::new();
        let leaf_id = self.find_leaf(key, Some(&mut path))?;
        let mut entries = self.read_leaf(leaf_id)?;
        let (position, existed) = find_entry(&entries, key);
        if !existed {
            return Ok(None);
        }
        entries.remove(position);
        let mut replacements = if entries.is_empty() {
            Vec::new()
        } else {
            vec![self.write_leaf(&entries)?]
        };
        while let Some((parent_id, child_index)) = path.pop() {
            let mut children = self.read_internal_children(parent_id)?;
            children.splice(child_index..=child_index, replacements);
            replacements = if children.is_empty() {
                Vec::new()
            } else if path.is_empty() && children.len() == 1 {
                children
            } else {
                self.write_internal_level(&children)?
            };
        }
        let root = replacements.first().map_or(0, |node| node.page_id);
        Ok(Some((root, self.len - 1)))
    }

    pub(crate) fn scan(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.scan_excluding_prefix(start, end, limit, None)
    }

    pub(crate) fn scan_excluding_prefix(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .scan_with_revisions_excluding_prefix(start, end, limit, excluded_prefix)?
            .into_iter()
            .map(|(key, value, _)| (key, value))
            .collect())
    }

    pub(crate) fn scan_with_revisions(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<VersionedRow>> {
        self.scan_with_revisions_excluding_prefix(start, end, limit, None)
    }

    /// Returns the greatest key in `[start, end)`, without reading values.
    ///
    /// Descends the rightmost child that can contain a matching key, so the cost
    /// is proportional to tree height rather than to the number of keys in range.
    pub(crate) fn last_key_in(&self, start: &[u8], end: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        if self.root == 0 {
            return Ok(None);
        }
        self.last_key_in_node(self.root, start, end, 0)
    }

    fn last_key_in_node(
        &self,
        page_id: u64,
        start: &[u8],
        end: Option<&[u8]>,
        depth: usize,
    ) -> Result<Option<Vec<u8>>> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => Ok(self
                .decode_leaf(&page, page_id)?
                .into_iter()
                .filter(|entry| {
                    entry.key.as_slice() >= start
                        && end.is_none_or(|end| entry.key.as_slice() < end)
                })
                .next_back()
                .map(|entry| entry.key.into_vec())),
            INTERNAL => {
                let children = self.decode_internal(&page, page_id)?;
                for (index, child) in children.iter().enumerate().rev() {
                    // Skip subtrees that start at or after the exclusive end.
                    if end.is_some_and(|end| child.min_key.as_slice() >= end) {
                        continue;
                    }
                    // Skip subtrees that end at or before the inclusive start.
                    let child_end = children.get(index + 1).map(|next| next.min_key.as_slice());
                    if child_end.is_some_and(|child_end| child_end <= start) {
                        continue;
                    }
                    if let Some(found) =
                        self.last_key_in_node(child.page_id, start, end, depth + 1)?
                    {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    pub(crate) fn changed_since(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        revision: u64,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<bool> {
        if self.root == 0 {
            return Ok(false);
        }
        self.node_changed_since(self.root, start, end, revision, excluded_prefix, 0)
    }

    pub(crate) fn scan_with_revisions_excluding_prefix(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<Vec<VersionedRow>> {
        let mut rows = Vec::with_capacity(limit.min(1024));
        if self.root != 0 && limit != 0 {
            self.scan_node(self.root, start, end, limit, excluded_prefix, &mut rows, 0)?;
        }
        Ok(rows)
    }

    fn validate_node(
        &self,
        page_id: u64,
        lower: Option<Bytes>,
        upper: Option<Bytes>,
        visited: &mut HashSet<u64>,
        depth: usize,
    ) -> Result<u64> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        if !visited.insert(page_id) {
            return Err(Error::CorruptPage {
                page_id,
                reason: "tree page is referenced more than once or cyclic".into(),
            });
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => {
                let entries = self.decode_leaf(&page, page_id)?;
                let mut previous: Option<&[u8]> = None;
                for entry in &entries {
                    if previous.is_some_and(|previous| previous >= entry.key.as_slice())
                        || lower
                            .as_ref()
                            .is_some_and(|lower| entry.key.as_slice() < lower.as_slice())
                        || upper
                            .as_ref()
                            .is_some_and(|upper| entry.key.as_slice() >= upper.as_slice())
                    {
                        return Err(Error::CorruptPage {
                            page_id,
                            reason: "leaf keys are not strictly ordered within bounds".into(),
                        });
                    }
                    previous = Some(entry.key.as_slice());
                }
                Ok(entries.len() as u64)
            }
            INTERNAL => {
                let children = self.decode_internal(&page, page_id)?;
                let separators: Vec<_> = children
                    .iter()
                    .skip(1)
                    .map(|child| child.min_key.clone())
                    .collect();
                for pair in separators.windows(2) {
                    if pair[0].as_slice() >= pair[1].as_slice() {
                        return Err(Error::CorruptPage {
                            page_id,
                            reason: "internal separators are not strictly ordered".into(),
                        });
                    }
                }
                let mut total = 0;
                for (index, child) in children.into_iter().enumerate() {
                    let child_lower = if index == 0 {
                        lower.clone()
                    } else {
                        Some(separators[index - 1].clone())
                    };
                    let child_upper = separators.get(index).cloned().or_else(|| upper.clone());
                    total += self.validate_node(
                        child.page_id,
                        child_lower,
                        child_upper,
                        visited,
                        depth + 1,
                    )?;
                }
                Ok(total)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    fn count_node_excluding_prefix(
        &self,
        page_id: u64,
        prefix: &[u8],
        depth: usize,
    ) -> Result<usize> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => Ok(self
                .decode_leaf(&page, page_id)?
                .into_iter()
                .filter(|entry| !entry.key.as_slice().starts_with(prefix))
                .count()),
            INTERNAL => {
                let mut count = 0;
                for child in self.decode_internal(&page, page_id)? {
                    count += self.count_node_excluding_prefix(child.page_id, prefix, depth + 1)?;
                }
                Ok(count)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    fn node_changed_since(
        &self,
        page_id: u64,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        revision: u64,
        excluded_prefix: Option<&[u8]>,
        depth: usize,
    ) -> Result<bool> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => Ok(self.decode_leaf(&page, page_id)?.into_iter().any(|entry| {
                excluded_prefix.is_none_or(|prefix| !entry.key.as_slice().starts_with(prefix))
                    && start.is_none_or(|start| entry.key.as_slice() >= start)
                    && end.is_none_or(|end| entry.key.as_slice() < end)
                    && entry.revision > revision
            })),
            INTERNAL => {
                let children = self.decode_internal(&page, page_id)?;
                for (index, child) in children.iter().enumerate() {
                    let child_end = children.get(index + 1).map(|next| next.min_key.as_slice());
                    if start.is_some_and(|start| child_end.is_some_and(|end| end <= start))
                        || end.is_some_and(|end| child.min_key.as_slice() >= end)
                    {
                        continue;
                    }
                    if self.node_changed_since(
                        child.page_id,
                        start,
                        end,
                        revision,
                        excluded_prefix,
                        depth + 1,
                    )? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    /// One argument past clippy's comfort: the trailing `depth` is the descent
    /// bound every walker carries, and folding the scan's four filters into a
    /// struct to shave it would obscure a signature that mirrors its callers.
    #[allow(clippy::too_many_arguments)]
    fn scan_node(
        &self,
        page_id: u64,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
        rows: &mut Vec<VersionedRow>,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_TREE_DEPTH {
            return Err(excessive_depth(page_id));
        }
        if rows.len() >= limit {
            return Ok(());
        }
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => {
                for entry in self.decode_leaf(&page, page_id)? {
                    if start.is_some_and(|start| entry.key.as_slice() < start) {
                        continue;
                    }
                    if end.is_some_and(|end| entry.key.as_slice() >= end) {
                        break;
                    }
                    if excluded_prefix
                        .is_some_and(|prefix| entry.key.as_slice().starts_with(prefix))
                    {
                        continue;
                    }
                    // The entry is owned here, so its inline value is MOVED into
                    // the row rather than cloned out of it. `read_value` takes a
                    // reference and has to clone, which meant every row of every
                    // scan allocated its value twice: once in `decode_leaf` and
                    // once here, with the first copy dropped immediately after.
                    let revision = entry.revision;
                    let value = match entry.value {
                        EntryValue::Inline(value) => value.into_vec(),
                        EntryValue::External(reference) => self.values.read(&reference)?,
                    };
                    rows.push((entry.key.into_vec(), value, revision));
                    if rows.len() == limit {
                        break;
                    }
                }
            }
            INTERNAL => {
                let children = self.decode_internal(&page, page_id)?;
                for (index, child) in children.iter().enumerate() {
                    let child_end = children.get(index + 1).map(|next| next.min_key.as_slice());
                    if start.is_some_and(|start| child_end.is_some_and(|end| end <= start))
                        || end.is_some_and(|end| child.min_key.as_slice() >= end)
                    {
                        continue;
                    }
                    self.scan_node(
                        child.page_id,
                        start,
                        end,
                        limit,
                        excluded_prefix,
                        rows,
                        depth + 1,
                    )?;
                    if rows.len() == limit {
                        break;
                    }
                }
            }
            page_type => return Err(unexpected_type(page_id, page_type)),
        }
        Ok(())
    }

    fn find_leaf(&self, key: &[u8], mut path: Option<&mut Vec<(u64, usize)>>) -> Result<u64> {
        let mut page_id = self.root;
        // The descent is bounded like the recursive walkers: a crafted page that
        // names itself (directly or through a ring of children) would otherwise
        // keep this loop spinning forever.
        let mut depth = 0;
        loop {
            if depth >= MAX_TREE_DEPTH {
                return Err(excessive_depth(page_id));
            }
            depth += 1;
            let page = self.pages.read(page_id)?;
            match page[5] {
                LEAF => return Ok(page_id),
                // The separators are compared against the page bytes in place.
                //
                // `decode_internal` was called here, and it does two things this
                // descent has no use for: it allocates an owned key for every
                // child of the page, and — to fill in child 0's minimum, which is
                // not stored in the page — it walks that child's whole leftmost
                // spine to a leaf. So a descent through a three-level tree read
                // its three pages plus two extra spines, and allocated a key per
                // child on every level, to end up following one child pointer per
                // page. Choosing the child by comparing separators where they lie
                // needs neither: child 0 is the answer precisely when the key
                // sorts below separator 1, which is a fact about separator 1.
                INTERNAL => {
                    let (index, child) = self.child_for_key(&page, page_id, key)?;
                    if let Some(path) = path.as_deref_mut() {
                        path.push((page_id, index));
                    }
                    page_id = child;
                }
                page_type => return Err(unexpected_type(page_id, page_type)),
            }
        }
    }

    /// Picks the child of an internal page that owns `key`, without decoding it.
    ///
    /// Returns the child's index within the page and its page id. The index is
    /// what `prepare_put` and `prepare_delete` record in their path so the
    /// copy-on-write rewrite knows which child slot to replace.
    ///
    /// Child 0 owns everything below the first stored separator, so the walk keeps
    /// the last child whose separator is at or below `key` and stops at the first
    /// one above it. Separators ascend, so stopping early is safe.
    fn child_for_key(&self, page: &Page, page_id: u64, key: &[u8]) -> Result<(usize, u64)> {
        let count = read_u32(page, 20) as usize;
        // Same bound and same reasoning as `decode_internal`.
        if count >= MAX_INTERNAL_CHILDREN {
            return Err(Error::CorruptPage {
                page_id,
                reason: format!(
                    "internal page claims {} children but a page holds at most {MAX_INTERNAL_CHILDREN}",
                    count + 1
                ),
            });
        }
        let first_id = read_u64(page, 24);
        // Every child id on the page is checked against the page's own id, not
        // just the one this descent follows.
        //
        // `decode_internal` used to resolve child 0 through `node_ref`, which
        // noticed a page naming itself because it walked into the loop and hit the
        // depth bound. Choosing a child without touching child 0 removed that
        // walk — and with it the detection: a forged page whose first child is
        // itself would be traversed happily by any lookup that lands on a
        // different child, and reported only by the lookups that happen to
        // descend into the cycle. A page can never legitimately be its own child,
        // so the check that used to be a side effect of the spine walk is now
        // explicit and costs a comparison. Longer rings still terminate on the
        // descent's depth bound, as they always did.
        if first_id == page_id {
            return Err(Error::CorruptPage {
                page_id,
                reason: "internal page names itself as its own child".into(),
            });
        }
        let mut chosen = (0, first_id);
        let mut offset = HEADER_SIZE;
        for index in 0..count {
            require_page(offset, INTERNAL_CELL_HEADER, page_id)?;
            let flags = page[offset];
            let key_len = read_u32(page, offset + 1) as usize;
            let key_page = read_u64(page, offset + 5);
            let child_id = read_u64(page, offset + 13);
            if key_len == 0 || key_len > MAX_STORED_KEY_SIZE || flags & !EXTERNAL_KEY != 0 {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "invalid internal cell metadata".into(),
                });
            }
            if child_id == page_id {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "internal page names itself as its own child".into(),
                });
            }
            offset += INTERNAL_CELL_HEADER;
            // An oversized separator lives in a blob and has to be read to be
            // compared; an inline one is compared where it lies, with no copy.
            let below = if flags & EXTERNAL_KEY != 0 {
                self.read_blob(key_page, key_len)?.as_slice() <= key
            } else {
                require_page(offset, key_len, page_id)?;
                let separator = &page[offset..offset + key_len];
                offset += key_len;
                separator <= key
            };
            if !below {
                break;
            }
            // `index` counts separators, and separator 0 introduces child 1.
            chosen = (index + 1, child_id);
        }
        Ok(chosen)
    }

    /// Reads just the first cell's key out of a leaf page.
    ///
    /// The separator work only ever wants this one key, and decoding the page to
    /// get it materialises every other key and value in it as well. Kept beside
    /// `decode_leaf` deliberately: the cell layout is described in one place
    /// there, and this repeats only the first cell's part of it.
    fn first_leaf_key(&self, page: &Arc<Page>, page_id: u64) -> Result<Bytes> {
        let count = read_u32(page.as_ref(), 20) as usize;
        if count == 0 || count > MAX_LEAF_ENTRIES {
            return Err(Error::CorruptPage {
                page_id,
                reason: "empty leaf is reachable".into(),
            });
        }
        let flags = page[HEADER_SIZE];
        let key_len = read_u32(page.as_ref(), HEADER_SIZE + 1) as usize;
        if key_len == 0
            || key_len > MAX_STORED_KEY_SIZE
            || flags & !(EXTERNAL_KEY | EXTERNAL_VALUE) != 0
        {
            return Err(Error::CorruptPage {
                page_id,
                reason: "invalid leaf cell metadata".into(),
            });
        }
        if flags & EXTERNAL_KEY != 0 {
            return Ok(Bytes::Owned(
                self.read_blob(read_u64(page.as_ref(), HEADER_SIZE + 9), key_len)?,
            ));
        }
        let start = HEADER_SIZE + LEAF_CELL_HEADER;
        require_page(start, key_len, page_id)?;
        Ok(Bytes::paged(page, start, key_len))
    }

    fn read_leaf(&self, page_id: u64) -> Result<Vec<Entry>> {
        let page = self.pages.read(page_id)?;
        require_type(&page, page_id, LEAF)?;
        self.decode_leaf(&page, page_id)
    }

    fn read_internal_children(&self, page_id: u64) -> Result<Vec<NodeRef>> {
        let page = self.pages.read(page_id)?;
        require_type(&page, page_id, INTERNAL)?;
        self.decode_internal(&page, page_id)
    }

    fn node_ref(&self, page_id: u64) -> Result<NodeRef> {
        let mut current = page_id;
        // Bounded like every other descent: the first-child field is read
        // straight from each page without validating where it leads, so a page
        // that is its own first descendant would spin here forever.
        let mut depth = 0;
        loop {
            if depth >= MAX_TREE_DEPTH {
                return Err(excessive_depth(current));
            }
            depth += 1;
            let page = self.pages.read(current)?;
            match page[5] {
                // Only the first cell's key is read, never the whole leaf.
                // `decode_leaf` was called here, which allocates a `Vec` for the
                // key AND one for the value of every entry in the page — up to a
                // hundred allocations and a copy of the page's whole payload — of
                // which this function keeps exactly one key and drops the rest.
                // It runs once per internal page a commit rewrites, so on a batch
                // that touches several levels it was one of the larger allocation
                // sources on the write path.
                LEAF => {
                    return Ok(NodeRef {
                        page_id,
                        min_key: self.first_leaf_key(&page, current)?,
                    })
                }
                // The first child's page id is a fixed header field, which is
                // exactly what `decode_internal` reads to build `children[0]`.
                // Going through the full decode to reach it allocated a key for
                // every child of every page on the way down, and because
                // `decode_internal` calls back into `node_ref` for its own first
                // child, the two recursed into each other once per level — so a
                // single decode of a root page walked and re-decoded the whole
                // leftmost spine.
                INTERNAL => current = read_u64(page.as_slice(), 24),
                page_type => return Err(unexpected_type(current, page_type)),
            }
        }
    }

    fn write_leaf_level(&mut self, entries: &[Entry]) -> Result<Vec<NodeRef>> {
        // Page boundaries are recorded as index ranges into `entries` rather than
        // by moving the entries into owned per-page vectors. Cloning them there
        // duplicated every key and value in the page — which `decode_leaf` had
        // just allocated and `write_leaf` is about to copy into the page anyway —
        // on a path that runs once per leaf touched by a batch.
        let mut bounds: Vec<(usize, usize)> = Vec::new();
        let mut start = 0;
        let mut used = HEADER_SIZE;
        for (index, entry) in entries.iter().enumerate() {
            let size = leaf_cell_size(entry);
            if size > PAGE_SIZE - HEADER_SIZE {
                return Err(Error::CorruptPage {
                    page_id: 0,
                    reason: "leaf cell exceeds page size".into(),
                });
            }
            // `index > start` is the old "current chunk is not empty" guard: an
            // entry never starts a new page when the current one holds nothing.
            if used + size > PAGE_SIZE && index > start {
                bounds.push((start, index));
                start = index;
                used = HEADER_SIZE;
            }
            used += size;
        }
        bounds.push((start, entries.len()));
        bounds
            .into_iter()
            .map(|(from, to)| self.write_leaf(&entries[from..to]))
            .collect()
    }

    fn write_leaf(&mut self, entries: &[Entry]) -> Result<NodeRef> {
        let started = std::time::Instant::now();
        let first = entries.first().ok_or_else(|| Error::CorruptPage {
            page_id: 0,
            reason: "cannot write an empty leaf".into(),
        })?;
        let mut page = new_page(LEAF, 0);
        write_u32(&mut page, 20, entries.len() as u32);
        let mut offset = HEADER_SIZE;
        for entry in entries {
            offset = self.encode_leaf_cell(&mut page, offset, entry)?;
        }
        crate::profile::add(&crate::profile::TREE_ENCODE_NS, started);
        let page_id = self.pages.append(page)?;
        Ok(NodeRef {
            page_id,
            min_key: first.key.clone(),
        })
    }

    fn write_internal_level(&mut self, children: &[NodeRef]) -> Result<Vec<NodeRef>> {
        // Page boundaries are index ranges into `children`, exactly as
        // `write_leaf_level` records them into `entries` and for the same
        // reason: chunking by moving children into per-page vectors cloned
        // every child's min_key, and a commit that touches one child of a
        // hundred-way level still cloned all hundred.
        let mut bounds: Vec<(usize, usize)> = Vec::new();
        let mut start = 0;
        let mut used = HEADER_SIZE + 8;
        for (index, child) in children.iter().enumerate() {
            // The first child of each page lives in the header rather than in a
            // body cell, so it costs no cell space and can never overflow the
            // page on its own; `index > start` is the "current page is not
            // empty" guard.
            if index > start {
                let size = internal_cell_size(child.min_key.as_slice());
                if used + size > PAGE_SIZE {
                    bounds.push((start, index));
                    start = index;
                    used = HEADER_SIZE + 8;
                } else {
                    used += size;
                }
            }
        }
        bounds.push((start, children.len()));
        bounds
            .into_iter()
            .map(|(from, to)| self.write_internal(&children[from..to]))
            .collect()
    }

    fn write_internal(&mut self, children: &[NodeRef]) -> Result<NodeRef> {
        let started = std::time::Instant::now();
        let first = children.first().ok_or_else(|| Error::CorruptPage {
            page_id: 0,
            reason: "cannot write an empty internal page".into(),
        })?;
        let mut page = new_page(INTERNAL, 0);
        write_u32(&mut page, 20, (children.len() - 1) as u32);
        write_u64(&mut page, 24, first.page_id);
        let mut offset = HEADER_SIZE;
        for child in children.iter().skip(1) {
            offset = self.encode_internal_cell(&mut page, offset, child)?;
        }
        crate::profile::add(&crate::profile::TREE_ENCODE_NS, started);
        let page_id = self.pages.append(page)?;
        Ok(NodeRef {
            page_id,
            min_key: first.min_key.clone(),
        })
    }

    fn encode_leaf_cell(
        &mut self,
        page: &mut Page,
        mut offset: usize,
        entry: &Entry,
    ) -> Result<usize> {
        let key_external = entry.key.len() > INLINE_LIMIT;
        let value_external = matches!(entry.value, EntryValue::External(_));
        let value_len = match &entry.value {
            EntryValue::Inline(value) => value.len(),
            EntryValue::External(reference) => reference.len as usize,
        };
        let flags =
            (u8::from(key_external) * EXTERNAL_KEY) | (u8::from(value_external) * EXTERNAL_VALUE);
        page[offset] = flags;
        write_u32(page, offset + 1, entry.key.len() as u32);
        write_u32(page, offset + 5, value_len as u32);
        let key_page = if key_external {
            self.write_blob(entry.key.as_slice())?.0
        } else {
            0
        };
        let value_offset = match &entry.value {
            EntryValue::Inline(_) => 0,
            EntryValue::External(reference) => reference.offset,
        };
        write_u64(page, offset + 9, key_page);
        write_u64(page, offset + 17, value_offset);
        write_u64(page, offset + 25, entry.revision);
        offset += LEAF_CELL_HEADER;
        if !key_external {
            page[offset..offset + entry.key.len()].copy_from_slice(entry.key.as_slice());
            offset += entry.key.len();
        }
        if let EntryValue::Inline(value) = &entry.value {
            page[offset..offset + value.len()].copy_from_slice(value.as_slice());
            offset += value.len();
        }
        Ok(offset)
    }

    fn decode_leaf(&self, page: &Arc<Page>, page_id: u64) -> Result<Vec<Entry>> {
        let started = std::time::Instant::now();
        let result = self.decode_leaf_inner(page, page_id);
        crate::profile::add(&crate::profile::TREE_DECODE_NS, started);
        result
    }

    fn decode_leaf_inner(&self, page: &Arc<Page>, page_id: u64) -> Result<Vec<Entry>> {
        let count = read_u32(page.as_ref(), 20) as usize;
        // The count is trusted only up to what the page can physically hold.
        // Beyond that it is a forged field, and it used to reach
        // `Vec::with_capacity` directly — a crafted page could ask the
        // allocator for gigabytes and take the process down with it. Every
        // legitimate entry needs its cell header inside this page, so anything
        // over [`MAX_LEAF_ENTRIES`] is corruption by arithmetic alone.
        if count > MAX_LEAF_ENTRIES {
            return Err(Error::CorruptPage {
                page_id,
                reason: format!(
                    "leaf claims {count} entries but a page holds at most {MAX_LEAF_ENTRIES}"
                ),
            });
        }
        let mut offset = HEADER_SIZE;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            require_page(offset, LEAF_CELL_HEADER, page_id)?;
            let flags = page[offset];
            let key_len = read_u32(page.as_ref(), offset + 1) as usize;
            let value_len = read_u32(page.as_ref(), offset + 5) as usize;
            if key_len == 0
                || key_len > MAX_STORED_KEY_SIZE
                || value_len > MAX_VALUE_SIZE
                || flags & !(EXTERNAL_KEY | EXTERNAL_VALUE) != 0
            {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "invalid leaf cell metadata".into(),
                });
            }
            let key_page = read_u64(page.as_ref(), offset + 9);
            let value_offset = read_u64(page.as_ref(), offset + 17);
            let revision = read_u64(page.as_ref(), offset + 25);
            offset += LEAF_CELL_HEADER;
            let key = if flags & EXTERNAL_KEY != 0 {
                Bytes::Owned(self.read_blob(key_page, key_len)?)
            } else {
                require_page(offset, key_len, page_id)?;
                let key = Bytes::paged(page, offset, key_len);
                offset += key_len;
                key
            };
            let value = if flags & EXTERNAL_VALUE != 0 {
                EntryValue::External(ValueRef {
                    offset: value_offset,
                    len: value_len as u32,
                    revision,
                })
            } else {
                require_page(offset, value_len, page_id)?;
                let value = Bytes::paged(page, offset, value_len);
                offset += value_len;
                EntryValue::Inline(value)
            };
            entries.push(Entry {
                key,
                value,
                revision,
            });
        }
        Ok(entries)
    }

    fn encode_internal_cell(
        &mut self,
        page: &mut Page,
        mut offset: usize,
        child: &NodeRef,
    ) -> Result<usize> {
        let external = child.min_key.len() > INLINE_LIMIT;
        page[offset] = u8::from(external) * EXTERNAL_KEY;
        write_u32(page, offset + 1, child.min_key.len() as u32);
        let key_page = if external {
            self.write_blob(child.min_key.as_slice())?.0
        } else {
            0
        };
        write_u64(page, offset + 5, key_page);
        write_u64(page, offset + 13, child.page_id);
        offset += INTERNAL_CELL_HEADER;
        if !external {
            page[offset..offset + child.min_key.len()].copy_from_slice(child.min_key.as_slice());
            offset += child.min_key.len();
        }
        Ok(offset)
    }

    fn decode_internal(&self, page: &Arc<Page>, page_id: u64) -> Result<Vec<NodeRef>> {
        let started = std::time::Instant::now();
        let result = self.decode_internal_inner(page, page_id);
        crate::profile::add(&crate::profile::TREE_DECODE_NS, started);
        result
    }

    fn decode_internal_inner(&self, page: &Arc<Page>, page_id: u64) -> Result<Vec<NodeRef>> {
        let count = read_u32(page.as_ref(), 20) as usize;
        // `count` is the children past the first, which lives in the header.
        // The per-cell bounds below already stop the loop once the body runs
        // out, so nothing here allocates from the count — but rejecting a
        // page-impossible child count up front reports the forged field as what
        // it is instead of letting the descent discover it one cell at a time.
        if count >= MAX_INTERNAL_CHILDREN {
            return Err(Error::CorruptPage {
                page_id,
                reason: format!(
                    "internal page claims {} children but a page holds at most {MAX_INTERNAL_CHILDREN}",
                    count + 1
                ),
            });
        }
        let first_id = read_u64(page.as_ref(), 24);
        let first = self.node_ref(first_id)?;
        let mut children = vec![first];
        let mut offset = HEADER_SIZE;
        for _ in 0..count {
            require_page(offset, INTERNAL_CELL_HEADER, page_id)?;
            let flags = page[offset];
            let key_len = read_u32(page.as_ref(), offset + 1) as usize;
            let key_page = read_u64(page.as_ref(), offset + 5);
            let child_id = read_u64(page.as_ref(), offset + 13);
            if key_len == 0 || key_len > MAX_STORED_KEY_SIZE || flags & !EXTERNAL_KEY != 0 {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "invalid internal cell metadata".into(),
                });
            }
            offset += INTERNAL_CELL_HEADER;
            let min_key = if flags & EXTERNAL_KEY != 0 {
                Bytes::Owned(self.read_blob(key_page, key_len)?)
            } else {
                require_page(offset, key_len, page_id)?;
                let key = Bytes::paged(page, offset, key_len);
                offset += key_len;
                key
            };
            children.push(NodeRef {
                page_id: child_id,
                min_key,
            });
        }
        Ok(children)
    }

    fn write_blob(&mut self, bytes: &[u8]) -> Result<(u64, u32)> {
        if bytes.is_empty() {
            return Ok((0, 0));
        }
        let chunks: Vec<&[u8]> = bytes.chunks(PAGE_SIZE - HEADER_SIZE).collect();
        let first_page = self.pages.page_count();
        for (index, chunk) in chunks.iter().enumerate() {
            let page_id = self.pages.page_count();
            let next = if index + 1 == chunks.len() {
                0
            } else {
                page_id + 1
            };
            let mut page = new_page(BLOB, 0);
            write_u32(&mut page, 20, chunk.len() as u32);
            write_u64(&mut page, 24, next);
            page[HEADER_SIZE..HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
            self.pages.append(page)?;
        }
        Ok((first_page, bytes.len() as u32))
    }

    fn read_blob(&self, first_page: u64, expected_len: usize) -> Result<Vec<u8>> {
        if expected_len == 0 {
            return if first_page == 0 {
                Ok(Vec::new())
            } else {
                Err(Error::CorruptPage {
                    page_id: first_page,
                    reason: "empty blob has a page reference".into(),
                })
            };
        }
        let mut result = Vec::with_capacity(expected_len);
        let mut page_id = first_page;
        let max_pages = expected_len.div_ceil(PAGE_SIZE - HEADER_SIZE);
        for _ in 0..max_pages {
            if page_id == 0 {
                break;
            }
            let page = self.pages.read(page_id)?;
            require_type(&page, page_id, BLOB)?;
            let chunk_len = read_u32(page.as_ref(), 20) as usize;
            if chunk_len > PAGE_SIZE - HEADER_SIZE || result.len() + chunk_len > expected_len {
                return Err(Error::CorruptPage {
                    page_id,
                    reason: "invalid blob chunk length".into(),
                });
            }
            result.extend_from_slice(&page[HEADER_SIZE..HEADER_SIZE + chunk_len]);
            page_id = read_u64(page.as_ref(), 24);
        }
        if result.len() != expected_len || page_id != 0 {
            return Err(Error::CorruptPage {
                page_id: first_page,
                reason: "blob length does not match reference".into(),
            });
        }
        Ok(result)
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

#[cfg(unix)]
fn write_all_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buffer, offset)
}

/// Windows has no `write_all_at`, so the partial-write loop is spelled out.
///
/// A short write is retried at the offset it stopped at rather than treated as
/// success, and a zero-length write is an error instead of an infinite loop —
/// this is the same shape as the WAL's own positioned write.
#[cfg(windows)]
fn write_all_at(file: &File, buffer: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0;
    while written < buffer.len() {
        match file.seek_write(&buffer[written..], offset + written as u64) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ))
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Merges sorted mutations into a leaf's sorted entries.
///
/// Records in `existed` whether each key was already present before the batch, so
/// the caller can maintain its entry count and report delete results. Repeated
/// mutations of one key collapse to the last one, and only the first of them sees
/// the pre-batch state.
fn merge_entries(
    entries: Vec<Entry>,
    mutations: &[PreparedMutation],
    existed: &mut [bool],
) -> Vec<Entry> {
    let mut merged: Vec<Entry> = Vec::with_capacity(entries.len() + mutations.len());
    let mut entries = entries.into_iter().peekable();
    let mut index = 0;
    while index < mutations.len() {
        let key = &mutations[index].key;
        // Carry over every entry that sorts before this key.
        while entries
            .peek()
            .is_some_and(|entry| entry.key.as_slice() < key.as_slice())
        {
            merged.push(entries.next().unwrap());
        }
        let present = entries
            .peek()
            .is_some_and(|entry| entry.key.as_slice() == key.as_slice());
        if present {
            entries.next();
        }
        // Collapse a run of mutations on the same key; the last one wins.
        let mut last = index;
        while last + 1 < mutations.len() && &mutations[last + 1].key == key {
            last += 1;
        }
        for mutation in &mutations[index..=last] {
            existed[mutation.index] = present;
        }
        if let Some((value, revision)) = &mutations[last].value {
            merged.push(Entry {
                key: Bytes::Owned(key.clone()),
                value: value.clone(),
                revision: *revision,
            });
        }
        index = last + 1;
    }
    merged.extend(entries);
    merged
}

fn find_entry(entries: &[Entry], key: &[u8]) -> (usize, bool) {
    match entries.binary_search_by(|entry| entry.key.as_slice().cmp(key)) {
        Ok(index) => (index, true),
        Err(index) => (index, false),
    }
}

fn leaf_cell_size(entry: &Entry) -> usize {
    LEAF_CELL_HEADER
        + if entry.key.len() <= INLINE_LIMIT {
            entry.key.len()
        } else {
            0
        }
        + match &entry.value {
            EntryValue::Inline(value) => value.len(),
            EntryValue::External(_) => 0,
        }
}

fn internal_cell_size(key: &[u8]) -> usize {
    INTERNAL_CELL_HEADER
        + if key.len() <= INLINE_LIMIT {
            key.len()
        } else {
            0
        }
}

fn require_page(offset: usize, length: usize, page_id: u64) -> Result<()> {
    if offset.checked_add(length).is_none_or(|end| end > PAGE_SIZE) {
        Err(Error::CorruptPage {
            page_id,
            reason: "cell exceeds page boundary".into(),
        })
    } else {
        Ok(())
    }
}

fn new_page(page_type: u8, page_id: u64) -> Page {
    let mut page = [0; PAGE_SIZE];
    page[0..4].copy_from_slice(MAGIC);
    page[4] = VERSION;
    page[5] = page_type;
    write_u64(&mut page, 8, page_id);
    page
}

fn finalize_page(page: &mut Page) {
    write_u32(page, 16, 0);
    let mut hasher = Hasher::new();
    hasher.update(page);
    write_u32(page, 16, hasher.finalize());
}

fn validate_page(page: &mut Page, page_id: u64) -> Result<()> {
    if &page[0..4] != MAGIC || page[4] != VERSION || read_u64(page, 8) != page_id {
        return Err(Error::CorruptPage {
            page_id,
            reason: "invalid page header".into(),
        });
    }
    let expected = read_u32(page, 16);
    write_u32(page, 16, 0);
    let mut hasher = Hasher::new();
    hasher.update(page);
    let actual = hasher.finalize();
    write_u32(page, 16, expected);
    if expected != actual {
        return Err(Error::CorruptPage {
            page_id,
            reason: "checksum mismatch".into(),
        });
    }
    Ok(())
}

fn require_type(page: &Page, page_id: u64, expected: u8) -> Result<()> {
    if page[5] != expected {
        Err(unexpected_type(page_id, page[5]))
    } else {
        Ok(())
    }
}

fn unexpected_type(page_id: u64, page_type: u8) -> Error {
    Error::CorruptPage {
        page_id,
        reason: format!("unexpected page type {page_type}"),
    }
}

/// The error every traversal raises once [`MAX_TREE_DEPTH`] is exceeded.
fn excessive_depth(page_id: u64) -> Error {
    Error::CorruptPage {
        page_id,
        reason: format!(
            "tree descent deeper than {MAX_TREE_DEPTH} levels; the page graph is cyclic or forged"
        ),
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
    use tempfile::tempdir;

    /// Rewrites one page of a page file with mutated contents behind a valid
    /// checksum. This is exactly what a crafted database looks like: the
    /// checksum protects against rot, not against whoever rewrites the bytes,
    /// so every field the decoders trust has to stand on its own.
    fn forge_page(path: &Path, page_id: u64, mutate: impl FnOnce(&mut Page)) {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut page = [0; PAGE_SIZE];
        read_exact_at(&file, &mut page, page_id * PAGE_SIZE as u64).unwrap();
        mutate(&mut page);
        finalize_page(&mut page);
        write_all_at(&file, &page, page_id * PAGE_SIZE as u64).unwrap();
        file.sync_all().unwrap();
    }

    /// Builds a tree tall enough that its root is an internal page spanning
    /// several leaves, which is what the descent guards below need to bite.
    fn tree_with_internal_root(path: &Path, values: &Path) -> (u64, u64) {
        let mut tree = PageTree::open(path, values, 0, 0).unwrap();
        let mut state = (0, 0);
        for index in 0..200_u64 {
            let key = format!("key-{index:06}");
            state = tree
                .prepare_put(key.as_bytes(), &[7; 40], index + 1)
                .unwrap();
            tree.publish(state.0, state.1);
        }
        tree.sync().unwrap();
        assert_eq!(
            tree.pages.read(state.0).unwrap()[5],
            INTERNAL,
            "this test needs a tree whose root is an internal page"
        );
        state
    }

    /// A forged entry count used to flow straight into `Vec::with_capacity`,
    /// turning four on-disk bytes into a quarter-terabyte allocation request
    /// that took the whole process down. A count above what a page can
    /// physically hold is corruption by arithmetic alone.
    #[test]
    fn a_forged_leaf_entry_count_is_reported_not_allocated() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let root = {
            let mut tree = PageTree::open(&path, &values, 0, 0).unwrap();
            let state = tree.prepare_put(b"key", b"value", 1).unwrap();
            tree.publish(state.0, state.1);
            tree.sync().unwrap();
            state.0
        };
        // A one-entry tree's root is its only leaf, so the very first decode
        // meets the forged count on the way to the data.
        forge_page(&path, root, |page| write_u32(page, 20, u32::MAX));
        let tree = PageTree::open(&path, &values, root, 1).unwrap();
        let error = tree.get(b"key").unwrap_err();
        assert!(
            matches!(error, Error::CorruptPage { .. }),
            "a forged entry count must be reported as corruption, got {error:?}"
        );
    }

    /// The internal-page sibling: children past the first each need a cell in
    /// the page body, so an impossible child count is corruption however the
    /// bytes got that way.
    #[test]
    fn a_forged_internal_child_count_is_reported_not_walked() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let (root, len) = tree_with_internal_root(&path, &values);
        forge_page(&path, root, |page| write_u32(page, 20, u32::MAX));
        let tree = PageTree::open(&path, &values, root, len).unwrap();
        let error = tree.get(b"key-000100").unwrap_err();
        assert!(
            matches!(error, Error::CorruptPage { .. }),
            "a forged child count must be reported as corruption, got {error:?}"
        );
    }

    /// An internal page naming itself as its own first descendant used to walk
    /// every traversal forever — the first-child field was followed without
    /// ever asking where the chain led.
    #[test]
    fn an_internal_page_that_is_its_own_descendant_is_reported() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let (root, len) = tree_with_internal_root(&path, &values);
        forge_page(&path, root, |page| write_u64(page, 24, root));
        let tree = PageTree::open(&path, &values, root, len).unwrap();
        // Point lookups descend through `find_leaf`; scans walk recursively.
        // Both must come back as corruption instead of hanging.
        for attempted in [
            tree.get(b"key-000100").err(),
            tree.scan(None, None, 10).err(),
            tree.count_excluding_prefix(b"key").err(),
        ] {
            let error = attempted.expect("every traversal of a cyclic tree must fail");
            assert!(
                matches!(error, Error::CorruptPage { .. }),
                "a cyclic page graph must be reported as corruption, got {error:?}"
            );
        }
    }

    /// A failed batch must not leave orphan pages behind — neither on disk nor
    /// as allocated page ids.
    ///
    /// Appended pages are buffered until the mutation returns, so a batch that
    /// fails mid-apply — here on a corrupt sibling leaf, after an earlier leaf
    /// was already rewritten — discards what it buffered. Before the buffer
    /// existed those pages were already on disk and stayed there as permanent
    /// orphans; now the failure leaves the page file exactly as it found it.
    #[test]
    fn a_failed_batch_discards_its_buffered_pages_and_their_ids() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let (root, len) = tree_with_internal_root(&path, &values);
        // Locate the victim leaf with a throwaway tree, then forge it on disk;
        // the tree under test must not have the honest copy cached.
        let victim = {
            let tree = PageTree::open(&path, &values, root, len).unwrap();
            tree.find_leaf(b"key-000199", None).unwrap()
        };
        assert_ne!(
            victim,
            {
                let tree = PageTree::open(&path, &values, root, len).unwrap();
                tree.find_leaf(b"key-000000", None).unwrap()
            },
            "this test needs the two keys on different leaves"
        );
        forge_page(&path, victim, |page| page[4] = 99);
        let mut tree = PageTree::open(&path, &values, root, len).unwrap();
        let pages_before = tree.page_count();
        // Sorted order routes the healthy leaf's rewrite first, so pages are
        // already buffered when the descent meets the forged leaf.
        let mutations = vec![
            (
                b"key-000000".to_vec(),
                Mutation::Put {
                    value: vec![1; 10],
                    revision: 900,
                },
            ),
            (
                b"key-000199".to_vec(),
                Mutation::Put {
                    value: vec![2; 10],
                    revision: 900,
                },
            ),
        ];
        let error = tree.prepare_batch(mutations).unwrap_err();
        assert!(
            matches!(error, Error::CorruptPage { .. }),
            "the forged leaf must surface as corruption, got {error:?}"
        );
        assert_eq!(
            tree.page_count(),
            pages_before,
            "a failed batch must not leave orphan pages or ids behind"
        );
        // The tree it found is the tree it leaves: untouched keys still read.
        assert!(tree.get(b"key-000000").unwrap().is_some());
    }

    /// A point lookup must return the same answer whether or not it took the
    /// in-place cell walk, across every shape of stored entry.
    ///
    /// `get_with_revision` used to reach its one entry by calling `decode_leaf`,
    /// which allocates a key `Vec` and a value `Vec` for every entry in the page
    /// — about two hundred allocations to answer a lookup that keeps one of them.
    /// It now walks the cells in place and copies only the entry it matched, so
    /// this covers the cases that walk has to get right by itself: inline values,
    /// external (value-log) values, external keys, and a miss that falls between
    /// two present keys.
    #[test]
    fn a_point_lookup_matches_a_full_leaf_decode() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let mut tree = PageTree::open(&path, &values, 0, 0).unwrap();
        // Deliberately mixed: short inline values, values over INLINE_LIMIT that
        // live in the value log, and a key over INLINE_LIMIT that becomes a blob.
        let long_key = vec![b'k'; INLINE_LIMIT + 10];
        let mut expected: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for index in 0..300_u64 {
            let key = format!("entry/{index:06}").into_bytes();
            let value = match index % 3 {
                0 => vec![(index % 251) as u8; 8],
                1 => vec![(index % 251) as u8; INLINE_LIMIT + 1],
                _ => Vec::new(),
            };
            let (root, len) = tree.prepare_put(&key, &value, index + 1).unwrap();
            tree.publish(root, len);
            expected.push((key, value));
        }
        let (root, len) = tree.prepare_put(&long_key, b"blobkey", 1_000).unwrap();
        tree.publish(root, len);
        expected.push((long_key, b"blobkey".to_vec()));
        tree.sync().unwrap();

        for (key, value) in &expected {
            assert_eq!(
                tree.get(key).unwrap().as_ref(),
                Some(value),
                "point lookup disagreed with what was written"
            );
        }
        // Misses either side of a present key, and between two of them.
        for missing in [
            b"entry/000000/x".to_vec(),
            b"entry".to_vec(),
            b"entry/0000005".to_vec(),
            b"zzz".to_vec(),
        ] {
            assert_eq!(tree.get(&missing).unwrap(), None, "phantom hit");
        }
    }

    #[test]
    fn inline_records_split_reopen_and_overflow() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let (root, len, pages) = {
            let mut tree = PageTree::open(&path, &values, 0, 0).unwrap();
            for index in 0..1_500_u32 {
                let key = format!("key-{index:06}");
                let value =
                    vec![(index % 251) as u8; if index == 777 { PAGE_SIZE * 2 } else { 40 }];
                let (root, len) = tree
                    .prepare_put(key.as_bytes(), &value, index as u64 + 1)
                    .unwrap();
                tree.publish(root, len);
            }
            tree.sync().unwrap();
            assert_eq!(
                std::fs::metadata(&values).unwrap().len(),
                (PAGE_SIZE * 2 + crate::value_log::record_overhead()) as u64,
                "copy-on-write leaf rewrites must preserve value-log references"
            );
            assert_eq!(
                tree.get(b"key-000777").unwrap().unwrap().len(),
                PAGE_SIZE * 2
            );
            (tree.root_id(), tree.len(), tree.page_count())
        };
        assert!(
            pages < 5_000,
            "inline records should avoid two blob pages per write"
        );
        let tree = PageTree::open(&path, &values, root, len).unwrap();
        tree.validate().unwrap();
        assert_eq!(
            tree.scan(Some(b"key-000500"), Some(b"key-000510"), 100)
                .unwrap()
                .len(),
            10
        );
    }

    #[test]
    fn uncommitted_pages_are_not_visible_after_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pages.vdb");
        let values = directory.path().join("values.vlog");
        let mut tree = PageTree::open(&path, &values, 0, 0).unwrap();
        let (root, len) = tree.prepare_put(b"committed", b"yes", 1).unwrap();
        tree.sync().unwrap();
        tree.publish(root, len);
        let _ = tree.prepare_put(b"uncommitted", b"no", 2).unwrap();
        tree.sync().unwrap();
        drop(tree);
        let tree = PageTree::open(&path, &values, root, len).unwrap();
        assert_eq!(tree.get(b"committed").unwrap(), Some(b"yes".to_vec()));
        assert_eq!(tree.get(b"uncommitted").unwrap(), None);
    }
}
