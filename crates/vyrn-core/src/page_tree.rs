use crate::{
    value_log::{ValueLog, ValueRef},
    Error, Result, MAX_STORED_KEY_SIZE, MAX_VALUE_SIZE,
};
use crc32fast::Hasher;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
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

type Page = [u8; PAGE_SIZE];
type VersionedRow = (Vec<u8>, Vec<u8>, u64);

#[derive(Clone, Debug)]
struct Entry {
    key: Vec<u8>,
    value: EntryValue,
    revision: u64,
}

#[derive(Clone, Debug)]
enum EntryValue {
    Inline(Vec<u8>),
    External(ValueRef),
}

#[derive(Clone, Debug)]
struct NodeRef {
    page_id: u64,
    min_key: Vec<u8>,
}

struct PageCache {
    pages: HashMap<u64, Arc<Page>>,
    clock: VecDeque<u64>,
}

struct PageManager {
    file: File,
    page_count: u64,
    cache: Mutex<PageCache>,
    cache_capacity: usize,
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
        let file_len = file.metadata()?.len();
        if file_len % PAGE_SIZE as u64 != 0 {
            return Err(Error::CorruptPage {
                page_id: 0,
                reason: "page file length is not page-aligned".into(),
            });
        }
        let page_count = file_len / PAGE_SIZE as u64;
        let manager = Self {
            file,
            page_count,
            cache: Mutex::new(PageCache {
                pages: HashMap::new(),
                clock: VecDeque::new(),
            }),
            cache_capacity: cache_capacity.max(1),
        };
        let super_page = manager.read(0)?;
        require_type(&super_page, 0, SUPER)?;
        Ok(manager)
    }

    fn read(&self, page_id: u64) -> Result<Arc<Page>> {
        if let Some(page) = self
            .cache
            .lock()
            .map_err(|_| Error::Poisoned)?
            .pages
            .get(&page_id)
            .cloned()
        {
            return Ok(page);
        }
        if page_id >= self.page_count {
            return Err(Error::CorruptPage {
                page_id,
                reason: "page reference is out of bounds".into(),
            });
        }
        let mut page = [0; PAGE_SIZE];
        read_exact_at(&self.file, &mut page, page_id * PAGE_SIZE as u64)?;
        validate_page(&mut page, page_id)?;
        let page = Arc::new(page);
        self.insert_cache(page_id, Arc::clone(&page))?;
        Ok(page)
    }

    fn append(&mut self, mut page: Page) -> Result<u64> {
        let page_id = self.page_count;
        write_u64(&mut page, 8, page_id);
        finalize_page(&mut page);
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&page)?;
        self.page_count += 1;
        self.insert_cache(page_id, Arc::new(page))?;
        Ok(page_id)
    }

    fn sync(&self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    fn page_count(&self) -> u64 {
        self.page_count
    }

    fn refresh_page_count(&mut self) -> Result<()> {
        let file_len = self.file.metadata()?.len();
        if file_len % PAGE_SIZE as u64 != 0 {
            return Err(Error::CorruptPage {
                page_id: 0,
                reason: "page file length is not page-aligned".into(),
            });
        }
        self.page_count = file_len / PAGE_SIZE as u64;
        Ok(())
    }

    fn insert_cache(&self, page_id: u64, page: Arc<Page>) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|_| Error::Poisoned)?;
        if cache.pages.insert(page_id, page).is_none() {
            cache.clock.push_back(page_id);
        }
        while cache.pages.len() > self.cache_capacity {
            if let Some(candidate) = cache.clock.pop_front() {
                cache.pages.remove(&candidate);
            }
        }
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
        let pages = PageManager::open(path, DEFAULT_CACHE_PAGES)?;
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
        self.count_node_excluding_prefix(self.root, prefix)
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

    pub(crate) fn sync(&self) -> Result<()> {
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
            self.validate_node(self.root, None, None, &mut visited)?
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

    fn get_with_revision(&self, key: &[u8]) -> Result<Option<(Vec<u8>, u64)>> {
        if self.root == 0 {
            return Ok(None);
        }
        let leaf = self.find_leaf(key, None)?;
        for entry in self.read_leaf(leaf)? {
            match entry.key.as_slice().cmp(key) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => {
                    return Ok(Some((self.read_value(&entry.value)?, entry.revision)))
                }
                std::cmp::Ordering::Greater => return Ok(None),
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
        let value = if value.len() > INLINE_LIMIT {
            EntryValue::External(self.values.append(value, revision)?)
        } else {
            EntryValue::Inline(value.to_vec())
        };
        let new_entry = Entry {
            key: key.to_vec(),
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

    pub(crate) fn prepare_delete(&mut self, key: &[u8]) -> Result<Option<(u64, u64)>> {
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
        self.node_changed_since(self.root, start, end, revision, excluded_prefix)
    }

    fn scan_with_revisions_excluding_prefix(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
    ) -> Result<Vec<VersionedRow>> {
        let mut rows = Vec::with_capacity(limit.min(1024));
        if self.root != 0 && limit != 0 {
            self.scan_node(self.root, start, end, limit, excluded_prefix, &mut rows)?;
        }
        Ok(rows)
    }

    fn validate_node(
        &self,
        page_id: u64,
        lower: Option<Vec<u8>>,
        upper: Option<Vec<u8>>,
        visited: &mut HashSet<u64>,
    ) -> Result<u64> {
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
                        || lower.as_ref().is_some_and(|lower| &entry.key < lower)
                        || upper.as_ref().is_some_and(|upper| &entry.key >= upper)
                    {
                        return Err(Error::CorruptPage {
                            page_id,
                            reason: "leaf keys are not strictly ordered within bounds".into(),
                        });
                    }
                    previous = Some(&entry.key);
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
                    if pair[0] >= pair[1] {
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
                    total +=
                        self.validate_node(child.page_id, child_lower, child_upper, visited)?;
                }
                Ok(total)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    fn count_node_excluding_prefix(&self, page_id: u64, prefix: &[u8]) -> Result<usize> {
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => Ok(self
                .decode_leaf(&page, page_id)?
                .into_iter()
                .filter(|entry| !entry.key.starts_with(prefix))
                .count()),
            INTERNAL => {
                let mut count = 0;
                for child in self.decode_internal(&page, page_id)? {
                    count += self.count_node_excluding_prefix(child.page_id, prefix)?;
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
    ) -> Result<bool> {
        let page = self.pages.read(page_id)?;
        match page[5] {
            LEAF => Ok(self.decode_leaf(&page, page_id)?.into_iter().any(|entry| {
                excluded_prefix.is_none_or(|prefix| !entry.key.starts_with(prefix))
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
                    )? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            page_type => Err(unexpected_type(page_id, page_type)),
        }
    }

    fn scan_node(
        &self,
        page_id: u64,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        limit: usize,
        excluded_prefix: Option<&[u8]>,
        rows: &mut Vec<VersionedRow>,
    ) -> Result<()> {
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
                    if excluded_prefix.is_some_and(|prefix| entry.key.starts_with(prefix)) {
                        continue;
                    }
                    let value = self.read_value(&entry.value)?;
                    rows.push((entry.key, value, entry.revision));
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
                    self.scan_node(child.page_id, start, end, limit, excluded_prefix, rows)?;
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
        loop {
            let page = self.pages.read(page_id)?;
            match page[5] {
                LEAF => return Ok(page_id),
                INTERNAL => {
                    let children = self.decode_internal(&page, page_id)?;
                    let mut index = 0;
                    for (child_index, child) in children.iter().enumerate().skip(1) {
                        if key < child.min_key.as_slice() {
                            break;
                        }
                        index = child_index;
                    }
                    if let Some(path) = path.as_deref_mut() {
                        path.push((page_id, index));
                    }
                    page_id = children[index].page_id;
                }
                page_type => return Err(unexpected_type(page_id, page_type)),
            }
        }
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
        loop {
            let page = self.pages.read(current)?;
            match page[5] {
                LEAF => {
                    let entries = self.decode_leaf(&page, current)?;
                    let first = entries.first().ok_or_else(|| Error::CorruptPage {
                        page_id: current,
                        reason: "empty leaf is reachable".into(),
                    })?;
                    return Ok(NodeRef {
                        page_id,
                        min_key: first.key.clone(),
                    });
                }
                INTERNAL => current = self.decode_internal(&page, current)?[0].page_id,
                page_type => return Err(unexpected_type(current, page_type)),
            }
        }
    }

    fn write_leaf_level(&mut self, entries: &[Entry]) -> Result<Vec<NodeRef>> {
        let mut chunks: Vec<Vec<Entry>> = vec![Vec::new()];
        let mut used = HEADER_SIZE;
        for entry in entries {
            let size = leaf_cell_size(entry);
            if size > PAGE_SIZE - HEADER_SIZE {
                return Err(Error::CorruptPage {
                    page_id: 0,
                    reason: "leaf cell exceeds page size".into(),
                });
            }
            if used + size > PAGE_SIZE && !chunks.last().unwrap().is_empty() {
                chunks.push(Vec::new());
                used = HEADER_SIZE;
            }
            chunks.last_mut().unwrap().push(entry.clone());
            used += size;
