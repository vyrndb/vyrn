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
