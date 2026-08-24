//! A logical dump that does not depend on the on-disk format.
//!
//! Backups are physical: they copy pages, WAL, and manifests, so they can only be
//! restored by a build that speaks the same storage format. Storage formats may
//! change until 1.0, which leaves an operator holding data written by a version
//! that the current binary refuses to open — intact, but unreachable.
//!
//! This is the way across. An export contains keys and values and nothing about
//! how they were stored, so a dump taken by the build that wrote the database can
//! be loaded by any later build. It is the migration path the format-version
//! error points at.
//!
//! What it carries is the *published* keyspace: user keys and documents, the same
//! set a change-log subscriber sees. Secondary indexes are deliberately excluded —
//! they are derived state, they are rebuilt by recreating the index against the
//! imported data, and copying them would tie the dump back to internal layout,
//! which is the whole thing this format exists to avoid.

use crate::{
    backup, document, Engine, Error, Result, INTERNAL_PREFIX, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};
use crc32fast::Hasher;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

const EXPORT_MAGIC: &[u8; 8] = b"VYRNDUMP";
/// Versions this dump format itself, independently of the storage format. A dump
/// has to stay readable across exactly the storage changes it exists to survive.
const EXPORT_VERSION: u8 = 1;
const SCAN_CHUNK: usize = 4_096;

/// How much an in-flight import batch may hold before it is flushed, whichever
/// limit fills first. The pair count alone is not a memory bound: a legal dump
/// may carry values up to `MAX_VALUE_SIZE`, so 512 buffered pairs could peak at
/// eight gibibytes while importing from a machine that wrote them casually.
const IMPORT_BATCH_PAIRS: usize = 512;
const IMPORT_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Whether a committed key belongs in a logical dump.
///
/// Mirrors the published keyspace: user keys plus documents, excluding Vyrn's own
/// bookkeeping (tombstones, index entries and definitions, the change log).
fn is_exportable(key: &[u8]) -> bool {
    !key.starts_with(INTERNAL_PREFIX) || key.starts_with(document::DOCUMENT_KEY_PREFIX)
}

fn write_u32(out: &mut impl Write, value: u32) -> Result<()> {
    out.write_all(&value.to_be_bytes())?;
    Ok(())
}

fn write_u64(out: &mut impl Write, value: u64) -> Result<()> {
    out.write_all(&value.to_be_bytes())?;
    Ok(())
}

/// Writes every exportable key and value in `engine` to `output`.
///
/// Returns the number of pairs written. The engine is read through a consistent
/// scan, so the dump is a point-in-time image rather than a smear across concurrent
/// writes.
pub fn export(engine: &Engine, output: &Path) -> Result<u64> {
    // `File::create` truncates what it is handed, so an output spelled like
    // engine state — a WAL segment, a page file, CURRENT — would destroy the
    // very database being exported and still report success. The same refusal
    // the physical backup applies before it touches anything.
    backup::reject_reserved_output(output)?;
    let file = File::create(output)?;
    let mut out = BufWriter::new(file);
    out.write_all(EXPORT_MAGIC)?;
    out.write_all(&[EXPORT_VERSION])?;

    let mut hasher = Hasher::new();
    let mut pairs: u64 = 0;
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        // The internal scan, not `Engine::scan`: the public one drops everything
        // under the reserved prefix at the tree, which would take documents with
        // it. `is_exportable` is what decides here.
        let batch = engine.scan_internal(cursor.as_deref(), None, SCAN_CHUNK)?;
        // `scan`'s start bound is inclusive, so the resume key comes back at the
        // head of the next chunk. Dropping it here means a chunk that holds only
        // that one key leaves nothing new, which is how the scan ends.
        let fresh: Vec<_> = batch
            .into_iter()
            .filter(|(key, _)| cursor.as_deref() != Some(key.as_slice()))
            .collect();
        if fresh.is_empty() {
            break;
        }
        cursor = fresh.last().map(|(key, _)| key.clone());
        for (key, value) in fresh {
            if !is_exportable(&key) {
                continue;
            }
            hasher.update(&key);
            hasher.update(&value);
            write_u32(&mut out, key.len() as u32)?;
            out.write_all(&key)?;
            write_u32(&mut out, value.len() as u32)?;
            out.write_all(&value)?;
            pairs += 1;
        }
    }

    write_u32(&mut out, 0)?;
    write_u64(&mut out, pairs)?;
    write_u32(&mut out, hasher.finalize())?;
    out.flush()?;
    // The dump is the migration path; it has to survive losing the host that
    // wrote it, so it is durable before this returns.
    out.into_inner()
        .map_err(|error| Error::Io(std::io::Error::other(error.to_string())))?
        .sync_all()?;
    // The dump is the migration path; it has to survive losing the host that
    // wrote it, so the containing directory entry is synced too — exactly what
    // a physical backup does after publishing its archive.
    if let Some(parent) = output.parent() {
        sync_directory(parent)?;
    }
    Ok(pairs)
}

fn read_exact(input: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    input.read_exact(buffer).map_err(Error::Io)
}

fn read_u32(input: &mut impl Read) -> Result<u32> {
    let mut bytes = [0; 4];
    read_exact(input, &mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &mut impl Read) -> Result<u64> {
    let mut bytes = [0; 8];
    read_exact(input, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

use crate::sync_directory;

/// Loads a dump into `engine`, returning the number of pairs applied.
///
/// The whole dump is proven sound before anything is written. Two streaming
/// passes: the first verifies framing against the engine's size limits,
/// reserved keys, document contents, the trailer's pair count and checksum,
/// and that nothing follows the trailer — while writing nothing at all. The
/// second re-streams the now-verified file into ordinary batches. A truncated
/// or bit-damaged dump therefore fails the import with the target untouched,
/// rather than leaving a half-loaded database that the fresh-directory
/// requirement makes unreachable, and memory stays flat in both passes because
/// nothing beyond the current batch is ever buffered. Writes go through the
/// ordinary batch path, so everything imported is durable and recoverable
/// exactly as if it had been written by a client.
pub fn import(engine: &mut Engine, input: &Path) -> Result<u64> {
    // Pass one: verify. Nothing reaches the engine, so damage found anywhere in
    // the file costs a read instead of a database.
    stream_dump(input, &mut |key, value| verify_pair(&key, &value))?;

    // Pass two: apply. Every content decision was made above, so the only
    // failures left are I/O ones, which no amount of pre-reading removes.
    let mut pairs: u64 = 0;
    let mut batch: Vec<crate::BatchOperation> = Vec::new();
    let mut batch_bytes: usize = 0;
    stream_dump(input, &mut |key, value| {
        batch_bytes += key.len().saturating_add(value.len());
        batch.push(crate::BatchOperation::Put(key, value));
        pairs += 1;
        if batch.len() >= IMPORT_BATCH_PAIRS || batch_bytes >= IMPORT_BATCH_BYTES {
            // The internal write path, because documents live under the reserved
            // prefix that the public one refuses.
            engine.write_batch_internal(std::mem::take(&mut batch))?;
            batch_bytes = 0;
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        engine.write_batch_internal(batch)?;
    }
    Ok(pairs)
}

/// Streams one pass over a dump, verifying everything that makes a pair safe to
/// load and handing each one to `sink`.
///
/// Verification covers the header, each pair's framing against the engine's own
/// write limits, the trailer's pair count and checksum, and that the file ends
/// where the trailer says it does. `sink` sees only well-framed pairs, so a
/// sink that inspects content cannot be ambushed by framing either.
fn stream_dump(input: &Path, sink: &mut impl FnMut(Vec<u8>, Vec<u8>) -> Result<()>) -> Result<u64> {
    let file = File::open(input)?;
    let mut source = BufReader::new(file);

    let mut magic = [0; 8];
    read_exact(&mut source, &mut magic)?;
    if &magic != EXPORT_MAGIC {
        return Err(Error::InvalidDocument("not a Vyrn logical dump".into()));
    }
    let mut version = [0; 1];
    read_exact(&mut source, &mut version)?;
    if version[0] != EXPORT_VERSION {
        return Err(Error::FormatVersion {
            structure: "logical dump",
            found: version[0],
            expected: EXPORT_VERSION,
        });
    }

    let mut hasher = Hasher::new();
    let mut pairs: u64 = 0;
    loop {
        // Lengths from an untrusted file are checked before they are trusted
        // with an allocation: twelve crafted bytes claiming a four-gibibyte
        // key must end as a damaged-dump error, not as an abort inside the
        // allocator. The caps are the engine's own write limits, so a pair
        // rejected here could never have been stored anyway.
        let key_len = read_u32(&mut source)? as usize;
        if key_len == 0 {
            break;
        }
        if key_len > MAX_KEY_SIZE {
            return Err(Error::InvalidDocument(format!(
                "dump declares a {key_len}-byte key; the engine accepts at most {MAX_KEY_SIZE}"
            )));
        }
        let mut key = vec![0; key_len];
        read_exact(&mut source, &mut key)?;
        let value_len = read_u32(&mut source)? as usize;
        if value_len > MAX_VALUE_SIZE {
            return Err(Error::InvalidDocument(format!(
                "dump declares a {value_len}-byte value; the engine accepts at most {MAX_VALUE_SIZE}"
            )));
        }
        let mut value = vec![0; value_len];
        read_exact(&mut source, &mut value)?;
        hasher.update(&key);
        hasher.update(&value);
        pairs += 1;
        sink(key, value)?;
    }

    let expected_pairs = read_u64(&mut source)?;
    let expected_checksum = read_u32(&mut source)?;
    if pairs != expected_pairs {
        return Err(Error::InvalidDocument(format!(
            "dump declares {expected_pairs} pairs but contains {pairs}"
        )));
    }
    if hasher.finalize() != expected_checksum {
        return Err(Error::InvalidDocument(
            "dump failed its checksum; the file is damaged".into(),
        ));
    }
    // The physical backup reader refuses bytes after its footer, and a logical
    // dump gets the same treatment: trailing data means either a splice or a
    // different file wearing this one's trailer, and neither may import.
    let mut trailing = [0; 1];
    if source.read(&mut trailing)? != 0 {
        return Err(Error::InvalidDocument(
            "dump carries data after its trailer".into(),
        ));
    }
    Ok(pairs)
}

/// Everything about one pair that must be true before it may reach the engine,
/// decided during verification so the importing pass cannot fail halfway
/// through on content.
fn verify_pair(key: &[u8], value: &[u8]) -> Result<()> {
    // A dump is a file an operator can edit or a stranger can hand over, so
    // it does not get to write Vyrn's bookkeeping. Only what an export is
    // allowed to carry may come back in; anything else would let a crafted
    // dump plant tombstones or index entries the engine believes it wrote.
    if !is_exportable(key) {
        return Err(Error::InvalidDocument(format!(
            "dump carries the reserved key {}",
            String::from_utf8_lossy(key)
        )));
    }
    // Import writes document pairs as raw bytes under the reserved prefix, so
    // the document layer never validates them on the way in and a crafted dump
    // would surface later as read-time errors instead. Enforce here what the
    // document layer enforces on write: a well-formed document key carrying a
    // JSON object. (`document.rs`'s decoder is private to that module, hence
    // the local mirror.)
    match document::target_from_key(key) {
        Some(target) => {
            let parsed: serde_json::Value = serde_json::from_slice(value).map_err(|error| {
                Error::InvalidDocument(format!(
                    "dump stores document {}/{} as invalid JSON: {error}",
                    target.collection, target.id
                ))
            })?;
            if !parsed.is_object() {
                return Err(Error::InvalidDocument(format!(
                    "dump stores document {}/{} as a JSON {} rather than an object",
                    target.collection,
                    target.id,
                    json_kind(&parsed)
                )));
            }
        }
        None if key.starts_with(document::DOCUMENT_KEY_PREFIX) => {
            return Err(Error::InvalidDocument(format!(
                "dump carries a malformed document key {}",
                String::from_utf8_lossy(key)
            )));
        }
        None => {}
    }
    Ok(())
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
