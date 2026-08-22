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

use crate::{document, Engine, Error, Result, INTERNAL_PREFIX};
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

/// Loads a dump into `engine`, returning the number of pairs applied.
///
/// The dump's checksum and pair count are verified as it is read, and a mismatch
/// fails the import rather than leaving a partially loaded database presented as
/// complete. Writes go through the ordinary batch path, so everything imported is
/// durable and recoverable exactly as if it had been written by a client.
pub fn import(engine: &mut Engine, input: &Path) -> Result<u64> {
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
    let mut batch: Vec<crate::BatchOperation> = Vec::new();
    loop {
        let key_len = read_u32(&mut source)? as usize;
        if key_len == 0 {
            break;
        }
        let mut key = vec![0; key_len];
        read_exact(&mut source, &mut key)?;
        let value_len = read_u32(&mut source)? as usize;
        let mut value = vec![0; value_len];
        read_exact(&mut source, &mut value)?;
        hasher.update(&key);
        hasher.update(&value);
        // A dump is a file an operator can edit or a stranger can hand over, so
        // it does not get to write Vyrn's bookkeeping. Only what an export is
        // allowed to carry may come back in; anything else would let a crafted
        // dump plant tombstones or index entries the engine believes it wrote.
        if !is_exportable(&key) {
            return Err(Error::InvalidDocument(format!(
                "dump carries the reserved key {}",
                String::from_utf8_lossy(&key)
            )));
        }
        batch.push(crate::BatchOperation::Put(key, value));
        pairs += 1;
        if batch.len() >= 512 {
            // The internal write path, because documents live under the reserved
            // prefix that the public one refuses.
            engine.write_batch_internal(std::mem::take(&mut batch))?;
        }
    }
    if !batch.is_empty() {
        engine.write_batch_internal(batch)?;
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
    Ok(pairs)
}
