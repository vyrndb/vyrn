use crate::{
    value_log::{ValueLog, ValueRef},
    Error, Result, MAX_KEY_SIZE, MAX_VALUE_SIZE,
};
use crc32fast::Hasher;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

const MAGIC: &[u8; 4] = b"VMVC";
const VERSION: u8 = 3;
const LEGACY_VERSION: u8 = 2;
const HEADER_LEN: usize = 24;
const KEY_HEADER_LEN: usize = 8;
const VERSION_HEADER_LEN: usize = 25;
const LEGACY_VERSION_HEADER_LEN: usize = 17;
/// Smallest legal per-version record across both formats, used only to bound
/// allocations that are sized from counts read off disk.
const MIN_VERSION_LEN: usize = LEGACY_VERSION_HEADER_LEN;

#[derive(Clone, Debug)]
pub(crate) struct Version {
    pub(crate) revision: u64,
    pub(crate) value: Option<ValueRef>,
}

#[derive(Clone, Default)]
pub(crate) struct State {
    /// Highest revision collection has swept past. Persisted, and the anchor the
    /// on-disk validation checks against.
    pub(crate) gc_floor: u64,
    /// Lowest revision whose history is complete, so a snapshot read at or above
    /// it is answerable and one below it is not.
    ///
    /// DISTINCT FROM `gc_floor`, and the distinction is the whole point. The
    /// floor only ever moves when `collect` runs, and `collect` is driven by a
    /// background task; history, meanwhile, is only recorded while a snapshot is
    /// open (see `Engine::maintain_history`). A database that opens a
    /// transaction, closes it, and then keeps writing therefore accumulates
    /// revisions that no history covers while the floor still names the old
    /// value — and every read against one of those revisions used to be answered
    /// from whatever was left behind, silently. Three shapes came out of that:
    ///
    /// - vanishing keys: a key readable at a snapshot disappears from a later
    ///   read at the same snapshot, because the write that displaced it did not
    ///   retain the displaced version.
    /// - present-as-past: `revision()` reports the stale history revision, the
    ///   read decides the live tree is old enough, and a value written AFTER the
    ///   snapshot is returned as if it had always been there.
    /// - missed conflicts: the same stale revision makes `changed_since` answer
    ///   "unchanged", so two transactions that overwrote each other both commit.
    ///
    /// This watermark is what makes those reads fail loudly instead. It is raised
    /// by `collect` like the floor, and additionally by every commit that retains
    /// no history at all, which is the case the floor cannot see.
    ///
    /// Not written to disk, and deliberately so: the format stays at version 3.
    /// `Engine::open` drops every history it replayed and republishes coverage at
    /// the committed LSN, so a value read back from a file could never be
    /// anything but that — persisting it would add a format migration to store a
    /// number that is recomputed before the first read.
    pub(crate) covered_through: u64,
    pub(crate) histories: BTreeMap<Vec<u8>, Vec<Version>>,
}

pub(crate) fn read(path: &Path, maximum_revision: u64, values: &mut ValueLog) -> Result<State> {
    if !path.exists() {
        return Ok(State::default());
    }
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER_LEN
        || &bytes[0..4] != MAGIC
        || !matches!(bytes[4], VERSION | LEGACY_VERSION)
        || checksum(&bytes[0..20]) != read_u32(&bytes, 20)
    {
        return Err(Error::CorruptManifest("invalid MVCC history header".into()));
    }
    let format = bytes[4];
    let key_count = read_u32(&bytes, 8) as usize;
    let gc_floor = read_u64(&bytes, 12);
    if gc_floor > maximum_revision {
        return Err(Error::CorruptManifest(
            "MVCC garbage-collection floor exceeds the committed revision".into(),
        ));
    }
    let mut histories = BTreeMap::new();
    let mut offset = HEADER_LEN;
    for _ in 0..key_count {
        require(&bytes, offset, KEY_HEADER_LEN)?;
        let key_len = read_u32(&bytes, offset) as usize;
        let version_count = read_u32(&bytes, offset + 4) as usize;
        offset += KEY_HEADER_LEN;
        if key_len == 0 || key_len > MAX_KEY_SIZE || version_count == 0 {
            return Err(Error::CorruptManifest("invalid MVCC key metadata".into()));
        }
        require(&bytes, offset, key_len)?;
        let key = bytes[offset..offset + key_len].to_vec();
        offset += key_len;
        // version_count comes off disk unvalidated, so the reservation is
        // clamped to what the remaining buffer could hold at the smallest
        // legal version record. A corrupt count near u32::MAX would otherwise
        // attempt a huge allocation before the per-version checks reject it;
        // a valid history always fits its buffer, so the clamp never binds
        // for one.
        let remaining = bytes.len() - offset;
        let mut versions = Vec::with_capacity(version_count.min(remaining / MIN_VERSION_LEN));
        let mut previous = None;
        for _ in 0..version_count {
            let version = if format == LEGACY_VERSION {
                read_legacy_version(&bytes, &mut offset, maximum_revision, previous, values)?
            } else {
                read_version(&bytes, &mut offset, maximum_revision, previous)?
            };
            previous = Some(version.revision);
            versions.push(version);
        }
        if histories.insert(key, versions).is_some() {
            return Err(Error::CorruptManifest("duplicate MVCC history key".into()));
        }
    }
    if offset != bytes.len() {
        return Err(Error::CorruptManifest("trailing MVCC history data".into()));
    }
    Ok(State {
        gc_floor,
        // Nothing on disk says how far coverage reached, so the most this file
        // can honestly claim is the floor it does carry. `Engine::open` replays
        // the WAL into this history and then collects it away against no active
        // snapshot, which republishes coverage at the committed LSN before the
        // first read can happen — so this value is a placeholder in practice and
        // a conservative one if a future caller ever reads a file without
        // collecting.
        covered_through: gc_floor,
        histories,
    })
}

pub(crate) fn write(path: &Path, state: &State) -> Result<()> {
    let key_count: u32 = state
        .histories
        .len()
        .try_into()
        .map_err(|_| Error::CorruptManifest("too many MVCC history keys".into()))?;
    let mut bytes = vec![0; HEADER_LEN];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION;
    write_u32(&mut bytes, 8, key_count);
    write_u64(&mut bytes, 12, state.gc_floor);
    let header_checksum = checksum(&bytes[0..20]);
    write_u32(&mut bytes, 20, header_checksum);
    for (key, versions) in &state.histories {
        let key_len: u32 = key.len().try_into().map_err(|_| Error::KeyTooLarge)?;
        let version_count: u32 = versions
            .len()
            .try_into()
            .map_err(|_| Error::CorruptManifest("too many versions for key".into()))?;
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(&version_count.to_be_bytes());
        bytes.extend_from_slice(key);
        for version in versions {
            let present = u8::from(version.value.is_some());
            let (value_offset, value_len) = version
                .value
                .as_ref()
                .map_or((0, 0), |reference| (reference.offset, reference.len));
            bytes.extend_from_slice(&version.revision.to_be_bytes());
            bytes.push(present);
            bytes.extend_from_slice(&value_offset.to_be_bytes());
            bytes.extend_from_slice(&value_len.to_be_bytes());
            bytes.extend_from_slice(
                &version_checksum(version.revision, present, value_offset, value_len).to_be_bytes(),
            );
        }
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn get_at(
    state: &State,
    values: &ValueLog,
    key: &[u8],
    revision: u64,
) -> Result<Option<Vec<u8>>> {
    // Checked against coverage, not the collection floor. The floor says what
    // was swept; coverage says what is answerable, and a revision can be above
    // the floor with no history behind it because history is only recorded while
    // a snapshot is open. Answering such a read from whatever versions happen to
    // remain is how a key readable at a snapshot silently vanished from the next
    // read at that same snapshot.
    if revision < state.covered_through {
        return Err(Error::SnapshotTooOld {
            requested: revision,
            oldest: state.covered_through,
        });
    }
    state
        .histories
        .get(key)
        .and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|version| version.revision <= revision)
        })
        .map_or(Ok(None), |version| {
            version
                .value
                .as_ref()
                .map(|reference| values.read(reference))
                .transpose()
        })
}

pub(crate) fn append(
    state: &mut State,
    values: &mut ValueLog,
    key: Vec<u8>,
    revision: u64,
    value: Option<Vec<u8>>,
) -> Result<()> {
    let value = prepare_value(values, revision, value.as_deref())?;
    append_prepared(state, key, revision, value);
    Ok(())
}

pub(crate) fn prepare_value(
    values: &mut ValueLog,
    revision: u64,
    value: Option<&[u8]>,
) -> Result<Option<ValueRef>> {
    value
        .map(|value| values.append(value, revision))
        .transpose()
}

pub(crate) fn append_prepared(
    state: &mut State,
    key: Vec<u8>,
    revision: u64,
    value: Option<ValueRef>,
) {
    let versions = state.histories.entry(key).or_default();
    if versions
        .last()
        .is_some_and(|latest| latest.revision == revision)
    {
        versions.last_mut().unwrap().value = value;
    } else {
        versions.push(Version { revision, value });
    }
}

pub(crate) fn compact(
    state: &State,
    source: &ValueLog,
    destination: &mut ValueLog,
) -> Result<State> {
    let mut compacted = State {
        gc_floor: state.gc_floor,
        // Compaction rewrites where the values live, not which revisions are
        // answerable, so coverage carries over untouched. Dropping it to the
        // default here would silently widen the answerable range after every
        // checkpoint and re-admit exactly the reads this watermark exists to
        // refuse.
        covered_through: state.covered_through,
        histories: BTreeMap::new(),
    };
    for (key, versions) in &state.histories {
        let mut compacted_versions = Vec::with_capacity(versions.len());
        for version in versions {
            let value = version
                .value
                .as_ref()
                .map(|reference| {
                    source
                        .read(reference)
                        .and_then(|value| destination.append(&value, version.revision))
                })
                .transpose()?;
            compacted_versions.push(Version {
                revision: version.revision,
                value,
            });
        }
        compacted.histories.insert(key.clone(), compacted_versions);
    }
    Ok(compacted)
}

pub(crate) fn revisions(state: &State) -> BTreeMap<Vec<u8>, u64> {
    state
        .histories
        .iter()
        .filter_map(|(key, versions)| {
            versions
                .last()
                .map(|version| (key.clone(), version.revision))
        })
        .collect()
}

pub(crate) fn collect(state: &mut State, oldest_active: Option<u64>, latest: u64) -> usize {
    let floor = oldest_active.unwrap_or(latest);
    let mut removed = 0;
    state.histories.retain(|_, versions| {
        let keep_from = versions
            .iter()
            .rposition(|version| version.revision <= floor)
            .unwrap_or(0);
        removed += keep_from;
        versions.drain(..keep_from);
        if oldest_active.is_none() {
            removed += versions.len();
            false
        } else {
            true
        }
    });
    state.gc_floor = state.gc_floor.max(floor);
    // Whatever was just dropped is unanswerable from here on, so coverage moves
    // with the floor. It moves in the other direction too — a commit that
    // retains nothing raises it without collecting anything (see
    // `Engine::publish_coverage`) — which is why the two are separate fields
    // rather than one.
    state.covered_through = state.covered_through.max(floor);
    removed
}

fn read_version(
    bytes: &[u8],
    offset: &mut usize,
    maximum_revision: u64,
    previous: Option<u64>,
) -> Result<Version> {
    require(bytes, *offset, VERSION_HEADER_LEN)?;
    let revision = read_u64(bytes, *offset);
    let present = bytes[*offset + 8];
    let value_offset = read_u64(bytes, *offset + 9);
    let value_len = read_u32(bytes, *offset + 17);
    let expected = read_u32(bytes, *offset + 21);
    *offset += VERSION_HEADER_LEN;
    if revision == 0
        || revision > maximum_revision
        || previous.is_some_and(|previous| previous >= revision)
        || present > 1
        || value_len as usize > MAX_VALUE_SIZE
        || (present == 0 && (value_offset != 0 || value_len != 0))
        || version_checksum(revision, present, value_offset, value_len) != expected
    {
        return Err(Error::CorruptManifest(
            "invalid MVCC version metadata".into(),
        ));
    }
    Ok(Version {
        revision,
        value: (present == 1).then_some(ValueRef {
            offset: value_offset,
            len: value_len,
            revision,
        }),
    })
}

fn read_legacy_version(
    bytes: &[u8],
    offset: &mut usize,
    maximum_revision: u64,
    previous: Option<u64>,
    values: &mut ValueLog,
) -> Result<Version> {
    require(bytes, *offset, LEGACY_VERSION_HEADER_LEN)?;
    let revision = read_u64(bytes, *offset);
    let present = bytes[*offset + 8];
    let value_len = read_u32(bytes, *offset + 9) as usize;
    let expected = read_u32(bytes, *offset + 13);
    *offset += LEGACY_VERSION_HEADER_LEN;
    if revision == 0
        || revision > maximum_revision
        || previous.is_some_and(|previous| previous >= revision)
        || present > 1
        || value_len > MAX_VALUE_SIZE
        || (present == 0 && value_len != 0)
    {
        return Err(Error::CorruptManifest(
            "invalid MVCC version metadata".into(),
        ));
    }
    require(bytes, *offset, value_len)?;
    let value = &bytes[*offset..*offset + value_len];
    if legacy_version_checksum(revision, present, value) != expected {
        return Err(Error::CorruptManifest(
            "invalid MVCC version checksum".into(),
        ));
    }
    *offset += value_len;
    Ok(Version {
        revision,
        value: (present == 1)
            .then(|| values.append(value, revision))
            .transpose()?,
    })
}

fn require(bytes: &[u8], offset: usize, length: usize) -> Result<()> {
    if offset
        .checked_add(length)
        .is_none_or(|end| end > bytes.len())
    {
        Err(Error::CorruptManifest("truncated MVCC history".into()))
    } else {
        Ok(())
    }
}

fn version_checksum(revision: u64, present: u8, offset: u64, len: u32) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&[VERSION, present]);
    hasher.update(&revision.to_be_bytes());
    hasher.update(&offset.to_be_bytes());
    hasher.update(&len.to_be_bytes());
    hasher.finalize()
}

fn legacy_version_checksum(revision: u64, present: u8, value: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&[LEGACY_VERSION, present]);
    hasher.update(&revision.to_be_bytes());
    hasher.update(&(value.len() as u32).to_be_bytes());
    hasher.update(value);
    hasher.finalize()
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
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

    #[test]
    fn history_round_trips_reads_and_collects_safely() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("history.vmvcc");
        let value_path = directory.path().join("history.vlog");
        let mut values = ValueLog::open(&value_path).unwrap();
        let mut state = State::default();
        append(
            &mut state,
            &mut values,
            b"a".to_vec(),
            1,
            Some(b"one".to_vec()),
        )
        .unwrap();
        append(
            &mut state,
            &mut values,
            b"a".to_vec(),
            3,
            Some(b"three".to_vec()),
        )
        .unwrap();
        append(&mut state, &mut values, b"a".to_vec(), 5, None).unwrap();
        append(
            &mut state,
            &mut values,
            b"b".to_vec(),
            4,
            Some(b"four".to_vec()),
        )
        .unwrap();
        assert_eq!(
            get_at(&state, &values, b"a", 2).unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(collect(&mut state, Some(3), 5), 1);
        assert_eq!(
            get_at(&state, &values, b"a", 3).unwrap(),
            Some(b"three".to_vec())
        );
        assert!(matches!(
            get_at(&state, &values, b"a", 2),
            Err(Error::SnapshotTooOld { .. })
        ));
        values.sync().unwrap();
        write(&path, &state).unwrap();
        let mut restored_values = ValueLog::open(&value_path).unwrap();
        let restored = read(&path, 5, &mut restored_values).unwrap();
        assert_eq!(restored.gc_floor, 3);
        assert_eq!(get_at(&restored, &restored_values, b"a", 5).unwrap(), None);
        assert_eq!(
            get_at(&restored, &restored_values, b"b", 4).unwrap(),
            Some(b"four".to_vec())
        );
    }

    #[test]
    fn a_corrupt_version_count_does_not_drive_the_allocation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("history.vmvcc");
        let value_path = directory.path().join("history.vlog");
        let mut values = ValueLog::open(&value_path).unwrap();

        // One well-formed header naming a single key that claims u32::MAX
        // versions and carries none of them. Reserving capacity for the claim
        // aborts the process before the first version's truncation check runs.
        let mut bytes = vec![0; HEADER_LEN];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4] = VERSION;
        write_u32(&mut bytes, 8, 1);
        write_u64(&mut bytes, 12, 0);
        let header_checksum = checksum(&bytes[0..20]);
        write_u32(&mut bytes, 20, header_checksum);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.push(b'k');
        fs::write(&path, &bytes).unwrap();

        // `State` is not `Debug`, so the error is matched out by hand.
        let error = match read(&path, 1, &mut values) {
            Ok(_) => panic!("a corrupt history must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::CorruptManifest(_)));
    }
}
