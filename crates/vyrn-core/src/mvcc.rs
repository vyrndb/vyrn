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

#[derive(Clone, Debug)]
pub(crate) struct Version {
    pub(crate) revision: u64,
    pub(crate) value: Option<ValueRef>,
}

#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) gc_floor: u64,
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
        let mut versions = Vec::with_capacity(version_count);
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
    if revision < state.gc_floor {
        return Err(Error::SnapshotTooOld {
            requested: revision,
            oldest: state.gc_floor,
        });
    }
    state
        .histories
        .get(key)
        .and_then(|versions| {
            versions
                .iter()
