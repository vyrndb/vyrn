use crate::{Error, Result, MAX_KEY_SIZE};

/// A committed change, addressed by a durable cursor.
///
/// `sequence` is the commit's WAL sequence number and `index` orders the
/// mutations inside that commit, so `(sequence, index)` totally orders every
/// change the database has ever published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    pub sequence: u64,
    pub index: u32,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    /// Set when the change is a document write, so subscribers see the
    /// collection and document ID instead of Vyrn's internal key encoding.
    pub document: Option<DocumentTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentTarget {
    pub collection: String,
    pub id: String,
}

impl ChangeRecord {
    pub fn cursor(&self) -> Cursor {
        Cursor {
            sequence: self.sequence,
            index: self.index,
        }
    }
}

/// A position in the change log. `Cursor::start()` replays everything retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Cursor {
    pub sequence: u64,
    pub index: u32,
}

impl Cursor {
    pub fn start() -> Self {
        Self::default()
    }

    pub fn new(sequence: u64, index: u32) -> Self {
        Self { sequence, index }
    }

    /// Encodes the cursor as an opaque ASCII token for clients to persist.
    pub fn to_token(self) -> String {
        format!("{:016x}-{:08x}", self.sequence, self.index)
    }

    pub fn parse_token(token: &str) -> Result<Self> {
        let (sequence, index) = token
            .split_once('-')
            .ok_or_else(|| Error::InvalidCursor("cursor must be <sequence>-<index>".into()))?;
        Ok(Self {
            sequence: u64::from_str_radix(sequence, 16)
                .map_err(|_| Error::InvalidCursor("cursor sequence is not hexadecimal".into()))?,
            index: u32::from_str_radix(index, 16)
                .map_err(|_| Error::InvalidCursor("cursor index is not hexadecimal".into()))?,
        })
    }

    pub(crate) fn suffix(self) -> Vec<u8> {
        let mut suffix = Vec::with_capacity(SUFFIX_LEN);
        suffix.extend_from_slice(&self.sequence.to_be_bytes());
        suffix.extend_from_slice(&self.index.to_be_bytes());
        suffix
    }

    pub(crate) fn from_suffix(suffix: &[u8]) -> Result<Self> {
        if suffix.len() != SUFFIX_LEN {
            return Err(corrupt("change log key has an invalid cursor"));
        }
        Ok(Self {
            sequence: u64::from_be_bytes(suffix[0..8].try_into().unwrap()),
            index: u32::from_be_bytes(suffix[8..12].try_into().unwrap()),
        })
    }
}

pub(crate) const SUFFIX_LEN: usize = 12;

/// Encodes every mutation of one commit into a single change-log value.
///
/// One record per commit rather than one per mutation keeps the change log to a
/// single tree insert per commit, which halves the copy-on-write page churn the
/// log would otherwise add to the write path.
pub(crate) fn encode_batch(entries: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (key, value) in entries {
        encoded.push(u8::from(value.is_some()));
        encoded.extend_from_slice(&(key.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(value.map_or(0, <[u8]>::len) as u32).to_be_bytes());
        encoded.extend_from_slice(key);
        if let Some(value) = value {
            encoded.extend_from_slice(value);
        }
    }
    encoded
}

/// Decodes one commit's change record into its individual changes.
pub(crate) fn decode_batch(sequence: u64, encoded: &[u8]) -> Result<Vec<ChangeRecord>> {
    if encoded.len() < 4 {
        return Err(corrupt("change log record is truncated"));
    }
    let count = u32::from_be_bytes(encoded[0..4].try_into().unwrap()) as usize;
    let mut offset = 4;
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        if encoded.len() < offset + 9 {
            return Err(corrupt("change log entry header is truncated"));
        }
        let present = match encoded[offset] {
            0 => false,
            1 => true,
            _ => return Err(corrupt("change log entry has an invalid presence flag")),
        };
        let key_len =
            u32::from_be_bytes(encoded[offset + 1..offset + 5].try_into().unwrap()) as usize;
        let value_len =
            u32::from_be_bytes(encoded[offset + 5..offset + 9].try_into().unwrap()) as usize;
        offset += 9;
        if key_len == 0 || key_len > MAX_KEY_SIZE || (!present && value_len != 0) {
            return Err(corrupt("change log entry has invalid lengths"));
        }
        if encoded.len() < offset + key_len + value_len {
            return Err(corrupt("change log entry is truncated"));
        }
        let key = encoded[offset..offset + key_len].to_vec();
        offset += key_len;
        let value = present.then(|| encoded[offset..offset + value_len].to_vec());
        offset += value_len;
        records.push(ChangeRecord {
            sequence,
            index: index as u32,
            document: crate::document::target_from_key(&key),
            key,
            value,
        });
    }
    if offset != encoded.len() {
        return Err(corrupt("change log record has trailing data"));
    }
    Ok(records)
}

fn corrupt(reason: &str) -> Error {
    Error::CorruptManifest(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_batches_round_trip_with_cursors() {
        let entries: Vec<(&[u8], Option<&[u8]>)> = vec![
            (b"users/1", Some(&b"active"[..])),
            (b"users/2", None),
            (b"users/3", Some(&b""[..])),
        ];
        let records = decode_batch(7, &encode_batch(&entries)).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].cursor(), Cursor::new(7, 0));
        assert_eq!(records[0].key, b"users/1");
        assert_eq!(records[0].value.as_deref(), Some(&b"active"[..]));
        assert_eq!(records[1].cursor(), Cursor::new(7, 1));
        assert_eq!(records[1].value, None, "deletions carry no value");
        assert_eq!(
            records[2].value.as_deref(),
            Some(&b""[..]),
            "an empty value is distinct from a deletion"
        );
    }

    #[test]
    fn empty_batches_round_trip() {
        assert!(decode_batch(1, &encode_batch(&[])).unwrap().is_empty());
    }

    #[test]
    fn rejects_corrupt_batches() {
        assert!(decode_batch(1, b"").is_err(), "missing count");
        assert!(
            decode_batch(1, b"\x00\x00\x00\x01").is_err(),
            "missing entry"
        );
        // Claims one entry with a zero-length key.
        assert!(decode_batch(1, b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00").is_err());
        // A deletion that claims a value length.
        assert!(decode_batch(1, b"\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01a").is_err());
        let mut trailing = encode_batch(&[(b"a", None)]);
        trailing.push(0);
        assert!(decode_batch(1, &trailing).is_err(), "trailing data");
    }

    #[test]
    fn cursor_tokens_round_trip_and_order() {
        let cursor = Cursor::new(4_294_967_296, 5);
        assert_eq!(Cursor::parse_token(&cursor.to_token()).unwrap(), cursor);
        assert!(Cursor::new(1, 2) < Cursor::new(1, 3));
        assert!(Cursor::new(1, 9) < Cursor::new(2, 0));
        assert!(Cursor::parse_token("nope").is_err());
        assert!(Cursor::parse_token("zz-01").is_err());
    }

    #[test]
    fn rejects_invalid_cursor_suffixes() {
        assert!(Cursor::from_suffix(&[]).is_err());
        assert!(Cursor::from_suffix(&Cursor::new(1, 0).suffix()[..4]).is_err());
        assert_eq!(
            Cursor::from_suffix(&Cursor::new(9, 3).suffix()).unwrap(),
            Cursor::new(9, 3)
        );
    }
}
