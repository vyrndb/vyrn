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

pub(crate) fn encode_entry(key: &[u8], value: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(key.len() + value.map_or(0, <[u8]>::len) + 5);
    encoded.push(u8::from(value.is_some()));
    encoded.extend_from_slice(&(key.len() as u32).to_be_bytes());
    encoded.extend_from_slice(key);
    if let Some(value) = value {
        encoded.extend_from_slice(value);
    }
    encoded
}

pub(crate) fn decode_entry(suffix: &[u8], encoded: &[u8]) -> Result<ChangeRecord> {
    let cursor = Cursor::from_suffix(suffix)?;
    if encoded.len() < 5 {
        return Err(corrupt("change log entry is truncated"));
    }
    let present = match encoded[0] {
        0 => false,
        1 => true,
        _ => return Err(corrupt("change log entry has an invalid presence flag")),
    };
    let key_len = u32::from_be_bytes(encoded[1..5].try_into().unwrap()) as usize;
    if key_len == 0 || key_len > MAX_KEY_SIZE || encoded.len() < 5 + key_len {
        return Err(corrupt("change log entry has an invalid key length"));
    }
    if !present && encoded.len() != 5 + key_len {
        return Err(corrupt("change log deletion carries a value"));
    }
    let key = encoded[5..5 + key_len].to_vec();
    Ok(ChangeRecord {
        sequence: cursor.sequence,
        index: cursor.index,
        document: crate::document::target_from_key(&key),
        key,
        value: present.then(|| encoded[5 + key_len..].to_vec()),
    })
}

fn corrupt(reason: &str) -> Error {
    Error::CorruptManifest(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip_with_cursors() {
        let cursor = Cursor::new(7, 2);
        let encoded = encode_entry(b"users/1", Some(b"active"));
        let record = decode_entry(&cursor.suffix(), &encoded).unwrap();
        assert_eq!(record.cursor(), cursor);
        assert_eq!(record.key, b"users/1");
        assert_eq!(record.value.as_deref(), Some(&b"active"[..]));

        let deletion = decode_entry(&cursor.suffix(), &encode_entry(b"users/1", None)).unwrap();
        assert_eq!(deletion.value, None);
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
    fn rejects_corrupt_entries() {
        let suffix = Cursor::new(1, 0).suffix();
        assert!(decode_entry(&suffix[..4], b"\x00\x00\x00\x00\x01a").is_err());
        assert!(decode_entry(&suffix, b"").is_err());
        assert!(decode_entry(&suffix, b"\x02\x00\x00\x00\x01a").is_err());
        assert!(decode_entry(&suffix, b"\x00\x00\x00\x00\x00").is_err());
        assert!(decode_entry(&suffix, b"\x00\x00\x00\x00\x01ab").is_err());
    }
}
