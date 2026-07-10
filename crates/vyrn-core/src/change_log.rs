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
