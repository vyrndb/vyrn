use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub const PROTOCOL_VERSION: u16 = 6;
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
pub const DEFAULT_SCAN_LIMIT: u32 = 1_000;
pub const MAX_SCAN_LIMIT: u32 = 10_000;
pub const MAX_DOCUMENT_INDEXES: usize = 256;
const MAX_AUTH_FIELD: usize = 4 * 1024;
const MAX_DOCUMENT_NAME: usize = 4 * 1024;
const MAX_CURSOR: usize = 64;
const MAX_ERROR_MESSAGE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentIndex {
    pub field: String,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub request_id: u64,
    pub message: Message,
}

impl Envelope {
    pub fn new(request_id: u64, message: Message) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            message,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    Authenticate {
        username: String,
        password: String,
        database: String,
    },
    Get {
        key: Vec<u8>,
    },
    MultiGet {
        keys: Vec<Vec<u8>>,
    },
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        key: Vec<u8>,
    },
    Scan {
        start: Option<Vec<u8>>,
        end: Option<Vec<u8>>,
        limit: u32,
    },
    Subscribe {
        prefix: Vec<u8>,
    },
    /// Subscribe from a durable cursor. An empty `cursor` starts from the
    /// beginning of the retained change log; `None` means live changes only.
    SubscribeFrom {
        prefix: Vec<u8>,
        cursor: Option<String>,
    },
    SubscribeCollectionFrom {
        collection: String,
        cursor: Option<String>,
    },
    Begin,
    Commit,
    Rollback,
    CreateIndex {
        name: Vec<u8>,
        unique: bool,
    },
    DropIndex {
        name: Vec<u8>,
    },
    IndexUpdate {
        index: Vec<u8>,
        primary_key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Option<Vec<u8>>,
    },
    IndexLookup {
        index: Vec<u8>,
        value: Vec<u8>,
        limit: u32,
    },
    CreateCollection {
        collection: String,
        indexes: Vec<DocumentIndex>,
    },
    GetDocument {
        collection: String,
        id: String,
    },
    PutDocument {
        collection: String,
        id: String,
        document: Vec<u8>,
    },
    DeleteDocument {
        collection: String,
        id: String,
    },
    ListDocuments {
        collection: String,
        limit: u32,
    },
    QueryDocuments {
        collection: String,
        field: String,
        value: Vec<u8>,
        limit: u32,
    },
    SubscribeCollection {
        collection: String,
    },
    Authenticated,
    Value {
        value: Option<Vec<u8>>,
    },
    Values {
        values: Vec<Option<Vec<u8>>>,
    },
    Written,
    Deleted {
        existed: bool,
    },
    Rows {
        rows: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Subscribed,
    Begun,
    Committed,
    RolledBack,
    IndexCreated,
    IndexDropped,
    IndexUpdated,
    Keys {
        keys: Vec<Vec<u8>>,
    },
    CollectionCreated,
    DocumentValue {
        document: Option<Vec<u8>>,
    },
    DocumentWritten,
    DocumentDeleted {
        existed: bool,
    },
    Documents {
        documents: Vec<(String, Vec<u8>)>,
    },
    CollectionSubscribed,
    DocumentChange {
        sequence: u64,
        id: String,
        document: Option<Vec<u8>>,
    },
    Change {
        sequence: u64,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    /// A change carrying the durable cursor that produced it, so a subscriber
    /// can persist its position and resume without gaps.
    CursorChange {
        cursor: String,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    CursorDocumentChange {
        cursor: String,
        collection: String,
        id: String,
        document: Option<Vec<u8>>,
    },
    /// Marks the end of the replayed backlog; everything after is live.
    Caught {
        cursor: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticate {
                username, database, ..
            } => formatter
                .debug_struct("Authenticate")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .field("database", database)
                .finish(),
            Self::Get { key } => formatter
                .debug_struct("Get")
                .field("key_len", &key.len())
                .finish(),
            Self::MultiGet { keys } => formatter
                .debug_struct("MultiGet")
                .field("key_count", &keys.len())
                .finish(),
            Self::Put { key, value } => formatter
                .debug_struct("Put")
                .field("key_len", &key.len())
                .field("value_len", &value.len())
                .finish(),
            Self::Delete { key } => formatter
                .debug_struct("Delete")
                .field("key_len", &key.len())
                .finish(),
            Self::Scan { start, end, limit } => formatter
                .debug_struct("Scan")
                .field("start_len", &start.as_ref().map(Vec::len))
                .field("end_len", &end.as_ref().map(Vec::len))
                .field("limit", limit)
                .finish(),
            Self::Subscribe { prefix } => formatter
                .debug_struct("Subscribe")
                .field("prefix_len", &prefix.len())
                .finish(),
            Self::SubscribeFrom { prefix, cursor } => formatter
                .debug_struct("SubscribeFrom")
                .field("prefix_len", &prefix.len())
                .field("cursor", cursor)
                .finish(),
            Self::SubscribeCollectionFrom { collection, cursor } => formatter
                .debug_struct("SubscribeCollectionFrom")
                .field("collection", collection)
                .field("cursor", cursor)
                .finish(),
            Self::CursorChange { cursor, key, value } => formatter
                .debug_struct("CursorChange")
                .field("cursor", cursor)
                .field("key_len", &key.len())
                .field("value_len", &value.as_ref().map(Vec::len))
                .finish(),
            Self::CursorDocumentChange {
                cursor,
                collection,
                id,
                document,
            } => formatter
                .debug_struct("CursorDocumentChange")
                .field("cursor", cursor)
                .field("collection", collection)
                .field("id", id)
                .field("document_len", &document.as_ref().map(Vec::len))
                .finish(),
            Self::Caught { cursor } => formatter
                .debug_struct("Caught")
                .field("cursor", cursor)
                .finish(),
            Self::Begin => formatter.write_str("Begin"),
            Self::Commit => formatter.write_str("Commit"),
            Self::Rollback => formatter.write_str("Rollback"),
            Self::CreateIndex { name, unique } => formatter
                .debug_struct("CreateIndex")
                .field("name_len", &name.len())
                .field("unique", unique)
                .finish(),
            Self::DropIndex { name } => formatter
                .debug_struct("DropIndex")
                .field("name_len", &name.len())
                .finish(),
            Self::IndexUpdate {
                index,
                primary_key,
                old_value,
                new_value,
            } => formatter
                .debug_struct("IndexUpdate")
                .field("index_len", &index.len())
                .field("primary_key_len", &primary_key.len())
                .field("old_value_len", &old_value.as_ref().map(Vec::len))
                .field("new_value_len", &new_value.as_ref().map(Vec::len))
                .finish(),
            Self::IndexLookup {
                index,
                value,
                limit,
            } => formatter
                .debug_struct("IndexLookup")
                .field("index_len", &index.len())
                .field("value_len", &value.len())
                .field("limit", limit)
                .finish(),
            Self::CreateCollection {
                collection,
                indexes,
            } => formatter
                .debug_struct("CreateCollection")
                .field("collection", collection)
                .field("index_count", &indexes.len())
                .finish(),
            Self::GetDocument { collection, id } | Self::DeleteDocument { collection, id } => {
                formatter
                    .debug_struct("DocumentRequest")
                    .field("collection", collection)
                    .field("id", id)
                    .finish()
            }
            Self::PutDocument {
                collection,
                id,
                document,
            } => formatter
                .debug_struct("PutDocument")
                .field("collection", collection)
                .field("id", id)
                .field("document_len", &document.len())
                .finish(),
            Self::ListDocuments { collection, limit } => formatter
                .debug_struct("ListDocuments")
                .field("collection", collection)
                .field("limit", limit)
                .finish(),
            Self::QueryDocuments {
                collection,
                field,
                value,
                limit,
            } => formatter
                .debug_struct("QueryDocuments")
                .field("collection", collection)
                .field("field", field)
                .field("value_len", &value.len())
                .field("limit", limit)
                .finish(),
            Self::SubscribeCollection { collection } => formatter
                .debug_struct("SubscribeCollection")
                .field("collection", collection)
                .finish(),
            Self::Authenticated => formatter.write_str("Authenticated"),
            Self::Value { value } => formatter
                .debug_struct("Value")
                .field("value_len", &value.as_ref().map(Vec::len))
                .finish(),
            Self::Values { values } => formatter
                .debug_struct("Values")
                .field("value_count", &values.len())
                .finish(),
            Self::Written => formatter.write_str("Written"),
            Self::Deleted { existed } => formatter
                .debug_struct("Deleted")
                .field("existed", existed)
                .finish(),
            Self::Rows { rows } => formatter
                .debug_struct("Rows")
                .field("row_count", &rows.len())
                .finish(),
            Self::Subscribed => formatter.write_str("Subscribed"),
            Self::Begun => formatter.write_str("Begun"),
            Self::Committed => formatter.write_str("Committed"),
            Self::RolledBack => formatter.write_str("RolledBack"),
            Self::IndexCreated => formatter.write_str("IndexCreated"),
            Self::IndexDropped => formatter.write_str("IndexDropped"),
            Self::IndexUpdated => formatter.write_str("IndexUpdated"),
            Self::Keys { keys } => formatter
                .debug_struct("Keys")
                .field("key_count", &keys.len())
                .finish(),
            Self::CollectionCreated => formatter.write_str("CollectionCreated"),
            Self::DocumentValue { document } => formatter
                .debug_struct("DocumentValue")
                .field("document_len", &document.as_ref().map(Vec::len))
                .finish(),
            Self::DocumentWritten => formatter.write_str("DocumentWritten"),
            Self::DocumentDeleted { existed } => formatter
                .debug_struct("DocumentDeleted")
                .field("existed", existed)
                .finish(),
            Self::Documents { documents } => formatter
                .debug_struct("Documents")
                .field("document_count", &documents.len())
                .finish(),
            Self::CollectionSubscribed => formatter.write_str("CollectionSubscribed"),
            Self::DocumentChange {
                sequence,
                id,
                document,
            } => formatter
                .debug_struct("DocumentChange")
                .field("sequence", sequence)
                .field("id", id)
                .field("document_len", &document.as_ref().map(Vec::len))
                .finish(),
            Self::Change {
                sequence,
                key,
                value,
            } => formatter
                .debug_struct("Change")
                .field("sequence", sequence)
                .field("key_len", &key.len())
                .field("value_len", &value.as_ref().map(Vec::len))
                .finish(),
            Self::Error { code, message } => formatter
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    AuthenticationFailed,
    InvalidRequest,
    UnsupportedVersion,
    Conflict,
    Storage,
    Internal,
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed protocol message: {0}")]
    Malformed(&'static str),
}

pub struct VyrnCodec {
    frames: LengthDelimitedCodec,
}

impl Default for VyrnCodec {
    fn default() -> Self {
        Self {
            frames: LengthDelimitedCodec::builder()
                .max_frame_length(MAX_FRAME_SIZE)
                .new_codec(),
        }
    }
}

impl Decoder for VyrnCodec {
    type Item = Envelope;
    type Error = CodecError;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(mut frame) = self.frames.decode(source)? else {
            return Ok(None);
        };
        let envelope = decode_envelope(&mut frame)?;
        if frame.has_remaining() {
            return Err(CodecError::Malformed("trailing bytes"));
        }
        Ok(Some(envelope))
    }
}

impl Encoder<Envelope> for VyrnCodec {
    type Error = CodecError;

    fn encode(&mut self, message: Envelope, destination: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = encode_envelope(message)?;
        if encoded.len() > MAX_FRAME_SIZE {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "message exceeds frame limit").into(),
            );
        }
        self.frames.encode(encoded, destination)?;
        Ok(())
    }
}

fn encode_envelope(envelope: Envelope) -> Result<Bytes, CodecError> {
    let mut output = BytesMut::with_capacity(64);
    output.put_u16(envelope.version);
    output.put_u64(envelope.request_id);
    encode_message(envelope.message, &mut output)?;
    Ok(output.freeze())
}

fn encode_message(message: Message, output: &mut BytesMut) -> Result<(), CodecError> {
    match message {
        Message::Authenticate {
            username,
            password,
            database,
        } => {
            output.put_u8(1);
            put_string(output, &username)?;
            put_string(output, &password)?;
            put_string(output, &database)?;
        }
        Message::Get { key } => {
            output.put_u8(2);
            put_bytes(output, &key)?;
        }
        Message::MultiGet { keys } => {
            output.put_u8(29);
            output.put_u32(
                keys.len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many keys"))?,
            );
            for key in keys {
                put_bytes(output, &key)?;
            }
        }
        Message::Put { key, value } => {
            output.put_u8(3);
            put_bytes(output, &key)?;
            put_bytes(output, &value)?;
        }
        Message::Delete { key } => {
            output.put_u8(4);
            put_bytes(output, &key)?;
        }
        Message::Scan { start, end, limit } => {
            output.put_u8(5);
            put_optional_bytes(output, start.as_deref())?;
            put_optional_bytes(output, end.as_deref())?;
            output.put_u32(limit);
        }
        Message::Subscribe { prefix } => {
            output.put_u8(12);
            put_bytes(output, &prefix)?;
        }
        Message::SubscribeFrom { prefix, cursor } => {
            output.put_u8(45);
            put_bytes(output, &prefix)?;
            put_optional_string(output, cursor.as_deref())?;
        }
        Message::SubscribeCollectionFrom { collection, cursor } => {
            output.put_u8(46);
            put_string(output, &collection)?;
            put_optional_string(output, cursor.as_deref())?;
        }
        Message::CursorChange { cursor, key, value } => {
            output.put_u8(47);
            put_string(output, &cursor)?;
            put_bytes(output, &key)?;
            put_optional_bytes(output, value.as_deref())?;
        }
        Message::CursorDocumentChange {
            cursor,
            collection,
            id,
            document,
        } => {
            output.put_u8(48);
            put_string(output, &cursor)?;
            put_string(output, &collection)?;
            put_string(output, &id)?;
            put_optional_bytes(output, document.as_deref())?;
        }
        Message::Caught { cursor } => {
            output.put_u8(49);
            put_string(output, &cursor)?;
        }
        Message::Begin => output.put_u8(15),
        Message::Commit => output.put_u8(16),
        Message::Rollback => output.put_u8(17),
        Message::CreateIndex { name, unique } => {
            output.put_u8(21);
            put_bytes(output, &name)?;
            output.put_u8(u8::from(unique));
        }
        Message::DropIndex { name } => {
            output.put_u8(22);
            put_bytes(output, &name)?;
        }
        Message::IndexUpdate {
            index,
            primary_key,
            old_value,
            new_value,
        } => {
            output.put_u8(23);
            put_bytes(output, &index)?;
            put_bytes(output, &primary_key)?;
            put_optional_bytes(output, old_value.as_deref())?;
            put_optional_bytes(output, new_value.as_deref())?;
        }
        Message::IndexLookup {
            index,
            value,
            limit,
        } => {
            output.put_u8(24);
            put_bytes(output, &index)?;
            put_bytes(output, &value)?;
            output.put_u32(limit);
        }
        Message::CreateCollection {
            collection,
            indexes,
        } => {
            output.put_u8(31);
            put_string(output, &collection)?;
            output.put_u32(
                indexes
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many document indexes"))?,
            );
            for index in indexes {
                put_string(output, &index.field)?;
                output.put_u8(u8::from(index.unique));
            }
        }
        Message::GetDocument { collection, id } => {
            output.put_u8(32);
            put_string(output, &collection)?;
            put_string(output, &id)?;
        }
        Message::PutDocument {
            collection,
            id,
            document,
        } => {
            output.put_u8(33);
            put_string(output, &collection)?;
            put_string(output, &id)?;
            put_bytes(output, &document)?;
        }
        Message::DeleteDocument { collection, id } => {
            output.put_u8(34);
            put_string(output, &collection)?;
            put_string(output, &id)?;
        }
        Message::ListDocuments { collection, limit } => {
            output.put_u8(35);
            put_string(output, &collection)?;
            output.put_u32(limit);
        }
        Message::QueryDocuments {
            collection,
            field,
            value,
            limit,
        } => {
            output.put_u8(36);
            put_string(output, &collection)?;
            put_string(output, &field)?;
            put_bytes(output, &value)?;
            output.put_u32(limit);
        }
        Message::SubscribeCollection { collection } => {
            output.put_u8(37);
            put_string(output, &collection)?;
        }
        Message::CollectionCreated => output.put_u8(38),
        Message::DocumentValue { document } => {
            output.put_u8(39);
            put_optional_bytes(output, document.as_deref())?;
        }
        Message::DocumentWritten => output.put_u8(40),
        Message::DocumentDeleted { existed } => {
            output.put_u8(41);
            output.put_u8(u8::from(existed));
        }
        Message::Documents { documents } => {
            output.put_u8(42);
            output.put_u32(
                documents
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many documents"))?,
            );
            for (id, document) in documents {
                put_string(output, &id)?;
                put_bytes(output, &document)?;
            }
        }
        Message::CollectionSubscribed => output.put_u8(43),
        Message::DocumentChange {
            sequence,
            id,
            document,
        } => {
            output.put_u8(44);
            output.put_u64(sequence);
            put_string(output, &id)?;
            put_optional_bytes(output, document.as_deref())?;
        }
        Message::Authenticated => output.put_u8(6),
        Message::Value { value } => {
            output.put_u8(7);
            put_optional_bytes(output, value.as_deref())?;
        }
        Message::Values { values } => {
            output.put_u8(30);
            output.put_u32(
                values
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many values"))?,
            );
            for value in values {
                put_optional_bytes(output, value.as_deref())?;
            }
        }
        Message::Written => output.put_u8(8),
        Message::Deleted { existed } => {
            output.put_u8(9);
            output.put_u8(u8::from(existed));
        }
        Message::Rows { rows } => {
            output.put_u8(10);
            output.put_u32(
                rows.len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many rows"))?,
            );
            for (key, value) in rows {
                put_bytes(output, &key)?;
                put_bytes(output, &value)?;
            }
        }
        Message::Subscribed => output.put_u8(13),
        Message::Begun => output.put_u8(18),
        Message::Committed => output.put_u8(19),
        Message::RolledBack => output.put_u8(20),
        Message::IndexCreated => output.put_u8(25),
        Message::IndexDropped => output.put_u8(26),
        Message::IndexUpdated => output.put_u8(27),
        Message::Keys { keys } => {
            output.put_u8(28);
            output.put_u32(
                keys.len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many keys"))?,
            );
            for key in keys {
                put_bytes(output, &key)?;
            }
        }
        Message::Change {
            sequence,
            key,
            value,
        } => {
            output.put_u8(14);
            output.put_u64(sequence);
            put_bytes(output, &key)?;
            put_optional_bytes(output, value.as_deref())?;
        }
        Message::Error { code, message } => {
            output.put_u8(11);
            output.put_u8(error_code(code));
            put_string(output, &message)?;
        }
    }
    Ok(())
}

fn decode_envelope(input: &mut BytesMut) -> Result<Envelope, CodecError> {
    require(input, 11)?;
    let version = input.get_u16();
    let request_id = input.get_u64();
    let kind = input.get_u8();
    let message = match kind {
        1 => Message::Authenticate {
            username: get_string(input, MAX_AUTH_FIELD)?,
            password: get_string(input, MAX_AUTH_FIELD)?,
            database: get_string(input, MAX_AUTH_FIELD)?,
        },
        2 => Message::Get {
            key: get_bytes(input, MAX_FRAME_SIZE)?,
        },
        3 => Message::Put {
            key: get_bytes(input, MAX_FRAME_SIZE)?,
            value: get_bytes(input, MAX_FRAME_SIZE)?,
        },
        4 => Message::Delete {
            key: get_bytes(input, MAX_FRAME_SIZE)?,
        },
        5 => Message::Scan {
            start: get_optional_bytes(input, MAX_FRAME_SIZE)?,
            end: get_optional_bytes(input, MAX_FRAME_SIZE)?,
            limit: get_u32(input)?,
        },
        6 => Message::Authenticated,
        7 => Message::Value {
            value: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        8 => Message::Written,
        9 => Message::Deleted {
            existed: get_bool(input)?,
        },
        10 => {
            let count = get_u32(input)? as usize;
            if count > MAX_SCAN_LIMIT as usize {
                return Err(CodecError::Malformed("too many rows"));
            }
            let mut rows = Vec::with_capacity(count);
            for _ in 0..count {
                rows.push((
                    get_bytes(input, MAX_FRAME_SIZE)?,
                    get_bytes(input, MAX_FRAME_SIZE)?,
                ));
            }
            Message::Rows { rows }
        }
        11 => Message::Error {
            code: decode_error_code(get_u8(input)?)?,
            message: get_string(input, MAX_ERROR_MESSAGE)?,
        },
        12 => Message::Subscribe {
            prefix: get_bytes(input, MAX_FRAME_SIZE)?,
        },
