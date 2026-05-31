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
