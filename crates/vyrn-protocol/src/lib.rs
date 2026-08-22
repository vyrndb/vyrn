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
/// Replica identifier length. Short on purpose: it names a node in logs and
/// metrics, so it is a label, not a channel for arbitrary data.
const MAX_REPLICA_ID: usize = 256;
/// Records carried in one `ReplicaRecords` frame.
///
/// The primary's flush stage coalesces commits, so a batch is normally a handful.
/// This is the ceiling that stops a wire-supplied count from driving a large
/// allocation before any record has been read.
const MAX_REPLICA_RECORDS: usize = 4_096;
/// Largest single WAL record accepted from the wire.
///
/// Vyrn permits values up to 16 MiB, and a record holds a whole batch of
/// operations, so this has to be generous — but it must still be bounded well
/// under `MAX_FRAME_SIZE` so one oversized record cannot fill a frame by itself.
const MAX_REPLICA_RECORD: usize = 32 * 1024 * 1024;

/// Which wire limit applies to the field currently being written.
///
/// The decoder has always enforced a ceiling on every length-delimited field;
/// this names those same ceilings on the encode side, so both directions fail
/// on exactly the same input. It exists because "how long may this field be"
/// is a property of the field's meaning, not of its Rust type: a cursor and a
/// document name are both `String` and both bounded, by very different amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldLimit {
    /// Username, password and database names.
    AuthField,
    /// Collection names and document ids.
    DocumentName,
    /// Durable subscription cursors.
    Cursor,
    /// Human-readable text carried by `Error` and `ReplicaDiverged`.
    ErrorMessage,
    /// The short label a replica is known by in logs and metrics.
    ReplicaId,
    /// One WAL record carried on the replication stream.
    ReplicaRecord,
    /// Keys, values and prefixes: bounded only by the frame that carries them.
    Opaque,
}

impl FieldLimit {
    fn maximum(self) -> usize {
        match self {
            Self::AuthField => MAX_AUTH_FIELD,
            Self::DocumentName => MAX_DOCUMENT_NAME,
            Self::Cursor => MAX_CURSOR,
            Self::ErrorMessage => MAX_ERROR_MESSAGE,
            Self::ReplicaId => MAX_REPLICA_ID,
            Self::ReplicaRecord => MAX_REPLICA_RECORD,
            Self::Opaque => MAX_FRAME_SIZE,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::AuthField => "authentication field",
            Self::DocumentName => "document name",
            Self::Cursor => "cursor",
            Self::ErrorMessage => "error message",
            Self::ReplicaId => "replica identifier",
            Self::ReplicaRecord => "replication record",
            Self::Opaque => "byte field",
        }
    }
}

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

    // ---- Replication -----------------------------------------------------
    //
    // A replica authenticates exactly like a client, then sends `ReplicaHello`
    // to convert the connection into a replication stream. There is no separate
    // credential system and no unauthenticated replication path.
    //
    // The records on the wire are the WAL's own encoded records, byte for byte,
    // so there is no second serialisation of a mutation to keep in step with the
    // first. The receiving side validates them with the same magic, version and
    // CRC32 checks that recovery uses.
    /// Sent by a replica after authenticating: where its log ends, and who it
    /// is. `last_lsn` is 0 for a replica with no records at all.
    ReplicaHello {
        database: String,
        last_lsn: u64,
        replica_id: String,
    },
    /// The primary accepting the stream, naming the first LSN it will send.
    ///
    /// `first_lsn` greater than the replica's `last_lsn + 1` means the primary
    /// no longer holds the records in between; the replica must close the gap
    /// from the WAL archive before it can stream.
    ReplicaStream {
        first_lsn: u64,
    },
    /// WAL records to append, in ascending LSN order.
    ///
    /// Batched because the primary's flush stage already coalesces commits, so a
    /// single barrier there usually covers several records.
    ReplicaRecords {
        records: Vec<Vec<u8>>,
    },
    /// The replica confirming records are durable on its own storage.
    ///
    /// Sent only after `sync_through` has returned for `durable_lsn`. Sending it
    /// any earlier would make the primary's acknowledgement to its client a lie.
    ReplicaAck {
        durable_lsn: u64,
    },
    /// The stream is refused because the two histories disagree.
    ///
    /// A replica ahead of the primary, or holding a different record at the join
    /// point, cannot be reconciled by streaming. Halting is the only safe answer:
    /// appending over a divergent history silently corrupts the replica.
    ReplicaDiverged {
        reason: String,
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
            Self::ReplicaHello {
                database,
                last_lsn,
                replica_id,
            } => formatter
                .debug_struct("ReplicaHello")
                .field("database", database)
                .field("last_lsn", last_lsn)
                .field("replica_id", replica_id)
                .finish(),
            Self::ReplicaStream { first_lsn } => formatter
                .debug_struct("ReplicaStream")
                .field("first_lsn", first_lsn)
                .finish(),
            // Counts and sizes, never contents: these records carry every value
            // written to the database, so logging them verbatim would put user
            // data in the log.
            Self::ReplicaRecords { records } => formatter
                .debug_struct("ReplicaRecords")
                .field("record_count", &records.len())
                .field("bytes", &records.iter().map(Vec::len).sum::<usize>())
                .finish(),
            Self::ReplicaAck { durable_lsn } => formatter
                .debug_struct("ReplicaAck")
                .field("durable_lsn", durable_lsn)
                .finish(),
            Self::ReplicaDiverged { reason } => formatter
                .debug_struct("ReplicaDiverged")
                .field("reason", reason)
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
    #[error("{field} is {found} bytes, above the {maximum}-byte wire limit")]
    FieldTooLong {
        field: &'static str,
        found: usize,
        maximum: usize,
    },
    #[error("peer speaks protocol version {found}; this codec speaks version {PROTOCOL_VERSION}")]
    VersionMismatch { found: u16 },
}

pub struct VyrnCodec {
    frames: LengthDelimitedCodec,
    max_frame_length: usize,
}

impl VyrnCodec {
    /// Begins configuring a codec. Everything except the frame ceiling is fixed
    /// by the protocol, so it is the only knob.
    pub fn builder() -> VyrnCodecBuilder {
        VyrnCodecBuilder {
            max_frame_length: MAX_FRAME_SIZE,
        }
    }

    fn with_frame_ceiling(max_frame_length: usize) -> Self {
        assert!(
            max_frame_length > 0,
            "max_frame_length must be greater than zero"
        );
        Self {
            frames: LengthDelimitedCodec::builder()
                .max_frame_length(max_frame_length)
                .new_codec(),
            max_frame_length,
        }
    }
}

/// Builder for [`VyrnCodec`].
///
/// The intended use is the pre-auth tier: an unauthenticated peer can make the
/// server buffer up to the frame ceiling per connection before it has shown a
/// single credential, so a server can lower that ceiling for the handshake and
/// raise it once the peer is trusted. The default stays `MAX_FRAME_SIZE`.
#[derive(Debug, Clone)]
pub struct VyrnCodecBuilder {
    max_frame_length: usize,
}

impl VyrnCodecBuilder {
    /// Caps the length of one framed message, in both directions.
    pub fn max_frame_length(mut self, max_frame_length: usize) -> Self {
        self.max_frame_length = max_frame_length;
        self
    }

    pub fn build(self) -> VyrnCodec {
        VyrnCodec::with_frame_ceiling(self.max_frame_length)
    }
}

impl Default for VyrnCodec {
    fn default() -> Self {
        Self::with_frame_ceiling(MAX_FRAME_SIZE)
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
        if encoded.len() > self.max_frame_length {
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
            put_string(output, &username, FieldLimit::AuthField)?;
            put_string(output, &password, FieldLimit::AuthField)?;
            put_string(output, &database, FieldLimit::AuthField)?;
        }
        Message::Get { key } => {
            output.put_u8(2);
            put_bytes(output, &key, FieldLimit::Opaque)?;
        }
        Message::MultiGet { keys } => {
            output.put_u8(29);
            output.put_u32(
                keys.len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many keys"))?,
            );
            for key in keys {
                put_bytes(output, &key, FieldLimit::Opaque)?;
            }
        }
        Message::Put { key, value } => {
            output.put_u8(3);
            put_bytes(output, &key, FieldLimit::Opaque)?;
            put_bytes(output, &value, FieldLimit::Opaque)?;
        }
        Message::Delete { key } => {
            output.put_u8(4);
            put_bytes(output, &key, FieldLimit::Opaque)?;
        }
        Message::Scan { start, end, limit } => {
            output.put_u8(5);
            put_optional_bytes(output, start.as_deref(), FieldLimit::Opaque)?;
            put_optional_bytes(output, end.as_deref(), FieldLimit::Opaque)?;
            output.put_u32(limit);
        }
        Message::Subscribe { prefix } => {
            output.put_u8(12);
            put_bytes(output, &prefix, FieldLimit::Opaque)?;
        }
        Message::SubscribeFrom { prefix, cursor } => {
            output.put_u8(45);
            put_bytes(output, &prefix, FieldLimit::Opaque)?;
            put_optional_string(output, cursor.as_deref(), FieldLimit::Cursor)?;
        }
        Message::SubscribeCollectionFrom { collection, cursor } => {
            output.put_u8(46);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_optional_string(output, cursor.as_deref(), FieldLimit::Cursor)?;
        }
        Message::CursorChange { cursor, key, value } => {
            output.put_u8(47);
            put_string(output, &cursor, FieldLimit::Cursor)?;
            put_bytes(output, &key, FieldLimit::Opaque)?;
            put_optional_bytes(output, value.as_deref(), FieldLimit::Opaque)?;
        }
        Message::CursorDocumentChange {
            cursor,
            collection,
            id,
            document,
        } => {
            output.put_u8(48);
            put_string(output, &cursor, FieldLimit::Cursor)?;
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_string(output, &id, FieldLimit::DocumentName)?;
            put_optional_bytes(output, document.as_deref(), FieldLimit::Opaque)?;
        }
        Message::Caught { cursor } => {
            output.put_u8(49);
            put_string(output, &cursor, FieldLimit::Cursor)?;
        }
        Message::ReplicaHello {
            database,
            last_lsn,
            replica_id,
        } => {
            output.put_u8(50);
            put_string(output, &database, FieldLimit::AuthField)?;
            output.put_u64(last_lsn);
            put_string(output, &replica_id, FieldLimit::ReplicaId)?;
        }
        Message::ReplicaStream { first_lsn } => {
            output.put_u8(51);
            output.put_u64(first_lsn);
        }
        Message::ReplicaRecords { records } => {
            output.put_u8(52);
            output.put_u32(
                records
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many replication records"))?,
            );
            for record in records {
                put_bytes(output, &record, FieldLimit::ReplicaRecord)?;
            }
        }
        Message::ReplicaAck { durable_lsn } => {
            output.put_u8(53);
            output.put_u64(durable_lsn);
        }
        Message::ReplicaDiverged { reason } => {
            output.put_u8(54);
            put_string(output, &reason, FieldLimit::ErrorMessage)?;
        }
        Message::Begin => output.put_u8(15),
        Message::Commit => output.put_u8(16),
        Message::Rollback => output.put_u8(17),
        Message::CreateIndex { name, unique } => {
            output.put_u8(21);
            put_bytes(output, &name, FieldLimit::Opaque)?;
            output.put_u8(u8::from(unique));
        }
        Message::DropIndex { name } => {
            output.put_u8(22);
            put_bytes(output, &name, FieldLimit::Opaque)?;
        }
        Message::IndexUpdate {
            index,
            primary_key,
            old_value,
            new_value,
        } => {
            output.put_u8(23);
            put_bytes(output, &index, FieldLimit::Opaque)?;
            put_bytes(output, &primary_key, FieldLimit::Opaque)?;
            put_optional_bytes(output, old_value.as_deref(), FieldLimit::Opaque)?;
            put_optional_bytes(output, new_value.as_deref(), FieldLimit::Opaque)?;
        }
        Message::IndexLookup {
            index,
            value,
            limit,
        } => {
            output.put_u8(24);
            put_bytes(output, &index, FieldLimit::Opaque)?;
            put_bytes(output, &value, FieldLimit::Opaque)?;
            output.put_u32(limit);
        }
        Message::CreateCollection {
            collection,
            indexes,
        } => {
            output.put_u8(31);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            output.put_u32(
                indexes
                    .len()
                    .try_into()
                    .map_err(|_| CodecError::Malformed("too many document indexes"))?,
            );
            for index in indexes {
                put_string(output, &index.field, FieldLimit::DocumentName)?;
                output.put_u8(u8::from(index.unique));
            }
        }
        Message::GetDocument { collection, id } => {
            output.put_u8(32);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_string(output, &id, FieldLimit::DocumentName)?;
        }
        Message::PutDocument {
            collection,
            id,
            document,
        } => {
            output.put_u8(33);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_string(output, &id, FieldLimit::DocumentName)?;
            put_bytes(output, &document, FieldLimit::Opaque)?;
        }
        Message::DeleteDocument { collection, id } => {
            output.put_u8(34);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_string(output, &id, FieldLimit::DocumentName)?;
        }
        Message::ListDocuments { collection, limit } => {
            output.put_u8(35);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            output.put_u32(limit);
        }
        Message::QueryDocuments {
            collection,
            field,
            value,
            limit,
        } => {
            output.put_u8(36);
            put_string(output, &collection, FieldLimit::DocumentName)?;
            put_string(output, &field, FieldLimit::DocumentName)?;
            put_bytes(output, &value, FieldLimit::Opaque)?;
            output.put_u32(limit);
        }
        Message::SubscribeCollection { collection } => {
            output.put_u8(37);
            put_string(output, &collection, FieldLimit::DocumentName)?;
        }
        Message::CollectionCreated => output.put_u8(38),
        Message::DocumentValue { document } => {
            output.put_u8(39);
            put_optional_bytes(output, document.as_deref(), FieldLimit::Opaque)?;
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
                put_string(output, &id, FieldLimit::DocumentName)?;
                put_bytes(output, &document, FieldLimit::Opaque)?;
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
            put_string(output, &id, FieldLimit::DocumentName)?;
            put_optional_bytes(output, document.as_deref(), FieldLimit::Opaque)?;
        }
        Message::Authenticated => output.put_u8(6),
        Message::Value { value } => {
            output.put_u8(7);
            put_optional_bytes(output, value.as_deref(), FieldLimit::Opaque)?;
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
                put_optional_bytes(output, value.as_deref(), FieldLimit::Opaque)?;
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
                put_bytes(output, &key, FieldLimit::Opaque)?;
                put_bytes(output, &value, FieldLimit::Opaque)?;
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
                put_bytes(output, &key, FieldLimit::Opaque)?;
            }
        }
        Message::Change {
            sequence,
            key,
            value,
        } => {
            output.put_u8(14);
            output.put_u64(sequence);
            put_bytes(output, &key, FieldLimit::Opaque)?;
            put_optional_bytes(output, value.as_deref(), FieldLimit::Opaque)?;
        }
        Message::Error { code, message } => {
            output.put_u8(11);
            output.put_u8(error_code(code));
            put_string(output, &message, FieldLimit::ErrorMessage)?;
        }
    }
    Ok(())
}

fn decode_envelope(input: &mut BytesMut) -> Result<Envelope, CodecError> {
    require(input, 11)?;
    let version = input.get_u16();
    // The version describes the layout of every byte that follows, so a peer
    // announcing a different one cannot have its frames interpreted safely:
    // they would be misread field by field rather than fail visibly. Enforcing
    // it here puts the check in the layer that owns the wire format instead of
    // leaving each peer to remember to do it.
    if version != PROTOCOL_VERSION {
        return Err(CodecError::VersionMismatch { found: version });
    }
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
        13 => Message::Subscribed,
        14 => Message::Change {
            sequence: get_u64(input)?,
            key: get_bytes(input, MAX_FRAME_SIZE)?,
            value: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        15 => Message::Begin,
        16 => Message::Commit,
        17 => Message::Rollback,
        18 => Message::Begun,
        19 => Message::Committed,
        20 => Message::RolledBack,
        21 => Message::CreateIndex {
            name: get_bytes(input, MAX_FRAME_SIZE)?,
            unique: get_bool(input)?,
        },
        22 => Message::DropIndex {
            name: get_bytes(input, MAX_FRAME_SIZE)?,
        },
        23 => Message::IndexUpdate {
            index: get_bytes(input, MAX_FRAME_SIZE)?,
            primary_key: get_bytes(input, MAX_FRAME_SIZE)?,
            old_value: get_optional_bytes(input, MAX_FRAME_SIZE)?,
            new_value: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        24 => Message::IndexLookup {
            index: get_bytes(input, MAX_FRAME_SIZE)?,
            value: get_bytes(input, MAX_FRAME_SIZE)?,
            limit: get_u32(input)?,
        },
        25 => Message::IndexCreated,
        26 => Message::IndexDropped,
        27 => Message::IndexUpdated,
        28 => {
            let count = get_u32(input)? as usize;
            if count > MAX_SCAN_LIMIT as usize {
                return Err(CodecError::Malformed("too many keys"));
            }
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                keys.push(get_bytes(input, MAX_FRAME_SIZE)?);
            }
            Message::Keys { keys }
        }
        29 => {
            let count = get_u32(input)? as usize;
            // An empty multi-get is odd but harmless, and every other collection
            // in the protocol (rows, keys, values, documents) accepts zero. The
            // codec's job is framing, not policy: refusing emptiness here would
            // kill the connection for something the request layer can decline
            // with an ordinary error response.
            if count > MAX_SCAN_LIMIT as usize {
                return Err(CodecError::Malformed("multi-get key count is out of range"));
            }
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                keys.push(get_bytes(input, MAX_FRAME_SIZE)?);
            }
            Message::MultiGet { keys }
        }
        30 => {
            let count = get_u32(input)? as usize;
            if count > MAX_SCAN_LIMIT as usize {
                return Err(CodecError::Malformed("too many values"));
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(get_optional_bytes(input, MAX_FRAME_SIZE)?);
            }
            Message::Values { values }
        }
        31 => {
            let collection = get_string(input, MAX_DOCUMENT_NAME)?;
            let count = get_u32(input)? as usize;
            if count > MAX_DOCUMENT_INDEXES {
                return Err(CodecError::Malformed("too many document indexes"));
            }
            let mut indexes = Vec::with_capacity(count);
            for _ in 0..count {
                indexes.push(DocumentIndex {
                    field: get_string(input, MAX_DOCUMENT_NAME)?,
                    unique: get_bool(input)?,
                });
            }
            Message::CreateCollection {
                collection,
                indexes,
            }
        }
        32 => Message::GetDocument {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            id: get_string(input, MAX_DOCUMENT_NAME)?,
        },
        33 => Message::PutDocument {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            id: get_string(input, MAX_DOCUMENT_NAME)?,
            document: get_bytes(input, MAX_FRAME_SIZE)?,
        },
        34 => Message::DeleteDocument {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            id: get_string(input, MAX_DOCUMENT_NAME)?,
        },
        35 => Message::ListDocuments {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            limit: get_u32(input)?,
        },
        36 => Message::QueryDocuments {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            field: get_string(input, MAX_DOCUMENT_NAME)?,
            value: get_bytes(input, MAX_FRAME_SIZE)?,
            limit: get_u32(input)?,
        },
        37 => Message::SubscribeCollection {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
        },
        38 => Message::CollectionCreated,
        39 => Message::DocumentValue {
            document: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        40 => Message::DocumentWritten,
        41 => Message::DocumentDeleted {
            existed: get_bool(input)?,
        },
        42 => {
            let count = get_u32(input)? as usize;
            if count > MAX_SCAN_LIMIT as usize {
                return Err(CodecError::Malformed("too many documents"));
            }
            let mut documents = Vec::with_capacity(count);
            for _ in 0..count {
                documents.push((
                    get_string(input, MAX_DOCUMENT_NAME)?,
                    get_bytes(input, MAX_FRAME_SIZE)?,
                ));
            }
            Message::Documents { documents }
        }
        43 => Message::CollectionSubscribed,
        44 => Message::DocumentChange {
            sequence: get_u64(input)?,
            id: get_string(input, MAX_DOCUMENT_NAME)?,
            document: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        45 => Message::SubscribeFrom {
            prefix: get_bytes(input, MAX_FRAME_SIZE)?,
            cursor: get_optional_string(input, MAX_CURSOR)?,
        },
        46 => Message::SubscribeCollectionFrom {
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            cursor: get_optional_string(input, MAX_CURSOR)?,
        },
        47 => Message::CursorChange {
            cursor: get_string(input, MAX_CURSOR)?,
            key: get_bytes(input, MAX_FRAME_SIZE)?,
            value: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        48 => Message::CursorDocumentChange {
            cursor: get_string(input, MAX_CURSOR)?,
            collection: get_string(input, MAX_DOCUMENT_NAME)?,
            id: get_string(input, MAX_DOCUMENT_NAME)?,
            document: get_optional_bytes(input, MAX_FRAME_SIZE)?,
        },
        49 => Message::Caught {
            cursor: get_string(input, MAX_CURSOR)?,
        },
        50 => Message::ReplicaHello {
            database: get_string(input, MAX_AUTH_FIELD)?,
            last_lsn: get_u64(input)?,
            replica_id: get_string(input, MAX_REPLICA_ID)?,
        },
        51 => Message::ReplicaStream {
            first_lsn: get_u64(input)?,
        },
        52 => {
            // Count is checked against its ceiling BEFORE reserving, so a
            // wire-supplied length cannot drive the allocation. `with_capacity`
            // on an unvalidated u32 is remotely triggerable memory exhaustion,
            // which is the exact class of bug tests/decode_fuzz.rs exists for.
            let count = get_u32(input)? as usize;
            if count == 0 || count > MAX_REPLICA_RECORDS {
                return Err(CodecError::Malformed(
                    "replication record count is out of range",
                ));
            }
            let mut records = Vec::with_capacity(count);
            for _ in 0..count {
                let record = get_bytes(input, MAX_REPLICA_RECORD)?;
                // An empty record cannot be a WAL record: the framing alone is
                // 45 header + 8 footer bytes. Rejecting it here means the apply
                // path never has to treat emptiness as a special case.
                if record.is_empty() {
                    return Err(CodecError::Malformed("empty replication record"));
                }
                records.push(record);
            }
            Message::ReplicaRecords { records }
        }
        53 => Message::ReplicaAck {
            durable_lsn: get_u64(input)?,
        },
        54 => Message::ReplicaDiverged {
            reason: get_string(input, MAX_ERROR_MESSAGE)?,
        },
        _ => return Err(CodecError::Malformed("unknown message type")),
    };
    Ok(Envelope {
        version,
        request_id,
        message,
    })
}

fn put_optional_bytes(
    output: &mut BytesMut,
    value: Option<&[u8]>,
    limit: FieldLimit,
) -> Result<(), CodecError> {
    match value {
        Some(value) => {
            output.put_u8(1);
            put_bytes(output, value, limit)
        }
        None => {
            output.put_u8(0);
            Ok(())
        }
    }
}

fn get_optional_bytes(input: &mut BytesMut, maximum: usize) -> Result<Option<Vec<u8>>, CodecError> {
    match get_u8(input)? {
        0 => Ok(None),
        1 => get_bytes(input, maximum).map(Some),
        _ => Err(CodecError::Malformed("invalid optional value")),
    }
}

fn put_string(output: &mut BytesMut, value: &str, limit: FieldLimit) -> Result<(), CodecError> {
    put_bytes(output, value.as_bytes(), limit)
}

fn put_optional_string(
    output: &mut BytesMut,
    value: Option<&str>,
    limit: FieldLimit,
) -> Result<(), CodecError> {
    put_optional_bytes(output, value.map(str::as_bytes), limit)
}

fn get_optional_string(input: &mut BytesMut, maximum: usize) -> Result<Option<String>, CodecError> {
    get_optional_bytes(input, maximum)?
        .map(|value| {
            String::from_utf8(value).map_err(|_| CodecError::Malformed("string is not UTF-8"))
        })
        .transpose()
}

fn get_string(input: &mut BytesMut, maximum: usize) -> Result<String, CodecError> {
    String::from_utf8(get_bytes(input, maximum)?)
        .map_err(|_| CodecError::Malformed("string is not UTF-8"))
}

fn put_bytes(output: &mut BytesMut, value: &[u8], limit: FieldLimit) -> Result<(), CodecError> {
    // The decoder answers an over-limit field by killing the connection, so
    // encoding one would trade a local, describable error for a remote fatal
    // one. Everything written here is produced by our own side, which makes
    // refusing it here a plain programming or input error the caller can
    // report, instead of a race against the peer's decoder.
    if value.len() > limit.maximum() {
        return Err(CodecError::FieldTooLong {
            field: limit.label(),
            maximum: limit.maximum(),
            found: value.len(),
        });
    }
    output.put_u32(
        value
            .len()
            .try_into()
            .map_err(|_| CodecError::Malformed("byte field is too large"))?,
    );
    output.extend_from_slice(value);
    Ok(())
}

fn get_bytes(input: &mut BytesMut, maximum: usize) -> Result<Vec<u8>, CodecError> {
    let length = get_u32(input)? as usize;
    if length > maximum {
        return Err(CodecError::Malformed("byte field exceeds limit"));
    }
    require(input, length)?;
    Ok(input.split_to(length).to_vec())
}

fn get_u8(input: &mut BytesMut) -> Result<u8, CodecError> {
    require(input, 1)?;
    Ok(input.get_u8())
}
fn get_u32(input: &mut BytesMut) -> Result<u32, CodecError> {
    require(input, 4)?;
    Ok(input.get_u32())
}
fn get_u64(input: &mut BytesMut) -> Result<u64, CodecError> {
    require(input, 8)?;
    Ok(input.get_u64())
}
fn get_bool(input: &mut BytesMut) -> Result<bool, CodecError> {
    match get_u8(input)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecError::Malformed("invalid boolean")),
    }
}
fn require(input: &BytesMut, length: usize) -> Result<(), CodecError> {
    if input.remaining() < length {
        Err(CodecError::Malformed("truncated message"))
    } else {
        Ok(())
    }
}

fn error_code(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::AuthenticationFailed => 1,
        ErrorCode::InvalidRequest => 2,
        ErrorCode::UnsupportedVersion => 3,
        ErrorCode::Conflict => 6,
        ErrorCode::Storage => 4,
        ErrorCode::Internal => 5,
    }
}
fn decode_error_code(code: u8) -> Result<ErrorCode, CodecError> {
    match code {
        1 => Ok(ErrorCode::AuthenticationFailed),
        2 => Ok(ErrorCode::InvalidRequest),
        3 => Ok(ErrorCode::UnsupportedVersion),
        4 => Ok(ErrorCode::Storage),
        6 => Ok(ErrorCode::Conflict),
        5 => Ok(ErrorCode::Internal),
        _ => Err(CodecError::Malformed("unknown error code")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(message: Message) {
        let envelope = Envelope::new(42, message);
        let mut codec = VyrnCodec::default();
        let mut bytes = BytesMut::new();
        codec.encode(envelope.clone(), &mut bytes).unwrap();
        assert_eq!(codec.decode(&mut bytes).unwrap(), Some(envelope));
    }

    #[test]
    fn every_message_round_trips() {
        for message in [
            Message::Authenticate {
                username: "u".into(),
                password: "secret".into(),
                database: "d".into(),
            },
            Message::Get { key: vec![0, 1] },
            Message::MultiGet {
                keys: vec![vec![0], vec![1]],
            },
            Message::Put {
                key: vec![2],
                value: vec![3, 4],
            },
            Message::Delete { key: vec![5] },
            Message::Scan {
                start: None,
                end: Some(vec![9]),
                limit: 10,
            },
            Message::Subscribe {
                prefix: b"users/".to_vec(),
            },
            Message::Begin,
            Message::Commit,
            Message::Rollback,
            Message::CreateIndex {
                name: b"email".to_vec(),
                unique: true,
            },
            Message::DropIndex {
                name: b"email".to_vec(),
            },
            Message::IndexUpdate {
                index: b"email".to_vec(),
                primary_key: b"user/1".to_vec(),
                old_value: None,
                new_value: Some(b"a@example.com".to_vec()),
            },
            Message::IndexLookup {
                index: b"email".to_vec(),
                value: b"a@example.com".to_vec(),
                limit: 10,
            },
            Message::Authenticated,
            Message::Value { value: None },
            Message::Values {
                values: vec![Some(vec![1]), None],
            },
            Message::Written,
            Message::Deleted { existed: true },
            Message::Rows {
                rows: vec![(vec![1], vec![2])],
            },
            Message::Subscribed,
            Message::Begun,
            Message::Committed,
            Message::RolledBack,
            Message::IndexCreated,
            Message::IndexDropped,
            Message::IndexUpdated,
            Message::Keys {
                keys: vec![b"user/1".to_vec()],
            },
            Message::Change {
                sequence: 7,
                key: b"users/a".to_vec(),
                value: Some(b"online".to_vec()),
            },
            Message::CreateCollection {
                collection: "users".into(),
                indexes: vec![DocumentIndex {
                    field: "email".into(),
                    unique: true,
                }],
            },
            Message::GetDocument {
                collection: "users".into(),
                id: "user_1".into(),
            },
            Message::PutDocument {
                collection: "users".into(),
                id: "user_1".into(),
                document: br#"{"email":"a@example.com"}"#.to_vec(),
            },
            Message::DeleteDocument {
                collection: "users".into(),
                id: "user_1".into(),
            },
            Message::ListDocuments {
                collection: "users".into(),
                limit: 25,
            },
            Message::QueryDocuments {
                collection: "users".into(),
                field: "email".into(),
                value: br#""a@example.com""#.to_vec(),
                limit: 25,
            },
            Message::SubscribeCollection {
                collection: "users".into(),
            },
            Message::CollectionCreated,
            Message::DocumentValue { document: None },
            Message::DocumentWritten,
            Message::DocumentDeleted { existed: true },
            Message::Documents {
                documents: vec![("user_1".into(), b"{}".to_vec())],
            },
            Message::CollectionSubscribed,
            Message::DocumentChange {
                sequence: 9,
                id: "user_1".into(),
                document: Some(b"{}".to_vec()),
            },
            Message::SubscribeFrom {
                prefix: b"users/".to_vec(),
                cursor: Some("0000000000000007-00000001".into()),
            },
            Message::SubscribeFrom {
                prefix: b"users/".to_vec(),
                cursor: None,
            },
            Message::SubscribeCollectionFrom {
                collection: "users".into(),
                cursor: Some("0000000000000007-00000001".into()),
            },
            Message::CursorChange {
                cursor: "0000000000000008-00000000".into(),
                key: b"users/a".to_vec(),
                value: Some(b"online".to_vec()),
            },
            Message::CursorDocumentChange {
                cursor: "0000000000000009-00000000".into(),
                collection: "users".into(),
                id: "user_1".into(),
                document: None,
            },
            Message::Caught {
                cursor: "0000000000000009-00000000".into(),
            },
            Message::Error {
                code: ErrorCode::Storage,
                message: "bad".into(),
            },
        ] {
            round_trip(message);
        }
    }

    #[test]
    fn an_empty_multi_get_round_trips() {
        // The codec frames, it does not judge: emptiness is the request layer's
        // business. This is the one collection the decoder used to refuse.
        round_trip(Message::MultiGet { keys: Vec::new() });
    }

    #[test]
    fn a_foreign_protocol_version_is_named_not_misread() {
        for version in [PROTOCOL_VERSION - 1, 999] {
            let mut body = BytesMut::new();
            body.put_u16(version);
            body.put_u64(1);
            body.put_u8(2); // Get, with a complete body: only the version is wrong.
            body.put_u32(0);
            match decode_envelope(&mut body) {
                Err(CodecError::VersionMismatch { found }) => assert_eq!(found, version),
                other => panic!("version {version} must be rejected as a version, got {other:?}"),
            }
        }
    }

    #[test]
    fn fields_at_their_limit_still_encode() {
        round_trip(Message::Caught {
            cursor: "c".repeat(MAX_CURSOR),
        });
        round_trip(Message::GetDocument {
            collection: "c".repeat(MAX_DOCUMENT_NAME),
            id: String::new(),
        });
    }

    #[test]
    fn an_oversized_cursor_fails_at_encode_not_on_the_wire() {
        let mut codec = VyrnCodec::default();
        let mut bytes = BytesMut::new();
        let error = codec
            .encode(
                Envelope::new(
                    1,
                    Message::Caught {
                        cursor: "c".repeat(MAX_CURSOR + 1),
                    },
                ),
                &mut bytes,
            )
            .unwrap_err();
        let CodecError::FieldTooLong {
            field,
            found,
            maximum,
        } = error
        else {
            panic!("expected FieldTooLong, got {error}");
        };
        assert_eq!(field, "cursor");
        assert_eq!(found, MAX_CURSOR + 1);
        assert_eq!(maximum, MAX_CURSOR);
        // Nothing was written: a half-built frame must not reach the transport.
        assert!(bytes.is_empty());
    }

    #[test]
    fn an_oversized_document_name_fails_at_encode_not_on_the_wire() {
        let mut codec = VyrnCodec::default();
        let mut bytes = BytesMut::new();
        let error = codec
            .encode(
                Envelope::new(
                    1,
                    Message::GetDocument {
                        collection: "users".into(),
                        id: "d".repeat(MAX_DOCUMENT_NAME + 1),
                    },
                ),
                &mut bytes,
            )
            .unwrap_err();
        let CodecError::FieldTooLong {
            field,
            found,
            maximum,
        } = error
        else {
            panic!("expected FieldTooLong, got {error}");
        };
        assert_eq!(field, "document name");
        assert_eq!(found, MAX_DOCUMENT_NAME + 1);
        assert_eq!(maximum, MAX_DOCUMENT_NAME);
        assert!(bytes.is_empty());
    }

    #[test]
    fn maximum_value_has_low_wire_overhead() {
        let message = Envelope::new(
            1,
            Message::Put {
                key: vec![1; 64 * 1024],
                value: vec![2; 16 * 1024 * 1024],
            },
        );
        let mut codec = VyrnCodec::default();
        let mut bytes = BytesMut::new();
        codec.encode(message, &mut bytes).unwrap();
        assert!(bytes.len() < 17 * 1024 * 1024);
    }

    #[test]
    fn malformed_input_never_panics() {
        for length in 0..64 {
            let mut input = BytesMut::from(&vec![0xff; length][..]);
            let _ = decode_envelope(&mut input);
        }
    }

    #[test]
    fn authentication_debug_redacts_password() {
        let debug = format!(
            "{:?}",
            Message::Authenticate {
                username: "u".into(),
                password: "top-secret".into(),
                database: "d".into()
            }
        );
        assert!(!debug.contains("top-secret"));
    }
}
