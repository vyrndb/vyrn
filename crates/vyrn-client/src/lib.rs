use futures_util::{SinkExt, StreamExt};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use std::{
    fmt,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;
use url::Url;
use vyrn_protocol::{
    DocumentIndex, Envelope, ErrorCode, Message, VyrnCodec, DEFAULT_SCAN_LIMIT, MAX_SCAN_LIMIT,
    PROTOCOL_VERSION,
};

const DEFAULT_PORT: u16 = 7432;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
type BoxedTransport = Box<dyn Transport>;

#[derive(Clone)]
pub struct ConnectionOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    password: String,
    pub database: String,
    pub tls_required: bool,
}

impl fmt::Debug for ConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("database", &self.database)
            .field("tls_required", &self.tls_required)
            .finish()
    }
}

impl ConnectionOptions {
    pub fn parse(connection_string: &str) -> Result<Self, Error> {
        let url = Url::parse(connection_string)
            .map_err(|_| Error::InvalidConnectionString("invalid URL".into()))?;
        if url.scheme() != "vyrn" {
            return Err(Error::InvalidConnectionString("scheme must be vyrn".into()));
        }
        if url.fragment().is_some() {
            return Err(Error::InvalidConnectionString(
                "fragments are not supported".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidConnectionString("host is required".into()))?
            .to_owned();
        let username = if url.username().is_empty() {
            return Err(Error::InvalidConnectionString(
                "username is required".into(),
            ));
        } else {
            url.username().to_owned()
        };
        let password = url
            .password()
            .filter(|password| !password.is_empty())
            .ok_or_else(|| Error::InvalidConnectionString("password is required".into()))?
            .to_owned();
        let database = url
            .path()
            .strip_prefix('/')
            .unwrap_or(url.path())
            .to_owned();
        if database.is_empty() || database.contains('/') {
            return Err(Error::InvalidConnectionString(
                "exactly one database name is required".into(),
            ));
        }

        let mut tls_required = true;
        let mut saw_tls = false;
        for (key, value) in url.query_pairs() {
            if key != "tls" || saw_tls {
                return Err(Error::InvalidConnectionString(format!(
                    "unsupported or duplicate option {key}"
                )));
            }
            tls_required = match value.as_ref() {
                "require" => true,
                "disable" => false,
                _ => {
                    return Err(Error::InvalidConnectionString(
                        "tls must be require or disable".into(),
                    ))
                }
            };
            saw_tls = true;
        }

        Ok(Self {
            host,
            port: url.port().unwrap_or(DEFAULT_PORT),
            username,
            password,
            database,
            tls_required,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid connection string: {0}")]
    InvalidConnectionString(String),
    #[error("TLS requires a CA certificate file")]
    MissingCa,
    #[error("connection timed out")]
    Timeout,
    #[error("connection has an unfinished transaction")]
    TransactionActive,
    #[error("connection closed by server")]
    ConnectionClosed,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("document error: {0}")]
    Document(String),
    #[error("server returned {code:?}: {message}")]
    Server { code: ErrorCode, message: String },
    #[error("transport security error: {0}")]
    Tls(String),
    #[error("I/O or codec error: {0}")]
    Transport(String),
}

pub struct Change {
    pub sequence: u64,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

/// One event from a resumable subscription.
///
/// Persist `cursor` after processing an event; passing it to a later
/// `subscribe_*_from` call resumes without gaps or duplicates. `Caught` marks
/// the end of the replayed backlog, so a client can tell history from live
/// traffic.
pub enum StreamEvent {
    Change {
        cursor: String,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    Document {
        cursor: String,
        collection: String,
        id: String,
        value: Option<serde_json::Value>,
    },
    Caught {
        cursor: String,
    },
}

impl StreamEvent {
    pub fn cursor(&self) -> &str {
        match self {
            Self::Change { cursor, .. }
            | Self::Document { cursor, .. }
            | Self::Caught { cursor } => cursor,
        }
    }
}

/// A subscription that reports durable cursors so it can be resumed.
pub struct CursorSubscription {
    framed: Framed<BoxedTransport, VyrnCodec>,
}

impl CursorSubscription {
    pub async fn next(&mut self) -> Result<Option<StreamEvent>, Error> {
        let Some(message) = self.framed.next().await else {
            return Ok(None);
        };
        let envelope = message.map_err(|error| Error::Transport(error.to_string()))?;
        match envelope.message {
            Message::CursorChange { cursor, key, value } => {
                Ok(Some(StreamEvent::Change { cursor, key, value }))
            }
            Message::CursorDocumentChange {
                cursor,
                collection,
                id,
                document,
            } => Ok(Some(StreamEvent::Document {
                cursor,
                collection,
                id,
                value: document.as_deref().map(decode_document).transpose()?,
            })),
            Message::Caught { cursor } => Ok(Some(StreamEvent::Caught { cursor })),
            Message::Error { code, message } => Err(Error::Server { code, message }),
            message => Err(unexpected(message)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionIndex {
    pub field: String,
    pub unique: bool,
}

impl CollectionIndex {
    pub fn new(field: impl Into<String>, unique: bool) -> Self {
        Self {
            field: field.into(),
            unique,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub id: String,
    pub value: serde_json::Value,
}

pub struct DocumentChange {
    pub sequence: u64,
    pub id: String,
    pub value: Option<serde_json::Value>,
}

pub struct DocumentSubscription {
    framed: Framed<BoxedTransport, VyrnCodec>,
}

impl DocumentSubscription {
    pub async fn next(&mut self) -> Result<Option<DocumentChange>, Error> {
        let Some(message) = self.framed.next().await else {
            return Ok(None);
        };
        let envelope = message.map_err(|error| Error::Transport(error.to_string()))?;
        match envelope.message {
            Message::DocumentChange {
                sequence,
                id,
                document,
            } => Ok(Some(DocumentChange {
                sequence,
                id,
                value: document.as_deref().map(decode_document).transpose()?,
            })),
            Message::Error { code, message } => Err(Error::Server { code, message }),
            message => Err(unexpected(message)),
        }
    }
}

pub struct Subscription {
    framed: Framed<BoxedTransport, VyrnCodec>,
}

impl Subscription {
    pub async fn next(&mut self) -> Result<Option<Change>, Error> {
        let Some(message) = self.framed.next().await else {
            return Ok(None);
        };
        let envelope = message.map_err(|error| Error::Transport(error.to_string()))?;
        match envelope.message {
            Message::Change {
                sequence,
                key,
                value,
            } => Ok(Some(Change {
                sequence,
                key,
                value,
            })),
            Message::Error { code, message } => Err(Error::Server { code, message }),
            message => Err(unexpected(message)),
        }
    }
}

pub struct Client {
    framed: Framed<BoxedTransport, VyrnCodec>,
    next_request_id: u64,
    transaction_active: bool,
}

pub struct Transaction<'a> {
    client: &'a mut Client,
}

impl Client {
    pub async fn connect(connection_string: &str) -> Result<Self, Error> {
        let ca_path = std::env::var_os("VYRN_TLS_CA_FILE").map(PathBuf::from);
        Self::connect_with_ca(connection_string, ca_path.as_deref()).await
    }

    pub async fn connect_with_ca(
        connection_string: &str,
        ca_path: Option<&Path>,
    ) -> Result<Self, Error> {
        let options = ConnectionOptions::parse(connection_string)?;
        let stream = timeout(
            REQUEST_TIMEOUT,
            TcpStream::connect((options.host.as_str(), options.port)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|error| Error::Transport(error.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|error| Error::Transport(error.to_string()))?;

        let transport: BoxedTransport = if options.tls_required {
            let ca_path = ca_path.ok_or(Error::MissingCa)?;
            let roots = load_ca(ca_path)?;
            let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = ServerName::try_from(options.host.clone())
                .map_err(|_| Error::Tls("host is not a valid TLS server name".into()))?;
            let tls = timeout(
                REQUEST_TIMEOUT,
                TlsConnector::from(Arc::new(config)).connect(server_name, stream),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Tls(error.to_string()))?;
            Box::new(tls)
        } else {
            Box::new(stream)
        };

        let mut client = Self {
            framed: Framed::new(transport, VyrnCodec::default()),
            next_request_id: 1,
            transaction_active: false,
        };
        match client
            .request(Message::Authenticate {
                username: options.username,
                password: options.password,
                database: options.database,
            })
            .await?
        {
            Message::Authenticated => Ok(client),
            _ => Err(Error::Protocol("unexpected authentication response".into())),
        }
    }

    pub async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        match self.request(Message::Get { key }).await? {
            Message::Value { value } => Ok(value),
            message => Err(unexpected(message)),
        }
    }

    pub async fn multi_get(&mut self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>, Error> {
        match self.request(Message::MultiGet { keys }).await? {
            Message::Values { values } => Ok(values),
            message => Err(unexpected(message)),
        }
    }

    pub async fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        match self.request(Message::Put { key, value }).await? {
            Message::Written => Ok(()),
            message => Err(unexpected(message)),
        }
    }

    pub async fn delete(&mut self, key: Vec<u8>) -> Result<bool, Error> {
        match self.request(Message::Delete { key }).await? {
            Message::Deleted { existed } => Ok(existed),
            message => Err(unexpected(message)),
        }
    }

    pub async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        match self.request(Message::Begin).await? {
            Message::Begun => {
                self.transaction_active = true;
                Ok(Transaction { client: self })
            }
            message => Err(unexpected(message)),
        }
    }

    pub async fn create_index(&mut self, name: Vec<u8>, unique: bool) -> Result<(), Error> {
        match self.request(Message::CreateIndex { name, unique }).await? {
            Message::IndexCreated => Ok(()),
            message => Err(unexpected(message)),
        }
    }

    pub async fn drop_index(&mut self, name: Vec<u8>) -> Result<(), Error> {
        match self.request(Message::DropIndex { name }).await? {
            Message::IndexDropped => Ok(()),
            message => Err(unexpected(message)),
        }
    }

    pub async fn lookup_index(
        &mut self,
        index: Vec<u8>,
        value: Vec<u8>,
        limit: Option<u32>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let limit = limit.unwrap_or(DEFAULT_SCAN_LIMIT).min(MAX_SCAN_LIMIT);
        match self
            .request(Message::IndexLookup {
                index,
                value,
                limit,
            })
            .await?
        {
            Message::Keys { keys } => Ok(keys),
            message => Err(unexpected(message)),
        }
    }

    pub async fn create_collection(
        &mut self,
        collection: &str,
        indexes: &[CollectionIndex],
    ) -> Result<(), Error> {
        match self
            .request(Message::CreateCollection {
                collection: collection.to_owned(),
                indexes: indexes
                    .iter()
                    .map(|index| DocumentIndex {
                        field: index.field.clone(),
                        unique: index.unique,
                    })
                    .collect(),
            })
            .await?
        {
            Message::CollectionCreated => Ok(()),
            message => Err(unexpected(message)),
        }
    }

    pub async fn get_document(
        &mut self,
        collection: &str,
        id: &str,
    ) -> Result<Option<Document>, Error> {
        match self
            .request(Message::GetDocument {
                collection: collection.to_owned(),
                id: id.to_owned(),
            })
            .await?
        {
            Message::DocumentValue { document } => document
                .as_deref()
                .map(|bytes| {
                    Ok(Document {
                        id: id.to_owned(),
                        value: decode_document(bytes)?,
                    })
                })
                .transpose(),
            message => Err(unexpected(message)),
        }
    }

    pub async fn put_document<T: serde::Serialize>(
        &mut self,
        collection: &str,
        id: &str,
        value: &T,
    ) -> Result<(), Error> {
        let document = serde_json::to_vec(value)
            .map_err(|error| Error::Document(format!("document is not valid JSON: {error}")))?;
        match self
            .request(Message::PutDocument {
                collection: collection.to_owned(),
                id: id.to_owned(),
                document,
            })
            .await?
        {
            Message::DocumentWritten => Ok(()),
            message => Err(unexpected(message)),
        }
    }

    pub async fn delete_document(&mut self, collection: &str, id: &str) -> Result<bool, Error> {
        match self
            .request(Message::DeleteDocument {
                collection: collection.to_owned(),
                id: id.to_owned(),
            })
            .await?
        {
            Message::DocumentDeleted { existed } => Ok(existed),
            message => Err(unexpected(message)),
        }
    }

    pub async fn list_documents(
        &mut self,
        collection: &str,
        limit: Option<u32>,
    ) -> Result<Vec<Document>, Error> {
        let limit = limit.unwrap_or(DEFAULT_SCAN_LIMIT).min(MAX_SCAN_LIMIT);
        match self
            .request(Message::ListDocuments {
                collection: collection.to_owned(),
                limit,
            })
            .await?
        {
            Message::Documents { documents } => decode_documents(documents),
            message => Err(unexpected(message)),
        }
    }

    pub async fn query_documents(
        &mut self,
        collection: &str,
        field: &str,
        value: &serde_json::Value,
        limit: Option<u32>,
    ) -> Result<Vec<Document>, Error> {
        let limit = limit.unwrap_or(DEFAULT_SCAN_LIMIT).min(MAX_SCAN_LIMIT);
        let value = serde_json::to_vec(value)
            .map_err(|error| Error::Document(format!("query value is not valid JSON: {error}")))?;
        match self
            .request(Message::QueryDocuments {
                collection: collection.to_owned(),
                field: field.to_owned(),
                value,
                limit,
            })
            .await?
        {
            Message::Documents { documents } => decode_documents(documents),
            message => Err(unexpected(message)),
        }
    }

    pub async fn subscribe_collection(
        mut self,
        collection: &str,
    ) -> Result<DocumentSubscription, Error> {
        match self
            .request(Message::SubscribeCollection {
                collection: collection.to_owned(),
            })
            .await?
        {
            Message::CollectionSubscribed => Ok(DocumentSubscription {
                framed: self.framed,
            }),
            message => Err(unexpected(message)),
        }
    }

    /// Subscribes to key changes, resuming after `cursor`.
    ///
    /// `None` delivers only changes committed after this call. `Some("")`
    /// replays everything still retained. A stale cursor fails with
    /// `ErrorCode::InvalidRequest` rather than silently skipping changes.
    pub async fn subscribe_from(
        mut self,
        prefix: Vec<u8>,
        cursor: Option<String>,
    ) -> Result<CursorSubscription, Error> {
        match self
            .request(Message::SubscribeFrom { prefix, cursor })
            .await?
        {
            Message::Subscribed => Ok(CursorSubscription {
                framed: self.framed,
            }),
            message => Err(unexpected(message)),
        }
    }

    /// Subscribes to document changes in one collection, resuming after `cursor`.
    pub async fn subscribe_collection_from(
        mut self,
        collection: &str,
        cursor: Option<String>,
    ) -> Result<CursorSubscription, Error> {
        match self
            .request(Message::SubscribeCollectionFrom {
                collection: collection.to_owned(),
                cursor,
            })
            .await?
        {
            Message::CollectionSubscribed => Ok(CursorSubscription {
                framed: self.framed,
            }),
            message => Err(unexpected(message)),
        }
    }

    pub async fn subscribe(mut self, prefix: Vec<u8>) -> Result<Subscription, Error> {
        match self.request(Message::Subscribe { prefix }).await? {
            Message::Subscribed => Ok(Subscription {
                framed: self.framed,
            }),
            message => Err(unexpected(message)),
        }
    }

    pub async fn scan(
        &mut self,
        start: Option<Vec<u8>>,
        end: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let limit = limit.unwrap_or(DEFAULT_SCAN_LIMIT).min(MAX_SCAN_LIMIT);
        match self.request(Message::Scan { start, end, limit }).await? {
            Message::Rows { rows } => Ok(rows),
            message => Err(unexpected(message)),
        }
    }

    async fn request(&mut self, message: Message) -> Result<Message, Error> {
        if self.transaction_active {
            match self.request_raw(Message::Rollback).await? {
                Message::RolledBack => self.transaction_active = false,
                message => return Err(unexpected(message)),
            }
        }
        self.request_raw(message).await
    }

    async fn request_raw(&mut self, message: Message) -> Result<Message, Error> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(1);
        timeout(
            REQUEST_TIMEOUT,
            self.framed.send(Envelope::new(request_id, message)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|error| Error::Transport(error.to_string()))?;

        let response = timeout(REQUEST_TIMEOUT, self.framed.next())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or(Error::ConnectionClosed)?
            .map_err(|error| Error::Transport(error.to_string()))?;
        if response.version != PROTOCOL_VERSION {
            return Err(Error::Protocol(
                "server used an unsupported protocol version".into(),
            ));
        }
        if response.request_id != request_id {
            return Err(Error::Protocol("response request ID did not match".into()));
        }
        match response.message {
            Message::Error { code, message } => Err(Error::Server { code, message }),
            message => Ok(message),
        }
    }
}

impl Transaction<'_> {
    pub async fn update_index(
        &mut self,
        index: Vec<u8>,
        primary_key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        match self
            .client
