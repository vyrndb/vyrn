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
