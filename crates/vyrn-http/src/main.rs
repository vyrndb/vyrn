use anyhow::{bail, Context, Result};
use axum::extract::{DefaultBodyLimit, FromRequest};
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use clap::Parser;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    future::Future,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::sleep,
};
use url::Url;
use vyrn_client::{Client, CollectionIndex, Error as ClientError};
use vyrn_protocol::{MAX_DOCUMENT_INDEXES, MAX_SCAN_LIMIT};

const JSON_LIMIT: usize = 24 * 1024 * 1024;

/// How long a pooled connection may sit idle before checkout refuses it.
///
/// The server closes client connections after 300 s of inactivity
/// (`CLIENT_IDLE_TIMEOUT`, vyrn-server); expiring them at half that keeps
/// every connection handed out well inside the server's window.
const MAX_IDLE_AGE: Duration = Duration::from_secs(150);

/// Silence between SSE keepalive comments. Proxies and load balancers drop
/// quiet streams long before subscribers notice anything is wrong.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "vyrn-http", version, about = "Vyrn HTTP and SSE gateway")]
struct Args {
    #[arg(long, env = "VYRN_HTTP_BIND", default_value = "127.0.0.1:7434")]
    bind: String,
    #[arg(long, env = "VYRN_URL")]
    url: String,
    #[arg(long, env = "VYRN_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_TLS_CA_FILE")]
    tls_ca_file: Option<PathBuf>,
    #[arg(long, env = "VYRN_HTTP_TOKEN_FILE")]
    token_file: PathBuf,
    #[arg(long, env = "VYRN_HTTP_IDLE_CONNECTIONS", default_value_t = 64)]
    idle_connections: usize,
    #[arg(long, env = "VYRN_HTTP_MAX_CONNECTIONS")]
    max_connections: Option<usize>,
}

#[derive(Clone)]
struct AppState {
    connection_url: String,
    tls_ca_file: Option<PathBuf>,
    token: Arc<str>,
    clients: Arc<ClientPool>,
}

struct ClientPool {
    idle: Mutex<Vec<PooledClient>>,
    maximum: usize,
    /// Slots for backend connections that are in flight on a request or pinned
    /// by a subscriber, on top of the ones parked in `idle`. Every connection
    /// holds one slot from the moment it is opened until it is dropped, so the
    /// total number of live backend connections never exceeds
    /// idle capacity plus these permits.
    active: Arc<Semaphore>,
}

/// A backend connection together with the connection-budget slot it occupies.
///
/// The permit is taken when the connection is opened and travels with it —
/// parked in `idle`, in flight on a request, or held by an SSE stream — so
/// dropping the connection always releases the slot.
struct PooledClient {
    client: Client,
    idle_since: Instant,
    permit: OwnedSemaphorePermit,
}

impl Deref for PooledClient {
    type Target = Client;

    fn deref(&self) -> &Client {
        &self.client
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorContent<'a>,
}

#[derive(Serialize)]
struct ErrorContent<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Deserialize)]
struct KeyRequest {
    key: String,
}

#[derive(Deserialize)]
struct MultiGetRequest {
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct PutRequest {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct ScanRequest {
    start: Option<String>,
    end: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct TransactionRequest {
    operations: Vec<OperationRequest>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum OperationRequest {
    Put { key: String, value: String },
    Delete { key: String },
}

#[derive(Deserialize)]
struct SubscribeQuery {
    prefix: String,
}

#[derive(Deserialize)]
struct CreateCollectionRequest {
    collection: String,
    #[serde(default)]
    indexes: Vec<IndexRequest>,
}

#[derive(Deserialize)]
struct IndexRequest {
    field: String,
    #[serde(default)]
    unique: bool,
}

#[derive(Deserialize)]
struct DocumentRequest {
    collection: String,
    id: String,
}

#[derive(Deserialize)]
struct PutDocumentRequest {
    collection: String,
    id: String,
    document: serde_json::Value,
}

#[derive(Deserialize)]
struct ListDocumentsRequest {
    collection: String,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct QueryDocumentsRequest {
    collection: String,
    field: String,
    value: serde_json::Value,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct SubscribeCollectionQuery {
    collection: String,
}

#[derive(Serialize)]
struct DocumentResponse {
    id: String,
    document: serde_json::Value,
}

#[derive(Serialize)]
struct OptionalDocumentResponse {
    document: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct DocumentsResponse {
    documents: Vec<DocumentResponse>,
}

#[derive(Serialize)]
struct DocumentChangeResponse {
    sequence: u64,
    id: String,
    document: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ValueResponse {
    value: Option<String>,
}

#[derive(Serialize)]
struct ValuesResponse {
    values: Vec<Option<String>>,
}

#[derive(Serialize)]
struct DeleteResponse {
    existed: bool,
}

#[derive(Serialize)]
struct RowsResponse {
    rows: Vec<RowResponse>,
}

#[derive(Serialize)]
struct RowResponse {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct TransactionResponse {
    deleted: Vec<bool>,
}

#[derive(Serialize)]
struct ChangeResponse {
    sequence: u64,
    key: String,
    value: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let token = read_secret_file(&args.token_file)?;
    let mut connection_url = args.url;
    if let Some(path) = args.password_file {
        connection_url = insert_password(&connection_url, &read_secret_file(&path)?)?;
    }
    let state = AppState {
        connection_url,
        tls_ca_file: args.tls_ca_file,
        token: token.into(),
        clients: Arc::new(ClientPool {
            idle: Mutex::new(Vec::new()),
            maximum: args.idle_connections,
            // Default the live-connection ceiling to twice the idle park size:
            // enough headroom for a burst without letting one endpoint open
            // connections without bound.
            active: Arc::new(Semaphore::new(
                args.max_connections
                    .unwrap_or(args.idle_connections.saturating_mul(2))
                    .max(1),
            )),
        }),
    };
    connect(&state)
        .await
        .context("failed to connect to Vyrn during gateway startup")?;

    let protected = Router::new()
        .route("/v1/get", post(get_value))
        .route("/v1/multi-get", post(multi_get))
        .route("/v1/put", post(put_value))
        .route("/v1/delete", post(delete_value))
        .route("/v1/scan", post(scan))
        .route("/v1/transaction", post(transaction))
        .route("/v1/subscribe", get(subscribe))
        .route("/v1/collections/create", post(create_collection))
        .route("/v1/documents/get", post(get_document))
        .route("/v1/documents/put", post(put_document))
        .route("/v1/documents/delete", post(delete_document))
        .route("/v1/documents/list", post(list_documents))
        .route("/v1/documents/query", post(query_documents))
        .route("/v1/documents/subscribe", get(subscribe_collection))
        .layer(DefaultBodyLimit::max(JSON_LIMIT))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let app = Router::new()
        .route("/health/live", get(|| async { "ok\n" }))
        .route("/health/ready", get(ready))
        .merge(protected)
        .with_state(state);
    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    println!("vyrn-http listening on {}", args.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Preflight is answered before the token check: browsers send OPTIONS
    // without credentials, and refusing it here would break CORS the moment
    // anyone adds it.
    if request.method() == Method::OPTIONS {
        return StatusCode::NO_CONTENT.into_response();
    }
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if supplied
        .is_none_or(|supplied| !constant_time_eq(supplied.as_bytes(), state.token.as_bytes()))
    {
        return ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            "invalid bearer token",
        )
        .into_response();
    }
    next.run(request).await
}

async fn ready(State(state): State<AppState>) -> Response {
    // Readiness shares the pool instead of opening a fresh backend connection
    // per probe. When nothing is idle and every slot in the connection budget
    // is taken, answer overloaded rather than queueing for a new connection:
    // this endpoint is unauthenticated, so a scriptable probe must not be able
    // to amplify connections past the budget.
    if state.clients.idle.lock().await.is_empty()
        && state.clients.active.available_permits() == 0
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "overloaded\n").into_response();
    }
    let probe = pooled(&state, |mut client| async {
        let scanned = client.scan(None, None, Some(1)).await;
        (client, scanned)
    })
    .await;
    match probe {
        Ok(_) => (StatusCode::OK, "ready\n").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response(),
    }
}

async fn get_value(
    State(state): State<AppState>,
    AppJson(request): AppJson<KeyRequest>,
) -> Result<Json<ValueResponse>, ApiError> {
    let key = decode("key", &request.key)?;
    let value = pooled(&state, |mut client| async {
        let value = client.get(key.clone()).await;
        (client, value)
    })
    .await?;
    Ok(Json(ValueResponse {
        value: value.map(|value| STANDARD.encode(value)),
    }))
}

async fn multi_get(
    State(state): State<AppState>,
    AppJson(request): AppJson<MultiGetRequest>,
) -> Result<Json<ValuesResponse>, ApiError> {
    if request.keys.is_empty() || request.keys.len() > MAX_SCAN_LIMIT as usize {
        return Err(ApiError::bad_request(
            "multi-get must contain between 1 and 10000 keys",
        ));
    }
    let keys = request
        .keys
        .into_iter()
        .map(|key| decode("key", &key))
        .collect::<Result<Vec<_>, _>>()?;
    let values = pooled(&state, |mut client| async {
        let values = client.multi_get(keys.clone()).await;
        (client, values)
    })
    .await?
    .into_iter()
    .map(|value| value.map(|value| STANDARD.encode(value)))
    .collect();
    Ok(Json(ValuesResponse { values }))
}

async fn put_value(
    State(state): State<AppState>,
    AppJson(request): AppJson<PutRequest>,
) -> Result<StatusCode, ApiError> {
    let key = decode("key", &request.key)?;
    let value = decode("value", &request.value)?;
    pooled(&state, |mut client| async {
        let written = client.put(key.clone(), value.clone()).await;
        (client, written)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_value(
    State(state): State<AppState>,
    AppJson(request): AppJson<KeyRequest>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let key = decode("key", &request.key)?;
    let existed = pooled(&state, |mut client| async {
        let deleted = client.delete(key.clone()).await;
        (client, deleted)
    })
    .await?;
    Ok(Json(DeleteResponse { existed }))
}

async fn scan(
    State(state): State<AppState>,
    AppJson(request): AppJson<ScanRequest>,
) -> Result<Json<RowsResponse>, ApiError> {
    let limit = request.limit.unwrap_or(1_000);
    if limit == 0 || limit > MAX_SCAN_LIMIT {
        return Err(ApiError::bad_request("limit must be between 1 and 10000"));
    }
    let start = request
        .start
        .map(|value| decode("start", &value))
        .transpose()?;
    let end = request.end.map(|value| decode("end", &value)).transpose()?;
    let rows = pooled(&state, |mut client| async {
        let rows = client.scan(start.clone(), end.clone(), Some(limit)).await;
        (client, rows)
    })
    .await?
    .into_iter()
    .map(|(key, value)| RowResponse {
        key: STANDARD.encode(key),
        value: STANDARD.encode(value),
    })
    .collect();
    Ok(Json(RowsResponse { rows }))
}

async fn transaction(
    State(state): State<AppState>,
    AppJson(request): AppJson<TransactionRequest>,
) -> Result<Json<TransactionResponse>, ApiError> {
    if request.operations.is_empty() {
        return Err(ApiError::bad_request(
            "transaction must contain an operation",
        ));
    }
    if request.operations.len() > 10_000 {
        return Err(ApiError::bad_request(
            "transaction exceeds 10000 operations",
        ));
    }
    // Begin is retried here rather than inside `pooled` on purpose. Begin is
    // the first exchange on the connection, so a stale pooled connection can
    // only have failed before the server saw anything — replaying it applies
    // nothing twice. Once a transaction is open the connection carries state:
    // a connection lost after some operations ran may still have committed
    // them server-side, so the remaining operations are never replayed.
    let mut client = checkout(&state).await?;
    let mut begun = client.transaction().await;
    if matches!(&begun, Err(error) if is_dead_connection(error)) {
        let error = begun.err().unwrap();
        eprintln!("vyrn-http discarding stale pooled connection: {error}");
        client = connect_api(&state).await?;
        begun = client.transaction().await;
    }
    let mut transaction = begun.map_err(ApiError::from)?;
    let mut deleted = Vec::new();
    for operation in &request.operations {
        match operation {
            OperationRequest::Put { key, value } => {
                transaction
                    .put(decode("key", key)?, decode("value", value)?)
                    .await?;
            }
            OperationRequest::Delete { key } => {
                deleted.push(transaction.delete(decode("key", key)?).await?);
            }
        }
    }
    transaction.commit().await?;
    checkin(&state, client).await;
    Ok(Json(TransactionResponse { deleted }))
}

async fn subscribe(
    State(state): State<AppState>,
    Query(query): Query<SubscribeQuery>,
) -> Result<Response, ApiError> {
    let prefix = decode_query("prefix", &query.prefix)?;
    let backend = connect_api(&state).await?;
    let PooledClient { client, permit, .. } = backend;
    let mut subscription = client.subscribe(prefix).await?;
    let stream = async_stream::stream! {
        // The connection-budget slot stays held for as long as the subscriber
        // is connected; dropping the stream releases it.
        let _permit = permit;
        loop {
            tokio::select! {
                event = subscription.next() => {
                    match event {
                        Ok(Some(change)) => {
                            let payload = serde_json::to_string(&ChangeResponse {
                                sequence: change.sequence,
                                key: STANDARD.encode(change.key),
                                value: change.value.map(|value| STANDARD.encode(value)),
                            }).unwrap();
                            yield Ok::<_, Infallible>(format!("data: {payload}\n\n"));
                        }
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("vyrn-http subscription failed: {error}");
                            let payload = serde_json::json!({
                                "error": { "code": "subscription_closed", "message": "subscription terminated" }
                            });
                            yield Ok(format!("event: error\ndata: {payload}\n\n"));
                            break;
                        }
                    }
                }
                _ = sleep(HEARTBEAT_INTERVAL) => {
                    yield Ok(": keepalive\n\n".to_owned());
                }
            }
        }
    };
    Ok(event_stream(Body::from_stream(stream)))
}

fn event_stream(body: Body) -> Response {
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response
}

async fn create_collection(
    State(state): State<AppState>,
    AppJson(request): AppJson<CreateCollectionRequest>,
) -> Result<StatusCode, ApiError> {
    if request.indexes.len() > MAX_DOCUMENT_INDEXES {
        return Err(ApiError::bad_request("too many document indexes"));
    }
    let indexes: Vec<_> = request
        .indexes
        .into_iter()
        .map(|index| CollectionIndex::new(index.field, index.unique))
        .collect();
    pooled(&state, |mut client| async {
        let created = client.create_collection(&request.collection, &indexes).await;
        (client, created)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_document(
    State(state): State<AppState>,
    AppJson(request): AppJson<DocumentRequest>,
) -> Result<Json<OptionalDocumentResponse>, ApiError> {
    let document = pooled(&state, |mut client| async {
        let fetched = client.get_document(&request.collection, &request.id).await;
        (client, fetched)
    })
    .await?
    .map(|document| document.value);
    Ok(Json(OptionalDocumentResponse { document }))
}

async fn put_document(
    State(state): State<AppState>,
    AppJson(request): AppJson<PutDocumentRequest>,
) -> Result<StatusCode, ApiError> {
    pooled(&state, |mut client| async {
        let written = client
            .put_document(&request.collection, &request.id, &request.document)
            .await;
        (client, written)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_document(
    State(state): State<AppState>,
    AppJson(request): AppJson<DocumentRequest>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let existed = pooled(&state, |mut client| async {
        let deleted = client
            .delete_document(&request.collection, &request.id)
            .await;
        (client, deleted)
    })
    .await?;
    Ok(Json(DeleteResponse { existed }))
}

async fn list_documents(
    State(state): State<AppState>,
    AppJson(request): AppJson<ListDocumentsRequest>,
) -> Result<Json<DocumentsResponse>, ApiError> {
    let limit = document_limit(request.limit)?;
    let documents = pooled(&state, |mut client| async {
        let listed = client.list_documents(&request.collection, Some(limit)).await;
        (client, listed)
    })
    .await?;
    Ok(Json(documents_response(documents)))
}

async fn query_documents(
    State(state): State<AppState>,
    AppJson(request): AppJson<QueryDocumentsRequest>,
) -> Result<Json<DocumentsResponse>, ApiError> {
    let limit = document_limit(request.limit)?;
    let documents = pooled(&state, |mut client| async {
        let queried = client
            .query_documents(
                &request.collection,
                &request.field,
                &request.value,
                Some(limit),
            )
            .await;
        (client, queried)
    })
    .await?;
    Ok(Json(documents_response(documents)))
}

async fn subscribe_collection(
    State(state): State<AppState>,
    Query(query): Query<SubscribeCollectionQuery>,
) -> Result<Response, ApiError> {
    let backend = connect_api(&state).await?;
    let PooledClient { client, permit, .. } = backend;
    let mut subscription = client.subscribe_collection(&query.collection).await?;
    let stream = async_stream::stream! {
        // The connection-budget slot stays held for as long as the subscriber
        // is connected; dropping the stream releases it.
        let _permit = permit;
        loop {
            tokio::select! {
                event = subscription.next() => {
                    match event {
                        Ok(Some(change)) => {
                            let payload = serde_json::to_string(&DocumentChangeResponse {
                                sequence: change.sequence,
                                id: change.id,
                                document: change.value,
                            }).unwrap();
                            yield Ok::<_, Infallible>(format!("data: {payload}\n\n"));
                        }
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("vyrn-http subscription failed: {error}");
                            let payload = serde_json::json!({
                                "error": { "code": "subscription_closed", "message": "subscription terminated" }
                            });
                            yield Ok(format!("event: error\ndata: {payload}\n\n"));
                            break;
                        }
                    }
                }
                _ = sleep(HEARTBEAT_INTERVAL) => {
                    yield Ok(": keepalive\n\n".to_owned());
                }
            }
        }
    };
    Ok(event_stream(Body::from_stream(stream)))
}

fn document_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    let limit = limit.unwrap_or(1_000);
    if limit == 0 || limit > MAX_SCAN_LIMIT {
        return Err(ApiError::bad_request("limit must be between 1 and 10000"));
    }
    Ok(limit)
}

fn documents_response(documents: Vec<vyrn_client::Document>) -> DocumentsResponse {
    DocumentsResponse {
        documents: documents
            .into_iter()
            .map(|document| DocumentResponse {
                id: document.id,
                document: document.value,
            })
            .collect(),
    }
}

async fn connect(state: &AppState) -> Result<Client, ClientError> {
    Client::connect_with_ca(&state.connection_url, state.tls_ca_file.as_deref()).await
}

/// Opens a brand-new backend connection, holding one slot of the connection
/// budget for its lifetime.
async fn connect_api(state: &AppState) -> Result<PooledClient, ApiError> {
    let permit = state
        .clients
        .active
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "backend connection budget exhausted",
            )
        })?;
    match connect(state).await {
        Ok(client) => Ok(PooledClient {
            client,
            idle_since: Instant::now(),
            permit,
        }),
        // Dropping the permit releases the slot.
        Err(error) => Err(ApiError::from(error)),
    }
}

async fn checkout(state: &AppState) -> Result<PooledClient, ApiError> {
    let mut idle = state.clients.idle.lock().await;
    while let Some(candidate) = idle.pop() {
        if candidate.idle_since.elapsed() < MAX_IDLE_AGE {
            return Ok(candidate);
        }
        // Too old: the server has closed it already or will soon (it times
        // out idle clients at 300 s). Dropping it releases the connection
        // slot and the caller gets a fresh connection instead.
    }
    drop(idle);
    connect_api(state).await
}

async fn checkin(state: &AppState, client: PooledClient) {
    let mut idle = state.clients.idle.lock().await;
    if idle.len() < state.clients.maximum {
        idle.push(PooledClient {
            idle_since: Instant::now(),
            ..client
        });
    }
}

/// Runs `operation` on a pooled backend connection.
///
/// Pooled connections sit idle between requests and the server closes them
/// after its own idle timeout, so a checkout can hand back a connection the
/// server has already closed. When the operation then fails with a
/// dead-connection error ([`is_dead_connection`]), the request never reached
/// the server's request loop: the socket was already closed while idle, so no
/// frame on it was processed. The operation is replayed exactly once on a
/// fresh connection — safe even for writes, because nothing was applied the
/// first time. Any other error is reported as-is and never retried.
async fn pooled<T, F, Fut>(state: &AppState, operation: F) -> Result<T, ApiError>
where
    F: Fn(PooledClient) -> Fut,
    Fut: Future<Output = (PooledClient, Result<T, ClientError>)>,
{
    let (client, result) = operation(checkout(state).await?).await;
    match result {
        Ok(value) => {
            checkin(state, client).await;
            Ok(value)
        }
        Err(error) if is_dead_connection(&error) => {
            eprintln!("vyrn-http discarding stale pooled connection: {error}");
            let (client, result) = operation(connect_api(state).await?).await;
            if result.is_ok() {
                checkin(state, client).await;
            }
            result.map_err(ApiError::from)
        }
        // The operation may have reached the server (or the failure is
        // deterministic); the connection is dropped either way.
        Err(error) => Err(ApiError::from(error)),
    }
}

/// Whether the error means the connection was dead before the request could be
/// answered: the server closed it while idle (clean EOF or TLS close_notify)
/// or the OS reported a reset. Timeouts are deliberately excluded — a
/// timed-out request may still be executing server-side, so replaying it
/// could apply twice. Server-produced errors never qualify: they mean the
/// request was processed.
fn is_dead_connection(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::ConnectionClosed | ClientError::Transport(_) | ClientError::Tls(_)
    )
}

fn decode(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD.decode(value).map_err(|_| invalid_base64(field))
}

/// Decodes base64 carried in a query-string parameter.
///
/// Form decoding rewrites `+` to a space before the value reaches us, which
/// corrupts STANDARD-alphabet input (about half of 32-byte prefixes contain a
/// `+`). A space is never valid base64 in any alphabet, so restoring it is
/// unambiguous. URL-safe encodings (`-`, `_`, with or without padding) are
/// accepted so emitters can sidestep the corruption entirely. Request bodies
/// keep using [`decode`], STANDARD only.
fn decode_query(field: &'static str, value: &str) -> Result<Vec<u8>, ApiError> {
    let restored = value.replace(' ', "+");
    for candidate in [value, restored.as_str()] {
        let decoded = STANDARD
            .decode(candidate)
            .or_else(|_| STANDARD_NO_PAD.decode(candidate))
            .or_else(|_| URL_SAFE.decode(candidate))
            .or_else(|_| URL_SAFE_NO_PAD.decode(candidate));
        if let Ok(decoded) = decoded {
            return Ok(decoded);
        }
    }
    Err(invalid_base64(field))
}

fn invalid_base64(field: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_base64",
        format!("{field} is not valid base64"),
    )
}

/// JSON extractor that answers malformed bodies with the standard error
/// envelope instead of axum's plain-text rejection, which would leak serde
/// diagnostics to API clients.
struct AppJson<T>(T);

impl<T, S> FromRequest<S> for AppJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| {
                ApiError::new(
                    rejection.status(),
                    "invalid_request",
                    "invalid request body",
                )
            })
    }
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
}

impl From<ClientError> for ApiError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Server { code, message } => {
                let (status, code) = match code {
                    vyrn_protocol::ErrorCode::AuthenticationFailed => {
                        (StatusCode::BAD_GATEWAY, "database_authentication_failed")
                    }
                    vyrn_protocol::ErrorCode::InvalidRequest => {
                        (StatusCode::BAD_REQUEST, "invalid_request")
                    }
                    vyrn_protocol::ErrorCode::Conflict => {
                        (StatusCode::CONFLICT, "transaction_conflict")
                    }
                    // Storage and internal failures name WAL segments, page ids
                    // and OS I/O errors; the full detail goes to stderr and API
                    // clients get a generic line. UnsupportedVersion likewise
                    // describes a gateway/server pairing the caller cannot act on.
                    vyrn_protocol::ErrorCode::Storage
                    | vyrn_protocol::ErrorCode::Internal
                    | vyrn_protocol::ErrorCode::UnsupportedVersion => {
                        eprintln!("vyrn-http database storage error: {message}");
                        return Self::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "database_storage_error",
                            "database storage error",
                        );
                    }
                };
                Self::new(status, code, message)
            }
            // Transport-class text includes TLS handshake details and OS I/O
            // messages; log it, return something generic.
            error => {
                eprintln!("vyrn-http backend connection failed: {error}");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database_unavailable",
                    "database unavailable",
                )
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: ErrorContent {
                code: self.code,
                message: &self.message,
            },
        });
        (self.status, body).into_response()
    }
}

fn read_secret_file(path: &PathBuf) -> Result<String> {
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let secret = secret.trim_end_matches(['\r', '\n']);
    if secret.is_empty() || secret.contains(['\r', '\n']) {
        bail!("secret file must contain exactly one non-empty line");
    }
    Ok(secret.to_owned())
}

fn insert_password(url: &str, password: &str) -> Result<String> {
    let mut parsed = Url::parse(url).context("invalid Vyrn URL")?;
    parsed
        .set_password(Some(password))
        .map_err(|_| anyhow::anyhow!("URL cannot contain a password"))?;
    Ok(parsed.into())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    sleep(Duration::from_millis(10)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_checks_contents_and_length() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrex"));
        assert!(!constant_time_eq(b"secret", b"secret-long"));
    }

    #[test]
    fn base64_validation_names_the_field() {
        let error = decode("key", "!!!").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("key"));
    }

    #[test]
    fn query_base64_survives_form_decoding_of_plus() {
        // 0xFA 0xBF encodes to a STANDARD string whose first character is '+';
        // a form decoder rewrites that '+' into a space before we see it.
        let bytes = vec![0xFA, 0xBF, 0x66, 0x11];
        let encoded = STANDARD.encode(&bytes);
        assert!(encoded.contains('+'), "sample must contain a plus: {encoded}");
        let corrupted = encoded.replace('+', " ");
        let decoded = decode_query("prefix", &corrupted).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn query_base64_accepts_url_safe_alphabets() {
        let bytes = b"\xfa\xbf\x66\x11".to_vec();
        for encoded in [
            URL_SAFE.encode(&bytes),
            URL_SAFE_NO_PAD.encode(&bytes),
            STANDARD_NO_PAD.encode(&bytes),
            STANDARD.encode(&bytes),
        ] {
            assert_eq!(decode_query("prefix", &encoded).unwrap(), bytes);
        }
    }

    #[test]
    fn query_base64_still_rejects_garbage() {
        let error = decode_query("prefix", "not base64 !!!").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("prefix"));
    }

    #[test]
    fn body_decode_stays_strictly_standard() {
        assert!(decode("key", "-_-_-_-_" ).is_err());
        assert!(decode("key", "aGVsbG8=" ).is_ok());
    }

    #[test]
    fn only_transport_failures_count_as_dead_connections() {
        assert!(is_dead_connection(&ClientError::ConnectionClosed));
        assert!(is_dead_connection(&ClientError::Tls("tls close notify".into())));
        assert!(is_dead_connection(&ClientError::Transport("reset by peer".into())));
        // A timeout may mean the request is still executing server-side.
        assert!(!is_dead_connection(&ClientError::Timeout));
        assert!(!is_dead_connection(&ClientError::Server {
            code: vyrn_protocol::ErrorCode::Conflict,
            message: "transaction conflict".into(),
        }));
    }

    #[test]
    fn storage_errors_are_reduced_to_a_generic_message() {
        let error = ApiError::from(ClientError::Server {
            code: vyrn_protocol::ErrorCode::Storage,
            message: "corrupt WAL segment 5 at byte 1234: Access is denied. (os error 5)".into(),
        });
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.message, "database storage error");
    }

    #[test]
    fn transport_errors_do_not_leak_os_text() {
        let error = ApiError::from(ClientError::Transport(
            "read tcp 127.0.0.1:54321: connection reset by peer".into(),
        ));
        assert_eq!(error.message, "database unavailable");
    }

    #[test]
    fn validation_errors_keep_their_message() {
        let error = ApiError::from(ClientError::Server {
            code: vyrn_protocol::ErrorCode::InvalidRequest,
            message: "limit must be between 1 and 10000".into(),
        });
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "limit must be between 1 and 10000");
    }
}
