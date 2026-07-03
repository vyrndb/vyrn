use anyhow::{bail, Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex, time::sleep};
use url::Url;
use vyrn_client::{Client, CollectionIndex, Error as ClientError};
use vyrn_protocol::{MAX_DOCUMENT_INDEXES, MAX_SCAN_LIMIT};

const JSON_LIMIT: usize = 24 * 1024 * 1024;

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
}

#[derive(Clone)]
struct AppState {
    connection_url: String,
    tls_ca_file: Option<PathBuf>,
    token: Arc<str>,
    clients: Arc<ClientPool>,
}

struct ClientPool {
    idle: Mutex<Vec<Client>>,
    maximum: usize,
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
    if request.method() == Method::OPTIONS {
        return StatusCode::NO_CONTENT.into_response();
    }
    next.run(request).await
}

async fn ready(State(state): State<AppState>) -> Response {
    match connect(&state).await {
        Ok(_) => (StatusCode::OK, "ready\n").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response(),
    }
}

async fn get_value(
    State(state): State<AppState>,
    Json(request): Json<KeyRequest>,
) -> Result<Json<ValueResponse>, ApiError> {
    let mut client = checkout(&state).await?;
    let value = client.get(decode("key", &request.key)?).await?;
    checkin(&state, client).await;
    Ok(Json(ValueResponse {
        value: value.map(|value| STANDARD.encode(value)),
    }))
}

async fn multi_get(
    State(state): State<AppState>,
    Json(request): Json<MultiGetRequest>,
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
    let mut client = checkout(&state).await?;
    let values = client
        .multi_get(keys)
        .await?
        .into_iter()
        .map(|value| value.map(|value| STANDARD.encode(value)))
        .collect();
    checkin(&state, client).await;
    Ok(Json(ValuesResponse { values }))
}

async fn put_value(
    State(state): State<AppState>,
    Json(request): Json<PutRequest>,
) -> Result<StatusCode, ApiError> {
    let mut client = checkout(&state).await?;
    client
        .put(
            decode("key", &request.key)?,
            decode("value", &request.value)?,
        )
        .await?;
    checkin(&state, client).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_value(
    State(state): State<AppState>,
    Json(request): Json<KeyRequest>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let mut client = checkout(&state).await?;
    let existed = client.delete(decode("key", &request.key)?).await?;
    checkin(&state, client).await;
    Ok(Json(DeleteResponse { existed }))
}

async fn scan(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<RowsResponse>, ApiError> {
    let limit = request.limit.unwrap_or(1_000);
    if limit == 0 || limit > MAX_SCAN_LIMIT {
        return Err(ApiError::bad_request("limit must be between 1 and 10000"));
    }
    let mut client = checkout(&state).await?;
    let rows = client
        .scan(
            request
                .start
                .map(|value| decode("start", &value))
                .transpose()?,
            request.end.map(|value| decode("end", &value)).transpose()?,
            Some(limit),
        )
        .await?
        .into_iter()
        .map(|(key, value)| RowResponse {
            key: STANDARD.encode(key),
            value: STANDARD.encode(value),
        })
        .collect();
    checkin(&state, client).await;
    Ok(Json(RowsResponse { rows }))
}

async fn transaction(
    State(state): State<AppState>,
    Json(request): Json<TransactionRequest>,
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
    let mut client = checkout(&state).await?;
    let mut transaction = client.transaction().await?;
    let mut deleted = Vec::new();
    for operation in request.operations {
        match operation {
            OperationRequest::Put { key, value } => {
                transaction
                    .put(decode("key", &key)?, decode("value", &value)?)
                    .await?;
            }
            OperationRequest::Delete { key } => {
                deleted.push(transaction.delete(decode("key", &key)?).await?);
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
    let client = connect_api(&state).await?;
    let mut subscription = client.subscribe(decode("prefix", &query.prefix)?).await?;
    let stream = async_stream::stream! {
        loop {
            match subscription.next().await {
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
                    let payload = serde_json::json!({
                        "error": { "code": "subscription_closed", "message": error.to_string() }
                    });
