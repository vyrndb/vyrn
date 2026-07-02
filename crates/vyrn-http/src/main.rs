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
