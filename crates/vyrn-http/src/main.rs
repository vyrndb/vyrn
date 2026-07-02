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
