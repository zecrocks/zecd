//! The HTTP/JSON-RPC server: axum router, auth gate, and bitcoind-compatible framing.

pub mod auth;
pub mod jsonrpc;

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::Value;
use tracing::info;

use crate::rpc;
use crate::server::jsonrpc::{Body, RpcRequest};
use crate::state::AppState;

/// Bind and serve until graceful shutdown is signalled.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    let addr = SocketAddr::new(state.config.rpc.bind, state.config.rpc.port);
    let shutdown = state.shutdown.clone();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("RPC server listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.notified().await })
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", post(handle_root))
        .route("/wallet/:name", post(handle_wallet))
        .with_state(state)
}

async fn handle_root(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, None, headers, body).await
}

async fn handle_wallet(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state, Some(name), headers, body).await
}

async fn handle(
    state: AppState,
    wallet: Option<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !state.auth.check(auth_header) {
        return unauthorized();
    }

    match jsonrpc::parse_body(&body) {
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &jsonrpc::error(Value::Null, &e),
        ),
        Ok(Body::Single(v)) => {
            let (resp, is_err) = process_single(&state, wallet.as_deref(), v).await;
            let status = if is_err {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            };
            json_response(status, &resp)
        }
        Ok(Body::Batch(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                let (resp, _) = process_single(&state, wallet.as_deref(), v).await;
                out.push(resp);
            }
            json_response(StatusCode::OK, &Value::Array(out))
        }
    }
}

/// Validate and dispatch one request, returning `(envelope, is_error)`.
async fn process_single(state: &AppState, wallet: Option<&str>, v: Value) -> (Value, bool) {
    match RpcRequest::from_value(v) {
        Err((id, err)) => (jsonrpc::error(id, &err), true),
        Ok(req) => match rpc::dispatch(state, wallet, &req).await {
            Ok(result) => (jsonrpc::success(req.id, result), false),
            Err(err) => (jsonrpc::error(req.id, &err), true),
        },
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"zecd\"")],
        "",
    )
        .into_response()
}
