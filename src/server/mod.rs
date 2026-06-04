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

/// Validate and dispatch one request, returning `(envelope, is_error)`. Emits one structured
/// log line per call (debug on success, info on error) with method, wallet, and latency.
async fn process_single(state: &AppState, wallet: Option<&str>, v: Value) -> (Value, bool) {
    match RpcRequest::from_value(v) {
        Err((id, err)) => {
            tracing::debug!(code = err.code, message = %err.message, "rpc request rejected");
            (jsonrpc::error(id, &err), true)
        }
        Ok(req) => {
            let start = std::time::Instant::now();
            let result = rpc::dispatch(state, wallet, &req).await;
            let elapsed_ms = start.elapsed().as_millis() as u64;
            match result {
                Ok(value) => {
                    tracing::debug!(method = %req.method, wallet = wallet.unwrap_or("default"), elapsed_ms, "rpc ok");
                    (jsonrpc::success(req.id, value), false)
                }
                Err(err) => {
                    tracing::info!(method = %req.method, wallet = wallet.unwrap_or("default"), elapsed_ms, code = err.code, message = %err.message, "rpc error");
                    (jsonrpc::error(req.id, &err), true)
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    use axum::body::Body as AxumBody;
    use axum::http::Request;
    use base64::Engine;
    use serde_json::Value;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use crate::config::{
        AppConfig, KeysConfig, LightwalletdConfig, RpcConfig, SyncConfig,
    };
    use crate::server::auth::Authenticator;
    use crate::wallet::WalletRegistry;

    fn test_state() -> AppState {
        let rpc = RpcConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            cookiefile: None,
        };
        let config = AppConfig {
            network: zcash_protocol::consensus::Network::TestNetwork,
            datadir: std::path::PathBuf::from("/tmp"),
            default_wallet: "default".into(),
            wallets: BTreeMap::new(),
            lightwalletd: LightwalletdConfig {
                server: "zecrocks".into(),
                connection: "direct".into(),
                tls_roots: crate::lightwalletd::TlsRoots::Native,
                force_tls: None,
            },
            rpc: rpc.clone(),
            keys: KeysConfig { age_identity: None, auto_unlock: true },
            sync: SyncConfig { interval_secs: 20 },
            health: crate::config::HealthConfig {
                enabled: false,
                bind: "127.0.0.1".parse().unwrap(),
                port: 9233,
                ready_progress: 0.999,
            },
            log: crate::config::LogConfig { level: "info".into(), format: "text".into() },
        };
        AppState {
            auth: Authenticator::from_config(&rpc).unwrap(),
            config: Arc::new(config),
            registry: Arc::new(WalletRegistry::new("default".into())),
            started_at: Instant::now(),
            shutdown: Arc::new(Notify::new()),
        }
    }

    fn req(body: &str, auth: Option<(&str, &str)>) -> Request<AxumBody> {
        let mut b = Request::builder().method("POST").uri("/");
        if let Some((u, p)) = auth {
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            b = b.header("authorization", format!("Basic {creds}"));
        }
        b.body(AxumBody::from(body.to_string())).unwrap()
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn missing_or_wrong_auth_is_401() {
        let r = router(test_state())
            .oneshot(req(r#"{"method":"getnetworkinfo","id":1}"#, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        let r = router(test_state())
            .oneshot(req(r#"{"method":"getnetworkinfo","id":1}"#, Some(("u", "wrong"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn getnetworkinfo_ok_200() {
        let r = router(test_state())
            .oneshot(req(r#"{"method":"getnetworkinfo","id":1,"params":[]}"#, Some(("u", "p"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        assert_eq!(v["error"], Value::Null);
        assert_eq!(v["id"], serde_json::json!(1));
        assert!(v["result"]["subversion"].as_str().unwrap().contains("zecd"));
    }

    #[tokio::test]
    async fn unknown_method_is_500_with_error_code() {
        let r = router(test_state())
            .oneshot(req(r#"{"method":"definitely_not_a_method","id":2}"#, Some(("u", "p"))))
            .await
            .unwrap();
        // Bitcoin Core returns HTTP 500 with the error object in the body.
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let v = body_json(r).await;
        assert_eq!(v["result"], Value::Null);
        assert_eq!(
            v["error"]["code"],
            serde_json::json!(crate::error::codes::RPC_METHOD_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn batch_returns_200_array() {
        let body = r#"[{"method":"uptime","id":1},{"method":"nope","id":2}]"#;
        let r = router(test_state()).oneshot(req(body, Some(("u", "p")))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["error"], Value::Null);
        assert!(arr[1]["error"]["code"].is_number());
    }
}
