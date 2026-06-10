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
    // Reject new work once shutdown has been requested (matches bitcoind).
    if state.shutting_down.load(std::sync::atomic::Ordering::Relaxed) {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Request rejected during server shutdown",
        );
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !state.auth.check(auth_header) {
        // Bitcoin Core inserts a small delay on auth failure to deter brute-forcing.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        return unauthorized();
    }

    // Bound concurrent in-flight requests like bitcoind's work queue; excess → 503.
    let _permit = match state.work_queue.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "Work queue depth exceeded")
        }
    };

    match jsonrpc::parse_body(&body) {
        Err(e) => json_response(status_for(&e), &jsonrpc::error(Value::Null, &e)),
        Ok(Body::Single(v)) => {
            let (resp, status) = process_single(&state, wallet.as_deref(), v).await;
            json_response(status, &resp)
        }
        Ok(Body::Batch(items)) => {
            // Batches always return HTTP 200; per-item errors live in the array.
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                let (resp, _) = process_single(&state, wallet.as_deref(), v).await;
                out.push(resp);
            }
            json_response(StatusCode::OK, &Value::Array(out))
        }
    }
}

/// HTTP status for an RPC error, matching Bitcoin Core's `JSONErrorReply`.
fn status_for(err: &crate::error::RpcError) -> StatusCode {
    StatusCode::from_u16(crate::error::http_status_for_code(err.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Validate and dispatch one request, returning `(envelope, http_status)`. Registers the
/// command as active (for `getrpcinfo`) and emits one structured log line per call.
async fn process_single(state: &AppState, wallet: Option<&str>, v: Value) -> (Value, StatusCode) {
    match RpcRequest::from_value(v) {
        Err((id, err)) => {
            tracing::debug!(code = err.code, message = %err.message, "rpc request rejected");
            (jsonrpc::error(id, &err), status_for(&err))
        }
        Ok(req) => {
            let _active = state.active.begin(&req.method);
            let start = std::time::Instant::now();
            let result = rpc::dispatch(state, wallet, &req).await;
            let elapsed_ms = start.elapsed().as_millis() as u64;
            match result {
                Ok(value) => {
                    tracing::debug!(method = %req.method, wallet = wallet.unwrap_or("default"), elapsed_ms, "rpc ok");
                    (jsonrpc::success(req.id, value), StatusCode::OK)
                }
                Err(err) => {
                    tracing::info!(method = %req.method, wallet = wallet.unwrap_or("default"), elapsed_ms, code = err.code, message = %err.message, "rpc error");
                    (jsonrpc::error(req.id, &err), status_for(&err))
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

/// A plain-text response (bitcoind uses these for 503/overload and shutdown messages).
fn plain_response(status: StatusCode, msg: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain")], msg).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
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
            work_queue: 16,
        };
        let config = AppConfig {
            network: crate::network::ZNetwork::Test,
            datadir: std::path::PathBuf::from("/tmp"),
            default_wallet: "default".into(),
            wallets: BTreeMap::new(),
            lightwalletd: LightwalletdConfig {
                servers: vec!["zecrocks".into()],
                connection: "direct".into(),
                tls_roots: crate::lightwalletd::TlsRoots::Native,
                force_tls: None,
                connect_timeout_secs: 10,
                reconnect_base_secs: 1,
                reconnect_max_secs: 60,
                primary_recheck_secs: 60,
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
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
            active: crate::state::ActiveCommands::default(),
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
    async fn unknown_method_is_404_with_error_code() {
        let r = router(test_state())
            .oneshot(req(r#"{"method":"definitely_not_a_method","id":2}"#, Some(("u", "p"))))
            .await
            .unwrap();
        // Bitcoin Core maps RPC_METHOD_NOT_FOUND to HTTP 404 (httprpc.cpp JSONErrorReply).
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let v = body_json(r).await;
        assert_eq!(v["result"], Value::Null);
        assert_eq!(
            v["error"]["code"],
            serde_json::json!(crate::error::codes::RPC_METHOD_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn work_queue_exhaustion_returns_503() {
        use std::sync::Arc;
        let mut state = test_state();
        // A zero-permit queue: every request is "over capacity".
        state.work_queue = Arc::new(tokio::sync::Semaphore::new(0));
        let r = router(state)
            .oneshot(req(r#"{"method":"uptime","id":1}"#, Some(("u", "p"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// One-shot a single RPC call and return the error code from the envelope (None = success).
    async fn call_err_code(body: &str) -> Option<i64> {
        let r = router(test_state())
            .oneshot(req(body, Some(("u", "p"))))
            .await
            .unwrap();
        let v = body_json(r).await;
        v["error"]["code"].as_i64()
    }

    /// The unsupported fee-shifting params must be rejected with -8 *before* any wallet
    /// access (these run against a registry with no wallets at all), so the guard can never
    /// be bypassed by wallet state.
    #[tokio::test]
    async fn money_semantics_params_are_rejected_before_wallet_access() {
        use crate::error::codes::RPC_INVALID_PARAMETER;
        // sendtoaddress param 4 = subtractfeefromamount.
        let code = call_err_code(
            r#"{"method":"sendtoaddress","id":1,"params":["uaddr","1.0","","",true]}"#,
        )
        .await;
        assert_eq!(code, Some(RPC_INVALID_PARAMETER as i64));
        // sendmany param 4 = subtractfeefrom (non-empty array engages it).
        let code = call_err_code(
            r#"{"method":"sendmany","id":1,"params":["",{"uaddr":1.0},1,"",["uaddr"]]}"#,
        )
        .await;
        assert_eq!(code, Some(RPC_INVALID_PARAMETER as i64));
        // ...but a false/empty value must NOT trip the guard (it fails later, on the
        // missing wallet, -18), so well-behaved clients passing defaults still work.
        use crate::error::codes::RPC_WALLET_NOT_FOUND;
        let code = call_err_code(
            r#"{"method":"sendtoaddress","id":1,"params":["uaddr","1.0","","",false]}"#,
        )
        .await;
        assert_eq!(code, Some(RPC_WALLET_NOT_FOUND as i64));
    }

    #[tokio::test]
    async fn parameter_validation_codes() {
        use crate::error::codes::{RPC_INVALID_ADDRESS_OR_KEY, RPC_INVALID_PARAMETER};
        // listtransactions: negative count / from -> -8 (before wallet access).
        let code =
            call_err_code(r#"{"method":"listtransactions","id":1,"params":["*",-1]}"#).await;
        assert_eq!(code, Some(RPC_INVALID_PARAMETER as i64));
        let code =
            call_err_code(r#"{"method":"listtransactions","id":1,"params":["*",10,-5]}"#).await;
        assert_eq!(code, Some(RPC_INVALID_PARAMETER as i64));
        // getnewaddress: unknown address_type -> -5; orchard/unified accepted (fails later
        // on the missing wallet instead).
        let code =
            call_err_code(r#"{"method":"getnewaddress","id":1,"params":["","bech32"]}"#).await;
        assert_eq!(code, Some(RPC_INVALID_ADDRESS_OR_KEY as i64));
        let code =
            call_err_code(r#"{"method":"getnewaddress","id":1,"params":["","orchard"]}"#).await;
        assert_ne!(code, Some(RPC_INVALID_ADDRESS_OR_KEY as i64));
    }

    /// The newer wallet methods are wired into dispatch: they must fail on the missing
    /// wallet / missing params - never with -32601 (method not found).
    #[tokio::test]
    async fn new_wallet_methods_are_dispatched() {
        use crate::error::codes::RPC_METHOD_NOT_FOUND;
        for body in [
            r#"{"method":"listsinceblock","id":1,"params":[]}"#,
            r#"{"method":"getreceivedbyaddress","id":1,"params":["uaddr"]}"#,
            r#"{"method":"listreceivedbyaddress","id":1,"params":[]}"#,
        ] {
            let code = call_err_code(body).await;
            assert!(code.is_some(), "walletless state must yield an error: {body}");
            assert_ne!(
                code,
                Some(RPC_METHOD_NOT_FOUND as i64),
                "method must be dispatched: {body}"
            );
        }
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
