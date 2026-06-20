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
use tracing::{info, warn};

use crate::rpc;
use crate::server::jsonrpc::{Body, RpcRequest};
use crate::state::AppState;

/// Bind and serve until graceful shutdown is signalled.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    let addr = SocketAddr::new(state.config.rpc.bind, state.config.rpc.port);
    let shutdown = state.shutdown_signal();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("RPC server listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Maximum accepted HTTP request-body size. JSON-RPC requests - even large batches - are small,
/// so this bounds memory from a hostile or buggy client while staying generous. It makes axum's
/// otherwise-implicit limit explicit and tunable; oversize requests are rejected with HTTP 413 by
/// the body-limit layer, before auth or dispatch.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", post(handle_root))
        .route("/wallet/:name", post(handle_wallet))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
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
    if state
        .shutting_down
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Request rejected during server shutdown",
        );
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let wallet_label = wallet.as_deref().unwrap_or("default");
    if !state.auth.check(auth_header) {
        // Bitcoin Core inserts a small delay on auth failure to deter brute-forcing.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        warn!(
            user = auth::basic_auth_username(auth_header)
                .as_deref()
                .unwrap_or("<none>"),
            wallet = wallet_label,
            "RPC authentication failed"
        );
        return unauthorized();
    }
    info!(
        user = auth::basic_auth_username(auth_header)
            .as_deref()
            .unwrap_or("<none>"),
        wallet = wallet_label,
        "RPC authentication succeeded"
    );

    // Bound concurrent in-flight requests like bitcoind's work queue; excess → 503.
    let _permit = match state.work_queue.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "Work queue depth exceeded");
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
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
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
    use tower::ServiceExt;

    use crate::config::{AppConfig, BackendConfig, KeysConfig, RpcConfig, SyncConfig};
    use crate::server::auth::Authenticator;
    use crate::wallet::WalletRegistry;

    fn test_state() -> AppState {
        let rpc = RpcConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            auth: vec![],
            cookiefile: None,
            work_queue: 16,
            allowed_methods: vec![],
        };
        test_state_with_rpc(rpc)
    }

    /// Like `test_state`, but with caller-supplied RPC auth config so tests can exercise the
    /// full HTTP auth gate against specific credentials (e.g. generated `rpcauth` entries).
    fn test_state_with_rpc(rpc: RpcConfig) -> AppState {
        let config = AppConfig {
            network: crate::network::ZNetwork::Test,
            datadir: std::path::PathBuf::from("/tmp"),
            default_wallet: "default".into(),
            wallets: BTreeMap::new(),
            backend: BackendConfig {
                server: "zebra".into(),
                connect_timeout_secs: 10,
                reconnect_base_secs: 1,
                reconnect_max_secs: 60,
            },
            zebra: Default::default(),
            rpc: rpc.clone(),
            keys: KeysConfig {
                age_identity: None,
                auto_unlock: true,
                bootstrap_from_keys: true,
            },
            sync: SyncConfig {
                interval_secs: 20,
                rebroadcast_secs: 60,
            },
            spend: crate::config::SpendConfig::default(),
            pools: crate::config::PoolsConfig::default(),
            health: crate::config::HealthConfig {
                enabled: false,
                bind: "127.0.0.1".parse().unwrap(),
                port: 9233,
                readiness: crate::config::ReadinessMode::Connected,
                max_scan_lag: 4,
            },
            log: crate::config::LogConfig {
                level: "info".into(),
                format: "text".into(),
            },
        };
        AppState {
            auth: Authenticator::from_config(&rpc).unwrap(),
            config: Arc::new(config),
            registry: Arc::new(WalletRegistry::new("default".into())),
            started_at: Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
            active: crate::state::ActiveCommands::default(),
            operations: Arc::new(crate::operations::OperationRegistry::new()),
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
            .oneshot(req(
                r#"{"method":"getnetworkinfo","id":1}"#,
                Some(("u", "wrong")),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// End-to-end auth flow over the full HTTP stack using a credential minted by
    /// `zecd rpcauth`: build the server from a generated `[rpc] auth` entry, then drive a real
    /// request through the router. Covers passwords with characters that could break Basic-auth
    /// parsing or hashing - including `:` (the Basic-auth field separator), `$` (the salt/hash
    /// delimiter in the entry), quotes/backslashes, whitespace, and non-ASCII - to prove the
    /// generator and the auth gate agree on every byte.
    #[tokio::test]
    async fn generated_rpcauth_authenticates_over_http() {
        for password in [
            "p@ss:word$with$delims",
            "has spaces and \"quotes\" and \\back\\slashes",
            "ünïcödë - 🔐",
            "trailing=padding==",
            "",
        ] {
            let (entry, _) = crate::server::auth::generate_rpcauth("operator", Some(password));
            let rpc = RpcConfig {
                bind: "127.0.0.1".parse().unwrap(),
                port: 1,
                // No user/password pair, so a cookie would be required - provide a cookiefile.
                user: None,
                password: None,
                auth: vec![entry],
                cookiefile: Some(
                    std::env::temp_dir().join(format!("zecd-test-cookie-{}", std::process::id())),
                ),
                work_queue: 16,
                allowed_methods: vec![],
            };

            // Correct credential → 200 through the real dispatch path.
            let r = router(test_state_with_rpc(rpc.clone()))
                .oneshot(req(
                    r#"{"method":"getnetworkinfo","id":1,"params":[]}"#,
                    Some(("operator", password)),
                ))
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::OK,
                "password {password:?} should auth"
            );

            // Same user, tweaked password → 401.
            let r = router(test_state_with_rpc(rpc))
                .oneshot(req(
                    r#"{"method":"getnetworkinfo","id":1,"params":[]}"#,
                    Some(("operator", &format!("{password}x"))),
                ))
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "wrong password for {password:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn oversize_body_is_413() {
        // A body past MAX_BODY_BYTES is rejected by the body-limit layer before auth/dispatch.
        let big = "a".repeat(MAX_BODY_BYTES + 1);
        let r = router(test_state())
            .oneshot(req(&big, Some(("u", "p"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn getnetworkinfo_ok_200() {
        let r = router(test_state())
            .oneshot(req(
                r#"{"method":"getnetworkinfo","id":1,"params":[]}"#,
                Some(("u", "p")),
            ))
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
            .oneshot(req(
                r#"{"method":"definitely_not_a_method","id":2}"#,
                Some(("u", "p")),
            ))
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

    /// One-shot a single RPC call against a state whose `[rpc] allowed_methods` safelist is
    /// `safelist`, returning `(http_status, envelope_error_code)`.
    async fn call_with_safelist(safelist: Vec<String>, body: &str) -> (StatusCode, Option<i64>) {
        let mut state = test_state();
        let mut cfg = (*state.config).clone();
        cfg.rpc.allowed_methods = safelist;
        state.config = Arc::new(cfg);
        let r = router(state)
            .oneshot(req(body, Some(("u", "p"))))
            .await
            .unwrap();
        let status = r.status();
        let code = body_json(r).await["error"]["code"].as_i64();
        (status, code)
    }

    /// A non-empty `allowed_methods` safelist serves only the listed methods; every other
    /// implemented method is rejected exactly like a nonexistent one (-32601 / HTTP 404), so a
    /// locked-down server leaks nothing about what it disabled. An empty safelist is the
    /// unrestricted default.
    #[tokio::test]
    async fn allowed_methods_safelist_restricts_surface() {
        use crate::error::codes::RPC_METHOD_NOT_FOUND;
        let only_uptime = vec!["uptime".to_string()];

        // A listed method dispatches normally.
        let (status, code) =
            call_with_safelist(only_uptime.clone(), r#"{"method":"uptime","id":1}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(code, None);

        // A real, implemented method that is NOT on the safelist is blocked, indistinguishable
        // from one that doesn't exist.
        let (status, code) =
            call_with_safelist(only_uptime, r#"{"method":"getnetworkinfo","id":1}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, Some(RPC_METHOD_NOT_FOUND as i64));

        // An empty safelist imposes no restriction (the default): the same method now works.
        let (status, code) =
            call_with_safelist(vec![], r#"{"method":"getnetworkinfo","id":1}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(code, None);
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
        // sendtoaddress param 9 / sendmany param 8 = fee_rate: an explicit fee instruction,
        // rejected (fees are ZIP-317 and never settable).
        let code = call_err_code(
            r#"{"method":"sendtoaddress","id":1,"params":["uaddr","1.0","","",false,false,null,"",false,25]}"#,
        )
        .await;
        assert_eq!(code, Some(RPC_INVALID_PARAMETER as i64));
        let code = call_err_code(
            r#"{"method":"sendmany","id":1,"params":["",{"uaddr":1.0},1,"",[],false,null,"",25]}"#,
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
        let code = call_err_code(r#"{"method":"listtransactions","id":1,"params":["*",-1]}"#).await;
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
            r#"{"method":"getbalances","id":1,"params":[]}"#,
            r#"{"method":"getreceivedbylabel","id":1,"params":["l"]}"#,
            r#"{"method":"listreceivedbylabel","id":1,"params":[]}"#,
            r#"{"method":"getrawtransaction","id":1,"params":["00"]}"#,
            r#"{"method":"sendrawtransaction","id":1,"params":["00"]}"#,
        ] {
            let code = call_err_code(body).await;
            assert!(
                code.is_some(),
                "walletless state must yield an error: {body}"
            );
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
        let r = router(test_state())
            .oneshot(req(body, Some(("u", "p"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["error"], Value::Null);
        assert!(arr[1]["error"]["code"].is_number());
    }

    /// Bitcoin Core's validateaddress returns only the verdict (plus error details) for
    /// invalid input; address/scriptPubKey/isscript appear only when valid. Transparent
    /// addresses carry their real scriptPubKey (vectors shared with zallet, from zcashd
    /// qa/rpc-tests/disablewallet.py).
    #[tokio::test]
    async fn validateaddress_matches_bitcoind_shape() {
        async fn result_for(addr: &str) -> Value {
            let body = format!(r#"{{"method":"validateaddress","id":1,"params":["{addr}"]}}"#);
            let r = router(test_state())
                .oneshot(req(&body, Some(("u", "p"))))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            body_json(r).await["result"].clone()
        }

        // Invalid (garbage, and a mainnet address on this testnet state): no address echo.
        for addr in ["notanaddress", "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY"] {
            let v = result_for(addr).await;
            assert_eq!(v["isvalid"], serde_json::json!(false));
            let obj = v.as_object().unwrap();
            assert!(
                !obj.contains_key("address"),
                "invalid result must not echo address"
            );
            assert!(!obj.contains_key("scriptPubKey"));
            assert!(!obj.contains_key("isscript"));
            assert!(obj.contains_key("error"));
            assert!(obj.contains_key("error_locations"));
        }

        // Valid testnet P2PKH: real scriptPubKey, isscript false.
        let v = result_for("tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86").await;
        assert_eq!(v["isvalid"], serde_json::json!(true));
        assert_eq!(
            v["address"],
            serde_json::json!("tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86")
        );
        let spk = v["scriptPubKey"].as_str().unwrap();
        assert!(
            spk.starts_with("76a914") && spk.ends_with("88ac"),
            "got {spk}"
        );
        assert_eq!(v["isscript"], serde_json::json!(false));
        assert_eq!(v["iswitness"], serde_json::json!(false));
    }
}
