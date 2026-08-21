//! The HTTP/JSON-RPC server: axum router, auth gate, and bitcoind-compatible framing.
//!
//! `auth` and `jsonrpc` are transport-agnostic (dispatch and the embeddable node use
//! `RpcRequest`; `config check` uses `auth::check_config`), so they compile unconditionally;
//! everything axum-shaped in this file is gated behind the `server` feature.

pub mod auth;
pub mod jsonrpc;

#[cfg(feature = "server")]
use std::net::SocketAddr;

#[cfg(feature = "server")]
use axum::body::Bytes;
#[cfg(feature = "server")]
use axum::extract::{ConnectInfo, Path, State};
#[cfg(feature = "server")]
use axum::http::{header, HeaderMap, StatusCode};
#[cfg(feature = "server")]
use axum::response::{IntoResponse, Response};
#[cfg(feature = "server")]
use axum::routing::post;
#[cfg(feature = "server")]
use axum::Router;
#[cfg(feature = "server")]
use serde_json::Value;
#[cfg(feature = "server")]
use tracing::{info, warn};

#[cfg(feature = "server")]
use crate::rpc;
#[cfg(feature = "server")]
use crate::server::jsonrpc::{Body, RpcRequest};
#[cfg(feature = "server")]
use crate::state::AppState;

/// State for the HTTP transport: the shared node state plus the HTTP-only auth gate. Auth is
/// a transport concern - an embedded node (`crate::node::Node`) never constructs an
/// `Authenticator` (`Authenticator::from_config` writes a cookie file as a side effect), so
/// the field lives here rather than on [`AppState`].
#[cfg(feature = "server")]
#[derive(Clone)]
pub struct HttpState {
    pub app: AppState,
    pub auth: auth::Authenticator,
}

/// Bind and serve until graceful shutdown is signalled.
#[cfg(feature = "server")]
pub async fn run(state: HttpState) -> anyhow::Result<()> {
    let addr = SocketAddr::new(state.app.config.rpc.bind, state.app.config.rpc.port);
    let shutdown = state.app.shutdown_signal();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("RPC server listening on http://{addr}");
    // `into_make_service_with_connect_info` makes each connection's peer `SocketAddr` available
    // to handlers via the `ConnectInfo` extractor, so RPC auth attempts can be attributed to a
    // client IP. (The `tower::oneshot` integration tests drive `router` directly without it; the
    // handlers extract it as `Option`, yielding `None` there.)
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

/// Maximum accepted HTTP request-body size. JSON-RPC requests - even large batches - are small,
/// so this bounds memory from a hostile or buggy client while staying generous. It makes axum's
/// otherwise-implicit limit explicit and tunable; oversize requests are rejected with HTTP 413 by
/// the body-limit layer, before auth or dispatch.
#[cfg(feature = "server")]
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

#[cfg(feature = "server")]
fn router(state: HttpState) -> Router {
    Router::new()
        .route("/", post(handle_root))
        .route("/wallet/:name", post(handle_wallet))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(feature = "server")]
async fn handle_root(
    State(state): State<HttpState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state, peer_addr(peer), None, headers, body).await
}

#[cfg(feature = "server")]
async fn handle_wallet(
    State(state): State<HttpState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state, peer_addr(peer), Some(name), headers, body).await
}

/// Unwrap the optional `ConnectInfo` extractor into the peer socket address, if known. It is
/// `None` for requests that arrive without connection info (the in-process `oneshot` tests).
#[cfg(feature = "server")]
fn peer_addr(peer: Option<ConnectInfo<SocketAddr>>) -> Option<SocketAddr> {
    peer.map(|ConnectInfo(addr)| addr)
}

#[cfg(feature = "server")]
async fn handle(
    state: HttpState,
    peer: Option<SocketAddr>,
    wallet: Option<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Reject new work once shutdown has been requested (matches bitcoind).
    if state
        .app
        .shutting_down
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Request rejected during server shutdown",
        );
    }

    // Bound concurrent in-flight requests like bitcoind's work queue; excess → 503. This gate
    // must precede the auth check: authentication (and its anti-bruteforce sleep on failure) is
    // real work, so admitting it without a permit would let unauthenticated floods bypass the
    // in-flight bound and starve legitimate clients.
    let _permit = match state.app.work_queue.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "Work queue depth exceeded");
        }
    };

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let wallet_label = wallet.as_deref().unwrap_or("default");
    // The connecting client's address, for auth attribution. Behind a reverse proxy the socket
    // peer is the proxy, so also surface `X-Forwarded-For` when the proxy set it (logged as-is;
    // it is client-supplied and only used for the log line, never for an auth decision).
    let peer = peer.map(|a| a.to_string());
    let peer = peer.as_deref().unwrap_or("unknown");
    let forwarded_for = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    if !state.auth.check(auth_header) {
        // Bitcoin Core inserts a small delay on auth failure to deter brute-forcing.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        warn!(
            target: "zecd::audit",
            user = auth::basic_auth_username(auth_header)
                .as_deref()
                .unwrap_or("<none>"),
            wallet = wallet_label,
            peer,
            forwarded_for,
            "RPC authentication failed"
        );
        return unauthorized();
    }
    // Success is the overwhelmingly common case - one line per authenticated request - so it
    // sits at DEBUG (still under the audit target for a sink that wants it); failures warn.
    tracing::debug!(
        target: "zecd::audit",
        user = auth::basic_auth_username(auth_header)
            .as_deref()
            .unwrap_or("<none>"),
        wallet = wallet_label,
        peer,
        forwarded_for,
        "RPC authentication succeeded"
    );

    match jsonrpc::parse_body(&body) {
        Err(e) => json_response(status_for(&e), &jsonrpc::error(Value::Null, &e)),
        Ok(Body::Single(v)) => {
            let (resp, status) = process_single(&state.app, wallet.as_deref(), v).await;
            json_response(status, &resp)
        }
        Ok(Body::Batch(items)) => {
            // Batches always return HTTP 200; per-item errors live in the array.
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                let (resp, _) = process_single(&state.app, wallet.as_deref(), v).await;
                out.push(resp);
            }
            json_response(StatusCode::OK, &Value::Array(out))
        }
    }
}

/// HTTP status for an RPC error, matching Bitcoin Core's `JSONErrorReply`.
#[cfg(feature = "server")]
fn status_for(err: &crate::error::RpcError) -> StatusCode {
    StatusCode::from_u16(crate::error::http_status_for_code(err.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Validate and dispatch one request, returning `(envelope, http_status)`. Registers the
/// command as active (for `getrpcinfo`) and emits one structured log line per call.
#[cfg(feature = "server")]
async fn process_single(state: &AppState, wallet: Option<&str>, v: Value) -> (Value, StatusCode) {
    match RpcRequest::from_value(v) {
        Err((id, err)) => {
            tracing::debug!(code = err.code, message = %err.message, "rpc request rejected");
            (jsonrpc::error(id, &err), status_for(&err))
        }
        Ok(req) => {
            let _active = state.active.begin(&req.method);
            let start = std::time::Instant::now();
            // Dispatch under a span so every event emitted while handling this call - down to
            // the sanitized-error detail lines in `error.rs` - carries the method and wallet,
            // and a JSON log consumer can join them to the `rpc ok`/`rpc error` event below.
            // The client-supplied request `id` is deliberately not a span field: it is
            // untrusted display data.
            let span = tracing::info_span!("rpc", method = %req.method, wallet = wallet.unwrap_or("default"));
            let result = {
                use tracing::Instrument as _;
                rpc::dispatch(state, wallet, &req).instrument(span).await
            };
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

#[cfg(feature = "server")]
fn json_response(status: StatusCode, body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

/// A plain-text response (bitcoind uses these for 503/overload and shutdown messages).
#[cfg(feature = "server")]
fn plain_response(status: StatusCode, msg: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain")], msg).into_response()
}

#[cfg(feature = "server")]
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
        "",
    )
        .into_response()
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::body::Body as AxumBody;
    use axum::http::Request;
    use base64::Engine;
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::config::{AppConfig, BackendConfig, KeysConfig, RpcConfig, SyncConfig};
    use crate::server::auth::Authenticator;
    use crate::wallet::WalletRegistry;

    fn test_state() -> HttpState {
        let rpc = RpcConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            auth: vec![],
            cookiefile: None,
            work_queue: 16,
            allowed_methods: vec![],
            allow_duplicate_shielded_recipients: false,
        };
        test_state_with_rpc(rpc)
    }

    /// Like `test_state`, but with caller-supplied RPC auth config so tests can exercise the
    /// full HTTP auth gate against specific credentials (e.g. generated `rpcauth` entries).
    fn test_state_with_rpc(rpc: RpcConfig) -> HttpState {
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
                rfc1918_is_local: true,
                allow_remote_cleartext: false,
                tls: None,
                tls_roots: Default::default(),
                tls_insecure_skip_verify: false,
                tls_ca_pem: None,
                tls_ca_file: None,
                tls_pins: Vec::new(),
                assume_transparent_in_compact_blocks: false,
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
        HttpState {
            auth: Authenticator::from_config(&rpc).unwrap(),
            app: AppState {
                config: Arc::new(config),
                registry: Arc::new(WalletRegistry::new("default".into())),
                started_at: Instant::now(),
                shutdown_tx: tokio::sync::watch::channel(false).0,
                shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
                active: crate::state::ActiveCommands::default(),
                operations: Arc::new(crate::operations::OperationRegistry::new()),
            },
        }
    }

    fn req(body: &str, auth: Option<(&str, &str)>) -> Request<AxumBody> {
        req_to("/", body, auth)
    }

    /// Like `req`, but targets an explicit URI (e.g. `/wallet/<name>`) so tests can drive the
    /// `/wallet/<name>` routing path.
    fn req_to(uri: &str, body: &str, auth: Option<(&str, &str)>) -> Request<AxumBody> {
        let mut b = Request::builder().method("POST").uri(uri);
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
                allow_duplicate_shielded_recipients: false,
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
        state.app.work_queue = Arc::new(tokio::sync::Semaphore::new(0));
        let r = router(state)
            .oneshot(req(r#"{"method":"uptime","id":1}"#, Some(("u", "p"))))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The in-flight bound must apply to *unauthenticated* traffic too: with the queue exhausted,
    /// even a bad-credential request is rejected with 503 before the auth check (and its
    /// anti-bruteforce sleep) runs - otherwise a bad-credential flood bypasses the work queue and
    /// can degrade availability for legitimate clients.
    #[tokio::test]
    async fn work_queue_exhaustion_bounds_bad_credentials() {
        use std::sync::Arc;
        let mut state = test_state();
        state.app.work_queue = Arc::new(tokio::sync::Semaphore::new(0));
        let r = router(state)
            .oneshot(req(
                r#"{"method":"getnetworkinfo","id":1}"#,
                Some(("u", "wrong")),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The chain-status RPCs must honor `/wallet/<name>` routing (like the wallet methods), not
    /// always report the default wallet's sync state. A default wallet caught up at height 2000
    /// and a routed `w2` still scanning at 500 must report their *own* heights - otherwise an
    /// integration polling `/wallet/w2` with `getblockcount` treats a not-yet-scanned deposit as
    /// confirmed. `getblockcount` reads only the published sync status, so no DB/network is
    /// involved (the other four chain-status RPCs thread the routed name identically).
    #[tokio::test]
    async fn getblockcount_honors_wallet_routing() {
        use crate::network::ZNetwork;
        use crate::wallet::{CoinWallet, SyncStatus, WalletHandle};

        let mut reg = WalletRegistry::new("default".into());
        reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
            "default",
            ZNetwork::Test,
            SyncStatus {
                fully_scanned: Some(2000),
                scanning: false,
                ..Default::default()
            },
        )));
        reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
            "w2",
            ZNetwork::Test,
            SyncStatus {
                fully_scanned: Some(500),
                scanning: true,
                ..Default::default()
            },
        )));
        let mut state = test_state();
        state.app.registry = Arc::new(reg);

        // The default route reports the default wallet's height…
        let r = router(state.clone())
            .oneshot(req(
                r#"{"method":"getblockcount","id":1}"#,
                Some(("u", "p")),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(r).await["result"].as_u64(), Some(2000));

        // …while /wallet/w2 reports w2's own (still-scanning) height, not the default's.
        let r = router(state)
            .oneshot(req_to(
                "/wallet/w2",
                r#"{"method":"getblockcount","id":1}"#,
                Some(("u", "p")),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(r).await["result"].as_u64(), Some(500));
    }

    /// A state whose default wallet publishes `status`, plus the sender - so a test can move the
    /// wallet's view of the chain the way the actor's `update_status` does. `fully_scanned` is
    /// deliberately left `None` by callers: `best_block` then answers purely from the published
    /// status, keeping these tests off the wallet DB.
    fn state_publishing(
        status: crate::wallet::SyncStatus,
    ) -> (
        HttpState,
        tokio::sync::watch::Sender<crate::wallet::SyncStatus>,
    ) {
        use crate::network::ZNetwork;
        use crate::wallet::{CoinWallet, WalletHandle};

        let (handle, tx) = WalletHandle::for_test_publishing("default", ZNetwork::Test, status);
        let mut reg = WalletRegistry::new("default".into());
        reg.insert(CoinWallet::Zcash(handle));
        let mut state = test_state();
        state.app.registry = Arc::new(reg);
        (state, tx)
    }

    /// One `waitfor*` call against `state`, returning the envelope's `result`.
    async fn wait_call(state: HttpState, body: &str) -> Value {
        let r = router(state)
            .oneshot(req(body, Some(("u", "p"))))
            .await
            .unwrap();
        body_json(r).await["result"].clone()
    }

    fn status_at(hash: &str) -> crate::wallet::SyncStatus {
        crate::wallet::SyncStatus {
            best_block_hash: Some(hash.to_string()),
            ..Default::default()
        }
    }

    /// The point of `waitforblockheight`: a height the wallet has already *scanned* to answers
    /// immediately, and a height it has not is waited on - with a timeout returning the current
    /// block rather than raising, exactly as Bitcoin Core does. (A timeout that errored would
    /// push callers straight back to the poll loops these RPCs replace.)
    #[tokio::test]
    async fn waitforblockheight_answers_now_when_reached_and_times_out_otherwise() {
        let hash = "ab".repeat(32);
        let (state, _tx) = state_publishing(status_at(&hash));

        let started = Instant::now();
        let res = wait_call(
            state.clone(),
            r#"{"method":"waitforblockheight","params":[0],"id":1}"#,
        )
        .await;
        assert_eq!(res["height"].as_u64(), Some(0));
        assert_eq!(res["hash"].as_str(), Some(hash.as_str()));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "an already-reached height must not wait"
        );

        // A height the wallet has not scanned: the wait runs, and the timeout answers with the
        // wallet's current block instead of an error.
        let res = wait_call(
            state,
            r#"{"method":"waitforblockheight","params":[9000,150],"id":1}"#,
        )
        .await;
        assert_eq!(res["height"].as_u64(), Some(0));
        assert_eq!(res["hash"].as_str(), Some(hash.as_str()));
    }

    /// `waitfornewblock` must wake on the actor's published status, not on the wait loop's
    /// backstop re-check - that is what makes it a blocking question rather than a poll with
    /// extra steps. The publish lands well inside the backstop interval, so a wait that only
    /// woke on the backstop would blow the bound here.
    #[tokio::test]
    async fn waitfornewblock_wakes_on_the_published_status() {
        let (state, tx) = state_publishing(status_at(&"ab".repeat(32)));
        let next = "cd".repeat(32);
        let publisher = {
            let next = next.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                tx.send_replace(status_at(&next));
                // Held open so the wait sees a live channel, not a dropped-sender error.
                tokio::time::sleep(Duration::from_millis(2000)).await;
                drop(tx);
            })
        };

        let started = Instant::now();
        // No timeout: only the published status can end this wait.
        let res = wait_call(state, r#"{"method":"waitfornewblock","id":1}"#).await;
        let elapsed = started.elapsed();
        assert_eq!(res["hash"].as_str(), Some(next.as_str()));
        assert!(
            elapsed < Duration::from_millis(700),
            "woke after {elapsed:?}; expected the publish to wake it, not the backstop re-check"
        );
        publisher.abort();
    }

    /// `waitforblock` watches the tip for one specific hash: the wallet's current best block
    /// answers immediately, any other hash waits (here, out to its timeout).
    #[tokio::test]
    async fn waitforblock_matches_the_current_best_block() {
        let hash = "ab".repeat(32);
        let (state, _tx) = state_publishing(status_at(&hash));

        let res = wait_call(
            state.clone(),
            &format!(r#"{{"method":"waitforblock","params":["{hash}"],"id":1}}"#),
        )
        .await;
        assert_eq!(res["hash"].as_str(), Some(hash.as_str()));

        // Core parses the argument as a hash, so the comparison is case-insensitive.
        let upper = hash.to_ascii_uppercase();
        let res = wait_call(
            state.clone(),
            &format!(r#"{{"method":"waitforblock","params":["{upper}",150],"id":1}}"#),
        )
        .await;
        assert_eq!(res["hash"].as_str(), Some(hash.as_str()));

        let other = "cd".repeat(32);
        let res = wait_call(
            state,
            &format!(r#"{{"method":"waitforblock","params":["{other}",150],"id":1}}"#),
        )
        .await;
        assert_eq!(
            res["hash"].as_str(),
            Some(hash.as_str()),
            "a timed-out wait reports the current tip, not the requested hash"
        );
    }

    /// Argument errors follow Bitcoin Core's taxonomy, and none of them may block: a bad
    /// argument must be rejected before the wait starts.
    #[tokio::test]
    async fn waitfor_rpcs_reject_bad_arguments_without_waiting() {
        let (state, _tx) = state_publishing(status_at(&"ab".repeat(32)));
        let cases: &[(&str, i64)] = &[
            // Missing height -> the help error; non-integer -> type error.
            (r#"{"method":"waitforblockheight","id":1}"#, -1),
            (
                r#"{"method":"waitforblockheight","params":["soon"],"id":1}"#,
                -3,
            ),
            // Negative height is out of the representable range, like getblockhash's.
            (
                r#"{"method":"waitforblockheight","params":[-1],"id":1}"#,
                -8,
            ),
            // A negative timeout is rejected rather than silently becoming an instant timeout.
            (
                r#"{"method":"waitforblockheight","params":[0,-1],"id":1}"#,
                -1,
            ),
            (r#"{"method":"waitfornewblock","params":["x"],"id":1}"#, -3),
            // Block-hash validation matches getblockheader's.
            (r#"{"method":"waitforblock","params":["abcd"],"id":1}"#, -8),
            (r#"{"method":"waitforblock","id":1}"#, -1),
            // Over-arity positional calls are Core's help error.
            (r#"{"method":"waitfornewblock","params":[1,2],"id":1}"#, -1),
        ];
        for (body, code) in cases {
            let started = Instant::now();
            let r = router(state.clone())
                .oneshot(req(body, Some(("u", "p"))))
                .await
                .unwrap();
            let env = body_json(r).await;
            assert_eq!(
                env["error"]["code"].as_i64(),
                Some(*code),
                "unexpected code for {body}: {env}"
            );
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "a rejected argument must not wait: {body}"
            );
        }
    }

    /// A `waitfor*` call with no timeout must still end when the daemon is stopping - otherwise
    /// it pins a work-queue slot through graceful shutdown and holds the process open.
    #[tokio::test]
    async fn waitfor_rpcs_return_on_shutdown() {
        let (state, _tx) = state_publishing(status_at(&"ab".repeat(32)));
        let shutting = state.clone();
        let stopper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutting.app.trigger_shutdown();
        });
        let res = wait_call(state, r#"{"method":"waitfornewblock","id":1}"#).await;
        assert_eq!(res["height"].as_u64(), Some(0));
        stopper.await.unwrap();
    }

    /// `z_waitforoperation` over the full HTTP path: the blocking alternative to the
    /// `z_getoperationstatus` poll loop. Everything it needs is offline - an inert test wallet
    /// handle (only its *name* is read) plus an operation the test itself gates - so the wait's
    /// semantics are pinned here rather than only in the regtest tier.
    #[tokio::test]
    async fn z_waitforoperation_blocks_until_the_operation_finishes() {
        use crate::error::RpcError;
        use crate::network::ZNetwork;
        use crate::wallet::{CoinWallet, SyncStatus, WalletHandle};

        let mut reg = WalletRegistry::new("default".into());
        reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
            "default",
            ZNetwork::Test,
            SyncStatus::default(),
        )));
        reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
            "w2",
            ZNetwork::Test,
            SyncStatus::default(),
        )));
        let mut state = test_state();
        state.app.registry = Arc::new(reg);

        // An operation the test releases by hand, so the "still running" and "finished" halves
        // are both deterministic.
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let opid = state
            .app
            .operations
            .try_insert("default", None, async move {
                let _ = gate.await;
                Ok::<Value, RpcError>(serde_json::json!({ "txid": "ab" }))
            })
            .expect("the registry has room for one operation");

        let call = |state: HttpState, uri: &'static str, params: String| async move {
            let body = format!(r#"{{"method":"z_waitforoperation","params":{params},"id":1}}"#);
            let r = router(state)
                .oneshot(req_to(uri, &body, Some(("u", "p"))))
                .await
                .unwrap();
            body_json(r).await
        };

        // timeout 0 is the immediate single-operation read: it returns the current status
        // without waiting for the still-gated operation.
        let v = call(state.clone(), "/", format!(r#"["{opid}",0]"#)).await;
        assert_eq!(v["result"]["id"], serde_json::json!(opid));
        assert_eq!(
            v["result"]["finished"],
            serde_json::json!(false),
            "the gated operation has not finished: {v}"
        );
        assert!(
            matches!(v["result"]["status"].as_str(), Some("queued" | "executing")),
            "the gated operation is still running: {v}"
        );

        // A non-zero timeout that expires is NOT an error: the current, non-terminal status
        // comes back with `finished: false` saying outright that the *wait* gave up, so callers
        // never have to know which status strings are terminal (Core's waitforblock behaviour).
        let v = call(state.clone(), "/", format!(r#"["{opid}",1]"#)).await;
        assert_eq!(v["error"], Value::Null, "a timeout is not an error: {v}");
        assert_eq!(
            v["result"]["finished"],
            serde_json::json!(false),
            "a timed-out wait reports finished=false: {v}"
        );
        assert!(
            matches!(v["result"]["status"].as_str(), Some("queued" | "executing")),
            "a timed-out wait reports the operation as unfinished: {v}"
        );

        // Released, the wait returns as soon as the operation finishes - with its result
        // visible, since the signal is published after the result is written.
        release.send(()).expect("release the operation");
        let v = call(state.clone(), "/", format!(r#"["{opid}",30]"#)).await;
        assert_eq!(v["result"]["finished"], serde_json::json!(true), "{v}");
        assert_eq!(v["result"]["status"], serde_json::json!("success"), "{v}");
        assert_eq!(v["result"]["result"]["txid"], serde_json::json!("ab"));

        // Non-destructive: waiting again returns the same terminal status, and the operation is
        // still there for z_getoperationresult to reap.
        let v = call(state.clone(), "/", format!(r#"["{opid}",0]"#)).await;
        assert_eq!(v["result"]["finished"], serde_json::json!(true), "{v}");
        assert_eq!(v["result"]["status"], serde_json::json!("success"), "{v}");
        assert_eq!(state.app.operations.take_results("default", None).len(), 1);

        // Once reaped there is nothing to wait for: -8 rather than a full-timeout block.
        let v = call(state.clone(), "/", format!(r#"["{opid}",30]"#)).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-8), "{v}");
    }

    /// A *failed* operation is a successful `z_waitforoperation` call: the wait observed the
    /// operation end (`finished: true`), and the send's own error rides in the status object's
    /// `error` rather than as an error on this call. This is the distinction the `finished`
    /// flag exists to make unambiguous - "the wait gave up" and "the operation failed" are
    /// different outcomes and must not look alike.
    #[tokio::test]
    async fn z_waitforoperation_reports_a_failed_operation_as_finished() {
        use crate::error::RpcError;
        use crate::network::ZNetwork;
        use crate::wallet::{CoinWallet, SyncStatus, WalletHandle};

        let mut reg = WalletRegistry::new("default".into());
        reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
            "default",
            ZNetwork::Test,
            SyncStatus::default(),
        )));
        let mut state = test_state();
        state.app.registry = Arc::new(reg);

        let opid = state
            .app
            .operations
            .try_insert("default", None, async {
                Err::<Value, _>(RpcError::insufficient_funds("broke"))
            })
            .expect("insert");

        let body = format!(r#"{{"method":"z_waitforoperation","params":["{opid}",30],"id":1}}"#);
        let r = router(state)
            .oneshot(req(&body, Some(("u", "p"))))
            .await
            .unwrap();
        let v = body_json(r).await;

        assert_eq!(v["error"], Value::Null, "the call itself succeeds: {v}");
        assert_eq!(v["result"]["finished"], serde_json::json!(true), "{v}");
        assert_eq!(v["result"]["status"], serde_json::json!("failed"), "{v}");
        assert_eq!(
            v["result"]["error"]["code"],
            serde_json::json!(crate::error::codes::RPC_WALLET_INSUFFICIENT_FUNDS),
            "the operation's own error is carried in the status object: {v}"
        );
        assert!(
            v["result"]["result"].is_null(),
            "a failed operation carries no result: {v}"
        );
    }

    /// The wait is wallet-scoped like the rest of the operation-tracking surface, and rejects
    /// an opid it has no operation for instead of blocking on it.
    #[tokio::test]
    async fn z_waitforoperation_is_wallet_scoped_and_rejects_unknown_ids() {
        use crate::error::RpcError;
        use crate::network::ZNetwork;
        use crate::wallet::{CoinWallet, SyncStatus, WalletHandle};

        let mut reg = WalletRegistry::new("default".into());
        for name in ["default", "w2"] {
            reg.insert(CoinWallet::Zcash(WalletHandle::for_test(
                name,
                ZNetwork::Test,
                SyncStatus::default(),
            )));
        }
        let mut state = test_state();
        state.app.registry = Arc::new(reg);

        let opid = state
            .app
            .operations
            .try_insert("default", None, async {
                Ok::<Value, RpcError>(serde_json::json!({ "txid": "ab" }))
            })
            .expect("insert");

        let call = |state: HttpState, uri: &'static str, params: String| async move {
            let body = format!(r#"{{"method":"z_waitforoperation","params":{params},"id":1}}"#);
            let r = router(state)
                .oneshot(req_to(uri, &body, Some(("u", "p"))))
                .await
                .unwrap();
            body_json(r).await
        };

        // The default wallet's own operation resolves...
        let v = call(state.clone(), "/", format!(r#"["{opid}",30]"#)).await;
        assert_eq!(v["result"]["finished"], serde_json::json!(true), "{v}");
        assert_eq!(v["result"]["status"], serde_json::json!("success"), "{v}");

        // ...but /wallet/w2 must not be able to wait on it, even naming the id exactly. A -8
        // (not a 30s block on someone else's operation) is the whole point.
        let v = call(state.clone(), "/wallet/w2", format!(r#"["{opid}",30]"#)).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-8), "{v}");

        // A well-formed-but-unknown id and a malformed one are both -8.
        let unknown = "opid-00000000-0000-0000-0000-000000000000";
        let v = call(state.clone(), "/", format!(r#"["{unknown}",30]"#)).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-8), "{v}");
        let v = call(state.clone(), "/", r#"["not-an-opid"]"#.to_string()).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-8), "{v}");

        // A negative timeout is -8; an over-arity call is Core's help error (-1).
        let v = call(state.clone(), "/", format!(r#"["{opid}",-1]"#)).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-8), "{v}");
        let v = call(state, "/", format!(r#"["{opid}",0,"extra"]"#)).await;
        assert_eq!(v["error"]["code"], serde_json::json!(-1), "{v}");
    }

    /// One-shot a single RPC call against a state whose `[rpc] allowed_methods` safelist is
    /// `safelist`, returning `(http_status, envelope_error_code)`.
    async fn call_with_safelist(safelist: Vec<String>, body: &str) -> (StatusCode, Option<i64>) {
        let mut state = test_state();
        let mut cfg = (*state.app.config).clone();
        cfg.rpc.allowed_methods = safelist;
        state.app.config = Arc::new(cfg);
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

    /// Bitcoin Core's argument-error taxonomy: a missing required param is the help error (-1),
    /// a wrong-typed one is a type error (-3), and no handler ever emits -32602 (which Core
    /// reserves for framing). All of these fire before any wallet access.
    #[tokio::test]
    async fn missing_and_wrong_typed_params_use_core_codes() {
        use crate::error::codes::{RPC_MISC_ERROR, RPC_TYPE_ERROR};
        // Missing required params -> -1. (These parse the param before resolving the wallet, so
        // the walletless state still reaches the param check. z_sendmany / z_getaddressforaccount
        // resolve the wallet first, so their missing-arg -1 is covered by conformance's funded
        // run instead.)
        for body in [
            r#"{"method":"getblockhash","id":1,"params":[]}"#,
            r#"{"method":"getblockheader","id":1,"params":[]}"#,
            r#"{"method":"sendtoaddress","id":1,"params":["uaddr"]}"#,
        ] {
            assert_eq!(
                call_err_code(body).await,
                Some(RPC_MISC_ERROR as i64),
                "missing param must be -1: {body}"
            );
        }
        // Present-but-wrong-typed params -> -3.
        for body in [
            // getblockhash height must be an integer.
            r#"{"method":"getblockhash","id":1,"params":["nope"]}"#,
            // require_str: a non-string where a string is required.
            r#"{"method":"getblockheader","id":1,"params":[123]}"#,
            r#"{"method":"sendmany","id":1,"params":["",42]}"#,
        ] {
            assert_eq!(
                call_err_code(body).await,
                Some(RPC_TYPE_ERROR as i64),
                "wrong-typed param must be -3: {body}"
            );
        }
    }

    /// Arity: a positional call with more arguments than the method accepts is rejected with
    /// Bitcoin Core's help error (-1) rather than silently ignoring the extras. Runs before any
    /// wallet access, so an empty registry suffices.
    #[tokio::test]
    async fn extra_positional_args_are_rejected() {
        use crate::error::codes::RPC_MISC_ERROR;
        for body in [
            // Zero-arg methods reject any positional arg.
            r#"{"method":"getblockcount","id":1,"params":[1]}"#,
            r#"{"method":"uptime","id":1,"params":["x"]}"#,
            // One-arg methods reject a second.
            r#"{"method":"getblockhash","id":1,"params":[1,2]}"#,
            r#"{"method":"validateaddress","id":1,"params":["a","b"]}"#,
        ] {
            assert_eq!(
                call_err_code(body).await,
                Some(RPC_MISC_ERROR as i64),
                "over-arity call must be -1: {body}"
            );
        }
        // A call at exactly the arity limit is not an arity error: getblockhash accepts one arg,
        // so `[1]` clears the bound and reaches the handler (failing later on the missing wallet).
        assert_ne!(
            call_err_code(r#"{"method":"getblockhash","id":1,"params":[1]}"#).await,
            Some(RPC_MISC_ERROR as i64),
            "a within-arity call must not be an arity error"
        );
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

    /// zecd is stateless: the off-chain label store is gone entirely, so the label-dedicated
    /// methods are not implemented at all and must surface as method-not-found (-32601), like any
    /// other unknown method - never reach a handler.
    #[tokio::test]
    async fn label_methods_are_not_implemented() {
        use crate::error::codes::RPC_METHOD_NOT_FOUND;
        for body in [
            r#"{"method":"setlabel","id":1,"params":["uaddr","x"]}"#,
            r#"{"method":"getaddressesbylabel","id":1,"params":["x"]}"#,
            r#"{"method":"listlabels","id":1,"params":[]}"#,
            r#"{"method":"getreceivedbylabel","id":1,"params":["x"]}"#,
            r#"{"method":"listreceivedbylabel","id":1,"params":[]}"#,
        ] {
            let code = call_err_code(body).await;
            assert_eq!(
                code,
                Some(RPC_METHOD_NOT_FOUND as i64),
                "label method must be unimplemented: {body}"
            );
        }
        // getnewaddress stays available, but a non-empty label argument is rejected (-8): a label
        // would be off-chain state zecd doesn't keep.
        let code = call_err_code(r#"{"method":"getnewaddress","id":1,"params":["mylabel"]}"#).await;
        assert_eq!(
            code,
            Some(crate::error::codes::RPC_INVALID_PARAMETER as i64)
        );
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
