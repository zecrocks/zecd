//! Unauthenticated liveness/readiness HTTP server on a separate port, for cloud-native
//! deployment (Kubernetes probes, load balancers).
//!
//! - `GET /healthz` - liveness: always 200 while the process is running.
//! - `GET /readyz` - readiness: 200 when every wallet is connected to lightwalletd and
//!   synced to at least `[health] ready_progress`; otherwise 503.
//! - `GET /status` - JSON snapshot of per-wallet sync state (for humans/ops).

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use crate::state::AppState;

/// Run the health server until graceful shutdown. Binding failures are non-fatal (logged).
pub async fn run(state: AppState) {
    if !state.config.health.enabled {
        return;
    }
    let addr = SocketAddr::new(state.config.health.bind, state.config.health.port);
    let shutdown = state.shutdown.clone();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/status", get(status))
        .with_state(state);

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            info!("health server listening on http://{addr} (/healthz /readyz /status)");
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move { shutdown.notified().await })
                .await
            {
                warn!("health server error: {e}");
            }
        }
        Err(e) => warn!(
            "health server: failed to bind {addr}: {e} (continuing without health endpoints)"
        ),
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Compute overall readiness, whether any wallet's upstream is down, and a per-wallet status map.
fn snapshot(state: &AppState) -> (bool, bool, Value) {
    let names = state.registry.names();
    let mut ready = !names.is_empty();
    let mut any_down = false;
    let mut wallets = Map::new();
    for name in names {
        if let Ok(h) = state.registry.get(Some(&name)) {
            let st = h.status();
            let w_ready = st.connected && st.scan_progress >= state.config.health.ready_progress;
            ready = ready && w_ready;
            if matches!(st.conn_state, crate::wallet::ConnState::Down) {
                any_down = true;
            }
            wallets.insert(
                name,
                json!({
                    "connected": st.connected,
                    "server": st.server,
                    "conn_state": st.conn_state.as_str(),
                    "chain_tip": st.chain_tip,
                    "fully_scanned": st.fully_scanned,
                    "scan_progress": st.scan_progress,
                    "scanning": st.scanning,
                    "ready": w_ready,
                }),
            );
        }
    }
    (ready, any_down, Value::Object(wallets))
}

async fn readyz(State(state): State<AppState>) -> Response {
    let (ready, any_down, wallets) = snapshot(&state);
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut body = json!({ "ready": ready, "wallets": wallets });
    if !ready {
        // Distinguish "all upstreams down" from "still syncing" so probes/alerts can tell them apart.
        body["reason"] = json!(if any_down { "upstream_down" } else { "syncing" });
    }
    (code, Json(body)).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let (ready, _any_down, wallets) = snapshot(&state);
    Json(json!({
        "ready": ready,
        "network": crate::rpc::net_name(state.config.network),
        "wallets": wallets,
    }))
    .into_response()
}
