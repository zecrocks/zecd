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
    let shutdown = state.shutdown_signal();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/status", get(status))
        .with_state(state);

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            info!("health server listening on http://{addr} (/healthz /readyz /status)");
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                warn!("health server error: {e}");
            }
        }
        Err(e) => {
            warn!("health server: failed to bind {addr}: {e} (continuing without health endpoints)")
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Compute overall readiness, whether any wallet's upstream is down, whether any wallet's
/// writer actor has died, and a per-wallet status map.
fn snapshot(state: &AppState) -> (bool, bool, bool, Value) {
    let names = state.registry.names();
    let mut ready = !names.is_empty();
    let mut any_down = false;
    let mut any_actor_down = false;
    let mut wallets = Map::new();
    for name in names {
        if let Ok(h) = state.registry.get(Some(&name)) {
            let st = h.status();
            // A dead writer actor means sends/address-generation are broken even though reads
            // still answer from the DB - so it must fail readiness, not silently report ready.
            let actor_alive = h.actor_alive();
            let w_ready = actor_alive
                && st.connected
                && st.scan_progress >= state.config.health.ready_progress;
            ready = ready && w_ready;
            if matches!(st.conn_state, crate::wallet::ConnState::Down) {
                any_down = true;
            }
            if !actor_alive {
                any_actor_down = true;
            }
            wallets.insert(
                name,
                json!({
                    "connected": st.connected,
                    "actor_alive": actor_alive,
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
    (ready, any_down, any_actor_down, Value::Object(wallets))
}

async fn readyz(State(state): State<AppState>) -> Response {
    let (ready, any_down, any_actor_down, wallets) = snapshot(&state);
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut body = json!({ "ready": ready, "wallets": wallets });
    if !ready {
        // Distinguish a dead writer actor from "all upstreams down" from "still syncing" so
        // probes/alerts can tell them apart (a dead actor needs a process restart).
        body["reason"] = json!(if any_actor_down {
            "actor_down"
        } else if any_down {
            "upstream_down"
        } else {
            "syncing"
        });
    }
    (code, Json(body)).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let (ready, _any_down, _any_actor_down, wallets) = snapshot(&state);
    Json(json!({
        "ready": ready,
        "network": state.config.network.name(),
        "wallets": wallets,
    }))
    .into_response()
}
