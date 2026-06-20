//! Unauthenticated liveness/readiness HTTP server on a separate port, for cloud-native
//! deployment (Kubernetes probes, load balancers).
//!
//! - `GET /healthz` - liveness: always 200 while the process is running.
//! - `GET /readyz` - readiness: 200 when every wallet is connected to its upstream and
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

/// The readiness snapshot: overall readiness, whether any wallet's upstream is down, whether
/// any wallet's writer actor has died, whether any (encrypted) wallet is currently locked, and
/// a per-wallet status map.
struct Snapshot {
    ready: bool,
    any_down: bool,
    any_actor_down: bool,
    any_locked: bool,
    wallets: Value,
}

/// Whether an encrypted wallet is currently locked (seed not loaded) - i.e. it needs a
/// `walletpassphrase` before it can spend. `unlocked_until` is `Some(0)` for a locked
/// encrypted wallet, a future unix time when unlocked, and `None` for unencrypted wallets.
fn is_locked(st: &crate::wallet::SyncStatus) -> bool {
    st.encrypted && st.unlocked_until == Some(0)
}

fn snapshot(state: &AppState) -> Snapshot {
    let names = state.registry.names();
    let mut ready = !names.is_empty();
    let mut any_down = false;
    let mut any_actor_down = false;
    let mut any_locked = false;
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
            // A locked wallet stays read-ready and syncs fine; it just can't spend. We surface
            // it as a distinct signal (not a readiness failure) so an operator/controller can
            // tell "needs walletpassphrase" apart from "still syncing" without breaking
            // read-only or watch-only deployments that are legitimately ready while locked.
            let locked = is_locked(&st);
            if locked {
                any_locked = true;
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
                    "encrypted": st.encrypted,
                    "locked": locked,
                    "ready": w_ready,
                }),
            );
        }
    }
    Snapshot {
        ready,
        any_down,
        any_actor_down,
        any_locked,
        wallets: Value::Object(wallets),
    }
}

async fn readyz(State(state): State<AppState>) -> Response {
    let snap = snapshot(&state);
    let code = if snap.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    // `locked` is reported regardless of readiness: a synced-but-locked wallet is ready for
    // reads (200) yet still needs a `walletpassphrase` before it can spend. A controller can
    // watch this flag to drive an unlock without misreading it as a sync stall.
    let mut body = json!({
        "ready": snap.ready,
        "locked": snap.any_locked,
        "wallets": snap.wallets,
    });
    if !snap.ready {
        // Distinguish a dead writer actor from "all upstreams down" from "still syncing" so
        // probes/alerts can tell them apart (a dead actor needs a process restart).
        body["reason"] = json!(if snap.any_actor_down {
            "actor_down"
        } else if snap.any_down {
            "upstream_down"
        } else {
            "syncing"
        });
    }
    (code, Json(body)).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let snap = snapshot(&state);
    Json(json!({
        "ready": snap.ready,
        "locked": snap.any_locked,
        "network": state.config.network.name(),
        "wallets": snap.wallets,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::is_locked;
    use crate::wallet::SyncStatus;

    #[test]
    fn locked_signal_tracks_encryption_and_unlock_state() {
        // An encrypted wallet with unlocked_until == Some(0) is locked (needs walletpassphrase).
        let locked = SyncStatus {
            encrypted: true,
            unlocked_until: Some(0),
            ..SyncStatus::default()
        };
        assert!(is_locked(&locked));

        // The same wallet once unlocked (a future relock time) is not locked.
        let unlocked = SyncStatus {
            encrypted: true,
            unlocked_until: Some(4_102_444_800),
            ..SyncStatus::default()
        };
        assert!(!is_locked(&unlocked));

        // An unencrypted (identity/auto-unlock) wallet is never "locked" in this sense - it has
        // no passphrase to enter; unlocked_until is None.
        let unencrypted = SyncStatus {
            encrypted: false,
            unlocked_until: None,
            ..SyncStatus::default()
        };
        assert!(!is_locked(&unencrypted));
    }
}
