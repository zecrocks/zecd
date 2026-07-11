//! Unauthenticated liveness/readiness HTTP server on a separate port, for cloud-native
//! deployment (Kubernetes probes, load balancers).
//!
//! - `GET /healthz` - liveness: always 200 while the process is running.
//! - `GET /readyz` - readiness: 200/503, gated by the configured [`ReadinessMode`] (see
//!   `[health] readiness`): either "the wallet has scanned to near the tip" or "the backend is
//!   connected and live".
//! - `GET /status` - JSON snapshot of per-wallet sync state (for humans/ops).

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use crate::config::{HealthConfig, ReadinessMode};
use crate::state::AppState;
use crate::wallet::SyncStatus;

/// Whether one wallet is ready to serve, per the configured readiness mode. The actor-liveness
/// check is applied by the caller.
fn wallet_ready(st: &SyncStatus, cfg: &HealthConfig) -> bool {
    if !st.connected {
        return false;
    }
    match cfg.readiness {
        // Strict: the wallet has actually scanned to (near) the tip, measured by the height gap,
        // AND its transaction-enhancement backlog has drained. We deliberately do NOT gate on
        // librustzcash's note-weighted `progress().scan()` ratio: it's computed over the
        // tip-priority range and hits 1.0 while lower-priority historical ranges keep climbing
        // `fully_scanned` (e.g. a from-birthday restore), so progress alone would report ready with
        // the wallet hundreds of thousands of blocks short of its own funds. The height gap is the
        // meaningful scan signal. But "scanned to tip" is not "ready to serve full history": after
        // the block scan catches up, `enhance_step` still has one upstream fetch + decrypt/store per
        // transaction to backfill memos - a multi-hour backlog on a from-birthday restore. Until
        // that drains, history RPCs are missing memos and lag, so readiness must wait on it too.
        ReadinessMode::Synced => match (st.chain_tip, st.fully_scanned) {
            (Some(tip), Some(scanned)) => {
                tip.saturating_sub(scanned) <= cfg.max_scan_lag && st.pending_enhancements == 0
            }
            // Until both heights are known the wallet hasn't demonstrably caught up.
            _ => false,
        },
        // Lenient: ready as soon as the backend is connected and its tip is past our birthday - a
        // cheap sanity check that we're talking to the right, live network. Does NOT wait for the
        // scan to finish, so RPC clients can reach zecd while it catches up, and readiness doesn't
        // flap during a long sync.
        ReadinessMode::Connected => match (st.chain_tip, st.birthday) {
            (Some(tip), Some(birthday)) => tip > birthday,
            // No tip yet (or, defensively, no birthday) means we can't sanity-check the upstream.
            _ => false,
        },
    }
}

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
    /// Some wallet has caught its block scan up to the tip but is still draining its
    /// transaction-enhancement backlog (see `SyncStatus::pending_enhancements`). Surfaced as a
    /// distinct `readyz` reason so an operator can tell "scanned to tip, backfilling memos" apart
    /// from "still scanning blocks" - the two look identical without it (both not-ready, scan done).
    any_enhancing: bool,
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
    let mut any_enhancing = false;
    let mut wallets = Map::new();
    for name in names {
        if let Ok(h) = state.registry.get(Some(&name)) {
            let st = h.status();
            // A dead writer actor means sends/address-generation are broken even though reads
            // still answer from the DB - so it must fail readiness, not silently report ready.
            let actor_alive = h.actor_alive();
            let w_ready = actor_alive && wallet_ready(&st, &state.config.health);
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
            // Block scan caught up to the tip, but the enhancement backlog hasn't drained yet.
            if !st.scanning && st.pending_enhancements > 0 {
                any_enhancing = true;
            }
            // The block-height gap between the tip and the last fully-scanned height - the
            // meaningful "how far behind" signal. Surfaced on every wallet regardless of the
            // configured readiness mode, so an operator on `readiness = "connected"` (which reports
            // ready before the scan finishes) can still see how stale the wallet's reads may be.
            // `null` until both heights are known.
            let scan_lag = match (st.chain_tip, st.fully_scanned) {
                (Some(tip), Some(scanned)) => Some(tip.saturating_sub(scanned)),
                _ => None,
            };
            wallets.insert(
                name,
                json!({
                    "connected": st.connected,
                    "actor_alive": actor_alive,
                    "server": st.server,
                    "conn_state": st.conn_state.as_str(),
                    "chain_tip": st.chain_tip,
                    "fully_scanned": st.fully_scanned,
                    "scan_lag": scan_lag,
                    "birthday": st.birthday,
                    "scan_progress": st.scan_progress,
                    "scanning": st.scanning,
                    "pending_enhancements": st.pending_enhancements,
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
        any_enhancing,
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
        // Distinguish a dead writer actor from "all upstreams down" from "still backfilling memos"
        // from "still scanning blocks" so probes/alerts can tell them apart (a dead actor needs a
        // process restart; an enhancing wallet is scanned to tip but not yet serving full history).
        body["reason"] = json!(if snap.any_actor_down {
            "actor_down"
        } else if snap.any_down {
            "upstream_down"
        } else if snap.any_enhancing {
            "enhancing"
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
    use super::{is_locked, wallet_ready};
    use crate::config::{HealthConfig, ReadinessMode};
    use crate::wallet::SyncStatus;

    fn st(connected: bool, tip: Option<u32>, scanned: Option<u32>) -> SyncStatus {
        SyncStatus {
            connected,
            chain_tip: tip,
            fully_scanned: scanned,
            birthday: Some(50),
            ..SyncStatus::default()
        }
    }

    fn cfg(readiness: ReadinessMode) -> HealthConfig {
        HealthConfig {
            enabled: true,
            bind: "127.0.0.1".parse().unwrap(),
            port: 9333,
            readiness,
            max_scan_lag: 4,
        }
    }

    #[test]
    fn synced_mode_requires_a_small_height_gap() {
        let synced = cfg(ReadinessMode::Synced);
        // The regression: the wallet is 357k blocks behind the tip (a from-birthday restore).
        // That must NOT report ready, even though note-weighted progress would read 1.0.
        assert!(!wallet_ready(
            &st(true, Some(4_080_983), Some(3_724_064)),
            &synced
        ));

        // Caught up to the tip (gap 0): ready.
        assert!(wallet_ready(
            &st(true, Some(4_080_983), Some(4_080_983)),
            &synced
        ));

        // Within the lag budget (gap 4 <= 4): ready; just over it (gap 5): not ready.
        assert!(wallet_ready(&st(true, Some(100), Some(96)), &synced));
        assert!(!wallet_ready(&st(true, Some(100), Some(95)), &synced));

        // Disconnected, or heights unknown: never ready.
        assert!(!wallet_ready(&st(false, Some(100), Some(100)), &synced));
        assert!(!wallet_ready(&st(true, None, Some(100)), &synced));
        assert!(!wallet_ready(&st(true, Some(100), None), &synced));
    }

    #[test]
    fn synced_mode_waits_for_the_enhancement_backlog_to_drain() {
        let synced = cfg(ReadinessMode::Synced);
        // Caught the block scan up to the tip (gap 0) but the transaction-enhancement backlog
        // hasn't drained: the headline bug - "scan complete" while memos are still being
        // backfilled for hours. That must NOT report ready.
        let mut caught_up_but_enhancing = st(true, Some(4_080_983), Some(4_080_983));
        caught_up_but_enhancing.pending_enhancements = 29_660;
        assert!(!wallet_ready(&caught_up_but_enhancing, &synced));

        // Even a single pending request keeps the wallet not-ready.
        let mut one_left = st(true, Some(100), Some(100));
        one_left.pending_enhancements = 1;
        assert!(!wallet_ready(&one_left, &synced));

        // Backlog drained (and within the lag budget): ready.
        let mut drained = st(true, Some(100), Some(100));
        drained.pending_enhancements = 0;
        assert!(wallet_ready(&drained, &synced));
    }

    #[test]
    fn connected_mode_ignores_the_enhancement_backlog() {
        // The lenient mode is "upstream is live past our birthday"; it deliberately doesn't wait on
        // the scan, so it shouldn't wait on enhancement either.
        let connected = cfg(ReadinessMode::Connected);
        let mut enhancing = st(true, Some(4_080_983), Some(4_080_983));
        enhancing.pending_enhancements = 29_660;
        assert!(wallet_ready(&enhancing, &connected));
    }

    #[test]
    fn connected_mode_only_requires_a_live_upstream_past_the_birthday() {
        let connected = cfg(ReadinessMode::Connected);
        // Far behind on the scan (gap 357k) but connected and the tip is past birthday 50: ready.
        // This is the whole point - RPC clients can reach zecd while it catches up.
        assert!(wallet_ready(
            &st(true, Some(4_080_983), Some(3_724_064)),
            &connected
        ));
        // Tip just past birthday: ready, regardless of scan state.
        assert!(wallet_ready(&st(true, Some(51), None), &connected));

        // Tip at or below birthday (wrong/dead network, or upstream not yet caught up to our
        // birthday): not ready.
        assert!(!wallet_ready(&st(true, Some(50), None), &connected));
        assert!(!wallet_ready(&st(true, Some(49), None), &connected));

        // Disconnected, or no tip yet: never ready.
        assert!(!wallet_ready(&st(false, Some(4_080_983), None), &connected));
        assert!(!wallet_ready(&st(true, None, None), &connected));
    }

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
