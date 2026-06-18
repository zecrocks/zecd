//! Prometheus `/metrics` instrumentation.
//!
//! A single global recorder (the [`metrics`] crate facade, used like `tracing`) collects the
//! counters and histograms emitted from call sites across the daemon; the `/metrics` HTTP
//! handler (in [`crate::health`]) renders them. Per-wallet **gauges** are not pushed from the
//! actor - they are refreshed on each scrape from every wallet's `SyncStatus` snapshot
//! ([`refresh_gauges`]), so they always agree with `/status` without threading anything through
//! the single-writer actor.
//!
//! Cardinality is deliberately bounded: labels are `method` (the fixed RPC table), `wallet`
//! (multiwallet is rare), and small `outcome`/`state` enums - never a txid, address, or remote
//! address.

use std::time::Duration;

use metrics::{
    counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram, Unit,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

use crate::state::AppState;

/// Latency buckets (seconds) for the `*_seconds` histograms: sub-millisecond reads up to the
/// multi-second Orchard proving path.
const SECONDS_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Buckets for reorg rewind depth (blocks).
const REWIND_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 500.0];

/// Install the global Prometheus recorder and return its render handle. Best-effort: a failure
/// (recorder already installed, or no Tokio runtime for the upkeep task) is logged and returns
/// `None`, so the daemon still serves - just without `/metrics`.
pub fn install() -> Option<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_string()), SECONDS_BUCKETS)
        .and_then(|b| {
            b.set_buckets_for_metric(
                Matcher::Full("zecd_reorg_rewind_depth_blocks".to_string()),
                REWIND_BUCKETS,
            )
        })
        .and_then(|b| b.install_recorder());
    match handle {
        Ok(handle) => {
            describe();
            gauge!("zecd_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
            Some(handle)
        }
        Err(e) => {
            tracing::warn!("metrics: failed to install Prometheus recorder: {e}");
            None
        }
    }
}

/// Register HELP/TYPE/units for every series so the scrape output is self-describing.
fn describe() {
    describe_gauge!(
        "zecd_build_info",
        "Constant 1, carrying the build version as a label"
    );

    // Per-wallet sync/chain gauges (refreshed on scrape from SyncStatus).
    describe_gauge!(
        "zecd_chain_tip_height",
        Unit::Count,
        "Upstream chain tip height seen by the wallet"
    );
    describe_gauge!(
        "zecd_wallet_scanned_height",
        Unit::Count,
        "Highest fully-scanned block height (getblockcount); tip minus this is the sync lag"
    );
    describe_gauge!("zecd_scan_progress_ratio", "Wallet scan progress in [0,1]");
    describe_gauge!(
        "zecd_connected",
        "1 when a lightwalletd/zebra upstream is connected"
    );
    describe_gauge!(
        "zecd_actor_alive",
        "1 while the wallet's single-writer actor is running"
    );
    describe_gauge!(
        "zecd_conn_state",
        "One-hot upstream connection state (labels state=down|syncing|ready)"
    );
    describe_gauge!(
        "zecd_wallet_encrypted",
        "1 when the wallet is passphrase-encrypted"
    );
    describe_gauge!(
        "zecd_wallet_watch_only",
        "1 when the wallet is watch-only (UFVK import)"
    );

    // Connection / failover counters.
    describe_counter!(
        "zecd_connection_failures_total",
        "Failed upstream connection attempts (per server candidate)"
    );
    describe_counter!(
        "zecd_server_switches_total",
        "Times the active upstream changed (failover or prefer-primary recovery)"
    );

    // RPC server.
    describe_counter!(
        "zecd_rpc_requests_total",
        "Dispatched RPC requests, by method and outcome (success|error)"
    );
    describe_histogram!(
        "zecd_rpc_request_duration_seconds",
        Unit::Seconds,
        "RPC dispatch latency, by method"
    );
    describe_gauge!(
        "zecd_rpc_active_commands",
        "RPC commands currently executing (getrpcinfo.active_commands)"
    );
    describe_counter!(
        "zecd_rpc_overload_total",
        "Requests rejected with 503 because the work queue was full"
    );
    describe_counter!(
        "zecd_rpc_auth_failures_total",
        "Requests rejected with 401 (bad auth)"
    );

    // Money flow.
    describe_counter!(
        "zecd_sends_total",
        "Outbound send/broadcast outcomes (accepted|rejected|transport_fail|deferred)"
    );
    describe_histogram!(
        "zecd_send_proposal_duration_seconds",
        Unit::Seconds,
        "Time to build and prove a send proposal (the CPU-heavy Orchard proving path)"
    );
    describe_counter!(
        "zecd_mempool_txs_decrypted_total",
        "Wallet-relevant mempool transactions trial-decrypted and stored (0-conf deposits)"
    );
    describe_counter!("zecd_reorgs_total", "Chain reorgs detected and rewound");
    describe_histogram!(
        "zecd_reorg_rewind_depth_blocks",
        Unit::Count,
        "Rewind distance in blocks when recovering from a reorg"
    );
    describe_counter!(
        "zecd_async_operations_total",
        "Async z_* operation outcomes, by method and outcome (success|failed) - captures \
         z_sendmany failures that abort before broadcast"
    );
}

/// Refresh the pull-style per-wallet gauges from the current `SyncStatus` snapshots, plus the
/// in-flight command gauge. Called by the `/metrics` handler on each scrape.
pub fn refresh_gauges(state: &AppState) {
    gauge!("zecd_rpc_active_commands").set(state.active.snapshot().len() as f64);

    for name in state.registry.names() {
        let Ok(h) = state.registry.get(Some(&name)) else {
            continue;
        };
        let st = h.status();
        gauge!("zecd_connected", "wallet" => name.clone()).set(b2f(st.connected));
        gauge!("zecd_actor_alive", "wallet" => name.clone()).set(b2f(h.actor_alive()));
        gauge!("zecd_scan_progress_ratio", "wallet" => name.clone()).set(st.scan_progress);
        gauge!("zecd_wallet_encrypted", "wallet" => name.clone()).set(b2f(st.encrypted));
        gauge!("zecd_wallet_watch_only", "wallet" => name.clone()).set(b2f(st.watch_only));
        if let Some(tip) = st.chain_tip {
            gauge!("zecd_chain_tip_height", "wallet" => name.clone()).set(tip as f64);
        }
        if let Some(scanned) = st.fully_scanned {
            gauge!("zecd_wallet_scanned_height", "wallet" => name.clone()).set(scanned as f64);
        }
        // One-hot the connection state so a single PromQL series covers each value.
        for s in ["down", "syncing", "ready"] {
            let active = st.conn_state.as_str() == s;
            gauge!("zecd_conn_state", "wallet" => name.clone(), "state" => s).set(b2f(active));
        }
    }
}

// --- Push helpers (called at instrumentation sites) ---------------------------------------

/// Record a dispatched RPC: increment the by-method/outcome counter and observe its latency.
pub fn record_rpc(method: &str, outcome: &'static str, elapsed: Duration) {
    counter!("zecd_rpc_requests_total", "method" => method.to_string(), "outcome" => outcome)
        .increment(1);
    histogram!("zecd_rpc_request_duration_seconds", "method" => method.to_string())
        .record(elapsed.as_secs_f64());
}

/// A request rejected with 503 because the work queue was full.
pub fn inc_rpc_overload() {
    counter!("zecd_rpc_overload_total").increment(1);
}

/// A request rejected with 401 for bad/missing auth.
pub fn inc_auth_failure() {
    counter!("zecd_rpc_auth_failures_total").increment(1);
}

/// A failed upstream connection attempt for `wallet`.
pub fn inc_connection_failure(wallet: &str) {
    counter!("zecd_connection_failures_total", "wallet" => wallet.to_string()).increment(1);
}

/// The active upstream for `wallet` changed (failover or prefer-primary recovery).
pub fn inc_server_switch(wallet: &str) {
    counter!("zecd_server_switches_total", "wallet" => wallet.to_string()).increment(1);
}

/// An outbound send/broadcast resolved with `outcome`.
pub fn record_send(outcome: &'static str) {
    counter!("zecd_sends_total", "outcome" => outcome).increment(1);
}

/// Observe the time spent building+proving a send proposal.
pub fn record_send_proposal(elapsed: Duration) {
    histogram!("zecd_send_proposal_duration_seconds").record(elapsed.as_secs_f64());
}

/// A wallet-relevant mempool tx was trial-decrypted and stored (0-conf deposit visibility).
pub fn inc_mempool_decrypt(wallet: &str) {
    counter!("zecd_mempool_txs_decrypted_total", "wallet" => wallet.to_string()).increment(1);
}

/// A reorg was detected and rewound `depth` blocks.
pub fn record_reorg(depth: u32) {
    counter!("zecd_reorgs_total").increment(1);
    histogram!("zecd_reorg_rewind_depth_blocks").record(depth as f64);
}

/// An async `z_*` operation (e.g. `z_sendmany`) finished with `outcome` (success|failed). Unlike
/// `zecd_sends_total`, this also counts sends that fail before broadcast (proposal/validation).
pub fn record_async_operation(method: &str, outcome: &'static str) {
    counter!("zecd_async_operations_total", "method" => method.to_string(), "outcome" => outcome)
        .increment(1);
}

fn b2f(b: bool) -> f64 {
    if b {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The push helpers emit series that render in Prometheus text form, with the expected
    /// names, labels, and TYPE/HELP metadata. Uses a *local* recorder so it never touches the
    /// process-global one (and needs no Tokio runtime).
    #[test]
    fn helpers_render_expected_series() {
        let recorder = PrometheusBuilder::new()
            .set_buckets_for_metric(Matcher::Suffix("_seconds".to_string()), SECONDS_BUCKETS)
            .unwrap()
            .build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            describe();
            gauge!("zecd_build_info", "version" => "test").set(1.0);
            record_rpc("uptime", "success", Duration::from_millis(3));
            record_rpc("getblockcount", "error", Duration::from_millis(1));
            inc_rpc_overload();
            inc_auth_failure();
            inc_connection_failure("default");
            inc_server_switch("default");
            record_send("accepted");
            record_send("rejected");
            record_send_proposal(Duration::from_secs(2));
            inc_mempool_decrypt("default");
            record_reorg(7);
            record_async_operation("z_sendmany", "failed");
        });

        let out = handle.render();
        // A representative series from each subsystem is present.
        for needle in [
            "zecd_build_info",
            "zecd_rpc_requests_total",
            "zecd_rpc_request_duration_seconds",
            "zecd_rpc_overload_total",
            "zecd_rpc_auth_failures_total",
            "zecd_connection_failures_total",
            "zecd_server_switches_total",
            "zecd_sends_total",
            "zecd_send_proposal_duration_seconds",
            "zecd_mempool_txs_decrypted_total",
            "zecd_reorgs_total",
            "zecd_reorg_rewind_depth_blocks",
            "zecd_async_operations_total",
        ] {
            assert!(out.contains(needle), "missing series {needle} in:\n{out}");
        }
        // Labels and metadata render as expected.
        assert!(out.contains(r#"method="uptime",outcome="success""#));
        assert!(out.contains(r#"outcome="rejected""#));
        assert!(out.contains(r#"wallet="default""#));
        assert!(out.contains("# TYPE zecd_rpc_requests_total counter"));
        assert!(out.contains("# HELP zecd_sends_total"));
    }
}
