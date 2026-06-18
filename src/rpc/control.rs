//! Control RPCs: stop, uptime, help, getrpcinfo.

use serde_json::{json, Value};

use crate::error::RpcError;
use crate::state::AppState;

/// `stop` - request graceful shutdown (in-flight requests finish; new ones get 503).
///
/// Gated to regtest (matching Zallet): on mainnet/testnet it reports method-not-found so a
/// stray `stop` can't take down a production daemon over RPC. Stop a live node with a signal
/// (SIGINT/SIGTERM) instead.
pub(crate) fn stop(state: &AppState) -> Result<Value, RpcError> {
    if !state.config.network.is_regtest() {
        return Err(RpcError::method_not_found("stop"));
    }
    state.trigger_shutdown();
    Ok(Value::String("zecd stopping".to_string()))
}

/// `uptime` - seconds since the daemon started.
pub(crate) fn uptime(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.started_at.elapsed().as_secs()))
}

/// `help` - a short orientation string (zecd has no per-method help pages; the README's
/// method table is the reference).
pub(crate) fn help() -> Result<Value, RpcError> {
    Ok(Value::String(
        "zecd: a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash. \
         Supported methods include getblockchaininfo, getnetworkinfo, getwalletinfo, \
         getnewaddress, getbalance, sendtoaddress, sendmany, listtransactions, \
         gettransaction, validateaddress. See the README for the full list and limits."
            .to_string(),
    ))
}

/// `getrpcinfo` - the currently-executing commands, Bitcoin Core's load-visibility RPC.
pub(crate) fn getrpcinfo(state: &AppState) -> Result<Value, RpcError> {
    // active_commands: one entry per currently-executing command, with elapsed microseconds -
    // the same shape as Bitcoin Core's getrpcinfo (gives visibility under load).
    let active: Vec<Value> = state
        .active
        .snapshot()
        .into_iter()
        .map(|(method, micros)| json!({ "method": method, "duration": micros as u64 }))
        .collect();
    // We log to stderr/tracing rather than a debug.log file, so logpath is empty.
    Ok(json!({ "active_commands": active, "logpath": "" }))
}
