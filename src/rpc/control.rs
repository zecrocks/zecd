//! Control RPCs: stop, uptime, help, getrpcinfo.

use serde_json::{json, Value};

use crate::error::RpcError;
use crate::state::AppState;

pub fn stop(state: &AppState) -> Result<Value, RpcError> {
    state.shutdown.notify_one();
    Ok(Value::String("zecd stopping".to_string()))
}

pub fn uptime(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.started_at.elapsed().as_secs()))
}

pub fn help() -> Result<Value, RpcError> {
    Ok(Value::String(
        "zecd: a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash. \
         Supported methods include getblockchaininfo, getnetworkinfo, getwalletinfo, \
         getnewaddress, getbalance, sendtoaddress, sendmany, listtransactions, \
         gettransaction, validateaddress. See the README for the full list and limits."
            .to_string(),
    ))
}

pub fn getrpcinfo() -> Result<Value, RpcError> {
    Ok(json!({ "active_commands": [], "logpath": "" }))
}
