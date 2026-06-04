//! Blockchain RPCs: getblockchaininfo, getblockcount, getbestblockhash, getblockhash.
//!
//! Heights come from the wallet's published sync status: `blocks` is the fully-scanned
//! height (the height up to which balances/history are accurate) and `headers` is the known
//! chain tip, so a syncing wallet reports `blocks < headers` as bitcoind does during IBD.

use serde_json::{json, Value};

use crate::error::RpcError;
use crate::rpc::net_name;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

pub fn getblockchaininfo(state: &AppState) -> Result<Value, RpcError> {
    let w = state.registry.get(None)?;
    let st = w.status();
    let blocks = st.fully_scanned.unwrap_or(0);
    let headers = st.chain_tip.unwrap_or(blocks);
    Ok(json!({
        "chain": net_name(w.network),
        "blocks": blocks,
        "headers": headers,
        "bestblockhash": st.best_block_hash.clone().unwrap_or_default(),
        "difficulty": 1.0,
        "mediantime": st.tip_time.unwrap_or(0),
        "verificationprogress": st.scan_progress,
        "initialblockdownload": st.scanning,
        "size_on_disk": 0,
        "pruned": false,
        "warnings": ""
    }))
}

pub fn getblockcount(state: &AppState) -> Result<Value, RpcError> {
    let w = state.registry.get(None)?;
    Ok(json!(w.status().fully_scanned.unwrap_or(0)))
}

pub fn getbestblockhash(state: &AppState) -> Result<Value, RpcError> {
    let w = state.registry.get(None)?;
    match w.status().best_block_hash {
        Some(h) => Ok(Value::String(h)),
        None => Err(RpcError::misc("best block hash not yet known (still connecting)")),
    }
}

pub fn getblockhash(state: &AppState, req: &RpcRequest) -> Result<Value, RpcError> {
    let height = req
        .param(0)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("getblockhash requires a height"))?
        as u32;
    let st = state.registry.get(None)?.status();
    match (st.chain_tip, st.best_block_hash) {
        (Some(tip), Some(hash)) if tip == height => Ok(Value::String(hash)),
        _ => Err(RpcError::invalid_parameter(
            "this light wallet can only return the hash of the current chain tip",
        )),
    }
}
