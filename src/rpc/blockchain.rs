//! Blockchain RPCs: getblockchaininfo, getblockcount, getbestblockhash, getblockhash.
//!
//! Heights come from the wallet's published sync status: `blocks` is the fully-scanned
//! height (the height up to which balances/history are accurate) and `headers` is the known
//! chain tip, so a syncing wallet reports `blocks < headers` as bitcoind does during IBD.
//! `getbestblockhash` and `getblockhash(getblockcount())` describe that same fully-scanned
//! block (hashes/times come from the wallet's `blocks` table), so the common poller pattern
//! `getblockhash(getblockcount())` always works.

use serde_json::{json, Value};

use crate::error::RpcError;
use crate::rpc::net_name;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::read;

/// The best (fully-scanned) block's `(height, hash, time)`, when known. Falls back to the
/// upstream tip hash in the brief window before anything has been scanned.
fn best_block(state: &AppState) -> Result<(u32, Option<String>, Option<i64>), RpcError> {
    let w = state.registry.get(None)?;
    let st = w.status();
    if let Some(h) = st.fully_scanned {
        if let Some((hash, time)) = read::block_info_at(&w.dir, h)? {
            return Ok((h, Some(hash), Some(time)));
        }
    }
    Ok((st.fully_scanned.unwrap_or(0), st.best_block_hash, None))
}

pub fn getblockchaininfo(state: &AppState) -> Result<Value, RpcError> {
    let w = state.registry.get(None)?;
    let st = w.status();
    let (blocks, best_hash, best_time) = best_block(state)?;
    let headers = st.chain_tip.unwrap_or(blocks);
    let mediantime = read::median_time_past(&w.dir, blocks).ok().flatten();
    Ok(json!({
        "chain": net_name(w.network),
        "blocks": blocks,
        "headers": headers,
        "bestblockhash": best_hash.unwrap_or_default(),
        "difficulty": 1.0,
        "time": best_time.unwrap_or(0),
        "mediantime": mediantime.or(best_time).unwrap_or(0),
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
    match best_block(state)? {
        (_, Some(hash), _) => Ok(Value::String(hash)),
        _ => Err(RpcError::misc("best block hash not yet known (still syncing)")),
    }
}

pub fn getblockhash(state: &AppState, req: &RpcRequest) -> Result<Value, RpcError> {
    let height = req
        .param(0)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("getblockhash requires a height"))?
        as u32;
    let w = state.registry.get(None)?;
    // Any block the wallet has scanned can be answered from the wallet DB; the not-yet-scanned
    // chain tip is answered from the sync status. Anything else (below the wallet birthday,
    // beyond the tip) is out of range for a light wallet.
    if let Some((hash, _)) = read::block_info_at(&w.dir, height)? {
        return Ok(Value::String(hash));
    }
    let st = w.status();
    if st.chain_tip == Some(height) {
        if let Some(hash) = st.best_block_hash {
            return Ok(Value::String(hash));
        }
    }
    Err(RpcError::invalid_parameter("Block height out of range"))
}
