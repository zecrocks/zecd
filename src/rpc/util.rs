//! Utility RPCs: validateaddress, estimatesmartfee, estimatefee, getmempoolinfo.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

pub fn validateaddress(state: &AppState, req: &RpcRequest) -> Result<Value, RpcError> {
    let addr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("validateaddress requires an address"))?;
    let v = crate::address::validate(&state.config.network, addr);
    // Bitcoin Core returns only the verdict plus error details for invalid input; the
    // address echo and script fields appear only when the address is valid.
    if !v.is_valid {
        return Ok(json!({
            "isvalid": false,
            "error_locations": [],
            "error": "Invalid or unsupported address format",
        }));
    }
    Ok(json!({
        "isvalid": true,
        "address": addr,
        // Real scriptPubKey for transparent addresses; shielded addresses have no
        // script form, so the field stays empty.
        "scriptPubKey": v.script_pub_key.unwrap_or_default(),
        "isscript": v.is_script,
        "iswitness": false,
        // Extension field: whether this address can receive Orchard funds.
        "isvalid_orchard": v.is_orchard,
    }))
}

pub fn estimatesmartfee(req: &RpcRequest) -> Result<Value, RpcError> {
    // Zcash fees are ZIP-317 (computed at build time); return a stable conventional rate so
    // clients that probe fees succeed.
    let blocks = req.param(0).and_then(|v| v.as_i64()).unwrap_or(6);
    Ok(json!({ "feerate": zats_to_value(1000), "blocks": blocks }))
}

pub fn estimatefee(_req: &RpcRequest) -> Result<Value, RpcError> {
    Ok(zats_to_value(1000))
}

pub fn getmempoolinfo() -> Result<Value, RpcError> {
    Ok(json!({
        "loaded": true,
        "size": 0,
        "bytes": 0,
        "usage": 0,
        "total_fee": zats_to_value(0),
        "maxmempool": 300_000_000,
        "mempoolminfee": zats_to_value(1000),
        "minrelaytxfee": zats_to_value(1000)
    }))
}
