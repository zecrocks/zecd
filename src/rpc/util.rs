//! Utility RPCs: validateaddress, estimatesmartfee, estimatefee, getmempoolinfo.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;

/// `validateaddress <address>` - network-aware validity verdict for any Zcash address kind,
/// with an `isvalid_orchard` extension flagging Orchard-receiver capability.
pub(crate) fn validateaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "validateaddress requires an address")?;
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
    let mut out = json!({
        "isvalid": true,
        "address": addr,
        // Real scriptPubKey for transparent addresses; shielded addresses have no
        // script form, so the field stays empty.
        "scriptPubKey": v.script_pub_key.unwrap_or_default(),
        "isscript": v.is_script,
        "iswitness": false,
        // Extension field: whether this address can receive into the Orchard pool.
        "isvalid_orchard": v.is_orchard,
        // Extension field: the pools this address can receive into, in canonical order
        // (`transparent`/`sapling`/`orchard`). For a unified address this enumerates its
        // receivers, so a client can see what a `u1...` actually carries.
        "receiver_types": v.receiver_types,
    });
    // Extension field: for a unified address, whether all its receivers belong to the routed
    // wallet at one diversifier index. `false` flags a hand-spliced UA (receivers from different
    // indices, or one of ours mixed with a stranger's); omitted when not computable - a foreign
    // UA (the index is the owner's secret) or a single-receiver address. Best-effort: if the
    // wallet can't be resolved, the field is simply absent.
    if let Ok(handle) = state.registry.get(wallet) {
        if let Some(consistent) =
            crate::wallet::read::classify_unified_receivers(handle.network, &handle.dir, addr)
                .consistent_flag()
        {
            out["receivers_consistent"] = json!(consistent);
        }
    }
    Ok(out)
}

/// `settxfee` - an explicit fee instruction, so it gets the same treatment as
/// `fee_rate`/`subtractfeefromamount`: a self-diagnosing `-8` rather than bitcoind's
/// `true` (which would be a lie) or a bare method-not-found.
pub(crate) fn settxfee(_req: &RpcRequest) -> Result<Value, RpcError> {
    Err(RpcError::invalid_parameter(
        "settxfee is not supported: fees follow ZIP-317 (computed at transaction-build time) \
         and are never client-settable",
    ))
}

/// `estimatesmartfee [conf_target]` - a stable conventional rate (Zcash fees are ZIP-317,
/// computed at build time; there is no estimator), so fee-probing clients succeed.
pub(crate) fn estimatesmartfee(req: &RpcRequest) -> Result<Value, RpcError> {
    // Zcash fees are ZIP-317 (computed at build time); return a stable conventional rate so
    // clients that probe fees succeed.
    let blocks = req.param(0).and_then(|v| v.as_i64()).unwrap_or(6);
    Ok(json!({ "feerate": zats_to_value(1000), "blocks": blocks }))
}

/// `estimatefee` - the legacy single-number fee probe; same conventional rate as
/// [`estimatesmartfee`].
pub(crate) fn estimatefee(_req: &RpcRequest) -> Result<Value, RpcError> {
    Ok(zats_to_value(1000))
}

/// `getmempoolinfo` - a light client sees no mempool of its own, so this reports an empty
/// (but loaded) pool with the conventional fee floors, satisfying client preflight checks.
pub(crate) fn getmempoolinfo() -> Result<Value, RpcError> {
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

#[cfg(test)]
mod tests {
    #[test]
    fn settxfee_is_rejected_with_fee_explanation() {
        let req = crate::server::jsonrpc::RpcRequest {
            id: serde_json::Value::Null,
            method: "settxfee".into(),
            params: vec![serde_json::json!(0.0001)],
        };
        let e = super::settxfee(&req).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("ZIP-317"), "{}", e.message);
    }
}
