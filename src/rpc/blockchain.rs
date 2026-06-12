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

/// `getblockchaininfo` - chain/sync overview; `blocks`/`headers` follow the module-level
/// height conventions and `initialblockdownload` mirrors the wallet's scanning state.
pub(crate) fn getblockchaininfo(state: &AppState) -> Result<Value, RpcError> {
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

/// `getblockcount` - the fully-scanned height (the height at which balances are accurate).
pub(crate) fn getblockcount(state: &AppState) -> Result<Value, RpcError> {
    let w = state.registry.get(None)?;
    Ok(json!(w.status().fully_scanned.unwrap_or(0)))
}

/// `getbestblockhash` - the hash of the [`getblockcount`] block (`-1` while nothing is
/// scanned yet).
pub(crate) fn getbestblockhash(state: &AppState) -> Result<Value, RpcError> {
    match best_block(state)? {
        (_, Some(hash), _) => Ok(Value::String(hash)),
        _ => Err(RpcError::misc(
            "best block hash not yet known (still syncing)",
        )),
    }
}

/// `getblockhash <height>` - answered from the wallet's scanned-blocks table (or the sync
/// status for the not-yet-scanned tip); heights outside the wallet's range are `-8`.
pub(crate) fn getblockhash(state: &AppState, req: &RpcRequest) -> Result<Value, RpcError> {
    let height = req
        .param(0)
        .and_then(|v| v.as_u64())
        .filter(|h| *h <= u64::from(u32::MAX))
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

/// Validate a display-hex block-hash parameter with Bitcoin Core's `ParseHashV` errors (-8).
fn parse_blockhash_param(s: &str) -> Result<(), RpcError> {
    if s.len() != 64 {
        return Err(RpcError::invalid_parameter(format!(
            "blockhash must be of length 64 (not {}, for '{s}')",
            s.len()
        )));
    }
    if hex::decode(s).is_err() {
        return Err(RpcError::invalid_parameter(format!(
            "blockhash must be hexadecimal string (not '{s}')"
        )));
    }
    Ok(())
}

/// `getblockheader <blockhash> [verbose]` - served from the wallet's scanned-blocks table,
/// so only blocks in the wallet's scan range can be answered, and only the fields a compact
/// block carries are present: `hash`, `confirmations`, `height`, `time`, `mediantime`, and
/// the `previousblockhash`/`nextblockhash` links (no version/merkleroot/nonce/bits/
/// difficulty - a light client never sees them). The common poller pattern - walk
/// `nextblockhash` from a checkpoint, read `height`/`confirmations`/`time` - works.
pub(crate) fn getblockheader(state: &AppState, req: &RpcRequest) -> Result<Value, RpcError> {
    let hash = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getblockheader requires a block hash"))?;
    parse_blockhash_param(hash)?;
    // Param 1 (verbose, default true): the non-verbose form is the serialized 80-byte-style
    // header, which a compact-block wallet does not store - reject rather than fabricate.
    match req.param(1) {
        None | Some(Value::Null) | Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => {
            return Err(RpcError::invalid_parameter(
                "verbose=false is not supported: a light wallet does not store serialized \
                 block headers",
            ))
        }
        Some(_) => return Err(RpcError::type_error("verbose must be a boolean")),
    }

    let w = state.registry.get(None)?;
    let height = read::block_height_by_hash(&w.dir, hash)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Block not found"))?;
    let (_, time) = read::block_info_at(&w.dir, height)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Block not found"))?;
    let st = w.status();
    let mediantime = read::median_time_past(&w.dir, height).ok().flatten();

    let mut obj = json!({
        "hash": hash,
        "confirmations": st.confirmations(Some(height)),
        "height": height,
        "time": time,
        "mediantime": mediantime.unwrap_or(time),
    });
    // Chain links, where the neighbors are in the wallet's scan range (Bitcoin Core also
    // omits previousblockhash on genesis and nextblockhash on the tip).
    if let Some(h) = height.checked_sub(1) {
        if let Some((prev, _)) = read::block_info_at(&w.dir, h)? {
            obj["previousblockhash"] = json!(prev);
        }
    }
    if let Some((next, _)) = read::block_info_at(&w.dir, height + 1)? {
        obj["nextblockhash"] = json!(next);
    }
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockhash_param_errors_match_parse_hash_v() {
        let e = parse_blockhash_param("abcd").unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("must be of length 64"), "{}", e.message);
        let e = parse_blockhash_param(&"zz".repeat(32)).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("must be hexadecimal"), "{}", e.message);
        assert!(parse_blockhash_param(&"ab".repeat(32)).is_ok());
    }
}
