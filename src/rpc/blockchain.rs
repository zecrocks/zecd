//! Blockchain RPCs: getblockchaininfo, getblockcount, getbestblockhash, getblockhash,
//! getblockheader, and the `waitfor*` family.
//!
//! Heights come from the wallet's published sync status: `blocks` is the fully-scanned
//! height (the height up to which balances/history are accurate) and `headers` is the known
//! chain tip, so a syncing wallet reports `blocks < headers` as bitcoind does during IBD.
//! `getbestblockhash` and `getblockhash(getblockcount())` describe that same fully-scanned
//! block (hashes/times come from the wallet's `blocks` table), so the common poller pattern
//! `getblockhash(getblockcount())` always works.
//!
//! That fully-scanned height is also the only correct answer to "has the wallet caught up?" -
//! a balance is not, because the mempool stream credits an incoming payment at 0 confirmations,
//! before the block confirming it has been scanned. `waitfornewblock`/`waitforblock`/
//! `waitforblockheight` make that question first-class (Bitcoin Core's RPCs, same arguments and
//! `{hash, height}` result) so callers stop reinventing a poll loop over `getblockchaininfo`.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::time::Instant;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::read;

/// The best (fully-scanned) block's `(height, hash, time)`, when known. Falls back to the
/// upstream tip hash in the brief window before anything has been scanned. Resolves the
/// `/wallet/<name>`-routed wallet so a syncing wallet reports its own height, not the default's.
fn best_block(
    state: &AppState,
    wallet: Option<&str>,
) -> Result<(u32, Option<String>, Option<i64>), RpcError> {
    let w = state.registry.get(wallet)?;
    let st = w.status();
    if let Some(h) = st.fully_scanned {
        if let Some((hash, time)) = read::block_info_at(&w.engine_dir, h)? {
            return Ok((h, Some(hash), Some(time)));
        }
    }
    Ok((st.fully_scanned.unwrap_or(0), st.best_block_hash, None))
}

/// `getblockchaininfo` - chain/sync overview; `blocks`/`headers` follow the module-level
/// height conventions and `initialblockdownload` mirrors the wallet's scanning state.
pub(crate) fn getblockchaininfo(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let w = state.registry.get(wallet)?;
    let st = w.status();
    let (blocks, best_hash, best_time) = best_block(state, wallet)?;
    let headers = st.chain_tip.unwrap_or(blocks);
    let mediantime = read::median_time_past(&w.engine_dir, blocks).ok().flatten();
    Ok(json!({
        "chain": w.network.name(),
        "blocks": blocks,
        "headers": headers,
        "bestblockhash": best_hash.unwrap_or_default(),
        "difficulty": 1.0,
        "time": best_time.unwrap_or(0),
        "mediantime": mediantime.or(best_time).unwrap_or(0),
        "verificationprogress": st.scan_progress,
        // True until the wallet is ready to serve full history - which includes draining the
        // post-scan transaction-enhancement backlog, not just catching the block scan up to tip.
        "initialblockdownload": st.scanning || st.pending_enhancements > 0,
        "size_on_disk": 0,
        "pruned": false,
        "warnings": ""
    }))
}

/// `getblockcount` - the fully-scanned height (the height at which balances are accurate).
pub(crate) fn getblockcount(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let w = state.registry.get(wallet)?;
    Ok(json!(w.status().fully_scanned.unwrap_or(0)))
}

/// `getbestblockhash` - the hash of the [`getblockcount`] block (`-1` while nothing is
/// scanned yet).
pub(crate) fn getbestblockhash(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    match best_block(state, wallet)? {
        (_, Some(hash), _) => Ok(Value::String(hash)),
        _ => Err(RpcError::misc(
            "best block hash not yet known (still syncing)",
        )),
    }
}

/// `getblockhash <height>` - answered from the wallet's scanned-blocks table (or the sync
/// status for the not-yet-scanned tip); heights outside the wallet's range are `-8`.
pub(crate) fn getblockhash(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Bitcoin Core's argument taxonomy: an omitted height is the help error (-1), a non-integer
    // is a type error (-3), and an integer outside the representable/valid range is -8.
    let height = match req.param(0) {
        None | Some(Value::Null) => {
            return Err(RpcError::missing_param("getblockhash requires a height"))
        }
        Some(v) => {
            let n = v
                .as_i64()
                .ok_or_else(|| RpcError::type_error("Block height must be an integer"))?;
            u32::try_from(n)
                .map_err(|_| RpcError::invalid_parameter("Block height out of range"))?
        }
    };
    let w = state.registry.get(wallet)?;
    // Any block the wallet has scanned can be answered from the wallet DB; the not-yet-scanned
    // chain tip is answered from the sync status. Anything else (below the wallet birthday,
    // beyond the tip) is out of range for a light wallet.
    if let Some((hash, _)) = read::block_info_at(&w.engine_dir, height)? {
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
pub(crate) fn getblockheader(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let hash = req.require_str(0, "getblockheader requires a block hash")?;
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

    let w = state.registry.get(wallet)?;
    let height = read::block_height_by_hash(&w.engine_dir, hash)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Block not found"))?;
    let (_, time) = read::block_info_at(&w.engine_dir, height)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Block not found"))?;
    let st = w.status();
    let mediantime = read::median_time_past(&w.engine_dir, height).ok().flatten();

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
        if let Some((prev, _)) = read::block_info_at(&w.engine_dir, h)? {
            obj["previousblockhash"] = json!(prev);
        }
    }
    if let Some((next, _)) = read::block_info_at(&w.engine_dir, height + 1)? {
        obj["nextblockhash"] = json!(next);
    }
    Ok(obj)
}

/// How long a `waitfor*` wait may sleep before re-checking the wallet's best block regardless of
/// notifications. The wait is event-driven - it wakes on every [`crate::wallet::SyncStatus`] the
/// wallet actor publishes, which is at least once per sync pass - so this is only a backstop
/// bounding how long a *missed* publish (or an actor wedged mid-batch) could stall a waiter. It
/// is not the polling loop these RPCs exist to replace.
const WAIT_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// The `{hash, height}` result Bitcoin Core's `waitfor*` RPCs return - describing the wallet's
/// best (fully-scanned) block, both when the wait was satisfied and when it timed out.
fn wait_result(height: u32, hash: Option<String>) -> Value {
    json!({ "hash": hash.unwrap_or_default(), "height": height })
}

/// Parse a `waitfor*` timeout argument: milliseconds, with an omitted/null/`0` value meaning
/// "wait indefinitely" (Bitcoin Core's convention). Follows Core's argument taxonomy - a
/// non-integer is a type error (-3), and a negative timeout is the `-1` "Negative timeout" Core
/// raises before waiting at all.
fn wait_timeout(req: &RpcRequest, i: usize) -> Result<Option<Duration>, RpcError> {
    let millis = match req.param(i) {
        None | Some(Value::Null) => 0,
        Some(v) => v.as_i64().ok_or_else(|| {
            RpcError::type_error("Timeout must be an integer number of milliseconds")
        })?,
    };
    if millis < 0 {
        return Err(RpcError::misc("Negative timeout"));
    }
    Ok((millis > 0).then(|| Duration::from_millis(millis as u64)))
}

/// Drive a `waitfor*` wait: re-evaluate `satisfied` against the wallet's best (fully-scanned)
/// block - as `(height, hash)` - whenever the wallet actor publishes a new sync status, until it
/// holds, the timeout expires, or the daemon shuts down. A timeout is **not** an error in
/// Bitcoin Core: all three outcomes return the current best block, so a caller that cares
/// distinguishes them by inspecting the returned height.
///
/// Note the wait holds a work-queue slot for its duration, exactly as Core's does (where it
/// holds an RPC thread); a caller that passes no timeout and never gets its block occupies that
/// slot until the daemon stops.
async fn wait_for_best_block(
    state: &AppState,
    wallet: Option<&str>,
    timeout: Option<Duration>,
    mut satisfied: impl FnMut(u32, Option<&str>) -> bool,
) -> Result<Value, RpcError> {
    let mut status = state.registry.get(wallet)?.subscribe_status();
    let deadline = timeout.map(|t| Instant::now() + t);
    let shutdown = state.shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        // Mark the current status seen *before* reading the block it describes, so an update
        // that lands while we read wakes the wait below instead of being missed.
        drop(status.borrow_and_update());
        let (height, hash, _) = best_block(state, wallet)?;
        if satisfied(height, hash.as_deref()) {
            return Ok(wait_result(height, hash));
        }
        let now = Instant::now();
        // Checked after the read above, so a timeout answers with the wallet's current view
        // rather than one taken a re-check interval ago.
        let remaining = match deadline {
            Some(d) if d <= now => return Ok(wait_result(height, hash)),
            Some(d) => Some(d - now),
            None => None,
        };
        let nap = remaining
            .unwrap_or(WAIT_RECHECK_INTERVAL)
            .min(WAIT_RECHECK_INTERVAL);
        tokio::select! {
            _ = &mut shutdown => return Ok(wait_result(height, hash)),
            _ = tokio::time::sleep(nap) => {}
            res = status.changed() => {
                // The actor is gone (shut down, or it died): the height will never advance, so
                // answer with what the wallet has instead of waiting out the timeout.
                if res.is_err() {
                    return Ok(wait_result(height, hash));
                }
            }
        }
    }
}

/// `waitfornewblock ( timeout )` - block until the wallet's best *scanned* block differs from
/// the one it is on now (by height or, across a reorg, by hash), then return `{hash, height}`.
/// `timeout` is in milliseconds; `0` (the default) waits indefinitely, and a timeout returns the
/// current block rather than an error.
pub(crate) async fn waitfornewblock(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let timeout = wait_timeout(req, 0)?;
    let (start_height, start_hash, _) = best_block(state, wallet)?;
    wait_for_best_block(state, wallet, timeout, move |height, hash| {
        height != start_height || hash != start_hash.as_deref()
    })
    .await
}

/// `waitforblock <blockhash> ( timeout )` - block until `blockhash` is the wallet's best scanned
/// block. Like Bitcoin Core this watches only the tip, so a hash the wallet has already scanned
/// past never matches; use `waitforblockheight` to wait for a height to be reached.
pub(crate) async fn waitforblock(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let target = req.require_str(0, "waitforblock requires a block hash")?;
    parse_blockhash_param(target)?;
    // Core parses the argument into a hash, so its comparison is case-insensitive; the wallet
    // stores display hex in lower case.
    let target = target.to_ascii_lowercase();
    let timeout = wait_timeout(req, 1)?;
    wait_for_best_block(state, wallet, timeout, move |_, hash| {
        hash == Some(target.as_str())
    })
    .await
}

/// `waitforblockheight <height> ( timeout )` - block until the wallet has *scanned* to at least
/// `height`, i.e. until `getblockchaininfo.blocks` (equivalently `getblockcount`) reaches it.
/// This is the RPC to use before asserting on a balance or history: an incoming payment is
/// credited from the mempool at 0 confirmations, so a balance alone never proves the confirming
/// block was scanned.
pub(crate) async fn waitforblockheight(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Same argument taxonomy as `getblockhash`: omitted is the help error (-1), a non-integer is
    // a type error (-3), and an integer outside the representable range is -8.
    let target = match req.param(0) {
        None | Some(Value::Null) => {
            return Err(RpcError::missing_param(
                "waitforblockheight requires a height",
            ))
        }
        Some(v) => {
            let n = v
                .as_i64()
                .ok_or_else(|| RpcError::type_error("Block height must be an integer"))?;
            u32::try_from(n)
                .map_err(|_| RpcError::invalid_parameter("Block height out of range"))?
        }
    };
    let timeout = wait_timeout(req, 1)?;
    wait_for_best_block(state, wallet, timeout, move |height, _| height >= target).await
}

/// `waitforsync ( timeout )` - zecd extension: start a sync pass immediately, then block until
/// the wallet is fully caught up, meaning **both** the block scan has reached the chain tip and
/// the transaction-enhancement backlog has drained.
///
/// This exists because "caught up" has two halves and only the first is a height. A consumer
/// that waits on `waitforblockheight` and then reads memos gets nothing for transactions whose
/// full data has not been fetched yet - compact blocks carry no memos, so a scanned output's
/// memo is NULL until enhancement backfills it. Answering that question previously meant
/// combining `waitforblockheight` with a poll of `getwalletinfo.scanning`, and the backlog count
/// itself was reachable only on the health server, which an embedded node does not run.
///
/// The immediate nudge matters as much as the wait: without it the first pass waits out
/// `[sync] interval_secs`, so a caller asking "sync now, then read" pays that latency on every
/// call. The nudge is best-effort - a wallet whose actor is gone, or whose sync has halted,
/// still gets the wait (and the answer that it is not synced) rather than an error, since the
/// point of the call is to report the state.
///
/// `timeout` is in **milliseconds** (Core's `waitfor*` convention, not `z_waitforoperation`'s
/// seconds), and `0`/omitted waits indefinitely. **A timeout is not an error**: it returns the
/// current state with `synced: false`, so a caller branches on the field rather than catching.
/// That boolean is load-bearing - without it "the wait gave up" and "the wallet is ready" would
/// be told apart only by re-deriving the predicate from the other fields.
pub(crate) async fn waitforsync(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let timeout = wait_timeout(req, 0)?;
    let handle = state.registry.get(wallet)?;
    // Nudge first, so the wait below is measuring a pass that is already starting.
    let _ = handle.sync_now().await;

    let mut status = handle.subscribe_status();
    let deadline = timeout.map(|t| Instant::now() + t);
    let shutdown = state.shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        // Mark the current status seen before reading it, so an update landing mid-read wakes
        // the wait below instead of being missed (as in `wait_for_best_block`).
        drop(status.borrow_and_update());
        let st = handle.status();
        let synced = !st.scanning && st.pending_enhancements == 0;
        let answer = || {
            let (height, hash, _) = best_block(state, wallet)?;
            Ok(json!({
                "hash": hash.unwrap_or_default(),
                "height": height,
                // The upstream's tip, so a caller can render "scanned H of TIP" without opening
                // its own connection to ask. `height` alone cannot express progress: it is the
                // scanned height, and what it is being compared against is exactly this.
                // `None` until the first tip is known (before the first successful connect).
                "chain_tip": st.chain_tip,
                "synced": synced,
                "pending_enhancements": st.pending_enhancements,
                "enhanced_through": st.enhanced_through,
            }))
        };
        if synced {
            return answer();
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) if d <= now => return answer(),
            Some(d) => Some(d - now),
            None => None,
        };
        let nap = remaining
            .unwrap_or(WAIT_RECHECK_INTERVAL)
            .min(WAIT_RECHECK_INTERVAL);
        tokio::select! {
            // Returning on shutdown keeps a no-timeout call from pinning a work-queue permit
            // through a graceful stop.
            _ = &mut shutdown => return answer(),
            _ = tokio::time::sleep(nap) => {}
            res = status.changed() => {
                // The actor is gone: nothing will advance, so answer with what the wallet has
                // rather than waiting out the timeout.
                if res.is_err() {
                    return answer();
                }
            }
        }
    }
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

    fn req_with(params: Vec<Value>) -> RpcRequest {
        RpcRequest {
            id: json!(1),
            method: "waitforblockheight".into(),
            params,
        }
    }

    /// Bitcoin Core's `waitfor*` timeout convention: milliseconds, with omitted/null/`0` all
    /// meaning "no timeout". Getting `0` wrong in either direction is the whole risk here - a
    /// `0` read as an instant deadline turns a blocking wait into a poll, and an omitted
    /// argument read as `0` milliseconds does the same.
    #[test]
    fn wait_timeout_treats_zero_and_omitted_as_no_timeout() {
        assert_eq!(wait_timeout(&req_with(vec![]), 0).unwrap(), None);
        assert_eq!(wait_timeout(&req_with(vec![Value::Null]), 0).unwrap(), None);
        assert_eq!(wait_timeout(&req_with(vec![json!(0)]), 0).unwrap(), None);
        assert_eq!(
            wait_timeout(&req_with(vec![json!(1500)]), 0).unwrap(),
            Some(Duration::from_millis(1500))
        );
    }

    /// The argument errors follow Core: a non-integer timeout is a type error, and a negative
    /// one is rejected outright rather than silently becoming an instant timeout.
    #[test]
    fn wait_timeout_rejects_negative_and_non_integer() {
        let e = wait_timeout(&req_with(vec![json!(-1)]), 0).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_MISC_ERROR);
        assert_eq!(e.message, "Negative timeout");
        let e = wait_timeout(&req_with(vec![json!("soon")]), 0).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }
}
