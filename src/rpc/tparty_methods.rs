//! tparty's RPC surface: transparent deposit addresses, unshielded-balance reporting, and
//! auto-shield visibility. History/label/encryption methods are shared with zecd (the
//! wallet DB rows cover transparent outputs the same way), while the address and balance
//! methods are tparty-specific: `getnewaddress` returns base58 t-addresses, and the
//! balances report *unshielded* funds only - the whole point of the daemon is that this
//! number trends to zero as deposits confirm and auto-shield.

use serde_json::{json, Value};

use crate::amount::zats_to_value;
use crate::error::RpcError;
use crate::rpc::{blockchain, control, network, rawtx, util, wallet_methods};
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::read;

/// tparty's method table. Methods zecd serves but tparty deliberately does not (e.g.
/// `sendtoaddress`/`sendmany` - tparty is a deposit funnel, not a spending wallet) fall
/// through to -32601 here.
pub(crate) async fn dispatch(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    match req.method.as_str() {
        // Control
        "stop" => stop(state),
        "uptime" => control::uptime(state),
        "help" => help(),
        "getrpcinfo" => control::getrpcinfo(state),

        // Network
        "getnetworkinfo" => network::getnetworkinfo(state),
        "getconnectioncount" => network::getconnectioncount(state),
        "getpeerinfo" => network::getpeerinfo(state),
        "ping" => network::ping(),

        // Blockchain
        "getblockchaininfo" => blockchain::getblockchaininfo(state),
        "getblockcount" => blockchain::getblockcount(state),
        "getbestblockhash" => blockchain::getbestblockhash(state),
        "getblockhash" => blockchain::getblockhash(state, req),
        "getblockheader" => blockchain::getblockheader(state, req),

        // Utility
        "validateaddress" => util::validateaddress(state, req),
        "settxfee" => util::settxfee(req),
        "estimatesmartfee" => util::estimatesmartfee(req),
        "estimatefee" => util::estimatefee(req),
        "getmempoolinfo" => util::getmempoolinfo(),

        // Raw transactions
        "getrawtransaction" => rawtx::getrawtransaction(state, wallet, req).await,
        "sendrawtransaction" => rawtx::sendrawtransaction(state, wallet, req).await,

        // Wallet - tparty-specific
        "getnewaddress" => getnewaddress(state, wallet, req).await,
        "getbalance" => getbalance(state, wallet, req),
        "getunconfirmedbalance" => getunconfirmedbalance(state, wallet),
        "getbalances" => getbalances(state, wallet),
        "getwalletinfo" => getwalletinfo(state, wallet),
        "listunspent" => listunspent(state, wallet, req),
        "getshieldinginfo" => getshieldinginfo(state, wallet),
        "shieldfunds" => shieldfunds(state, wallet).await,

        // Wallet - shared with zecd (history, received-by, labels, encryption). The
        // underlying wallet views cover transparent receives/spends identically.
        "getaddressinfo" => wallet_methods::getaddressinfo(state, wallet, req),
        "getaddressesbylabel" => wallet_methods::getaddressesbylabel(state, wallet, req),
        "listlabels" => wallet_methods::listlabels(state, wallet),
        "setlabel" => wallet_methods::setlabel(state, wallet, req),
        "listtransactions" => wallet_methods::listtransactions(state, wallet, req),
        "z_listtransactions" => wallet_methods::z_listtransactions(state, wallet, req),
        "listsinceblock" => wallet_methods::listsinceblock(state, wallet, req),
        "gettransaction" => wallet_methods::gettransaction(state, wallet, req).await,
        "getreceivedbyaddress" => wallet_methods::getreceivedbyaddress(state, wallet, req),
        "listreceivedbyaddress" => wallet_methods::listreceivedbyaddress(state, wallet, req),
        "getreceivedbylabel" => wallet_methods::getreceivedbylabel(state, wallet, req),
        "listreceivedbylabel" => wallet_methods::listreceivedbylabel(state, wallet, req),
        "listwallets" => wallet_methods::listwallets(state),
        "encryptwallet" => wallet_methods::encryptwallet(state, wallet, req).await,
        "walletpassphrase" => wallet_methods::walletpassphrase(state, wallet, req).await,
        "walletpassphrasechange" => {
            wallet_methods::walletpassphrasechange(state, wallet, req).await
        }
        "walletlock" => wallet_methods::walletlock(state, wallet).await,

        other => Err(RpcError::method_not_found(other)),
    }
}

fn stop(state: &AppState) -> Result<Value, RpcError> {
    state.trigger_shutdown();
    Ok(Value::String("tparty stopping".to_string()))
}

fn help() -> Result<Value, RpcError> {
    Ok(Value::String(
        "tparty: transparent Zcash deposit addresses that auto-shield into the wallet's \
         shielded pool once deposits confirm. getnewaddress returns t-addresses; getbalance \
         reports only funds that have not shielded yet. Key methods: getnewaddress, \
         getbalance, getunconfirmedbalance, getbalances, listunspent, listtransactions, \
         gettransaction, listsinceblock, getreceivedbyaddress, listreceivedbyaddress, \
         getshieldinginfo, shieldfunds, getwalletinfo, getblockchaininfo, validateaddress. \
         See the README for the full list and limits."
            .to_string(),
    ))
}

/// `getnewaddress [label] [address_type]` - a fresh transparent (P2PKH) deposit address.
/// Every address tparty hands out is a t-address; `address_type` is accepted only as
/// `"legacy"` (bitcoind's name for base58 P2PKH) so a caller asking for e.g. `"bech32"`
/// isn't silently handed something else.
async fn getnewaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = wallet_methods::opt_str(req, 0).filter(|s| !s.is_empty());
    if let Some(t) = req
        .param(1)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        if !t.eq_ignore_ascii_case("legacy") {
            return Err(RpcError::invalid_address_or_key(format!(
                "Unknown address type '{t}'"
            )));
        }
    }
    let handle = state.registry.get(wallet)?.clone();
    let addr = handle.get_new_transparent_address(label).await?;
    Ok(Value::String(addr))
}

/// `getbalance [dummy] [minconf]` - the confirmed transparent balance, i.e. deposits that
/// have *not yet* shielded. With auto-shield healthy this hovers near zero (each balance
/// lives at most a sync interval between confirmation and the shielding broadcast); a
/// persistently positive number means shielding is blocked (locked wallet, dust below the
/// threshold, upstream down - see `getshieldinginfo`). The dummy/minconf arguments follow
/// Bitcoin Core: dummy must be excluded or `"*"`; minconf defaults to 1, and (unlike
/// shielded notes) transparent outputs *can* be counted at 0 confirmations.
fn getbalance(state: &AppState, wallet: Option<&str>, req: &RpcRequest) -> Result<Value, RpcError> {
    wallet_methods::check_balance_dummy(req.param(0))?;
    let minconf = match req.param(1).filter(|v| !v.is_null()) {
        None => 1,
        Some(v) => match v.as_i64() {
            Some(n) => u32::try_from(n.max(0)).unwrap_or(u32::MAX),
            None => return Err(RpcError::type_error("minconf must be a number")),
        },
    };
    let handle = state.registry.get(wallet)?;
    let (spendable, _) = read::transparent_balance(handle.network, &handle.dir, minconf)?;
    Ok(zats_to_value(spendable))
}

/// `getunconfirmedbalance` - transparent deposits seen (mempool or too few confirmations)
/// but not yet eligible to shield.
fn getunconfirmedbalance(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let (_, pending) = read::transparent_balance(handle.network, &handle.dir, 1)?;
    Ok(zats_to_value(pending))
}

/// `getbalances` - bitcoind's shape for the *unshielded* funds, plus a `shielded` object
/// (a tparty extension) so operators can watch deposits land in the pool.
fn getbalances(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let (spendable, pending) = read::transparent_balance(handle.network, &handle.dir, 1)?;
    let shielded = read::balance(handle.network, &handle.dir, handle.confirmations)?;
    let mut obj = json!({
        "mine": {
            "trusted": zats_to_value(spendable),
            "untrusted_pending": zats_to_value(pending),
            "immature": zats_to_value(0),
        },
        "shielded": {
            "trusted": zats_to_value(shielded.total_spendable),
            "untrusted_pending": zats_to_value(shielded.pending),
            "immature": zats_to_value(shielded.immature),
        },
    });
    if let Some(h) = handle.status().fully_scanned {
        if let Ok(Some((hash, _))) = read::block_info_at(&handle.dir, h) {
            obj["lastprocessedblock"] = json!({ "hash": hash, "height": h });
        }
    }
    Ok(obj)
}

/// `getwalletinfo` - bitcoind's shape with the standard balance fields reporting
/// *unshielded* funds; the destination pool rides on `shielded_*` extension fields.
fn getwalletinfo(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let (spendable, pending) = read::transparent_balance(handle.network, &handle.dir, 1)?;
    let shielded = read::balance(handle.network, &handle.dir, handle.confirmations)?;
    let txcount = read::tx_count(&handle.dir).unwrap_or(0);
    let st = handle.status();
    let scanning = if st.scanning {
        json!({ "duration": 0, "progress": st.scan_progress })
    } else {
        Value::Bool(false)
    };
    let mut obj = json!({
        "walletname": handle.name,
        "walletversion": 169900,
        "format": "sqlite",
        // The bitcoind-shaped fields report unshielded (transparent) funds...
        "balance": zats_to_value(spendable),
        "unconfirmed_balance": zats_to_value(pending),
        "immature_balance": zats_to_value(0),
        // ...and the destination pool's funds ride on tparty-specific extensions. Freshly
        // shielded value is wallet *change* (an internal note), so until it reaches the
        // trusted confirmation depth it counts as pending here, not spendable.
        "shielded_balance": zats_to_value(shielded.total_spendable),
        "shielded_unconfirmed_balance": zats_to_value(shielded.pending + shielded.immature),
        "txcount": txcount,
        "keypoolsize": state.config.tparty.gap_limit,
        "keypoolsize_hd_internal": 0,
        "paytxfee": zats_to_value(0),
        // False for a watch-only wallet (imported UFVK; auto-shield cannot run on one).
        "private_keys_enabled": !st.watch_only,
        "avoid_reuse": false,
        "scanning": scanning,
        "descriptors": false
    });
    if st.encrypted {
        obj["unlocked_until"] = json!(st.unlocked_until.unwrap_or(0));
    }
    Ok(obj)
}

/// `listunspent [minconf] [maxconf]` - the wallet's unspent transparent outputs (deposits
/// awaiting shielding). Unlike zecd's synthesized note entries these are real bitcoin-style
/// outpoints with an address and scriptPubKey.
fn listunspent(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Strict typed parsing (a non-number is -3), matching zecd's listunspent and bitcoind -
    // rather than silently swallowing a wrong-typed minconf/maxconf and using the default.
    let minconf = wallet_methods::depth_param(req.param(0), "minconf", 1)?;
    let maxconf = wallet_methods::depth_param(req.param(1), "maxconf", 9_999_999)?;
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let utxos = read::list_transparent_unspent(handle.network, &handle.dir)?;
    let arr: Vec<Value> = utxos
        .iter()
        .map(|u| (st.confirmations(u.mined_height), u))
        .filter(|(conf, _)| *conf >= minconf && *conf <= maxconf)
        .map(|(conf, u)| {
            json!({
                "txid": u.txid,
                "vout": u.vout,
                "address": u.address,
                "scriptPubKey": hex::encode(&u.script_pubkey),
                "amount": zats_to_value(u.value),
                "confirmations": conf,
                "spendable": true,
                "solvable": true,
                "safe": conf > 0,
            })
        })
        .collect();
    Ok(Value::Array(arr))
}

/// `getshieldinginfo` - the operator's one-stop health view of the auto-shield pipeline:
/// policy, what is waiting (and why it might be stuck), what has made it into the pool, and
/// the most recent shielding txid.
fn getshieldinginfo(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let t = &state.config.tparty;
    let (spendable, pending) = read::transparent_balance(handle.network, &handle.dir, 1)?;
    let shielded = read::balance(handle.network, &handle.dir, handle.confirmations)?;
    Ok(json!({
        "enabled": true,
        "pool": t.pool.name(),
        "min_conf": t.min_conf,
        "threshold": zats_to_value(t.threshold_zat),
        "unshielded": zats_to_value(spendable),
        "unshielded_pending": zats_to_value(pending),
        "shielded": zats_to_value(shielded.total_spendable),
        // Freshly shielded value is wallet change (an internal note) and rides here until it
        // reaches the trusted confirmation depth, then moves to `shielded`.
        "shielded_pending": zats_to_value(shielded.pending + shielded.immature),
        "last_shield_txid": st.last_shield_txid,
        "connected": st.connected,
        "conn_state": st.conn_state.as_str(),
        "blocks": st.fully_scanned.unwrap_or(0),
        "scanning": st.scanning,
    }))
}

/// `shieldfunds` - immediately shield all spendable transparent funds, ignoring the value
/// threshold. Returns the shielding txid, or null when there was nothing spendable. The
/// safety valve for funds the automatic path is skipping (e.g. dust below the threshold).
async fn shieldfunds(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?.clone();
    match handle.shield_now().await? {
        Some(txid) => Ok(Value::String(txid.to_string())),
        None => Ok(Value::Null),
    }
}
